"""IFC plugin: information-flow / confidentiality, adapted to the plugin SPI.

This is a thin adapter over the existing, tested IFC logic:
  - prompt construction  : ifc_prompts._system_prompt / _user_prompt
  - response parsing      : ifc_prompts._extract_flow_json
  - deterministic checker : ifc_reasoner.classify / render_gaps
  - composition operator  : ifc_reasoner.instantiate_callee

Behavior is intended to match ifc_main.py exactly (same per-function flow
signatures, same verdicts), so the migration is non-regressing. The driver now
owns extraction, call-graph, ordering, the LLM retry loop, and tracing.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

from config import IFC_FLOW_SIGNATURE_MODEL
from src.ifc_prompts import _system_prompt, _user_prompt, _extract_flow_json
from src.ifc_reasoner import (
    classify, render_gaps, instantiate_callee,
    _raw_input_labels, HIGH, LOW, UNKNOWN,
)
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    DriverContext,
    Evidence,
    FactEnvelope,
    Finding,
    PluginMetadata,
    ResolvedCall,
    Verdict,
)


def _arg_label(arg_expr: str, caller_raw_labels: Dict[str, str]) -> str:
    """Deterministically label a call-site argument expression in caller context.

    Mirrors ifc_main._arg_label:
      - string/number literal -> Low
      - bare caller-parameter name -> that parameter's label
      - anything else -> Unknown (conservative)
    """
    expr = (arg_expr or "").strip()
    if re.fullmatch(r'["\'].*["\']', expr) or re.fullmatch(r"[-+]?\d+(\.\d+)?", expr):
        return LOW
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        key = f"param:{expr}"
        if key in caller_raw_labels:
            return caller_raw_labels[key]
        return UNKNOWN
    return UNKNOWN


def _summarize_callee(name: str, signature: dict) -> str:
    """One-line callee flow summary to feed a caller's prompt (mirrors ifc_main)."""
    outs = (signature or {}).get("outputs", {}) or {}
    parts = []
    for ch, spec in outs.items():
        deps = (spec or {}).get("deps", [])
        parts.append(f"{ch}<-{{{','.join(deps)}}}")
    return f"{name}: " + ("; ".join(parts) if parts else "(no tracked outputs)")


class IfcPlugin(AnalysisPlugin):
    """Information-flow control plugin (confidentiality non-interference)."""

    model = IFC_FLOW_SIGNATURE_MODEL
    SCHEMA = "ifc.flow_signature.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="ifc",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "go",
                                 "java", "c", "cpp", "rust", "cuda", "arkts"),
            verdicts=("LEAK", "DECLASSIFIED", "POLYMORPHIC", "SECURE", "ERROR"),
            requires_top_down_context=False,
            needs_entrypoint=True,
        )

    # -- abstraction -----------------------------------------------------------

    def build_abstraction_prompt(self, request: AbstractionRequest) -> List[Dict[str, str]]:
        unit = request.function
        numbered = "\n".join(
            f"Line {i+1}: {ln}" for i, ln in enumerate(unit.source.splitlines())
        )
        callee_summaries = None
        if request.callee_context:
            # The driver already produced per-callee summaries via summarize_for_caller.
            callee_summaries = "\n".join(request.callee_context.values())
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(
                numbered, unit.signature_line, unit.id.language, callee_summaries)},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        signature = _extract_flow_json(raw_response)
        if signature is None:
            return None
        return FactEnvelope(
            plugin_name="ifc",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=signature,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        from src.plugins.base import Diagnostic
        return FactEnvelope(
            plugin_name="ifc",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition -----------------------------------------------------------

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no valid signature)"
        return _summarize_callee(facts.function.name, facts.payload)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Instantiate each callee at its call sites with the caller's actual
        argument labels (the IFC composition operator). Records resolutions on
        the payload under `callee_resolutions`, matching ifc_main output."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        caller_raw = _raw_input_labels(caller_facts.payload)
        resolutions = []
        for rc in sorted(resolved_calls, key=lambda r: r.call_site.order_index):
            callee_facts = rc.callee_facts
            if callee_facts.status != "ok" or not callee_facts.payload:
                continue
            binding = {
                formal: _arg_label(expr, caller_raw)
                for formal, expr in rc.call_site.arg_bindings.items()
            }
            resolved = instantiate_callee(callee_facts.payload, binding)
            resolutions.append({
                "callee": rc.call_site.callee_name,
                "arg_binding": binding,
                "resolved_outputs": resolved,
            })
        if resolutions:
            caller_facts.payload = dict(caller_facts.payload)
            caller_facts.payload["_callee_resolutions"] = resolutions
        return caller_facts

    # -- checker ---------------------------------------------------------------

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="ifc", verdict="ERROR", status="error",
                           data={"error": "no valid flow signature (fail-closed)"})
        cls = classify(facts.payload, is_entrypoint=context.is_entrypoint)
        verdict = cls["verdict"]
        findings: List[Finding] = []
        gaps = None
        if verdict in ("LEAK", "DECLASSIFIED", "POLYMORPHIC"):
            gaps = render_gaps(cls, facts.payload)
            sev = {"LEAK": "high", "DECLASSIFIED": "low", "POLYMORPHIC": "info"}[verdict]
            findings.append(Finding(
                rule_id=f"ifc.{verdict.lower()}",
                title=f"IFC {verdict}",
                message=gaps.get("notes", "") if gaps else "",
                severity=sev,
                function=facts.function,
                data={"leaking_channel": gaps.get("leaking_channel") if gaps else None,
                      "high_sources": gaps.get("high_sources") if gaps else None},
            ))
        return Verdict(
            plugin_name="ifc",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"signature": facts.payload, "classification": cls, "gaps": gaps,
                  "callee_resolutions": (facts.payload or {}).get("_callee_resolutions")},
        )

    # -- legacy result serialization (ifc_eval.py / ifc_viewer.py compat) ------

    def render_result(self, unit, facts, verdict, context):
        """Emit the exact ifc_main.py per-function JSON so downstream tools
        (ifc_eval.py reads `verdict`; ifc_viewer.py reads `signature`/`gaps`/
        `callee_resolutions`) keep working unchanged."""
        if verdict.verdict == "ERROR":
            return {
                "function": unit.abs_path,
                "verdict": "ERROR",
                "gaps": None,
                "error": (facts.diagnostics[0].message if facts.diagnostics
                          else "no valid flow signature (fail-closed)"),
            }
        # Strip the internal composition key so `signature` matches the raw LLM
        # flow signature (resolutions are surfaced separately, as in ifc_main).
        sig = dict(facts.payload or {})
        resolutions = sig.pop("_callee_resolutions", None)
        return {
            "function": unit.abs_path,
            "verdict": verdict.verdict,
            "signature": sig,
            "callee_resolutions": resolutions or None,
            "gaps": verdict.data.get("gaps"),
        }

    def render_summary(self, results, counts):
        """Emit the exact ifc_main.py summary.json shape."""
        return {
            "total": len(results),
            "leaks": counts.get("LEAK", 0),
            "declassified": counts.get("DECLASSIFIED", 0),
            "polymorphic": counts.get("POLYMORPHIC", 0),
            "secure": counts.get("SECURE", 0),
            "errors": counts.get("ERROR", 0),
            "results": list(results),
        }
