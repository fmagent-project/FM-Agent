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
import ast
import copy
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from config import IFC_FLOW_SIGNATURE_MODEL
from src.ifc_prompts import _system_prompt, _user_prompt, _extract_flow_json
from src.ifc_validation import source_only_fallback, validate_and_enrich
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
from src.plugins import callgraph as _callgraph


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
        sink = (spec or {}).get("sink_channel", "unknown")
        visibility = (spec or {}).get("observability", "unknown")
        parts.append(f"{ch}[{sink},{visibility}]<-{{{','.join(deps)}}}")
    return f"{name}: " + ("; ".join(parts) if parts else "(no tracked outputs)")


def _source_rel_from_extracted(rel: str) -> str:
    """Map ``path/file-py/function.py`` back to ``path/file.py``."""
    path = Path(rel)
    if len(path.parts) < 2:
        return rel
    encoded = path.parent.name
    extension = path.suffix.lstrip(".")
    suffix = "-" + extension
    if not extension or not encoded.endswith(suffix):
        return rel
    return (path.parent.parent / (encoded[:-len(suffix)] + "." + extension)).as_posix()


def _called_names(source: str, language: str) -> Optional[set[str]]:
    if language.lower() != "python":
        return None
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return None
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def _directly_returns_call(source: str, language: str, callee_name: str) -> bool:
    if language.lower() != "python":
        return True
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Call):
            continue
        function = node.value.func
        name = function.id if isinstance(function, ast.Name) else (
            function.attr if isinstance(function, ast.Attribute) else ""
        )
        if name == callee_name:
            return True
    return False


def _is_python_method(source: str, language: str) -> bool:
    if language.lower() != "python":
        return False
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, TypeError, ValueError):
        return False
    function = next(
        (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )
    if function is None:
        return False
    args = [*function.args.posonlyargs, *function.args.args]
    return bool(args and args[0].arg in {"self", "cls"})


def _has_ambiguous_dispatch_caller(context: DriverContext) -> bool:
    callers = context.program.callers_by_callee.get(context.function.id, ())
    if not callers:
        return False
    for call in callers:
        candidates = [
            function_id for function_id in context.program.functions
            if _callgraph.base_name(function_id.name) == call.callee_name
        ]
        if len(candidates) <= 1:
            return False
    return True


def _order_bottom_up_all(units):
    """Bottom-up order keyed by FunctionId, preserving duplicate function names."""
    dependencies = {unit.id: set() for unit in units}
    by_id = {unit.id: unit for unit in units}
    for caller in units:
        for callee in units:
            if caller.id == callee.id:
                continue
            name = re.escape(_callgraph.base_name(callee.id.name))
            if re.search(rf"\b{name}\s*\(", caller.source):
                dependencies[caller.id].add(callee.id)

    ordered = []
    visited = set()
    active = set()

    def visit(function_id):
        if function_id in visited or function_id in active:
            return
        active.add(function_id)
        for dependency in dependencies.get(function_id, ()):
            visit(dependency)
        active.remove(function_id)
        visited.add(function_id)
        ordered.append(by_id[function_id])

    for unit in units:
        visit(unit.id)
    return ordered


_order_bottom_up_all._ifc_preserves_duplicates = True


class IfcPlugin(AnalysisPlugin):
    """Information-flow control plugin (confidentiality non-interference)."""

    model = IFC_FLOW_SIGNATURE_MODEL
    SCHEMA = "ifc.flow_signature.v2"

    @property
    def metadata(self) -> PluginMetadata:
        # The shared legacy sorter keys by bare function name and drops one of
        # two same-named functions in different files. IFC activates a scoped
        # FunctionId-keyed replacement before the driver loads/orders units.
        if not getattr(_callgraph.order_bottom_up, "_ifc_preserves_duplicates", False):
            _callgraph.order_bottom_up = _order_bottom_up_all
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
        signature = validate_and_enrich(signature, request.function.source)
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
        fallback = source_only_fallback(request.function.source)
        if fallback is not None:
            return FactEnvelope(
                plugin_name="ifc",
                schema_version=self.SCHEMA,
                function=request.function.id,
                status="ok",
                payload=fallback,
                confidence=0.5,
                diagnostics=[Diagnostic(
                    level="warning",
                    message=f"LLM abstraction failed; used source-settled IFC facts: {error}",
                )],
            )
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
        composed_outputs = dict(caller_facts.payload.get("outputs") or {})
        called_names = _called_names(context.function.source, context.function.id.language)
        candidate_counts = {}
        for rc in resolved_calls:
            candidate_counts[rc.call_site.callee_name] = (
                candidate_counts.get(rc.call_site.callee_name, 0) + 1
            )
        for candidate_index, rc in enumerate(sorted(
            resolved_calls, key=lambda r: r.call_site.order_index
        )):
            callee_name = rc.call_site.callee_name
            if called_names is not None and callee_name not in called_names:
                continue
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
            for channel, output in resolved.items():
                observability = output.get("observability")
                if observability == "internal":
                    continue
                if (
                    observability == "caller"
                    and output.get("sink_channel") == "return"
                    and not _directly_returns_call(
                        context.function.source,
                        context.function.id.language,
                        callee_name,
                    )
                ):
                    continue
                suffix = (
                    f":candidate-{candidate_index}"
                    if candidate_counts[callee_name] > 1 else ""
                )
                composed_outputs[f"callee:{callee_name}{suffix}:{channel}"] = {
                    "deps": [],
                    # Unknown candidate effects remain obligations rather than
                    # disappearing under ambiguous name-based resolution.
                    "const": LOW if output.get("label") == LOW else HIGH,
                    "declass": ([{"anchor": "callee", "reason": "callee declassification"}]
                                if output.get("declassified") else []),
                    "sink_channel": output.get("sink_channel", "unknown"),
                    "observability": observability or "caller",
                }
        if resolutions:
            caller_facts.payload = dict(caller_facts.payload)
            caller_facts.payload["outputs"] = composed_outputs
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
        validated = validate_and_enrich(
            facts.payload,
            context.function.source,
            allow_composed=bool(facts.payload.get("_callee_resolutions")),
        )
        if validated is None:
            return Verdict(plugin_name="ifc", verdict="ERROR", status="error",
                           data={"error": "invalid cached flow signature (fail-closed)"})
        facts.payload = validated
        is_entrypoint = context.is_entrypoint
        if _is_python_method(context.function.source, context.function.id.language):
            is_entrypoint = False
        classification_signature = facts.payload
        if _has_ambiguous_dispatch_caller(context):
            classification_signature = copy.deepcopy(facts.payload)
            for spec in classification_signature.get("outputs", {}).values():
                if (
                    spec.get("observability") == "caller"
                    and spec.get("sink_channel")
                    in {"exception_control", "exception_message"}
                ):
                    spec["observability"] = "external"
        cls = classify(classification_signature, is_entrypoint=is_entrypoint)
        verdict = cls["verdict"]
        findings: List[Finding] = []
        gaps = None
        if verdict in ("LEAK", "DECLASSIFIED", "POLYMORPHIC"):
            gaps = render_gaps(cls, facts.payload)
            sev = {"LEAK": "high", "DECLASSIFIED": "low", "POLYMORPHIC": "info"}[verdict]
            channels = (cls.get("violations") or cls.get("declassified_channels")
                        or cls.get("conditional_channels") or [{}])
            for channel in channels:
                findings.append(Finding(
                    rule_id=f"ifc.{verdict.lower()}",
                    title=f"IFC {verdict}",
                    message=gaps.get("notes", "") if gaps else "",
                    severity=sev,
                    function=facts.function,
                    data={"leaking_channel": channel.get("channel"),
                          "high_sources": gaps.get("high_sources") if gaps else None,
                          "cwe": channel.get("cwe")},
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
                "function": unit.id.name,
                "rel": _source_rel_from_extracted(unit.id.rel),
                "verdict": "ERROR",
                "status": "error",
                "findings": [],
                "gaps": None,
                "error": (facts.diagnostics[0].message if facts.diagnostics
                          else "no valid flow signature (fail-closed)"),
            }
        # Strip the internal composition key so `signature` matches the raw LLM
        # flow signature (resolutions are surfaced separately, as in ifc_main).
        sig = dict(facts.payload or {})
        resolutions = sig.pop("_callee_resolutions", None)
        return {
            "function": unit.id.name,
            "rel": _source_rel_from_extracted(unit.id.rel),
            "verdict": verdict.verdict,
            "status": verdict.status,
            "findings": [
                {"rule_id": finding.rule_id, "title": finding.title,
                 "message": finding.message, "severity": finding.severity,
                 "data": finding.data}
                for finding in verdict.findings
            ],
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
