"""Integrity-taint plugin: injection detection (SQLi/cmd/path/SSRF/XSS/deser/...).

The DUAL of the IFC plugin on the shared substrate:
  - abstraction  : taint_prompts (sources + typed sinks + typed sanitizers + flows)
  - checker      : taint_reasoner.classify (source->sink reachability, typed
                   sanitizer matching, 3-status lattice, verdict precedence)
  - composition  : BOTTOM-UP (like IFC, unlike authz). A callee's parametric sink
                   ("param:x reaches sql_query unsanitized") is instantiated at
                   the caller's call site with the caller's actual argument taint;
                   if the caller passes a tainted arg, the caller inherits the
                   finding. No top-down pass needed (Oracle: taint is discharged
                   at sink sites; unknown-param taint stays POLYMORPHIC until a
                   caller instantiates it).

Verdicts: VULNERABLE / SANITIZED / POLYMORPHIC / SAFE / ERROR.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import TAINT_MODEL
from src.taint_prompts import _system_prompt, _user_prompt, _extract_taint_json
from src.taint_reasoner import (
    classify, instantiate_sink, instantiate_flows,
    VULNERABLE, SANITIZED, POLYMORPHIC, SAFE, ERROR,
)
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    Diagnostic,
    DriverContext,
    FactEnvelope,
    Finding,
    PluginMetadata,
    ResolvedCall,
    Verdict,
)


def _summarize(payload: dict, fn_name: str) -> str:
    """Concise callee summary for caller prompts: which params reach which sinks."""
    if not payload:
        return f"{fn_name}: (no taint facts)"
    parts = []
    for k in payload.get("sinks") or []:
        srcs = ",".join((fl.get("source") or "?") for fl in (k.get("flows") or []))
        parts.append(f"{k.get('sink_kind')}({k.get('arg_context')})<-{{{srcs}}}")
    rets = payload.get("return_flows") or []
    if rets:
        rs = ",".join((fl.get("source") or "?")
                      for r in rets for fl in (r.get("flows") or []))
        if rs:
            parts.append(f"return<-{{{rs}}}")
    return f"{fn_name}: " + ("; ".join(parts) if parts else "(no sinks)")


def _match_call_site(caller_call_sites, callee_name):
    """Find the caller's LLM-recorded call_site facts for a callee (by name)."""
    for cs in caller_call_sites or []:
        c = (cs.get("callee") or "")
        if c == callee_name or c.endswith("." + callee_name) or c.split(".")[-1] == callee_name:
            return cs
    return None


class TaintPlugin(AnalysisPlugin):
    """Integrity-taint / injection plugin (dual of IFC)."""

    model = TAINT_MODEL
    SCHEMA = "taint.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="taint",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "go",
                                 "java", "php", "ruby", "c", "cpp"),
            verdicts=(VULNERABLE, POLYMORPHIC, SANITIZED, SAFE, ERROR),
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
            callee_summaries = "\n".join(request.callee_context.values())
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(
                numbered, unit.signature_line, unit.id.language, callee_summaries)},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        payload = _extract_taint_json(raw_response)
        if payload is None:
            return None
        return FactEnvelope(
            plugin_name="taint",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=payload,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="taint",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up: instantiate callee sinks at the call site) ----

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no taint facts)"
        return _summarize(facts.payload, facts.function.name)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Instantiate each callee's parametric sinks (and return flows) at the
        caller's call site, substituting the caller's actual-argument taint. A
        callee sink over `param:p` becomes a caller sink over whatever the caller
        passes as `p` — so a tainted argument makes the caller VULNERABLE."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = dict(caller_facts.payload)
        caller_call_sites = payload.get("call_sites") or []
        composed_sinks = list(payload.get("sinks") or [])
        composed_bindings = list(payload.get("taint_bindings") or [])
        added = []

        for rc in resolved_calls:
            cf = rc.callee_facts
            if cf.status != "ok" or not cf.payload:
                continue
            callee_name = rc.call_site.callee_name
            cs = _match_call_site(caller_call_sites, callee_name)
            if cs:
                call_id = cs.get("id") or callee_name
                param_to_actual = {
                    a.get("param_name"): (a.get("flows") or [])
                    for a in (cs.get("args") or []) if a.get("param_name")
                }
            else:
                # Fall back to the driver's regex arg bindings. We don't know the
                # actuals' taint, so fail closed: treat each as unknown-tainted.
                call_id = callee_name
                param_to_actual = {}
                for formal, actual_expr in (rc.call_site.arg_bindings or {}).items():
                    p = formal[len("param:"):] if formal.startswith("param:") else formal
                    param_to_actual[p] = [
                        {"source": f"unknown:{call_id}:{actual_expr}", "sanitizers": []}
                    ]

            for ksink in cf.payload.get("sinks") or []:
                inst = instantiate_sink(ksink, call_id, param_to_actual)
                composed_sinks.append(inst)
                added.append({"callee": callee_name, "sink_id": inst["id"],
                              "sink_kind": inst.get("sink_kind")})

            ret_expr = (cs or {}).get("return_expr")
            if ret_expr:
                for rf in cf.payload.get("return_flows") or []:
                    composed_bindings.append({
                        "expr": ret_expr,
                        "flows": instantiate_flows(rf.get("flows"), param_to_actual, call_id),
                    })

        payload["sinks"] = composed_sinks
        payload["taint_bindings"] = composed_bindings
        if added:
            payload["_composed_sinks"] = added
        caller_facts.payload = payload
        return caller_facts

    # -- checker ---------------------------------------------------------------

    def _seed_param_status(self, facts, context):
        """Optional top-down-free seeding: at an entrypoint, a parameter that the
        LLM itself classified as an untrusted source (untrusted_param) is TAINTED.
        Other params stay UNKNOWN_PARAM (=> POLYMORPHIC). Conservative, no global pass."""
        status = {}
        if not (facts.payload and context.is_entrypoint):
            return status
        for s in facts.payload.get("taint_sources") or []:
            if s.get("source_kind") == "untrusted_param":
                expr = (s.get("expr") or "").strip()
                if expr.isidentifier():
                    status[expr] = "TAINTED"
        return status

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="taint", verdict=ERROR, status="error",
                           data={"error": "no valid taint abstraction (fail-closed)"})

        param_status = self._seed_param_status(facts, context)
        result = classify(facts.payload, param_status=param_status)
        verdict = result["verdict"]
        findings: List[Finding] = []
        for f in result.get("findings", []):
            if f["status"] == SANITIZED:
                sev = "info"
            elif f["status"] == POLYMORPHIC:
                sev = "low"
            else:
                sev = "high"
            findings.append(Finding(
                rule_id=f"taint.{f['kind'].lower()}",
                title=f["kind"],
                message=f.get("message", ""),
                severity=sev,
                function=facts.function,
                data={"status": f["status"], "cwe": f.get("cwe"),
                      "sink_kind": f.get("sink_kind"), "arg_context": f.get("arg_context"),
                      "source": f.get("source"), "sanitized_by": f.get("sanitized_by"),
                      "evidence": f.get("evidence")},
            ))
        return Verdict(
            plugin_name="taint",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"signature": facts.payload, "result_findings": result.get("findings", [])},
        )
