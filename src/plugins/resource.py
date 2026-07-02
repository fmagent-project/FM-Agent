"""Resource-exhaustion plugin: denial-of-service detection (unbounded allocation/
read, decompression bombs, ReDoS, uncontrolled recursion/loops).

A SIBLING of the taint plugin on the shared substrate:
  - abstraction  : resource_prompts (magnitude sources + costly ops + typed bounds)
  - checker      : resource_reasoner.classify (magnitude->op reachability, typed
                   dominating-bound matching, 3-status lattice, verdict precedence)
  - composition  : BOTTOM-UP (like taint). A callee's parametric costly op
                   ("param:n drives allocation, unbounded") is instantiated at the
                   caller's call site with the caller's actual argument magnitude;
                   if the caller passes an attacker-controlled magnitude, the
                   caller inherits the finding. No top-down pass needed (a bound is
                   discharged at the op site; unknown-param magnitude stays
                   POLYMORPHIC until a caller instantiates it).

Verdicts: VULNERABLE / BOUNDED / POLYMORPHIC / SAFE / ERROR.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import RESOURCE_MODEL
from src.resource_prompts import _system_prompt, _user_prompt, _extract_resource_json
from src.resource_reasoner import (
    classify, instantiate_op,
    VULNERABLE, BOUNDED, POLYMORPHIC, SAFE, ERROR,
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
    """Concise callee summary for caller prompts: which params drive which costly
    ops, and whether they look bounded."""
    if not payload:
        return f"{fn_name}: (no resource facts)"
    parts = []
    for op in payload.get("costly_ops") or []:
        mags = ",".join((m.get("source") or "?") for m in (op.get("magnitudes") or []))
        parts.append(f"{op.get('op_kind')}<-{{{mags}}}")
    return f"{fn_name}: " + ("; ".join(parts) if parts else "(no costly ops)")


def _match_call_site(caller_call_sites, callee_name):
    """Find the caller's LLM-recorded call_site facts for a callee (by name)."""
    for cs in caller_call_sites or []:
        c = (cs.get("callee") or "")
        if c == callee_name or c.endswith("." + callee_name) or c.split(".")[-1] == callee_name:
            return cs
    return None


class ResourcePlugin(AnalysisPlugin):
    """Resource-exhaustion / DoS plugin (sibling of taint)."""

    model = RESOURCE_MODEL
    SCHEMA = "resource.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="resource",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "go",
                                 "java", "php", "ruby", "c", "cpp"),
            verdicts=(VULNERABLE, POLYMORPHIC, BOUNDED, SAFE, ERROR),
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
        payload = _extract_resource_json(raw_response)
        if payload is None:
            return None
        return FactEnvelope(
            plugin_name="resource",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=payload,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="resource",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up: instantiate callee costly ops at the call site) -

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no resource facts)"
        return _summarize(facts.payload, facts.function.name)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Instantiate each callee's parametric costly ops at the caller's call
        site, substituting the caller's actual-argument magnitude. A callee op
        over `param:p` becomes a caller op over whatever the caller passes as `p`
        — so an attacker-controlled argument makes the caller VULNERABLE."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = dict(caller_facts.payload)
        caller_call_sites = payload.get("call_sites") or []
        composed_ops = list(payload.get("costly_ops") or [])
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
                    a.get("param_name"): (a.get("magnitudes") or [])
                    for a in (cs.get("args") or []) if a.get("param_name")
                }
            else:
                # Fall back to the driver's regex arg bindings. We don't know the
                # actuals' magnitude, so fail closed: treat each as unknown-attacker.
                call_id = callee_name
                param_to_actual = {}
                for formal, actual_expr in (rc.call_site.arg_bindings or {}).items():
                    p = formal[len("param:"):] if formal.startswith("param:") else formal
                    param_to_actual[p] = [
                        {"source": f"unknown:{call_id}:{actual_expr}", "bounds": []}
                    ]

            for callee_op in cf.payload.get("costly_ops") or []:
                inst = instantiate_op(callee_op, call_id, param_to_actual)
                composed_ops.append(inst)
                added.append({"callee": callee_name, "op_id": inst["id"],
                              "op_kind": inst.get("op_kind")})

        payload["costly_ops"] = composed_ops
        if added:
            payload["_composed_ops"] = added
        caller_facts.payload = payload
        return caller_facts

    # -- checker ---------------------------------------------------------------

    def _seed_param_status(self, facts, context):
        """Optional top-down-free seeding: at an entrypoint, a parameter the LLM
        itself classified as an attacker-controllable magnitude is ATTACKER. Other
        params stay UNKNOWN_PARAM (=> POLYMORPHIC). Conservative, no global pass."""
        status = {}
        if not (facts.payload and context.is_entrypoint):
            return status
        for m in facts.payload.get("magnitude_sources") or []:
            expr = (m.get("expr") or "").strip()
            if expr.isidentifier():
                status[expr] = "ATTACKER"
        return status

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="resource", verdict=ERROR, status="error",
                           data={"error": "no valid resource abstraction (fail-closed)"})

        param_status = self._seed_param_status(facts, context)
        result = classify(facts.payload, param_status=param_status)
        verdict = result["verdict"]
        findings: List[Finding] = []
        for f in result.get("findings", []):
            if f["status"] == BOUNDED:
                sev = "info"
            elif f["status"] == POLYMORPHIC:
                sev = "low"
            else:
                sev = "high"
            findings.append(Finding(
                rule_id=f"resource.{f['kind'].lower()}",
                title=f["kind"],
                message=f.get("message", ""),
                severity=sev,
                function=facts.function,
                data={"status": f["status"], "cwe": f.get("cwe"),
                      "op_kind": f.get("op_kind"), "op_id": f.get("op_id"),
                      "source": f.get("source"), "bounded_by": f.get("bounded_by"),
                      "evidence": f.get("evidence")},
            ))
        return Verdict(
            plugin_name="resource",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"signature": facts.payload, "result_findings": result.get("findings", [])},
        )
