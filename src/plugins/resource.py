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

import ast
import re
from typing import Dict, List, Optional, Sequence

from config import RESOURCE_MODEL
from src.resource_prompts import _system_prompt, _user_prompt, _extract_resource_json
from src.resource_reasoner import (
    classify, instantiate_op,
    VULNERABLE, BOUNDED, POLYMORPHIC, SAFE, ERROR,
)
from src.resource_validation import (
    RESOURCE_VALIDATION_VERSION,
    accepted_bound,
    bounds_by_id,
    iteration_magnitudes_for_call,
    rejecting_guard_for_call,
    returned_parameter_bounds,
    source_digest,
    source_operation_line,
    source_rel_from_extracted,
    validate_and_enrich,
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


def _match_call_site(caller_call_sites, callee_name, occurrence=0):
    """Find the caller's LLM-recorded call_site facts for a callee (by name)."""
    matched = []
    for cs in caller_call_sites or []:
        c = (cs.get("callee") or "")
        if c == callee_name or c.endswith("." + callee_name) or c.split(".")[-1] == callee_name:
            matched.append(cs)
    return matched[occurrence] if occurrence < len(matched) else None


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
        if payload is None or not isinstance(payload, dict):
            return None
        payload = {
            key: value for key, value in payload.items()
            if not str(key).startswith("_")
        }
        costly_ops = payload.get("costly_ops")
        if isinstance(costly_ops, list):
            payload = dict(payload)
            payload["costly_ops"] = [
                {key: value for key, value in op.items() if not key.startswith("_")}
                if isinstance(op, dict) else op
                for op in costly_ops
            ]
        payload = validate_and_enrich(payload, request.function)
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
        payload = validate_and_enrich(caller_facts.payload, context.function)
        caller_call_sites = payload.get("call_sites") or []
        composed_ops = list(payload.get("costly_ops") or [])
        composed_bounds = list(payload.get("bounds") or [])
        added = []
        callee_occurrences = {}

        for rc in resolved_calls:
            cf = rc.callee_facts
            if cf.status != "ok" or not cf.payload:
                continue
            callee_name = rc.call_site.callee_name
            callee_unit = context.program.functions.get(cf.function)
            if callee_unit is not None:
                cf.payload = validate_and_enrich(cf.payload, callee_unit)
            composed_ops = [op for op in composed_ops if not _op_calls(op, callee_name)]
            if cf.payload.get("_resource_cached") is True:
                continue
            if payload.get("_resource_exact_extents") is True and any(
                word in callee_name.lower() for word in ("allocate", "reserve")
            ):
                continue
            occurrence = callee_occurrences.get(callee_name, 0)
            callee_occurrences[callee_name] = occurrence + 1
            cs = _match_call_site(caller_call_sites, callee_name, occurrence)
            iteration_magnitudes = iteration_magnitudes_for_call(
                payload, context.function.source, callee_name, occurrence
            )
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
                    try:
                        ast.literal_eval(actual_expr)
                    except (SyntaxError, ValueError):
                        param_to_actual[p] = [
                            {"source": f"unknown:{call_id}:{actual_expr}", "bounds": []}
                        ]
                    else:
                        param_to_actual[p] = []

            guard = rejecting_guard_for_call(
                context.function.source, callee_name, occurrence
            )
            if guard and cs and callee_unit is not None:
                _propagate_validated_argument_bounds(
                    composed_ops,
                    composed_bounds,
                    cf.payload,
                    callee_unit.source,
                    cs,
                    guard,
                    call_id,
                    context.function.source,
                    payload,
                )

            bound_id_map = {}
            for bound in cf.payload.get("bounds") or []:
                if not isinstance(bound, dict) or not isinstance(bound.get("id"), str):
                    continue
                old_id = bound["id"]
                new_id = f"{call_id}::{old_id}"
                bound_id_map[old_id] = new_id
                reanchored = dict(bound)
                reanchored["id"] = new_id
                protected = bound.get("protects_op_ids")
                if isinstance(protected, list):
                    reanchored["protects_op_ids"] = [
                        f"{call_id}::{op_id}" for op_id in protected
                        if isinstance(op_id, str)
                    ]
                composed_bounds.append(reanchored)

            for callee_op in cf.payload.get("costly_ops") or []:
                inst = instantiate_op(callee_op, call_id, param_to_actual, bound_id_map)
                existing_sources = {
                    magnitude.get("source") for magnitude in inst.get("magnitudes") or []
                    if isinstance(magnitude, dict)
                }
                inst.setdefault("magnitudes", []).extend(
                    magnitude for magnitude in iteration_magnitudes
                    if magnitude["source"] not in existing_sources
                )
                composed_ops.append(inst)
                added.append({"callee": callee_name, "op_id": inst["id"],
                              "op_kind": inst.get("op_kind")})

        payload["costly_ops"] = composed_ops
        payload["bounds"] = composed_bounds
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
        if not facts.payload:
            return status
        params = {str(param) for param in (facts.payload.get("params") or [])}
        for m in facts.payload.get("magnitude_sources") or []:
            expr = (m.get("expr") or "").strip()
            for param in params:
                if expr == param or re.search(rf"\b{re.escape(param)}\b", expr):
                    status[param] = "ATTACKER"
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

        if (
            facts.payload.get("_resource_validated") != RESOURCE_VALIDATION_VERSION
            or facts.payload.get("_resource_source_digest")
            != source_digest(context.function)
        ):
            facts.payload = validate_and_enrich(facts.payload, context.function)
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

    def render_result(self, unit, facts, verdict, context):
        result = super().render_result(unit, facts, verdict, context)
        result["rel"] = source_rel_from_extracted(unit.id.rel)
        result["function"] = unit.id.name
        return result


def _op_calls(op, callee_name):
    if not isinstance(op, dict):
        return False
    callee = str(op.get("callee") or "")
    expression = str(op.get("call_expr") or "")
    bare = callee_name.split(".")[-1]
    return callee == callee_name or callee.endswith("." + bare) or bare + "(" in expression


def _propagate_validated_argument_bounds(
    caller_ops, caller_bounds, callee_payload, callee_source, call_site, guard,
    call_id, caller_source, caller_payload,
):
    bounded = _bounded_parameters(callee_payload)
    established = returned_parameter_bounds(callee_source, bounded)
    guarded_args = set(guard.get("args") or [])
    for argument in call_site.get("args") or []:
        if not isinstance(argument, dict):
            continue
        parameter = argument.get("param_name")
        actual = str(argument.get("expr") or "").strip()
        proof = bounded.get(parameter)
        if proof is None or parameter not in established or actual not in guarded_args:
            continue
        kind, callee_bound = proof
        _refine_validated_source_kind(caller_payload, actual, kind)
        operation_occurrences = {}
        for op in caller_ops:
            if not isinstance(op, dict) or str(op.get("arg_expr") or "").strip() != actual:
                continue
            occurrence_key = str(op.get("call_expr") or "")
            occurrence = operation_occurrences.get(occurrence_key, 0)
            operation_occurrences[occurrence_key] = occurrence + 1
            line = source_operation_line(
                caller_source, op.get("call_expr"), occurrence
            )
            if line is None or line <= guard.get("line", 0):
                continue
            bound_id = f"{call_id}::guard::{parameter}::{op.get('id', 'OP')}"
            if any(
                isinstance(bound, dict) and bound.get("id") == bound_id
                for bound in caller_bounds
            ):
                continue
            caller_bounds.append({
                "id": bound_id,
                "bound_kind": callee_bound.get("bound_kind"),
                "expr": guard.get("expr"),
                "caps": [kind],
                "protects_op_ids": [op.get("id")],
                "placement": "before",
                "enforcement": "reject",
                "limit_origin": callee_bound.get("limit_origin", "constant"),
                "dominates": True,
                "confidence": "high",
            })
            for flow in op.get("magnitudes") or []:
                if isinstance(flow, dict):
                    flow["magnitude_kind"] = kind
                    flow.setdefault("bounds", []).append(bound_id)


def _refine_validated_source_kind(payload, expression, kind):
    candidate = expression.strip()
    for source in payload.get("magnitude_sources") or []:
        if not isinstance(source, dict):
            continue
        raw = str(source.get("expr") or "").strip()
        try:
            parsed = ast.parse(raw, mode="eval").body
        except (SyntaxError, TypeError, ValueError):
            continue
        if raw == candidate or (
            candidate.isidentifier()
            and any(
                isinstance(node, ast.Name) and node.id == candidate
                for node in ast.walk(parsed)
            )
        ):
            source["magnitude_kind"] = kind


def _bounded_parameters(payload):
    indexed = bounds_by_id(payload)
    bounded = {}
    for op in payload.get("costly_ops") or []:
        if not isinstance(op, dict):
            continue
        for magnitude in op.get("magnitudes") or []:
            if not isinstance(magnitude, dict):
                continue
            source = magnitude.get("source")
            kind = magnitude.get("magnitude_kind")
            if not isinstance(source, str) or not source.startswith("param:") or not kind:
                continue
            bound = accepted_bound(magnitude, op, kind, indexed)
            if bound is not None:
                bounded[source[len("param:"):]] = (kind, bound)
    return bounded
