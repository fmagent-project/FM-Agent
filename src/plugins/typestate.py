"""Typestate / temporal-protocol plugin: ordering-bug detection (TOCTOU, CSRF,
TLS-verify-before-use, resource lifecycle, auth-before-action).

The fifth plugin on the shared substrate. It uses BOTH composition directions
(Oracle's design):
  - BOTTOM-UP (like taint/crypto): a callee's exported events (e.g. it returns an
    open resource, or it performs a STATE_CHANGE on a request param) are spliced
    into the caller's ordered trace at the call site.
  - TOP-DOWN (like authz): a required event (CSRF_VALIDATE / AUTH_CHECK) may be
    performed by an ANCESTOR caller, so established contexts propagate from
    entrypoints down the call graph to discharge a callee's required-before-
    trigger obligation.

Unlike taint/crypto there is NO data-flow sink: the bug is an ORDERING property
checked by small built-in property automata.

Verdicts: VULNERABLE / POLYMORPHIC / NEEDS_REVIEW / SAFE / ERROR.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import TYPESTATE_MODEL
from src.typestate_prompts import _system_prompt, _user_prompt, _extract_typestate_json
from src.typestate_reasoner import (
    classify, summarize_facts, _combine_coverage, _ordered, _by_id,
    VULNERABLE, POLYMORPHIC, NEEDS_REVIEW, SAFE, ERROR,
)
from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    CallSite,
    Diagnostic,
    DriverContext,
    FactEnvelope,
    Finding,
    PluginMetadata,
    ResolvedCall,
    Verdict,
)


def _summarize_text(payload: dict, verdict: str, fn_name: str) -> str:
    """Concise callee summary for caller prompts."""
    if not payload:
        return f"{fn_name}: (no typestate facts)"
    s = summarize_facts(payload, verdict)
    parts = []
    for p in s.get("context_provides") or []:
        parts.append(f"provides {p['kind']}({p['resource']})")
    for r in s.get("context_requires") or []:
        parts.append(f"requires {r['kind']}({r['resource']})")
    for rr in s.get("return_resources") or []:
        parts.append(f"returns {rr['state']} resource")
    ev = s.get("exported_events") or []
    if ev:
        parts.append("events[" + ",".join(sorted({e["kind"] for e in ev})) + "]")
    return f"{fn_name}: " + ("; ".join(parts) if parts else "(no caller-visible effects)")


def _freeze(d: dict):
    return tuple(sorted((k, d.get(k)) for k in ("kind", "resource", "coverage")))


def _thaw(fr):
    return dict(fr) if not isinstance(fr, dict) else fr


class TypestatePlugin(AnalysisPlugin):
    """Typestate / temporal-protocol plugin (ordering bugs)."""

    model = TYPESTATE_MODEL
    SCHEMA = "typestate.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="typestate",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "java",
                                 "go", "c", "cpp", "ruby", "php"),
            verdicts=(VULNERABLE, POLYMORPHIC, NEEDS_REVIEW, SAFE, ERROR),
            requires_top_down_context=True,
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
        role_hint = "entrypoint" if request.context.is_entrypoint else "internal"
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(
                numbered, unit.signature_line, unit.id.language, callee_summaries, role_hint)},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        payload = _extract_typestate_json(raw_response)
        if payload is None:
            return None
        return FactEnvelope(
            plugin_name="typestate",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=payload,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="typestate",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up: splice callee exported events) ----------------

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no typestate facts)"
        verdict = (facts.payload.get("_verdict") or "")
        return _summarize_text(facts.payload, verdict, facts.function.name)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Splice each resolved callee's exported events into the caller's ordered
        trace at the CALL site, mapping the callee's formal-param resources to the
        caller's actual resources. This lets a callee that returns an open
        resource, or performs a STATE_CHANGE on a passed-in request, surface in
        the caller's automaton."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = dict(caller_facts.payload)
        calls = {c.get("event_id"): c for c in (payload.get("calls") or [])}
        callee_by_name = {}
        for rc in resolved_calls:
            cf = rc.callee_facts
            if cf.status == "ok" and cf.payload:
                callee_by_name[rc.call_site.callee_name] = cf.payload

        if not callee_by_name:
            return caller_facts

        events = _ordered(payload.get("events"))
        new_events = list(events)
        spliced = []
        for ev in events:
            if ev.get("kind") != "CALL":
                continue
            call = calls.get(ev.get("id"))
            callee_name = (call or {}).get("callee") or ev.get("callee")
            cpayload = callee_by_name.get(callee_name)
            if not cpayload:
                continue
            summary = summarize_facts(cpayload, cpayload.get("_verdict", ""))
            arg_map = (call or {}).get("arg_resources") or ev.get("arg_resources") or {}
            ret_res = (call or {}).get("return_resource") or ev.get("return_resource")
            base_order = ev.get("order", 0)
            for i, ce in enumerate(summary.get("exported_events") or [], 1):
                sym = ce.get("resource", "")
                mapped_res = sym
                if isinstance(sym, str) and sym.startswith("formal:"):
                    formal = sym[len("formal:"):]
                    mapped_res = arg_map.get(formal, sym)
                elif sym == "return" and ret_res:
                    mapped_res = ret_res
                new_events.append({
                    "id": f"{ev.get('id')}:{ce.get('id')}",
                    "order": base_order + i / 1000.0,
                    "kind": ce.get("kind"),
                    "resource": mapped_res,
                    "operation": ce.get("operation"),
                    "path_coverage": _combine_coverage(
                        ev.get("path_coverage", "may"), ce.get("path_coverage", "may")),
                    "predecessors_must": [], "control_depends_on": [],
                    "atomicity": ce.get("atomicity", "not_applicable"),
                    "tls_verify": ce.get("tls_verify", "not_applicable"),
                    "_via": callee_name,
                })
                spliced.append({"callee": callee_name, "kind": ce.get("kind"),
                                "resource": mapped_res})
        if spliced:
            payload["events"] = new_events
            payload["_spliced"] = spliced
            caller_facts.payload = payload
        return caller_facts

    # -- top-down context (csrf/auth required event may be in an ancestor) -----

    def initial_context(self, facts: FactEnvelope, context: DriverContext):
        """Seed contexts this entrypoint establishes for callees: ambient
        decorators (@csrf_protect, @login_required) and must CSRF/AUTH events."""
        if facts.status != "ok" or not facts.payload:
            return None
        out = []
        for a in facts.payload.get("ambient_contexts") or []:
            if a.get("coverage") == "must" and a.get("kind") in (
                    "csrf_validated", "auth_checked", "tls_verify_disabled"):
                out.append({"kind": a["kind"], "resource": "*", "coverage": "must"})
        s = summarize_facts(facts.payload, "")
        for p in s.get("context_provides") or []:
            out.append({"kind": p["kind"], "resource": "*", "coverage": "must"})
        return tuple(_freeze(c) for c in out) if out else None

    def propagate_context(
        self,
        caller_facts: FactEnvelope,
        callee_facts: FactEnvelope,
        call_site: CallSite,
        caller_context,
        context: DriverContext,
    ):
        """Pass the caller's established must-contexts down, plus any csrf/auth
        the caller establishes before THIS call site."""
        established = list(caller_context) if caller_context else []
        if caller_facts.status == "ok" and caller_facts.payload:
            ipayload = caller_facts.payload
            for a in ipayload.get("ambient_contexts") or []:
                if a.get("coverage") == "must" and a.get("kind") in (
                        "csrf_validated", "auth_checked", "tls_verify_disabled"):
                    established.append(_freeze({"kind": a["kind"], "resource": "*", "coverage": "must"}))
            # any must CSRF/AUTH event that precedes the call site
            call_order = None
            for c in ipayload.get("calls") or []:
                if c.get("callee") == call_site.callee_name:
                    # find the matching CALL event's order
                    for e in ipayload.get("events") or []:
                        if e.get("id") == c.get("event_id"):
                            call_order = e.get("order")
                            break
                    break
            for e in _ordered(ipayload.get("events")):
                if call_order is not None and e.get("order", 0) >= call_order:
                    break
                if e.get("path_coverage") == "must":
                    if e.get("kind") == "CSRF_VALIDATE":
                        established.append(_freeze({"kind": "csrf_validated", "resource": "*", "coverage": "must"}))
                    elif e.get("kind") == "AUTH_CHECK":
                        established.append(_freeze({"kind": "auth_checked", "resource": "*", "coverage": "must"}))
        merged = []
        seen = set()
        for fr in established:
            if fr not in seen:
                seen.add(fr)
                merged.append(fr)
        return tuple(merged) if merged else None

    # -- checker ---------------------------------------------------------------

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="typestate", verdict=ERROR, status="error",
                           data={"error": "no valid typestate abstraction (fail-closed)"})

        # Flatten propagated contexts (each entry is a tuple of frozen dicts).
        flat = []
        for entry in propagated_contexts or ():
            if isinstance(entry, tuple):
                for x in entry:
                    flat.append(_thaw(x))
            elif isinstance(entry, dict):
                flat.append(entry)

        result = classify(facts.payload, propagated_contexts=flat,
                          is_entrypoint=context.is_entrypoint)
        # stash verdict for caller summaries
        if facts.payload is not None:
            facts.payload["_verdict"] = result["verdict"]
        verdict = result["verdict"]
        findings: List[Finding] = []
        sev_map = {VULNERABLE: "high", POLYMORPHIC: "low", NEEDS_REVIEW: "info"}
        for f in result.get("findings", []):
            findings.append(Finding(
                rule_id=f"typestate.{f['kind'].lower()}",
                title=f["kind"],
                message=f.get("reason") or f["kind"],
                severity=sev_map.get(f["verdict"], "info"),
                function=facts.function,
                data={"verdict": f["verdict"], "cwe": f.get("cwe"), "rule": f.get("rule"),
                      "resource": f.get("resource"), "evidence": f.get("evidence")},
            ))
        return Verdict(
            plugin_name="typestate",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"signature": facts.payload, "result_findings": result.get("findings", [])},
        )
