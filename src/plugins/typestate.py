"""Typestate plugin adapter for temporal-protocol analysis."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import TYPESTATE_MODEL
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
from src.typestate_prompts import _extract_typestate_json, _system_prompt, _user_prompt
from src.typestate_reasoner import (
    ERROR,
    NEEDS_REVIEW,
    POLYMORPHIC,
    SAFE,
    VULNERABLE,
    _combine_coverage,
    _ordered,
    classify,
    summarize_facts,
)
from src.typestate_validation import (
    source_only_facts,
    source_rel_from_extracted,
    validate_and_enrich,
)


_AMBIENT_KINDS = {"csrf_validated", "auth_checked", "tls_verify_disabled"}


def _freeze(value):
    return tuple(sorted((key, value.get(key)) for key in ("kind", "resource", "coverage")))


def _thaw(value):
    return dict(value) if not isinstance(value, dict) else value


def _summary_text(payload, verdict, name):
    if not payload:
        return f"{name}: (no typestate facts)"
    summary = summarize_facts(payload, verdict)
    parts = [
        *(f"provides {item['kind']}({item['resource']})" for item in summary.get("context_provides") or []),
        *(f"requires {item['kind']}({item['resource']})" for item in summary.get("context_requires") or []),
        *(f"returns {item['state']} resource" for item in summary.get("return_resources") or []),
    ]
    events = summary.get("exported_events") or []
    if events:
        parts.append("events[" + ",".join(sorted({event["kind"] for event in events})) + "]")
    return f"{name}: " + ("; ".join(parts) if parts else "(no caller-visible effects)")


def _ambient_contexts(payload):
    return [
        _freeze({"kind": item["kind"], "resource": "*", "coverage": "must"})
        for item in payload.get("ambient_contexts") or []
        if item.get("coverage") == "must" and item.get("kind") in _AMBIENT_KINDS
    ]


class TypestatePlugin(AnalysisPlugin):
    model = TYPESTATE_MODEL
    SCHEMA = "typestate.v1"

    @property
    def metadata(self):
        return PluginMetadata(
            name="typestate",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "java", "go", "c", "cpp", "ruby", "php"),
            verdicts=(VULNERABLE, POLYMORPHIC, NEEDS_REVIEW, SAFE, ERROR),
            requires_top_down_context=True,
            needs_entrypoint=True,
        )

    def build_abstraction_prompt(self, request: AbstractionRequest) -> List[Dict[str, str]]:
        unit = request.function
        numbered = "\n".join(f"Line {index + 1}: {line}" for index, line in enumerate(unit.source.splitlines()))
        callees = "\n".join(request.callee_context.values()) if request.callee_context else None
        role = "entrypoint" if request.context.is_entrypoint else "internal"
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(numbered, unit.signature_line, unit.id.language, callees, role)},
        ]

    def parse_abstraction_response(self, request, raw_response) -> Optional[FactEnvelope]:
        payload = validate_and_enrich(_extract_typestate_json(raw_response), request.function)
        if payload is None:
            return None
        return FactEnvelope("typestate", self.SCHEMA, request.function.id, "ok", payload)

    def make_error_facts(self, request, error):
        return FactEnvelope(
            "typestate",
            self.SCHEMA,
            request.function.id,
            "error",
            None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    def summarize_for_caller(self, facts):
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no typestate facts)"
        return _summary_text(facts.payload, facts.payload.get("_verdict", ""), facts.function.name)

    def compose_calls(self, caller_facts, resolved_calls: Sequence[ResolvedCall], context):
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = dict(caller_facts.payload)
        calls = {call.get("event_id"): call for call in payload.get("calls") or []}
        callees = {
            resolved.call_site.callee_name: resolved.callee_facts.payload
            for resolved in resolved_calls
            if resolved.callee_facts.status == "ok" and resolved.callee_facts.payload
        }
        if not callees:
            return caller_facts
        events = _ordered(payload.get("events"))
        new_events, spliced = list(events), []
        for event in events:
            if event.get("kind") != "CALL":
                continue
            call = calls.get(event.get("id")) or {}
            callee_name = call.get("callee") or event.get("callee")
            callee = callees.get(callee_name)
            if not callee:
                continue
            summary = summarize_facts(callee, callee.get("_verdict", ""))
            arguments = call.get("arg_resources") or event.get("arg_resources") or {}
            returned = call.get("return_resource") or event.get("return_resource")
            for index, exported in enumerate(summary.get("exported_events") or [], 1):
                resource = exported.get("resource", "")
                if isinstance(resource, str) and resource.startswith("formal:"):
                    resource = arguments.get(resource[len("formal:"):], resource)
                elif resource == "return" and returned:
                    resource = returned
                new_events.append({
                    "id": f"{event.get('id')}:{exported.get('id')}",
                    "order": event.get("order", 0) + index / 1000.0,
                    "kind": exported.get("kind"),
                    "resource": resource,
                    "operation": exported.get("operation"),
                    "path_coverage": _combine_coverage(event.get("path_coverage", "may"), exported.get("path_coverage", "may")),
                    "predecessors_must": [],
                    "control_depends_on": [],
                    "atomicity": exported.get("atomicity", "not_applicable"),
                    "tls_verify": exported.get("tls_verify", "not_applicable"),
                    "_via": callee_name,
                })
                spliced.append({"callee": callee_name, "kind": exported.get("kind"), "resource": resource})
        if spliced:
            payload.update(events=new_events, _spliced=spliced)
            caller_facts.payload = payload
        return caller_facts

    def initial_context(self, facts, context):
        if facts.status != "ok" or not facts.payload:
            return None
        established = _ambient_contexts(facts.payload)
        for item in summarize_facts(facts.payload, "").get("context_provides") or []:
            established.append(_freeze({"kind": item["kind"], "resource": "*", "coverage": "must"}))
        return tuple(established) if established else None

    def propagate_context(self, caller_facts, callee_facts, call_site: CallSite, caller_context, context):
        established = list(caller_context) if caller_context else []
        if caller_facts.status == "ok" and caller_facts.payload:
            payload = caller_facts.payload
            established.extend(_ambient_contexts(payload))
            event_id = next((call.get("event_id") for call in payload.get("calls") or [] if call.get("callee") == call_site.callee_name), None)
            call_order = next((event.get("order") for event in payload.get("events") or [] if event.get("id") == event_id), None)
            kinds = {"CSRF_VALIDATE": "csrf_validated", "AUTH_CHECK": "auth_checked"}
            for event in _ordered(payload.get("events")):
                if call_order is not None and event.get("order", 0) >= call_order:
                    break
                if event.get("path_coverage") == "must" and event.get("kind") in kinds:
                    established.append(_freeze({"kind": kinds[event["kind"]], "resource": "*", "coverage": "must"}))
        unique = list(dict.fromkeys(established))
        return tuple(unique) if unique else None

    def merge_contexts(self, old, new):
        atoms = {atom for entry in list(old) + list(new) for atom in entry}
        return [tuple(sorted(atoms, key=repr))] if atoms else []

    def check(self, facts, context: DriverContext, propagated_contexts: Sequence = ()):
        if facts.status == "error" or not facts.payload:
            derived = source_only_facts(context.function)
            if derived is None:
                return Verdict("typestate", ERROR, status="error", data={"error": "no valid typestate abstraction (fail-closed)"})
            facts.payload = derived
            facts.status = "partial"
        facts.payload = validate_and_enrich(facts.payload, context.function)
        if facts.payload is None:
            return Verdict("typestate", ERROR, status="error", data={"error": "invalid typestate abstraction (fail-closed)"})
        propagated = [
            _thaw(item)
            for entry in propagated_contexts or ()
            for item in (entry if isinstance(entry, tuple) else (entry,))
            if isinstance(item, (tuple, dict))
        ]
        result = classify(facts.payload, propagated_contexts=propagated, is_entrypoint=context.is_entrypoint)
        facts.payload["_verdict"] = result["verdict"]
        severities = {VULNERABLE: "high", POLYMORPHIC: "low", NEEDS_REVIEW: "info"}
        findings = [Finding(
            rule_id=f"typestate.{finding['kind'].lower()}",
            title=finding["kind"],
            message=finding.get("reason") or finding["kind"],
            severity=severities.get(finding["verdict"], "info"),
            function=facts.function,
            data={key: finding.get(key) for key in ("verdict", "cwe", "rule", "resource", "evidence")},
        ) for finding in result.get("findings", [])]
        return Verdict("typestate", result["verdict"], findings=findings, data={"signature": facts.payload, "result_findings": result.get("findings", [])})

    def render_result(self, unit, facts, verdict, context):
        result = super().render_result(unit, facts, verdict, context)
        result["rel"] = source_rel_from_extracted(unit.id.rel)
        result["function"] = unit.id.name
        return result
