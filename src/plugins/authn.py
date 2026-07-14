"""Authentication-integrity plugin: improper-authentication detection (missing/
weak authentication, asserted identity, session fixation, insufficient session
expiration).

A SIBLING of the authz plugin on the shared substrate (guarded-Hoare theory),
asking the PRIOR question to access control: authz checks "may THIS subject act
on THIS resource"; authn checks "was the subject's identity actually VERIFIED".
  - abstraction  : authn_prompts (protected ops + auth events + session events + obligations)
  - checker      : authn_reasoner.classify (event-domination + auth-strength + session-hygiene)
  - composition  : callee obligations surface to callers via the prompt summary;
                   deterministic discharge happens TOP-DOWN (a genuine dominating
                   authentication established by an ancestor discharges a callee's
                   obligation).
  - top-down     : requires_top_down_context=True, mirroring authz.

Verdicts: VULNERABLE / NEEDS_REVIEW / SAFE / ERROR (reuses authz's verdict CSS in
the viewer).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import AUTHN_MODEL
from src.authn_prompts import _system_prompt, _user_prompt, _extract_authn_json
from src.authn_reasoner import (
    classify, establishes_to_contexts,
    VULNERABLE, SAFE, NEEDS_REVIEW, ERROR,
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
    Verdict,
)


def _summarize(abstraction: dict, fn_name: str) -> str:
    """Concise callee summary for caller prompts: what authentication it REQUIRES."""
    if not abstraction:
        return f"{fn_name}: (no authentication facts)"
    obligations = abstraction.get("obligations") or []
    ops = abstraction.get("protected_operations") or []
    parts = []
    if obligations:
        reqs = "; ".join(o.get("requires_nl", "") for o in obligations if o.get("requires_nl"))
        if reqs:
            parts.append(f"REQUIRES[{reqs}]")
    if ops:
        kinds = ",".join(sorted({o.get("kind", "op") for o in ops}))
        parts.append(f"protected_ops[{kinds}]")
    return f"{fn_name}: " + ("; ".join(parts) if parts else "(no protected operations)")


class AuthnPlugin(AnalysisPlugin):
    """Authentication-integrity plugin (guarded-Hoare; sibling of authz)."""

    model = AUTHN_MODEL
    SCHEMA = "authn.guarded_hoare.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="authn",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "go",
                                 "java", "c", "cpp", "rust", "arkts"),
            verdicts=(VULNERABLE, SAFE, NEEDS_REVIEW, ERROR),
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
        return [
            {"role": "system", "content": _system_prompt(unit.id.language)},
            {"role": "user", "content": _user_prompt(
                numbered, unit.signature_line, unit.id.language,
                callee_summaries, request.context.is_entrypoint)},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        abstraction = _extract_authn_json(raw_response)
        if abstraction is None:
            return None
        return FactEnvelope(
            plugin_name="authn",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=abstraction,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="authn",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up summary only; discharge is top-down) ----------

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no authentication facts)"
        return _summarize(facts.payload, facts.function.name)

    # compose_calls: default no-op. Authentication discharge is not a bottom-up
    # value computation — an ancestor caller may establish the genuine auth — so
    # it is resolved in the top-down context worklist, not here.

    # -- top-down auth-context propagation ------------------------------------

    def initial_context(self, facts: FactEnvelope, context: DriverContext):
        """At an entrypoint, seed the contexts this function establishes for its
        callees (genuine, dominating authentication events)."""
        if facts.status != "ok" or not facts.payload:
            return None
        ctxs = establishes_to_contexts(facts.payload)
        return tuple(_freeze(c) for c in ctxs) if ctxs else None

    def propagate_context(
        self,
        caller_facts: FactEnvelope,
        callee_facts: FactEnvelope,
        call_site: CallSite,
        caller_context,
        context: DriverContext,
    ):
        """Pass the caller's established auth contexts down to the callee,
        augmented by any genuine authentication the caller establishes."""
        established = []
        if caller_facts.status == "ok" and caller_facts.payload:
            established = [_freeze(c) for c in establishes_to_contexts(caller_facts.payload)]
        incoming = list(caller_context) if caller_context else []
        merged = tuple(dict_from_frozen(x) for x in (incoming + established))
        return tuple(_freeze(c) for c in merged) if merged else None

    def merge_contexts(self, old, new):
        """Join top-down contexts as a SINGLE unioned atom-set.

        The verdict only depends on the UNION of distinct auth-context atoms
        reaching a function (check() flattens+unions them). The base default
        dedups whole path-tuples by repr, so on a dense graph a node accumulates
        combinatorially many distinct ordered tuples and the worklist never
        reaches a fixpoint (a 9.5h hang was observed for the sibling authz
        plugin at 272 entrypoints). Collapsing to one set of atoms bounds each
        node by the finite universe of auth atoms, so the fixpoint is reached
        quickly — and is verdict-identical.
        """
        atoms = set()
        for entry in list(old) + list(new):
            for atom in entry:  # entry is a tuple of frozen atom-tuples
                atoms.add(atom)
        # Sort by repr: atom values may be None, so a direct sort would raise
        # TypeError comparing None to str. repr is deterministic + None-safe.
        return [tuple(sorted(atoms, key=repr))] if atoms else []

    # -- checker ---------------------------------------------------------------

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="authn", verdict=ERROR, status="error",
                           data={"error": "no valid authentication abstraction (fail-closed)"})

        # Flatten propagated contexts (each entry is a tuple of frozen dicts).
        flat_ctx = []
        for entry in propagated_contexts or ():
            if isinstance(entry, tuple):
                flat_ctx.extend(dict_from_frozen(x) for x in entry)
            elif isinstance(entry, dict):
                flat_ctx.append(entry)

        result = classify(facts.payload,
                          is_entrypoint=context.is_entrypoint,
                          propagated_contexts=flat_ctx)
        verdict = result["verdict"]
        findings: List[Finding] = []
        for f in result.get("findings", []):
            op = f.get("op", {})
            findings.append(Finding(
                rule_id=f"authn.{f['kind'].lower()}",
                title=f["kind"],
                message=f.get("message", ""),
                severity="high" if verdict == VULNERABLE else "info",
                function=facts.function,
                data={"op": op, "kind": f["kind"]},
            ))
        return Verdict(
            plugin_name="authn",
            verdict=verdict,
            status="ok",
            findings=findings,
            data={"abstraction": facts.payload, "result": _strip_ops(result)},
        )


# --- helpers: freeze context dicts so merge_contexts can dedup by repr --------

def _freeze(d: dict):
    return tuple(sorted((k, d.get(k)) for k in ("authenticated", "strength", "method")))


def dict_from_frozen(fr):
    if isinstance(fr, dict):
        return fr
    return dict(fr)


def _strip_ops(result: dict) -> dict:
    """Lighten the result for the data field (drop nested op echoes)."""
    return {"verdict": result.get("verdict"),
            "num_findings": len(result.get("findings", [])),
            "needs_review": (result.get("local") or {}).get("needs_review", False)}
