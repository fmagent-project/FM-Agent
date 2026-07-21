"""Crypto-misuse plugin: cryptographic API misuse detection (CrySL-flavored).

The fourth plugin on the shared substrate. Like taint, it is BOTTOM-UP (no
top-down pass): most crypto facts are local to the operation, and the only
interprocedural case is material provenance flowing through a helper's return
(e.g. a make_key() helper that returns a hardcoded key, used by a caller's
cipher). compose_calls resolves a callee's return-provenance into the caller's
key/iv material so the caller becomes VULNERABLE.

Unlike taint there is NO source->sink flow: the crypto OPERATION itself is the
locus, and verify-before-trust is an ordering/typestate check.

Verdicts: VULNERABLE / WEAK / POLYMORPHIC / NEEDS_REVIEW / SAFE / ERROR.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from config import CRYPTO_MODEL
from src.crypto_prompts import _system_prompt, _user_prompt, _extract_crypto_json
from src.crypto_reasoner import (
    classify, instantiate_return_material,
    VULNERABLE, WEAK, POLYMORPHIC, NEEDS_REVIEW, SAFE, ERROR,
)
from src.crypto_validation import (
    source_only_facts,
    source_provenance_context,
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
    """Concise callee summary for caller prompts: returned crypto material +
    headline operations (so a caller knows a helper's return provenance)."""
    if not payload:
        return f"{fn_name}: (no crypto facts)"
    parts = []
    for ret in payload.get("returns") or []:
        mk = ret.get("material_kind")
        if mk in {"key", "iv_nonce", "random_token"}:
            parts.append(f"returns {mk}={ret.get('provenance')}")
    ops = payload.get("crypto_operations") or []
    if ops:
        kinds = ",".join(sorted({o.get("kind", "op") for o in ops}))
        parts.append(f"ops[{kinds}]")
    return f"{fn_name}: " + ("; ".join(parts) if parts else "(no crypto material returned)")


def _match_call(caller_calls, callee_name):
    """Find the caller's LLM-recorded `calls[]` entry for a callee (by name)."""
    for c in caller_calls or []:
        cn = c.get("callee") or ""
        if cn == callee_name or cn.endswith("." + callee_name) or cn.split(".")[-1] == callee_name:
            return c
    return None


class CryptoPlugin(AnalysisPlugin):
    """Cryptographic API misuse plugin (CrySL-flavored operation+provenance)."""

    model = CRYPTO_MODEL
    SCHEMA = "crypto_v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="crypto",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("python", "javascript", "typescript", "java",
                                 "go", "php", "ruby", "c", "cpp"),
            verdicts=(VULNERABLE, WEAK, POLYMORPHIC, NEEDS_REVIEW, SAFE, ERROR),
            requires_top_down_context=False,
            needs_entrypoint=False,
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
                numbered, unit.signature_line, unit.id.language, callee_summaries,
                source_provenance_context(unit))},
        ]

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        payload = _extract_crypto_json(raw_response)
        if not isinstance(payload, dict):
            return None
        payload = validate_and_enrich(payload, request.function)
        if payload is None:
            return None
        return FactEnvelope(
            plugin_name="crypto",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=payload,
        )

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="crypto",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    # -- composition (bottom-up: resolve callee return-provenance) ------------

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no crypto facts)"
        return _summarize(facts.payload, facts.function.name)

    def compose_calls(
        self,
        caller_facts: FactEnvelope,
        resolved_calls: Sequence[ResolvedCall],
        context: DriverContext,
    ) -> FactEnvelope:
        """Resolve any caller crypto material whose source is a callee return.

        If op.key (or op.iv_nonce) has source.kind == call_return, look up the
        callee's returned key/iv material and substitute its provenance into the
        caller's material — so a helper returning a hardcoded key makes the
        caller's cipher VULNERABLE."""
        if caller_facts.status != "ok" or not caller_facts.payload:
            return caller_facts
        payload = dict(caller_facts.payload)
        caller_calls = payload.get("calls") or []

        # callee_name -> returns[] (only callees that produced ok facts)
        callee_returns: Dict[str, list] = {}
        for rc in resolved_calls:
            cf = rc.callee_facts
            if cf.status == "ok" and cf.payload:
                callee_returns[rc.call_site.callee_name] = cf.payload.get("returns") or []
        if not callee_returns:
            return caller_facts

        composed = []
        new_ops = []
        for op in payload.get("crypto_operations") or []:
            op2 = dict(op)
            for mat_key in ("key", "iv_nonce"):
                mat = op2.get(mat_key)
                if not isinstance(mat, dict):
                    continue
                src = mat.get("source") or {}
                if src.get("kind") != "call_return":
                    continue
                # Resolve callee by recorded source.callee, else the lone callee.
                cname = src.get("callee")
                rets = callee_returns.get(cname)
                if rets is None and len(callee_returns) == 1:
                    cname = next(iter(callee_returns))
                    rets = callee_returns[cname]
                if not rets:
                    continue
                want = "iv_nonce" if mat_key == "iv_nonce" else "key"
                callee_ret = next(
                    (r for r in rets if r.get("material_kind") == want), rets[0]
                )
                call = _match_call(caller_calls, cname)
                actual = None
                if call and callee_ret.get("param"):
                    actual = (call.get("actual_args") or {}).get(callee_ret["param"])
                new_prov = instantiate_return_material(callee_ret, actual)
                mat = dict(mat)
                if mat_key == "iv_nonce":
                    # map key-style provenance onto iv vocabulary
                    mat["provenance"] = (
                        "constant_or_literal" if new_prov == "hardcoded_literal"
                        else new_prov if new_prov in (
                            "fresh_random_per_call", "constant_or_literal",
                            "reused_across_calls", "counter", "from_param", "unknown")
                        else "unknown"
                    )
                else:
                    mat["provenance"] = new_prov
                mat["_resolved_from"] = cname
                op2[mat_key] = mat
                composed.append({"op": op2.get("id"), "material": mat_key,
                                 "callee": cname, "resolved": mat["provenance"]})
            new_ops.append(op2)

        if composed:
            payload["crypto_operations"] = new_ops
            payload["_composed_material"] = composed
            caller_facts.payload = payload
        return caller_facts

    # -- checker ---------------------------------------------------------------

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            derived = source_only_facts(context.function)
            derived_result = classify(derived) if derived else None
            if not derived_result or derived_result["verdict"] in {ERROR, NEEDS_REVIEW}:
                return Verdict(plugin_name="crypto", verdict=ERROR, status="error",
                               data={"error": "no valid crypto abstraction (fail-closed)"})
            facts.payload = derived
            facts.status = "partial"

        # Facts caches intentionally survive interrupted runs. Revalidate at the
        # checker boundary so stale/misleading LLM facts cannot bypass newer
        # deterministic source semantics on resume.
        payload = validate_and_enrich(facts.payload, context.function)
        if payload is None:
            return Verdict(plugin_name="crypto", verdict=ERROR, status="error",
                           data={"error": "invalid crypto abstraction (fail-closed)"})
        facts.payload = payload

        result = classify(facts.payload)
        verdict = result["verdict"]
        findings: List[Finding] = []
        for f in result.get("findings", []):
            sev_map = {VULNERABLE: "high", WEAK: "medium", POLYMORPHIC: "low",
                       NEEDS_REVIEW: "info"}
            findings.append(Finding(
                rule_id=f"crypto.{f['kind']}",
                title=f["kind"],
                message=f.get("reason") or f["kind"],
                severity=sev_map.get(f["severity"], "info"),
                function=facts.function,
                data={"severity": f["severity"], "cwe": f.get("cwe"),
                      "operation_id": f.get("operation_id"), "evidence": f.get("evidence")},
            ))
        return Verdict(
            plugin_name="crypto",
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
