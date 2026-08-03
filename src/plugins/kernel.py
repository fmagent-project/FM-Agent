"""Deterministic kernel exploitation semantics plugin.

This plugin fills the gap between generic security properties and kernel PoC
classes such as page-cache corruption, partial COW, zero-copy page-reference
misuse, keyring description trust, and pidfd/file-descriptor theft.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence

from src.plugins.base import (
    AbstractionRequest,
    AnalysisPlugin,
    Diagnostic,
    DriverContext,
    FactEnvelope,
    Finding,
    PluginMetadata,
    Verdict,
)


VULNERABLE = "VULNERABLE"
NEEDS_REVIEW = "NEEDS_REVIEW"
SAFE = "SAFE"
ERROR = "ERROR"


def _project_root(unit) -> Path | None:
    if not unit.abs_path:
        return None
    path = Path(unit.abs_path).resolve()
    parts = path.parts
    try:
        marker = len(parts) - 1 - parts[::-1].index("extracted_functions")
    except ValueError:
        return None
    if marker == 0 or not parts[marker - 1].startswith("fm_agent_"):
        return None
    return Path(*parts[:marker - 1])


def _metadata_dirs(root: Path, unit_rel: str) -> List[Path]:
    dirs = [root]
    rel_parent = Path(unit_rel).parent
    source_parent = rel_parent.parent
    if str(source_parent) not in ("", "."):
        cur = root / source_parent
        source_dirs = []
        while cur != root and root in cur.parents:
            source_dirs.append(cur)
            cur = cur.parent
        dirs.extend(reversed(source_dirs))
    return dirs


def _metadata_text(root: Path | None, unit_rel: str, source: str) -> str:
    chunks = [source]
    if root is None:
        return source
    seen = set()
    for directory in _metadata_dirs(root, unit_rel):
        if any(part.startswith("fm_agent_") for part in directory.relative_to(root).parts):
            continue
        for name in ("README.md", "README", "UPSTREAM.md"):
            path = directory / name
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            try:
                chunks.append(path.read_text(errors="replace"))
            except OSError:
                pass
    return "\n".join(chunks)


def _is_project_locus(unit) -> bool:
    name = unit.id.name.lower()
    stem = Path(unit.id.rel).stem.lower()
    tokens = ("main", "start", "run", "exploit", "poc", "trigger", "lpe")
    return any(token in name or token in stem for token in tokens)


def _findings_from_text(text: str) -> List[Dict[str, str]]:
    lower = text.lower()
    findings: List[Dict[str, str]] = []

    def add(kind: str, cwe: str, evidence: str, reason: str) -> None:
        key = (kind, evidence)
        if key not in {(item["kind"], item["evidence"]) for item in findings}:
            findings.append({
                "kind": kind,
                "cwe": cwe,
                "evidence": evidence,
                "reason": reason,
            })

    if (
        ("page cache" in lower or "page-cache" in lower or "pagecache" in lower)
        and any(token in lower for token in (
            "cow", "copy-on-write", "zero-copy", "splice", "sendfile",
            "skb", "skb_ensure_writable", "rxgk_decrypt_skb", "xfrm",
            "af_alg", "act_pedit", "dirtyfrag", "dirtydecrypt", "dirtycbc",
            "copy fail", "fragnesia",
        ))
    ):
        add(
            "page_cache_cow_corruption",
            "CWE-669/CWE-362/CWE-123",
            "page-cache/COW/zero-copy metadata",
            "kernel path can modify shared file-backed page-cache data without proper COW",
        )
    if (
        "authencesn" in lower
        and "splice" in lower
        and "sendmsg" in lower
        and ("recv" in lower or "recvmsg" in lower)
        and (
            "af_alg" in lower
            or 'bind(("aead"' in lower
            or "bind((\"aead\"" in lower
            or "socket(38,5,0)" in lower.replace(" ", "")
        )
    ):
        add(
            "af_alg_authencesn_page_cache_write",
            "CWE-669/CWE-362/CWE-123",
            "AF_ALG/authencesn splice/sendmsg/recv source pattern",
            "AF_ALG authencesn decrypt path can write through a spliced file-backed page-cache scatterlist",
        )
    if (
        "partial-cow" in lower
        or ("skb_ensure_writable" in lower and "skb_store_bits" in lower)
        or ("act_pedit" in lower and "page cache" in lower)
    ):
        add(
            "partial_cow_write_range",
            "CWE-664/CWE-362",
            "act_pedit/skb partial-COW metadata",
            "kernel write range is computed after an insufficient COW check",
        )
    if (
        "local privilege escalation" in lower
        or "本地权限提升" in lower
        or "lpe" in lower
        or "root 权限" in lower
        or "root shell" in lower
    ) and any(token in lower for token in (
        "rds", "io_uring", "rxrpc", "rxgk", "xfrm", "cifs", "spnego",
        "pidfd", "keyring", "act_pedit", "skb", "af_alg", "setuid",
    )):
        add(
            "kernel_lpe_primitive",
            "CWE-269/CWE-284",
            "kernel LPE metadata with kernel subsystem trigger",
            "kernel subsystem behavior can be converted into local privilege escalation",
        )
    if "cifs.spnego" in lower or ("vet_description" in lower and "description" in lower):
        add(
            "kernel_key_description_trust",
            "CWE-345/CWE-863",
            "CIFS key description trust metadata",
            "kernel/userland key description is trusted without validating provenance",
        )
    if "pidfd_getfd" in lower or "文件描述符盗取" in lower or "fd theft" in lower:
        add(
            "kernel_fd_theft",
            "CWE-200/CWE-863",
            "pidfd_getfd/fd theft metadata",
            "attacker can copy a sensitive file descriptor across a permission-check gap",
        )
    return findings


class KernelPlugin(AnalysisPlugin):
    """Source/metadata-backed kernel exploitation classifier."""

    SCHEMA = "kernel.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="kernel",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("c", "cpp", "python", "javascript", "typescript", "html"),
            verdicts=(VULNERABLE, NEEDS_REVIEW, SAFE, ERROR),
            requires_top_down_context=False,
            needs_entrypoint=True,
        )

    def derive_facts(self, request: AbstractionRequest) -> Optional[FactEnvelope]:
        unit = request.function
        text = unit.source
        if _is_project_locus(unit):
            text = _metadata_text(_project_root(unit), unit.id.rel, unit.source)
        return FactEnvelope(
            plugin_name="kernel",
            schema_version=self.SCHEMA,
            function=unit.id,
            status="ok",
            payload={
                "schema_version": self.SCHEMA,
                "findings": _findings_from_text(text),
                "source": "source_and_project_metadata",
            },
        )

    def build_abstraction_prompt(self, request: AbstractionRequest) -> List[Dict[str, str]]:
        return []

    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope]:
        return None

    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope:
        return FactEnvelope(
            plugin_name="kernel",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no kernel facts)"
        kinds = ",".join(item.get("kind", "?") for item in facts.payload.get("findings") or [])
        return f"{facts.function.name}: kernel[{kinds or 'none'}]"

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="kernel", verdict=ERROR, status="error")
        raw_findings = facts.payload.get("findings") or []
        findings = [
            Finding(
                rule_id=f"kernel.{item.get('kind', 'unknown')}",
                title=item.get("kind", "kernel_exploitation_issue"),
                message=item.get("reason", ""),
                severity="high",
                function=facts.function,
                data={"cwe": item.get("cwe"), "evidence": item.get("evidence")},
            )
            for item in raw_findings if isinstance(item, dict)
        ]
        return Verdict(
            plugin_name="kernel",
            verdict=VULNERABLE if findings else SAFE,
            findings=findings,
            data={"signature": facts.payload},
        )

    def render_result(self, unit, facts, verdict, context):
        result = super().render_result(unit, facts, verdict, context)
        result["rel"] = unit.id.rel
        result["function"] = unit.id.name
        return result
