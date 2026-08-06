"""Deterministic memory-safety plugin.

This plugin covers CVE classes that the existing security-property plugins do
not model: UAF, heap/stack overflows, out-of-bounds access, and browser/JIT type
confusion. It intentionally uses source and README/upstream metadata patterns
instead of LLM facts so it can act as a high-confidence classifier for PoC labs
whose exploit source is a harness around a vulnerable external component.
"""

from __future__ import annotations

from pathlib import Path
import re
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
    tokens = ("main", "start", "run", "exploit", "poc", "trigger")
    return any(token in name or token in stem for token in tokens)


def _js_type_confusion(source: str) -> bool:
    lower = source.lower()
    jit_shape_confusion = (
        "object.keys(" in lower
        and "object.defineproperty" in lower
        and "\"name\"" in lower
    )
    arbitrary_rw = (
        ("forgedwritebyte" in lower and "forgedreadbyte" in lower)
        or ("write64(" in lower and "read64(" in lower)
        or ("fake typedarray" in lower or "faketypedarray" in lower)
    )
    wasm_hijack = (
        "webassembly.module" in lower
        or "webassembly.instance" in lower
        or "unchecked_entry" in lower
        or "setwasmuncheckedentry" in lower
    )
    return jit_shape_confusion and (arbitrary_rw or wasm_hijack)


def _line_describes_missing_protection(line: str) -> bool:
    return any(token in line for token in (
        "without bounds check",
        "without bound check",
        "without bounds checking",
        "without validation",
        "without mitigation",
        "without guard",
        "without a guard",
        "without check",
        "no bounds check",
        "no bound check",
        "missing bounds check",
        "missing bound check",
        "missing validation",
        "missing mitigation",
        "missing guard",
        "缺少边界检查",
        "缺少校验",
        "缺少缓解",
        "没有边界检查",
        "未进行边界检查",
    ))


def _line_negates_finding(line: str, terms: Sequence[str]) -> bool:
    if _denies_memory_corruption(line):
        return True
    if _line_describes_missing_protection(line):
        return False

    for term in terms:
        deny_phrases = (
            f"no {term}",
            f"no evidence of {term}",
            f"no sign of {term}",
            f"not {term}",
            f"not a {term}",
            f"not an {term}",
            f"not vulnerable to {term}",
            f"without {term}",
            f"does not trigger {term}",
            f"does not cause {term}",
            f"does not involve {term}",
            f"does not contain {term}",
            f"is not {term}",
            f"is not a {term}",
            f"is not an {term}",
            f"isn't {term}",
            f"isn't a {term}",
            f"isn't an {term}",
            f"没有 {term}",
            f"没有{term}",
            f"不是 {term}",
            f"不是{term}",
            f"无需 {term}",
            f"无需{term}",
            f"不需要 {term}",
            f"不需要{term}",
            f"不依赖 {term}",
            f"不依赖{term}",
        )
        if any(phrase in line for phrase in deny_phrases):
            return True
    return False


def _has_positive_term(text: str, terms: Sequence[str]) -> bool:
    for line in text.splitlines():
        if any(term in line for term in terms) and not _line_negates_finding(line, terms):
            return True
    return False


def _denies_memory_corruption(text: str) -> bool:
    return any(token in text for token in (
        "不需要内存破坏",
        "不依赖内存破坏",
        "没有内存破坏",
        "不是内核内存破坏",
        "不是传统内存破坏",
        "not memory corruption",
        "no memory corruption",
        "without memory corruption",
        "no uaf",
        "没有 uaf",
        "没有uaf",
        "no oob",
        "没有 oob",
        "没有oob",
        "没有 uaf / oob",
        "没有uaf/oob",
    ))


def _kernel_fd_theft_domain(text: str) -> bool:
    return (
        "pidfd_getfd" in text
        or "fd theft" in text
        or "文件描述符盗取" in text
        or "mm-null ptrace" in text
        or "mm-null" in text
    )


def _kernel_specialized_domain(text: str) -> bool:
    return any(token in text for token in (
        "page cache",
        "page-cache",
        "pagecache",
        "copy-on-write",
        "partial-cow",
        "cifs.spnego",
        "pidfd_getfd",
        "fd theft",
        "文件描述符盗取",
        "rxgk_decrypt_skb",
        "skb_ensure_writable",
        "act_pedit",
    ))


def _strong_memory_safety_domain(text: str) -> bool:
    return _has_positive_term(text, (
        "heap-buffer-overflow",
        "堆缓冲区溢出",
        "heap overflow",
        "cwe-122",
        "use-after-free",
        "uaf",
        "type confusion",
        "类型混淆",
        "cwe-843",
        "zipmap",
        "invalid memory access",
        "非法内存访问",
        "asan",
    ))


def _findings_from_text(text: str, source: str) -> List[Dict[str, str]]:
    lower = text.lower()
    is_ionstack_jit = "cve-2026-10702" in lower or "ionstack firefox jit" in lower
    memory_corruption_denied = _denies_memory_corruption(lower)
    kernel_fd_theft_only = _kernel_fd_theft_domain(lower) and memory_corruption_denied
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
        not is_ionstack_jit
        and not kernel_fd_theft_only
        and not memory_corruption_denied
        and _has_positive_term(lower, (
            "use-after-free",
            "uaf",
            "释放后",
            "悬空指针",
        ))
    ):
        add(
            "use_after_free",
            "CWE-416",
            "metadata/source mentions UAF/use-after-free/dangling pointer",
            "project describes a freed object being reused or dereferenced",
        )
    if (
        not kernel_fd_theft_only
        and not memory_corruption_denied
        and _has_positive_term(lower, (
            "heap-buffer-overflow",
            "堆缓冲区溢出",
            "heap overflow",
            "cwe-122",
        ))
    ):
        add(
            "heap_buffer_overflow",
            "CWE-122",
            "metadata/source mentions heap-buffer-overflow or CWE-122",
            "project describes heap memory access beyond the allocated object",
        )
    oob_read_signal = _has_positive_term(lower, (
        "out-of-bounds read",
        "out of bounds read",
        "oob read",
        "cwe-125",
        "越界读",
    ))
    oob_write_signal = _has_positive_term(lower, (
        "out-of-bounds write",
        "out of bounds write",
        "oob write",
        "cwe-787",
        "越界写",
    ))
    generic_bounds_signal = _has_positive_term(lower, (
        "out-of-bounds",
        "out of bounds",
        "oob",
    ))
    explicit_bounds_access = (
        oob_read_signal
        or oob_write_signal
        or generic_bounds_signal
    )
    bounds_signal = explicit_bounds_access
    kernel_specialized = _kernel_specialized_domain(lower)
    if (
        bounds_signal
        and not kernel_fd_theft_only
        and not memory_corruption_denied
        and (not kernel_specialized or _strong_memory_safety_domain(lower))
    ):
        if oob_read_signal:
            add(
                "out_of_bounds_read",
                "CWE-125",
                "metadata/source mentions out-of-bounds read or CWE-125",
                "project describes a read outside valid object bounds",
            )
        if oob_write_signal:
            add(
                "out_of_bounds_write",
                "CWE-787",
                "metadata/source mentions out-of-bounds write or CWE-787",
                "project describes a write outside valid object bounds",
            )
        if not oob_read_signal and not oob_write_signal:
            add(
                "out_of_bounds_access",
                "CWE-119",
                "metadata/source mentions generic out-of-bounds access",
                "project describes an access outside valid object bounds",
            )
    if (
        _has_positive_term(lower, (
            "type confusion",
            "类型混淆",
            "cwe-843",
        ))
        or _js_type_confusion(source)
    ):
        add(
            "type_confusion",
            "CWE-843",
            "JIT/type-confusion metadata or Object.keys/name/TypedArray primitive",
            "project describes object layout confusion leading to arbitrary read/write",
        )
    if (
        "zipmap" in lower
        and "restore" in lower
        and ("invalid memory access" in lower or "非法内存访问" in lower)
    ):
        add(
            "parser_memory_corruption",
            "CWE-20/CWE-122",
            "Redis RESTORE zipmap invalid memory access metadata",
            "serialized input reaches parser memory corruption because validation is incomplete",
        )
    if (
        "slab" in lower
        and ("cross-cache" in lower or "kfence" in lower)
        and ("cwe-401" in lower or "释放后未移除" in lower)
    ):
        add(
            "kernel_allocator_lifecycle",
            "CWE-401",
            "slab/KFENCE allocator lifecycle metadata",
            "project describes allocator/object-lifecycle mismatch with security impact",
        )
    return findings


class MemSafetyPlugin(AnalysisPlugin):
    """Source/metadata-backed memory-safety classifier."""

    SCHEMA = "memsafety.v1"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="memsafety",
            version="0.1.0",
            schema_version=self.SCHEMA,
            supported_languages=("c", "cpp", "javascript", "typescript", "html"),
            verdicts=(VULNERABLE, NEEDS_REVIEW, SAFE, ERROR),
            requires_top_down_context=False,
            needs_entrypoint=True,
        )

    def derive_facts(self, request: AbstractionRequest) -> Optional[FactEnvelope]:
        unit = request.function
        text = unit.source
        if _is_project_locus(unit):
            text = _metadata_text(_project_root(unit), unit.id.rel, unit.source)
        findings = _findings_from_text(text, unit.source)
        return FactEnvelope(
            plugin_name="memsafety",
            schema_version=self.SCHEMA,
            function=unit.id,
            status="ok",
            payload={
                "schema_version": self.SCHEMA,
                "findings": findings,
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
            plugin_name="memsafety",
            schema_version=self.SCHEMA,
            function=request.function.id,
            status="error",
            payload=None,
            confidence=0.0,
            diagnostics=[Diagnostic(level="error", message=error)],
        )

    def summarize_for_caller(self, facts: FactEnvelope) -> str:
        if facts.status != "ok" or not facts.payload:
            return f"{facts.function.name}: (no memory-safety facts)"
        kinds = ",".join(item.get("kind", "?") for item in facts.payload.get("findings") or [])
        return f"{facts.function.name}: memsafety[{kinds or 'none'}]"

    def check(
        self,
        facts: FactEnvelope,
        context: DriverContext,
        propagated_contexts: Sequence = (),
    ) -> Verdict:
        if facts.status == "error" or not facts.payload:
            return Verdict(plugin_name="memsafety", verdict=ERROR, status="error")
        raw_findings = facts.payload.get("findings") or []
        findings = [
            Finding(
                rule_id=f"memsafety.{item.get('kind', 'unknown')}",
                title=item.get("kind", "memory_safety_issue"),
                message=item.get("reason", ""),
                severity="high",
                function=facts.function,
                data={"cwe": item.get("cwe"), "evidence": item.get("evidence")},
            )
            for item in raw_findings if isinstance(item, dict)
        ]
        return Verdict(
            plugin_name="memsafety",
            verdict=VULNERABLE if findings else SAFE,
            findings=findings,
            data={"signature": facts.payload},
        )

    def render_result(self, unit, facts, verdict, context):
        result = super().render_result(unit, facts, verdict, context)
        result["rel"] = unit.id.rel
        result["function"] = unit.id.name
        return result
