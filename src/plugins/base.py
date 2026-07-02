"""Plugin SPI for FM-Agent's multi-theory analysis substrate.

FM-Agent's general technique: an LLM produces a MODULAR, PER-FUNCTION
natural-language abstraction of the relevant semantics, and a small
DETERMINISTIC checker (plain code, no LLM) makes the verdict over that
abstraction; results compose interprocedurally bottom-up.

This module factors that technique into a plugin contract so that each
security property class (information flow, integrity taint, access control,
typestate, ...) can be implemented as a plugin embodying its own formal theory
while reusing one shared driver (extraction + call graph + bottom-up ordering +
parallel LLM dispatch + optional top-down context propagation + tracing +
aggregation).

Design (see docs/plugin_architecture.md):

- The CORE owns orchestration and a small set of STABLE common envelopes
  (FunctionUnit, FactEnvelope, Verdict, Finding, DriverContext). The core never
  inspects a plugin's payload schema; it only reads envelope-level fields.
- Each PLUGIN owns its theory: prompt construction, response parsing, a text
  summary for callers, a composition operator, and a deterministic checker.
- Composition is NOT one-size-fits-all. IFC composes dependency-label sets;
  access control propagates precondition OBLIGATIONS up the call chain; typestate
  composes ordered event traces. The SPI therefore exposes `compose_calls` over
  the WHOLE ordered call list (the general hook) plus an optional top-down
  context worklist (`initial_context`/`propagate_context`/`merge_contexts`) for
  theories whose property is not a pure bottom-up value computation.

3.10-compatible; plain dataclasses; no third-party frameworks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Generic, List, Mapping, Optional, Sequence, TypeVar


# A plugin's per-function "facts" payload is plugin-owned. We only require it to
# be JSON-serializable so the core can persist/trace it. Typed as Any to keep the
# cross-plugin boundary plain.
PayloadT = TypeVar("PayloadT")
ContextT = TypeVar("ContextT")


# --- common identity / evidence envelopes (core-readable) --------------------

@dataclass(frozen=True)
class SourceSpan:
    """Source location. Lines are 1-based; cols optional (0 = unknown)."""
    path: str
    start_line: int = 0
    end_line: int = 0


@dataclass(frozen=True)
class FunctionId:
    """Stable function identity within an analyzed project.

    `rel` is the extracted-file rel path (e.g. "sessions-py/rebuild_proxies.py"),
    matching the on-disk layout that ifc_eval.py keys on. `name` is the deduped
    function name (foo, foo_1, ...). `base_name` strips the dedupe suffix so the
    call graph can match call sites that reference the source name `foo(`.
    """
    rel: str
    name: str
    base_name: str
    language: str


@dataclass(frozen=True)
class FunctionUnit:
    """One extracted function: identity + source + best-effort signature line."""
    id: FunctionId
    source: str
    signature_line: str
    params: Sequence[str] = field(default_factory=tuple)
    abs_path: Optional[str] = None


@dataclass(frozen=True)
class Evidence:
    """A human-legible evidence atom attached to facts or findings."""
    kind: str
    message: str
    span: Optional[SourceSpan] = None
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Diagnostic:
    """A non-finding note: parse failure, retry exhaustion, imprecision."""
    level: str  # "debug" | "info" | "warning" | "error"
    message: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FactEnvelope(Generic[PayloadT]):
    """Common wrapper for a plugin's per-function facts.

    The core may persist, trace, and route this object, but must access
    `payload` ONLY through plugin methods. `status`:
      - "ok"      : facts derived successfully
      - "partial" : facts derived but incomplete (still usable)
      - "error"   : derivation failed; checker MUST fail-closed (never SECURE)
    """
    plugin_name: str
    schema_version: str
    function: FunctionId
    status: str                       # "ok" | "partial" | "error"
    payload: PayloadT
    confidence: float = 1.0
    evidence: List[Evidence] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    trace_ids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    """A reportable result. `verdict_tag` is plugin-defined but should be one of
    PluginMetadata.verdicts; `severity` and `status` are common."""
    rule_id: str
    title: str
    message: str
    severity: str = "medium"          # info|low|medium|high|critical
    function: Optional[FunctionId] = None
    span: Optional[SourceSpan] = None
    evidence: List[Evidence] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Verdict:
    """Common checker output. `verdict` is a plugin-defined tag (must be in
    PluginMetadata.verdicts). `status` tells the core whether the check itself
    succeeded ("ok") or errored ("error")."""
    plugin_name: str
    verdict: str
    status: str = "ok"                # "ok" | "error"
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)


# --- call graph / driver context (core-owned) --------------------------------

@dataclass(frozen=True)
class CallSite:
    """A resolved caller->callee edge with best-effort argument binding.

    `arg_bindings` maps callee formal-parameter source keys (e.g. "param:x") to
    the caller's actual argument expressions. Plugins must tolerate partial or
    empty bindings (the regex-based resolver is best-effort).
    """
    caller: FunctionId
    callee: FunctionId
    callee_name: str
    order_index: int = 0
    arg_bindings: Mapping[str, str] = field(default_factory=dict)
    span: Optional[SourceSpan] = None


@dataclass(frozen=True)
class ProgramIndex:
    """Whole-program structure the driver computes once and shares (read-only)."""
    functions: Mapping[FunctionId, FunctionUnit]
    calls_by_caller: Mapping[FunctionId, Sequence[CallSite]]
    callers_by_callee: Mapping[FunctionId, Sequence[CallSite]]
    entrypoints: Sequence[FunctionId]


@dataclass(frozen=True)
class DriverContext:
    """Per-function context the driver hands to a plugin at every step."""
    program: ProgramIndex
    function: FunctionUnit
    is_entrypoint: bool
    callers: Sequence[CallSite] = field(default_factory=tuple)
    callees: Sequence[CallSite] = field(default_factory=tuple)


@dataclass(frozen=True)
class ResolvedCall(Generic[PayloadT]):
    """A call site paired with the callee's already-derived facts (for composition)."""
    call_site: CallSite
    callee_facts: FactEnvelope[PayloadT]


@dataclass(frozen=True)
class AbstractionRequest:
    """Input to a plugin's LLM-abstraction step for one function.

    `callee_context` maps each referenced, already-analyzed callee to the text
    produced by `summarize_for_caller`, for injection into the prompt. The
    prompt boundary is text, not a typed API, by design.
    """
    function: FunctionUnit
    context: DriverContext
    callee_context: Mapping[FunctionId, str] = field(default_factory=dict)
    trace_dir: Optional[str] = None
    trace_meta: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginMetadata:
    """Static plugin capabilities + driver requirements.

    `requires_top_down_context`: run the optional context worklist after
      bottom-up facts exist (access control needs it; typestate benefits).
    `needs_entrypoint`: the checker uses DriverContext.is_entrypoint as a trust
      boundary (IFC does: an entrypoint's return is an external sink).
    """
    name: str
    version: str
    schema_version: str
    supported_languages: Sequence[str]
    verdicts: Sequence[str]
    requires_top_down_context: bool = False
    needs_entrypoint: bool = False
    supports_recursion: bool = False


# --- the plugin interface -----------------------------------------------------

class AnalysisPlugin(ABC, Generic[PayloadT, ContextT]):
    """Service-provider interface for one formal theory.

    Lifecycle per function (driven by the shared driver, bottom-up):
      1. build_abstraction_prompt -> (system, user) messages
      2. [driver calls the LLM with retries]
      3. parse_abstraction_response -> FactEnvelope (or make_error_facts on failure)
      4. compose_calls -> fold already-derived callee facts into caller facts
      5. [optional] top-down context worklist via initial/propagate/merge_contexts
      6. check -> Verdict
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Static capabilities + driver requirements."""

    # -- (a) LLM abstraction step ---------------------------------------------

    @abstractmethod
    def build_abstraction_prompt(self, request: AbstractionRequest) -> List[Dict[str, str]]:
        """Return OpenAI-style messages [{"role","content"}, ...] for one function."""

    @abstractmethod
    def parse_abstraction_response(
        self, request: AbstractionRequest, raw_response: str
    ) -> Optional[FactEnvelope[PayloadT]]:
        """Parse one LLM response into facts. Return None to trigger a retry
        (the driver appends a format-correction turn and re-calls)."""

    @abstractmethod
    def make_error_facts(self, request: AbstractionRequest, error: str) -> FactEnvelope[PayloadT]:
        """Produce fail-closed facts after retries are exhausted or the call
        raised. For security plugins this MUST lead to ERROR/unsafe, never SECURE."""

    # -- (b) composition -------------------------------------------------------

    @abstractmethod
    def summarize_for_caller(self, facts: FactEnvelope[PayloadT]) -> str:
        """Concise text summary of callee facts, injected into a caller's prompt."""

    def compose_calls(
        self,
        caller_facts: FactEnvelope[PayloadT],
        resolved_calls: Sequence[ResolvedCall[PayloadT]],
        context: DriverContext,
    ) -> FactEnvelope[PayloadT]:
        """Fold already-derived callee facts into the caller's facts.

        Primary composition hook, over the WHOLE ordered call list (ordering
        matters for typestate; obligation accumulation matters for authz). The
        default is a no-op (pure bottom-up plugins that need no deterministic
        composition, e.g. when the LLM summary already carried callee context).
        IFC overrides this to instantiate callee signatures at each call site.
        """
        return caller_facts

    # -- (c) deterministic checker --------------------------------------------

    @abstractmethod
    def check(
        self,
        facts: FactEnvelope[PayloadT],
        context: DriverContext,
        propagated_contexts: Sequence[ContextT] = (),
    ) -> Verdict:
        """Decide the verdict over facts. `propagated_contexts` is empty unless
        the plugin requested top-down context (authz: established guards;
        typestate: possible entry states)."""

    # -- (d) optional top-down context propagation ----------------------------

    def initial_context(
        self, facts: FactEnvelope[PayloadT], context: DriverContext
    ) -> Optional[ContextT]:
        """Initial top-down context at an entrypoint. Only used when
        metadata.requires_top_down_context is True."""
        return None

    def propagate_context(
        self,
        caller_facts: FactEnvelope[PayloadT],
        callee_facts: FactEnvelope[PayloadT],
        call_site: CallSite,
        caller_context: ContextT,
        context: DriverContext,
    ) -> Optional[ContextT]:
        """Propagate context from caller to callee across one call site. Return
        None if irrelevant/unreachable."""
        return None

    def merge_contexts(
        self, old: Sequence[ContextT], new: Sequence[ContextT]
    ) -> Sequence[ContextT]:
        """Merge top-down contexts at a function. Must be deterministic and
        monotonic. Default dedups by repr()."""
        seen = {repr(x): x for x in old}
        for x in new:
            seen.setdefault(repr(x), x)
        return list(seen.values())

    # -- (e) optional result serialization ------------------------------------
    # These let a plugin emit a bespoke per-function / summary JSON shape (e.g.
    # IFC's legacy ifc_results format consumed by ifc_eval.py + ifc_viewer.py)
    # instead of the generic envelope. The driver calls these to serialize; the
    # default is a generic, stable shape.

    def render_result(
        self,
        unit: FunctionUnit,
        facts: FactEnvelope[PayloadT],
        verdict: Verdict,
        context: DriverContext,
    ) -> Dict[str, Any]:
        """Serialize one function's result to a JSON-able dict. Override to emit
        a plugin-specific schema for downstream tools."""
        return {
            "function": unit.abs_path,
            "rel": unit.id.rel,
            "verdict": verdict.verdict,
            "status": verdict.status,
            "facts": facts.payload,
            "facts_status": facts.status,
            "findings": [
                {"rule_id": f.rule_id, "title": f.title, "message": f.message,
                 "severity": f.severity, "data": f.data}
                for f in verdict.findings
            ],
            "diagnostics": [
                {"level": d.level, "message": d.message} for d in verdict.diagnostics
            ],
            "data": verdict.data,
        }

    def render_summary(self, results: Sequence[Dict[str, Any]],
                       counts: Mapping[str, int]) -> Dict[str, Any]:
        """Serialize the aggregate summary. `results` is the list of
        {"function","name","verdict"} rows the driver collected. Override to emit
        a plugin-specific summary schema."""
        return {
            "plugin": self.metadata.name,
            "total": len(results),
            "counts": dict(counts),
            "results": list(results),
        }
