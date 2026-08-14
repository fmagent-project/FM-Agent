"""Acceptance gate for boundary-witness bug validation submissions.

Design: docs/superpowers/specs/2026-07-10-boundary-witness-bug-validation-design.md §5.4
Check order (first failure rejects, reason is fed back to the agent):
  schema -> replay capture -> call_index/actual consistency
  -> phenomenon recheck -> mandatory L1 patch attempt and verification.

Log-shape contract pinned by tests/test_audit_log_shape.py:
  raw tracing JSONL events; span args live in event["span"] (e.g. self_flags),
  the per-call return value arrives in a separate event with fields["return"],
  "new"/"close" marker events carry fields["message"].
"""
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    from .compiler_recipe import CompileRecipeError, compile_argv
    from .coverage_witness import CoverageError, capture_coverage
    from .phenomenon_runner import PhenomenonError, run_phenomenon
    from .submission_schema import SchemaError, validate_v3
except ImportError:  # flat import (tests, scripts)
    from compiler_recipe import CompileRecipeError, compile_argv
    from coverage_witness import CoverageError, capture_coverage
    from phenomenon_runner import PhenomenonError, run_phenomenon
    from submission_schema import SchemaError, validate_v3


@dataclass
class Rejection:
    check: str
    reason: str

    def to_feedback(self) -> str:
        return f"SUBMISSION REJECTED at check [{self.check}]: {self.reason}"


class ReplayError(ValueError):
    """The harness could not produce a trustworthy replay."""


# PIN: boundary-events-pair-by-call-id
def parse_records(lines, manifest_id):
    """Collapse raw tracing events into per-call records for one manifest ID.

    A record is opened by a "new" event and joined to return/close events by
    the harness-injected unique span ID. This remains correct when recursive
    or concurrent calls interleave in the JSONL stream.
    Returns [{"input": {...}, "return": str|None, "target": str}].
    """
    records = []
    active = {}
    seen = set()
    returned = set()
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayError(
                f"invalid JSON on line {line_number}: {exc.msg}"
            ) from exc
        if type(e) is not dict:
            raise ReplayError(f"line {line_number} is not a JSON object")
        raw_span = e.get("span")
        if type(raw_span) is not dict:
            raise ReplayError(f"line {line_number} has an invalid span object")
        raw_fields = e.get("fields")
        if type(raw_fields) is not dict:
            raise ReplayError(f"line {line_number} has an invalid fields object")
        span = raw_span
        fields = raw_fields
        span_name = span.get("name")
        if type(span_name) is not str or not span_name:
            raise ReplayError(f"line {line_number} has an invalid span name")
        has_message = "message" in fields
        message = fields.get("message")
        has_return = "return" in fields
        if has_return and has_message:
            raise ReplayError(
                f"line {line_number} mixes a span marker with a return event"
            )
        if has_return:
            event_kind = "return"
        elif message in ("new", "close"):
            event_kind = message
        else:
            raise ReplayError(
                f"line {line_number} has an unrecognized trace event shape"
            )
        if span_name != manifest_id:
            continue
        span_id = span.get("fm_span_id")
        if type(span_id) not in (str, int) or isinstance(span_id, bool) \
                or span_id == "":
            raise ReplayError("target trace event is missing a valid unique span ID")
        if event_kind == "new":
            if span_id in seen:
                raise ReplayError(f"duplicate target span ID: {span_id!r}")
            seen.add(span_id)
            inputs = dict(span)
            inputs.pop("name", None)
            inputs.pop("fm_span_id", None)
            records.append({
                "input": inputs,
                "return": None,
                "target": e.get("target", ""),
                "manifest_id": manifest_id,
            })
            active[span_id] = len(records) - 1
        elif event_kind == "return":
            if span_id not in active:
                raise ReplayError(f"return event has no matching span ID: {span_id!r}")
            index = active[span_id]
            if span_id in returned:
                raise ReplayError(f"span ID has multiple return events: {span_id!r}")
            returned.add(span_id)
            records[index]["return"] = fields["return"]
        else:
            if span_id not in active:
                raise ReplayError(f"close event has no matching span ID: {span_id!r}")
            if span_id not in returned:
                raise ReplayError(
                    f"close event has no matching return event: {span_id!r}"
                )
            del active[span_id]
    if active:
        raise ReplayError("trace ended with target span IDs still open")
    return records


# Strip `Span { .. }` and its preceding separator entirely: agents commonly
# omit spans when transcribing an AST value, while replay keeps them, so a
# placeholder is not enough — both sides must collapse to the span-free form.
_SPAN_RE = re.compile(r"\s*,?\s*Span\s*\{[^{}]*\}")


def canonical_value(value):
    """Compare boundary values ignoring source-position noise.

    Debug strings of AST nodes embed `Span { start: N, end: M, .. }` byte
    offsets that shift with any probe edit and carry no semantic meaning for a
    boundary-violation judgment. Remove them (and a preceding comma, if any) so
    exact-match replay is robust across the whole class of AST-returning parser
    functions, and so an agent that omitted spans still matches the spanned
    replay. Anti-fabrication is preserved: the full structural content must
    still match."""
    if type(value) is str:
        s = value
        prev = None
        while prev != s:
            prev = s
            s = _SPAN_RE.sub("", s)
        return ("string", re.sub(r"\s+", " ", s).strip())
    if value is None:
        return ("null", None)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value)
    if type(value) is list:
        return ("list", tuple(canonical_value(item) for item in value))
    if type(value) is dict:
        return (
            "object",
            tuple((key, canonical_value(value[key])) for key in sorted(value)),
        )
    return (type(value).__name__, repr(value))


# PIN: nonzero-validation-capture-requires-complete-evidence
def default_replay_capture(context, recipe, process_runner=subprocess.run):
    """Compile the canonical probe with trusted argv and parse its trace."""
    probe = Path(context.probe_path)
    expected = Path(context.validation_dir) / f"_probe_{context.bug_id}.c"
    if probe != expected or probe.suffix != ".c" or probe.is_symlink() \
            or not probe.is_file():
        raise ReplayError(f"canonical probe is missing or unsafe: {probe}")
    scratch = Path(context.scratch_dir)
    scratch.mkdir(parents=True, exist_ok=True)
    log = scratch / "boundary-replay.audit.jsonl"
    log.unlink(missing_ok=True)
    out_bin = scratch / "boundary-replay.bin"
    out_bin.unlink(missing_ok=True)
    manifest_id = context.manifest_entry.manifest_id
    try:
        argv = compile_argv(context.audit_ccc, recipe, probe, out_bin)
    except CompileRecipeError as exc:
        raise ReplayError(f"audit compile recipe is invalid: {exc}") from exc
    try:
        result = process_runner(
            argv, capture_output=True, text=True, timeout=120,
            cwd=context.project_dir if hasattr(context, "project_dir") else probe.parent,
            env=dict(os.environ, FM_AUDIT_FN=manifest_id, FM_AUDIT_LOG=str(log)),
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ReplayError(f"audit compile failed to execute: {exc}") from exc
    out_bin.unlink(missing_ok=True)
    if not log.exists():
        if result.returncode != 0:
            detail = (getattr(result, "stderr", "") or "")[-400:]
            raise ReplayError(
                f"audit compile failed with rc={result.returncode}: {detail}"
            )
        return []
    try:
        lines = log.read_text().splitlines()
    except OSError as exc:
        raise ReplayError(f"audit log is unreadable: {exc}") from exc
    records = parse_records(lines, manifest_id)
    if not records and result.returncode != 0:
        detail = (getattr(result, "stderr", "") or "")[-400:]
        raise ReplayError(
            f"audit compile failed with rc={result.returncode} and captured no "
            f"target calls: {detail}"
        )
    return records


class Gate:
    def __init__(self, replay_capture=default_replay_capture,
                 phenomenon_runner=run_phenomenon, l1_verifier=None,
                 coverage_runner=capture_coverage):
        self.replay_capture = replay_capture
        self.phenomenon_runner = phenomenon_runner
        self.l1_verifier = l1_verifier
        self.coverage_runner = coverage_runner
        self.last_l1_rejection = None

    # PIN: validation-context-is-authoritative
    # PIN: confirmed-results-require-complete-evidence
    def check(self, sub: dict, context):
        self.last_l1_rejection = None
        # 1. schema
        try:
            validate_v3(sub)
        except SchemaError as e:
            return Rejection("schema", str(e))
        if sub["id"] != context.bug_id or sub["function_id"] != context.function_id:
            return Rejection(
                "identity",
                "submission id/function_id do not match the requested validation context",
            )
        if sub["confirmation_status"] == "not_confirmed":
            return None
        w = sub["witness"]
        try:
            expected_probe = Path(context.probe_path).relative_to(
                context.project_dir
            ).as_posix()
        except ValueError:
            return Rejection("identity", "canonical probe is outside the project")
        if w["probe"] != expected_probe:
            return Rejection("identity", "witness.probe is not the canonical context probe")

        # PIN: boundary-evidence-has-two-independent-counts
        # PIN: validation-replay-uses-submitted-compile-recipe
        # 2/3. replay capture + L0 + witness consistency
        try:
            records = self.replay_capture(context, sub["phenomenon"])
        except ReplayError as exc:
            return Rejection("replay", str(exc))
        if not records:
            return Rejection("L0", f"zero boundary records for {context.bug_id} on replay; "
                                   "the probe never executes the target function")
        try:
            coverage_count = self.coverage_runner(context, sub["phenomenon"])
        except CoverageError as exc:
            return Rejection("L0", f"independent coverage check failed: {exc}")
        if type(coverage_count) is not int or coverage_count < 1:
            return Rejection(
                "L0", "independent coverage recorded zero target entries",
            )
        if coverage_count != len(records):
            return Rejection(
                "L0", f"trace count {len(records)} does not match independent "
                f"coverage count {coverage_count}",
            )
        if w["call_index"] >= len(records):
            return Rejection("replay", f"call_index {w['call_index']} out of range "
                                       f"({len(records)} records on replay)")
        rec = records[w["call_index"]]
        if rec.get("manifest_id") != context.manifest_entry.manifest_id:
            return Rejection("replay", "cited record has the wrong manifest span identity")
        if canonical_value(rec["return"]) != canonical_value(w["actual_output"]):
            return Rejection("replay", f"actual_output mismatch: replay={rec['return']!r} "
                                       f"submitted={w['actual_output']!r}")
        if set(w["captured_input"]) != set(rec["input"]):
            return Rejection(
                "replay", "captured_input keys do not exactly match the replayed record",
            )
        for k, v in w["captured_input"].items():
            if canonical_value(rec["input"][k]) != canonical_value(v):
                return Rejection("replay", f"captured_input.{k} mismatch: "
                                           f"replay={rec['input'][k]!r} submitted={v!r}")

        # Condition A is a validator-agent judgment. Logic results do not yet
        # provide a structured contract the harness can evaluate, so the gate
        # deliberately does not pretend to re-prove it mechanically.

        # 4. Reconstruct and observe the compiler phenomenon without shell text.
        try:
            observed = self.phenomenon_runner(sub["phenomenon"], context)
        except PhenomenonError as exc:
            return Rejection("phenomenon", str(exc))
        expected_kind = sub["phenomenon"]["expected_kind"]
        if observed.kind != expected_kind:
            return Rejection(
                "phenomenon",
                f"observed kind {observed.kind!r} does not match declared {expected_kind!r}",
            )
        # PIN: l1-patches-are-narrow-and-behaviorally-closed
        # 5. Every confirmed submission must first offer a target-body patch.
        #    Only the Gate may turn that attempted L1 into L0 after the already
        #    verified L0 evidence passes and patch verification fails.
        if sub["grade"] != "L1":
            return Rejection(
                "L1-attempt",
                "confirmed submissions must first submit a canonical target-function "
                "patch as grade L1; only a failed Gate verification may downgrade "
                "that attempt to L0",
            )
        rej = self.verify_l1(sub, context)
        if rej is not None:
            if rej.check != "L1":
                return rej
            self.last_l1_rejection = rej
            sub["grade"] = "L0"
            sub["l1_patch"] = None
            note = sub.get("notes") or ""
            sub["notes"] = (note + " " if note else "") + \
                f"[L1 downgraded to L0: {rej.reason[:160]}]"
        return None

    def verify_l1(self, sub, context):
        if self.l1_verifier is None:
            try:
                from .l1_verifier import verify_l1
            except ImportError:  # flat import (tests, scripts)
                from l1_verifier import verify_l1
            return verify_l1(sub, context)
        return self.l1_verifier(sub, context)
