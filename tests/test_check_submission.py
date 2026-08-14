import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from check_submission import (  # noqa: E402
    Gate,
    Rejection,
    ReplayError,
    canonical_value,
    default_replay_capture,
    parse_records,
)


MANIFEST_ID = "src--frontend--parser--ast-rs--is_const"
FUNCTION_ID = "src::frontend::parser::ast-rs::is_const"
def _raw_events(fn=MANIFEST_ID, flags=0, ret="false", span_id=1,
                target="ccc::frontend::parser::ast"):
    """Three raw tracing events (new/return/close) as captured in real logs."""
    span = {"self_flags": flags, "fm_span_id": span_id, "name": fn}
    return [
        {"timestamp": "t", "level": "INFO", "fields": {"message": "new"},
         "target": target, "span": span, "spans": []},
        {"timestamp": "t", "level": "INFO", "fields": {"return": ret},
         "target": target, "span": span, "spans": [span]},
        {"timestamp": "t", "level": "INFO",
         "fields": {"message": "close", "time.busy": "1µs", "time.idle": "1µs"},
         "target": target, "span": span, "spans": []},
    ]


def _submission(call_index=0, grade="L1", flags=0, actual="false"):
    return {
        "schema_version": 3,
        "id": MANIFEST_ID,
        "function_id": FUNCTION_ID,
        "confirmation_status": "confirmed",
        "grade": grade,
        "witness": {
            "probe": f"fm_agent/bug_validation/_probe_{MANIFEST_ID}.c",
            "call_index": call_index,
            "captured_input": {"self_flags": flags},
            "actual_output": actual,
            "spec_violation_claim": "probe line 1 expects true but boundary returned false",
        },
        "phenomenon": {
            "mode": "run", "standard": "c11", "extra_args": [],
            "expected_kind": "run_exit_differs",
        },
        "l1_patch": "fix.patch" if grade == "L1" else None,
        "attempts": 1,
        "notes": "",
    }


def _context(tmp):
    validation = tmp / "fm_agent" / "bug_validation"
    scratch = validation / ".attempts" / "attempt-1"
    validation.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        bug_id=MANIFEST_ID,
        function_id=FUNCTION_ID,
        project_dir=tmp,
        validation_dir=validation,
        probe_path=validation / f"_probe_{MANIFEST_ID}.c",
        scratch_dir=scratch,
        audit_ccc=Path("/trusted/ccc-audit"),
        release_ccc=Path("/trusted/ccc"),
        reference_cc=Path("/trusted/gcc"),
        manifest_entry=SimpleNamespace(manifest_id=MANIFEST_ID),
    )


def _gate(records=None, observed_kind="run_exit_differs", l1_verifier=None,
          coverage_count=None):
    count = len(records or []) if coverage_count is None else coverage_count
    if l1_verifier is None:
        l1_verifier = lambda _submission, _context: None
    return Gate(
        replay_capture=lambda context, recipe: records if records is not None else [],
        coverage_runner=lambda context, recipe: count,
        phenomenon_runner=lambda recipe, context: SimpleNamespace(kind=observed_kind),
        l1_verifier=l1_verifier,
    )


class ParseRecordsTests(unittest.TestCase):
    def test_pairs_new_and_return_events(self):
        recs = parse_records([json.dumps(e) for e in _raw_events()], MANIFEST_ID)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["input"], {"self_flags": 0})
        self.assertEqual(recs[0]["return"], "false")
        self.assertEqual(recs[0]["manifest_id"], MANIFEST_ID)

    def test_missing_return_fails_closed(self):
        no_ret = [e for e in _raw_events() if "return" not in e["fields"]]
        with self.assertRaisesRegex(ReplayError, "no matching return event"):
            parse_records([json.dumps(e) for e in no_ret], MANIFEST_ID)

    def test_explicit_null_return_is_still_a_return_event(self):
        recs = parse_records(
            [json.dumps(e) for e in _raw_events(ret=None)], MANIFEST_ID,
        )
        self.assertEqual(len(recs), 1)
        self.assertIsNone(recs[0]["return"])

    def test_null_return_cannot_be_overwritten_by_a_second_return(self):
        events = _raw_events(ret=None)
        events.insert(2, {
            "span": events[0]["span"],
            "fields": {"return": "second"},
            "target": events[0]["target"],
        })
        with self.assertRaisesRegex(ReplayError, "multiple return events"):
            parse_records([json.dumps(event) for event in events], MANIFEST_ID)

    def test_marker_and_return_cannot_share_one_event(self):
        for marker, index in (("new", 0), ("close", 2)):
            events = _raw_events()
            events[index]["fields"]["return"] = None
            with self.subTest(marker=marker), self.assertRaisesRegex(
                ReplayError, "mixes a span marker"
            ):
                parse_records([json.dumps(event) for event in events], MANIFEST_ID)

    def test_filters_on_unique_manifest_id_not_bare_name(self):
        other = "src--other--is_const"
        lines = [json.dumps(e) for e in _raw_events(MANIFEST_ID, flags=1, ret="true")]
        lines += [json.dumps(e) for e in _raw_events(other, flags=2, ret="false")]
        recs = parse_records(lines, MANIFEST_ID)
        self.assertEqual([(r["input"], r["return"]) for r in recs],
                         [({"self_flags": 1}, "true")])

    def test_nested_calls_pair_returns_with_the_correct_input(self):
        fn = "src--recursive--parse"
        def event(message=None, ret=None, depth=0, span_id=1):
            span = {"name": fn, "depth": depth, "fm_span_id": span_id}
            fields = {"return": ret} if ret is not None else {"message": message}
            return json.dumps({"span": span, "fields": fields, "target": "parser"})
        lines = [
            event("new", depth=0, span_id=1), event("new", depth=1, span_id=2),
            event(ret="inner", depth=1, span_id=2),
            event("close", depth=1, span_id=2),
            event(ret="outer", depth=0, span_id=1),
            event("close", depth=0, span_id=1),
        ]
        recs = parse_records(lines, fn)
        self.assertEqual([(r["input"]["depth"], r["return"]) for r in recs],
                         [(0, "outer"), (1, "inner")])

    def test_interleaved_threads_pair_by_unique_span_id(self):
        fn = "src--parallel--parse"
        def event(message=None, ret=None, label="A", span_id=1):
            span = {"name": fn, "label": label, "fm_span_id": span_id}
            fields = {"return": ret} if ret is not None else {"message": message}
            return json.dumps({"span": span, "fields": fields, "target": "parser"})
        lines = [
            event("new", label="A", span_id=10),
            event("new", label="B", span_id=20),
            event(ret="ret-A", label="A", span_id=10),
            event("close", label="A", span_id=10),
            event(ret="ret-B", label="B", span_id=20),
            event("close", label="B", span_id=20),
        ]
        recs = parse_records(lines, fn)
        self.assertEqual(
            [(record["input"]["label"], record["return"]) for record in recs],
            [("A", "ret-A"), ("B", "ret-B")],
        )

    def test_missing_span_id_fails_closed(self):
        lines = _raw_events()
        for event in lines:
            event["span"].pop("fm_span_id", None)
        with self.assertRaisesRegex(ReplayError, "span ID"):
            parse_records([json.dumps(event) for event in lines], MANIFEST_ID)

    def test_reused_closed_span_id_fails_closed(self):
        first = _raw_events(span_id=7, flags=1, ret="true")
        second = _raw_events(span_id=7, flags=2, ret="false")
        with self.assertRaisesRegex(ReplayError, "duplicate.*span ID"):
            parse_records(
                [json.dumps(event) for event in first + second], MANIFEST_ID,
            )

    def test_malformed_json_or_event_shapes_fail_closed(self):
        cases = [
            ["{truncated"],
            [json.dumps("not-an-object")],
            [json.dumps({"span": [], "fields": {}})],
            [json.dumps({"span": None, "fields": {}})],
            [json.dumps({"fields": {}})],
            [json.dumps({
                "span": {"name": MANIFEST_ID, "fm_span_id": 1},
                "fields": [],
            })],
            [json.dumps({
                "span": {"name": MANIFEST_ID, "fm_span_id": 1},
                "fields": None,
            })],
            [json.dumps({
                "span": {"name": "src--other--function"},
                "fields": [],
            })],
            [json.dumps({"span": {}, "fields": {}})],
            [json.dumps({
                "span": {"name": "src--other--function"},
                "fields": {},
            })],
        ]
        for lines in cases:
            with self.subTest(lines=lines), self.assertRaises(ReplayError):
                parse_records(lines, MANIFEST_ID)


class ReplayCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.context = _context(self.tmp)
        self.context.probe_path.write_text("int main(void) { return 0; }\n")

    def test_uses_argv_trusted_binary_and_context_paths(self):
        seen = []
        def run(argv, **kwargs):
            seen.append((argv, kwargs))
            Path(kwargs["env"]["FM_AUDIT_LOG"]).write_text(
                "\n".join(json.dumps(e) for e in _raw_events())
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        recipe = _submission()["phenomenon"]
        records = default_replay_capture(
            self.context, recipe, process_runner=run,
        )
        self.assertEqual(records[0]["return"], "false")
        argv, kwargs = seen[0]
        self.assertEqual(argv[0], "/trusted/ccc-audit")
        self.assertEqual(argv[1:3], ["-std=c11", str(self.context.probe_path)])
        self.assertNotIn("bash", argv)
        self.assertEqual(kwargs["env"]["FM_AUDIT_FN"], MANIFEST_ID)
        self.assertTrue(str(argv[-1]).startswith(str(self.context.scratch_dir)))

    def test_compile_failure_is_not_zero_call_evidence(self):
        run = mock.Mock(return_value=SimpleNamespace(
            returncode=1, stdout="", stderr="compile failed"
        ))
        with self.assertRaisesRegex(ReplayError, "compile failed"):
            default_replay_capture(
                self.context, _submission()["phenomenon"], process_runner=run,
            )

    def test_missing_return_event_is_not_boundary_evidence(self):
        def run(argv, **kwargs):
            events = [
                event for event in _raw_events()
                if "return" not in event["fields"]
            ]
            Path(kwargs["env"]["FM_AUDIT_LOG"]).write_text(
                "\n".join(json.dumps(event) for event in events)
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with self.assertRaisesRegex(ReplayError, "no matching return event"):
            default_replay_capture(
                self.context,
                _submission()["phenomenon"],
                process_runner=run,
            )

    def test_nonzero_compile_keeps_complete_replay_trace(self):
        def run(argv, **kwargs):
            Path(kwargs["env"]["FM_AUDIT_LOG"]).write_text(
                "\n".join(json.dumps(e) for e in _raw_events())
            )
            return SimpleNamespace(returncode=1, stdout="", stderr="expected rejection")

        recipe = {
            "mode": "syntax", "standard": "gnu23",
            "extra_args": ["-pedantic"], "expected_kind": "accept_reject_differs",
        }
        records = default_replay_capture(
            self.context, recipe, process_runner=run,
        )
        self.assertEqual(len(records), 1)

    def test_nonzero_compile_rejects_complete_record_plus_malformed_tail(self):
        def run(argv, **kwargs):
            valid = "\n".join(json.dumps(e) for e in _raw_events())
            Path(kwargs["env"]["FM_AUDIT_LOG"]).write_text(
                valid + "\n{truncated\n"
            )
            return SimpleNamespace(returncode=1, stdout="", stderr="expected rejection")

        with self.assertRaisesRegex(ReplayError, "invalid JSON"):
            default_replay_capture(
                self.context,
                _submission()["phenomenon"],
                process_runner=run,
            )

    def test_replay_uses_submitted_compile_recipe(self):
        seen = []

        def run(argv, **kwargs):
            seen.append(list(argv))
            Path(kwargs["env"]["FM_AUDIT_LOG"]).write_text(
                "\n".join(json.dumps(e) for e in _raw_events())
            )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        recipe = {
            "mode": "syntax", "standard": "c23",
            "extra_args": ["-O2"], "expected_kind": "accept_reject_differs",
        }
        default_replay_capture(self.context, recipe, process_runner=run)
        self.assertEqual(seen[0][:3], ["/trusted/ccc-audit", "-std=c23", "-O2"])
        self.assertIn("-fsyntax-only", seen[0])

    def test_timeout_is_a_structured_replay_error(self):
        run = mock.Mock(side_effect=__import__("subprocess").TimeoutExpired(["ccc"], 120))
        with self.assertRaisesRegex(ReplayError, "failed to execute"):
            default_replay_capture(
                self.context, _submission()["phenomenon"], process_runner=run,
            )

    def test_rejects_symlink_noncanonical_and_non_c_probe(self):
        outside = self.tmp / "outside.c"
        outside.write_text("int main(void){}")
        self.context.probe_path.unlink()
        self.context.probe_path.symlink_to(outside)
        cases = [
            self.context.probe_path,
            self.context.validation_dir / "../outside.c",
            self.context.validation_dir / f"_probe_{MANIFEST_ID}.txt",
        ]
        for path in cases:
            with self.subTest(path=path):
                context = SimpleNamespace(**{**self.context.__dict__, "probe_path": path})
                with self.assertRaisesRegex(ReplayError, "probe"):
                    default_replay_capture(
                        context, _submission()["phenomenon"],
                        process_runner=mock.Mock(),
                    )


class ExactValueTests(unittest.TestCase):
    def test_json_types_do_not_collapse(self):
        self.assertNotEqual(canonical_value(0), canonical_value("0"))
        self.assertNotEqual(canonical_value(False), canonical_value(0))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.context = _context(self.tmp)

    def records(self, **kwargs):
        return parse_records([json.dumps(e) for e in _raw_events(**kwargs)], MANIFEST_ID)

    def test_accepts_exact_automatic_witness(self):
        self.assertIsNone(_gate(self.records()).check(_submission(), self.context))

    def test_rejects_confirmed_l0_without_a_patch_attempt(self):
        rejection = _gate(self.records()).check(
            _submission(grade="L0"), self.context,
        )
        self.assertEqual(rejection.check, "L1-attempt")
        self.assertIn("must first submit", rejection.reason)
        self.assertIn("only a failed Gate verification", rejection.reason)

    def test_requires_context_argument(self):
        with self.assertRaises(TypeError):
            _gate(self.records()).check(_submission())

    def test_rejects_submission_identity_mismatch(self):
        for field in ("id", "function_id"):
            with self.subTest(field=field):
                sub = _submission()
                sub[field] = "wrong"
                rejection = _gate(self.records()).check(sub, self.context)
                self.assertEqual(rejection.check, "identity")

    def test_rejects_noncanonical_probe_claim(self):
        sub = _submission()
        sub["witness"]["probe"] = "other.c"
        self.assertEqual(_gate(self.records()).check(sub, self.context).check, "identity")

    def test_rejects_wrong_span_identity(self):
        records = self.records()
        records[0]["manifest_id"] = "src--other--is_const"
        self.assertEqual(_gate(records).check(_submission(), self.context).check, "replay")

    def test_rejects_out_of_range_call_index(self):
        rejection = _gate(self.records()).check(_submission(call_index=5), self.context)
        self.assertEqual(rejection.check, "replay")

    def test_rejects_zero_records(self):
        self.assertEqual(_gate([]).check(_submission(), self.context).check, "L0")

    def test_rejects_trace_without_matching_independent_coverage(self):
        records = self.records()
        for count in (0, 2):
            with self.subTest(count=count):
                rejection = _gate(records, coverage_count=count).check(
                    _submission(), self.context,
                )
                self.assertEqual(rejection.check, "L0")
                self.assertIn("coverage", rejection.reason)

    def test_rejects_tampered_actual_output(self):
        rejection = _gate(self.records()).check(_submission(actual="true"), self.context)
        self.assertIn("actual_output", rejection.reason)

    def test_captured_input_keys_must_match_exactly(self):
        for value in ({}, {"self_flags": 0, "invented": 1}):
            with self.subTest(value=value):
                sub = _submission()
                sub["witness"]["captured_input"] = value
                rejection = _gate(self.records()).check(sub, self.context)
                self.assertIn("captured_input keys", rejection.reason)

    def test_captured_input_json_types_must_match(self):
        sub = _submission(flags="0")
        rejection = _gate(self.records(flags=0)).check(sub, self.context)
        self.assertIn("captured_input.self_flags", rejection.reason)

    def test_condition_a_requires_no_harness_contract(self):
        # The validator agent owns the semantic judgment. A normal context has
        # no condition expression or ID for the harness to evaluate.
        self.assertIsNone(
            _gate(self.records(flags=8, ret="true")).check(
                _submission(flags=8, actual="true"), self.context,
            )
        )

    def test_gate_passes_the_submitted_recipe_to_both_boundary_checks(self):
        sub = _submission()
        seen = []
        gate = Gate(
            replay_capture=lambda context, recipe: (
                seen.append(("replay", recipe)), self.records()
            )[1],
            coverage_runner=lambda context, recipe: (
                seen.append(("coverage", recipe)), 1
            )[1],
            phenomenon_runner=lambda recipe, context: SimpleNamespace(
                kind="run_exit_differs"
            ),
            l1_verifier=lambda _submission, _context: None,
        )
        self.assertIsNone(gate.check(sub, self.context))
        self.assertEqual(seen, [
            ("replay", sub["phenomenon"]),
            ("coverage", sub["phenomenon"]),
        ])

    def test_rejects_observed_phenomenon_kind_mismatch(self):
        rejection = _gate(self.records(), observed_kind="stdout_differs").check(
            _submission(), self.context
        )
        self.assertEqual(rejection.check, "phenomenon")

    def test_schema_v2_is_rejected_before_execution(self):
        sub = {"id": MANIFEST_ID, "function_id": FUNCTION_ID,
               "confirmation_status": "confirmed"}
        self.assertEqual(_gate(self.records()).check(sub, self.context).check, "schema")

    def test_not_confirmed_passes_schema_and_identity_only(self):
        sub = {
            "schema_version": 3, "id": MANIFEST_ID, "function_id": FUNCTION_ID,
            "confirmation_status": "not_confirmed", "attempts": 3, "notes": "n/a",
        }
        self.assertIsNone(_gate().check(sub, self.context))

    def test_span_offsets_normalized_but_structure_preserved(self):
        submitted = "Pointer(Array(Int, Some(IntLiteral(4, Span { start: 208, end: 209, file_id: 0 }))))"
        replayed = "Pointer(Array(Int, Some(IntLiteral(4, Span { start: 214, end: 215, file_id: 0 }))))"
        self.assertIsNone(_gate(self.records(ret=replayed)).check(
            _submission(actual=submitted), self.context
        ))
        rejection = _gate(self.records(ret="Pointer(Int)")).check(
            _submission(actual="Array(Int)"), self.context
        )
        self.assertEqual(rejection.check, "replay")

    def test_l1_failure_downgrades_to_l0(self):
        rejection = Rejection("L1", "patched compiler still shows a difference")
        sub = _submission(grade="L1")
        gate = _gate(self.records(), l1_verifier=lambda sub, context: rejection)
        self.assertIsNone(gate.check(sub, self.context))
        self.assertEqual(sub["grade"], "L0")
        self.assertIsNone(sub["l1_patch"])
        self.assertIn("L1 downgraded", sub["notes"])

    def test_invalid_patch_attempt_is_rejected_instead_of_downgraded(self):
        rejection = Rejection(
            "L1-attempt", "patch does not change the parsed target function body",
        )
        sub = _submission(grade="L1")
        gate = _gate(self.records(), l1_verifier=lambda sub, context: rejection)
        decision = gate.check(sub, self.context)
        self.assertEqual(decision, rejection)
        self.assertEqual(sub["grade"], "L1")
        self.assertEqual(sub["l1_patch"], "fix.patch")
        self.assertEqual(sub["notes"], "")

    def test_successful_l1_verification_retains_l1_grade(self):
        sub = _submission(grade="L1")
        gate = _gate(self.records(), l1_verifier=lambda sub, context: None)
        self.assertIsNone(gate.check(sub, self.context))
        self.assertEqual(sub["grade"], "L1")
        self.assertEqual(sub["l1_patch"], "fix.patch")


if __name__ == "__main__":
    unittest.main()
