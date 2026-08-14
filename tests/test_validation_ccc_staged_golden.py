import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.check_submission import Rejection
from src.phenomenon_runner import PhenomenonObservation
from src.validation_core.presets.ccc.staged_executor import (
    StagedCCCContext,
    StagedCCCExecutor,
    StagedCCCProviders,
)
from tests.validator_legacy_golden import load_corpus


_EXECUTABLE_ENTRYPOINTS = {"gate", "phenomenon", "trace_parser"}
_EXECUTABLE_CASE_IDS = {
    "gate.not_confirmed_fast_path",
    "gate.schema_v2_pre_execution_reject",
    "gate.identity_mismatch",
    "gate.exact_boundary_l1_accept",
    "gate.witness_output_mismatch",
    "gate.coverage_count_mismatch",
    "gate.phenomenon_kind_mismatch",
    "gate.direct_l0_hard_reject_after_evidence",
    "gate.l1_behavior_failure_downgrades_l0",
    "gate.l1_attempt_invalid_hard_reject",
    "gate.condition_a_not_mechanical",
    "phenomenon.preprocess_normalized_text_diff",
    "phenomenon.syntax_accept_reject",
    "phenomenon.asm_success_output_ignored",
    "phenomenon.object_success_output_ignored",
    "phenomenon.run_build_accept_reject",
    "phenomenon.run_exit_diff",
    "phenomenon.run_stdout_diff",
    "phenomenon.both_compilers_fail",
    "trace.interleaved_span_pairing",
    "trace.missing_return_fails_closed",
}
_EXECUTION_INPUT_KEYS = {
    "case_id",
    "entrypoint",
    "submission_ref",
    "input_mutations",
    "drivers",
}


def _pointer_tokens(pointer: str) -> list[str]:
    return [token.replace("~1", "/").replace("~0", "~")
            for token in pointer.split("/")[1:]]


def _apply_mutations(document: object, mutations: list[dict]) -> object:
    target = copy.deepcopy(document)
    for mutation in mutations:
        tokens = _pointer_tokens(mutation["path"])
        parent = target
        for token in tokens[:-1]:
            parent = parent[int(token)] if type(parent) is list else parent[token]
        leaf = tokens[-1]
        if mutation["op"] == "remove":
            if type(parent) is list:
                del parent[int(leaf)]
            else:
                del parent[leaf]
        elif type(parent) is list:
            if mutation["op"] == "add" and leaf == "-":
                parent.append(copy.deepcopy(mutation["value"]))
            elif mutation["op"] == "add":
                parent.insert(int(leaf), copy.deepcopy(mutation["value"]))
            else:
                parent[int(leaf)] = copy.deepcopy(mutation["value"])
        else:
            parent[leaf] = copy.deepcopy(mutation["value"])
    return target


def _context(project: Path) -> StagedCCCContext:
    probe = project / "fm_agent" / "bug_validation" / "_probe_bug1.c"
    probe.parent.mkdir(parents=True)
    probe.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    scratch = project / "scratch"
    scratch.mkdir()
    return StagedCCCContext(
        bug_id="bug1",
        function_id="bug1",
        project_dir=project,
        probe_path=probe,
        scratch_dir=scratch,
        manifest_id="bug1",
        release_ccc=Path("/trusted/ccc"),
        reference_cc=Path("/trusted/gcc"),
    )


def _gate_result(execution: dict, fixtures: dict, context: StagedCCCContext):
    submission = _apply_mutations(
        fixtures["submissions"][execution["submission_ref"]],
        execution["input_mutations"],
    )
    submission_before = copy.deepcopy(submission)
    drivers = execution["drivers"]
    replay_driver = drivers.get(
        "replay",
        {"kind": "records", "records_ref": "one_call_false"},
    )
    if replay_driver["kind"] != "records":
        raise AssertionError(f"unsupported replay driver: {replay_driver}")
    records = copy.deepcopy(fixtures["records"][replay_driver["records_ref"]])
    coverage_driver = drivers.get(
        "coverage",
        {"kind": "count", "value": len(records)},
    )
    phenomenon_driver = drivers.get(
        "phenomenon",
        {
            "kind": "observation",
            "value": submission.get("phenomenon", {}).get("expected_kind"),
        },
    )
    l1_driver = drivers.get("l1", {"kind": "accept"})

    def replay(_context, _recipe):
        return copy.deepcopy(records)

    def coverage(_context, _recipe):
        if coverage_driver["kind"] != "count":
            raise AssertionError(f"unsupported coverage driver: {coverage_driver}")
        return coverage_driver["value"]

    def phenomenon(_recipe, _context):
        if phenomenon_driver["kind"] != "observation":
            raise AssertionError(
                f"unsupported phenomenon driver: {phenomenon_driver}"
            )
        return PhenomenonObservation(phenomenon_driver["value"], ())

    def l1(_candidate, _context):
        if l1_driver["kind"] == "accept":
            return None
        if l1_driver["kind"] == "rejection":
            return Rejection(l1_driver["check"], l1_driver["reason"])
        raise AssertionError(f"unsupported L1 driver: {l1_driver}")

    result = StagedCCCExecutor().run_gate(
        submission,
        context,
        StagedCCCProviders(
            replay_capture=replay,
            coverage_runner=coverage,
            phenomenon_runner=phenomenon,
            l1_verifier=l1,
        ),
    )
    if submission != submission_before:
        raise AssertionError("staged Gate mutated its caller-owned submission")
    return result, submission_before


def _phenomenon_result(execution: dict, context: StagedCCCContext):
    drivers = execution["drivers"]
    recipe = {
        "mode": drivers["mode"],
        "standard": "c11",
        "extra_args": [],
    }

    def runner(argv, **_kwargs):
        executable = Path(str(argv[0]))
        if executable == context.release_ccc:
            side = "ccc"
            phase = "build"
        elif executable == context.reference_cc:
            side = "gcc"
            phase = "build"
        elif executable == context.scratch_dir / "phenomenon-ccc.bin":
            side = "ccc"
            phase = "run"
        elif executable == context.scratch_dir / "phenomenon-gcc.bin":
            side = "gcc"
            phase = "run"
        else:
            raise AssertionError(f"unexpected executable: {executable}")

        if recipe["mode"] != "run":
            phase_driver = drivers[side]
            rc = phase_driver["rc"]
            stdout = phase_driver.get("stdout", "")
        elif phase == "build" and f"{side}_build" in drivers:
            phase_driver = drivers[f"{side}_build"]
            rc = phase_driver["rc"]
            stdout = phase_driver.get("stdout", "")
        elif phase == "build":
            phase_driver = drivers[side]
            rc = phase_driver["build_rc"]
            stdout = ""
        else:
            phase_driver = drivers[side]
            rc = phase_driver["run_rc"]
            stdout = phase_driver.get("stdout", "")

        if phase == "build" and rc == 0 and "-o" in argv:
            output = Path(argv[argv.index("-o") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(phase_driver.get("artifact", "binary"), encoding="utf-8")
        return rc, stdout, phase_driver.get("stderr", "")

    return StagedCCCExecutor().run_phenomenon(recipe, context, runner)


def _record_events(record: dict) -> tuple[dict, dict, dict]:
    span = {
        "name": record["manifest_id"],
        "fm_span_id": record["span_id"],
        **record["input"],
    }
    target = "ccc::frontend::parser::ast"
    return (
        {"fields": {"message": "new"}, "target": target, "span": span},
        {"fields": {"return": record["return"]}, "target": target, "span": span},
        {"fields": {"message": "close"}, "target": target, "span": span},
    )


def _trace_result(execution: dict, fixtures: dict):
    drivers = execution["drivers"]
    if "records_ref" in drivers:
        records = fixtures["records"][drivers["records_ref"]]
        events = [_record_events(record) for record in records]
        raw_events = [events[0][0], events[1][0], events[1][1],
                      events[1][2], events[0][1], events[0][2]]
    elif drivers.get("trace") == "entry_without_matching_return":
        record = fixtures["records"]["one_call_false"][0]
        new, _returned, close = _record_events(record)
        raw_events = [new, close]
    else:
        raise AssertionError(f"unsupported trace driver: {drivers}")
    lines = [json.dumps(event, sort_keys=True) for event in raw_events]
    return StagedCCCExecutor().parse_trace(lines, "bug1")


def _execute_projected_case(
    execution: dict,
    fixtures: dict,
    context: StagedCCCContext,
):
    if set(execution) != _EXECUTION_INPUT_KEYS:
        raise AssertionError("executor projection contains unexpected fields")
    if execution["entrypoint"] == "gate":
        return _gate_result(execution, fixtures, context)
    if execution["entrypoint"] == "phenomenon":
        return _phenomenon_result(execution, context), None
    if execution["entrypoint"] == "trace_parser":
        return _trace_result(execution, fixtures), None
    raise AssertionError(f"unsupported staged entrypoint: {execution['entrypoint']}")


class StagedCCCGoldenTests(unittest.TestCase):
    def test_exactly_twenty_one_cells_are_executed_and_eleven_are_deferred(self):
        corpus = load_corpus()
        executable = [
            case for case in corpus["cases"]
            if case["entrypoint"] in _EXECUTABLE_ENTRYPOINTS
        ]
        deferred = [
            case for case in corpus["cases"]
            if case["entrypoint"] not in _EXECUTABLE_ENTRYPOINTS
        ]
        self.assertEqual(len(executable), 21)
        self.assertEqual(
            {case["case_id"] for case in executable},
            _EXECUTABLE_CASE_IDS,
        )
        self.assertEqual(
            {case["entrypoint"] for case in executable},
            {"gate", "phenomenon", "trace_parser"},
        )
        self.assertEqual(
            {case["parity_policy"] for case in executable},
            {"must_match", "legacy_known_gap"},
        )
        self.assertEqual(
            sum(case["parity_policy"] == "must_match" for case in executable),
            20,
        )
        self.assertEqual(
            {
                case["case_id"] for case in executable
                if case["parity_policy"] == "legacy_known_gap"
            },
            {"gate.condition_a_not_mechanical"},
        )
        self.assertEqual(
            {case["entrypoint"] for case in deferred},
            {"flow", "l1", "artifact", "consumer"},
        )
        self.assertEqual(len(deferred), 11)
        self.assertEqual(
            sum(
                case["parity_policy"] == "intentional_cutover_delta"
                for case in deferred
            ),
            1,
        )

    def test_staged_executor_matches_all_twenty_one_executable_cells(self):
        corpus = load_corpus()
        fixtures = corpus["fixtures"]
        for case in corpus["cases"]:
            if case["entrypoint"] not in _EXECUTABLE_ENTRYPOINTS:
                continue
            execution = {
                key: copy.deepcopy(case[key]) for key in _EXECUTION_INPUT_KEYS
            }
            self.assertNotIn("expected", execution)
            self.assertNotIn("parity_policy", execution)
            poison = AssertionError("staged golden execution used a host command")
            with self.subTest(case_id=case["case_id"]), \
                 tempfile.TemporaryDirectory() as temporary, \
                 mock.patch("subprocess.run", side_effect=poison), \
                 mock.patch("os.system", side_effect=poison):
                project = Path(temporary).resolve()
                context = _context(project)
                result, submitted = _execute_projected_case(
                    execution,
                    fixtures,
                    context,
                )
                self.assertEqual(list(project.rglob("*.result.json")), [])
                self.assertEqual(list(project.rglob("*.gate.json")), [])
                expected = case["expected"]
                self.assertEqual(result.decision.kind, expected["decision"]["kind"])
                self.assertEqual(result.decision.check, expected["decision"]["check"])
                reason = expected["decision"]["reason_contains"]
                if reason is not None:
                    self.assertIsNotNone(result.decision.raw_reason)
                    self.assertIn(reason, result.decision.raw_reason)
                self.assertEqual(
                    list(result.call_ledger),
                    expected["external_calls"],
                )

                if case["entrypoint"] == "gate":
                    expected_final = _apply_mutations(
                        submitted,
                        expected["submission_mutations"],
                    )
                    self.assertEqual(result.original_submission, submitted)
                    self.assertEqual(result.final_submission, expected_final)
                    self.assertEqual(
                        result.requested_grade,
                        expected["flow"]["requested_grade"],
                    )
                    self.assertEqual(
                        result.final_grade,
                        expected["flow"]["inner_final_grade"],
                    )
                    self.assertTrue(result.submitted_recipe_identity_preserved)
                    self.assertEqual(expected["flow"]["outer_calls"], 0)
                    self.assertFalse(expected["flow"]["published"])

                if case["case_id"] == "trace.interleaved_span_pairing":
                    self.assertEqual(
                        [(record["input"]["self_flags"], record["return"])
                         for record in result.records],
                        [(0, "false"), (8, "true")],
                    )


if __name__ == "__main__":
    unittest.main()
