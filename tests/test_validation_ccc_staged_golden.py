import copy
import difflib
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import src.validation_core.presets.ccc.staged_executor as staged_executor_module
from src.check_submission import Rejection
from src.phenomenon_runner import NoPhenomenonError, PhenomenonObservation
from src.validation_artifacts import publish_validation_artifact
from src.validation_context import sha256_directory
from src.validation_core.presets.ccc.staged_executor import (
    StagedCCCArtifactContext,
    StagedCCCContext,
    StagedCCCConsumerProviders,
    StagedCCCExecutor,
    StagedCCCFlowAttemptIdentity,
    StagedCCCFlowContext,
    StagedCCCFlowEvent,
    StagedCCCFlowMaterialization,
    StagedCCCFlowProviders,
    StagedCCCL1Context,
    StagedCCCL1Providers,
    StagedCCCProviders,
    StagedCCCGateResult,
    StagedCCCDecision,
)
from src.validation_core.presets.ccc.preset import CCC_LEGACY_PRESET
from tests.validator_legacy_golden import load_corpus


_ROOT = Path(__file__).resolve().parents[1]
_EXECUTABLE_ENTRYPOINTS = {
    "gate",
    "phenomenon",
    "trace_parser",
    "l1",
    "artifact",
    "consumer",
    "flow",
}
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
    "l1.non_building_patch_hard_reject",
    "l1.patch_still_differs_downgrade_eligible",
    "l1.sanity_output_change_downgrade_eligible",
    "artifact.bound_inputs_fail_closed_on_tamper",
    "consumer.current_verified_artifact_skips",
    "consumer.raw_or_tampered_artifact_reruns",
    "flow.inner_reject_does_not_run_outer",
    "flow.inner_reject_then_fix_same_session",
    "flow.inner_downgrade_preserves_outer_l1",
    "flow.outer_reject_starts_fresh_attempt_on_budget",
    "flow.direct_scratch_candidate_bypasses_submit",
}
_EXECUTION_INPUT_KEYS = {
    "case_id",
    "entrypoint",
    "submission_ref",
    "input_mutations",
    "drivers",
}
_L1_ORIGINAL = """use std::fmt;

struct Demo;

impl Demo {
    #[inline]
    fn target(&self) -> i32 { 1 }

    fn neighbor(&self) -> i32 { 2 }
}
"""
_L1_PATCHED = _L1_ORIGINAL.replace("{ 1 }", "{ 3 }")
_LEGACY_ARTIFACT_VERSIONS = {
    "result": 3,
    "sidecar": 5,
    "gate": "boundary-witness-v6",
}
_EXPECTED_MULTI_VARIANTS = {
    "artifact.bound_inputs_fail_closed_on_tamper": (
        "result",
        "sidecar",
        "source",
        "reasoning",
        "manifest",
        "toolchain.release",
        "toolchain.reference",
        "toolchain.audit",
        "toolchain.coverage",
        "probe",
        "patch",
        "sanity_corpus",
    ),
    "consumer.current_verified_artifact_skips": ("current_verified_v5",),
    "consumer.raw_or_tampered_artifact_reruns": (
        "raw_no_sidecar",
        "tampered_result_pair",
    ),
}
_INTENTIONAL_FLOW_DELTAS = {
    "flow.direct_scratch_candidate_bypasses_submit": {
        "decision": {
            "kind": "reject",
            "check": "submission",
            "reason_contains": "trusted Inner result",
        },
        "call_ledger": (),
        "published": False,
        "same_agent_retry": False,
        "new_attempt_on_budget": False,
        "outer_candidate": "none",
        "outer_calls": 0,
        "requested_grade": None,
        "final_grade": None,
        "scheduled_attempt": None,
    },
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


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode & 0o7777
        if path.is_symlink():
            entries.append((relative, "symlink", mode, path.readlink().as_posix()))
        elif path.is_file():
            entries.append((relative, "file", mode, path.read_bytes()))
        elif path.is_dir():
            entries.append((relative, "directory", mode, None))
        else:
            entries.append((relative, "other", mode, None))
    return tuple(entries)


def _materialize_legacy_pair(
    shadow_root: Path,
    submission: dict,
    versions: dict,
):
    shadow_root.mkdir()
    shadow_root = shadow_root.resolve()
    project = shadow_root / "project"
    validation = project / "fm_agent" / "bug_validation"
    validation.mkdir(parents=True)

    paths = {
        "logic_result": (
            project / "fm_agent" / "logic_verification_results" / "bug1.json"
        ),
        "manifest": project / "tools" / "audit_manifest.json",
        "source": project / "src" / "lib.rs",
        "release_binary": project / "target" / "release" / "ccc",
        "reference_binary": project / "toolchain" / "gcc",
        "audit_binary": project / "target" / "audit" / "ccc",
        "coverage_binary": project / "target" / "coverage" / "ccc",
        "sanity_corpus": project / "tools" / "validation_sanity_corpus",
        "probe": validation / "_probe_bug1.c",
        "l1_patch": validation / "bug1.l1.patch",
    }
    file_payloads = {
        "logic_result": b'{"verdict":"MISMATCH"}\n',
        "manifest": (
            b'{"functions":{"bug1":{"file":"src/lib.rs",'
            b'"fn_name":"target","source_line":1,"opts":{}}}}\n'
        ),
        "source": b"fn target() -> i32 { 1 }\n",
        "release_binary": b"release-ccc",
        "reference_binary": b"reference-gcc",
        "audit_binary": b"audit-ccc",
        "coverage_binary": b"coverage-ccc",
    }
    for label, payload in file_payloads.items():
        paths[label].parent.mkdir(parents=True, exist_ok=True)
        paths[label].write_bytes(payload)
    paths["sanity_corpus"].mkdir(parents=True)
    (paths["sanity_corpus"] / "one.c").write_text(
        "int main(void){return 0;}\n",
        encoding="utf-8",
    )

    if submission["confirmation_status"] == "confirmed":
        paths["probe"].write_text(
            "int main(void){return 0;}\n",
            encoding="utf-8",
        )
    if submission.get("grade") == "L1":
        paths["l1_patch"].write_text(
            "diff --git a/src/lib.rs b/src/lib.rs\n",
            encoding="utf-8",
        )

    scratch = validation / ".attempts" / "attempt-1"
    scratch.mkdir(parents=True)
    context = SimpleNamespace(
        bug_id="bug1",
        function_id="bug1",
        project_dir=project,
        validation_dir=validation,
        logic_result_path=paths["logic_result"],
        logic_result_sha256=_sha256_file(paths["logic_result"]),
        manifest_path=paths["manifest"],
        manifest_sha256=_sha256_file(paths["manifest"]),
        manifest_entry=SimpleNamespace(file="src/lib.rs"),
        source_sha256=_sha256_file(paths["source"]),
        release_ccc=paths["release_binary"],
        release_binary_sha256=_sha256_file(paths["release_binary"]),
        reference_cc=paths["reference_binary"],
        reference_binary_sha256=_sha256_file(paths["reference_binary"]),
        audit_ccc=paths["audit_binary"],
        audit_binary_sha256=_sha256_file(paths["audit_binary"]),
        coverage_ccc=paths["coverage_binary"],
        coverage_binary_sha256=_sha256_file(paths["coverage_binary"]),
        sanity_corpus_dir=paths["sanity_corpus"],
        sanity_corpus_sha256=sha256_directory(paths["sanity_corpus"]),
        scratch_dir=scratch,
    )
    result_path = validation / "bug1.result.json"
    gate_path = publish_validation_artifact(
        result_path,
        copy.deepcopy(submission),
        context,
        state="accepted",
        attempt=1,
    )
    published_result = json.loads(result_path.read_text(encoding="utf-8"))
    published_sidecar = json.loads(gate_path.read_text(encoding="utf-8"))
    if published_result["schema_version"] != versions["result"] \
            or published_sidecar["schema_version"] != versions["sidecar"] \
            or published_sidecar["gate_version"] != versions["gate"]:
        raise AssertionError("legacy publisher did not honor pinned driver versions")
    return SimpleNamespace(
        shadow_root=shadow_root,
        project_dir=project,
        result_path=result_path,
        gate_path=gate_path,
        paths=paths,
    )


def _mutate_legacy_pair(fixture, variant: str) -> None:
    if variant == "result":
        result = json.loads(fixture.result_path.read_text(encoding="utf-8"))
        result["notes"] = "tampered result"
        fixture.result_path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return
    if variant == "sidecar":
        sidecar = json.loads(fixture.gate_path.read_text(encoding="utf-8"))
        sidecar["attempt"] = 2
        fixture.gate_path.write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return
    if variant == "patch":
        fixture.paths["l1_patch"].unlink()
        return
    if variant == "sanity_corpus":
        (fixture.paths["sanity_corpus"] / "two.c").write_text(
            "int changed(void){return 1;}\n",
            encoding="utf-8",
        )
        return
    path_label = {
        "source": "source",
        "reasoning": "logic_result",
        "manifest": "manifest",
        "toolchain.release": "release_binary",
        "toolchain.reference": "reference_binary",
        "toolchain.audit": "audit_binary",
        "toolchain.coverage": "coverage_binary",
        "probe": "probe",
    }.get(variant)
    if path_label is None:
        raise AssertionError(f"unsupported artifact mutation: {variant}")
    path = fixture.paths[path_label]
    path.write_bytes(path.read_bytes() + b"\nchanged")


def _artifact_variants(drivers: dict) -> tuple[str, ...]:
    if set(drivers) != {"published_versions", "tampered_inputs"} \
            or drivers["published_versions"] != _LEGACY_ARTIFACT_VERSIONS \
            or drivers["tampered_inputs"] != [
                "result",
                "sidecar",
                "source",
                "reasoning",
                "manifest",
                "toolchain",
                "probe",
                "patch",
                "sanity_corpus",
            ]:
        raise AssertionError(f"unsupported artifact driver: {drivers}")
    expanded = []
    for token in drivers["tampered_inputs"]:
        if token == "toolchain":
            expanded.extend(
                (
                    "toolchain.release",
                    "toolchain.reference",
                    "toolchain.audit",
                    "toolchain.coverage",
                )
            )
        else:
            expanded.append(token)
    return tuple(expanded)


def _artifact_results(execution: dict, fixtures: dict, root: Path):
    submission = _apply_mutations(
        fixtures["submissions"][execution["submission_ref"]],
        execution["input_mutations"],
    )
    submission_before = copy.deepcopy(submission)
    results = []
    for index, variant in enumerate(_artifact_variants(execution["drivers"])):
        safe_variant = variant.replace(".", "-")
        fixture = _materialize_legacy_pair(
            root / f"artifact-{index:02d}-{safe_variant}",
            submission,
            execution["drivers"]["published_versions"],
        )
        _mutate_legacy_pair(fixture, variant)
        before = _tree_snapshot(fixture.shadow_root)
        result = StagedCCCExecutor().run_artifact_binding(
            submission,
            StagedCCCArtifactContext(
                bug_id="bug1",
                shadow_root=fixture.shadow_root,
                project_dir=fixture.project_dir,
                result_path=fixture.result_path,
            ),
        )
        if _tree_snapshot(fixture.shadow_root) != before:
            raise AssertionError("artifact observer mutated its shadow materialization")
        if result.observer_ledger != (
            "load_verified_artifact",
            "load_archived_legacy_certificate",
        ):
            raise AssertionError("artifact observer ledger is incomplete")
        results.append((variant, result, submission_before))
    if submission != submission_before:
        raise AssertionError("artifact execution mutated caller-owned submission")
    return results


def _consumer_results(execution: dict, fixtures: dict, root: Path):
    submission = _apply_mutations(
        fixtures["submissions"][execution["submission_ref"]],
        execution["input_mutations"],
    )
    submission_before = copy.deepcopy(submission)
    if set(execution["drivers"]) != {"artifact"}:
        raise AssertionError(f"unsupported consumer driver: {execution['drivers']}")
    artifact_driver = execution["drivers"]["artifact"]
    if artifact_driver == "current_verified_v5":
        variants = ("current_verified_v5",)
    elif artifact_driver == "raw_or_tampered":
        variants = ("raw_no_sidecar", "tampered_result_pair")
    else:
        raise AssertionError(f"unsupported consumer artifact: {artifact_driver}")

    results = []
    for index, variant in enumerate(variants):
        fixture = _materialize_legacy_pair(
            root / f"consumer-{index:02d}-{variant}",
            submission,
            _LEGACY_ARTIFACT_VERSIONS,
        )
        if variant == "raw_no_sidecar":
            fixture.gate_path.unlink()
        elif variant == "tampered_result_pair":
            _mutate_legacy_pair(fixture, "result")

        scheduled = []

        def schedule_agent():
            scheduled.append("agent")

        if variant == "current_verified_v5":
            def schedule_agent():
                raise AssertionError("verified legacy pair scheduled an Agent")

        before = _tree_snapshot(fixture.shadow_root)
        result = StagedCCCExecutor().run_legacy_consumer_shadow(
            submission,
            StagedCCCArtifactContext(
                bug_id="bug1",
                shadow_root=fixture.shadow_root,
                project_dir=fixture.project_dir,
                result_path=fixture.result_path,
            ),
            StagedCCCConsumerProviders(agent_scheduler=schedule_agent),
        )
        if _tree_snapshot(fixture.shadow_root) != before:
            raise AssertionError("resume observer mutated its shadow materialization")
        if result.observer_ledger != (
            "load_verified_artifact",
            "load_archived_legacy_certificate",
        ):
            raise AssertionError("resume observer ledger is incomplete")
        if variant != "current_verified_v5" and scheduled != ["agent"]:
            raise AssertionError("invalid legacy pair did not schedule one attempt")
        results.append((variant, result, submission_before))
    if submission != submission_before:
        raise AssertionError("consumer execution mutated caller-owned submission")
    return results


def _l1_context(root: Path) -> StagedCCCL1Context:
    shadow_root = (root / "l1-shadow").resolve()
    baseline = shadow_root / "baseline"
    project = shadow_root / "working"
    baseline_source = baseline / "src" / "lib.rs"
    baseline_source.parent.mkdir(parents=True)
    baseline_source.write_text(_L1_ORIGINAL, encoding="utf-8")
    (baseline / "Cargo.toml").write_text(
        '[package]\nname="fake_ccc"\nversion="0.1.0"\nedition="2021"\n'
        '[[bin]]\nname="ccc"\npath="src/main.rs"\n',
        encoding="utf-8",
    )
    (baseline / "src" / "main.rs").write_text(
        "fn main() {}\n",
        encoding="utf-8",
    )
    (baseline / "README.md").write_text("before\n", encoding="utf-8")
    shutil.copytree(baseline, project)

    validation = project / "fm_agent" / "bug_validation"
    validation.mkdir(parents=True)
    scratch = shadow_root / "scratch"
    scratch.mkdir()
    corpus = project / "seed_corpus"
    corpus.mkdir()
    (corpus / "one.c").write_text(
        "int main(void){return 0;}\n",
        encoding="utf-8",
    )
    release = project / "target" / "release" / "ccc"
    release.parent.mkdir(parents=True)
    release.write_bytes(b"base")
    reference = shadow_root / "trusted-gcc"
    reference.write_bytes(b"reference")
    return StagedCCCL1Context(
        bug_id="bug1",
        function_id="bug1",
        shadow_root=shadow_root,
        project_dir=project,
        baseline_project_dir=baseline,
        validation_dir=validation,
        scratch_dir=scratch,
        release_ccc=release,
        reference_cc=reference,
        sanity_corpus_dir=corpus,
        manifest_id="bug1",
        manifest_file="src/lib.rs",
        manifest_fn_name="target",
        manifest_occurrence=0,
        source_sha256=hashlib.sha256(_L1_ORIGINAL.encode("utf-8")).hexdigest(),
        sanity_corpus_sha256=sha256_directory(corpus),
    )


def _l1_result(execution: dict, fixtures: dict, root: Path):
    submission = _apply_mutations(
        fixtures["submissions"][execution["submission_ref"]],
        execution["input_mutations"],
    )
    submission_before = copy.deepcopy(submission)
    drivers = execution["drivers"]
    driver_shapes = {
        ("target_body_change", "failure", None, None): {"patch", "build"},
        ("valid_target_body_change", "success", "still_present", None): {
            "patch", "build", "phenomenon_after_patch",
        },
        ("valid_target_body_change", "success", "closed", "stdout_changed"): {
            "patch", "build", "phenomenon_after_patch", "sanity",
        },
    }
    driver_key = (
        drivers.get("patch"),
        drivers.get("build"),
        drivers.get("phenomenon_after_patch"),
        drivers.get("sanity"),
    )
    if driver_key not in driver_shapes or set(drivers) != driver_shapes[driver_key]:
        raise AssertionError(f"unsupported L1 driver shape: {drivers}")
    patched_source = {
        "target_body_change": _L1_PATCHED,
        "valid_target_body_change": _L1_PATCHED,
    }[drivers["patch"]]

    context = _l1_context(root)
    patch_lines = difflib.unified_diff(
        _L1_ORIGINAL.splitlines(True),
        patched_source.splitlines(True),
        fromfile="a/src/lib.rs",
        tofile="b/src/lib.rs",
    )
    patch = context.validation_dir / "bug1.l1.patch"
    patch.write_text("".join(patch_lines), encoding="utf-8")
    events = []
    repair_projects = []

    def source_copier(source, destination):
        if Path(source) != context.baseline_project_dir:
            raise AssertionError(f"unexpected L1 copy source: {source}")
        repair_project = Path(destination)
        if repair_project.name != "l1-project" \
                or repair_project.parent.parent != context.scratch_dir \
                or not repair_project.parent.name.startswith("l1-"):
            raise AssertionError(
                f"unexpected L1 repair destination: {repair_project}"
            )
        repair_projects.append(repair_project)
        events.append("copy")
        shutil.copytree(source, destination, dirs_exist_ok=True)

    def command_runner(argv, *, cwd, env=None):
        command = tuple(str(part) for part in argv)
        if len(repair_projects) != 1:
            raise AssertionError("L1 command ran without one repair project")
        repair_project = repair_projects[0]
        if command[:3] == ("git", "apply", "--check"):
            if Path(cwd) != repair_project or Path(command[-1]) != patch:
                raise AssertionError(f"misbound L1 apply check: {command}, {cwd}")
            events.append("apply_check")
            return 0, "", ""
        if command[:2] == ("git", "apply"):
            if Path(cwd) != repair_project or Path(command[-1]) != patch:
                raise AssertionError(f"misbound L1 apply: {command}, {cwd}")
            events.append("apply")
            (Path(cwd) / "src" / "lib.rs").write_text(
                patched_source,
                encoding="utf-8",
            )
            return 0, "", ""
        if command[:2] == ("cargo", "run"):
            manifest = Path(command[command.index("--manifest-path") + 1])
            if manifest != _ROOT / "tools" / "l1_scope" / "Cargo.toml":
                raise AssertionError(f"unexpected L1 scope manifest: {manifest}")
            target_dir = Path(command[command.index("--target-dir") + 1])
            if target_dir != repair_project.parent / "l1-scope-target":
                raise AssertionError(f"unexpected L1 scope target: {target_dir}")
            separator = command.index("--")
            scope_args = command[separator + 1:]
            if Path(cwd) != context.project_dir or scope_args != (
                str(repair_project.parent / "before.rs"),
                str(repair_project / "src" / "lib.rs"),
                context.manifest_fn_name,
                str(context.manifest_occurrence),
            ):
                raise AssertionError(f"misbound L1 scope check: {command}, {cwd}")
            events.append("scope")
            return 0, "", ""
        if command[:2] == ("cargo", "build"):
            if command != ("cargo", "build", "--release", "--bin", "ccc") \
                    or Path(cwd) != repair_project:
                raise AssertionError(f"misbound L1 build: {command}, {cwd}")
            events.append("build")
            if drivers["build"] == "failure":
                return 1, "", "synthetic compiler error"
            binary = Path(cwd) / "target" / "release" / "ccc"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"patched")
            return 0, "", ""
        raise AssertionError(f"unsupported L1 command: {command}")

    seen_recipes = []

    def phenomenon(recipe, phenomenon_context):
        if seen_recipes and recipe is not seen_recipes[0]:
            raise AssertionError("legacy L1 did not preserve recipe identity")
        seen_recipes.append(recipe)
        if Path(phenomenon_context.release_ccc) == context.release_ccc:
            if Path(phenomenon_context.project_dir) != context.project_dir:
                raise AssertionError("baseline phenomenon used the wrong project")
            events.append("phenomenon_base")
            return PhenomenonObservation(recipe["expected_kind"], ())
        repair_project = repair_projects[0]
        if Path(phenomenon_context.project_dir) != repair_project \
                or Path(phenomenon_context.release_ccc) \
                != repair_project / "target" / "release" / "ccc":
            raise AssertionError("patched phenomenon used the wrong repair variant")
        events.append("phenomenon_patched")
        remaining = drivers.get("phenomenon_after_patch")
        if remaining == "still_present":
            return PhenomenonObservation(recipe["expected_kind"], ())
        if remaining == "closed":
            raise NoPhenomenonError("no difference", ())
        raise AssertionError(f"unsupported patched phenomenon driver: {drivers}")

    def sanity(argv, *, cwd, env):
        if drivers.get("sanity") != "stdout_changed":
            raise AssertionError(f"unsupported L1 sanity driver: {drivers}")
        executable = Path(str(argv[0]))
        repair_project = repair_projects[0]
        if executable == context.release_ccc and Path(cwd) == context.project_dir:
            events.append("sanity_base")
            output = "base\n"
        elif executable == repair_project / "target" / "release" / "ccc" \
                and Path(cwd) == repair_project:
            events.append("sanity_patched")
            output = "patched\n"
        else:
            raise AssertionError(f"misbound L1 sanity call: {argv}, {cwd}")
        return 0, output, ""

    result = StagedCCCExecutor().run_l1(
        submission,
        context,
        StagedCCCL1Providers(
            source_copier=source_copier,
            command_runner=command_runner,
            phenomenon_runner=phenomenon,
            sanity_runner=sanity,
        ),
    )
    if submission != submission_before:
        raise AssertionError("staged L1 mutated its caller-owned submission")
    if (context.baseline_project_dir / "src" / "lib.rs").read_text(
        encoding="utf-8"
    ) != _L1_ORIGINAL:
        raise AssertionError("staged L1 mutated the frozen baseline")
    if (context.project_dir / "src" / "lib.rs").read_text(
        encoding="utf-8"
    ) != _L1_ORIGINAL:
        raise AssertionError("staged L1 mutated the working project")
    if list(context.scratch_dir.iterdir()):
        raise AssertionError("staged L1 left data in its disposable scratch")
    expected_events = ["copy", "apply_check", "apply", "scope", "build"]
    if drivers["build"] == "success":
        expected_events.extend(("phenomenon_base", "phenomenon_patched"))
    if drivers.get("sanity"):
        expected_events.extend(("sanity_base", "sanity_patched"))
    if events != expected_events:
        raise AssertionError(f"unexpected L1 event sequence: {events}")
    return result, submission_before


def _flow_gate_result(
    candidate: dict,
    *,
    decision: StagedCCCDecision,
    final_submission: dict | None = None,
    call_ledger: tuple[str, ...] = (),
) -> StagedCCCGateResult:
    final = copy.deepcopy(
        candidate if final_submission is None else final_submission
    )
    return StagedCCCGateResult(
        decision=decision,
        call_ledger=call_ledger,
        original_submission=copy.deepcopy(candidate),
        final_submission=final,
        requested_grade=candidate.get("grade"),
        final_grade=final.get("grade"),
        submitted_recipe_identity_preserved=True,
        preset_ref=CCC_LEGACY_PRESET.ref,
    )


def _flow_result(execution: dict, fixtures: dict, root: Path):
    submitted = _apply_mutations(
        fixtures["submissions"][execution["submission_ref"]],
        execution["input_mutations"],
    )
    submitted_before = copy.deepcopy(submitted)
    drivers = execution["drivers"]

    shadow_root = (root / "flow-shadow").resolve()
    snapshot = shadow_root / "snapshot"
    snapshot.mkdir(parents=True)
    (snapshot / "source.txt").write_text("frozen source\n", encoding="utf-8")
    (snapshot / "nested").mkdir()
    (snapshot / "nested" / "manifest.json").write_text(
        '{"id":"bug1"}\n',
        encoding="utf-8",
    )
    snapshot_sha256 = staged_executor_module._require_staged_tree(
        snapshot,
        "staged snapshot",
    )
    context = StagedCCCFlowContext(
        bug_id="bug1",
        function_id="bug1",
        shadow_root=shadow_root,
        snapshot_dir=snapshot,
        snapshot_sha256=snapshot_sha256,
        attempt_id="attempt-1",
        session_id="session-1",
        attempt_budget_remaining=drivers.get(
            "attempt_budget_remaining",
            True,
        ),
    )

    if "submissions" in drivers:
        if set(drivers) != {"submissions"}:
            raise AssertionError(f"unsupported flow submission driver: {drivers}")
        token_submissions = {
            "schema_invalid": {
                "schema_version": 3,
                "id": "bug1",
                "function_id": "bug1",
                "confirmation_status": "confirmed",
            },
            "not_confirmed": fixtures["submissions"]["not_confirmed"],
        }
        try:
            formal_submissions = [
                copy.deepcopy(token_submissions[token])
                for token in drivers["submissions"]
            ]
        except KeyError as exc:
            raise AssertionError(
                f"unsupported flow submission token: {exc.args[0]}"
            ) from exc
        events = tuple(
            StagedCCCFlowEvent("submit", candidate, True)
            for candidate in formal_submissions
        ) + (StagedCCCFlowEvent("session_exit", None, None),)
    elif drivers.get("agent_write") == "accepted-submission.json":
        if drivers != {
            "agent_write": "accepted-submission.json",
            "submit_command_called": False,
        }:
            raise AssertionError(f"unsupported direct scratch driver: {drivers}")
        events = (
            StagedCCCFlowEvent("direct_scratch", submitted, False),
            StagedCCCFlowEvent("session_exit", None, None),
        )
    else:
        allowed = {
            "inner",
            "inner_l1",
            "outer",
            "outer_l1",
            "attempt_budget_remaining",
        }
        if not set(drivers).issubset(allowed):
            raise AssertionError(f"unsupported flow driver: {drivers}")
        events = (
            StagedCCCFlowEvent("submit", submitted, True),
            StagedCCCFlowEvent("session_exit", None, None),
        )

    materializations = []
    provider_events = []
    published = []
    scheduled = []
    inner_final_submissions = []
    materialization_counter = 0

    def materialize(request):
        nonlocal materialization_counter
        materialization_counter += 1
        safe_role = request.role.replace("_", "-").lower()
        role_root = (
            shadow_root
            / "roles"
            / f"{materialization_counter:02d}-{safe_role}-{request.submission_ordinal}"
        )
        role_root.mkdir(parents=True)
        project = role_root / "project"
        shutil.copytree(snapshot, project)
        workspace = StagedCCCFlowMaterialization(
            role=request.role,
            root=role_root,
            project_dir=project,
            materialization_id=f"materialization-{materialization_counter}",
            snapshot_sha256=request.snapshot_sha256,
            attempt_id=request.attempt_id,
            session_id=request.session_id,
            submission_ordinal=request.submission_ordinal,
        )
        materializations.append(workspace)
        provider_events.append(
            f"materialize:{request.role}:{request.submission_ordinal}"
        )
        return workspace

    def destroy(workspace):
        provider_events.append(
            f"destroy:{workspace.role}:{workspace.submission_ordinal}"
        )
        shutil.rmtree(workspace.root)

    def inner_gate(candidate, workspace):
        self_contained = copy.deepcopy(candidate)
        if workspace.role != "B1":
            raise AssertionError("Inner did not receive a B1 materialization")
        if "submissions" in drivers:
            if candidate["confirmation_status"] == "confirmed":
                result = _flow_gate_result(
                    candidate,
                    decision=StagedCCCDecision(
                        "reject",
                        "schema",
                        "witness is required for a confirmed submission",
                    ),
                )
            else:
                result = _flow_gate_result(
                    candidate,
                    decision=StagedCCCDecision("accept", None, None),
                )
        elif "inner_l1" in drivers:
            if drivers["inner_l1"] != {"kind": "rejection", "check": "L1"}:
                raise AssertionError(f"unsupported Inner L1 driver: {drivers}")
            final = copy.deepcopy(candidate)
            final["grade"] = "L0"
            final["l1_patch"] = None
            result = _flow_gate_result(
                candidate,
                decision=StagedCCCDecision("accept", None, None),
                final_submission=final,
                call_ledger=("replay", "coverage", "phenomenon", "l1"),
            )
        else:
            inner_driver = drivers.get("inner", {"kind": "accept"})
            if inner_driver == {"kind": "accept"}:
                result = _flow_gate_result(
                    candidate,
                    decision=StagedCCCDecision("accept", None, None),
                )
            elif inner_driver == {"kind": "rejection", "check": "schema"}:
                result = _flow_gate_result(
                    candidate,
                    decision=StagedCCCDecision(
                        "reject",
                        "schema",
                        "witness is required for a confirmed submission",
                    ),
                )
            else:
                raise AssertionError(f"unsupported Inner driver: {inner_driver}")
        inner_final_submissions.append(copy.deepcopy(result.final_submission))
        if candidate != self_contained:
            raise AssertionError("Inner helper mutated its caller-owned candidate")
        return result

    def outer_gate(candidate, workspace):
        if workspace.role != "B2":
            raise AssertionError("Outer did not receive a B2 materialization")
        if not inner_final_submissions:
            raise AssertionError("Outer ran before an accepted Inner result")
        if "inner_l1" in drivers:
            if candidate.get("grade") != "L1" \
                    or not isinstance(candidate.get("l1_patch"), str):
                raise AssertionError("Outer did not receive the original L1 candidate")
            if inner_final_submissions[-1].get("grade") != "L0":
                raise AssertionError("Inner L1 driver did not create a private L0")
        outer_driver = drivers.get("outer", {"kind": "accept"})
        if outer_driver == {"kind": "rejection", "check": "schema"}:
            return _flow_gate_result(
                candidate,
                decision=StagedCCCDecision(
                    "reject",
                    "schema",
                    "accepted candidate unreadable: malformed JSON",
                ),
            )
        if outer_driver != {"kind": "accept"}:
            raise AssertionError(f"unsupported Outer driver: {outer_driver}")
        if "outer_l1" in drivers:
            if drivers["outer_l1"] != {"kind": "rejection", "check": "L1"}:
                raise AssertionError(f"unsupported Outer L1 driver: {drivers}")
            final = copy.deepcopy(candidate)
            final["grade"] = "L0"
            final["l1_patch"] = None
            return _flow_gate_result(
                candidate,
                decision=StagedCCCDecision("accept", None, None),
                final_submission=final,
                call_ledger=("replay", "coverage", "phenomenon", "l1"),
            )
        return _flow_gate_result(
            candidate,
            decision=StagedCCCDecision("accept", None, None),
        )

    def legacy_outer(candidate, workspace):
        if workspace.role != "legacy_observer":
            raise AssertionError("legacy observer received a trusted B2 role")
        return _flow_gate_result(
            candidate,
            decision=StagedCCCDecision("accept", None, None),
        )

    def schedule(request):
        if request.previous_attempt_id != context.attempt_id \
                or request.previous_session_id != context.session_id \
                or request.snapshot_sha256 != context.snapshot_sha256:
            raise AssertionError("scheduler received the wrong predecessor")
        provider_events.append("schedule_new_attempt")
        scheduled.append(request)
        return StagedCCCFlowAttemptIdentity("attempt-2", "session-2")

    def publish(candidate, workspace):
        if workspace.role != "B2":
            raise AssertionError("shadow publication did not originate from B2")
        published.append(copy.deepcopy(candidate))
        provider_events.append("observe_publishable")

    result = StagedCCCExecutor().run_isolated_flow(
        events,
        context,
        StagedCCCFlowProviders(
            materialize_role=materialize,
            destroy_role=destroy,
            inner_gate=inner_gate,
            outer_gate=outer_gate,
            legacy_outer_observer=legacy_outer,
            schedule_new_attempt=schedule,
            observe_publishable=publish,
        ),
    )
    if submitted != submitted_before:
        raise AssertionError("staged flow mutated its caller-owned submission")
    if staged_executor_module._require_staged_tree(
        snapshot,
        "staged snapshot",
    ) != snapshot_sha256:
        raise AssertionError("staged flow mutated its frozen snapshot")
    if any(workspace.root.exists() for workspace in materializations):
        raise AssertionError("staged flow left a disposable role materialization")
    if len({workspace.root for workspace in materializations}) \
            != len(materializations):
        raise AssertionError("staged flow reused a role root")
    if len({workspace.materialization_id for workspace in materializations}) \
            != len(materializations):
        raise AssertionError("staged flow reused a materialization identity")
    if any(
        workspace.snapshot_sha256 != snapshot_sha256
        or workspace.attempt_id != context.attempt_id
        or workspace.session_id != context.session_id
        for workspace in materializations
    ):
        raise AssertionError("staged flow role identity drifted")
    if bool(published) != result.published:
        raise AssertionError("shadow publication ledger disagrees with the result")
    if len(scheduled) != int(result.new_attempt_on_budget):
        raise AssertionError("attempt scheduler ledger disagrees with the result")
    if result.new_attempt_on_budget:
        if result.scheduled_attempt != StagedCCCFlowAttemptIdentity(
            "attempt-2",
            "session-2",
        ):
            raise AssertionError("attempt scheduler did not return a fresh identity")
    elif result.scheduled_attempt is not None:
        raise AssertionError("unscheduled flow carried an attempt identity")
    if tuple(result.role_ledger).count("session_exit") != 1:
        raise AssertionError("staged flow did not close exactly one Agent session")
    return result, submitted_before


def _execute_projected_variants(
    execution: dict,
    fixtures: dict,
    context: StagedCCCContext,
):
    if set(execution) != _EXECUTION_INPUT_KEYS:
        raise AssertionError("executor projection contains unexpected fields")
    if execution["entrypoint"] == "gate":
        result, submitted = _gate_result(execution, fixtures, context)
        return (("gate", result, submitted),)
    if execution["entrypoint"] == "phenomenon":
        return (("phenomenon", _phenomenon_result(execution, context), None),)
    if execution["entrypoint"] == "trace_parser":
        return (("trace_parser", _trace_result(execution, fixtures), None),)
    if execution["entrypoint"] == "l1":
        result, submitted = _l1_result(
            execution,
            fixtures,
            context.project_dir,
        )
        return (("l1", result, submitted),)
    if execution["entrypoint"] == "artifact":
        return _artifact_results(
            execution,
            fixtures,
            context.project_dir,
        )
    if execution["entrypoint"] == "consumer":
        return _consumer_results(
            execution,
            fixtures,
            context.project_dir,
        )
    if execution["entrypoint"] == "flow":
        result, submitted = _flow_result(
            execution,
            fixtures,
            context.project_dir,
        )
        return (("flow", result, submitted),)
    raise AssertionError(f"unsupported staged entrypoint: {execution['entrypoint']}")


class StagedCCCGoldenTests(unittest.TestCase):
    def test_exactly_thirty_two_cells_are_executed_with_pinned_policies(self):
        corpus = load_corpus()
        executable = [
            case for case in corpus["cases"]
            if case["entrypoint"] in _EXECUTABLE_ENTRYPOINTS
        ]
        deferred = [
            case for case in corpus["cases"]
            if case["entrypoint"] not in _EXECUTABLE_ENTRYPOINTS
        ]
        self.assertEqual(len(executable), 32)
        self.assertEqual(
            {case["case_id"] for case in executable},
            _EXECUTABLE_CASE_IDS,
        )
        self.assertEqual(
            {case["entrypoint"] for case in executable},
            {
                "gate",
                "phenomenon",
                "trace_parser",
                "l1",
                "artifact",
                "consumer",
                "flow",
            },
        )
        self.assertEqual(
            {case["parity_policy"] for case in executable},
            {"must_match", "legacy_known_gap", "intentional_cutover_delta"},
        )
        self.assertEqual(
            sum(case["parity_policy"] == "must_match" for case in executable),
            30,
        )
        self.assertEqual(
            {
                case["case_id"] for case in executable
                if case["parity_policy"] == "legacy_known_gap"
            },
            {"gate.condition_a_not_mechanical"},
        )
        self.assertEqual(deferred, [])
        self.assertEqual(
            {
                case["case_id"] for case in executable
                if case["parity_policy"] == "intentional_cutover_delta"
            },
            set(_INTENTIONAL_FLOW_DELTAS),
        )

    def test_staged_executor_accounts_for_all_thirty_two_cells(self):
        corpus = load_corpus()
        fixtures = corpus["fixtures"]
        concrete_execution_count = 0
        observed_legacy_deltas = set()
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
                concrete_results = _execute_projected_variants(
                    execution,
                    fixtures,
                    context,
                )
                concrete_variants = tuple(
                    variant for variant, _result, _submitted in concrete_results
                )
                if case["case_id"] in _EXPECTED_MULTI_VARIANTS:
                    self.assertEqual(
                        concrete_variants,
                        _EXPECTED_MULTI_VARIANTS[case["case_id"]],
                    )
                else:
                    self.assertEqual(len(concrete_results), 1)
                concrete_execution_count += len(concrete_results)
                expected = case["expected"]
                parity_policy = case["parity_policy"]
                if case["entrypoint"] not in {"artifact", "consumer"}:
                    self.assertEqual(list(project.rglob("*.result.json")), [])
                    self.assertEqual(list(project.rglob("*.gate.json")), [])
                for variant, result, submitted in concrete_results:
                    with self.subTest(
                        case_id=case["case_id"],
                        variant=variant,
                    ):
                        compared_result = result
                        if parity_policy == "intentional_cutover_delta":
                            self.assertEqual(case["entrypoint"], "flow")
                            self.assertIsNotNone(result.legacy_observation)
                            compared_result = result.legacy_observation
                            observed_legacy_deltas.add(case["case_id"])
                            target = _INTENTIONAL_FLOW_DELTAS[case["case_id"]]
                            self.assertEqual(
                                result.decision.kind,
                                target["decision"]["kind"],
                            )
                            self.assertEqual(
                                result.decision.check,
                                target["decision"]["check"],
                            )
                            self.assertIn(
                                target["decision"]["reason_contains"],
                                result.decision.raw_reason,
                            )
                            self.assertEqual(
                                result.call_ledger,
                                target["call_ledger"],
                            )
                            self.assertEqual(
                                result.published,
                                target["published"],
                            )
                            self.assertEqual(
                                result.original_submission,
                                submitted,
                            )
                            self.assertEqual(
                                result.final_submission,
                                submitted,
                            )
                            self.assertEqual(
                                result.requested_grade,
                                target["requested_grade"],
                            )
                            self.assertEqual(
                                result.final_grade,
                                target["final_grade"],
                            )
                            self.assertEqual(
                                result.same_agent_retry,
                                target["same_agent_retry"],
                            )
                            self.assertEqual(
                                result.new_attempt_on_budget,
                                target["new_attempt_on_budget"],
                            )
                            self.assertEqual(
                                result.outer_candidate,
                                target["outer_candidate"],
                            )
                            self.assertEqual(
                                result.outer_calls,
                                target["outer_calls"],
                            )
                            self.assertEqual(
                                result.scheduled_attempt,
                                target["scheduled_attempt"],
                            )
                        elif case["entrypoint"] == "flow":
                            self.assertIsNone(result.legacy_observation)
                        self.assertEqual(
                            compared_result.decision.kind,
                            expected["decision"]["kind"],
                        )
                        self.assertEqual(
                            compared_result.decision.check,
                            expected["decision"]["check"],
                        )
                        reason = expected["decision"]["reason_contains"]
                        if reason is not None:
                            self.assertIsNotNone(
                                compared_result.decision.raw_reason
                            )
                            self.assertIn(
                                reason,
                                compared_result.decision.raw_reason,
                            )
                        self.assertEqual(
                            list(compared_result.call_ledger),
                            expected["external_calls"],
                        )

                        if case["entrypoint"] in {
                            "gate",
                            "l1",
                            "artifact",
                            "consumer",
                            "flow",
                        }:
                            expected_final = _apply_mutations(
                                submitted,
                                expected["submission_mutations"],
                            )
                            self.assertEqual(
                                compared_result.original_submission,
                                submitted,
                            )
                            self.assertEqual(
                                compared_result.final_submission,
                                expected_final,
                            )
                            self.assertEqual(
                                compared_result.requested_grade,
                                expected["flow"]["requested_grade"],
                            )
                            self.assertEqual(
                                compared_result.final_grade,
                                expected["flow"]["inner_final_grade"],
                            )
                            if case["entrypoint"] == "gate":
                                self.assertTrue(
                                    result.submitted_recipe_identity_preserved
                                )
                            if case["entrypoint"] != "flow":
                                self.assertEqual(
                                    expected["flow"]["outer_calls"],
                                    0,
                                )

                        if case["entrypoint"] in {"gate", "l1"}:
                            self.assertFalse(expected["flow"]["published"])
                        if case["entrypoint"] in {
                            "artifact",
                            "consumer",
                            "flow",
                        }:
                            self.assertEqual(
                                compared_result.published,
                                expected["flow"]["published"],
                            )
                            self.assertEqual(
                                compared_result.same_agent_retry,
                                expected["flow"]["same_agent_retry"],
                            )
                            self.assertEqual(
                                compared_result.new_attempt_on_budget,
                                expected["flow"]["new_attempt_on_budget"],
                            )
                            self.assertEqual(
                                compared_result.outer_candidate,
                                expected["flow"]["outer_candidate"],
                            )
                            self.assertEqual(
                                compared_result.outer_calls,
                                expected["flow"]["outer_calls"],
                            )

                        if case["case_id"] == "trace.interleaved_span_pairing":
                            self.assertEqual(
                                [
                                    (
                                        record["input"]["self_flags"],
                                        record["return"],
                                    )
                                    for record in result.records
                                ],
                                [(0, "false"), (8, "true")],
                            )
        self.assertEqual(concrete_execution_count, 44)
        self.assertEqual(observed_legacy_deltas, set(_INTENTIONAL_FLOW_DELTAS))


if __name__ == "__main__":
    unittest.main()
