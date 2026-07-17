import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
import src.prompts as prompts
import src.reasoner as reasoner_module
import src.verification as verification
from src.entry_reasoning_pipeline import _count_mismatches
from src.file_utils import (
    ResumeModeMismatchError,
    _all_bugs_candidate_paths,
    _candidate_sha256,
    _candidate_validation_error,
    _ensure_resume_mode_compatible,
    _json_sha256,
)


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _candidate(function="/project/example.py", counterexample="x = 0"):
    return {
        "function": function,
        "verdict": "MISMATCH",
        "gaps": {
            "spec_claim": "result is positive",
            "actual_behavior": "result is zero",
            "code_evidence": "return 0",
            "trigger_condition": counterexample,
            "counterexample": counterexample,
        },
    }


def test_spec_check_default_return_shape_is_unchanged(monkeypatch):
    response = json.dumps(
        {
            "verdict": "MISMATCH",
            "counterexample": "x = 0",
            "offending_statements": "return 0",
            "reason": "zero violates the post-condition",
        }
    )
    monkeypatch.setattr(prompts, "_retry_create", lambda *args: (response, {}))
    monkeypatch.setattr(prompts, "record_llm_exchange", lambda *args: None)

    legacy = prompts._check_post_implies_spec(
        "return 0", "result == 0", "result > 0", "", "Python"
    )
    all_bugs = prompts._check_post_implies_spec(
        "return 0",
        "result == 0",
        "result > 0",
        "",
        "Python",
        include_counterexample=True,
    )

    assert legacy == (
        False,
        "return 0",
        "result == 0",
        "zero violates the post-condition",
    )
    assert all_bugs == legacy + ("x = 0",)


def test_all_bugs_preserves_violations_when_later_generation_raises(monkeypatch):
    monkeypatch.setattr(
        reasoner_module,
        "_split_into_blocks_braced",
        lambda *args: ["return 0", "return 1"],
    )
    post_conditions = iter(["result == 0", RuntimeError("provider failed")])

    def generate(*args, **kwargs):
        value = next(post_conditions)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(reasoner_module, "_generate_block_post_condition", generate)
    monkeypatch.setattr(
        reasoner_module, "_has_terminating_statement", lambda *args: True
    )

    def check(*args, include_counterexample=False, **kwargs):
        assert include_counterexample is True
        return False, "return 0", "result == 0", "wrong result", "x = 0"

    monkeypatch.setattr(reasoner_module, "_check_post_implies_spec", check)

    result = reasoner_module.reasoner(
        "function body",
        "Pre-condition:\ntrue\nPost-condition:\nresult > 0",
        "",
        "Python",
        all_bugs=True,
    )

    assert result["status"] == "ERROR"
    assert result["reasoning_complete"] is False
    assert result["violations"] == [
        {
            "statements": "return 0",
            "post_condition": "result == 0",
            "reason": "wrong result",
            "counterexample": "x = 0",
        }
    ]


def test_default_reasoner_keeps_original_exception_and_first_mismatch_behavior(
    monkeypatch,
):
    monkeypatch.setattr(
        reasoner_module,
        "_split_into_blocks_braced",
        lambda *args: ["return 0"],
    )
    monkeypatch.setattr(
        reasoner_module,
        "_generate_block_post_condition",
        lambda *args, **kwargs: "result == 0",
    )
    monkeypatch.setattr(
        reasoner_module, "_has_terminating_statement", lambda *args: True
    )

    def legacy_check(*args, **kwargs):
        assert "include_counterexample" not in kwargs
        return False, "return 0", "result == 0", "wrong result"

    monkeypatch.setattr(reasoner_module, "_check_post_implies_spec", legacy_check)
    result = reasoner_module.reasoner(
        "function body",
        "Pre-condition:\ntrue\nPost-condition:\nresult > 0",
        "",
        "Python",
    )
    assert result == (
        "Verification FAILED.\n"
        "Statements triggering the violation:\nreturn 0\n\n"
        "Post-condition:\nresult == 0\n\n"
        "Reason for violation:\nwrong result"
    )

    monkeypatch.setattr(
        reasoner_module,
        "_generate_block_post_condition",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("provider failed")),
    )
    with pytest.raises(RuntimeError, match="provider failed"):
        reasoner_module.reasoner(
            "function body",
            "Pre-condition:\ntrue\nPost-condition:\nresult > 0",
            "",
            "Python",
        )


def test_resume_rejects_default_and_all_bugs_schema_mixing(tmp_path):
    all_bugs_dir = tmp_path / "all-bugs"
    _write_json(
        all_bugs_dir / "function.json",
        {
            "function": "/project/function.py",
            "verdict": "MATCH",
            "gaps": None,
            "all_bugs": True,
            "bug_count": 0,
            "reasoning_complete": True,
        },
    )
    with pytest.raises(ResumeModeMismatchError):
        _ensure_resume_mode_compatible(str(all_bugs_dir), all_bugs=False)

    default_dir = tmp_path / "default"
    _write_json(
        default_dir / "function.json",
        {"function": "/project/function.py", "verdict": "MATCH", "gaps": None},
    )
    with pytest.raises(ResumeModeMismatchError):
        _ensure_resume_mode_compatible(str(default_dir), all_bugs=True)

    _ensure_resume_mode_compatible(str(all_bugs_dir), all_bugs=True)
    _ensure_resume_mode_compatible(str(default_dir), all_bugs=False)


def test_all_bugs_candidate_function_must_match_primary(tmp_path):
    results_dir = tmp_path / "logic_verification_results" / "mod"
    primary_path = results_dir / "function.json"
    candidate_path = results_dir / "function.bug-001.json"
    function_path = (
        "/tmp/run/fm_agent/extracted_functions/mod/function.py"
    )
    primary = {
        "function": function_path,
        "verdict": "MISMATCH",
        "gaps": _candidate(function_path)["gaps"],
        "all_bugs": True,
        "bug_count": 1,
        "reasoning_complete": True,
    }
    _write_json(primary_path, primary)
    _write_json(candidate_path, _candidate(function_path))

    assert _all_bugs_candidate_paths(str(primary_path), primary) == [
        str(candidate_path)
    ]

    _write_json(
        candidate_path,
        _candidate("/tmp/run/fm_agent/extracted_functions/mod/other.py"),
    )
    assert _all_bugs_candidate_paths(str(primary_path), primary) is None


def test_candidate_sha_is_stable_across_isolate_roots(tmp_path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    windows_path = tmp_path / "windows.json"
    first = _candidate(
        "/tmp/fm_agent_wt_one/fm_agent/extracted_functions/mod/function.py"
    )
    second = _candidate(
        "/tmp/fm_agent_wt_two/fm_agent/extracted_functions/mod/function.py"
    )
    _write_json(first_path, first)
    _write_json(second_path, second)

    assert _json_sha256(str(first_path)) != _json_sha256(str(second_path))
    assert _candidate_sha256(str(first_path)) == _candidate_sha256(
        str(second_path)
    )
    _write_json(
        windows_path,
        _candidate(
            r"C:\tmp\fm_agent_wt_three\fm_agent\extracted_functions\mod\function.py"
        ),
    )
    assert _candidate_sha256(str(first_path)) == _candidate_sha256(
        str(windows_path)
    )

    second["function"] = (
        "/tmp/fm_agent_wt_two/fm_agent/extracted_functions/mod/other.py"
    )
    _write_json(second_path, second)
    assert _candidate_sha256(str(first_path)) != _candidate_sha256(
        str(second_path)
    )

    second = _candidate(
        "/tmp/fm_agent_wt_two/fm_agent/extracted_functions/mod/function.py",
        counterexample="x = 1",
    )
    _write_json(second_path, second)
    assert _candidate_sha256(str(first_path)) != _candidate_sha256(
        str(second_path)
    )


def test_candidate_validation_is_reusable_across_isolate_roots(tmp_path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    validation_path = tmp_path / "validation.json"
    _write_json(
        first_path,
        _candidate(
            "/tmp/fm_agent_wt_one/fm_agent/extracted_functions/mod/function.py"
        ),
    )
    _write_json(
        second_path,
        _candidate(
            "/tmp/fm_agent_wt_two/fm_agent/extracted_functions/mod/function.py"
        ),
    )
    _write_json(
        validation_path,
        {
            "confirmation_status": "confirmed",
            "candidate_sha256": _candidate_sha256(str(first_path)),
            "validated_counterexample": "x = 0",
        },
    )

    assert _candidate_validation_error(
        str(validation_path), str(second_path)
    ) is None


def test_default_summary_keeps_legacy_shape_and_directory_behavior(tmp_path):
    work_dir = tmp_path / "workspace"
    verification._generate_validation_summary(str(work_dir))
    assert not (work_dir / "bug_validation").exists()

    record = {
        "id": "legacy",
        "confirmation_status": "confirmed",
    }
    _write_json(work_dir / "bug_validation" / "legacy.result.json", record)
    verification._generate_validation_summary(str(work_dir))
    summary = json.loads(
        (work_dir / "bug_validation" / "summary.json").read_text(encoding="utf-8")
    )

    assert summary == {
        "total_reported": 1,
        "total_confirmed": 1,
        "total_not_confirmed": 0,
        "total_error": 0,
        "bugs": [record],
    }
    assert "total_pending" not in summary


def test_all_bugs_summary_marks_missing_candidate_pending_and_ignores_stale(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(config, "BUG_VALIDATION_MAX_RETRIES", 1)
    work_dir = tmp_path / "workspace"
    primary = work_dir / "logic_verification_results" / "mod" / "function.json"
    sidecar = primary.with_name("function.bug-001.json")
    _write_json(
        primary,
        {
            "function": "/project/function.py",
            "verdict": "MISMATCH",
            "gaps": _candidate()["gaps"],
            "all_bugs": True,
            "bug_count": 1,
            "reasoning_complete": True,
        },
    )
    _write_json(sidecar, _candidate("/project/function.py"))
    _write_json(
        work_dir / "bug_validation" / "stale.result.json",
        {"id": "stale", "confirmation_status": "confirmed"},
    )

    verification._generate_all_bugs_validation_summary(str(work_dir))
    summary = json.loads(
        (work_dir / "bug_validation" / "summary.json").read_text(encoding="utf-8")
    )

    assert summary["total_reported"] == 1
    assert summary["total_confirmed"] == 0
    assert summary["total_pending"] == 1
    assert summary["bugs"][0]["id"] == "mod--function.bug-001"
    assert summary["bugs"][0]["confirmation_status"] == "pending"
    assert summary["bugs"][0]["expected_counterexample"] == "x = 0"


def test_all_bugs_summary_is_not_created_when_entry_validation_is_disabled(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(config, "BUG_VALIDATION_MAX_RETRIES", 0)
    work_dir = tmp_path / "workspace"
    primary = work_dir / "logic_verification_results" / "function.json"
    _write_json(
        primary,
        {
            "function": "/project/function.py",
            "verdict": "MISMATCH",
            "gaps": _candidate()["gaps"],
            "all_bugs": True,
            "bug_count": 1,
            "reasoning_complete": True,
        },
    )
    _write_json(primary.with_name("function.bug-001.json"), _candidate())

    verification._generate_all_bugs_validation_summary(str(work_dir))

    assert not (work_dir / "bug_validation").exists()


def test_candidate_binding_is_injected_only_for_all_bugs_prompt(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    work_dir = project / "fm_agent"
    results_dir = work_dir / "logic_verification_results" / "mod"
    legacy_rel = "fm_agent/logic_verification_results/mod/function.json"
    candidate_rel = (
        "fm_agent/logic_verification_results/mod/function.bug-001.json"
    )
    _write_json(results_dir / "function.json", _candidate())
    _write_json(results_dir / "function.bug-001.json", _candidate())
    monkeypatch.setattr(config, "BUG_VALIDATION_MAX_RETRIES", 0)

    prompts_seen = []

    def capture_command(*, files, **kwargs):
        prompts_seen.append(Path(files[0]).read_text(encoding="utf-8"))
        return ["opencode"]

    monkeypatch.setattr(verification, "build_llm_cli_command", capture_command)

    verification._validate_single_bug(
        legacy_rel, str(project), str(work_dir), resume=False
    )
    verification._validate_single_bug(
        candidate_rel, str(project), str(work_dir), resume=False
    )

    assert "## Candidate Binding" not in prompts_seen[0]
    assert "candidate_sha256" not in prompts_seen[0]
    assert "validated_counterexample" not in prompts_seen[0]
    assert "## Candidate Binding" in prompts_seen[1]
    assert "candidate_sha256" in prompts_seen[1]
    assert '"validated_counterexample": "x = 0"' in prompts_seen[1]


def test_entry_count_uses_legacy_verdict_or_all_bugs_primary_count(tmp_path):
    legacy_dir = tmp_path / "legacy"
    _write_json(
        legacy_dir / "function.json",
        {"function": "/project/function.py", "verdict": "MISMATCH", "gaps": {}},
    )
    assert _count_mismatches(str(legacy_dir)) == 1

    all_bugs_dir = tmp_path / "all-bugs"
    _write_json(
        all_bugs_dir / "function.json",
        {
            "function": "/project/function.py",
            "verdict": "MISMATCH",
            "gaps": _candidate()["gaps"],
            "all_bugs": True,
            "bug_count": 2,
            "reasoning_complete": True,
        },
    )
    _write_json(all_bugs_dir / "function.bug-001.json", _candidate())
    _write_json(all_bugs_dir / "function.bug-002.json", _candidate())
    assert _count_mismatches(str(all_bugs_dir), all_bugs=True) == 2
