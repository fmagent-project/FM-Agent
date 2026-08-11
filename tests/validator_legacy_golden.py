"""Test-only loader and validator for the pinned legacy validator corpus."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


CORPUS_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "validator_legacy_golden"
    / "v1"
    / "corpus.json"
)

_TOP_LEVEL_KEYS = {
    "corpus_schema_version",
    "baseline",
    "normalization_policy",
    "required_capabilities",
    "fixtures",
    "cases",
}
_BASELINE_KEYS = {
    "repository_ref",
    "git_commit",
    "submission_schema_version",
    "result_schema_version",
    "sidecar_schema_version",
    "gate_version",
    "toolchain_descriptor_version",
}
_NORMALIZATION_KEYS = {"ignored_fields", "path_tokens"}
_FIXTURE_KEYS = {"submissions", "records"}
_CASE_KEYS = {
    "case_id",
    "capability",
    "entrypoint",
    "parity_policy",
    "source_tests",
    "submission_ref",
    "input_mutations",
    "drivers",
    "expected",
}
_EXPECTED_KEYS = {
    "decision",
    "external_calls",
    "submission_mutations",
    "flow",
}
_DECISION_KEYS = {"kind", "check", "reason_contains"}
_FLOW_KEYS = {
    "requested_grade",
    "inner_final_grade",
    "outer_candidate",
    "outer_calls",
    "published",
    "same_agent_retry",
    "new_attempt_on_budget",
}
_MUTATION_KEYS = {"op", "path", "value"}
_SOURCE_TEST_RE = re.compile(r"^tests/test_[a-z0-9_]+\.py::test_[a-z0-9_]+$")
_CASE_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_FORBIDDEN_ABSOLUTE_PATH_RE = re.compile(
    r"(?:^[A-Za-z]:[\\/]|^/tmp/|^/home/|^/Users/|^/var/tmp/)",
)


class GoldenCorpusError(ValueError):
    """Raised when the committed corpus is ambiguous or unstable."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the deterministic JSON encoding used to bind the corpus."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def corpus_sha256(corpus: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(corpus)).hexdigest()


def _require_exact_keys(value: object, expected: set[str], where: str) -> dict:
    if type(value) is not dict:
        raise GoldenCorpusError(f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise GoldenCorpusError(
            f"{where} keys differ; missing={missing}, extra={extra}"
        )
    return value


def _require_string(value: object, where: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value.strip()):
        raise GoldenCorpusError(f"{where} must be a non-empty string")
    return value


def _require_optional_string(value: object, where: str) -> None:
    if value is not None:
        _require_string(value, where)


def _require_exact_int(value: object, where: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise GoldenCorpusError(f"{where} must be an integer >= {minimum}")
    return value


def _validate_json_tree(value: object, where: str) -> None:
    if value is None or type(value) in (str, int, float, bool):
        if type(value) is str and _FORBIDDEN_ABSOLUTE_PATH_RE.search(value):
            raise GoldenCorpusError(f"{where} contains an unstable absolute path")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_tree(item, f"{where}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            _require_string(key, f"{where} key")
            _validate_json_tree(item, f"{where}.{key}")
        return
    raise GoldenCorpusError(f"{where} is not a JSON value")


def _validate_mutations(value: object, where: str) -> None:
    if type(value) is not list:
        raise GoldenCorpusError(f"{where} must be a list")
    for index, mutation in enumerate(value):
        item = _require_exact_keys(mutation, _MUTATION_KEYS, f"{where}[{index}]")
        if item["op"] not in {"add", "remove", "replace"}:
            raise GoldenCorpusError(f"{where}[{index}].op is not closed")
        path = _require_string(item["path"], f"{where}[{index}].path")
        if not path.startswith("/") or ".." in path.split("/"):
            raise GoldenCorpusError(f"{where}[{index}].path is not a JSON pointer")
        _validate_json_tree(item["value"], f"{where}[{index}].value")


def validate_corpus(corpus: object) -> dict:
    """Strictly validate the versioned corpus without importing production code."""
    doc = _require_exact_keys(corpus, _TOP_LEVEL_KEYS, "corpus")
    if doc["corpus_schema_version"] != 1 or type(doc["corpus_schema_version"]) is not int:
        raise GoldenCorpusError("corpus_schema_version must be integer 1")

    baseline = _require_exact_keys(doc["baseline"], _BASELINE_KEYS, "baseline")
    _require_string(baseline["repository_ref"], "baseline.repository_ref")
    commit = _require_string(baseline["git_commit"], "baseline.git_commit")
    if not _COMMIT_RE.fullmatch(commit):
        raise GoldenCorpusError("baseline.git_commit must be a full lowercase SHA-1")
    for key in (
        "submission_schema_version",
        "result_schema_version",
        "sidecar_schema_version",
        "toolchain_descriptor_version",
    ):
        _require_exact_int(baseline[key], f"baseline.{key}", minimum=1)
    _require_string(baseline["gate_version"], "baseline.gate_version")

    normalization = _require_exact_keys(
        doc["normalization_policy"], _NORMALIZATION_KEYS, "normalization_policy"
    )
    for key in _NORMALIZATION_KEYS:
        values = normalization[key]
        if type(values) is not list or not values:
            raise GoldenCorpusError(f"normalization_policy.{key} must be a non-empty list")
        if any(type(item) is not str or not item for item in values):
            raise GoldenCorpusError(f"normalization_policy.{key} must contain strings")

    capabilities = doc["required_capabilities"]
    if type(capabilities) is not list or not capabilities:
        raise GoldenCorpusError("required_capabilities must be a non-empty list")
    if any(type(item) is not str or not item for item in capabilities):
        raise GoldenCorpusError("required_capabilities must contain strings")
    if len(capabilities) != len(set(capabilities)):
        raise GoldenCorpusError("required_capabilities contains duplicates")

    fixtures = _require_exact_keys(doc["fixtures"], _FIXTURE_KEYS, "fixtures")
    for group_name, group in fixtures.items():
        if type(group) is not dict or not group:
            raise GoldenCorpusError(f"fixtures.{group_name} must be a non-empty object")
        _validate_json_tree(group, f"fixtures.{group_name}")
    submission_refs = set(fixtures["submissions"])

    cases = doc["cases"]
    if type(cases) is not list or not cases:
        raise GoldenCorpusError("cases must be a non-empty list")
    seen_ids: set[str] = set()
    covered_capabilities: set[str] = set()
    for index, case_value in enumerate(cases):
        where = f"cases[{index}]"
        case = _require_exact_keys(case_value, _CASE_KEYS, where)
        case_id = _require_string(case["case_id"], f"{where}.case_id")
        if not _CASE_ID_RE.fullmatch(case_id) or case_id in seen_ids:
            raise GoldenCorpusError(f"{where}.case_id is invalid or duplicated")
        seen_ids.add(case_id)

        capability = _require_string(case["capability"], f"{where}.capability")
        if capability not in capabilities:
            raise GoldenCorpusError(f"{where}.capability is not declared")
        covered_capabilities.add(capability)
        if case["entrypoint"] not in {
            "gate", "trace_parser", "phenomenon", "l1", "flow", "artifact", "consumer"
        }:
            raise GoldenCorpusError(f"{where}.entrypoint is not closed")
        if case["parity_policy"] not in {
            "must_match", "legacy_known_gap", "intentional_cutover_delta"
        }:
            raise GoldenCorpusError(f"{where}.parity_policy is not closed")

        source_tests = case["source_tests"]
        if type(source_tests) is not list or not source_tests:
            raise GoldenCorpusError(f"{where}.source_tests must be a non-empty list")
        for test_name in source_tests:
            if type(test_name) is not str or not _SOURCE_TEST_RE.fullmatch(test_name):
                raise GoldenCorpusError(f"{where}.source_tests contains an invalid test id")

        submission_ref = case["submission_ref"]
        _require_optional_string(submission_ref, f"{where}.submission_ref")
        if submission_ref is not None and submission_ref not in submission_refs:
            raise GoldenCorpusError(f"{where}.submission_ref is unknown")
        _validate_mutations(case["input_mutations"], f"{where}.input_mutations")
        _validate_json_tree(case["drivers"], f"{where}.drivers")

        expected = _require_exact_keys(case["expected"], _EXPECTED_KEYS, f"{where}.expected")
        decision = _require_exact_keys(
            expected["decision"], _DECISION_KEYS, f"{where}.expected.decision"
        )
        if decision["kind"] not in {"accept", "reject", "no_phenomenon", "skip", "rerun"}:
            raise GoldenCorpusError(f"{where}.expected.decision.kind is not closed")
        _require_optional_string(decision["check"], f"{where}.expected.decision.check")
        _require_optional_string(
            decision["reason_contains"], f"{where}.expected.decision.reason_contains"
        )
        external_calls = expected["external_calls"]
        if type(external_calls) is not list or any(
            type(call) is not str or not call for call in external_calls
        ):
            raise GoldenCorpusError(f"{where}.expected.external_calls must be strings")
        _validate_mutations(
            expected["submission_mutations"], f"{where}.expected.submission_mutations"
        )
        flow = _require_exact_keys(expected["flow"], _FLOW_KEYS, f"{where}.expected.flow")
        for key in ("requested_grade", "inner_final_grade"):
            if flow[key] not in {None, "L0", "L1"}:
                raise GoldenCorpusError(f"{where}.expected.flow.{key} is invalid")
        if flow["outer_candidate"] not in {"none", "original_submission", "inner_normalized"}:
            raise GoldenCorpusError(f"{where}.expected.flow.outer_candidate is invalid")
        _require_exact_int(flow["outer_calls"], f"{where}.expected.flow.outer_calls")
        for key in ("published", "same_agent_retry", "new_attempt_on_budget"):
            if type(flow[key]) is not bool:
                raise GoldenCorpusError(f"{where}.expected.flow.{key} must be boolean")

    if covered_capabilities != set(capabilities):
        missing = sorted(set(capabilities) - covered_capabilities)
        raise GoldenCorpusError(f"required capabilities are uncovered: {missing}")
    return doc


def load_corpus(path: Path = CORPUS_PATH) -> dict:
    def reject_constant(value: str) -> None:
        raise GoldenCorpusError(f"non-finite JSON number is forbidden: {value}")

    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenCorpusError(f"cannot read golden corpus: {exc}") from exc
    return validate_corpus(parsed)
