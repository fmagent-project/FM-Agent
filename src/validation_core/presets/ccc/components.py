"""Non-executable descriptors for the legacy CCC validation semantics."""

from __future__ import annotations

from ...contracts.component import (
    ComponentDescriptor,
    ImplementationRef,
    SemanticClause,
    SemanticContract,
)
from ...contracts.base import ComponentKind


_REPOSITORY_ID = "fmagent.private"
_REVISION = "29eb099c01e6b6ef2f8e68ebc41608184b9f13d4"

_SOURCES = {
    "src/audit_runner.py": (
        "59a595ee4a3535bea183b290c5d5dd8496ed22b7",
        "fb4ddaa996609192741dce8f39083743247bad64c86cb175e567a40c37770f2d",
        7038,
    ),
    "src/check_submission.py": (
        "1fdbf4332cd22f66f16a77432e66e8f2e8f13af7",
        "9412aa276c478a51f717f83992cae60d18ad3710dcd48e237fce2febea7dca7b",
        15023,
    ),
    "src/compiler_recipe.py": (
        "cd68b941d9a8686199c9e25c7daaa2f21c0a594b",
        "4804f99707f160ad908ea367c54049d98ef89288a379aa4ad9ba6f80155f0c96",
        2693,
    ),
    "src/coverage_witness.py": (
        "aa736d1587f2fcf1d9a1b426985dfa60e77580cc",
        "92384721600cfbb7505102dc57f70360e27471d0ed48fe78df1e2fff6c129342",
        7651,
    ),
    "src/l1_verifier.py": (
        "df2beb3a3bc41285931b5757e88d791f2d3420fa",
        "a25f872aa9d37b01eaa32ac56040fa9916da6a497e56c12ab3ab0b824d6ac192",
        11916,
    ),
    "src/l1_patch_tool.py": (
        "1f537f4822630dd6c8d8bd9b19669defa0260b5a",
        "dee732dccf50d86f955a6e19719cf064c84134bc52ae6ee4b9285ef6339aaa22",
        2583,
    ),
    "src/phenomenon_runner.py": (
        "065ee77d05a166b57e59158b326e977d5d714bfc",
        "ba2c6cf674b3087e0c3b00155b300a37d152dbf93d90bbec2c3474a4cd02732d",
        5464,
    ),
    "src/submission_schema.py": (
        "695277beb39e61a0184bc4d1c5d98dc50ef735f2",
        "0ad8e93d4efe5d566d0818f9e0c88fe0c9c57945ca02dddd740b4a6e547490d5",
        7593,
    ),
    "src/validation_artifacts.py": (
        "753d2170e2612c8022eff2d1030c34c637dc947b",
        "8d323d83af2f52a7cd8323413b566f8f60c4f5796d35fb70483c849df8a15ed2",
        16608,
    ),
    "src/validation_context.py": (
        "28689452bbcd8dee410d2d8088685c24839696dc",
        "3ae8fad704b90fc066670105d23b0ad21394ec85e3aece5ddaf865e2f9863f37",
        18780,
    ),
    "src/validation_recheck.py": (
        "aef483a278e809599577b954f1986e482c3cdfda",
        "016bc1552338b54e65109e9ee5b838d80f8984dfdfecb43fc715093ead75a6c6",
        3568,
    ),
    "src/validation_submit.py": (
        "b27306c251dfefb108d1f1c2d39b7ddc69f23626",
        "00cbab886b47ccc59aa5e2da34a6c9a8b506411dbf8fe82096ce131d0a524a94",
        7418,
    ),
    "src/validation_toolchain.py": (
        "12bea9e19a30bdec6f7abe5c2ef15a276175e568",
        "21fa4b0322feb6f2bd9bc8a5319b66ad89b4df5cd68ec6070890e4f1875dbd48",
        13956,
    ),
    "src/validation_workspace.py": (
        "a07c25b2d946fb7928aa0ce9b714fc9cf0c5b108",
        "3d6eaa395c553337908a7a44d96f7aa90cdcb6ae669ec875fe307fa5144614ad",
        8096,
    ),
    "src/validator_sandbox.py": (
        "1543c749ebfa912fad87a52ae0a7ca0cfcd63f28",
        "daa509affe8d12365be4a30677abab9bb2d6c49c0f8cd9df2ec7b2d5865647fa",
        13625,
    ),
    "src/verification.py": (
        "1df28798fcfcc41c755ada29cc11d4c18fed200a",
        "b318bb6d63dc8d6e5432acd4ebe10b1ea105f07d6f70e2512daf42c7bbc621ee",
        40581,
    ),
    "tools/audit_setup.py": (
        "cea647d5dce1422c20ace2e8b4d9e182eb98ee28",
        "215faecb0ee599ae5ab37fcde3d234e83b9662b940d7cbc5b3fd58852e7a593b",
        18852,
    ),
    "tools/fm_audit_init.rs": (
        "6766ba4b7b09b993d8857aebbaa79f0ab38ed77e",
        "cad4bbcddd835fa6dca79be239a7324f121c72344975b859edb7a5dfcd21c13b",
        1104,
    ),
    "tools/fm_audit_span_id.rs": (
        "53ebc3f093e5d9a22ec2517c6de61cff81a08518",
        "1e8581a5a28991bfb35ba95baddca3ee4eed80cab4c47b744167528432d2b459",
        305,
    ),
    "tools/instrument.py": (
        "25ce848d08b0ce43a001b39f59bd6ecbe9752323",
        "d7a28cc983a7f2be5193e3eedf45c64a2b873c3f550de5bad0c537b625965a4c",
        3016,
    ),
    "tools/l1_scope/Cargo.lock": (
        "2d736e8bf75424b14a9b33a13cc2140b46a1ea28",
        "59b15405118d93cece4bc739bd380233a23f357e58ec95f845bde6e7cbf7c51e",
        1114,
    ),
    "tools/l1_scope/Cargo.toml": (
        "b994058b2174c9ee9e08a6801c903f25b7e9d3da",
        "26ccae4d4ae7d9c0a705cd316fa1c18a5d14de1bd8e588fc6784fa24556a5c83",
        277,
    ),
    "tools/l1_scope/src/main.rs": (
        "4e90a88323b72e793a30a577c8473467fc535bc8",
        "1387da923013e1374149efd23613c5384492d9b7190dca4f8a1ae0913f8a5a19",
        6305,
    ),
    "tools/validation_sanity_corpus/basic.c": (
        "86c204a237b65945209e575048a8950fea038157",
        "8ad2fe20c851f7cb69e57baa235d85f1ffb3a46c3bfa2b72424f8ab656955191",
        120,
    ),
    "tools/validation_sanity_corpus/control_flow.c": (
        "fa82014da973023f1809a910d0edb045e5a33f9a",
        "3da5ca8d66011d1ae5a4c960985ab612208c5c18b227fb79632572232012a8e1",
        223,
    ),
    "tools/validation_sanity_corpus/declarations.c": (
        "4e76fb0caf6bac3b0d89c0216f261769497dcfb6",
        "46b5d0ef5aa775e45d39bcb3dd7255532f8a957660bf88ddd19088743b5cad20",
        189,
    ),
    "tools/validation_sanity_corpus/function_pointer.c": (
        "6efb9bd8fd812b0a57e21f47f2477b3792510af2",
        "237369fcf883154351396b11c6f4b019e96571a5c99bf692c50bad5b5609319f",
        253,
    ),
}


def _source(path: str) -> ImplementationRef:
    blob, sha256, size = _SOURCES[path]
    return ImplementationRef(
        repository_id=_REPOSITORY_ID,
        revision=_REVISION,
        relative_path=path,
        git_blob_sha1=blob,
        source_sha256=sha256,
        size_bytes=size,
    )


def _contract(
    contract_id: str,
    clauses: dict[str, tuple[str, ...]],
    version: str = "1.0.0",
) -> SemanticContract:
    return SemanticContract(
        contract_id=contract_id,
        contract_version=version,
        clauses=tuple(
            SemanticClause(clause_id, values)
            for clause_id, values in clauses.items()
        ),
    )


def _descriptor(
    kind: ComponentKind,
    component_id: str,
    clauses: dict[str, tuple[str, ...]],
    source_paths: tuple[str, ...],
    version: str = "1.0.0",
) -> ComponentDescriptor:
    return ComponentDescriptor(
        kind=kind,
        component_id=component_id,
        component_version=version,
        semantic_contract=_contract(f"{component_id}.semantics", clauses, version),
        implementation_refs=tuple(_source(path) for path in source_paths),
    )


CCC_ADAPTER = _descriptor(
    ComponentKind.ADAPTER,
    "ccc.legacy_boundary_adapter",
    {
        "entry": ("supported C compiler CLI invoked with a canonical C probe",),
        "tool_roles": (
            "release CCC",
            "audit CCC",
            "coverage CCC",
            "trusted GCC reference",
        ),
        "providers": (
            "boundary trace replay",
            "independent target coverage",
            "differential phenomenon observation",
            "L1 repair verification",
        ),
        "execution": ("argv only", "no Agent-supplied shell text"),
    },
    (
        "src/audit_runner.py",
        "src/check_submission.py",
        "src/compiler_recipe.py",
        "src/coverage_witness.py",
        "src/l1_verifier.py",
        "src/phenomenon_runner.py",
        "src/validation_toolchain.py",
    ),
)

CCC_ORACLE_BUNDLE = _descriptor(
    ComponentKind.ORACLE_BUNDLE,
    "ccc.legacy_differential_oracles",
    {
        "preprocess": (
            "both compilers must succeed",
            "single-sided preprocess failure is an execution error",
            "normalize CRLF, rstrip each line, join with LF, then strip the whole text",
            "different normalized stdout means preprocess_differs",
            "equal normalized stdout means no phenomenon",
        ),
        "syntax_asm_object": (
            "only success versus failure is compared",
            "successful asm or object bytes are not compared",
            "matching outcomes mean no phenomenon",
        ),
        "run_precedence": (
            "compare build acceptance first",
            "then executable exit code",
            "then executable stdout by exact string comparison",
            "matching exit and stdout mean no phenomenon",
        ),
        "classification": (
            "both compiler failures establish no differential",
            "stderr never participates in the differential",
            "observed kind must equal the submitted expected_kind",
        ),
        "limits": (
            "legacy parity semantics",
            "no UB precondition",
            "no independent causal control",
        ),
    },
    ("src/phenomenon_runner.py", "src/check_submission.py"),
)

CCC_RECIPE_SCHEMA = _descriptor(
    ComponentKind.EXECUTION_RECIPE_SCHEMA,
    "ccc.legacy_compiler_recipe_schema",
    {
        "modes": ("preprocess", "syntax", "asm", "object", "run"),
        "standards": (
            "c89", "c90", "c99", "c11", "c17", "c23",
            "gnu89", "gnu90", "gnu99", "gnu11", "gnu17", "gnu23",
        ),
        "safe_flags": (
            "-O0", "-O1", "-O2", "-O3", "-Og", "-Os",
            "-Wall", "-Wextra", "-Werror", "-w", "-pedantic",
            "-pedantic-errors", "-fwrapv", "-fno-wrapv",
            "-fno-strict-aliasing", "-funsigned-char", "-fsigned-char",
            "-fcommon", "-fno-common", "-trigraphs",
        ),
        "argument_semantics": (
            "extra_args preserve submitted order and may repeat allowed flags",
            "paths and compiler binaries are supplied by the Harness",
        ),
        "argv_templates": (
            "common: compiler -std=STANDARD EXTRA_ARGS",
            "preprocess: -E -P PROBE",
            "syntax: -fsyntax-only PROBE",
            "asm: -S PROBE -o OUTPUT",
            "object: -c PROBE -o OUTPUT",
            "run: PROBE -o OUTPUT",
        ),
    },
    ("src/compiler_recipe.py",),
)

CCC_TARGET_EVIDENCE = _descriptor(
    ComponentKind.TARGET_EVIDENCE_POLICY,
    "ccc.legacy_boundary_target_evidence",
    {
        "provider_one": (
            "audit trace pairs target calls by unique span ID",
            "capture exact input and return for selected call_index",
        ),
        "provider_two": (
            "independent coverage compiler counts target entries",
            "coverage count must equal trace record count and be nonzero",
        ),
        "witness": (
            "probe path is canonical",
            "call_index is within replayed records and manifest identity matches",
            "input keys and values equal replay",
            "actual_output equals replayed return",
        ),
        "canonical_value": (
            "preserve JSON value type and recursively compare lists and sorted object keys",
            "remove Debug Span structures and collapse whitespace in strings",
        ),
        "trace_fail_closed": (
            "reject malformed or mixed trace events",
            "reject duplicate or reused span IDs",
            "reject missing return close pairing or open spans at end",
        ),
        "coverage_target": (
            "match authoritative manifest source file suffix",
            "match target source line and count only target entries",
        ),
        "cross_phase_binding": (
            "audit replay independent coverage and phenomenon recheck use the same submitted phenomenon recipe",
        ),
        "known_gap": (
            "spec_violation_claim remains an Agent judgment and is not mechanically re-proved",
        ),
    },
    (
        "src/audit_runner.py",
        "src/check_submission.py",
        "src/coverage_witness.py",
        "src/validation_context.py",
    ),
)

CCC_REPAIR_POLICY = _descriptor(
    ComponentKind.REPAIR_POLICY,
    "ccc.legacy_l1_repair_policy",
    {
        "mandatory_attempt": (
            "confirmed submissions must first submit a canonical L1 patch",
            "direct Agent-authored L0 is rejected after evidence checks",
        ),
        "scope": (
            "patch only the authoritative target file",
            "change only the target function body",
            "preserve file kind and mode",
        ),
        "verification": (
            "apply to a clean baseline copy",
            "patched compiler must build",
            "baseline differential must reproduce",
            "patched compiler must remove the differential",
        ),
        "classification": (
            "malformed unevaluable or non-building patch is L1-attempt hard rejection",
            "remaining differential is L1 failure eligible for downgrade to L0",
        ),
    },
    (
        "src/check_submission.py",
        "src/l1_patch_tool.py",
        "src/l1_verifier.py",
        "src/validation_workspace.py",
        "tools/l1_scope/src/main.rs",
        "tools/l1_scope/Cargo.toml",
        "tools/l1_scope/Cargo.lock",
    ),
)

CCC_SANITY_POLICY = _descriptor(
    ComponentKind.SANITY_POLICY,
    "ccc.legacy_repair_sanity_policy",
    {
        "corpus": (
            "source-bound corpus containing at least one regular C file",
            "corpus hash must remain frozen and corpus must contain no symlink",
        ),
        "comparison": (
            "run baseline and patched compilers with syntax-only on every seed",
            "exit code stdout and stderr must match exactly",
        ),
        "failure": ("changed sanity output is L1 failure eligible for downgrade",),
        "hard_rejection": (
            "changed corpus hash is L1-attempt hard rejection",
            "empty corpus is L1-attempt hard rejection",
            "sanity execution failure is L1-attempt hard rejection",
        ),
    },
    (
        "src/l1_verifier.py",
        "src/validation_artifacts.py",
        "src/validation_context.py",
        "src/validation_toolchain.py",
        "tools/validation_sanity_corpus/basic.c",
        "tools/validation_sanity_corpus/control_flow.c",
        "tools/validation_sanity_corpus/declarations.c",
        "tools/validation_sanity_corpus/function_pointer.c",
    ),
)

CCC_COMPATIBILITY_POLICY = _descriptor(
    ComponentKind.COMPATIBILITY_POLICY,
    "ccc.legacy_boundary_compatibility",
    {
        "versions": (
            "submission and result schema v3",
            "sidecar schema v5",
            "Gate boundary-witness-v6",
            "toolchain descriptor v2",
        ),
        "gate_order": (
            "schema and identity",
            "replay and independent coverage",
            "witness consistency",
            "phenomenon",
            "mandatory L1 verification",
        ),
        "not_confirmed": (
            "validate schema and bug/function identity only",
            "do not run replay coverage Oracle or L1 verification",
        ),
        "lifecycle": (
            "Inner rejection does not run Outer",
            "same Agent session may resubmit after Inner rejection",
            "Outer independently receives the original requested L1 candidate",
            "Outer rejection may start a fresh attempt when budget remains",
        ),
        "artifact": (
            "result raw bytes are hash-bound by result_sha256",
            "sidecar records bind logic result manifest target source release reference audit and coverage binaries sanity corpus probe and optional L1 patch",
            "only sidecar-enumerated records are bound; no whole-project or environment snapshot is claimed",
            "only a current verified sidecar satisfies legacy resume consumers",
        ),
        "intentional_cutover": (
            "direct scratch accepted-submission bypass must not survive the future Coordinator",
        ),
        "golden_corpus": (
            "validator_legacy_golden/v1 canonical sha256 a6708bf3b5e9b0e6066cdd8c8f512c17bcf7897ff4eabfcaee2d0317ecae2131",
            "30 must_match cells",
            "1 legacy_known_gap cell",
            "1 intentional_cutover_delta cell",
            "static semantic coverage only; executor parity not yet established",
        ),
    },
    (
        "src/submission_schema.py",
        "src/check_submission.py",
        "src/validation_artifacts.py",
        "src/validation_context.py",
        "src/validation_recheck.py",
        "src/validation_submit.py",
        "src/validation_workspace.py",
        "src/validator_sandbox.py",
        "src/verification.py",
    ),
    version="1.0.1",
)

CCC_TOOLCHAIN_POLICY = _descriptor(
    ComponentKind.TOOLCHAIN_POLICY,
    "ccc.legacy_source_bound_toolchain",
    {
        "descriptor": (
            "schema version 2",
            "run-local project bundle",
            "exact-key JSON",
            "exact keys: schema_version source_sha256 release_ccc audit_ccc coverage_ccc manifest_path sanity_corpus_dir",
            "bundle source hash must match current project inputs",
        ),
        "source_fingerprint": (
            "hash src/**/*.rs",
            "hash Cargo.toml Cargo.lock build.rs and existing .cargo config files",
        ),
        "tools": (
            "release CCC",
            "audit CCC",
            "coverage CCC",
            "trusted GCC reference",
            "effective manifest",
            "sanity corpus",
        ),
        "reference_compiler": (
            "GCC is not a descriptor v2 field",
            "resolve reference GCC at runtime from FM_REFERENCE_CC or PATH",
        ),
        "safety": (
            "local bundle paths cannot escape or be symlinks",
            "no parent-directory fallback",
        ),
    },
    (
        "src/validation_context.py",
        "src/validation_toolchain.py",
        "src/validator_sandbox.py",
        "src/verification.py",
        "tools/audit_setup.py",
        "tools/fm_audit_init.rs",
        "tools/fm_audit_span_id.rs",
        "tools/instrument.py",
    ),
)

CCC_COMPONENTS = (
    CCC_ADAPTER,
    CCC_ORACLE_BUNDLE,
    CCC_RECIPE_SCHEMA,
    CCC_TARGET_EVIDENCE,
    CCC_REPAIR_POLICY,
    CCC_SANITY_POLICY,
    CCC_COMPATIBILITY_POLICY,
    CCC_TOOLCHAIN_POLICY,
)
