import dataclasses
import json
import unittest

from src.validation_core.contracts.base import (
    MAX_CANONICAL_JSON_DEPTH,
    CanonicalDecimal,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    load_strict_json_object,
    require_exact_keys,
    validate_control_free_string,
    validate_non_negative_int,
    validate_safe_relative_path,
)
from src.validation_core.contracts.references import (
    ArtifactRef,
    ContractRef,
    ContractRefKind,
)


_HASH_A = "a" * 64


class StrictJSONPrimitiveTests(unittest.TestCase):
    def test_existing_canonical_hash_vector_is_unchanged(self):
        value = {"b": 1, "a": 2}

        self.assertEqual(canonical_json_bytes(value), b'{"a":2,"b":1}')
        self.assertEqual(
            canonical_sha256(value),
            "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        )

    def test_loader_accepts_one_bounded_utf8_object(self):
        document = load_strict_json_object(
            '{"nested":{"message":"你好","values":[true,null,3]}}'.encode()
        )

        self.assertEqual(
            document,
            {"nested": {"message": "你好", "values": [True, None, 3]}},
        )
        document["new"] = "the schema parser receives an independent tree"

    def test_loader_rejects_nested_duplicate_keys_and_ambiguous_numbers(self):
        invalid_payloads = (
            b'{"value":1,"value":2}',
            b'{"outer":{"value":1,"value":2}}',
            b'{"outer":{"a":1,"\\u0061":2}}',
            b'{"value":1.0}',
            b'{"value":1e3}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":-Infinity}',
        )

        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ContractError):
                    load_strict_json_object(payload)

    def test_loader_rejects_encoding_size_root_and_depth_boundaries(self):
        overly_deep = (
            b'{"value":'
            + b"[" * (MAX_CANONICAL_JSON_DEPTH + 1)
            + b"0"
            + b"]" * (MAX_CANONICAL_JSON_DEPTH + 1)
            + b"}"
        )
        invalid_calls = (
            lambda: load_strict_json_object("{}"),
            lambda: load_strict_json_object(b""),
            lambda: load_strict_json_object(b'"not-an-object"'),
            lambda: load_strict_json_object(b"[]"),
            lambda: load_strict_json_object(b"\xff"),
            lambda: load_strict_json_object(b'{"text":"\\ud800"}'),
            lambda: load_strict_json_object(b'{"a":1}', max_bytes=6),
            lambda: load_strict_json_object(b"{}", max_bytes=True),
            lambda: load_strict_json_object(overly_deep),
        )

        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(ContractError):
                    call()

    def test_exact_keys_reports_missing_and_unexpected_fields(self):
        self.assertEqual(
            require_exact_keys(
                {"required": 1, "optional": 2},
                required=("required",),
                optional=("optional",),
                where="sample",
            ),
            {"required": 1, "optional": 2},
        )
        for document in (
            {},
            {"required": 1, "trusted": True},
            {"required": 1, "path": "/host/file"},
            {"required": 1, 2: "non-string key"},
        ):
            with self.subTest(document=document):
                with self.assertRaises(ContractError):
                    require_exact_keys(
                        document,
                        required=("required",),
                        where="sample",
                    )

    def test_safe_scalar_validators_are_exact_type_and_control_free(self):
        self.assertEqual(validate_safe_relative_path("a/b.json", "path"), "a/b.json")
        self.assertEqual(validate_control_free_string("review note", "note"), "review note")
        self.assertEqual(validate_non_negative_int(0, "size"), 0)

        invalid_paths = ("/a", "a/../b", "a//b", "a\\b", "C:/a", "a/")
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ContractError):
                    validate_safe_relative_path(path, "path")
        with self.assertRaises(ContractError):
            validate_control_free_string("line\nbreak", "note")
        with self.assertRaises(ContractError):
            validate_non_negative_int(True, "size")


class CanonicalDecimalTests(unittest.TestCase):
    def test_canonical_values_round_trip_as_strings(self):
        values = ("0", "1", "-1", "10", "0.1", "-0.1", "1.25", "-100.001")

        for value in values:
            with self.subTest(value=value):
                decimal = CanonicalDecimal.parse(value, "threshold")
                self.assertEqual(decimal.to_document(), value)
                self.assertEqual(str(decimal), value)

    def test_noncanonical_or_nonfinite_spellings_are_rejected(self):
        invalid = (
            "",
            "00",
            "01",
            "-01",
            "+1",
            ".1",
            "1.",
            "1.0",
            "0.10",
            "-0",
            "-0.0",
            "1e2",
            "1E2",
            "NaN",
            "Infinity",
            " 1",
            "1 ",
            "1" * 257,
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ContractError):
                    CanonicalDecimal.parse(value)
        with self.assertRaises(ContractError):
            CanonicalDecimal.parse(1)

    def test_decimal_is_frozen(self):
        value = CanonicalDecimal("0.25")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.value = "0.5"


class StrongReferenceTests(unittest.TestCase):
    def test_contract_reference_round_trip_is_hash_stable_and_typed(self):
        reference = ContractRef(
            kind=ContractRefKind.ORACLE_SPEC,
            contract_id="vllm.prefix-cache",
            contract_version="1.0.0",
            content_sha256=_HASH_A,
        )
        encoded = canonical_json_bytes(reference.to_document())
        restored = ContractRef.from_document(load_strict_json_object(encoded))

        self.assertEqual(restored, reference)
        self.assertEqual(
            canonical_sha256(restored.to_document()),
            canonical_sha256(reference.to_document()),
        )
        self.assertNotEqual(
            reference,
            ContractRef(
                kind=ContractRefKind.ORACLE_BUNDLE,
                contract_id=reference.contract_id,
                contract_version=reference.contract_version,
                content_sha256=reference.content_sha256,
            ),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            reference.contract_id = "changed"

    def test_all_contract_reference_kinds_round_trip(self):
        for kind in ContractRefKind:
            with self.subTest(kind=kind):
                reference = ContractRef(kind, "component", "v1", _HASH_A)
                self.assertEqual(
                    ContractRef.from_document(reference.to_document()), reference
                )

    def test_contract_reference_rejects_schema_trust_path_and_type_forgery(self):
        base = ContractRef(
            ContractRefKind.TOOL,
            "compiler",
            "v1",
            _HASH_A,
        ).to_document()
        invalid_documents = []
        for field, value in (
            ("trusted", True),
            ("approved", True),
            ("path", "/usr/bin/compiler"),
            ("url", "https://example.invalid/tool"),
        ):
            document = dict(base)
            document[field] = value
            invalid_documents.append(document)
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("kind", "user_defined_shell"),
            ("contract_id", "/host/tool"),
            ("content_sha256", "A" * 64),
        ):
            document = dict(base)
            document[field] = value
            invalid_documents.append(document)

        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(ContractError):
                    ContractRef.from_document(document)

    def test_artifact_reference_round_trip_has_no_location_or_trust(self):
        reference = ArtifactRef(
            role="request_trace",
            media_type="application/json",
            size_bytes=0,
            content_sha256=_HASH_A,
        )
        document = reference.to_document()
        parsed = ArtifactRef.from_document(json.loads(json.dumps(document)))

        self.assertEqual(parsed, reference)
        self.assertFalse(
            {"path", "url", "workspace", "trusted", "approved"}.intersection(
                document
            )
        )

    def test_artifact_reference_rejects_location_trust_and_scalar_forgery(self):
        base = ArtifactRef(
            "stderr",
            "text/plain",
            12,
            _HASH_A,
        ).to_document()
        invalid_documents = []
        for field, value in (
            ("path", "artifacts/stderr"),
            ("host_path", "/tmp/stderr"),
            ("trusted", True),
            ("approval_sha256", _HASH_A),
        ):
            document = dict(base)
            document[field] = value
            invalid_documents.append(document)
        for field, value in (
            ("size_bytes", True),
            ("size_bytes", -1),
            ("media_type", "text/plain; charset=utf-8"),
            ("media_type", "Text/Plain"),
            ("role", "../stderr"),
        ):
            document = dict(base)
            document[field] = value
            invalid_documents.append(document)

        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(ContractError):
                    ArtifactRef.from_document(document)

    def test_parsed_references_do_not_alias_the_input_document(self):
        document = ContractRef(
            ContractRefKind.NORMALIZER,
            "json.tokens",
            "v1",
            _HASH_A,
        ).to_document()
        reference = ContractRef.from_document(document)

        document["contract_id"] = "mutated"
        self.assertEqual(reference.contract_id, "json.tokens")


if __name__ == "__main__":
    unittest.main()
