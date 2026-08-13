import dataclasses
import unittest

from src.validation_core import (
    ComponentDescriptor,
    ComponentKind,
    ContractError,
    ImplementationRef,
    SemanticClause,
    SemanticContract,
)


def _source(**changes):
    values = {
        "repository_id": "fmagent.private",
        "revision": "1" * 40,
        "relative_path": "src/example.py",
        "git_blob_sha1": "2" * 40,
        "source_sha256": "3" * 64,
        "size_bytes": 10,
    }
    values.update(changes)
    return ImplementationRef(**values)


def _semantics(value="closed behavior"):
    return SemanticContract(
        contract_id="example.semantics",
        contract_version="1.0.0",
        clauses=(SemanticClause("behavior", (value,)),),
    )


def _descriptor(**changes):
    values = {
        "kind": ComponentKind.ADAPTER,
        "component_id": "example.adapter",
        "component_version": "1.0.0",
        "semantic_contract": _semantics(),
        "implementation_refs": (_source(),),
    }
    values.update(changes)
    return ComponentDescriptor(**values)


class ValidationComponentContractTests(unittest.TestCase):
    def test_descriptor_identity_binds_semantics_and_source_provenance(self):
        baseline = _descriptor()
        variants = (
            _descriptor(semantic_contract=_semantics("changed behavior")),
            _descriptor(implementation_refs=(_source(source_sha256="4" * 64),)),
            _descriptor(implementation_refs=(_source(git_blob_sha1="5" * 40),)),
            _descriptor(implementation_refs=(_source(revision="6" * 40),)),
            _descriptor(
                implementation_refs=(_source(relative_path="src/other.py"),)
            ),
        )

        for variant in variants:
            with self.subTest(variant=variant.to_document()):
                self.assertNotEqual(baseline.ref, variant.ref)

    def test_descriptor_document_contains_no_trust_or_execution_authority(self):
        document = _descriptor().to_document()
        rendered = repr(document)

        self.assertEqual(document["contract_kind"], "component_descriptor")
        self.assertNotIn("trust", rendered)
        self.assertNotIn("approved", rendered)
        self.assertNotIn("active", rendered)
        self.assertNotIn("callable", rendered)
        self.assertNotIn("command", rendered)

    def test_source_path_and_digest_contracts_fail_closed(self):
        invalid_sources = (
            {"relative_path": ""},
            {"relative_path": "/src/example.py"},
            {"relative_path": "C:/src/example.py"},
            {"relative_path": "src\\example.py"},
            {"relative_path": "src/../example.py"},
            {"relative_path": "src//example.py"},
            {"relative_path": "src/example.py/"},
            {"relative_path": "src/\x00example.py"},
            {"revision": "A" * 40},
            {"git_blob_sha1": "not-a-blob"},
            {"source_sha256": "4" * 63},
            {"size_bytes": True},
            {"size_bytes": 0},
        )
        for changes in invalid_sources:
            with self.subTest(changes=changes):
                with self.assertRaises(ContractError):
                    _source(**changes)

    def test_duplicate_source_keys_and_duplicate_clause_ids_are_rejected(self):
        source = _source()
        with self.assertRaises(ContractError):
            _descriptor(implementation_refs=(source, source))

        with self.assertRaises(ContractError):
            SemanticContract(
                contract_id="example.semantics",
                contract_version="1.0.0",
                clauses=(
                    SemanticClause("behavior", ("one",)),
                    SemanticClause("behavior", ("two",)),
                ),
            )

    def test_ordered_clause_values_preserve_recipe_argument_semantics(self):
        first = SemanticContract(
            contract_id="example.recipe",
            contract_version="1.0.0",
            clauses=(SemanticClause("flags", ("-O2", "-Wall", "-O2")),),
        )
        second = SemanticContract(
            contract_id="example.recipe",
            contract_version="1.0.0",
            clauses=(SemanticClause("flags", ("-Wall", "-O2", "-O2")),),
        )

        self.assertNotEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.clauses[0].values.count("-O2"), 2)

    def test_contract_values_are_immutable(self):
        values = (_source(), _semantics(), _semantics().clauses[0], _descriptor())
        for value in values:
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    value.component_id = "changed"


if __name__ == "__main__":
    unittest.main()
