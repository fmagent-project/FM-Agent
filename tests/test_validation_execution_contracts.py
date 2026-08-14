import ast
import copy
import dataclasses
import json
import unittest
from pathlib import Path

from src.validation_core.contracts.base import ContractError
from src.validation_core.contracts.execution import (
    ExecutionInputBinding,
    ExecutionRecipe,
    ExecutionStep,
    InputBindingSource,
)
from src.validation_core.contracts.references import ContractRef, ContractRefKind


def _ref(kind, name):
    return ContractRef(
        kind=kind,
        contract_id=f"example.{name}",
        contract_version="1.0.0",
        content_sha256=(name[0].encode("utf-8").hex()[0] * 64),
    )


def _step(step_id="compile", *, depends_on=(), bindings=None, **changes):
    if bindings is None:
        bindings = (
            ExecutionInputBinding(
                "model",
                InputBindingSource.PROFILE_VALUE,
                "model.primary",
            ),
            ExecutionInputBinding(
                "probe",
                InputBindingSource.ARTIFACT_ROLE,
                "probe.source",
            ),
            ExecutionInputBinding(
                "port",
                InputBindingSource.BROKER_VALUE,
                "network.loopback_port",
            ),
            ExecutionInputBinding(
                "mode",
                InputBindingSource.CASE_PARAMETER,
                "compiler.mode",
            ),
        )
    values = {
        "step_id": step_id,
        "execution_block": _ref(ContractRefKind.EXECUTION_BLOCK, "block"),
        "tool": _ref(ContractRefKind.TOOL, "tool"),
        "argv_template": _ref(ContractRefKind.ARGV_TEMPLATE, "argv"),
        "timeout_policy": _ref(ContractRefKind.TIMEOUT_POLICY, "timeout"),
        "resource_policy": _ref(ContractRefKind.RESOURCE_POLICY, "resource"),
        "output_contract": _ref(ContractRefKind.OUTPUT_CONTRACT, "output"),
        "environment_policy": _ref(
            ContractRefKind.ENVIRONMENT_POLICY,
            "environment",
        ),
        "input_bindings": bindings,
        "cwd_symbol": "workspace.project",
        "stdin_artifact_role": "compiler.stdin",
        "depends_on": depends_on,
    }
    values.update(changes)
    return ExecutionStep(**values)


def _recipe(steps=None, **changes):
    if steps is None:
        steps = (_step(),)
    values = {
        "recipe_id": "example.compiler",
        "recipe_version": "1.0.0",
        "recipe_schema": _ref(
            ContractRefKind.EXECUTION_RECIPE_SCHEMA,
            "schema",
        ),
        "steps": steps,
    }
    values.update(changes)
    return ExecutionRecipe(**values)


class ExecutionRecipeContractTests(unittest.TestCase):
    def test_round_trip_binds_every_closed_component_and_content_hash(self):
        recipe = _recipe()
        reconstructed = ExecutionRecipe.from_document(recipe.to_document())
        from_json = ExecutionRecipe.from_json(
            json.dumps(recipe.to_document()).encode("utf-8")
        )

        self.assertEqual(reconstructed, recipe)
        self.assertEqual(from_json, recipe)
        self.assertEqual(reconstructed.to_document(), recipe.to_document())
        self.assertEqual(recipe.ref.kind, ContractRefKind.EXECUTION_RECIPE)
        self.assertEqual(recipe.ref.contract_id, recipe.recipe_id)
        self.assertEqual(recipe.ref.contract_version, recipe.recipe_version)
        self.assertEqual(recipe.ref.content_sha256, recipe.content_sha256)
        self.assertEqual(
            {reference.kind for reference in recipe.component_refs},
            {
                ContractRefKind.EXECUTION_RECIPE_SCHEMA,
                ContractRefKind.EXECUTION_BLOCK,
                ContractRefKind.TOOL,
                ContractRefKind.ARGV_TEMPLATE,
                ContractRefKind.TIMEOUT_POLICY,
                ContractRefKind.RESOURCE_POLICY,
                ContractRefKind.OUTPUT_CONTRACT,
                ContractRefKind.ENVIRONMENT_POLICY,
            },
        )
        self.assertEqual(
            recipe.component_refs,
            tuple(
                sorted(
                    recipe.component_refs,
                    key=lambda reference: (
                        reference.kind.value,
                        reference.contract_id,
                        reference.contract_version,
                        reference.content_sha256,
                    ),
                )
            ),
        )

    def test_constructor_deep_freezes_collections_and_values_are_frozen(self):
        bindings = [
            ExecutionInputBinding(
                "probe",
                InputBindingSource.ARTIFACT_ROLE,
                "probe.source",
            )
        ]
        dependencies = []
        step = _step(bindings=bindings, depends_on=dependencies)
        steps = [step]
        recipe = _recipe(steps=steps)
        digest = recipe.content_sha256

        bindings.append(
            ExecutionInputBinding(
                "port",
                InputBindingSource.BROKER_VALUE,
                "network.loopback_port",
            )
        )
        dependencies.append("late")
        steps.append(_step("late"))

        self.assertEqual(len(recipe.steps), 1)
        self.assertEqual(len(recipe.steps[0].input_bindings), 1)
        self.assertEqual(recipe.steps[0].depends_on, ())
        self.assertEqual(recipe.content_sha256, digest)
        for value, field, replacement in (
            (recipe, "recipe_id", "changed"),
            (step, "cwd_symbol", "changed"),
            (bindings[0], "symbol", "changed"),
        ):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(value, field, replacement)

    def test_step_order_is_semantic_but_named_bindings_are_canonical(self):
        prepare = _step("prepare", bindings=())
        execute = _step("execute", bindings=())
        forward = _recipe(steps=(prepare, execute))
        reverse = _recipe(steps=(execute, prepare))
        self.assertNotEqual(forward.content_sha256, reverse.content_sha256)

        bindings = list(_step().input_bindings)
        reordered = _step(bindings=tuple(reversed(bindings)))
        self.assertEqual(_step().to_document(), reordered.to_document())

    def test_dependencies_must_be_unique_and_reference_prior_steps(self):
        prepare = _step("prepare", bindings=())
        execute = _step("execute", bindings=(), depends_on=("prepare",))
        recipe = _recipe(steps=(prepare, execute))
        self.assertEqual(recipe.steps[1].depends_on, ("prepare",))

        invalid_steps = (
            (_step("execute", bindings=(), depends_on=("missing",)),),
            (
                _step("execute", bindings=(), depends_on=("prepare",)),
                prepare,
            ),
            (prepare, _step("prepare", bindings=())),
        )
        for steps in invalid_steps:
            with self.subTest(steps=[step.step_id for step in steps]):
                with self.assertRaises(ContractError):
                    _recipe(steps=steps)

        with self.assertRaises(ContractError):
            _step("execute", bindings=(), depends_on=("execute",))
        with self.assertRaises(ContractError):
            _step(
                "execute",
                bindings=(),
                depends_on=("prepare", "prepare"),
            )

    def test_each_component_role_requires_the_exact_contract_ref_kind(self):
        baseline = _step()
        fields = {
            "execution_block": ContractRefKind.TOOL,
            "tool": ContractRefKind.ARGV_TEMPLATE,
            "argv_template": ContractRefKind.TOOL,
            "timeout_policy": ContractRefKind.RESOURCE_POLICY,
            "resource_policy": ContractRefKind.TIMEOUT_POLICY,
            "output_contract": ContractRefKind.ENVIRONMENT_POLICY,
            "environment_policy": ContractRefKind.OUTPUT_CONTRACT,
        }
        for field, wrong_kind in fields.items():
            with self.subTest(field=field), self.assertRaises(ContractError):
                dataclasses.replace(
                    baseline,
                    **{field: _ref(wrong_kind, "wrong")},
                )
        with self.assertRaises(ContractError):
            _recipe(recipe_schema=_ref(ContractRefKind.EXECUTION_BLOCK, "wrong"))

    def test_collection_budgets_and_conflicting_component_hashes_fail_closed(self):
        bindings = tuple(
            ExecutionInputBinding(
                f"binding{i}",
                InputBindingSource.CASE_PARAMETER,
                f"case.value{i}",
            )
            for i in range(1025)
        )
        with self.assertRaises(ContractError):
            _step(bindings=bindings)

        dependencies = tuple(f"step{i}" for i in range(1025))
        with self.assertRaises(ContractError):
            _step("last", bindings=(), depends_on=dependencies)

        with self.assertRaises(ContractError):
            _recipe(
                steps=tuple(
                    _step(f"step{i}", bindings=()) for i in range(1025)
                )
            )

        first = _step("first", bindings=())
        conflicting_tool = ContractRef(
            kind=first.tool.kind,
            contract_id=first.tool.contract_id,
            contract_version=first.tool.contract_version,
            content_sha256="f" * 64,
        )
        second = _step(
            "second",
            bindings=(),
            depends_on=("first",),
            tool=conflicting_tool,
        )
        with self.assertRaises(ContractError):
            _recipe(steps=(first, second))

    def test_parser_rejects_executable_values_and_decision_authority(self):
        base_document = _recipe().to_document()
        forbidden_fields = (
            "command",
            "shell",
            "argv",
            "env",
            "path",
            "workspace",
            "port",
            "gpu_uuid",
            "device_lease",
            "verdict",
            "threshold",
        )
        for field in forbidden_fields:
            document = copy.deepcopy(base_document)
            document["steps"][0][field] = "untrusted"
            with self.subTest(field=field), self.assertRaises(ContractError):
                ExecutionRecipe.from_document(document)

        document = copy.deepcopy(base_document)
        document["command"] = "bash -c 'touch owned'"
        with self.assertRaises(ContractError):
            ExecutionRecipe.from_document(document)

    def test_symbols_cannot_smuggle_shell_or_physical_paths(self):
        invalid_symbols = (
            ";touch-owned",
            "$(touch-owned)",
            "bash -c true",
            "/tmp/project",
            "../project",
            "workspace/project",
            "C:\\project",
            "value\x00tail",
        )
        for symbol in invalid_symbols:
            with self.subTest(symbol=symbol):
                with self.assertRaises(ContractError):
                    ExecutionInputBinding(
                        "input",
                        InputBindingSource.PROFILE_VALUE,
                        symbol,
                    )
                with self.assertRaises(ContractError):
                    _step(cwd_symbol=symbol)
                with self.assertRaises(ContractError):
                    _step(stdin_artifact_role=symbol)

    def test_parser_is_exact_and_rejects_wrong_versions_and_binding_values(self):
        document = _recipe().to_document()
        mutations = (
            ("contract_kind", "other"),
            ("schema_version", 2),
            ("schema_version", True),
        )
        for field, value in mutations:
            changed = copy.deepcopy(document)
            changed[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ContractError):
                    ExecutionRecipe.from_document(changed)

        missing = copy.deepcopy(document)
        missing.pop("recipe_version")
        with self.assertRaises(ContractError):
            ExecutionRecipe.from_document(missing)

        bad_source = copy.deepcopy(document)
        bad_source["steps"][0]["input_bindings"][0]["source"] = "literal"
        with self.assertRaises(ContractError):
            ExecutionRecipe.from_document(bad_source)

        literal_value = copy.deepcopy(document)
        literal_value["steps"][0]["input_bindings"][0]["value"] = "owned"
        with self.assertRaises(ContractError):
            ExecutionRecipe.from_document(literal_value)

    def test_semantic_tampering_changes_hash_and_ref(self):
        baseline = _recipe()
        changed_cwd = _recipe(
            steps=(
                dataclasses.replace(
                    _step(),
                    cwd_symbol="workspace.variant",
                ),
            )
        )
        changed_tool = _recipe(
            steps=(
                dataclasses.replace(
                    _step(),
                    tool=_ref(ContractRefKind.TOOL, "other"),
                ),
            )
        )
        for changed in (changed_cwd, changed_tool):
            self.assertNotEqual(baseline.content_sha256, changed.content_sha256)
            self.assertNotEqual(baseline.ref, changed.ref)

    def test_contract_module_has_no_execution_or_host_resource_imports(self):
        source_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "validation_core"
            / "contracts"
            / "execution.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_roots = {
            "asyncio",
            "ctypes",
            "multiprocessing",
            "os",
            "pathlib",
            "shlex",
            "socket",
            "subprocess",
        }
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(imported.isdisjoint(forbidden_roots), imported)


if __name__ == "__main__":
    unittest.main()
