"""Chisel and Verilog specification Profiles for the public Pipeline."""

from __future__ import annotations

from typing import Sequence

from src.specification import (
    ArtifactPair,
    BatchPromptContext,
    GenerationPromptContext,
    PromptBundle,
    SpecificationProfile,
)

from .readers import HARDWARE_DEPENDENCY_READER, HARDWARE_SELF_SPEC_READER
from .validation import validate_chisel_artifacts, validate_verilog_artifacts


class HardwarePromptContract:
    """Dynamic Markdown output and retry wording shared by chip dialects."""

    def __init__(self, dialect: str) -> None:
        if dialect not in {"chisel", "verilog"}:
            raise ValueError(f"unsupported hardware prompt dialect: {dialect!r}")
        self.dialect = dialect

    def batch_output_section(
        self,
        context: BatchPromptContext,
    ) -> Sequence[str]:
        dependency_rule = (
            "For Verilog/SystemVerilog, every expected direct module dependency "
            "must have a non-empty matching section; missing coverage is an error."
            if self.dialect == "verilog"
            else
            "For Chisel, include every known direct module dependency; missing "
            "coverage is advisory and must not be replaced by an invented dependency."
        )
        dialect_rules = (
            (
                "Treat Scala constructors, loops, conditionals, generators, and "
                "type-level computation as elaboration-time behavior, not runtime cycles.",
                "Expand Bundle, Vec, Decoupled, Valid, enum, and nested interface "
                "fields only when their names, types, directions, or meanings are "
                "supported by the source or domain context.",
                "Keep ordinary Scala classes, objects, traits, parameters, and helpers "
                "as context rather than independent hardware modules.",
            )
            if self.dialect == "chisel"
            else
            (
                "Treat macros, packages, parameters, generate conditions, and "
                "preprocessor choices as elaboration-time configuration.",
                "Do not infer ready/valid transfers or protocol behavior from signal "
                "names; use the exact RTL control condition.",
                "State exact cycle counts only when counter load, decrement, zero "
                "detection, and transition behavior establish them; otherwise use TBD.",
            )
        )
        return (
            "## OUTPUT FORMAT (two standalone Markdown files per module)",
            "",
            "For each extracted module, write both sibling artifacts in the same "
            "directory:",
            f"- `{context.self_artifact_name}`: the module's observable behavioral contract",
            f"- `{context.dependency_artifact_name}`: caller-driven requirements for "
            "its direct module dependencies",
            "",
            "Use the exact extracted filename stem for both artifact names. Do not "
            "modify the extracted source file.",
            "",
            "## REQUIRED CONTENT",
            "- Follow the complete structure and dialect rules in "
            "`fm_agent/spec_prompts/system_prompt.md`.",
            "- Every self-spec must contain a standalone `<FG-API>` group, with the "
            "literal `<FG-API>` tag on its own line.",
            "- Every `<FG-*>` must contain an `<FC-*>`, and every `<FC-*>` must "
            "contain at least one `<CK-*>`.",
            "- Use `# Submodule: <ExactDeclaredModuleType>` once per known direct "
            "dependency, folding repeated instances by module type.",
            "- Write the exact leaf marker `(no submodules)` only when no direct "
            "dependency is known; never combine it with dependency headings.",
            f"- {dependency_rule}",
            *[f"- {rule}" for rule in dialect_rules],
            "- Describe intended, observable behavior; do not invent ports, widths, "
            "parameters, reset values, dependencies, protocol rules, or cycle counts.",
            "",
            "## PROCESS",
            "1. Read the extracted module source and the supplied caller expectations.",
            "2. Read the domain context and the mandatory system prompt.",
            "3. Write complete sibling self-spec and dependency-info Markdown files.",
            "4. Check the FG/FC/CK tree, dependency headings, and exact artifact names.",
            "5. Use the Write tool to save both artifacts and leave source files unchanged.",
        )

    def generation_instruction(self, context: GenerationPromptContext) -> str:
        if context.attempt == 1:
            return (
                f"Process the hardware batch prompt at {context.batch_prompt_rel}. "
                f"Read it and {context.system_prompt_rel}, generate the requested "
                "behavioral Markdown for every module listed, and write both "
                f"{context.self_artifact_suffix} and "
                f"{context.dependency_artifact_suffix} files for each module."
            )
        return (
            f"Continue processing the hardware batch prompt at {context.batch_prompt_rel}. "
            "Check every listed module. Skip a module only when both sibling artifacts "
            "already satisfy the Markdown validation contract; otherwise rewrite both "
            f"{context.self_artifact_suffix} and {context.dependency_artifact_suffix} "
            f"after reading {context.system_prompt_rel} and the validation feedback."
        )


CHIP_MARKDOWN_PROMPT_CONTRACT = HardwarePromptContract("chisel")
VERILOG_MARKDOWN_PROMPT_CONTRACT = HardwarePromptContract("verilog")


_HARDWARE_ARTIFACTS = ArtifactPair(
    self_suffix="_spec.md",
    dependency_suffix="_info.md",
    append_to_filename=False,
)


def _prompt_bundle(dialect: str) -> PromptBundle:
    return PromptBundle(
        phase_plan=f"prompts/{dialect}/workflow_generate_phases.md",
        domain_context=f"prompts/{dialect}/workflow_generate_domain_context.md",
        system=f"prompts/{dialect}/system_prompt.md",
        batch_workflow="prompts/workflow_spec_step4_batch.md",
    )


CHISEL_PROMPTS = _prompt_bundle("chisel")
VERILOG_PROMPTS = _prompt_bundle("verilog")


CHISEL_PROFILE = SpecificationProfile(
    id="chip-chisel",
    schema_version="V1",
    artifacts=_HARDWARE_ARTIFACTS,
    prompts=CHISEL_PROMPTS,
    languages=("chisel",),
    validator=validate_chisel_artifacts,
    self_spec_reader=HARDWARE_SELF_SPEC_READER,
    dependency_reader=HARDWARE_DEPENDENCY_READER,
    enable_reasoning=False,
    prompt_contract=CHIP_MARKDOWN_PROMPT_CONTRACT,
)

VERILOG_PROFILE = SpecificationProfile(
    id="chip-verilog",
    schema_version="V1",
    artifacts=_HARDWARE_ARTIFACTS,
    prompts=VERILOG_PROMPTS,
    languages=("verilog",),
    validator=validate_verilog_artifacts,
    self_spec_reader=HARDWARE_SELF_SPEC_READER,
    dependency_reader=HARDWARE_DEPENDENCY_READER,
    enable_reasoning=False,
    prompt_contract=VERILOG_MARKDOWN_PROMPT_CONTRACT,
)


PROFILES: dict[str, SpecificationProfile] = {
    "chisel": CHISEL_PROFILE,
    "verilog": VERILOG_PROFILE,
}
