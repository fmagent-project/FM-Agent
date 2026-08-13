"""Staged CCC preset content; deliberately absent from every Registry."""

from __future__ import annotations

from ...contracts.preset import PresetDependency, ValidationPreset
from .components import (
    CCC_ADAPTER,
    CCC_COMPATIBILITY_POLICY,
    CCC_ORACLE_BUNDLE,
    CCC_RECIPE_SCHEMA,
    CCC_REPAIR_POLICY,
    CCC_SANITY_POLICY,
    CCC_TARGET_EVIDENCE,
    CCC_TOOLCHAIN_POLICY,
)


CCC_LEGACY_PRESET = ValidationPreset(
    preset_id="ccc.legacy_boundary_witness_v3",
    preset_version="1.0.0",
    system_id="ccc",
    dependencies=(
        PresetDependency("adapter.primary", CCC_ADAPTER.ref),
        PresetDependency("oracle.bundle", CCC_ORACLE_BUNDLE.ref),
        PresetDependency("recipe.schema", CCC_RECIPE_SCHEMA.ref),
        PresetDependency("target_evidence.policy", CCC_TARGET_EVIDENCE.ref),
        PresetDependency("repair.policy", CCC_REPAIR_POLICY.ref),
        PresetDependency("sanity.policy", CCC_SANITY_POLICY.ref),
        PresetDependency(
            "compatibility.policy",
            CCC_COMPATIBILITY_POLICY.ref,
        ),
        PresetDependency("toolchain.policy", CCC_TOOLCHAIN_POLICY.ref),
    ),
    capabilities=(
        "compiler_entry",
        "differential_oracle",
        "legacy_compatibility",
        "l1_repair",
        "target_evidence",
    ),
)
