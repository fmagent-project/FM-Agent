"""Verilog hardware specification form."""

from typing import Sequence

from .base import HardwareSpecForm


class VerilogSpecForm(HardwareSpecForm):
    id = "chip-verilog"
    dialect = "verilog"
    dependency_coverage_is_blocking = True

    def batch_rules(self, language: str) -> Sequence[str]:
        return (
            *super().batch_rules(language),
            "Preserve exact module, parameter, port, packed/unpacked width, "
            "and clock/reset declarations without inferring missing values",
            "Distinguish compile/preprocessor and generate-time configuration "
            "from cycle-observable RTL behavior",
            "Use exact declared module types, not instance labels, in "
            "'# Submodule:' entries and fold repeated instances into one "
            "dependency contract",
            "Do not infer ready/valid transfers or other protocol behavior "
            "from signal names; check the exact RTL control condition",
            "State exact cycle counts only after accounting for counter load, "
            "decrement, zero, and transition cycles; otherwise use TBD",
            "If the RTL diverges from an intended protocol rule, describe the "
            "intended contract and the source divergence without asserting "
            "conflicting guarantees",
            "Cover every known direct module dependency in _info.md; missing "
            "Verilog dependency coverage blocks artifact completion",
        )
