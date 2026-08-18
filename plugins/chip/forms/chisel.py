"""Chisel hardware specification form."""

from typing import Sequence

from .base import HardwareSpecForm


class ChiselSpecForm(HardwareSpecForm):
    id = "chip-chisel"
    dialect = "chisel"

    def batch_rules(self, language: str) -> Sequence[str]:
        return (
            *super().batch_rules(language),
            "Treat Scala constructors, loops, conditionals, and generators as "
            "elaboration-time behavior, not runtime cycles",
            "Expand verification-relevant Bundle, Vec, Decoupled, Valid, enum, "
            "and nested interface fields without inventing widths or directions",
            "Keep ordinary Scala classes, objects, traits, parameters, and "
            "helpers as context; do not turn them into hardware modules",
            "Use exact declared module names in '# Submodule:' entries and fold "
            "repeated instances into one dependency contract",
        )
