"""Chisel specification-form identity for run-scoped configuration."""

from .base import BootstrapHardwareSpecForm


class ChiselSpecForm(BootstrapHardwareSpecForm):
    id = "chip-chisel"
    dialect = "chisel"
