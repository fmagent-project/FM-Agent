"""Verilog specification-form identity for run-scoped configuration."""

from .base import BootstrapHardwareSpecForm


class VerilogSpecForm(BootstrapHardwareSpecForm):
    id = "chip-verilog"
    dialect = "verilog"
