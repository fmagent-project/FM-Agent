"""Verilog hardware specification form."""

from .base import HardwareSpecForm


class VerilogSpecForm(HardwareSpecForm):
    id = "chip-verilog"
    dialect = "verilog"
    dependency_coverage_is_blocking = True
