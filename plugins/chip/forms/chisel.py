"""Chisel hardware specification form."""

from .base import HardwareSpecForm


class ChiselSpecForm(HardwareSpecForm):
    id = "chip-chisel"
    dialect = "chisel"
