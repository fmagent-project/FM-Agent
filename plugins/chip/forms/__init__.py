"""Hardware specification forms selected by the chip plugin."""

from .chisel import ChiselSpecForm
from .verilog import VerilogSpecForm

__all__ = ["ChiselSpecForm", "VerilogSpecForm"]
