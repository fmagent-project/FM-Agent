"""Verilog/SystemVerilog Stage 1/2 strategy."""

from .base import DialectStrategy


VERILOG_STRATEGY = DialectStrategy(
    dialect="verilog",
    language="verilog",
    extensions=("v", "sv", "svh"),
)
