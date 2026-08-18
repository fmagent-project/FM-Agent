"""Chisel Stage 1/2 strategy."""

from .base import DialectStrategy


CHISEL_STRATEGY = DialectStrategy(
    dialect="chisel",
    language="chisel",
    extensions=("scala", "sc"),
)
