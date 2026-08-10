"""Runtime configuration for the built-in specification pipeline."""

from dataclasses import dataclass

from .base import SpecForm


@dataclass
class SpecGenerationConfig:
    """Select the specification strategy and optional downstream reasoning."""

    spec_form: SpecForm
    enable_reasoning: bool = True

    def should_run_reasoning(self, only_spec: bool) -> bool:
        """Return whether reasoning and bug validation should run."""
        return self.enable_reasoning and not only_spec
