"""Runtime configuration for the built-in specification pipeline."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator

from .base import SpecForm


@dataclass
class SpecGenerationConfig:
    """Select the specification strategy and optional downstream reasoning."""

    spec_form: SpecForm
    enable_reasoning: bool = True

    def should_run_reasoning(self, only_spec: bool) -> bool:
        """Return whether reasoning and bug validation should run."""
        return self.enable_reasoning and not only_spec


_CURRENT_SPEC_GENERATION_CONFIG: ContextVar[SpecGenerationConfig] = (
    ContextVar("fm_agent_spec_generation_config")
)


@contextmanager
def _bind_spec_generation_config(
    config: SpecGenerationConfig,
) -> Iterator[None]:
    """Bind one pipeline run's configuration while its configure hook runs."""
    token = _CURRENT_SPEC_GENERATION_CONFIG.set(config)
    try:
        yield
    finally:
        _CURRENT_SPEC_GENERATION_CONFIG.reset(token)


def configure_current_spec_generation(
    *,
    spec_form: SpecForm,
    enable_reasoning: bool,
) -> None:
    """Update the specification strategy for the active pipeline run."""
    try:
        config = _CURRENT_SPEC_GENERATION_CONFIG.get()
    except LookupError as exc:
        raise RuntimeError(
            "configure_current_spec_generation() may only be called from "
            "a plugin configure hook"
        ) from exc

    config.spec_form = spec_form
    config.enable_reasoning = enable_reasoning


def _validate_spec_generation_config(
    config: SpecGenerationConfig,
) -> None:
    """Fail fast when a pipeline run has an invalid specification strategy."""
    if not isinstance(config, SpecGenerationConfig):
        raise ValueError(
            "specification strategy must be a SpecGenerationConfig instance"
        )
    if not isinstance(config.spec_form, SpecForm):
        raise ValueError(
            "SpecGenerationConfig.spec_form must be a SpecForm instance"
        )
    if type(config.enable_reasoning) is not bool:
        raise ValueError(
            "SpecGenerationConfig.enable_reasoning must be bool"
        )
    if (
        not isinstance(config.spec_form.id, str)
        or not config.spec_form.id.strip()
    ):
        raise ValueError("SpecForm.id must be a non-empty string")
    if (
        not isinstance(config.spec_form.schema_version, str)
        or not config.spec_form.schema_version.strip()
    ):
        raise ValueError(
            "SpecForm.schema_version must be a non-empty string"
        )
