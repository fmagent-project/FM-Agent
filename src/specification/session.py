"""Runtime binding for one plugin's specification profile configuration."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .profile import SOFTWARE_PROFILE, SpecificationProfile


@dataclass
class SpecificationProfileSession:
    """Collect at most one profile during a configure hook invocation."""

    default_profile: SpecificationProfile = SOFTWARE_PROFILE
    plugin_root: Path | None = None
    default_prompt_root: Path | None = None
    _registered_profile: SpecificationProfile | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _closed: bool = field(default=False, init=False, repr=False)

    def register(self, profile: SpecificationProfile) -> None:
        if self._closed:
            raise RuntimeError(
                "specification profile configuration is already frozen"
            )
        if not isinstance(profile, SpecificationProfile):
            raise TypeError(
                "configure_specification() expects a SpecificationProfile"
            )
        if self._registered_profile is not None:
            raise RuntimeError(
                "a configure hook may register only one specification profile"
            )
        self._registered_profile = profile

    def freeze_and_validate(self) -> SpecificationProfile:
        if self._closed:
            raise RuntimeError("specification profile session is already frozen")
        self._closed = True

        registered = self._registered_profile is not None
        profile = self._registered_profile or self.default_profile
        prompt_root = self.plugin_root if registered else self.default_prompt_root
        try:
            resolved = profile.with_prompt_root(prompt_root)
            resolved.validate_configuration(
                allow_reasoning=(
                    not registered and profile is SOFTWARE_PROFILE
                )
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"invalid specification profile {profile.id!r}: {exc}"
            ) from exc
        return resolved


_BOUND_SESSION: ContextVar[SpecificationProfileSession | None] = ContextVar(
    "fm_agent_specification_profile_session",
    default=None,
)


@contextmanager
def bind_profile_session(
    session: SpecificationProfileSession,
) -> Iterator[SpecificationProfileSession]:
    """Bind a session only for the synchronous configure hook lifetime."""
    token = _BOUND_SESSION.set(session)
    try:
        yield session
    finally:
        _BOUND_SESSION.reset(token)


def configure_specification(profile: SpecificationProfile) -> None:
    """Register a profile from inside the active configure hook."""
    session = _BOUND_SESSION.get()
    if session is None:
        raise RuntimeError(
            "configure_specification() may only be called from a plugin "
            "configure hook"
        )
    session.register(profile)
