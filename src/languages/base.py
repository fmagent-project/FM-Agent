"""Shared base classes for language backends."""

from dataclasses import dataclass


@dataclass(frozen=True)
class IndirectSite:
    """One indirect call and the functions it may reach.

    An indirect call's callee is a value chosen at run time, such as a C
    function pointer, so the source names no callee. Returned by a language
    handler's ``indirect_calls``. ``label`` is how the call site is written
    (the name a caller's .info.json entry uses for it).
    """

    caller: str
    label: str
    short_name: str
    file: str
    line: int
    targets: tuple[str, ...]
    how: str  # "flow": reached by value flow; "type": matched by function type
    via: tuple[str, ...] = ()  # where the called value is read from, for humans


class BackendUnavailableError(RuntimeError):
    """Raised when a language's semantic backend is needed but cannot be consulted.

    function_spans may raise this for languages where a regex fallback is
    unsafe (currently Erlang/ELP). Callers that only want to detect current
    functions can fall back to regex; callers that are about to delete
    extracted-function artifacts should skip the file instead.
    """
