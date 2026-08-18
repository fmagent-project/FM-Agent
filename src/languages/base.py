"""Shared base classes for language backends."""


class BackendUnavailableError(RuntimeError):
    """Raised when a language's semantic backend is needed but cannot be consulted.

    function_spans may raise this for languages where a regex fallback is
    unsafe. Callers that only want to detect current
    functions can fall back to regex; callers that are about to delete
    extracted-function artifacts should skip the file instead.
    """
