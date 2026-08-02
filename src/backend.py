"""Backend adapter for external FM-Agent services."""

from .opencode_trace import run_opencode_traced
from .reasoner import reasoner


class ProductionBackend:
    """Default backend that calls the real OpenCode runner and LLM reasoner."""

    def run_opencode_traced(self, **kwargs):
        return run_opencode_traced(**kwargs)

    def reasoner(self, func, spec, info, language, trace_context=None):
        return reasoner(func, spec, info, language, trace_context=trace_context)


DEFAULT_BACKEND = ProductionBackend()
