from typing import Protocol

from .models import LspProviderResult


class LspProvider(Protocol):
    id: str
    languages: set[str]
    extensions: set[str]

    def is_available(self) -> bool:
        ...

    def can_handle(self, proj_dir: str, source_files: list[str]) -> bool:
        ...

    def analyze(self, proj_dir: str, work_dir: str, source_files: list[str]) -> LspProviderResult:
        ...


class LspRegistry:
    def __init__(self):
        self._providers = []

    def register(self, provider: LspProvider):
        if any(existing.id == provider.id for existing in self._providers):
            return
        self._providers.append(provider)

    def providers_for(self, proj_dir: str, source_files: list[str]):
        return [
            provider for provider in self._providers
            if provider.can_handle(proj_dir, source_files)
        ]

    def provider_extensions(self):
        exts = set()
        for provider in self._providers:
            exts.update(provider.extensions)
        return exts


LSP_REGISTRY = LspRegistry()


def register_default_providers():
    from .providers.go import GoGoplsProvider

    LSP_REGISTRY.register(GoGoplsProvider())
