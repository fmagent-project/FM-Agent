from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LspSymbol:
    id: str
    name: str
    qualified_name: str
    language: str
    kind: str
    source_file: str
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self):
        return asdict(self)


@dataclass
class LspCallEdge:
    caller_id: str
    callee_id: str | None
    caller_name: str
    callee_name: str
    caller_file: str
    callee_file: str | None
    line: int | None = None
    kind: str = "direct"
    confidence: str = "resolved"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self):
        return asdict(self)


@dataclass
class LspProviderResult:
    provider_id: str
    success: bool
    symbols: list[LspSymbol] = field(default_factory=list)
    calls: list[LspCallEdge] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def status_json(self):
        return {
            "id": self.provider_id,
            "success": self.success,
            "symbols": len(self.symbols),
            "calls": len(self.calls),
            "error": self.error,
            "metadata": self.metadata,
        }
