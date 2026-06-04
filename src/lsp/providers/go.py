import os
import re
import shutil

from config import LSP_TIMEOUT_SECONDS

from ..client import JsonRpcLspClient, path_to_uri
from ..models import LspCallEdge, LspProviderResult, LspSymbol


_GO_CALL_RE = re.compile(r"(?<!\.)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_GO_KEYWORDS = {
    "append", "cap", "close", "complex", "copy", "delete", "imag", "len",
    "make", "new", "panic", "print", "println", "real", "recover",
    "if", "for", "switch", "select", "return", "defer", "go", "range",
}


class GoGoplsProvider:
    """Go provider backed by gopls document symbols.

    Calls are resolved best-effort from source against the LSP symbol table.
    Method calls are intentionally left to regex fallback until we add a
    call-hierarchy based resolver.
    """

    id = "go.gopls"
    languages = {"go"}
    extensions = {".go"}

    def is_available(self):
        return shutil.which("gopls") is not None

    def can_handle(self, proj_dir, source_files):
        return any(path.endswith(".go") and not path.endswith("_test.go") for path in source_files)

    def analyze(self, proj_dir, work_dir, source_files):
        go_files = [
            path for path in source_files
            if path.endswith(".go") and not path.endswith("_test.go")
        ]
        if not go_files:
            return LspProviderResult(self.id, True)
        if not self.is_available():
            return LspProviderResult(self.id, False, error="gopls not found in PATH")

        client = JsonRpcLspClient(["gopls"], proj_dir, timeout=LSP_TIMEOUT_SECONDS)
        try:
            client.initialize()
            symbols = []
            for rel in go_files:
                full_path = os.path.join(proj_dir, rel)
                if not os.path.exists(full_path):
                    continue
                client.did_open(full_path, "go")
                raw_symbols = client.request("textDocument/documentSymbol", {
                    "textDocument": {"uri": path_to_uri(full_path)}
                }) or []
                symbols.extend(self._symbols_from_document(rel, raw_symbols))
            calls = self._build_calls_from_source(proj_dir, go_files, symbols)
            return LspProviderResult(
                self.id,
                True,
                symbols=symbols,
                calls=calls,
                metadata={"files": len(go_files), "method": "documentSymbol+source-resolution"},
            )
        except Exception as exc:
            return LspProviderResult(self.id, False, error=str(exc), metadata={"files": len(go_files)})
        finally:
            client.shutdown()

    def _symbols_from_document(self, rel_path, raw_symbols):
        symbols = []
        name_counts = {}
        for item in self._flatten_symbols(raw_symbols):
            kind = item.get("kind")
            if kind not in (6, 12):  # Method, Function
                continue
            name = item.get("name", "")
            if not name:
                continue
            range_info = item.get("range") or item.get("location", {}).get("range") or {}
            start = range_info.get("start", {})
            end = range_info.get("end", {})
            line_start = int(start.get("line", 0))
            line_end = int(end.get("line", line_start))
            clean_name = name.rsplit(".", 1)[-1]
            # Match extraction's duplicate-name convention: Set, Set_1, ...
            count = name_counts.get(clean_name, 0)
            name_counts[clean_name] = count + 1
            extracted_name = f"{clean_name}_{count}" if count > 0 else clean_name
            symbol_id = f"{rel_path}::{extracted_name}"
            symbols.append(LspSymbol(
                id=symbol_id,
                name=extracted_name,
                qualified_name=name,
                language="go",
                kind="method" if kind == 6 else "function",
                source_file=rel_path,
                start_line=line_start,
                end_line=line_end,
                start_col=int(start.get("character", 0)),
                end_col=int(end.get("character", 0)),
                metadata={"lsp_kind": kind, "base_name": clean_name},
            ))
        return symbols

    def _flatten_symbols(self, raw_symbols):
        out = []
        for item in raw_symbols:
            if "location" in item:
                out.append(item)
                continue
            out.append(item)
            children = item.get("children") or []
            if children:
                out.extend(self._flatten_symbols(children))
        return out

    def _build_calls_from_source(self, proj_dir, go_files, symbols):
        """Build intra-project call edges from direct function calls."""
        stem_to_symbols = {}
        file_to_symbols = {}
        for symbol in symbols:
            stem_to_symbols.setdefault(symbol.name, []).append(symbol)
            file_to_symbols.setdefault(symbol.source_file, []).append(symbol)

        calls = []
        seen = set()
        for rel in go_files:
            full_path = os.path.join(proj_dir, rel)
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            for caller in file_to_symbols.get(rel, []):
                body = "".join(lines[caller.start_line:caller.end_line + 1])
                for match in _GO_CALL_RE.finditer(_strip_go_comments_and_strings(body)):
                    name = match.group(1)
                    if name in _GO_KEYWORDS:
                        continue
                    for callee in stem_to_symbols.get(name, []):
                        if callee.id == caller.id:
                            continue
                        key = (caller.id, callee.id, name)
                        if key in seen:
                            continue
                        seen.add(key)
                        calls.append(LspCallEdge(
                            caller_id=caller.id,
                            callee_id=callee.id,
                            caller_name=caller.qualified_name,
                            callee_name=callee.qualified_name,
                            caller_file=caller.source_file,
                            callee_file=callee.source_file,
                            kind="direct",
                            confidence="name_resolved",
                        ))
        return calls


def _strip_go_comments_and_strings(text):
    result = []
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if ch == "/" and nxt == "/":
            while i < len(text) and text[i] != "\n":
                result.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            result.extend("  ")
            i += 2
            while i < len(text):
                if text[i] == "*" and i + 1 < len(text) and text[i + 1] == "/":
                    result.extend("  ")
                    i += 2
                    break
                result.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        if ch in ('"', "'", "`"):
            quote = ch
            result.append(" ")
            i += 1
            while i < len(text):
                if quote != "`" and text[i] == "\\":
                    result.extend("  ")
                    i += 2
                    continue
                if text[i] == quote:
                    result.append(" ")
                    i += 1
                    break
                result.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        result.append(ch)
        i += 1
    return "".join(result)
