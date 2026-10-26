"""Calls through C function pointers, resolved from Clang's AST.

A call such as ``s_hooks[i].fn(e)`` or ``(*me->temp.fun)(me, e)`` names no
function, so neither codegraph nor the Clang direct-call pass can give it a
callee. This module follows function addresses instead: wherever a function is
used as a value (an initializer, an assignment, an argument, a return value, a
cast), the address is recorded at the location it is stored in, and every
indirect call is linked to all functions that can reach the location it reads.

Locations are field-based and context-insensitive:

- a global variable (static ones qualified by their file), a local variable,
- the i-th parameter and the return value of a function,
- a struct field, keyed by struct name and field name (all fields of a union
  are one location; an unnamed struct is named by where it is declared).

Facts from every translation unit are merged, so a callback registered in one
file and called in another is connected. A call whose location receives no
function falls back to the functions of the same type that are used as values.
The analysis reads macro-expanded code, so calls hidden in macros are seen.

Each resolved call site is returned as an ``IndirectSite``; the layer
generator turns its targets into supplemental call edges named by the site's
label, so a caller's ``.info.json`` entry for the site reaches every target.
"""

import logging
import os
import re
from collections import defaultdict
from pathlib import Path

from src.languages import clang as _clang
from src.languages.base import IndirectSite

logger = logging.getLogger(__name__)

_MAX_ROUNDS = 6
_SKIPPED_DIRS = {".git", ".codegraph", "fm_agent", "node_modules"}
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".h++"}
_TRANSPARENT = {
    "ImplicitCastExpr",
    "CStyleCastExpr",
    "ParenExpr",
    "UnaryOperator",
    "ConstantExpr",
}
# Clang names the type of an unnamed struct or union by where it is declared:
# "struct (unnamed struct at src/a.c:5:14)".
_UNNAMED_RECORD = re.compile(r"\(unnamed(?: struct| union)? at (.+):(\d+):(\d+)\)")
_CACHE = {}


def analyze(extractor) -> list[IndirectSite]:
    """Return the indirect call sites of the project's C code.

    Empty when Clang is unavailable or the project has no indexed C functions.
    Results are cached for the life of the process and invalidated when the
    codegraph index or compilation database changes.
    """
    root = Path(extractor._db).resolve().parent.parent
    command = _clang._clang_command("c")
    if command is None:
        return []
    database_path = _clang._compile_database_path(root)
    cache_key = _clang._cache_key(root, extractor, "c", command, database_path)
    if cache_key is not None and cache_key in _CACHE:
        return _CACHE[cache_key]

    indexed = _clang._clang_function_fqns(extractor, root, "c")
    if indexed is None or not indexed[1]:
        return []
    functions = indexed[0]
    # codegraph labels some C headers as C++; their functions still take part
    # in the C code's calls through pointers.
    cpp_indexed = _clang._clang_function_fqns(extractor, root, "cpp")
    for path, entries in (cpp_indexed[0] if cpp_indexed else {}).items():
        if path not in functions and Path(path).suffix.lower() in _HEADER_SUFFIXES:
            functions[path] = entries
    # Headers are analyzed through the .c files that include them; parsed on
    # their own they add time (and, in C++ projects, noise) but no new facts.
    tasks = [
        task
        for task in _clang._clang_tasks(root, "c", functions, database_path) or ()
        if task[0].suffix.lower() not in _HEADER_SUFFIXES
    ]
    if not tasks:
        return []
    include_args = None
    analysis = _Analysis(root, functions)
    parsed = 0
    timeout = _clang._clang_timeout()
    for index, (source, directory, arguments) in enumerate(tasks):
        if not arguments:
            # No compilation database: point Clang at every header directory,
            # which is what a build would have passed with -I.
            if include_args is None:
                include_args = [f"-I{path}" for path in _header_dirs(root)]
            arguments = [command[0], *include_args]
        # A translation unit with errors still has an AST for what Clang parsed.
        ast = _clang._run_clang_ast(
            command, (source, directory, arguments), "c", timeout, allow_errors=True
        )
        if ast is None:
            continue
        try:
            analysis.add_translation_unit(ast, index, directory)
        except Exception as exc:  # noqa: BLE001 - one odd AST must not cost the rest
            logger.debug("Skipped the AST of %s: %s: %s", source, type(exc).__name__, exc)
            continue
        finally:
            del ast
        parsed += 1

    sites = analysis.solve()
    resolved = defaultdict(int)
    for site in sites:
        resolved[site.how] += 1
    print(
        f"[IndirectCalls] c: {len(sites)} call sites through function pointers "
        f"from {parsed}/{len(tasks)} translation units; {resolved['flow']} resolved "
        f"by value flow, {resolved['type']} by function type, "
        f"{analysis.unresolved} unresolved."
    )
    if analysis.lost:
        names = sorted(set().union(*analysis.lost.values()))
        shown = ", ".join(names[:5]) + (f", and {len(names) - 5} more" if len(names) > 5 else "")
        noun = "call site" if len(analysis.lost) == 1 else "call sites"
        print(
            f"[IndirectCalls] c: left out targets of {len(analysis.lost)} {noun} "
            f"because codegraph did not extract them as functions: {shown}."
        )
    _clang._cache_result(_CACHE, cache_key, sites)
    return sites


def _header_dirs(root: Path) -> list[str]:
    found = set()
    for directory, subdirectories, filenames in os.walk(root):
        subdirectories[:] = [
            name for name in subdirectories
            if name not in _SKIPPED_DIRS and not name.startswith(".")
        ]
        if any(name.endswith(".h") for name in filenames):
            found.add(directory)
    return sorted(found)


def _normalize_type(text):
    """'void (*const)(int)' and 'void (int)' both become 'void(int)'."""
    if not text:
        return None
    text = re.sub(r"\(\s*\*\s*(const\s*)?\)", "", text, count=1)
    text = re.sub(r"\b(const|volatile)\b", "", text)
    return re.sub(r"\s+", "", text)


def _type_of(node, desugar=True):
    node_type = node.get("type") or {}
    return (node_type.get("desugaredQualType") if desugar else None) or node_type.get("qualType")


def _first_child(node):
    children = node.get("inner") if isinstance(node, dict) else None
    return children[0] if children else None


def _children(node):
    """Child nodes, including the elements of a partly filled array initializer.

    Clang lists the elements of an array initializer with gaps (``f[8] = {a}``,
    ``[3] = a``) under "array_filler" instead of "inner".
    """
    return [*(node.get("inner") or ()), *(node.get("array_filler") or ())]


class _Analysis:
    """Value-flow facts collected across translation units, then solved."""

    def __init__(self, root: Path, functions):
        self.root = root
        self.functions = functions
        self.flows = defaultdict(set)      # location -> sources (functions or locations)
        # function key -> FQNs of its definitions; a non-static name may be
        # defined in several files (e.g. a test build and the real one)
        self.fqns_of = defaultdict(set)
        self.types_of = defaultdict(set)   # function key -> types it is used as
        self.sites = []                    # raw indirect call sites, by id
        self.sources = {}                  # relative path -> bytes, for labels
        self.unresolved = 0
        # function key -> name, for definitions codegraph did not extract
        self.unextracted = {}
        self.lost = defaultdict(set)       # site key -> names of unextracted targets

    # ---- collection ---------------------------------------------------------

    def add_translation_unit(self, ast, tu, directory):
        unit = _TranslationUnit(self, tu, directory)
        unit.declarations(ast)
        unit.facts(ast)

    def source_text(self, relative, start, end):
        if relative is None or start is None or end is None:
            return None
        if relative not in self.sources:
            try:
                self.sources[relative] = (self.root / relative).read_bytes()
            except OSError:
                self.sources[relative] = b""
        return self.sources[relative][start:end].decode("utf-8", "replace")

    # ---- solving ------------------------------------------------------------

    def _points_to(self):
        points = defaultdict(set)
        changed = True
        while changed:
            changed = False
            for location, sources in list(self.flows.items()):
                new = set()
                for source in sources:
                    if source[0] == "fn":
                        new.add(source[1])
                    else:
                        new |= points.get(source, set())
                if not new <= points[location]:
                    points[location] |= new
                    changed = True
        return points

    def solve(self) -> list[IndirectSite]:
        sites = [site for site in self.sites if site]
        for _ in range(_MAX_ROUNDS):
            points = self._points_to()
            before = sum(len(value) for value in self.flows.values())
            for site in sites:
                targets = set()
                for value in site["callee"]:
                    targets |= {value[1]} if value[0] == "fn" else points.get(value, set())
                site["targets"] = targets
                # A resolved indirect call passes its arguments and receives
                # the return value exactly as a direct call would.
                for target in targets:
                    for position, argument in enumerate(site["args"]):
                        self.flows[("p", target, position)] |= argument
                    self.flows[("rs", site["id"])].add(("r", target))
            if sum(len(value) for value in self.flows.values()) == before:
                break

        taken = {
            source[1]
            for sources in self.flows.values()
            for source in sources
            if source[0] == "fn"
        }
        by_type = defaultdict(set)
        for function in taken:
            for function_type in self.types_of.get(function, ()):
                by_type[function_type].add(function)

        merged = {}
        for site in sites:
            caller = site["caller"]
            if caller is None:
                continue
            how = "flow"
            targets = site["targets"]
            if not targets:
                targets = by_type.get(site["type"], set())
                how = "type"
            key = (caller, site["file"], site["line"], site["col"])
            fqns = set()
            for target in targets:
                fqns |= self.fqns_of.get(target, set())
                if target in self.unextracted and not self.fqns_of.get(target):
                    self.lost[key].add(self.unextracted[target])
            fqns.discard(caller)
            if key in merged:
                previous = merged[key]
                fqns |= set(previous.targets)
                how = previous.how if previous.how == "flow" else how
            if not fqns:
                if key not in merged and key not in self.lost:
                    self.unresolved += 1
                continue
            merged[key] = IndirectSite(
                caller=caller,
                label=site["label"],
                short_name=site["short_name"],
                file=site["file"] or "",
                line=site["line"] or 0,
                targets=tuple(sorted(fqns)),
                how=how,
                via=tuple(sorted({_describe(value) for value in site["callee"]})),
            )
        return sorted(merged.values(), key=lambda s: (s.file, s.line, s.caller))


class _TranslationUnit:
    """Walks one Clang JSON AST, recording declarations and value flows."""

    def __init__(self, analysis: _Analysis, tu: int, directory):
        self.analysis = analysis
        self.tu = tu
        self.directory = directory
        self.last_file = None
        self.function_keys = {}    # decl id -> function key
        self.definition_fqns = {}  # definition decl id -> FQN of that very definition
        self.parameters = {}       # decl id -> ("p", function key, position)
        self.variables = {}        # decl id -> location
        self.fields = {}           # decl id -> ("f", record, field)
        self.records = {}          # record decl id -> {"name", "union", "fields"}
        self.record_by_name = {}   # struct tag or typedef name -> record decl id
        self.record_by_place = {}  # (file, line, column) of an unnamed record -> decl id
        self.site_ids = {}         # id() of an indirect CallExpr -> index in analysis.sites

    # Clang's JSON prints a file name only when it differs from the previously
    # printed location, so the current file is tracked in print order.
    def _advance(self, location):
        if not isinstance(location, dict):
            return self.last_file
        parts = [
            location[key]
            for key in ("spellingLoc", "expansionLoc")
            if isinstance(location.get(key), dict)
        ] or [location]
        for part in parts:
            if part.get("file"):
                self.last_file = part["file"]
        return self.last_file

    def _visit_locations(self, node):
        current = self._advance(node.get("loc"))
        node_range = node.get("range") or {}
        begin = self._advance(node_range.get("begin"))
        self._advance(node_range.get("end"))
        return current, begin

    def _relative(self, path):
        if not path:
            return None
        return _clang._canonical_relative(path, self.analysis.root, self.directory)

    # ---- pass 1: declarations ----------------------------------------------

    def declarations(self, ast):
        self.last_file = None
        self._declare(ast, in_function=False)
        for info in self.records.values():
            if "fields" not in info:
                continue
            name = info.get("name") or info.get("typedef") or f"<anonymous at {info['declared_at']}>"
            for field_id, field_name in info["fields"]:
                self.fields[field_id] = ("f", name, "*" if info["union"] else field_name)

    def _declare(self, node, in_function):
        if not isinstance(node, dict):
            return
        current, _ = self._visit_locations(node)
        kind = node.get("kind")
        if kind == "FunctionDecl":
            self._declare_function(node, self._relative(current))
        elif kind == "VarDecl":
            if in_function and node.get("storageClass") != "extern":
                self.variables[node["id"]] = ("l", self.tu, node["id"])
            else:
                static_file = (
                    self._relative(current)
                    if node.get("storageClass") == "static"
                    else None
                )
                self.variables[node["id"]] = ("g", node.get("name"), static_file)
        elif kind == "RecordDecl":
            fields = [
                (child["id"], child.get("name"))
                for child in node.get("inner", ())
                if child.get("kind") == "FieldDecl"
            ]
            info = self.records.setdefault(node["id"], {})
            complete = bool(node.get("completeDefinition") or fields)
            info.update({
                "name": node.get("name") or "",
                "union": node.get("tagUsed") == "union",
                "fields": fields,
                "complete": complete,
            })
            # A later `struct S;` redeclares S without fields; only the
            # definition may supply the field order for initializers.
            if node.get("name") and complete:
                self.record_by_name[node["name"]] = node["id"]
            if not node.get("name"):
                # An unnamed struct is keyed by where it is declared, which is
                # the same in every translation unit that includes it.
                relative = self._relative(current)
                line, column = _clang._location_position(node.get("loc"), self.analysis.root, relative, {})
                info["declared_at"] = f"{relative or current}:{line}"
                self.record_by_place[(relative or current, line, column)] = node["id"]
        elif kind == "TypedefDecl":
            record_id = _typedef_record(node)
            if record_id is not None:
                self.record_by_name.setdefault(node.get("name"), record_id)
                self.records.setdefault(record_id, {}).setdefault("typedef", node.get("name"))
        for child in _children(node):
            self._declare(child, in_function or kind == "FunctionDecl")

    def _declare_function(self, node, relative):
        # A redeclaration keeps the first declaration's key: after
        # `static void f(void);`, a definition `void f(void) {...}` is still
        # static although its node carries no storage class.
        key = self.function_keys.get(node.get("previousDecl")) or _clang._symbol_key(node, relative)
        if key is None:
            return
        self.function_keys[node["id"]] = key
        position = 0
        for child in node.get("inner", ()):
            if child.get("kind") == "ParmVarDecl":
                self.parameters[child["id"]] = ("p", key, position)
                position += 1
        has_body = any(child.get("kind") == "CompoundStmt" for child in node.get("inner", ()))
        if has_body:
            line, column = _clang._location_position(node.get("loc"), self.analysis.root, relative, {})
            match = (
                _clang._function_at(self.analysis.functions.get(relative, ()), line, column)
                if line is not None
                else None
            )
            if match is not None:
                self.analysis.fqns_of[key].add(match[4])
                self.definition_fqns[node["id"]] = match[4]
            elif relative is not None:
                self.analysis.unextracted.setdefault(key, node.get("name"))

    # ---- pass 2: flows and call sites --------------------------------------

    def facts(self, ast):
        self.last_file = None
        self._collect(ast, caller=None, caller_fqn=None)

    def _collect(self, node, caller, caller_fqn):
        if not isinstance(node, dict):
            return
        _, begin_file = self._visit_locations(node)
        kind = node.get("kind")
        flows = self.analysis.flows
        if kind == "FunctionDecl" and node.get("id") in self.function_keys:
            caller = self.function_keys[node["id"]]
            caller_fqn = self.definition_fqns.get(node["id"])
        elif kind == "VarDecl" and node.get("id") in self.variables:
            initializer = next(
                (child for child in node.get("inner", ()) if "Expr" in child.get("kind", "")),
                None,
            )
            if initializer is not None:
                target = self.variables[node["id"]]
                if initializer.get("kind") == "InitListExpr":
                    self._distribute(initializer, {target})
                else:
                    flows[target] |= self._value(initializer)
        elif kind == "BinaryOperator" and node.get("opcode") == "=":
            children = node.get("inner", ())
            if len(children) == 2:
                for target in self._lvalue(children[0]):
                    flows[target] |= self._value(children[1])
        elif kind == "ReturnStmt" and caller and node.get("inner"):
            flows[("r", caller)] |= self._value(node["inner"][0])
        elif kind == "CompoundLiteralExpr":
            for child in _children(node):
                if child.get("kind") == "InitListExpr":
                    self._distribute(child, set())
        elif kind == "CStyleCastExpr":
            # A function cast to another pointer type can be called as that type.
            cast_type = _normalize_type(_type_of(node))
            for value in self._value(node):
                if value[0] == "fn":
                    self.analysis.types_of[value[1]].add(cast_type)
        elif kind == "DeclRefExpr":
            declaration = node.get("referencedDecl") or {}
            if declaration.get("kind") == "FunctionDecl" and declaration.get("id") in self.function_keys:
                function = self.function_keys[declaration["id"]]
                self.analysis.types_of[function].add(
                    _normalize_type(declaration.get("type", {}).get("qualType"))
                )
        elif kind == "CallExpr" and caller:
            self._call(node, caller_fqn, begin_file)
        for child in _children(node):
            self._collect(child, caller, caller_fqn)

    def _call(self, node, caller_fqn, begin_file):
        children = node.get("inner", ())
        arguments = children[1:]
        callee = self._direct_callee(node)
        if callee is not None:
            for position, argument in enumerate(arguments):
                self.analysis.flows[("p", callee, position)] |= self._value(argument)
            return
        callee_expression = children[0] if children else None
        if callee_expression is None:
            return
        begin = (node.get("range") or {}).get("begin")
        relative = self._relative(begin_file)
        line, column = _clang._location_position(begin, self.analysis.root, relative, {})
        label = self._label(begin, callee_expression, relative)
        site_id = self._site_id(node)
        self.analysis.sites[site_id] = {
            "id": site_id,
            "caller": caller_fqn,
            "callee": self._value(callee_expression),
            "type": _normalize_type(_type_of(callee_expression)),
            "args": [self._value(argument) for argument in arguments],
            "file": relative,
            "line": line,
            "col": column,
            "label": label,
            "short_name": _short_name(callee_expression) or label,
        }

    def _label(self, begin, callee_expression, relative):
        """Name the call site as a caller's .info.json would.

        A call written inside a macro's body is named by the macro (the
        identifier at the expansion point). A call written in the source, even
        as a macro argument (``CHECK(p->fn(1))``), is named by the callee
        expression's own text.
        """
        expansion = begin.get("expansionLoc") if isinstance(begin, dict) else None
        if isinstance(expansion, dict) and not expansion.get("isMacroArgExpansion"):
            offset = expansion.get("offset")
            length = expansion.get("tokLen")
            if offset is not None and length:
                text = self.analysis.source_text(relative, offset, offset + length)
                if text:
                    return text
        callee_range = callee_expression.get("range") or {}
        start = _written_part(callee_range.get("begin")).get("offset")
        end_part = _written_part(callee_range.get("end"))
        end = end_part.get("offset")
        if start is not None and end is not None:
            text = self.analysis.source_text(relative, start, end + (end_part.get("tokLen") or 0))
            if text:
                return re.sub(r"\s+", " ", text).strip()
        return _short_name(callee_expression) or "<indirect call>"

    def _site_id(self, node):
        # Parents are processed before children, so an indirect call whose
        # result flows somewhere gets its id when that value is first read.
        key = id(node)
        if key not in self.site_ids:
            self.site_ids[key] = len(self.analysis.sites)
            self.analysis.sites.append(None)
        return self.site_ids[key]

    def _direct_callee(self, call):
        expression = _first_child(call)
        while isinstance(expression, dict) and expression.get("kind") in ("ImplicitCastExpr", "ParenExpr"):
            expression = _first_child(expression)
        if isinstance(expression, dict) and expression.get("kind") == "DeclRefExpr":
            declaration = expression.get("referencedDecl") or {}
            if declaration.get("kind") == "FunctionDecl":
                return self.function_keys.get(declaration.get("id"))
        return None

    def _value(self, expression):
        """Functions and locations an expression's value may come from."""
        if not isinstance(expression, dict):
            return set()
        kind = expression.get("kind")
        if kind == "DeclRefExpr":
            declaration = expression.get("referencedDecl") or {}
            declaration_id = declaration.get("id")
            if declaration.get("kind") == "FunctionDecl" and declaration_id in self.function_keys:
                return {("fn", self.function_keys[declaration_id])}
            if declaration_id in self.variables:
                return {self.variables[declaration_id]}
            if declaration_id in self.parameters:
                return {self.parameters[declaration_id]}
            return set()
        if kind == "MemberExpr":
            field = self.fields.get(expression.get("referencedMemberDecl"))
            return {field} if field else set()
        if kind == "ArraySubscriptExpr":
            return self._value(_first_child(expression))
        if kind in _TRANSPARENT:
            values = set()
            for child in expression.get("inner", ()):
                values |= self._value(child)
            return values
        if kind == "ConditionalOperator":
            children = expression.get("inner", ())
            values = set()
            for child in children[1:3]:
                values |= self._value(child)
            return values
        if kind == "BinaryOperator" and expression.get("opcode") in ("=", ","):
            return self._value(expression["inner"][-1])
        if kind == "CallExpr":
            callee = self._direct_callee(expression)
            if callee is not None:
                return {("r", callee)}
            return {("rs", self._site_id(expression))}
        return set()

    def _lvalue(self, expression):
        kind = expression.get("kind") if isinstance(expression, dict) else None
        if kind in ("DeclRefExpr", "MemberExpr"):
            return self._value(expression)
        if kind in ("ArraySubscriptExpr", "ParenExpr", "ImplicitCastExpr", "UnaryOperator", "CStyleCastExpr"):
            return self._lvalue(_first_child(expression))
        return set()

    def _record_fields(self, type_text):
        unnamed = _UNNAMED_RECORD.search(type_text or "")
        if unnamed:
            path, line, column = unnamed.groups()
            place = (self._relative(path) or path, int(line), int(column))
            info = self.records.get(self.record_by_place.get(place)) or {}
        else:
            name = re.sub(r"\b(const|volatile|struct|union)\b", "", type_text or "").strip()
            info = self.records.get(self.record_by_name.get(name)) or {}
            if not info.get("complete") and info.get("name"):
                # `typedef struct S S;` may name the forward declaration.
                info = self.records.get(self.record_by_name.get(info["name"])) or info
        if "fields" not in info:
            return None
        return [self.fields.get(field_id) for field_id, _ in info["fields"]]

    def _distribute(self, initializer, targets):
        """Send each initializer element to the field (or array) it initializes."""
        initializer_type = _type_of(initializer, desugar=False) or ""
        fields = None if initializer_type.rstrip().endswith("]") else self._record_fields(initializer_type)
        # Struct elements follow field order; array elements all go to the array.
        elements = _children(initializer) if fields is None else initializer.get("inner", ())
        for position, element in enumerate(elements):
            if fields is None:
                destination = targets
            else:
                field = fields[position] if position < len(fields) else None
                destination = {field} if field else set()
            if element.get("kind") == "InitListExpr":
                self._distribute(element, destination)
            else:
                for target in destination:
                    self.analysis.flows[target] |= self._value(element)


def _function_name(key):
    return str(key[0]).split("\0", 1)[0]


def _describe(location):
    kind = location[0]
    if kind == "f":
        return f"union {location[1]}" if location[2] == "*" else f"field {location[1]}.{location[2]}"
    if kind == "g":
        return f"variable {location[1]}"
    if kind == "l":
        return "local variable"
    if kind == "p":
        return f"parameter {location[2] + 1} of {_function_name(location[1])}"
    if kind == "r":
        return f"return value of {_function_name(location[1])}"
    if kind == "fn":
        return f"function {_function_name(location[1])}"
    return "result of another indirect call"


def _written_part(location):
    """The location where the text was written: a macro argument's spelling."""
    if not isinstance(location, dict):
        return {}
    expansion = location.get("expansionLoc")
    spelling = location.get("spellingLoc")
    if isinstance(expansion, dict) and expansion.get("isMacroArgExpansion") and isinstance(spelling, dict):
        return spelling
    return _clang._location_part(location)


def _typedef_record(node):
    stack = list(node.get("inner", ()))
    while stack:
        child = stack.pop()
        if not isinstance(child, dict):
            continue
        declaration = child.get("decl")
        if child.get("kind") == "RecordType" and isinstance(declaration, dict):
            return declaration.get("id")
        stack.extend(child.get("inner", ()))
    return None


def _short_name(expression):
    """The outermost field or variable name the callee expression reads."""
    while isinstance(expression, dict):
        kind = expression.get("kind")
        if kind == "MemberExpr":
            return expression.get("name")
        if kind == "DeclRefExpr":
            return (expression.get("referencedDecl") or {}).get("name")
        expression = _first_child(expression)
    return None
