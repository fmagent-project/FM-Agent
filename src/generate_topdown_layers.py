import json
import os
import re
import logging
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass

try:
    from src.extract import EXT_TO_LANG, LANG_CONFIG, load_units_manifest
    from src.chisel_support import chisel_decl_info, chisel_declared_name, find_chisel_call_sites, strip_chisel_comments
    from src.verilog_support import find_verilog_call_sites, verilog_declared_name
    from src.languages.registry import call_edges_all
except ModuleNotFoundError:
    # Allow standalone execution as `python3 src/generate_topdown_layers.py`.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.extract import EXT_TO_LANG, LANG_CONFIG, load_units_manifest
    from src.chisel_support import chisel_decl_info, chisel_declared_name, find_chisel_call_sites, strip_chisel_comments
    from src.verilog_support import find_verilog_call_sites, verilog_declared_name
    from src.languages.registry import call_edges_all


# ---------------------------------------------------------------------------
# 1.1 Configuration
# ---------------------------------------------------------------------------

def _load_phases(proj_dir):
    """Load phases.json from the project root."""
    phases_path = os.path.join(proj_dir, "phases.json")
    with open(phases_path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 1.2 Collect files per phase
# ---------------------------------------------------------------------------

def _collect_phase_files(proj_dir, phase_data):
    """For a phase, collect all extracted function file paths.

    Returns list of (file_path, module_name) tuples. Prefers the extraction
    round's manifest (extracted_units.json) so stale units from previous
    rounds never enter the layer graph; enumeration is the fallback for
    pre-manifest workspaces.
    """
    extracted_base = os.path.join(proj_dir, "extracted_functions")
    manifest = load_units_manifest(proj_dir)
    results = []

    for module in phase_data.get("modules", []):
        module_name = module["name"]
        src_files = module.get("source_files", [])
        if isinstance(src_files, str):
            # Same normalization as _get_phase_files: iterating a bare string
            # walks characters, and '/' collapses os.path.join to the root.
            src_files = [src_files]
        for src_file in src_files:
            if manifest is not None:
                for rel in sorted(manifest.get(src_file, [])):
                    fpath = os.path.join(extracted_base, rel)
                    if os.path.isfile(fpath):
                        results.append((fpath, module_name))
                continue
            # Derive extracted directory: xxx/yyy/zzz.ext -> xxx/yyy/zzz-ext
            src_dir = os.path.dirname(src_file)
            src_base = os.path.basename(src_file)
            last_dot = src_base.rfind(".")
            if last_dot > 0:
                dir_name = src_base[:last_dot] + "-" + src_base[last_dot + 1:]
            else:
                dir_name = src_base

            func_dir = os.path.join(extracted_base, src_dir, dir_name) if src_dir else os.path.join(extracted_base, dir_name)
            if not os.path.isdir(func_dir):
                continue

            for fname in os.listdir(func_dir):
                # Generated spec/info documents (preserved by --resume) live
                # next to extracted units; they are outputs, not units.
                if fname.endswith(("_spec.md", "_info.md")):
                    continue
                fpath = os.path.join(func_dir, fname)
                if os.path.isfile(fpath):
                    results.append((fpath, module_name))

    return results


# ---------------------------------------------------------------------------
# 1.3 Assign FQNs
# ---------------------------------------------------------------------------

def _file_to_fqn(filepath, proj_dir):
    """Convert an extracted function file path to its FQN.

    extracted_functions/src/engine/loader-cpp/loadData.cpp -> src::engine::loader-cpp::loadData
    """
    extracted_base = os.path.join(proj_dir, "extracted_functions")
    rel = os.path.relpath(filepath, extracted_base)
    # Strip file extension from the function file itself
    stem, _ = os.path.splitext(rel)
    # Join with :: separator
    parts = Path(stem).parts
    return "::".join(parts)


# ---------------------------------------------------------------------------
# 1.4 Build call graph by static analysis
# ---------------------------------------------------------------------------

# Language keywords to exclude from call site detection.
# We merge the per-language keywords from LANG_CONFIG with some common extras.
_COMMON_EXTRA_KEYWORDS = {
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memset", "memmove", "memcmp",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat",
    "assert", "static_assert",
    "print", "len", "range", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "list", "dict", "set", "tuple", "int",
    "float", "str", "bool", "type", "super", "isinstance", "issubclass",
    "hasattr", "getattr", "setattr", "delattr", "open", "close",
    "input", "round", "abs", "min", "max", "sum", "any", "all",
    "iter", "next", "hash", "id", "repr", "ord", "chr", "hex", "oct", "bin",
    "format", "vars", "dir", "help", "eval", "exec", "compile",
    "append", "extend", "insert", "remove", "pop", "clear", "copy",
    "keys", "values", "items", "get", "update",
    "make", "new", "nil", "panic", "recover", "close", "delete",
    "len", "cap", "append", "copy",
    "println", "eprintln", "format", "write", "writeln",
    "vec", "box", "rc", "arc", "option", "result", "some", "none", "ok", "err",
    "console", "log", "warn", "error", "info", "debug",
    "require", "define", "module", "exports",
    "Math", "Object", "Array", "String", "Number", "Boolean",
    "Date", "RegExp", "Error", "Promise", "JSON",
    "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "main",
}


def _detect_lang_from_ext(filepath):
    """Detect the language key from a file's extension."""
    base = os.path.basename(filepath)
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    return EXT_TO_LANG.get(ext)


def _declared_name_for(filepath):
    """Name declared INSIDE an extracted HDL unit file, or None.

    Stamped into the layer metadata as ``declared_name`` — the single place
    it is derived. Consumers (caller-expectation lookup, the advisory) read
    the field instead of re-parsing files with their own regexes: the
    extractor deduplicates same-named units by renaming the FILE, never the
    declaration, so declared-name != file-stem proves a dedup alias.
    """
    lang_key = _detect_lang_from_ext(filepath)
    body = LANG_CONFIG.get(lang_key, {}).get("body")
    if body not in ("chisel", "verilog"):
        return None
    try:
        with open(filepath, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    if body == "chisel":
        return chisel_declared_name(text)
    return verilog_declared_name(text)


def _strip_comments_from_source(text, lang_key):
    """Strip comments from source text, replacing their content with spaces
    to preserve character positions. Returns the cleaned text."""
    result = list(text)
    i = 0
    lang_cfg = LANG_CONFIG.get(lang_key, {})
    comment_prefix = lang_cfg.get("comment_prefix", "//")
    is_hash_comment = comment_prefix == "#"

    while i < len(result):
        ch = result[i]

        # Mask string literals (including Python triple-quoted strings)
        if ch in ('"', "'"):
            quote = ch
            # Check for triple-quote
            if i + 2 < len(result) and result[i + 1] == quote and result[i + 2] == quote:
                result[i] = " "
                result[i + 1] = " "
                result[i + 2] = " "
                i += 3
                while i < len(result):
                    if result[i] == "\\":
                        if result[i] != "\n":
                            result[i] = " "
                        if i + 1 < len(result) and result[i + 1] != "\n":
                            result[i + 1] = " "
                        i += 2
                        continue
                    if result[i] == quote and i + 2 < len(result) and result[i + 1] == quote and result[i + 2] == quote:
                        result[i] = " "
                        result[i + 1] = " "
                        result[i + 2] = " "
                        i += 3
                        break
                    if result[i] != "\n":
                        result[i] = " "
                    i += 1
                continue
            if result[i] != "\n":
                result[i] = " "
            i += 1
            while i < len(result):
                if result[i] == "\\":
                    if result[i] != "\n":
                        result[i] = " "
                    if i + 1 < len(result) and result[i + 1] != "\n":
                        result[i + 1] = " "
                    i += 2
                    continue
                if result[i] == quote:
                    if result[i] != "\n":
                        result[i] = " "
                    i += 1
                    break
                if result[i] != "\n":
                    result[i] = " "
                i += 1
            continue

        # Hash-style line comments (Python, Ruby, Shell)
        if is_hash_comment and ch == "#":
            start = i
            while i < len(result) and result[i] != "\n":
                result[i] = " "
                i += 1
            continue

        # C-style line comments
        if not is_hash_comment and ch == "/" and i + 1 < len(result) and result[i + 1] == "/":
            while i < len(result) and result[i] != "\n":
                result[i] = " "
                i += 1
            continue

        # C-style block comments
        if not is_hash_comment and ch == "/" and i + 1 < len(result) and result[i + 1] == "*":
            result[i] = " "
            result[i + 1] = " "
            i += 2
            while i < len(result):
                if result[i] == "*" and i + 1 < len(result) and result[i + 1] == "/":
                    result[i] = " "
                    result[i + 1] = " "
                    i += 2
                    break
                if result[i] != "\n":
                    result[i] = " "
                i += 1
            continue

        i += 1

    return "".join(result)


def _get_call_regex(lang_key):
    """Return the call-site regex for the given language."""
    if lang_key in ("cpp", "c", "java", "typescript", "javascript", "cuda", "arkts"):
        # identifier, optional template args, open paren
        return re.compile(r"\b(\w+)\s*(?:<[^>]*>)?\s*\(")
    elif lang_key == "rust":
        # identifier, optional turbofish, open paren
        return re.compile(r"\b(\w+)\s*(?:::<[^>]*>)?\s*\(")
    elif lang_key == "go":
        # identifier, optional type params [T], open paren
        return re.compile(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*\(")
    else:
        # Python, Ruby, Shell, SQL, etc.
        return re.compile(r"\b(\w+)\s*\(")


def _get_keywords_for_lang(lang_key):
    """Get the combined set of keywords to exclude for a language."""
    lang_cfg = LANG_CONFIG.get(lang_key, {})
    kw = set(lang_cfg.get("keywords", set()))
    kw.update(_COMMON_EXTRA_KEYWORDS)
    return kw


def _find_call_sites(text, lang_key, known_stems, keywords):
    """Find call sites in source text, returning set of matched stem names."""
    # Chisel/Scala needs nested-comment-aware stripping and reference forms
    # (new/extends/with/member access) the generic scanner does not handle.
    if LANG_CONFIG.get(lang_key, {}).get("body") == "chisel":
        return find_chisel_call_sites(text, known_stems, keywords)
    if LANG_CONFIG.get(lang_key, {}).get("body") == "verilog":
        return find_verilog_call_sites(text, known_stems, keywords)
    cleaned = _strip_comments_from_source(text, lang_key)
    regex = _get_call_regex(lang_key)
    found = set()
    for m in regex.finditer(cleaned):
        ident = m.group(1)
        if ident in keywords:
            continue
        if ident in known_stems:
            found.add(ident)
    return found

_CHISEL_REF_RE = re.compile(
    r"\b(?P<ctor>new)\s+(?P<ctor_name>[A-Za-z_$][\w$]*)"
    r"|\b(?P<inherit>extends|with)\s+(?P<inherit_name>[A-Za-z_$][\w$]*)"
    r"|\b(?P<ref>[A-Za-z_$][\w$]*)\s*(?P<op>[(.])"
)


def _read_file_text(filepath):
    try:
        with open(filepath, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _build_chisel_aliases(file_map):
    """Build source declaration aliases for deduped Chisel extraction files.

    extract.py deduplicates same-name declarations on disk (for example
    class Foo -> Foo.scala, object Foo -> Foo_1.scala). Source references still
    use `Foo`, so layer generation needs the original declaration name and kind
    to resolve `new Foo` to the class while resolving `Foo(...)`/`Foo.bar` to the
    companion object when one exists.
    """
    aliases = defaultdict(lambda: defaultdict(set))

    for fqn, filepath in file_map.items():
        lang_key = _detect_lang_from_ext(filepath)
        if LANG_CONFIG.get(lang_key, {}).get("body") != "chisel":
            continue
        text = _read_file_text(filepath)
        if text is None:
            continue
        kind, source_name, _parent, _parent_prefix = chisel_decl_info(text)
        if not kind or not source_name:
            continue
        aliases[source_name][kind].add(fqn)

    return aliases


# Root Chisel/Scala base classes that mark a declaration as elaboratable
# hardware, and library base classes known to never be hardware (IO
# Bundles, records, plain data payloads) -- both matched by bare name or by
# the last segment of a package-qualified name.
_MODULE_ROOT_NAMES = {"Module", "RawModule", "ExtModule", "BlackBox", "MultiIOModule"}
_KNOWN_NON_MODULE_NAMES = {"Bundle", "Record", "Data"}


def _build_chisel_decl_map(file_map):
    """fqn -> (kind, name, parent, parent_qualified) for every Chisel unit.

    Single-pass, project-wide input to the module-ness classifier -- built
    once from the same ``chisel_decl_info`` used everywhere else, so the
    classifier never re-derives declaration parsing on its own.
    """
    decl_map = {}
    for fqn, filepath in file_map.items():
        lang_key = _detect_lang_from_ext(filepath)
        if LANG_CONFIG.get(lang_key, {}).get("body") != "chisel":
            continue
        text = _read_file_text(filepath)
        if text is None:
            continue
        decl_map[fqn] = chisel_decl_info(text)
    return decl_map


def _classify_chisel_modules(decl_map):
    """Compute ``(is_module, reason)`` for every FQN in ``decl_map``.

    FQN-indexed, kind-aware, cycle-safe inheritance closure. For a given
    unit's parent reference, resolves in this exact priority order:

    1. A parent qualified with chisel3's own package (``chisel3.Module``,
       ``_root_.chisel3.Module``, first-segment matched so
       ``chisel3.util.*``/``chisel3.experimental.*`` qualify too) that
       matches a root name -> ``extends_module_direct``, definitive.
    2. Same, but matching a known-non-module name -> ``known_non_module_parent``,
       definitive.
    3. A project-local class/trait declaration matching the parent's bare
       simple name -> resolved via THAT declaration's own (recursively
       computed) classification. This applies to a genuinely bare
       reference AND to a reference qualified with some OTHER (non-chisel3)
       package -- e.g. a project's own ``mypkg.Data`` normalizes to the
       same bare ``"Data"`` as chisel3.Data, but is NOT chisel3's Data, so
       it must resolve via ITS real extends chain, never via the fixed
       known-non-module/root sets below (steps 4-5). For the QUALIFIED
       variant, a local result is trusted only when it is True: the
       qualifying prefix cannot be verified against the local candidate's
       package (extraction discards package declarations), and a
       misdirected local False silently drops a real module, so False
       falls back to ``unresolved_parent`` conservative-True instead.
       Bare references trust False too -- that is what keeps local Bundle
       chains filterable -- EXCEPT when the bare name is itself a root
       name (``Module``/``RawModule``/``ExtModule``/``BlackBox``/
       ``MultiIOModule``) and that local resolution is False: an
       unrelated, non-hardware declaration sharing a root class's bare
       name must never silently shadow a real ``extends Module``-style
       reference into False
       (``root_name_shadowed_conservative_true``). This asymmetry is safe
       for the known-non-module set (Bundle/Record/Data) in either shadow
       direction, but not for root names.
    4. Only for a genuinely bare (unqualified) reference with no
       project-local declaration match: bare root name.
    5. Only for a genuinely bare (unqualified) reference with no
       project-local declaration match: bare known-non-module name.
    6. Otherwise: ``unresolved_parent``, conservative-True. A
       non-chisel3-qualified reference with no project-local match lands
       here directly too (steps 4-5 never apply to it -- see step 3).

    KNOWN LIMITATION: step 3's project-local lookup has no package/import
    scoping (extraction discards import info), so for a BARE reference an
    unrelated, differently-scoped project-local declaration can still
    coincidentally share a bare name with something the reference actually
    meant to name externally (not just the 5 root names, which step 3
    specifically guards against; qualified references no longer trust a
    local False at all). Closing this fully would require a real Scala
    import/package resolver, explicitly out of scope for this heuristic,
    plain-text classifier -- see ``_resolve_local_candidates`` for the
    full rationale.

    Ambiguous same-``(kind, name)`` candidates that disagree, and cycles
    detected during traversal, both classify conservative-True too --
    false negatives (silently excluding a real module) are strictly worse
    than false positives here.
    """
    local_index = defaultdict(set)
    for fqn, (kind, name, _parent, _parent_prefix) in decl_map.items():
        if kind in ("class", "trait") and name:
            local_index[(kind, name)].add(fqn)

    cache = {}
    visiting = set()
    for fqn in decl_map:
        try:
            _classify_one_chisel_module(fqn, decl_map, local_index, cache, visiting)
        except RecursionError:
            # An inheritance chain deep enough to exhaust Python's call
            # stack (hundreds of levels -- unusual for real hardware
            # designs, but not impossible). This runs unconditionally
            # regardless of --chisel-modules-only, so a hard crash here
            # would break the existing, always-on Chisel flow too. Every
            # try/finally along the (now unwound) recursive chain already
            # cleared its own entry from `visiting`; clearing it again here
            # is just defensive. Conservative-True, same tier as the
            # cycle/ambiguity guards -- never let "couldn't resolve
            # cleanly" become "crashed" instead of "kept".
            visiting.clear()
            cache[fqn] = (True, "recursion_limit_conservative_true")
    return cache


def _classify_one_chisel_module(fqn, decl_map, local_index, cache, visiting):
    if fqn in cache:
        return cache[fqn]
    if fqn in visiting:
        # Mid-traversal cycle: this is a transient probe result for the
        # frame that re-entered fqn, not fqn's own final answer -- the
        # frame that owns fqn's computation (below) decides what goes in
        # the cache.
        return True, "cycle_detected_conservative_true"
    visiting.add(fqn)
    try:
        result = _resolve_chisel_module_classification(fqn, decl_map, local_index, cache, visiting)
    finally:
        visiting.discard(fqn)
    cache[fqn] = result
    return result


def _is_chisel3_prefix(prefix):
    """True when a qualifying prefix is chisel3's own package, optionally
    rooted via ``_root_.`` (e.g. ``"chisel3"``, ``"_root_.chisel3.experimental"``).

    First-segment matching (not exact-string matching) so ``chisel3.util.*``/
    ``chisel3.experimental.*`` qualify too, not just the bare ``chisel3.``
    forms.
    """
    if prefix.startswith("_root_."):
        prefix = prefix[len("_root_."):]
    return prefix.split(".", 1)[0] == "chisel3"


def _resolve_local_candidates(parent, decl_map, local_index, cache, visiting):
    """Resolve a bare simple name against project-local class/trait
    declarations sharing it, or None if there are no candidates.

    Ambiguous (disagreeing) candidates and cycles both classify
    conservative-True. A single candidate resolving False is trusted UNLESS
    ``parent`` also happens to be a fixed Chisel root name -- an unrelated,
    non-hardware project-local declaration coincidentally sharing a root
    class's bare name must not silently shadow a real module (this is the
    one direction where shadowing is actually dangerous; for the
    known-non-module set either shadow outcome is safe by construction).

    KNOWN LIMITATION: this has zero package/import scoping (extraction
    discards import info entirely), so an unrelated project-local
    declaration sharing ANY bare name -- not just a root name -- can still
    misresolve a reference that was meant to name a different, externally
    imported class of the same simple name. Fully closing this requires a
    real Scala import/package resolver, explicitly out of scope for this
    heuristic, plain-text classifier. The reason this isn't blanket-flipped
    to conservative-True: a class extending a local non-hardware base, or
    transitively through a local Bundle-rooted chain (e.g. ``class BarIO
    extends FooIO`` where ``FooIO extends Bundle``), is a common and
    legitimate pattern this classifier must keep recognizing as
    non-hardware -- that's the real value step 3 provides, and a blanket
    conservative-True override here would discard it entirely. Same tier as
    the already-accepted import-alias limitation (a DIFFERENT limitation:
    the with-mixin gap is about which clauses get scanned at all, not this
    one, and isn't independent evidence for keeping this specific
    trade-off).
    """
    candidates = set()
    for local_kind in ("class", "trait"):
        candidates |= local_index.get((local_kind, parent), set())
    if not candidates:
        return None

    results = [
        _classify_one_chisel_module(cand_fqn, decl_map, local_index, cache, visiting)
        for cand_fqn in candidates
    ]
    if any(reason == "cycle_detected_conservative_true" for _, reason in results):
        return True, "cycle_detected_conservative_true"
    is_mods = {is_mod for is_mod, _reason in results}
    if len(is_mods) > 1:
        return True, "ambiguous_conservative_true"
    is_mod = is_mods.pop()
    if is_mod:
        return True, "extends_module_transitive"
    if parent in _MODULE_ROOT_NAMES:
        return True, "root_name_shadowed_conservative_true"
    return False, "non_module_parent"


def _resolve_chisel_module_classification(fqn, decl_map, local_index, cache, visiting):
    kind, _name, parent, parent_prefix = decl_map[fqn]

    if kind in ("object", "def"):
        return False, "non_module_decl_kind"
    if parent is None:
        return False, "no_extends_clause"

    if parent_prefix is not None:
        if _is_chisel3_prefix(parent_prefix):
            # chisel3's own namespace -- definitive, no project-local
            # declaration could ever be what this actually refers to.
            if parent in _MODULE_ROOT_NAMES:
                return True, "extends_module_direct"
            if parent in _KNOWN_NON_MODULE_NAMES:
                return False, "known_non_module_parent"
            return True, "unresolved_parent"
        # Qualified with some OTHER package -- e.g. a project's own
        # `mypkg.Data` is NOT chisel3.Data, even though both normalize to
        # the same bare "Data". Falling through to the bare-name fixed-set
        # checks below would reintroduce exactly that bug via a different
        # path, so resolve via project-local declarations only -- but trust
        # a local result ONLY when it is True: extraction discards package
        # declarations, so the qualifying prefix cannot be verified against
        # the local candidate's own package. A local True is safe either
        # way (keeps mypkg.Data's transitive precision; the ambiguity/cycle
        # guards already return True). A local FALSE would silently drop a
        # real module whenever the prefix actually names a different,
        # external package (`vendor.hardware.ExternalBase` vs an unrelated
        # local `ExternalBase extends Bundle`), so it falls back to
        # unresolved_parent instead. Bare references (below) still trust
        # False -- that is what keeps local Bundle chains filterable.
        local_result = _resolve_local_candidates(parent, decl_map, local_index, cache, visiting)
        if local_result is not None and local_result[0]:
            return local_result
        return True, "unresolved_parent"

    local_result = _resolve_local_candidates(parent, decl_map, local_index, cache, visiting)
    if local_result is not None:
        return local_result

    if parent in _MODULE_ROOT_NAMES:
        return True, "extends_module_direct"
    if parent in _KNOWN_NON_MODULE_NAMES:
        return False, "known_non_module_parent"
    return True, "unresolved_parent"


def _resolve_chisel_refs(text, chisel_aliases, known_stems, keywords):
    cleaned = strip_chisel_comments(text)
    resolved = set()

    def add_by_kind(name, preferred_kinds):
        if not name or name in keywords:
            return
        by_kind = chisel_aliases.get(name)
        if by_kind:
            for kind in preferred_kinds:
                targets = by_kind.get(kind, set())
                if targets:
                    resolved.update(targets)
                    return
        if name in known_stems:
            resolved.add(name)

    for m in _CHISEL_REF_RE.finditer(cleaned):
        if m.group("ctor"):
            add_by_kind(m.group("ctor_name"), ("class",))
        elif m.group("inherit"):
            add_by_kind(m.group("inherit_name"), ("class", "trait"))
        else:
            # `Foo(...)` and `Foo.bar` most often target a companion object.
            # Fall back to class/trait/def when there is no companion object.
            add_by_kind(m.group("ref"), ("object", "def", "class", "trait"))

    return resolved


def _build_call_graph(
    phase_files,
    proj_dir,
    global_stem_to_fqns=None,
    global_file_map=None,
    extra_call_edges=None,
):
    """Build callees_map and callers_map for a set of phase files.

    Args:
        phase_files: list of (filepath, module_name) tuples
        proj_dir: project root directory
        global_stem_to_fqns: optional global stem->set(fqn) mapping across all phases,
                             used to compute all_callees (cross-phase)
        global_file_map: optional global fqn->filepath mapping across all phases,
                         used for Chisel source-name/kind aliases
        extra_call_edges: optional iterable of supplemental CallEdge objects.
                          caller.fqn is exact; caller.callsite_names are matched
                          only against explicitly listed source callsite names.

    Returns:
        (callees_map, callers_map, all_callees_map, file_map, module_map,
        edge_aliases_map) where keys are FQNs.
        callees_map/callers_map contain only within-phase edges.
        all_callees_map contains callees from any phase.
        edge_aliases_map maps callee -> caller -> supplemental callee labels
        that may appear in a caller's [INFO] block.
    """
    # Build FQN mappings
    fqn_map = {}  # filepath -> fqn
    stem_to_fqns = defaultdict(set)  # stem -> set of fqns (phase-local)
    file_map = {}  # fqn -> filepath
    module_map = {}  # fqn -> module_name

    for filepath, module_name in phase_files:
        fqn = _file_to_fqn(filepath, proj_dir)
        fqn_map[filepath] = fqn
        file_map[fqn] = filepath
        module_map[fqn] = module_name
        stem = fqn.split("::")[-1]
        stem_to_fqns[stem].add(fqn)

    phase_fqns = set(fqn_map.values())
    # For call-site detection, use global stems if available
    effective_stem_to_fqns = global_stem_to_fqns if global_stem_to_fqns else stem_to_fqns
    effective_file_map = global_file_map if global_file_map else file_map
    chisel_aliases = _build_chisel_aliases(effective_file_map)
    # All extracted FQNs (across phases when a global map is supplied), used to
    # keep only codegraph callees that correspond to an extracted function.
    known_fqns = {
        fqn
        for fqns in effective_stem_to_fqns.values()
        for fqn in fqns
    }
    extra_edges_by_caller_fqn, extra_edges_by_callsite = _resolve_extra_call_edges(
        extra_call_edges,
        phase_fqns=phase_fqns,
        known_fqns=known_fqns,
    )
    known_stems = set(effective_stem_to_fqns.keys()) | set(extra_edges_by_callsite.keys())

    callees_map = defaultdict(set)  # fqn -> set of callee fqns (within phase)
    callers_map = defaultdict(set)  # fqn -> set of caller fqns (within phase)
    all_callees_map = defaultdict(set)  # fqn -> set of callee fqns (any phase)
    edge_aliases_map = defaultdict(lambda: defaultdict(set))  # callee -> caller -> aliases

    phase_langs = {_detect_lang_from_ext(fp) for fp, _ in phase_files if _detect_lang_from_ext(fp)}
    registry_edges, registry_langs = call_edges_all(proj_dir, phase_langs)

    for filepath, module_name in phase_files:
        fqn = fqn_map[filepath]
        lang_key = _detect_lang_from_ext(filepath)
        if not lang_key:
            continue

        called_stems = set()
        if lang_key in registry_langs:
            # codegraph: edges are already precise caller_fqn -> callee_fqn (the
            # exact node codegraph resolved). Keep only callees that are extracted
            # functions; drop external/library targets.
            callee_fqns = {c for c in registry_edges.get(fqn, set())
                           if c != fqn and c in known_fqns}
            if extra_edges_by_callsite:
                keywords = _get_keywords_for_lang(lang_key)
                try:
                    with open(filepath, "r", errors="replace") as f:
                        text = f.read()
                except OSError:
                    text = ""
                called_stems = _find_call_sites(
                    text, lang_key, set(extra_edges_by_callsite.keys()), keywords
                )
        else:
            # regex fallback: detect bare-name call sites, then resolve each stem
            # to every same-named FQN (an over-approximation — unchanged).
            keywords = _get_keywords_for_lang(lang_key)
            try:
                with open(filepath, "r", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            if LANG_CONFIG.get(lang_key, {}).get("body") == "chisel":
                called_refs = _resolve_chisel_refs(
                    text, chisel_aliases, known_stems, keywords
                )
            else:
                called_refs = _find_call_sites(text, lang_key, known_stems, keywords)
            called_stems = set()
            callee_fqns = set()
            for ref in called_refs:
                if ref in effective_stem_to_fqns:
                    called_stems.add(ref)
                    callee_fqns.update(
                        cf for cf in effective_stem_to_fqns.get(ref, set()) if cf != fqn
                    )
                elif ref != fqn:
                    callee_fqns.add(ref)

        for callee_fqn in callee_fqns:
            all_callees_map[fqn].add(callee_fqn)
            if callee_fqn in phase_fqns:
                callees_map[fqn].add(callee_fqn)
                callers_map[callee_fqn].add(fqn)

        for stem in called_stems:
            for edge in extra_edges_by_callsite.get(stem, ()):
                _add_resolved_extra_edge(
                    fqn,
                    edge,
                    phase_fqns,
                    callees_map,
                    callers_map,
                    all_callees_map,
                    edge_aliases_map,
                )

        for edge in extra_edges_by_caller_fqn.get(fqn, ()):
            _add_resolved_extra_edge(
                fqn,
                edge,
                phase_fqns,
                callees_map,
                callers_map,
                all_callees_map,
                edge_aliases_map,
            )

    return callees_map, callers_map, all_callees_map, file_map, module_map, edge_aliases_map


@dataclass(frozen=True)
class _ResolvedExtraEdge:
    callee_fqn: str
    info_names: tuple[str, ...]
    source: str


def _resolve_extra_call_edges(extra_call_edges, phase_fqns, known_fqns):
    """Resolve supplemental edges into phase-local caller indexes."""
    by_caller_fqn = defaultdict(list)
    by_callsite = defaultdict(list)
    if not extra_call_edges:
        return by_caller_fqn, by_callsite

    phase_fqns = set(phase_fqns)
    known_fqns = set(known_fqns)
    for edge in extra_call_edges:
        callee_fqn = edge.callee.fqn
        if callee_fqn not in known_fqns:
            logging.warning(
                "Skipping supplemental edge from %s: callee.fqn %r "
                "was not found among extracted functions.",
                edge.source or "edge file",
                callee_fqn,
            )
            continue

        resolved = _ResolvedExtraEdge(
            callee_fqn=callee_fqn,
            info_names=tuple(edge.callee.info_names),
            source=edge.source,
        )

        if edge.caller.fqn:
            caller_fqn = edge.caller.fqn
            if caller_fqn in phase_fqns:
                by_caller_fqn[caller_fqn].append(resolved)
            else:
                logging.debug(
                    "Skipping supplemental edge from %s in current phase: "
                    "caller FQN %r is not in phase.",
                    edge.source or "edge file",
                    caller_fqn,
                )

        for callsite in edge.caller.callsite_names:
            if not re.fullmatch(r"[A-Za-z_]\w*", callsite):
                logging.warning(
                    "Skipping supplemental edge callsite selector %r from %s: "
                    "the current scanner only matches identifier callsites.",
                    callsite,
                    edge.source or "edge file",
                )
                continue
            by_callsite[callsite].append(resolved)

    return by_caller_fqn, by_callsite


def _add_resolved_extra_edge(
    caller_fqn,
    edge: _ResolvedExtraEdge,
    phase_fqns,
    callees_map,
    callers_map,
    all_callees_map,
    edge_aliases_map,
):
    """Inject one resolved supplemental edge and attach its callee aliases."""
    callee_fqn = edge.callee_fqn
    if caller_fqn == callee_fqn:
        return False

    before = len(all_callees_map[caller_fqn])
    all_callees_map[caller_fqn].add(callee_fqn)
    edge_aliases_map[callee_fqn][caller_fqn].update(edge.info_names)

    if callee_fqn in phase_fqns:
        callees_map[caller_fqn].add(callee_fqn)
        callers_map[callee_fqn].add(caller_fqn)

    return len(all_callees_map[caller_fqn]) != before


# ---------------------------------------------------------------------------
# 1.5 Topological layer computation
# ---------------------------------------------------------------------------

def _tarjan_scc(nodes, edges):
    """Compute strongly connected components using Tarjan's algorithm (iterative).

    Args:
        nodes: iterable of node identifiers
        edges: dict mapping node -> set of successor nodes

    Returns:
        list of SCCs (each SCC is a set of nodes), in reverse topological order
    """
    index_counter = 0
    scc_stack = []
    on_stack = set()
    index_map = {}
    lowlink = {}
    result = []

    for node in nodes:
        if node in index_map:
            continue
        # Iterative DFS using an explicit call stack.
        # Each frame is (v, iterator_over_successors, is_initial_visit)
        call_stack = [(node, iter(edges.get(node, set())), True)]
        while call_stack:
            v, successors, initial = call_stack[-1]
            if initial:
                index_map[v] = index_counter
                lowlink[v] = index_counter
                index_counter += 1
                scc_stack.append(v)
                on_stack.add(v)
                # Mark as visited so we don't re-init
                call_stack[-1] = (v, successors, False)

            advanced = False
            for w in successors:
                if w not in index_map:
                    call_stack.append((w, iter(edges.get(w, set())), True))
                    advanced = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            if advanced:
                continue

            # All successors processed — check if v is a root
            if lowlink[v] == index_map[v]:
                scc = set()
                while True:
                    w = scc_stack.pop()
                    on_stack.discard(w)
                    scc.add(w)
                    if w == v:
                        break
                result.append(scc)

            call_stack.pop()
            if call_stack:
                parent = call_stack[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[v])

    return result


def _compute_layers(phase_fqns, callees_map, callers_map):
    """Compute topological layers using Kahn's algorithm with cycle handling.

    Returns list of layer dicts: [{"layer": N, "functions": [...], "cycle_resolution": bool}, ...]
    """
    phase_set = set(phase_fqns)

    # Build in-phase caller counts
    remaining = set(phase_set)
    assigned = {}  # fqn -> layer index
    layers = []

    while remaining:
        # Find functions whose all same-phase callers are already assigned
        ready = set()
        for fqn in remaining:
            phase_callers = callers_map.get(fqn, set()) & phase_set
            unassigned_callers = phase_callers - set(assigned.keys())
            if not unassigned_callers:
                ready.add(fqn)

        if ready:
            layer_idx = len(layers)
            for fqn in ready:
                assigned[fqn] = layer_idx
            layers.append({"layer": layer_idx, "functions": sorted(ready), "cycle_resolution": False})
            remaining -= ready
        else:
            # Cycle detected — use Tarjan's SCC
            # Build subgraph of remaining functions
            sub_edges = {}
            for fqn in remaining:
                sub_edges[fqn] = callees_map.get(fqn, set()) & remaining

            # Compute SCCs on the *caller* graph (edges from callee to caller)
            # Actually we need topological ordering of SCCs by the caller relationship.
            # An SCC can be assigned once all SCCs that *call into it* are assigned.
            # So we use the callers graph direction for the SCC ordering.
            caller_edges_sub = {}
            for fqn in remaining:
                caller_edges_sub[fqn] = callers_map.get(fqn, set()) & remaining

            sccs = _tarjan_scc(remaining, caller_edges_sub)

            # Build SCC DAG and assign layers
            fqn_to_scc = {}
            for i, scc in enumerate(sccs):
                for fqn in scc:
                    fqn_to_scc[fqn] = i

            # Build DAG between SCCs based on caller edges
            scc_callers = defaultdict(set)  # scc_idx -> set of scc_idx that call into it
            for fqn in remaining:
                scc_i = fqn_to_scc[fqn]
                for caller_fqn in callers_map.get(fqn, set()) & remaining:
                    scc_j = fqn_to_scc[caller_fqn]
                    if scc_i != scc_j:
                        scc_callers[scc_i].add(scc_j)

            # Topological sort of SCCs
            scc_assigned = {}
            scc_remaining = set(range(len(sccs)))

            while scc_remaining:
                scc_ready = set()
                for scc_idx in scc_remaining:
                    unassigned_scc_callers = scc_callers.get(scc_idx, set()) - set(scc_assigned.keys())
                    if not unassigned_scc_callers:
                        scc_ready.add(scc_idx)

                if not scc_ready:
                    # Should not happen if Tarjan is correct, but handle gracefully
                    # Assign all remaining to the same layer
                    layer_idx = len(layers)
                    all_fqns = set()
                    for scc_idx in scc_remaining:
                        all_fqns.update(sccs[scc_idx])
                    for fqn in all_fqns:
                        assigned[fqn] = layer_idx
                    layers.append({"layer": layer_idx, "functions": sorted(all_fqns), "cycle_resolution": True})
                    remaining -= all_fqns
                    break

                layer_idx = len(layers)
                layer_fqns = set()
                is_cycle = False
                for scc_idx in scc_ready:
                    scc_assigned[scc_idx] = layer_idx
                    layer_fqns.update(sccs[scc_idx])
                    if len(sccs[scc_idx]) > 1:
                        is_cycle = True

                for fqn in layer_fqns:
                    assigned[fqn] = layer_idx
                layers.append({"layer": layer_idx, "functions": sorted(layer_fqns), "cycle_resolution": is_cycle})
                remaining -= layer_fqns
                scc_remaining -= scc_ready

    return layers


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_topdown_layers(proj_dir, phase_numbers=None, extra_call_edges=None):
    """Generate topdown layer JSON files for the specified phases (or all phases).

    Args:
        proj_dir: project root directory
        phase_numbers: list of phase numbers to process, or None for all
        extra_call_edges: optional iterable of supplemental caller/callee edges

    Returns:
        list of output file paths written
    """
    phases_data = _load_phases(proj_dir)

    output_dir = os.path.join(proj_dir, "spec_prompts")
    os.makedirs(output_dir, exist_ok=True)

    # Build global mappings across ALL phases for all_callees and Chisel aliases.
    global_stem_to_fqns = defaultdict(set)
    global_file_map = {}
    for pi in phases_data["phases"]:
        for filepath, _ in _collect_phase_files(proj_dir, pi):
            fqn = _file_to_fqn(filepath, proj_dir)
            stem = fqn.split("::")[-1]
            global_stem_to_fqns[stem].add(fqn)
            global_file_map[fqn] = filepath

    output_files = []

    for phase_info in phases_data["phases"]:
        phase_num = phase_info["phase"]
        phase_name = phase_info["name"]

        if phase_numbers and phase_num not in phase_numbers:
            continue

        # 1.2 Collect files
        phase_files = _collect_phase_files(proj_dir, phase_info)
        if not phase_files:
            logging.warning(f"Phase {phase_num} ({phase_name}): no extracted files found, skipping.")
            continue

        # 1.4 Build call graph (also returns file_map and module_map)
        (
            callees_map,
            callers_map,
            all_callees_map,
            file_map,
            module_map,
            edge_aliases_map,
        ) = _build_call_graph(
            phase_files,
            proj_dir,
            global_stem_to_fqns,
            global_file_map=global_file_map,
            extra_call_edges=extra_call_edges,
        )
        phase_fqns = set(file_map.keys())

        # 1.5 Compute topological layers
        layers = _compute_layers(phase_fqns, callees_map, callers_map)

        # Build phase-specific key names
        phase_callers_key = f"phase{phase_num}_callers"
        phase_callees_key = f"phase{phase_num}_callees"
        phase_info_names_key = f"phase{phase_num}_callee_info_names_by_caller"

        # 1.6 Build output JSON
        total_functions = len(phase_fqns)
        total_layers = len(layers)

        output_layers = []
        for layer_info in layers:
            layer_dict = {
                "layer": layer_info["layer"],
            }
            if layer_info["cycle_resolution"]:
                layer_dict["cycle_resolution"] = True

            func_entries = []
            for fqn in layer_info["functions"]:
                filepath = file_map[fqn]
                rel_path = os.path.relpath(filepath, proj_dir)
                unit = module_map.get(fqn, "")
                declared = _declared_name_for(filepath)

                phase_callers = sorted(callers_map.get(fqn, set()) & phase_fqns)
                phase_callees = sorted(callees_map.get(fqn, set()) & phase_fqns)
                all_callees = sorted(all_callees_map.get(fqn, set()))

                entry = {
                    "name": fqn,
                    "file": rel_path,
                    "unit": unit,
                    "declared_name": declared,
                    phase_callers_key: phase_callers,
                    phase_callees_key: phase_callees,
                    "all_callees": all_callees,
                }
                if LANG_CONFIG.get(_detect_lang_from_ext(filepath), {}).get("body") == "chisel":
                    entry["is_module"] = True
                    entry["module_classification_reason"] = "module_unit"
                info_names_by_caller = {
                    caller: sorted(info_names)
                    for caller, info_names in edge_aliases_map.get(fqn, {}).items()
                    if caller in phase_fqns and info_names
                }
                if info_names_by_caller:
                    entry[phase_info_names_key] = info_names_by_caller
                func_entries.append(entry)

            layer_dict["functions"] = func_entries
            output_layers.append(layer_dict)

        output = {
            "phase": phase_num,
            "phase_name": phase_name,
            "total_functions": total_functions,
            "total_layers": total_layers,
            "layers": output_layers,
        }

        # Write output
        out_path = os.path.join(output_dir, f"phase_{phase_num:02d}_topdown_layers.json")
        with open(out_path, "w") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        output_files.append(out_path)
        print(f"[TopdownLayers] Phase {phase_num} ({phase_name}): {total_functions} functions, {total_layers} layers -> {os.path.relpath(out_path, proj_dir)}")

    return output_files
