"""Resource-exhaustion prompts — derive a per-function RESOURCE SIGNATURE for
denial-of-service detection (unbounded allocation/read, decompression bombs,
ReDoS, unbounded/uncontrolled recursion and loops).

Theory (a sibling of integrity-taint; see docs/security_portfolio_roadmap.md):
  Magnitude source = an attacker-controllable size/count/depth/ratio (replaces
  taint's untrusted-input source). Costly op = an operation whose cost grows with
  that magnitude (replaces taint's sink). Bound = a guard that dominates the
  costly op and caps the magnitude before it is consumed (replaces taint's typed
  sanitizer). A costly op reached by an attacker-controlled magnitude with NO
  dominating bound is a resource-exhaustion vulnerability.

What the LLM is good at here (and is asked to extract):
  - recognizing MAGNITUDE SOURCES by code pattern: len(request.body), an
    attacker-supplied count/limit/size param, request-driven recursion depth,
    a decompressed-size or compression ratio, the length of a string fed to a
    regex, the number of items in a parsed structure, request frequency, and a
    compile-time logical allocation/storage extent. Unknown external magnitude
    -> magnitude_kind "unknown_external" (NEVER omitted).
  - recognizing COSTLY OPS: allocation sized by input (bytes(n), [0]*n,
    list(range(n))), unbounded read (.read() with no cap, iterate full stream),
    decompression (zlib/gzip/zipfile extract), unsafe regex match on attacker
    input (ReDoS), repeated regex compilation, input-sized parser/database/email
    work, logical storage allocation arithmetic, recursion whose depth tracks
    input, or a loop whose trip count tracks input — with the exact magnitude.
  - recognizing BOUNDS and what they cap: an explicit size/len/count check that
    raises/returns before the op, a max-depth guard, a chunked read with a cap,
    a stream-size limit, a timeout, a regex input-length cap, recursion-limit,
    or a checked logical storage extent. Bounds must identify exact protected op
    ids, placement, enforcement, and limit provenance.
  - PARAMETRIC consumption so callers compose: express a costly op's magnitude
    over the function's own parameters (param:<name>) when the magnitude
    originates there.

What the LLM must NOT do:
  - decide the verdict, or claim a bound is adequate when it does not actually
    dominate the costly op or does not cap THE magnitude the op consumes. The
    deterministic checker matches dominating bounds to the costly op's magnitude
    and decides VULNERABLE/BOUNDED/POLYMORPHIC/SAFE.

The model returns ONE JSON object wrapped in [RESOURCE_JSON] ... [/RESOURCE_JSON].
"""

import json

from config import RESOURCE_MODEL, MAX_RESOURCE_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_resource_json(text):
    """Pull the JSON object wrapped in [RESOURCE_JSON] ... [/RESOURCE_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[RESOURCE_JSON]", "[/RESOURCE_JSON]"
    s = text.find(start_tag)
    e = text.rfind(end_tag)
    if s == -1 or e == -1 or e <= s:
        s2 = text.find("{")
        e2 = text.rfind("}")
        if s2 == -1 or e2 == -1 or e2 <= s2:
            return None
        candidate = text[s2:e2 + 1]
    else:
        candidate = text[s + len(start_tag):e]
    try:
        return json.loads(candidate.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _system_prompt(language):
    lang_expertise = _LANGUAGE_EXPERTISE.get(
        language.lower(),
        f"You are an expert in logic, formal verification, and {language} programming. ",
    )
    return (
        lang_expertise
        + "You are performing static RESOURCE-EXHAUSTION analysis to find "
        "DENIAL-OF-SERVICE vulnerabilities (unbounded memory allocation, unbounded "
        "reads, decompression bombs, regular-expression denial of service / ReDoS, "
        "uncontrolled recursion, and unbounded loops). The principle: an "
        "ATTACKER-CONTROLLABLE MAGNITUDE (a size, count, depth, or ratio) must not "
        "drive a COSTLY OPERATION without a BOUND that caps the magnitude before "
        "the operation consumes it.\n\n"
        "For ONE function, extract a structured RESOURCE SIGNATURE. You report FACTS "
        "only; a separate deterministic checker decides the verdict by matching "
        "dominating bounds to the costly operation's magnitude. Do NOT declare a "
        "verdict, and do NOT claim a bound is adequate unless it BOTH dominates the "
        "operation (executes on every path before it) AND caps the SAME magnitude "
        "the operation consumes.\n\n"
        "DEFINITIONS:\n"
        "1. MAGNITUDE SOURCE — an attacker-controllable quantity. Recognize by CODE "
        "PATTERN, not variable name:\n"
        "   - request_size: len(request.body/data/files), Content-Length, uploaded size\n"
        "   - element_count: number of items in an attacker-supplied list/dict/parse\n"
        "   - input_length: len() of an attacker-supplied string (esp. fed to a regex)\n"
        "   - recursion_depth: nesting/depth of attacker-supplied data driving recursion\n"
        "   - decompressed_size: output size or ratio of a decompression of external bytes\n"
        "   - numeric_param: an attacker-supplied count/limit/size/range integer\n"
        "   - request_frequency: attacker-controlled repetition of a request-facing operation\n"
        "   - logical_size: source/type-declaration-controlled logical array, byte, offset, "
        "or storage-slot extent, even if it does not immediately allocate host RAM\n"
        "   - unknown_external: a magnitude crosses a trust boundary but you cannot "
        "classify it. EMIT THIS rather than omit.\n"
        "   Do NOT invent magnitudes for constants or clearly-internal bounded values.\n"
        "2. COSTLY OP — an operation whose cost grows with a magnitude. For EACH, "
        "record op_kind, the exact magnitude argument expression, and its position:\n"
        "   - allocation: bytes(n), bytearray(n), [x]*n, list(range(n)), n*'a'\n"
        "   - unbounded_read: .read() / .recv() with no size cap, reading a full stream\n"
        "   - decompression: zlib/gzip/bz2/lzma decompress, zipfile/tarfile extract\n"
        "   - regex_match: re.match/search/sub on an attacker-controlled string (ReDoS)\n"
        "   - regex_compile: compiling attacker-controlled glob/regex rules repeatedly, "
        "especially inside a request path or an unbounded ACL loop\n"
        "   - expensive_call: parsing, hashing, encoding, database/token, email, or external "
        "work whose cost grows with an attacker-controlled input length\n"
        "   - logical_allocation: unchecked or precision-losing logical array/storage/offset "
        "allocation arithmetic driven by a source/type declaration\n"
        "   - recursion: a call to self/this function whose depth tracks a magnitude\n"
        "   - loop: a loop whose trip count tracks a magnitude (and does costly work)\n"
        "   - collection_build: building a list/dict/string whose size tracks a magnitude\n"
        "   A lookup/match through a stable cached evaluator whose regexes were precompiled "
        "outside the repeated request path is NOT regex_compile. Emit regex_match only when "
        "the engine/pattern can have unsafe input-dependent complexity, not for every match. "
        "Constant-size token generation is not attacker-sized work.\n"
        "3. BOUND — an operation that caps a magnitude for a SPECIFIC costly op. "
        "Record bound_kind, the expr, the magnitude it caps, exact `protects_op_ids`, "
        "`placement` (before|after|unknown), `enforcement` "
        "(reject|cap|truncate|warning|log|none), `limit_origin` "
        "(constant|trusted_config|trusted_system|type_limit|attacker_controlled|unknown), "
        "and whether it `dominates` the op (executes on EVERY path before the op). Examples: "
        "size_check (if len(x) > N: raise) caps request_size/input_length; "
        "count_limit caps element_count; depth_limit/recursion_limit caps "
        "recursion_depth; chunked_read_cap caps unbounded_read; "
        "decompress_limit caps decompressed_size; timeout caps loop/regex; "
        "input_length_cap caps regex/expensive-call input; arithmetic_limit caps "
        "logical_size by rejecting overflow before assigning/reserving storage; rate_limit "
        "caps request_frequency. A bound is ONLY valid for the magnitude it truly caps. "
        "A check after costly work is post-hoc and invalid. A warning/log, an attacker-"
        "selected threshold, or a huge nominal type maximum that still permits the dangerous "
        "arithmetic is NOT a bound. A cached/precompiled evaluator removes per-request "
        "regex_compile work; do not misreport the cache lookup itself as a bound.\n"
        "4. CONSUMPTION is PARAMETRIC. When a costly op's magnitude originates from "
        "one of THIS function's parameters, record the magnitude source as "
        "`param:<name>` so a caller can instantiate it. When it originates from a "
        "concrete in-function magnitude source, use `mag:<id>`.\n\n"
        "MAGNITUDE REFERENCE GRAMMAR (use these exact prefixes in every `magnitudes[].source`):\n"
        "   param:<parameter_name>   — symbolic magnitude from this function's parameter\n"
        "   mag:<magnitude_id>       — a concrete magnitude declared in magnitude_sources\n"
        "   unknown:<id>             — fail-closed unknown external magnitude\n\n"
        "Be conservative and fail-closed: if unsure whether a quantity is "
        "attacker-controllable, treat it as a magnitude source; if unsure a bound "
        "dominates the op, is before it, hard-enforces a trusted limit, or caps the right "
        "magnitude, use unknown fields / set `dominates` false and do NOT attach it to "
        "the costly operation."
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee resource summaries (already derived; if you call one of these "
            "and pass an attacker-controlled magnitude into a parameter that the "
            "callee consumes in a costly op, that op is reached THROUGH the call — "
            "the checker composes this, but record the call_site):\n"
            + callee_summaries
        )
    return (
        f"Programming language: {language}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [RESOURCE_JSON] and "
        "[/RESOURCE_JSON]. ALL top-level fields are REQUIRED; use empty lists where "
        "a fact is absent:\n"
        "{\n"
        '  "schema_version": "resource.v1",\n'
        '  "function": "<name>",\n'
        '  "language": "' + language.lower() + '",\n'
        '  "params": ["<p1>", "..."],\n'
        '  "magnitude_sources": [\n'
        '    {"id": "M1", "magnitude_kind": "request_size", "expr": "<exact expr>", '
        '"introduced_by": "<how>", "confidence": "high|medium|low"}\n'
        "  ],\n"
        '  "bounds": [\n'
        '    {"id": "B1", "bound_kind": "size_check", "expr": "<exact expr>", '
        '"caps": ["request_size"], "protects_op_ids": ["OP1"], '
        '"placement": "before|after|unknown", "enforcement": "reject|cap|truncate|warning|log|none", '
        '"limit_origin": "constant|trusted_config|trusted_system|type_limit|attacker_controlled|unknown", '
        '"dominates": true, "confidence": "high|medium|low"}\n'
        "  ],\n"
        '  "call_sites": [\n'
        '    {"id": "C1", "callee": "<fn>", "call_expr": "<expr>", '
        '"args": [{"position": 0, "param_name": "<callee_param>", "expr": "<actual>", '
        '"magnitudes": [{"source": "mag:M1", "bounds": []}]}], "return_expr": "<var|null>"}\n'
        "  ],\n"
        '  "costly_ops": [\n'
        '    {"id": "OP1", "op_kind": "allocation", "callee": "bytes", '
        '"call_expr": "<expr>", "arg_position": 0, "arg_expr": "<magnitude arg>", '
        '"magnitudes": [{"source": "param:n", "bounds": []}]}\n'
        "  ],\n"
        '  "notes": []\n'
        "}\n"
        "Rules: every magnitudes[].source uses param:/mag:/unknown: prefix. A bound "
        "appears in a costly op's flow ONLY via the `bounds` list on that magnitude, "
        "referencing a bound id (e.g. \"B1\"); list a bound there only if it is a "
        "hard, trusted, pre-operation check that genuinely dominates that exact op and "
        "caps that magnitude. `protects_op_ids` must name that op. Mark request-derived "
        "sizes/counts as magnitude sources even if assigned to an innocuously-named "
        "variable. In compiler or type-system code, treat source-controlled array extents, "
        "byte sizes, offsets, and storage-slot arithmetic as logical_size inputs to "
        "logical_allocation when they can drive unchecked or precision-losing resource "
        "growth; warning-only checks are not bounds. Recognize magnitude sources by "
        "pattern, not name."
    )
