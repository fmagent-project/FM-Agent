"""Integrity-taint prompts — derive a per-function taint signature for injection
detection (SQLi/command-injection/path-traversal/SSRF/XSS/unsafe-deserialization).

Theory (dual of IFC; see docs/security_portfolio_roadmap.md, Oracle design):
  Source = untrusted input (replaces IFC's High-secret). Sink = a sensitive
  OPERATION SITE with a typed argument context (replaces IFC's Low output
  channel). Sanitizer = a TYPED endorsement for a specific sink context
  (replaces declassification). A sink reached by a tainted, un-endorsed flow is
  an injection vulnerability.

What the LLM is good at here (and is asked to extract):
  - recognizing SOURCES by code PATTERN, not variable name: request.GET[...],
    request.json/body, headers, sys.argv, input(), os.environ, socket reads,
    unsafe object deserializers of external bytes, framework request objects. Unrecognized
    external input -> source_kind "unknown_external" (NEVER omitted).
  - recognizing SINKS: cursor.execute(sql), os.system(x), subprocess(argv),
    open(path), requests.get(url), redirect(url), template render, eval/exec,
    deserializers — with the exact tainted argument and its TYPED context.
  - recognizing SANITIZERS and which sink-context they endorse (parameterized
    query -> sql_param; html escape -> html_body; int cast -> sql_numeric_literal).
  - recognizing VALIDATION GUARDS: control-flow gates that reject/abort before a
    sink runs, distinct from value sanitizers and reported at top level.
  - PARAMETRIC flows so callers compose: express sink/return/mutation taint over
    the function's own parameters (param:<name>) when the taint originates there.

What the LLM must NOT do:
  - decide the verdict, or claim a sanitizer is adequate for a context it does
    not actually cover. The deterministic checker matches typed sanitizers to
    sink contexts and decides VULNERABLE/SANITIZED/POLYMORPHIC/SAFE.

The model returns ONE JSON object wrapped in [TAINT_JSON] ... [/TAINT_JSON].
"""

import json

from config import TAINT_MODEL, MAX_TAINT_ITER  # noqa: F401 (model used by driver)
from .prompts import _LANGUAGE_EXPERTISE


def _extract_taint_json(text):
    """Pull the JSON object wrapped in [TAINT_JSON] ... [/TAINT_JSON]."""
    if not text:
        return None
    start_tag, end_tag = "[TAINT_JSON]", "[/TAINT_JSON]"
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
        + "You are performing static INTEGRITY TAINT analysis to find INJECTION "
        "vulnerabilities (SQL injection, command injection, path traversal, SSRF, "
        "open redirect, XSS, template/code injection, unsafe deserialization, LDAP/XPath "
        "injection). This is the DUAL of information-flow: instead of secrets leaking to "
        "public outputs, here UNTRUSTED INPUT must not reach a SENSITIVE OPERATION SITE "
        "without an adequate, context-appropriate sanitizer.\n\n"
        "For ONE function, extract a structured TAINT SIGNATURE. You report FACTS only; a "
        "separate deterministic checker decides the verdict by matching typed sanitizers to "
        "typed sink contexts. Do NOT declare a verdict, and do NOT claim a sanitizer is "
        "adequate for a context it does not actually cover.\n\n"
        "DEFINITIONS:\n"
        "1. TAINT SOURCE — untrusted input. Recognize by CODE PATTERN, not variable name:\n"
        "   - http_param: request.GET/args[...], req.query, query_params\n"
        "   - http_body: request.POST/form/json/body, including login form fields such as "
        "form.data['email']\n"
        "   - http_header: request.headers[...], headers.get(...), cookies\n"
        "   - cli_arg: sys.argv, argparse/click args\n"
        "   - stdin: input(), sys.stdin.read()\n"
        "   - socket: network stream reads\n"
        "   - env: os.environ, os.getenv\n"
        "   - file: open(...).read() when the file is not clearly trusted\n"
        "   - db_read: reads of data that may have been user-written (second-order)\n"
        "   - deserialized: unsafe object-deserializer output from external bytes\n"
        "   - untrusted_param: a parameter named/documented as request/payload/event/user_input, "
        "or a parameter that directly selects externally supplied serialized content consumed "
        "by an unsafe deserializer. EMIT a taint_sources record; notes are not enough.\n"
        "   - unknown_external: value crosses a trust boundary (external API, plugin, webhook, "
        "queue, RPC, dynamic call) but you cannot classify it. EMIT THIS rather than omit.\n"
        "   Do NOT invent sources for ordinary internal variables with no external origin.\n"
        "2. SINK — a sensitive operation site. For EACH, record sink_kind, the exact tainted "
        "argument expression, its position, and the TYPED arg_context:\n"
        "   - sql_query (cursor.execute, raw SQL): context sql_query_text | sql_identifier | "
        "sql_numeric_literal | sql_param (a value passed as a BIND parameter)\n"
        "   - shell_command (os.system, shell=True, or attacker-controlled Python passed to "
        "eval/exec as free-form command dispatch): shell_command_text | shell_arg_token. Record "
        "attacker-controlled Python passed to eval/exec for command dispatch as shell_command "
        "with shell_command_text so arbitrary command execution is reported as CWE-78.\n"
        "   - subprocess_argv (subprocess([...], shell=False)): shell_argv_token | executable_path\n"
        "   - fs_path (open, send_file, os.path.join to FS): fs_path | fs_path_segment\n"
        "   - http_url_ssrf (requests.get/urlopen): http_url\n"
        "   - redirect_location (redirect(...)): redirect_url\n"
        "   - html_output (HttpResponse/render with raw data): html_body | html_attr | js_string "
        "| url_attr | css_string\n"
        "   - template_source (render_template_string): template_source\n"
        "   - deserialize (pickle/unsafe YAML/torch.load-style pickle semantics or "
        "framework loaders with pickle-like object "
        "construction): serialized_blob\n"
        "     A dedicated serialized-artifact security scan helper that decides whether the "
        "artifact may continue to a downstream unsafe object loader is also a deserialize "
        "acceptance boundary: emit a deserialize sink on the scanned blob even if torch.load "
        "is in its caller. Bind the helper's content_scan guard to that sink. Checking only an "
        "infected count while ignoring an explicit scan-error result is open and unprotected; "
        "rejecting on infection OR scan error is closed and protected. Do not apply this rule "
        "to generic file scanners with no serialized-artifact/deserialization role.\n"
        "   - code_eval (eval/exec used as code evaluation rather than command dispatch): code_string\n"
        "   - ldap (LDAP search APIs receiving a constructed filter): ldap_filter ;  "
        "xpath: xpath_expr\n"
        "   This sink-kind list is CLOSED. Never emit unknown_external as a sink_kind or "
        "arg_context; unknown_external is a SOURCE kind only. An external API call, JQL call, "
        "ORM helper, getattr, or ordinary dynamic method call is not automatically SQL, shell, "
        "or code execution. Emit a sink only when it matches one of the operations above.\n"
        "   Removing eval/exec removes that execution sink. json.loads followed by getattr and "
        "an ordinary method call is structured API dispatch, not an execution sink; do not emit "
        "shell_command or code_eval solely for that pattern.\n"
        "   IMPORTANT: a value passed as a BIND parameter (e.g. execute('... ?', (x,))) IS still a "
        "sink with arg_context=sql_param — record it; the checker marks it SANITIZED, not absent.\n"
        "3. SANITIZER — a value-transforming or value-binding operation that endorses a value "
        "for a SPECIFIC sink context. "
        "Record sanitizer_kind, the input/output expr, and `endorses` (the arg_context(s) it "
        "covers). Examples: parameterized_query->sql_param; int_cast->sql_numeric_literal; "
        "html_escape->html_body; shell_quote->shell_arg_token; path_containment->fs_path; "
        "url_allowlist->http_url; ldap_escape->ldap_filter. LDAP escape helpers such as "
        "escape_filter_chars sanitize only when applied before the value is interpolated into "
        "the LDAP filter passed to search. A sanitizer is ONLY valid for the context it truly covers — "
        "html escaping does NOT make a value safe for SQL, shell, JS, or a URL.\n"
        "4. VALIDATION GUARD — a control-flow gate that decides whether the sink may execute "
        "(reject/abort/return before the sink), not a transformed value. Put these only in the "
        "top-level `validation_guards` list; never put them in any flow `sanitizers` list. "
        "Allowed guard_kind values here: schema_validation, deserialization_allowlist, "
        "content_scan. A content_scan can endorse only serialized_blob sinks, and only when it "
        "scans the exact same input expression consumed by the exact sink id it protects. Emit "
        "protects_sink_ids, input_expr, endorses, coverage, failure_mode, bypass_param, and "
        "confidence. coverage is `must` if unavoidable, `default` if enabled by default but a "
        "caller can bypass it, `conditional` otherwise. If the function signature defaults the "
        "guard on (for example scan=True), use coverage=default with bypass_param set to that "
        "parameter; explicit false bypass does NOT make it conditional. Use conditional only "
        "for default-off guards or paths with no protected default. failure_mode is `closed` only when "
        "infection OR scan error rejects/aborts before the sink; it is `open` when scan errors "
        "are ignored or incompletely handled; use unknown if unclear. For a default content scan, "
        "use coverage=default and a non-empty bypass_param. A default-false scan has "
        "coverage=conditional. Determine failure_mode independently from its error handling: an "
        "exception that aborts before the sink is closed, while a returned scan-error flag that is "
        "ignored (or an exception that is swallowed and execution continues) is open. A content "
        "scanner guard is closed only when code or a proven callee contract handles both positive "
        "detections and scanner failure/error status. Checking only an infected-item count is open "
        "unless the API contract proves all scanner failures throw. Callee summaries include "
        "guard kind, input, coverage, and failure mode; use a high-confidence fail-closed scan "
        "callee as the guard for the caller's exact downstream deserialize sink.\n"
        "5. FLOWS are PARAMETRIC. When a tainted value originates from one of THIS function's "
        "parameters, record the flow source as `param:<name>` so a caller can instantiate it. "
        "When it originates from a concrete in-function source, use `source:<id>`.\n\n"
        "6. CALLER/CALLEE OWNERSHIP. If a sensitive operation is inside a known callee, record "
        "only the call_site in the caller; do not duplicate or guess the callee's sink in the "
        "caller's own `sinks`. The deterministic composer inherits the callee sink together with "
        "its exact sanitizer or validation guard.\n\n"
        "SOURCE REFERENCE GRAMMAR (use these exact prefixes in every `flows[].source`):\n"
        "   param:<parameter_name>   — symbolic taint from this function's parameter\n"
        "   source:<source_id>       — a concrete source declared in taint_sources\n"
        "   unknown:<id>             — fail-closed unknown external source\n\n"
        "Be conservative and fail-closed: if unsure whether input is trusted, treat it as a "
        "source; if unsure a sanitizer covers a context, do NOT list that context in `endorses`. "
        "A login-form value remains tainted when stored on instance state (for example "
        "form.data['email'] -> self.username) and later used by an LDAP-search method. In an "
        "authentication/login class, when self.username is consumed in an LDAP filter and this "
        "function does not prove a trusted origin, emit a concrete untrusted_param source for "
        "self.username rather than only param:self or a note; this stored request state must give "
        "the LDAP-search function a concrete verdict. "
        "Compute validation coverage per protected sink path: an alternate branch that does not "
        "execute that sink is not a bypass. If every path reaching a torch.load sink first runs "
        "the same fail-closed scan, use coverage=must even when safe-format or custom-loader "
        "branches skip both the scan and that torch.load sink. "
        "Do not emit deserialize for data-only formats/loaders (including safetensors or "
        "data-only GGUF readers) unless there is concrete evidence "
        "they can construct attacker-controlled objects or execute code; binary tensor/data "
        "containers alone are not unsafe-deserialization sinks. Externally supplied "
        "serialized-artifact parameters remain eligible untrusted inputs. "
        "A generic caller-supplied callable named loader is not a deserialize sink without "
        "concrete evidence that it performs unsafe object construction. "
        "For fs_path sinks, emit fs_path only with evidence that attacker-controlled path "
        "structure can escape an intended trusted root or allowlist; opaque/unknown path "
        "handling or an internal file reader accepting a path is not enough."
    )


def _user_prompt(numbered_src, signature_line, language, callee_summaries):
    callee_ctx = ""
    if callee_summaries:
        callee_ctx = (
            "\n\nCallee taint summaries (already derived; if you call one of these and pass a "
            "tainted argument into a parameter that the callee flows to a sink, that sink is "
            "reached THROUGH the call — the checker composes this, but record the call_site):\n"
            + callee_summaries
        )
    return (
        f"Programming language: {language}\n\n"
        f"Function under analysis:\n{signature_line}\n"
        f"```{language.lower()}\n{numbered_src}\n```\n"
        f"{callee_ctx}\n\n"
        "Return EXACTLY ONE JSON object wrapped in [TAINT_JSON] and [/TAINT_JSON]. ALL top-level "
        "fields are REQUIRED; use empty lists where a fact is absent:\n"
        "{\n"
        '  "schema_version": "taint.v1",\n'
        '  "function": "<name>",\n'
        '  "language": "' + language.lower() + '",\n'
        '  "params": ["<p1>", "..."],\n'
        '  "taint_sources": [\n'
        '    {"id": "S1", "source_kind": "http_param", "expr": "<exact expr>", '
        '"introduced_by": "<how>", "confidence": "high|medium|low"}\n'
        "  ],\n"
        '  "sanitizers": [\n'
        '    {"id": "Z1", "sanitizer_kind": "parameterized_query", "expr": "<exact expr>", '
        '"input_expr": "<x>", "output_expr": "<y>", "endorses": ["sql_param"], '
        '"confidence": "high|medium|low"}\n'
        "  ],\n"
        '  "validation_guards": [\n'
        '    {"id": "G1", "guard_kind": "content_scan", "expr": "<guard expr>", '
        '"input_expr": "<same expr as protected sink arg>", "protects_sink_ids": ["K1"], '
        '"endorses": ["serialized_blob"], "coverage": "must|default|conditional", '
        '"failure_mode": "closed|open|unknown", "bypass_param": "<param or empty>", '
        '"confidence": "high|medium|low"}\n'
        "  ],\n"
        '  "taint_bindings": [\n'
        '    {"expr": "<local var>", "flows": [{"source": "source:S1", "sanitizers": []}]}\n'
        "  ],\n"
        '  "return_flows": [\n'
        '    {"expr": "return", "flows": [{"source": "param:x", "sanitizers": []}]}\n'
        "  ],\n"
        '  "param_mutations": [\n'
        '    {"param": "<out>", "path": "<out.field>", "flows": [{"source": "param:x", "sanitizers": []}]}\n'
        "  ],\n"
        '  "call_sites": [\n'
        '    {"id": "C1", "callee": "<fn>", "call_expr": "<expr>", '
        '"args": [{"position": 0, "param_name": "<callee_param>", "expr": "<actual>", '
        '"flows": [{"source": "source:S1", "sanitizers": []}]}], "return_expr": "<var|null>"}\n'
        "  ],\n"
        '  "sinks": [\n'
        '    {"id": "K1", "sink_kind": "sql_query", "callee": "cursor.execute", '
        '"call_expr": "<expr>", "arg_position": 0, "arg_expr": "<tainted arg>", '
        '"arg_context": "sql_query_text", "flows": [{"source": "param:name", "sanitizers": []}]}\n'
        "  ],\n"
        '  "notes": []\n'
        "}\n"
        "Rules: every flows[].source uses param:/source:/unknown: prefix. A bind-parameter value "
        "is a sink with arg_context=sql_param (do not omit it). Only list a context in a "
        "sanitizer's `endorses` if it genuinely covers it. Mark request-derived values as sources "
        "even if assigned to an innocuously-named variable. Validation guards are not flow "
        "sanitizers: keep flow sanitizer lists for value endorsements only. Content scans for "
        "serialized blobs must name exact sink ids, use the same input expression as the sink, "
        "endorse serialized_blob, and include coverage/failure_mode/bypass_param/confidence. "
        "If a parameter directly selects externally supplied serialized content consumed by an "
        "unsafe deserializer, emit an untrusted_param source record. A scan that defaults true "
        "and rejects on infection or scan error is default/closed even when scan=False can "
        "bypass; a default-false scan is conditional; missing scan-error rejection is open. "
        "Emit deserialize only for unsafe object construction/code execution, not data-only "
        "formats without concrete unsafe-constructor evidence. Emit fs_path only when path "
        "structure can escape a trusted root or allowlist, not for opaque/internal path readers."
    )
