from config import *
import json
from .llm_client import (
    _llm_provider_client,
    _retry_create,
    _llm_json_call,
    _parse_json_response,
)
from .trace_writer import (
    new_event_id,
    record_llm_exchange,
    utc_now_iso,
)


def _load_spec_check_json(response):
    """Load a single JSON object from a specification-check response.

    The shared parser handles direct, fenced, and prose-wrapped structured
    responses.  This adapter retains the spec-checker's object-only contract
    and its ``JSONDecodeError`` failure type.
    """
    text = response.strip() if isinstance(response, str) else ""
    try:
        data = _parse_json_response(response)
    except ValueError as exc:
        raise json.JSONDecodeError(str(exc), text, 0) from exc
    if not isinstance(data, dict):
        raise json.JSONDecodeError("spec-check response must contain a JSON object", text, 0)
    return data

def _parse_spec_check_json(response):
    """Parse and validate the spec-check model structured JSON verdict."""
    try:
        data = _load_spec_check_json(response)
    except json.JSONDecodeError as exc:
        raise ValueError(f"spec-check response is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("spec-check JSON must be an object")

    required = ("verdict", "counterexample", "offending_statements", "reason")
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError("spec-check JSON missing required field(s): " + ", ".join(missing))

    verdict = data.get("verdict")
    if isinstance(verdict, str):
        verdict = verdict.upper()
    if verdict not in ("MATCH", "MISMATCH"):
        raise ValueError("spec-check JSON verdict must be MATCH or MISMATCH")

    counterexample = data.get("counterexample")
    offending_statements = data.get("offending_statements")
    reason = data.get("reason")

    if counterexample is not None and not isinstance(counterexample, str):
        raise ValueError("spec-check JSON field counterexample must be a string or null")
    if offending_statements is not None and not isinstance(offending_statements, str):
        raise ValueError("spec-check JSON field offending_statements must be a string or null")
    if not isinstance(reason, str):
        raise ValueError("spec-check JSON field reason must be a string")

    def _nonempty_string(value):
        return isinstance(value, str) and bool(value.strip())

    data["verdict"] = verdict

    if verdict == "MISMATCH":
        missing = [
            name for name, value in (
                ("counterexample", counterexample),
                ("offending_statements", offending_statements),
                ("reason", reason),
            )
            if not _nonempty_string(value)
        ]
        if missing:
            raise ValueError(
                "spec-check MISMATCH JSON missing non-empty field(s): " + ", ".join(missing)
            )
        data["counterexample"] = counterexample.strip()
        data["offending_statements"] = offending_statements.strip()
        data["reason"] = reason.strip()
        return True, data["offending_statements"], data["reason"], data

    if _nonempty_string(counterexample) or _nonempty_string(offending_statements):
        raise ValueError(
            "spec-check MATCH JSON must not include counterexample or offending_statements"
        )
    data["counterexample"] = None
    data["offending_statements"] = None
    data["reason"] = reason.strip()
    return False, None, None, data


def _parse_post_condition_json(data):
    """Validate the structured response used to generate one block's post-condition."""
    if not isinstance(data, dict):
        raise ValueError("post-condition JSON must be an object")
    post_condition = data.get("post_condition")
    if not isinstance(post_condition, str) or not post_condition.strip():
        raise ValueError("post-condition JSON requires a non-empty string field: post_condition")
    return post_condition.strip()

def _generate_block_post_condition(block, pre_condition, knowledge, language,
                                   trace_dir=None, trace_meta=None):
    info_str = f"\nAdditional context:\n{knowledge}" if knowledge else ""
    messages = [
        {"role": "system", "content": (
            f"You are an expert in formal verification of {language} programs. "
            f"Given a {language} code block and its pre-condition, generate the post-condition "
            "that describes the program state after the code block finishes execution. "
            "Cover all execution paths including early returns, exceptions, and normal flow-through. "
            f"Apply {language}-specific semantics (ownership, lifetimes, error handling, etc.) as appropriate. "
            "Be precise and unambiguous. Express the post-condition in natural language and formal logic."
        )},
        {"role": "user", "content": (
            f"Programming language: {language}\n\n"
            f"Pre-condition:\n{pre_condition}\n\n"
            f"Code block:\n```{language.lower()}\n{block}\n```\n"
            f"{info_str}\n"
            "Generate the post-condition. Return only a valid JSON object with this "
            "required field: {\"post_condition\": \"...\"}. Do not include Markdown, "
            "tags, or prose outside the JSON object."
        )}
    ]
    meta = {
        "purpose": "generate_block_post_condition",
        "summary": "Generated post-condition for code block",
        **(trace_meta or {}),
    }
    return _llm_json_call(
        _llm_provider_client,
        REASONER_POST_CONDITION_MODEL,
        messages,
        _parse_post_condition_json,
        '{"post_condition": "non-empty string"}',
        trace_dir=trace_dir,
        trace_meta=meta,
    )


_LANGUAGE_EXPERTISE = {
    "rust": (
        "You are an expert in logic, formal verification, and the Rust programming language. "
        "You have deep knowledge of Rust's type system, ownership model, borrow checker, "
        "pattern matching exhaustiveness, trait system, and standard library. "
        "You know all Rust editions (2015, 2018, 2021, 2024) and their differences. "
    ),
    "c": (
        "You are an expert in logic, formal verification, and C compilation standards. "
        "You have encyclopedic knowledge of every C standard revision (C89, C99, C11, C17, C23) "
        "and know exactly which keywords, types, and constructs each revision introduced. "
    ),
    "c++": (
        "You are an expert in logic, formal verification, and C++ standards. "
        "You have encyclopedic knowledge of every C++ standard revision (C++98, C++03, C++11, C++14, C++17, C++20, C++23) "
        "and know exactly which keywords, types, templates, concepts, and constructs each revision introduced. "
        "You understand RAII, exception safety guarantees, move semantics, and the C++ object model. "
    ),
    "python": (
        "You are an expert in logic, formal verification, and the Python programming language. "
        "You have deep knowledge of Python's type system, exception handling, "
        "standard library, and semantics across Python 3.x versions. "
    ),
    "java": (
        "You are an expert in logic, formal verification, and the Java programming language. "
        "You have deep knowledge of Java's type system, generics, exception handling (checked and unchecked), "
        "collections framework, concurrency utilities, and semantics across Java SE versions (8 through 21). "
        "You understand the JVM memory model, garbage collection, class loading, autoboxing, "
        "and the differences between primitives and wrapper types. "
    ),
    "go": (
        "You are an expert in logic, formal verification, and the Go programming language. "
        "You have deep knowledge of Go's type system, interfaces, goroutines, channels, "
        "error handling conventions (multiple return values), defer/panic/recover, "
        "slices, maps, and semantics across Go versions (1.x through 1.22). "
        "You understand the Go memory model, garbage collection, and concurrency primitives. "
    ),
    "c#": (
        "You are an expert in logic, formal verification, and the C# programming language. "
        "You have deep knowledge of C#'s type system, generics, LINQ, async/await, "
        "nullable reference types, pattern matching, records, and semantics across C# versions (7.x through 12). "
        "You understand the .NET runtime, garbage collection, value types vs reference types, "
        "and the differences between struct and class. "
    ),
    "kotlin": (
        "You are an expert in logic, formal verification, and the Kotlin programming language. "
        "You have deep knowledge of Kotlin's null safety, extension functions, coroutines, "
        "sealed classes, data classes, delegation, and semantics across Kotlin versions (1.x through 2.x). "
        "You understand Kotlin's interop with Java, smart casts, and scope functions. "
    ),
    "swift": (
        "You are an expert in logic, formal verification, and the Swift programming language. "
        "You have deep knowledge of Swift's type system, optionals, protocol-oriented programming, "
        "generics, error handling (do/try/catch/throw), value semantics, ARC, "
        "and semantics across Swift versions (5.x through 6.x). "
    ),
    "php": (
        "You are an expert in logic, formal verification, and the PHP programming language. "
        "You have deep knowledge of PHP's type system, type juggling, traits, "
        "exception handling, generators, and semantics across PHP versions (7.x through 8.x). "
        "You understand PHP's reference counting, copy-on-write, and the differences between == and ===. "
    ),
    "ruby": (
        "You are an expert in logic, formal verification, and the Ruby programming language. "
        "You have deep knowledge of Ruby's dynamic type system, blocks/procs/lambdas, "
        "metaprogramming, mixins, exception handling (begin/rescue/ensure), "
        "and semantics across Ruby versions (2.x through 3.x). "
    ),
    "scala": (
        "You are an expert in logic, formal verification, and the Scala programming language. "
        "You have deep knowledge of Scala's type system, pattern matching, implicits/given, "
        "traits, case classes, higher-kinded types, and semantics across Scala 2.x and Scala 3. "
        "You understand the JVM runtime model and Scala's interop with Java. "
    ),
    "dart": (
        "You are an expert in logic, formal verification, and the Dart programming language. "
        "You have deep knowledge of Dart's sound null safety, type system, generics, "
        "async/await, streams, isolates, extension methods, and semantics across Dart versions (2.x through 3.x). "
    ),
    "cuda": (
        "You are an expert in logic, formal verification, CUDA programming, and C/C++ standards. "
        "You have deep knowledge of CUDA execution model, kernel launch semantics, "
        "memory hierarchy (global, shared, local, constant), thread synchronization, "
        "and GPU-specific concerns like race conditions and warp divergence. "
    ),
    "javascript": (
        "You are an expert in logic, formal verification, and the JavaScript programming language. "
        "You have deep knowledge of JavaScript's type coercion, prototypal inheritance, closures, "
        "event loop, async/await, Promises, and semantics across ECMAScript editions (ES5, ES6/ES2015 through ES2024). "
    ),
    "typescript": (
        "You are an expert in logic, formal verification, and the TypeScript programming language. "
        "You have deep knowledge of TypeScript's structural type system, generics, union/intersection types, "
        "type narrowing, type guards, utility types, declaration merging, and module resolution. "
        "You understand the full JavaScript runtime semantics and how TypeScript's compile-time checks "
        "interact with runtime behavior across TypeScript versions (2.x through 5.x). "
    ),
    "erlang": (
        "You are an expert in logic, formal verification, and the Erlang programming language. "
        "You have deep knowledge of Erlang modules, name/arity function identity, pattern matching, "
        "guards, multi-clause functions, recursion, exceptions, processes, message passing, OTP "
        "behaviours, and the BEAM execution model. "
    ),
    "arkts": (
        "You are an expert in logic, formal verification, and the ArkTS programming language for OpenHarmony. "
        "You have deep knowledge of ArkTS's strict typing enforced at compile time, its declarative UI paradigm "
        "with struct-based components (@Component, @Entry), state management decorators (@State, @Prop, @Link, "
        "@Provide, @Consume, @StorageLink), and its restrictions compared to standard TypeScript "
        "(no structural typing, no any/unknown, no duck typing, limited union types, mandatory explicit types). "
        "You understand the ArkUI framework, the OpenHarmony application lifecycle, and the differences "
        "between ArkTS and TypeScript semantics. "
    ),
}


def _check_post_implies_spec(block, post_condition, spec_post_condition, knowledge, language,
                             trace_dir=None, trace_meta=None,
                             include_counterexample=False):
    info_str = f"\nAdditional context:\n{knowledge}" if knowledge else ""
    lang_expertise = _LANGUAGE_EXPERTISE.get(language.lower(), f"You are an expert in logic, formal verification, and {language} programming. ")
    messages = [
        {"role": "system", "content": (
            lang_expertise +
            "Given a code block, its post-condition A (what the code actually does), and a specification post-condition B (what the code should do), "
            "determine whether there exists a concrete valid input where the code's behavior (A) violates the specification (B). "
            "Focus on finding CONCRETE COUNTEREXAMPLES: specific input values where the code produces an output that does not satisfy the specification. "
            "Check these common violation patterns:\n"
            "  1. The code rejects/filters out inputs that the specification says should be accepted (missing cases). "
            "Enumerate all required cases from the specification and the relevant language standard, and check each one against what the code handles.\n"
            "  2. The code accepts inputs that the specification says should be rejected.\n"
            "  3. The code produces a wrong output value for a valid input.\n"
            "For each potential violation, construct a specific input, trace what the code does (A), and check if the specification (B) is satisfied.\n"
            "Return only a valid JSON object. Do not include markdown, tags, or prose. "
            "Use exactly this schema: "
            "{\"verdict\": \"MATCH|MISMATCH\", \"counterexample\": string|null, "
            "\"offending_statements\": string|null, \"reason\": string}. "
            "For MISMATCH, counterexample, offending_statements, and reason must be non-empty strings; "
            "offending_statements must preserve any 'Line N:' prefixes from the code block. "
            "For MATCH, counterexample and offending_statements must be null or empty, and reason may be empty."
        )},
        {"role": "user", "content": (
            f"Programming language: {language}\n\n"
            f"Code block:\n```{language.lower()}\n{block}\n```\n\n"
            f"Condition A (what the code actually does):\n{post_condition}\n\n"
            f"Condition B (what the specification requires):\n{spec_post_condition}\n"
            f"{info_str}\n"
            "Is there a concrete valid input where the code's behavior violates the specification? "
            "Enumerate all cases required by condition B and check if condition A covers each one. "
            "Provide a specific counterexample if any case is missing. Return only the JSON object."
        )}
    ]
    trace_meta = trace_meta or {}
    for attempt in range(1, MAX_SPC_ITER + 1):
        event_id = new_event_id("llm")
        started = utc_now_iso()
        response = None
        usage = {}
        try:
            response, usage = _retry_create(_llm_provider_client, REASONER_SPEC_CHECK_MODEL, messages)
        except Exception as exc:
            event = {
                "event_id": event_id,
                "type": "llm_call",
                "stage": "verification",
                "status": "error",
                "start_time": started,
                "end_time": utc_now_iso(),
                "summary": f"LLM implication check failed: {exc}",
                "metadata": {
                    **trace_meta,
                    "purpose": "check_post_implies_spec",
                    "model": REASONER_SPEC_CHECK_MODEL,
                    "attempt": attempt,
                    "error": str(exc),
                },
            }
            record_llm_exchange(trace_dir, event_id, event, messages)
            raise
        parsed_result = None
        parse_error = None
        try:
            has_violation, stmts, reason, parsed_result = _parse_spec_check_json(response)
            status = "mismatch" if has_violation else "success"
        except ValueError as exc:
            has_violation = None
            stmts = reason = None
            parse_error = str(exc)
            status = "format_error"
        event = {
            "event_id": event_id,
            "type": "llm_call",
            "stage": "verification",
            "status": status,
            "start_time": started,
            "end_time": utc_now_iso(),
            "summary": "Checked whether actual post-condition implies the spec",
            "metadata": {
                **trace_meta,
                "purpose": "check_post_implies_spec",
                "model": REASONER_SPEC_CHECK_MODEL,
                "attempt": attempt,
                "usage": usage,
                "parsed_json": parsed_result,
                "parse_error": parse_error,
            },
        }
        record_llm_exchange(trace_dir, event_id, event, messages, response)
        if has_violation is not None:
            if has_violation:
                stmts = stmts or "(unable to extract)"
                reason = reason or "(unable to extract)"
                result = (False, stmts, post_condition, reason)
                if include_counterexample:
                    return result + (parsed_result["counterexample"],)
                return result
            else:
                result = (True, None, None, None)
                if include_counterexample:
                    return result + (None,)
                return result
        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {
                "role": "user",
                "content": (
                    "Return only valid JSON with schema: "
                    "{\"verdict\": \"MATCH|MISMATCH\", "
                    "\"counterexample\": string|null, "
                    "\"offending_statements\": string|null, "
                    "\"reason\": string}. "
                    "For MISMATCH, all evidence fields must be non-empty strings. "
                    "For MATCH, counterexample and offending_statements must be null or empty, and reason may be empty."
                ),
            }
        ]
    raise ValueError("Could not parse a valid structured JSON verdict from spec-check response.")
