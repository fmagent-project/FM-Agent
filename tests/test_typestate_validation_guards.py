import copy
import json
import os
import subprocess
import sys
import unittest

from src.plugins.base import (
    AbstractionRequest,
    DriverContext,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
)
from src.plugins import callgraph
from src.plugins.typestate import TypestatePlugin
from src.typestate_reasoner import SAFE, VULNERABLE, classify
from src.typestate_validation import source_rel_from_extracted


def _facts(events, resources=None):
    return {
        "schema_version": "typestate.v1",
        "function": "target",
        "function_role": "entrypoint",
        "language": "python",
        "resources": resources or [],
        "ambient_contexts": [],
        "entry_states": [],
        "events": events,
        "exit_states": [],
        "calls": [],
        "uncertainties": [],
    }


def _event(event_id, order, kind, resource, predecessors=(), **extra):
    return {
        "id": event_id,
        "order": order,
        "kind": kind,
        "resource": resource,
        "operation": extra.pop("operation", kind),
        "path_coverage": extra.pop("path_coverage", "must"),
        "predecessors_must": list(predecessors),
        "control_depends_on": extra.pop("control_depends_on", []),
        "atomicity": extra.pop("atomicity", "not_applicable"),
        "tls_verify": extra.pop("tls_verify", "not_applicable"),
        **extra,
    }


def _resource(resource_id, kind, canonical, origin="local", mutability="stable"):
    return {
        "id": resource_id,
        "kind": kind,
        "canonical": canonical,
        "origin": origin,
        "formal": canonical if origin == "param" else None,
        "mutability": mutability,
        "escapes": "none",
    }


def _request(source, rel="app.py", name="target", base_name=None):
    function_id = FunctionId(rel, name, base_name or name, "python")
    unit = FunctionUnit(function_id, source, source.splitlines()[0])
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[function_id],
    )
    return AbstractionRequest(unit, DriverContext(program, unit, True))


def _parse(source, payload=None, **identity):
    raw = "[TYPESTATE_JSON]" + json.dumps(payload or _facts([])) + "[/TYPESTATE_JSON]"
    return TypestatePlugin().parse_abstraction_response(_request(source, **identity), raw)


class TypestateCharacterizationTests(unittest.TestCase):
    def test_existing_csrf_state_change_without_validation_is_vulnerable(self):
        request = _resource("request", "http_request", "request", "param")
        result = classify(_facts([_event("change", 1, "STATE_CHANGE", "request")], [request]))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-352", result["findings"][0]["cwe"])

    def test_existing_disabled_tls_use_is_vulnerable(self):
        client = _resource("client", "http_client", "client")
        use = _event("use", 1, "NETWORK_USE", "client", tls_verify="disabled")

        result = classify(_facts([use], [client]))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-295", result["findings"][0]["cwe"])

    def test_existing_check_then_non_atomic_use_is_vulnerable(self):
        path = _resource("path", "filesystem_path", "path", "param", "external_mutable")
        check = _event("check", 1, "FS_CHECK", "path")
        use = _event(
            "use", 2, "FS_USE", "path", predecessors=("check",),
            control_depends_on=["check"], atomicity="non_atomic",
        )

        result = classify(_facts([check, use], [path]))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-367", result["findings"][0]["cwe"])


class TypestateProtocolGuardTests(unittest.TestCase):
    def test_content_type_must_dominate_json_parsing(self):
        request = _resource("request", "http_request", "request", "param")
        guard = _event("content", 1, "CONTENT_TYPE_CHECK", "request")
        parse = _event("parse", 2, "JSON_PARSE", "request", predecessors=("content",))

        self.assertEqual(SAFE, classify(_facts([guard, parse], [request]))["verdict"])
        for unsafe in (
            [parse],
            [_event("parse", 1, "JSON_PARSE", "request"), _event("content", 2, "CONTENT_TYPE_CHECK", "request")],
            [guard, _event("parse", 2, "JSON_PARSE", "request")],
        ):
            with self.subTest(events=[event["kind"] for event in unsafe]):
                result = classify(_facts(unsafe, [request]))
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn("CWE-352", {finding["cwe"] for finding in result["findings"]})

    def test_default_certificates_require_a_dominating_internal_context_creation(self):
        context = _resource("context", "tls_context", "context")
        create = _event("create", 1, "SSL_CONTEXT_CREATE", "context")
        load = _event("load", 2, "CERT_DEFAULT_LOAD", "context", predecessors=("create",))

        self.assertEqual(SAFE, classify(_facts([create, load], [context]))["verdict"])
        for unsafe in (
            [load],
            [_event("load", 1, "CERT_DEFAULT_LOAD", "context"), _event("create", 2, "SSL_CONTEXT_CREATE", "context")],
            [create, _event("load", 2, "CERT_DEFAULT_LOAD", "context")],
        ):
            with self.subTest(events=[event["kind"] for event in unsafe]):
                result = classify(_facts(unsafe, [context]))
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn("CWE-295", {finding["cwe"] for finding in result["findings"]})

    def test_correct_context_state_does_not_excuse_disabled_verification(self):
        context = _resource("context", "tls_context", "context")
        events = [
            _event("create", 1, "SSL_CONTEXT_CREATE", "context"),
            _event("load", 2, "CERT_DEFAULT_LOAD", "context", predecessors=("create",)),
            _event("disable", 3, "TLS_VERIFY_DISABLE", "context"),
            _event("use", 4, "NETWORK_USE", "context", tls_verify="disabled"),
        ]

        result = classify(_facts(events, [context]))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("TLS_VERIFY_DISABLED_USE", {finding["kind"] for finding in result["findings"]})

    def test_no_follow_or_reparse_guard_must_dominate_destructive_acquisition(self):
        path = _resource("path", "filesystem_path", "self.lock_file", "param", "external_mutable")
        for protection in ("nofollow", "reparse"):
            with self.subTest(protection=protection):
                guard = _event("guard", 1, "FS_NOFOLLOW_GUARD", "path", protection=protection)
                acquire = _event("acquire", 2, "FS_ACQUIRE", "path", predecessors=("guard",))
                self.assertEqual(SAFE, classify(_facts([guard, acquire], [path]))["verdict"])

                unsynchronized = _facts([guard, _event("acquire", 2, "FS_ACQUIRE", "path")], [path])
                result = classify(unsynchronized)
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn("CWE-367", {finding["cwe"] for finding in result["findings"]})


class TypestateSourceValidationTests(unittest.TestCase):
    def test_content_type_gated_json_source_overrides_empty_llm_facts(self):
        vulnerable = """def handler(request):
    body = request.body()
    return request.json()
"""
        fixed = """def handler(request):
    body = request.body()
    content_type = request.headers.get("content-type")
    if content_type and content_type.startswith("application/json"):
        return request.json()
    return body
"""

        self.assertEqual(VULNERABLE, classify(_parse(vulnerable).payload)["verdict"])
        self.assertEqual(SAFE, classify(_parse(fixed).payload)["verdict"])

    def test_parsed_content_type_main_and_json_subtype_guard_request_parsing(self):
        source = """def handler(request):
    content_type = request.headers.get("content-type")
    if content_type:
        message = Message()
        message["content-type"] = content_type
        if message.get_content_maintype() == "application":
            subtype = message.get_content_subtype()
            if subtype == "json" or subtype.endswith("+json"):
                return request.json()
    return request.body()
"""

        self.assertEqual(SAFE, classify(_parse(source).payload)["verdict"])

    def test_default_cert_loading_tracks_internal_context_state(self):
        vulnerable = """def wrap(sock, ssl_context=None):
    context = ssl_context
    if context is None:
        context = create_urllib3_context()
    if hasattr(context, "load_default_certs"):
        context.load_default_certs()
    return context.wrap_socket(sock)
"""
        fixed = vulnerable.replace(
            'if hasattr(context, "load_default_certs"):',
            'if ssl_context is None and hasattr(context, "load_default_certs"):',
        )

        self.assertEqual(VULNERABLE, classify(_parse(vulnerable).payload)["verdict"])
        self.assertEqual(SAFE, classify(_parse(fixed).payload)["verdict"])

    def test_context_creation_is_inferred_without_factory_name(self):
        vulnerable = """def wrap_socket(sock, supplied=None):
    active = supplied
    if active is None:
        active = make_context()
    if hasattr(active, "load_default_certs"):
        active.load_default_certs()
    return active.wrap_socket(sock)
"""
        fixed = vulnerable.replace(
            'if hasattr(active, "load_default_certs"):',
            'if supplied is None and hasattr(active, "load_default_certs"):',
        )

        self.assertEqual(VULNERABLE, classify(_parse(vulnerable).payload)["verdict"])
        self.assertEqual(SAFE, classify(_parse(fixed).payload)["verdict"])

    def test_optional_context_creation_does_not_establish_required_state(self):
        source = """def wrap(sock, ssl_context=None, configure=False):
    context = ssl_context
    if configure:
        context = create_urllib3_context()
    if ssl_context is None and hasattr(context, "load_default_certs"):
        context.load_default_certs()
    return context.wrap_socket(sock)
"""

        self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_content_type_negative_branch_does_not_guard_json_parsing(self):
        source = """def handler(request):
    content_type = request.headers.get("content-type")
    if content_type == "application/json":
        return request.body()
    else:
        return request.json()
"""

        self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_unrelated_json_feature_flag_does_not_guard_request_parsing(self):
        source = """def handler(request, application_json_enabled):
    content_type = request.headers.get("content-type")
    if application_json_enabled:
        return request.json()
"""

        self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_overwritten_no_follow_flag_does_not_guard_acquisition(self):
        source = """def acquire(path):
    flags = os.O_TRUNC | os.O_NOFOLLOW
    flags = os.O_TRUNC
    return os.open(path, flags)
"""

        self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_swallowed_reparse_rejection_does_not_guard_acquisition(self):
        source = """def acquire(path):
    try:
        if is_reparse_point(path):
            raise OSError("reparse")
    except OSError:
        pass
    flags = os.O_RDWR | os.O_TRUNC
    return os.open(path, flags)
"""

        self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_optional_filesystem_guards_do_not_dominate_acquisition(self):
        unix = """def acquire(path, harden):
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    if harden:
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)
"""
        windows = """def acquire(path, harden):
    if harden:
        if is_reparse_point(path):
            raise OSError("reparse point")
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    return os.open(path, flags)
"""

        for source in (unix, windows):
            with self.subTest(source=source):
                self.assertEqual(VULNERABLE, classify(_parse(source).payload)["verdict"])

    def test_inline_and_keyword_open_flags_use_the_same_protocol(self):
        fixed = """def acquire(path):
    return os.open(path, os.O_RDWR | os.O_TRUNC | os.O_NOFOLLOW)
"""
        vulnerable = """def acquire(path):
    return os.open(path=path, flags=os.O_RDWR | os.O_TRUNC)
"""

        self.assertEqual(SAFE, classify(_parse(fixed).payload)["verdict"])
        self.assertEqual(VULNERABLE, classify(_parse(vulnerable).payload)["verdict"])

    def test_source_protocols_replace_unrelated_model_noise(self):
        request = _resource("request", "http_request", "request", "param")
        response = _resource("response", "generic_resource", "response")
        content_noise = _facts([
            _event(
                "change", 30, "STATE_CHANGE", "response",
                operation="Line 30-32: response = build_response(result)",
            ),
        ], [request, response])
        content_source = """def handler(request):
    content_type = request.headers.get("content-type")
    if content_type and content_type.startswith("application/json"):
        result = request.json()
    response = build_response(result)
    response.headers.extend(headers)
    return response
"""

        context = _resource("context", "tls_context", "context")
        ca_file = _resource("ca_file", "filesystem_path", "ca_file", "param", "external_mutable")
        cert_noise = _facts([
            _event("change", 20, "STATE_CHANGE", "context", operation="self.keyfile = keyfile"),
            _event("open", 21, "RESOURCE_OPEN", "context"),
            _event("check", 22, "FS_CHECK", "ca_file"),
            _event(
                "use", 23, "FS_USE", "ca_file", predecessors=("check",),
                control_depends_on=["check"], atomicity="non_atomic",
                operation="context.load_verify_locations(ca_file)",
            ),
        ], [context, ca_file])
        cert_noise["events"].extend(
            _event(f"noise_{index}", 100 + index, "CALL", None)
            for index in range(65)
        )
        cert_noise["function_role"] = "internal_helper"
        cert_noise["exit_states"] = [{
            "resource": "context", "state": "unknown", "condition": "normal",
            "path_coverage": "unknown", "source_event": "open",
        }]
        cert_source = """def wrap(sock, ssl_context=None):
    context = ssl_context
    if context is None:
        context = create_urllib3_context()
    if ssl_context is None and hasattr(context, "load_default_certs"):
        context.load_default_certs()
    return context.wrap_socket(sock)
"""

        for source, payload in ((content_source, content_noise), (cert_source, cert_noise)):
            with self.subTest(source=source):
                self.assertEqual(SAFE, classify(_parse(source, payload).payload)["verdict"])

    def test_unix_and_windows_fixes_keep_qualified_duplicate_tokens_distinct(self):
        vulnerable = """def _acquire(self):
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    fd = os.open(self.lock_file, flags, self._context.mode)
"""
        fixed_sources = (
            (
                "src/filelock/_unix.py", "_acquire_1", "UnixFileLock._acquire",
                vulnerable.replace("os.O_TRUNC", "os.O_TRUNC | os.O_NOFOLLOW"),
            ),
            (
                "src/filelock/_windows.py", "_acquire", "WindowsFileLock._acquire",
                """def _acquire(self):
    if _is_reparse_point(self.lock_file):
        raise OSError("reparse point")
    flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
    fd = os.open(self.lock_file, flags, self._context.mode)
""",
            ),
        )
        plugin = TypestatePlugin()

        for rel, token, qualified, fixed in fixed_sources:
            with self.subTest(qualified=qualified):
                vulnerable_facts = _parse(vulnerable, rel=rel, name=token, base_name="_acquire")
                fixed_facts = _parse(fixed, rel=rel, name=token, base_name="_acquire")
                request = _request(fixed, rel=rel, name=token, base_name="_acquire")
                verdict = plugin.check(fixed_facts, request.context)
                rendered = plugin.render_result(request.function, fixed_facts, verdict, request.context)

                self.assertEqual(VULNERABLE, classify(vulnerable_facts.payload)["verdict"])
                self.assertEqual(SAFE, verdict.verdict)
                self.assertEqual((rel, token), (rendered["rel"], rendered["function"]))

    def test_raw_guard_claims_are_replaced_by_source_evidence(self):
        request = _resource("request", "http_request", "request", "param")
        lie = _facts([
            _event("content", 1, "CONTENT_TYPE_CHECK", "request"),
            _event("parse", 2, "JSON_PARSE", "request", predecessors=("content",)),
        ], [request])
        source = "def handler(request):\n    return request.json()\n"

        parsed = _parse(source, lie)

        self.assertEqual(VULNERABLE, classify(parsed.payload)["verdict"])

    def test_validation_does_not_mutate_dirty_llm_facts(self):
        request = _resource("request", "http_request", "request", "param")
        dirty = _facts([
            _event("content", 1, "CONTENT_TYPE_CHECK", "request"),
            _event("parse", 2, "JSON_PARSE", "request", predecessors=("content",)),
        ], [request])
        original = copy.deepcopy(dirty)

        parsed = _parse("def handler(request):\n    return request.json()\n", dirty)

        self.assertEqual(original, dirty)
        self.assertNotEqual(dirty, parsed.payload)

    def test_non_object_payload_is_rejected(self):
        request = _request("def target():\n    return None\n")

        parsed = TypestatePlugin().parse_abstraction_response(
            request, "[TYPESTATE_JSON][][/TYPESTATE_JSON]"
        )

        self.assertIsNone(parsed)

    def test_extracted_result_path_maps_to_original_stock_runner_locus(self):
        self.assertEqual(
            "fastapi/routing.py",
            source_rel_from_extracted("fastapi/routing-py/get_request_handler.py"),
        )

    def test_plugin_ordering_is_stable_across_python_hash_seeds(self):
        script = r"""
from src.plugins import callgraph
from src.plugins.base import FunctionId, FunctionUnit
from src.plugins.typestate import TypestatePlugin

def unit(rel, name, source):
    identity = FunctionId(rel, name, name, "python")
    return FunctionUnit(identity, source, source.splitlines()[0])

units = [
    unit("caller.py", "run", "def run():\n    return alpha() + beta() + gamma() + delta()"),
    unit("alpha.py", "alpha", "def alpha():\n    return 1"),
    unit("beta.py", "beta", "def beta():\n    return 2"),
    unit("gamma.py", "gamma", "def gamma():\n    return 3"),
    unit("delta.py", "delta", "def delta():\n    return 4"),
]
TypestatePlugin()
print("|".join(item.id.rel for item in callgraph.order_bottom_up(units)))
"""
        orders = set()
        for seed in ("1", "2", "3", "4", "5", "11", "17", "23"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            output = subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=os.path.dirname(os.path.dirname(__file__)),
                env=environment,
                text=True,
            )
            orders.add(output.strip())

        self.assertEqual(1, len(orders), f"callee order varied by hash seed: {sorted(orders)}")

    def test_plugin_does_not_replace_shared_callgraph_ordering(self):
        shared_order = callgraph.order_bottom_up

        TypestatePlugin()

        self.assertIs(shared_order, callgraph.order_bottom_up)

    def test_same_name_and_duplicate_identities_keep_input_order(self):
        first = _request("def _acquire(self):\n    return 1\n", "_unix.py", "_acquire").function
        second = _request("def _acquire(self):\n    return 2\n", "_windows.py", "_acquire").function

        TypestatePlugin()
        ordered = callgraph.order_bottom_up([first, second])

        self.assertEqual([first.id, second.id], [unit.id for unit in ordered])
        self.assertEqual(
            "fastapi/routing.py",
            source_rel_from_extracted(
                "fm_agent_typestate/extracted_functions/fastapi/routing-py/"
                "get_request_handler-py/get_request_handler.py"
            ),
        )

    def test_typestate_cycle_order_is_stable_and_identity_complete(self):
        first = _request("def first():\n    return second()\n", "a.py", "first").function
        second = _request("def second():\n    return first()\n", "b.py", "second").function

        TypestatePlugin()
        orders = [callgraph.order_bottom_up([first, second]) for _ in range(5)]

        self.assertTrue(all([unit.id for unit in order] == [second.id, first.id] for order in orders))
        self.assertEqual({first.id, second.id}, {unit.id for unit in orders[0]})


if __name__ == "__main__":
    unittest.main()
