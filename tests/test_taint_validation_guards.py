import json
import unittest

from src.taint_prompts import _system_prompt
from src.taint_reasoner import (
    POLYMORPHIC,
    SAFE,
    SANITIZED,
    TAINTED,
    VULNERABLE,
    classify,
)
from src.taint_validation import validation_guard_coverage_for_call
from src.plugins.base import (
    AbstractionRequest,
    CallSite,
    DriverContext,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
    ResolvedCall,
)
from src.plugins.taint import TaintPlugin, _normalize_operation_sinks, _summarize


def _facts(validation_guards):
    return {
        "schema_version": "taint.v1",
        "function": "read_checkpoint_meta",
        "language": "python",
        "params": ["path", "scan"],
        "taint_sources": [
            {
                "id": "S1",
                "source_kind": "untrusted_param",
                "expr": "path",
                "confidence": "high",
            }
        ],
        "sanitizers": [],
        "validation_guards": validation_guards,
        "taint_bindings": [],
        "return_flows": [],
        "param_mutations": [],
        "call_sites": [],
        "sinks": [
            {
                "id": "K1",
                "sink_kind": "deserialize",
                "callee": "torch.load",
                "call_expr": "torch.load(path)",
                "arg_position": 0,
                "arg_expr": "path",
                "arg_context": "serialized_blob",
                "flows": [{"source": "param:path", "sanitizers": []}],
            }
        ],
        "notes": [],
    }


def _scan_guard(coverage, failure_mode):
    return {
        "id": "G1",
        "guard_kind": "content_scan",
        "input_expr": "path",
        "protects_sink_ids": ["K1"],
        "endorses": ["serialized_blob"],
        "coverage": coverage,
        "failure_mode": failure_mode,
        "bypass_param": "scan",
        "confidence": "high",
    }


def _family_facts(sink_kind, arg_context, sanitizer_kind=None):
    sanitizer_ids = ["Z1"] if sanitizer_kind else []
    return {
        "schema_version": "taint.v1",
        "function": "security_boundary",
        "language": "python",
        "params": [],
        "taint_sources": [
            {
                "id": "S1",
                "source_kind": "http_body",
                "expr": "form.data['email']",
                "confidence": "high",
            }
        ],
        "sanitizers": [
            {
                "id": "Z1",
                "sanitizer_kind": sanitizer_kind,
                "input_expr": "form.data['email']",
                "output_expr": "value",
                "endorses": [arg_context],
                "confidence": "high",
            }
        ] if sanitizer_kind else [],
        "validation_guards": [],
        "taint_bindings": [],
        "return_flows": [],
        "param_mutations": [],
        "call_sites": [],
        "sinks": [
            {
                "id": "K1",
                "sink_kind": sink_kind,
                "callee": "sensitive_operation",
                "call_expr": "sensitive_operation(value)",
                "arg_position": 0,
                "arg_expr": "value",
                "arg_context": arg_context,
                "flows": [{"source": "source:S1", "sanitizers": sanitizer_ids}],
            }
        ],
        "notes": [],
    }


def _source_backed_family_facts(*sink_kinds):
    facts = _family_facts("ldap", "ldap_filter")
    facts["function"] = "process_request"
    facts["sanitizers"] = [{
        "id": "Z1",
        "sanitizer_kind": "ldap_escape",
        "input_expr": "self.username",
        "output_expr": "escaped_username",
        "endorses": ["ldap_filter"],
        "confidence": "high",
    }]
    facts["sinks"] = []
    if "ldap" in sink_kinds:
        facts["sinks"].append({
            "id": "K_LDAP",
            "sink_kind": "ldap",
            "callee": "self.conn.search",
            "call_expr": "self.conn.search(search_filter=search_filter)",
            "arg_position": 1,
            "arg_expr": "search_filter",
            "arg_context": "ldap_filter",
            "flows": [{"source": "source:S1", "sanitizers": []}],
        })
    if "html_output" in sink_kinds:
        facts["sinks"].append({
            "id": "K_HTML",
            "sink_kind": "html_output",
            "callee": "render_template_string",
            "call_expr": "render_template_string(user_markup)",
            "arg_position": 0,
            "arg_expr": "user_markup",
            "arg_context": "html_body",
            "flows": [{"source": "source:S1", "sanitizers": []}],
        })
    return facts


def _source_backed_scan_facts(confidence="medium"):
    facts = _family_facts("deserialize", "serialized_blob")
    facts["function"] = "load_artifact"
    facts["taint_sources"][0].update(
        source_kind="untrusted_param",
        expr="blob",
    )
    facts["validation_guards"] = [{
        "id": "G_MODEL",
        "guard_kind": "content_scan",
        "expr": "scan_file_path(blob)",
        "input_expr": "blob",
        "protects_sink_ids": ["K1"],
        "endorses": ["serialized_blob"],
        "coverage": "default",
        "failure_mode": "unknown",
        "bypass_param": "custom_loader",
        "confidence": confidence,
    }]
    facts["sinks"][0].update(
        callee="pickle.loads",
        call_expr="pickle.loads(blob)",
        arg_expr="blob",
        flows=[{"source": "source:S1", "sanitizers": []}],
    )
    return facts


def _compose_default_guard(scan_arg):
    return _compose_default_guard_with_bindings(scan_arg, {})


def _compose_default_guard_with_bindings(
    scan_arg, arg_bindings, callee_source=None, callee_payload=None
):
    caller_id = FunctionId("caller.py", "caller", "caller", "python")
    callee_id = FunctionId("callee.py", "read_checkpoint_meta", "read_checkpoint_meta", "python")
    caller_unit = FunctionUnit(caller_id, "read_checkpoint_meta(path)", "def caller(path):")
    callee_unit = FunctionUnit(
        callee_id,
        callee_source or "torch.load(path)",
        "def read_checkpoint_meta(path, scan=True):",
    )
    call_site = CallSite(caller_id, callee_id, "read_checkpoint_meta", arg_bindings=arg_bindings)
    program = ProgramIndex(
        functions={caller_id: caller_unit, callee_id: callee_unit},
        calls_by_caller={caller_id: [call_site], callee_id: []},
        callers_by_callee={caller_id: [], callee_id: [call_site]},
        entrypoints=[caller_id],
    )
    context = DriverContext(program, caller_unit, True, (), (call_site,))
    args = [
        {
            "position": 0,
            "param_name": "path",
            "expr": "path",
            "flows": [{"source": "source:S1", "sanitizers": []}],
        }
    ]
    if scan_arg is not None:
        args.append({"position": 1, "param_name": "scan", "expr": scan_arg, "flows": []})
    caller_payload = {
        "taint_sources": [{"id": "S1", "source_kind": "untrusted_param", "expr": "path"}],
        "sanitizers": [],
        "validation_guards": [],
        "taint_bindings": [],
        "return_flows": [],
        "param_mutations": [],
        "call_sites": [
            {
                "id": "C1",
                "callee": "read_checkpoint_meta",
                "args": args,
                "return_expr": "checkpoint",
            }
        ],
        "sinks": [],
    }
    caller_facts = FactEnvelope("taint", "taint.v1", caller_id, "ok", caller_payload)
    callee_facts = FactEnvelope(
        "taint",
        "taint.v1",
        callee_id,
        "ok",
        callee_payload or _facts([_scan_guard("default", "closed")]),
    )
    composed = TaintPlugin().compose_calls(
        caller_facts,
        [ResolvedCall(call_site, callee_facts)],
        context,
    )
    return classify(composed.payload), composed.payload["sinks"][0]


def _source_backed_default_scan():
    source = (
        "def read_checkpoint_meta(path, scan=True):\n"
        "    if str(path).endswith('.safetensors'):\n"
        "        return {}\n"
        "    else:\n"
        "        if scan:\n"
        "            scan_result = scan_file_path(path)\n"
        "            if scan_result.infected_files or scan_result.scan_err:\n"
        "                raise ValueError('unsafe artifact')\n"
        "        if str(path).endswith('.gguf'):\n"
        "            return {}\n"
        "        else:\n"
        "            return pickle.loads(path)"
    )
    guard = _scan_guard("must", "closed")
    guard["bypass_param"] = ""
    payload = _facts([guard])
    payload["sinks"][0].update(
        callee="pickle.loads",
        call_expr="pickle.loads(path)",
    )
    return source, payload


def _compose_source_backed_default_guard(scan_arg):
    source, payload = _source_backed_default_scan()
    return _compose_default_guard_with_bindings(
        scan_arg, {}, callee_source=source, callee_payload=payload
    )


def _compose_interprocedural_scan_guard(
    caller_source,
    helper_source=None,
    helper_actual="model_path",
    helper_coverage="must",
    helper_bypass="",
):
    helper_source = helper_source or (
        "@classmethod\n"
        "def _scan_model(cls, model_name, checkpoint):\n"
        "    scan_result = scan_file_path(checkpoint)\n"
        "    if scan_result.infected_files or scan_result.scan_err:\n"
        "        raise ValueError('unsafe artifact')"
    )
    caller_id = FunctionId("probe.py", "_scan_and_load_checkpoint", "_scan_and_load_checkpoint", "python")
    helper_id = FunctionId("probe.py", "_scan_model", "_scan_model", "python")
    caller_unit = FunctionUnit(
        caller_id,
        caller_source,
        "def _scan_and_load_checkpoint(cls, model_path):",
    )
    helper_unit = FunctionUnit(
        helper_id,
        helper_source,
        "def _scan_model(cls, model_name, checkpoint):",
    )
    call_site = CallSite(
        caller_id,
        helper_id,
        "_scan_model",
        arg_bindings={
            "param:model_name": f"{helper_actual}.name",
            "param:checkpoint": helper_actual,
        },
    )
    program = ProgramIndex(
        functions={caller_id: caller_unit, helper_id: helper_unit},
        calls_by_caller={caller_id: [call_site], helper_id: []},
        callers_by_callee={caller_id: [], helper_id: [call_site]},
        entrypoints=[caller_id],
    )
    caller_payload = _facts([])
    caller_payload.update(
        function="_scan_and_load_checkpoint",
        params=["model_path"],
        validation_guards=[{
            **_scan_guard("must", "closed"),
            "expr": f"cls._scan_model({helper_actual}.name, {helper_actual})",
            "input_expr": "model_path",
            "bypass_param": "",
        }],
        call_sites=[{
            "id": "C1",
            "callee": "_scan_model",
            "args": [{
                "position": 1,
                "param_name": "checkpoint",
                "expr": helper_actual,
                "flows": [{"source": f"param:{helper_actual}", "sanitizers": []}],
            }],
            "return_expr": None,
        }],
    )
    caller_payload["taint_sources"][0]["expr"] = "model_path"
    caller_payload["sinks"][0].update(
        callee="torch.load",
        call_expr='torch.load(model_path, map_location="cpu")',
        arg_expr="model_path",
        flows=[{"source": "param:model_path", "sanitizers": []}],
    )
    helper_guard = _scan_guard(helper_coverage, "closed")
    helper_guard.update(
        expr="scan_file_path(checkpoint)",
        input_expr="checkpoint",
        protects_sink_ids=[],
        bypass_param=helper_bypass,
    )
    helper_payload = _facts([helper_guard])
    helper_payload.update(
        function="_scan_model",
        params=["model_name", "checkpoint"],
        taint_sources=[],
        sinks=[],
    )
    caller_facts = FactEnvelope("taint", "taint.v1", caller_id, "ok", caller_payload)
    helper_facts = FactEnvelope("taint", "taint.v1", helper_id, "ok", helper_payload)
    context = DriverContext(program, caller_unit, True, (), (call_site,))
    composed = TaintPlugin().compose_calls(
        caller_facts,
        [ResolvedCall(call_site, helper_facts)],
        context,
    )
    return classify(composed.payload, param_status={"model_path": TAINTED}), composed.payload


def _compose_ldap_sanitizer(sanitizer_kind):
    caller_id = FunctionId("caller.py", "authenticate", "authenticate", "python")
    callee_id = FunctionId("callee.py", "search_ldap_user", "search_ldap_user", "python")
    caller_unit = FunctionUnit(caller_id, "search_ldap_user(email)", "def authenticate(form):")
    callee_unit = FunctionUnit(callee_id, "conn.search(search_filter)", "def search_ldap_user(username):")
    call_site = CallSite(caller_id, callee_id, "search_ldap_user")
    program = ProgramIndex(
        functions={caller_id: caller_unit, callee_id: callee_unit},
        calls_by_caller={caller_id: [call_site], callee_id: []},
        callers_by_callee={caller_id: [], callee_id: [call_site]},
        entrypoints=[caller_id],
    )
    context = DriverContext(program, caller_unit, True, (), (call_site,))
    caller_payload = _family_facts("ldap", "ldap_filter")
    caller_payload["sinks"] = []
    caller_payload["call_sites"] = [
        {
            "id": "C1",
            "callee": "search_ldap_user",
            "args": [
                {
                    "position": 0,
                    "param_name": "username",
                    "expr": "form.data['email']",
                    "flows": [{"source": "source:S1", "sanitizers": []}],
                }
            ],
            "return_expr": None,
        }
    ]
    callee_payload = _family_facts("ldap", "ldap_filter", sanitizer_kind)
    callee_payload["taint_sources"] = []
    callee_payload["sinks"][0]["flows"][0]["source"] = "param:username"
    caller_facts = FactEnvelope("taint", "taint.v1", caller_id, "ok", caller_payload)
    callee_facts = FactEnvelope("taint", "taint.v1", callee_id, "ok", callee_payload)
    composed = TaintPlugin().compose_calls(
        caller_facts,
        [ResolvedCall(call_site, callee_facts)],
        context,
    )
    return classify(composed.payload)


def _abstraction_request():
    function_id = FunctionId("callee.py", "read_checkpoint_meta", "read_checkpoint_meta", "python")
    unit = FunctionUnit(function_id, "torch.load(path)", "def read_checkpoint_meta(path, scan=True):")
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[function_id],
    )
    return AbstractionRequest(unit, DriverContext(program, unit, True))


def _member_state_context(source):
    function_id = FunctionId("member.py", "search", "search", "python")
    unit = FunctionUnit(function_id, source, "def search(self):")
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[],
    )
    return unit, DriverContext(program, unit, False)


class TaintValidationGuardTests(unittest.TestCase):
    def test_vulnerable_when_scan_is_disabled_by_default_and_errors_fail_open(self):
        # Given
        facts = _facts([_scan_guard("conditional", "open")])

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(VULNERABLE, result["verdict"])

    def test_sanitized_on_local_path_when_fail_closed_scan_is_enabled_by_default(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("validation_guard", result["findings"][0]["sanitized_by"])

    def test_sanitized_when_fail_closed_scan_dominates_every_path(self):
        # Given
        facts = _facts([_scan_guard("must", "closed")])

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("validation_guard", result["findings"][0]["sanitized_by"])

    def test_plugin_checks_default_closed_scan_as_the_safe_default_path(self):
        # Given
        request = _abstraction_request()
        facts = FactEnvelope(
            "taint",
            "taint.v1",
            request.function.id,
            "ok",
            _facts([_scan_guard("default", "closed")]),
        )

        # When
        result = TaintPlugin().check(facts, request.context)

        # Then
        self.assertEqual(SANITIZED, result.verdict)

    def test_vulnerable_when_default_guard_has_no_explicit_bypass_parameter(self):
        # Given
        guard = _scan_guard("default", "closed")
        guard["bypass_param"] = None
        facts = _facts([guard])

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(VULNERABLE, result["verdict"])

    def test_vulnerable_when_guard_protects_a_different_sink(self):
        # Given
        guard = _scan_guard("must", "closed")
        guard["protects_sink_ids"] = ["K2"]
        facts = _facts([guard])

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(VULNERABLE, result["verdict"])

    def test_must_cover_when_caller_omits_default_enabled_bypass_parameter(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], [])

        # Then
        self.assertEqual("must", coverage)

    def test_must_cover_when_caller_explicitly_enables_guard(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])
        args = [{"param_name": "scan", "expr": "True"}]

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], args)

        # Then
        self.assertEqual("must", coverage)

    def test_uncovered_when_caller_explicitly_disables_guard(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])
        args = [{"param_name": "scan", "expr": "False"}]

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], args)

        # Then
        self.assertIsNone(coverage)

    def test_lowercase_true_must_cover_when_caller_explicitly_enables_guard(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])
        args = [{"param_name": "scan", "expr": "true"}]

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], args)

        # Then
        self.assertEqual("must", coverage)

    def test_lowercase_false_uncovers_when_caller_explicitly_disables_guard(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])
        args = [{"param_name": "scan", "expr": "false"}]

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], args)

        # Then
        self.assertIsNone(coverage)

    def test_default_cover_when_caller_passes_dynamic_guard_value(self):
        # Given
        facts = _facts([_scan_guard("default", "closed")])
        args = [{"param_name": "scan", "expr": "scan_models"}]

        # When
        coverage = validation_guard_coverage_for_call(facts, facts["sinks"][0], args)

        # Then
        self.assertEqual("default", coverage)

    def test_sanitized_when_composed_sink_carries_must_guard_coverage(self):
        # Given
        facts = _facts([])
        facts["sinks"][0]["_validation_guard_coverage"] = "must"

        # When
        result = classify(facts, param_status={"path": TAINTED})

        # Then
        self.assertEqual(SANITIZED, result["verdict"])

    def test_raw_llm_sink_guard_coverage_is_stripped_before_classification(self):
        # Given
        facts = _facts([])
        facts["sinks"][0]["_validation_guard_coverage"] = "must"
        raw_response = json.dumps(facts)

        # When
        parsed = TaintPlugin().parse_abstraction_response(_abstraction_request(), raw_response)
        result = classify(parsed.payload, param_status={"path": TAINTED})

        # Then
        self.assertNotIn("_validation_guard_coverage", parsed.payload["sinks"][0])
        self.assertEqual(VULNERABLE, result["verdict"])

    def test_valid_json_array_payload_is_rejected_without_crashing(self):
        # Given
        raw_response = "[TAINT_JSON][][/TAINT_JSON]"

        # When
        parsed = TaintPlugin().parse_abstraction_response(_abstraction_request(), raw_response)

        # Then
        self.assertIsNone(parsed)

    def test_malformed_sink_collection_is_error_not_a_crash(self):
        facts = _facts([])
        facts["sinks"] = {"K1": "not a sink list"}
        self.assertEqual("ERROR", classify(facts)["verdict"])

    def test_composed_default_call_is_sanitized_when_bypass_parameter_is_omitted(self):
        # Given / When
        result, sink = _compose_default_guard(None)

        # Then
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", sink["_validation_guard_coverage"])

    def test_composed_explicit_false_call_remains_vulnerable(self):
        # Given / When
        result, sink = _compose_default_guard("False")

        # Then
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", sink)

    def test_composed_dynamic_guard_call_remains_caller_dependent(self):
        # Given / When
        result, sink = _compose_default_guard("scan_models")

        # Then
        self.assertEqual(POLYMORPHIC, result["verdict"])
        self.assertEqual("default", sink["_validation_guard_coverage"])

    def test_source_backed_default_scan_is_preserved_when_call_omits_bypass(self):
        source, payload = _source_backed_default_scan()
        normalized = _normalize_operation_sinks(payload, source)

        guard = normalized["validation_guards"][0]
        self.assertEqual("default", guard["coverage"])
        self.assertEqual("scan", guard["bypass_param"])
        self.assertNotIn("_validation_guard_coverage", normalized["sinks"][0])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

        result, sink = _compose_source_backed_default_guard(None)
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", sink["_validation_guard_coverage"])

    def test_source_backed_default_scan_covers_explicit_true_call(self):
        result, sink = _compose_source_backed_default_guard("True")

        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", sink["_validation_guard_coverage"])

    def test_source_backed_default_scan_does_not_cover_explicit_false_call(self):
        result, sink = _compose_source_backed_default_guard("False")

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", sink)

    def test_source_backed_default_scan_keeps_dynamic_call_polymorphic(self):
        result, sink = _compose_source_backed_default_guard("scan_models")

        self.assertEqual(POLYMORPHIC, result["verdict"])
        self.assertEqual("default", sink["_validation_guard_coverage"])

    def test_source_validated_helper_guard_covers_exact_later_caller_sink(self):
        source = (
            "@classmethod\n"
            "def _scan_and_load_checkpoint(cls, model_path):\n"
            "    with SilenceWarnings():\n"
            "        if model_path.suffix.endswith(('.ckpt', '.pt', '.pth', '.bin')):\n"
            "            cls._scan_model(model_path.name, model_path)\n"
            "            model = torch.load(model_path, map_location='cpu')\n"
            "            return model\n"
            "        elif model_path.suffix.endswith('.gguf'):\n"
            "            return gguf_sd_loader(model_path)\n"
            "        return safetensors.torch.load_file(model_path)"
        )

        result, payload = _compose_interprocedural_scan_guard(source)

        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", payload["sinks"][0]["_validation_guard_coverage"])

    def test_source_contract_overrides_bogus_default_helper_guard(self):
        helper_source = (
            "def validate_artifact(checkpoint):\n"
            "    scan_result = scan_file_path(checkpoint)\n"
            "    if scan_result.infected_files or scan_result.scan_err:\n"
            "        raise ValueError('unsafe artifact')"
        )
        guard = _scan_guard("default", "closed")
        guard.update(
            expr="scan_result.infected_files or scan_result.scan_err",
            input_expr="checkpoint",
            protects_sink_ids=["K_SCAN_ACCEPT"],
            bypass_param="scan_file_path (no bypass parameter in this function)",
        )
        helper_payload = _facts([guard])
        helper_payload.update(function="validate_artifact", params=["checkpoint"])
        helper_payload["taint_sources"][0]["expr"] = "checkpoint"
        helper_payload["sinks"][0].update(
            id="K_SCAN_ACCEPT",
            callee="scan_file_path",
            call_expr="scan_file_path(checkpoint)",
            arg_expr="checkpoint",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )

        normalized = _normalize_operation_sinks(helper_payload, helper_source)
        normalized_guard = normalized["validation_guards"][0]

        self.assertEqual("must", normalized_guard["coverage"])
        self.assertEqual("closed", normalized_guard["failure_mode"])
        self.assertEqual("", normalized_guard["bypass_param"])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

        caller_source = (
            "def _scan_and_load_checkpoint(cls, model_path):\n"
            "    cls._scan_model(model_path.name, model_path)\n"
            "    return torch.load(model_path, map_location='cpu')"
        )
        result, payload = _compose_interprocedural_scan_guard(
            caller_source,
            helper_coverage="default",
            helper_bypass="scan_file_path (no bypass parameter in this function)",
        )
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", payload["sinks"][0]["_validation_guard_coverage"])

    def test_source_validated_helper_guard_requires_exact_input_binding(self):
        source = (
            "def _scan_and_load_checkpoint(cls, model_path, other):\n"
            "    cls._scan_model(other.name, other)\n"
            "    return torch.load(model_path, map_location='cpu')"
        )

        result, payload = _compose_interprocedural_scan_guard(
            source, helper_actual="other"
        )

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", payload["sinks"][0])

    def test_source_validated_helper_guard_must_dominate_caller_sink(self):
        source = (
            "def _scan_and_load_checkpoint(cls, model_path, should_scan):\n"
            "    if should_scan:\n"
            "        cls._scan_model(model_path.name, model_path)\n"
            "    return torch.load(model_path, map_location='cpu')"
        )

        result, payload = _compose_interprocedural_scan_guard(source)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", payload["sinks"][0])

    def test_fail_open_helper_guard_does_not_cover_caller_sink(self):
        caller_source = (
            "def _scan_and_load_checkpoint(cls, model_path):\n"
            "    cls._scan_model(model_path.name, model_path)\n"
            "    return torch.load(model_path, map_location='cpu')"
        )
        helper_source = (
            "def _scan_model(cls, model_name, checkpoint):\n"
            "    scan_result = scan_file_path(checkpoint)\n"
            "    if scan_result.infected_files:\n"
            "        raise ValueError('unsafe artifact')"
        )

        result, payload = _compose_interprocedural_scan_guard(
            caller_source, helper_source=helper_source
        )

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", payload["sinks"][0])

    def test_bypassable_helper_guard_does_not_cover_caller_sink_as_must(self):
        caller_source = (
            "def _scan_and_load_checkpoint(cls, model_path):\n"
            "    cls._scan_model(model_path.name, model_path)\n"
            "    return torch.load(model_path, map_location='cpu')"
        )
        helper_source = (
            "def _scan_model(cls, model_name, checkpoint, scan=True):\n"
            "    if scan:\n"
            "        scan_result = scan_file_path(checkpoint)\n"
            "        if scan_result.infected_files or scan_result.scan_err:\n"
            "            raise ValueError('unsafe artifact')"
        )

        result, payload = _compose_interprocedural_scan_guard(
            caller_source, helper_source=helper_source
        )

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", payload["sinks"][0])

    def test_composed_llm_omitted_false_arg_uses_parser_binding_to_uncover_guard(self):
        # Given / When
        result, sink = _compose_default_guard_with_bindings(None, {"param:scan": "false"})

        # Then
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertNotIn("_validation_guard_coverage", sink)

    def test_composed_keyword_binding_enables_default_guard(self):
        result, sink = _compose_default_guard_with_bindings(
            None, {"param:scan": "scan=True"}
        )
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", sink["_validation_guard_coverage"])

    def test_composed_llm_arg_overrides_parser_fallback_for_same_parameter(self):
        # Given / When
        result, sink = _compose_default_guard_with_bindings("true", {"param:scan": "false"})

        # Then
        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("must", sink["_validation_guard_coverage"])

    def test_jira_query_exec_is_cwe78_but_structured_dispatch_has_no_exec_sink(self):
        # Given
        vulnerable = _family_facts("shell_command", "shell_command_text")
        fixed = _family_facts("shell_command", "shell_command_text")
        fixed["sinks"] = []

        # When
        vulnerable_result = classify(vulnerable)
        fixed_result = classify(fixed)

        # Then
        self.assertEqual(VULNERABLE, vulnerable_result["verdict"])
        self.assertEqual("CWE-78", vulnerable_result["findings"][0]["cwe"])
        self.assertEqual(SAFE, fixed_result["verdict"])

    def test_source_guard_drops_structured_dispatch_shell_hallucination(self):
        facts = _family_facts("shell_command", "shell_command_text")
        source = "params = json.loads(query)\nfn = getattr(self.jira, params['function'])\nfn()"
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual([], normalized["sinks"])

    def test_source_guard_keeps_real_exec_sink(self):
        facts = _family_facts("shell_command", "shell_command_text")
        normalized = _normalize_operation_sinks(facts, "exec(f'result = {query}', context)")
        self.assertEqual(1, len(normalized["sinks"]))

    def test_deepseek_exec_code_eval_is_normalized_to_cwe78(self):
        facts = _family_facts("code_eval", "code_string")
        facts["sinks"][0].update(
            callee="exec",
            call_expr='exec(f"result = {query}", context)',
            arg_expr='f"result = {query}"',
        )
        normalized = _normalize_operation_sinks(
            facts, 'exec(f"result = {query}", context)'
        )
        result = classify(normalized)
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-78", result["findings"][0]["cwe"])

    def test_source_guard_drops_path_construction_without_filesystem_sink(self):
        facts = _family_facts("fs_path", "fs_path_segment")
        source = "path_or_prefix=(self.model_path / key).resolve().as_posix()"
        self.assertEqual([], _normalize_operation_sinks(facts, source)["sinks"])

    def test_source_guard_drops_filesystem_access_below_caller_selected_root(self):
        facts = _family_facts("fs_path", "fs_path")
        facts["taint_sources"][0].update(
            source_kind="untrusted_param",
            expr="folder_path",
        )
        facts["sinks"][0].update(
            callee="open",
            call_expr='open(folder_path / "config.json")',
            arg_expr='folder_path / "config.json"',
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        source = 'with open(folder_path / "config.json") as config: pass'
        self.assertEqual([], _normalize_operation_sinks(facts, source)["sinks"])

    def test_source_guard_keeps_tainted_segment_below_distinct_root(self):
        facts = _family_facts("fs_path", "fs_path_segment")
        facts["taint_sources"][0].update(
            source_kind="untrusted_param",
            expr="filename",
        )
        facts["sinks"][0].update(
            callee="open",
            call_expr="open(UPLOAD_ROOT / filename)",
            arg_expr="UPLOAD_ROOT / filename",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        source = "with open(UPLOAD_ROOT / filename) as upload: pass"
        self.assertEqual(1, len(_normalize_operation_sinks(facts, source)["sinks"]))

    def test_shell_metacharacter_probe_is_not_cleared_by_argument_quoting(self):
        # A whole command string remains dangerous even if modeled with shell_quote.
        facts = _family_facts("shell_command", "shell_command_text", "shell_quote")
        facts["taint_sources"][0]["expr"] = "query = \"projects(); __import__('os').system('id')\""
        facts["sinks"][0]["arg_expr"] = "f'result = {query}'"
        result = classify(facts)
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-78", result["findings"][0]["cwe"])

    def test_ldap_form_email_requires_ldap_escaping_before_search(self):
        # Given / When
        vulnerable = classify(_family_facts("ldap", "ldap_filter"))
        fixed = classify(_family_facts("ldap", "ldap_filter", "ldap_escape"))

        # Then
        self.assertEqual(VULNERABLE, vulnerable["verdict"])
        self.assertEqual("CWE-90", vulnerable["findings"][0]["cwe"])
        self.assertEqual(SANITIZED, fixed["verdict"])

    def test_ldap_filter_metacharacter_probe_requires_ldap_family_escape(self):
        attack = "*)(|(uid=*))"
        vulnerable_facts = _family_facts("ldap", "ldap_filter")
        fixed_facts = _family_facts("ldap", "ldap_filter", "ldap_escape")
        for facts in (vulnerable_facts, fixed_facts):
            facts["taint_sources"][0]["expr"] = repr(attack)
            facts["sinks"][0]["arg_expr"] = f"(uid={attack})"
        self.assertEqual(VULNERABLE, classify(vulnerable_facts)["verdict"])
        self.assertEqual(SANITIZED, classify(fixed_facts)["verdict"])

    def test_source_backed_family_rejects_logger_xss_but_keeps_ldap(self):
        facts = _source_backed_family_facts("ldap", "html_output")
        facts["sinks"][1].update(
            callee="current_app.logger.info",
            call_expr="current_app.logger.info(create_msg.format(self.username))",
            arg_expr="create_msg.format(self.username)",
        )
        source = (
            "self.username = form.data['email']\n"
            "escaped_username = escape_filter_chars(self.username)\n"
            "search_filter = f'(uid={self.username})'\n"
            "self.conn.search(search_filter=search_filter)\n"
            "current_app.logger.info(create_msg.format(self.username))"
        )

        normalized = _normalize_operation_sinks(facts, source)
        result = classify(normalized)

        self.assertEqual(["ldap"], [sink["sink_kind"] for sink in normalized["sinks"]])
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(["CWE-90"], [finding["cwe"] for finding in result["findings"]])

    def test_source_backed_family_preserves_real_xss(self):
        facts = _source_backed_family_facts("html_output")
        source = "user_markup = form.data['email']\nreturn render_template_string(user_markup)"

        result = classify(_normalize_operation_sinks(facts, source))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(["CWE-79"], [finding["cwe"] for finding in result["findings"]])

    def test_source_backed_family_preserves_real_ldap_injection(self):
        facts = _source_backed_family_facts("ldap")
        source = (
            "search_filter = f\"(uid={form.data['email']})\"\n"
            "self.conn.search(search_filter=search_filter)"
        )

        result = classify(_normalize_operation_sinks(facts, source))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(["CWE-90"], [finding["cwe"] for finding in result["findings"]])

    def test_source_backed_family_preserves_independent_xss_and_ldap_sinks(self):
        facts = _source_backed_family_facts("ldap", "html_output")
        source = (
            "search_filter = f\"(uid={form.data['email']})\"\n"
            "self.conn.search(search_filter=search_filter)\n"
            "user_markup = form.data['email']\n"
            "return render_template_string(user_markup)"
        )

        result = classify(_normalize_operation_sinks(facts, source))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(
            {"CWE-79", "CWE-90"},
            {finding["cwe"] for finding in result["findings"]},
        )

    def test_composed_ldap_escape_remains_typed_at_the_caller(self):
        self.assertEqual(SANITIZED, _compose_ldap_sanitizer("ldap_escape")["verdict"])

    def test_command_sanitizers_never_discharge_ldap_or_deserialization(self):
        command_sanitizers = ("shell_quote", "argv_boundary", "command_allowlist")
        sink_families = (("ldap", "ldap_filter"), ("deserialize", "serialized_blob"))
        for sanitizer_kind in command_sanitizers:
            for sink_kind, arg_context in sink_families:
                with self.subTest(sanitizer=sanitizer_kind, sink=sink_kind):
                    result = classify(_family_facts(sink_kind, arg_context, sanitizer_kind))
                    self.assertEqual(VULNERABLE, result["verdict"])

    def test_sql_bind_parameter_context_is_intrinsically_sanitized(self):
        result = classify(_family_facts("sql_query", "sql_param"))
        self.assertEqual(SANITIZED, result["verdict"])

    def test_explicit_untrusted_param_is_seeded_outside_entrypoints(self):
        request = _abstraction_request()
        context = DriverContext(request.context.program, request.context.function, False)
        facts = FactEnvelope(
            "taint", "taint.v1", request.function.id, "ok", _facts([])
        )
        self.assertEqual(
            {"path": TAINTED},
            TaintPlugin()._seed_param_status(facts, context),
        )

    def test_prompt_pins_jira_exec_and_structured_dispatch_boundary(self):
        prompt = _system_prompt("python")
        self.assertIn("attacker-controlled Python passed to eval/exec", prompt)
        self.assertIn("shell_command with shell_command_text", prompt)
        self.assertIn("json.loads followed by getattr", prompt)
        self.assertIn("structured API dispatch, not an execution sink", prompt)
        self.assertIn("unknown_external is a SOURCE kind only", prompt)
        self.assertIn("record only the call_site in the caller", prompt)

    def test_prompt_pins_login_form_source_and_ldap_escape_boundary(self):
        prompt = _system_prompt("python")
        self.assertIn("login form fields such as form.data['email']", prompt)
        self.assertIn("escape_filter_chars", prompt)
        self.assertIn("before the value is interpolated into the LDAP filter", prompt)
        self.assertIn("emit a concrete untrusted_param source for self.username", prompt)

    def test_prompt_models_fail_open_serialized_scan_helpers_as_cwe502_boundaries(self):
        prompt = _system_prompt("python")
        self.assertIn("serialized-artifact security scan helper", prompt)
        self.assertIn("deserialize acceptance boundary", prompt)
        self.assertIn("rejecting on infection OR scan error is closed and protected", prompt)
        self.assertIn("an alternate branch that does not execute that sink is not a bypass", prompt)
        self.assertIn("generic caller-supplied callable named loader is not a deserialize sink", prompt)

    def test_source_guard_promotes_exact_closed_dominating_scan(self):
        facts = _facts([_scan_guard("conditional", "closed")])
        source = "scan_file_path(path)\nif infected or scan_err: raise Error\ntorch.load(path)"
        facts["validation_guards"][0]["expr"] = "scan_file_path(path)"
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual("must", normalized["sinks"][0]["_validation_guard_coverage"])

    def test_source_guard_uses_exact_call_expr_terminal_over_model_callee(self):
        facts = _facts([_scan_guard("must", "open")])
        facts["taint_sources"][0]["expr"] = "checkpoint"
        facts["validation_guards"][0].update(
            expr="scan_file_path(checkpoint)",
            input_expr="checkpoint",
            bypass_param="",
        )
        facts["sinks"][0].update(
            callee="torch.load",
            call_expr='torch_load(checkpoint, map_location="cpu")',
            arg_expr="checkpoint",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        source = (
            "def load_model(model_path):\n"
            "    def torch_load_file(checkpoint):\n"
            "        scan_result = scan_file_path(checkpoint)\n"
            "        if scan_result.infected_files or scan_result.scan_err:\n"
            "            raise ValueError('unsafe artifact')\n"
            "        return torch_load(checkpoint, map_location='cpu')\n"
            "    return torch_load_file(model_path)"
        )

        normalized = _normalize_operation_sinks(facts, source)

        self.assertEqual("deserialize", normalized["sinks"][0]["sink_kind"])
        self.assertEqual("closed", normalized["validation_guards"][0]["failure_mode"])
        self.assertEqual("must", normalized["sinks"][0]["_validation_guard_coverage"])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_invented_call_expr_does_not_override_mismatched_model_callee(self):
        facts = _facts([_scan_guard("must", "closed")])
        facts["taint_sources"][0]["expr"] = "checkpoint"
        facts["validation_guards"][0].update(
            expr="scan_file_path(checkpoint)",
            input_expr="checkpoint",
            bypass_param="",
        )
        facts["sinks"][0].update(
            callee="torch.load",
            call_expr="torch_load(checkpoint)",
            arg_expr="checkpoint",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        source = (
            "scan_result = scan_file_path(checkpoint)\n"
            "if scan_result.infected_files or scan_result.scan_err:\n"
            "    raise ValueError('unsafe artifact')\n"
            "torch_load_real(checkpoint)"
        )

        normalized = _normalize_operation_sinks(facts, source)

        self.assertEqual("open", normalized["validation_guards"][0]["failure_mode"])
        self.assertNotIn("_validation_guard_coverage", normalized["sinks"][0])
        self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_exact_call_expr_with_wrong_input_does_not_bind_sink(self):
        facts = _facts([_scan_guard("must", "closed")])
        facts["taint_sources"][0]["expr"] = "checkpoint"
        facts["validation_guards"][0].update(
            expr="scan_file_path(checkpoint)",
            input_expr="checkpoint",
            bypass_param="",
        )
        facts["sinks"][0].update(
            callee="torch.load",
            call_expr="torch_load(other)",
            arg_expr="checkpoint",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        source = (
            "scan_result = scan_file_path(checkpoint)\n"
            "if scan_result.infected_files or scan_result.scan_err:\n"
            "    raise ValueError('unsafe artifact')\n"
            "value = torch.load(checkpoint)\n"
            "torch_load(other)"
        )

        normalized = _normalize_operation_sinks(facts, source)

        self.assertEqual("open", normalized["validation_guards"][0]["failure_mode"])
        self.assertNotIn("_validation_guard_coverage", normalized["sinks"][0])
        self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_source_guard_closes_deserialization_after_fail_closed_scan(self):
        source = (
            "scan_result = scan_file_path(blob)\n"
            "if scan_result.unsafe_files or scan_result.scan_err:\n"
            "    raise ValueError('unsafe artifact')\n"
            "return pickle.loads(blob)"
        )

        normalized = _normalize_operation_sinks(_source_backed_scan_facts(), source)
        result = classify(normalized)

        self.assertEqual(SANITIZED, result["verdict"])
        self.assertEqual("validation_guard", result["findings"][0]["sanitized_by"])

    def test_source_guard_ignoring_scan_error_remains_vulnerable(self):
        source = (
            "scan_result = scan_file_path(blob)\n"
            "if scan_result.unsafe_files:\n"
            "    raise ValueError('unsafe artifact')\n"
            "return pickle.loads(blob)"
        )

        result = classify(_normalize_operation_sinks(_source_backed_scan_facts("high"), source))

        self.assertEqual(VULNERABLE, result["verdict"])

    def test_source_guard_with_fail_open_scan_exception_remains_vulnerable(self):
        source = (
            "try:\n"
            "    scan_result = scan_file_path(blob)\n"
            "except Exception:\n"
            "    scan_result = None\n"
            "if scan_result and (scan_result.unsafe_files or scan_result.scan_err):\n"
            "    raise ValueError('unsafe artifact')\n"
            "return pickle.loads(blob)"
        )

        result = classify(_normalize_operation_sinks(_source_backed_scan_facts("high"), source))

        self.assertEqual(VULNERABLE, result["verdict"])

    def test_source_guard_after_deserialization_remains_vulnerable(self):
        source = (
            "value = pickle.loads(blob)\n"
            "scan_result = scan_file_path(blob)\n"
            "if scan_result.unsafe_files or scan_result.scan_err:\n"
            "    raise ValueError('unsafe artifact')\n"
            "return value"
        )

        result = classify(_normalize_operation_sinks(_source_backed_scan_facts("high"), source))

        self.assertEqual(VULNERABLE, result["verdict"])

    def test_deepseek_scan_helper_without_sink_is_source_enriched(self):
        facts = _facts([])
        facts["function"] = "_scan_model"
        facts["sinks"] = []
        facts["validation_guards"] = [_scan_guard("must", "open")]
        facts["validation_guards"][0].update(
            input_expr="checkpoint",
            protects_sink_ids=[],
            bypass_param="",
        )
        facts["taint_sources"][0]["expr"] = "checkpoint"
        source = (
            "scan_result = scan_file_path(checkpoint)\n"
            "if scan_result.infected_files != 0: raise Exception()"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual(1, len(normalized["sinks"]))
        self.assertEqual("deserialize", normalized["sinks"][0]["sink_kind"])
        self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_deepseek_scan_helper_without_guard_is_source_enriched(self):
        facts = _facts([])
        facts["function"] = "_scan_model"
        facts["sinks"] = []
        facts["validation_guards"] = []
        facts["taint_sources"][0]["expr"] = "checkpoint"
        source = (
            "scan_result = scan_file_path(checkpoint)\n"
            "if scan_result.infected_files != 0: raise Exception()"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual(1, len(normalized["sinks"]))
        self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_scan_helper_replaces_hypothetical_torch_load_with_acceptance_sink(self):
        facts = _facts([_scan_guard("must", "closed")])
        facts["function"] = "_scan_model"
        facts["sinks"][0].update(
            callee="torch.load",
            call_expr="torch.load(checkpoint)",
            arg_expr="checkpoint",
            flows=[{"source": "source:S1", "sanitizers": []}],
        )
        facts["taint_sources"][0]["expr"] = "checkpoint"
        source = (
            "scan_result = scan_file_path(checkpoint)\n"
            "if scan_result.infected_files != 0 or scan_result.scan_err: raise Exception()"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual(["scan_file_path"], [sink["callee"] for sink in normalized["sinks"]])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_source_scan_error_handling_overrides_false_closed_claim(self):
        facts = _facts([_scan_guard("must", "closed")])
        source = (
            "scan_result = scan_file_path(path)\n"
            "if scan_result.infected_files != 0: raise Exception()\n"
            "torch.load(path)"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual("open", normalized["validation_guards"][0]["failure_mode"])
        self.assertEqual(
            VULNERABLE,
            classify(normalized, param_status={"path": TAINTED})["verdict"],
        )

    def test_source_scan_binding_corrects_guard_call_expression_input(self):
        facts = _facts([_scan_guard("must", "closed")])
        facts["validation_guards"][0]["input_expr"] = "torch.load(path)"
        source = (
            "scan_result = scan_file_path(path)\n"
            "if scan_result.infected_files != 0 or scan_result.scan_err: raise Exception()\n"
            "torch.load(path)"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual("path", normalized["validation_guards"][0]["input_expr"])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_source_closed_scan_without_bypass_is_mandatory(self):
        facts = _facts([_scan_guard("conditional", "closed")])
        facts["validation_guards"][0]["bypass_param"] = ""
        source = (
            "scan_result = scan_file_path(path)\n"
            "if scan_result.infected_files != 0 or scan_result.scan_err: raise Exception()\n"
            "torch.load(path)"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual("must", normalized["validation_guards"][0]["coverage"])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_source_scan_rebinds_mismatched_model_sink_ids(self):
        facts = _facts([_scan_guard("default", "closed")])
        facts["validation_guards"][0]["protects_sink_ids"] = ["K_OTHER"]
        source = (
            "scan_result = scan_file_path(path)\n"
            "if scan_result.infected_files != 0 or scan_result.scan_err: raise Exception()\n"
            "torch.load(path)"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertIn("K1", normalized["validation_guards"][0]["protects_sink_ids"])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_source_guard_drops_data_only_safetensors_deserializer_claim(self):
        facts = _family_facts("deserialize", "serialized_blob")
        facts["sinks"][0].update(
            callee="safetensors.torch.load_file",
            call_expr='safetensors.torch.load_file(path, device="cpu")',
        )
        normalized = _normalize_operation_sinks(
            facts, 'safetensors.torch.load_file(path, device="cpu")'
        )
        self.assertEqual([], normalized["sinks"])

    def test_source_guard_drops_getattr_code_eval_claim(self):
        facts = _family_facts("code_eval", "code_string")
        facts["sinks"][0].update(
            callee="getattr",
            call_expr='getattr(self.jira, params["function"])',
        )
        source = 'params = json.loads(query)\ngetattr(self.jira, params["function"])'
        self.assertEqual([], _normalize_operation_sinks(facts, source)["sinks"])

    def test_deepseek_member_expr_untrusted_source_seeds_matching_parameter(self):
        request = _abstraction_request()
        facts = FactEnvelope(
            "taint", "taint.v1", request.function.id, "ok", _facts([])
        )
        facts.payload["taint_sources"][0]["expr"] = "self.path"
        self.assertEqual(
            {"path": TAINTED},
            TaintPlugin()._seed_param_status(facts, request.context),
        )

    def test_source_backed_dotted_member_source_seeds_exact_normalized_key(self):
        source = (
            "def search(self):\n"
            "    search_filter = f'(uid={self.username})'\n"
            "    return self.conn.search(search_filter=search_filter)"
        )
        unit, context = _member_state_context(source)
        payload = _family_facts("ldap", "ldap_filter")
        payload.update(function="search", params=["self"])
        payload["taint_sources"][0].update(
            source_kind="untrusted_param",
            expr="self . username",
            confidence="high",
        )
        payload["sinks"][0].update(
            callee="self.conn.search",
            call_expr="self.conn.search(search_filter=search_filter)",
            arg_expr="search_filter",
            flows=[{"source": "param:self.username", "sanitizers": []}],
        )
        facts = FactEnvelope("taint", "taint.v1", unit.id, "ok", payload)

        self.assertEqual(
            {"self.username": TAINTED},
            TaintPlugin()._seed_param_status(facts, context),
        )
        self.assertEqual(VULNERABLE, TaintPlugin().check(facts, context).verdict)

    def test_member_sink_flow_without_untrusted_source_remains_polymorphic(self):
        source = (
            "def search(self):\n"
            "    search_filter = f'(uid={self.username})'\n"
            "    return self.conn.search(search_filter=search_filter)"
        )
        unit, context = _member_state_context(source)
        payload = _family_facts("ldap", "ldap_filter")
        payload.update(function="search", params=["self"], taint_sources=[])
        payload["sinks"][0].update(
            callee="self.conn.search",
            call_expr="self.conn.search(search_filter=search_filter)",
            arg_expr="search_filter",
            flows=[{"source": "param:self.username", "sanitizers": []}],
        )
        facts = FactEnvelope("taint", "taint.v1", unit.id, "ok", payload)

        self.assertEqual({}, TaintPlugin()._seed_param_status(facts, context))
        self.assertEqual(POLYMORPHIC, TaintPlugin().check(facts, context).verdict)

    def test_arbitrary_untrusted_member_expressions_are_not_seeded(self):
        expressions = (
            "self.username.strip()",
            "self.usernames[0]",
            "self.username + suffix",
        )
        source = (
            "def search(self, suffix):\n"
            "    self.username.strip()\n"
            "    self.usernames[0]\n"
            "    return self.username + suffix"
        )
        unit, context = _member_state_context(source)
        for expr in expressions:
            with self.subTest(expr=expr):
                payload = _facts([])
                payload.update(params=["self", "suffix"], sinks=[])
                payload["taint_sources"] = [{
                    "id": "S1",
                    "source_kind": "untrusted_param",
                    "expr": expr,
                    "confidence": "high",
                }]
                facts = FactEnvelope("taint", "taint.v1", unit.id, "ok", payload)

                self.assertEqual({}, TaintPlugin()._seed_param_status(facts, context))

    def test_deepseek_fs_path_source_kind_is_normalized_to_untrusted_param(self):
        facts = _facts([])
        facts["taint_sources"][0].update(
            source_kind="fs_path",
            expr="self.model_path",
        )
        normalized = _normalize_operation_sinks(facts, "torch.load(self.model_path)")
        self.assertEqual("untrusted_param", normalized["taint_sources"][0]["source_kind"])
        self.assertNotEqual("ERROR", classify(normalized)["verdict"])

    def test_deepseek_file_read_source_kind_is_normalized_to_file(self):
        facts = _facts([])
        facts["taint_sources"][0]["source_kind"] = "file_read"
        normalized = _normalize_operation_sinks(facts, "torch.load(path)")
        self.assertEqual("file", normalized["taint_sources"][0]["source_kind"])
        self.assertNotEqual("ERROR", classify(normalized)["verdict"])

    def test_signature_name_is_not_composed_as_a_recursive_call(self):
        caller_id = FunctionId("probe.py", "get_format_1", "get_format", "python")
        callee_id = FunctionId("probe.py", "get_format_2", "get_format", "python")
        caller_unit = FunctionUnit(caller_id, "def get_format(self):\n    return None", "def get_format(self):")
        callee_unit = FunctionUnit(callee_id, "torch.load(path)", "def get_format(path):")
        call_site = CallSite(caller_id, callee_id, "get_format", arg_bindings={"param:path": "self"})
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope("taint", "taint.v1", caller_id, "ok", _family_facts("ldap", "ldap_filter"))
        caller.payload["sinks"] = []
        callee = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        context = DriverContext(program, caller_unit, True, (), (call_site,))
        composed = TaintPlugin().compose_calls(caller, [ResolvedCall(call_site, callee)], context)
        self.assertEqual([], composed.payload["sinks"])

    def test_same_name_member_dispatch_is_not_treated_as_recursion(self):
        caller_id = FunctionId("probe.py", "get_format_1", "get_format", "python")
        callee_id = FunctionId("probe.py", "get_format_2", "get_format", "python")
        caller_unit = FunctionUnit(
            caller_id,
            "def get_format(self):\n    return self.delegate.get_format()",
            "def get_format(self):",
        )
        callee_unit = FunctionUnit(callee_id, "torch.load(path)", "def get_format(path):")
        call_site = CallSite(caller_id, callee_id, "get_format")
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope("taint", "taint.v1", caller_id, "ok", _family_facts("ldap", "ldap_filter"))
        caller.payload["sinks"] = []
        callee = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        context = DriverContext(program, caller_unit, True, (), (call_site,))
        composed = TaintPlugin().compose_calls(caller, [ResolvedCall(call_site, callee)], context)
        self.assertEqual([], composed.payload["sinks"])

    def test_comment_mention_is_not_composed_as_a_call(self):
        caller_id = FunctionId("caller.py", "inspect", "inspect", "python")
        callee_id = FunctionId("callee.py", "load", "load", "python")
        caller_unit = FunctionUnit(caller_id, "def inspect(path):\n    # load(path)\n    return path", "def inspect(path):")
        callee_unit = FunctionUnit(callee_id, "torch.load(path)", "def load(path):")
        call_site = CallSite(caller_id, callee_id, "load")
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope("taint", "taint.v1", caller_id, "ok", _family_facts("ldap", "ldap_filter"))
        caller.payload["sinks"] = []
        callee = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        context = DriverContext(program, caller_unit, True, (), (call_site,))
        composed = TaintPlugin().compose_calls(caller, [ResolvedCall(call_site, callee)], context)
        self.assertEqual([], composed.payload["sinks"])

    def test_actual_recursive_body_call_is_still_composed(self):
        caller_id = FunctionId("probe.py", "load_1", "load", "python")
        callee_id = FunctionId("probe.py", "load_2", "load", "python")
        caller_unit = FunctionUnit(caller_id, "def load(path):\n    return load(path)", "def load(path):")
        callee_unit = FunctionUnit(callee_id, "torch.load(path)", "def load(path):")
        call_site = CallSite(caller_id, callee_id, "load", arg_bindings={"param:path": "path"})
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope("taint", "taint.v1", caller_id, "ok", _family_facts("ldap", "ldap_filter"))
        caller.payload["sinks"] = []
        callee = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        context = DriverContext(program, caller_unit, True, (), (call_site,))
        composed = TaintPlugin().compose_calls(caller, [ResolvedCall(call_site, callee)], context)
        self.assertEqual(1, len(composed.payload["sinks"]))

    def test_entrypoint_param_reaching_inherited_sink_is_tainted(self):
        request = _abstraction_request()
        payload = _facts([])
        payload["taint_sources"] = []
        facts = FactEnvelope(
            "taint", "taint.v1", request.function.id, "ok", payload
        )
        self.assertEqual(
            VULNERABLE,
            TaintPlugin().check(facts, request.context).verdict,
        )

    def test_helper_sink_param_reachable_from_entrypoint_is_tainted(self):
        caller_id = FunctionId("caller.py", "probe", "probe", "python")
        callee_id = FunctionId("callee.py", "load", "load", "python")
        caller_unit = FunctionUnit(
            caller_id,
            "def probe(model_path):\n    return load(model_path)",
            "def probe(model_path):",
            ("model_path",),
        )
        callee_unit = FunctionUnit(
            callee_id,
            "def load(path):\n    return torch.load(path)",
            "def load(path):",
            ("path",),
        )
        call_site = CallSite(
            caller_id,
            callee_id,
            "load",
            arg_bindings={"param:path": "model_path"},
        )
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        facts = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        facts.payload["taint_sources"] = []
        context = DriverContext(program, callee_unit, False, (call_site,), ())
        self.assertEqual({"path": TAINTED}, TaintPlugin()._seed_param_status(facts, context))

    def test_isolated_helper_sink_param_remains_caller_dependent(self):
        request = _abstraction_request()
        context = DriverContext(request.context.program, request.function, False)
        facts = FactEnvelope("taint", "taint.v1", request.function.id, "ok", _facts([]))
        facts.payload["taint_sources"] = []
        self.assertEqual({}, TaintPlugin()._seed_param_status(facts, context))

    def test_decorated_helper_recovers_missing_call_bindings_for_entrypoint_taint(self):
        caller_id = FunctionId("caller.py", "probe", "probe", "python")
        callee_id = FunctionId("callee.py", "load", "load", "python")
        caller_unit = FunctionUnit(
            caller_id,
            "@classmethod\ndef probe(cls, model_path):\n    return load(model_path, scan=True)",
            "@classmethod",
        )
        callee_unit = FunctionUnit(
            callee_id,
            "@classmethod\ndef load(cls, path, scan=True):\n    return torch.load(path)",
            "@classmethod",
        )
        call_site = CallSite(caller_id, callee_id, "load")
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call_site], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call_site]},
            entrypoints=[caller_id],
        )
        facts = FactEnvelope("taint", "taint.v1", callee_id, "ok", _facts([]))
        facts.payload["taint_sources"] = []
        context = DriverContext(program, callee_unit, False, (call_site,), ())
        self.assertEqual({"path": TAINTED}, TaintPlugin()._seed_param_status(facts, context))

    def test_member_state_reaching_concrete_sink_is_tainted_not_review_only(self):
        request = _abstraction_request()
        context = DriverContext(request.context.program, request.function, False)
        facts = FactEnvelope("taint", "taint.v1", request.function.id, "ok", _facts([]))
        facts.payload["taint_sources"] = []
        facts.payload["sinks"][0]["flows"] = [
            {"source": "param:self", "sanitizers": []}
        ]
        self.assertEqual({"self": TAINTED}, TaintPlugin()._seed_param_status(facts, context))

    def test_deepseek_ldap_config_pseudosources_and_nonfilter_args_are_removed(self):
        facts = _family_facts("ldap", "ldap_filter", "ldap_escape")
        facts["taint_sources"].extend([
            {
                "id": "S2",
                "source_kind": "http_param",
                "expr": "config.LDAP_USERNAME_ATTRIBUTE",
                "confidence": "low",
            },
            {
                "id": "S3",
                "source_kind": "http_param",
                "expr": "config.LDAP_SEARCH_FILTER",
                "confidence": "low",
            },
        ])
        facts["sinks"][0]["arg_expr"] = "search_filter"
        facts["sinks"][0]["flows"].extend([
            {"source": "source:S2", "sanitizers": []},
            {"source": "source:S3", "sanitizers": []},
        ])
        for sink_id, arg_expr in (("K2", "search_base_dn"), ("K3", "config.LDAP_SEARCH_SCOPE")):
            sink = dict(facts["sinks"][0])
            sink.update(id=sink_id, arg_expr=arg_expr, flows=[{"source": "source:S2", "sanitizers": []}])
            facts["sinks"].append(sink)
        source = (
            "search_filter = '{}={}'.format(config.LDAP_USERNAME_ATTRIBUTE, "
            "escape_filter_chars(self.username))\n"
            "search_filter = '{}{}'.format(search_filter, config.LDAP_SEARCH_FILTER)\n"
            "self.conn.search(search_filter=search_filter, "
            "search_scope=config.LDAP_SEARCH_SCOPE)"
        )
        normalized = _normalize_operation_sinks(facts, source)
        self.assertEqual(["K1"], [sink["id"] for sink in normalized["sinks"]])
        self.assertEqual(["source:S1"], [flow["source"] for flow in normalized["sinks"][0]["flows"]])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_deepseek_env_labeled_config_pseudosources_are_removed(self):
        facts = _family_facts("ldap", "ldap_filter", "ldap_escape")
        facts["taint_sources"].extend([
            {
                "id": "S2",
                "source_kind": "env",
                "expr": "config.LDAP_USERNAME_ATTRIBUTE",
                "introduced_by": "configuration value specifying an LDAP attribute",
                "confidence": "low",
            },
            {
                "id": "S3",
                "source_kind": "env",
                "expr": "config.LDAP_SEARCH_FILTER",
                "introduced_by": "additional LDAP filter from application configuration",
                "confidence": "low",
            },
            {
                "id": "S4",
                "source_kind": "env",
                "expr": "config.LDAP_SEARCH_SCOPE",
                "introduced_by": "LDAP search scope from application configuration",
                "confidence": "low",
            },
        ])
        facts["sinks"][0].update(
            arg_expr="search_filter",
            flows=[
                {"source": "source:S1", "sanitizers": ["Z1"]},
                {"source": "source:S2", "sanitizers": []},
                {"source": "source:S3", "sanitizers": []},
                {"source": "source:S4", "sanitizers": []},
            ],
        )
        source = (
            "search_filter = '({0}={1})'.format(\n"
            "    config.LDAP_USERNAME_ATTRIBUTE, escape_filter_chars(self.username))\n"
            "if config.LDAP_SEARCH_FILTER:\n"
            "    search_filter = f'(&{search_filter}{config.LDAP_SEARCH_FILTER})'\n"
            "self.conn.search(search_filter=search_filter, "
            "search_scope=config.LDAP_SEARCH_SCOPE)"
        )

        normalized = _normalize_operation_sinks(facts, source)

        self.assertEqual(["S1"], [item["id"] for item in normalized["taint_sources"]])
        self.assertEqual(["source:S1"], [flow["source"] for flow in normalized["sinks"][0]["flows"]])
        self.assertEqual(SANITIZED, classify(normalized)["verdict"])

    def test_runtime_env_and_request_syntax_remain_tainted_regardless_of_label(self):
        runtime_sources = (
            "os.environ['LDAP_FILTER']",
            "os.getenv('LDAP_FILTER')",
            "request.args['filter']",
            "form.data['filter']",
        )
        for expr in runtime_sources:
            with self.subTest(expr=expr):
                facts = _family_facts("ldap", "ldap_filter", "ldap_escape")
                facts["taint_sources"].append({
                    "id": "S2",
                    "source_kind": "env",
                    "expr": expr,
                    "introduced_by": "runtime attacker-controlled input",
                    "confidence": "high",
                })
                facts["sinks"][0].update(
                    arg_expr="search_filter",
                    flows=[
                        {"source": "source:S1", "sanitizers": ["Z1"]},
                        {"source": "source:S2", "sanitizers": []},
                    ],
                )
                source = f"search_filter = {expr}\nself.conn.search(search_filter=search_filter)"

                normalized = _normalize_operation_sinks(facts, source)

                self.assertIn("S2", [item["id"] for item in normalized["taint_sources"]])
                self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_runtime_request_assignment_to_config_attribute_remains_tainted(self):
        facts = _family_facts("ldap", "ldap_filter", "ldap_escape")
        facts["taint_sources"].append({
            "id": "S2",
            "source_kind": "env",
            "expr": "config.RUNTIME_FILTER",
            "introduced_by": "assigned from a request parameter at runtime",
            "confidence": "high",
        })
        facts["sinks"][0].update(
            arg_expr="search_filter",
            flows=[
                {"source": "source:S1", "sanitizers": ["Z1"]},
                {"source": "source:S2", "sanitizers": []},
            ],
        )
        source = (
            "config.RUNTIME_FILTER = request.args['filter']\n"
            "search_filter = config.RUNTIME_FILTER\n"
            "self.conn.search(search_filter=search_filter)"
        )

        normalized = _normalize_operation_sinks(facts, source)

        self.assertIn("S2", [item["id"] for item in normalized["taint_sources"]])
        self.assertEqual(VULNERABLE, classify(normalized)["verdict"])

    def test_callee_summary_is_bounded_for_recursive_call_graphs(self):
        payload = _family_facts("deserialize", "serialized_blob")
        payload["sinks"] = [dict(payload["sinks"][0], id=f"K{i}") for i in range(100)]
        self.assertLessEqual(len(_summarize(payload, "recursive")), 4096)

    def test_callee_summary_preserves_validation_guard_contract(self):
        request = _abstraction_request()
        facts = FactEnvelope(
            "taint",
            "taint.v1",
            request.function.id,
            "ok",
            _facts([_scan_guard("must", "closed")]),
        )
        summary = TaintPlugin().summarize_for_caller(facts)
        self.assertIn("guard:content_scan(path)[must/closed]", summary)

    def test_render_result_uses_stock_runner_source_identity(self):
        request = _abstraction_request()
        facts = FactEnvelope(
            "taint", "taint.v1", request.function.id, "ok", _facts([])
        )
        verdict = TaintPlugin().check(facts, request.context)
        rendered = TaintPlugin().render_result(
            request.function, facts, verdict, request.context
        )
        self.assertEqual("callee.py", rendered["rel"])
        self.assertEqual("read_checkpoint_meta", rendered["function"])


if __name__ == "__main__":
    unittest.main()
