import json
import unittest

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
from src.plugins.resource import ResourcePlugin
from src.resource_reasoner import BOUNDED, SAFE, VULNERABLE, classify
from src.resource_validation import (
    RESOURCE_VALIDATION_VERSION,
    iteration_magnitudes_for_call,
    rejecting_guard_for_call,
    returned_parameter_bounds,
    source_digest,
    source_operation_line,
)


def _facts(
    *,
    op_kind="allocation",
    magnitude_kind="numeric_param",
    bounds=None,
    flow_bounds=None,
    arg_expr="count",
):
    return {
        "schema_version": "resource.v1",
        "function": "target",
        "language": "python",
        "params": [],
        "magnitude_sources": [
            {
                "id": "M1",
                "magnitude_kind": magnitude_kind,
                "expr": arg_expr,
                "introduced_by": "attacker input",
                "confidence": "high",
            }
        ],
        "bounds": bounds or [],
        "call_sites": [],
        "costly_ops": [
            {
                "id": "OP1",
                "op_kind": op_kind,
                "callee": "consume",
                "call_expr": f"consume({arg_expr})",
                "arg_position": 0,
                "arg_expr": arg_expr,
                "magnitudes": [
                    {"source": "mag:M1", "bounds": flow_bounds or []}
                ],
            }
        ],
        "notes": [],
    }


def _guard(
    *,
    bound_kind="count_limit",
    caps=("numeric_param",),
    placement="before",
    enforcement="reject",
    limit_origin="constant",
    protects=("OP1",),
):
    return {
        "id": "B1",
        "bound_kind": bound_kind,
        "expr": "if count > MAX_COUNT: raise ValueError",
        "caps": list(caps),
        "protects_op_ids": list(protects),
        "placement": placement,
        "enforcement": enforcement,
        "limit_origin": limit_origin,
        "dominates": True,
        "confidence": "high",
    }


def _request(source="consume(count)", rel="target.py", name="target", language="python"):
    function_id = FunctionId(rel, name, name, language)
    unit = FunctionUnit(function_id, source, source.splitlines()[0])
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[function_id],
    )
    return AbstractionRequest(unit, DriverContext(program, unit, True))


class ResourceBaselineCharacterizationTests(unittest.TestCase):
    def test_unbounded_attacker_count_driving_allocation_is_vulnerable(self):
        result = classify(_facts())

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-789", result["findings"][0]["cwe"])

    def test_existing_typed_dominating_bound_is_bounded(self):
        bound = {
            "id": "B1",
            "bound_kind": "count_limit",
            "caps": ["numeric_param"],
            "dominates": True,
            "confidence": "high",
        }
        result = classify(_facts(bounds=[bound], flow_bounds=["B1"]))

        self.assertEqual(BOUNDED, result["verdict"])

    def test_function_without_costly_operations_is_safe(self):
        facts = _facts()
        facts["costly_ops"] = []

        self.assertEqual(SAFE, classify(facts)["verdict"])


class ResourceValidationGuardTests(unittest.TestCase):
    def _parse(self, source, facts, language="python"):
        request = _request(source, language=language)
        parsed = ResourcePlugin().parse_abstraction_response(
            request, "[RESOURCE_JSON]" + json.dumps(facts) + "[/RESOURCE_JSON]"
        )
        self.assertIsNotNone(parsed)
        return parsed.payload

    def test_pre_sink_email_length_limit_bounds_expensive_work(self):
        bound = _guard(
            bound_kind="input_length_cap",
            caps=("input_length",),
        )
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="email",
        )

        result = classify(facts)

        self.assertEqual(BOUNDED, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_post_hoc_length_check_does_not_bound_expensive_work(self):
        bound = _guard(
            bound_kind="input_length_cap",
            caps=("input_length",),
            placement="after",
        )
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="client_secret",
        )

        self.assertEqual(VULNERABLE, classify(facts)["verdict"])

    def test_attacker_controlled_nominal_limit_does_not_bound_work(self):
        bound = _guard(limit_origin="attacker_controlled")
        facts = _facts(bounds=[bound], flow_bounds=["B1"])

        self.assertEqual(VULNERABLE, classify(facts)["verdict"])

    def test_bound_for_a_different_operation_does_not_discharge_allocation(self):
        bound = _guard(protects=("OP2",))
        facts = _facts(bounds=[bound], flow_bounds=["B1"])

        self.assertEqual(VULNERABLE, classify(facts)["verdict"])

    def test_type_predicate_does_not_bound_regex_compilation(self):
        bound = _guard(
            bound_kind="size_check",
            caps=("input_length",),
        )
        bound["expr"] = "isinstance(entry, str)"
        facts = _facts(
            op_kind="regex_compile",
            magnitude_kind="input_length",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="entry",
        )

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-770", result["findings"][0]["cwe"])

    def test_concrete_source_kind_overrides_inconsistent_flow_hint(self):
        bound = _guard(
            bound_kind="input_length_cap",
            caps=("input_length",),
        )
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="email",
        )
        facts["costly_ops"][0]["magnitudes"][0]["magnitude_kind"] = "numeric_param"

        self.assertEqual(BOUNDED, classify(facts)["verdict"])

    def test_unproven_flow_kind_does_not_refine_unknown_concrete_source(self):
        bound = _guard(
            bound_kind="input_length_cap",
            caps=("input_length",),
        )
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="unknown_external",
            bounds=[bound], flow_bounds=["B1"], arg_expr="credential",
        )
        facts["costly_ops"][0]["magnitudes"][0]["magnitude_kind"] = "input_length"

        self.assertEqual(VULNERABLE, classify(facts)["verdict"])

    def test_warning_only_nominal_limit_does_not_bound_logical_allocation(self):
        bound = _guard(
            bound_kind="arithmetic_limit",
            caps=("logical_size",),
            enforcement="warning",
            limit_origin="type_limit",
        )
        facts = _facts(
            op_kind="logical_allocation",
            magnitude_kind="logical_size",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="storage_slot + n_slots",
        )

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-789", result["findings"][0]["cwe"])

    def test_trusted_pre_operation_storage_arithmetic_check_is_bounded(self):
        bound = _guard(
            bound_kind="arithmetic_limit",
            caps=("logical_size",),
            limit_origin="type_limit",
        )
        facts = _facts(
            op_kind="logical_allocation",
            magnitude_kind="logical_size",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="self._slot + n",
        )

        self.assertEqual(BOUNDED, classify(facts)["verdict"])

    def test_unbounded_acl_count_driving_repeated_regex_compilation_is_vulnerable(self):
        facts = _facts(
            op_kind="regex_compile",
            magnitude_kind="element_count",
            arg_expr="acl_entries",
        )

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-770", result["findings"][0]["cwe"])

    def test_cached_precompiled_acl_evaluator_has_no_per_request_compile_op(self):
        facts = _facts()
        facts["costly_ops"] = []
        facts["notes"] = ["ACL evaluator is cached and regexes are precompiled"]

        self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_source_recovers_omitted_hard_pre_sink_length_bound(self):
        source = """def target(email):
    if not (0 < len(email) <= MAX_LENGTH):
        return None
    return send_message(email)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="email",
        )
        facts["costly_ops"][0].update(
            callee="send_message", call_expr="send_message(email)"
        )

        self.assertEqual(BOUNDED, classify(self._parse(source, facts))["verdict"])

    def test_parameter_flow_inherits_kind_from_length_source(self):
        source = """def target(client_secret):
    return (
        0 < len(client_secret) <= 255
        and CLIENT_SECRET_REGEX.match(client_secret) is not None
    )
"""
        bound = _guard(
            bound_kind="input_length_cap",
            caps=("input_length",),
        )
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            bounds=[bound],
            flow_bounds=["B1"],
            arg_expr="client_secret",
        )
        facts["params"] = ["client_secret"]
        facts["magnitude_sources"][0]["expr"] = "len(client_secret)"
        facts["costly_ops"][0].update(
            callee="CLIENT_SECRET_REGEX.match",
            call_expr="CLIENT_SECRET_REGEX.match(client_secret)",
            magnitudes=[{"source": "param:client_secret", "bounds": ["B1"]}],
        )

        parsed = self._parse(source, facts)

        self.assertEqual("input_length", parsed["costly_ops"][0]["magnitudes"][0]["magnitude_kind"])
        self.assertEqual(BOUNDED, classify(parsed)["verdict"])

    def test_model_operation_with_nonexistent_call_expression_is_rejected(self):
        source = """def target(email, next_link):
    return service.send(email, nextLink)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="next_link",
        )
        facts["costly_ops"][0].update(
            callee="service.send",
            call_expr="service.send(email, next_link)",
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_structurally_matching_multiline_call_is_retained(self):
        source = """def target(email):
    return service.send(
        email,
    )
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="email",
        )
        facts["costly_ops"][0].update(
            callee="service.send", call_expr="service.send(email)"
        )

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_model_invented_alias_does_not_create_a_magnitude_flow(self):
        source = """def target(args):
    substitutions = {key: value for key, value in args.items()}
    return Header(template % substitutions)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="substitutions",
        )
        facts["magnitude_sources"][0]["expr"] = "args"
        facts["costly_ops"][0].update(
            callee="Header", call_expr="Header(template % substitutions)"
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_prose_magnitude_expression_does_not_create_a_flow(self):
        source = """def target(args):
    substitutions = {}
    for key, value in args.items():
        substitutions[key] = value
    return send_message(substitutions)
"""
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="unknown_external",
            arg_expr="substitutions",
        )
        facts["magnitude_sources"][0]["expr"] = (
            "substitutions dictionary (built from args)"
        )
        facts["costly_ops"][0].update(
            callee="send_message",
            call_expr="send_message(substitutions)",
        )

        parsed = self._parse(source, facts)

        self.assertEqual([], parsed["magnitude_sources"])
        self.assertEqual(SAFE, classify(parsed)["verdict"])

    def test_grounded_prose_input_length_recovers_source_provenance(self):
        source = """def target(request):
    values = extract_values(request)
    destination = values['destination']
    return deliver(destination)
"""
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            arg_expr="destination",
        )
        facts["magnitude_sources"][0]["expr"] = (
            "destination (from values['destination'])"
        )
        facts["costly_ops"][0].update(
            callee="deliver", call_expr="deliver(destination)"
        )

        parsed = self._parse(source, facts)
        result = classify(parsed)

        self.assertEqual("values['destination']", parsed["magnitude_sources"][0]["expr"])
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_grounded_prose_count_is_normalized_but_ungrounded_prose_is_rejected(self):
        source = """def target(payload):
    entries = payload['entries']
    return list(entries)
"""
        facts = _facts(
            op_kind="collection_build",
            magnitude_kind="element_count",
            arg_expr="entries",
        )
        facts["magnitude_sources"] = [
            {
                "id": "M1", "magnitude_kind": "element_count",
                "expr": "len(entries) (derived from payload['entries'])",
                "introduced_by": "source-controlled collection", "confidence": "high",
            },
            {
                "id": "M2", "magnitude_kind": "element_count",
                "expr": "len(invented) (derived from missing['entries'])",
                "introduced_by": "claimed collection", "confidence": "high",
            },
        ]
        facts["costly_ops"][0].update(
            callee="list", call_expr="list(entries)",
            magnitudes=[
                {"source": "mag:M1", "bounds": []},
                {"source": "mag:M2", "bounds": []},
            ],
        )

        parsed = self._parse(source, facts)

        self.assertEqual(["M1"], [item["id"] for item in parsed["magnitude_sources"]])
        self.assertEqual("len(entries)", parsed["magnitude_sources"][0]["expr"])
        self.assertEqual(["mag:M1"], [
            flow["source"] for flow in parsed["costly_ops"][0]["magnitudes"]
        ])
        self.assertEqual(VULNERABLE, classify(parsed)["verdict"])

    def test_expensive_argument_requires_source_provenance_and_exact_bound_scope(self):
        source = """def target(request):
    values = extract_values(request, ('primary', 'attempt'))
    primary = values['primary']
    attempt = values['attempt']
    if not 0 < len(primary) <= MAX_LENGTH:
        return None
    optional = None
    return process(primary, attempt, optional)
"""
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            arg_expr="primary",
        )
        facts["magnitude_sources"] = [
            {
                "id": "M1", "magnitude_kind": "input_length",
                "expr": "values['primary']", "introduced_by": "request value",
                "confidence": "high",
            },
            {
                "id": "M2", "magnitude_kind": "input_length",
                "expr": "values['attempt']", "introduced_by": "numeric string parameter",
                "confidence": "medium",
            },
            {
                "id": "M3", "magnitude_kind": "unknown_external",
                "expr": "values.get('optional')", "introduced_by": "claimed optional input",
                "confidence": "high",
            },
        ]
        facts["costly_ops"] = [
            {
                "id": "OP1", "op_kind": "expensive_call", "callee": "process",
                "call_expr": "process(primary, attempt, optional)", "arg_position": 0,
                "arg_expr": "primary", "magnitudes": [{"source": "mag:M1", "bounds": []}],
            },
            {
                "id": "OP2", "op_kind": "expensive_call", "callee": "process",
                "call_expr": "process(primary, attempt, optional)", "arg_position": 1,
                "arg_expr": "attempt", "magnitudes": [{"source": "mag:M2", "bounds": []}],
            },
            {
                "id": "OP3", "op_kind": "expensive_call", "callee": "process",
                "call_expr": "process(primary, attempt, optional)", "arg_position": 2,
                "arg_expr": "optional", "magnitudes": [{"source": "mag:M3", "bounds": []}],
            },
        ]

        parsed = self._parse(source, facts)
        result = classify(parsed)
        operations = {op["id"]: op for op in parsed["costly_ops"]}

        self.assertEqual(["M1", "M2"], [item["id"] for item in parsed["magnitude_sources"]])
        self.assertTrue(operations["OP1"]["magnitudes"])
        self.assertEqual([], operations["OP2"]["magnitudes"])
        self.assertEqual([], operations["OP3"]["magnitudes"])
        self.assertTrue(operations["OP1"]["magnitudes"][0]["bounds"])
        self.assertEqual(BOUNDED, result["verdict"])

    def test_simple_source_assignment_preserves_a_magnitude_flow(self):
        source = """def target(args):
    count = args['count']
    return bytes(count)
"""
        facts = _facts(arg_expr="count")
        facts["magnitude_sources"][0]["expr"] = "args['count']"
        facts["costly_ops"][0].update(callee="bytes", call_expr="bytes(count)")

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_source_recovers_omitted_email_recipient_flow(self):
        source = """def target(args):
    address = args['address']
    return sendEmail(config, template, address, {})
"""
        facts = _facts(
            op_kind="expensive_call",
            magnitude_kind="input_length",
            arg_expr="address",
        )
        facts["magnitude_sources"][0]["expr"] = "args['address']"
        facts["costly_ops"][0].update(
            callee="sendEmail",
            call_expr="sendEmail(config, template, address, {})",
            arg_position=3,
            arg_expr="{}",
            magnitudes=[],
        )

        result = classify(self._parse(source, facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_source_derives_omitted_delivery_operation_from_call_site(self):
        source = """def target(request):
    args = get_args(request, ('address',))
    address = args['address']
    sendEmail(service, template, address, {})
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="address",
        )
        facts["magnitude_sources"][0]["expr"] = "len(address)"
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "sendEmail",
            "call_expr": "sendEmail(service, template, address, {})",
            "args": [{
                "position": 2, "param_name": "address", "expr": "address",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]

        parsed = self._parse(source, facts)
        result = classify(parsed)

        self.assertEqual(1, len(parsed["costly_ops"]))
        self.assertEqual("address", parsed["costly_ops"][0]["arg_expr"])
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_request_extraction_derives_recipient_without_model_magnitudes(self):
        source = """def target(inbound_request):
    fields = decode_fields(inbound_request, ('destination', 'template'))
    recipient_alias = fields['destination']
    dispatch_message(fields['template'], recipient=recipient_alias)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="recipient_alias",
        )
        facts["params"] = ["inbound_request"]
        facts["magnitude_sources"] = []
        facts["call_sites"] = []
        facts["costly_ops"] = []

        parsed = self._parse(source, facts)
        result = classify(parsed)

        self.assertEqual(1, len(parsed["magnitude_sources"]))
        self.assertEqual("input_length", parsed["magnitude_sources"][0]["magnitude_kind"])
        self.assertEqual("recipient_alias", parsed["costly_ops"][0]["arg_expr"])
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_request_extracted_recipient_inherits_source_length_rejection(self):
        source = """def target(request_payload):
    fields = parse_input(request_payload, ('address',))
    address = fields['address']
    if not (0 < len(address) <= MAX_ADDRESS_LENGTH):
        return None
    send_message(address)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="address",
        )
        facts["params"] = ["request_payload"]
        facts["magnitude_sources"] = []
        facts["call_sites"] = []
        facts["costly_ops"] = []

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["costly_ops"][0]["magnitudes"][0]["bounds"])
        self.assertEqual(BOUNDED, classify(parsed)["verdict"])

    def test_static_recipient_source_is_not_assumed_attacker_controlled(self):
        source = """def target(settings):
    fields = read_settings(settings, ('destination',))
    destination = fields['destination']
    dispatch_message(destination)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="destination",
        )
        facts["params"] = ["settings"]
        facts["magnitude_sources"] = []
        facts["call_sites"] = []
        facts["costly_ops"] = []

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_undeclared_request_field_is_not_accepted_as_extracted(self):
        source = """def target(request):
    fields = extract_fields(request, ('subject',))
    destination = fields['destination']
    dispatch_message(destination)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="destination",
        )
        facts["params"] = ["request"]
        facts["magnitude_sources"] = []
        facts["call_sites"] = []
        facts["costly_ops"] = []

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_source_derived_delivery_operation_inherits_length_guard(self):
        source = """def target(request):
    args = get_args(request, ('destination',))
    destination = args['destination']
    if not (0 < len(destination) <= MAX_ADDRESS_LENGTH):
        return None
    dispatch_message(template, destination)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="destination",
        )
        facts["magnitude_sources"][0]["expr"] = "len(destination)"
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "dispatch_message",
            "call_expr": "dispatch_message(template, destination)",
            "args": [{
                "position": 1, "param_name": "recipient", "expr": "destination",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["costly_ops"][0]["magnitudes"][0]["bounds"])
        self.assertEqual(BOUNDED, classify(parsed)["verdict"])

    def test_email_domain_non_recipient_model_cost_does_not_bypass_recipient_bound(self):
        source = """def target(request):
    args = get_args(request, ('email', 'send_attempt'))
    email = args['email']
    send_attempt = args['send_attempt']
    if not (0 < len(email) <= MAX_ADDRESS_LENGTH):
        return None
    service.email.request_token(email, send_attempt)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="element_count",
            arg_expr="send_attempt",
        )
        facts["magnitude_sources"] = [
            {
                "id": "M_EMAIL", "magnitude_kind": "input_length",
                "expr": "args['email']", "introduced_by": "request argument",
                "confidence": "high",
            },
            {
                "id": "M_ATTEMPT", "magnitude_kind": "element_count",
                "expr": "args['send_attempt']", "introduced_by": "request argument",
                "confidence": "high",
            },
        ]
        facts["costly_ops"][0].update(
            id="OP_ATTEMPT", callee="service.email.request_token",
            call_expr="service.email.request_token(email, send_attempt)",
            arg_position=1, arg_expr="send_attempt",
            magnitudes=[{"source": "mag:M_ATTEMPT", "bounds": []}],
        )
        facts["call_sites"] = [{
            "id": "C1", "callee": "service.email.request_token",
            "call_expr": "service.email.request_token(email, send_attempt)",
            "args": [{
                "position": 0, "param_name": "email", "expr": "email",
                "magnitudes": [{"source": "mag:M_EMAIL", "bounds": []}],
            }, {
                "position": 1, "param_name": "attempt", "expr": "send_attempt",
                "magnitudes": [{"source": "mag:M_ATTEMPT", "bounds": []}],
            }],
        }]

        parsed = self._parse(source, facts)

        self.assertEqual(["email"], [op["arg_expr"] for op in parsed["costly_ops"]])
        self.assertTrue(parsed["costly_ops"][0]["magnitudes"][0]["bounds"])
        self.assertEqual(BOUNDED, classify(parsed)["verdict"])

    def test_unbounded_email_domain_recipient_remains_cwe400(self):
        source = """def target(request):
    args = get_args(request, ('email', 'send_attempt'))
    email = args['email']
    send_attempt = args['send_attempt']
    service.email.request_token(email, send_attempt)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="element_count",
            arg_expr="send_attempt",
        )
        facts["magnitude_sources"] = [{
            "id": "M_EMAIL", "magnitude_kind": "input_length",
            "expr": "args['email']", "introduced_by": "request argument",
            "confidence": "high",
        }]
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "service.email.request_token",
            "call_expr": "service.email.request_token(email, send_attempt)",
            "args": [{
                "position": 0, "param_name": "email", "expr": "email",
                "magnitudes": [{"source": "mag:M_EMAIL", "bounds": []}],
            }],
        }]

        result = classify(self._parse(source, facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-400", result["findings"][0]["cwe"])

    def test_warning_only_recipient_length_check_is_not_a_bound(self):
        source = """def target(request):
    args = get_args(request, ('email',))
    email = args['email']
    if not (0 < len(email) <= MAX_ADDRESS_LENGTH):
        warnings.warn('long recipient')
    service.email.request_token(email)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="email",
        )
        facts["magnitude_sources"][0]["expr"] = "args['email']"
        facts["costly_ops"] = []

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_post_hoc_recipient_length_rejection_is_not_a_bound(self):
        source = """def target(request):
    args = get_args(request, ('email',))
    email = args['email']
    service.email.request_token(email)
    if not (0 < len(email) <= MAX_ADDRESS_LENGTH):
        return None
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="email",
        )
        facts["magnitude_sources"][0]["expr"] = "args['email']"
        facts["costly_ops"] = []

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_non_delivery_call_does_not_gain_recipient_operation(self):
        source = """def target(request):
    args = get_args(request, ('destination',))
    destination = args['destination']
    store_profile(destination)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="destination",
        )
        facts["magnitude_sources"][0]["expr"] = "len(destination)"
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "store_profile",
            "call_expr": "store_profile(destination)",
            "args": [{
                "position": 0, "param_name": "destination", "expr": "destination",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_email_named_validation_call_is_not_delivery_work(self):
        source = """def target(request):
    args = get_args(request, ('address',))
    address = args['address']
    return validate_email(address)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="address",
        )
        facts["magnitude_sources"][0]["expr"] = "len(address)"
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "validate_email",
            "call_expr": "validate_email(address)",
            "args": [{
                "position": 0, "param_name": "email_address", "expr": "address",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_invented_delivery_call_site_does_not_create_operation(self):
        source = """def target(request):
    args = get_args(request, ('address',))
    address = args['address']
    return address
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="address",
        )
        facts["magnitude_sources"][0]["expr"] = "len(address)"
        facts["costly_ops"] = []
        facts["call_sites"] = [{
            "id": "C1", "callee": "send_message",
            "call_expr": "send_message(address)",
            "args": [{
                "position": 0, "param_name": "recipient", "expr": "address",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_scalar_string_conversion_is_not_an_amplifying_resource_op(self):
        source = "def target(value):\n    return int(value)\n"
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="value",
        )
        facts["costly_ops"][0].update(callee="int", call_expr="int(value)")

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_repeated_callee_calls_use_their_matching_argument_facts(self):
        caller_id = FunctionId("caller.py", "target", "target", "python")
        callee_id = FunctionId("callee.py", "consume", "consume", "python")
        caller = FunctionUnit(caller_id, "def target(count):\n    consume(1)\n    consume(count)", "def target(count):")
        callee = FunctionUnit(callee_id, "def consume(n):\n    return bytes(n)", "def consume(n):", ("n",))
        first = CallSite(caller_id, callee_id, "consume", 0, {"param:n": "1"})
        second = CallSite(caller_id, callee_id, "consume", 1, {"param:n": "count"})
        program = ProgramIndex(
            functions={caller_id: caller, callee_id: callee},
            calls_by_caller={caller_id: [first, second], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [first, second]},
            entrypoints=[caller_id],
        )
        caller_payload = _facts(arg_expr="count")
        caller_payload["costly_ops"] = []
        caller_payload["call_sites"] = [
            {"id": "C1", "callee": "consume", "args": [{"param_name": "n", "expr": "1", "magnitudes": []}]},
            {"id": "C2", "callee": "consume", "args": [{"param_name": "n", "expr": "count", "magnitudes": [{"source": "mag:M1", "bounds": []}]}]},
        ]
        callee_payload = _facts(arg_expr="n")
        callee_payload["params"] = ["n"]
        callee_payload["magnitude_sources"] = []
        callee_payload["costly_ops"][0].update(
            callee="bytes", call_expr="bytes(n)",
            magnitudes=[{"source": "param:n", "bounds": []}],
        )
        caller_facts = FactEnvelope("resource", "resource.v1", caller_id, "ok", caller_payload)
        callee_facts = FactEnvelope("resource", "resource.v1", callee_id, "ok", callee_payload)

        composed = ResourcePlugin().compose_calls(
            caller_facts,
            [ResolvedCall(first, callee_facts), ResolvedCall(second, callee_facts)],
            DriverContext(program, caller, True),
        )

        self.assertEqual(VULNERABLE, classify(composed.payload)["verdict"])
        self.assertIn("C2::OP1", [op["id"] for op in composed.payload["costly_ops"]])

    def test_literal_fallback_argument_does_not_become_attacker_controlled(self):
        caller_id = FunctionId("caller.py", "target", "target", "python")
        callee_id = FunctionId("callee.py", "consume", "consume", "python")
        caller = FunctionUnit(caller_id, "def target():\n    return consume(128)", "def target():")
        callee = FunctionUnit(callee_id, "def consume(n):\n    return bytes(n)", "def consume(n):", ("n",))
        call = CallSite(caller_id, callee_id, "consume", 0, {"param:n": "128"})
        program = ProgramIndex(
            functions={caller_id: caller, callee_id: callee},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller_payload = _facts()
        caller_payload["magnitude_sources"] = []
        caller_payload["costly_ops"] = []
        caller_payload["call_sites"] = []
        callee_payload = _facts(arg_expr="n")
        callee_payload["params"] = ["n"]
        callee_payload["magnitude_sources"] = []
        callee_payload["costly_ops"][0].update(
            callee="bytes",
            call_expr="bytes(n)",
            magnitudes=[{"source": "param:n", "bounds": []}],
        )

        composed = ResourcePlugin().compose_calls(
            FactEnvelope("resource", "resource.v1", caller_id, "ok", caller_payload),
            [ResolvedCall(call, FactEnvelope("resource", "resource.v1", callee_id, "ok", callee_payload))],
            DriverContext(program, caller, True),
        )

        self.assertEqual(SAFE, classify(composed.payload)["verdict"])

    def test_composed_call_in_loop_inherits_collection_count(self):
        caller_id = FunctionId("caller.py", "target", "target", "python")
        callee_id = FunctionId("callee.py", "matches", "matches", "python")
        caller_source = """def target(entries, value):
    for entry in entries:
        if matches(value, entry):
            return True
    return False
"""
        callee_source = """def matches(value, entry):
    regex = compile(entry)
    return regex.match(value)
"""
        caller = FunctionUnit(caller_id, caller_source, "def target(entries, value):", ("entries", "value"))
        callee = FunctionUnit(callee_id, callee_source, "def matches(value, entry):", ("value", "entry"))
        call = CallSite(
            caller_id,
            callee_id,
            "matches",
            0,
            {"param:value": "value", "param:entry": "entry"},
        )
        program = ProgramIndex(
            functions={caller_id: caller, callee_id: callee},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller_payload = _facts(magnitude_kind="element_count", arg_expr="entries")
        caller_payload["params"] = ["entries", "value"]
        caller_payload["magnitude_sources"][0]["expr"] = "len(entries)"
        caller_payload["costly_ops"] = []
        caller_payload["call_sites"] = [{
            "id": "C1",
            "callee": "matches",
            "call_expr": "matches(value, entry)",
            "args": [
                {"param_name": "value", "expr": "value", "magnitudes": []},
                {"param_name": "entry", "expr": "entry", "magnitudes": []},
            ],
        }]
        callee_payload = _facts(op_kind="regex_compile", arg_expr="entry")
        callee_payload["params"] = ["value", "entry"]
        callee_payload["magnitude_sources"] = []
        callee_payload["costly_ops"][0].update(
            callee="compile",
            call_expr="compile(entry)",
            magnitudes=[{"source": "param:entry", "bounds": []}],
        )
        caller_facts = FactEnvelope("resource", "resource.v1", caller_id, "ok", caller_payload)
        callee_facts = FactEnvelope("resource", "resource.v1", callee_id, "ok", callee_payload)

        composed = ResourcePlugin().compose_calls(
            caller_facts,
            [ResolvedCall(call, callee_facts)],
            DriverContext(program, caller, True),
        )
        result = classify(composed.payload)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("CWE-770", {finding["cwe"] for finding in result["findings"]})

    def test_loop_count_matches_source_expression_behind_iterable_alias(self):
        source = """def target(event, value):
    entries = event.content.get('entries', [])
    for entry in entries:
        if matches(value, entry):
            return True
    return False
"""
        facts = _facts(magnitude_kind="element_count", arg_expr="entries")
        facts["magnitude_sources"][0]["expr"] = (
            'len(event.content.get("entries", []))'
        )

        flows = iteration_magnitudes_for_call(facts, source, "matches", 0)

        self.assertEqual("mag:M1", flows[0]["source"])
        self.assertEqual("element_count", flows[0]["magnitude_kind"])

    def test_nested_caller_preserves_two_reset_loop_work_magnitudes(self):
        outer_id = FunctionId("outer.py", "route", "route", "python")
        loop_id = FunctionId("loop.py", "evaluate", "evaluate", "python")
        leaf_id = FunctionId("leaf.py", "match_rule", "match_rule", "python")
        outer = FunctionUnit(
            outer_id,
            "def route(policy, value):\n    return evaluate(policy, value)",
            "def route(policy, value):",
            ("policy", "value"),
        )
        loop_source = """def evaluate(policy, value):
    blocked = policy.get('blocked', [])
    if not isinstance(blocked, (list, tuple)):
        blocked = []
    for rule in blocked:
        if match_rule(value, rule):
            return False
    permitted = policy.get('permitted', [])
    if not isinstance(permitted, (list, tuple)):
        permitted = []
    for rule in permitted:
        if match_rule(value, rule):
            return True
    return False
"""
        loop = FunctionUnit(
            loop_id, loop_source, "def evaluate(policy, value):", ("policy", "value")
        )
        leaf = FunctionUnit(
            leaf_id,
            "def match_rule(value, rule):\n    return compile(rule).match(value)",
            "def match_rule(value, rule):",
            ("value", "rule"),
        )
        outer_call = CallSite(
            outer_id, loop_id, "evaluate", 0,
            {"param:policy": "policy", "param:value": "value"},
        )
        blocked_call = CallSite(
            loop_id, leaf_id, "match_rule", 0,
            {"param:value": "value", "param:rule": "rule"},
        )
        permitted_call = CallSite(
            loop_id, leaf_id, "match_rule", 1,
            {"param:value": "value", "param:rule": "rule"},
        )
        program = ProgramIndex(
            functions={outer_id: outer, loop_id: loop, leaf_id: leaf},
            calls_by_caller={
                outer_id: [outer_call], loop_id: [blocked_call, permitted_call], leaf_id: [],
            },
            callers_by_callee={
                outer_id: [], loop_id: [outer_call], leaf_id: [blocked_call, permitted_call],
            },
            entrypoints=[outer_id],
        )
        loop_payload = _facts(magnitude_kind="element_count", arg_expr="blocked")
        loop_payload["params"] = ["policy", "value"]
        loop_payload["magnitude_sources"] = [
            {
                "id": "M1", "magnitude_kind": "element_count", "expr": "len(blocked)",
                "introduced_by": "source-controlled collection", "confidence": "high",
            },
            {
                "id": "M2", "magnitude_kind": "element_count", "expr": "len(permitted)",
                "introduced_by": "source-controlled collection", "confidence": "high",
            },
        ]
        loop_payload["costly_ops"] = []
        loop_payload["call_sites"] = [
            {
                "id": "C1", "callee": "match_rule", "call_expr": "match_rule(value, rule)",
                "args": [
                    {"param_name": "value", "expr": "value", "magnitudes": []},
                    {"param_name": "rule", "expr": "rule", "magnitudes": []},
                ],
            },
            {
                "id": "C2", "callee": "match_rule", "call_expr": "match_rule(value, rule)",
                "args": [
                    {"param_name": "value", "expr": "value", "magnitudes": []},
                    {"param_name": "rule", "expr": "rule", "magnitudes": []},
                ],
            },
        ]
        leaf_payload = _facts(op_kind="regex_compile", arg_expr="rule")
        leaf_payload["params"] = ["value", "rule"]
        leaf_payload["magnitude_sources"] = []
        leaf_payload["costly_ops"][0].update(
            callee="compile", call_expr="compile(rule)",
            magnitudes=[{"source": "param:rule", "bounds": []}],
        )
        loop_facts = ResourcePlugin().compose_calls(
            FactEnvelope("resource", "resource.v1", loop_id, "ok", loop_payload),
            [
                ResolvedCall(
                    blocked_call,
                    FactEnvelope("resource", "resource.v1", leaf_id, "ok", leaf_payload),
                ),
                ResolvedCall(
                    permitted_call,
                    FactEnvelope("resource", "resource.v1", leaf_id, "ok", leaf_payload),
                ),
            ],
            DriverContext(program, loop, False),
        )
        loop_result = classify(loop_facts.payload)
        outer_payload = _facts()
        outer_payload["params"] = ["policy", "value"]
        outer_payload["magnitude_sources"] = []
        outer_payload["costly_ops"] = []
        outer_payload["call_sites"] = [{
            "id": "C1", "callee": "evaluate", "call_expr": "evaluate(policy, value)",
            "args": [
                {"param_name": "policy", "expr": "policy", "magnitudes": []},
                {"param_name": "value", "expr": "value", "magnitudes": []},
            ],
        }]
        outer_facts = ResourcePlugin().compose_calls(
            FactEnvelope("resource", "resource.v1", outer_id, "ok", outer_payload),
            [ResolvedCall(outer_call, loop_facts)],
            DriverContext(program, outer, True),
        )
        outer_result = classify(outer_facts.payload)

        self.assertEqual(VULNERABLE, loop_result["verdict"])
        self.assertEqual(
            {"mag:M1", "mag:M2"},
            {
                flow["source"]
                for op in loop_facts.payload["costly_ops"]
                for flow in op["magnitudes"]
            },
        )
        self.assertEqual(VULNERABLE, outer_result["verdict"])
        self.assertIn("CWE-770", {finding["cwe"] for finding in outer_result["findings"]})

    def test_rejecting_validator_propagates_proven_bound_to_later_exact_argument(self):
        caller_id = FunctionId("caller.py", "target", "target", "python")
        validator_id = FunctionId("validator.py", "validate_value", "validate_value", "python")
        caller_source = """def target(value):
    if not validate_value(value):
        return None
    return consume(value)
"""
        validator_source = """def validate_value(value):
    return 0 < len(value) <= 255 and PATTERN.match(value) is not None
"""
        caller = FunctionUnit(caller_id, caller_source, "def target(value):", ("value",))
        validator = FunctionUnit(
            validator_id, validator_source, "def validate_value(value):", ("value",)
        )
        call = CallSite(
            caller_id, validator_id, "validate_value", 0, {"param:value": "value"}
        )
        program = ProgramIndex(
            functions={caller_id: caller, validator_id: validator},
            calls_by_caller={caller_id: [call], validator_id: []},
            callers_by_callee={caller_id: [], validator_id: [call]},
            entrypoints=[caller_id],
        )
        caller_payload = _facts(
            op_kind="expensive_call", magnitude_kind="input_length", arg_expr="value"
        )
        caller_payload["params"] = ["value"]
        caller_payload["magnitude_sources"][0]["magnitude_kind"] = "unknown_external"
        caller_payload["call_sites"] = [{
            "id": "C1", "callee": "validate_value",
            "call_expr": "validate_value(value)",
            "args": [{
                "param_name": "value", "expr": "value",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]
        caller_payload["costly_ops"][0].update(
            callee="consume", call_expr="consume(value)"
        )
        validator_payload = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            bounds=[_guard(
                bound_kind="input_length_cap", caps=("input_length",)
            )],
            flow_bounds=["B1"], arg_expr="value",
        )
        validator_payload["params"] = ["value"]
        validator_payload["magnitude_sources"][0]["expr"] = "len(value)"
        validator_payload["costly_ops"][0].update(
            callee="PATTERN.match", call_expr="PATTERN.match(value)",
            magnitudes=[{"source": "param:value", "bounds": ["B1"]}],
        )

        composed = ResourcePlugin().compose_calls(
            FactEnvelope("resource", "resource.v1", caller_id, "ok", caller_payload),
            [ResolvedCall(
                call,
                FactEnvelope(
                    "resource", "resource.v1", validator_id, "ok", validator_payload
                ),
            )],
            DriverContext(program, caller, True),
        )
        result = classify(composed.payload)
        local = next(op for op in composed.payload["costly_ops"] if op["id"] == "OP1")

        self.assertTrue(local["magnitudes"][0]["bounds"])
        self.assertEqual(
            "input_length", composed.payload["magnitude_sources"][0]["magnitude_kind"]
        )
        self.assertEqual(BOUNDED, result["verdict"])

    def test_validator_return_must_establish_parameter_bound(self):
        self.assertEqual(
            {"value"},
            returned_parameter_bounds(
                "def validate(value):\n    return 0 < len(value) <= 255\n",
                {"value"},
            ),
        )
        self.assertEqual(
            set(),
            returned_parameter_bounds(
                "def validate(value):\n"
                "    if len(value) <= 255:\n"
                "        inspect(value)\n"
                "    return True\n",
                {"value"},
            ),
        )
        self.assertEqual(
            set(),
            returned_parameter_bounds(
                "def validate(value, bypass):\n"
                "    return len(value) <= 255 or bypass\n",
                {"value"},
            ),
        )

    def test_operation_line_lookup_is_occurrence_aware(self):
        source = """def target(value):
    consume(value)
    if ready(value):
        consume(value)
"""

        self.assertEqual(2, source_operation_line(source, "consume(value)", 0))
        self.assertEqual(4, source_operation_line(source, "consume(value)", 1))

    def test_partially_rejecting_validator_guard_is_not_propagated(self):
        source = """def target(value, bypass):
    if not validate(value):
        if not bypass:
            return None
    return consume(value)
"""

        self.assertIsNone(rejecting_guard_for_call(source, "validate", 0))

    def test_cached_lookup_does_not_replay_precompiled_regex_work(self):
        source = """async def target(room_id, server_name):
    evaluator = await state.get_cached_evaluator(room_id)
    return evaluator.matches(server_name)
"""
        facts = _facts(
            op_kind="regex_compile", magnitude_kind="element_count",
            arg_expr="cached evaluator rules",
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_repeated_pattern_compilation_is_cwe770(self):
        source = """def target(entries, value):
    for entry in entries:
        pattern = glob_to_regex(entry)
        if pattern.match(value):
            return True
    return False
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="element_count",
            arg_expr="entries",
        )
        facts["costly_ops"][0].update(
            callee="glob_to_regex", call_expr="glob_to_regex(entry)"
        )

        result = classify(self._parse(source, facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-770", result["findings"][0]["cwe"])

    def test_source_regex_compile_stabilizes_model_kind_and_magnitude_variation(self):
        source = """def target(pattern):
    compiled = pattern_to_regex(pattern)
    return compiled
"""
        facts = _facts(
            op_kind="looped_allocation_at_internal_callee",
            magnitude_kind="input_length", arg_expr="pattern",
        )
        facts["params"] = ["pattern"]
        facts["magnitude_sources"] = [{
            "id": "RENAMED_MAGNITUDE", "magnitude_kind": "input_length",
            "expr": "len(pattern)", "introduced_by": "external pattern",
            "confidence": "high",
        }]
        facts["costly_ops"][0].update(
            callee="pattern_to_regex", call_expr="pattern_to_regex(pattern)",
            magnitudes=[{"source": "mag:invented", "bounds": []}],
        )

        parsed = self._parse(source, facts)
        result = classify(parsed, param_status={"pattern": "ATTACKER"})

        self.assertEqual(["regex_compile"], [op["op_kind"] for op in parsed["costly_ops"]])
        self.assertEqual(
            "param:pattern",
            parsed["costly_ops"][0]["magnitudes"][0]["source"],
        )
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-770", result["findings"][0]["cwe"])

    def test_source_regex_compile_derives_pattern_magnitude_when_model_omits_it(self):
        source = """def target(pattern):
    return pattern_to_regex(pattern)
"""
        facts = _facts(
            op_kind="regex_compile", magnitude_kind="input_length",
            arg_expr="pattern",
        )
        facts["params"] = ["pattern"]
        facts["magnitude_sources"] = []
        facts["costly_ops"] = []
        request = _request(source)
        plugin = ResourcePlugin()
        parsed = plugin.parse_abstraction_response(
            request, "[RESOURCE_JSON]" + json.dumps(facts) + "[/RESOURCE_JSON]"
        )

        verdict = plugin.check(parsed, request.context)

        self.assertEqual(["len(pattern)"], [
            item["expr"] for item in parsed.payload["magnitude_sources"]
        ])
        self.assertEqual(VULNERABLE, verdict.verdict)

    def test_rust_scalar_parse_and_precompiled_match_ignore_expensive_call_claims(self):
        source = """fn target(server_name: &str, entries: &[Regex]) -> bool {
    if Ipv4Addr::from_str(server_name).is_ok() { return true; }
    entries.iter().any(|entry| entry.is_match(server_name))
}
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="input_length",
            arg_expr="server_name",
        )
        facts["costly_ops"] = [
            {
                **facts["costly_ops"][0],
                "id": "parse",
                "callee": "<Ipv4Addr::from_str>::call",
                "call_expr": "Ipv4Addr::from_str(server_name)",
            },
            {
                **facts["costly_ops"][0],
                "id": "match",
                "callee": "Regex::is_match",
                "call_expr": "entry.is_match(server_name)",
            },
        ]

        parsed = self._parse(source, facts, language="rust")

        self.assertEqual([], parsed["costly_ops"])

    def test_raw_unknown_flow_does_not_make_opaque_call_expensive(self):
        source = """def target(request):
    return authenticate(request)
"""
        facts = _facts(
            op_kind="expensive_call", magnitude_kind="request_size",
            arg_expr="request",
        )
        facts["costly_ops"][0].update(
            callee="authenticate",
            call_expr="authenticate(request)",
            magnitudes=[{"source": "unknown:request", "bounds": []}],
        )

        parsed = self._parse(source, facts)

        self.assertEqual([], parsed["costly_ops"][0]["magnitudes"])
        self.assertEqual(SAFE, classify(parsed)["verdict"])

    def test_source_derived_regex_compile_inherits_rejecting_length_bound(self):
        source = """def target(pattern):
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError('pattern too long')
    return pattern_to_regex(pattern)
"""
        facts = _facts(
            op_kind="regex_compile", magnitude_kind="input_length",
            arg_expr="pattern",
        )
        facts["magnitude_sources"][0]["expr"] = "len(pattern)"
        facts["costly_ops"] = []

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["costly_ops"][0]["magnitudes"][0]["bounds"])
        self.assertEqual(BOUNDED, classify(parsed)["verdict"])

    def test_constant_regex_compile_does_not_create_attacker_work(self):
        source = """def target():
    return pattern_to_regex('fixed-pattern')
"""
        facts = _facts(op_kind="regex_compile", magnitude_kind="input_length")
        facts["magnitude_sources"] = []
        facts["costly_ops"] = []

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_cached_regex_builder_is_not_replayed_at_caller(self):
        caller_id = FunctionId("caller.py", "target", "target", "python")
        callee_id = FunctionId("builder.py", "build_rules", "build_rules", "python")
        caller = FunctionUnit(
            caller_id,
            "def target(pattern):\n    return build_rules(pattern)",
            "def target(pattern):",
            ("pattern",),
        )
        callee = FunctionUnit(
            callee_id,
            "@cache\ndef build_rules(pattern):\n    return pattern_to_regex(pattern)",
            "def build_rules(pattern):",
            ("pattern",),
        )
        call = CallSite(
            caller_id, callee_id, "build_rules", 0, {"param:pattern": "pattern"}
        )
        program = ProgramIndex(
            functions={caller_id: caller, callee_id: callee},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller_payload = _facts(magnitude_kind="input_length", arg_expr="pattern")
        caller_payload["params"] = ["pattern"]
        caller_payload["magnitude_sources"][0]["expr"] = "len(pattern)"
        caller_payload["costly_ops"] = []
        caller_payload["call_sites"] = [{
            "id": "C1", "callee": "build_rules",
            "call_expr": "build_rules(pattern)",
            "args": [{
                "position": 0, "param_name": "pattern", "expr": "pattern",
                "magnitudes": [{"source": "mag:M1", "bounds": []}],
            }],
        }]
        callee_payload = _facts(magnitude_kind="input_length", arg_expr="pattern")
        callee_payload["params"] = ["pattern"]
        callee_payload["magnitude_sources"] = []
        callee_payload["costly_ops"] = []

        composed = ResourcePlugin().compose_calls(
            FactEnvelope("resource", "resource.v1", caller_id, "ok", caller_payload),
            [ResolvedCall(
                call,
                FactEnvelope("resource", "resource.v1", callee_id, "ok", callee_payload),
            )],
            DriverContext(program, caller, True),
        )

        self.assertEqual(SAFE, classify(composed.payload)["verdict"])

    def test_precision_losing_allocation_arithmetic_is_cwe789(self):
        source = """def target(type_info):
    slot = 0
    slot += math.ceil(type_info.size_in_bytes / 32)
    return slot
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )

        result = classify(self._parse(source, facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-789", result["findings"][0]["cwe"])

    def test_source_precision_loss_stabilizes_unknown_model_operation_kind(self):
        source = """def target(type_info):
    storage_slot = 0
    storage_slot += math.ceil(type_info.byte_extent / 32)
    return storage_slot
"""
        facts = _facts(
            op_kind="logic", magnitude_kind="logical_size",
            arg_expr="math.ceil(type_info.byte_extent / 32)",
        )
        facts["magnitude_sources"] = []
        facts["costly_ops"][0].update(
            callee="storage arithmetic",
            call_expr="storage_slot += math.ceil(type_info.byte_extent / 32)",
            magnitudes=[{"source": "mag:invented_name", "bounds": []}],
        )

        parsed = self._parse(source, facts)
        result = classify(parsed)

        self.assertEqual("logical_allocation", parsed["costly_ops"][0]["op_kind"])
        self.assertTrue(parsed["costly_ops"][0]["magnitudes"])
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-789", result["findings"][0]["cwe"])

    def test_unrelated_unknown_operation_kind_is_rejected_by_validation(self):
        source = """def target(type_info):
    total = 0
    total += estimate_extent(type_info)
    return total
"""
        facts = _facts(
            op_kind="logic", magnitude_kind="logical_size",
            arg_expr="type_info",
        )
        facts["costly_ops"][0].update(
            callee="estimate_extent", call_expr="total += estimate_extent(type_info)"
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_exact_integer_rounding_drops_unknown_model_operation_kind(self):
        source = """def target(type_info):
    offset = 0
    rounded = ((type_info.byte_extent + 31) // 32) * 32
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logic", magnitude_kind="logical_size",
            arg_expr="type_info.byte_extent",
        )
        facts["costly_ops"][0].update(
            callee="storage arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_named_precision_losing_extent_is_derived_as_cwe789(self):
        source = """def target(type_info):
    storage_length = math.ceil(type_info.size_in_bytes / 32)
    reserve_slot_range(0, storage_length)
"""
        facts = _facts(
            op_kind="logical_allocation",
            magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"] = []
        facts["magnitude_sources"][0]["expr"] = (
            "math.ceil(type_info.size_in_bytes / 32)"
        )

        result = classify(self._parse(source, facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("CWE-789", {finding["cwe"] for finding in result["findings"]})

    def test_assigning_sequence_length_is_derived_as_logical_allocation(self):
        source = """def target(value_type, length):
    if not 0 < length < 2**256:
        raise ValueError('invalid length')
    self.length = length
"""
        facts = _facts(magnitude_kind="numeric_param", arg_expr="length")
        facts["params"] = ["value_type", "length"]
        facts["costly_ops"] = []
        facts["bounds"] = [_guard(
            bound_kind="size_check",
            caps=("numeric_param",),
            protects=(),
        )]

        result = classify(
            self._parse(source, facts), param_status={"length": "ATTACKER"}
        )

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("CWE-789", {finding["cwe"] for finding in result["findings"]})

    def test_checked_addition_bounds_logical_allocation(self):
        source = """def target(slot, amount):
    if slot + amount >= 2**256:
        raise ValueError("overflow")
    slot += amount
    return slot
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="amount",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="slot += amount"
        )

        self.assertEqual(BOUNDED, classify(self._parse(source, facts))["verdict"])

    def test_exact_integer_rounding_is_not_precision_losing_allocation(self):
        source = """def align_extent(value):
    return ((value + 15) // 16) * 16

def target(type_info):
    offset = 0
    rounded = align_extent(type_info.size_in_bytes)
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_inline_exact_round_up_is_identifier_independent(self):
        source = """def target(metadata):
    cursor = 0
    padded = ((metadata.payload_octets + 7) // 8) * 8
    cursor += padded
    return cursor
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="metadata.payload_octets",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="cursor += padded"
        )

        self.assertEqual(SAFE, classify(self._parse(source, facts))["verdict"])

    def test_direct_integral_extent_is_identifier_independent(self):
        source = """def target(type_info):
    units = type_info.compiled_word_extent
    allocator.reserve_region(0, units)
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.compiled_word_extent",
        )
        facts["costly_ops"][0].update(
            callee="allocator.reserve_region",
            call_expr="allocator.reserve_region(0, units)",
            arg_position=1,
        )

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["_resource_exact_extents"])
        self.assertNotIn("OP1", [op["id"] for op in parsed["costly_ops"]])
        self.assertEqual(SAFE, classify(parsed)["verdict"])

    def test_string_label_alias_is_not_treated_as_an_extent_argument(self):
        source = """def target(type_info):
    allocator = RegionAllocator()
    variable_name = f"nonreentrant.{type_info.lock_name}"
    allocator.allocate_region(1, variable_name)
    extent = type_info.compiled_word_extent
    allocator.allocate_region(extent, type_info.declaration_id)
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.compiled_word_extent",
        )
        facts["costly_ops"][0].update(
            callee="allocator.allocate_region",
            call_expr="allocator.allocate_region(extent, type_info.declaration_id)",
            arg_position=0,
        )

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["_resource_exact_extents"])
        self.assertEqual(SAFE, classify(parsed)["verdict"])

    def test_string_label_does_not_hide_unsafe_numeric_extent(self):
        source = """def target(type_info):
    variable_name = f"region.{type_info.lock_name}"
    extent = math.ceil(type_info.byte_extent / 32)
    allocator.reserve_region(extent, variable_name)
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.byte_extent",
        )
        facts["costly_ops"][0].update(
            callee="allocator.reserve_region",
            call_expr="allocator.reserve_region(extent, variable_name)",
            arg_position=0,
        )

        parsed = self._parse(source, facts)

        self.assertFalse(parsed["_resource_exact_extents"])
        self.assertEqual(VULNERABLE, classify(parsed)["verdict"])

    def test_patched_extent_identifier_does_not_hide_float_rounding(self):
        source = """def target(type_info):
    units = math.ceil(type_info.storage_size_in_words / 32)
    allocator.reserve_region(0, units)
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.storage_size_in_words",
        )
        facts["costly_ops"][0].update(
            callee="allocator.reserve_region",
            call_expr="allocator.reserve_region(0, units)",
            arg_position=1,
        )

        parsed = self._parse(source, facts)

        self.assertFalse(parsed["_resource_exact_extents"])
        self.assertEqual(VULNERABLE, classify(parsed)["verdict"])

    def test_unrelated_float_rounding_does_not_poison_exact_extent(self):
        source = """def target(type_info):
    units = type_info.compiled_word_extent
    preview_rows = math.ceil(type_info.preview_bytes / 8)
    allocator.reserve_region(0, units)
    return preview_rows
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.compiled_word_extent",
        )
        facts["costly_ops"][0].update(
            callee="allocator.reserve_region",
            call_expr="allocator.reserve_region(0, units)",
            arg_position=1,
        )

        parsed = self._parse(source, facts)

        self.assertTrue(parsed["_resource_exact_extents"])
        self.assertNotIn("OP1", [op["id"] for op in parsed["costly_ops"]])

    def test_rounding_helper_name_does_not_override_unsafe_body(self):
        source = """def ceil32(value):
    return math.ceil(value / 32) * 32

def target(type_info):
    offset = 0
    rounded = ceil32(type_info.size_in_bytes)
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_incorrect_integer_round_up_formula_is_rejected(self):
        source = """def align_extent(value):
    return ((value + 32) // 32) * 32

def target(type_info):
    offset = 0
    rounded = align_extent(type_info.size_in_bytes)
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_true_division_round_up_lookalike_is_rejected(self):
        source = """def align_extent(value):
    return ((value + 31) / 32) * 32

def target(type_info):
    offset = 0
    rounded = align_extent(type_info.size_in_bytes)
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_opaque_rounding_helper_is_not_assumed_exact(self):
        source = """def target(type_info):
    offset = 0
    rounded = imported_alignment(type_info.size_in_bytes)
    offset += rounded
    return offset
"""
        facts = _facts(
            op_kind="logical_allocation", magnitude_kind="logical_size",
            arg_expr="type_info.size_in_bytes",
        )
        facts["costly_ops"][0].update(
            callee="arithmetic", call_expr="offset += rounded"
        )

        self.assertEqual(VULNERABLE, classify(self._parse(source, facts))["verdict"])

    def test_unknown_candidate_bound_cannot_poison_an_unbounded_finding(self):
        facts = _facts(
            bounds=[_guard(bound_kind="type_filter")], flow_bounds=["B1"]
        )
        facts["costly_ops"][0].update(callee="bytes", call_expr="bytes(count)")

        result = classify(self._parse("def target(count):\n    return bytes(count)\n", facts))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIsNone(result["error"])

    def test_render_result_uses_stock_runner_source_identity(self):
        request = _request(
            "def target(count):\n    return consume(count)\n",
            rel="src/service-py/target.py",
        )
        facts = FactEnvelope(
            "resource", "resource.v1", request.function.id, "ok", _facts()
        )
        verdict = ResourcePlugin().check(facts, request.context)

        rendered = ResourcePlugin().render_result(
            request.function, facts, verdict, request.context
        )

        self.assertEqual("src/service.py", rendered["rel"])
        self.assertEqual("target", rendered["function"])

    def test_valid_json_array_payload_is_rejected_without_crashing(self):
        parsed = ResourcePlugin().parse_abstraction_response(
            _request(), "[RESOURCE_JSON][][/RESOURCE_JSON]"
        )

        self.assertIsNone(parsed)

    def test_raw_llm_internal_fields_are_removed(self):
        facts = _facts()
        facts["costly_ops"][0].update(callee="bytes", call_expr="bytes(count)")
        facts["costly_ops"][0]["_validated_bound"] = "B1"

        parsed = ResourcePlugin().parse_abstraction_response(
            _request("def target(count):\n    return bytes(count)\n"), json.dumps(facts)
        )

        self.assertNotIn("_validated_bound", parsed.payload["costly_ops"][0])

    def test_raw_llm_cannot_forge_source_validation_marker(self):
        request = _request("def target(count):\n    return None\n")
        facts = _facts()
        facts["costly_ops"][0].update(callee="bytes", call_expr="bytes(count)")
        facts["_resource_validated"] = RESOURCE_VALIDATION_VERSION
        facts["_resource_source_digest"] = source_digest(request.function)

        parsed = ResourcePlugin().parse_abstraction_response(
            request, "[RESOURCE_JSON]" + json.dumps(facts) + "[/RESOURCE_JSON]"
        )

        self.assertEqual([], parsed.payload["costly_ops"])

    def test_cached_source_facts_are_revalidated_after_source_change(self):
        old_request = _request("def target(count):\n    return bytes(count)\n")
        facts = _facts()
        facts["costly_ops"][0].update(callee="bytes", call_expr="bytes(count)")
        parsed = ResourcePlugin().parse_abstraction_response(
            old_request, "[RESOURCE_JSON]" + json.dumps(facts) + "[/RESOURCE_JSON]"
        )
        new_request = _request("def target(count):\n    return None\n")

        verdict = ResourcePlugin().check(parsed, new_request.context)

        self.assertEqual(SAFE, verdict.verdict)
        self.assertEqual([], parsed.payload["costly_ops"])
        self.assertEqual(
            source_digest(new_request.function),
            parsed.payload["_resource_source_digest"],
        )

    def test_prompt_requires_hard_pre_sink_limits_and_logical_arithmetic(self):
        system, user = ResourcePlugin().build_abstraction_prompt(_request())
        prompt = system["content"] + user["content"]

        for phrase in (
            "expensive_call",
            "regex_compile",
            "logical_allocation",
            "protects_op_ids",
            "placement",
            "limit_origin",
            "warning",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, prompt)
        self.assertIn("source-controlled array extents", prompt)
        self.assertIn("precision-losing resource growth", prompt)
        self.assertNotIn("Vyper", prompt)


if __name__ == "__main__":
    unittest.main()
