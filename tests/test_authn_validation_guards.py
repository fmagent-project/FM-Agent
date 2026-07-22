import json
import unittest

from src.authn_reasoner import ERROR, SAFE, VULNERABLE, classify
from src.authn_prompts import _system_prompt
from src.authn_validation import related_authentication_context
from src.plugins.base import (
    AbstractionRequest,
    DriverContext,
    FactEnvelope,
    FunctionId,
    FunctionUnit,
    ProgramIndex,
)
from src.plugins.authn import AuthnPlugin


def _facts(*, operations=None, authentication=None, sessions=None):
    return {
        "protected_operations": operations or [],
        "authentication_events": authentication or [],
        "session_events": sessions or [],
        "obligations": [],
    }


def _operation(op_id="op1"):
    return {
        "op_id": op_id,
        "kind": "account_change",
        "subject_expr": "user",
        "evidence": "change_account(user)",
    }


def _authentication(strength):
    return {
        "method": "password",
        "strength": strength,
        "dominates_all_paths": True,
        "evidence": "verify_password(user, password)",
    }


def _request():
    function_id = FunctionId("account.py", "recover", "recover", "python")
    unit = FunctionUnit(function_id, "def recover():\n    pass", "def recover():")
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[function_id],
    )
    return AbstractionRequest(unit, DriverContext(program, unit, True))


def _request_with_related(source, related_sources):
    function_id = FunctionId("target.py", "target", "target", "python")
    unit = FunctionUnit(function_id, source, source.splitlines()[0])
    functions = {function_id: unit}
    for index, related_source in enumerate(related_sources):
        related_id = FunctionId(
            f"related_{index}.py", f"related_{index}", f"related_{index}", "python"
        )
        functions[related_id] = FunctionUnit(
            related_id, related_source, related_source.splitlines()[0]
        )
    program = ProgramIndex(
        functions=functions,
        calls_by_caller={function: [] for function in functions},
        callers_by_callee={function: [] for function in functions},
        entrypoints=list(functions),
    )
    return AbstractionRequest(unit, DriverContext(program, unit, True))


class AuthnCurrentBehaviorTests(unittest.TestCase):
    def test_genuine_dominating_authentication_is_safe(self):
        result = classify(_facts(
            operations=[_operation()],
            authentication=[_authentication("genuine")],
        ))

        self.assertEqual(SAFE, result["verdict"])
        self.assertEqual([], result["findings"])

    def test_weak_dominating_authentication_is_vulnerable(self):
        result = classify(_facts(
            operations=[_operation()],
            authentication=[_authentication("weak")],
        ))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("WEAK_AUTHENTICATION", result["findings"][0]["kind"])

    def test_asserted_identity_is_vulnerable(self):
        result = classify(_facts(
            operations=[_operation()],
            authentication=[_authentication("asserted_only")],
        ))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("ASSERTED_IDENTITY", result["findings"][0]["kind"])

    def test_established_session_without_rotation_or_expiry_is_vulnerable(self):
        result = classify(_facts(sessions=[
            {"kind": "establish", "evidence": "session[user] = user.id"},
        ]))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(
            {"SESSION_FIXATION", "INSUFFICIENT_SESSION_EXPIRATION"},
            {finding["kind"] for finding in result["findings"]},
        )


class AuthnPatchSemanticsTests(unittest.TestCase):
    def test_parser_corrects_python_shared_credential_file_contract(self):
        fixed_source = (
            "def target(data):\n"
            "    with open('/srv/auth.secret', 'w', 432, encoding='UTF-8') as stream:\n"
            "        stream.write(str(data))"
        )
        fixed_reader = (
            "def load_shared_secret():\n"
            "    try:\n"
            "        with open('/srv/auth.secret', 'r', encoding='UTF-8') as stream:\n"
            "            return stream.read()\n"
            "    except Exception:\n"
            "        return -1"
        )
        fixed_verifier = (
            "def verify(candidate):\n"
            "    if self.shared_secret == -1:\n"
            "        raise ValueError('authentication failed')\n"
            "    return candidate == self.shared_secret"
        )
        facts = _facts(operations=[_operation()])
        facts["credential_events"] = [{
            "kind": "provision",
            "contract_status": "invalid",
            "failure_mode": "open",
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "confidence": "high",
            "evidence": "misleading model claim that text mode is binary",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(fixed_source, [fixed_reader, fixed_verifier]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("valid", parsed.payload["credential_events"][0]["contract_status"])
        self.assertEqual("closed", parsed.payload["credential_events"][0]["failure_mode"])

        vulnerable_source = fixed_source.replace("'w', 432, encoding='UTF-8'", "'wb'")
        vulnerable_reader = fixed_reader.replace("'r'", "'rb'")
        facts["credential_events"][0].update(contract_status="valid", failure_mode="closed")

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable_source, [vulnerable_reader, fixed_verifier]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("invalid", parsed.payload["credential_events"][0]["contract_status"])
        self.assertEqual("open", parsed.payload["credential_events"][0]["failure_mode"])

    def test_exact_fresh_shared_secret_provision_covers_same_file_lifecycle(self):
        fixed_source = (
            "def regen_ss_file() -> None:\n"
            "    \"\"\"\n"
            "    This is only used for Kerberos auth at the moment. It identifies XMLRPC requests from Apache that have already been\n"
            "    cleared by Kerberos.\n"
            "    \"\"\"\n"
            "    ssfile = '/var/lib/cobbler/web.ss'\n"
            "    data = os.urandom(512)\n"
            "\n"
            "    with open(ssfile, 'w', 0o660, encoding='UTF-8') as ss_file_fd:\n"
            "        ss_file_fd.write(str(binascii.hexlify(data)))\n"
            "\n"
            "    http_user = 'apache'\n"
            "    family = utils.get_family()\n"
            "    if family == 'debian':\n"
            "        http_user = 'www-data'\n"
            "    elif family == 'suse':\n"
            "        http_user = 'wwwrun'\n"
            "    os.lchown(ssfile, pwd.getpwnam(http_user)[2], -1)"
        )
        fixed_reader = (
            "def get_shared_secret():\n"
            "    try:\n"
            "        with open('/var/lib/cobbler/web.ss', 'r', encoding='UTF-8') as web_secret_fd:\n"
            "            data = web_secret_fd.read()\n"
            "    except Exception:\n"
            "        return -1\n"
            "    return data"
        )
        fixed_verifier = (
            "def login(self, login_user, login_password):\n"
            "    if login_user == '':\n"
            "        if self.shared_secret == -1:\n"
            "            raise ValueError('login failed')\n"
            "        if login_password == self.shared_secret:\n"
            "            return self.issue_token()\n"
            "        raise ValueError('login failed')"
        )
        facts = _facts(operations=[_operation("op_1"), _operation("op_2")])
        facts["protected_operations"][0].update(
            kind="token_issue",
            evidence=(
                "with open(ssfile, 'w', 0o660, encoding='UTF-8') as ss_file_fd: "
                "ss_file_fd.write(str(binascii.hexlify(data)))"
            ),
        )
        facts["protected_operations"][1].update(
            kind="privileged_action",
            evidence="os.lchown(ssfile, pwd.getpwnam(http_user)[2], -1)",
        )
        facts["obligations"] = [{
            "requires_nl": "caller authenticates credential provisioning",
            "reason": "model treats the file lifecycle as caller policy",
        }]
        facts["credential_events"] = [{
            "kind": "provision",
            "contract_status": "valid",
            "failure_mode": "closed",
            "dominates_all_paths": True,
            "protects_op_ids": ["op_1"],
            "confidence": "high",
            "evidence": "model omitted same-file ownership",
        }]

        plugin = AuthnPlugin()
        request = _request_with_related(fixed_source, [fixed_reader, fixed_verifier])
        cached = FactEnvelope(
            plugin_name="authn",
            schema_version=plugin.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=facts,
        )
        verdict = plugin.check(cached, request.context)

        event = verdict.data["abstraction"]["credential_events"][0]
        self.assertEqual("valid", event["contract_status"])
        self.assertEqual("closed", event["failure_mode"])
        self.assertEqual(["op_1", "op_2"], event["protects_op_ids"])
        self.assertEqual(SAFE, verdict.verdict)

        misleading = json.loads(json.dumps(facts))
        misleading["credential_events"][0].update(
            contract_status="invalid",
            failure_mode="open",
            protects_op_ids=[],
            evidence="contradictory model event",
        )
        parsed = plugin.parse_abstraction_response(
            request,
            "[AUTHN_JSON]" + json.dumps(misleading) + "[/AUTHN_JSON]",
        )
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])
        self.assertEqual(
            ["op_1", "op_2"], parsed.payload["credential_events"][0]["protects_op_ids"]
        )

        coarse = json.loads(json.dumps(facts))
        coarse["protected_operations"] = [coarse["protected_operations"][0]]
        coarse["protected_operations"][0]["evidence"] = "def target() -> None:"
        parsed = plugin.parse_abstraction_response(
            request,
            "[AUTHN_JSON]" + json.dumps(coarse) + "[/AUTHN_JSON]",
        )
        self.assertEqual(
            ["op_1"], parsed.payload["credential_events"][0]["protects_op_ids"]
        )
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

        vulnerable_source = fixed_source.replace(
            "open(ssfile, 'w', 0o660, encoding='UTF-8')",
            "open(ssfile, 'wb', 0o660)",
        ).replace(
            "ss_file_fd.write(str(binascii.hexlify(data)))",
            "ss_file_fd.write(binascii.hexlify(data))",
        )
        vulnerable_reader = fixed_reader.replace(
            "'r', encoding='UTF-8'", "'rb', encoding='UTF-8'"
        ).replace("    return data", "    return str(data).strip()")
        fail_open_verifier = fixed_verifier.replace(
            "        if self.shared_secret == -1:\n"
            "            raise ValueError('login failed')\n",
            "",
        )
        dynamic_default_reader = (
            "def load_credential(default_value):\n"
            "    try:\n"
            "        return open('/var/lib/cobbler/web.ss', 'r', encoding='UTF-8').read()\n"
            "    except Exception:\n"
            "        return default_value"
        )
        dynamic_default_verifier = (
            "def verify(candidate):\n"
            "    if candidate == self.credential:\n"
            "        return issue_token()\n"
            "    raise ValueError('authentication failed')"
        )
        reusable_default_source = (
            "def provision(default_secret='development'):\n"
            "    path = '/var/lib/cobbler/web.ss'\n"
            "    with open(path, 'w', encoding='UTF-8') as stream:\n"
            "        stream.write(str(default_secret))"
        )
        controls = {
            "incompatible binary reader contract": (
                vulnerable_source, [vulnerable_reader, fail_open_verifier]
            ),
            "accepted loader failure sentinel": (
                fixed_source, [fixed_reader, fail_open_verifier]
            ),
            "dynamic loader failure default": (
                fixed_source, [dynamic_default_reader, dynamic_default_verifier]
            ),
            "reusable provision default": (
                reusable_default_source, [fixed_reader, fixed_verifier]
            ),
        }
        for name, (source, related) in controls.items():
            with self.subTest(name=name):
                parsed = plugin.parse_abstraction_response(
                    _request_with_related(source, related),
                    "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
                )
                event = parsed.payload["credential_events"][0]
                self.assertEqual("open", event["failure_mode"])
                result = classify(parsed.payload)
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn(
                    "CWE-287", {finding.get("cwe") for finding in result["findings"]}
                )

    def test_parser_resolves_constant_file_path_aliases_on_both_contract_sides(self):
        writer = (
            "def target(data):\n"
            "    secret_path = '/srv/auth.secret'\n"
            "    with open(secret_path, 'w', 432, encoding='UTF-8') as stream:\n"
            "        stream.write(str(data))"
        )
        reader = (
            "def load_shared_secret():\n"
            "    with open('/srv/auth.secret', 'r', encoding='UTF-8') as stream:\n"
            "        return stream.read()"
        )
        facts = _facts(operations=[_operation()])
        facts["credential_events"] = [{
            "kind": "provision",
            "contract_status": "valid",
            "failure_mode": "closed",
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "confidence": "medium",
            "evidence": "write shared authenticator",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(writer, [reader]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("high", parsed.payload["credential_events"][0]["confidence"])

        facts["credential_events"][0].update(
            kind="load", contract_status="invalid", failure_mode="open", confidence="high"
        )
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(reader, [writer]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("valid", parsed.payload["credential_events"][0]["contract_status"])
        self.assertEqual("closed", parsed.payload["credential_events"][0]["failure_mode"])

    def test_parser_keeps_file_contract_events_local_to_the_writer(self):
        writer = (
            "def target(data):\n"
            "    with open('/srv/auth.secret', 'w', encoding='UTF-8') as stream:\n"
            "        stream.write(data)"
        )
        reader = (
            "def load_secret():\n"
            "    return open('/srv/auth.secret', 'r', encoding='UTF-8').read()"
        )
        facts = _facts(operations=[_operation()])
        facts["protected_operations"][0]["evidence"] = "stream.write(data)"
        facts["credential_events"] = [{
            "kind": "provision",
            "contract_status": "valid",
            "failure_mode": "closed",
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "open('/srv/auth.secret', 'w')",
        }, {
            "kind": "load",
            "contract_status": "invalid",
            "failure_mode": "open",
            "dominates_all_paths": False,
            "protects_op_ids": [],
            "confidence": "low",
            "evidence": "related reader",
        }, {
            "kind": "verify",
            "contract_status": "invalid",
            "failure_mode": "open",
            "dominates_all_paths": False,
            "protects_op_ids": [],
            "confidence": "low",
            "evidence": "related verifier",
        }]
        facts["session_key_events"] = [{
            "kind": "retire",
            "replacement": "fresh_random",
            "storage_cleared": True,
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "incorrectly treats shared secret replacement as a session key",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(writer, [reader]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(["provision"], [
            event["kind"] for event in parsed.payload["credential_events"]
        ])
        self.assertEqual(["op1"], parsed.payload["credential_events"][0]["protects_op_ids"])
        self.assertEqual([], parsed.payload["session_key_events"])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_parser_normalizes_indented_extracted_method_source(self):
        source = (
            "    def target(self, candidate):\n"
            "        if candidate == self.shared_secret:\n"
            "            token = self.make_token()\n"
            "            return token\n"
            "        raise ValueError('authentication failed')"
        )
        facts = _facts()
        facts["session_events"] = [{
            "kind": "establish",
            "evidence": "token = self.make_token(); return token",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual([], parsed.payload["session_events"])

    def test_parser_corrects_shared_authenticator_sentinel_and_token_session_facts(self):
        loader = (
            "def load_shared_secret():\n"
            "    try:\n"
            "        return read_secret()\n"
            "    except Exception:\n"
            "        return -1"
        )
        unrelated_token_helper = (
            "def make_token():\n"
            "    try:\n"
            "        return fetch_token()\n"
            "    except Exception:\n"
            "        return None"
        )
        fixed_source = (
            "def target(candidate):\n"
            "    if self.shared_secret == -1:\n"
            "        raise ValueError('authentication failed')\n"
            "    if candidate == self.shared_secret:\n"
            "        return make_token()\n"
            "    raise ValueError('authentication failed')"
        )
        facts = _facts(operations=[_operation()])
        facts["authentication_events"] = [{
            "method": "api_key",
            "strength": "weak",
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "evidence": "candidate == self.shared_secret",
        }]
        facts["session_events"] = [{
            "kind": "establish",
            "evidence": "return make_token()",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(fixed_source, [loader, unrelated_token_helper]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual([], parsed.payload["session_events"])
        self.assertEqual("valid", parsed.payload["credential_events"][0]["contract_status"])
        self.assertEqual("closed", parsed.payload["credential_events"][0]["failure_mode"])

        vulnerable_source = fixed_source.replace(
            "    if self.shared_secret == -1:\n"
            "        raise ValueError('authentication failed')\n",
            "",
        )
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable_source, [loader, unrelated_token_helper]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("invalid", parsed.payload["credential_events"][0]["contract_status"])
        self.assertEqual("open", parsed.payload["credential_events"][0]["failure_mode"])

    def test_parser_drops_related_loader_event_from_local_verifier(self):
        loader = (
            "def load_shared_secret():\n"
            "    try:\n"
            "        return read_secret()\n"
            "    except Exception:\n"
            "        return -1"
        )
        source = (
            "def target(candidate):\n"
            "    if self.shared_secret == -1:\n"
            "        raise ValueError('authentication failed')\n"
            "    return candidate == self.shared_secret"
        )
        facts = _facts(operations=[_operation()])
        facts["authentication_events"] = [{
            "method": "api_key",
            "strength": "genuine",
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "evidence": "candidate == self.shared_secret",
        }]
        facts["credential_events"] = [{
            "kind": "load",
            "contract_status": "invalid",
            "failure_mode": "open",
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "confidence": "low",
            "evidence": "related loader returns a sentinel",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, [loader]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(["verify"], [
            event["kind"] for event in parsed.payload["credential_events"]
        ])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_parser_canonicalizes_shared_secret_and_delegated_authenticate_gate(self):
        source = (
            "def target(user, password, shared_secret):\n"
            "    if password == shared_secret:\n"
            "        issue_direct_token()\n"
            "    if validate_user(user, password):\n"
            "        issue_user_token()"
        )
        helper = (
            "def validate_user(user, password):\n"
            "    return api.authenticate(user, password)"
        )
        facts = _facts(operations=[_operation("direct"), _operation("user")])
        facts["protected_operations"][0]["evidence"] = "issue_direct_token()"
        facts["protected_operations"][1]["evidence"] = "issue_user_token()"
        facts["authentication_events"] = [{
            "method": "shared_secret",
            "strength": "genuine",
            "dominates_all_paths": False,
            "protects_op_ids": ["direct"],
            "evidence": "password == shared_secret",
        }, {
            "method": "password",
            "strength": "weak",
            "dominates_all_paths": False,
            "protects_op_ids": ["user"],
            "evidence": "validate_user(user, password)",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, [helper]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(
            ["api_key", "password"],
            [event["method"] for event in parsed.payload["authentication_events"]],
        )
        self.assertEqual("genuine", parsed.payload["authentication_events"][1]["strength"])
        self.assertTrue(all(
            event["dominates_all_paths"]
            for event in parsed.payload["authentication_events"]
        ))
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_related_credential_context_joins_shared_authenticator_identifier(self):
        loader_id = FunctionId("loader.py", "load_shared_secret", "load_shared_secret", "python")
        verifier_id = FunctionId("verifier.py", "verify", "verify", "python")
        loader = FunctionUnit(
            loader_id,
            "def load_shared_secret():\n    return read_secret_file()",
            "def load_shared_secret():",
        )
        verifier = FunctionUnit(
            verifier_id,
            "def verify(candidate):\n    return candidate == self.shared_secret",
            "def verify(candidate):",
        )
        program = ProgramIndex(
            functions={loader_id: loader, verifier_id: verifier},
            calls_by_caller={loader_id: [], verifier_id: []},
            callers_by_callee={loader_id: [], verifier_id: []},
            entrypoints=[loader_id, verifier_id],
        )

        context = related_authentication_context(loader, program)

        self.assertIn("Related function verify", context)

    def test_related_credential_context_joins_shared_absolute_path(self):
        writer_id = FunctionId("writer.py", "write_secret", "write_secret", "python")
        reader_id = FunctionId("reader.py", "read_secret", "read_secret", "python")
        writer = FunctionUnit(
            writer_id,
            'def write_secret(value):\n    open("/var/lib/app/web.ss", "w").write(value)',
            "def write_secret(value):",
        )
        reader = FunctionUnit(
            reader_id,
            'def read_secret():\n    return open("/var/lib/app/web.ss").read()',
            "def read_secret():",
        )
        program = ProgramIndex(
            functions={writer_id: writer, reader_id: reader},
            calls_by_caller={writer_id: [], reader_id: []},
            callers_by_callee={writer_id: [], reader_id: []},
            entrypoints=[writer_id, reader_id],
        )

        context = related_authentication_context(writer, program)

        self.assertIn("Related function read_secret", context)
        self.assertIn("/var/lib/app/web.ss", context)

    def test_password_recovery_rejects_backend_only_unicode_identity_match(self):
        facts = _facts()
        facts["recovery_events"] = [{
            "kind": "select_account",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "candidate.email",
            "binding": "backend_case_insensitive",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "lookup submitted identity using backend collation",
        }]

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("WEAK_PASSWORD_RECOVERY", result["findings"][0]["kind"])
        self.assertEqual("CWE-640", result["findings"][0]["cwe"])

    def test_password_recovery_accepts_canonical_unicode_identity_match(self):
        facts = _facts()
        facts["recovery_events"] = [{
            "kind": "select_account",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "candidate.email",
            "binding": "canonical_equivalent",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "normalize and casefold both identities before equality",
        }]

        self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_password_recovery_rejects_delivery_to_submitted_identity(self):
        facts = _facts()
        facts["recovery_events"] = [{
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "candidate.email",
            "binding": "untrusted_input",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "send reset credential to submitted_email",
        }]

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-640", result["findings"][0]["cwe"])

    def test_password_recovery_accepts_delivery_to_stored_identity(self):
        facts = _facts()
        facts["recovery_events"] = [{
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "candidate.email",
            "binding": "stored_identity",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "send reset credential to candidate.email",
        }]

        self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_parser_does_not_duplicate_delegated_recovery_selection(self):
        source = (
            "def target(submitted_email):\n"
            "    for account in select_accounts(submitted_email):\n"
            "        stored_email = account.email\n"
            "        send_reset(stored_email)"
        )
        facts = _facts()
        facts["recovery_events"] = [{
            "kind": "select_account",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account from select_accounts",
            "binding": "unknown",
            "dominates_all_paths": True,
            "failure_mode": "unknown",
            "protects_op_ids": [],
            "confidence": "medium",
            "evidence": "for account in select_accounts(submitted_email)",
        }, {
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account.email",
            "binding": "stored_identity",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "send_reset(stored_email)",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(
            ["deliver_credential"],
            [event["kind"] for event in parsed.payload["recovery_events"]],
        )
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

        local_selection = (
            "def target(submitted_email):\n"
            "    return Users.filter(email__iexact=submitted_email)"
        )
        facts["recovery_events"] = [dict(
            facts["recovery_events"][0],
            binding="backend_case_insensitive",
            failure_mode="closed",
            confidence="high",
        )]
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(local_selection, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(1, len(parsed.payload["recovery_events"]))
        self.assertEqual(VULNERABLE, classify(parsed.payload)["verdict"])

    def test_parser_proves_canonical_identity_selection_from_comparator_source(self):
        source = (
            "def target(submitted_email, accounts):\n"
            "    return (account for account in accounts "
            "if identity_equal(submitted_email, account.email))"
        )
        comparator = (
            "def identity_equal(left, right):\n"
            "    return normalize('NFKC', left).casefold() == "
            "normalize('NFKC', right).casefold()"
        )
        facts = _facts(operations=[_operation("select_account")])
        facts["recovery_events"] = [{
            "kind": "select_account",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account.email",
            "binding": "backend_case_insensitive",
            "dominates_all_paths": True,
            "failure_mode": "open",
            "protects_op_ids": ["select_account"],
            "confidence": "medium",
            "evidence": "identity_equal(submitted_email, account.email)",
        }, {
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account.email",
            "binding": "canonical_equivalent",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": ["select_account"],
            "confidence": "high",
            "evidence": "incorrect model claim that comparison delivers a credential",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, [comparator]),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["recovery_events"][0]
        self.assertEqual("canonical_equivalent", event["binding"])
        self.assertEqual("closed", event["failure_mode"])
        self.assertEqual("high", event["confidence"])
        self.assertEqual(["select_account"], [
            recovery["kind"] for recovery in parsed.payload["recovery_events"]
        ])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_parser_links_stored_delivery_to_same_flow_credential_generation(self):
        source = (
            "def target(submitted_email):\n"
            "    for account in select_accounts(submitted_email):\n"
            "        stored_email = account.email\n"
            "        reset_token = token_generator.make_token(account)\n"
            "        send_reset(stored_email, reset_token)"
        )
        facts = _facts(operations=[
            _operation("generate_reset_token"),
            _operation("send_reset_email"),
        ])
        facts["protected_operations"][0]["evidence"] = "token_generator.make_token(account)"
        facts["protected_operations"][1]["evidence"] = "send_reset(stored_email)"
        facts["recovery_events"] = [{
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account.email",
            "binding": "stored_identity",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": ["send_reset_email"],
            "confidence": "high",
            "evidence": "send_reset(stored_email, reset_token)",
        }]

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual(
            ["generate_reset_token", "send_reset_email"],
            parsed.payload["recovery_events"][0]["protects_op_ids"],
        )
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_parser_synthesizes_source_proven_recovery_delivery_when_omitted(self):
        fixed_source = (
            "def target(submitted_email):\n"
            "    for account in select_accounts(submitted_email):\n"
            "        stored_email = account.email\n"
            "        reset_token = token_generator.make_token(account)\n"
            "        send_reset(stored_email, reset_token)"
        )
        facts = _facts(operations=[_operation("password_reset")])
        facts["protected_operations"][0]["evidence"] = "token_generator.make_token(account)"

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(fixed_source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["recovery_events"][0]
        self.assertEqual("deliver_credential", event["kind"])
        self.assertEqual("stored_identity", event["binding"])
        self.assertEqual(["password_reset"], event["protects_op_ids"])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

        vulnerable_source = fixed_source.replace(
            "send_reset(stored_email, reset_token)",
            "send_reset(submitted_email, reset_token)",
        )
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable_source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        self.assertEqual("untrusted_input", parsed.payload["recovery_events"][0]["binding"])
        self.assertEqual(VULNERABLE, classify(parsed.payload)["verdict"])

        facts["recovery_events"] = [{
            "kind": "deliver_credential",
            "requested_identity_expr": "submitted_email",
            "account_identity_expr": "account.email",
            "binding": "stored_identity",
            "dominates_all_paths": True,
            "failure_mode": "closed",
            "protects_op_ids": ["password_reset"],
            "confidence": "high",
            "evidence": "incorrect model claim that submitted_email is persisted",
        }]
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable_source, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["recovery_events"][0]
        self.assertEqual("untrusted_input", event["binding"])
        self.assertEqual("open", event["failure_mode"])
        self.assertEqual(VULNERABLE, classify(parsed.payload)["verdict"])

    def test_exact_recovery_save_is_source_proven_despite_cached_model_fact_variation(self):
        fixed_source = (
            "def save(self, domain_override=None,\n"
            "         subject_template_name='registration/password_reset_subject.txt',\n"
            "         email_template_name='registration/password_reset_email.html',\n"
            "         use_https=False, token_generator=default_token_generator,\n"
            "         from_email=None, request=None, html_email_template_name=None,\n"
            "         extra_email_context=None):\n"
            "    \"\"\"\n"
            "    Generates a one-use only link for resetting password and sends to the\n"
            "    user.\n"
            "    \"\"\"\n"
            "    email = self.cleaned_data['email']\n"
            "    email_field_name = UserModel.get_email_field_name()\n"
            "    for user in self.get_users(email):\n"
            "        if not domain_override:\n"
            "            current_site = get_current_site(request)\n"
            "            site_name = current_site.name\n"
            "            domain = current_site.domain\n"
            "        else:\n"
            "            site_name = domain = domain_override\n"
            "        user_email = getattr(user, email_field_name)\n"
            "        context = {\n"
            "            'email': user_email,\n"
            "            'domain': domain,\n"
            "            'site_name': site_name,\n"
            "            'uid': urlsafe_base64_encode(force_bytes(user.pk)),\n"
            "            'user': user,\n"
            "            'token': token_generator.make_token(user),\n"
            "            'protocol': 'https' if use_https else 'http',\n"
            "        }\n"
            "        if extra_email_context is not None:\n"
            "            context.update(extra_email_context)\n"
            "        self.send_mail(\n"
            "            subject_template_name, email_template_name, context, from_email,\n"
            "            user_email, html_email_template_name=html_email_template_name,\n"
            "        )"
        )
        facts = _facts(operations=[_operation("op1")])
        facts["protected_operations"][0].update(
            subject_expr="user",
            evidence=(
                "Line 8-9: Generates a one-use only link for resetting password "
                "and sends to the user."
            ),
        )
        facts["obligations"] = [{
            "requires_nl": "caller authenticates sensitive messages",
            "reason": "model omitted the local recovery contract",
        }]

        plugin = AuthnPlugin()
        request = _request_with_related(fixed_source, [])
        cached = FactEnvelope(
            plugin_name="authn",
            schema_version=plugin.SCHEMA,
            function=request.function.id,
            status="ok",
            payload=facts,
        )
        cached_verdict = plugin.check(cached, request.context)
        self.assertEqual(SAFE, cached_verdict.verdict)
        self.assertEqual(
            "stored_identity",
            cached_verdict.data["abstraction"]["recovery_events"][0]["binding"],
        )

        parsed = plugin.parse_abstraction_response(
            request,
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["recovery_events"][0]
        self.assertEqual("stored_identity", event["binding"])
        self.assertEqual(["op1"], event["protects_op_ids"])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

        misleading = json.loads(json.dumps(facts))
        misleading["recovery_events"] = [{
            "kind": "deliver_credential",
            "requested_identity_expr": "email",
            "account_identity_expr": "email",
            "binding": "untrusted_input",
            "dominates_all_paths": True,
            "failure_mode": "open",
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "model missed the persisted recipient",
        }]
        reparsed = plugin.parse_abstraction_response(
            request,
            "[AUTHN_JSON]" + json.dumps(misleading) + "[/AUTHN_JSON]",
        )
        self.assertEqual("stored_identity", reparsed.payload["recovery_events"][0]["binding"])
        self.assertEqual(SAFE, classify(reparsed.payload)["verdict"])

        controls = {
            "request-derived message and recipient": fixed_source.replace(
                "'email': user_email", "'email': email"
            ).replace(
                "            user_email, html_email_template_name=html_email_template_name,",
                "            email, html_email_template_name=html_email_template_name,",
            ),
            "request-derived message with stored recipient": fixed_source.replace(
                "'email': user_email", "'email': email"
            ),
            "credential and recipient belong to different selected accounts": (
                "def target(submitted_identity):\n"
                "    for account, alternate in select_accounts(submitted_identity):\n"
                "        destination = alternate.email\n"
                "        credential = issue_token(account)\n"
                "        notify(destination, credential)"
            ),
        }
        for name, source in controls.items():
            with self.subTest(name=name):
                parsed = plugin.parse_abstraction_response(
                    _request_with_related(source, []),
                    "[AUTHN_JSON]" + json.dumps(misleading) + "[/AUTHN_JSON]",
                )
                result = classify(parsed.payload)
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn(
                    "CWE-640", {finding.get("cwe") for finding in result["findings"]}
                )

    def test_invalid_credential_contract_is_fail_open_authentication(self):
        for kind in ("provision", "load", "verify"):
            with self.subTest(kind=kind):
                facts = _facts()
                facts["credential_events"] = [{
                    "kind": kind,
                    "contract_status": "invalid",
                    "failure_mode": "open",
                    "dominates_all_paths": True,
                    "protects_op_ids": [],
                    "confidence": "high",
                    "evidence": "credential errors can equal accepted credentials",
                }]

                result = classify(facts)

                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertEqual("FAIL_OPEN_AUTHENTICATION", result["findings"][0]["kind"])
                self.assertEqual("CWE-287", result["findings"][0]["cwe"])

    def test_valid_fail_closed_credential_contract_is_safe(self):
        for kind in ("provision", "load", "verify"):
            with self.subTest(kind=kind):
                facts = _facts()
                facts["credential_events"] = [{
                    "kind": kind,
                    "contract_status": "valid",
                    "failure_mode": "closed",
                    "dominates_all_paths": True,
                    "protects_op_ids": [],
                    "confidence": "high",
                    "evidence": "credential errors are rejected before comparison",
                }]

                self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_non_dominating_local_authentication_gate_is_not_discharged_by_caller(self):
        authentication = _authentication("genuine")
        authentication["dominates_all_paths"] = False
        authentication["protects_op_ids"] = ["op1"]
        facts = _facts(operations=[_operation()], authentication=[authentication])

        result = classify(
            facts,
            is_entrypoint=False,
            propagated_contexts=[{"authenticated": True, "strength": "genuine"}],
        )

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("MISSING_AUTHENTICATION", result["findings"][0]["kind"])

    def test_retiring_session_key_to_reusable_value_is_session_fixation(self):
        facts = _facts()
        facts["session_key_events"] = [{
            "kind": "retire",
            "replacement": "reusable_value",
            "storage_cleared": True,
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "session key is replaced with a shared fixed value",
        }]

        result = classify(facts)

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("SESSION_FIXATION", result["findings"][0]["kind"])
        self.assertEqual("CWE-384", result["findings"][0]["cwe"])

    def test_retiring_session_key_to_absent_state_is_safe(self):
        facts = _facts()
        facts["session_key_events"] = [{
            "kind": "retire",
            "replacement": "absent",
            "storage_cleared": True,
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "session key is cleared so the next use generates a new key",
        }]

        self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_valid_session_retirement_discharges_its_cleanup_operation(self):
        facts = _facts(operations=[_operation()])
        facts["obligations"] = [{
            "requires_nl": "caller owns the session being retired",
            "reason": "cleanup operation is invoked by the session framework",
        }]
        facts["session_key_events"] = [{
            "kind": "retire",
            "replacement": "absent",
            "storage_cleared": True,
            "dominates_all_paths": True,
            "protects_op_ids": ["op1"],
            "confidence": "high",
            "evidence": "delete old state and make the key absent",
        }]

        self.assertEqual(SAFE, classify(facts)["verdict"])

    def test_parser_distinguishes_reusable_empty_and_absent_session_keys(self):
        vulnerable = (
            "    def target(self):\n"
            "        self.clear()\n"
            "        self.delete(self.session_key)\n"
            "        self._session_key = ''"
        )
        facts = _facts(operations=[_operation("delete_session")])
        facts["protected_operations"][0]["evidence"] = "self.delete(self.session_key)"

        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["session_key_events"][0]
        self.assertEqual("reusable_value", event["replacement"])
        result = classify(parsed.payload)
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertIn("CWE-384", {finding.get("cwe") for finding in result["findings"]})

        facts_without_operation = _facts()
        facts_without_operation["session_key_events"] = [{
            "kind": "retire",
            "replacement": "fresh_random",
            "storage_cleared": True,
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "incorrect model label",
        }]
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(vulnerable, []),
            "[AUTHN_JSON]" + json.dumps(facts_without_operation) + "[/AUTHN_JSON]",
        )

        self.assertEqual(
            "reusable_value", parsed.payload["session_key_events"][0]["replacement"]
        )
        self.assertIn(
            "CWE-384",
            {finding.get("cwe") for finding in classify(parsed.payload)["findings"]},
        )

        fixed = vulnerable.replace("self._session_key = ''", "self._session_key = None")
        facts["session_key_events"] = [{
            "kind": "retire",
            "replacement": "reusable_value",
            "storage_cleared": False,
            "dominates_all_paths": True,
            "protects_op_ids": ["delete_session"],
            "confidence": "low",
            "evidence": "incorrect model label",
        }]
        parsed = AuthnPlugin().parse_abstraction_response(
            _request_with_related(fixed, []),
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        event = parsed.payload["session_key_events"][0]
        self.assertEqual("absent", event["replacement"])
        self.assertEqual(SAFE, classify(parsed.payload)["verdict"])

    def test_parser_proves_complete_session_retirement_from_source_order(self):
        def parse(source, *, model_claims_client_trust=False):
            facts = _facts(sessions=([{
                "kind": "trust_client_id",
                "evidence": "model claims the retired identifier came from the client",
            }] if model_claims_client_trust else []))
            facts["session_key_events"] = [{
                "kind": "retire",
                "replacement": "reusable_value",
                "storage_cleared": False,
                "dominates_all_paths": True,
                "protects_op_ids": [],
                "confidence": "low",
                "evidence": "model retirement claim",
            }]
            parsed = AuthnPlugin().parse_abstraction_response(
                _request_with_related(source, []),
                "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
            )
            self.assertIsNotNone(parsed)
            return parsed.payload

        complete = parse(
            "def retire_state(self):\n"
            "    self.clear()\n"
            "    self.delete(self.session_key)\n"
            "    self._session_key = None\n",
            model_claims_client_trust=True,
        )
        self.assertEqual([], [
            event for event in complete["session_events"]
            if event["kind"] == "trust_client_id"
        ])
        self.assertEqual(SAFE, classify(complete)["verdict"])

        controls = {
            "empty-string sentinel reuse": (
                "def retire_state(self):\n"
                "    self.clear()\n"
                "    self.delete(self.session_key)\n"
                "    self._session_key = ''\n"
            ),
            "client-provided replacement": (
                "def retire_state(self, replacement):\n"
                "    self.clear()\n"
                "    self.delete(self.session_key)\n"
                "    self._session_key = replacement\n"
            ),
            "missing authoritative storage clear": (
                "def retire_state(self):\n"
                "    self.clear()\n"
                "    self._session_key = None\n"
            ),
            "reassignment after invalidation": (
                "def retire_state(self, replacement):\n"
                "    self.clear()\n"
                "    self.delete(self.session_key)\n"
                "    self._session_key = None\n"
                "    self._session_key = replacement\n"
            ),
        }
        for name, source in controls.items():
            with self.subTest(name=name):
                result = classify(parse(source))
                self.assertEqual(VULNERABLE, result["verdict"])
                self.assertIn(
                    "CWE-384", {finding.get("cwe") for finding in result["findings"]}
                )

    def test_prompt_distinguishes_bearer_tokens_and_fail_open_sentinels(self):
        prompt = _system_prompt("python")

        self.assertNotIn("establish (login creates a session/token)", prompt)
        self.assertIn("binary mode with an encoding argument", prompt)
        self.assertIn("error sentinel", prompt)
        self.assertIn("text mode with an encoding argument is valid", prompt)
        self.assertIn("third positional argument to Python open", prompt)

    def test_malformed_guard_facts_are_error_not_safe(self):
        facts = _facts()
        facts["recovery_events"] = [{"kind": "select_account", "binding": "magic"}]

        self.assertEqual(ERROR, classify(facts)["verdict"])

    def test_string_protected_operation_ids_are_rejected_fail_closed(self):
        facts = _facts()
        facts["credential_events"] = [{
            "kind": "verify",
            "contract_status": "valid",
            "failure_mode": "closed",
            "dominates_all_paths": True,
            "protects_op_ids": "op1",
            "confidence": "high",
            "evidence": "verify shared authenticator",
        }]

        self.assertEqual(ERROR, classify(facts)["verdict"])

    def test_parser_rejects_non_object_payload(self):
        parsed = AuthnPlugin().parse_abstraction_response(
            _request(),
            "[AUTHN_JSON][][/AUTHN_JSON]",
        )

        self.assertIsNone(parsed)

    def test_plugin_finding_carries_expected_cwe(self):
        facts = _facts()
        facts["credential_events"] = [{
            "kind": "verify",
            "contract_status": "invalid",
            "failure_mode": "open",
            "dominates_all_paths": True,
            "protects_op_ids": [],
            "confidence": "high",
            "evidence": "failure marker is accepted as a credential",
        }]
        request = _request()
        envelope = AuthnPlugin().parse_abstraction_response(
            request,
            "[AUTHN_JSON]" + json.dumps(facts) + "[/AUTHN_JSON]",
        )

        verdict = AuthnPlugin().check(envelope, request.context)

        self.assertEqual("CWE-287", verdict.findings[0].data["cwe"])


if __name__ == "__main__":
    unittest.main()
