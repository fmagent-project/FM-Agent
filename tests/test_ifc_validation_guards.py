import json
import inspect
import unittest

from src.ifc_reasoner import HIGH, LOW, classify
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
from src.plugins.ifc import IfcPlugin, _order_bottom_up_all
from src import ifc_validation


def _request(source, name="target", rel="sample-py/target.py", entrypoint=True):
    function_id = FunctionId(rel, name, name, "python")
    unit = FunctionUnit(function_id, source, source.splitlines()[0])
    program = ProgramIndex(
        functions={function_id: unit},
        calls_by_caller={function_id: []},
        callers_by_callee={function_id: []},
        entrypoints=[function_id] if entrypoint else [],
    )
    return AbstractionRequest(unit, DriverContext(program, unit, entrypoint))


def _parse(source, payload, name="target"):
    response = "[FLOW_JSON]" + json.dumps(payload) + "[/FLOW_JSON]"
    return IfcPlugin().parse_abstraction_response(_request(source, name), response)


def _empty_signature():
    return {"inputs": {}, "outputs": {}, "notes": ""}


class IfcLegacyCharacterizationTests(unittest.TestCase):
    def test_legacy_log_channel_remains_fail_closed_external(self):
        signature = {
            "inputs": {"param:secret": HIGH},
            "outputs": {"io:log": {"deps": ["param:secret"], "const": None}},
        }

        result = classify(signature, is_entrypoint=False)

        self.assertEqual("LEAK", result["verdict"])

    def test_legacy_internal_return_is_propagation_only(self):
        signature = {
            "inputs": {"param:secret": HIGH},
            "outputs": {"return": {"deps": ["param:secret"], "const": None}},
        }

        result = classify(signature, is_entrypoint=False)

        self.assertEqual("SECURE", result["verdict"])

    def test_declassification_requires_an_explicit_high_source(self):
        proposed = [{"anchor": "publish(detail)", "reason": "operator output"}]
        unknown = {
            "inputs": {"receiver.detail": "Unknown"},
            "outputs": {"io:stdout": {
                "deps": ["receiver.detail"], "const": None, "declass": proposed,
            }},
        }
        confirmed = {
            "inputs": {"receiver.detail": HIGH},
            "outputs": {"io:stdout": {
                "deps": ["receiver.detail"], "const": None, "declass": proposed,
            }},
        }

        self.assertEqual("SECURE", classify(unknown)["verdict"])
        self.assertEqual("DECLASSIFIED", classify(confirmed)["verdict"])


class IfcExternalObservabilityTests(unittest.TestCase):
    def test_conventional_low_receiver_name_overrides_model_unknown(self):
        source = """def exact(self):
    if failed:
        self.fail(self.name)
"""
        facts = _parse(source, {
            "inputs": {"receiver.name": "Unknown"},
            "outputs": {"exception:message": {
                "deps": ["receiver.name"],
                "const": None,
                "sink_channel": "exception_message",
                "observability": "external",
            }},
            "notes": "",
        }, "exact")

        self.assertEqual(LOW, facts.payload["inputs"]["receiver.name"])
        self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_called_receiver_method_is_not_secret_data(self):
        source = """def main(self):
    value = self._is_present()
    return value
"""
        facts = _parse(source, {
            "inputs": {"receiver._is_present": "Unknown"},
            "outputs": {"return": {
                "deps": ["receiver._is_present"],
                "const": None,
                "sink_channel": "return",
                "observability": "caller",
            }},
            "notes": "",
        }, "main")

        self.assertEqual(LOW, facts.payload["inputs"]["receiver._is_present"])
        self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_model_container_alias_requires_real_sink_dependency(self):
        vulnerable = """def main():
    module.params.update(module.params['params'])
"""
        fixed = """def main():
    if 'api_secret' in module.params['params']:
        module.fail_json(msg='sensitive options are not accepted')
    module.params.update(module.params['params'])
"""
        payload = {
            "inputs": {"param:params": LOW},
            "outputs": {
                "return": {
                    "deps": ["param:params"],
                    "const": None,
                    "sink_channel": "return",
                    "observability": "caller",
                },
                "error:result": {
                    "deps": ["param:params"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                },
            },
            "notes": "",
        }

        vulnerable_facts = _parse(vulnerable, payload, "main")
        fixed_facts = _parse(fixed, payload, "main")

        self.assertTrue(any(
            source.endswith(".<sensitive>")
            for source in vulnerable_facts.payload["inputs"]
        ))
        vulnerable_result = classify(vulnerable_facts.payload)
        self.assertEqual("LEAK", vulnerable_result["verdict"])
        self.assertEqual(
            {"CWE-200"}, {item["cwe"] for item in vulnerable_result["violations"]}
        )
        self.assertEqual("SECURE", classify(fixed_facts.payload)["verdict"])

    def test_schema_declared_non_sensitive_parameter_is_low(self):
        source = """def main():
    module = Module(argument_spec=spec(values=dict(type='raw'), params=dict(type='dict')))
    if 'api_secret' in module.params['params']:
        module.fail_json(msg='sensitive options are not accepted')
    module.params.update(module.params['params'])
    module.exit_json(values=module.params['values'])
"""
        facts = _parse(source, {
            "inputs": {"param:values": "Unknown", "param:params": LOW},
            "outputs": {"return": {
                "deps": ["param:values", "param:params"],
                "const": None,
                "sink_channel": "return",
                "observability": "caller",
            }},
            "notes": "",
        }, "main")

        self.assertEqual(LOW, facts.payload["inputs"]["param:values"])
        self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_nested_merge_without_sink_does_not_invent_external_flow(self):
        source = """def merge(options):
    options.update(options['extra'])
"""

        facts = _parse(source, _empty_signature(), "merge")
        unrelated = _parse(source, {
            "inputs": {"param:status": LOW},
            "outputs": {"io:log": {
                "deps": ["param:status"],
                "const": None,
                "sink_channel": "log",
                "observability": "external",
            }},
            "notes": "",
        }, "merge")
        fallback = IfcPlugin().make_error_facts(_request(source, "merge"), "bad JSON")

        self.assertEqual({}, facts.payload["inputs"])
        self.assertEqual({}, facts.payload["outputs"])
        self.assertFalse(any(
            source.endswith(".<sensitive>") for source in unrelated.payload["inputs"]
        ))
        self.assertEqual(["param:status"], unrelated.payload["outputs"]["io:log"]["deps"])
        self.assertEqual("SECURE", classify(unrelated.payload)["verdict"])
        self.assertEqual("error", fallback.status)

    def test_nested_merge_with_explicit_stdout_flow_is_enriched(self):
        source = """def merge(options):
    options.update(options['extra'])
    print(options)
"""

        facts = _parse(source, _empty_signature(), "merge")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertEqual({"io:stdout"}, set(facts.payload["outputs"]))

    def test_source_logger_does_not_invent_or_reclassify_log_sink(self):
        source = """def handle(error):
    logger.error('failed: %s', error)
"""
        empty = _parse(source, _empty_signature(), "handle")
        external = _parse(source, {
            "inputs": {"param:error": HIGH},
            "outputs": {"io:log": {
                "deps": ["param:error"],
                "const": None,
                "sink_channel": "log",
                "observability": "external",
            }},
        }, "handle")

        self.assertNotIn("io:log", empty.payload["outputs"])
        self.assertEqual(
            "external", external.payload["outputs"]["io:log"]["observability"]
        )
        self.assertEqual("LEAK", classify(external.payload)["verdict"])

    def test_local_persistence_session_is_internal_not_external(self):
        source = """def save(self, item):
    self.session.add(item)
    self.session.commit()
    return True
"""
        payload = {
            "inputs": {"param:item": "Unknown"},
            "outputs": {"database": {
                "deps": ["param:item"],
                "const": None,
                "sink_channel": "database",
                "observability": "external",
            }},
        }

        facts = _parse(source, payload, "save")

        self.assertEqual("internal", facts.payload["outputs"]["database"]["observability"])
        self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_indented_extracted_method_preserves_external_error_detail(self):
        source = """    def save(self, record):
        try:
            self.store.commit(record)
        except Exception as failure:
            self.notice = ('Save failed: ' + str(failure), 'danger')
            logger.exception('save failed: %s', failure)
            return False
"""

        facts = _parse(source, {
            "inputs": {},
            "outputs": {"io:log": {
                "deps": [], "const": None,
                "sink_channel": "log", "observability": "internal",
            }},
            "notes": "",
        }, "save")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertEqual("CWE-209", result["violations"][0]["cwe"])
        self.assertEqual("internal", facts.payload["outputs"]["io:log"]["observability"])

    def test_nested_sensitive_option_bypass_is_enriched_to_log_and_stdout_leaks(self):
        source = """def main():
    module = AnsibleModule(argument_spec=gen_specs(params=dict(type='dict')))
    if isinstance(module.params['params'], dict):
        module.params.update(module.params['params'])
    module.exit_json(changed=False)
"""

        facts = _parse(source, {
            "inputs": {},
            "outputs": {
                "io:log": {
                    "deps": ["param:module.params"], "const": None,
                    "sink_channel": "log", "observability": "external",
                },
                "io:stdout": {
                    "deps": ["param:module.params"], "const": None,
                    "sink_channel": "stdout", "observability": "external",
                },
            },
            "notes": "",
        }, "main")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        sources = [
            source for source, label in facts.payload["inputs"].items()
            if source.endswith(".<sensitive>") and label == HIGH
        ]
        self.assertEqual(["param:module.params.params.<sensitive>"], sources)
        self.assertEqual(
            {"io:log", "io:stdout"},
            {violation["channel"] for violation in result["violations"]},
        )
        self.assertEqual(
            {"CWE-200", "CWE-532"},
            {violation["cwe"] for violation in result["violations"]},
        )

    def test_bind_password_rejected_before_merge_has_no_disclosure(self):
        source = """def main():
    module = AnsibleModule(argument_spec=gen_specs(params=dict(type='dict')))
    if module.params['params']:
        if 'bind_pw' in module.params['params']:
            module.fail_json(msg='bind_pw is disallowed')
        module.params.update(module.params['params'])
    module.exit_json(changed=False)
"""

        facts = _parse(source, _empty_signature(), "main")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])
        self.assertNotIn("param:module.params.params.bind_pw", facts.payload["inputs"])

    def test_serialized_module_invocation_normalizes_v12_model_variation(self):
        vulnerable = """def main():
    module = AnsibleModule(
        argument_spec=gen_specs(
            name=dict(type='str', required=True),
            params=dict(type='dict'),
            state=dict(type='str', default='present', choices=['absent', 'exact', 'present']),
            values=dict(type='raw', required=True),
        ),
        supports_check_mode=True,
    )
    if not HAS_LDAP:
        module.fail_json(msg=missing_required_lib('python-ldap'), exception=LDAP_IMP_ERR)
    if 'params' in module.params and isinstance(module.params['params'], dict):
        module.params.update(module.params['params'])
        module.params.pop('params', None)
    ldap = LdapAttr(module)
    state = module.params['state']
    if state == 'present':
        modlist = ldap.add()
    elif state == 'absent':
        modlist = ldap.delete()
    elif state == 'exact':
        modlist = ldap.exact()
    changed = False
    if len(modlist) > 0:
        changed = True
        if not module.check_mode:
            try:
                ldap.connection.modify_s(ldap.dn, modlist)
            except Exception as e:
                module.fail_json(msg='Attribute action failed.', details=to_native(e))
    module.exit_json(changed=changed, modlist=modlist)
"""
        fixed = vulnerable.replace(
            "    if 'params' in module.params and isinstance(module.params['params'], dict):\n"
            "        module.params.update(module.params['params'])\n"
            "        module.params.pop('params', None)",
            "    if LooseVersion(module.ansible_version) < LooseVersion('2.10'):\n"
            "        if module.params['params']:\n"
            "            module.deprecate('params bypasses option handling', version='2.10')\n"
            "            if 'bind_pw' in module.params['params']:\n"
            "                module.fail_json(msg='sensitive option is not accepted')\n"
            "            module.params.update(module.params['params'])\n"
            "            module.params.pop('params', None)\n"
            "    else:\n"
            "        if module.params['params']:\n"
            "            module.fail_json(msg='params option was removed')",
        )
        vulnerable_payload = {
            "inputs": {
                "param:name": LOW,
                "param:params": LOW,
                "param:state": LOW,
                "param:values": LOW,
                "global:HAS_LDAP": LOW,
                "global:LDAP_IMP_ERR": LOW,
            },
            "outputs": {
                "return": {
                    "deps": [
                        "param:state", "param:name", "param:values",
                        "receiver.name", "receiver.values", "receiver.connection",
                    ],
                    "const": LOW,
                    "sink_channel": "return",
                    "observability": "caller",
                },
                "error:module_fail_json_details": {
                    "deps": ["receiver.name", "receiver.values", "receiver.connection"],
                    "const": LOW,
                    "sink_channel": "error_detail",
                    "observability": "external",
                },
            },
            "notes": "model labeled the generic parameters and LDAP values Low",
        }

        vulnerable_facts = _parse(vulnerable, vulnerable_payload, "main")
        fixed_facts = _parse(fixed, vulnerable_payload, "main")
        vulnerable_result = classify(vulnerable_facts.payload)

        self.assertEqual("LEAK", vulnerable_result["verdict"])
        self.assertEqual(
            [("io:stdout", "CWE-200")],
            [(item["channel"], item["cwe"]) for item in vulnerable_result["violations"]],
        )
        self.assertIn(
            "param:module.params.params.<sensitive>",
            vulnerable_facts.payload["inputs"],
        )
        self.assertEqual("SECURE", classify(fixed_facts.payload)["verdict"])

    def test_v14_fixed_module_paths_clear_constant_composed_exception_control(self):
        attr_source = """def main():
    module = AnsibleModule(argument_spec=gen_specs(
        name=dict(type='str', required=True), params=dict(type='dict'),
        state=dict(type='str'), values=dict(type='raw', required=True)))
    if not HAS_LDAP:
        module.fail_json(msg=missing_required_lib('python-ldap'), exception=LDAP_IMP_ERR)
    if LooseVersion(module.ansible_version) < LooseVersion('2.10'):
        if module.params['params']:
            module.deprecate('params bypasses option handling', version='2.10')
            if 'bind_pw' in module.params['params']:
                module.fail_json(msg='sensitive option is not accepted')
            module.params.update(module.params['params'])
            module.params.pop('params', None)
    else:
        if module.params['params']:
            module.fail_json(msg='params option was removed')
    ldap = LdapAttr(module)
    state = module.params['state']
    if state == 'present':
        modlist = ldap.add()
    elif state == 'absent':
        modlist = ldap.delete()
    elif state == 'exact':
        modlist = ldap.exact()
    module.exit_json(changed=bool(modlist), modlist=modlist)
"""
        entry_source = attr_source.replace(
            "name=dict(type='str', required=True), params=dict(type='dict'),\n"
            "        state=dict(type='str'), values=dict(type='raw', required=True)",
            "attributes=dict(default={}, type='dict'), objectClass=dict(type='raw'),\n"
            "        params=dict(type='dict'), state=dict(default='present')",
        ).replace(
            "    ldap = LdapAttr(module)\n"
            "    state = module.params['state']\n"
            "    if state == 'present':\n"
            "        modlist = ldap.add()\n"
            "    elif state == 'absent':\n"
            "        modlist = ldap.delete()\n"
            "    elif state == 'exact':\n"
            "        modlist = ldap.exact()\n"
            "    module.exit_json(changed=bool(modlist), modlist=modlist)",
            "    state = module.params['state']\n"
            "    if state == 'present' and module.params['objectClass'] is None:\n"
            "        module.fail_json(msg='objectClass is required')\n"
            "    ldap = LdapEntry(module)\n"
            "    if state == 'present':\n"
            "        action = ldap.add()\n"
            "    elif state == 'absent':\n"
            "        action = ldap.delete()\n"
            "    module.exit_json(changed=(action is not None))",
        )
        cases = (
            (attr_source, {
                "inputs": {
                    "receiver.ansible_version": LOW,
                    "receiver.params": LOW,
                    "receiver.check_mode": LOW,
                },
                "outputs": {
                    "return": {
                        "deps": ["receiver.params", "receiver.ansible_version"],
                        "const": None, "sink_channel": "return", "observability": "caller",
                    },
                    "io:deprecate": {
                        "deps": ["receiver.params"], "const": None,
                        "sink_channel": "log", "observability": "internal",
                    },
                    "io:stdout": {
                        "deps": [], "const": None,
                        "sink_channel": "stdout", "observability": "external",
                    },
                    "callee:add:candidate-3:exception:control": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "exception_control", "observability": "caller",
                    },
                    "callee:delete:candidate-4:exception:control": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "exception_control", "observability": "caller",
                    },
                },
                "_callee_resolutions": [{"callee": "add"}],
            }),
            (entry_source, {
                "inputs": {
                    "param:attributes": LOW,
                    "param:objectClass": LOW,
                    "param:params": LOW,
                    "param:state": LOW,
                    "receiver.ansible_version": LOW,
                    "receiver.params": LOW,
                },
                "outputs": {
                    "return": {
                        "deps": ["receiver.params"], "const": None,
                        "sink_channel": "return", "observability": "caller",
                    },
                    "io:stdout": {
                        "deps": [], "const": None,
                        "sink_channel": "stdout", "observability": "external",
                    },
                    "callee:add:candidate-2:exception:control": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "exception_control", "observability": "caller",
                    },
                    "callee:delete:candidate-3:exception:control": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "exception_control", "observability": "caller",
                    },
                },
                "_callee_resolutions": [{"callee": "add"}],
            }),
        )

        for source, payload in cases:
            with self.subTest(module="entry" if "LdapEntry" in source else "attr"):
                request = _request(source, "main")
                facts = FactEnvelope(
                    "ifc", "ifc.flow_signature.v2", request.function.id, "ok", payload
                )

                verdict = IfcPlugin().check(facts, request.context)

                self.assertEqual("SECURE", verdict.verdict)
                composed = [
                    spec for channel, spec in facts.payload["outputs"].items()
                    if channel.startswith("callee:")
                ]
                self.assertTrue(composed)
                self.assertTrue(all(spec["const"] == LOW for spec in composed))

    def test_partial_sensitive_resolution_preserves_unresolved_external_flow(self):
        source = """def configure(module):
    if 'api_secret' in module.params['extra']:
        module.fail_json(msg='api_secret is not accepted')
    module.params.update(module.params['extra'])
    module.exit_json(changed=False)
"""
        payload = {
            "inputs": {
                "param:module.params.extra.api_secret": HIGH,
                "param:module.params.extra.access_token": HIGH,
            },
            "outputs": {},
        }

        facts = _parse(source, payload, "configure")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertNotIn("param:module.params.extra.api_secret", facts.payload["inputs"])
        self.assertEqual(
            ["param:module.params.extra.access_token"],
            facts.payload["outputs"]["io:stdout"]["deps"],
        )

    def test_non_dominating_or_nonconstant_redaction_does_not_suppress_leak(self):
        variants = (
            """def configure(module, redact):
    if redact:
        module.params['extra'].pop('api_secret', None)
    module.params.update(module.params['extra'])
    module.exit_json(changed=False)
""",
            """def configure(module):
    module.params.update(module.params['extra'])
    module.params['extra']['api_secret'] = None
    module.exit_json(changed=False)
""",
            """def configure(module):
    module.params['extra']['api_secret'] = sanitize(module.params['extra']['api_secret'])
    module.params.update(module.params['extra'])
    module.exit_json(changed=False)
""",
            """def configure(module):
    module.params['extra'].pop('access_token', None)
    module.params.update(module.params['extra'])
    module.exit_json(changed=False)
""",
        )
        payload = {
            "inputs": {"param:module.params.extra.api_secret": HIGH},
            "outputs": {},
        }

        for source in variants:
            with self.subTest(source=source):
                facts = _parse(source, payload, "configure")
                self.assertEqual("LEAK", classify(facts.payload)["verdict"])

    def test_serialized_invocation_does_not_change_internal_or_caller_observability(self):
        source = """def configure(options):
    options.update(options['extra'])
    audit.info(options)
    return options
"""
        payload = {
            "inputs": {"param:options.extra": LOW},
            "outputs": {
                "io:audit": {
                    "deps": ["param:options.extra"],
                    "const": None,
                    "sink_channel": "log",
                    "observability": "internal",
                },
                "return": {
                    "deps": ["param:options.extra"],
                    "const": None,
                    "sink_channel": "return",
                    "observability": "caller",
                },
            },
        }

        facts = _parse(source, payload, "configure")

        self.assertEqual("SECURE", classify(facts.payload, is_entrypoint=False)["verdict"])
        self.assertEqual("internal", facts.payload["outputs"]["io:audit"]["observability"])
        self.assertEqual("caller", facts.payload["outputs"]["return"]["observability"])

    def test_unrelated_json_emitter_is_not_an_implicit_module_sink(self):
        source = """def configure(options, reporter):
    options.update(options['extra'])
    reporter.exit_json(changed=False)
"""

        facts = _parse(source, _empty_signature(), "configure")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertEqual({}, facts.payload["outputs"])

    def test_removed_or_redacted_sensitive_field_blocks_serialized_invocation(self):
        variants = (
            "module.params['params'].pop('api_secret', None)",
            "module.params['params']['api_secret'] = None",
            "del module.params['params']['api_secret']",
        )
        for protection in variants:
            with self.subTest(protection=protection):
                source = f"""def configure(module):
    {protection}
    module.params.update(module.params['params'])
    module.exit_json(changed=False)
"""
                facts = _parse(source, _empty_signature(), "configure")

                self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_rejected_sensitive_nested_field_clears_misleading_external_flow(self):
        source = """def configure():
    if options['extra']:
        if 'api_secret' in options['extra']:
            abort_publicly('sensitive options are not accepted')
        options.update(options['extra'])
"""
        payload = {
            "inputs": {"param:options.extra.api_secret": HIGH},
            "outputs": {
                "error:rejection": {
                    "deps": ["param:options.extra.api_secret"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                }
            },
        }

        facts = _parse(source, payload, "configure")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])
        self.assertNotIn("param:options.extra.api_secret", facts.payload["inputs"])

    def test_nested_secret_rejection_must_dominate_merge_on_every_path(self):
        payload = {
            "inputs": {
                "param:options['extra']['api_secret']": HIGH,
                "param:options['extra']": LOW,
                "receiver.transform": "Unknown",
            },
            "outputs": {
                "io:publish": {
                    "deps": [
                        "param:options['extra']['api_secret']",
                        "param:options['extra']",
                        "receiver.transform",
                    ],
                    "const": None,
                    "sink_channel": "stdout",
                    "observability": "external",
                },
            },
        }
        sources = {
            "dominating": """def configure():
    if 'api_secret' in options['extra']:
        reject_request('sensitive option is not accepted')
    options.update(options['extra'])
    publish(options)
""",
            "missing": """def configure():
    options.update(options['extra'])
    publish(options)
""",
            "after_merge": """def configure():
    options.update(options['extra'])
    if 'api_secret' in options['extra']:
        reject_request('sensitive option is not accepted')
    publish(options)
""",
            "partial_branch": """def configure(enforce):
    if enforce:
        if 'api_secret' in options['extra']:
            reject_request('sensitive option is not accepted')
    options.update(options['extra'])
    publish(options)
""",
        }

        for helper_label in (LOW, "Unknown"):
            with self.subTest(guard="dominating", helper_label=helper_label):
                payload["inputs"]["receiver.transform"] = helper_label
                facts = _parse(sources["dominating"], payload, "configure")
                self.assertEqual("SECURE", classify(facts.payload)["verdict"])

        payload["inputs"]["receiver.transform"] = "Unknown"
        for guard in ("missing", "after_merge", "partial_branch"):
            with self.subTest(guard=guard):
                facts = _parse(sources[guard], payload, "configure")
                self.assertEqual("LEAK", classify(facts.payload)["verdict"])

    def test_rejected_sensitive_field_clears_model_declassification_review(self):
        source = """def configure():
    if options['extra']:
        if 'api_secret' in options['extra']:
            abort_publicly('sensitive options are not accepted')
        options.update(options['extra'])
"""
        payload = {
            "inputs": {"param:options.extra": "Unknown"},
            "outputs": {
                "error:rejection": {
                    "deps": ["param:options.extra"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                    "declass": [{
                        "anchor": "reject api_secret in extra options",
                        "reason": "report validation failure",
                    }],
                }
            },
        }

        facts = _parse(source, payload, "configure")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertEqual([], facts.payload["outputs"]["error:rejection"]["declass"])

    def test_rejected_sensitive_field_clears_unknown_only_error_guess(self):
        source = """def configure():
    if 'api_secret' in options['extra']:
        abort_publicly('sensitive options are not accepted')
    options.update(options['extra'])
"""
        payload = {
            "inputs": {"receiver.abort": "Unknown", "receiver.connection": "Unknown"},
            "outputs": {
                "error:guessed": {
                    "deps": ["receiver.abort", "receiver.connection"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                }
            },
        }

        facts = _parse(source, payload, "configure")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertEqual([], facts.payload["outputs"]["error:guessed"]["deps"])

    def test_rejected_sensitive_field_clears_constant_high_error_guess(self):
        source = """def configure():
    if 'api_secret' in options['extra']:
        abort_publicly('sensitive options are not accepted')
    options.update(options['extra'])
"""
        payload = {
            "inputs": {},
            "outputs": {
                "error:guessed": {
                    "deps": [],
                    "const": HIGH,
                    "sink_channel": "error_detail",
                    "observability": "external",
                }
            },
        }

        facts = _parse(source, payload, "configure")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertEqual(LOW, facts.payload["outputs"]["error:guessed"]["const"])

    def test_nested_mapping_iteration_is_an_external_serialization_bypass(self):
        source = """def configure():
    for key, value in options['extra'].items():
        if key in known_options:
            options[key] = value
        else:
            attributes[key] = value
    publish_result(changed=True)
"""

        facts = _parse(source, {
            "inputs": {},
            "outputs": {"io:stdout": {
                "deps": ["param:options.extra"], "const": None,
                "sink_channel": "stdout", "observability": "external",
            }},
            "notes": "",
        }, "configure")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertIn("param:options.extra.<sensitive>", facts.payload["inputs"])

    def test_domain_mapping_iteration_is_not_a_registration_bypass(self):
        source = """def normalize(record):
    normalized = {}
    for key, value in record['attributes'].items():
        normalized[key] = encode(value)
    return normalized
"""

        facts = _parse(source, _empty_signature(), "normalize")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertFalse(any(name.endswith(".<sensitive>") for name in facts.payload["inputs"]))

    def test_guarded_source_overrides_misleading_rejected_field_facts(self):
        source = """def main():
    module = AnsibleModule(argument_spec=gen_specs(params=dict(type='dict')))
    if module.params['params']:
        if 'bind_pw' in module.params['params']:
            module.fail_json(msg='bind_pw is disallowed')
        module.params.update(module.params['params'])
    module.exit_json(changed=False)
"""
        payload = {
            "inputs": {
                "param:module.params.params.bind_pw": HIGH,
            },
            "outputs": {
                "error:dynamic": {
                    "deps": ["param:module.params.params.bind_pw"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                },
            },
        }

        facts = _parse(source, payload, "main")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])
        self.assertNotIn("param:module.params.params.bind_pw", facts.payload["inputs"])

    def test_guard_removes_rejected_field_missing_from_model_inputs(self):
        source = """def main():
    if 'api_secret' in module.params['params']:
        module.fail_json(msg='sensitive options are not accepted')
    module.params.update(module.params['params'])
"""
        facts = _parse(source, {
            "inputs": {"param:params": LOW},
            "outputs": {"return": {
                "deps": ["param:params.api_secret", "param:params"],
                "const": None,
                "sink_channel": "return",
                "observability": "caller",
            }},
            "notes": "",
        }, "main")

        self.assertEqual("SECURE", classify(facts.payload)["verdict"])
        self.assertEqual(["param:params"], facts.payload["outputs"]["return"]["deps"])

    def test_guard_removes_embedded_rejected_field_alias(self):
        source = """def main():
    if 'api_secret' in module.params['params']:
        module.fail_json(msg='sensitive options are not accepted')
    module.params.update(module.params['params'])
"""
        facts = _parse(source, {
            "inputs": {"receiver.api_secret_in_options": HIGH},
            "outputs": {"exception:message": {
                "deps": ["receiver.api_secret_in_options"],
                "const": None,
                "sink_channel": "exception_message",
                "observability": "caller",
            }},
            "notes": "",
        }, "main")

        self.assertNotIn("receiver.api_secret_in_options", facts.payload["inputs"])
        self.assertEqual("SECURE", classify(facts.payload)["verdict"])

    def test_external_database_error_detail_is_cwe_209(self):
        source = """def edit(self, item):
    try:
        self.session.merge(item)
    except Exception as e:
        self.message = (str(sys.exc_info()[0]), 'danger')
        log.exception('Database failure: %s', str(e))
        return False
"""

        facts = _parse(source, {
            "inputs": {},
            "outputs": {"io:log": {
                "deps": [], "const": None,
                "sink_channel": "log", "observability": "internal",
            }},
            "notes": "",
        }, "edit")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        external = next(v for v in result["violations"] if v["channel"] == "error:self.message")
        self.assertEqual("CWE-209", external["cwe"])
        self.assertEqual("external", facts.payload["outputs"]["error:self.message"]["observability"])
        self.assertEqual("internal", facts.payload["outputs"]["io:log"]["observability"])

    def test_internal_detailed_exception_log_alone_is_not_public(self):
        source = """def edit(self, item):
    try:
        self.session.merge(item)
    except Exception as e:
        self.message = ('Database Error', 'danger')
        log.exception('Database failure: %s', str(e))
        return False
"""

        facts = _parse(source, {
            "inputs": {},
            "outputs": {"io:log": {
                "deps": [], "const": None,
                "sink_channel": "log", "observability": "internal",
            }},
            "notes": "",
        }, "edit")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])
        self.assertEqual("internal", facts.payload["outputs"]["io:log"]["observability"])

    def test_generic_external_db_message_overrides_misleading_error_facts(self):
        source = """def edit(self, item):
    try:
        self.session.merge(item)
    except Exception as e:
        self.message = ('Database Error', 'danger')
        log.exception('Database error')
        return False
"""
        payload = {
            "inputs": {"caught:e": HIGH},
            "outputs": {
                "error:guessed": {
                    "deps": ["caught:e"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                },
                "exception": {
                    "deps": ["caught:e"],
                    "const": None,
                    "sink_channel": "exception_control",
                    "observability": "external",
                },
            },
        }

        facts = _parse(source, payload, "edit")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])

    def test_generic_method_messages_and_constant_returns_override_model_noise(self):
        source = """def add(self, item, raise_exception=False):
    try:
        self.session.add(item)
        self.message = (self.success_message, 'success')
        return True
    except Exception as error:
        self.message = (self.database_error_message, 'danger')
        if raise_exception:
            raise error
        return False
"""
        request = _request(source, "add")
        facts = _parse(source, {
            "inputs": {"param:item": "Unknown", "receiver.session": LOW},
            "outputs": {
                "return": {
                    "deps": ["param:item", "receiver.session"],
                    "const": None,
                    "sink_channel": "return",
                    "observability": "caller",
                },
                "error:<self.message>": {
                    "deps": ["param:item"],
                    "const": None,
                    "sink_channel": "shared_state",
                    "observability": "external",
                },
                "exception:message": {
                    "deps": ["param:item", "receiver.session"],
                    "const": None,
                    "sink_channel": "exception_message",
                    "observability": "caller",
                },
            },
            "notes": "",
        }, "add")

        verdict = IfcPlugin().check(facts, request.context)

        self.assertEqual("SECURE", verdict.verdict)
        self.assertEqual([], facts.payload["outputs"]["return"]["deps"])
        self.assertNotIn("error:<self.message>", facts.payload["outputs"])

    def test_catching_exception_does_not_clear_external_detail(self):
        signature = {
            "inputs": {"caught:error": HIGH},
            "outputs": {
                "error:response": {
                    "deps": ["caught:error"],
                    "const": None,
                    "sink_channel": "error_detail",
                    "observability": "external",
                }
            },
        }

        result = classify(signature, is_entrypoint=False)

        self.assertEqual("LEAK", result["verdict"])
        self.assertEqual("CWE-209", result["violations"][0]["cwe"])

    def test_internal_observability_overrides_log_channel_name(self):
        signature = {
            "inputs": {"caught:error": HIGH},
            "outputs": {
                "io:log": {
                    "deps": ["caught:error"],
                    "const": None,
                    "sink_channel": "log",
                    "observability": "internal",
                }
            },
        }

        result = classify(signature)

        self.assertEqual("SECURE", result["verdict"])

    def test_caller_observability_only_crosses_boundary_at_entrypoint(self):
        signature = {
            "inputs": {"caught:error": HIGH},
            "outputs": {
                "exception:message": {
                    "deps": ["caught:error"],
                    "const": None,
                    "sink_channel": "exception_message",
                    "observability": "caller",
                }
            },
        }

        internal = classify(signature, is_entrypoint=False)
        boundary = classify(signature, is_entrypoint=True)

        self.assertEqual("SECURE", internal["verdict"])
        self.assertEqual("LEAK", boundary["verdict"])


class IfcMistralExceptionTests(unittest.TestCase):
    def test_raised_error_detail_stays_caller_only_inside_helper(self):
        source = """def helper(error):
    raise InternalFailure(str(error))
"""

        facts = _parse(source, _empty_signature(), "helper")
        result = classify(facts.payload, is_entrypoint=False)

        self.assertEqual(
            "caller", facts.payload["outputs"]["exception:message"]["observability"]
        )
        self.assertEqual("SECURE", result["verdict"])

    def test_indented_custom_exception_detail_is_external_without_class_special_case(self):
        source = """    def dispatch(self):
        def fail(cause=None):
            text = 'operation failed'
            if cause:
                text += ': %s' % str(cause)
            raise ClientVisibleFailure(text)
        try:
            execute()
        except Exception as failure:
            return fail(cause=failure)
"""

        facts = _parse(source, _empty_signature(), "dispatch")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertEqual("CWE-200", result["violations"][0]["cwe"])
        self.assertEqual(
            "caller", facts.payload["outputs"]["exception:message"]["observability"]
        )

    def test_ifc_validation_contains_no_fixture_or_cve_names(self):
        implementation = inspect.getsource(ifc_validation)

        self.assertNotIn("bind_pw", implementation)
        self.assertNotIn("ActionException", implementation)
        self.assertNotIn("CVE-", implementation)

    def test_parent_exception_detail_in_action_exception_is_external(self):
        source = """def run(self, context):
    def raise_exc(parent_exc=None):
        message = 'Failed to execute ssh cmd'
        if parent_exc:
            message += '\\nException: %s' % str(parent_exc)
        raise exc.ActionException(message)
    try:
        execute()
    except Exception as e:
        return raise_exc(parent_exc=e)
"""

        facts = _parse(source, _empty_signature(), "run_6")
        result = classify(facts.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertEqual("CWE-200", result["violations"][0]["cwe"])
        self.assertEqual("exception:message", result["violations"][0]["channel"])

    def test_generic_action_exception_with_detailed_internal_log_is_secure(self):
        source = """def run(self, context):
    def raise_exc(parent_exc=None):
        message = 'Failed to execute ssh cmd'
        if parent_exc:
            LOG.exception(message + ' Exception: %s', str(parent_exc))
        raise exc.ActionException(message)
    try:
        execute()
    except Exception as e:
        return raise_exc(parent_exc=e)
"""

        payload = {
            "inputs": {"caught:error_detail": HIGH},
            "outputs": {
                "exception:message": {
                    "deps": ["caught:error_detail"],
                    "const": None,
                    "sink_channel": "exception_message",
                    "observability": "external",
                },
                "io:log": {
                    "deps": ["caught:error_detail"],
                    "const": None,
                    "sink_channel": "log",
                    "observability": "internal",
                }
            },
        }

        facts = _parse(source, payload, "run_6")
        result = classify(facts.payload)

        self.assertEqual("SECURE", result["verdict"])
        self.assertEqual("internal", facts.payload["outputs"]["io:log"]["observability"])


class IfcCompositionAndValidationTests(unittest.TestCase):
    def test_retry_fallback_handles_generic_method_error_boundary(self):
        source = """def add(self, item, raise_exception=False):
    try:
        self.session.add(item)
        self.message = (self.success_message, 'success')
        return True
    except Exception as error:
        self.message = (self.database_error_message, 'danger')
        if raise_exception:
            raise error
        return False
"""
        request = _request(source, "add")

        facts = IfcPlugin().make_error_facts(request, "bad JSON")
        verdict = IfcPlugin().check(facts, request.context)

        self.assertEqual("ok", facts.status)
        self.assertEqual("SECURE", verdict.verdict)

    def test_assigned_ambiguous_return_is_not_an_external_caller_obligation(self):
        caller_id = FunctionId("caller-py/caller.py", "caller", "caller", "python")
        callee_id = FunctionId("callee-py/load.py", "load", "load", "python")
        caller_unit = FunctionUnit(
            caller_id, "def caller():\n    value = load()\n    return False", "def caller():"
        )
        callee_unit = FunctionUnit(callee_id, "def load():\n    return secret", "def load():")
        call = CallSite(caller_id, callee_id, "load")
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", caller_id, "ok", _empty_signature()
        )
        callee = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", callee_id, "ok",
            {
                "inputs": {},
                "outputs": {"return": {
                    "deps": [], "const": HIGH,
                    "sink_channel": "return", "observability": "caller",
                }},
                "notes": "",
            },
        )
        context = DriverContext(program, caller_unit, True, (), (call,))

        composed = IfcPlugin().compose_calls(
            caller, [ResolvedCall(call, callee)], context
        )

        self.assertEqual("SECURE", classify(composed.payload)["verdict"])

    def test_ambiguous_dynamic_method_dispatch_is_a_caller_boundary(self):
        caller_id = FunctionId("base-py/run.py", "run", "run", "python")
        target_id = FunctionId("action-py/run.py", "run_6", "run", "python")
        other_id = FunctionId("other-py/run.py", "run_7", "run", "python")
        caller_unit = FunctionUnit(
            caller_id,
            "def run(self, context):\n    return super(Base, self).run(context)",
            "def run(self, context):",
        )
        target_unit = FunctionUnit(
            target_id,
            "def run(self, context):\n    raise PublicFailure(self.detail)",
            "def run(self, context):",
        )
        other_unit = FunctionUnit(
            other_id, "def run(self, context):\n    return None", "def run(self, context):"
        )
        target_call = CallSite(caller_id, target_id, "run")
        other_call = CallSite(caller_id, other_id, "run")
        program = ProgramIndex(
            functions={caller_id: caller_unit, target_id: target_unit, other_id: other_unit},
            calls_by_caller={
                caller_id: [target_call, other_call], target_id: [], other_id: [],
            },
            callers_by_callee={
                caller_id: [], target_id: [target_call], other_id: [other_call],
            },
            entrypoints=[caller_id],
        )
        leaking = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", target_id, "ok",
            {
                "inputs": {"caught:error_detail": HIGH},
                "outputs": {
                    "return": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "return", "observability": "caller",
                    },
                    "exception:message": {
                        "deps": ["caught:error_detail"], "const": None,
                        "sink_channel": "exception_message", "observability": "caller",
                    },
                },
                "notes": "",
            },
        )
        fixed = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", target_id, "ok",
            {
                "inputs": {},
                "outputs": {
                    "return": {
                        "deps": [], "const": HIGH,
                        "sink_channel": "return", "observability": "caller",
                    },
                    "exception:message": {
                        "deps": [], "const": None,
                        "sink_channel": "exception_message", "observability": "caller",
                    },
                },
                "notes": "",
            },
        )
        context = DriverContext(program, target_unit, False, (target_call,), ())

        self.assertEqual("LEAK", IfcPlugin().check(leaking, context).verdict)
        self.assertEqual("SECURE", IfcPlugin().check(fixed, context).verdict)

    def test_ambiguous_callee_preserves_caller_boundary_obligation(self):
        caller_id = FunctionId("caller-py/caller.py", "caller", "caller", "python")
        safe_id = FunctionId("safe-py/emit.py", "emit", "emit", "python")
        leaking_id = FunctionId("leaking-py/emit.py", "emit", "emit", "python")
        caller_unit = FunctionUnit(
            caller_id, "def caller(secret):\n    emit(secret)", "def caller(secret):"
        )
        safe_unit = FunctionUnit(safe_id, "def emit(value):\n    return None", "def emit(value):")
        leaking_unit = FunctionUnit(
            leaking_id,
            "def emit(value):\n    raise PublicFailure(value)",
            "def emit(value):",
        )
        safe_call = CallSite(
            caller_id, safe_id, "emit", arg_bindings={"param:value": "secret"}
        )
        leaking_call = CallSite(
            caller_id, leaking_id, "emit", arg_bindings={"param:value": "secret"}
        )
        program = ProgramIndex(
            functions={caller_id: caller_unit, safe_id: safe_unit, leaking_id: leaking_unit},
            calls_by_caller={
                caller_id: [safe_call, leaking_call], safe_id: [], leaking_id: [],
            },
            callers_by_callee={
                caller_id: [], safe_id: [safe_call], leaking_id: [leaking_call],
            },
            entrypoints=[caller_id],
        )
        caller = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", caller_id, "ok",
            {"inputs": {"param:secret": HIGH}, "outputs": {}, "notes": ""},
        )
        safe = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", safe_id, "ok", _empty_signature()
        )
        leaking = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", leaking_id, "ok",
            {
                "inputs": {"param:value": "Unknown"},
                "outputs": {"exception:message": {
                    "deps": ["param:value"],
                    "const": None,
                    "sink_channel": "exception_message",
                    "observability": "caller",
                }},
                "notes": "",
            },
        )
        context = DriverContext(
            program, caller_unit, True, (), (safe_call, leaking_call)
        )

        composed = IfcPlugin().compose_calls(
            caller,
            [ResolvedCall(safe_call, safe), ResolvedCall(leaking_call, leaking)],
            context,
        )

        self.assertEqual("LEAK", classify(composed.payload, is_entrypoint=True)["verdict"])

    def test_check_revalidates_stale_cached_facts_against_source(self):
        source = """def configure():
    if 'api_secret' in options['extra']:
        abort_publicly('sensitive options are not accepted')
    options.update(options['extra'])
"""
        request = _request(source, "configure")
        facts = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", request.function.id, "ok",
            {
                "inputs": {},
                "outputs": {"error:stale": {
                    "deps": [], "const": HIGH,
                    "sink_channel": "error_detail", "observability": "external",
                }},
                "notes": "stale cache",
            },
        )

        verdict = IfcPlugin().check(facts, request.context)

        self.assertEqual("SECURE", verdict.verdict)
        self.assertEqual(LOW, facts.payload["outputs"]["error:stale"]["const"])

    def test_retry_exhaustion_uses_only_source_settled_ifc_facts(self):
        vulnerable = """def configure():
    options.update(options['extra'])
    print(options)
"""
        fixed = """def configure():
    if 'api_secret' in options['extra']:
        abort_publicly('sensitive options are not accepted')
    options.update(options['extra'])
    print(options)
"""
        plugin = IfcPlugin()

        vulnerable_facts = plugin.make_error_facts(_request(vulnerable, "configure"), "bad JSON")
        fixed_facts = plugin.make_error_facts(_request(fixed, "configure"), "bad JSON")
        unknown_facts = plugin.make_error_facts(
            _request("def calculate(value):\n    return value + 1\n", "calculate"),
            "bad JSON",
        )

        self.assertEqual("ok", vulnerable_facts.status)
        self.assertEqual("LEAK", classify(vulnerable_facts.payload)["verdict"])
        self.assertEqual("ok", fixed_facts.status)
        self.assertEqual("SECURE", classify(fixed_facts.payload)["verdict"])
        self.assertEqual("error", unknown_facts.status)

    def test_same_named_method_declaration_is_not_composed_as_a_call(self):
        caller_id = FunctionId("service-py/run.py", "run_6", "run", "python")
        callee_id = FunctionId("other-py/run.py", "run", "run", "python")
        caller_unit = FunctionUnit(
            caller_id,
            "    def run(self, secret):\n        return secret\n",
            "def run(self, secret):",
        )
        callee_unit = FunctionUnit(callee_id, "def run(value):\n    print(value)", "def run(value):")
        call = CallSite(caller_id, callee_id, "run", arg_bindings={"param:value": "secret"})
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", caller_id, "ok",
            {"inputs": {"param:secret": HIGH}, "outputs": {}, "notes": ""},
        )
        callee = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", callee_id, "ok",
            {
                "inputs": {"param:value": "Unknown"},
                "outputs": {
                    "io:stdout": {
                        "deps": ["param:value"],
                        "const": None,
                        "sink_channel": "stdout",
                        "observability": "external",
                    }
                },
                "notes": "",
            },
        )
        context = DriverContext(program, caller_unit, True, (), (call,))

        composed = IfcPlugin().compose_calls(caller, [ResolvedCall(call, callee)], context)

        self.assertEqual("SECURE", classify(composed.payload)["verdict"])
        self.assertNotIn("_callee_resolutions", composed.payload)

    def test_ifc_order_preserves_same_named_functions_from_different_files(self):
        first_id = FunctionId("a-py/main.py", "main", "main", "python")
        second_id = FunctionId("b-py/main.py", "main", "main", "python")
        units = [
            FunctionUnit(first_id, "def main():\n    pass", "def main():"),
            FunctionUnit(second_id, "def main():\n    pass", "def main():"),
        ]

        ordered = _order_bottom_up_all(units)

        self.assertEqual({first_id, second_id}, {unit.id for unit in ordered})
        self.assertEqual(2, len(ordered))

    def test_external_callee_sink_is_enforced_in_caller(self):
        caller_id = FunctionId("caller-py/caller.py", "caller", "caller", "python")
        callee_id = FunctionId("callee-py/emit.py", "emit", "emit", "python")
        caller_unit = FunctionUnit(caller_id, "def caller(secret):\n    emit(secret)", "def caller(secret):")
        callee_unit = FunctionUnit(callee_id, "def emit(value):\n    print(value)", "def emit(value):")
        call = CallSite(caller_id, callee_id, "emit", arg_bindings={"param:value": "secret"})
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", caller_id, "ok",
            {"inputs": {"param:secret": HIGH}, "outputs": {}, "notes": ""},
        )
        callee = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", callee_id, "ok",
            {
                "inputs": {"param:value": "Unknown"},
                "outputs": {
                    "io:stdout": {
                        "deps": ["param:value"],
                        "const": None,
                        "sink_channel": "stdout",
                        "observability": "external",
                    }
                },
                "notes": "",
            },
        )
        context = DriverContext(program, caller_unit, True, (), (call,))

        composed = IfcPlugin().compose_calls(caller, [ResolvedCall(call, callee)], context)
        result = classify(composed.payload)

        self.assertEqual("LEAK", result["verdict"])
        self.assertTrue(any(v["channel"].startswith("callee:emit:") for v in result["violations"]))

    def test_internal_callee_log_is_not_promoted_to_external(self):
        caller_id = FunctionId("caller-py/caller.py", "caller", "caller", "python")
        callee_id = FunctionId("callee-py/emit.py", "emit", "emit", "python")
        caller_unit = FunctionUnit(caller_id, "def caller(secret):\n    emit(secret)", "def caller(secret):")
        callee_unit = FunctionUnit(callee_id, "def emit(value):\n    LOG.exception(value)", "def emit(value):")
        call = CallSite(caller_id, callee_id, "emit", arg_bindings={"param:value": "secret"})
        program = ProgramIndex(
            functions={caller_id: caller_unit, callee_id: callee_unit},
            calls_by_caller={caller_id: [call], callee_id: []},
            callers_by_callee={caller_id: [], callee_id: [call]},
            entrypoints=[caller_id],
        )
        caller = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", caller_id, "ok",
            {"inputs": {"param:secret": HIGH}, "outputs": {}, "notes": ""},
        )
        callee = FactEnvelope(
            "ifc", "ifc.flow_signature.v2", callee_id, "ok",
            {
                "inputs": {"param:value": "Unknown"},
                "outputs": {
                    "io:log": {
                        "deps": ["param:value"],
                        "const": None,
                        "sink_channel": "log",
                        "observability": "internal",
                    }
                },
                "notes": "",
            },
        )
        context = DriverContext(program, caller_unit, True, (), (call,))

        composed = IfcPlugin().compose_calls(caller, [ResolvedCall(call, callee)], context)
        result = classify(composed.payload)

        self.assertEqual("SECURE", result["verdict"])

    def test_raw_internal_composition_fields_are_stripped(self):
        payload = {
            "inputs": {"param:public": LOW},
            "outputs": {},
            "_callee_resolutions": [{"resolved_outputs": {"io:stdout": {"label": HIGH}}}],
        }

        facts = _parse("def target(public):\n    return public\n", payload)

        self.assertNotIn("_callee_resolutions", facts.payload)

    def test_malformed_observability_is_rejected_without_crashing(self):
        payload = {
            "inputs": {"param:secret": HIGH},
            "outputs": {
                "io:log": {
                    "deps": ["param:secret"],
                    "const": None,
                    "sink_channel": "log",
                    "observability": "probably-public",
                }
            },
        }

        facts = _parse("def target(secret):\n    LOG.info(secret)\n", payload)

        self.assertIsNone(facts)

    def test_unhashable_schema_values_are_rejected_without_crashing(self):
        variants = (
            {"inputs": {"param:value": {}}, "outputs": {}},
            {"inputs": {}, "outputs": {"return": {"deps": [], "const": {}}}},
            {"inputs": {}, "outputs": {"return": {
                "deps": [], "const": None, "sink_channel": {},
            }}},
            {"inputs": {}, "outputs": {"return": {
                "deps": [], "const": None, "observability": {},
            }}},
        )

        for payload in variants:
            with self.subTest(payload=payload):
                self.assertIsNone(_parse("def target():\n    return None\n", payload))

    def test_valid_json_array_payload_is_rejected_without_crashing(self):
        parsed = IfcPlugin().parse_abstraction_response(
            _request("def target():\n    pass\n"),
            "[FLOW_JSON][][/FLOW_JSON]",
        )

        self.assertIsNone(parsed)


if __name__ == "__main__":
    unittest.main()
