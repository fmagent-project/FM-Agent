import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.authz_reasoner import ERROR, SAFE, VULNERABLE, classify
from src.authz_validation import source_rel_from_extracted, validate_and_enrich
from src.plugins.authz import AuthzPlugin
from src.plugins.base import DriverContext, FactEnvelope, FunctionId, FunctionUnit, ProgramIndex


def _operation(**overrides):
    operation = {
        "op_id": "effect",
        "kind": "write",
        "resource_type": "Resource",
        "resource_id_expr": "target",
        "resource_id_origin": "request",
        "action": "dispatch",
        "evidence": "dispatch(target)",
    }
    operation.update(overrides)
    return operation


def _payload(operation=None, guards=None):
    return {
        "authenticated_subject": {"expr": "request.user", "origin": "framework_global"},
        "sensitive_operations": [operation or _operation()],
        "guards": guards or [],
        "obligations": [],
        "establishes": [],
    }


def _unit(root: Path, source: str, function_source: str, name: str = "post"):
    source_path = root / "app.py"
    source_path.write_text(source)
    extracted = root / "fm_agent_authz" / "extracted_functions" / "app-py"
    extracted.mkdir(parents=True)
    extracted_path = extracted / f"{name}.py"
    extracted_path.write_text(function_source)
    function_id = FunctionId(f"app-py/{name}.py", name, name, "python")
    return FunctionUnit(function_id, function_source, function_source.splitlines()[0], abs_path=str(extracted_path))


def _context(unit):
    program = ProgramIndex(
        functions={unit.id: unit},
        calls_by_caller={unit.id: []},
        callers_by_callee={unit.id: []},
        entrypoints=[unit.id],
    )
    return DriverContext(program, unit, True)


class AuthzValidationGuardTests(unittest.TestCase):
    def test_absolute_session_lifetime_is_required_not_merely_an_authenticated_subject(self):
        operation = _operation(
            resource_type="Session",
            resource_id_expr="session",
            action="authenticate",
            required_checks=["absolute_authentication_lifetime"],
        )
        incidental_guard = {
            "kind": "authentication",
            "subject": "request.user",
            "resource_id_expr": "session",
            "action_scope": "any",
            "dominates_all_paths": False,
        }
        result = classify(_payload(operation, [incidental_guard]))
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("MISSING_ABSOLUTE_AUTHENTICATION_LIFETIME", result["findings"][0]["kind"])
        self.assertEqual("CWE-306", result["findings"][0]["cwe"])

    def test_source_validation_distinguishes_sliding_from_absolute_session_lifetime(self):
        vulnerable = """def run(session, idle_timeout):
    session.timeout = idle_timeout
    return session.user
"""
        fixed = """def run(session, idle_timeout, absolute_timeout):
    idle_deadline = session.now() + timedelta(minutes=idle_timeout)
    auth_deadline = session.login_time + timedelta(minutes=absolute_timeout)
    expiration = min(idle_deadline, auth_deadline)
    session.timeout = expiration - session.now()
    return session.user
"""
        for name, source, expected in (("sliding", vulnerable, VULNERABLE), ("absolute", fixed, SAFE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                unit = _unit(root, source, source, name="run")
                enriched = validate_and_enrich(_payload(), unit)
                self.assertIsNotNone(enriched)
                self.assertEqual(expected, classify(enriched)["verdict"])

    def test_session_acceptance_uses_module_absolute_lifetime_not_session_key_reads(self):
        vulnerable_module = """def accepts_session(request, session):
    if not request.current_user:
        return False
    return session.get(USER_KEY) is not None and session.get(AUTH_TIME) is not None

def refresh(session, idle_timeout):
    session.timeout = idle_timeout
"""
        fixed_module = """def accepts_session(request, session):
    if not request.current_user:
        return False
    return session.get(USER_KEY) is not None and session.get(AUTH_TIME) is not None

def refresh(session, idle_timeout, absolute_timeout):
    idle_deadline = session.now() + idle_timeout
    auth_deadline = session[AUTH_TIME] + absolute_timeout
    session.timeout = min(idle_deadline, auth_deadline) - session.now()
"""
        function = """def accepts_session(request, session):
    if not request.current_user:
        return False
    return session.get(USER_KEY) is not None and session.get(AUTH_TIME) is not None
"""
        model_operation = _operation(
            kind="read", resource_type="Session", resource_id_expr="USER_KEY",
            action="read", evidence="session.get(USER_KEY)",
        )
        for name, module, expected in (
            ("sliding-only", vulnerable_module, VULNERABLE),
            ("absolute-cap", fixed_module, SAFE),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                unit = _unit(Path(tmp), module, function, name="accepts_session")
                result = classify(validate_and_enrich(_payload(model_operation), unit))
                self.assertEqual(expected, result["verdict"])
                if expected == VULNERABLE:
                    self.assertEqual("CWE-306", result["findings"][0]["cwe"])

    def test_project_bound_argument_is_safe_but_unscoped_lookup_is_cwe_639(self):
        vulnerable_module = """class Endpoint:
    def post(self, request, project, target_id):
        target = self.get_target(target_id)
        return dispatch(target)
"""
        vulnerable_function = """def post(self, request, project, target_id):
    target = self.get_target(target_id)
    return dispatch(target)
"""
        fixed_module = """class Endpoint:
    def convert_args(self, request, target_id, *args, **kwargs):
        project = kwargs[\"project\"]
        queryset = Target.objects.filter(project=project)
        target = queryset.get(id=target_id)
        kwargs[\"target\"] = target
        return args, kwargs

    def post(self, request, project, target):
        return dispatch(target)
"""
        fixed_function = """def post(self, request, project, target):
    return dispatch(target)
"""
        for name, module, function, expected in (
            ("unscoped", vulnerable_module, vulnerable_function, VULNERABLE),
            ("project-bound", fixed_module, fixed_function, SAFE),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                unit = _unit(Path(tmp), module, function)
                enriched = validate_and_enrich(_payload(), unit)
                result = classify(enriched)
                self.assertEqual(expected, result["verdict"])
                if expected == VULNERABLE:
                    self.assertEqual("CWE-639", result["findings"][0]["cwe"])

    def test_source_binding_replaces_untrusted_model_check_vocabulary(self):
        module = """class Endpoint:
    def convert_args(self, request, target_id, *args, **kwargs):
        account = kwargs["account"]
        queryset = Target.objects.filter(account=account)
        target = queryset.get(id=target_id)
        kwargs["target"] = target
        return args, kwargs

    def post(self, request, account, target):
        return update(target)
"""
        function = """def post(self, request, account, target):
    return update(target)
"""
        operation = _operation(
            resource_id_expr="target", scope_id_expr="account",
            required_checks=["subject_resource_binding"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), module, function)
            enriched = validate_and_enrich(_payload(operation), unit)

        self.assertIsNotNone(enriched)
        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_dispatch_permission_must_bind_the_dispatched_object_before_call(self):
        operation = _operation(
            resource_id_expr="job_model",
            permission_object_expr="job_model",
            required_checks=["object_permission"],
        )
        wrong_object_guard = {
            "predicate_nl": "framework checks permission on job_button",
            "subject": "request.user",
            "resource_type": "JobButton",
            "resource_id_expr": "job_button",
            "action_scope": "dispatch",
            "kind": "permission",
            "source": "framework",
            "dominates_all_paths": True,
            "evidence": "queryset = JobButton.objects.all()",
        }
        result = classify(_payload(operation, [wrong_object_guard]))
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("OBJECT_PERMISSION_BINDING_MISMATCH", result["findings"][0]["kind"])
        self.assertEqual("CWE-863", result["findings"][0]["cwe"])

    def test_source_validation_binds_inherited_permission_to_queryset_not_related_dispatch_target(self):
        module = """class Endpoint(ObjectPermissionRequiredMixin):
    queryset = Button.objects.all()

    def post(self, request, pk):
        button = Button.objects.get(pk=pk)
        target = button.job
        return Queue.enqueue(func=run, name=target.class_path, user=request.user)
"""
        function = """def post(self, request, pk):
    button = Button.objects.get(pk=pk)
    target = button.job
    return Queue.enqueue(func=run, name=target.class_path, user=request.user)
"""
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), module, function)
            payload = _payload()
            payload["sensitive_operations"] = []
            enriched = validate_and_enrich(payload, unit)
            result = classify(enriched)
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual(["CWE-863"], [finding["cwe"] for finding in result["findings"]])

    def test_transactional_object_permission_recheck_authorizes_only_committed_effects(self):
        module = """class EditEndpoint(generic.ObjectEditView):
    queryset = Secret.objects.all()

    def post(self, request, *args, **kwargs):
        obj = self.alter_obj(self.get_object(kwargs), request, args, kwargs)
        form = self.model_form(data=request.POST, instance=obj)
        if form.is_valid():
            try:
                with transaction.atomic():
                    obj = form.save()
                    self.queryset.get(pk=obj.pk)
                    associations = self.get_associations(request, obj)
                    associations.save()
            except ObjectDoesNotExist:
                form.add_error(None, "permission denied")
        return render(request, self.template_name, {"obj": obj})
"""
        function = """def post(self, request, *args, **kwargs):
    obj = self.alter_obj(self.get_object(kwargs), request, args, kwargs)
    form = self.model_form(data=request.POST, instance=obj)
    if form.is_valid():
        try:
            with transaction.atomic():
                obj = form.save()
                self.queryset.get(pk=obj.pk)
                associations = self.get_associations(request, obj)
                associations.save()
        except ObjectDoesNotExist:
            form.add_error(None, "permission denied")
    return render(request, self.template_name, {"obj": obj})
"""
        operations = [
            _operation(op_id="alter", resource_id_expr="kwargs", action="modify",
                       evidence="self.alter_obj(self.get_object(kwargs), request, args, kwargs)"),
            _operation(op_id="save", resource_id_expr="obj.pk", action="save",
                       evidence="obj = form.save()"),
            _operation(op_id="associations", resource_id_expr=None, action="save",
                       evidence="associations.save()"),
        ]
        payload = _payload()
        payload["sensitive_operations"] = operations
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), module, function)
            enriched = validate_and_enrich(payload, unit)

        self.assertEqual(SAFE, classify(enriched)["verdict"])

    def test_transactional_recheck_does_not_authorize_a_different_dispatched_object(self):
        module = """class EditEndpoint(generic.ObjectEditView):
    queryset = Wrapper.objects.all()

    def post(self, request, *args, **kwargs):
        wrapper = self.get_object(kwargs)
        try:
            with transaction.atomic():
                wrapper = wrapper.save()
                self.queryset.get(pk=wrapper.pk)
                target = wrapper.task
                return Queue.enqueue(func=run, name=target.class_path, user=request.user)
        except ObjectDoesNotExist:
            return denied()
"""
        function = """def post(self, request, *args, **kwargs):
    wrapper = self.get_object(kwargs)
    try:
        with transaction.atomic():
            wrapper = wrapper.save()
            self.queryset.get(pk=wrapper.pk)
            target = wrapper.task
            return Queue.enqueue(func=run, name=target.class_path, user=request.user)
    except ObjectDoesNotExist:
        return denied()
"""
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), module, function)
            payload = _payload()
            payload["sensitive_operations"] = []
            result = classify(validate_and_enrich(payload, unit))

        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-863", result["findings"][0]["cwe"])

    def test_authenticated_but_wrong_project_context_does_not_discharge_binding(self):
        operation = _operation(
            scope_id_expr="requested_project",
            required_checks=["subject_object_binding"],
        )
        result = classify(
            _payload(operation),
            is_entrypoint=False,
            propagated_contexts=[{
                "resource_id_expr": "other_project",
                "action": "dispatch",
                "subject_bound": True,
                "kind": "tenant",
            }],
        )
        self.assertEqual(VULNERABLE, result["verdict"])
        self.assertEqual("CWE-639", result["findings"][0]["cwe"])

    def test_raw_model_cannot_spoof_source_validation(self):
        source = """def run(session, idle_timeout):
    session.timeout = idle_timeout
    return session.user
"""
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), source, source, name="run")
            payload = _payload()
            payload["_authz_validation"] = {"absolute_lifetime": True}
            payload["sensitive_operations"][0]["_source_authorized"] = True
            payload["guards"] = [{
                "kind": "authentication",
                "subject": "session.user",
                "resource_id_expr": None,
                "action_scope": "any",
                "dominates_all_paths": True,
                "absolute_lifetime_bound": True,
                "source": "source_validation",
            }]
            enriched = validate_and_enrich(payload, unit)
        self.assertFalse(enriched["_authz_validation"]["absolute_lifetime"])
        self.assertEqual(VULNERABLE, classify(enriched)["verdict"])

    def test_stale_cached_facts_fail_closed_after_source_change(self):
        source = "def post(request, target):\n    return dispatch(target)\n"
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), source, source)
            payload = validate_and_enrich(_payload(), unit)
            payload["_function_digest"] = hashlib.sha256(b"stale").hexdigest()
            facts = FactEnvelope("authz", AuthzPlugin.SCHEMA, unit.id, "ok", payload)
            verdict = AuthzPlugin().check(facts, _context(unit))
        self.assertEqual(ERROR, verdict.verdict)
        self.assertEqual("error", verdict.status)

    def test_plugin_rejects_old_schema_checkpoint_and_renders_source_identity(self):
        source = "def post(request, target):\n    return dispatch(target)\n"
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), source, source)
            facts = FactEnvelope("authz", "authz.guarded_hoare.v1", unit.id, "ok", _payload())
            plugin = AuthzPlugin()
            verdict = plugin.check(facts, _context(unit))
            rendered = plugin.render_result(unit, facts, verdict, _context(unit))
        self.assertEqual(ERROR, verdict.verdict)
        self.assertEqual("app.py", rendered["rel"])
        self.assertEqual("post", rendered["function"])
        self.assertEqual("src/app.py", source_rel_from_extracted("src/app-py/post.py"))

    def test_checkpoint_from_an_older_validation_pass_fails_closed(self):
        source = "def post(request, target):\n    return dispatch(target)\n"
        with tempfile.TemporaryDirectory() as tmp:
            unit = _unit(Path(tmp), source, source)
            payload = validate_and_enrich(_payload(), unit)
            payload["_authz_validation"].pop("version")
            facts = FactEnvelope("authz", AuthzPlugin.SCHEMA, unit.id, "ok", payload)
            verdict = AuthzPlugin().check(facts, _context(unit))
        self.assertEqual(ERROR, verdict.verdict)
        self.assertEqual("error", verdict.status)

    def test_live_removed_authz_endpoints_are_declared_fixed_absent(self):
        manifest = Path(__file__).resolve().parents[1] / "eval" / "securebench_corpus.json"
        cases = {case["cve"]: case for case in json.loads(manifest.read_text())["cases"]}
        sentry = cases["CVE-2024-45606"]["loci"]
        nautobot = cases["CVE-2023-51649"]["loci"]
        self.assertEqual("absent", next(x for x in sentry if x["function"] == "get_rule")["fixed_expectation"])
        self.assertEqual("absent", next(x for x in nautobot if x["qualified_name"] == "JobButtonRunView.post")["fixed_expectation"])


if __name__ == "__main__":
    unittest.main()
