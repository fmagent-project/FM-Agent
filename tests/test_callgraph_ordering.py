import unittest

from src.plugins.base import FunctionId, FunctionUnit
from src.plugins.callgraph import build_program_index, order_bottom_up


def _unit(rel, name, base_name, source):
    function_id = FunctionId(rel, name, base_name, "python")
    return FunctionUnit(function_id, source, source.splitlines()[0])


class CallgraphOrderingTests(unittest.TestCase):
    def test_same_method_name_in_distinct_paths_and_classes_is_not_dropped(self):
        request = _unit(
            "http/emailservlet-py/render_POST.py", "render_POST", "render_POST",
            "class EmailRequestCodeServlet:\n    def render_POST(self, request):\n        return request",
        )
        validate = _unit(
            "http/validateservlet-py/render_POST.py", "render_POST", "render_POST",
            "class EmailValidateCodeServlet:\n    def render_POST(self, request):\n        return request",
        )

        ordered = order_bottom_up([request, validate])

        self.assertEqual(2, len(ordered))
        self.assertEqual({request.id, validate.id}, {unit.id for unit in ordered})

    def test_same_file_extractor_suffixes_remain_distinct(self):
        first = _unit("service-py/handle.py", "handle", "handle", "def handle():\n    pass")
        second = _unit("service-py/handle_1.py", "handle_1", "handle", "def handle():\n    pass")

        ordered = order_bottom_up([first, second])

        self.assertEqual({first.id, second.id}, {unit.id for unit in ordered})

    def test_duplicate_method_declarations_do_not_create_call_edges(self):
        first = _unit(
            "email-py/render_POST.py", "render_POST", "render_POST",
            "def render_POST(self, request):\n    return request",
        )
        second = _unit(
            "invite-py/render_POST.py", "render_POST", "render_POST",
            "def render_POST(self, request):\n    return request",
        )

        program = build_program_index([first, second])

        self.assertEqual([], program.calls_by_caller[first.id])
        self.assertEqual([], program.calls_by_caller[second.id])
        self.assertEqual({first.id, second.id}, set(program.entrypoints))

    def test_real_unique_name_call_still_creates_an_edge(self):
        caller = _unit("caller-py/run.py", "run", "run", "def run():\n    return helper()")
        callee = _unit("helper-py/helper.py", "helper", "helper", "def helper():\n    return 1")

        program = build_program_index([caller, callee])

        self.assertEqual([callee.id], [site.callee for site in program.calls_by_caller[caller.id]])
        self.assertEqual([caller.id], [site.caller for site in program.callers_by_callee[callee.id]])

    def test_super_constructor_does_not_resolve_to_unrelated_initializers(self):
        caller = _unit(
            "child-py/__init__.py", "__init__", "__init__",
            "def __init__(self):\n    super().__init__()",
        )
        unrelated = _unit(
            "other-py/__init__.py", "__init__", "__init__",
            "def __init__(self, value):\n    self.value = value",
        )

        program = build_program_index([caller, unrelated])

        self.assertEqual([], program.calls_by_caller[caller.id])

    def test_callee_still_precedes_caller(self):
        caller = _unit("caller-py/run.py", "run", "run", "def run():\n    return helper()")
        callee = _unit("helper-py/helper.py", "helper", "helper", "def helper():\n    return 1")

        ordered = order_bottom_up([caller, callee])

        self.assertLess(ordered.index(callee), ordered.index(caller))

    def test_cycle_preserves_every_identity(self):
        first = _unit("a-py/first.py", "first", "first", "def first():\n    return second()")
        second = _unit("b-py/second.py", "second", "second", "def second():\n    return first()")

        ordered = order_bottom_up([first, second])

        self.assertEqual(2, len(ordered))
        self.assertEqual({first.id, second.id}, {unit.id for unit in ordered})

    def test_repeated_ordering_is_deterministic(self):
        units = [
            _unit("z-py/check.py", "check", "check", "def check():\n    return helper()"),
            _unit("a-py/check.py", "check", "check", "def check():\n    return 1"),
            _unit("h-py/helper.py", "helper", "helper", "def helper():\n    return 1"),
        ]

        expected = [unit.id for unit in order_bottom_up(units)]
        for _ in range(5):
            self.assertEqual(expected, [unit.id for unit in order_bottom_up(units)])


if __name__ == "__main__":
    unittest.main()
