"""Tests for the deterministic HTML report index generator.

Run from the repository root:
    uv run python -m unittest discover -s tests -v

Uses only the stdlib (``unittest``, ``tempfile``) — no new dependencies.
"""

import json
import os
import re
import tempfile
import unittest

from src.file_utils import locate_workdir
from src.report_index import (
    _collect_analyses,
    _collect_bugs,
    _map_source,
    _match_span,
    _extracted_suffix,
    generate_report_index,
)

_PAYLOAD_RE = re.compile(
    r'<script id="report-data" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def _load_items(html_path):
    """Extract and parse the embedded JSON payload from report.html."""
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    match = _PAYLOAD_RE.search(html)
    assert match is not None, "report-data payload not found"
    return json.loads(match.group(1))


def _build_fixture(work):
    """Create a minimal but representative set of run artifacts."""
    results = os.path.join(work, "logic_verification_results", "mod")
    bv = os.path.join(work, "bug_validation")
    os.makedirs(results, exist_ok=True)
    os.makedirs(bv, exist_ok=True)

    abs_func = os.path.join(
        work, "extracted_functions", "src", "engine", "loader-cpp", "loadData.cpp"
    )
    rel_func = "fm_agent/extracted_functions/src/engine/loader-cpp/loadData.cpp"

    def write(path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)

    write(os.path.join(results, "a.json"), {
        "function": abs_func, "verdict": "MATCH", "gaps": None,
    })
    write(os.path.join(results, "b.json"), {
        "function": rel_func,
        "verdict": "MISMATCH",
        "all_bugs": True,
        "bug_count": 2,
        "reasoning_complete": True,
        "gaps": {
            "spec_claim": "x </script> <b>y</b> & z",
            "actual_behavior": "a",
            "code_evidence": "c",
            "trigger_condition": "t",
        },
    })
    other_func = os.path.join(
        work, "extracted_functions", "src", "other", "tool-py", "util.py"
    )
    write(os.path.join(results, "c.json"), {
        "function": other_func, "verdict": "ERROR", "gaps": None, "error": "boom",
    })
    write(os.path.join(results, "d.json"), {
        "function": other_func, "verdict": "SKIPPED", "gaps": None,
    })
    # --all-bugs candidate files: must be skipped as duplicate analysis rows.
    write(os.path.join(results, "b.bug-001.json"), {
        "function": abs_func, "verdict": "MISMATCH",
    })
    write(os.path.join(results, "b.bug-002.json"), {
        "function": abs_func, "verdict": "MISMATCH",
    })

    summary_bugs = [
        {
            "id": "src--engine--loader-cpp--loadData",
            "source_file": abs_func,
            "function_name": "loadData",
            "confirmation_status": "confirmed",
            "attempts": 1,
            "probe_script": "fm_agent/bug_validation/probe_x.py",
            "probe_stdout": "CONFIRMED",
            "trigger_summary": "null deref",
        },
        {
            "id": "y",
            "source_file": other_func,
            "function_name": "util",
            "confirmation_status": "not_confirmed",
            "attempts": 2,
        },
        {
            "id": "z",  # pending — exists ONLY in summary.json, no file on disk
            "source_file": rel_func,
            "function_name": "loadData",
            "confirmation_status": "pending",
            "attempts": 0,
        },
    ]
    write(os.path.join(bv, "summary.json"), {
        "total_reported": 3,
        "total_confirmed": 1,
        "total_not_confirmed": 1,
        "total_pending": 1,
        "bugs": summary_bugs,
    })
    write(os.path.join(bv, "src--engine--loader-cpp--loadData.result.json"), summary_bugs[0])
    write(os.path.join(bv, "y.result.json"), summary_bugs[1])
    return abs_func, rel_func


class ReportIndexTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.work = os.path.join(self.base, "fm_agent")

    def tearDown(self):
        self._tmp.cleanup()

    def test_item_counts(self):
        _build_fixture(self.work)
        html_path = generate_report_index(self.work)
        items = _load_items(html_path)
        bugs = [it for it in items if it["kind"] == "bug"]
        analyses = [it for it in items if it["kind"] == "analysis"]
        self.assertEqual(len(bugs), 3)
        self.assertEqual(len(analyses), 4)

    def test_candidates_skipped(self):
        _build_fixture(self.work)
        html_path = generate_report_index(self.work)
        items = _load_items(html_path)
        self.assertFalse(
            any(it["id"].endswith(".bug-001.json") or it["id"].endswith(".bug-002.json")
                for it in items)
        )

    def test_source_mapping(self):
        _build_fixture(self.work)
        items = _load_items(generate_report_index(self.work))
        b = next(it for it in items if it["kind"] == "analysis" and it["id"] == "mod/b.json")
        self.assertEqual(b["source_file"], "src/engine/loader.cpp")
        self.assertEqual(b["function_name"], "loadData")

    def test_pending_included_from_summary(self):
        _build_fixture(self.work)
        items = _load_items(generate_report_index(self.work))
        z = next(it for it in items if it["kind"] == "bug" and it["id"] == "z")
        self.assertEqual(z["status"], "pending")
        # no .md on disk -> falls back to nothing available for the detail link
        self.assertEqual(z["detail_ref"], "")

    def test_fallback_when_summary_missing(self):
        _build_fixture(self.work)
        os.remove(os.path.join(self.work, "bug_validation", "summary.json"))
        bugs = _collect_bugs(self.work)
        # fallback scans *.result.json on disk: x and y only, pending z is lost
        self.assertEqual(len(bugs), 2)

    def test_deterministic(self):
        _build_fixture(self.work)
        p1 = generate_report_index(self.work)
        with open(p1, "rb") as f:
            first = f.read()
        p2 = generate_report_index(self.work)
        with open(p2, "rb") as f:
            second = f.read()
        self.assertEqual(first, second)

    def test_escaping(self):
        _build_fixture(self.work)
        html_path = generate_report_index(self.work)
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        payload = _PAYLOAD_RE.search(html).group(1)
        # the raw payload region must not contain a live </script> close
        self.assertNotIn("</script", payload)
        # but the parsed data must preserve the literal malicious string
        items = json.loads(payload)
        b = next(it for it in items if it["kind"] == "analysis" and it["id"] == "mod/b.json")
        self.assertIn("</script>", b["detail"]["Spec claim"])
        self.assertIn("<b>", b["detail"]["Spec claim"])

    def test_empty_workdir(self):
        os.makedirs(self.work, exist_ok=True)
        html_path = generate_report_index(self.work)
        items = _load_items(html_path)
        self.assertEqual(items, [])

    def test_no_codegraph_location_empty(self):
        _build_fixture(self.work)
        items = _load_items(generate_report_index(self.work))
        self.assertTrue(all(it["location"] == "" for it in items))

    def test_locate_workdir(self):
        _build_fixture(self.work)
        self.assertEqual(locate_workdir(self.base), self.work)
        self.assertEqual(locate_workdir(self.work), self.work)

    def test_path_mapping_helpers(self):
        path = "fm_agent/extracted_functions/src/engine/loader-cpp/loadData.cpp"
        self.assertEqual(_extracted_suffix(path), "src/engine/loader-cpp/loadData.cpp")
        self.assertEqual(_map_source(path), "src/engine/loader.cpp")

    def test_source_already_original_path(self):
        # A record that already stores the original source path must pass
        # through unchanged — regression: the reverse-mapping fallback used to
        # truncate it (src/engine/loader.cpp -> src/engine).
        self.assertEqual(_map_source("src/engine/loader.cpp"), "src/engine/loader.cpp")
        # a source base name containing a hyphen before the extension is not an
        # extracted shape either (component ends in "-cpp.cpp", not "-cpp")
        self.assertEqual(_map_source("src/engine/loader-cpp.cpp"), "src/engine/loader-cpp.cpp")

    def test_source_leading_slash_extracted(self):
        # Bug validators strip the fm_agent/extracted_functions prefix, leaving a
        # leading-slash extracted suffix (see md/bug_validator.md).
        self.assertEqual(_map_source("/src/engine/loader-cpp/loadData.cpp"), "src/engine/loader.cpp")

    def test_source_bare_marker(self):
        self.assertEqual(
            _map_source("extracted_functions/src/engine/loader-cpp/loadData.cpp"),
            "src/engine/loader.cpp",
        )
        self.assertEqual(
            _map_source("fm_agent/extracted_functions/src/engine/loader-cpp/loadData.cpp"),
            "src/engine/loader.cpp",
        )

    def test_source_href(self):
        _build_fixture(self.work)
        items = _load_items(generate_report_index(self.work))
        self.assertTrue(items)
        # report.html lives in <tmp>/fm_agent; the source tree sits at <tmp>.
        for it in items:
            if it["source_file"]:
                self.assertEqual(it["source_href"], "../" + it["source_file"])
            else:
                self.assertNotIn("source_href", it)

    def test_source_href_skips_invalid(self):
        from src.report_index import _attach_source_href
        items = [
            {"source_file": "src/engine/loader.cpp"},
            {"source_file": ""},
            {"source_file": "../evil.py"},
            {"source_file": "/abs/path.py"},
        ]
        _attach_source_href(self.work, items)
        self.assertEqual(items[0]["source_href"], "../src/engine/loader.cpp")
        for it in items[1:]:
            self.assertNotIn("source_href", it)

    def test_match_span(self):
        spans = [("Flush", 11, 29), ("LocalStorage::Write", 40, 55)]
        # exact bare name
        self.assertEqual(_match_span(spans, "Flush"), "L12-L30")
        # class-qualified name matches its bare tail
        self.assertEqual(_match_span(spans, "Write"), "L41-L56")
        # dedup suffix is stripped before retry
        self.assertEqual(_match_span([("Load", 3, 7)], "Load_1"), "L4-L8")
        # no match -> empty
        self.assertEqual(_match_span(spans, "Missing"), "")
        self.assertEqual(_match_span(None, "Flush"), "")


if __name__ == "__main__":
    unittest.main()
