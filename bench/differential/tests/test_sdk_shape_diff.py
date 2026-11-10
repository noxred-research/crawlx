"""Offline tests of `sdk_shape_diff.py` on a tiny hand-made pair of captures.

    python3 -B -m unittest discover -s bench/differential/tests
"""

import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("sdk_shape_diff", os.path.join(HERE, "..", "sdk_shape_diff.py"))
diff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diff)

UP_SITE = "http://gym.test:4100"
CX_SITE = "http://site.example.test:4100"
ID_A = "01a1811c-9b40-76f8-b2b4-8da53d7be668"
ID_B = "11111111-2222-3333-4444-555555555555"


def exchange(method, path, status, response, headers=("content-type",)):
    return {"method": method, "path": path, "request": None, "status": status,
            "headers": list(headers), "response": response}


def call(raw, sdk=None, **extra):
    return {"sdk": sdk, "sdk_wire": [], "raw": raw, **extra}


def capture(label, site, calls):
    return {"label": label, "api": site, "site": site, "seed": site + "/s1/", "fixture": "s1",
            "sdk_version": "4.54.0", "calls": calls}


def doc(site, path, status=200, **extra):
    return {"markdown": f"# {path}", "links": [f"{site}{path}a/"],
            "metadata": {"sourceURL": f"{site}{path}", "statusCode": status, "scrapeId": "x", **extra}}


class FlattenTests(unittest.TestCase):
    def test_arrays_collapse_and_member_sets_are_unioned(self):
        shape = diff.Shape({"data": [{"a": 1}, {"a": 2, "b": "x"}], "ok": True, "none": None, "list": []})
        self.assertEqual(shape.types["$.data"], {"array"})
        self.assertEqual(shape.types["$.data[]"], {"object"})
        self.assertEqual(shape.types["$.data[].a"], {"number"})
        self.assertEqual(shape.types["$.data[].b"], {"string"})
        self.assertEqual(shape.types["$.ok"], {"boolean"})
        self.assertEqual(shape.types["$.none"], {"null"})
        self.assertIn("$.list", shape.empty_arrays)
        self.assertNotIn("$.list[]", shape.types)

    def test_optional_members_are_those_some_sibling_object_lacks(self):
        shape = diff.Shape({"data": [{"a": 1}, {"a": 2, "b": "x"}]})
        self.assertFalse(shape.optional("$.data[].a"))
        self.assertTrue(shape.optional("$.data[].b"))
        self.assertFalse(shape.optional("$.data"))

    def test_null_and_absent_differ_and_integers_equal_floats(self):
        shape = diff.Shape({"a": None, "n": 1, "m": 1.5})
        self.assertEqual(shape.types["$.a"], {"null"})
        self.assertEqual(shape.types["$.n"], shape.types["$.m"])
        self.assertNotIn("$.absent", shape.types)
        self.assertEqual(shape.populated(), {"$", "$.n", "$.m"})

    def test_scalars_are_kept_for_value_comparison(self):
        shape = diff.Shape({"data": [{"s": 200}, {"s": 404}]})
        self.assertEqual(shape.values["$.data[].s"], [200, 404])


class DiffTests(unittest.TestCase):
    def test_only_upstream_only_crawlx_and_type_differences(self):
        up = diff.Shape({"success": True, "id": "a", "creditsUsed": -1, "x": {"y": 1}})
        cx = diff.Shape({"success": True, "id": 7, "warnings": []})
        d = diff.diff_shapes(up, cx)
        self.assertEqual(d["only_upstream"], ["$.creditsUsed", "$.x", "$.x.y"])
        self.assertEqual(d["only_crawlx"], ["$.warnings"])
        self.assertEqual(d["type_diff"], ["$.id"])

    def test_sent_as_null_is_not_the_same_as_left_out(self):
        d = diff.diff_shapes(diff.Shape({"a": None}), diff.Shape({}))
        self.assertEqual(d["only_upstream"], ["$.a"])
        d = diff.diff_shapes(diff.Shape({"a": None}), diff.Shape({"a": "x"}))
        self.assertEqual(d["type_diff"], ["$.a"])

    def test_always_versus_sometimes(self):
        up = diff.Shape({"data": [{"e": 1}, {"e": 2}]})
        cx = diff.Shape({"data": [{"e": 1}, {}]})
        self.assertEqual(diff.diff_shapes(up, cx)["presence_diff"], ["$.data[].e"])

    def test_nested_paths_are_grouped_under_their_top_most_ancestor(self):
        paths = ["$.counters", "$.counters.urls", "$.counters.urls.failed", "$.counterX", "$.warnings[]", "$.warnings"]
        groups = dict(diff.nest(paths))
        self.assertEqual(groups["$.counters"], ["$.counters.urls", "$.counters.urls.failed"])
        self.assertEqual(groups["$.warnings"], ["$.warnings[]"])
        self.assertEqual(groups["$.counterX"], [])
        self.assertEqual(set(groups), {"$.counters", "$.counterX", "$.warnings"})
        self.assertEqual(diff.describe_nested("$.counters", groups["$.counters"]), "2: `.urls`, `.urls.failed`")
        self.assertEqual(diff.describe_nested("$.counterX", []), "-")

    def test_origins_are_made_equal_and_volatile_leaves_are_ignored(self):
        up = diff.Shape({"url": UP_SITE + "/s1/", "id": "a", "metadata": {"sourceURL": UP_SITE + "/s1/", "statusCode": 200}})
        cx = diff.Shape({"url": CX_SITE + "/s1/", "id": "b", "metadata": {"sourceURL": CX_SITE + "/s1/", "statusCode": 200}})
        self.assertEqual(diff.value_diffs(up, cx, UP_SITE, CX_SITE), [])

    def test_stable_values_that_differ_are_listed_per_side(self):
        up = diff.Shape({"data": [doc(UP_SITE, "/s1/", 200), doc(UP_SITE, "/s1/missing", 404)]})
        cx = diff.Shape({"data": [doc(CX_SITE, "/s1/", 200)]})
        rows = {path: (a, b) for path, a, b in diff.value_diffs(up, cx, UP_SITE, CX_SITE)}
        self.assertIn("`<ORIGIN>/s1/missing`", rows["$.data[].metadata.sourceURL"][0])
        self.assertEqual(rows["$.data[].metadata.sourceURL"][1], "-")
        self.assertEqual(rows["$.data[].metadata.statusCode"], ("`404`", "-"))
        self.assertIn("$.data[].markdown", rows)  # bodies are counted, never dumped

    def test_typed_results_report_set_versus_null(self):
        up = {"ok": True, "result": {"a": 1, "b": None, "c": 3}}
        cx = {"ok": True, "result": {"a": 1, "b": 2, "c": None}}
        typed = diff.typed_diffs(up, cx)
        self.assertEqual(typed["set_upstream_only"], ["$.c"])
        self.assertEqual(typed["set_crawlx_only"], ["$.b"])
        failed = {"ok": False, "error": "UpstreamSdkError", "message": "boom", "status_code": 500}
        self.assertIn("UpstreamSdkError", diff.typed_diffs(up, failed)["failure"][1])


class ReportTests(unittest.TestCase):
    def captures(self):
        up = capture("upstream", UP_SITE, {
            "scrape": call([exchange("POST", "/v2/scrape", 200,
                                     {"success": True, "data": doc(UP_SITE, "/s1/", description="d")},
                                     headers=("content-type", "etag"))],
                           sdk={"ok": True, "result": {"markdown": "# x", "warning": "w"}}),
            "get_crawl_status": call([exchange("GET", f"/v2/crawl/{ID_A}", 200,
                                               {"status": "completed", "total": 3, "next": None})],
                                     sdk={"ok": True, "result": {}}, polls={"sdk": 4, "raw": 1}),
            "cancel_crawl": call([exchange("DELETE", f"/v2/crawl/{ID_A}", 200, {"status": "cancelled"})]),
        })
        cx = capture("crawlx", CX_SITE, {
            "scrape": call([exchange("POST", "/v2/scrape", 200,
                                     {"success": True, "data": doc(CX_SITE, "/s1/"), "warnings": []})],
                           sdk={"ok": True, "result": {"markdown": "# x", "warning": None}}),
            "get_crawl_status": call([exchange("GET", f"/v2/crawl/{ID_B}", 200,
                                               {"status": "completed", "total": 3, "next": None})],
                                     sdk={"ok": True, "result": {}}, polls={"sdk": 2, "raw": 1}),
        })
        return up, cx

    def test_report_lists_every_difference_and_the_clean_calls(self):
        up, cx = self.captures()
        report = diff.render_report(up, cx, diff.compare(up, cx), [("upstream commit", "c31e88c")])
        self.assertIn("* upstream commit: c31e88c", report)
        self.assertIn("#### POST /v2/scrape", report)
        self.assertIn("| `$.data.metadata.description` | string | always |", report)  # only upstream
        self.assertIn("| `$.warnings` | array | always (empty here) |", report)  # only crawlx
        self.assertIn("set upstream, `null` on crawlx: `$.warning`", report)
        self.assertIn("Response headers only upstream: `etag`", report)
        self.assertIn("#### GET /v2/crawl/{id}", report)
        self.assertIn("No difference in paths, types, presence or stable values.", report)
        self.assertIn("upstream 4 (SDK) / 1 (raw), crawlx 2 (SDK) / 1 (raw)", report)
        # a call only one side captured is said so, not dropped
        self.assertIn("Captured by upstream only.", report)
        self.assertIn("Not observed on crawlx.", report)
        # the consolidated lists name the exchanges
        self.assertIn("| `$.data.metadata.description` | - | POST /v2/scrape |", report)

    def test_unfinished_cases_do_not_crash(self):
        up = capture("upstream", UP_SITE, {"scrape": call([exchange("POST", "/v2/scrape", 500, {"error": "x"})])})
        cx = capture("crawlx", CX_SITE, {"scrape": call([exchange("POST", "/v2/scrape", 200, None)], sdk=None)})
        report = diff.render_report(up, cx, diff.compare(up, cx), [])
        self.assertIn("HTTP status: upstream **500**, crawlx **200**.", report)


class TrimTests(unittest.TestCase):
    def test_long_strings_are_cut_with_a_byte_count(self):
        notes = []
        out = diff.trim_value({"rawHtml": "x" * 5000, "short": "ok"}, "$", notes)
        self.assertTrue(out["rawHtml"].startswith("x" * 2048))
        self.assertIn("trimmed, 5000 bytes in total", out["rawHtml"])
        self.assertEqual(out["short"], "ok")
        self.assertEqual(notes, [{"path": "$.rawHtml", "bytes": 5000}])

    def test_long_arrays_keep_one_element_per_distinct_shape(self):
        items = [{"a": 1} for _ in range(20)] + [{"a": 1, "metadata": {"error": "Not Found"}}]
        notes = []
        out = diff.trim_value({"data": items}, "$", notes)
        self.assertEqual(len(out["data"]), 2)
        self.assertEqual(out["data"][1]["metadata"]["error"], "Not Found")
        self.assertEqual(notes, [{"path": "$.data[]", "kept": 2, "of": 21}])

    def test_short_arrays_and_non_object_arrays_are_untouched(self):
        notes = []
        value = {"links": [f"u{i}" for i in range(50)], "few": [{"a": 1}] * 3}
        self.assertEqual(diff.trim_value(value, "$", notes), value)
        self.assertEqual(notes, [])


class CommandLineTests(unittest.TestCase):
    def test_main_writes_the_report_and_the_trimmed_evidence(self):
        up, cx = ReportTests().captures()
        up["calls"]["scrape"]["raw"][0]["response"]["data"]["rawHtml"] = "y" * 4000
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, value in (("up", up), ("cx", cx)):
                paths[name] = os.path.join(tmp, f"{name}.json")
                with open(paths[name], "w", encoding="utf-8") as fh:
                    json.dump(value, fh)
            out = os.path.join(tmp, "report.md")
            evidence = os.path.join(tmp, "evidence")
            self.assertEqual(
                diff.main(["--upstream", paths["up"], "--crawlx", paths["cx"], "--out", out,
                           "--meta", "x=y", "--evidence-dir", evidence]),
                0,
            )
            with open(out, encoding="utf-8") as fh:
                self.assertTrue(fh.read().startswith("# SDK shape diff"))
            with open(os.path.join(evidence, "upstream.json"), encoding="utf-8") as fh:
                trimmed = json.load(fh)
            self.assertEqual(trimmed["_trimmed"][0]["bytes"], 4000)
            self.assertTrue(os.path.exists(os.path.join(evidence, "crawlx.json")))


if __name__ == "__main__":
    unittest.main()
