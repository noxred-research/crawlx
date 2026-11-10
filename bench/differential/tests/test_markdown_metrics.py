"""Offline tests of `markdown_metrics.py` and of the markdown section of `sdk_shape_diff.py`.

    python3 -B -m unittest discover -s bench/differential/tests
"""

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mdm = load("markdown_metrics")
diff = load("sdk_shape_diff")

UP = "http://gym.test:4100"
CX = "http://site.example.test:4100"


def blocks(text):
    return mdm.markdown_blocks(text)


class BlockTests(unittest.TestCase):
    def test_one_block_per_heading_item_row_code_span_and_paragraph(self):
        text = "# Title\n\nfirst line\nsecond   line\n\n- one\n- two\n1. three\n\n| a | b |\n| --- | --- |\n\n```\nx  =  1\n\ny\n```\nlast"
        self.assertEqual(
            blocks(text),
            ["# Title", "first line second line", "- one", "- two", "1. three", "| a | b |", "| --- | --- |",
             "```x  =  1\n\ny", "last"],
        )
        self.assertEqual(blocks(""), [])

    def test_an_unterminated_code_span_is_still_a_block(self):
        self.assertEqual(blocks("```\nopen"), ["```open"])


class ScoreTests(unittest.TestCase):
    def test_block_f1_sees_what_token_similarity_misses(self):
        a = blocks("# T\n\none two\n\nthree four")
        merged = blocks("# T\n\none two three four")  # same tokens, different blocks
        self.assertAlmostEqual(mdm.block_f1(a, merged), 0.4)
        self.assertEqual(mdm.block_f1(a, a), 1.0)
        self.assertEqual(mdm.block_f1(a, []), 0.0)
        self.assertEqual(mdm.block_f1([], a), 0.0)
        self.assertEqual(mdm.block_f1([], []), 1.0)

    def test_a_repeated_block_counts_once_per_occurrence(self):
        self.assertAlmostEqual(mdm.block_f1(blocks("x\n\nx"), blocks("x")), 2.0 / 3.0)

    def test_reordering_keeps_f1_but_lowers_the_ordered_ratio(self):
        abc, cba = blocks("a\n\nb\n\nc"), blocks("c\n\nb\n\na")
        self.assertEqual(mdm.block_f1(abc, cba), 1.0)
        self.assertAlmostEqual(mdm.ordered_subsequence_ratio(abc, cba), 2.0 / 6.0)
        self.assertEqual(mdm.ordered_subsequence_ratio(abc, abc), 1.0)
        self.assertEqual(mdm.ordered_subsequence_ratio([], []), 1.0)
        self.assertEqual(mdm.ordered_subsequence_ratio(abc, []), 0.0)

    def test_missing_and_extra_blocks_lower_the_ordered_ratio(self):
        ref = blocks("a\n\nb\n\nc\n\nd")
        self.assertAlmostEqual(mdm.ordered_subsequence_ratio(ref, blocks("a\n\nc\n\nd")), 2.0 * 3 / 7)
        self.assertAlmostEqual(mdm.ordered_subsequence_ratio(blocks("a\n\nc\n\nd"), ref), 2.0 * 3 / 7)
        self.assertAlmostEqual(mdm.ordered_subsequence_ratio(ref, blocks("a\n\nx\n\nb\n\nc\n\nd")), 2.0 * 4 / 9)

    def test_lists_over_the_cell_budget_are_not_aligned(self):
        big = [str(i) for i in range(2001)]
        self.assertIsNone(mdm.ordered_subsequence_ratio(big, big))


class NormalizeTests(unittest.TestCase):
    def norm(self, text, page=UP + "/s1/", origin=UP):
        return mdm.normalize_markdown(text, page, origin)

    def test_formatting_choices_cancel(self):
        up = "Title\n=====\n\n* one\n+ two\n\n__bold__ &amp; &lt;x&gt;\r\n\r\n\r\n\r\nend  \n"
        cx = "# Title #\n\n- one\n- two\n\n**bold** & <x>\n\nend\n"
        self.assertEqual(self.norm(up), self.norm(cx))

    def test_setext_levels_and_table_rows(self):
        self.assertEqual(self.norm("Sub\n---"), "## Sub")
        self.assertEqual(self.norm("|a|b|\n|:--|---:|"), "| a | b |\n| --- | --- |")

    def test_code_is_left_alone(self):
        self.assertEqual(self.norm("```\n* a  b\n```"), "```\n* a  b\n```")

    def test_links_are_resolved_rebased_and_stripped_of_tracking(self):
        text = "[a](/s1/a/?utm_source=x&b=2&a=1) [b](b.html#frag) [c](#top) <http://other.test/p/>"
        self.assertEqual(
            self.norm(text),
            "[a]({origin}/s1/a?a=1&b=2) [b]({origin}/s1/b.html) [c]() [http://other.test/p]"
            "(http://other.test/p)",
        )

    def test_the_two_origins_normalize_to_the_same_text(self):
        self.assertEqual(
            self.norm("[x](/s1/a/)", UP + "/s1/", UP),
            self.norm("[x](http://site.example.test:4100/s1/a)", CX + "/s1/", CX),
        )

    def test_other_hosts_of_the_gym_port_get_a_port_placeholder(self):
        self.assertEqual(mdm.url_key("http://app.gym.test:4100/d2/sub/", UP), "http://app.gym.test:{port}/d2/sub")
        self.assertEqual(mdm.url_key("http://app.gym.test:9/x", UP), "http://app.gym.test:9/x")


class PageMetricsTests(unittest.TestCase):
    def test_same_page_on_two_hosts_scores_one(self):
        up = "# T\n\n[a](/s1/a/)\n\n* one"
        cx = "# T\n\n[a](http://site.example.test:4100/s1/a)\n\n- one"
        m = mdm.page_metrics(up, UP + "/s1/", UP, cx, CX + "/s1/", CX)
        self.assertEqual((m["block_f1"], m["ordered_ratio"], m["blocks"]), (1.0, 1.0, (3, 3)))

    def test_a_divergent_page_scores_below_one(self):
        m = mdm.page_metrics("# T\n\na\n\nb", UP + "/p", UP, "# T\n\nb\n\na", CX + "/p", CX)
        self.assertEqual(m["block_f1"], 1.0)
        self.assertLess(m["ordered_ratio"], 1.0)


def doc(site, path, markdown):
    return {"markdown": markdown, "metadata": {"sourceURL": f"{site}{path}", "statusCode": 200}}


class ScorerTests(unittest.TestCase):
    def test_pages_are_paired_by_origin_independent_url(self):
        up = {"success": True, "data": [doc(UP, "/s1/", "# T\n\na\n\nb"), doc(UP, "/s1/only-up", "x")]}
        cx = {"success": True, "data": [doc(CX, "/s1/", "# T\n\nb\n\na"), doc(CX, "/s1/only-cx", "y")]}
        scores = diff.markdown_scores(up, cx, UP, CX)
        self.assertEqual([r["page"] for r in scores["pages"]], ["{origin}/s1"])
        self.assertEqual((scores["only_upstream"], scores["only_crawlx"]), (1, 1))
        self.assertEqual(scores["mean_block_f1"], 1.0)
        self.assertAlmostEqual(scores["mean_ordered_ratio"], 2.0 * 2 / 6)

    def test_a_single_scrape_document_is_found(self):
        body = {"success": True, "data": doc(UP, "/s1/", "# T")}
        self.assertEqual(diff.pages_of(body), {UP + "/s1/": "# T"})
        self.assertEqual(diff.pages_of(None), {})
        scores = diff.markdown_scores(None, body, UP, CX)
        self.assertEqual((scores["pages"], scores["only_crawlx"], scores["mean_block_f1"]), ([], 1, None))

    def test_the_report_carries_both_metrics(self):
        def capture(site, markdown):
            raw = [{"method": "POST", "path": "/v2/scrape", "request": None, "status": 200,
                    "headers": ["content-type"],
                    "response": {"success": True, "data": doc(site, "/s1/", markdown)}}]
            return {"label": site, "api": site, "site": site, "seed": site + "/s1/", "fixture": "s1",
                    "sdk_version": "4.54.0", "calls": {"scrape": {"sdk": None, "sdk_wire": [], "raw": raw}}}

        up, cx = capture(UP, "# T\n\na\n\nb\n\nc"), capture(CX, "# T\n\nb\n\na\n\nd")
        report = diff.render_report(up, cx, diff.compare(up, cx), [])
        self.assertIn("## Markdown metrics", report)
        self.assertIn("| `scrape` | POST /v2/scrape | 1 | 0 | 0 | 0.7500 | 0.5000 |", report)
        self.assertIn("| `{origin}/s1` | 4 / 4 | 0.7500 | 0.5000 |", report)

    def test_no_pages_is_said_so(self):
        self.assertEqual(diff.markdown_summary({}), ["No page bodies on both sides."])


if __name__ == "__main__":
    unittest.main()
