"""Offline regression cases for the provenance tripwire."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("shingle", Path(__file__).parents[1] / "shingle.py")
shingle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shingle)
FIXTURES = Path(__file__).parent / "fixtures"


class ShingleTests(unittest.TestCase):
    def run_scan(self, tree, threshold=shingle.DEFAULT_THRESHOLD):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = shingle.main([
                "--crawlx-tree", str(tree),
                "--upstream-tree", str(FIXTURES / "upstream"),
                "--threshold", str(threshold),
            ])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_renamed_translated_copy_is_flagged(self):
        status, output, error = self.run_scan(FIXTURES / "copied")
        self.assertEqual(status, 1)
        self.assertIn("flagged_pairs=1", output)
        self.assertIn("score.rs\tscore.ts", output)
        self.assertIn("requires provenance review", error)
        self.assertNotIn("return", output)  # Reports never quote source material.

    def test_independent_equivalent_implementation_is_not_flagged(self):
        status, output, error = self.run_scan(FIXTURES / "independent")
        self.assertEqual(status, 0)
        self.assertIn("flagged_pairs=0", output)
        self.assertEqual(error, "")

    def test_threshold_is_inclusive(self):
        matches, _, _ = shingle.scan(FIXTURES / "copied", FIXTURES / "upstream")
        count = matches[0][0]
        self.assertEqual(self.run_scan(FIXTURES / "copied", count)[0], 1)
        self.assertEqual(self.run_scan(FIXTURES / "copied", count + 1)[0], 0)

    def test_literals_identifiers_comments_and_whitespace_are_normalized(self):
        first = 'let alpha = "hello"; if (alpha > 23) { return alpha + 4; }'
        second = 'let beta=\'bye\'; /* ignored */ if(beta>99){return beta+8;}'
        self.assertEqual(shingle.shingles(first), shingle.shingles(second))

    def test_rust_raw_byte_char_and_lifetime_tokens(self):
        source = 'r###"raw // /* text"### br#"bytes"# c"hello" b"data" \'x\' b\'y\' 23u64'
        self.assertEqual(list(shingle.tokenize(source, rust=True)), ["LIT"] * 7)
        self.assertEqual(list(shingle.tokenize("&'a str", rust=True)), ["&", "'", "ID", "ID"])

    def test_nested_rust_comments_and_escaped_js_literals(self):
        self.assertEqual(list(shingle.tokenize("/* a /* b */ c */ return", rust=True)), ["return"])
        self.assertEqual(list(shingle.tokenize('"a\\\"b" `a\\`b`')), ["LIT", "LIT"])

    def test_javascript_dollar_identifiers_and_literal_kinds_are_normalized(self):
        self.assertEqual(
            list(shingle.tokenize("$first _second false true null undefined .5 0x20 23n")),
            ["ID", "ID"] + ["LIT"] * 7,
        )

    def test_repeated_windows_count_once(self):
        tokens = " ".join(["alpha"] * 80)
        self.assertEqual(len(shingle.shingles(tokens)), 1)
        self.assertEqual(shingle.shingles("a b c"), set())

    def test_empty_or_missing_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_scan(Path(directory))[0], 2)
            self.assertEqual(self.run_scan(Path(directory) / "missing")[0], 2)

    def test_malformed_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "bad.rs").write_text('let source = "unterminated;', encoding="utf-8")
            status, _, error = self.run_scan(path)
            self.assertEqual(status, 2)
            self.assertIn("bad.rs: unterminated string literal", error)

    def test_javascript_regexp_literals_do_not_become_comments_or_strings(self):
        self.assertEqual(
            list(shingle.tokenize("const pattern = /[\"'/]+\\/word/gi; value / 2;")),
            ["const", "ID", "=", "LIT", ";", "ID", "/", "LIT", ";"],
        )

    def test_output_is_deterministic(self):
        self.assertEqual(self.run_scan(FIXTURES / "copied"), self.run_scan(FIXTURES / "copied"))


class IdiomFilterTests(unittest.TestCase):
    """Shingles present in many files of a tree are idioms, not copied code."""

    KEYWORDS = ["if", "else", "for", "while", "return", "break", "continue", "match", "let", "mut"]

    def boilerplate(self):
        """Sixty-odd keyword tokens in a fixed pseudo-random order: many distinct 12-token windows."""
        state, words = 7, []
        for _ in range(70):
            state = (state * 31 + 11) % 1009
            words.append(self.KEYWORDS[state % len(self.KEYWORDS)])
        return " ".join(words)

    def trees(self, directory, crawlx_copies):
        root = Path(directory)
        (root / "crawlx").mkdir()
        (root / "upstream").mkdir()
        for number in range(crawlx_copies):
            (root / "crawlx" / f"idiom{number}.rs").write_text(self.boilerplate(), encoding="utf-8")
        (root / "upstream" / "idiom.ts").write_text(self.boilerplate(), encoding="utf-8")
        return root / "crawlx", root / "upstream"

    def test_a_window_set_in_one_file_per_tree_is_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            crawlx, upstream = self.trees(directory, 1)
            matches, _, _ = shingle.scan(crawlx, upstream)
            self.assertGreaterEqual(matches[0][0], shingle.DEFAULT_THRESHOLD)

    def test_a_window_set_repeated_across_the_tree_is_an_idiom(self):
        with tempfile.TemporaryDirectory() as directory:
            crawlx, upstream = self.trees(directory, shingle.DEFAULT_MAX_DOC_FREQ + 1)
            self.assertEqual(shingle.scan(crawlx, upstream)[0], [])
            unfiltered, _, _ = shingle.scan(crawlx, upstream, max_doc_freq=0)
            self.assertGreaterEqual(unfiltered[0][0], shingle.DEFAULT_THRESHOLD)

    def test_the_filter_boundary_is_inclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            crawlx, upstream = self.trees(directory, shingle.DEFAULT_MAX_DOC_FREQ)
            self.assertGreaterEqual(shingle.scan(crawlx, upstream)[0][0][0], shingle.DEFAULT_THRESHOLD)

    def test_max_doc_freq_zero_disables_the_filter_on_the_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            crawlx, upstream = self.trees(directory, shingle.DEFAULT_MAX_DOC_FREQ + 1)
            for extra, status in (([], 0), (["--max-doc-freq", "0"], 1)):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = shingle.main(["--crawlx-tree", str(crawlx), "--upstream-tree", str(upstream), *extra])
                self.assertEqual(code, status)


if __name__ == "__main__":
    unittest.main()
