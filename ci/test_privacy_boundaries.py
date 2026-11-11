"""Offline tests for concrete raw transport and provider boundary enforcement."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("privacy_boundaries", HERE / "privacy-boundaries.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
DOMAIN = "crawlx-core/src/domain.rs"
ADAPTER = "crawlx-model/src/llm/chat_completions.rs"
ALLOW = '#[allow(clippy::disallowed_types, reason = "bounded HTTP adapter boundary")]\n'


class PrivacyBoundaryTests(unittest.TestCase):
    def test_qualified_import_alias_glob_and_extern_crate_are_rejected(self):
        for source in [
            "struct State { client: reqwest::Client }",
            "use reqwest::{Client as Transport, Response};",
            "use reqwest::*;",
            "use ::reqwest as transport;",
            "extern crate reqwest as transport;",
            "type Provider = aws_sdk_kms::Client;",
            "fn call(body: hyper::body::Incoming) {}",
            "use wreq::Client;",
            "use hyper_util::client::legacy::Client;",
            "use r#reqwest::Client;",
            "type Request = http::Request<()>;",
            "use http::{Request as WireRequest, Response};",
            "use http::request::Request;",
            "use http as transport;",
        ]:
            with self.subTest(source=source):
                self.assertTrue(GATE.violations(DOMAIN, source))

    def test_comments_strings_and_lifetimes_preserve_locations(self):
        source = r'''// reqwest::Client
/* outer /* reqwest::Client */ aws_sdk_kms::Client */
const EXAMPLE: &str = "reqwest::Client";
const RAW: &str = r###"quote \" reqwest::Client /*"###;
const BYTE: &[u8] = br#"hyper::body::Incoming"#;
const C: char = '\'';
fn clean<'a>(value: &'a str) -> &'a str { value }
fn bad() { let client = reqwest::Client::new(); }
'''
        hits = GATE.violations(DOMAIN, source)
        self.assertEqual(len(hits), 1)
        self.assertIn(":8:", hits[0])

    def test_multiline_commented_imports_still_fail(self):
        source = "use\n reqwest /* explanation */ ::\n {Client as Http};"
        self.assertEqual(len(GATE.violations(DOMAIN, source)), 1)

    def test_test_modules_are_scanned_and_need_explicit_justified_item_allow(self):
        source = '''#[cfg(test)]
mod tests {
    use reqwest::Client;
    fn fixture() { if true { let _ = Client::new(); } }
}
use reqwest::Response;
'''
        self.assertEqual(len(GATE.violations(DOMAIN, source)), 2)
        # One concrete test module may own its fixture transport; its adjacent
        # production declaration is still rejected.
        source = source.replace("mod tests", ALLOW + "mod tests")
        hits = GATE.violations(DOMAIN, source)
        self.assertEqual(len(hits), 1)
        self.assertIn(":7:", hits[0])

    def test_root_or_reasonless_allows_cannot_bypass_adapter_policy(self):
        for attributes in [
            '#![allow(clippy::disallowed_types, reason = "adapter")]',
            '#[allow(clippy::disallowed_types)]',
            '#[allow(clippy::disallowed_types, reason = " ")]',
            '#[allow(clippy::disallowed_types /* reason = "not an actual lint reason" */)]',
            '#[cfg(feature = "http")]',
            '#[cfg(not(test))]',
        ]:
            with self.subTest(attributes=attributes):
                self.assertTrue(GATE.violations(ADAPTER, attributes + "\nuse reqwest::Client;"))
        self.assertTrue(GATE.violations(DOMAIN, ALLOW + "use reqwest::Client;"))

    def test_file_envelope_does_not_itself_grant_raw_access(self):
        self.assertTrue(GATE.violations(ADAPTER, "use reqwest::Client;"))
        self.assertFalse(GATE.violations(ADAPTER, ALLOW + "use reqwest::Client;"))
        self.assertTrue(GATE.violations(ADAPTER, ALLOW + "use aws_sdk_kms::Client;"))
        self.assertTrue(GATE.violations(ADAPTER + "/child.rs", ALLOW + "use reqwest::Client;"))
        self.assertTrue(GATE.violations("crawlx-model/src/llm/new.rs", ALLOW + "use reqwest::Client;"))
        for path, (namespaces, reason) in GATE.ADAPTERS.items():
            self.assertTrue(reason.strip())
            self.assertTrue(namespaces <= GATE.RAW_NAMESPACES)
            self.assertNotIn("*", path)
            self.assertTrue(path.endswith(".rs"))

    def test_item_allow_does_not_cover_siblings(self):
        source = ALLOW + "fn adapter() { let _ = reqwest::Client::new(); }\n"
        source += "fn sibling() { let _ = reqwest::Client::new(); }"
        hits = GATE.violations(ADAPTER, source)
        self.assertEqual(len(hits), 1)
        self.assertIn(":3:", hits[0])

    def test_field_allow_stops_before_sibling_fields_and_next_impl(self):
        for field in [
            "client: reqwest::Client,",
            "pub(crate) client: Option<reqwest::Client>,",
            "client: fn(u8, u8) -> Result<reqwest::Client, ()>,",
            "#[serde(default)]\nclient: reqwest::Client,",
        ]:
            source = "struct Adapter {\n" + ALLOW + field
            source += "\nsibling: reqwest::Client,\n}\n"
            source += "impl Adapter { fn raw() { let _ = reqwest::Client::new(); } }"
            hits = GATE.violations(ADAPTER, source)
            self.assertEqual(len(hits), 2)
        source = "struct Adapter {\n" + ALLOW + "client: reqwest::Client\n}\n"
        source += "impl Adapter { fn raw() { let _ = reqwest::Client::new(); } }"
        self.assertEqual(len(GATE.violations(ADAPTER, source)), 1)

    def test_benign_header_status_and_url_types_do_not_need_privacy_exceptions(self):
        source = "use reqwest::{header::HeaderMap, StatusCode}; fn value() -> reqwest::Url { todo!() }"
        self.assertFalse(GATE.violations(DOMAIN, source))

    def test_raw_reexports_fail_even_inside_annotated_adapter(self):
        for source in [
            "pub use reqwest::Client;",
            "pub(crate) use reqwest as transport;",
            "pub use reqwest::{Client, Response};",
        ]:
            with self.subTest(source=source):
                self.assertTrue(GATE.violations(ADAPTER, ALLOW + source))

    def test_failures_report_locations_without_source_contents(self):
        secret = "generated-" + "diagnostic-" * 3
        hits = GATE.violations(DOMAIN, f'let {secret.replace("-", "_")} = reqwest::Client::new();')
        self.assertTrue(hits)
        self.assertNotIn(secret, "\n".join(hits))
        self.assertNotIn("Client::new", "\n".join(hits))

    def test_missing_empty_and_unreadable_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertTrue(GATE.check(root))
            (root / "crates").mkdir()
            self.assertTrue(GATE.check(root))
            source = root / "crates/crawlx-core/src/domain.rs"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"\xff")
            self.assertTrue(GATE.check(root))
            source.write_text("/* unterminated", encoding="utf-8")
            self.assertTrue(GATE.check(root))

    def test_walk_includes_new_crates_integration_tests_and_fixture_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "crates/new-domain/src/nested/worker.rs"
            source.parent.mkdir(parents=True)
            source.write_text("struct SafeState;", encoding="utf-8")
            fixture = root / "crates/new-domain/tests/fixture.rs"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("use reqwest::Client;", encoding="utf-8")
            hits = GATE.check(root)
            self.assertEqual(len(hits), 1)
            self.assertIn("new-domain/tests/fixture.rs", hits[0])
            fixture.write_text(ALLOW + "use reqwest::Client;", encoding="utf-8")
            self.assertFalse(GATE.check(root))


if __name__ == "__main__":
    unittest.main()
