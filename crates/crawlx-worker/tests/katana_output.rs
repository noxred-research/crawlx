//! Output parity: katana's `-mdc/-fdc`, `-fpt`, `-mr/-fr`, `-f`, `-or/-ob/-eof`,
//! `-lof`, `-sr/-srd`, `-ncb`, `-o`, `-elog`, the JSONL record additions, the
//! `KATANA_TRAFFIC_*` exporter against a local collector, and a real crawl feeding the
//! output layer. Deterministic, no network beyond loopback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use crawlx_core::hash::Digest;
use crawlx_core::repo::PageRecord;
use crawlx_core::{CrawlRunId, TrustLane};
use crawlx_worker::katana::traffic_export::{
    Exchange, TrafficExportConfig, TrafficExportError, TrafficExporter,
};
use crawlx_worker::output::{
    expand_patterns, field_names, write_error_log, Dsl, ExportFormat, Exporter, Field, OutputFilters,
    PageText, StoreFields, StoredResponses, Template, TextFile,
};
use crawlx_worker::UrlFailure;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------------------
// helpers

fn page(url: &str, status: u16, metadata: Value) -> PageRecord {
    PageRecord {
        run: CrawlRunId::new(),
        frontier_id: 1,
        url: crawlx_storage::testkit::canonical_url(url),
        status,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", b"x"),
        title: None,
        markdown: None,
        html: None,
        metadata,
        links: Vec::new(),
        fetched_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        lane: TrustLane::Diagnostic,
    }
}

/// Metadata as the URL plane writes it (page-metadata contract), every katana key present.
fn full_metadata() -> Value {
    json!({
        "request": {
            "method": "POST",
            "headers": {"content-type": "application/x-www-form-urlencoded", "cookie": "[redacted]"},
            "body": "user=a",
            "raw": "POST /p HTTP/1.1\r\nhost: e.com\r\n\r\nuser=a",
            "custom_fields": {"email": ["a@e.com"]},
            "tag": "form", "attribute": "action", "source": "https://e.com/"
        },
        "response_headers": {"content-type": "text/html", "server": "nginx"},
        "content_length": 321,
        "technologies": [{"name": "nginx", "evidence": "header:server"}],
        "page_type": "login",
        "forms": [{
            "action": "https://e.com/login", "method": "POST",
            "enctype": "application/x-www-form-urlencoded",
            "inputs": [
                {"name": "username", "kind": "text", "required": false, "options": []},
                {"name": "password", "kind": "password", "required": false, "options": []}
            ],
            "submit_labels": ["Log in"]
        }],
        "custom_fields": {"email": ["a@e.com"]},
        "secrets": [{"kind": "jwt", "location": {"body": {"offset": 3}}, "value_hash": "ab", "validation": "unknown"}],
        "xhr_requests": [{"method": "GET", "url": "https://e.com/api", "status": 200, "resource_type": "xhr"}],
        "endpoints": [{"url": "https://e.com/api", "method": "GET", "class": "rest"}]
    })
}

fn export(exporter: &Exporter, pages: &[PageRecord]) -> String {
    let mut out = Vec::new();
    exporter.export_pages(pages, |_| None, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn jsonl(exporter: &Exporter, pages: &[PageRecord], text: PageText) -> Vec<Value> {
    let mut out = Vec::new();
    exporter
        .export_pages_with(pages, |_| text.clone(), &mut out)
        .unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn jsonl_exporter() -> Exporter {
    Exporter {
        format: ExportFormat::Jsonl,
        ..Exporter::default()
    }
}

fn s(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

// ---------------------------------------------------------------------------------------
// -mdc / -fdc

fn status_pages() -> Vec<PageRecord> {
    vec![
        page(
            "https://e.com/ok",
            200,
            json!({"response_headers": {"content-type": "text/html"}, "technologies": [{"name": "PHP", "evidence": "x"}]}),
        ),
        page(
            "https://e.com/forbidden",
            403,
            json!({"response_headers": {"content-type": "application/json"}}),
        ),
        page(
            "https://e.com/default/home",
            200,
            json!({"technologies": [{"name": "Cloudflare", "evidence": "x"}]}),
        ),
        page("https://e.com/default/denied", 403, json!({})),
    ]
}

fn urls(lines: &str) -> Vec<&str> {
    lines.lines().collect()
}

#[test]
fn match_condition_selects_by_status_code() {
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("status_code == 200").unwrap()),
        ..Exporter::default()
    };
    assert_eq!(
        urls(&export(&exporter, &status_pages())),
        ["https://e.com/ok", "https://e.com/default/home"]
    );
}

#[test]
fn katana_readme_conditions_work() {
    // README.md:1075-1115, each example against the same fixture
    let cases: [(&str, bool, &[&str]); 3] = [
        (
            "contains(endpoint, \"default\") && status_code != 403",
            true,
            &["https://e.com/default/home"],
        ),
        (
            "contains(to_lower(technologies), \"php\")",
            true,
            &["https://e.com/ok"],
        ),
        (
            "contains(to_lower(technologies), \"cloudflare\")",
            false,
            &[
                "https://e.com/ok",
                "https://e.com/forbidden",
                "https://e.com/default/denied",
            ],
        ),
    ];
    for (condition, as_match, expected) in cases {
        let dsl = Some(Dsl::parse(condition).unwrap());
        let exporter = if as_match {
            Exporter {
                match_condition: dsl,
                ..Exporter::default()
            }
        } else {
            Exporter {
                filter_condition: dsl,
                ..Exporter::default()
            }
        };
        assert_eq!(urls(&export(&exporter, &status_pages())), expected, "{condition}");
    }
}

#[test]
fn conditions_see_headers_and_nested_paths_in_jsonl() {
    let exporter = Exporter {
        match_condition: Some(
            Dsl::parse("response.headers.content-type contains \"json\" && request.method == \"GET\"")
                .unwrap(),
        ),
        ..jsonl_exporter()
    };
    let records = jsonl(&exporter, &status_pages(), PageText::default());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["request"]["endpoint"], "https://e.com/forbidden");
}

#[test]
fn filter_and_match_conditions_combine_and_filter_wins() {
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("status_code == 200").unwrap()),
        filter_condition: Some(Dsl::parse("contains(url, \"default\")").unwrap()),
        ..Exporter::default()
    };
    assert_eq!(urls(&export(&exporter, &status_pages())), ["https://e.com/ok"]);
}

#[test]
fn a_condition_that_cannot_be_evaluated_never_matches_and_never_filters() {
    let page_set = status_pages();
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("no_such_field == 1").unwrap()),
        ..Exporter::default()
    };
    assert_eq!(export(&exporter, &page_set), "");
    let exporter = Exporter {
        filter_condition: Some(Dsl::parse("no_such_field == 1").unwrap()),
        ..Exporter::default()
    };
    assert_eq!(urls(&export(&exporter, &page_set)).len(), 4);
}

#[test]
fn dsl_errors_report_the_position() {
    let err = Dsl::parse("status_code == 200 && ").unwrap_err();
    assert_eq!(err.position(), Some(22));
    assert!(err.to_string().contains("byte 22"), "{err}");
    let err = Dsl::parse("nosuch(1)").unwrap_err();
    assert_eq!(err.position(), Some(0));
}

#[test]
fn body_conditions_load_the_body_without_emitting_it() {
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("contains(body, \"needle\")").unwrap()),
        ..jsonl_exporter()
    };
    let pages = status_pages();
    let mut out = Vec::new();
    exporter
        .export_pages(
            &pages,
            |p| {
                Some(
                    if p.url.url.path() == "/forbidden" {
                        "hay needle hay"
                    } else {
                        "hay"
                    }
                    .to_owned(),
                )
            },
            &mut out,
        )
        .unwrap();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["request"]["endpoint"], "https://e.com/forbidden");
    assert!(v["response"].get("body").is_none());
}

#[test]
fn trim_conditions_select_and_filter_without_emitting_loaded_body() {
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("trim_space(trim_prefix(body, 'prefix:')) == 'keep'").unwrap()),
        filter_condition: Some(
            Dsl::parse("trim_suffix(trim_prefix(endpoint, 'https://e.com/'), '/home') == 'default'").unwrap(),
        ),
        ..jsonl_exporter()
    };
    let records = jsonl(
        &exporter,
        &status_pages(),
        PageText::default().with_body("prefix: \u{a0}keep\u{3000}\n"),
    );
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| {
        record["request"]["endpoint"] != "https://e.com/default/home"
            && record["response"].get("body").is_none()
    }));
}

// ---------------------------------------------------------------------------------------
// -fpt

#[test]
fn filter_page_type_drops_from_output_only() {
    let pages = vec![
        page("https://e.com/login", 200, json!({"page_type": "login"})),
        page("https://e.com/err", 500, json!({"page_type": "error"})),
        page("https://e.com/ok", 200, json!({"page_type": "article"})),
    ];
    let exporter = Exporter {
        filter_page_types: s(&["Error", "captcha"]),
        ..Exporter::default()
    };
    let out = export(&exporter, &pages);
    assert_eq!(urls(&out), ["https://e.com/login", "https://e.com/ok"]);
    // the pages themselves are untouched
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[1].metadata["page_type"], "error");
    // JSONL too
    let exporter = Exporter {
        filter_page_types: s(&["login"]),
        ..jsonl_exporter()
    };
    assert_eq!(jsonl(&exporter, &pages, PageText::default()).len(), 2);
}

// ---------------------------------------------------------------------------------------
// -mr / -fr / -f

#[test]
fn match_and_filter_regex_lists_accept_commas_and_files() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("fr.txt");
    std::fs::write(&file, "# skip these\nforbidden\n\ndenied\n").unwrap();
    let mr = expand_patterns(&s(&["/ok,/default"])).unwrap();
    assert_eq!(mr, ["/ok", "/default"]);
    let fr = expand_patterns(&[file.to_string_lossy().into_owned()]).unwrap();
    assert_eq!(fr, ["forbidden", "denied"]);
    let exporter = Exporter {
        filters: OutputFilters::new(&mr, &fr, &[], &[]).unwrap(),
        ..Exporter::default()
    };
    assert_eq!(
        urls(&export(&exporter, &status_pages())),
        ["https://e.com/ok", "https://e.com/default/home"]
    );
}

#[test]
fn comma_separated_field_lists_emit_each_field() {
    let pages = vec![page(
        "https://e.com/a/b.php?x=1",
        200,
        json!({"custom_fields": {"email": ["m@e.com"]}}),
    )];
    let exporter = Exporter {
        fields: Field::parse_list("fqdn,file,key,email").unwrap(),
        ..Exporter::default()
    };
    assert_eq!(
        urls(&export(&exporter, &pages)),
        ["e.com", "b.php", "x", "m@e.com"]
    );
    assert!(Field::parse_list("fqdn,not a field").is_err());
}

#[test]
fn stored_fields_are_independent_of_display_and_template_fields() {
    let dir = tempfile::tempdir().unwrap();
    let pages = vec![page(
        "https://e.com:8443/a/b.php?x=1&y=2",
        200,
        json!({"custom_fields": {"email": ["m@e.com"]}}),
    )];
    let words = StoreFields::new(dir.path());
    let exporter = Exporter {
        fields: vec![Field::Url],
        store_fields: Some(words.clone()),
        stored_field_selection: Some(Field::parse_list("qurl,key").unwrap()),
        ..Exporter::default()
    };
    assert_eq!(export(&exporter, &pages), "https://e.com:8443/a/b.php?x=1&y=2\n");
    let url = &pages[0].url.url;
    assert_eq!(
        std::fs::read_to_string(words.file_for(url, &Field::Qurl)).unwrap(),
        "https://e.com:8443/a/b.php?x=1&y=2\n"
    );
    assert_eq!(
        std::fs::read_to_string(words.file_for(url, &Field::Key)).unwrap(),
        "x\ny\n"
    );
    assert!(!words.file_for(url, &Field::Url).exists());
    assert!(words
        .file_for(url, &Field::Key)
        .ends_with("https_e.com_8443_key.txt"));

    let exporter = Exporter {
        template: Some(Template::parse("{{email}} {{path}}").unwrap()),
        ..exporter
    };
    assert_eq!(export(&exporter, &pages), "m@e.com /a/b.php\n");
    assert!(!words.file_for(url, &Field::Path).exists());
    assert!(!words.file_for(url, &Field::Custom("email".to_owned())).exists());
    assert_eq!(
        std::fs::read_to_string(words.file_for(url, &Field::Key)).unwrap(),
        "x\ny\n",
        "wordlists retain stable deduplication across exports"
    );
}

#[test]
fn explicit_empty_stored_fields_do_not_fall_back_to_display_fields() {
    let dir = tempfile::tempdir().unwrap();
    let exporter = Exporter {
        store_fields: Some(StoreFields::new(dir.path())),
        stored_field_selection: Some(Vec::new()),
        ..Exporter::default()
    };
    assert_eq!(export(&exporter, &status_pages()).lines().count(), 4);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn jsonl_can_store_custom_fields_without_storing_display_fields() {
    let dir = tempfile::tempdir().unwrap();
    let words = StoreFields::new(dir.path());
    let pages = vec![page("http://[::1]:81/a", 200, full_metadata())];
    let exporter = Exporter {
        fields: vec![Field::Url],
        store_fields: Some(words.clone()),
        stored_field_selection: Some(Field::parse_list("email,missing_custom").unwrap()),
        ..jsonl_exporter()
    };
    assert_eq!(jsonl(&exporter, &pages, PageText::default()).len(), 1);
    let path = words.file_for(&pages[0].url.url, &Field::Custom("email".to_owned()));
    assert!(!path.file_name().unwrap().to_str().unwrap().contains(':'));
    assert_eq!(std::fs::read_to_string(path).unwrap(), "a@e.com\n");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn missing_template_values_do_not_suppress_explicit_wordlists_or_bypass_filters() {
    let pages = vec![
        page("https://e.com/allowed.php?kept=1", 200, json!({})),
        page("https://e.com/filtered.php?regex_denied=1", 200, json!({})),
        page("https://e.com/error.php?condition_denied=1", 500, json!({})),
        page(
            "https://e.com/login.php?type_denied=1",
            200,
            json!({"page_type": "login"}),
        ),
        page("https://e.com/image.png?extension_denied=1", 200, json!({})),
    ];
    for combined_jsonl in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let words = StoreFields::new(dir.path().join("selected"));
        let text = Exporter {
            template: Some(Template::parse("{{email}} {{url}}").unwrap()),
            store_fields: Some(words.clone()),
            stored_field_selection: Some(Field::parse_list("qurl,key").unwrap()),
            filters: OutputFilters::new(
                &["https://e.com/".to_owned()],
                &["filtered".to_owned()],
                &[],
                &["png".to_owned()],
            )
            .unwrap(),
            filter_condition: Some(Dsl::parse("status_code != 200").unwrap()),
            filter_page_types: s(&["login"]),
            ..Exporter::default()
        };
        if combined_jsonl {
            let jsonl = Exporter {
                format: ExportFormat::Jsonl,
                store_fields: None,
                ..text.clone()
            };
            assert_eq!(export(&jsonl, &pages).lines().count(), 1);
        }
        assert_eq!(export(&text, &pages), "");
        assert_eq!(
            std::fs::read_to_string(words.file_for(&pages[0].url.url, &Field::Qurl)).unwrap(),
            "https://e.com/allowed.php?kept=1\n"
        );
        assert_eq!(
            std::fs::read_to_string(words.file_for(&pages[0].url.url, &Field::Key)).unwrap(),
            "kept\n"
        );
        assert_eq!(std::fs::read_dir(words.dir()).unwrap().count(), 2);

        let legacy_words = StoreFields::new(dir.path().join("legacy"));
        let legacy = Exporter {
            store_fields: Some(legacy_words.clone()),
            stored_field_selection: None,
            ..text
        };
        assert_eq!(export(&legacy, &pages), "");
        assert!(!legacy_words.dir().exists());
    }
}

// ---------------------------------------------------------------------------------------
// JSONL record additions, -or / -ob / -eof / -lof

#[test]
fn jsonl_record_carries_every_katana_field() {
    let pages = vec![page("https://e.com/p", 200, full_metadata())];
    let exporter = Exporter {
        include_body: true,
        knowledge_base: true,
        ..jsonl_exporter()
    };
    let text = PageText::default()
        .with_body("<html/>")
        .with_raw("HTTP/1.1 200 OK\r\n\r\n<html/>");
    let v = &jsonl(&exporter, &pages, text)[0];
    assert_eq!(v["request"]["method"], "POST");
    assert_eq!(v["request"]["endpoint"], "https://e.com/p");
    assert_eq!(v["request"]["body"], "user=a");
    assert_eq!(v["request"]["headers"]["cookie"], "[redacted]");
    assert_eq!(
        v["request"]["raw"],
        "POST /p HTTP/1.1\r\nhost: e.com\r\n\r\nuser=a"
    );
    assert_eq!(v["request"]["custom_fields"]["email"][0], "a@e.com");
    assert_eq!(
        v["response"]["custom_fields"]["email"][0], "a@e.com",
        "crawlx's older key stays"
    );
    assert_eq!(v["response"]["status_code"], 200);
    assert_eq!(v["response"]["content_length"], 321);
    assert_eq!(v["response"]["body"], "<html/>");
    assert_eq!(v["response"]["raw"], "HTTP/1.1 200 OK\r\n\r\n<html/>");
    assert_eq!(
        v["response"]["xhr_requests"][0],
        json!({"method": "GET", "endpoint": "https://e.com/api", "status": 200, "resource_type": "xhr"})
    );
    let kb = &v["response"]["knowledgebase"];
    assert_eq!(kb["PageType"], "login");
    assert_eq!(kb["Forms"][0]["type"], "login");
    assert_eq!(kb["Forms"][0]["fields"]["password"], "password");
    assert_eq!(kb["secrets"][0]["validation"], "unknown");
    assert_eq!(kb["endpoints"][0]["class"], "rest");
    assert!(v.get("error").is_none());
}

#[test]
fn knowledgebase_and_xhr_only_when_present() {
    let pages = vec![page("https://e.com/p", 200, json!({"page_type": "login"}))];
    let v = &jsonl(&jsonl_exporter(), &pages, PageText::default())[0];
    assert!(v["response"].get("knowledgebase").is_none(), "without -kb");
    assert!(v["response"].get("xhr_requests").is_none());
    let exporter = Exporter {
        knowledge_base: true,
        ..jsonl_exporter()
    };
    let v = &jsonl(&exporter, &pages, PageText::default())[0];
    assert_eq!(v["response"]["knowledgebase"]["PageType"], "login");
}

#[test]
fn omit_raw_and_omit_body_remove_them_from_the_record() {
    let pages = vec![page("https://e.com/p", 200, full_metadata())];
    let text = PageText::default()
        .with_body("<html/>")
        .with_raw("HTTP/1.1 200 OK\r\n\r\n<html/>");
    let base = Exporter {
        include_body: true,
        ..jsonl_exporter()
    };
    let v = jsonl(&base, &pages, text.clone()).remove(0);
    assert!(
        v["response"]["body"].is_string()
            && v["response"]["raw"].is_string()
            && v["request"]["raw"].is_string()
    );

    let omit_raw = Exporter {
        omit_raw: true,
        ..base.clone()
    };
    let v = jsonl(&omit_raw, &pages, text.clone()).remove(0);
    assert!(v["response"].get("raw").is_none() && v["request"].get("raw").is_none());
    assert!(v["response"]["body"].is_string(), "-or keeps the body");

    let omit_body = Exporter {
        omit_body: true,
        ..base
    };
    let v = jsonl(&omit_body, &pages, text).remove(0);
    assert!(v["response"].get("body").is_none());
    assert!(v["response"]["raw"].is_string(), "-ob keeps raw");
}

/// Every key at the record's three levels.
fn keys(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    for part in ["request", "response"] {
        if let Some(o) = v.get(part).and_then(Value::as_object) {
            out.extend(o.keys().cloned());
        }
    }
    out
}

#[test]
fn every_listed_output_field_is_present_and_excludable_through_the_exporter() {
    let dir = tempfile::tempdir().unwrap();
    let pages = vec![page("https://e.com/p", 200, full_metadata())];
    let text = PageText::default()
        .with_body("<html/>")
        .with_raw("HTTP/1.1 200 OK\r\n\r\n");
    // every page field: body, raw, knowledgebase, stored_response_path
    let full = Exporter {
        include_body: true,
        knowledge_base: true,
        stored_responses: Some(StoredResponses::new(dir.path().join("sr"), false).unwrap()),
        ..jsonl_exporter()
    };
    let failures = [UrlFailure::new("https://e.com/x", 1, "http_500")];
    let failure_keys = |exporter: &Exporter| -> Vec<String> {
        let mut out = Vec::new();
        exporter.export_failures(&failures, &mut out).unwrap();
        keys(&serde_json::from_slice::<Value>(&out).unwrap())
    };
    let mut present = keys(&jsonl(&full, &pages, text.clone()).remove(0));
    present.extend(failure_keys(&jsonl_exporter()));

    let names = field_names();
    assert!(names.windows(2).all(|w| w[0] < w[1]), "-lof is sorted and unique");
    for name in names {
        // `extra` is for embedders: no page metadata produces it
        if name == "extra" {
            continue;
        }
        assert!(
            present.iter().any(|k| k == name),
            "`{name}` never appears in an exported record"
        );
        let excluded = Exporter {
            exclude_fields: vec![name.to_owned()],
            ..full.clone()
        };
        let record = jsonl(&excluded, &pages, text.clone()).remove(0);
        assert!(
            !keys(&record).iter().any(|k| k == name),
            "-eof {name} left it in the page record"
        );
        let excluded = Exporter {
            exclude_fields: vec![name.to_owned()],
            ..jsonl_exporter()
        };
        assert!(
            !failure_keys(&excluded).iter().any(|k| k == name),
            "-eof {name} left it in the failure record"
        );
    }
    // one exclusion leaves the other fields alone
    let some = Exporter {
        exclude_fields: s(&["raw", "body", "knowledgebase"]),
        ..full
    };
    let v = jsonl(&some, &pages, text).remove(0);
    assert_eq!(v["response"]["status_code"], 200);
    assert_eq!(v["request"]["method"], "POST");
    assert!(v["response"]["stored_response_path"].is_string());
}

#[test]
fn eof_accepts_names_shared_by_request_and_response() {
    let pages = vec![page("https://e.com/p", 200, full_metadata())];
    let exporter = Exporter {
        exclude_fields: s(&["headers", "custom_fields", "raw"]),
        ..jsonl_exporter()
    };
    let v = jsonl(&exporter, &pages, PageText::default().with_raw("x")).remove(0);
    for part in ["request", "response"] {
        for k in ["headers", "custom_fields", "raw"] {
            assert!(v[part].get(k).is_none(), "{part}.{k}");
        }
    }
}

// ---------------------------------------------------------------------------------------
// -sr / -srd / -ncb / -o / -elog

#[test]
fn store_response_writes_files_index_and_the_path_on_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = StoredResponses::new(dir.path().join("resp"), false).unwrap();
    let pages = vec![
        page("https://e.com:8443/a?b=1", 200, full_metadata()),
        page("https://e.com/missing", 404, json!({})),
    ];
    let exporter = Exporter {
        stored_responses: Some(store.clone()),
        ..jsonl_exporter()
    };
    let mut out = Vec::new();
    let stats = exporter
        .export_pages_with(
            &pages,
            |p| {
                PageText::default()
                    .with_body(format!("body of {}", p.url.url.path()))
                    .with_raw(format!("RAW {}", p.url.url.path()))
            },
            &mut out,
        )
        .unwrap();
    assert_eq!(stats.stored, 2);
    let records: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let first = records[0]["response"]["stored_response_path"].as_str().unwrap();
    assert!(
        first.contains("e.com_8443"),
        "host directory replaces ':' with '_': {first}"
    );
    let text = std::fs::read_to_string(first).unwrap();
    assert!(
        text.starts_with("https://e.com:8443/a?b=1\n\n\nPOST /p HTTP/1.1"),
        "metadata raw request: {text}"
    );
    assert!(text.ends_with("\n\nRAW /a\n"), "{text}");
    // second page has no captured raw: both texts are rebuilt from the record
    let second =
        std::fs::read_to_string(records[1]["response"]["stored_response_path"].as_str().unwrap()).unwrap();
    assert!(
        second.contains("GET /missing HTTP/1.1") && second.contains("host: e.com"),
        "{second}"
    );
    // the page also had `RAW /missing` supplied, which wins over the rebuilt text
    assert!(second.contains("RAW /missing"), "{second}");
    let index = std::fs::read_to_string(store.index_path()).unwrap();
    let lines: Vec<&str> = index.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].ends_with(" https://e.com:8443/a?b=1 (200 OK)"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].ends_with(" https://e.com/missing (404 Not Found)"),
        "{}",
        lines[1]
    );
}

#[test]
fn store_response_also_runs_in_text_mode() {
    let dir = tempfile::tempdir().unwrap();
    let store = StoredResponses::new(dir.path().join("resp"), false).unwrap();
    let exporter = Exporter {
        stored_responses: Some(store.clone()),
        ..Exporter::default()
    };
    let mut out = Vec::new();
    let stats = exporter
        .export_pages_with(
            &status_pages(),
            |_| PageText::default().with_body("b").with_raw("r"),
            &mut out,
        )
        .unwrap();
    assert_eq!(stats.stored, 4);
    assert_eq!(
        std::fs::read_to_string(store.index_path())
            .unwrap()
            .lines()
            .count(),
        4
    );
    assert_eq!(urls(&String::from_utf8(out).unwrap()).len(), 4);
}

#[test]
fn no_clobber_never_overwrites_an_earlier_store_directory() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("resp");
    let pages = vec![page("https://e.com/a", 200, json!({}))];
    let run = |no_clobber: bool| -> std::path::PathBuf {
        let store = StoredResponses::new(&target, no_clobber).unwrap();
        let exporter = Exporter {
            stored_responses: Some(store.clone()),
            ..jsonl_exporter()
        };
        jsonl(&exporter, &pages, PageText::default().with_raw("r"));
        store.dir().to_owned()
    };
    assert_eq!(run(true), target);
    let first_files: Vec<_> = std::fs::read_dir(target.join("e.com")).unwrap().collect();
    assert_eq!(first_files.len(), 1);
    assert_eq!(run(true), dir.path().join("resp1"));
    assert_eq!(run(true), dir.path().join("resp2"));
    assert_eq!(
        std::fs::read_to_string(target.join("index.txt"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    // without -ncb the directory is reused and the index appended
    assert_eq!(run(false), target);
    assert_eq!(
        std::fs::read_to_string(target.join("index.txt"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn output_file_with_no_clobber_numbers_instead_of_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("urls.txt");
    let exporter = Exporter::default();
    for (round, expected) in [(1, "urls.txt"), (2, "urls1.txt"), (3, "urls2.txt")] {
        let mut file = TextFile::create(&target, true).unwrap();
        assert_eq!(file.path().file_name().unwrap(), expected);
        exporter
            .export_pages(
                &[page(&format!("https://e.com/{round}"), 200, json!({}))],
                |_| None,
                &mut file,
            )
            .unwrap();
        file.finish().unwrap();
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "https://e.com/1\n");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("urls2.txt")).unwrap(),
        "https://e.com/3\n"
    );
    // plain -o truncates
    let mut file = TextFile::create(&target, false).unwrap();
    file.write_all(b"fresh\n").unwrap();
    file.finish().unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "fresh\n");
}

#[test]
fn error_log_lists_failures_and_respects_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let failures = vec![
        UrlFailure::new("https://e.com/a", 1, "timeout"),
        UrlFailure::new("https://e.com/b", 2, "http_503"),
    ];
    let target = dir.path().join("errors.jsonl");
    let written = write_error_log(&target, &failures, true).unwrap();
    assert_eq!(written, target);
    let lines: Vec<Value> = std::fs::read_to_string(&target)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        (lines[0]["endpoint"].as_str(), lines[0]["error"].as_str()),
        (Some("https://e.com/a"), Some("timeout"))
    );
    assert_eq!(lines[1]["status_code"], 503);
    let second = write_error_log(&target, &failures[..1], true).unwrap();
    assert_eq!(second, dir.path().join("errors1.jsonl"));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap().lines().count(),
        2,
        "first log untouched"
    );
    // no failures: the file still exists, empty
    let empty = write_error_log(dir.path().join("none.log"), &[], false).unwrap();
    assert_eq!(std::fs::read_to_string(empty).unwrap(), "");
}

#[test]
fn failed_urls_are_exported_as_records_with_an_error() {
    let failures = vec![
        UrlFailure::new("https://e.com/gone", 1, "http_404"),
        UrlFailure::new("https://e.com/down", 2, "timeout"),
    ];
    let mut out = Vec::new();
    let stats = jsonl_exporter().export_failures(&failures, &mut out).unwrap();
    assert_eq!(stats.lines, 2);
    let records: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records[0]["error"], "http_404");
    assert_eq!(records[0]["response"]["status_code"], 404);
    assert_eq!(records[1]["error"], "timeout");
    assert!(records[1].get("response").is_none());
    // conditions can read `error`
    let exporter = Exporter {
        match_condition: Some(Dsl::parse("error == \"timeout\"").unwrap()),
        ..jsonl_exporter()
    };
    let mut out = Vec::new();
    assert_eq!(exporter.export_failures(&failures, &mut out).unwrap().lines, 1);
}

// ---------------------------------------------------------------------------------------
// traffic export against a local collector

fn config(server: &MockServer) -> TrafficExportConfig {
    let mut config = TrafficExportConfig::new(Url::parse(&format!("{}/ingest", server.uri())).unwrap());
    config.token = Some("tok-123".to_owned());
    config.flush_interval = Duration::from_secs(3600);
    config.retry_delays = vec![Duration::from_millis(10), Duration::from_millis(10)];
    config
}

async fn collector(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ingest"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

fn exchange(n: usize) -> Exchange {
    let ts = chrono::DateTime::from_timestamp(1_700_000_000 + i64::try_from(n).unwrap(), 0).unwrap();
    Exchange::new("url", ts, "GET", format!("https://target.test/{n}"), 200).with_response(
        BTreeMap::from([("content-type".to_owned(), "text/html".to_owned())]),
        Some(format!("body {n}")),
    )
}

/// The batches the collector received, each as its list of events.
async fn batches(server: &MockServer) -> Vec<Vec<Value>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let v: Value = serde_json::from_slice(&r.body).unwrap();
            assert!(v["batch_id"].is_string());
            v["events"].as_array().unwrap().clone()
        })
        .collect()
}

async fn wait_for_requests(server: &MockServer, n: usize) {
    for _ in 0..500 {
        if server.received_requests().await.unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("collector did not receive {n} requests");
}

#[tokio::test]
async fn events_are_batched_by_size_and_flush_posts_the_rest() {
    let server = collector(200).await;
    let mut cfg = config(&server);
    cfg.batch_size = 2;
    let exporter = TrafficExporter::new(cfg).unwrap();
    for n in 0..5 {
        exporter.record(exchange(n));
    }
    exporter.flush().await;
    let got = batches(&server).await;
    assert_eq!(got.iter().map(Vec::len).collect::<Vec<_>>(), [2, 2, 1]);
    let urls: Vec<&str> = got
        .iter()
        .flatten()
        .map(|e| e["request"]["full_url"].as_str().unwrap())
        .collect();
    assert_eq!(
        urls,
        (0..5)
            .map(|n| format!("https://target.test/{n}"))
            .collect::<Vec<_>>(),
        "order preserved"
    );
    let first = &got[0][0];
    assert_eq!(first["process"], "crawlx");
    assert_eq!(first["source_type"], "cli");
    assert_eq!(first["plane"], "url");
    assert_eq!(first["request"]["method"], "GET");
    assert_eq!(first["response"]["status"], 200);
    assert_eq!(first["response"]["status_text"], "OK");
    assert_eq!(first["response"]["content_type"], "text/html");
    assert_eq!(first["response"]["body_preview"], "body 0");
    assert_eq!(first["response"]["body_size"], 6);
    assert_eq!(first["timestamp"], "2023-11-14T22:13:20.000000000Z");
    let ids: std::collections::BTreeSet<&str> =
        got.iter().flatten().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 5, "unique event ids");
    // headers of the POSTs
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        "Bearer tok-123"
    );
    assert_eq!(
        requests[0].headers.get("content-type").unwrap(),
        "application/json"
    );
    let stats = exporter.stats();
    assert_eq!((stats.sent, stats.dropped, stats.failed_batches), (5, 0, 0));
    exporter.shutdown().await;
}

#[tokio::test]
async fn a_partial_batch_is_posted_after_the_flush_interval() {
    let server = collector(200).await;
    let mut cfg = config(&server);
    cfg.flush_interval = Duration::from_millis(50);
    let exporter = TrafficExporter::new(cfg).unwrap();
    exporter.record(exchange(1));
    wait_for_requests(&server, 1).await;
    assert_eq!(batches(&server).await[0].len(), 1);
    exporter.shutdown().await;
}

#[tokio::test]
async fn attributes_are_added_to_every_event_and_validated() {
    let server = collector(200).await;
    let mut cfg = config(&server);
    cfg.attributes = BTreeMap::from([
        ("team".to_owned(), "red".to_owned()),
        ("run_id".to_owned(), "7".to_owned()),
    ]);
    let exporter = TrafficExporter::new(cfg.clone()).unwrap();
    exporter.record(exchange(1));
    exporter.record(exchange(2));
    exporter.flush().await;
    for event in batches(&server).await.iter().flatten() {
        assert_eq!(event["team"], "red");
        assert_eq!(event["run_id"], "7");
    }
    exporter.shutdown().await;
    for bad in ["Team", "request", "id", "9x", "a-b"] {
        let mut cfg = cfg.clone();
        cfg.attributes = BTreeMap::from([(bad.to_owned(), "x".to_owned())]);
        assert!(
            matches!(
                TrafficExporter::new(cfg),
                Err(TrafficExportError::InvalidAttribute(_))
            ),
            "{bad}"
        );
    }
}

fn credential_exchange() -> Exchange {
    let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    Exchange::new("url", ts, "GET", "https://target.test/me", 200)
        .with_request(
            BTreeMap::from([
                ("Authorization".to_owned(), "Bearer victim".to_owned()),
                ("cookie".to_owned(), "sid=1".to_owned()),
                ("x-api-key".to_owned(), "k".to_owned()),
                ("accept".to_owned(), "*/*".to_owned()),
            ]),
            None,
        )
        .with_response(
            BTreeMap::from([
                ("set-cookie".to_owned(), "sid=2".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ]),
            Some("{}".to_owned()),
        )
}

#[tokio::test]
async fn credential_headers_are_dropped_unless_included() {
    for include in [false, true] {
        let server = collector(200).await;
        let mut cfg = config(&server);
        cfg.include_credentials = include;
        let exporter = TrafficExporter::new(cfg).unwrap();
        exporter.record(credential_exchange());
        exporter.flush().await;
        let event = batches(&server).await.remove(0).remove(0);
        let request = event["request"]["headers"].as_object().unwrap();
        let response = event["response"]["headers"].as_object().unwrap();
        assert!(
            request.contains_key("accept") && response.contains_key("content-type"),
            "plain headers stay"
        );
        for name in ["Authorization", "cookie", "x-api-key"] {
            assert_eq!(
                request.contains_key(name),
                include,
                "request {name} include={include}"
            );
        }
        assert_eq!(response.contains_key("set-cookie"), include);
        if include {
            assert_eq!(request["Authorization"], "Bearer victim");
        }
        let raw = serde_json::to_string(&event).unwrap();
        assert_eq!(raw.contains("victim"), include);
        exporter.shutdown().await;
    }
}

#[test]
fn plain_http_to_a_remote_host_is_refused_unless_allowed() {
    // `new` spawns a task, so give it a runtime even though nothing is sent
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let cfg = |u: &str| TrafficExportConfig::new(Url::parse(u).unwrap());
        let refused = TrafficExporter::new(cfg("http://collector.example/ingest"));
        assert!(
            matches!(refused, Err(TrafficExportError::InvalidEndpoint(_))),
            "{refused:?}"
        );
        let mut allowed = cfg("http://collector.example/ingest");
        allowed.allow_insecure = true;
        TrafficExporter::new(allowed).unwrap().shutdown().await;
        TrafficExporter::new(cfg("https://collector.example/ingest"))
            .unwrap()
            .shutdown()
            .await;
        TrafficExporter::new(cfg("http://127.0.0.1:1/ingest"))
            .unwrap()
            .shutdown()
            .await;
        for bad in [
            "https://user:pw@collector.example/ingest",
            "https://collector.example/ingest?x=1",
            "https://collector.example/ingest#f",
            "ftp://collector.example/ingest",
        ] {
            assert!(
                matches!(
                    TrafficExporter::new(cfg(bad)),
                    Err(TrafficExportError::InvalidEndpoint(_))
                ),
                "{bad}"
            );
        }
    });
}

#[tokio::test]
async fn from_env_drives_a_working_exporter() {
    let server = collector(200).await;
    let endpoint = format!("{}/ingest", server.uri());
    let env = move |key: &str| -> Option<String> {
        match key {
            "CRAWLX_TRAFFIC_ENDPOINT" => Some(endpoint.clone()),
            "CRAWLX_TRAFFIC_TOKEN" => Some("env-token".to_owned()),
            "CRAWLX_TRAFFIC_ATTRIBUTES" => Some(r#"{"team":"blue"}"#.to_owned()),
            "CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS" => Some("1".to_owned()),
            _ => None,
        }
    };
    let mut cfg = TrafficExportConfig::from_env(&env).unwrap().unwrap();
    assert!(cfg.include_credentials);
    assert!(
        !format!("{cfg:?}").contains("env-token"),
        "Debug redacts the token"
    );
    cfg.flush_interval = Duration::from_secs(3600);
    let exporter = TrafficExporter::new(cfg).unwrap();
    exporter.record(credential_exchange());
    exporter.flush().await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        "Bearer env-token"
    );
    let event = &batches(&server).await[0][0];
    assert_eq!(event["team"], "blue");
    assert_eq!(event["request"]["headers"]["cookie"], "sid=1");
    exporter.shutdown().await;
    assert!(TrafficExportConfig::from_env(&|_| None).unwrap().is_none());
    assert!(matches!(
        TrafficExportConfig::from_env(&|k| (k == "CRAWLX_TRAFFIC_TOKEN").then(|| "t".to_owned())),
        Err(TrafficExportError::IncompleteEnv)
    ));
}

#[tokio::test]
async fn server_errors_are_retried_and_client_errors_are_not() {
    // 503 once, then 200
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let exporter = TrafficExporter::new(config(&server)).unwrap();
    exporter.record(exchange(1));
    exporter.flush().await;
    assert_eq!(server.received_requests().await.unwrap().len(), 2, "one retry");
    assert_eq!(exporter.stats().sent, 1);
    exporter.shutdown().await;

    // 400 is final
    let server = collector(400).await;
    let exporter = TrafficExporter::new(config(&server)).unwrap();
    exporter.record(exchange(1));
    exporter.flush().await;
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "no retry for 400"
    );
    let stats = exporter.stats();
    assert_eq!((stats.sent, stats.dropped, stats.failed_batches), (0, 1, 1));
    exporter.shutdown().await;

    // 503 forever: the configured number of retries, then the batch is dropped
    let server = collector(503).await;
    let exporter = TrafficExporter::new(config(&server)).unwrap();
    exporter.record(exchange(1));
    exporter.flush().await;
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        3,
        "1 try + 2 retries"
    );
    assert_eq!(exporter.stats().failed_batches, 1);
    exporter.shutdown().await;
}

#[tokio::test]
async fn redirects_are_never_followed_so_the_token_cannot_leak() {
    let elsewhere = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&elsewhere)
        .await;
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", format!("{}/stolen", elsewhere.uri())),
        )
        .mount(&collector)
        .await;
    let exporter = TrafficExporter::new(config(&collector)).unwrap();
    exporter.record(exchange(1));
    exporter.flush().await;
    assert!(
        elsewhere.received_requests().await.unwrap().is_empty(),
        "redirect target was contacted"
    );
    assert_eq!(exporter.stats().failed_batches, 1);
    exporter.shutdown().await;
}

#[tokio::test]
async fn bodies_are_previewed_hashed_and_bounded() {
    let server = collector(200).await;
    let exporter = TrafficExporter::new(config(&server)).unwrap();
    let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let big = "x".repeat(100 * 1024);
    exporter.record(
        Exchange::new("url", ts, "POST", "https://target.test/big", 200)
            .with_request(BTreeMap::new(), Some("a=b".to_owned()))
            .with_response(
                BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
                Some(big.clone()),
            ),
    );
    exporter.record(
        Exchange::new("browser", ts, "GET", "https://target.test/img", 200).with_response(
            BTreeMap::from([("content-type".to_owned(), "image/png".to_owned())]),
            Some("PNGDATA".to_owned()),
        ),
    );
    exporter.record(
        Exchange::new("url", ts, "GET", "https://target.test/down", 0).with_error("connection refused"),
    );
    exporter.flush().await;
    let events = batches(&server).await.remove(0);
    let large = &events[0]["response"];
    assert_eq!(large["body_preview"].as_str().unwrap().len(), 64 * 1024);
    assert_eq!(large["body_truncated"], true);
    assert_eq!(large["body_size"], 100 * 1024);
    assert_eq!(large["body_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(events[0]["request"]["body_preview"], "a=b");
    let png = &events[1]["response"];
    assert!(
        png.get("body_preview").is_none(),
        "non-textual bodies have no preview"
    );
    assert_eq!(png["body_truncated"], true);
    assert_eq!(png["body_size"], 7);
    assert_eq!(events[1]["plane"], "browser");
    assert_eq!(events[2]["error"], "connection refused");
    assert_eq!(events[2]["response"]["status"], 0);
    exporter.shutdown().await;
}

#[tokio::test]
async fn shutdown_delivers_what_is_queued_and_later_records_are_counted_as_dropped() {
    let server = collector(200).await;
    let exporter = TrafficExporter::new(config(&server)).unwrap();
    for n in 0..3 {
        exporter.record(exchange(n));
    }
    exporter.shutdown().await;
    assert_eq!(batches(&server).await.iter().map(Vec::len).sum::<usize>(), 3);
    exporter.record(exchange(9));
    assert_eq!(exporter.stats().dropped, 1);
    exporter.shutdown().await; // a second call does nothing
    exporter.flush().await; // and flushing a stopped exporter returns
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_stalled_collector_never_blocks_recording_and_shutdown_gives_up() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let mut cfg = config(&server);
    cfg.batch_size = 1;
    cfg.drain_timeout = Duration::from_millis(200);
    let exporter = TrafficExporter::new(cfg).unwrap();
    let started = std::time::Instant::now();
    for n in 0..3000 {
        exporter.record(exchange(n));
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "record() blocked on the collector"
    );
    assert!(
        exporter.stats().dropped >= 900,
        "the bounded queue overflowed: {:?}",
        exporter.stats()
    );
    let shutdown_started = std::time::Instant::now();
    exporter.shutdown().await;
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(10),
        "shutdown waited for the stalled collector"
    );
    let stats = exporter.stats();
    assert_eq!(stats.sent, 0);
    assert_eq!(stats.dropped, 3000, "every event is accounted for: {stats:?}");
}

// ---------------------------------------------------------------------------------------
// a real crawl feeding the output layer (page-metadata contract end to end)

mod crawl {
    use super::*;
    use crate::authorization_fixture::run_authorized_local_with as run_local_with;
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;
    use crawlx_core::config::{CrawlMode, CustomField, OutputFormat, SitemapMode};
    use crawlx_core::CreateCrawl;
    use crawlx_fetch::StaticResolver;
    use crawlx_storage::MemoryStore;
    use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
    use std::sync::Arc;

    fn html(body: &'static str) -> axum::response::Response {
        ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
    }

    const HOME: &str = r#"<html><head><title>Home</title></head><body><main><h1>Home</h1>
        <p>Write to team@example.test for help.</p>
        <a href="/a">A</a> <a href="/gone">gone</a>
        <form method="post" action="/login"><input name="username" type="text">
        <input name="password" type="password"><button>Sign in</button></form>
        </main></body></html>"#;

    pub struct Crawled {
        pub report: RunReport,
        _dir: tempfile::TempDir,
        _server: tokio::task::JoinHandle<()>,
    }

    pub async fn run() -> Crawled {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/", get(|| async { html(HOME) }))
            .route(
                "/a",
                get(|| async {
                    html("<html><head><title>A</title></head><body><main><h1>A</h1><p>Plain page A.</p></main></body></html>")
                }),
            )
            .route(
                "/gone",
                get(|| async { (StatusCode::NOT_FOUND, "no such page").into_response() }),
            );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let dir = tempfile::tempdir().unwrap();
        let mut crawl = CreateCrawl::new(Url::parse(&format!("{base}/")).unwrap());
        crawl.mode = CrawlMode::Static;
        crawl.seed = Some(20_261_027);
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        crawl.politeness.delay_ms = 0;
        crawl.scope.sitemap = SitemapMode::Skip;
        crawl.extract.knowledge_base = true;
        crawl.output.capture_raw = true;
        crawl.output.only_main_content = false;
        crawl.output.formats.push(OutputFormat::Html);
        crawl.extract.custom_fields = vec![CustomField {
            name: "email".to_owned(),
            regex: vec![r"[a-z]+@example\.test".to_owned()],
            part: Default::default(),
            group: 0,
        }];
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        };
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores))
            .await
            .unwrap();
        Crawled {
            report,
            _dir: dir,
            _server: server,
        }
    }
}

/// The body and raw text of a page from the run's contents.
fn text_of(report: &crawlx_worker::RunReport, page: &PageRecord) -> PageText {
    let mut text = PageText::default();
    if let Some(c) = report
        .page_contents
        .iter()
        .find(|c| c.url == page.url.url.as_str())
    {
        if let Some(html) = &c.html {
            text = text.with_body(html.clone());
        }
        if let Some(raw) = &c.raw {
            text = text.with_raw(raw.clone());
        }
    }
    text
}

#[tokio::test]
async fn a_real_crawl_fills_every_katana_field_the_exporter_reads() {
    let crawled = crawl::run().await;
    let report = &crawled.report;
    let dir = tempfile::tempdir().unwrap();
    let store = StoredResponses::new(dir.path().join("sr"), false).unwrap();
    let exporter = Exporter {
        include_body: true,
        knowledge_base: true,
        stored_responses: Some(store.clone()),
        ..jsonl_exporter()
    };
    let mut out = Vec::new();
    let stats = exporter
        .export_pages_with(&report.pages, |p| text_of(report, p), &mut out)
        .unwrap();
    let records: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(usize::try_from(stats.stored).unwrap(), report.pages.len());
    let home = records
        .iter()
        .find(|r| {
            r["request"]["endpoint"]
                .as_str()
                .is_some_and(|u| u.ends_with('/') && !u.ends_with("//"))
        })
        .expect("home page record");
    assert_eq!(home["request"]["method"], "GET");
    assert_eq!(home["response"]["status_code"], 200);
    assert!(
        home["response"]["content_length"].as_u64().unwrap() > 100,
        "{home}"
    );
    assert_eq!(home["request"]["custom_fields"]["email"][0], "team@example.test");
    assert_eq!(home["response"]["custom_fields"]["email"][0], "team@example.test");
    assert!(home["response"]["body"]
        .as_str()
        .unwrap()
        .contains("Write to team@example.test"));
    let raw = home["response"]["raw"]
        .as_str()
        .expect("captureRaw keeps the raw response");
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(raw.contains("Write to team@example.test"));
    assert!(
        home["request"]["raw"]
            .as_str()
            .unwrap()
            .starts_with("GET / HTTP/1.1"),
        "{home}"
    );
    let kb = &home["response"]["knowledgebase"];
    assert!(kb["PageType"].is_string(), "{kb}");
    assert!(kb["Forms"][0]["type"].is_string(), "forms are classified: {kb}");
    // -sr: the stored file is the raw request and response, and the index lists every page
    let stored = std::fs::read_to_string(home["response"]["stored_response_path"].as_str().unwrap()).unwrap();
    assert!(
        stored.contains("GET / HTTP/1.1") && stored.contains("HTTP/1.1 200"),
        "{stored}"
    );
    assert_eq!(
        std::fs::read_to_string(store.index_path())
            .unwrap()
            .lines()
            .count(),
        report.pages.len()
    );

    // -fpt drops the home page's type from the output only
    let page_type = kb["PageType"].as_str().unwrap().to_owned();
    let dropping = Exporter {
        filter_page_types: vec![page_type.to_ascii_uppercase()],
        ..jsonl_exporter()
    };
    let kept = jsonl(&dropping, &report.pages, PageText::default());
    assert!(
        kept.len() < report.pages.len(),
        "pages of type {page_type} must be left out"
    );
    assert!(kept
        .iter()
        .all(|r| r["response"].get("page_type").and_then(Value::as_str) != Some(page_type.as_str())));
    // -mdc over the real record
    let matching = Exporter {
        match_condition: Some(Dsl::parse("status_code == 200 && endpoint contains \"/a\"").unwrap()),
        ..jsonl_exporter()
    };
    let only = jsonl(&matching, &report.pages, PageText::default());
    assert_eq!(only.len(), 1);
    assert!(only[0]["request"]["endpoint"].as_str().unwrap().ends_with("/a"));
}

#[tokio::test]
async fn a_real_crawls_failed_urls_feed_the_error_log_and_failure_records() {
    let crawled = crawl::run().await;
    let failures = &crawled.report.failures;
    let gone = failures
        .iter()
        .find(|f| f.url.ends_with("/gone"))
        .unwrap_or_else(|| panic!("the 404 is a failed URL: {failures:?}"));
    assert_eq!(gone.status, Some(404));
    let dir = tempfile::tempdir().unwrap();
    let log = write_error_log(dir.path().join("errors.log"), failures, false).unwrap();
    let lines: Vec<Value> = std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), failures.len());
    assert!(lines
        .iter()
        .any(|l| l["endpoint"].as_str().unwrap().ends_with("/gone") && l["status_code"] == 404));
    let mut out = Vec::new();
    jsonl_exporter().export_failures(failures, &mut out).unwrap();
    let first: Value = serde_json::from_str(String::from_utf8(out).unwrap().lines().next().unwrap()).unwrap();
    assert!(first["error"].is_string());
}
