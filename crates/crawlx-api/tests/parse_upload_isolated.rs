#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `POST /compat/v2/parse` with an HTML upload: the bytes are reserved from the shared parser
//! budget while the body streams in, the document is parsed through the isolated parser, and
//! the reservation lives until the response is assembled. Other formats keep their path.
//!
//! The parser budget is process-wide, so every test takes [`GATE`] and restores the limit.

use axum::body::Body;
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::{ApiConfig, AppState, Repos, Scope, Settings};
use crawlx_core::parser_memory;
use crawlx_extract::parse::{parse_document_with, ParseLimits, ParseOptions};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::MemoryStore;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const PARSE: &str = "/compat/v2/parse";
const BOUNDARY: &str = "----crawlxisolatedupload7MA4YWxkTrZu0gW";
const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Uploaded Page</title><meta name="description" content="from a file"></head><body><nav><a href="/menu">Menu</a></nav><main><h1>Hello</h1><p>Body with <a href="https://example.com/abs">an absolute link</a> and <a href="rel/page.html">a relative one</a>.</p><img src="pic.png" alt="pic"></main><footer>Footer text</footer></body></html>"#;

/// Serializes the tests that read or change the process-wide parser budget.
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Restores the budget ceiling when a test ends, also when it fails.
struct Ceiling(usize);

impl Ceiling {
    fn set(limit: usize) -> Self {
        let previous = parser_memory::global().limit();
        parser_memory::global().set_limit(limit);
        Self(previous)
    }
}

impl Drop for Ceiling {
    fn drop(&mut self) {
        parser_memory::global().set_limit(self.0);
    }
}

struct Rig {
    app: Router,
    key: String,
}

fn rig() -> Rig {
    let repos = Repos::memory(Arc::new(MemoryStore::new()));
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
    let settings = Settings {
        parse_limits: ParseLimits::default(),
        ..Settings::default()
    };
    let state = AppState::builder(repos.clone(), AdmissionPolicy::new(clock.clone()), config)
        .settings(settings)
        .clock(clock)
        .build();
    let tenant = tenant_id_for("acme");
    let key = generate_key();
    let record = key_record(&key, tenant, Scope::all_set()).unwrap();
    futures::executor::block_on(async { repos.api.key_insert(&record, "acme").await.unwrap() });
    Rig {
        app: crawlx_api::router(state),
        key,
    }
}

fn multipart(name: &str, bytes: &[u8], options: Option<&Value>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    if let Some(options) = options {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"options\"\r\nContent-Type: application/json\r\n\r\n{options}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

impl Rig {
    async fn upload(
        &self,
        name: &str,
        bytes: &[u8],
        options: Option<Value>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let request = Request::builder()
            .method(Method::POST)
            .uri(PARSE)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={BOUNDARY}"),
            )
            .header("authorization", format!("Bearer {}", self.key))
            .body(Body::from(multipart(name, bytes, options.as_ref())))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap();
        (
            parts.status,
            parts.headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

fn local(
    only_main_content: bool,
    include: &[&str],
    exclude: &[&str],
) -> crawlx_extract::parse::ParsedDocument {
    let options = ParseOptions {
        only_main_content,
        include_tags: include.iter().map(|tag| (*tag).to_owned()).collect(),
        exclude_tags: exclude.iter().map(|tag| (*tag).to_owned()).collect(),
        ..ParseOptions::default()
    };
    parse_document_with(PAGE.as_bytes(), Some("page.html"), None, &options).unwrap()
}

#[tokio::test]
async fn html_upload_equals_the_local_parse_and_releases_its_reservation() {
    let _gate = GATE.lock().await;
    let before = parser_memory::global().used();
    let t = rig();
    let (status, _, response) = t
        .upload(
            "page.html",
            PAGE.as_bytes(),
            Some(json!({"formats": ["markdown", "html", "rawHtml", "links", "text"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let expected = local(true, &[], &[]);
    let data = &response["data"];
    assert_eq!(data["markdown"], expected.markdown);
    assert_eq!(data["html"], expected.html);
    assert_eq!(data["text"], expected.text);
    assert_eq!(data["rawHtml"], expected.raw_html);
    assert_eq!(data["links"], json!(expected.links));
    assert_eq!(data["metadata"]["title"], "Uploaded Page");
    assert_eq!(data["metadata"]["description"], "from a file");
    assert_eq!(data["metadata"]["sourceURL"], "page.html");
    assert_eq!(data["metadata"]["contentType"], "text/html");
    assert_eq!(data["warnings"], json!([]));
    assert_eq!(
        parser_memory::global().used(),
        before,
        "the upload, the document and the response leave no reservation behind"
    );
}

#[tokio::test]
async fn html_upload_honours_main_content_and_tag_options() {
    let _gate = GATE.lock().await;
    let t = rig();
    let (status, _, response) = t.upload("page.html", PAGE.as_bytes(), None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let markdown = response["data"]["markdown"].as_str().unwrap();
    assert_eq!(markdown, local(true, &[], &[]).markdown);
    assert!(!markdown.contains("Menu"), "{markdown}");
    assert!(!markdown.contains("Footer text"), "{markdown}");

    let (status, _, response) = t
        .upload(
            "page.html",
            PAGE.as_bytes(),
            Some(json!({"onlyMainContent": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let markdown = response["data"]["markdown"].as_str().unwrap();
    assert_eq!(markdown, local(false, &[], &[]).markdown);
    assert!(markdown.contains("Footer text"), "{markdown}");

    let (status, _, response) = t
        .upload(
            "page.html",
            PAGE.as_bytes(),
            Some(json!({"onlyMainContent": false, "includeTags": ["h1"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        response["data"]["markdown"].as_str().unwrap(),
        local(false, &["h1"], &[]).markdown
    );
    assert_eq!(response["data"]["markdown"].as_str().unwrap().trim(), "# Hello");

    let (status, _, response) = t
        .upload(
            "page.html",
            PAGE.as_bytes(),
            Some(json!({"onlyMainContent": false, "excludeTags": ["footer", "nav"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let markdown = response["data"]["markdown"].as_str().unwrap();
    assert_eq!(markdown, local(false, &[], &["footer", "nav"]).markdown);
    assert!(!markdown.contains("Footer text"), "{markdown}");
    assert!(markdown.contains("# Hello"), "{markdown}");

    let (status, _, response) = t
        .upload(
            "page.html",
            PAGE.as_bytes(),
            Some(json!({"includeTags": ["h1["]})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["details"][0]["path"], "/includeTags");
}

#[tokio::test]
async fn an_upload_above_the_whole_budget_is_refused_before_parsing() {
    let _gate = GATE.lock().await;
    let before = parser_memory::global().used();
    let t = rig();
    let _ceiling = Ceiling::set(before + 4 * 1024);
    let big = format!(
        "<html><body><main>{}</main></body></html>",
        "word ".repeat(40 * 1024)
    );
    let (status, headers, response) = t.upload("big.html", big.as_bytes(), None).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response}");
    assert_eq!(response["code"], "payload_too_large", "{response}");
    assert!(
        headers.get("retry-after").is_none(),
        "a terminal refusal is not retryable"
    );
    assert_eq!(
        parser_memory::global().used(),
        before,
        "a refused upload holds nothing"
    );
}

#[tokio::test]
async fn transient_budget_pressure_answers_503_and_a_retry_succeeds() {
    let _gate = GATE.lock().await;
    let before = parser_memory::global().used();
    let t = rig();
    // The retry must fit the in-process parse reservation (500 x the ~200 KiB page plus scratch
    // and output). A smaller ceiling would route the retry to the helper process, which a test
    // binary cannot act as.
    let room = 256 * 1024 * 1024;
    let _ceiling = Ceiling::set(before + room);
    // everything but 1 KiB is taken by another owner: not a refusal for good, only for now
    let hog = parser_memory::global().try_reserve(room - 1024).unwrap();
    let body = format!(
        "<html><body><main>{}</main></body></html>",
        "word ".repeat(40 * 1024)
    );
    let (status, headers, response) = t.upload("busy.html", body.as_bytes(), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{response}");
    assert!(
        headers.get("retry-after").is_some(),
        "a transient refusal says when to retry"
    );
    drop(hog);
    assert_eq!(parser_memory::global().used(), before);

    let (status, _, response) = t.upload("busy.html", body.as_bytes(), None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(response["data"]["markdown"].as_str().unwrap().contains("word"));
    assert_eq!(parser_memory::global().used(), before);
}

#[tokio::test]
async fn other_formats_keep_their_pipeline_path() {
    let _gate = GATE.lock().await;
    let before = parser_memory::global().used();
    let t = rig();
    let (status, _, response) = t.upload("notes.txt", b"plain notes\nsecond line\n", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        response["data"]["markdown"]
            .as_str()
            .unwrap()
            .contains("plain notes"),
        "{response}"
    );

    let (status, _, response) = t.upload("people.csv", b"name,age\nAda,36\n", None).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        response["data"]["markdown"].as_str().unwrap().contains("Ada"),
        "{response}"
    );

    let (status, _, response) = t
        .upload(
            "notes.txt",
            b"plain notes\n",
            Some(json!({"onlyMainContent": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        response["data"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "option_not_applicable" && w["path"] == "/onlyMainContent"),
        "{response}"
    );
    assert_eq!(parser_memory::global().used(), before);
}
