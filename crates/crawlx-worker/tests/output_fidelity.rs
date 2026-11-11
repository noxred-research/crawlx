//! Native diagnostic capture fidelity through page metadata, JSONL and stored exchange output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "surface_common/mod.rs"]
mod rig;

use axum::http::header;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use crawlx_core::acquisition::OversizePolicy;
use crawlx_core::config::OutputFormat;
use crawlx_worker::output::{ExportFormat, Exporter, PageText, StoredResponses};
use serde_json::Value;

async fn capture(body: Bytes, limit: u64) -> rig::Crawled {
    let site = rig::Site::start(move |_| {
        Router::new().route(
            "/",
            get(move || {
                let body = body.clone();
                async move { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body) }
            }),
        )
    })
    .await;
    rig::crawl(&site.base, |crawl| {
        crawl.output.capture_raw = true;
        crawl.output.only_main_content = false;
        crawl.output.formats.push(OutputFormat::Html);
        crawl.fetch.max_response_bytes = limit;
        crawl.fetch.oversize = Some(OversizePolicy::Truncate);
        crawl.fetch.retries = 0;
    })
    .await
}

fn page_text(crawled: &rig::Crawled) -> PageText {
    let page = rig::page_at(&crawled.report, "/");
    let content = crawled
        .report
        .page_contents
        .iter()
        .find(|content| content.url == page.url.url.as_str())
        .unwrap();
    let mut text = PageText::default();
    if let Some(body) = &content.html {
        text = text.with_body(body.clone());
    }
    if let Some(raw) = &content.raw {
        text = text.with_raw(raw.clone());
    }
    text
}

#[tokio::test]
async fn invalid_utf8_retained_prefix_is_labelled_reconstructed_redacted_lossy_and_truncated() {
    let mut body = b"<html><head><title>Fidelity</title></head><body><main>prefix ".to_vec();
    body.push(0xff);
    body.extend(std::iter::repeat_n(b'x', 8192));
    body.extend_from_slice(b"</main></body></html>");
    let crawled = capture(Bytes::from(body), 1024).await;
    let page = rig::page_at(&crawled.report, "/");
    let native = &page.metadata["output_fidelity"]["response_raw"];
    assert_eq!(native["representation"], "reconstructed");
    assert_eq!(native["redacted"], true);
    assert_eq!(native["binary_lossy"], true);
    assert_eq!(native["truncated"], true);

    let store = StoredResponses::new(crawled.dir.path().join("diagnostic"), false).unwrap();
    let exporter = Exporter {
        format: ExportFormat::Jsonl,
        include_body: true,
        stored_responses: Some(store),
        ..Exporter::default()
    };
    let mut out = Vec::new();
    exporter
        .export_pages_with([page], |_| page_text(&crawled), &mut out)
        .unwrap();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["fidelity"]["response_raw"]["availability"], "available");
    assert_eq!(
        value["fidelity"]["response_raw"]["representation"],
        "reconstructed"
    );
    assert_eq!(value["fidelity"]["response_raw"]["binary_lossy"], true);
    assert_eq!(value["fidelity"]["response_raw"]["truncated"], true);
    let path = value["response"]["stored_response_path"].as_str().unwrap();
    let stored = std::fs::read_to_string(path).unwrap();
    assert!(stored.contains("representation=Reconstructed"));
    assert!(stored.contains("redacted=true"));
    assert!(stored.contains("binary_lossy=true"));
    assert!(stored.contains("truncated=true"));
    assert!(!stored.contains("representation=CapturedWire"));
}

#[tokio::test]
async fn valid_replacement_character_does_not_claim_binary_loss_or_truncation() {
    let body = Bytes::from_static("<html><head><title>Fidelity</title></head><body><main>Known replacement: \u{fffd}</main></body></html>".as_bytes());
    let crawled = capture(body, 8192).await;
    let page = rig::page_at(&crawled.report, "/");
    let native = &page.metadata["output_fidelity"]["response_raw"];
    assert_eq!(native["binary_lossy"], false);
    assert_eq!(native["truncated"], false);
    let exporter = Exporter {
        format: ExportFormat::Jsonl,
        omit_raw: true,
        omit_body: true,
        ..Exporter::default()
    };
    let value = serde_json::to_value(exporter.record_with(page, page_text(&crawled)).unwrap()).unwrap();
    assert!(value["response"].get("raw").is_none());
    assert!(value["response"].get("body").is_none());
    assert_eq!(value["fidelity"]["response_raw"]["availability"], "omitted");
    assert_eq!(value["fidelity"]["response_raw"]["binary_lossy"], false);
    assert_eq!(value["fidelity"]["response_raw"]["truncated"], false);
}
