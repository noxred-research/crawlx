#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A compat crawl produces one trace with the spans of its life: the API's `admission`, then for
//! every page the worker's `fetch`, `extract` and `persist`, all carrying the run's `crawl_id` and
//! all below the run's `crawl` span (the worker's own, opened when it takes the run).
//!
//! The subscriber is process-global, so this file holds a single test.
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use axum::http::StatusCode;
use parking_lot::Mutex;
use scrape_rig::{Rig, RigConfig};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// One span as it was opened.
#[derive(Clone, Debug)]
struct Opened {
    name: &'static str,
    crawl_id: Option<String>,
    /// Names of the enclosing spans, innermost first.
    ancestors: Vec<&'static str>,
    /// `crawl_id` of the enclosing `crawl` span, if any.
    crawl_ancestor: Option<String>,
}

#[derive(Default)]
struct CrawlId(Option<String>);

impl Visit for CrawlId {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "crawl_id" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

struct Capture(Arc<Mutex<Vec<Opened>>>);

impl<S> Layer<S> for Capture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut crawl_id = CrawlId::default();
        attrs.record(&mut crawl_id);
        let Some(span) = ctx.span(id) else { return };
        let mut ancestors = Vec::new();
        let mut crawl_ancestor = None;
        for parent in span.scope().skip(1) {
            ancestors.push(parent.name());
            if parent.name() == "crawl" && crawl_ancestor.is_none() {
                crawl_ancestor = parent.extensions().get::<CrawlIdOf>().map(|c| c.0.clone());
            }
        }
        if span.name() == "crawl" {
            if let Some(c) = &crawl_id.0 {
                span.extensions_mut().insert(CrawlIdOf(c.clone()));
            }
        }
        self.0.lock().push(Opened {
            name: span.name(),
            crawl_id: crawl_id.0,
            ancestors,
            crawl_ancestor,
        });
    }
}

/// The `crawl_id` of a `crawl` span, kept in its extensions for its descendants.
struct CrawlIdOf(String);

#[tokio::test]
async fn a_compat_crawl_has_admission_fetch_extract_and_persist_spans_under_its_crawl_span() {
    let spans = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(Capture(spans.clone())))
        .unwrap();

    let rig = Rig::start(RigConfig::default()).await;
    let (s, _, v) = rig
        .env
        .post(
            "/compat/v2/crawl",
            &json!({"url": rig.url("/"), "sitemap": "skip", "limit": 3}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let mut done = false;
    for _ in 0..600 {
        let (_, _, status) = rig.env.get(&format!("/compat/v2/crawl/{id}")).await;
        if status["status"] != "scraping" {
            assert_eq!(status["status"], "completed", "{status}");
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(done, "the crawl did not finish");
    rig.stop().await;

    let all = spans.lock().clone();
    let of_run = |name: &str| -> Vec<&Opened> {
        all.iter()
            .filter(|s| s.name == name && s.crawl_id.as_deref() == Some(id.as_str()))
            .collect()
    };

    let admission = of_run("admission");
    assert_eq!(admission.len(), 1, "{all:#?}");
    assert!(
        admission[0].ancestors.contains(&"http_request"),
        "admission runs inside the request: {:?}",
        admission[0]
    );

    assert!(
        !of_run("crawl").is_empty(),
        "the worker opens the run's crawl span: {all:#?}"
    );
    for name in ["fetch", "extract", "persist"] {
        let pages = of_run(name);
        assert!(
            pages.len() >= 2,
            "{name}: one span per page, {} seen",
            pages.len()
        );
        for span in pages {
            assert_eq!(
                span.crawl_ancestor.as_deref(),
                Some(id.as_str()),
                "{name} sits below the crawl span of its run: {span:?}"
            );
        }
    }
}
