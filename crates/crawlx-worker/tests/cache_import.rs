//! Importing an exported response cache: only screened entries are stored, only into a run the
//! importing tenant owns and that retains content, and an imported page is never served as a scrape
//! cache hit. In-memory stores; no network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::cache::CacheExportV1;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::repo::CrawlRun;
use crawlx_core::scrape::ScrapeOptions;
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId, Timestamp};
use crawlx_storage::MemoryStore;
use crawlx_worker::scrape::cache::{import_entries, lookup, ImportError};
use crawlx_worker::Stores;
use serde_json::json;
use std::sync::Arc;

async fn stores(dir: &std::path::Path) -> Stores {
    Stores::over_memory(Arc::new(MemoryStore::new()), dir)
        .await
        .unwrap()
}

/// A stored run of `tenant` created at `created_at` under `mode` with `days` of retention.
async fn run(
    stores: &Stores,
    tenant: TenantId,
    mode: RetentionMode,
    days: u16,
    created_at: Timestamp,
) -> CrawlRunId {
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.retention.mode = mode;
    crawl.retention.days = days;
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at,
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    run.id
}

fn export(tenant: TenantId) -> CacheExportV1 {
    CacheExportV1::parse(
        &serde_json::to_vec(&json!({
            "version": 1,
            "tenant": tenant,
            "entries": [
                {"url": "https://example.test/a", "statusCode": 200, "contentType": "text/html",
                 "fetchedAt": "2026-01-01T00:00:00Z", "body": "<h1>alpha</h1>",
                 "headers": [{"name": "ETag", "value": "\"v1\""}]},
                {"url": "https://example.test/private", "statusCode": 200, "contentType": "text/html",
                 "fetchedAt": "2026-01-01T00:00:00Z", "body": "<h1>secret-canary</h1>", "private": true},
                {"url": "https://example.test/cookie", "statusCode": 200, "contentType": "text/html",
                 "fetchedAt": "2026-01-01T00:00:00Z", "body": "<h1>secret-canary</h1>",
                 "headers": [{"name": "Set-Cookie", "value": "sid=secret-canary"}]},
                {"url": "https://example.test/other-tenant", "statusCode": 200, "contentType": "text/html",
                 "fetchedAt": "2026-01-01T00:00:00Z", "body": "<h1>secret-canary</h1>",
                 "tenant": TenantId::new()},
                {"url": "https://example.test/b", "statusCode": 200, "contentType": "application/json",
                 "fetchedAt": "2026-01-02T00:00:00Z", "body": "{\"n\":1}"}
            ]
        }))
        .unwrap(),
    )
    .unwrap()
}

fn now() -> Timestamp {
    "2026-02-01T00:00:00Z".parse().unwrap()
}

#[tokio::test]
async fn only_screened_entries_become_retained_pages_with_their_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let stores = stores(dir.path()).await;
    let run = run(&stores, stores.tenant, RetentionMode::Standard, 30, now()).await;

    let screened = export(stores.tenant).screen(stores.tenant, now());
    assert_eq!(screened.accepted.len(), 2);
    assert_eq!(screened.refused.len(), 3);
    let stored = import_entries(
        stores.pages.as_ref(),
        stores.runs.as_ref(),
        stores.artifacts.as_ref(),
        stores.tenant,
        run,
        &screened.accepted,
        now(),
    )
    .await
    .unwrap();
    assert_eq!(stored, 2);

    let mut pages = stores.pages.list(run).await.unwrap();
    pages.sort_by(|a, b| a.url.url.as_str().cmp(b.url.url.as_str()));
    let urls: Vec<&str> = pages.iter().map(|p| p.url.url.as_str()).collect();
    assert_eq!(urls, ["https://example.test/a", "https://example.test/b"]);
    assert_eq!(pages[0].status, 200);
    assert_eq!(pages[0].content_type.as_deref(), Some("text/html"));
    assert_eq!(pages[0].metadata["cacheImport"]["validators"]["etag"], "\"v1\"");
    assert_eq!(pages[1].content_type.as_deref(), Some("application/json"));
    // the body is retrievable and is exactly what the export declared
    let body = stores
        .artifacts
        .get(pages[0].html.as_ref().unwrap())
        .await
        .unwrap();
    assert_eq!(body, b"<h1>alpha</h1>");
    let body = stores
        .artifacts
        .get(pages[1].html.as_ref().unwrap())
        .await
        .unwrap();
    assert_eq!(body, b"{\"n\":1}");
    // nothing of the refused entries reached the store: no page, no metadata, no canary
    let dump = serde_json::to_string(
        &pages
            .iter()
            .map(|p| (&p.metadata, p.url.url.as_str(), &p.links, &p.title))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!dump.contains("secret-canary") && !dump.contains("private") && !dump.contains("cookie"));
}

#[tokio::test]
async fn an_export_of_another_tenant_stores_nothing_even_into_the_importers_run() {
    let dir = tempfile::tempdir().unwrap();
    let stores = stores(dir.path()).await;
    let run = run(&stores, stores.tenant, RetentionMode::Standard, 30, now()).await;
    let screened = export(TenantId::new()).screen(stores.tenant, now());
    assert!(screened.accepted.is_empty());
    assert_eq!(screened.refused.len(), 5);
    let stored = import_entries(
        stores.pages.as_ref(),
        stores.runs.as_ref(),
        stores.artifacts.as_ref(),
        stores.tenant,
        run,
        &screened.accepted,
        now(),
    )
    .await
    .unwrap();
    assert_eq!(stored, 0);
    assert!(stores.pages.list(run).await.unwrap().is_empty());
}

#[tokio::test]
async fn another_tenants_run_and_runs_that_retain_nothing_refuse_the_import() {
    let dir = tempfile::tempdir().unwrap();
    let stores = stores(dir.path()).await;
    let screened = export(stores.tenant).screen(stores.tenant, now());
    let attempt = |run: CrawlRunId, at: Timestamp| {
        let stores = &stores;
        let entries = &screened.accepted;
        async move {
            import_entries(
                stores.pages.as_ref(),
                stores.runs.as_ref(),
                stores.artifacts.as_ref(),
                stores.tenant,
                run,
                entries,
                at,
            )
            .await
        }
    };
    // a run of another tenant
    let foreign = run(&stores, TenantId::new(), RetentionMode::Standard, 30, now()).await;
    assert!(matches!(
        attempt(foreign, now()).await,
        Err(ImportError::ForeignRun)
    ));
    assert!(stores.pages.list(foreign).await.unwrap().is_empty());
    // zero-data retention keeps nothing
    let zdr = run(&stores, stores.tenant, RetentionMode::Zdr, 0, now()).await;
    assert!(matches!(
        attempt(zdr, now()).await,
        Err(ImportError::RunNotRetaining)
    ));
    assert!(stores.pages.list(zdr).await.unwrap().is_empty());
    // a run whose retention window has passed
    let old = "2025-01-01T00:00:00Z".parse().unwrap();
    let expired = run(&stores, stores.tenant, RetentionMode::Standard, 1, old).await;
    assert!(matches!(
        attempt(expired, now()).await,
        Err(ImportError::RunNotRetaining)
    ));
    // an unknown run
    assert!(matches!(
        attempt(CrawlRunId::new(), now()).await,
        Err(ImportError::Store(_))
    ));
}

#[tokio::test]
async fn an_imported_page_is_never_served_as_a_scrape_cache_hit() {
    let dir = tempfile::tempdir().unwrap();
    let stores = stores(dir.path()).await;
    let run_id = run(
        &stores,
        stores.tenant,
        RetentionMode::Standard,
        30,
        SystemClock.now(),
    )
    .await;
    let screened = export(stores.tenant).screen(stores.tenant, now());
    import_entries(
        stores.pages.as_ref(),
        stores.runs.as_ref(),
        stores.artifacts.as_ref(),
        stores.tenant,
        run_id,
        &screened.accepted,
        SystemClock.now(),
    )
    .await
    .unwrap();
    let options = ScrapeOptions {
        max_age_ms: u64::MAX / 4,
        ..ScrapeOptions::default()
    };
    let canonical = crawlx_url::Canonicalizer::canonicalize_url(
        &url::Url::parse("https://example.test/a").unwrap(),
        &crawlx_url::CanonicalizeOptions::default(),
    )
    .unwrap();
    let hit = lookup(
        stores.pages.as_ref(),
        stores.runs.as_ref(),
        stores.artifacts.as_ref(),
        stores.tenant,
        &canonical,
        &options,
        None,
        run_id,
        SystemClock.now(),
    )
    .await
    .unwrap();
    assert!(
        hit.is_none(),
        "an export cannot supply the scoped request identity of a hit"
    );
}
