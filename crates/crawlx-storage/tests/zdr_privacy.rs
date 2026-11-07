//! ZDR durable confidentiality and live operational consumer behavior on real PostgreSQL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{EventRepo, FrontierRepo, FrontierStatus, PageRecord, PageRepo, RunRepo};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock as _, CrawlRunId, StoreError, TenantId, TrustLane, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl, sessions};
use crawlx_storage::{
    BufferLimits, DeliveryBuffer, DeliveryStatus, LeaseRepo, Pg, PgApiRepo, PgConfig, WebhookDelivery,
};
use std::sync::Arc;

const QUERY: &str = "Zq7v-canary-query-2c8e4a6d0b9f";
const CONTENT: &str = "private-page-action-prompt-canary-70d639b";

async fn setup() -> Option<(Pg, Arc<DeliveryBuffer>, Arc<ManualClock>, TenantId)> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let clock = Arc::new(ManualClock::new("2026-01-01T00:00:00Z".parse().unwrap()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_{}", CrawlRunId::new().0.simple())),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap()
    .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "privacy-test").await.unwrap();
    Some((pg, buffer, clock, tenant))
}

async fn durable_dump(pg: &Pg, run: CrawlRunId) -> String {
    let mut dump = String::new();
    for table in ["crawl_runs", "url_frontier", "pages", "webhook_deliveries"] {
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t)::text FROM {table} t WHERE run_id = $1"
        ))
        .bind(run.0)
        .fetch_all(pg.pool())
        .await
        .unwrap();
        for row in rows {
            dump.push_str(&row);
        }
    }
    dump
}

#[tokio::test]
async fn zdr_keeps_live_urls_and_full_pages_out_of_durable_rows_before_and_after_delivery() {
    let Some((pg, buffer, clock, tenant)) = setup().await else {
        return;
    };
    let seed = format!("https://example.test/private/{CONTENT}?token={QUERY}");
    let mut config = create_crawl(&seed, &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let run = crawl_run(tenant, config);
    pg.create(&run, None).await.unwrap();
    assert_eq!(pg.get(run.id).await.unwrap().config.seed_url.as_str(), seed);
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    assert_eq!(pg.active_runs().await.unwrap()[0].run, run.id);

    let canonical = canonical_url(&seed);
    let (_, frontier) = pg.discover(run.id, &canonical, 0, None, None).await.unwrap();
    let frontier = frontier.unwrap();
    let leased = pg.lease_batch_fenced(run.id, WorkerId::new(), 1).await.unwrap();
    assert_eq!(leased[0].0.url.url.as_str(), seed);
    pg.complete_fenced(frontier, leased[0].1, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    let page = PageRecord {
        run: run.id,
        frontier_id: frontier,
        url: canonical.clone(),
        status: 200,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("test", CONTENT.as_bytes()),
        title: Some(CONTENT.to_owned()),
        markdown: None,
        html: None,
        metadata: serde_json::json!({
            "final_url": seed,
            "scrape": {"summary": CONTENT, "json": {"secret": CONTENT}, "answer": CONTENT,
                "highlights": [CONTENT], "actions": {"javascriptReturns": [CONTENT], "scrapes": [CONTENT]},
                "rawHtml": CONTENT, "rawBase64": CONTENT, "markdown": CONTENT, "html": CONTENT},
            "model_prompt": CONTENT,
        }),
        links: vec![seed.clone()],
        fetched_at: clock.now(),
        lane: TrustLane::Diagnostic,
    };
    PageRepo::put(&pg, &page).await.unwrap();
    assert_eq!(PageRepo::list(&pg, run.id).await.unwrap(), vec![page]);
    assert!(pg.recent_for_url(tenant, &canonical, 5).await.unwrap().is_empty());
    // Database guards also cover alternate SQL writers, not only repository bind choices.
    sqlx::query("UPDATE pages SET canonical_url = $2, title = $3, metadata = $4 WHERE run_id = $1")
        .bind(run.id.0)
        .bind(&seed)
        .bind(CONTENT)
        .bind(serde_json::json!({"javascriptReturns": CONTENT}))
        .execute(pg.pool())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE url_frontier SET canonical_url = $2, query_schema = $3, denial_reason = $4 WHERE run_id = $1",
    )
    .bind(run.id.0)
    .bind(&seed)
    .bind(serde_json::json!({"token": QUERY}))
    .bind(CONTENT)
    .execute(pg.pool())
    .await
    .unwrap();
    let active_dump = durable_dump(&pg, run.id).await;
    assert!(!active_dump.contains(QUERY));
    assert!(!active_dump.contains(CONTENT));
    assert!(!active_dump.contains("https://example.test"));

    buffer.ack(tenant, run.id, frontier).await.unwrap();
    assert!(PageRepo::list(&pg, run.id).await.unwrap().is_empty());
    assert_eq!(FrontierRepo::list(&pg, run.id).await.unwrap()[0].url, canonical);
    assert!(!durable_dump(&pg, run.id).await.contains(QUERY));
    clock.advance_ms(7_200_000);
    buffer.sweep(clock.now()).await.unwrap();
    assert!(matches!(
        pg.get(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert_eq!(pg.get_metadata(run.id).await.unwrap().id, run.id);
    assert!(matches!(
        FrontierRepo::list(&pg, run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(PageRepo::list(&pg, run.id).await.unwrap().is_empty());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn zdr_creation_without_ephemeral_transport_fails_before_durable_insert() {
    let Some((pg, _, _, tenant)) = setup().await else {
        return;
    };
    // A separately connected process does not inherit this process's local-memory buffer.
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap();
    let disconnected = Pg::connect(&url, pg.config().clone()).await.unwrap();
    let mut config = create_crawl("https://example.test/?token=private", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let run = crawl_run(tenant, config);
    assert!(matches!(
        disconnected.create(&run, None).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM crawl_runs WHERE run_id = $1")
        .bind(run.id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn expired_zdr_webhook_never_sends_hashed_url_or_blocks_durable_delivery() {
    let Some((pg, buffer, clock, tenant)) = setup().await else {
        return;
    };
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let zdr = crawl_run(tenant, config);
    let durable = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    pg.create(&zdr, None).await.unwrap();
    pg.create(&durable, None).await.unwrap();
    let api = PgApiRepo::new(pg.clone());
    let private_url = format!("https://receiver.test/hook?token={QUERY}");
    for (run, url) in [
        (zdr.id, private_url.clone()),
        (durable.id, "https://receiver.test/public".to_owned()),
    ] {
        let seq = pg.append(run, "completed", serde_json::json!({})).await.unwrap();
        api.webhook_enqueue(&WebhookDelivery {
            id: CrawlRunId::new().0,
            run,
            event_seq: seq,
            event_type: "completed".to_owned(),
            url,
            status: DeliveryStatus::Pending,
            attempts: 0,
            next_attempt_at: clock.now(),
            delivered_at: None,
            last_status: None,
            last_error: None,
        })
        .await
        .unwrap();
    }
    assert_eq!(api.webhook_list(zdr.id).await.unwrap()[0].url, private_url);
    assert!(!durable_dump(&pg, zdr.id).await.contains(QUERY));
    buffer.ack(tenant, zdr.id, i64::MIN + 2).await.unwrap();
    let claimed = api.webhook_claim_due(clock.now(), 10, 30).await.unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].run, durable.id);
    assert_eq!(claimed[0].url, "https://receiver.test/public");
    assert_eq!(api.webhook_dead_count(zdr.id).await.unwrap(), 1);
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn zdr_billing_keeps_exact_pdf_llm_guard_credits_and_tokens_after_expiry() {
    use crawlx_core::scrape::{FormatSpec, JobKind, ParserSpec, ScrapeDocument, ScrapeJob, ScrapeOptions};
    let Some((pg, buffer, clock, tenant)) = setup().await else {
        return;
    };
    let mut config = create_crawl("https://example.test/private.pdf", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let options = ScrapeOptions {
        parsers: vec![ParserSpec::pdf()],
        formats: vec![
            FormatSpec::Json {
                schema: None,
                prompt: Some(CONTENT.to_owned()),
            },
            FormatSpec::Question {
                question: CONTENT.to_owned(),
            },
        ],
        ..ScrapeOptions::default()
    };
    config.scrape = Some(ScrapeJob::new(JobKind::Crawl, options));
    let run = crawl_run(tenant, config);
    pg.create(&run, None).await.unwrap();
    let url = canonical_url("https://example.test/private.pdf");
    let (_, frontier) = pg.discover(run.id, &url, 0, None, None).await.unwrap();
    let mut document = ScrapeDocument::new(
        url.url.to_string(),
        url.url.to_string(),
        200,
        Digest::of("test", b"options"),
    );
    document.num_pages = Some(3);
    document.llm_tokens = 123;
    document.prompt_injection_checked = true;
    document.pii_redacted = true;
    document.summary = Some(CONTENT.to_owned());
    let page = PageRecord {
        run: run.id,
        frontier_id: frontier.unwrap(),
        url,
        status: 200,
        content_type: Some("application/pdf".to_owned()),
        content_digest: Digest::of("test", b"pdf"),
        title: Some(CONTENT.to_owned()),
        markdown: None,
        html: None,
        metadata: serde_json::json!({"scrape": document}),
        links: Vec::new(),
        fetched_at: clock.now(),
        lane: TrustLane::Diagnostic,
    };
    PageRepo::put(&pg, &page).await.unwrap();
    PageRepo::put(&pg, &page).await.unwrap();
    let billing = pg.billing(run.id).await.unwrap().unwrap();
    assert_eq!((billing.credits, billing.llm_tokens, billing.pages), (28, 123, 1));
    assert!(!durable_dump(&pg, run.id).await.contains(CONTENT));
    clock.advance_ms(7_200_000);
    buffer.sweep(clock.now()).await.unwrap();
    assert!(PageRepo::list(&pg, run.id).await.unwrap().is_empty());
    let billing = pg.billing(run.id).await.unwrap().unwrap();
    assert_eq!((billing.credits, billing.llm_tokens, billing.pages), (28, 123, 1));
    pg.drop_schema().await.unwrap();
}
