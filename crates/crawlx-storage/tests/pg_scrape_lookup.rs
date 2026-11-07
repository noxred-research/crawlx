//! `PageRepo::recent_for_url` on PostgreSQL (migration 0017): the lookup behind the
//! scrape engine's `maxAge`, `minAge`, `lockdown` and `changeTracking`. Each test runs in its own
//! schema on `CRAWLX_TEST_DATABASE_URL`; without that variable every test returns early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{PageRecord, PageRepo, RunRepo};
use crawlx_core::{ArtifactId, ArtifactRef, CanonicalUrl, CrawlRunId, TenantId, TrustLane};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{Pg, PgConfig};
use sqlx::Row as _;

struct Env {
    pg: Pg,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("t_{}", CrawlRunId::new().0.simple())),
            max_connections: 4,
            ..PgConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    Some(Env { pg })
}

macro_rules! env {
    () => {
        match setup().await {
            Some(e) => e,
            None => {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

impl Env {
    async fn teardown(self) {
        self.pg.drop_schema().await.expect("drop schema");
    }

    async fn tenant(&self, name: &str) -> TenantId {
        let tenant = TenantId::new();
        self.pg.ensure_tenant(tenant, name).await.expect("tenant");
        tenant
    }

    async fn run(&self, tenant: TenantId) -> CrawlRunId {
        let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        self.pg.create(&run, None).await.expect("create run");
        run.id
    }

    /// A page of `run` for `url`, fetched at `at`, carrying `marker` in its metadata.
    async fn page(&self, run: CrawlRunId, url: &CanonicalUrl, at: DateTime<Utc>, marker: &str) {
        let (_, frontier) = crawlx_core::repo::FrontierRepo::discover(&self.pg, run, url, 0, None, None)
            .await
            .unwrap();
        let page = PageRecord {
            run,
            frontier_id: frontier.unwrap(),
            url: url.clone(),
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("t", marker.as_bytes()),
            title: None,
            markdown: Some(ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest::of("t", marker.as_bytes()),
            }),
            html: None,
            metadata: serde_json::json!({ "marker": marker }),
            links: Vec::new(),
            fetched_at: at,
            lane: TrustLane::Diagnostic,
        };
        PageRepo::put(&self.pg, &page).await.unwrap();
    }

    async fn markers(&self, tenant: TenantId, url: &CanonicalUrl, limit: u32) -> Vec<String> {
        self.pg
            .recent_for_url(tenant, url, limit)
            .await
            .unwrap()
            .iter()
            .map(|p| p.metadata["marker"].as_str().unwrap().to_owned())
            .collect()
    }
}

#[tokio::test]
async fn recent_pages_of_a_url_come_newest_first_within_one_tenant() {
    let env = env!();
    let (alpha, beta) = (env.tenant("alpha").await, env.tenant("beta").await);
    let (a1, a2, b1) = (env.run(alpha).await, env.run(alpha).await, env.run(beta).await);
    let u = canonical_url("https://example.test/pricing");
    let other = canonical_url("https://example.test/other");
    let t0 = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
    env.page(a1, &u, t0, "alpha-old").await;
    env.page(a2, &u, t0 + Duration::seconds(10), "alpha-new").await;
    env.page(b1, &u, t0 + Duration::seconds(20), "beta-newest").await;
    env.page(a1, &other, t0 + Duration::seconds(30), "alpha-other-url")
        .await;

    assert_eq!(
        env.markers(alpha, &u, 10).await,
        ["alpha-new", "alpha-old"],
        "newest first"
    );
    assert_eq!(
        env.markers(beta, &u, 10).await,
        ["beta-newest"],
        "another tenant's pages never leak"
    );
    assert_eq!(env.markers(alpha, &other, 10).await, ["alpha-other-url"]);
    assert!(env
        .markers(alpha, &canonical_url("https://example.test/never-scraped"), 10)
        .await
        .is_empty());
    assert!(env.markers(env.tenant("gamma").await, &u, 10).await.is_empty());

    assert_eq!(
        env.markers(alpha, &u, 1).await,
        ["alpha-new"],
        "the limit keeps the newest"
    );
    assert!(env.markers(alpha, &u, 0).await.is_empty());
    env.teardown().await;
}

#[tokio::test]
async fn the_page_rows_come_back_whole_including_artifacts_and_metadata() {
    let env = env!();
    let tenant = env.tenant("alpha").await;
    let run = env.run(tenant).await;
    let u = canonical_url("https://example.test/whole");
    let at = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
    env.page(run, &u, at, "whole").await;
    let rows = env.pg.recent_for_url(tenant, &u, 5).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!((row.run, row.status, &row.url), (run, 200, &u));
    assert_eq!(row.fetched_at, at);
    assert!(row.markdown.is_some() && row.html.is_none());
    assert_eq!(row.content_type.as_deref(), Some("text/html"));
    env.teardown().await;
}

#[tokio::test]
async fn the_lookup_has_an_index_on_url_hash_and_fetched_at() {
    let env = env!();
    let row = sqlx::query("SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'pages_url_recent'")
        .fetch_one(env.pg.pool())
        .await
        .expect("migration 0017 created pages_url_recent");
    let def: String = row.get("indexdef");
    assert!(
        def.contains("url_hash") && def.contains("fetched_at DESC"),
        "{def}"
    );

    // with sequential scans disabled the planner must reach the table through that index
    let mut tx = env.pg.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN SELECT p.run_id FROM pages p WHERE p.url_hash = '\\x00'::bytea ORDER BY p.fetched_at DESC LIMIT 5",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>(0))
    .collect();
    assert!(plan.iter().any(|l| l.contains("pages_url_recent")), "{plan:?}");
    drop(tx);
    env.teardown().await;
}
