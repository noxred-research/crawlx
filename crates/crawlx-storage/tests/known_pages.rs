//! `PageRepo::known_pages` (migration 0018): the stored pages of one site behind the
//! URL sources of `POST /v2/map`. The same scenario runs on the in-memory store and on
//! PostgreSQL, so the two agree on host matching, tenant scope, retention, status, the
//! `notCacheable` flag, ordering and the limit. The PostgreSQL tests run in their own schema on
//! `CRAWLX_TEST_DATABASE_URL`; without that variable they return early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, Utc};
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{FrontierRepo, KnownPage, PageRecord, PageRepo, RunRepo};
use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
use crawlx_core::{CrawlRunId, TenantId, TrustLane};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{MemoryStore, Pg, StoreConfig};
use serde_json::{json, Value};
use sqlx::Row as _;

/// Millisecond precision: what PostgreSQL round-trips.
fn now_ms() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

/// A page to store.
struct Spec {
    url: &'static str,
    status: u16,
    title: Option<&'static str>,
    description: Option<&'static str>,
    links: &'static [&'static str],
    not_cacheable: bool,
}

impl Spec {
    const fn new(url: &'static str) -> Self {
        Self {
            url,
            status: 200,
            title: None,
            description: None,
            links: &[],
            not_cacheable: false,
        }
    }
}

async fn new_run<S: RunRepo>(
    s: &S,
    tenant: TenantId,
    mode: RetentionMode,
    days: u16,
    created_at: DateTime<Utc>,
) -> CrawlRunId {
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = mode;
    cfg.retention.days = days;
    let mut run = crawl_run(tenant, cfg);
    run.created_at = created_at;
    s.create(&run, None).await.unwrap();
    run.id
}

async fn store_page<S: FrontierRepo + PageRepo>(s: &S, run: CrawlRunId, at: DateTime<Utc>, spec: &Spec) {
    let url = canonical_url(spec.url);
    let (_, frontier) = FrontierRepo::discover(s, run, &url, 0, None, None).await.unwrap();
    let mut metadata = json!({});
    if let Some(d) = spec.description {
        metadata["description"] = json!(d);
    }
    if spec.not_cacheable {
        // the real document layout, so the flag's JSON path is the one the scrape engine writes
        let mut doc = ScrapeDocument::new(
            spec.url.to_owned(),
            spec.url.to_owned(),
            spec.status,
            ScrapeOptions::default().cache_digest(),
        );
        doc.not_cacheable = true;
        metadata[ScrapeDocument::METADATA_KEY] = serde_json::to_value(&doc).unwrap();
    }
    let page = PageRecord {
        run,
        frontier_id: frontier.unwrap(),
        url,
        status: spec.status,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", spec.url.as_bytes()),
        title: spec.title.map(str::to_owned),
        markdown: None,
        html: None,
        metadata,
        links: spec.links.iter().map(|l| (*l).to_owned()).collect(),
        fetched_at: at,
        lane: TrustLane::Diagnostic,
    };
    PageRepo::put(s, &page).await.unwrap();
}

fn urls(pages: &[KnownPage]) -> Vec<String> {
    pages.iter().map(|p| p.url.url.to_string()).collect()
}

/// Four tenants' worth of pages around `example.test`, then every lookup the facade makes.
async fn scenario<S: RunRepo + PageRepo + FrontierRepo>(
    s: &S,
    alpha: TenantId,
    beta: TenantId,
    gamma: TenantId,
) {
    let t0 = now_ms();
    let sec = Duration::seconds;
    let standard = RetentionMode::Standard;
    let main = new_run(s, alpha, standard, 7, t0).await;
    let later = new_run(s, alpha, standard, 7, t0).await;
    let zdr = new_run(s, alpha, RetentionMode::Zdr, 0, t0).await;
    let old = new_run(s, alpha, standard, 7, t0 - Duration::days(10)).await;
    let other = new_run(s, beta, standard, 7, t0).await;

    let home = Spec {
        title: Some("Home"),
        description: Some("The home page"),
        links: &[
            "https://example.test/a",
            "https://example.test/b",
            "https://other.test/x",
        ],
        ..Spec::new("https://example.test/")
    };
    store_page(s, main, t0, &home).await;
    let blog = Spec {
        links: &["https://www.example.test/blog/p1"],
        ..Spec::new("https://www.example.test/blog")
    };
    store_page(s, main, t0 + sec(1), &blog).await;
    // listed: an HTTP status of 0 means none was recorded
    let no_status = Spec {
        status: 0,
        ..Spec::new("https://example.test/nostatus")
    };
    store_page(s, main, t0 + sec(4), &no_status).await;
    // userinfo and a port do not hide the host
    store_page(
        s,
        main,
        t0 + sec(8),
        &Spec::new("http://user:secret@example.test:8080/auth"),
    )
    .await;
    store_page(s, main, t0 + sec(9), &Spec::new("http://[::1]:8080/v6")).await;
    // never listed: an error page, a page flagged not cacheable, other hosts (a name that merely
    // ends in the domain, a domain that merely starts with it)
    let gone = Spec {
        status: 404,
        links: &["https://example.test/from-404"],
        ..Spec::new("https://example.test/gone")
    };
    store_page(s, main, t0 + sec(2), &gone).await;
    let unlisted = Spec {
        not_cacheable: true,
        links: &["https://example.test/from-unlisted"],
        ..Spec::new("https://example.test/unlisted")
    };
    store_page(s, main, t0 + sec(3), &unlisted).await;
    for (i, u) in [
        "https://example.org/",
        "https://notexample.test/",
        "https://example.test.evil.org/",
    ]
    .into_iter()
    .enumerate()
    {
        store_page(s, main, t0 + sec(5 + i64::try_from(i).unwrap()), &Spec::new(u)).await;
    }
    store_page(s, later, t0 + sec(10), &Spec::new("https://example.test/new")).await;
    store_page(s, zdr, t0 + sec(11), &Spec::new("https://example.test/zdr")).await;
    store_page(s, old, t0 + sec(12), &Spec::new("https://example.test/expired")).await;
    store_page(
        s,
        other,
        t0 + sec(13),
        &Spec::new("https://example.test/beta-only"),
    )
    .await;

    let now = t0 + Duration::minutes(1);
    let known = |tenant, domain: &'static str, subdomains, at, limit| {
        let s = &*s;
        async move {
            s.known_pages(tenant, domain, subdomains, at, limit)
                .await
                .unwrap()
        }
    };

    // the domain and its subdomains, newest first; the zero-data-retention run, the expired run
    // and the other tenant's pages are never read
    let all = known(alpha, "example.test", true, now, 100).await;
    assert_eq!(
        urls(&all),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth",
            "https://example.test/nostatus",
            "https://www.example.test/blog",
            "https://example.test/",
        ]
    );
    let page = all.last().unwrap();
    assert_eq!(page.title.as_deref(), Some("Home"));
    assert_eq!(page.description.as_deref(), Some("The home page"));
    assert_eq!(
        page.links,
        [
            "https://example.test/a",
            "https://example.test/b",
            "https://other.test/x"
        ]
    );
    assert!(all[0].title.is_none() && all[0].description.is_none() && all[0].links.is_empty());

    // one host only
    assert_eq!(
        urls(&known(alpha, "example.test", false, now, 100).await),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth",
            "https://example.test/nostatus",
            "https://example.test/",
        ]
    );
    assert_eq!(
        urls(&known(alpha, "www.example.test", false, now, 100).await),
        ["https://www.example.test/blog"]
    );
    // case and a trailing dot of the argument do not matter
    assert_eq!(
        known(alpha, "EXAMPLE.test.", true, now, 100).await,
        all,
        "the domain is matched case-insensitively"
    );
    // an IP literal is a host of its own
    assert_eq!(
        urls(&known(alpha, "[::1]", false, now, 100).await),
        ["http://[::1]:8080/v6"]
    );
    // a domain with LIKE metacharacters matches nothing it should not
    assert!(known(alpha, "ex_mple.test", true, now, 100).await.is_empty());
    assert!(known(alpha, "%", true, now, 100).await.is_empty());

    // tenants
    assert_eq!(
        urls(&known(beta, "example.test", true, now, 100).await),
        ["https://example.test/beta-only"]
    );
    assert!(known(gamma, "example.test", true, now, 100).await.is_empty());

    // the limit keeps the newest pages
    assert_eq!(
        urls(&known(alpha, "example.test", true, now, 2).await),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth"
        ]
    );
    assert!(known(alpha, "example.test", true, now, 0).await.is_empty());

    // `now` decides which runs expired: the standard runs live seven days from their creation
    assert_eq!(
        known(alpha, "example.test", true, t0 + Duration::days(6), 100)
            .await
            .len(),
        5
    );
    assert!(
        known(alpha, "example.test", true, t0 + Duration::days(8), 100)
            .await
            .is_empty(),
        "every run of the tenant has expired"
    );
}

#[tokio::test]
async fn the_memory_store_lists_the_stored_pages_of_a_site() {
    let store = MemoryStore::new();
    scenario(&store, TenantId::new(), TenantId::new(), TenantId::new()).await;
}

struct Env {
    pg: Pg,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("t_{}", CrawlRunId::new().0.simple())),
            max_connections: 4,
            ..StoreConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    let pg = pg.with_delivery_buffer(std::sync::Arc::new(crawlx_storage::DeliveryBuffer::new(
        std::sync::Arc::new(crawlx_core::SystemClock),
        crawlx_storage::BufferLimits::default(),
    )));
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
}

#[tokio::test]
async fn postgres_lists_the_stored_pages_of_a_site() {
    let env = env!();
    let (alpha, beta, gamma) = (
        env.tenant("alpha").await,
        env.tenant("beta").await,
        env.tenant("gamma").await,
    );
    scenario(&env.pg, alpha, beta, gamma).await;
    env.teardown().await;
}

#[tokio::test]
async fn the_host_key_is_the_reversed_lower_case_host_of_every_url_shape() {
    let env = env!();
    let tenant = env.tenant("alpha").await;
    let run = new_run(&env.pg, tenant, RetentionMode::Standard, 7, now_ms()).await;
    for (i, u) in [
        "https://Example.TEST/p",
        "http://user:pw@example.test:8080/q?x=1#f",
        "http://[::1]:8080/v6",
        "https://sub.example.test./dot",
    ]
    .into_iter()
    .enumerate()
    {
        store_page(
            &env.pg,
            run,
            now_ms() + Duration::seconds(i64::try_from(i).unwrap()),
            &Spec::new(u),
        )
        .await;
    }
    let keys: Vec<String> = sqlx::query("SELECT host_key FROM pages ORDER BY fetched_at")
        .fetch_all(env.pg.pool())
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>("host_key"))
        .collect();
    assert_eq!(
        keys,
        ["tset.elpmaxe", "tset.elpmaxe", "]1::[", ".tset.elpmaxe.bus"]
    );
    env.teardown().await;
}

#[tokio::test]
async fn the_site_lookup_reaches_pages_through_the_host_key_index() {
    let env = env!();
    let row = sqlx::query(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'pages_host_key'",
    )
    .fetch_one(env.pg.pool())
    .await
    .expect("migration 0018 created pages_host_key");
    let def: String = row.get("indexdef");
    assert!(
        def.contains("host_key") && def.contains("text_pattern_ops"),
        "{def}"
    );

    // with sequential scans disabled the planner must reach the table through that index, for the
    // exact host and for the domain with its subdomains
    let mut tx = env.pg.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query(
        "EXPLAIN SELECT p.run_id FROM pages p WHERE p.host_key = 'tset.elpmaxe' OR p.host_key LIKE 'tset.elpmaxe.%'",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>(0))
    .collect();
    assert!(plan.iter().any(|l| l.contains("pages_host_key")), "{plan:?}");
    drop(tx);
    env.teardown().await;
}

#[test]
fn the_not_cacheable_flag_is_read_from_the_stored_scrape_document() {
    let mut page = PageRecord {
        run: CrawlRunId::new(),
        frontier_id: 0,
        url: canonical_url("https://example.test/"),
        status: 200,
        content_type: None,
        content_digest: Digest::of("t", b"x"),
        title: None,
        markdown: None,
        html: None,
        metadata: Value::Null,
        links: Vec::new(),
        fetched_at: now_ms(),
        lane: TrustLane::Diagnostic,
    };
    assert!(!page.is_not_cacheable(), "no metadata");
    let mut doc = ScrapeDocument::new(
        page.url.url.to_string(),
        page.url.url.to_string(),
        200,
        ScrapeOptions::default().cache_digest(),
    );
    page.metadata = json!({ ScrapeDocument::METADATA_KEY: serde_json::to_value(&doc).unwrap() });
    assert!(!page.is_not_cacheable(), "a cacheable scrape");
    doc.not_cacheable = true;
    page.metadata = json!({ ScrapeDocument::METADATA_KEY: serde_json::to_value(&doc).unwrap() });
    assert!(page.is_not_cacheable());
}
