//! The scrape engine over PostgreSQL: the stored document, the artifacts, the cache
//! and `changeTracking` through `Stores::over_pg`, and a queued run executed by the lease loop.
//! Each test runs in its own schema on `CRAWLX_TEST_DATABASE_URL`; without it every test returns
//! early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use chrono::SecondsFormat;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::repo::{CrawlRun, FrontierStatus, PageRecord, RunRepo};
use crawlx_core::scrape::{
    CacheState, ChangeMode, ChangeStatus, FormatSpec, JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions,
};
use crawlx_core::{CanonicalUrl, Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::scrape::cache;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

const PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Pricing</title>
<meta name="description" content="All the plans"></head>
<body><main><h1>Pricing</h1><p>Main text here.</p><a href="/more">More</a></main></body></html>"#;

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    body: Arc<Mutex<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let body = Arc::new(Mutex::new(String::new()));
    let seen = Arc::clone(&hits);
    let app = Router::new()
        .route(
            "/page",
            get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], PAGE) }),
        )
        .route(
            "/missing",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><body><main><h1>Gone</h1></main></body></html>",
                )
            }),
        )
        .route(
            "/mutable",
            get(|State(b): State<Arc<Mutex<String>>>| async move {
                ([(header::CONTENT_TYPE, "text/html")], b.lock().unwrap().clone()).into_response()
            }),
        )
        .with_state(Arc::clone(&body))
        .layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().unwrap().push(req.uri().path().to_owned());
                    next.run(req).await
                }
            },
        ));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base,
        hits,
        body,
        task,
    }
}

struct Rig {
    pg: Pg,
    stores: Stores,
    dir: tempfile::TempDir,
    auth: AuthorizationRecord,
}

async fn rig() -> Option<Rig> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("t_scrape_{}", uuid::Uuid::now_v7().simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_durable(
        crawlx_worker::DurableStore::Postgres(pg.clone()),
        Arc::new(artifacts),
        TenantId::new(),
    );
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let now = SystemClock.now();
    let auth = AuthorizationRecord {
        url_prefixes: vec!["http://127.0.0.1".to_owned()],
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        valid_from: now - chrono::Duration::days(1),
        valid_to: now + chrono::Duration::days(1),
        verified_at: Some(now),
        ..sample_record(stores.tenant, now, &[])
    };
    authorization_fixture::register_verified(&pg, &auth).await;
    Some(Rig {
        pg,
        stores,
        dir,
        auth,
    })
}

macro_rules! rig {
    () => {
        match rig().await {
            Some(r) => r,
            None => {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

impl Rig {
    fn cfg(&self) -> WorkerConfig {
        WorkerConfig {
            artifacts_dir: self.dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        }
    }

    async fn scrape(&self, seed: &str, options: ScrapeOptions) -> Done {
        let report = run_local_with(
            LocalRun::new(crawl(seed, options, &self.auth), self.cfg())
                .with_authorization(self.auth.clone())
                .with_stores(self.stores.clone()),
        )
        .await
        .unwrap();
        Done {
            report,
            stores: self.stores.clone(),
        }
    }

    async fn teardown(self) {
        drop(self.stores);
        self.pg.drop_schema().await.unwrap();
    }
}

fn crawl(seed: &str, options: ScrapeOptions, auth: &AuthorizationRecord) -> CreateCrawl {
    let mut c = CreateCrawl::new(Url::parse(seed).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_027);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(auth.id);
    c.politeness.delay_ms = 0;
    c.scope.sitemap = SitemapMode::Skip;
    c.scope.known_files = Vec::new();
    c.scope.host_scope = HostScope::None;
    c.scope.max_discovery_depth = 0;
    c.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
    c
}

struct Done {
    report: RunReport,
    stores: Stores,
}

impl Done {
    fn page(&self) -> &PageRecord {
        assert_eq!(self.report.pages.len(), 1, "exactly one page row");
        &self.report.pages[0]
    }
    fn doc(&self) -> ScrapeDocument {
        ScrapeDocument::from_page_metadata(&self.page().metadata).expect("scrape document")
    }
    async fn markdown(&self) -> String {
        let artifact = self.page().markdown.as_ref().expect("markdown artifact");
        String::from_utf8(self.stores.artifacts.get(artifact).await.unwrap()).unwrap()
    }
}

fn opts(formats: Vec<FormatSpec>) -> ScrapeOptions {
    ScrapeOptions {
        formats,
        cache_principal: Some(uuid::Uuid::from_u128(1)),
        ..ScrapeOptions::default()
    }
}

fn rfc3339(page: &PageRecord) -> String {
    page.fetched_at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[tokio::test]
async fn a_scrape_over_postgres_stores_the_document_and_its_artifacts() {
    let rig = rig!();
    let site = start().await;
    let options = opts(vec![
        FormatSpec::Markdown,
        FormatSpec::Html,
        FormatSpec::Links,
        FormatSpec::RawHtml,
    ]);
    let done = rig.scrape(&site.url("/page"), options.clone()).await;
    assert_eq!(done.report.status, RunStatus::Completed);

    let page = done.page();
    assert_eq!((page.status, page.title.as_deref()), (200, Some("Pricing")));
    assert!(done.markdown().await.contains("Main text here."));
    assert!(String::from_utf8(
        done.stores
            .artifacts
            .get(page.html.as_ref().unwrap())
            .await
            .unwrap()
    )
    .unwrap()
    .contains("Main text here."));
    assert_eq!(page.links, [site.url("/more")]);

    // the document survives the jsonb round trip, blob references included
    let doc = done.doc();
    assert_eq!((doc.status_code, doc.cache_state), (200, CacheState::Miss));
    assert_eq!(
        doc.options_digest,
        cache::key(&options, None, done.report.run_id).digest()
    );
    assert_eq!(doc.meta["description"], serde_json::json!("All the plans"));
    let raw = doc.raw_html.expect("rawHtml blob");
    assert_eq!(
        done.stores.artifacts.get(&raw.artifact).await.unwrap(),
        PAGE.as_bytes()
    );
    assert_eq!(raw.size, PAGE.len() as u64);

    // the artifact index knows them as content artifacts of the run
    let indexed: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE run_id = $1")
        .bind(done.report.run_id.0)
        .fetch_one(rig.pg.pool())
        .await
        .unwrap();
    assert!(indexed >= 3, "markdown, html and rawHtml are indexed: {indexed}");

    let rows = rig.stores.frontier.list(done.report.run_id).await.unwrap();
    assert_eq!(rows[0].status, FrontierStatus::Succeeded);
    rig.teardown().await;
}

#[tokio::test]
async fn a_second_scrape_is_served_from_the_stored_one_over_postgres() {
    let rig = rig!();
    let site = start().await;
    let options = opts(vec![FormatSpec::Markdown]);
    let first = rig.scrape(&site.url("/page"), options.clone()).await;
    let second = rig.scrape(&site.url("/page"), options.clone()).await;
    assert_eq!(site.count("/page"), 1, "the second run did not fetch");

    let (a, b) = (first.page(), second.page());
    assert_ne!(a.run, b.run);
    let doc = second.doc();
    assert_eq!(doc.cache_state, CacheState::Hit);
    assert_eq!(doc.cached_at.as_deref(), Some(rfc3339(a).as_str()));
    assert_eq!(a.markdown, b.markdown, "the hit references the stored artifact");
    assert_eq!(second.markdown().await, first.markdown().await);
    assert_eq!(a.fetched_at, b.fetched_at);

    // the lookup the API's fast path uses answers the same way
    let canonical: CanonicalUrl = a.url.clone();
    let stored = cache::lookup(
        rig.stores.pages.as_ref(),
        rig.stores.runs.as_ref(),
        rig.stores.artifacts.as_ref(),
        rig.stores.tenant,
        &canonical,
        &options,
        None,
        a.run,
        SystemClock.now(),
    )
    .await
    .unwrap()
    .expect("a stored scrape");
    assert_eq!(stored.markdown, a.markdown);
    let none = cache::lookup(
        rig.stores.pages.as_ref(),
        rig.stores.runs.as_ref(),
        rig.stores.artifacts.as_ref(),
        rig.stores.tenant,
        &canonical,
        &ScrapeOptions {
            max_age_ms: 0,
            ..options.clone()
        },
        None,
        a.run,
        SystemClock.now(),
    )
    .await
    .unwrap();
    assert!(none.is_none(), "maxAge 0 disables the cache");

    // an error page is a document too, and is never served from the cache
    let missing = rig.scrape(&site.url("/missing"), options.clone()).await;
    assert_eq!((missing.page().status, missing.doc().status_code), (404, 404));
    assert!(missing.doc().not_cacheable);
    rig.scrape(&site.url("/missing"), options).await;
    assert_eq!(site.count("/missing"), 2);
    rig.teardown().await;
}

#[tokio::test]
async fn change_tracking_over_postgres_walks_new_same_changed() {
    let rig = rig!();
    let site = start().await;
    let tracking = opts(vec![FormatSpec::ChangeTracking {
        modes: vec![ChangeMode::GitDiff],
        schema: None,
        prompt: None,
        tag: None,
    }]);
    let set = |text: &str| {
        *site.body.lock().unwrap() =
            format!("<html><body><main><h1>Plans</h1><p>{text}</p></main></body></html>");
    };
    set("old text");
    let one = rig.scrape(&site.url("/mutable"), tracking.clone()).await;
    assert_eq!(
        one.doc().change_tracking.unwrap().change_status,
        ChangeStatus::New
    );
    let same = rig.scrape(&site.url("/mutable"), tracking.clone()).await;
    let t = same.doc().change_tracking.unwrap();
    assert_eq!(t.change_status, ChangeStatus::Same);
    assert_eq!(t.previous_scrape_at.unwrap(), rfc3339(one.page()));
    assert_eq!(site.count("/mutable"), 2, "changeTracking always fetches");

    set("new text");
    let changed = rig.scrape(&site.url("/mutable"), tracking).await;
    let t = changed.doc().change_tracking.unwrap();
    assert_eq!(t.change_status, ChangeStatus::Changed);
    let text = t.diff.unwrap()["text"].as_str().unwrap().to_owned();
    assert!(text.contains("-old text") && text.contains("+new text"), "{text}");
    assert_eq!(t.previous_scrape_at.unwrap(), rfc3339(same.page()));
    rig.teardown().await;
}

#[tokio::test]
async fn the_lease_loop_runs_a_queued_scrape_over_postgres() {
    let rig = rig!();
    let site = start().await;
    let mut c = crawl(
        &site.url("/page"),
        opts(vec![FormatSpec::Markdown, FormatSpec::Links]),
        &rig.auth,
    );
    c.mode = CrawlMode::Hybrid; // whatever the creator wrote: a scrape run executes as a static run
    c.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: rig.stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: c.effective_seed(),
        config_digest: c.digest().unwrap(),
        config: c.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    rig.stores.runs.create(&run, None).await.unwrap();
    rig.stores
        .runs
        .create_sessions(&crawlx_scheduler::RunPlanner::sessions(run.id, &c))
        .await
        .unwrap();
    let mut cfg = rig.cfg();
    cfg.database_url = None;
    cfg.idle_exit_after = Some(Duration::from_millis(700));
    run_with(cfg, rig.stores.clone(), None, CancellationToken::new())
        .await
        .unwrap();

    let row = rig.stores.runs.get(run.id).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed);
    assert_eq!(row.counters.urls.succeeded, 1);
    let pages = rig.stores.pages.list(run.id).await.unwrap();
    assert_eq!(pages.len(), 1);
    let doc = ScrapeDocument::from_page_metadata(&pages[0].metadata).unwrap();
    assert_eq!(doc.status_code, 200);
    assert_eq!(pages[0].links, [site.url("/more")]);
    assert!(pages[0].markdown.is_some());
    rig.teardown().await;
}
