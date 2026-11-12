//! Adaptive crawl and discovery end to end against an in-process site: the seeded render probe
//! paid from the effect budget, the query-driven stop policy, recorded seed sources with a live
//! check, and typed hops with queue cost.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::adaptive::{AdaptiveRendering, AdaptiveStopConfigV1};
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::counters::TerminalReason;
use crawlx_core::discovery::{SeedFixtureV1, SeedLiveCheckV1, SeedSourceKindV1, SeedSourcesV1};
use crawlx_core::orchestration::OrchestrationConfigV1;
use crawlx_core::repo::FrontierStatus;
use crawlx_core::request::hops::HopPolicyV1;
use crawlx_core::{CrawlRunId, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---- fixture site ---------------------------------------------------------------------------

#[derive(Clone)]
struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
    location: Option<String>,
}

fn html(body: impl Into<String>) -> Reply {
    Reply {
        status: 200,
        content_type: "text/html; charset=utf-8",
        body: body.into(),
        location: None,
    }
}

fn text(body: impl Into<String>) -> Reply {
    Reply {
        content_type: "text/plain",
        ..html(body)
    }
}

fn redirect(to: &str) -> Reply {
    Reply {
        status: 302,
        content_type: "text/plain",
        body: String::new(),
        location: Some(to.to_owned()),
    }
}

struct Hit {
    method: String,
    path: String,
    at: Instant,
}

struct Shared {
    routes: BTreeMap<String, Reply>,
    log: Mutex<Vec<Hit>>,
}

struct Site {
    base: String,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    /// Requests seen, in arrival order, as `(method, path)`.
    fn hits(&self) -> Vec<(String, String)> {
        self.shared
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|hit| (hit.method.clone(), hit.path.clone()))
            .collect()
    }

    /// Paths requested with `method`, in arrival order, `robots.txt` left out.
    fn paths(&self, method: &str) -> Vec<String> {
        self.hits()
            .into_iter()
            .filter(|(m, p)| m == method && p != "/robots.txt")
            .map(|(_, path)| path)
            .collect()
    }

    fn instants(&self, method: &str) -> Vec<Instant> {
        self.shared
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.method == method)
            .map(|hit| hit.at)
            .collect()
    }
}

async fn handle(
    axum::extract::State(shared): axum::extract::State<Arc<Shared>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let path = request.uri().path().to_owned();
    shared.log.lock().unwrap().push(Hit {
        method: request.method().to_string(),
        path: path.clone(),
        at: Instant::now(),
    });
    let reply = shared.routes.get(&path).cloned().unwrap_or(Reply {
        status: 404,
        content_type: "text/plain",
        body: "not found".into(),
        location: None,
    });
    let mut builder = axum::response::Response::builder()
        .status(reply.status)
        .header("content-type", reply.content_type);
    if let Some(location) = &reply.location {
        builder = builder.header("location", location);
    }
    builder.body(axum::body::Body::from(reply.body)).unwrap()
}

/// Serve the routes `build` returns for the site's own base URL.
async fn site(build: impl FnOnce(&str) -> BTreeMap<String, Reply>) -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let shared = Arc::new(Shared {
        routes: build(&base),
        log: Mutex::new(Vec::new()),
    });
    let app = axum::Router::new()
        .fallback(handle)
        .with_state(Arc::clone(&shared));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, shared, task }
}

fn routes(entries: Vec<(&str, Reply)>) -> BTreeMap<String, Reply> {
    entries
        .into_iter()
        .map(|(path, reply)| (path.to_owned(), reply))
        .collect()
}

// ---- run helpers ----------------------------------------------------------------------------

fn cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn crawl_of(base: &str, mode: CrawlMode) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = mode;
    crawl.seed = Some(7);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files = Vec::new();
    crawl
}

struct Done {
    report: RunReport,
    stores: Stores,
    _dir: tempfile::TempDir,
}

async fn run(crawl: CreateCrawl, backend: Option<Arc<FakeBackend>>) -> Done {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut local = LocalRun::new(crawl, cfg(dir.path())).with_stores(stores.clone());
    if let Some(backend) = backend {
        local = local.with_backend(backend);
    }
    let report = run_local_with(local).await.unwrap();
    Done {
        report,
        stores,
        _dir: dir,
    }
}

async fn events(done: &Done, kind: &str) -> Vec<serde_json::Value> {
    done.stores
        .events
        .list_after(done.report.run_id, 0, 100_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == kind)
        .map(|event| event.payload)
        .collect()
}

fn path_of(url: &str) -> String {
    url::Url::parse(url).unwrap().path().to_owned()
}

// ---- adaptive render prediction (probe) ----------------------------------------------------

/// Plain server-rendered text, nothing a browser would add.
fn plain(title: &str) -> Reply {
    html(format!(
        "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>{}</p>\
         <a href=\"/static1\">one</a><a href=\"/static2\">two</a><a href=\"/static3\">three</a>\
         <a href=\"/spa\">app</a></main></body></html>",
        format!("server rendered words for {title} ").repeat(30)
    ))
}

async fn render_site() -> Site {
    site(|_| {
        routes(vec![
            ("/", plain("home")),
            ("/static1", plain("static one")),
            ("/static2", plain("static two")),
            ("/static3", plain("static three")),
            ("/main.js", text("console.log(1)")),
            (
                "/spa",
                html(
                    "<html><head><title>app</title></head><body><div id=\"app\"></div>\
                     <script type=\"module\" src=\"/main.js\"></script></body></html>",
                ),
            ),
        ])
    })
    .await
}

fn render_backend(base: &str) -> Arc<FakeBackend> {
    let mut script = FakeScript::new();
    for path in ["/", "/static1", "/static2", "/static3", "/spa"] {
        script = script.page(FakePage::new(&format!("{base}{path}")).title(path));
    }
    Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// Effects one plain fetch reserves: every redirect hop of a single attempt.
fn base_effects() -> u32 {
    u32::try_from(crawlx_fetch::DEFAULT_MAX_REDIRECTS).unwrap() + 1
}

struct Rendered {
    /// Recorded predictor decision of each page, by path.
    records: BTreeMap<String, serde_json::Value>,
    /// The dynamic signal stored with each page, by path.
    signals: BTreeMap<String, Option<String>>,
    /// Paths the browser plane observed.
    states: BTreeSet<String>,
    predictor_events: usize,
    failed: u64,
}

async fn hybrid(site: &Site, seed: u64, per_mille: u16, max_probes: u32, effect_cap: u32) -> Rendered {
    let mut crawl = crawl_of(&site.base, CrawlMode::Hybrid);
    crawl.seed = Some(seed);
    crawl.limits.interactions = 10;
    crawl.fetch.retries = 0;
    crawl.dynamic.adaptive = Some(AdaptiveRendering::new(per_mille, max_probes));
    let mut orchestration = OrchestrationConfigV1::default();
    orchestration.attempts.max_total_effects = effect_cap;
    crawl.orchestration = Some(orchestration);
    let done = run(crawl, Some(render_backend(&site.base))).await;
    let mut records = BTreeMap::new();
    let mut signals = BTreeMap::new();
    for page in &done.report.pages {
        let Some(record) = page.metadata.get("dynamicPredictor") else {
            continue;
        };
        let path = path_of(page.url.url.as_str());
        records.insert(path.clone(), record.clone());
        signals.insert(
            path,
            page.metadata
                .get("dynamic_signal")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        );
    }
    Rendered {
        records,
        signals,
        // the seed page is always opened by the hybrid hand-off; only the others say anything
        states: done
            .report
            .states
            .iter()
            .map(|state| state.url.url.path().to_owned())
            .filter(|path| path != "/")
            .collect(),
        predictor_events: events(&done, "dynamic.predictor").await.len(),
        failed: done.report.counters.urls.failed,
    }
}

#[tokio::test]
async fn a_static_page_never_reaches_the_browser_and_a_dynamic_page_always_does() {
    let site = render_site().await;
    let seen = hybrid(&site, 7, 0, 16, 64).await;
    assert_eq!(seen.records.len(), 5, "every page carries its predictor decision");
    for path in ["/", "/static1", "/static2", "/static3"] {
        assert_eq!(seen.records[path]["verdict"], "static", "{path}");
        assert_eq!(seen.signals[path], None, "{path}");
    }
    assert_eq!(seen.records["/spa"]["verdict"], "escalate");
    assert_eq!(seen.records["/spa"]["signal"], "spa_root");
    assert_eq!(seen.signals["/spa"].as_deref(), Some("spa_root"));
    assert_eq!(
        seen.states,
        BTreeSet::from(["/spa".to_owned()]),
        "only the dynamic page is rendered"
    );
    assert_eq!(seen.failed, 0);
}

#[tokio::test]
async fn a_probe_is_paid_from_the_effect_budget_and_denied_when_it_cannot_be() {
    let site = render_site().await;
    // Every URL is selected; the run may pay for two probes; the budget has room for exactly one
    // effect above a plain fetch.
    let paid = hybrid(&site, 7, 1000, 2, base_effects() + 1).await;
    for path in ["/", "/static1"] {
        let record = &paid.records[path];
        assert_eq!(record["verdict"], "probe", "{path}");
        assert_eq!(record["charged"], true, "{path}");
        assert_eq!(paid.signals[path].as_deref(), Some("predictor_probe"), "{path}");
    }
    for path in ["/static2", "/static3"] {
        let record = &paid.records[path];
        assert_eq!(record["verdict"], "probe_denied", "{path}");
        assert_eq!(record["denial"], "probe_allowance", "{path}");
        assert_eq!(record["charged"], false);
        assert_eq!(
            paid.signals[path], None,
            "an unpaid probe never reaches the browser"
        );
    }
    assert_eq!(
        paid.records["/spa"]["verdict"], "escalate",
        "a dynamic page needs no probe"
    );
    assert_eq!(
        paid.states,
        BTreeSet::from(["/static1".to_owned(), "/spa".to_owned()]),
        "paid probes and the dynamic page reach the browser exactly once each"
    );
    assert_eq!(paid.failed, 0);

    // The same crawl with one effect less: the probe cannot be paid for, so no static page is
    // probed, and the page is still fetched, never failed for it.
    let broke = hybrid(&site, 7, 1000, 16, base_effects()).await;
    for path in ["/", "/static1", "/static2", "/static3"] {
        let record = &broke.records[path];
        assert_eq!(record["verdict"], "probe_denied", "{path}");
        assert_eq!(record["denial"], "effect_budget", "{path}");
    }
    assert_eq!(broke.states, BTreeSet::from(["/spa".to_owned()]));
    assert_eq!(broke.failed, 0, "an unpayable probe costs the page nothing");
}

#[tokio::test]
async fn the_same_seed_replays_the_same_draws_and_each_row_commits_one_decision() {
    let site = render_site().await;
    let first = hybrid(&site, 7, 500, 100, 64).await;
    let again = hybrid(&site, 7, 500, 100, 64).await;
    let other = hybrid(&site, 9, 500, 100, 64).await;
    let draws = |seen: &Rendered| -> BTreeMap<String, (u64, bool)> {
        seen.records
            .iter()
            .map(|(path, record)| {
                (
                    path.clone(),
                    (
                        record["drawPerMille"].as_u64().unwrap(),
                        record["selected"].as_bool().unwrap(),
                    ),
                )
            })
            .collect()
    };
    assert_eq!(
        draws(&first),
        draws(&again),
        "a replay of the run reproduces its draws"
    );
    assert_ne!(draws(&first), draws(&other), "the draw follows the run seed");
    assert!(first.records.values().all(|record| record["version"] == 1));
    assert_eq!(first.predictor_events, 5, "one recorded decision per row");
    assert_eq!(first.records.len(), 5, "and one committed page per row");
    // the selection is exactly `draw < probePerMille`
    for (draw, selected) in draws(&first).values() {
        assert_eq!(*selected, *draw < 500);
    }
}

// ---- query-driven stop ---------------------------------------------------------------------

fn corpus_page(n: usize, link: Option<usize>) -> Reply {
    let next = link.map_or(String::new(), |next| format!("<a href=\"/p{next}\">more</a>"));
    html(format!(
        "<html><head><title>p{n}</title></head><body><main><p>rust async runtime tokio executor scheduler item{n}</p>{next}</main></body></html>"
    ))
}

/// A chain `/` -> `/p1` -> ... -> `/p9` whose pages repeat each other's words.
async fn chain_site() -> Site {
    site(|_| {
        let mut entries = vec![("/".to_owned(), corpus_page(0, Some(1)))];
        for n in 1..=9 {
            entries.push((format!("/p{n}"), corpus_page(n, (n < 9).then_some(n + 1))));
        }
        entries.into_iter().collect()
    })
    .await
}

/// A star `/` -> `/q1` .. `/q6`; every page brings words of its own.
async fn star_site(word: &str) -> Site {
    let word = word.to_owned();
    site(move |_| {
        let page = |n: usize, links: bool| {
            let links = if links {
                (1..=6).map(|q| format!("<a href=\"/q{q}\">q{q}</a>")).collect::<String>()
            } else {
                String::new()
            };
            html(format!(
                "<html><head><title>{word}{n}</title></head><body><main><p>rust async {word}{n} {word}x{n} {word}y{n}</p>{links}</main></body></html>"
            ))
        };
        let mut entries: BTreeMap<String, Reply> = BTreeMap::from([("/".to_owned(), page(0, true))]);
        for q in 1..=6 {
            entries.insert(format!("/q{q}"), page(q, false));
        }
        entries
    })
    .await
}

fn adaptive_crawl(base: &str, tune: impl FnOnce(&mut AdaptiveStopConfigV1)) -> CreateCrawl {
    let mut crawl = crawl_of(base, CrawlMode::Static);
    let mut policy = AdaptiveStopConfigV1::new("Rust async");
    tune(&mut policy);
    crawl.adaptive = Some(policy);
    crawl
}

#[tokio::test]
async fn saturation_stops_a_crawl_that_keeps_finding_the_same_words() {
    let site = chain_site().await;
    let done = run(
        adaptive_crawl(&site.base, |policy| policy.min_gain_permille = 200),
        None,
    )
    .await;
    let report = &done.report;
    assert_eq!(report.terminal_reason, Some(TerminalReason::PolicyStopped));
    assert_eq!(report.counters.urls.succeeded, 4, "{:?}", report.counters);
    assert_eq!(
        site.paths("GET"),
        ["/", "/p1", "/p2", "/p3"],
        "page four was never fetched"
    );

    let observed = events(&done, "adaptive.observed").await;
    let gains: Vec<u64> = observed
        .iter()
        .map(|e| e["gainPermille"].as_u64().unwrap())
        .collect();
    assert_eq!(gains.len(), 4);
    assert_eq!(gains[0], 1000, "the first relevant page is all news");
    assert!(
        gains[1..].iter().all(|gain| *gain > 0 && *gain < 200),
        "{gains:?}"
    );
    assert_eq!(observed[3]["stop"], "saturated");

    let stopped = events(&done, "adaptive.stopped").await;
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0]["reason"], "saturated");
    assert_eq!(stopped[0]["pages"], 4);
    assert_eq!(
        stopped[0]["exhaustive"], false,
        "a stop never claims exhaustive coverage"
    );
    assert!(stopped[0]["confidencePermille"].as_u64().unwrap() <= 950);
}

#[tokio::test]
async fn the_page_limit_stops_at_exactly_that_many_pages() {
    let site = star_site("alpha").await;
    let done = run(adaptive_crawl(&site.base, |policy| policy.max_pages = 3), None).await;
    assert_eq!(done.report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(
        done.report.counters.urls.succeeded, 3,
        "{:?}",
        done.report.counters
    );
    assert_eq!(
        site.paths("GET"),
        ["/", "/q1", "/q2"],
        "the lease never overshoots the limit"
    );
    let stopped = events(&done, "adaptive.stopped").await;
    assert_eq!(stopped[0]["reason"], "page_limit");
    assert_eq!(stopped[0]["pages"], 3);
}

#[tokio::test]
async fn exported_state_continues_a_later_run_of_the_same_query() {
    let first_site = star_site("alpha").await;
    let first = run(
        adaptive_crawl(&first_site.base, |policy| {
            policy.max_pages = 2;
            policy.min_pages = 1;
        }),
        None,
    )
    .await;
    assert_eq!(first.report.counters.urls.succeeded, 2);
    let exports = events(&first, "adaptive.export").await;
    let exported: crawlx_core::adaptive::AdaptiveStopExportV1 =
        serde_json::from_value(exports.last().unwrap().clone()).unwrap();
    assert_eq!(exported.version, 1);
    assert_eq!(exported.pages, 2);
    assert_eq!(
        exported.query_digest,
        crawlx_core::adaptive::query_digest("async RUST")
    );
    // the export is terms and counts, never page text or a URL
    let wire = serde_json::to_string(&exported).unwrap();
    assert!(!wire.contains(&first_site.base) && !wire.contains("server rendered"));

    let second_site = star_site("omega").await;
    let second = run(
        adaptive_crawl(&second_site.base, |policy| {
            policy.max_pages = 4;
            policy.import = Some(exported);
        }),
        None,
    )
    .await;
    assert_eq!(
        second.report.counters.urls.succeeded, 2,
        "two pages were already counted by the imported state: {:?}",
        second.report.counters
    );
    let observed = events(&second, "adaptive.observed").await;
    let pages: Vec<u64> = observed.iter().map(|e| e["pages"].as_u64().unwrap()).collect();
    assert_eq!(pages, [3, 4], "the count continues across runs");
    let stopped = events(&second, "adaptive.stopped").await;
    assert_eq!(
        (stopped[0]["reason"].as_str(), stopped[0]["pages"].as_u64()),
        (Some("page_limit"), Some(4))
    );
}

// ---- recorded seed sources -----------------------------------------------------------------

async fn seed_site() -> Site {
    site(|_| {
        let alive = |title: &str| html(format!("<html><head><title>{title}</title></head><body><main><p>{title} text</p></main></body></html>"));
        routes(vec![
            ("/", html("<html><head><title>seed</title></head><body><main><p>seed page</p></main></body></html>")),
            ("/robots.txt", text("User-agent: *\nDisallow: /private/\n")),
            ("/a", alive("a")),
            ("/b", alive("b")),
            ("/c", alive("c")),
            ("/post-1", alive("post one")),
            ("/post-2", alive("post two")),
            ("/home-link", alive("home link")),
            ("/private/x", alive("private x")),
        ])
    })
    .await
}

fn seed_fixtures(base: &str) -> Vec<SeedFixtureV1> {
    vec![
        SeedFixtureV1::new(
            SeedSourceKindV1::ArchiveIndex,
            format!(
                "com,x)/a 20240101000000 {base}/a text/html 200 AAA 10\n\
                 com,x)/b 20240101000000 {base}/b text/html 200 BBB 10\n\
                 com,x)/gone 20240101000000 {base}/gone text/html 200 CCC 10\n\
                 com,x)/private/x 20240101000000 {base}/private/x text/html 200 DDD 10\n\
                 com,x)/z 20240101000000 https://elsewhere.test/z text/html 200 EEE 10\n"
            ),
        ),
        SeedFixtureV1::new(
            SeedSourceKindV1::CertificateTransparency,
            r#"[{"name_value":"elsewhere.test\nother.test"}]"#,
        ),
        SeedFixtureV1::new(
            SeedSourceKindV1::Sitemap,
            format!("<urlset><url><loc>{base}/c</loc></url><url><loc>{base}/a</loc></url></urlset>"),
        ),
        SeedFixtureV1::new(
            SeedSourceKindV1::Robots,
            format!("Sitemap: {base}/sitemap.xml\nAllow: /post-1\nDisallow: /private/\n"),
        ),
        SeedFixtureV1::new(
            SeedSourceKindV1::Feed,
            format!(
                "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel><title>t</title>\
                 <item><title>two</title><link>{base}/post-2</link></item></channel></rss>"
            ),
        ),
        SeedFixtureV1::new(
            SeedSourceKindV1::Homepage,
            "<html><body><a href=\"/home-link\">h</a><a href=\"https://elsewhere.test/q\">q</a></body></html>",
        ),
    ]
}

fn seeded_crawl(base: &str, live_check: SeedLiveCheckV1) -> CreateCrawl {
    let mut crawl = crawl_of(base, CrawlMode::Static);
    let mut seeding = SeedSourcesV1::new(seed_fixtures(base));
    seeding.live_check = live_check;
    crawl.scope.seeding = Some(seeding);
    crawl
}

fn fetched_paths(report: &RunReport) -> BTreeSet<String> {
    report
        .pages
        .iter()
        .map(|page| path_of(page.url.url.as_str()))
        .collect()
}

#[tokio::test]
async fn seeding_from_recorded_sources_queues_only_live_in_scope_robots_allowed_urls() {
    let site = seed_site().await;
    let mut crawl = seeded_crawl(&site.base, SeedLiveCheckV1::Head);
    // the governor spaces every request to the origin, live checks included
    crawl.politeness.delay_ms = 150;
    let done = run(crawl, None).await;

    // 14 distinct candidates; the second sighting of `/a` was a duplicate
    let tally = &events(&done, "seed.sources").await[0];
    assert_eq!(tally["candidates"], 14, "{tally}");
    assert_eq!(tally["duplicateSightings"], 1);
    assert_eq!(tally["queued"], 6, "{tally}");
    assert_eq!(
        tally["liveDead"], 2,
        "the 404 listing and the missing sitemap answer"
    );
    assert_eq!(
        tally["liveRefused"], 6,
        "the disallowed paths and the hosts outside the scope never get a request: {tally}"
    );
    assert_eq!(tally["liveFailed"], 0);

    // exactly the live ones were crawled; nothing disallowed, dead or out of scope
    assert_eq!(
        fetched_paths(&done.report),
        ["/", "/a", "/b", "/c", "/home-link", "/post-1", "/post-2"]
            .map(str::to_owned)
            .into(),
        "{:?}",
        done.report.counters
    );
    let heads = site.paths("HEAD");
    assert_eq!(
        heads.iter().cloned().collect::<BTreeSet<_>>(),
        [
            "/a",
            "/b",
            "/c",
            "/gone",
            "/home-link",
            "/post-1",
            "/post-2",
            "/sitemap.xml"
        ]
        .map(str::to_owned)
        .into()
    );
    assert!(
        !site.hits().iter().any(|(_, path)| path.starts_with("/private/")),
        "robots held"
    );
    assert!(!site.paths("GET").contains(&"/gone".to_owned()));

    // every live check went through the governor: the origin saw them spaced by the delay
    let mut starts = site.instants("HEAD");
    starts.sort();
    assert_eq!(starts.len(), 8);
    for pair in starts.windows(2) {
        assert!(
            pair[1] - pair[0] >= std::time::Duration::from_millis(100),
            "{:?}",
            pair[1] - pair[0]
        );
    }
}

#[tokio::test]
async fn without_a_live_check_candidates_still_pass_scope_and_robots() {
    let site = seed_site().await;
    let done = run(seeded_crawl(&site.base, SeedLiveCheckV1::Off), None).await;
    assert!(site.paths("HEAD").is_empty(), "no live check was asked for");
    let tally = &events(&done, "seed.sources").await[0];
    // `/private/x` and `/private/` are robots-blocked rows, the other hosts policy-blocked
    assert_eq!(tally["robotsBlocked"], 2, "{tally}");
    assert_eq!(tally["policyBlocked"], 4, "{tally}");
    assert_eq!(tally["queued"], 8, "{tally}");
    let fetched = fetched_paths(&done.report);
    assert!(fetched.contains("/a") && fetched.contains("/post-2"));
    assert!(!fetched.iter().any(|path| path.starts_with("/private/")));
    // the dead URLs were fetched and recorded as failures
    assert!(
        done.report.counters.urls.failed >= 2,
        "{:?}",
        done.report.counters
    );
}

#[tokio::test]
async fn seeding_is_deterministic_and_a_source_cannot_widen_the_scope() {
    let site = seed_site().await;
    let order = |done: &Done| -> Vec<String> {
        done.report
            .pages
            .iter()
            .map(|page| path_of(page.url.url.as_str()))
            .collect()
    };
    let first = run(seeded_crawl(&site.base, SeedLiveCheckV1::Head), None).await;
    let again = run(seeded_crawl(&site.base, SeedLiveCheckV1::Head), None).await;
    assert_eq!(order(&first), order(&again));
    // a crawl that allows only `/a` still refuses every other candidate
    let mut narrow = seeded_crawl(&site.base, SeedLiveCheckV1::Head);
    narrow.scope.include_paths = vec!["^/a$".to_owned()];
    let done = run(narrow, None).await;
    assert_eq!(
        fetched_paths(&done.report)
            .into_iter()
            .filter(|path| path != "/")
            .collect::<Vec<_>>(),
        ["/a"]
    );
}

// ---- typed hops and queue cost -------------------------------------------------------------

async fn hop_site() -> Site {
    site(|_| {
        let page = |title: &str, body: &str| {
            html(format!(
                "<html><head><title>{title}</title></head><body><main><p>{title} page text</p>{body}</main></body></html>"
            ))
        };
        routes(vec![
            (
                "/",
                html(
                    "<html><head><title>seed</title><link rel=\"stylesheet\" href=\"/site.css\"></head><body><main>\
                     <p>seed page text</p>\
                     <a href=\"/next\">next</a> <a href=\"/calendar/2024/05\">calendar</a> <a href=\"/old\">old</a>\
                     <iframe src=\"/frame\"></iframe> <script src=\"/app.js\"></script>\
                     <a href=\"https://other.test/x\">out</a> <iframe src=\"https://other.test/embed\"></iframe>\
                     </main></body></html>",
                ),
            ),
            ("/site.css", text("body { margin: 0 }")),
            ("/app.js", text("console.log(1)")),
            ("/next", page("next", "<a href=\"/next/next/next/next\">loop</a>")),
            ("/next/next/next/next", page("loop", "")),
            ("/old", redirect("/new")),
            ("/new", page("new", "")),
            ("/frame", page("frame", "<iframe src=\"/frame2\"></iframe>")),
            ("/frame2", page("frame2", "<iframe src=\"/frame3\"></iframe>")),
            ("/frame3", page("frame3", "")),
            ("/calendar/2024/05", page("may", "<a href=\"/calendar/2024/06\">june</a>")),
            ("/calendar/2024/06", page("june", "<a href=\"/calendar/2024/07\">july</a>")),
            ("/calendar/2024/07", page("july", "<a href=\"/calendar/2024/08\">august</a>")),
            ("/calendar/2024/08", page("august", "<a href=\"/calendar/2024/09\">september</a>")),
            ("/calendar/2024/09", page("september", "<a href=\"/calendar/2024/10\">october</a>")),
        ])
    })
    .await
}

fn hop_crawl(base: &str) -> CreateCrawl {
    let mut crawl = crawl_of(base, CrawlMode::Static);
    crawl.scope.no_default_extension_filter = true;
    crawl.scope.hops = Some(HopPolicyV1::new(4, 2, 3).following(true, true));
    crawl.scope.queue_cost = Some(crawlx_core::priority::cost::QueueCostPolicyV1::default());
    crawl
}

struct RowFacts {
    status: FrontierStatus,
    denial: Option<String>,
    hop_path: String,
    priority: i32,
}

async fn rows(done: &Done, run: CrawlRunId) -> BTreeMap<String, RowFacts> {
    let mut facts = BTreeMap::new();
    let mut after = 0;
    loop {
        let page = done.stores.frontier.page(run, after, 100).await.unwrap();
        if page.is_empty() {
            break;
        }
        for entry in page {
            after = entry.id;
            let request = done.stores.frontier.get_request(run, entry.id).await.unwrap();
            facts.insert(
                entry.url.url.to_string(),
                RowFacts {
                    status: entry.status,
                    denial: entry.denial_reason.clone(),
                    hop_path: request.envelope.hop_path().as_str().to_owned(),
                    priority: request.envelope.priority,
                },
            );
        }
    }
    facts
}

#[tokio::test]
async fn hops_are_typed_limits_end_traps_and_nothing_leaves_the_scope() {
    let site = hop_site().await;
    let done = run(hop_crawl(&site.base), None).await;
    let facts = rows(&done, done.report.run_id).await;
    let at = |path: &str| &facts[&format!("{}{path}", site.base)];

    for (path, hops, kind) in [
        ("/", "", None),
        ("/next", "L", Some("link")),
        ("/calendar/2024/05", "L", Some("link")),
        ("/old", "L", Some("link")),
        ("/site.css", "P", Some("prerequisite")),
        ("/app.js", "P", Some("prerequisite")),
        ("/frame", "E", Some("embed")),
        ("/new", "LR", Some("redirect")),
        ("/frame2", "EE", Some("embed")),
        ("/calendar/2024/06", "LL", Some("link")),
        ("/calendar/2024/08", "LLLL", Some("link")),
    ] {
        let row = at(path);
        assert_eq!(row.hop_path, hops, "{path}");
        assert_eq!(row.status, FrontierStatus::Succeeded, "{path}");
        let page = done
            .report
            .pages
            .iter()
            .find(|page| page.url.url.path() == path)
            .unwrap_or_else(|| panic!("{path} was kept"));
        let recorded = &page.metadata["request"]["hop"];
        assert_eq!(recorded["path"], hops, "{path}");
        assert_eq!(recorded["kind"], serde_json::json!(kind), "{path}");
    }

    // limits: a fifth link hop, a third transitive hop, a repeating path segment
    for (path, code) in [
        ("/calendar/2024/09", "hop_limit"),
        ("/frame3", "transitive_hop_limit"),
        ("/next/next/next/next", "pathological_path"),
    ] {
        let row = at(path);
        assert_eq!(row.status, FrontierStatus::PolicyBlocked, "{path}");
        assert_eq!(row.denial.as_deref(), Some(code), "{path}");
        assert!(
            !site.paths("GET").contains(&path.to_owned()),
            "{path} was fetched"
        );
    }
    assert!(
        !site.paths("GET").iter().any(|path| path == "/calendar/2024/10"),
        "the trap ends at the hop limit"
    );

    // out-of-scope navigation and embeds are refused whatever their kind
    for target in ["https://other.test/x", "https://other.test/embed"] {
        let row = &facts[target];
        assert_eq!(row.status, FrontierStatus::PolicyBlocked, "{target}");
        assert!(
            !matches!(row.denial.as_deref(), Some("hop_limit" | "transitive_hop_limit")),
            "{target}"
        );
    }
}

#[tokio::test]
async fn queue_cost_orders_the_queue_cheapest_first_with_a_stable_trap_order() {
    let site = hop_site().await;
    let done = run(hop_crawl(&site.base), None).await;
    let facts = rows(&done, done.report.run_id).await;
    let at = |path: &str| &facts[&format!("{}{path}", site.base)];
    // priority is -cost: link 1, embed and prerequisite 0, a date-like token 4 (calendar, 2024, 05)
    assert_eq!(at("/site.css").priority, 0);
    assert_eq!(at("/frame").priority, 0);
    assert_eq!(at("/app.js").priority, 0);
    assert_eq!(at("/next").priority, -1);
    assert_eq!(at("/old").priority, -1);
    assert_eq!(at("/calendar/2024/05").priority, -(1 + 3 * 4));
    assert_eq!(at("/calendar/2024/06").priority, -(2 + 3 * 4));

    // the seed's children were all queued together; they are fetched in cost order, ties by id
    // (the redirecting fetch of `/old` also requests `/new` once on its own)
    let mut gets = site.paths("GET");
    gets.remove(gets.iter().position(|path| path == "/new").unwrap());
    assert_eq!(
        gets[..7],
        [
            "/",
            "/site.css",
            "/frame",
            "/app.js",
            "/next",
            "/old",
            "/calendar/2024/05"
        ],
        "{gets:?}"
    );
    // and the order replays: the same crawl against the same site fetches in the same order
    let again = run(hop_crawl(&site.base), None).await;
    let order_again: Vec<String> = again
        .report
        .pages
        .iter()
        .map(|p| p.url.url.path().to_owned())
        .collect();
    let order_first: Vec<String> = done
        .report
        .pages
        .iter()
        .map(|p| p.url.url.path().to_owned())
        .collect();
    assert_eq!(order_first, order_again);
}

/// Endpoint discovery finds the same iframes, scripts and stylesheets as the typed hops. A hop
/// policy that declines them must decline them there too: they are never fetched as links.
#[tokio::test]
async fn endpoint_discovery_never_follows_as_links_what_the_hop_policy_declines() {
    let site = hop_site().await;
    let mut crawl = hop_crawl(&site.base);
    crawl.scope.hops = Some(HopPolicyV1::new(4, 2, 3));
    let done = run(crawl, None).await;
    let facts = rows(&done, done.report.run_id).await;
    let at = |path: &str| &facts[&format!("{}{path}", site.base)];
    for (path, code) in [
        ("/frame", "embed_not_followed"),
        ("/app.js", "prerequisite_not_followed"),
        ("/site.css", "prerequisite_not_followed"),
    ] {
        let row = at(path);
        assert_eq!(row.status, FrontierStatus::PolicyBlocked, "{path}");
        assert_eq!(row.denial.as_deref(), Some(code), "{path}");
        assert!(
            !site.paths("GET").contains(&path.to_owned()),
            "{path} was fetched"
        );
    }
    // links are still followed, and only links
    assert_eq!(at("/next").status, FrontierStatus::Succeeded);
    assert_eq!(at("/next").hop_path, "L");

    // following embeds alone follows the iframe as an embed, and still declines the rest
    let mut crawl = hop_crawl(&site.base);
    crawl.scope.hops = Some(HopPolicyV1::new(4, 2, 3).following(true, false));
    let done = run(crawl, None).await;
    let facts = rows(&done, done.report.run_id).await;
    let at = |path: &str| &facts[&format!("{}{path}", site.base)];
    assert_eq!(
        (at("/frame").status, at("/frame").hop_path.as_str()),
        (FrontierStatus::Succeeded, "E")
    );
    assert_eq!(at("/app.js").denial.as_deref(), Some("prerequisite_not_followed"));
    assert_eq!(
        at("/site.css").denial.as_deref(),
        Some("prerequisite_not_followed")
    );
}

#[tokio::test]
async fn without_hop_or_cost_policies_nothing_is_recorded_or_reordered() {
    let site = hop_site().await;
    let mut crawl = crawl_of(&site.base, CrawlMode::Static);
    crawl.scope.no_default_extension_filter = true;
    let done = run(crawl, None).await;
    let facts = rows(&done, done.report.run_id).await;
    assert!(facts
        .values()
        .all(|row| row.hop_path.is_empty() && row.priority == 0));
    assert!(done
        .report
        .pages
        .iter()
        .all(|page| page.metadata["request"].get("hop").is_none()));
}
