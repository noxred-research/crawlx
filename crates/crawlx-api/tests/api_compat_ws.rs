#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The reference SDK's WebSocket watcher (`Watcher` of the JS SDK): a real TCP
//! listener serving the router, a `tokio-tungstenite` client that passes the API key as the
//! `Sec-WebSocket-Protocol` subprotocol the way `new WebSocket(url, apiKey)` does, and either a
//! REAL worker (`common/scrape_rig.rs`) or hand-written runs, pages and journal events so the
//! interleaving of frames and pages is exact.
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use common::{env_with, Env};
use crawlx_api::auth::{generate_compat_key, generate_key, key_record_for};
use crawlx_api::{ApiConfig, CompatConfig, Scope, Settings};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{CrawlRun, EventRepo, PageRecord, PageRepo, RunRepo};
use crawlx_core::scrape::{JobKind, ScrapeDocument, ScrapeJob, ScrapeOptions};
use crawlx_core::{Clock, CreateCrawl, SystemClock, TrustLane};
use crawlx_storage::testkit;
use futures::StreamExt;
use scrape_rig::{Rig, RigConfig};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const V2: &str = "/compat/v2";

/// Longest wait for one frame or one condition; every wait is bounded by it.
const WAIT: Duration = Duration::from_secs(30);

// ---- a real server and a real client ---------------------------------------------------------

/// The router on `127.0.0.1:<random port>`.
struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(app: axum::Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server { addr, task }
}

type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;
type Handshake = tungstenite::handshake::client::Response;

/// Open `path` the way the SDK does: the key (when any) as the subprotocol, or as a bearer
/// header (`bearer`).
async fn try_open(
    server: &Server,
    path: &str,
    subprotocol: Option<&str>,
    bearer: Option<&str>,
) -> Result<(Client, Handshake), tungstenite::Error> {
    let mut req = format!("ws://{}{path}", server.addr)
        .into_client_request()
        .unwrap();
    if let Some(key) = subprotocol {
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_str(key).unwrap());
    }
    if let Some(key) = bearer {
        req.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
        );
    }
    tokio::time::timeout(WAIT, tokio_tungstenite::connect_async(req))
        .await
        .expect("the handshake answers")
}

async fn open(server: &Server, path: &str, key: &str) -> (Client, Handshake) {
    try_open(server, path, Some(key), None).await.unwrap()
}

/// The status and the JSON body of a handshake the server refused (it never upgraded).
async fn refused(
    server: &Server,
    path: &str,
    subprotocol: Option<&str>,
    bearer: Option<&str>,
) -> (u16, Value) {
    match try_open(server, path, subprotocol, bearer).await {
        Err(tungstenite::Error::Http(resp)) => {
            let body = resp
                .body()
                .as_deref()
                .map_or(Value::Null, |b| serde_json::from_slice(b).unwrap_or(Value::Null));
            (resp.status().as_u16(), body)
        }
        Ok(_) => panic!("the handshake was accepted"),
        Err(e) => panic!("expected an HTTP refusal, got {e}"),
    }
}

/// What the server sent next.
#[derive(Debug)]
enum Seen {
    Text(Value),
    Ping,
    /// A close frame (its code) or the end of the stream (`None`).
    Closed(Option<u16>),
}

async fn recv(ws: &mut Client) -> Seen {
    loop {
        let next = tokio::time::timeout(WAIT, ws.next())
            .await
            .expect("a frame arrives in time");
        match next {
            Some(Ok(Message::Text(text))) => return Seen::Text(serde_json::from_str(text.as_str()).unwrap()),
            Some(Ok(Message::Ping(_))) => return Seen::Ping,
            Some(Ok(Message::Close(frame))) => return Seen::Closed(frame.map(|f| u16::from(f.code))),
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("socket error: {e}"),
            None => return Seen::Closed(None),
        }
    }
}

/// The next JSON frame; pings are skipped.
async fn frame(ws: &mut Client) -> Value {
    loop {
        match recv(ws).await {
            Seen::Text(v) => return v,
            Seen::Ping => {}
            Seen::Closed(c) => panic!("closed ({c:?}) while a frame was expected"),
        }
    }
}

/// Every JSON frame up to the close, and the close code.
async fn drain(ws: &mut Client) -> (Vec<Value>, Option<u16>) {
    let mut frames = Vec::new();
    loop {
        match recv(ws).await {
            Seen::Text(v) => frames.push(v),
            Seen::Ping => {}
            Seen::Closed(code) => return (frames, code),
        }
    }
}

fn kind_of(frame: &Value) -> &str {
    frame["type"].as_str().unwrap()
}

/// `metadata.sourceURL` of a document frame or a catchup document.
fn source(doc: &Value) -> &str {
    doc["metadata"]["sourceURL"].as_str().unwrap()
}

/// Every source of the documents a frame sequence delivered, with how often each came.
fn delivered(frames: &[Value]) -> BTreeMap<String, usize> {
    let mut seen = BTreeMap::new();
    for f in frames {
        let docs: Vec<&Value> = match kind_of(f) {
            "catchup" => f["data"]["data"].as_array().unwrap().iter().collect(),
            "document" => vec![&f["data"]],
            _ => vec![],
        };
        for d in docs {
            *seen.entry(source(d).to_owned()).or_insert(0) += 1;
        }
    }
    seen
}

/// Assert the sequence is `catchup, document*, done` and return the `done` data.
fn assert_sequence(frames: &[Value]) -> &Value {
    let kinds: Vec<&str> = frames.iter().map(kind_of).collect();
    assert_eq!(kinds.first(), Some(&"catchup"), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&"done"), "{kinds:?}");
    assert!(
        kinds[1..kinds.len() - 1].iter().all(|k| *k == "document"),
        "only documents between catchup and done: {kinds:?}"
    );
    &frames[frames.len() - 1]["data"]
}

// ---- hand-written runs -----------------------------------------------------------------------

/// An environment whose journal polls fast, with the facade's keys on.
fn fast_env(configure: impl FnOnce(&mut Settings)) -> Env {
    let mut settings = Settings {
        sse_poll_interval: Duration::from_millis(10),
        ..Settings::default()
    };
    configure(&mut settings);
    env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            compat: CompatConfig {
                prefixed_keys: true,
                ..CompatConfig::default()
            },
            ..ApiConfig::default()
        },
        settings,
        Arc::new(SystemClock),
    )
}

/// A running run of `kind` owned by `env`'s tenant.
async fn plant_run(env: &Env, kind: JobKind) -> CrawlRun {
    let mut crawl = CreateCrawl::new("https://stored.example.test/".parse().unwrap());
    crawl.mode = CrawlMode::Static;
    let mut job = ScrapeJob::new(kind, ScrapeOptions::default());
    if kind == JobKind::Batch {
        job.urls = vec![
            "https://stored.example.test/two".parse().unwrap(),
            "https://stored.example.test/three".parse().unwrap(),
        ];
    }
    crawl.scrape = Some(job);
    crawl.normalize().unwrap();
    let run = testkit::crawl_run(env.tenant, crawl);
    RunRepo::create(env.store.as_ref(), &run, None).await.unwrap();
    RunRepo::set_status(env.store.as_ref(), run.id, RunStatus::Running, None)
        .await
        .unwrap();
    RunRepo::get(env.store.as_ref(), run.id).await.unwrap()
}

fn page_url(n: i64) -> String {
    format!("https://stored.example.test/{n}")
}

/// Store page `n` of `run` and, when `announce`, its `page` journal event (what the worker does
/// right after it stores a page).
async fn plant_page(env: &Env, run: &CrawlRun, n: i64, announce: bool) {
    let url = page_url(n);
    let doc = ScrapeDocument::new(url.clone(), url.clone(), 200, Digest::of("t", b"x"));
    let page = PageRecord {
        run: run.id,
        frontier_id: n,
        url: testkit::canonical_url(&url),
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("c", n.to_string().as_bytes()),
        title: Some(format!("Page {n}")),
        markdown: None,
        html: None,
        metadata: json!({ "scrape": doc }),
        links: vec![],
        fetched_at: SystemClock.now(),
        lane: TrustLane::Diagnostic,
    };
    PageRepo::put(env.store.as_ref(), &page).await.unwrap();
    if announce {
        announce_page(env, run, n).await;
    }
}

async fn announce_page(env: &Env, run: &CrawlRun, n: i64) {
    EventRepo::append(
        env.store.as_ref(),
        run.id,
        "page",
        json!({ "pageId": n, "url": page_url(n), "status": 200, "title": format!("Page {n}") }),
    )
    .await
    .unwrap();
}

/// End `run` as the worker does: the counters, the terminal status and the `completed` event.
async fn finish_run(env: &Env, run: &CrawlRun, status: RunStatus, reason: TerminalReason, pages: u64) {
    let mut counters = PlaneCounters::default();
    counters.urls.admitted = pages;
    counters.urls.succeeded = pages;
    RunRepo::update_counters(env.store.as_ref(), run.id, counters)
        .await
        .unwrap();
    RunRepo::set_status(env.store.as_ref(), run.id, status, Some(reason))
        .await
        .unwrap();
    EventRepo::append(
        env.store.as_ref(),
        run.id,
        "completed",
        json!({ "status": status.as_str(), "terminalReason": reason.as_str() }),
    )
    .await
    .unwrap();
}

fn crawl_path(run: &CrawlRun) -> String {
    format!("{V2}/crawl/{}", run.id)
}

fn batch_path(run: &CrawlRun) -> String {
    format!("{V2}/batch/scrape/{}", run.id)
}

/// The totals of an HTTP status body, to compare with a `done` frame.
fn totals(v: &Value) -> Value {
    json!({
        "status": v["status"],
        "total": v["total"],
        "completed": v["completed"],
        "creditsUsed": v["creditsUsed"],
    })
}

fn done_totals(d: &Value) -> Value {
    json!({
        "status": d["status"],
        "total": d["total"],
        "completed": d["completed"],
        "creditsUsed": d["creditsUsed"],
    })
}

// ---- deterministic frame order ----------------------------------------------------------------

#[tokio::test]
async fn crawl_watcher_sends_catchup_then_each_new_page_once_then_done() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    plant_page(&env, &run, 1, true).await;

    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    let catchup = frame(&mut ws).await;
    assert_eq!(kind_of(&catchup), "catchup", "{catchup}");
    let c = &catchup["data"];
    assert_eq!(c["status"], "scraping");
    assert_eq!(c["next"], Value::Null);
    assert_eq!(c["expiresAt"], Value::Null, "a running crawl has no expiry yet");
    assert_eq!(c["creditsUsed"], 1);
    let docs = c["data"].as_array().unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(source(&docs[0]), page_url(1));

    // the page of the catchup is announced again (a retried worker), a failed page and an
    // unrelated event follow: none of them is a document
    announce_page(&env, &run, 1).await;
    EventRepo::append(
        env.store.as_ref(),
        run.id,
        "page.failed",
        json!({ "url": page_url(9), "reason": "timeout" }),
    )
    .await
    .unwrap();
    plant_page(&env, &run, 2, true).await;
    let two = frame(&mut ws).await;
    assert_eq!(kind_of(&two), "document", "{two}");
    assert_eq!(source(&two["data"]), page_url(2));
    assert!(two["data"]["metadata"]["creditsUsed"].is_number(), "{two}");

    // a page stored without its event still reaches the client before `done`
    plant_page(&env, &run, 3, false).await;
    finish_run(
        &env,
        &run,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        3,
    )
    .await;
    let three = frame(&mut ws).await;
    assert_eq!(kind_of(&three), "document", "{three}");
    assert_eq!(source(&three["data"]), page_url(3));
    let done = frame(&mut ws).await;
    assert_eq!(kind_of(&done), "done", "{done}");
    assert_eq!(done["data"]["status"], "completed");
    assert_eq!(done["data"]["data"], json!([]));
    assert_eq!(done["data"]["creditsUsed"], 3);

    let (rest, code) = drain(&mut ws).await;
    assert!(rest.is_empty(), "nothing follows done: {rest:?}");
    assert_eq!(code, Some(1000), "a normal close");

    let (s, _, status) = env.get(&crawl_path(&run)).await;
    assert_eq!(s, axum::http::StatusCode::OK, "{status}");
    assert_eq!(done_totals(&done["data"]), totals(&status), "{status}");
    assert_eq!(status["total"], 3);
    assert_eq!(status["data"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_finished_crawl_yields_catchup_and_done() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    plant_page(&env, &run, 1, true).await;
    plant_page(&env, &run, 2, true).await;
    finish_run(
        &env,
        &run,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        2,
    )
    .await;

    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    let (frames, code) = drain(&mut ws).await;
    assert_eq!(frames.len(), 2, "{frames:?}");
    assert_eq!(kind_of(&frames[0]), "catchup");
    assert_eq!(frames[0]["data"]["status"], "completed");
    assert!(frames[0]["data"]["expiresAt"].is_string(), "{}", frames[0]);
    assert_eq!(frames[0]["data"]["data"].as_array().unwrap().len(), 2);
    assert_eq!(kind_of(&frames[1]), "done");
    assert_eq!(frames[1]["data"]["status"], "completed");
    assert_eq!(frames[1]["data"]["total"], 2);
    assert_eq!(frames[1]["data"]["completed"], 2);
    assert_eq!(frames[1]["data"]["creditsUsed"], 2);
    assert_eq!(code, Some(1000));
    assert_eq!(
        delivered(&frames),
        BTreeMap::from([(page_url(1), 1), (page_url(2), 1)])
    );
    // the watcher books a finished run in the usage ledger like the status route does
    let booked = env
        .state
        .repos
        .intel
        .usage_by_ref(env.tenant, run.id.0)
        .await
        .unwrap();
    assert!(booked.is_some(), "the finished run is in the usage ledger");
}

#[tokio::test]
async fn a_failed_crawl_ends_with_done_failed() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(frame(&mut ws).await["data"]["status"], "scraping");
    finish_run(&env, &run, RunStatus::Failed, TerminalReason::FatalError, 0).await;
    let done = frame(&mut ws).await;
    assert_eq!(kind_of(&done), "done", "{done}");
    assert_eq!(done["data"]["status"], "failed");
    assert_eq!(drain(&mut ws).await.1, Some(1000));
}

#[tokio::test]
async fn a_cancelled_run_ends_with_done_cancelled() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    plant_page(&env, &run, 1, true).await;
    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(frame(&mut ws).await["data"]["status"], "scraping");
    let (s, _, v) = env.delete(&crawl_path(&run)).await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    assert_eq!(v["status"], "cancelled");
    let (frames, code) = drain(&mut ws).await;
    let last = frames.last().unwrap();
    assert_eq!(kind_of(last), "done", "{frames:?}");
    assert_eq!(last["data"]["status"], "cancelled");
    assert_eq!(code, Some(1000));
}

#[tokio::test]
async fn batch_watcher_follows_a_batch_scrape() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Batch).await;
    plant_page(&env, &run, 1, true).await;
    let (mut ws, _) = open(&server, &batch_path(&run), &env.key).await;
    let catchup = frame(&mut ws).await;
    assert_eq!(kind_of(&catchup), "catchup");
    assert_eq!(catchup["data"]["status"], "scraping");
    assert_eq!(catchup["data"]["total"], 3, "the primary URL and two more");
    assert_eq!(catchup["data"]["completed"], 1);
    assert!(catchup["data"]["expiresAt"].is_string(), "{catchup}");
    assert_eq!(catchup["data"]["data"].as_array().unwrap().len(), 1);
    plant_page(&env, &run, 2, true).await;
    plant_page(&env, &run, 3, true).await;
    finish_run(
        &env,
        &run,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        3,
    )
    .await;
    let (frames, code) = drain(&mut ws).await;
    let all: Vec<Value> = std::iter::once(catchup).chain(frames).collect();
    let done = assert_sequence(&all);
    assert_eq!(done["status"], "completed");
    assert_eq!(done["total"], 3);
    assert_eq!(done["completed"], 3);
    assert_eq!(done["creditsUsed"], 3);
    assert_eq!(code, Some(1000));
    assert_eq!(
        delivered(&all),
        BTreeMap::from([(page_url(1), 1), (page_url(2), 1), (page_url(3), 1)])
    );
    let (_, _, status) = env.get(&batch_path(&run)).await;
    assert_eq!(done_totals(done), totals(&status), "{status}");
}

#[tokio::test]
async fn the_ws_sibling_paths_behave_like_the_status_paths() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    for (kind, path) in [
        (JobKind::Crawl, format!("{V2}/crawl/{{id}}/ws")),
        (JobKind::Batch, format!("{V2}/batch/scrape/{{id}}/ws")),
    ] {
        let run = plant_run(&env, kind).await;
        plant_page(&env, &run, 1, true).await;
        finish_run(
            &env,
            &run,
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            1,
        )
        .await;
        let path = path.replace("{id}", &run.id.to_string());
        let (mut ws, _) = open(&server, &path, &env.key).await;
        let (frames, code) = drain(&mut ws).await;
        let done = assert_sequence(&frames);
        assert_eq!(done["status"], "completed", "{path}");
        assert_eq!(code, Some(1000), "{path}");
        assert_eq!(delivered(&frames), BTreeMap::from([(page_url(1), 1)]), "{path}");
        // without an upgrade the sibling answers the status JSON as well
        let (s, _, v) = env.get(&path).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{path}: {v}");
        assert_eq!(v["status"], "completed");
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_plain_get_still_answers_the_status_json() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    plant_page(&env, &run, 1, true).await;
    let batch = plant_run(&env, JobKind::Batch).await;
    plant_page(&env, &batch, 1, true).await;
    for (path, completed) in [(crawl_path(&run), 0), (batch_path(&batch), 1)] {
        let (s, _, v) = env.get(&path).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{path}: {v}");
        assert_eq!(v["success"], true);
        assert_eq!(v["status"], "scraping");
        assert_eq!(v["completed"], completed);
        assert_eq!(v["data"].as_array().unwrap().len(), 1);
        // and over a real connection without the upgrade headers
        let url = format!("http://{}{path}", server.addr);
        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(&env.key)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "scraping");
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_malformed_upgrade_is_a_400_and_never_a_status_body() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    // `Upgrade: websocket` without the `Sec-WebSocket-Key` of a handshake
    let resp = reqwest::Client::new()
        .get(format!("http://{}{}", server.addr, crawl_path(&run)))
        .bearer_auth(&env.key)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false, "{body}");
}

// ---- authentication and ownership --------------------------------------------------------------

#[tokio::test]
async fn the_key_in_the_subprotocol_authenticates_and_is_echoed() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    finish_run(
        &env,
        &run,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        0,
    )
    .await;

    // a `cx_live_` key
    let (mut ws, handshake) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(
        handshake
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some(env.key.as_str()),
        "the chosen subprotocol is the key"
    );
    assert_eq!(kind_of(&frame(&mut ws).await), "catchup");

    // an `fc-` key (the one the SDK holds)
    let fc = generate_compat_key();
    let rec = key_record_for(&fc, env.tenant, Scope::all_set(), true).unwrap();
    crawlx_api::ApiStore::key_insert(env.api.as_ref(), &rec, "acme")
        .await
        .unwrap();
    let (mut ws, handshake) = open(&server, &crawl_path(&run), &fc).await;
    assert_eq!(
        handshake
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok()),
        Some(fc.as_str())
    );
    assert_eq!(drain(&mut ws).await.0.len(), 2);

    // a bearer header still works and selects no subprotocol
    let (mut ws, handshake) = try_open(&server, &crawl_path(&run), None, Some(&env.key))
        .await
        .unwrap();
    assert!(handshake.headers().get("sec-websocket-protocol").is_none());
    assert_eq!(drain(&mut ws).await.0.len(), 2);
}

#[tokio::test]
async fn missing_or_bad_keys_are_refused_before_the_upgrade() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let path = crawl_path(&run);

    let (status, body) = refused(&server, &path, None, None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated")),
        "{body}"
    );
    // well-formed but unknown keys
    for key in [generate_key(), generate_compat_key()] {
        let (status, body) = refused(&server, &path, Some(&key), None).await;
        assert_eq!(status, 401, "{body}");
        assert_eq!(body["success"], false, "{body}");
    }
    // a token that is no key at all
    let (status, _) = refused(&server, &path, Some("graphql"), None).await;
    assert_eq!(status, 401);
    // a key with the wrong secret: the last character changed (to a different one, so the
    // forgery never equals the real key when that already ends in the replacement)
    let (head, last) = env.key.split_at(env.key.len() - 1);
    let forged = format!("{head}{}", if last == "x" { "y" } else { "x" });
    assert_ne!(forged, env.key);
    let (status, _) = refused(&server, &path, Some(&forged), None).await;
    assert_eq!(status, 401);
    // an `fc-` key is off unless `compat.prefixedKeys` is on
    let plain = env_with(
        ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        },
        Settings::default(),
        Arc::new(SystemClock),
    );
    let fc = generate_compat_key();
    let rec = key_record_for(&fc, plain.tenant, Scope::all_set(), true).unwrap();
    crawlx_api::ApiStore::key_insert(plain.api.as_ref(), &rec, "acme")
        .await
        .unwrap();
    let plain_server = serve(plain.app.clone()).await;
    let (status, _) = refused(&plain_server, &path, Some(&fc), None).await;
    assert_eq!(status, 401);
    // the subprotocol is a facade-only credential: a native route never accepts it
    let (status, _) = refused(
        &server,
        &format!("/v1/crawls/{}/events", run.id),
        Some(&env.key),
        None,
    )
    .await;
    assert_eq!(status, 401);
    // a key without `crawls:read` is a 403 JSON error
    let write_only = env.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (status, body) = refused(&server, &path, Some(&write_only), None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("scope_missing")),
        "{body}"
    );
}

#[tokio::test]
async fn other_tenants_runs_and_the_wrong_kind_are_404_before_the_upgrade() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let crawl = plant_run(&env, JobKind::Crawl).await;
    let batch = plant_run(&env, JobKind::Batch).await;

    let stranger = env.key_for("someone-else", &[Scope::CrawlsRead]).await;
    let unknown = format!("{V2}/crawl/{}", crawlx_core::CrawlRunId::new());
    for path in [
        crawl_path(&crawl),
        batch_path(&batch),
        format!("{}/ws", crawl_path(&crawl)),
        unknown.clone(),
    ] {
        let (status, body) = refused(&server, &path, Some(&stranger), None).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (404, Some("not_found")),
            "{path}: {body}"
        );
    }
    // the owner is refused the same way for the other kind and for an unknown run
    for path in [
        batch_path(&crawl),
        crawl_path(&batch),
        unknown,
        format!("{V2}/crawl/not-an-id"),
    ] {
        let (status, body) = refused(&server, &path, Some(&env.key), None).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (404, Some("not_found")),
            "{path}: {body}"
        );
    }
}

// ---- stream slots, keep-alive, shutdown --------------------------------------------------------

#[tokio::test]
async fn watchers_take_and_free_a_stream_slot() {
    let env = fast_env(|s| s.sse_max_per_run = 1);
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let path = crawl_path(&run);
    let (mut first, _) = open(&server, &path, &env.key).await;
    assert_eq!(kind_of(&frame(&mut first).await), "catchup");

    let (status, body) = refused(&server, &path, Some(&env.key), None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (429, Some("too_many_streams")),
        "{body}"
    );

    // the slot is free again once the client has gone
    first.close(None).await.ok();
    drop(first);
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match try_open(&server, &path, Some(&env.key), None).await {
            Ok((mut again, _)) => {
                assert_eq!(kind_of(&frame(&mut again).await), "catchup");
                break;
            }
            Err(tungstenite::Error::Http(r)) if r.status().as_u16() == 429 => {
                assert!(tokio::time::Instant::now() < deadline, "the slot was never freed");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
}

#[tokio::test]
async fn an_idle_watcher_is_pinged() {
    let env = fast_env(|s| s.sse_keepalive = Duration::from_millis(30));
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(kind_of(&frame(&mut ws).await), "catchup");
    assert!(
        matches!(recv(&mut ws).await, Seen::Ping),
        "a ping while nothing happens"
    );
}

#[tokio::test]
async fn shutdown_closes_the_watcher_going_away() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(kind_of(&frame(&mut ws).await), "catchup");
    env.state.shutdown.cancel();
    let (frames, code) = drain(&mut ws).await;
    assert!(frames.is_empty(), "{frames:?}");
    assert_eq!(code, Some(1001), "going away");
}

#[tokio::test]
async fn a_vanished_run_is_an_error_frame_and_a_close() {
    let env = fast_env(|_| {});
    let server = serve(env.app.clone()).await;
    let run = plant_run(&env, JobKind::Crawl).await;
    let (mut ws, _) = open(&server, &crawl_path(&run), &env.key).await;
    assert_eq!(kind_of(&frame(&mut ws).await), "catchup");
    // erase the run underneath the watcher
    env.state.repos.eraser.erase(run.id).await.unwrap();
    let (frames, code) = drain(&mut ws).await;
    assert_eq!(frames.len(), 1, "{frames:?}");
    assert_eq!(kind_of(&frames[0]), "error", "{frames:?}");
    assert!(
        frames[0]["error"].as_str().unwrap().contains("no longer exists"),
        "{frames:?}"
    );
    assert_eq!(code, Some(1011), "an internal-error close");
}

// ---- a REAL worker ------------------------------------------------------------------------------

/// Poll an HTTP status path until it reports `want`.
async fn wait_status(rig: &Rig, path: &str, want: &str) -> Value {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let (s, _, v) = rig.env.get(path).await;
        assert_eq!(s, axum::http::StatusCode::OK, "{v}");
        if v["status"] == want {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{path} never reached {want}: {v}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The `metadata.sourceURL` of every document of an HTTP status body.
fn status_sources(v: &Value) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for d in v["data"].as_array().unwrap() {
        *out.entry(source(d).to_owned()).or_insert(0) += 1;
    }
    out
}

#[tokio::test]
async fn a_watched_crawl_delivers_every_page_once_and_totals_match_the_status() {
    let rig = Rig::start(RigConfig::default()).await;
    let server = serve(rig.env.app.clone()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({
                "url": rig.url("/"),
                "limit": 3,
                "includePaths": ["^/$", "^/a$", "^/b$"],
                "scrapeOptions": { "formats": ["markdown", "links"] },
            }),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let (mut ws, _) = open(&server, &format!("{V2}/crawl/{id}"), &rig.env.key).await;
    let (frames, code) = drain(&mut ws).await;
    assert_eq!(code, Some(1000));
    let done = assert_sequence(&frames);
    assert_eq!(done["status"], "completed", "{frames:?}");

    let status = wait_status(&rig, &format!("{V2}/crawl/{id}"), "completed").await;
    assert_eq!(done_totals(done), totals(&status), "{status}");
    let seen = delivered(&frames);
    assert!(seen.len() >= 2, "{seen:?}");
    assert!(
        seen.values().all(|n| *n == 1),
        "every page exactly once: {seen:?}"
    );
    assert_eq!(
        seen,
        status_sources(&status),
        "the watcher saw the pages the status lists"
    );
    assert_eq!(seen.len() as u64, status["completed"].as_u64().unwrap());
    // the documents are the compat documents of the status route
    let first_doc = frames
        .iter()
        .flat_map(|f| match kind_of(f) {
            "catchup" => f["data"]["data"].as_array().unwrap().clone(),
            "document" => vec![f["data"].clone()],
            _ => vec![],
        })
        .next()
        .unwrap();
    assert!(
        first_doc["markdown"].is_string() && first_doc["links"].is_array(),
        "{first_doc}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn watching_after_completion_yields_catchup_and_done() {
    let rig = Rig::start(RigConfig::default()).await;
    let server = serve(rig.env.app.clone()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({ "url": rig.url("/a"), "limit": 1, "maxDiscoveryDepth": 0 }),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let status = wait_status(&rig, &format!("{V2}/crawl/{id}"), "completed").await;
    assert_eq!(status["data"].as_array().unwrap().len(), 1, "{status}");

    let (mut ws, _) = open(&server, &format!("{V2}/crawl/{id}"), &rig.env.key).await;
    let (frames, code) = drain(&mut ws).await;
    assert_eq!(
        frames.iter().map(kind_of).collect::<Vec<_>>(),
        ["catchup", "done"]
    );
    assert_eq!(frames[0]["data"]["status"], "completed");
    assert_eq!(code, Some(1000));
    assert_eq!(delivered(&frames), status_sources(&status));
    assert_eq!(done_totals(&frames[1]["data"]), totals(&status));
    rig.stop().await;
}

#[tokio::test]
async fn a_watched_batch_delivers_every_page_once() {
    let rig = Rig::start(RigConfig::default()).await;
    let server = serve(rig.env.app.clone()).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/batch/scrape"),
            &json!({ "urls": [rig.url("/a"), rig.url("/b"), rig.url("/c")], "formats": ["markdown"] }),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let (mut ws, _) = open(&server, &format!("{V2}/batch/scrape/{id}"), &rig.env.key).await;
    let (frames, code) = drain(&mut ws).await;
    assert_eq!(code, Some(1000));
    let done = assert_sequence(&frames);
    assert_eq!(done["status"], "completed", "{frames:?}");
    assert_eq!(
        (
            done["total"].clone(),
            done["completed"].clone(),
            done["creditsUsed"].clone()
        ),
        (json!(3), json!(3), json!(3))
    );
    assert_eq!(
        delivered(&frames),
        BTreeMap::from([(rig.url("/a"), 1), (rig.url("/b"), 1), (rig.url("/c"), 1)])
    );
    let status = wait_status(&rig, &format!("{V2}/batch/scrape/{id}"), "completed").await;
    assert_eq!(done_totals(done), totals(&status), "{status}");
    rig.stop().await;
}

#[tokio::test]
async fn deleting_a_running_crawl_ends_the_watch_with_done_cancelled() {
    let rig = Rig::start(RigConfig::default()).await;
    let server = serve(rig.env.app.clone()).await;
    // `/slow` answers after a minute: the crawl is still running when it is cancelled
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({ "url": rig.url("/slow"), "limit": 1 }),
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let path = format!("{V2}/crawl/{id}");
    let (mut ws, _) = open(&server, &path, &rig.env.key).await;
    let catchup = frame(&mut ws).await;
    assert_eq!(kind_of(&catchup), "catchup", "{catchup}");
    assert_eq!(catchup["data"]["status"], "scraping");
    let (s, _, v) = rig.env.delete(&path).await;
    assert_eq!(s, axum::http::StatusCode::OK, "{v}");
    let (frames, code) = drain(&mut ws).await;
    let last = frames.last().unwrap();
    assert_eq!(kind_of(last), "done", "{frames:?}");
    assert_eq!(last["data"]["status"], "cancelled");
    assert_eq!(code, Some(1000));
    rig.stop().await;
}
