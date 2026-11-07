//! The CrawlerGym HTTP server.
//!
//! One Axum app serves every fixture under `/<fixture-id>/`, the ledger at
//! `/__gym/ledger` (alias `/ledger`), `/__gym/reset` (alias `/reset`), the client beacons
//! (`/__gym/click`, `/__gym/probe`), `/robots.txt`, the stateful fixture backends
//! ([`fixtures::backend`]) under `/<fixture-id>/api/` and a WebSocket at `/<fixture-id>/ws`.

use crate::error::BenchError;
use crate::gym::fixtures::backend::{self, Backend, BackendSnapshot};
use crate::gym::fixtures::{self, crawl_maze, d2, s1, FileDef};
use crate::gym::ledger::Ledger;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use crawlx_core::hash::Digest;
use crawlx_core::time::Clock;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Ledger fixture label for requests that belong to no fixture (`robots.txt`).
pub const GYM_LABEL: &str = "_gym";

/// Mutable server state: the ledger, the seed all pages derive their content from, the
/// stateful fixture backends and which fixture owns the origin-level files.
#[derive(Debug)]
pub struct GymState {
    ledger: Arc<Ledger>,
    seed: AtomicU64,
    backend: Backend,
    checkpoints: parking_lot::Mutex<BTreeMap<String, (u64, BackendSnapshot)>>,
    file_override: Option<(&'static str, FileDef)>,
    /// Fixture whose `robots.txt` the origin serves (`s1` by default, `g32` for crawl-maze
    /// known-files runs, `d2` for the differential site's per-host rules); one origin can
    /// only have one robots file.
    origin_owner: parking_lot::Mutex<String>,
}

impl GymState {
    fn snapshot(&self) -> serde_json::Value {
        let seed = self.seed.load(Ordering::SeqCst);
        let digest = Digest::of("crawlx/bench/gym-snapshot/v1", &seed.to_le_bytes());
        json!({ "seed": seed, "digest": digest.to_hex() })
    }
}

/// Entry point: [`GymServer::start`].
#[derive(Debug)]
pub struct GymServer;

/// A running gym. Dropping it aborts the server task; prefer [`GymHandle::shutdown`].
#[derive(Debug)]
pub struct GymHandle {
    /// `http://127.0.0.1:PORT`
    pub base_url: String,
    /// TCP port the server is actually listening on (the resolved port when bound with port 0).
    pub port: u16,
    state: Arc<GymState>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
    evaluation: Option<crawlx_worker::fixture_evaluation::FixtureEvaluationHost>,
}

impl GymServer {
    /// Bind `bind` (port 0 picks a free one) and serve until [`GymHandle::shutdown`].
    ///
    /// # Errors
    /// [`BenchError::Bind`] when binding fails.
    pub async fn start(bind: SocketAddr) -> Result<GymHandle, BenchError> {
        Self::start_with_ledger(bind, Arc::new(Ledger::default()), None).await
    }

    /// Serve one historical authored file in place of an existing embedded fixture file.
    ///
    /// The override is immutable for this listener. Only a matching fixture id and resolved
    /// file name are replaced; manifests, other files, routes and backend behavior stay current.
    /// Ordinary and evaluation listeners continue to serve the embedded catalog unchanged.
    ///
    /// # Errors
    /// [`BenchError::Bind`] when binding fails.
    pub async fn start_with_fixture_file(
        bind: SocketAddr,
        fixture: &'static str,
        file: FileDef,
    ) -> Result<GymHandle, BenchError> {
        Self::start_with_ledger(bind, Arc::new(Ledger::default()), Some((fixture, file))).await
    }

    /// Start an owned loopback fixture listener capable of issuing bounded Advisory evaluation permits.
    /// Unlike the public display URL, its retained listener identity cannot be changed by callers.
    ///
    /// # Errors
    /// Fails if the real listener cannot be bound, cloned or registered with Tokio.
    pub async fn start_evaluation() -> Result<GymHandle, BenchError> {
        let owner = crawlx_worker::fixture_evaluation::FixtureEvaluationHost::bind()?;
        let listener = owner.listener()?;
        let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|source| BenchError::Bind { addr, source })?;
        Self::serve(listener, Arc::new(Ledger::default()), Some(owner), None)
    }

    /// As [`Self::start`] with ledger timestamps from `clock` (deterministic tests).
    ///
    /// # Errors
    /// [`BenchError::Bind`] when binding fails.
    pub async fn start_with_clock(bind: SocketAddr, clock: Arc<dyn Clock>) -> Result<GymHandle, BenchError> {
        Self::start_with_ledger(bind, Arc::new(Ledger::new(clock)), None).await
    }

    async fn start_with_ledger(
        bind: SocketAddr,
        ledger: Arc<Ledger>,
        file_override: Option<(&'static str, FileDef)>,
    ) -> Result<GymHandle, BenchError> {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|source| BenchError::Bind { addr: bind, source })?;
        Self::serve(listener, ledger, None, file_override)
    }

    fn serve(
        listener: tokio::net::TcpListener,
        ledger: Arc<Ledger>,
        evaluation: Option<crawlx_worker::fixture_evaluation::FixtureEvaluationHost>,
        file_override: Option<(&'static str, FileDef)>,
    ) -> Result<GymHandle, BenchError> {
        let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
        let state = Arc::new(GymState {
            ledger,
            seed: AtomicU64::new(0),
            backend: Backend::default(),
            checkpoints: parking_lot::Mutex::new(BTreeMap::new()),
            file_override,
            origin_owner: parking_lot::Mutex::new(s1::ID.to_owned()),
        });
        let app = router(Arc::clone(&state));
        let stop = CancellationToken::new();
        let evaluation_scope = evaluation.as_ref().map(|owner| owner.scope());
        let task = tokio::spawn({
            let stop = stop.clone();
            async move {
                let served = axum::serve(listener, app)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await;
                if let Err(error) = served {
                    tracing::error!(%error, %addr, "gym server stopped with an error");
                }
                if let Some(scope) = evaluation_scope {
                    scope.revoke();
                }
            }
        });
        Ok(GymHandle {
            base_url: format!("http://{}:{}", addr.ip(), addr.port()),
            port: addr.port(),
            state,
            stop,
            task: Some(task),
            evaluation,
        })
    }
}

impl GymHandle {
    /// Immutable actual origin of an evaluation server, not the mutable display URL.
    #[must_use]
    pub fn evaluation_origin(&self) -> Option<&url::Url> {
        self.evaluation.as_ref().map(|owner| owner.origin())
    }

    /// Narrow egress to this retained evaluation listener, never the mutable display URL or port.
    ///
    /// Returns `None` for ordinary servers or a revoked listener. Keep this handle alive while
    /// using the scope; dropping or shutting down the server revokes every issued clone.
    #[must_use]
    pub fn evaluation_scope(&self) -> Option<crawlx_policy::fixture_evaluation::FixtureEvaluationScope> {
        self.evaluation
            .as_ref()
            .map(|owner| owner.scope())
            .filter(crawlx_policy::fixture_evaluation::FixtureEvaluationScope::is_live)
    }

    /// Bind one normalized experiment to this live fixture listener and authorization.
    ///
    /// # Errors
    /// Refuses ordinary servers, stopped servers, widened requests, Active and excessive budgets.
    pub fn evaluation_permit(
        &self,
        fixture: &super::manifest::FixtureManifest,
        crawl: &crawlx_core::CreateCrawl,
        record: &crawlx_policy::AuthorizationRecord,
    ) -> Result<crawlx_worker::fixture_evaluation::FixtureEvaluationPermit, BenchError> {
        let owner = self
            .evaluation
            .as_ref()
            .ok_or_else(|| BenchError::Gate("server has no controlled evaluation listener".to_owned()))?;
        Ok(owner.permit(&fixture.id, crawl, record)?)
    }

    /// The server-side ledger (ground truth).
    #[must_use]
    pub fn ledger(&self) -> Arc<Ledger> {
        Arc::clone(&self.state.ledger)
    }

    /// Server-side count of the `counter` fixture (`POST /counter/api/increment` applied);
    /// also the `counter` field of `/__gym/ledger`.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.state.backend.counter()
    }

    /// The seed pages are currently rendered with.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.state.seed.load(Ordering::SeqCst)
    }

    /// Absolute URL of fixture `id`'s entry page.
    #[must_use]
    pub fn fixture_url(&self, id: &str) -> String {
        format!("{}/{id}/", self.base_url)
    }

    /// Restore the baseline: clear the ledger, reset the fixture backends and reseed all page
    /// content (`/__gym/reset?seed=N`).
    pub fn reset(&self, seed: u64) {
        self.state.seed.store(seed, Ordering::SeqCst);
        self.state.ledger.clear();
        self.state.backend.reset();
    }

    /// Restore a checkpoint captured by `/__gym/snapshot?checkpoint=NAME`.
    ///
    /// Each capture returns a unique `x-gym-checkpoint` response header. Restoration
    /// changes only fixture state and seed; the evidence ledger is never rewound.
    /// Returns `false` when `checkpoint` was not captured by this server.
    #[must_use]
    pub fn restore_checkpoint(&self, checkpoint: &str) -> bool {
        let checkpoints = self.state.checkpoints.lock();
        let Some((seed, backend)) = checkpoints.get(checkpoint) else {
            return false;
        };
        self.state.seed.store(*seed, Ordering::SeqCst);
        self.state.backend.restore(backend);
        true
    }

    /// Make fixture `id` own the origin-level files: `/robots.txt` is rendered by that
    /// fixture (`s1` by default; `g32` adds the crawl-maze `Allow:` path and sitemap, `d2`
    /// answers per request `Host`).
    pub fn claim_origin(&self, id: &str) {
        *self.state.origin_owner.lock() = id.to_owned();
    }

    /// Stop serving and wait for the task.
    pub async fn shutdown(mut self) {
        if let Some(owner) = &self.evaluation {
            owner.scope().revoke();
        }
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for GymHandle {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(owner) = &self.evaluation {
            owner.scope().revoke();
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The gym router (exposed so tests can mount it on their own listener).
pub fn router(state: Arc<GymState>) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/robots.txt", get(robots))
        .route("/__gym/ledger", get(ledger_json))
        .route("/ledger", get(ledger_json))
        .route("/__gym/reset", post(reset).get(reset))
        .route("/reset", post(reset).get(reset))
        .route("/__gym/snapshot", get(snapshot).post(snapshot))
        .route("/__gym/restore", post(restore))
        .route("/__gym/click", post(click))
        .route("/__gym/probe", post(probe))
        .route("/{fixture}/ws", get(ws_upgrade))
        .fallback(any(fixture))
        .with_state(state)
}

fn no_store(status: StatusCode, content_type: &'static str, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST).and_then(|v| v.to_str().ok())
}

fn host_of(headers: &HeaderMap) -> String {
    host_header(headers).unwrap_or("127.0.0.1").to_owned()
}

/// Append `headers` to `resp`, skipping names or values that are not valid HTTP.
fn with_headers<N: AsRef<str>, V: AsRef<str>>(mut resp: Response, headers: &[(N, V)]) -> Response {
    for (name, value) in headers {
        if let (Ok(n), Ok(v)) = (
            header::HeaderName::from_bytes(name.as_ref().as_bytes()),
            header::HeaderValue::from_str(value.as_ref()),
        ) {
            resp.headers_mut().append(n, v);
        }
    }
    resp
}

async fn root(State(state): State<Arc<GymState>>) -> Json<serde_json::Value> {
    let fixtures: Vec<_> = fixtures::all()
        .iter()
        .map(|d| json!({ "id": d.id, "path": format!("/{}/", d.id) }))
        .collect();
    Json(json!({ "gym": "crawlx-bench", "seed": state.seed.load(Ordering::SeqCst), "fixtures": fixtures }))
}

async fn robots(State(state): State<Arc<GymState>>, headers: HeaderMap) -> Response {
    state
        .ledger
        .op_at_host(GYM_LABEL, "GET", "/robots.txt", None, host_header(&headers));
    let host = host_of(&headers);
    let (status, body) = match state.origin_owner.lock().as_str() {
        crawl_maze::ID => (200, crawl_maze::robots_txt(&host)),
        d2::ID => d2::robots(&host),
        _ => (200, s1::robots_txt(&host)),
    };
    no_store(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        "text/plain; charset=utf-8",
        body,
    )
}

/// `/__gym/ledger`: the ledger rows plus the `counter` fixture's server-side count, so a
/// harness outside the process (the CLI chaos suite) can check `repeated_non_idempotent_actions`.
async fn ledger_json(State(state): State<Arc<GymState>>) -> Json<serde_json::Value> {
    let mut doc = state.ledger.to_json();
    if let serde_json::Value::Object(map) = &mut doc {
        map.insert("counter".to_owned(), json!(state.backend.counter()));
    }
    Json(doc)
}

async fn reset(
    State(state): State<Arc<GymState>>,
    Query(q): Query<BTreeMap<String, String>>,
) -> Json<serde_json::Value> {
    if let Some(seed) = q.get("seed").and_then(|s| s.parse::<u64>().ok()) {
        state.seed.store(seed, Ordering::SeqCst);
    }
    state.ledger.clear();
    state.backend.reset();
    let mut snap = state.snapshot();
    if let Some(name) = q.get("snapshot") {
        snap["snapshot"] = json!(name);
    }
    Json(snap)
}

async fn snapshot(
    State(state): State<Arc<GymState>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let checkpoint = query.get("checkpoint").map(|name| {
        let mut checkpoints = state.checkpoints.lock();
        let id = format!("{name}-{}", checkpoints.len());
        checkpoints.insert(
            id.clone(),
            (state.seed.load(Ordering::SeqCst), state.backend.snapshot()),
        );
        id
    });
    if let Some(id) = checkpoint {
        return ([("x-gym-checkpoint", id)], Json(state.snapshot())).into_response();
    }
    Json(state.snapshot()).into_response()
}

async fn restore(State(state): State<Arc<GymState>>, Json(body): Json<serde_json::Value>) -> Response {
    let Some(seed) = body.get("seed").and_then(serde_json::Value::as_u64) else {
        return no_store(
            StatusCode::BAD_REQUEST,
            "application/json",
            r#"{"error":"missing seed"}"#.to_owned(),
        );
    };
    state.seed.store(seed, Ordering::SeqCst);
    state.ledger.clear();
    state.backend.reset();
    Json(state.snapshot()).into_response()
}

async fn click(State(state): State<Arc<GymState>>, Query(q): Query<BTreeMap<String, String>>) -> StatusCode {
    let (Some(fixture), Some(control)) = (q.get("fixture"), q.get("control")) else {
        return StatusCode::BAD_REQUEST;
    };
    let trusted = q.get("trusted").is_some_and(|v| v == "1" || v == "true");
    state.ledger.click(fixture, control, trusted);
    StatusCode::NO_CONTENT
}

async fn probe(State(state): State<Arc<GymState>>, Query(q): Query<BTreeMap<String, String>>) -> StatusCode {
    let (Some(fixture), Some(name)) = (q.get("fixture"), q.get("name")) else {
        return StatusCode::BAD_REQUEST;
    };
    state
        .ledger
        .probe(fixture, name, q.get("value").map_or("", String::as_str));
    StatusCode::NO_CONTENT
}

fn parse_fields(headers: &HeaderMap, body: &[u8]) -> BTreeMap<String, String> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("json"));
    if is_json {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(body) {
            return map
                .into_iter()
                .map(|(k, v)| {
                    let s = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    (k, s)
                })
                .collect();
        }
        return BTreeMap::new();
    }
    url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Everything under `/<fixture>/`.
async fn fixture(
    State(state): State<Arc<GymState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    let trimmed = path.trim_start_matches('/');
    let (id, rest) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    let known = fixtures::find(id);
    let label = if known.is_some() { id } else { GYM_LABEL };
    state
        .ledger
        .op_at_host(label, method.as_str(), path, uri.query(), host_header(&headers));

    let Some(def) = known else {
        return no_store(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "no such fixture\n".to_owned(),
        );
    };

    if let Some(api) = rest.strip_prefix("api/") {
        let fields = parse_fields(&headers, &body);
        let query: BTreeMap<String, String> = uri.query().map_or_else(BTreeMap::new, |q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        });
        let cookies = backend::parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
        let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
        let req = backend::Request {
            fixture: id,
            method: method.as_str(),
            route: api.trim_end_matches('/'),
            query: &query,
            fields: &fields,
            cookies: &cookies,
            body: &body,
            content_type,
        };
        if let Some(reply) = state.backend.handle(&state.ledger, &req) {
            if reply.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(reply.delay_ms)).await;
            }
            let mut resp = no_store(
                StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                "application/json",
                reply.body.to_string(),
            );
            for c in &reply.set_cookies {
                if let Ok(v) = header::HeaderValue::from_str(c) {
                    resp.headers_mut().append(header::SET_COOKIE, v);
                }
            }
            return resp;
        }
        if let Some(form) = api.strip_prefix("form/") {
            state.ledger.form_submit(id, form.trim_end_matches('/'), fields);
        }
        let reply = json!({ "ok": true, "method": method.as_str(), "path": path });
        return no_store(StatusCode::OK, "application/json", reply.to_string());
    }

    if id == "g29" && rest == "redirect" {
        let target = uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "to")
                .map(|(_, v)| v.into_owned())
        });
        return match target {
            Some(t) if t.starts_with("http://") || t.starts_with("https://") => {
                (StatusCode::FOUND, [(header::LOCATION, t)]).into_response()
            }
            _ => no_store(
                StatusCode::BAD_REQUEST,
                "text/plain; charset=utf-8",
                "missing or bad `to`\n".to_owned(),
            ),
        };
    }

    if id == "s1" {
        return match s1::serve(rest, &host_of(&headers)) {
            Some(r) => no_store(
                StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                r.content_type,
                r.body,
            ),
            None => no_store(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "not found\n".to_owned(),
            ),
        };
    }

    if id == d2::ID {
        return match d2::serve(rest, &host_of(&headers)) {
            Some(r) => {
                if r.delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(r.delay_ms)).await;
                }
                let resp = no_store(
                    StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    r.content_type,
                    r.body,
                );
                with_headers(resp, &r.headers)
            }
            None => no_store(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "not found\n".to_owned(),
            ),
        };
    }

    if id == crawl_maze::ID {
        if let Some(r) = crawl_maze::serve(rest, &host_of(&headers)) {
            let resp = no_store(
                StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                r.content_type,
                r.body,
            );
            return with_headers(resp, &r.headers);
        }
    }

    match def.file(rest) {
        Some(file) => {
            let file = state
                .file_override
                .as_ref()
                .filter(|(fixture, replacement)| *fixture == id && replacement.name == file.name)
                .map_or(file, |(_, replacement)| replacement);
            let base = format!("http://{}", host_of(&headers));
            let rendered = fixtures::render(file.body, id, state.seed.load(Ordering::SeqCst), &base);
            no_store(StatusCode::OK, file.content_type, rendered)
        }
        None => no_store(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".to_owned(),
        ),
    }
}

/// `/<fixture>/ws`: unsolicited pushes on the fixture's schedule plus request/reply.
async fn ws_upgrade(
    State(state): State<Arc<GymState>>,
    AxumPath(fixture): AxumPath<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let label = if fixtures::find(&fixture).is_some() {
        fixture.clone()
    } else {
        GYM_LABEL.to_owned()
    };
    state.ledger.op(&label, "WS", &format!("/{fixture}/ws"), None);
    ws.on_upgrade(move |socket| ws_session(state, fixture, socket))
}

async fn ws_session(state: Arc<GymState>, fixture: String, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let path = format!("/{fixture}/ws");
    let pushes = backend::ws_pushes(&fixture);
    let mut next_push = 0usize;
    let started = tokio::time::Instant::now();
    loop {
        let push_at = pushes
            .get(next_push)
            .map(|(delay, _)| started + std::time::Duration::from_millis(*delay));
        tokio::select! {
            () = async {
                match push_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let (_, name) = pushes[next_push];
                next_push += 1;
                state.ledger.op(&fixture, "WS-PUSH", &path, Some(&format!("push={name}")));
                let msg = json!({ "push": name, "n": next_push }).to_string();
                if sink.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            incoming = stream.next() => {
                let Some(Ok(msg)) = incoming else { break };
                let Message::Text(text) = msg else {
                    if matches!(msg, Message::Close(_)) { break; }
                    continue;
                };
                let req = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("req").and_then(serde_json::Value::as_str).map(str::to_owned))
                    .unwrap_or_default();
                state.ledger.op(&fixture, "WS", &path, Some(&format!("req={req}")));
                if let Some(reply) = backend::ws_reply(&fixture, &req) {
                    if sink.send(Message::Text(reply.to_string().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

impl GymState {
    /// Fresh state for tests that mount [`router`] themselves.
    #[must_use]
    pub fn new(ledger: Arc<Ledger>) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            seed: AtomicU64::new(0),
            backend: Backend::default(),
            checkpoints: parking_lot::Mutex::new(BTreeMap::new()),
            file_override: None,
            origin_owner: parking_lot::Mutex::new(s1::ID.to_owned()),
        })
    }
}
