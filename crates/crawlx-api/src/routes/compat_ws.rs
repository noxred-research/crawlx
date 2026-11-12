//! The reference SDK's WebSocket watcher (`Watcher` of the JS SDK `v2/watcher.ts`):
//! `GET /compat/v2/crawl/{id}` and `GET /compat/v2/batch/scrape/{id}` with
//! `Upgrade: websocket` stream the job instead of returning its status (a plain `GET` still
//! answers the status JSON). `.../crawl/{id}/ws` and `.../batch/scrape/{id}/ws` are siblings with
//! the same behaviour.
//!
//! The SDK opens `new WebSocket(url, apiKey)`, so the key arrives as the `Sec-WebSocket-Protocol`
//! subprotocol ([`crate::auth::auth_layer`] accepts it there) and the handshake echoes it back.
//!
//! Frames are JSON text messages: one `catchup` with the status body and every document stored so
//! far, one `document` per page stored after that snapshot (each page exactly once), then a `done`
//! with the terminal status and totals before a normal close. A failure is an `error` frame and a
//! close. The documents come from the run's event journal (`page` events of `crawl_events`, the
//! feed behind SSE and webhooks), polled the way [`crate::routes::events`] does.
//!
//! Contract. A watcher speaks exactly these frames: `catchup`, `document`, `done` (status
//! `completed`, `failed` or `cancelled`, so the run's `started`, `completed` and `failed`
//! journal events show up as the stored pages and the final status) and `error`. A page that
//! failed (including one whose content failed validation) and a page a cooldown of its origin
//! defers have no frame: the first is listed by the crawl's `errors` route, the second only
//! arrives later as a `document`. A client that does not accept a frame (or a keep-alive ping)
//! within `Settings::ws_send_timeout` is closed with code 1008 and frees its stream slot; the
//! run is unaffected and a reconnect starts with a fresh `catchup`.

use crate::auth::{is_websocket_upgrade, websocket_key, Principal};
use crate::errors::{ApiResult, HttpError};
use crate::openapi::Operation;
use crate::resources::expires_at;
use crate::routes::compat::{crawl_pages, crawl_total, facade_status, load_crawl};
use crate::routes::compat_scrape::{
    batch_expires, batch_status_name, batch_total, live_batch_total, load_batch,
};
use crate::routes::pages::sorted_pages;
use crate::scrape_service::{base_url, compat_document, credits_for, record_run_usage};
use crate::state::AppState;
use crate::store::Scope;
use crate::streams::StreamPermit;
use crate::util::{ts, ts_opt, Params};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use bytes::Bytes;
use crawlx_core::repo::{CrawlRun, PageRecord, RunEvent};
use crawlx_core::{CrawlRunId, StoreError};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::time::{interval_at, Instant, Interval, MissedTickBehavior};

/// How long a closing socket waits for the client's close frame before it is dropped.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Shortest keep-alive period (a zero `Settings::sse_keepalive` would make the timer panic).
const MIN_KEEPALIVE: Duration = Duration::from_millis(1);

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "get",
        "/compat/v2/crawl/{id}/ws",
        "compatCrawlWatch",
        "WebSocket watcher of a crawl (the key may be the Sec-WebSocket-Protocol; catchup, document and done frames); the crawl status path upgrades too",
        "crawls:read",
        "101",
    ),
    (
        "get",
        "/compat/v2/batch/scrape/{id}/ws",
        "compatBatchScrapeWatch",
        "WebSocket watcher of a batch scrape (catchup, document and done frames); the batch status path upgrades too",
        "crawls:read",
        "101",
    ),
];

/// The authenticated `/ws` sibling routes of this module, mounted behind the auth layer. The
/// upgrading `GET` of the two status paths is [`crawl`] and [`batch`] in their own route tables.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/v2/crawl/{id}/ws", get(crawl))
        .route("/compat/v2/batch/scrape/{id}/ws", get(batch))
}

/// What a watcher follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Crawl,
    Batch,
}

/// The numbers of a status body at one moment.
struct Counts {
    status: &'static str,
    total: u64,
    completed: u64,
    credits: u64,
    expires: Value,
}

/// The stored pages of a run and what they add up to.
struct Snapshot {
    pages: Vec<PageRecord>,
    counts: Counts,
}

impl Kind {
    /// The run `id` of the caller; the HTTP routes' `404` for any other run.
    async fn load(self, state: &AppState, principal: &Principal, id: &str) -> ApiResult<CrawlRun> {
        match self {
            Self::Crawl => load_crawl(state, principal, id).await,
            Self::Batch => load_batch(state, principal, id).await,
        }
    }

    /// The pages the status route of this kind lists and its `status`, `total`, `completed`,
    /// `creditsUsed` and `expiresAt`.
    async fn snapshot(self, state: &AppState, run: &CrawlRun) -> ApiResult<Snapshot> {
        match self {
            Self::Crawl => {
                let (keyed, credits) = crawl_pages(state, run).await?;
                Ok(Snapshot {
                    pages: keyed.into_iter().map(|(_, page)| page).collect(),
                    counts: Counts {
                        status: facade_status(run.status),
                        total: crawl_total(run),
                        completed: run.counters.urls.succeeded,
                        credits,
                        expires: ts_opt(expires_at(run)),
                    },
                })
            }
            Self::Batch => {
                let pages = sorted_pages(state, run, None).await?;
                let credits = pages.iter().map(|p| credits_for(run, p)).sum();
                let counts = Counts {
                    status: batch_status_name(run.status),
                    total: u64::try_from(live_batch_total(state, run.id, batch_total(run)).await?)
                        .unwrap_or(u64::MAX),
                    completed: u64::try_from(pages.len()).unwrap_or(u64::MAX),
                    credits,
                    expires: Value::String(ts(batch_expires(run))),
                };
                Ok(Snapshot { pages, counts })
            }
        }
    }
}

/// The `catchup` frame: the status body with every document stored so far.
fn catchup_frame(counts: &Counts, documents: Vec<Value>) -> Value {
    json!({
        "type": "catchup",
        "data": {
            "status": counts.status,
            "total": counts.total,
            "completed": counts.completed,
            "creditsUsed": counts.credits,
            "expiresAt": counts.expires,
            "next": null,
            "data": documents,
        },
    })
}

/// The `done` frame: the terminal status and totals; the documents were already streamed.
fn done_frame(counts: &Counts) -> Value {
    json!({
        "type": "done",
        "data": {
            "status": counts.status,
            "data": [],
            "total": counts.total,
            "completed": counts.completed,
            "creditsUsed": counts.credits,
        },
    })
}

/// The `error` frame.
fn error_frame(message: &str) -> Value {
    json!({ "type": "error", "error": message })
}

/// The `document` frame of one page.
fn document_frame(document: Value) -> Value {
    json!({ "type": "document", "data": document })
}

/// The extraction result of the WebSocket upgrade; it is a rejection for a plain `GET`.
type Upgrade = Result<WebSocketUpgrade, WebSocketUpgradeRejection>;

/// `GET /compat/v2/crawl/{id}` and `GET /compat/v2/crawl/{id}/ws`: with
/// `Upgrade: websocket` the crawl watcher, otherwise [`crate::routes::compat::status`].
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run, a run owned by
/// another tenant or a batch/scrape/map run (before the upgrade, as JSON), `400` for a malformed
/// handshake and `429 too_many_streams` above the open-stream caps of
/// [`crate::routes::events::events`]; a plain `GET` answers the errors of the status route.
pub async fn crawl(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    params: Params,
    ws: Upgrade,
) -> ApiResult<Response> {
    if !is_websocket_upgrade(&headers) {
        return crate::routes::compat::status(State(state), Extension(principal), Path(id), headers, params)
            .await;
    }
    upgrade(state, &principal, Kind::Crawl, &id, &headers, ws).await
}

/// `GET /compat/v2/batch/scrape/{id}` and `GET /compat/v2/batch/scrape/{id}/ws`:
/// with `Upgrade: websocket` the batch watcher, otherwise
/// [`crate::routes::compat_scrape::batch_status`].
///
/// # Errors
/// As [`crawl`], with `404` for a run that is not a batch scrape.
pub async fn batch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    params: Params,
    ws: Upgrade,
) -> ApiResult<Response> {
    if !is_websocket_upgrade(&headers) {
        return crate::routes::compat_scrape::batch_status(
            State(state),
            Extension(principal),
            Path(id),
            headers,
            params,
        )
        .await;
    }
    upgrade(state, &principal, Kind::Batch, &id, &headers, ws).await
}

/// Check the caller and the run, take a stream slot, and answer the handshake; the watcher runs
/// on the upgraded socket.
async fn upgrade(
    state: AppState,
    principal: &Principal,
    kind: Kind,
    id: &str,
    headers: &HeaderMap,
    ws: Upgrade,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = kind.load(&state, principal, id).await?;
    let ws = ws.map_err(|e| HttpError::malformed(e.body_text()))?;
    let permit = state.streams.acquire(principal.tenant, run.id)?;
    let base = base_url(headers);
    // a client that offered its key as the subprotocol needs it echoed, or it drops the socket
    let ws = match websocket_key(headers, state.config.compat.prefixed_keys) {
        Some(key) => ws.protocols([key.to_owned()]),
        None => ws,
    };
    let tenant = principal.tenant;
    Ok(ws.on_upgrade(move |socket| {
        crawlx_storage::tenant::scope(tenant, watch(socket, state, kind, run.id, base, permit))
    }))
}

/// Why a watcher ended before its `done` frame.
enum Stop {
    /// The client closed the socket or a write failed.
    ClientGone,
    /// The server is shutting down.
    Shutdown,
    /// The client did not take a frame within `Settings::ws_send_timeout`.
    SlowClient,
    /// The run could not be followed; the text goes to the client in an `error` frame.
    Failed(String),
}

impl From<axum::Error> for Stop {
    fn from(_: axum::Error) -> Self {
        Self::ClientGone
    }
}

impl From<StoreError> for Stop {
    fn from(e: StoreError) -> Self {
        if matches!(e, StoreError::NotFound { .. }) {
            return Self::Failed("the run no longer exists".to_owned());
        }
        tracing::warn!(error = %e, "crawl watcher ends: storage failure");
        Self::Failed("the run could not be read".to_owned())
    }
}

impl From<HttpError> for Stop {
    fn from(e: HttpError) -> Self {
        tracing::warn!(error = %e, "crawl watcher ends: status unavailable");
        Self::Failed(e.message)
    }
}

/// The run and the events past a cursor.
struct Polled {
    run: CrawlRun,
    events: Vec<RunEvent>,
}

/// Read the run and its events after `after`; wait one poll interval while the run is live and
/// has nothing new. Only reads, so a caller may drop it between awaits without losing state.
async fn poll_run(state: &AppState, run: CrawlRunId, after: u64) -> Result<Polled, StoreError> {
    loop {
        // the status first: events listed afterwards include everything stored before it
        let record = state.repos.runs.get(run).await?;
        let events = state
            .repos
            .events
            .list_after(run, after, state.settings.sse_batch)
            .await?;
        if !events.is_empty() || record.status.is_terminal() {
            return Ok(Polled { run: record, events });
        }
        tokio::time::sleep(state.settings.sse_poll_interval).await;
    }
}

/// The page a `page` event of the journal stored.
fn page_id(event: &RunEvent) -> Option<i64> {
    if event.kind != "page" {
        return None;
    }
    event.payload.get("pageId").and_then(Value::as_i64)
}

/// One open watcher.
struct Watcher {
    state: AppState,
    kind: Kind,
    run: CrawlRunId,
    base: String,
    socket: WebSocket,
    /// Pages already sent, in the catchup or as a `document`.
    sent: BTreeSet<i64>,
    /// Sequence number of the last journal event handled.
    after: u64,
    ping: Interval,
}

impl Watcher {
    /// Write one message; a client that takes more than `Settings::ws_send_timeout` to accept it
    /// ends the watcher instead of holding its stream slot and the run's reads.
    async fn write(&mut self, message: Message) -> Result<(), Stop> {
        let limit = self.state.settings.ws_send_timeout;
        tokio::select! {
            () = self.state.shutdown.cancelled() => Err(Stop::Shutdown),
            sent = tokio::time::timeout(limit, self.socket.send(message)) => match sent {
                Ok(written) => Ok(written?),
                Err(_) => Err(Stop::SlowClient),
            },
        }
    }

    async fn send(&mut self, frame: Value) -> Result<(), Stop> {
        self.write(Message::Text(frame.to_string().into())).await
    }

    /// Send the documents of `pages` the client has not seen.
    async fn send_documents(&mut self, run: &CrawlRun, pages: &[&PageRecord]) -> Result<(), Stop> {
        for page in pages {
            if self.sent.insert(page.frontier_id) {
                let document = compat_document(&self.state, run, page, &self.base).await;
                self.send(document_frame(document)).await?;
            }
        }
        Ok(())
    }

    /// Catch up, follow the journal, and finish with the `done` frame.
    async fn stream(&mut self) -> Result<(), Stop> {
        let run = self.state.repos.runs.get(self.run).await?;
        let snapshot = self.kind.snapshot(&self.state, &run).await?;
        let mut documents = Vec::with_capacity(snapshot.pages.len());
        for page in &snapshot.pages {
            self.sent.insert(page.frontier_id);
            documents.push(compat_document(&self.state, &run, page, &self.base).await);
        }
        self.send(catchup_frame(&snapshot.counts, documents)).await?;
        if run.status.is_terminal() {
            return self.finish(&run).await;
        }
        loop {
            let polled = tokio::select! {
                biased;
                () = self.state.shutdown.cancelled() => return Err(Stop::Shutdown),
                incoming = self.socket.recv() => match incoming {
                    None | Some(Err(_) | Ok(Message::Close(_))) => return Err(Stop::ClientGone),
                    Some(Ok(_)) => continue,
                },
                _ = self.ping.tick() => {
                    self.write(Message::Ping(Bytes::new())).await?;
                    continue;
                }
                polled = poll_run(&self.state, self.run, self.after) => polled?,
            };
            let Polled { run, events } = polled;
            self.relay(&run, &events).await?;
            if let Some(last) = events.last() {
                self.after = last.seq;
            }
            if events.is_empty() && run.status.is_terminal() {
                return self.finish(&run).await;
            }
        }
    }

    /// One `document` frame per page of `events` the client has not seen.
    async fn relay(&mut self, run: &CrawlRun, events: &[RunEvent]) -> Result<(), Stop> {
        let fresh: Vec<i64> = events
            .iter()
            .filter_map(page_id)
            .filter(|id| !self.sent.contains(id))
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }
        let stored = sorted_pages(&self.state, run, None).await?;
        let by_id: BTreeMap<i64, &PageRecord> = stored.iter().map(|p| (p.frontier_id, p)).collect();
        let pages: Vec<&PageRecord> = fresh.iter().filter_map(|id| by_id.get(id).copied()).collect();
        self.send_documents(run, &pages).await
    }

    /// The run is terminal and its journal drained: send any stored page the journal did not
    /// announce, book the run's credits and send the `done` frame.
    async fn finish(&mut self, run: &CrawlRun) -> Result<(), Stop> {
        let snapshot = self.kind.snapshot(&self.state, run).await?;
        let pages: Vec<&PageRecord> = snapshot.pages.iter().collect();
        self.send_documents(run, &pages).await?;
        record_run_usage(&self.state, run).await;
        self.send(done_frame(&snapshot.counts)).await
    }

    /// End the connection: an `error` frame for a failed watcher, then a close frame (normal,
    /// going away or internal error) and the client's answer, for at most [`CLOSE_WAIT`].
    async fn close(mut self, outcome: Result<(), Stop>) {
        let (error, code, reason) = match outcome {
            Err(Stop::ClientGone) => return,
            Ok(()) => (None, close_code::NORMAL, ""),
            Err(Stop::Shutdown) => (None, close_code::AWAY, "server shutting down"),
            Err(Stop::SlowClient) => (None, close_code::POLICY, "client too slow"),
            Err(Stop::Failed(message)) => (Some(message), close_code::ERROR, "watcher failed"),
        };
        let frame = CloseFrame {
            code,
            reason: reason.into(),
        };
        let socket = &mut self.socket;
        let closing = async {
            if let Some(message) = error {
                socket
                    .send(Message::Text(error_frame(&message).to_string().into()))
                    .await?;
            }
            socket.send(Message::Close(Some(frame))).await?;
            while let Some(Ok(_)) = socket.recv().await {}
            Ok::<(), axum::Error>(())
        };
        if let Ok(Err(e)) = tokio::time::timeout(CLOSE_WAIT, closing).await {
            tracing::debug!(error = %e, run = %self.run, "crawl watcher close failed");
        }
    }
}

/// Run a watcher on `socket` until its job ends, the client leaves or the server stops.
async fn watch(
    socket: WebSocket,
    state: AppState,
    kind: Kind,
    run: CrawlRunId,
    base: String,
    permit: StreamPermit,
) {
    let keepalive = state.settings.sse_keepalive.max(MIN_KEEPALIVE);
    let mut ping = interval_at(Instant::now() + keepalive, keepalive);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut watcher = Watcher {
        state,
        kind,
        run,
        base,
        socket,
        sent: BTreeSet::new(),
        after: 0,
        ping,
    };
    let outcome = watcher.stream().await;
    // the slot is free as soon as the stream ends, not after the closing handshake
    drop(permit);
    watcher.close(outcome).await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn counts(status: &'static str) -> Counts {
        Counts {
            status,
            total: 3,
            completed: 2,
            credits: 2,
            expires: Value::Null,
        }
    }

    #[test]
    fn frames_have_the_sdk_shapes() {
        let c = counts("scraping");
        let catchup = catchup_frame(&c, vec![json!({"markdown": "x"})]);
        assert_eq!(catchup["type"], "catchup");
        assert_eq!(catchup["data"]["status"], "scraping");
        assert_eq!(catchup["data"]["total"], 3);
        assert_eq!(catchup["data"]["completed"], 2);
        assert_eq!(catchup["data"]["creditsUsed"], 2);
        assert_eq!(catchup["data"]["next"], Value::Null);
        assert_eq!(catchup["data"]["data"][0]["markdown"], "x");
        let done = done_frame(&counts("cancelled"));
        assert_eq!(done["type"], "done");
        assert_eq!(done["data"]["status"], "cancelled");
        assert_eq!(done["data"]["data"], json!([]));
        assert_eq!(
            document_frame(json!({"a": 1})),
            json!({"type": "document", "data": {"a": 1}})
        );
        assert_eq!(error_frame("boom"), json!({"type": "error", "error": "boom"}));
    }

    #[test]
    fn only_page_events_with_an_id_announce_a_document() {
        let event = |kind: &str, payload: Value| RunEvent {
            seq: 1,
            kind: kind.to_owned(),
            payload,
            at: chrono::Utc::now(),
        };
        assert_eq!(page_id(&event("page", json!({"pageId": 7}))), Some(7));
        assert_eq!(page_id(&event("page", json!({}))), None);
        assert_eq!(page_id(&event("page.failed", json!({"pageId": 7}))), None);
        assert_eq!(page_id(&event("completed", json!({"pageId": 7}))), None);
    }
}
