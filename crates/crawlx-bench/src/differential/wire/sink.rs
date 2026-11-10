//! The webhook sink of the runner: an HTTP server the system
//! under test delivers webhooks to. It records every delivery (headers, JSON body, arrival
//! order) per label and can answer the first deliveries of a label with an error status to
//! observe retry behavior.
//!
//! The sink listens on a port the system can reach: for the upstream containers
//! `0.0.0.0:PORT`, addressed as `http://gym.test:PORT/hook/<label>` (the compose alias of the
//! host gateway), for an in-process facade `127.0.0.1:PORT`.

use crate::error::BenchError;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::any;
use axum::Router;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One delivery the sink received.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct SinkEvent {
    /// Sink label the delivery named.
    pub label: String,
    /// Arrival order over the whole sink, from 1.
    pub seq: u64,
    /// Milliseconds since the sink started (informational, never compared).
    pub at_ms: u64,
    /// HTTP method.
    pub method: String,
    /// Request headers, names lower-cased; transport headers (`host`, `content-length`,
    /// `connection`, `accept-encoding`) are left out.
    pub headers: BTreeMap<String, String>,
    /// JSON body; a body that is not JSON is `{"_text": "..."}`.
    pub body: Value,
    /// Status the sink answered.
    pub replied: u16,
}

#[derive(Debug, Default)]
struct Script {
    fail_first: u32,
    fail_status: u16,
    seen: u32,
}

#[derive(Debug)]
struct SinkState {
    started: Instant,
    seq: Mutex<u64>,
    events: Mutex<Vec<SinkEvent>>,
    scripts: Mutex<BTreeMap<String, Script>>,
}

/// A running sink. Dropping it aborts the server task; prefer [`Sink::shutdown`].
#[derive(Debug)]
pub struct Sink {
    /// Port the sink listens on.
    pub port: u16,
    state: Arc<SinkState>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

const TRANSPORT_HEADERS: [&str; 4] = ["host", "content-length", "connection", "accept-encoding"];

async fn deliver(
    State(state): State<Arc<SinkState>>,
    Path(label): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let replied = {
        let mut scripts = state.scripts.lock();
        match scripts.get_mut(&label) {
            Some(s) if s.seen < s.fail_first => {
                s.seen += 1;
                StatusCode::from_u16(s.fail_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Some(s) => {
                s.seen = s.seen.saturating_add(1);
                StatusCode::OK
            }
            None => StatusCode::OK,
        }
    };
    let parsed = serde_json::from_slice::<Value>(&body)
        .unwrap_or_else(|_| serde_json::json!({ "_text": String::from_utf8_lossy(&body) }));
    let headers = headers
        .iter()
        .filter(|(k, _)| !TRANSPORT_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let seq = {
        let mut s = state.seq.lock();
        *s += 1;
        *s
    };
    state.events.lock().push(SinkEvent {
        label,
        seq,
        at_ms: u64::try_from(state.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        method: method.as_str().to_owned(),
        headers,
        body: parsed,
        replied: replied.as_u16(),
    });
    replied
}

impl Sink {
    /// Bind `bind` (port 0 picks a free one) and serve until [`Sink::shutdown`].
    ///
    /// # Errors
    /// [`BenchError::Bind`] when binding fails.
    pub async fn start(bind: SocketAddr) -> Result<Self, BenchError> {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|source| BenchError::Bind { addr: bind, source })?;
        let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
        let state = Arc::new(SinkState {
            started: Instant::now(),
            seq: Mutex::new(0),
            events: Mutex::new(Vec::new()),
            scripts: Mutex::new(BTreeMap::new()),
        });
        let app = Router::new()
            .route("/hook/{label}", any(deliver))
            .with_state(Arc::clone(&state));
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let stop = stop.clone();
            async move {
                let served = axum::serve(listener, app)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await;
                if let Err(error) = served {
                    tracing::error!(%error, %addr, "webhook sink stopped with an error");
                }
            }
        });
        Ok(Self {
            port: addr.port(),
            state,
            stop,
            task: Some(task),
        })
    }

    /// Answer the first `fail_first` deliveries of `label` with `fail_status`, then `200`.
    pub fn script(&self, label: &str, fail_first: u32, fail_status: u16) {
        self.state.scripts.lock().insert(
            label.to_owned(),
            Script {
                fail_first,
                fail_status,
                seen: 0,
            },
        );
    }

    /// Remove and return the deliveries of `label`, in arrival order, and forget its script.
    #[must_use]
    pub fn take(&self, label: &str) -> Vec<SinkEvent> {
        self.state.scripts.lock().remove(label);
        let mut events = self.state.events.lock();
        let (mine, rest): (Vec<_>, Vec<_>) = events.drain(..).partition(|e| e.label == label);
        *events = rest;
        mine
    }

    /// Stop serving and wait for the task.
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn the_sink_records_deliveries_and_fails_the_first_ones_on_request() {
        let sink = Sink::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        sink.script("retry", 2, 503);
        let http = reqwest::Client::new();
        let url = |l: &str| format!("http://127.0.0.1:{}/hook/{l}", sink.port);
        let mut replies = Vec::new();
        for n in 0..3 {
            let r = http
                .post(url("retry"))
                .header("x-differential", "1")
                .json(&serde_json::json!({"type": "crawl.page", "n": n}))
                .send()
                .await
                .unwrap();
            replies.push(r.status().as_u16());
        }
        http.post(url("other")).body("plain").send().await.unwrap();
        assert_eq!(replies, [503, 503, 200]);
        let mine = sink.take("retry");
        assert_eq!(mine.len(), 3);
        assert_eq!(mine[2].seq, 3);
        assert_eq!(mine[0].replied, 503);
        assert_eq!(
            mine[0].headers.get("x-differential").map(String::as_str),
            Some("1")
        );
        assert!(!mine[0].headers.contains_key("host"));
        assert_eq!(mine[1].body["n"], 1);
        let other = sink.take("other");
        assert_eq!(other[0].body["_text"], "plain");
        assert!(sink.take("retry").is_empty());
        sink.shutdown().await;
    }
}
