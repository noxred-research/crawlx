//! The CDP adapter boundary: the only module that touches `chromiumoxide`.
//!
//! chromiumoxide's high-level `Handler` initializes every target with `Runtime.enable`,
//! which the `Stealth` profile must never send, so only its message types are used. The
//! WebSocket transport enforces frame and assembled-message limits before decoding JSON.
//! Every command goes through [`CdpClient::call`], which records the method name in a transcript.
//!
//! Params are built as JSON and results are deserialized into small crawlx-owned structs
//! that carry only the fields the adapter reads.

use chromiumoxide::types::{CallId, EventMessage, Message, Method, MethodCall, MethodId};
use crawlx_core::browser::BrowserError;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message as WsMessage};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Default per-command timeout.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Default capacity of the command queue to the connection driver
/// ([`crate::LaunchConfig::cdp_queue`]); senders wait when it is full (backpressure).
pub const COMMAND_QUEUE: usize = 1024;
const EVENT_BUFFER: usize = 8192;
const TRANSCRIPT_CAP: usize = 20_000;

/// A CDP event as received.
#[derive(Debug, Clone)]
pub struct CdpEvent {
    /// CDP event name, e.g. `Page.frameNavigated`; the synthetic `crawlx.connectionClosed`
    /// is emitted once when the connection ends.
    pub method: String,
    /// Flattened-session id the event belongs to; `None` for browser-level events.
    pub session_id: Option<String>,
    /// Raw event parameters as sent by the browser; `Value::Null` when absent.
    pub params: Value,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    method: String,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    params: Value,
}

impl Method for RawEvent {
    fn identifier(&self) -> MethodId {
        Cow::Owned(self.method.clone())
    }
}

impl EventMessage for RawEvent {
    fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// Largest inbound CDP frame [`decode_frame`] accepts, in bytes (64 MiB: tungstenite's
/// default message cap and far above any result the adapter reads, including full-page
/// screenshots and DOM snapshots). Covered by the `fuzz_cdp_decode` fuzz target.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// A command failure reported by the browser inside a response frame.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("cdp error {code}: {message}")]
pub struct CdpProtocolError {
    /// JSON-RPC style error code.
    pub code: i64,
    /// Browser-supplied message.
    pub message: String,
}

/// One inbound frame after [`decode_frame`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CdpFrame {
    /// Reply to a command: the call id and either the `result` object (`Null` when the
    /// browser omits it) or the browser's error.
    Response {
        /// Id of the command this frame answers.
        id: u64,
        /// The `result` payload or the `error` object.
        outcome: Result<Value, CdpProtocolError>,
    },
    /// An event (`method`, `params`, optional `sessionId`).
    Event(CdpEvent),
}

/// Why an inbound frame was refused by [`decode_frame`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameDecodeError {
    /// The frame is larger than [`MAX_FRAME_BYTES`].
    #[error("cdp frame of {len} bytes exceeds the {max} byte limit")]
    Oversized {
        /// Frame length in bytes.
        len: usize,
        /// The limit that was applied.
        max: usize,
    },
    /// The frame is not a CDP response or event.
    #[error("cdp frame is not a response or event")]
    Json(#[source] serde_json::Error),
}

impl From<Message<RawEvent>> for CdpFrame {
    fn from(msg: Message<RawEvent>) -> Self {
        match msg {
            Message::Response(resp) => Self::Response {
                // chromiumoxide keeps `CallId(usize)` opaque; it serializes as a JSON number.
                id: serde_json::to_value(resp.id)
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(u64::MAX),
                outcome: match resp.error {
                    Some(err) => Err(CdpProtocolError {
                        code: err.code,
                        message: err.message,
                    }),
                    None => Ok(resp.result.unwrap_or(Value::Null)),
                },
            },
            Message::Event(ev) => Self::Event(CdpEvent {
                method: ev.method,
                session_id: ev.session_id,
                params: ev.params,
            }),
        }
    }
}

/// Decode one inbound text frame with the adapter's message types (the same
/// `Message<RawEvent>` the connection driver receives from `chromiumoxide`), bounded by
/// [`MAX_FRAME_BYTES`]. Unknown fields are ignored; `params` defaults to `Null`.
///
/// # Errors
/// [`FrameDecodeError::Oversized`] when `text` is longer than [`MAX_FRAME_BYTES`];
/// [`FrameDecodeError::Json`] when it is neither a response (`id`) nor an event (`method`).
pub fn decode_frame(text: &str) -> Result<CdpFrame, FrameDecodeError> {
    if text.len() > MAX_FRAME_BYTES {
        return Err(FrameDecodeError::Oversized {
            len: text.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    serde_json::from_str::<Message<RawEvent>>(text)
        .map(CdpFrame::from)
        .map_err(FrameDecodeError::Json)
}

struct Call {
    method: String,
    session: Option<String>,
    params: Value,
    reply: oneshot::Sender<Result<Value, BrowserError>>,
}

/// Shared handle to one DevTools WebSocket connection.
#[derive(Clone)]
pub struct CdpClient {
    tx: mpsc::Sender<Call>,
    events: broadcast::Sender<Arc<CdpEvent>>,
    transcript: Arc<Mutex<VecDeque<String>>>,
    calls: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl CdpClient {
    /// Connect to the browser endpoint (`ws://127.0.0.1:<port>/devtools/browser/<id>`) with
    /// a command queue of [`COMMAND_QUEUE`] entries.
    ///
    /// # Errors
    /// Returns [`BrowserError::Transport`] if the WebSocket connection cannot be established.
    pub async fn connect(ws_url: &str) -> Result<Self, BrowserError> {
        Self::connect_with_queue(ws_url, COMMAND_QUEUE).await
    }

    /// [`Self::connect`] with an explicit command-queue capacity (`0` is treated as `1`).
    ///
    /// # Errors
    /// Returns [`BrowserError::Transport`] if the WebSocket connection cannot be established.
    pub async fn connect_with_queue(ws_url: &str, queue: usize) -> Result<Self, BrowserError> {
        Self::connect_bounded(ws_url, queue, MAX_FRAME_BYTES).await
    }

    async fn connect_bounded(ws_url: &str, queue: usize, limit: usize) -> Result<Self, BrowserError> {
        let config = WebSocketConfig::default()
            .max_frame_size(Some(limit))
            .max_message_size(Some(limit));
        let (conn, _) = tokio_tungstenite::connect_async_with_config(ws_url, Some(config), false)
            .await
            .map_err(|e| BrowserError::Transport(e.to_string()))?;
        let (tx, rx) = mpsc::channel(queue.max(1));
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let closed = Arc::new(AtomicBool::new(false));
        tokio::spawn(drive(conn, rx, events.clone(), Arc::clone(&closed)));
        Ok(Self {
            tx,
            events,
            transcript: Arc::new(Mutex::new(VecDeque::new())),
            calls: Arc::new(AtomicU64::new(0)),
            closed,
        })
    }

    /// Has the connection closed (browser exited)?
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Subscribe to every event on the connection (all sessions).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<CdpEvent>> {
        self.events.subscribe()
    }

    /// Methods sent so far, in order (bounded; oldest entries are dropped first).
    #[must_use]
    pub fn transcript(&self) -> Vec<String> {
        self.transcript.lock().iter().cloned().collect()
    }

    /// Number of commands sent so far.
    #[must_use]
    pub fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Send `method` on `session` (`None` = browser endpoint) and await the result.
    ///
    /// # Errors
    /// Returns [`BrowserError::TargetClosed`] if the connection is closed or closes before the
    /// reply, [`BrowserError::Timeout`] after [`COMMAND_TIMEOUT`], [`BrowserError::Transport`] if
    /// the command cannot be sent, and [`BrowserError::Protocol`] if the browser answers with an
    /// error response.
    pub async fn call(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
    ) -> Result<Value, BrowserError> {
        self.call_with_timeout(method, session, params, COMMAND_TIMEOUT)
            .await
    }

    /// [`Self::call`] with an explicit timeout.
    ///
    /// # Errors
    /// Same as [`Self::call`], except [`BrowserError::Timeout`] fires after `timeout`.
    pub async fn call_with_timeout(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, BrowserError> {
        if self.is_closed() {
            return Err(BrowserError::TargetClosed);
        }
        {
            let mut t = self.transcript.lock();
            // Reuse evicted storage: long-lived sessions record millions of commands.
            let mut recorded = if t.len() >= TRANSCRIPT_CAP {
                t.pop_front().unwrap_or_default()
            } else {
                String::new()
            };
            recorded.clear();
            recorded.push_str(method);
            t.push_back(recorded);
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let (reply, rx) = oneshot::channel();
        let call = Call {
            method: method.to_owned(),
            session: session.map(str::to_owned),
            params,
            reply,
        };
        // the deadline covers queueing (backpressure when the driver is behind) and the reply
        let exchange = async {
            self.tx.send(call).await.map_err(|_| BrowserError::TargetClosed)?;
            rx.await.map_err(|_| BrowserError::TargetClosed)?
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(method, "cdp command deadline elapsed");
                Err(BrowserError::Timeout(
                    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                ))
            }
        }
    }

    /// Typed variant of [`Self::call`].
    ///
    /// # Errors
    /// Same as [`Self::call`], plus [`BrowserError::Protocol`] if the result does not
    /// deserialize into `T`.
    pub async fn call_as<T: DeserializeOwned>(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
    ) -> Result<T, BrowserError> {
        let v = self.call(method, session, params).await?;
        serde_json::from_value(v).map_err(|e| BrowserError::Protocol {
            method: method.to_owned(),
            message: format!("unexpected result shape: {e}"),
        })
    }
}

async fn drive(
    mut conn: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    mut rx: mpsc::Receiver<Call>,
    events: broadcast::Sender<Arc<CdpEvent>>,
    closed: Arc<AtomicBool>,
) {
    let mut pending: HashMap<
        chromiumoxide::types::CallId,
        (String, oneshot::Sender<Result<Value, BrowserError>>),
    > = HashMap::new();
    let mut next_id = 0usize;
    // A timed-out caller no longer owns its reply. Do not retain its method indefinitely
    // when Chromium never answers (for example, an evaluation awaiting a page promise).
    loop {
        pending.retain(|_, (_, reply)| !reply.is_closed());
        tokio::select! {
            call = rx.recv() => match call {
                Some(call) => {
                    let id = CallId::new(next_id);
                    let Some(next) = next_id.checked_add(1) else {
                        let _ = call.reply.send(Err(BrowserError::TargetClosed));
                        break;
                    };
                    next_id = next;
                    let command = MethodCall {
                        id,
                        method: Cow::Owned(call.method),
                        session_id: call.session,
                        params: call.params,
                    };
                    let text = match serde_json::to_string(&command) {
                        Ok(text) => text,
                        Err(error) => {
                            let _ = call.reply.send(Err(BrowserError::Transport(error.to_string())));
                            continue;
                        }
                    };
                    match tokio::time::timeout(COMMAND_TIMEOUT, conn.send(WsMessage::Text(text.into()))).await {
                        Ok(Ok(())) => {
                            pending.insert(id, (command.method.into_owned(), call.reply));
                        }
                        result => {
                            let error = match result {
                                Ok(Err(error)) => BrowserError::Transport(error.to_string()),
                                _ => BrowserError::Timeout(30_000),
                            };
                            let _ = call.reply.send(Err(error));
                            break;
                        }
                    }
                }
                // No client can consume any pending reply once every sender is gone.
                None => break,
            },
            msg = conn.next() => match msg {
                Some(Ok(WsMessage::Text(text))) => match serde_json::from_str::<Message<RawEvent>>(&text) {
                Ok(Message::Response(resp)) => {
                    if let Some((method, reply)) = pending.remove(&resp.id) {
                        let out = match resp.error {
                            Some(err) => Err(BrowserError::Protocol { method, message: err.message }),
                            None => Ok(resp.result.unwrap_or(Value::Null)),
                        };
                        let _ = reply.send(out);
                    }
                }
                Ok(Message::Event(ev)) => {
                    let _ = events.send(Arc::new(CdpEvent {
                        method: ev.method,
                        session_id: ev.session_id,
                        params: ev.params,
                    }));
                }
                Err(error) => {
                    tracing::debug!(%error, "ignoring undecodable CDP message");
                }
                },
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => {}
                Some(Ok(WsMessage::Close(_))) => break,
                Some(Ok(_)) => {
                    tracing::debug!("unexpected binary CDP message");
                    break;
                }
                Some(Err(error)) => {
                    // Transport limits and I/O failures close the driver and release
                    // every pending reply, rather than leaving calls to time out.
                    tracing::debug!(%error, "CDP transport closed");
                    break;
                }
                None => break,
            },
        }
    }
    closed.store(true, Ordering::Release);
    for (_, (_, reply)) in pending.drain() {
        let _ = reply.send(Err(BrowserError::TargetClosed));
    }
    // wake event consumers so they can observe the closure
    let _ = events.send(Arc::new(CdpEvent {
        method: "crawlx.connectionClosed".to_owned(),
        session_id: None,
        params: Value::Null,
    }));
}

/// A client bound to one attached target session.
#[derive(Clone)]
pub struct CdpSession {
    /// Connection the commands are sent over.
    pub client: CdpClient,
    /// CDP `sessionId` of the attached target; attached to every command sent via this handle.
    pub session_id: String,
}

/// Round a viewport coordinate (CSS px) to the integer pixel `DOM.getNodeForLocation` expects.
///
/// Clamped to the `i32` range first: Chromium lays out in 32-bit fixed point, so real
/// viewport coordinates are far inside it; NaN rounds to 0.
#[allow(
    clippy::cast_possible_truncation,
    reason = "value is clamped to the i32 range, so the f64 -> i64 conversion is exact"
)]
fn css_px(v: f64) -> i64 {
    v.round().clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i64
}

fn num(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(Value::as_f64).unwrap_or_default()
}

/// Rectangle in CSS pixels.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct Rect {
    /// Left edge (CSS px).
    pub x: f64,
    /// Top edge (CSS px).
    pub y: f64,
    /// Width (CSS px).
    pub w: f64,
    /// Height (CSS px).
    pub h: f64,
}

impl Rect {
    /// Center point `(x, y)` in CSS px.
    #[must_use]
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.w / 2.0, self.y + self.h / 2.0)
    }
    /// Convert to the observation-layer [`BoundingBox`](crawlx_core::observation::BoundingBox).
    #[must_use]
    pub fn to_bbox(self) -> crawlx_core::observation::BoundingBox {
        crawlx_core::observation::BoundingBox {
            x: self.x,
            y: self.y,
            width: self.w,
            height: self.h,
        }
    }
}

/// A content quad: four corner points.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Quad(pub [(f64, f64); 4]);

impl Quad {
    /// Build from a CDP flat quad `[x1, y1, x2, y2, x3, y3, x4, y4]`; `None` when fewer
    /// than eight numbers are given (extra values are ignored).
    #[must_use]
    pub fn from_flat(q: &[f64]) -> Option<Self> {
        if q.len() < 8 {
            return None;
        }
        Some(Self([(q[0], q[1]), (q[2], q[3]), (q[4], q[5]), (q[6], q[7])]))
    }

    /// Polygon area (shoelace).
    #[must_use]
    pub fn area(&self) -> f64 {
        let p = &self.0;
        let mut s = 0.0;
        for i in 0..4 {
            let (x1, y1) = p[i];
            let (x2, y2) = p[(i + 1) % 4];
            s += x1 * y2 - x2 * y1;
        }
        (s / 2.0).abs()
    }

    /// Axis-aligned bounding rectangle of the four corners.
    #[must_use]
    pub fn bounds(&self) -> Rect {
        let xs = self.0.map(|p| p.0);
        let ys = self.0.map(|p| p.1);
        let min_x = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let max_x = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let min_y = ys.iter().copied().fold(f64::INFINITY, f64::min);
        let max_y = ys.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        Rect {
            x: min_x,
            y: min_y,
            w: max_x - min_x,
            h: max_y - min_y,
        }
    }

    /// Mean of the four corners `(x, y)`.
    #[must_use]
    pub fn centroid(&self) -> (f64, f64) {
        let p = &self.0;
        (
            (p[0].0 + p[1].0 + p[2].0 + p[3].0) / 4.0,
            (p[0].1 + p[1].1 + p[2].1 + p[3].1) / 4.0,
        )
    }

    /// Point-in-convex-quad test (works for either winding).
    #[must_use]
    pub fn contains(&self, x: f64, y: f64) -> bool {
        let p = &self.0;
        let mut pos = false;
        let mut neg = false;
        for i in 0..4 {
            let (x1, y1) = p[i];
            let (x2, y2) = p[(i + 1) % 4];
            let cross = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1);
            if cross > 0.0 {
                pos = true;
            } else if cross < 0.0 {
                neg = true;
            }
        }
        !(pos && neg)
    }
}

/// Visual viewport in CSS pixels.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct VisualViewport {
    /// Scroll offset of the viewport within the page, horizontal (`pageX`, CSS px).
    pub x: f64,
    /// Scroll offset of the viewport within the page, vertical (`pageY`, CSS px).
    pub y: f64,
    /// Viewport width (`clientWidth`, CSS px).
    pub width: f64,
    /// Viewport height (`clientHeight`, CSS px).
    pub height: f64,
}

/// One entry of the frame tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawFrame {
    /// CDP frame id.
    pub id: String,
    /// Id of the parent frame; `None` for the main frame.
    pub parent: Option<String>,
    /// Current document URL of the frame.
    pub url: String,
    /// The frame's `name` (from the owner element or `window.name`); empty if unnamed.
    pub name: String,
    /// Security origin of the frame's document; empty when the browser omits it.
    pub security_origin: String,
}

/// CDP `Accessibility.AXValue`; only the `value` payload is kept.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct RawAxValue {
    /// JSON payload (string, boolean, number, ...); `None` when the property carries no value.
    pub value: Option<Value>,
}

/// CDP `Accessibility.AXProperty`: one named state or relation of an AX node.
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct RawAxProperty {
    /// Property name, e.g. `focusable` or `checked`.
    pub name: String,
    /// Property value.
    pub value: RawAxValue,
}

/// CDP `Accessibility.AXNode` (the fields the adapter reads).
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct RawAxNode {
    /// AX node id, unique within one accessibility tree.
    #[serde(rename = "nodeId")]
    pub node_id: String,
    /// `true` when the node is excluded from the accessibility tree.
    pub ignored: bool,
    /// ARIA/computed role, e.g. `button`.
    pub role: Option<RawAxValue>,
    /// Computed accessible name.
    pub name: Option<RawAxValue>,
    /// Computed accessible description.
    pub description: Option<RawAxValue>,
    /// Current value (e.g. of a text field or slider).
    pub value: Option<RawAxValue>,
    /// Additional AX states and properties.
    pub properties: Vec<RawAxProperty>,
    /// AX ids of the child nodes, in order.
    #[serde(rename = "childIds")]
    pub child_ids: Vec<String>,
    /// Backing DOM node id; `None` for nodes without a DOM counterpart.
    #[serde(rename = "backendDOMNodeId")]
    pub backend_dom_node_id: Option<i64>,
    /// Id of the frame the node belongs to.
    #[serde(rename = "frameId")]
    pub frame_id: Option<String>,
    /// AX id of the parent node; `None` for the root.
    #[serde(rename = "parentId")]
    pub parent_id: Option<String>,
}

/// Render an AX value (`string`, `boolean`, `number`) as text.
#[must_use]
pub fn ax_value_text(v: Option<&RawAxValue>) -> Option<String> {
    match v?.value.as_ref()? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Result of `DOM.describeNode` (the fields the adapter uses).
#[derive(Clone, Debug, Default)]
pub struct NodeDesc {
    /// DOM node name, e.g. `DIV` or `#text`.
    pub node_name: String,
    /// DOM `nodeType` (1 = element, 3 = text, ...).
    pub node_type: i64,
    /// Attributes as `(name, value)` pairs in document order.
    pub attributes: Vec<(String, String)>,
    /// For frame owner elements (`iframe`/`frame`), the id of the hosted frame.
    pub frame_id: Option<String>,
    /// Backend node id this description was requested for.
    pub backend_node_id: i64,
}

impl NodeDesc {
    /// Value of attribute `name` (ASCII case-insensitive), if present.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An event listener found by `DOMDebugger.getEventListeners`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawListener {
    /// Event type, e.g. `click`.
    pub kind: String,
    /// Whether the listener was registered for the capture phase (`useCapture`).
    pub capture: bool,
}

impl CdpSession {
    async fn call(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.client.call(method, Some(&self.session_id), params).await
    }

    /// `Accessibility.getFullAXTree` for `frame` (`None` = root frame).
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors, and [`BrowserError::Protocol`] if the returned
    /// nodes do not deserialize.
    pub async fn ax_full_tree(&self, frame: Option<&str>) -> Result<Vec<RawAxNode>, BrowserError> {
        let params = frame.map_or_else(|| json!({}), |f| json!({ "frameId": f }));
        let v = self.call("Accessibility.getFullAXTree", params).await?;
        let nodes = v.get("nodes").cloned().unwrap_or(Value::Null);
        serde_json::from_value(nodes).map_err(|e| BrowserError::Protocol {
            method: "Accessibility.getFullAXTree".to_owned(),
            message: e.to_string(),
        })
    }

    /// `Accessibility.getPartialAXTree` for one node; returns that node.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors, and [`BrowserError::Protocol`] if the returned
    /// node does not deserialize.
    pub async fn ax_node(&self, backend_node_id: i64) -> Result<Option<RawAxNode>, BrowserError> {
        let v = self
            .call(
                "Accessibility.getPartialAXTree",
                json!({ "backendNodeId": backend_node_id, "fetchRelatives": false }),
            )
            .await?;
        let first = v.get("nodes").and_then(|n| n.get(0)).cloned();
        match first {
            Some(n) => serde_json::from_value(n)
                .map(Some)
                .map_err(|e| BrowserError::Protocol {
                    method: "Accessibility.getPartialAXTree".to_owned(),
                    message: e.to_string(),
                }),
            None => Ok(None),
        }
    }

    /// `DOMSnapshot.captureSnapshot` with the styles and rects the discovery ladder needs.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn dom_snapshot(&self) -> Result<Value, BrowserError> {
        self.call(
            "DOMSnapshot.captureSnapshot",
            json!({
                "computedStyles": ["cursor", "pointer-events", "display", "visibility"],
                "includePaintOrder": true,
                "includeDOMRects": true,
            }),
        )
        .await
    }

    /// `Page.getFrameTree`, flattened pre-order.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn frame_tree(&self) -> Result<Vec<RawFrame>, BrowserError> {
        let v = self.call("Page.getFrameTree", json!({})).await?;
        let mut out = Vec::new();
        if let Some(tree) = v.get("frameTree") {
            flatten_frames(tree, &mut out);
        }
        Ok(out)
    }

    /// `DOM.describeNode` by backend id.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors (including [`BrowserError::Protocol`] for an
    /// unknown node id).
    pub async fn describe_node(&self, backend_node_id: i64) -> Result<NodeDesc, BrowserError> {
        let v = self
            .call("DOM.describeNode", json!({ "backendNodeId": backend_node_id }))
            .await?;
        let node = v.get("node").cloned().unwrap_or(Value::Null);
        let mut attributes = Vec::new();
        if let Some(arr) = node.get("attributes").and_then(Value::as_array) {
            for pair in arr.chunks(2) {
                if let [k, val] = pair {
                    attributes.push((
                        k.as_str().unwrap_or_default().to_owned(),
                        val.as_str().unwrap_or_default().to_owned(),
                    ));
                }
            }
        }
        Ok(NodeDesc {
            node_name: node
                .get("nodeName")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            node_type: node.get("nodeType").and_then(Value::as_i64).unwrap_or_default(),
            attributes,
            frame_id: node.get("frameId").and_then(Value::as_str).map(str::to_owned),
            backend_node_id,
        })
    }

    /// `DOM.getContentQuads`, quads that can be rendered (non-degenerate).
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors (including [`BrowserError::Protocol`] for a node
    /// without layout).
    pub async fn content_quads(&self, backend_node_id: i64) -> Result<Vec<Quad>, BrowserError> {
        let v = self
            .call("DOM.getContentQuads", json!({ "backendNodeId": backend_node_id }))
            .await?;
        let mut quads = Vec::new();
        if let Some(arr) = v.get("quads").and_then(Value::as_array) {
            for q in arr {
                let flat: Vec<f64> = q
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_f64).collect())
                    .unwrap_or_default();
                if let Some(quad) = Quad::from_flat(&flat) {
                    if quad.area() > 0.5 {
                        quads.push(quad);
                    }
                }
            }
        }
        Ok(quads)
    }

    /// Border box of a node via `DOM.getBoxModel`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors (including [`BrowserError::Protocol`] for a node
    /// without layout). `Ok(None)` when the response has no usable border quad.
    pub async fn box_model(&self, backend_node_id: i64) -> Result<Option<Rect>, BrowserError> {
        let v = self
            .call("DOM.getBoxModel", json!({ "backendNodeId": backend_node_id }))
            .await?;
        let flat: Vec<f64> = v
            .get("model")
            .and_then(|m| m.get("border"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        Ok(Quad::from_flat(&flat).map(|q| q.bounds()))
    }

    /// `Page.getLayoutMetrics().cssVisualViewport`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn visual_viewport(&self) -> Result<VisualViewport, BrowserError> {
        let v = self.call("Page.getLayoutMetrics", json!({})).await?;
        let vp = v.get("cssVisualViewport").cloned().unwrap_or(Value::Null);
        Ok(VisualViewport {
            x: num(&vp, "pageX"),
            y: num(&vp, "pageY"),
            width: num(&vp, "clientWidth"),
            height: num(&vp, "clientHeight"),
        })
    }

    /// `DOM.getNodeForLocation`; `None` when nothing is at the point.
    ///
    /// `x` and `y` are CSS px relative to the viewport. A protocol error from the browser
    /// (nothing hittable at the point) is mapped to `None`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors other than [`BrowserError::Protocol`].
    pub async fn node_for_location(&self, x: f64, y: f64) -> Result<Option<i64>, BrowserError> {
        match self
            .call(
                "DOM.getNodeForLocation",
                json!({
                    "x": css_px(x),
                    "y": css_px(y),
                    "includeUserAgentShadowDOM": false,
                    "ignorePointerEventsNone": false,
                }),
            )
            .await
        {
            Ok(v) => Ok(v.get("backendNodeId").and_then(Value::as_i64)),
            Err(BrowserError::Protocol { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `DOM.resolveNode` into `context_id` (or the node's own world); returns the object id.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors, and [`BrowserError::Protocol`] if the result
    /// has no `objectId`.
    pub async fn resolve_node(
        &self,
        backend_node_id: i64,
        context_id: Option<i64>,
        group: &str,
    ) -> Result<String, BrowserError> {
        let mut params = json!({ "backendNodeId": backend_node_id, "objectGroup": group });
        if let Some(id) = context_id {
            params["executionContextId"] = json!(id);
        }
        let v = self.call("DOM.resolveNode", params).await?;
        v.get("object")
            .and_then(|o| o.get("objectId"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| BrowserError::Protocol {
                method: "DOM.resolveNode".to_owned(),
                message: "no objectId in result".to_owned(),
            })
    }

    /// `Runtime.releaseObjectGroup` (does not enable the Runtime domain).
    pub async fn release_group(&self, group: &str) {
        let _ = self
            .call("Runtime.releaseObjectGroup", json!({ "objectGroup": group }))
            .await;
    }

    /// `DOMDebugger.getEventListeners` for a resolved object.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn event_listeners(&self, object_id: &str) -> Result<Vec<RawListener>, BrowserError> {
        let v = self
            .call("DOMDebugger.getEventListeners", json!({ "objectId": object_id }))
            .await?;
        Ok(v.get("listeners")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|l| RawListener {
                        kind: l
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        capture: l.get("useCapture").and_then(Value::as_bool).unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// `Runtime.callFunctionOn` returning the by-value result.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors, and [`BrowserError::Script`] if the function
    /// threw.
    pub async fn call_function_on(
        &self,
        object_id: &str,
        function: &str,
        args: Vec<Value>,
        await_promise: bool,
    ) -> Result<Value, BrowserError> {
        let v = self
            .call(
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": function,
                    "arguments": args,
                    "returnByValue": true,
                    "awaitPromise": await_promise,
                }),
            )
            .await?;
        runtime_result("Runtime.callFunctionOn", &v)
    }

    /// `Runtime.evaluate` in the isolated world `context_id`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors, and [`BrowserError::Script`] if the expression
    /// threw.
    pub async fn evaluate_in(
        &self,
        context_id: i64,
        expression: &str,
        await_promise: bool,
    ) -> Result<Value, BrowserError> {
        let v = self
            .call(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "contextId": context_id,
                    "returnByValue": true,
                    "awaitPromise": await_promise,
                }),
            )
            .await?;
        runtime_result("Runtime.evaluate", &v)
    }

    /// `Input.dispatchMouseEvent`.
    ///
    /// `x`/`y` are CSS px relative to the viewport; `delta` is the wheel `(deltaX, deltaY)`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_mouse(
        &self,
        kind: &str,
        x: f64,
        y: f64,
        button: &str,
        buttons: u32,
        click_count: u32,
        modifiers: u32,
        delta: Option<(f64, f64)>,
    ) -> Result<(), BrowserError> {
        let mut p = json!({
            "type": kind, "x": x, "y": y, "button": button,
            "buttons": buttons, "clickCount": click_count, "modifiers": modifiers,
        });
        if let Some((dx, dy)) = delta {
            p["deltaX"] = json!(dx);
            p["deltaY"] = json!(dy);
        }
        self.call("Input.dispatchMouseEvent", p).await.map(|_| ())
    }

    /// `Input.dispatchKeyEvent`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn dispatch_key(&self, params: Value) -> Result<(), BrowserError> {
        self.call("Input.dispatchKeyEvent", params).await.map(|_| ())
    }

    /// `Input.insertText`.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn insert_text(&self, text: &str) -> Result<(), BrowserError> {
        self.call("Input.insertText", json!({ "text": text }))
            .await
            .map(|_| ())
    }

    /// `Fetch.enable` with `patterns`: matching requests pause until `Fetch.continueRequest` or
    /// `Fetch.failRequest` answers them. Only a context with a navigation guard enables it
    /// (`context::guard`); the egress proxy enforces policy for everything else.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn fetch_enable(&self, patterns: Value) -> Result<(), BrowserError> {
        self.call("Fetch.enable", json!({ "patterns": patterns }))
            .await
            .map(|_| ())
    }

    /// Send any command on this session.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call`] errors.
    pub async fn send(&self, method: &str, params: Value) -> Result<Value, BrowserError> {
        self.call(method, params).await
    }
}

fn flatten_frames(node: &Value, out: &mut Vec<RawFrame>) {
    if let Some(f) = node.get("frame") {
        out.push(RawFrame {
            id: f.get("id").and_then(Value::as_str).unwrap_or_default().to_owned(),
            parent: f.get("parentId").and_then(Value::as_str).map(str::to_owned),
            url: f
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            name: f
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            security_origin: f
                .get("securityOrigin")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }
    if let Some(children) = node.get("childFrames").and_then(Value::as_array) {
        for c in children {
            flatten_frames(c, out);
        }
    }
}

/// Extract the by-value result of `Runtime.evaluate`/`callFunctionOn`, mapping exceptions.
///
/// # Errors
/// Returns [`BrowserError::Script`] (`"<method>: <text>"`) when the response carries
/// `exceptionDetails`.
pub fn runtime_result(method: &str, v: &Value) -> Result<Value, BrowserError> {
    if let Some(ex) = v.get("exceptionDetails") {
        let text = ex
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(Value::as_str)
            .or_else(|| ex.get("text").and_then(Value::as_str))
            .unwrap_or("exception");
        return Err(BrowserError::Script(format!("{method}: {text}")));
    }
    Ok(v.get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn oversized_wire_frames_and_fragmented_messages_close_pending_calls() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        for fragmented in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("ws://{}", listener.local_addr().unwrap());
            let (release, released) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                // Keep a real command pending while the peer advertises oversized input.
                assert!(socket.next().await.unwrap().unwrap().is_text());
                let stream = socket.get_mut();
                if fragmented {
                    // Each fragment is below the frame limit; the complete message exceeds
                    // the assembled-message limit. Keep the socket open after both bodies.
                    stream.write_all(&[0x01, 126, 0x02, 0xbc]).await.unwrap();
                    stream.write_all(&[b' '; 700]).await.unwrap();
                    stream.write_all(&[0x80, 126, 0x02, 0xbc]).await.unwrap();
                    stream.write_all(&[b' '; 700]).await.unwrap();
                } else {
                    let length = u64::try_from(MAX_FRAME_BYTES).unwrap() + 1;
                    stream.write_all(&[0x81, 127]).await.unwrap();
                    stream.write_all(&length.to_be_bytes()).await.unwrap();
                }
                // Without a transport limit, the client waits for missing payload bytes.
                // Do not let EOF make this test pass instead of size enforcement.
                let _ = released.await;
                drop(socket);
            });
            let client = if fragmented {
                CdpClient::connect_bounded(&endpoint, 1, 1024).await.unwrap()
            } else {
                CdpClient::connect(&endpoint).await.unwrap()
            };
            let mut events = client.subscribe();
            let result = client
                .call_with_timeout("Browser.getVersion", None, json!({}), Duration::from_secs(2))
                .await;
            let _ = release.send(());
            server.await.unwrap();
            assert!(matches!(result, Err(BrowserError::TargetClosed)), "{result:?}");
            assert!(client.is_closed());
            assert_eq!(events.recv().await.unwrap().method, "crawlx.connectionClosed");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn twelve_chromium_cycles_release_driver_and_event_ring_with_unanswered_calls() {
        let Some(executable) = crate::launch::find_executable() else {
            eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
            return;
        };
        for cycle in 0..12 {
            let mut config = crate::LaunchConfig::new();
            config.executable.clone_from(&executable);
            config.allow_unpinned = true;
            let profile = tempfile::tempdir().unwrap();
            let dir = profile.path().to_path_buf();
            let mut browser = crate::launch::spawn(&config, Some(profile), dir).await.unwrap();
            let client = CdpClient::connect(&browser.ws_url).await.unwrap();
            let target = client
                .call("Target.createTarget", None, json!({"url": "about:blank"}))
                .await
                .unwrap();
            let attached = client
                .call(
                    "Target.attachToTarget",
                    None,
                    json!({"targetId": target["targetId"], "flatten": true}),
                )
                .await
                .unwrap();
            let session = attached["sessionId"].as_str().unwrap();
            let result = client
                .call_with_timeout(
                    "Runtime.evaluate",
                    Some(session),
                    json!({"expression": "new Promise(() => {})", "awaitPromise": true}),
                    Duration::from_millis(100),
                )
                .await;
            assert!(matches!(result, Err(BrowserError::Timeout(_))), "{result:?}");
            // The driver alone owns this clone, not event consumers. Its destruction
            // releases the WebSocket buffers, pending calls and broadcast ring together.
            let driver = Arc::downgrade(&client.closed);
            let mut events = client.subscribe();
            drop(client);
            let released = tokio::time::timeout(Duration::from_secs(2), async {
                while driver.strong_count() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            browser.process.shutdown(Duration::from_millis(100)).await;
            assert!(
                released,
                "cycle {cycle}: CDP driver retained after last client dropped"
            );
            let closed = events.recv().await.unwrap();
            assert_eq!(closed.method, "crawlx.connectionClosed");
            assert!(matches!(
                events.recv().await,
                Err(broadcast::error::RecvError::Closed)
            ));
        }
    }

    #[test]
    fn decode_frame_response_event_and_unknown_fields() {
        match decode_frame(r#"{"id":7,"result":{"ok":true},"extra":[1,{"x":null}]}"#).unwrap() {
            CdpFrame::Response { id, outcome } => {
                assert_eq!(id, 7);
                assert_eq!(outcome.unwrap()["ok"], true);
            }
            other => panic!("expected response, got {other:?}"),
        }
        match decode_frame(r#"{"id":8,"error":{"code":-32601,"message":"nope","data":{}}}"#).unwrap() {
            CdpFrame::Response { outcome, .. } => {
                let err = outcome.unwrap_err();
                assert_eq!((err.code, err.message.as_str()), (-32601, "nope"));
            }
            other => panic!("expected response, got {other:?}"),
        }
        match decode_frame(
            r#"{"method":"Page.frameNavigated","sessionId":"S1","params":{"frame":{"id":"F"}},"unknown":1}"#,
        )
        .unwrap()
        {
            CdpFrame::Event(ev) => {
                assert_eq!(ev.method, "Page.frameNavigated");
                assert_eq!(ev.session_id.as_deref(), Some("S1"));
                assert_eq!(ev.params["frame"]["id"], "F");
            }
            other => panic!("expected event, got {other:?}"),
        }
        assert!(matches!(
            decode_frame(r#"{"method":"Page.frameNavigated""#),
            Err(FrameDecodeError::Json(_))
        ));
        assert!(matches!(decode_frame("[1,2]"), Err(FrameDecodeError::Json(_))));
    }

    #[test]
    fn decode_frame_rejects_oversized() {
        let mut text = String::from(r#"{"id":1,"result":{}}"#);
        text.extend(std::iter::repeat_n(' ', MAX_FRAME_BYTES + 1 - text.len()));
        assert!(matches!(
            decode_frame(&text),
            Err(FrameDecodeError::Oversized { len, max }) if len == MAX_FRAME_BYTES + 1 && max == MAX_FRAME_BYTES
        ));
    }

    #[test]
    fn quad_geometry() {
        let q = Quad::from_flat(&[10.0, 10.0, 110.0, 10.0, 110.0, 60.0, 10.0, 60.0]).unwrap();
        assert!((q.area() - 5000.0).abs() < 1e-9);
        assert_eq!(q.centroid(), (60.0, 35.0));
        assert!(q.contains(60.0, 35.0));
        assert!(!q.contains(5.0, 35.0));
        let b = q.bounds();
        assert_eq!((b.x, b.y, b.w, b.h), (10.0, 10.0, 100.0, 50.0));
        assert!(Quad::from_flat(&[1.0, 2.0]).is_none());
    }

    #[test]
    fn rotated_quad_contains() {
        let q = Quad([(50.0, 0.0), (100.0, 50.0), (50.0, 100.0), (0.0, 50.0)]);
        assert!(q.contains(50.0, 50.0));
        assert!(!q.contains(5.0, 5.0));
    }

    #[test]
    fn ax_value_rendering() {
        let s = RawAxValue {
            value: Some(json!("hi")),
        };
        let b = RawAxValue {
            value: Some(json!(true)),
        };
        assert_eq!(ax_value_text(Some(&s)).as_deref(), Some("hi"));
        assert_eq!(ax_value_text(Some(&b)).as_deref(), Some("true"));
        assert_eq!(ax_value_text(None), None);
    }

    #[test]
    fn frame_tree_flattening() {
        let tree = json!({
            "frame": {"id": "a", "url": "http://x/", "name": "", "securityOrigin": "http://x"},
            "childFrames": [{"frame": {"id": "b", "parentId": "a", "url": "http://x/f", "name": "f"}}]
        });
        let mut out = Vec::new();
        flatten_frames(&tree, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].parent.as_deref(), Some("a"));
    }

    #[test]
    fn runtime_exceptions_map_to_script_errors() {
        let ok = json!({"result": {"type": "number", "value": 3}});
        assert_eq!(runtime_result("m", &ok).unwrap(), json!(3));
        let bad = json!({"exceptionDetails": {"text": "Uncaught", "exception": {"description": "ReferenceError: x"}}});
        assert!(
            matches!(runtime_result("m", &bad), Err(BrowserError::Script(m)) if m.contains("ReferenceError"))
        );
    }
}
