//! The CDP adapter boundary: the only module that touches the WebSocket transport.
//!
//! The high-level `chromiumoxide` `Handler` initializes every target with `Runtime.enable`,
//! which the `Stealth` profile must never send, so the adapter speaks the protocol itself.
//! Every command goes through [`CdpClient::call`], which records the method name in a transcript.
//!
//! # Byte admission
//!
//! Every byte the connection holds is charged to a [`ByteBudget`] (the process-wide
//! [`parser_memory::global`] budget unless [`CdpClient::connect_with_budget`] injects another)
//! before it is allocated:
//!
//! * inbound frames are admitted by `meter::FrameMeter` from their header, before the
//!   WebSocket codec allocates the payload buffer; the charge moves with the decoded text;
//! * the JSON value (and the parser's scratch buffer) is reserved from a bound computed from
//!   the text before decoding, and travels with the result as a [`Budgeted<Value>`]
//!   ([`CdpClient::call_budgeted`]) or with the event ([`CdpEvent::charge`]);
//! * every command is serialized into reserved memory by its caller and queued as admitted
//!   text, so the command queue and the pending table are bounded in bytes and in entries;
//! * a result whose caller timed out is dropped with its reservation: the value first, then the
//!   permit.
//!
//! Boundary: [`CdpClient::call`] and [`CdpSession::send`] hand the caller a bare
//! [`serde_json::Value`] and release its reservation on return, so the caller's copy is not
//! charged. Producers that retain large results use the `*_budgeted` variants. Only plaintext
//! `ws://` endpoints are supported: the meter must see the plaintext frames. The decode bound is
//! an upper estimate (one pass over the text), not a measurement.
//!
//! Params are built as JSON and results are deserialized into small crawlx-owned structs
//! that carry only the fields the adapter reads.

use crawlx_core::browser::BrowserError;
use crawlx_core::parser_memory::{self, AdmittedBytes, Budgeted, ByteAdmissionError, ByteBudget, BytePermit};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{sleep, Instant};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message as WsMessage, Utf8Bytes};
use tokio_tungstenite::WebSocketStream;

mod meter;

/// Default per-command timeout.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Default capacity of the command queue to the connection driver
/// ([`crate::LaunchConfig::cdp_queue`]); senders wait when it is full (backpressure). The
/// driver also never holds more unanswered commands than this.
pub const COMMAND_QUEUE: usize = 1024;
const EVENT_BUFFER: usize = 8192;
const TRANSCRIPT_CAP: usize = 20_000;
/// Longest an admission request waits for other owners to release bytes before it fails.
const ADMISSION_WAIT: Duration = Duration::from_secs(5);
/// Pause between two admission attempts while the budget is exhausted.
const ADMISSION_RETRY: Duration = Duration::from_millis(10);
/// Heap the codec owns per connection regardless of traffic (read and write buffers).
const TRANSPORT_BUFFER: usize = 16 * 1024;
const TRANSPORT_BASELINE: usize = 4 * TRANSPORT_BUFFER;
/// Heap bound per JSON container element or member: a `Value` plus map-node overhead.
const ELEMENT_BYTES: usize = 96;

/// Largest decoded reply, in bytes, a plain [`CdpClient::call`] returns. The caller owns that
/// value after its reservation ends, so its size is bounded here instead. Methods that may
/// answer with more (page content, response bodies, snapshots, accessibility trees, cookies)
/// use the budgeted calls, which keep the value charged while it is held.
pub const METADATA_REPLY_LIMIT: usize = 1024 * 1024;

type Conn = WebSocketStream<meter::FrameMeter<TcpStream>>;
type Reply = Result<Budgeted<Value>, BrowserError>;
type Pending = HashMap<u64, (String, Option<usize>, oneshot::Sender<Reply>)>;

/// A CDP event as received.
///
/// Not `Clone`: the decoded `params` are charged once, through [`Self::charge`].
#[derive(Debug)]
pub struct CdpEvent {
    /// CDP event name, e.g. `Page.frameNavigated`; the synthetic `crawlx.connectionClosed`
    /// is emitted once when the connection ends.
    pub method: String,
    /// Flattened-session id the event belongs to; `None` for browser-level events.
    pub session_id: Option<String>,
    /// Raw event parameters as sent by the browser; `Value::Null` when absent.
    pub params: Value,
    /// Reservation covering `params`; released when the last handle to the event drops.
    /// `None` for synthetic events.
    pub charge: Option<BytePermit>,
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
#[derive(Debug)]
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

#[derive(Deserialize)]
struct WireError {
    code: i64,
    message: String,
}

/// Classify one decoded JSON value as a response (`id`) or an event (`method`). Unknown
/// members are ignored and `params` defaults to `Null`. The value is consumed member by
/// member, so no second copy of the tree exists.
fn frame_from_value(value: Value) -> Result<CdpFrame, serde_json::Error> {
    let Value::Object(mut frame) = value else {
        return Err(serde_json::Error::custom("cdp frame is not an object"));
    };
    if let Some(id) = frame.get("id").and_then(Value::as_u64) {
        let outcome = match frame.remove("error") {
            None | Some(Value::Null) => Ok(frame.remove("result").unwrap_or(Value::Null)),
            Some(error) => {
                let WireError { code, message } = serde_json::from_value(error)?;
                Err(CdpProtocolError { code, message })
            }
        };
        return Ok(CdpFrame::Response { id, outcome });
    }
    let Some(Value::String(method)) = frame.remove("method") else {
        return Err(serde_json::Error::custom("cdp frame has neither id nor method"));
    };
    let session_id = match frame.remove("sessionId") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(id),
        Some(_) => return Err(serde_json::Error::custom("sessionId is not a string")),
    };
    Ok(CdpFrame::Event(CdpEvent {
        method,
        session_id,
        params: frame.remove("params").unwrap_or(Value::Null),
        charge: None,
    }))
}

/// Decode one inbound text frame, bounded by [`MAX_FRAME_BYTES`]. Unknown fields are
/// ignored; `params` defaults to `Null`. The result carries no byte reservation
/// ([`CdpEvent::charge`] is `None`); the connection driver reserves before it decodes.
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
    serde_json::from_str::<Value>(text)
        .and_then(frame_from_value)
        .map_err(FrameDecodeError::Json)
}

/// Upper bound of the heap decoding one JSON text needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DecodeCost {
    /// The decoded `Value` tree: string and number text plus per-element overhead.
    value: usize,
    /// The parser's unescape buffer, alive only while decoding.
    scratch: usize,
}

/// Bound the decoding cost of `text` without allocating: one string-aware pass counting
/// containers, separators and the longest string.
fn decode_cost(text: &str) -> DecodeCost {
    let (mut elements, mut run, mut longest) = (1usize, 0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
    for &byte in text.as_bytes() {
        if in_string {
            match (escaped, byte) {
                (true, _) => {
                    escaped = false;
                    run += 1;
                }
                (false, b'\\') => {
                    escaped = true;
                    run += 1;
                }
                (false, b'"') => {
                    in_string = false;
                    longest = longest.max(run);
                }
                _ => run += 1,
            }
        } else {
            match byte {
                b'"' => {
                    in_string = true;
                    run = 0;
                }
                b'{' | b'[' | b',' => elements = elements.saturating_add(1),
                _ => {}
            }
        }
    }
    DecodeCost {
        value: text.len().saturating_add(elements.saturating_mul(ELEMENT_BYTES)),
        scratch: longest.saturating_mul(2),
    }
}

/// The numeric `id` a response text announces, read from its prefix without decoding.
fn response_id(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("{\"id\":")?;
    let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
    digits[..end].parse().ok()
}

/// Reserve `bytes`, waiting up to `wait` for other owners to release memory.
async fn admit(
    budget: &Arc<ByteBudget>,
    bytes: usize,
    wait: Duration,
) -> Result<BytePermit, ByteAdmissionError> {
    let deadline = Instant::now() + wait;
    loop {
        match budget.try_reserve(bytes) {
            Ok(permit) => return Ok(permit),
            Err(refused) if refused.exceeds_budget() || Instant::now() >= deadline => return Err(refused),
            Err(_) => sleep(ADMISSION_RETRY).await,
        }
    }
}

#[derive(Serialize)]
struct Command<'a> {
    id: u64,
    method: &'a str,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    params: &'a Value,
}

/// Serializes into memory reserved ahead of every growth step.
struct AdmittedWriter {
    buf: Vec<u8>,
    permit: BytePermit,
    limit: usize,
    refusal: Option<ByteAdmissionError>,
}

impl std::io::Write for AdmittedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let needed = self.buf.len().saturating_add(data.len());
        if needed > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command exceeds the frame limit",
            ));
        }
        if needed > self.buf.capacity() {
            let doubled = self.buf.capacity().saturating_mul(2).max(256);
            let target = std::cmp::min(self.limit, needed.max(doubled));
            if let Err(refused) = self.permit.grow_to(target) {
                self.refusal = Some(refused);
                return Err(std::io::Error::other(refused));
            }
            self.buf
                .try_reserve_exact(target - self.buf.len())
                .map_err(std::io::Error::other)?;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialize one command into admitted memory. `params` are consumed: their allocation ends
/// here and the admitted text carries the queue-resident bytes instead.
fn encode_command(
    budget: &Arc<ByteBudget>,
    limit: usize,
    id: u64,
    method: &str,
    session: Option<&str>,
    params: Value,
) -> Result<Budgeted<String>, BrowserError> {
    let mut writer = AdmittedWriter {
        buf: Vec::new(),
        permit: budget.try_reserve(0).map_err(BrowserError::Memory)?,
        limit,
        refusal: None,
    };
    let command = Command {
        id,
        method,
        session_id: session,
        params: &params,
    };
    let written = serde_json::to_writer(&mut writer, &command);
    drop(params);
    if let Err(error) = written {
        return Err(writer.refusal.map_or_else(
            || BrowserError::Transport(error.to_string()),
            BrowserError::Memory,
        ));
    }
    let AdmittedWriter { buf, permit, .. } = writer;
    let text = String::from_utf8(buf).map_err(|e| BrowserError::Transport(e.to_string()))?;
    Ok(Budgeted::new(text, permit))
}

/// Serialize `value` to JSON bytes that carry their own reservation, reserved ahead of every
/// growth step.
///
/// # Errors
/// [`BrowserError::Memory`] when the bytes are not admitted, [`BrowserError::Script`] when
/// serialization fails.
pub(crate) fn to_admitted_json(
    budget: &Arc<ByteBudget>,
    value: &Value,
) -> Result<AdmittedBytes, BrowserError> {
    let mut writer = AdmittedWriter {
        buf: Vec::new(),
        permit: budget.try_reserve(0).map_err(BrowserError::Memory)?,
        limit: usize::MAX,
        refusal: None,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return Err(writer
            .refusal
            .map_or_else(|| BrowserError::Script(error.to_string()), BrowserError::Memory));
    }
    let AdmittedWriter { buf, mut permit, .. } = writer;
    if buf.capacity() > permit.bytes() {
        if let Err(refused) = permit.grow_to(buf.capacity()) {
            drop(buf);
            drop(permit);
            return Err(BrowserError::Memory(refused));
        }
    }
    Ok(AdmittedBytes::new(buf, permit))
}

/// Decode the base64 `data` of a command result into bytes that carry their own reservation,
/// reserved before the output buffer is allocated.
///
/// # Errors
/// [`BrowserError::Memory`] when the decoded size is not admitted,
/// [`BrowserError::Protocol`] (naming `method`) when `data` is not valid base64.
pub(crate) fn decode_admitted_base64(
    budget: &Arc<ByteBudget>,
    method: &str,
    data: &str,
) -> Result<AdmittedBytes, BrowserError> {
    use base64::Engine as _;
    let estimate = base64::decoded_len_estimate(data.len());
    let permit = budget.try_reserve(estimate).map_err(BrowserError::Memory)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(estimate)
        .map_err(|e| BrowserError::Io(e.to_string()))?;
    base64::engine::general_purpose::STANDARD
        .decode_vec(data, &mut bytes)
        .map_err(|e| BrowserError::Protocol {
            method: method.to_owned(),
            message: e.to_string(),
        })?;
    Ok(AdmittedBytes::new(bytes, permit))
}

struct Call {
    method: String,
    id: u64,
    /// Decoded-size cap of a plain call's reply; `None` for budgeted calls.
    cap: Option<usize>,
    wire: Budgeted<String>,
    reply: oneshot::Sender<Reply>,
}

/// Shared handle to one DevTools WebSocket connection.
#[derive(Clone)]
pub struct CdpClient {
    tx: mpsc::Sender<Call>,
    events: broadcast::Sender<Arc<CdpEvent>>,
    transcript: Arc<Mutex<VecDeque<String>>>,
    calls: Arc<AtomicU64>,
    ids: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    budget: Arc<ByteBudget>,
    limit: usize,
}

impl CdpClient {
    /// Connect to the browser endpoint (`ws://127.0.0.1:<port>/devtools/browser/<id>`) with
    /// a command queue of [`COMMAND_QUEUE`] entries, charging the shared
    /// [`parser_memory::global`] budget.
    ///
    /// # Errors
    /// Returns [`BrowserError::Transport`] if the WebSocket connection cannot be established
    /// (or the endpoint is not plaintext `ws://`) and [`BrowserError::Memory`] when the
    /// connection's buffers cannot be admitted.
    pub async fn connect(ws_url: &str) -> Result<Self, BrowserError> {
        Self::connect_with_queue(ws_url, COMMAND_QUEUE).await
    }

    /// [`Self::connect`] with an explicit command-queue capacity (`0` is treated as `1`).
    ///
    /// # Errors
    /// Same as [`Self::connect`].
    pub async fn connect_with_queue(ws_url: &str, queue: usize) -> Result<Self, BrowserError> {
        Self::connect_with_budget(ws_url, queue, parser_memory::global()).await
    }

    /// [`Self::connect_with_queue`] charging `budget` instead of the process-wide one.
    ///
    /// # Errors
    /// Same as [`Self::connect`].
    pub async fn connect_with_budget(
        ws_url: &str,
        queue: usize,
        budget: &Arc<ByteBudget>,
    ) -> Result<Self, BrowserError> {
        Self::connect_bounded(ws_url, queue, MAX_FRAME_BYTES, budget).await
    }

    async fn connect_bounded(
        ws_url: &str,
        queue: usize,
        limit: usize,
        budget: &Arc<ByteBudget>,
    ) -> Result<Self, BrowserError> {
        let transport = |error: &dyn std::fmt::Display| BrowserError::Transport(error.to_string());
        let request = ws_url.into_client_request().map_err(|e| transport(&e))?;
        let uri = request.uri();
        if uri.scheme_str() != Some("ws") {
            return Err(BrowserError::Transport(
                "only plaintext ws:// DevTools endpoints are supported".to_owned(),
            ));
        }
        let host = uri
            .host()
            .ok_or_else(|| BrowserError::Transport("DevTools endpoint has no host".to_owned()))?;
        let address = format!("{host}:{}", uri.port_u16().unwrap_or(80));
        let tcp = TcpStream::connect(address).await.map_err(|e| transport(&e))?;
        let baseline = budget
            .try_reserve(TRANSPORT_BASELINE)
            .map_err(BrowserError::Memory)?;
        let admission = meter::Admission::new(budget, limit, ADMISSION_WAIT);
        let stream = meter::FrameMeter::new(tcp, Arc::clone(&admission));
        let config = WebSocketConfig::default()
            .max_frame_size(Some(limit))
            .max_message_size(Some(limit))
            .read_buffer_size(TRANSPORT_BUFFER)
            .write_buffer_size(TRANSPORT_BUFFER);
        let (conn, _) = tokio_tungstenite::client_async_with_config(request, stream, Some(config))
            .await
            .map_err(|e| transport(&e))?;
        let capacity = queue.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        let closed = Arc::new(AtomicBool::new(false));
        let link = Link {
            budget: Arc::clone(budget),
            admission,
            max_pending: capacity,
        };
        tokio::spawn(drive(
            conn,
            rx,
            events.clone(),
            Arc::clone(&closed),
            link,
            baseline,
        ));
        Ok(Self {
            tx,
            events,
            transcript: Arc::new(Mutex::new(VecDeque::new())),
            calls: Arc::new(AtomicU64::new(0)),
            ids: Arc::new(AtomicU64::new(0)),
            closed,
            budget: Arc::clone(budget),
            limit,
        })
    }

    /// The budget this connection charges; producers reserve against it before they copy a
    /// result they retain.
    #[must_use]
    pub fn budget(&self) -> &Arc<ByteBudget> {
        &self.budget
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
    /// The returned value is not charged to the budget once this returns; see the module
    /// documentation and [`Self::call_budgeted`].
    ///
    /// # Errors
    /// Returns [`BrowserError::TargetClosed`] if the connection is closed or closes before the
    /// reply, [`BrowserError::Timeout`] after [`COMMAND_TIMEOUT`], [`BrowserError::Transport`] if
    /// the command cannot be sent, [`BrowserError::Memory`] if byte admission refused the
    /// command or its reply, and [`BrowserError::Protocol`] if the browser answers with an
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
        let reply = self
            .exchange(method, session, params, timeout, Some(METADATA_REPLY_LIMIT))
            .await?;
        // The caller takes the bare value, so its reply was capped at the metadata limit: it is
        // small by construction. Its reservation ends here (module documentation).
        let (value, permit) = reply.into_parts();
        drop(permit);
        Ok(value)
    }

    /// [`Self::call`] that keeps the result charged: the reservation covering the decoded
    /// value travels with it and is released when the [`Budgeted`] drops.
    ///
    /// # Errors
    /// Same as [`Self::call`].
    pub async fn call_budgeted(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
    ) -> Result<Budgeted<Value>, BrowserError> {
        self.call_budgeted_with_timeout(method, session, params, COMMAND_TIMEOUT)
            .await
    }

    /// [`Self::call_budgeted`] with an explicit timeout. A reply that arrives after the
    /// caller gave up is dropped by the driver together with its reservation.
    ///
    /// # Errors
    /// Same as [`Self::call`], except [`BrowserError::Timeout`] fires after `timeout`.
    pub async fn call_budgeted_with_timeout(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
        timeout: Duration,
    ) -> Result<Budgeted<Value>, BrowserError> {
        self.exchange(method, session, params, timeout, None).await
    }

    async fn exchange(
        &self,
        method: &str,
        session: Option<&str>,
        params: Value,
        timeout: Duration,
        cap: Option<usize>,
    ) -> Result<Budgeted<Value>, BrowserError> {
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
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        // The command is serialized by the caller into reserved memory; the queue holds
        // admitted text, not the caller's params.
        let wire = encode_command(&self.budget, self.limit, id, method, session, params)?;
        let (reply, rx) = oneshot::channel();
        let call = Call {
            method: method.to_owned(),
            id,
            cap,
            wire,
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

/// What the driver needs besides the socket.
struct Link {
    budget: Arc<ByteBudget>,
    admission: Arc<meter::Admission>,
    /// Most unanswered commands the driver keeps; the bounded queue backs the rest up.
    max_pending: usize,
}

/// Write one admitted command. `false` ends the connection.
async fn transmit(conn: &mut Conn, link: &Link, pending: &mut Pending, call: Call) -> bool {
    let Call {
        method,
        id,
        cap,
        wire,
        reply,
    } = call;
    let (text, mut permit) = wire.into_parts();
    // the codec copies the frame into its own write buffer
    match admit(&link.budget, text.len(), ADMISSION_WAIT).await {
        Ok(copy) => {
            // same budget: merging only fails on arithmetic overflow, which dropping handles
            let _ = permit.merge(copy);
        }
        Err(refused) => {
            let _ = reply.send(Err(BrowserError::Memory(refused)));
            return true;
        }
    }
    let sent = tokio::time::timeout(COMMAND_TIMEOUT, conn.send(WsMessage::Text(text.into()))).await;
    drop(permit);
    match sent {
        Ok(Ok(())) => {
            pending.insert(id, (method, cap, reply));
            true
        }
        result => {
            let error = match result {
                Ok(Err(error)) => BrowserError::Transport(error.to_string()),
                _ => BrowserError::Timeout(30_000),
            };
            let _ = reply.send(Err(error));
            false
        }
    }
}

/// Refuse one inbound frame whose decode bytes were not admitted: answer the command it
/// belongs to, or drop the event.
fn refuse(pending: &mut Pending, text: &str, refused: ByteAdmissionError) {
    match response_id(text).and_then(|id| pending.remove(&id)) {
        Some((_, _, reply)) => {
            let _ = reply.send(Err(BrowserError::Memory(refused)));
        }
        None => tracing::warn!(
            requested = refused.requested,
            available = refused.available,
            "CDP event dropped: byte admission refused"
        ),
    }
}

/// Decode one admitted text frame and route it. The frame's own bytes (`wire`) are released
/// as soon as the value exists; the value's reservation moves to its owner.
async fn dispatch(
    link: &Link,
    wire: Budgeted<Utf8Bytes>,
    pending: &mut Pending,
    events: &broadcast::Sender<Arc<CdpEvent>>,
) {
    let text = wire.value().as_str();
    let cost = decode_cost(text);
    // A plain call hands the caller a bare `Value` that outlives its reservation, so its reply
    // is held to the metadata cap; replies that may be larger use the budgeted calls.
    let cap = response_id(text)
        .and_then(|id| pending.get(&id))
        .and_then(|(_, cap, _)| *cap);
    if let Some(cap) = cap {
        // a throwaway budget of exactly `cap` bytes yields the typed refusal
        if let Err(refused) = Arc::new(ByteBudget::new(cap)).try_reserve(cost.value) {
            refuse(pending, text, refused);
            return;
        }
    }
    let mut permit = match admit(
        &link.budget,
        cost.value.saturating_add(cost.scratch),
        ADMISSION_WAIT,
    )
    .await
    {
        Ok(permit) => permit,
        Err(refused) => {
            refuse(pending, text, refused);
            return;
        }
    };
    let parsed = serde_json::from_str::<Value>(text).and_then(frame_from_value);
    drop(wire);
    if let Ok(scratch) = permit.split(cost.scratch) {
        drop(scratch);
    }
    match parsed {
        Err(error) => tracing::debug!(%error, "ignoring undecodable CDP message"),
        Ok(CdpFrame::Response { id, outcome }) => {
            if let Some((method, _, reply)) = pending.remove(&id) {
                let out = match outcome {
                    Err(error) => Err(BrowserError::Protocol {
                        method,
                        message: error.message,
                    }),
                    Ok(value) => Ok(Budgeted::new(value, permit)),
                };
                // a caller that already gave up drops the value, then its permit
                let _ = reply.send(out);
            }
        }
        Ok(CdpFrame::Event(mut event)) => {
            event.charge = Some(permit);
            let _ = events.send(Arc::new(event));
        }
    }
}

async fn drive(
    mut conn: Conn,
    mut rx: mpsc::Receiver<Call>,
    events: broadcast::Sender<Arc<CdpEvent>>,
    closed: Arc<AtomicBool>,
    link: Link,
    _baseline: BytePermit,
) {
    let mut pending = Pending::new();
    // A timed-out caller no longer owns its reply. Do not retain its method indefinitely
    // when Chromium never answers (for example, an evaluation awaiting a page promise).
    loop {
        pending.retain(|_, (_, _, reply)| !reply.is_closed());
        tokio::select! {
            call = rx.recv(), if pending.len() < link.max_pending => match call {
                Some(call) => {
                    if !transmit(&mut conn, &link, &mut pending, call).await {
                        break;
                    }
                }
                // No client can consume any pending reply once every sender is gone.
                None => break,
            },
            // Abandoned calls free their pending slot even while the browser stays silent.
            () = sleep(ADMISSION_RETRY * 25), if pending.len() >= link.max_pending => {}
            msg = conn.next() => match msg {
                Some(Ok(message)) => {
                    // every message, control frames included, owns the bytes admitted for its frames
                    let Ok(permit) = link.admission.take_message() else { break };
                    match message {
                        WsMessage::Text(text) => {
                            dispatch(&link, Budgeted::new(text, permit), &mut pending, &events).await;
                        }
                        WsMessage::Ping(_) | WsMessage::Pong(_) => drop(permit),
                        WsMessage::Close(_) => break,
                        _ => {
                            tracing::debug!("unexpected binary CDP message");
                            break;
                        }
                    }
                }
                Some(Err(error)) => {
                    // Transport limits, admission refusals and I/O failures close the driver
                    // and release every pending reply, rather than leaving calls to time out.
                    tracing::debug!(%error, "CDP transport closed");
                    break;
                }
                None => break,
            },
        }
    }
    closed.store(true, Ordering::Release);
    let refusal = link.admission.refusal();
    for (_, (_, _, reply)) in pending.drain() {
        let _ = reply.send(Err(
            refusal.map_or(BrowserError::TargetClosed, BrowserError::Memory)
        ));
    }
    // wake event consumers so they can observe the closure
    let _ = events.send(Arc::new(CdpEvent {
        method: "crawlx.connectionClosed".to_owned(),
        session_id: None,
        params: Value::Null,
        charge: None,
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
        // The response stays charged while the typed nodes are built from it, without a
        // second copy of the JSON tree; only the (smaller, field-subset) typed nodes outlive it.
        let reply = self.send_budgeted("Accessibility.getFullAXTree", params).await?;
        let nodes = reply.value().get("nodes").unwrap_or(&Value::Null);
        Vec::<RawAxNode>::deserialize(nodes).map_err(|e| BrowserError::Protocol {
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

    /// `DOMSnapshot.captureSnapshot` with the styles and rects the discovery ladder needs. The
    /// result stays charged to the budget until the caller drops it.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call_budgeted`] errors.
    pub async fn dom_snapshot(&self) -> Result<Budgeted<Value>, BrowserError> {
        self.send_budgeted(
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

    /// [`Self::evaluate_in`] returning the whole `Runtime.evaluate` response, still charged to
    /// the budget, for results the caller retains. The caller reads `exceptionDetails` and
    /// `result.value` itself, moving large strings out instead of cloning them.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call_budgeted`] errors.
    pub async fn evaluate_in_budgeted(
        &self,
        context_id: i64,
        expression: &str,
        await_promise: bool,
    ) -> Result<Budgeted<Value>, BrowserError> {
        self.send_budgeted(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "contextId": context_id,
                "returnByValue": true,
                "awaitPromise": await_promise,
            }),
        )
        .await
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

    /// [`Self::send`] that keeps the result charged to the budget while the caller holds it.
    ///
    /// # Errors
    /// Returns the [`CdpClient::call_budgeted`] errors.
    pub async fn send_budgeted(&self, method: &str, params: Value) -> Result<Budgeted<Value>, BrowserError> {
        self.client
            .call_budgeted(method, Some(&self.session_id), params)
            .await
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
                CdpClient::connect_bounded(&endpoint, 1, 1024, parser_memory::global())
                    .await
                    .unwrap()
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

    /// A loopback DevTools peer: reads `commands` commands, reports each id on `seen`, waits for
    /// the gate, answers every command with `pad` bytes of result, then emits one event.
    async fn peer(pad: usize, commands: usize) -> (String, oneshot::Sender<()>, mpsc::Receiver<u64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("ws://{}", listener.local_addr().unwrap());
        let (gate, gated) = oneshot::channel::<()>();
        let (seen_tx, seen) = mpsc::channel(commands.max(1));
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut ids = Vec::new();
            for _ in 0..commands {
                let message = socket.next().await.unwrap().unwrap();
                let command: Value = serde_json::from_str(message.to_text().unwrap()).unwrap();
                let id = command["id"].as_u64().unwrap();
                ids.push(id);
                let _ = seen_tx.send(id).await;
            }
            let _ = gated.await;
            for id in ids {
                let reply = json!({ "id": id, "result": { "pad": "x".repeat(pad) } });
                socket
                    .send(WsMessage::Text(reply.to_string().into()))
                    .await
                    .unwrap();
            }
            let event = json!({ "method": "Page.frameStoppedLoading", "params": { "n": 1 } });
            socket
                .send(WsMessage::Text(event.to_string().into()))
                .await
                .unwrap();
            while socket.next().await.is_some() {}
        });
        (endpoint, gate, seen)
    }

    async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let waited = tokio::time::timeout(Duration::from_secs(10), async {
            while !done() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "timed out waiting for {what}");
    }

    #[tokio::test]
    async fn reply_above_the_budget_is_refused_from_its_header() {
        let budget = Arc::new(ByteBudget::new(TRANSPORT_BASELINE + 128 * 1024));
        let (endpoint, gate, mut seen) = peer(150_000, 1).await;
        let client = CdpClient::connect_with_budget(&endpoint, 4, &budget)
            .await
            .unwrap();
        let release = async {
            seen.recv().await.unwrap();
            let _ = gate.send(());
        };
        let (result, ()) = tokio::join!(
            client.call_with_timeout("Browser.getVersion", None, json!({}), Duration::from_secs(10)),
            release
        );
        match result {
            Err(BrowserError::Memory(refused)) => assert!(refused.exceeds_budget(), "{refused:?}"),
            other => panic!("{other:?}"),
        }
        assert!(client.is_closed());
        drop(client);
        wait_until("the driver to release the connection", || budget.used() == 0).await;
    }

    #[tokio::test]
    async fn concurrent_replies_stay_charged_until_each_caller_drops_its_result() {
        let budget = Arc::new(ByteBudget::new(64 * 1024 * 1024));
        let (endpoint, gate, mut seen) = peer(20_000, 2).await;
        let client = CdpClient::connect_with_budget(&endpoint, 4, &budget)
            .await
            .unwrap();
        let baseline = budget.used();
        let mut events = client.subscribe();
        let release = async {
            seen.recv().await.unwrap();
            seen.recv().await.unwrap();
            let _ = gate.send(());
        };
        let (first, second, ()) = tokio::join!(
            client.call_budgeted("Browser.getVersion", None, json!({})),
            client.call_budgeted("Browser.getVersion", None, json!({})),
            release
        );
        let (first, second) = (first.unwrap(), second.unwrap());
        // the peer's closing event proves all traffic was processed; release it before measuring
        while events.recv().await.unwrap().method != "Page.frameStoppedLoading" {}
        assert_eq!(first.value()["pad"].as_str().unwrap().len(), 20_000);
        let both = budget.used();
        assert!(both >= baseline + 2 * 20_000, "{both} vs {baseline}");
        drop(first);
        let one = budget.used();
        assert!(one >= baseline + 20_000 && one < both, "{one} vs {both}");
        drop(second);
        assert_eq!(budget.used(), baseline);
    }

    #[tokio::test]
    async fn abandoned_call_and_event_release_only_after_their_bytes_drop() {
        let budget = Arc::new(ByteBudget::new(64 * 1024 * 1024));
        let (endpoint, gate, mut seen) = peer(20_000, 1).await;
        let client = CdpClient::connect_with_budget(&endpoint, 4, &budget)
            .await
            .unwrap();
        let baseline = budget.used();
        let mut events = client.subscribe();
        let abandoned = client
            .call_budgeted_with_timeout("Browser.getVersion", None, json!({}), Duration::from_millis(100))
            .await;
        assert!(
            matches!(abandoned, Err(BrowserError::Timeout(_))),
            "{abandoned:?}"
        );
        seen.recv().await.unwrap();
        assert_eq!(
            budget.used(),
            baseline,
            "the command's reservation ends with its transmission"
        );
        let _ = gate.send(());
        // the late reply is dropped by the driver with its reservation; the event after it
        // proves the reply was processed, and stays charged while a consumer holds it
        let done = loop {
            let event = events.recv().await.unwrap();
            if event.method == "Page.frameStoppedLoading" {
                break event;
            }
        };
        assert!(done.charge.as_ref().is_some_and(|charge| charge.bytes() > 0));
        assert!(budget.used() > baseline);
        drop(done);
        wait_until("the event's reservation", || budget.used() == baseline).await;
    }

    #[tokio::test]
    async fn plain_call_refuses_a_reply_above_the_metadata_cap_but_budgeted_call_keeps_it_charged() {
        let budget = Arc::new(ByteBudget::new(64 * 1024 * 1024));
        let (endpoint, gate, mut seen) = peer(METADATA_REPLY_LIMIT + 4096, 2).await;
        let client = CdpClient::connect_with_budget(&endpoint, 4, &budget)
            .await
            .unwrap();
        let release = async {
            seen.recv().await.unwrap();
            seen.recv().await.unwrap();
            let _ = gate.send(());
        };
        let (plain, charged, ()) = tokio::join!(
            client.call("Browser.getVersion", None, json!({})),
            client.call_budgeted("Browser.getVersion", None, json!({})),
            release
        );
        match plain {
            Err(BrowserError::Memory(refused)) => assert!(refused.exceeds_budget(), "{refused:?}"),
            other => panic!("{other:?}"),
        }
        let charged = charged.unwrap();
        assert!(
            budget.used() >= METADATA_REPLY_LIMIT,
            "the large reply stays charged while held"
        );
        drop(charged);
    }

    #[test]
    fn decode_cost_bounds_the_decoded_tree() {
        let text = r#"{"id":1,"result":{"a":[1,2,3],"b":"xy\"z"}}"#;
        let cost = decode_cost(text);
        assert!(cost.value >= text.len() + 5 * ELEMENT_BYTES, "{cost:?}");
        assert!(cost.scratch >= 2 * 4, "{cost:?}");
        assert_eq!(response_id(text), Some(1));
        assert_eq!(response_id(r#"{"method":"M"}"#), None);
    }

    #[test]
    fn command_serialization_is_admitted_before_it_grows() {
        let budget = Arc::new(ByteBudget::new(512));
        let big = json!({ "expression": "x".repeat(4096) });
        match encode_command(&budget, MAX_FRAME_BYTES, 1, "Runtime.evaluate", Some("S1"), big) {
            Err(BrowserError::Memory(refused)) => assert!(refused.exceeds_budget()),
            other => panic!("{other:?}"),
        }
        assert_eq!(budget.used(), 0);
        let small =
            encode_command(&budget, MAX_FRAME_BYTES, 7, "Page.enable", Some("S1"), json!({})).unwrap();
        let text: Value = serde_json::from_str(small.value()).unwrap();
        assert_eq!(text["id"], 7);
        assert_eq!(text["sessionId"], "S1");
        assert!(budget.used() > 0);
        drop(small);
        assert_eq!(budget.used(), 0);
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
