//! HTTP traffic export (katana `KATANA_TRAFFIC_*`, `pkg/output/export/export.go`, MIT).
//!
//! A [`TrafficExporter`] forwards every observed HTTP exchange to a collector as batched JSON
//! `POST`s. Recording never blocks the crawl: an exchange is encoded on the caller's thread and
//! queued on a bounded channel; one background task batches the queue and posts it. When the
//! queue is full the exchange is dropped and counted ([`TrafficStats::dropped`]).
//!
//! Configuration is operator-level, never from crawled content or API requests
//! ([`TrafficExportConfig::from_env`]):
//!
//! | variable | meaning |
//! |---|---|
//! | `CRAWLX_TRAFFIC_ENDPOINT` | collector URL; `https`, or `http` for a loopback host or with `ALLOW_INSECURE`; no credentials, query or fragment in it |
//! | `CRAWLX_TRAFFIC_TOKEN` | bearer token sent as `Authorization: Bearer <token>`; both endpoint and token are required |
//! | `CRAWLX_TRAFFIC_ATTRIBUTES` | JSON object of string values added to every event (keys `[a-z][a-z0-9_]{0,63}`, at most 32, values at most 1024 bytes) |
//! | `CRAWLX_TRAFFIC_ALLOW_INSECURE` | `1` allows plain `http` to a non-loopback host |
//! | `CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS` | `1` exports credential headers; otherwise they are dropped |
//!
//! Safety properties kept from katana: redirects are never followed (a redirect would resend the
//! bearer token), the `HTTP_PROXY` environment is ignored (the token must not travel through an
//! inherited proxy), a batch is retried on network errors, `429` and `5xx` with the configured
//! delays and dropped otherwise, shutdown waits at most `drain_timeout` for queued events.
//!
//! Differences from katana: credential headers (`authorization`, `proxy-authorization`,
//! `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`) are
//! removed rather than replaced by `[REDACTED]`; an exchange that got no response is exported
//! with its `error` and `response.status` 0 instead of being skipped; events carry the
//! `plane` (`url` or `browser`) that produced them and `process` is `crawlx`.
//!
//! The collector is trusted operator configuration and is reached directly, not through the
//! egress policy that guards crawled targets.

use crawlx_core::Timestamp;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

/// Environment variable: collector URL.
pub const ENV_ENDPOINT: &str = "CRAWLX_TRAFFIC_ENDPOINT";
/// Environment variable: bearer token.
pub const ENV_TOKEN: &str = "CRAWLX_TRAFFIC_TOKEN";
/// Environment variable: JSON object of static event attributes.
pub const ENV_ATTRIBUTES: &str = "CRAWLX_TRAFFIC_ATTRIBUTES";
/// Environment variable: `1` allows plain `http` to a non-loopback collector.
pub const ENV_ALLOW_INSECURE: &str = "CRAWLX_TRAFFIC_ALLOW_INSECURE";
/// Environment variable: `1` exports credential headers.
pub const ENV_INCLUDE_CREDENTIALS: &str = "CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS";

/// Capacity of the queue between [`TrafficExporter::record`] and the sender task.
const QUEUE_SIZE: usize = 2048;
/// A batch is posted early once its events add up to this many bytes (common request body
/// limits of collectors and proxies).
const MAX_BATCH_BYTES: usize = 1 << 20;
/// Longest body preview in bytes.
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Most static attributes.
const MAX_ATTRIBUTES: usize = 32;
/// Longest static attribute value in bytes.
const MAX_ATTRIBUTE_VALUE: usize = 1024;
/// Timeout of one POST.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Header names whose values are credentials.
const CREDENTIAL_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
];
/// Event keys owned by the exporter; attributes may not use them.
const RESERVED_KEYS: [&str; 9] = [
    "id",
    "timestamp",
    "captured_at",
    "source_type",
    "process",
    "plane",
    "request",
    "response",
    "error",
];

/// Why a traffic exporter cannot be configured or built.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrafficExportError {
    /// Only one of the endpoint and the token variables is set.
    #[error("both {ENV_ENDPOINT} and {ENV_TOKEN} are required")]
    IncompleteEnv,
    /// The endpoint cannot be used; the text says why.
    #[error("invalid traffic export endpoint: {0}")]
    InvalidEndpoint(&'static str),
    /// `CRAWLX_TRAFFIC_ATTRIBUTES` is not a JSON object of string values.
    #[error("{ENV_ATTRIBUTES} must be a JSON object of string values")]
    AttributesJson(#[source] serde_json::Error),
    /// An attribute key is malformed or reserved.
    #[error("invalid traffic export attribute `{0}`")]
    InvalidAttribute(String),
    /// More than the allowed number of attributes.
    #[error("at most {MAX_ATTRIBUTES} traffic export attributes are allowed")]
    TooManyAttributes,
    /// An attribute value is longer than the allowed length.
    #[error("traffic export attribute `{0}` exceeds {MAX_ATTRIBUTE_VALUE} bytes")]
    AttributeTooLong(String),
    /// The token cannot be sent in a header.
    #[error("the traffic export token is not a valid header value")]
    InvalidToken,
    /// The HTTP client could not be built.
    #[error("building the traffic export HTTP client")]
    Client(#[source] reqwest::Error),
}

/// Configuration of a [`TrafficExporter`].
#[derive(Clone)]
#[non_exhaustive]
pub struct TrafficExportConfig {
    /// The collector URL.
    pub endpoint: Url,
    /// Bearer token; never shown by `Debug`.
    pub token: Option<String>,
    /// Static attributes added to every event.
    pub attributes: BTreeMap<String, String>,
    /// Allow plain `http` to a non-loopback endpoint.
    pub allow_insecure: bool,
    /// Export credential headers instead of dropping them.
    pub include_credentials: bool,
    /// Post as soon as this many events are queued (at least 1).
    pub batch_size: usize,
    /// Post a partial batch after this long.
    pub flush_interval: Duration,
    /// Delays between the attempts at one batch; its length is the retry count.
    pub retry_delays: Vec<Duration>,
    /// How long [`TrafficExporter::shutdown`] waits for queued events before abandoning them.
    pub drain_timeout: Duration,
}

impl fmt::Debug for TrafficExportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafficExportConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("attributes", &self.attributes)
            .field("allow_insecure", &self.allow_insecure)
            .field("include_credentials", &self.include_credentials)
            .field("batch_size", &self.batch_size)
            .field("flush_interval", &self.flush_interval)
            .field("retry_delays", &self.retry_delays)
            .field("drain_timeout", &self.drain_timeout)
            .finish()
    }
}

impl TrafficExportConfig {
    /// A configuration for `endpoint` with katana's defaults: batches of 100, a one second
    /// flush interval, retries after 1 s, 2 s and 4 s, a 10 s drain timeout, credentials
    /// dropped, no token and no attributes.
    #[must_use]
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            token: None,
            attributes: BTreeMap::new(),
            allow_insecure: false,
            include_credentials: false,
            batch_size: 100,
            flush_interval: Duration::from_secs(1),
            retry_delays: vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
            ],
            drain_timeout: Duration::from_secs(10),
        }
    }

    /// Read the `CRAWLX_TRAFFIC_*` variables through `get`. `Ok(None)` when neither the endpoint
    /// nor the token is set (export off). The endpoint is checked when the exporter is built
    /// ([`TrafficExporter::new`]).
    ///
    /// # Errors
    /// [`TrafficExportError::IncompleteEnv`] when only one of endpoint and token is set,
    /// [`TrafficExportError::InvalidEndpoint`] when the endpoint is not a URL,
    /// [`TrafficExportError::AttributesJson`] when the attributes are not a JSON object of
    /// strings.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, TrafficExportError> {
        let value = |key: &str| get(key).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        let (endpoint, token) = match (value(ENV_ENDPOINT), value(ENV_TOKEN)) {
            (None, None) => return Ok(None),
            (Some(endpoint), Some(token)) => (endpoint, token),
            _ => return Err(TrafficExportError::IncompleteEnv),
        };
        let endpoint = Url::parse(&endpoint).map_err(|_| TrafficExportError::InvalidEndpoint("not a URL"))?;
        let attributes = match value(ENV_ATTRIBUTES) {
            Some(raw) => serde_json::from_str::<BTreeMap<String, String>>(&raw)
                .map_err(TrafficExportError::AttributesJson)?,
            None => BTreeMap::new(),
        };
        let mut config = Self::new(endpoint);
        config.token = Some(token);
        config.attributes = attributes;
        config.allow_insecure = value(ENV_ALLOW_INSECURE).as_deref() == Some("1");
        config.include_credentials = value(ENV_INCLUDE_CREDENTIALS).as_deref() == Some("1");
        Ok(Some(config))
    }

    fn validate(&self) -> Result<(), TrafficExportError> {
        validate_endpoint(&self.endpoint, self.allow_insecure)?;
        validate_attributes(&self.attributes)?;
        if let Some(token) = &self.token {
            HeaderValue::from_str(token).map_err(|_| TrafficExportError::InvalidToken)?;
        }
        Ok(())
    }
}

fn validate_endpoint(endpoint: &Url, allow_insecure: bool) -> Result<(), TrafficExportError> {
    let Some(host) = endpoint.host() else {
        return Err(TrafficExportError::InvalidEndpoint("missing host"));
    };
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(TrafficExportError::InvalidEndpoint(
            "cannot contain credentials, query or fragment",
        ));
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match host {
                Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
            };
            if allow_insecure || loopback {
                Ok(())
            } else {
                Err(TrafficExportError::InvalidEndpoint(
                    "plain http is allowed only for a loopback host unless allow_insecure is set",
                ))
            }
        }
        _ => Err(TrafficExportError::InvalidEndpoint("must use http or https")),
    }
}

fn attribute_key_ok(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && key.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn validate_attributes(attributes: &BTreeMap<String, String>) -> Result<(), TrafficExportError> {
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(TrafficExportError::TooManyAttributes);
    }
    for (key, value) in attributes {
        if RESERVED_KEYS.contains(&key.as_str()) || !attribute_key_ok(key) {
            return Err(TrafficExportError::InvalidAttribute(key.clone()));
        }
        if value.len() > MAX_ATTRIBUTE_VALUE {
            return Err(TrafficExportError::AttributeTooLong(key.clone()));
        }
    }
    Ok(())
}

/// One observed HTTP exchange. Build it with [`Exchange::new`] and the `with_*` methods.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Exchange {
    /// The plane that made the request: `url` or `browser`.
    pub plane: &'static str,
    /// When the request was made.
    pub timestamp: Timestamp,
    /// HTTP method.
    pub method: String,
    /// Request URL.
    pub url: String,
    /// Request headers.
    pub request_headers: BTreeMap<String, String>,
    /// Request body, when text.
    pub request_body: Option<String>,
    /// Response status; `0` when there was no response.
    pub status: u16,
    /// Response headers.
    pub response_headers: BTreeMap<String, String>,
    /// Response body, when text.
    pub response_body: Option<String>,
    /// Why there was no response.
    pub error: Option<String>,
}

impl Exchange {
    /// An exchange with no headers, bodies or error.
    #[must_use]
    pub fn new(
        plane: &'static str,
        timestamp: Timestamp,
        method: impl Into<String>,
        url: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            plane,
            timestamp,
            method: method.into(),
            url: url.into(),
            request_headers: BTreeMap::new(),
            request_body: None,
            status,
            response_headers: BTreeMap::new(),
            response_body: None,
            error: None,
        }
    }

    /// Set the request headers and body.
    #[must_use]
    pub fn with_request(mut self, headers: BTreeMap<String, String>, body: Option<String>) -> Self {
        self.request_headers = headers;
        self.request_body = body;
        self
    }

    /// Set the response headers and body.
    #[must_use]
    pub fn with_response(mut self, headers: BTreeMap<String, String>, body: Option<String>) -> Self {
        self.response_headers = headers;
        self.response_body = body;
        self
    }

    /// Mark the exchange as failed with `error`.
    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// What a [`TrafficExporter`] has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrafficStats {
    /// Events the collector accepted.
    pub sent: u64,
    /// Events lost: the queue was full, the exporter was shut down, a batch failed for good or
    /// was abandoned at the drain deadline.
    pub dropped: u64,
    /// Batches that failed for good.
    pub failed_batches: u64,
}

#[derive(Debug, Default)]
struct Counters {
    sent: AtomicU64,
    dropped: AtomicU64,
    failed_batches: AtomicU64,
}

enum Command {
    Event(String),
    Flush(oneshot::Sender<()>),
    Shutdown,
}

/// Forwards exchanges to a collector. Must be built inside a Tokio runtime.
#[derive(Debug)]
pub struct TrafficExporter {
    tx: mpsc::Sender<Command>,
    cancel: CancellationToken,
    task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    counters: Arc<Counters>,
    include_credentials: bool,
    attributes: Map<String, Value>,
    drain_timeout: Duration,
}

fn sha256_hex(text: &str) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(text.as_bytes()) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Katana's rule for bodies whose preview is worth sending.
fn is_textual(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return true;
    };
    if content_type.is_empty() {
        return true;
    }
    let lower = content_type.to_ascii_lowercase();
    [
        "text/",
        "json",
        "xml",
        "javascript",
        "graphql",
        "x-www-form-urlencoded",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Add `body_sha256`, `body_size` and the preview fields of `body` to `message`.
fn add_body(message: &mut Map<String, Value>, body: Option<&str>, textual: bool) {
    let Some(body) = body.filter(|b| !b.is_empty()) else {
        return;
    };
    message.insert("body_sha256".to_owned(), Value::from(sha256_hex(body)));
    message.insert("body_size".to_owned(), Value::from(body.len()));
    if !textual {
        message.insert("body_truncated".to_owned(), Value::Bool(true));
    } else if body.len() > MAX_BODY_BYTES {
        let mut end = MAX_BODY_BYTES;
        while !body.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        message.insert("body_preview".to_owned(), Value::from(&body[..end]));
        message.insert("body_truncated".to_owned(), Value::Bool(true));
    } else {
        message.insert("body_preview".to_owned(), Value::from(body));
    }
}

impl TrafficExporter {
    /// Validate `config` and start the sender task.
    ///
    /// # Errors
    /// [`TrafficExportError`] when the endpoint is not https (nor http to a loopback host, nor
    /// http with `allow_insecure`), carries credentials, a query or a fragment, when an
    /// attribute is invalid, when the token is not a valid header value, or when the HTTP client
    /// cannot be built.
    ///
    /// # Panics
    /// Never; but it spawns a Tokio task, so it must run inside a Tokio runtime.
    pub fn new(config: TrafficExportConfig) -> Result<Self, TrafficExportError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            // A redirect would resend the bearer token (even from https to http).
            .redirect(Policy::none())
            // The token must not travel through an inherited HTTP_PROXY.
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .user_agent("crawlx-traffic-export")
            .build()
            .map_err(TrafficExportError::Client)?;
        let (tx, rx) = mpsc::channel(QUEUE_SIZE);
        let cancel = CancellationToken::new();
        let counters = Arc::new(Counters::default());
        let attributes = config
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
            .collect();
        let sender = Sender {
            client,
            endpoint: config.endpoint.clone(),
            token: config.token.clone(),
            retry_delays: config.retry_delays.clone(),
            cancel: cancel.clone(),
            counters: Arc::clone(&counters),
        };
        let task = tokio::spawn(sender.run(rx, config.batch_size.max(1), config.flush_interval));
        Ok(Self {
            tx,
            cancel,
            task: parking_lot::Mutex::new(Some(task)),
            counters,
            include_credentials: config.include_credentials,
            attributes,
            drain_timeout: config.drain_timeout,
        })
    }

    fn headers(&self, headers: &BTreeMap<String, String>) -> Value {
        let map: Map<String, Value> = headers
            .iter()
            .filter(|(name, _)| {
                self.include_credentials || !CREDENTIAL_HEADERS.contains(&name.to_ascii_lowercase().as_str())
            })
            .map(|(name, value)| (name.clone(), Value::from(value.as_str())))
            .collect();
        Value::Object(map)
    }

    /// The JSON event of `exchange`.
    fn encode(&self, exchange: &Exchange) -> String {
        let content_type = exchange
            .response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str());
        let mut request = Map::new();
        request.insert("method".to_owned(), Value::from(exchange.method.as_str()));
        request.insert("full_url".to_owned(), Value::from(exchange.url.as_str()));
        request.insert("headers".to_owned(), self.headers(&exchange.request_headers));
        add_body(&mut request, exchange.request_body.as_deref(), true);
        let mut response = Map::new();
        response.insert("status".to_owned(), Value::from(exchange.status));
        if let Some(text) = http::StatusCode::from_u16(exchange.status)
            .ok()
            .and_then(|s| s.canonical_reason())
        {
            response.insert("status_text".to_owned(), Value::from(text));
        }
        if let Some(content_type) = content_type {
            response.insert("content_type".to_owned(), Value::from(content_type));
        }
        response.insert("headers".to_owned(), self.headers(&exchange.response_headers));
        add_body(
            &mut response,
            exchange.response_body.as_deref(),
            is_textual(content_type),
        );

        let mut event = Map::new();
        event.insert("id".to_owned(), Value::from(uuid::Uuid::now_v7().to_string()));
        event.insert(
            "timestamp".to_owned(),
            Value::from(
                exchange
                    .timestamp
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            ),
        );
        event.insert(
            "captured_at".to_owned(),
            Value::from(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
        );
        event.insert("source_type".to_owned(), Value::from("cli"));
        event.insert("process".to_owned(), Value::from("crawlx"));
        event.insert("plane".to_owned(), Value::from(exchange.plane));
        event.insert("request".to_owned(), Value::Object(request));
        event.insert("response".to_owned(), Value::Object(response));
        if let Some(error) = &exchange.error {
            event.insert("error".to_owned(), Value::from(error.as_str()));
        }
        for (key, value) in &self.attributes {
            event.insert(key.clone(), value.clone());
        }
        Value::Object(event).to_string()
    }

    /// Queue `exchange` for export. Never blocks and never fails: when the queue is full, or
    /// the exporter is shut down, the event is dropped and counted in
    /// [`TrafficStats::dropped`].
    pub fn record(&self, exchange: Exchange) {
        let event = self.encode(&exchange);
        if self.tx.try_send(Command::Event(event)).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Post everything recorded so far and wait until the collector answered (or the batch was
    /// given up on).
    pub async fn flush(&self) {
        let (reply, done) = oneshot::channel();
        if self.tx.send(Command::Flush(reply)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Flush and stop the sender task. Waits at most `drain_timeout` for queued events, then
    /// abandons what is left (counted as dropped). Calling it again does nothing.
    pub async fn shutdown(&self) {
        let Some(mut task) = self.task.lock().take() else {
            return;
        };
        let drained = tokio::time::timeout(self.drain_timeout, async {
            let _ = self.tx.send(Command::Shutdown).await;
            let _ = (&mut task).await;
        })
        .await;
        if drained.is_err() {
            tracing::warn!("traffic export did not drain before the deadline; abandoning queued events");
            self.cancel.cancel();
            let _ = task.await;
        }
    }

    /// What the exporter has delivered and lost so far.
    #[must_use]
    pub fn stats(&self) -> TrafficStats {
        TrafficStats {
            sent: self.counters.sent.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            failed_batches: self.counters.failed_batches.load(Ordering::Relaxed),
        }
    }
}

/// The sender task's state.
struct Sender {
    client: reqwest::Client,
    endpoint: Url,
    token: Option<String>,
    retry_delays: Vec<Duration>,
    cancel: CancellationToken,
    counters: Arc<Counters>,
}

impl Sender {
    async fn run(self, mut rx: mpsc::Receiver<Command>, batch_size: usize, flush_interval: Duration) {
        let mut batch: Vec<String> = Vec::with_capacity(batch_size);
        let mut bytes = 0usize;
        let mut ticker = tokio::time::interval(flush_interval.max(Duration::from_millis(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                command = rx.recv() => match command {
                    Some(Command::Event(event)) => {
                        bytes = bytes.saturating_add(event.len());
                        batch.push(event);
                        if batch.len() >= batch_size || bytes >= MAX_BATCH_BYTES {
                            self.post(&mut batch).await;
                            bytes = 0;
                        }
                    }
                    Some(Command::Flush(reply)) => {
                        self.post(&mut batch).await;
                        bytes = 0;
                        let _ = reply.send(());
                    }
                    Some(Command::Shutdown) | None => {
                        self.post(&mut batch).await;
                        break;
                    }
                },
                () = self.cancel.cancelled() => {
                    let lost = u64::try_from(batch.len()).unwrap_or(u64::MAX);
                    self.counters.dropped.fetch_add(lost, Ordering::Relaxed);
                    batch.clear();
                    break;
                }
                _ = ticker.tick() => {
                    self.post(&mut batch).await;
                    bytes = 0;
                }
            }
        }
        // Whatever is still queued was recorded after the shutdown request.
        rx.close();
        while let Some(command) = rx.recv().await {
            if matches!(command, Command::Event(_)) {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Post `batch` and empty it; counts the outcome.
    async fn post(&self, batch: &mut Vec<String>) {
        if batch.is_empty() {
            return;
        }
        let events = std::mem::take(batch);
        let count = u64::try_from(events.len()).unwrap_or(u64::MAX);
        let payload = format!(
            "{{\"batch_id\":\"{}\",\"events\":[{}]}}",
            uuid::Uuid::now_v7(),
            events.join(",")
        );
        match self.deliver(&payload).await {
            Ok(()) => {
                self.counters.sent.fetch_add(count, Ordering::Relaxed);
            }
            Err(error) => {
                self.counters.dropped.fetch_add(count, Ordering::Relaxed);
                self.counters.failed_batches.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, dropped = count, "traffic export batch failed");
            }
        }
    }

    /// POST with retries; the error text never contains the token or the payload.
    async fn deliver(&self, payload: &str) -> Result<(), String> {
        let mut attempt = 0usize;
        loop {
            if self.cancel.is_cancelled() {
                return Err("traffic export did not finish before the shutdown deadline".to_owned());
            }
            let (retryable, error) = tokio::select! {
                outcome = self.post_once(payload) => match outcome {
                    Ok(()) => return Ok(()),
                    Err(failure) => failure,
                },
                () = self.cancel.cancelled() => {
                    return Err("traffic export did not finish before the shutdown deadline".to_owned());
                }
            };
            let Some(delay) = self.retry_delays.get(attempt).copied().filter(|_| retryable) else {
                return Err(error);
            };
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = self.cancel.cancelled() => {
                    return Err("traffic export did not finish before the shutdown deadline".to_owned());
                }
            }
        }
    }

    /// One POST; the error says whether a retry makes sense.
    async fn post_once(&self, payload: &str) -> Result<(), (bool, String)> {
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(payload.to_owned());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|_| (true, "traffic export request failed".to_owned()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let retryable = status.as_u16() == 429 || status.is_server_error();
        Err((
            retryable,
            format!(
                "traffic collector rejected the batch with status {}",
                status.as_u16()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::HashMap;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn env_off_when_nothing_is_set_and_incomplete_when_half_set() {
        assert!(TrafficExportConfig::from_env(&env(&[])).unwrap().is_none());
        assert!(TrafficExportConfig::from_env(&env(&[(ENV_ENDPOINT, "  ")]))
            .unwrap()
            .is_none());
        for pairs in [[(ENV_ENDPOINT, "https://c.example/in")], [(ENV_TOKEN, "tok")]] {
            assert!(matches!(
                TrafficExportConfig::from_env(&env(&pairs)),
                Err(TrafficExportError::IncompleteEnv)
            ));
        }
    }

    #[test]
    fn env_reads_every_variable() {
        let cfg = TrafficExportConfig::from_env(&env(&[
            (ENV_ENDPOINT, "https://c.example/in"),
            (ENV_TOKEN, " tok "),
            (ENV_ATTRIBUTES, r#"{"team":"red","run":"7"}"#),
            (ENV_ALLOW_INSECURE, "1"),
            (ENV_INCLUDE_CREDENTIALS, "1"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.endpoint.as_str(), "https://c.example/in");
        assert_eq!(cfg.token.as_deref(), Some("tok"));
        assert_eq!(cfg.attributes["team"], "red");
        assert_eq!(cfg.attributes.len(), 2);
        assert!(cfg.allow_insecure && cfg.include_credentials);
        // anything but "1" is off
        let cfg = TrafficExportConfig::from_env(&env(&[
            (ENV_ENDPOINT, "https://c.example/in"),
            (ENV_TOKEN, "t"),
            (ENV_ALLOW_INSECURE, "true"),
        ]))
        .unwrap()
        .unwrap();
        assert!(!cfg.allow_insecure && !cfg.include_credentials);
        assert_eq!(cfg.batch_size, 100);
        assert_eq!(cfg.flush_interval, Duration::from_secs(1));
        assert!(matches!(
            TrafficExportConfig::from_env(&env(&[
                (ENV_ENDPOINT, "https://c.example/in"),
                (ENV_TOKEN, "t"),
                (ENV_ATTRIBUTES, "[1]"),
            ])),
            Err(TrafficExportError::AttributesJson(_))
        ));
        assert!(matches!(
            TrafficExportConfig::from_env(&env(&[(ENV_ENDPOINT, "not a url"), (ENV_TOKEN, "t")])),
            Err(TrafficExportError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn endpoint_rules() {
        let ok = |u: &str, insecure| validate_endpoint(&url(u), insecure).is_ok();
        assert!(ok("https://c.example/in", false));
        assert!(ok("http://127.0.0.1:9/in", false), "loopback may be plain http");
        assert!(ok("http://localhost/in", false));
        assert!(ok("http://[::1]:8080/in", false));
        assert!(!ok("http://c.example/in", false), "plain http to a remote host");
        assert!(ok("http://c.example/in", true), "unless allowed");
        assert!(!ok("ftp://c.example/in", true));
        assert!(!ok("https://user:pw@c.example/in", false));
        assert!(!ok("https://c.example/in?token=x", false));
        assert!(!ok("https://c.example/in#frag", false));
    }

    #[test]
    fn attribute_rules() {
        let attrs = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        assert!(validate_attributes(&attrs(&[("team", "red"), ("run_1", "x")])).is_ok());
        for bad in ["Team", "1a", "a-b", "", "id", "request", "plane", "error"] {
            assert!(
                matches!(
                    validate_attributes(&attrs(&[(bad, "x")])),
                    Err(TrafficExportError::InvalidAttribute(_))
                ),
                "{bad}"
            );
        }
        let long = "x".repeat(MAX_ATTRIBUTE_VALUE + 1);
        assert!(matches!(
            validate_attributes(&attrs(&[("a", long.as_str())])),
            Err(TrafficExportError::AttributeTooLong(_))
        ));
        let many: BTreeMap<String, String> = (0..=MAX_ATTRIBUTES)
            .map(|i| (format!("k{i}"), "v".to_owned()))
            .collect();
        assert!(matches!(
            validate_attributes(&many),
            Err(TrafficExportError::TooManyAttributes)
        ));
        assert!(validate_attributes(&attrs(&[(&"a".repeat(64), "v")])).is_ok());
        assert!(validate_attributes(&attrs(&[(&"a".repeat(65), "v")])).is_err());
    }

    #[test]
    fn debug_never_shows_the_token() {
        let mut cfg = TrafficExportConfig::new(url("https://c.example/in"));
        cfg.token = Some("super-secret-token".to_owned());
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("super-secret-token"), "{shown}");
        assert!(shown.contains("[redacted]"));
    }

    #[test]
    fn textual_rule_follows_katana() {
        for t in [
            "text/html",
            "application/json",
            "application/xml",
            "application/javascript",
            "application/graphql",
            "application/x-www-form-urlencoded",
            "TEXT/PLAIN",
        ] {
            assert!(is_textual(Some(t)), "{t}");
        }
        assert!(is_textual(None) && is_textual(Some("")));
        for t in ["image/png", "application/octet-stream", "application/pdf"] {
            assert!(!is_textual(Some(t)), "{t}");
        }
    }

    #[test]
    fn body_preview_is_bounded_on_a_char_boundary() {
        let mut m = Map::new();
        let body = "é".repeat(MAX_BODY_BYTES); // 2 bytes per char
        add_body(&mut m, Some(&body), true);
        let preview = m["body_preview"].as_str().unwrap();
        assert!(preview.len() <= MAX_BODY_BYTES);
        assert_eq!(preview.len(), MAX_BODY_BYTES, "even number of bytes fits exactly");
        assert_eq!(m["body_size"], body.len());
        assert_eq!(m["body_truncated"], true);
        assert_eq!(m["body_sha256"], sha256_hex(&body));

        let mut m = Map::new();
        add_body(&mut m, Some("abc"), true);
        assert_eq!(m["body_preview"], "abc");
        assert!(m.get("body_truncated").is_none());

        let mut m = Map::new();
        add_body(&mut m, Some("abc"), false);
        assert!(m.get("body_preview").is_none());
        assert_eq!(m["body_truncated"], true);
        assert_eq!(m["body_size"], 3);

        let mut m = Map::new();
        add_body(&mut m, Some(""), true);
        add_body(&mut m, None, true);
        assert!(m.is_empty());
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
