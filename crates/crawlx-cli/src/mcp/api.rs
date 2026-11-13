//! The HTTP side of `crawlx mcp`: one thin client of the crawlx compatibility API (v2).
//!
//! Each tool call is a single request (or, for jobs the caller waits on, a start request
//! plus status polls). The API key travels only in the `Authorization` header; it is never
//! logged and never part of an error message.

use super::tools::{Call, Plan, Shape, Source, Upload, MAX_UPLOAD_BYTES};
#[allow(
    clippy::disallowed_types,
    reason = "bounded API protocol client imports raw reqwest request and response types"
)]
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{json, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Path prefix of the compatibility API (v2).
const FACADE_PREFIX: [&str; 2] = ["compat", "v2"];

/// Largest response body read into memory. Larger bodies fail the call; smaller ones are
/// cut to [`crate::mcp::MAX_RESULT_BYTES`] when rendered.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Longest API error body quoted verbatim when it is not JSON.
const MAX_QUOTED_BYTES: usize = 512;

/// A boxed sleep future.
pub(crate) type SleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Sleep function the poll loop calls between status reads. Production passes
/// [`tokio_sleep`]; tests pass a recorder that returns at once.
pub(crate) type SleepFn = Arc<dyn Fn(Duration) -> SleepFuture + Send + Sync>;

/// Body of a native request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NativeBody {
    /// No body.
    None,
    /// A JSON value, serialized by the client.
    Json(Value),
    /// JSON text sent byte for byte.
    Raw(Vec<u8>),
}

/// One request of the native surface, already validated and path-encoded.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NativeCall {
    /// Upper-case HTTP method.
    pub(crate) method: &'static str,
    /// Encoded path below the API base URL.
    pub(crate) path: String,
    /// Query pairs, in order.
    pub(crate) query: Vec<(String, String)>,
    /// Extra headers, in order.
    pub(crate) headers: Vec<(&'static str, String)>,
    /// Request body.
    pub(crate) body: NativeBody,
}

/// What the API answered, undecoded.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NativeResponse {
    /// HTTP status code.
    pub(crate) status: u16,
    /// `Content-Type` of the body, when sent.
    pub(crate) content_type: Option<String>,
    /// Body bytes (bounded).
    pub(crate) body: Vec<u8>,
}

/// A [`SleepFn`] over `tokio::time::sleep`.
pub(crate) fn tokio_sleep() -> SleepFn {
    Arc::new(|duration| -> SleepFuture { Box::pin(tokio::time::sleep(duration)) })
}

/// Everything the client needs, already resolved from flags and environment.
#[derive(Clone)]
pub(crate) struct Config {
    /// Base URL of the crawlx API.
    pub(crate) api_url: Url,
    /// Bearer token, when the API wants one.
    pub(crate) api_key: Option<String>,
    /// Timeout of every HTTP request.
    pub(crate) timeout: Duration,
    /// Pause between job status reads.
    pub(crate) poll_interval: Duration,
    /// Longest a call waits for a job to end.
    pub(crate) poll_timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_host", &self.api_url.host_str())
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("poll_interval", &self.poll_interval)
            .field("poll_timeout", &self.poll_timeout)
            .finish()
    }
}

/// Why a tool call failed. Rendered as an `isError` tool result, never as a protocol error.
#[allow(
    clippy::disallowed_types,
    reason = "API protocol failures wrap the raw reqwest error as their source"
)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    /// The API base URL cannot carry a path.
    #[error("the api url cannot be used as a base")]
    BadBase,
    /// The HTTP client could not be built.
    #[error("cannot build the http client")]
    Client(#[source] reqwest::Error),
    /// The request did not complete.
    #[error("request to {path} failed")]
    Transport {
        /// Request path.
        path: String,
        /// Underlying error (URL stripped).
        #[source]
        source: reqwest::Error,
    },
    /// The request hit the per-call timeout.
    #[error("request to {path} timed out after {millis} ms")]
    Timeout {
        /// Request path.
        path: String,
        /// The configured timeout.
        millis: u128,
    },
    /// The body is larger than the server reads.
    #[error("response from {path} is larger than {limit} bytes")]
    TooLarge {
        /// Request path.
        path: String,
        /// Read limit.
        limit: usize,
    },
    /// A successful response is not JSON.
    #[error("response from {path} is not valid json")]
    Decode {
        /// Request path.
        path: String,
        /// Parse error.
        #[source]
        source: serde_json::Error,
    },
    /// The API answered with an error status, or with `success: false`.
    #[error("the api answered with status {status}: {message}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// The API's error text.
        message: String,
    },
    /// A job response carried no `id`.
    #[error("the api response has no job id")]
    MissingId,
    /// A waited-on job ended unsuccessfully.
    #[error("{endpoint} job {id} ended with status {status}")]
    JobFailed {
        /// Job family (`extract`, `agent`).
        endpoint: &'static str,
        /// Job id.
        id: String,
        /// Terminal status.
        status: String,
        /// Final status body.
        detail: Value,
    },
    /// The file to upload cannot be read.
    #[error("cannot read {path}")]
    File {
        /// The path as given.
        path: String,
        /// I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file to upload is larger than the upload limit.
    #[error("{path} is larger than the {limit} byte upload limit")]
    FileTooLarge {
        /// The path as given.
        path: String,
        /// Upload limit.
        limit: usize,
    },
    /// The multipart part could not be built.
    #[error("invalid content type {content_type:?}")]
    ContentType {
        /// The rejected MIME type.
        content_type: String,
    },
}

/// Client of the compatibility API (v2).
#[allow(
    clippy::disallowed_types,
    reason = "API protocol client owns the raw reqwest client"
)]
pub(crate) struct Api {
    http: reqwest::Client,
    base: Url,
    key: Option<String>,
    timeout: Duration,
    poll_interval: Duration,
    max_polls: u32,
    sleep: SleepFn,
}

impl Api {
    /// Build a client.
    ///
    /// # Errors
    /// Fails when the HTTP client cannot be constructed.
    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client builds the raw reqwest client"
    )]
    pub(crate) fn new(config: &Config, sleep: SleepFn) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("crawlx-mcp/", env!("CARGO_PKG_VERSION")))
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .build()
            .map_err(|error| ApiError::Client(error.without_url()))?;
        let interval_ms = config.poll_interval.as_millis().max(1);
        let polls = config.poll_timeout.as_millis().div_ceil(interval_ms).max(1);
        let mut base = config.api_url.clone();
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self {
            http,
            base,
            key: config.api_key.clone(),
            timeout: config.timeout,
            poll_interval: config.poll_interval,
            max_polls: u32::try_from(polls).unwrap_or(u32::MAX),
            sleep,
        })
    }

    /// Run a planned call and return the value to show the model.
    ///
    /// # Errors
    /// Fails with an [`ApiError`] on transport problems, error statuses, `success: false`
    /// bodies and waited-on jobs that end unsuccessfully.
    pub(crate) async fn execute(&self, plan: Plan) -> Result<Value, ApiError> {
        let Plan { call, shape, wait } = plan;
        let started = match call {
            Call::Get(path) => self.json_request(Method::GET, &path, None).await?,
            Call::Post(path, body) => self.json_request(Method::POST, &path, Some(&body)).await?,
            Call::Upload(upload) => self.upload(upload).await?,
        };
        let Some(endpoint) = wait else {
            return Ok(shape.apply(started));
        };
        let id = started
            .get("id")
            .and_then(Value::as_str)
            .ok_or(ApiError::MissingId)?
            .to_owned();
        self.wait_for(endpoint, &id).await
    }

    /// Send one native request and return the response whatever its status.
    ///
    /// # Errors
    /// Fails with an [`ApiError`] on transport problems, timeouts and oversized bodies.
    pub(crate) async fn native(&self, call: &NativeCall) -> Result<NativeResponse, ApiError> {
        self.exchange(call, None).await
    }

    /// Read a server-sent event stream until `max_events` events arrived, the stream ended,
    /// or `wait` passed without a new event. The stream is then dropped, never left open.
    /// The answer is a JSON body `{events: [{id, event, data}], lastEventId}`; a non-success
    /// status is returned like [`Api::native`] returns it.
    ///
    /// # Errors
    /// Fails with an [`ApiError`] on transport problems, timeouts and oversized bodies.
    pub(crate) async fn native_events(
        &self,
        call: &NativeCall,
        max_events: usize,
        wait: Duration,
    ) -> Result<NativeResponse, ApiError> {
        self.exchange(call, Some((max_events, wait))).await
    }

    async fn exchange(
        &self,
        call: &NativeCall,
        events: Option<(usize, Duration)>,
    ) -> Result<NativeResponse, ApiError> {
        let method = match call.method {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            _ => Method::DELETE,
        };
        let mut url = self.base.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}{}", call.path));
        if !call.query.is_empty() {
            url.query_pairs_mut().extend_pairs(call.query.iter());
        }
        let mut request = self.authorize(self.http.request(method, url.clone()));
        for (name, value) in &call.headers {
            request = request.header(*name, value);
        }
        request = match &call.body {
            NativeBody::None => request,
            NativeBody::Json(value) => request.json(value),
            NativeBody::Raw(bytes) => request
                .header("Content-Type", "application/json")
                .body(bytes.clone()),
        };
        if events.is_some() {
            request = request.header("Accept", "text/event-stream");
        }
        let path = url.path();
        let mut response = request
            .send()
            .await
            .map_err(|error| self.transport(path, error))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let Some((max_events, wait)) = events.filter(|_| (200..300).contains(&status)) else {
            let body = self.read_body(path, response).await?;
            return Ok(NativeResponse {
                status,
                content_type,
                body,
            });
        };
        let mut parser = EventParser::default();
        let mut found: Vec<Value> = Vec::new();
        let mut last_id: Option<String> = None;
        let mut buffered = 0_usize;
        let mut idle_since = tokio::time::Instant::now();
        'read: while found.len() < max_events {
            // keep-alive comments must not extend the wait for a real event
            let remaining = wait.saturating_sub(idle_since.elapsed());
            let chunk = match tokio::time::timeout(remaining, response.chunk()).await {
                Err(_) | Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(self.transport(path, error)),
                Ok(Ok(Some(chunk))) => chunk,
            };
            buffered = buffered.saturating_add(chunk.len());
            if buffered > MAX_BODY_BYTES {
                return Err(ApiError::TooLarge {
                    path: path.to_owned(),
                    limit: MAX_BODY_BYTES,
                });
            }
            for event in parser.push(&chunk) {
                idle_since = tokio::time::Instant::now();
                if let Some(id) = event.get("id").and_then(Value::as_str) {
                    last_id = Some(id.to_owned());
                }
                found.push(event);
                if found.len() >= max_events {
                    break 'read;
                }
            }
        }
        let body =
            serde_json::to_vec(&json!({ "events": found, "lastEventId": last_id })).map_err(|source| {
                ApiError::Decode {
                    path: path.to_owned(),
                    source,
                }
            })?;
        Ok(NativeResponse {
            status,
            content_type: Some("application/json".to_owned()),
            body,
        })
    }

    /// The origin (`scheme://host[:port]`) of the API, as an interactive profile request
    /// must present it.
    pub(crate) fn origin(&self) -> String {
        self.base.origin().ascii_serialization()
    }

    /// Read `<endpoint>/{id}` until the job ends or the poll budget is spent.
    async fn wait_for(&self, endpoint: &'static str, id: &str) -> Result<Value, ApiError> {
        let path = vec![endpoint.to_owned(), id.to_owned()];
        let mut last = Value::Null;
        for attempt in 0..=self.max_polls {
            if attempt > 0 {
                (self.sleep)(self.poll_interval).await;
            }
            let body = self.json_request(Method::GET, &path, None).await?;
            match body.get("status").and_then(Value::as_str) {
                Some("completed") => return Ok(Shape::Body.apply(body)),
                Some(status @ ("failed" | "cancelled")) => {
                    return Err(ApiError::JobFailed {
                        endpoint,
                        id: id.to_owned(),
                        status: status.to_owned(),
                        detail: Shape::Body.apply(body),
                    })
                }
                _ => last = body,
            }
        }
        let status = last.get("status").cloned().unwrap_or(Value::Null);
        Ok(json!({
            "id": id,
            "status": status,
            "note": format!(
                "the job is still running after {} status reads; read it again with the {endpoint} status tool",
                self.max_polls.saturating_add(1)
            ),
        }))
    }

    fn url(&self, path: &[String]) -> Result<Url, ApiError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| ApiError::BadBase)?
            .pop_if_empty()
            .extend(FACADE_PREFIX)
            .extend(path);
        Ok(url)
    }

    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client authorizes the raw reqwest request builder"
    )]
    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.key {
            Some(key) => request.bearer_auth(key),
            None => request,
        }
    }

    async fn json_request(
        &self,
        method: Method,
        path: &[String],
        body: Option<&Value>,
    ) -> Result<Value, ApiError> {
        let url = self.url(path)?;
        let mut request = self.authorize(self.http.request(method, url.clone()));
        if let Some(body) = body {
            request = request.json(body);
        }
        self.finish(url.path(), request).await
    }

    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client builds the raw reqwest multipart upload"
    )]
    async fn upload(&self, upload: Upload) -> Result<Value, ApiError> {
        let Upload {
            source,
            filename,
            content_type,
            options,
        } = upload;
        let bytes = match source {
            Source::Bytes(bytes) => bytes,
            Source::File(path) => read_upload(&path).await?,
        };
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename)
            .mime_str(&content_type)
            .map_err(|_| ApiError::ContentType { content_type })?;
        let mut form = reqwest::multipart::Form::new().part("file", part);
        if let Some(options) = options {
            form = form.text("options", options.to_string());
        }
        let url = self.url(&["parse".to_owned()])?;
        let request = self.authorize(self.http.post(url.clone())).multipart(form);
        self.finish(url.path(), request).await
    }

    /// Send, read the body (bounded), and turn error statuses and `success: false` into
    /// [`ApiError::Status`].
    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client sends the raw reqwest request builder"
    )]
    async fn finish(&self, path: &str, request: RequestBuilder) -> Result<Value, ApiError> {
        let response = request
            .send()
            .await
            .map_err(|error| self.transport(path, error))?;
        let status = response.status();
        let body = self.read_body(path, response).await?;
        if !status.is_success() {
            return Err(ApiError::Status {
                status: status.as_u16(),
                message: failure_message(status, &body),
            });
        }
        let value: Value = if body.iter().all(u8::is_ascii_whitespace) {
            json!({})
        } else {
            serde_json::from_slice(&body).map_err(|source| ApiError::Decode {
                path: path.to_owned(),
                source,
            })?
        };
        if value.get("success") == Some(&Value::Bool(false)) {
            return Err(ApiError::Status {
                status: status.as_u16(),
                message: failure_message(status, &body),
            });
        }
        Ok(value)
    }

    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client reads the raw reqwest response body"
    )]
    async fn read_body(&self, path: &str, mut response: Response) -> Result<Vec<u8>, ApiError> {
        let too_large = || ApiError::TooLarge {
            path: path.to_owned(),
            limit: MAX_BODY_BYTES,
        };
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(MAX_BODY_BYTES).unwrap_or(u64::MAX))
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| self.transport(path, error))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    #[allow(
        clippy::disallowed_types,
        reason = "API protocol client translates the raw reqwest error"
    )]
    fn transport(&self, path: &str, error: reqwest::Error) -> ApiError {
        if error.is_timeout() {
            ApiError::Timeout {
                path: path.to_owned(),
                millis: self.timeout.as_millis(),
            }
        } else {
            ApiError::Transport {
                path: path.to_owned(),
                source: error.without_url(),
            }
        }
    }
}

/// Incremental parser of a server-sent event stream.
#[derive(Default)]
struct EventParser {
    pending: Vec<u8>,
}

impl EventParser {
    /// Feed bytes; returns the events completed by them.
    fn push(&mut self, bytes: &[u8]) -> Vec<Value> {
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some(end) = find_block_end(&self.pending) {
            let block: Vec<u8> = self.pending.drain(..end.0).collect();
            self.pending.drain(..end.1);
            if let Some(event) = parse_block(&String::from_utf8_lossy(&block)) {
                events.push(event);
            }
        }
        events
    }
}

/// `(block length, separator length)` of the first blank-line separator in `bytes`.
fn find_block_end(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut index = 0;
    while index < bytes.len() {
        let rest = bytes.get(index..)?;
        if rest.starts_with(b"\r\n\r\n") {
            return Some((index, 4));
        }
        if rest.starts_with(b"\n\n") {
            return Some((index, 2));
        }
        index += 1;
    }
    None
}

fn parse_block(block: &str) -> Option<Value> {
    let mut id = None;
    let mut name = None;
    let mut data: Vec<&str> = Vec::new();
    for line in block.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" => id = Some(value.to_owned()),
            "event" => name = Some(value.to_owned()),
            "data" => data.push(value),
            _ => {}
        }
    }
    if data.is_empty() && id.is_none() && name.is_none() {
        return None;
    }
    let text = data.join("\n");
    let data = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text));
    Some(json!({ "id": id, "event": name, "data": data }))
}

async fn read_upload(path: &std::path::Path) -> Result<Vec<u8>, ApiError> {
    let shown = path.display().to_string();
    let metadata = tokio::fs::metadata(path).await.map_err(|source| ApiError::File {
        path: shown.clone(),
        source,
    })?;
    if metadata.len() > u64::try_from(MAX_UPLOAD_BYTES).unwrap_or(u64::MAX) {
        return Err(ApiError::FileTooLarge {
            path: shown,
            limit: MAX_UPLOAD_BYTES,
        });
    }
    tokio::fs::read(path)
        .await
        .map_err(|source| ApiError::File { path: shown, source })
}

/// The API's own error text for an error status (or a `success: false` body): the `error`
/// member (or `message`), with `code`, `details` and `requestId` appended when present;
/// the start of the body when it is not JSON.
fn failure_message(status: StatusCode, body: &[u8]) -> String {
    let reason = status.canonical_reason().unwrap_or("error");
    let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
        let text = String::from_utf8_lossy(body);
        let quoted = crate::mcp::truncate_str(text.trim(), MAX_QUOTED_BYTES);
        return if quoted.is_empty() {
            reason.to_owned()
        } else {
            quoted.to_owned()
        };
    };
    let text = ["error", "message"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .unwrap_or(reason);
    let mut message = text.to_owned();
    if let Some(code) = object.get("code").and_then(Value::as_str) {
        message.push_str(&format!(" [{code}]"));
    }
    if let Some(details) = object.get("details").filter(|details| !details.is_null()) {
        message.push_str(&format!(" details: {details}"));
    }
    if let Some(request_id) = object.get("requestId").and_then(Value::as_str) {
        message.push_str(&format!(" (request {request_id})"));
    }
    message
}

/// Render an error for the model: the message, its `source` chain, and for a failed job the
/// final status body.
pub(crate) fn describe(error: &ApiError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    if let ApiError::JobFailed { detail, .. } = error {
        text.push('\n');
        text.push_str(&serde_json::to_string_pretty(detail).unwrap_or_default());
    }
    text
}
