//! `crawlx mcp`: a Model Context Protocol server over stdio.
//!
//! Newline-delimited JSON-RPC 2.0 on stdin/stdout, MCP revision 2025-03-26 with a graceful
//! downgrade to 2024-11-05. stdout carries protocol frames and nothing else; logs go to
//! stderr. The server exits 0 when stdin reaches end of file, after answering every
//! request already received.
//!
//! The tools mirror the Firecrawl MCP server (`firecrawl_scrape`, `firecrawl_map`,
//! `firecrawl_search`, `firecrawl_crawl`, `firecrawl_check_crawl_status`,
//! `firecrawl_extract`, `firecrawl_extract_status`, `firecrawl_parse`, `firecrawl_agent`,
//! `firecrawl_agent_status`). Each call is a thin HTTP client of a crawlx API's Firecrawl-v2
//! facade (`<api-url>/compat/firecrawl/v2/...`) with `Authorization: Bearer <key>`:
//!
//! * a successful call returns one text content item holding the pretty-printed JSON of the
//!   API's `data` (with the API's `warning` beside it when there is one; the whole body,
//!   minus `success`, for map and the job endpoints), cut at 1 MiB with a marker;
//! * an API error (4xx, 5xx, `success: false`, transport failure, timeout) returns the
//!   same shape with `isError: true` and the API's own error text, never a protocol error;
//! * unknown tools and invalid arguments are JSON-RPC `-32602` errors, as the spec says.

mod api;
mod protocol;
mod schema;
mod tools;

use anyhow::Context as _;
use api::{describe, tokio_sleep, Api, Config};
use clap::Args;
use protocol::{
    error_frame, parse_incoming, read_frame, result_frame, write_frame, Frame, Incoming, RpcError,
    INVALID_REQUEST, MAX_FRAME_BYTES, METHOD_NOT_FOUND, PARSE_ERROR, SERVER_BUSY,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncWrite, BufReader};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tools::Tool;
use url::Url;

/// Longest text a tool result carries; the rest is cut and replaced by a marker.
pub(crate) const MAX_RESULT_BYTES: usize = 1024 * 1024;

/// Protocol revision answered to clients that ask for an unknown one.
const LATEST_PROTOCOL: &str = "2025-03-26";
/// Revisions the server speaks. The tool surface is identical in both.
const SUPPORTED_PROTOCOLS: [&str; 2] = [LATEST_PROTOCOL, "2024-11-05"];
/// API used when neither a flag nor an environment variable names one.
const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
/// Requests served at once; more are answered with a `-32000` error instead of queueing.
const MAX_IN_FLIGHT: usize = 32;
/// Frames waiting for the stdout writer.
const OUTBOX_DEPTH: usize = 64;

/// Arguments of `crawlx mcp`.
#[derive(Args, Clone)]
pub struct McpArgs {
    /// Base URL of the crawlx API whose `/compat/firecrawl/v2` facade the tools call.
    /// Falls back to `FIRECRAWL_API_URL`, then `http://127.0.0.1:8080`.
    #[arg(long, env = "CRAWLX_API_URL", value_name = "URL")]
    pub api_url: Option<String>,
    /// Bearer token sent to the API. Prefer the environment variable: command-line
    /// arguments are visible to other users. Falls back to `FIRECRAWL_API_KEY`. Never logged.
    #[arg(long, env = "CRAWLX_API_KEY", hide_env_values = true, value_name = "KEY")]
    pub api_key: Option<String>,
    /// Timeout of every HTTP request to the API, in milliseconds.
    #[arg(
        long,
        default_value_t = 120_000,
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..=3_600_000)
    )]
    pub timeout_ms: u64,
    /// Pause between status reads while waiting for an extract or agent job, in milliseconds.
    #[arg(
        long,
        default_value_t = 2_000,
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..=60_000)
    )]
    pub poll_interval_ms: u64,
    /// Longest a call waits for an extract or agent job to end, in milliseconds. A job still
    /// running then is reported with its id so it can be read later.
    #[arg(
        long,
        default_value_t = 600_000,
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..=86_400_000)
    )]
    pub poll_timeout_ms: u64,
}

impl fmt::Debug for McpArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpArgs")
            .field("api_url", &self.api_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("timeout_ms", &self.timeout_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("poll_timeout_ms", &self.poll_timeout_ms)
            .finish()
    }
}

impl McpArgs {
    /// Resolve flags, the `CRAWLX_*` variables clap already read, and the `FIRECRAWL_*`
    /// fallbacks (looked up through `env`) into a client configuration.
    fn resolve(&self, env: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        let present = |value: Option<String>| value.filter(|text| !text.trim().is_empty());
        let url_text = present(self.api_url.clone())
            .or_else(|| present(env("FIRECRAWL_API_URL")))
            .unwrap_or_else(|| DEFAULT_API_URL.to_owned());
        // the text is not echoed: a URL may carry credentials
        let api_url = Url::parse(url_text.trim())
            .map_err(|error| anyhow::anyhow!("the api url is not a valid URL: {error}"))?;
        anyhow::ensure!(
            matches!(api_url.scheme(), "http" | "https") && api_url.has_host(),
            "the api url must be an absolute http or https URL"
        );
        let api_key = present(self.api_key.clone())
            .or_else(|| present(env("FIRECRAWL_API_KEY")))
            .map(|key| key.trim().to_owned());
        Ok(Config {
            api_url,
            api_key,
            timeout: Duration::from_millis(self.timeout_ms),
            poll_interval: Duration::from_millis(self.poll_interval_ms),
            poll_timeout: Duration::from_millis(self.poll_timeout_ms),
        })
    }
}

/// Run `crawlx mcp` on the process's stdin and stdout until stdin closes.
///
/// # Errors
/// Fails when the arguments cannot be resolved or the stdio transport breaks.
pub(crate) async fn run(args: McpArgs) -> anyhow::Result<ExitCode> {
    let config = args.resolve(&|name| std::env::var(name).ok())?;
    let api = Api::new(&config, tokio_sleep()).context("cannot build the api client")?;
    tracing::info!(
        api_host = config.api_url.host_str().unwrap_or_default(),
        authenticated = config.api_key.is_some(),
        "crawlx mcp server ready on stdio"
    );
    let server = Arc::new(Server::new(api));
    serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout(), server)
        .await
        .context("the mcp stdio transport failed")?;
    Ok(ExitCode::SUCCESS)
}

/// Protocol state: the API client, the cancellation tokens of requests in flight and the
/// admission semaphore.
struct Server {
    api: Api,
    in_flight: Mutex<BTreeMap<String, CancellationToken>>,
    permits: Arc<Semaphore>,
}

impl Server {
    fn new(api: Api) -> Self {
        Self {
            api,
            in_flight: Mutex::new(BTreeMap::new()),
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        }
    }

    fn tokens(&self) -> MutexGuard<'_, BTreeMap<String, CancellationToken>> {
        // a poisoned map is still a valid map: tokens are inserted and removed atomically
        self.in_flight.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notifications never get a reply. `notifications/cancelled` aborts the named request.
    fn notify(&self, method: &str, params: Option<&Value>) {
        if method != "notifications/cancelled" {
            return;
        }
        let Some(request_id) = params.and_then(|params| params.get("requestId")) else {
            return;
        };
        if let Some(token) = self.tokens().get(&request_id.to_string()) {
            token.cancel();
        }
    }

    /// Create and remember the cancellation token of request `id`. Done before the request
    /// is spawned, so a `notifications/cancelled` that follows at once finds it.
    fn register(&self, id: &Value) -> CancellationToken {
        let token = CancellationToken::new();
        self.tokens().insert(id.to_string(), token.clone());
        token
    }

    /// Run request `id` until it answers or `token` is cancelled. `None` means the client
    /// cancelled it: the spec says such a request gets no reply.
    async fn run_request(
        &self,
        id: Value,
        method: String,
        params: Option<Value>,
        token: CancellationToken,
    ) -> Option<Value> {
        let outcome = tokio::select! {
            () = token.cancelled() => None,
            result = self.dispatch(&method, params) => Some(result),
        };
        self.tokens().remove(&id.to_string());
        outcome.map(|result| match result {
            Ok(value) => result_frame(&id, value),
            Err(error) => error_frame(&id, &error),
        })
    }

    /// Answer one member of a batch. `None` means no reply goes out.
    async fn handle_member(&self, incoming: Incoming) -> Option<Value> {
        match incoming {
            Incoming::Response => None,
            Incoming::Notification { method, params } => {
                self.notify(&method, params.as_ref());
                None
            }
            Incoming::Request { id, method, params } => {
                let token = self.register(&id);
                self.run_request(id, method, params, token).await
            }
        }
    }

    /// Answer a JSON-RPC batch: the replies of its members, or `None` when all were silent.
    async fn handle_batch(&self, items: Vec<Value>) -> Option<Value> {
        if items.is_empty() {
            return Some(error_frame(
                &Value::Null,
                &RpcError::new(INVALID_REQUEST, "a batch must not be empty"),
            ));
        }
        let mut replies = Vec::new();
        for item in items {
            let reply = match parse_incoming(item) {
                Ok(incoming) => self.handle_member(incoming).await,
                Err((id, error)) => Some(error_frame(&id, &error)),
            };
            replies.extend(reply);
        }
        (!replies.is_empty()).then_some(Value::Array(replies))
    }

    async fn dispatch(&self, method: &str, params: Option<Value>) -> Result<Value, RpcError> {
        match method {
            "initialize" => initialize(params),
            "ping" => Ok(json!({})),
            "tools/list" => tools_list(params),
            "tools/call" => self.tools_call(params).await,
            other => Err(RpcError::new(
                METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )),
        }
    }

    async fn tools_call(&self, params: Option<Value>) -> Result<Value, RpcError> {
        let params = params_object(params)?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("`name` must be a string"))?;
        let tool =
            Tool::from_name(name).ok_or_else(|| RpcError::invalid_params(format!("unknown tool: {name}")))?;
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(arguments @ Value::Object(_)) => arguments.clone(),
            Some(_) => return Err(RpcError::invalid_params("`arguments` must be an object")),
        };
        let plan = tool.plan(arguments).map_err(|issues| {
            RpcError::invalid_params(format!("invalid arguments for {name}: {}", issues.join("; ")))
                .with_data(json!({ "issues": issues }))
        })?;
        Ok(match self.api.execute(plan).await {
            Ok(value) => tool_result(&pretty(&value), false),
            Err(error) => tool_result(&describe(&error), true),
        })
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// The `result` of `tools/call`: one text item, cut at [`MAX_RESULT_BYTES`].
fn tool_result(text: &str, is_error: bool) -> Value {
    let kept = truncate_str(text, MAX_RESULT_BYTES);
    let text = if kept.len() < text.len() {
        format!(
            "{kept}\n\n[output truncated: {} of {} bytes shown]",
            kept.len(),
            text.len()
        )
    } else {
        text.to_owned()
    };
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// The longest prefix of `text` that is at most `max` bytes and ends on a character boundary.
pub(crate) fn truncate_str(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default()
}

fn params_object(params: Option<Value>) -> Result<Map<String, Value>, RpcError> {
    match params {
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(RpcError::invalid_params("`params` must be an object")),
        None => Err(RpcError::invalid_params("`params` is required")),
    }
}

fn initialize(params: Option<Value>) -> Result<Value, RpcError> {
    let params = params_object(params)?;
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("`protocolVersion` must be a string"))?;
    for key in ["capabilities", "clientInfo"] {
        if params.get(key).is_some_and(|value| !value.is_object()) {
            return Err(RpcError::invalid_params(format!("`{key}` must be an object")));
        }
    }
    let version = SUPPORTED_PROTOCOLS
        .into_iter()
        .find(|supported| *supported == requested)
        .unwrap_or(LATEST_PROTOCOL);
    Ok(json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "crawlx", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "Firecrawl-compatible web tools backed by a crawlx API. Use \
            firecrawl_scrape for one page, firecrawl_map to find URLs, firecrawl_search to \
            search, firecrawl_crawl for many pages, firecrawl_extract or firecrawl_agent for \
            structured data, firecrawl_parse for local files.",
    }))
}

fn tools_list(params: Option<Value>) -> Result<Value, RpcError> {
    if let Some(params) = params {
        let params = params_object(Some(params))?;
        if params.get("cursor").is_some_and(|cursor| !cursor.is_string()) {
            return Err(RpcError::invalid_params("`cursor` must be a string"));
        }
    }
    let tools: Vec<Value> = Tool::ALL.into_iter().map(Tool::descriptor).collect();
    Ok(json!({ "tools": tools }))
}

/// Serve MCP over `input` and `output` until `input` ends, then answer the requests still
/// in flight and return.
///
/// Requests run concurrently (at most [`MAX_IN_FLIGHT`]), each under a cancellation token
/// that `notifications/cancelled` fires; replies are written by one task, so frames never
/// interleave.
async fn serve<R, W>(mut input: R, output: W, server: Arc<Server>) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (outbox, mut inbox) = mpsc::channel::<Value>(OUTBOX_DEPTH);
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(frame) = inbox.recv().await {
            write_frame(&mut output, &frame).await?;
        }
        Ok::<(), std::io::Error>(())
    });
    let mut tasks: JoinSet<()> = JoinSet::new();
    let read = loop {
        let frame = match read_frame(&mut input, MAX_FRAME_BYTES).await {
            Ok(frame) => frame,
            Err(error) => break Err(error),
        };
        // reap finished request tasks so a long session does not accumulate them
        while tasks.try_join_next().is_some() {}
        let early = match frame {
            Frame::Eof => break Ok(()),
            Frame::Oversized => Some(error_frame(
                &Value::Null,
                &RpcError::new(
                    INVALID_REQUEST,
                    format!("a frame must not exceed {MAX_FRAME_BYTES} bytes"),
                ),
            )),
            Frame::Message(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => admit(&server, &outbox, &mut tasks, value),
                Err(error) => Some(error_frame(
                    &Value::Null,
                    &RpcError::new(PARSE_ERROR, format!("parse error: {error}")),
                )),
            },
        };
        if let Some(frame) = early {
            if outbox.send(frame).await.is_err() {
                break Ok(()); // the writer failed; its error is reported below
            }
        }
    };
    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            tracing::error!(%error, "a request task failed");
        }
    }
    drop(outbox);
    let written = writer.await.map_err(std::io::Error::other)?;
    read.and(written)
}

/// Route one decoded frame: answer what needs no work at once (returned as `Some`), run
/// requests and batches on `tasks`.
fn admit(
    server: &Arc<Server>,
    outbox: &mpsc::Sender<Value>,
    tasks: &mut JoinSet<()>,
    value: Value,
) -> Option<Value> {
    let incoming = match value {
        Value::Array(items) => Err(items),
        other => match parse_incoming(other) {
            Err((id, error)) => return Some(error_frame(&id, &error)),
            Ok(Incoming::Notification { method, params }) => {
                server.notify(&method, params.as_ref());
                return None;
            }
            Ok(Incoming::Response) => return None,
            Ok(Incoming::Request { id, method, params }) => Ok((id, method, params)),
        },
    };
    let Ok(permit) = Arc::clone(&server.permits).try_acquire_owned() else {
        let id = incoming.as_ref().map_or(Value::Null, |(id, _, _)| id.clone());
        return Some(error_frame(
            &id,
            &RpcError::new(
                SERVER_BUSY,
                format!("too many requests in flight (limit {MAX_IN_FLIGHT})"),
            ),
        ));
    };
    let server = Arc::clone(server);
    let outbox = outbox.clone();
    match incoming {
        // registered here, before the task starts, so an immediate cancellation finds it
        Ok((id, method, params)) => {
            let token = server.register(&id);
            tasks.spawn(async move {
                let _permit = permit;
                let reply = server.run_request(id, method, params, token).await;
                send_reply(&outbox, reply).await;
            });
        }
        Err(items) => {
            tasks.spawn(async move {
                let _permit = permit;
                let reply = server.handle_batch(items).await;
                send_reply(&outbox, reply).await;
            });
        }
    }
    None
}

async fn send_reply(outbox: &mpsc::Sender<Value>, reply: Option<Value>) {
    if let Some(frame) = reply {
        // a closed outbox means the writer failed: nothing more to do
        let _ = outbox.send(frame).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::api::{ApiError, SleepFn};
    use super::tools::{Call, Shape, Source};
    use super::*;
    use clap::Parser as _;
    use tokio::io::AsyncReadExt as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(clap::Parser, Debug)]
    struct Wrapper {
        #[command(flatten)]
        args: McpArgs,
    }

    fn config(url: &str) -> Config {
        Config {
            api_url: Url::parse(url).unwrap(),
            api_key: Some("k".to_owned()),
            timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(10),
            poll_timeout: Duration::from_millis(50),
        }
    }

    fn recording_sleep() -> (SleepFn, Arc<Mutex<Vec<Duration>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let sleep: SleepFn = Arc::new(move |duration| -> api::SleepFuture {
            sink.lock().unwrap().push(duration);
            Box::pin(std::future::ready(()))
        });
        (sleep, log)
    }

    fn api_for(url: &str) -> (Api, Arc<Mutex<Vec<Duration>>>) {
        let (sleep, log) = recording_sleep();
        (Api::new(&config(url), sleep).unwrap(), log)
    }

    fn server_for(url: &str) -> Arc<Server> {
        Arc::new(Server::new(api_for(url).0))
    }

    /// Feed `input` to a server and collect every frame it writes before it exits.
    async fn converse_raw(server: Arc<Server>, input: String) -> Vec<Value> {
        let (mut reader, writer) = tokio::io::duplex(4 << 20);
        let served = serve(BufReader::new(input.as_bytes()), writer, server);
        let collected = async {
            let mut out = String::new();
            reader.read_to_string(&mut out).await.unwrap();
            out
        };
        let (served, out) =
            tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(served, collected) })
                .await
                .expect("serve did not finish");
        served.unwrap();
        out.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    async fn converse(server: Arc<Server>, messages: &[Value]) -> Vec<Value> {
        let input: String = messages.iter().map(|message| format!("{message}\n")).collect();
        converse_raw(server, input).await
    }

    fn request(id: i64, rpc_method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": rpc_method, "params": params})
    }

    fn by_id(replies: &[Value], id: i64) -> &Value {
        replies
            .iter()
            .find(|reply| reply["id"] == json!(id))
            .unwrap_or_else(|| panic!("no reply with id {id} in {replies:?}"))
    }

    fn call_message(id: i64, tool: &str, arguments: Value) -> Value {
        request(id, "tools/call", json!({"name": tool, "arguments": arguments}))
    }

    fn post_body(plan: &tools::Plan) -> &Value {
        match &plan.call {
            Call::Post(_, body) => body,
            other => panic!("not a POST: {other:?}"),
        }
    }

    // ---- framing ----

    async fn next_frame<R>(reader: &mut R, max: usize) -> Frame
    where
        R: AsyncBufRead + Unpin,
    {
        read_frame(reader, max).await.unwrap()
    }

    #[tokio::test]
    async fn frames_split_on_newlines_skip_blank_lines_and_drop_the_carriage_return() {
        let mut reader = BufReader::with_capacity(3, &b"{\"a\":1}\r\n\n   \n[2]\nlast"[..]);
        assert_eq!(
            next_frame(&mut reader, 64).await,
            Frame::Message(br#"{"a":1}"#.to_vec())
        );
        assert_eq!(next_frame(&mut reader, 64).await, Frame::Message(b"[2]".to_vec()));
        // a final line without a newline is still delivered
        assert_eq!(
            next_frame(&mut reader, 64).await,
            Frame::Message(b"last".to_vec())
        );
        assert_eq!(next_frame(&mut reader, 64).await, Frame::Eof);
        assert_eq!(next_frame(&mut reader, 64).await, Frame::Eof);
    }

    #[tokio::test]
    async fn oversized_frames_are_discarded_up_to_their_newline() {
        let mut reader = BufReader::with_capacity(4, &b"0123456789ABCDEF\nok\n0123456789"[..]);
        assert_eq!(next_frame(&mut reader, 8).await, Frame::Oversized);
        assert_eq!(next_frame(&mut reader, 8).await, Frame::Message(b"ok".to_vec()));
        // an overlong unterminated tail is oversized too
        assert_eq!(next_frame(&mut reader, 8).await, Frame::Oversized);
        assert_eq!(next_frame(&mut reader, 8).await, Frame::Eof);
    }

    #[tokio::test]
    async fn a_frame_exactly_at_the_limit_is_accepted() {
        let mut reader = BufReader::new(&b"12345678\n123456789\n"[..]);
        assert_eq!(
            read_frame(&mut reader, 8).await.unwrap(),
            Frame::Message(b"12345678".to_vec())
        );
        assert_eq!(read_frame(&mut reader, 8).await.unwrap(), Frame::Oversized);
    }

    #[tokio::test]
    async fn a_written_frame_is_exactly_one_line() {
        let mut sink: Vec<u8> = Vec::new();
        let frame = json!({"text": "line one\nline two\r\n", "n": [1, 2]});
        write_frame(&mut sink, &frame).await.unwrap();
        assert!(sink.ends_with(b"\n"));
        assert_eq!(sink.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(serde_json::from_slice::<Value>(&sink).unwrap(), frame);
    }

    #[test]
    fn messages_are_classified_and_malformed_ones_name_their_id() {
        assert_eq!(
            parse_incoming(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})).unwrap(),
            Incoming::Request {
                id: json!(1),
                method: "ping".to_owned(),
                params: None
            }
        );
        assert_eq!(
            parse_incoming(json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}))
                .unwrap(),
            Incoming::Notification {
                method: "notifications/initialized".to_owned(),
                params: Some(json!({}))
            }
        );
        assert_eq!(
            parse_incoming(json!({"jsonrpc": "2.0", "id": "x", "result": {}})).unwrap(),
            Incoming::Response
        );
        for (message, id) in [
            (json!(42), Value::Null),
            (
                json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
                Value::Null,
            ),
            (
                json!({"jsonrpc": "2.0", "id": [1], "method": "ping"}),
                Value::Null,
            ),
            (json!({"id": 3, "method": "ping"}), json!(3)),
            (json!({"jsonrpc": "2.0", "id": 4}), json!(4)),
            (json!({"jsonrpc": "2.0", "id": 5, "method": 7}), json!(5)),
            (
                json!({"jsonrpc": "2.0", "id": 6, "method": "ping", "params": "x"}),
                json!(6),
            ),
        ] {
            let (reply_id, error) = parse_incoming(message.clone()).unwrap_err();
            assert_eq!(reply_id, id, "{message}");
            assert_eq!(error.code, INVALID_REQUEST, "{message}");
        }
    }

    // ---- the protocol over `serve` ----

    #[tokio::test]
    async fn initialize_answers_the_client_revision_or_the_latest_one() {
        let server = server_for("http://127.0.0.1:9");
        let replies = converse(
            server,
            &[
                request(
                    1,
                    "initialize",
                    json!({"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {}}),
                ),
                request(2, "initialize", json!({"protocolVersion": "2025-03-26"})),
                request(3, "initialize", json!({"protocolVersion": "2030-01-01"})),
                request(4, "initialize", json!({"capabilities": {}})),
                request(
                    5,
                    "initialize",
                    json!({"protocolVersion": "2025-03-26", "capabilities": 3}),
                ),
                request(6, "initialize", json!(null)),
            ],
        )
        .await;
        assert_eq!(
            by_id(&replies, 1)["result"]["protocolVersion"],
            json!("2024-11-05")
        );
        assert_eq!(
            by_id(&replies, 2)["result"]["protocolVersion"],
            json!("2025-03-26")
        );
        assert_eq!(
            by_id(&replies, 3)["result"]["protocolVersion"],
            json!("2025-03-26")
        );
        let result = &by_id(&replies, 2)["result"];
        assert_eq!(result["capabilities"], json!({"tools": {"listChanged": false}}));
        assert_eq!(
            result["serverInfo"],
            json!({"name": "crawlx", "version": env!("CARGO_PKG_VERSION")})
        );
        for id in [4, 5, 6] {
            assert_eq!(
                by_id(&replies, id)["error"]["code"],
                json!(INVALID_PARAMS_CODE),
                "{id}"
            );
        }
    }

    const INVALID_PARAMS_CODE: i64 = -32602;

    #[tokio::test]
    async fn tools_list_describes_every_tool_and_the_schemas_agree_with_the_validator() {
        let server = server_for("http://127.0.0.1:9");
        let replies = converse(
            server,
            &[
                request(1, "tools/list", json!({})),
                request(2, "tools/list", json!({"cursor": 7})),
                request(3, "tools/list", Value::Null),
            ],
        )
        .await;
        let listed = by_id(&replies, 1)["result"]["tools"].as_array().unwrap().clone();
        assert_eq!(listed.len(), Tool::ALL.len());
        assert!(by_id(&replies, 1)["result"].get("nextCursor").is_none());
        assert_eq!(by_id(&replies, 2)["error"]["code"], json!(INVALID_PARAMS_CODE));
        assert!(by_id(&replies, 3)["result"]["tools"].is_array());
        let mut seen = std::collections::BTreeSet::new();
        for (entry, tool) in listed.iter().zip(Tool::ALL) {
            assert_eq!(entry, &tool.descriptor());
            assert!(seen.insert(tool.name()), "duplicate {}", tool.name());
            assert_eq!(Tool::from_name(tool.name()), Some(tool));
            let schema = tool.input_schema();
            let required: Vec<&str> = schema["required"]
                .as_array()
                .map(|names| names.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for name in &required {
                assert!(
                    schema["properties"].get(name).is_some(),
                    "{}: {name}",
                    tool.name()
                );
            }
            // `{}` fails exactly when something is required
            assert_eq!(
                schema::check(&schema, json!({})).is_err(),
                !required.is_empty(),
                "{}",
                tool.name()
            );
        }
        assert_eq!(Tool::from_name("firecrawl_nope"), None);
    }

    #[tokio::test]
    async fn ping_unknown_methods_and_parse_errors() {
        let server = server_for("http://127.0.0.1:9");
        let input = format!(
            "{{oops\n\n{}\n{}\n42\n",
            request(1, "ping", json!({})),
            request(2, "no/such", json!({}))
        );
        let replies = converse_raw(server, input).await;
        assert_eq!(replies.len(), 4, "{replies:?}");
        let parse = replies
            .iter()
            .find(|reply| reply["error"]["code"] == json!(-32700))
            .unwrap();
        assert_eq!(parse["id"], Value::Null);
        assert!(parse["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("parse error"));
        assert_eq!(by_id(&replies, 1)["result"], json!({}));
        assert_eq!(by_id(&replies, 2)["error"]["code"], json!(-32601));
        assert!(replies
            .iter()
            .any(|reply| reply["error"]["code"] == json!(-32600) && reply["id"].is_null()));
    }

    #[tokio::test]
    async fn notifications_and_client_replies_are_never_answered() {
        let server = server_for("http://127.0.0.1:9");
        let replies = converse(
            server,
            &[
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}}),
                json!({"jsonrpc": "2.0", "method": "whatever/else"}),
                json!({"jsonrpc": "2.0", "id": 5, "result": {}}),
                request(2, "ping", json!({})),
            ],
        )
        .await;
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(replies[0]["id"], json!(2));
    }

    #[tokio::test]
    async fn a_batch_is_answered_as_a_batch() {
        let server = server_for("http://127.0.0.1:9");
        let replies = converse(
            server,
            &[
                json!([
                    request(1, "ping", json!({})),
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    request(2, "nope", json!({})),
                    7
                ]),
                json!([{"jsonrpc": "2.0", "method": "notifications/initialized"}]),
                json!([]),
            ],
        )
        .await;
        assert_eq!(replies.len(), 2, "{replies:?}");
        let batch = replies.iter().find_map(|reply| reply.as_array()).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0]["result"], json!({}));
        assert_eq!(batch[1]["error"]["code"], json!(-32601));
        assert_eq!(batch[2]["error"]["code"], json!(-32600));
        let empty = replies.iter().find(|reply| reply.is_object()).unwrap();
        assert_eq!(empty["error"]["code"], json!(-32600));
    }

    #[tokio::test]
    async fn tools_call_rejects_unknown_tools_and_bad_arguments_before_any_request() {
        let mock = MockServer::start().await;
        let server = server_for(&mock.uri());
        let replies = converse(
            server,
            &[
                call_message(1, "firecrawl_teleport", json!({})),
                call_message(2, "firecrawl_scrape", json!({"url": "nope"})),
                request(3, "tools/call", json!({"name": "firecrawl_map", "arguments": 4})),
                request(4, "tools/call", json!({"arguments": {}})),
                request(5, "tools/call", Value::Null),
                call_message(6, "firecrawl_map", json!(null)),
            ],
        )
        .await;
        for id in 1..=5 {
            assert_eq!(
                by_id(&replies, id)["error"]["code"],
                json!(INVALID_PARAMS_CODE),
                "{id}"
            );
        }
        assert_eq!(
            by_id(&replies, 1)["error"]["message"],
            json!("unknown tool: firecrawl_teleport")
        );
        assert_eq!(
            by_id(&replies, 2)["error"]["data"]["issues"],
            json!(["arguments.url must be an absolute http(s) URL"])
        );
        // null arguments mean "none": the missing url is reported, not a type error
        assert_eq!(
            by_id(&replies, 6)["error"]["data"]["issues"],
            json!(["arguments.url is required"])
        );
        assert!(mock.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_request_is_dropped_without_a_reply() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
            .mount(&mock)
            .await;
        let replies = converse(
            server_for(&mock.uri()),
            &[
                call_message(1, "firecrawl_scrape", json!({"url": "https://example.com"})),
                json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
                request(2, "ping", json!({})),
            ],
        )
        .await;
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(replies[0]["id"], json!(2));
    }

    #[tokio::test]
    async fn requests_beyond_the_concurrency_limit_are_answered_busy() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
            .mount(&mock)
            .await;
        let limit = i64::try_from(MAX_IN_FLIGHT).unwrap();
        let mut messages: Vec<Value> = (1..=limit + 1)
            .map(|id| call_message(id, "firecrawl_scrape", json!({"url": "https://example.com"})))
            .collect();
        messages.extend((1..=limit).map(
            |id| json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id}}),
        ));
        let replies = converse(server_for(&mock.uri()), &messages).await;
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(replies[0]["id"], json!(limit + 1));
        assert_eq!(replies[0]["error"]["code"], json!(-32000));
    }

    // ---- argument validation and request planning ----

    #[test]
    fn the_validator_enforces_the_advertised_keywords_and_drops_unlisted_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "n": {"type": "integer", "minimum": 1, "maximum": 5},
                "s": {"type": "string", "enum": ["a", "b"]},
                "u": {"type": "string", "format": "uri"},
                "id": {"type": "string", "format": "uuid"},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                "m": {"type": "object", "additionalProperties": {"type": "string"}},
                "nested": {"type": "object", "properties": {"x": {"type": "number"}}, "required": ["x"]},
                "flag": {"type": "boolean"},
                "name": {"type": "string", "minLength": 2, "maxLength": 3},
            },
            "required": ["n"],
        });
        // valid input: nulls and blank strings of optional properties count as absent, unknown
        // properties are dropped
        let checked = schema::check(
            &schema,
            json!({"n": 2, "extra": 1, "s": "", "u": null, "tags": ["a"], "m": {"k": "v"}, "flag": " "}),
        )
        .unwrap();
        assert_eq!(checked, json!({"n": 2, "tags": ["a"], "m": {"k": "v"}}));
        for (input, issue) in [
            (json!({}), "arguments.n is required"),
            (json!({"n": null}), "arguments.n is required"),
            (json!({"n": 1.5}), "arguments.n must be an integer (got a number)"),
            (json!({"n": "1"}), "arguments.n must be an integer (got a string)"),
            (json!({"n": 0}), "arguments.n must be at least 1"),
            (json!({"n": 9}), "arguments.n must be at most 5"),
            (
                json!({"n": 1, "s": "c"}),
                "arguments.s must be one of \"a\", \"b\"",
            ),
            (
                json!({"n": 1, "u": "ftp://x.org/f"}),
                "arguments.u must be an absolute http(s) URL",
            ),
            (
                json!({"n": 1, "u": "not a url"}),
                "arguments.u must be an absolute http(s) URL",
            ),
            (json!({"n": 1, "id": "123"}), "arguments.id must be a UUID"),
            (
                json!({"n": 1, "tags": ["a", "b", "c"]}),
                "arguments.tags must have at most 2 item(s)",
            ),
            (
                json!({"n": 1, "tags": [1]}),
                "arguments.tags[0] must be a string (got a number)",
            ),
            (
                json!({"n": 1, "m": {"k": 1}}),
                "arguments.m.k must be a string (got a number)",
            ),
            (json!({"n": 1, "nested": {}}), "arguments.nested.x is required"),
            (
                json!({"n": 1, "nested": []}),
                "arguments.nested must be an object (got an array)",
            ),
            (
                json!({"n": 1, "name": "a"}),
                "arguments.name must be at least 2 character(s) long",
            ),
            (
                json!({"n": 1, "name": "abcd"}),
                "arguments.name must be at most 3 character(s) long",
            ),
            (json!([1]), "arguments must be an object (got an array)"),
        ] {
            let issues = schema::check(&schema, input.clone()).unwrap_err();
            assert!(issues.iter().any(|found| found == issue), "{input}: {issues:?}");
        }
        assert!(schema::check(
            &schema,
            json!({"n": 1, "u": "https://example.com/x?y=1", "id": "6f1c2d9e-2c1d-4f8a-9d3e-3f1d2c4b5a69"})
        )
        .is_ok());
        // at most a handful of issues are reported
        let many = json!({"n": 1, "tags": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]});
        assert_eq!(schema::check(&schema, many).unwrap_err().len(), 8);
    }

    #[test]
    fn scrape_folds_the_option_objects_into_the_format_entries() {
        let plan = Tool::Scrape
            .plan(json!({
                "url": "https://example.com",
                "formats": ["markdown", "json", "screenshot", "query", "links"],
                "jsonOptions": {"prompt": "p", "schema": {"type": "object"}},
                "screenshotOptions": {"fullPage": true},
                "queryOptions": {"prompt": "what?"},
                "parsers": ["pdf"],
                "pdfOptions": {"maxPages": 3},
                "bogus": true,
                "includeTags": [],
                "waitFor": null,
                "mobile": "",
            }))
            .unwrap();
        assert_eq!(plan.shape, Shape::Data);
        assert_eq!(plan.wait, None);
        assert_eq!(
            plan.call,
            Call::Post(
                vec!["scrape".to_owned()],
                json!({
                    "url": "https://example.com",
                    "formats": [
                        "markdown",
                        {"type": "json", "prompt": "p", "schema": {"type": "object"}},
                        {"type": "screenshot", "fullPage": true},
                        {"type": "query", "prompt": "what?"},
                        "links",
                    ],
                    "parsers": [{"type": "pdf", "maxPages": 3}],
                })
            )
        );
        // json and query are always object entries; screenshot and pdf only with options
        let bare = Tool::Scrape
            .plan(
                json!({"url": "https://example.com", "formats": ["json", "screenshot"], "parsers": ["pdf"]}),
            )
            .unwrap();
        assert_eq!(
            post_body(&bare),
            &json!({"url": "https://example.com", "formats": [{"type": "json"}, "screenshot"], "parsers": ["pdf"]})
        );
    }

    #[test]
    fn option_objects_need_their_format() {
        let issues = Tool::Scrape
            .plan(json!({
                "url": "https://example.com",
                "formats": ["markdown"],
                "jsonOptions": {"prompt": "p"},
                "queryOptions": {"prompt": "q"},
                "pdfOptions": {"maxPages": 1},
            }))
            .unwrap_err();
        assert_eq!(
            issues,
            [
                "jsonOptions needs formats to include \"json\"",
                "queryOptions needs formats to include \"query\"",
                "pdfOptions needs parsers to include \"pdf\"",
            ]
        );
        let nested = Tool::Crawl
            .plan(json!({"url": "https://example.com", "scrapeOptions": {"jsonOptions": {"prompt": "p"}}}))
            .unwrap_err();
        assert_eq!(
            nested,
            ["scrapeOptions: jsonOptions needs formats to include \"json\""]
        );
    }

    #[test]
    fn search_rules_and_nested_scrape_options() {
        let plan = Tool::Search
            .plan(json!({
                "query": "q",
                "includeDomains": ["a.com"],
                "scrapeOptions": {"formats": ["json"], "jsonOptions": {"prompt": "p"}, "onlyMainContent": true},
            }))
            .unwrap();
        assert_eq!(plan.shape, Shape::Data);
        assert_eq!(
            post_body(&plan),
            &json!({
                "query": "q",
                "includeDomains": ["a.com"],
                "scrapeOptions": {"formats": [{"type": "json", "prompt": "p"}], "onlyMainContent": true},
            })
        );
        assert_eq!(
            Tool::Search
                .plan(json!({"query": "q", "includeDomains": ["a.com"], "excludeDomains": ["b.com"]}))
                .unwrap_err(),
            ["includeDomains and excludeDomains cannot both be set"]
        );
        assert!(Tool::Search
            .plan(json!({"query": "q", "categories": ["gov"]}))
            .is_ok());
        assert!(Tool::Search
            .plan(json!({"query": "q", "categories": ["pdf", "research"]}))
            .is_ok());
        assert_eq!(
            Tool::Search
                .plan(json!({"query": "q", "categories": ["developer", "pdf"]}))
                .unwrap_err(),
            ["the developer and gov categories cannot be combined with other categories"]
        );
    }

    #[test]
    fn crawl_merges_the_webhook_headers_into_the_webhook() {
        let with_headers = Tool::Crawl
            .plan(json!({"url": "https://e.com/*", "webhook": "https://h.example/x", "webhookHeaders": {"A": "1"}}))
            .unwrap();
        assert_eq!(
            post_body(&with_headers),
            &json!({"url": "https://e.com/*", "webhook": {"url": "https://h.example/x", "headers": {"A": "1"}}})
        );
        let plain = Tool::Crawl
            .plan(json!({"url": "https://e.com", "webhook": "https://h.example/x", "excludePaths": []}))
            .unwrap();
        assert_eq!(
            post_body(&plain),
            &json!({"url": "https://e.com", "webhook": "https://h.example/x"})
        );
        let orphan = Tool::Crawl
            .plan(json!({"url": "https://e.com", "webhookHeaders": {"A": "1"}}))
            .unwrap();
        assert_eq!(post_body(&orphan), &json!({"url": "https://e.com"}));
        assert_eq!(with_headers.shape, Shape::Body);
        assert_eq!(with_headers.wait, None);
    }

    #[test]
    fn jobs_wait_by_default_for_extract_but_not_for_agent() {
        let extract = Tool::Extract.plan(json!({"urls": ["https://e.com/*"]})).unwrap();
        assert_eq!(extract.wait, Some("extract"));
        assert_eq!(post_body(&extract), &json!({"urls": ["https://e.com/*"]}));
        let no_wait = Tool::Extract
            .plan(json!({"urls": ["https://e.com"], "wait": false}))
            .unwrap();
        assert_eq!(no_wait.wait, None);
        assert!(post_body(&no_wait).get("wait").is_none());
        let agent = Tool::Agent.plan(json!({"prompt": "p"})).unwrap();
        assert_eq!(agent.wait, None);
        let waiting = Tool::Agent.plan(json!({"prompt": "p", "wait": true})).unwrap();
        assert_eq!(waiting.wait, Some("agent"));
        assert_eq!(post_body(&waiting), &json!({"prompt": "p"}));
        for (tool, endpoint) in [
            (Tool::CheckCrawlStatus, "crawl"),
            (Tool::ExtractStatus, "extract"),
            (Tool::AgentStatus, "agent"),
        ] {
            let plan = tool.plan(json!({"id": "abc"})).unwrap();
            assert_eq!(plan.call, Call::Get(vec![endpoint.to_owned(), "abc".to_owned()]));
            assert_eq!(plan.shape, Shape::Body);
        }
    }

    #[test]
    fn parse_plans_a_file_or_inline_content() {
        let plan = Tool::Parse
            .plan(json!({"path": "/tmp/Report.PDF", "formats": ["markdown"], "parsers": ["pdf"], "pdfOptions": {"maxPages": 2}}))
            .unwrap();
        assert_eq!(plan.shape, Shape::Data);
        let Call::Upload(upload) = plan.call else {
            panic!("not an upload")
        };
        assert_eq!(upload.source, Source::File("/tmp/Report.PDF".into()));
        assert_eq!(upload.filename, "Report.PDF");
        assert_eq!(upload.content_type, "application/pdf");
        assert_eq!(
            upload.options,
            Some(json!({"formats": ["markdown"], "parsers": [{"type": "pdf", "maxPages": 2}]}))
        );

        let inline = Tool::Parse
            .plan(json!({"contentBase64": "aGVs\nbG8=", "filename": "dir/notes.html"}))
            .unwrap();
        let Call::Upload(upload) = inline.call else {
            panic!("not an upload")
        };
        assert_eq!(upload.source, Source::Bytes(b"hello".to_vec()));
        assert_eq!(upload.filename, "notes.html");
        assert_eq!(upload.content_type, "text/html");
        assert_eq!(upload.options, None);

        let typed = Tool::Parse
            .plan(json!({"filePath": "/x/data.bin", "contentType": "text/plain"}))
            .unwrap();
        let Call::Upload(upload) = typed.call else {
            panic!("not an upload")
        };
        assert_eq!(upload.content_type, "text/plain");
        assert_eq!(tools::infer_content_type("a.unknown"), "application/octet-stream");
        assert_eq!(
            tools::infer_content_type("noextension"),
            "application/octet-stream"
        );
        assert_eq!(
            tools::infer_content_type("S.XLSX"),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        );

        // the same path under both names is fine; different paths are not
        assert!(Tool::Parse
            .plan(json!({"filePath": "/a.pdf", "path": "/a.pdf"}))
            .is_ok());
        for (arguments, issue) in [
            (
                json!({"filePath": "/a.pdf", "path": "/b.pdf"}),
                "filePath and path name different files; give one",
            ),
            (
                json!({}),
                "give exactly one of filePath (or path) and contentBase64",
            ),
            (json!({"contentBase64": "AAAA"}), "contentBase64 needs filename"),
            (
                json!({"contentBase64": "!!!", "filename": "a.pdf"}),
                "contentBase64 is not valid base64: ",
            ),
            (
                json!({"contentBase64": "  ", "filename": "a.pdf"}),
                "give exactly one of filePath (or path) and contentBase64",
            ),
            (
                json!({"filePath": "/a.pdf", "contentType": "not a mime"}),
                "contentType \"not a mime\" is not a valid MIME type",
            ),
        ] {
            let issues = Tool::Parse.plan(arguments.clone()).unwrap_err();
            assert!(
                issues.iter().any(|found| found.starts_with(issue)),
                "{arguments}: {issues:?}"
            );
        }
    }

    #[test]
    fn shapes_pick_the_payload() {
        let body = json!({"success": true, "data": {"markdown": "m"}, "warning": "w"});
        // a warning is kept next to the data; without one the data stands alone
        assert_eq!(
            Shape::Data.apply(body.clone()),
            json!({"warning": "w", "data": {"markdown": "m"}})
        );
        assert_eq!(
            Shape::Data
                .apply(json!({"success": true, "data": {"markdown": "m"}, "warning": null, "id": "s"})),
            json!({"markdown": "m"})
        );
        assert_eq!(
            Shape::Body.apply(body),
            json!({"data": {"markdown": "m"}, "warning": "w"})
        );
        assert_eq!(
            Shape::Data.apply(json!({"success": true, "links": []})),
            json!({"links": []})
        );
        assert_eq!(
            Shape::Data.apply(json!({"data": null, "id": 1})),
            json!({"id": 1})
        );
        assert_eq!(Shape::Body.apply(json!([1])), json!([1]));
    }

    // ---- configuration and rendering ----

    fn args(api_url: Option<&str>, api_key: Option<&str>) -> McpArgs {
        McpArgs {
            api_url: api_url.map(str::to_owned),
            api_key: api_key.map(str::to_owned),
            timeout_ms: 1_500,
            poll_interval_ms: 20,
            poll_timeout_ms: 400,
        }
    }

    #[test]
    fn configuration_prefers_flags_then_firecrawl_variables_then_defaults() {
        let none = |_: &str| None;
        let config = args(None, None).resolve(&none).unwrap();
        assert_eq!(config.api_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(config.api_key, None);
        assert_eq!(config.timeout, Duration::from_millis(1_500));
        assert_eq!(config.poll_interval, Duration::from_millis(20));
        assert_eq!(config.poll_timeout, Duration::from_millis(400));

        let fallback = |name: &str| match name {
            "FIRECRAWL_API_URL" => Some("https://fc.example.com/base".to_owned()),
            "FIRECRAWL_API_KEY" => Some(" fc-key ".to_owned()),
            _ => None,
        };
        let config = args(None, None).resolve(&fallback).unwrap();
        assert_eq!(config.api_url.as_str(), "https://fc.example.com/base");
        assert_eq!(config.api_key.as_deref(), Some("fc-key"));

        let config = args(Some("http://own:9"), Some("own"))
            .resolve(&fallback)
            .unwrap();
        assert_eq!(config.api_url.as_str(), "http://own:9/");
        assert_eq!(config.api_key.as_deref(), Some("own"));

        // blank values count as unset
        let config = args(Some("  "), Some("")).resolve(&none).unwrap();
        assert_eq!(config.api_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(config.api_key, None);
    }

    #[test]
    fn bad_api_urls_are_refused_without_echoing_them() {
        let none = |_: &str| None;
        for bad in [
            "not a url",
            "ftp://files.example.com",
            "file:///etc/passwd",
            "http://",
        ] {
            let error = args(Some(bad), None).resolve(&none).unwrap_err().to_string();
            assert!(error.contains("api url"), "{bad}: {error}");
            assert!(!error.contains(bad), "{bad} echoed in {error}");
        }
        let secret = "http://user:hunter2@[::1";
        let error = args(Some(secret), None).resolve(&none).unwrap_err().to_string();
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[test]
    fn flags_have_bounded_ranges_and_the_key_is_redacted() {
        let parsed = Wrapper::try_parse_from(["crawlx-mcp", "--api-url", "http://h:1"])
            .unwrap()
            .args;
        assert_eq!(parsed.timeout_ms, 120_000);
        assert_eq!(parsed.poll_interval_ms, 2_000);
        assert_eq!(parsed.poll_timeout_ms, 600_000);
        for bad in [
            ["--timeout-ms", "0"],
            ["--timeout-ms", "3600001"],
            ["--poll-interval-ms", "0"],
            ["--poll-interval-ms", "60001"],
            ["--poll-timeout-ms", "0"],
        ] {
            let attempt = Wrapper::try_parse_from(["crawlx-mcp", "--api-url", "http://h:1", bad[0], bad[1]]);
            assert!(attempt.is_err(), "{bad:?} accepted");
        }
        let with_key = args(Some("http://h"), Some("sekrit-value"));
        let shown = format!("{with_key:?}");
        assert!(!shown.contains("sekrit-value"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn results_are_cut_on_a_character_boundary_with_a_marker() {
        assert_eq!(truncate_str("abc", 8), "abc");
        assert_eq!(truncate_str("aéb", 2), "a");
        assert_eq!(truncate_str("aéb", 3), "aé");
        assert_eq!(truncate_str("é", 1), "");

        let small = tool_result("hello", false);
        assert_eq!(
            small,
            json!({"content": [{"type": "text", "text": "hello"}], "isError": false})
        );
        let failed = tool_result("nope", true);
        assert_eq!(failed["isError"], json!(true));

        let big = "é".repeat(MAX_RESULT_BYTES);
        let cut = tool_result(&big, false);
        let text = cut["content"][0]["text"].as_str().unwrap();
        let marker = format!(
            "\n\n[output truncated: {} of {} bytes shown]",
            MAX_RESULT_BYTES,
            big.len()
        );
        assert!(text.ends_with(&marker), "{}", &text[text.len() - 80..]);
        assert!(text.len() <= MAX_RESULT_BYTES + marker.len());
        // exactly at the cap nothing is cut
        let exact = "a".repeat(MAX_RESULT_BYTES);
        assert_eq!(
            tool_result(&exact, false)["content"][0]["text"]
                .as_str()
                .unwrap()
                .len(),
            MAX_RESULT_BYTES
        );
    }

    // ---- the HTTP client ----

    async fn mount_post(mock: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(mock)
            .await;
    }

    async fn run_map(response: ResponseTemplate) -> Result<Value, ApiError> {
        let mock = MockServer::start().await;
        mount_post(&mock, response).await;
        let (api, _) = api_for(&mock.uri());
        api.execute(Tool::Map.plan(json!({"url": "https://example.com"})).unwrap())
            .await
    }

    #[tokio::test]
    async fn error_statuses_carry_the_api_error_text() {
        let error = run_map(ResponseTemplate::new(422).set_body_json(json!({
            "success": false,
            "error": "Invalid URL",
            "code": "BAD_REQUEST",
            "details": [{"path": ["url"]}],
            "requestId": "req-1",
        })))
        .await
        .unwrap_err();
        assert_eq!(
            api::describe(&error),
            "the api answered with status 422: Invalid URL [BAD_REQUEST] details: [{\"path\":[\"url\"]}] (request req-1)"
        );
        let message_only = run_map(ResponseTemplate::new(400).set_body_json(json!({"message": "bad input"})))
            .await
            .unwrap_err();
        assert_eq!(
            api::describe(&message_only),
            "the api answered with status 400: bad input"
        );
        let empty = run_map(ResponseTemplate::new(500)).await.unwrap_err();
        assert_eq!(
            api::describe(&empty),
            "the api answered with status 500: Internal Server Error"
        );
        let html = run_map(ResponseTemplate::new(502).set_body_string("  <h1>Bad Gateway</h1>  "))
            .await
            .unwrap_err();
        assert_eq!(
            api::describe(&html),
            "the api answered with status 502: <h1>Bad Gateway</h1>"
        );
        let long = run_map(ResponseTemplate::new(500).set_body_string("x".repeat(5_000)))
            .await
            .unwrap_err();
        assert!(api::describe(&long).len() < 600, "{}", api::describe(&long).len());
    }

    #[tokio::test]
    async fn success_false_and_undecodable_bodies_are_errors_and_empty_ones_are_not() {
        let refused =
            run_map(ResponseTemplate::new(200).set_body_json(json!({"success": false, "error": "refused"})))
                .await
                .unwrap_err();
        assert_eq!(
            api::describe(&refused),
            "the api answered with status 200: refused"
        );
        let garbled = run_map(ResponseTemplate::new(200).set_body_string("<html>"))
            .await
            .unwrap_err();
        let text = api::describe(&garbled);
        assert!(
            text.starts_with("response from /compat/firecrawl/v2/map is not valid json: "),
            "{text}"
        );
        assert_eq!(run_map(ResponseTemplate::new(200)).await.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn an_unreachable_api_reports_the_path_and_the_cause_chain() {
        let (api, _) = api_for("http://127.0.0.1:9");
        let error = api
            .execute(Tool::Map.plan(json!({"url": "https://example.com"})).unwrap())
            .await
            .unwrap_err();
        let text = api::describe(&error);
        assert!(
            text.starts_with("request to /compat/firecrawl/v2/map failed: "),
            "{text}"
        );
        assert!(text.len() > "request to /compat/firecrawl/v2/map failed: ".len());
    }

    #[tokio::test]
    async fn a_base_url_with_a_path_prefix_keeps_it() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/gateway/compat/firecrawl/v2/map"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "links": []})))
            .expect(1)
            .mount(&mock)
            .await;
        let (api, _) = api_for(&format!("{}/gateway/?ignored=1#frag", mock.uri()));
        let value = api
            .execute(Tool::Map.plan(json!({"url": "https://example.com"})).unwrap())
            .await
            .unwrap();
        assert_eq!(value, json!({"links": []}));
    }

    #[tokio::test]
    async fn jobs_are_polled_through_the_injected_sleep() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/compat/firecrawl/v2/extract"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "id": "j1"})))
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/compat/firecrawl/v2/extract/j1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"success": true, "status": "processing"})),
            )
            .up_to_n_times(3)
            .expect(3)
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/compat/firecrawl/v2/extract/j1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"success": true, "status": "completed", "data": {"n": 1}})),
            )
            .expect(1)
            .mount(&mock)
            .await;
        let (api, sleeps) = api_for(&mock.uri());
        let plan = Tool::Extract
            .plan(json!({"urls": ["https://example.com"]}))
            .unwrap();
        let value = api.execute(plan).await.unwrap();
        assert_eq!(value, json!({"status": "completed", "data": {"n": 1}}));
        assert_eq!(*sleeps.lock().unwrap(), vec![Duration::from_millis(10); 3]);
    }

    #[tokio::test]
    async fn the_poll_budget_is_bounded_by_the_timeout_over_the_interval() {
        let mock = MockServer::start().await;
        mount_post(
            &mock,
            ResponseTemplate::new(200).set_body_json(json!({"success": true, "id": "j2"})),
        )
        .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"success": true, "status": "processing"})),
            )
            .mount(&mock)
            .await;
        // 50 ms budget / 10 ms interval = 5 sleeps between 6 reads
        let (api, sleeps) = api_for(&mock.uri());
        let plan = Tool::Agent.plan(json!({"prompt": "p", "wait": true})).unwrap();
        let value = api.execute(plan).await.unwrap();
        assert_eq!(value["id"], json!("j2"));
        assert_eq!(value["status"], json!("processing"));
        assert!(
            value["note"].as_str().unwrap().contains("6 status reads"),
            "{value}"
        );
        assert!(
            value["note"].as_str().unwrap().contains("firecrawl_agent_status"),
            "{value}"
        );
        assert_eq!(sleeps.lock().unwrap().len(), 5);
        let gets = mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "GET")
            .count();
        assert_eq!(gets, 6);
    }

    #[tokio::test]
    async fn failed_and_cancelled_jobs_are_errors_that_show_the_final_body() {
        for status in ["failed", "cancelled"] {
            let mock = MockServer::start().await;
            mount_post(
                &mock,
                ResponseTemplate::new(200).set_body_json(json!({"success": true, "id": "j3"})),
            )
            .await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"success": true, "status": status, "error": "why"})),
                )
                .mount(&mock)
                .await;
            let (api, sleeps) = api_for(&mock.uri());
            let plan = Tool::Extract
                .plan(json!({"urls": ["https://example.com"]}))
                .unwrap();
            let error = api.execute(plan).await.unwrap_err();
            let text = api::describe(&error);
            assert!(
                text.starts_with(&format!("extract job j3 ended with status {status}\n{{")),
                "{text}"
            );
            assert!(text.contains("\"error\": \"why\""), "{text}");
            assert!(sleeps.lock().unwrap().is_empty());
        }
        let mock = MockServer::start().await;
        mount_post(
            &mock,
            ResponseTemplate::new(200).set_body_json(json!({"success": true})),
        )
        .await;
        let (api, _) = api_for(&mock.uri());
        let plan = Tool::Extract
            .plan(json!({"urls": ["https://example.com"]}))
            .unwrap();
        assert!(matches!(api.execute(plan).await, Err(ApiError::MissingId)));
    }
}
