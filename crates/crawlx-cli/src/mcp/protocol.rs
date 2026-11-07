//! JSON-RPC 2.0 framing for the MCP stdio transport: one JSON value per line, UTF-8, `\n`
//! terminated, nothing else on the stream.

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// The frame is not valid JSON.
pub(crate) const PARSE_ERROR: i64 = -32700;
/// The JSON is not a valid JSON-RPC request.
pub(crate) const INVALID_REQUEST: i64 = -32600;
/// The method does not exist.
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// The method exists but the parameters are wrong.
pub(crate) const INVALID_PARAMS: i64 = -32602;
/// Implementation-defined: more requests are in flight than the server accepts.
pub(crate) const SERVER_BUSY: i64 = -32000;

/// Longest accepted frame. A longer line is discarded up to its newline and answered with
/// [`INVALID_REQUEST`], so a runaway client cannot grow the server's memory without bound.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RpcError {
    /// Error code.
    pub(crate) code: i64,
    /// Short description.
    pub(crate) message: String,
    /// Optional structured detail.
    pub(crate) data: Option<Value>,
}

impl RpcError {
    /// Error with `code` and `message`.
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// [`INVALID_PARAMS`] with `message`.
    pub(crate) fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    /// Attach structured detail.
    pub(crate) fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    fn to_value(&self) -> Value {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let (Some(data), Some(map)) = (&self.data, error.as_object_mut()) {
            map.insert("data".to_owned(), data.clone());
        }
        error
    }
}

/// A well-formed inbound message.
#[derive(Debug, PartialEq)]
pub(crate) enum Incoming {
    /// Expects a response with the same `id`.
    Request {
        /// Request id (string or number).
        id: Value,
        /// Method name.
        method: String,
        /// Structured parameters, when sent.
        params: Option<Value>,
    },
    /// Fire-and-forget: never answered.
    Notification {
        /// Method name.
        method: String,
        /// Structured parameters, when sent.
        params: Option<Value>,
    },
    /// A reply to a server-initiated request. The server sends none, so it is ignored.
    Response,
}

/// Classify one decoded JSON value. The error carries the `id` to answer with (`null` when
/// the id is unreadable) and the JSON-RPC error.
pub(crate) fn parse_incoming(value: Value) -> Result<Incoming, (Value, RpcError)> {
    let Value::Object(mut object) = value else {
        return Err((
            Value::Null,
            RpcError::new(INVALID_REQUEST, "a request must be a JSON object"),
        ));
    };
    let id = match object.remove("id") {
        None => None,
        Some(id @ (Value::String(_) | Value::Number(_))) => Some(id),
        Some(_) => {
            return Err((
                Value::Null,
                RpcError::new(INVALID_REQUEST, "`id` must be a string or a number"),
            ))
        }
    };
    let reply_id = id.clone().unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "`jsonrpc` must be \"2.0\""),
        ));
    }
    let Some(method) = object.remove("method") else {
        // a reply to a request this server never sent carries `result` or `error`
        if id.is_some() && (object.contains_key("result") || object.contains_key("error")) {
            return Ok(Incoming::Response);
        }
        return Err((reply_id, RpcError::new(INVALID_REQUEST, "`method` is required")));
    };
    let Value::String(method) = method else {
        return Err((
            reply_id,
            RpcError::new(INVALID_REQUEST, "`method` must be a string"),
        ));
    };
    let params = match object.remove("params") {
        None | Some(Value::Null) => None,
        Some(params @ (Value::Object(_) | Value::Array(_))) => Some(params),
        Some(_) => {
            return Err((
                reply_id,
                RpcError::new(INVALID_REQUEST, "`params` must be an object or an array"),
            ))
        }
    };
    Ok(match id {
        Some(id) => Incoming::Request { id, method, params },
        None => Incoming::Notification { method, params },
    })
}

/// Success frame for request `id`.
pub(crate) fn result_frame(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Error frame for request `id` (`null` when the request id could not be read).
pub(crate) fn error_frame(id: &Value, error: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error.to_value() })
}

/// One line read from the client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    /// A non-blank line, without its terminator.
    Message(Vec<u8>),
    /// A line longer than the limit; it was discarded.
    Oversized,
    /// The stream ended.
    Eof,
}

/// Read the next non-blank line, keeping at most `max` bytes of it in memory. A final line
/// without a newline is still delivered.
pub(crate) async fn read_frame<R>(reader: &mut R, max: usize) -> std::io::Result<Frame>
where
    R: AsyncBufRead + Unpin,
{
    let mut line: Vec<u8> = Vec::new();
    let mut oversized = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if oversized {
                Frame::Oversized
            } else if line.iter().all(u8::is_ascii_whitespace) {
                Frame::Eof
            } else {
                message(line)
            });
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if !oversized {
            if line.len().saturating_add(take) > max {
                oversized = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&chunk[..take]);
            }
        }
        reader.consume(take.saturating_add(usize::from(newline.is_some())));
        if newline.is_none() {
            continue;
        }
        if oversized {
            return Ok(Frame::Oversized);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            line.clear();
            continue;
        }
        return Ok(message(line));
    }
}

/// A message frame without a trailing `\r`.
fn message(mut line: Vec<u8>) -> Frame {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Frame::Message(line)
}

/// Write `frame` as one line and flush. `serde_json` escapes newlines inside strings, so
/// the output is always exactly one line.
pub(crate) async fn write_frame<W>(writer: &mut W, frame: &Value) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(frame)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}
