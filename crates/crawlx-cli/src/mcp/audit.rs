//! The tool-call audit log of `crawlx mcp --audit-log`: an append-only, hash-chained JSON Lines
//! file with one record per phase of every call that reads or changes something.
//!
//! A call writes an `intent` record before it runs and a `result` record after it. Records carry
//! digests and sizes only: the tool name, its capability family, the SHA-256 of the canonical JSON
//! of the arguments and of the result, the outcome, a stable error code, and opaque (UUID)
//! resource ids. Argument values, URLs, page content, error messages, keys and tokens never reach
//! the file.
//!
//! Every record holds `prev`, the `hash` of the line before it (64 zeros for the first), and its
//! own `hash`: the SHA-256, in hex, of the canonical JSON (object keys sorted at every level) of
//! the record without its `hash` member. Editing, deleting or reordering a line breaks the chain
//! at that line and [`verify`] names it. Cutting whole lines off the end cannot be seen from the
//! file alone: keep the last hash `audit-verify` prints somewhere the writer cannot reach.
//!
//! One file belongs to one server process. The process holds an exclusive advisory lock on it for
//! its lifetime and a second process refuses to start. Records are written under one mutex, so
//! concurrent requests keep the chain linear. If a write ever fails, the log refuses every later
//! record (a partial line may be on disk) and the server refuses every call: it never runs
//! unaudited.

use super::catalog::{self, Capability};
use super::native::Native;
use super::protocol::{RpcError, INVALID_PARAMS, METHOD_NOT_FOUND, SERVER_BUSY};
use super::tools::Tool;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, BufRead as _, BufReader, Read, Seek as _, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// The `prev` of the first record.
pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Longest record line the writer reads back and the verifier accepts.
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Most resource ids one record lists.
const MAX_RESOURCE_IDS: usize = 16;
/// How deep resource ids are looked for in arguments.
const MAX_ID_DEPTH: usize = 6;
/// `tool` of a call whose name is not a registered tool.
const UNKNOWN_TOOL: &str = "unknown";
/// Error code of a call cut short before it answered.
const CANCELLED: &str = "cancelled";

/// What went wrong opening or writing the audit log. Messages name the file and the cause,
/// never a record's content.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuditError {
    /// The directory of the log is not there.
    #[error("the directory of the audit log `{}` does not exist", .0.display())]
    ParentMissing(PathBuf),
    /// The log path is a symbolic link.
    #[error("the audit log `{}` is a symbolic link", .0.display())]
    Symlink(PathBuf),
    /// The log path is not a regular file.
    #[error("the audit log `{}` is not a regular file", .0.display())]
    NotRegular(PathBuf),
    /// The existing file is readable or writable by group or other.
    #[error("the audit log `{}` has mode {mode:04o}: group and other access must be off (chmod 600)", .path.display())]
    Permissions {
        /// The log path.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Another process holds the log.
    #[error("the audit log `{}` is in use by another process; one file belongs to one server", .0.display())]
    Locked(PathBuf),
    /// Opening, locking or reading the file failed.
    #[error("cannot open the audit log `{}`: {source}", .path.display())]
    Open {
        /// The log path.
        path: PathBuf,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// The last line of the existing file does not verify.
    #[error("the last line of the audit log is broken ({reason}); keep the file and start a new one")]
    BrokenTail {
        /// What is wrong with the line.
        reason: &'static str,
    },
    /// Appending a record failed.
    #[error("cannot append to the audit log: {0}")]
    Write(#[source] io::Error),
    /// An earlier append failed.
    #[error("the audit log failed earlier and accepts no more records")]
    Failed,
    /// The sequence number cannot grow.
    #[error("the audit log's sequence number is exhausted")]
    Exhausted,
}

/// The phase a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Intent,
    Result,
}

impl Phase {
    const fn name(self) -> &'static str {
        match self {
            Phase::Intent => "intent",
            Phase::Result => "result",
        }
    }
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Recorded with the intent: the call has not run yet.
    Intent,
    /// The call succeeded.
    Ok,
    /// The call failed.
    Error,
    /// The call was refused: capability not granted, unknown tool, or a policy refusal.
    Refused,
}

impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Outcome::Intent => "intent",
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Refused => "refused",
        }
    }
}

/// What the log records about one request, computed before it runs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CallInfo {
    method: &'static str,
    tool: &'static str,
    capability: &'static str,
    args_digest: String,
    resource_ids: Vec<String>,
    /// Set when the request is certain to be refused: its stable error code.
    refusal: Option<&'static str>,
}

/// How a finished call is recorded.
struct Verdict {
    outcome: Outcome,
    error_code: Option<String>,
    digest: String,
    bytes: usize,
}

/// One record to append.
struct Entry<'a> {
    phase: Phase,
    call: &'a CallInfo,
    outcome: Outcome,
    error_code: Option<&'a str>,
    result: Option<(&'a str, usize)>,
    intent_seq: Option<u64>,
}

/// The sink and the tail of the chain, behind one mutex.
struct Chain {
    sink: Box<dyn Write + Send>,
    seq: u64,
    prev: String,
    failed: bool,
}

/// The open audit log.
pub(crate) struct Audit {
    chain: Mutex<Chain>,
}

impl Audit {
    /// Open (creating it with mode 0600) the log at `path`, take its lock and continue its
    /// chain from the verified last line.
    ///
    /// # Errors
    /// Fails closed: when the directory is missing, the path is a symlink or not a regular
    /// file, an existing file is group- or other-accessible, another process holds the file,
    /// or the last line of an existing file does not verify.
    pub(crate) fn open(path: &Path) -> Result<Self, AuditError> {
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        if !std::fs::metadata(dir).is_ok_and(|meta| meta.is_dir()) {
            return Err(AuditError::ParentMissing(dir.to_path_buf()));
        }
        let open_error = |source| AuditError::Open {
            path: path.to_path_buf(),
            source,
        };
        let mut file = match std::fs::symlink_metadata(path) {
            Ok(seen) => {
                if seen.file_type().is_symlink() {
                    return Err(AuditError::Symlink(path.to_path_buf()));
                }
                if !seen.is_file() {
                    return Err(AuditError::NotRegular(path.to_path_buf()));
                }
                let file = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(path)
                    .map_err(open_error)?;
                let opened = file.metadata().map_err(open_error)?;
                // the path was swapped for a link between the check and the open
                if (opened.dev(), opened.ino()) != (seen.dev(), seen.ino()) {
                    return Err(AuditError::Symlink(path.to_path_buf()));
                }
                let mode = opened.mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(AuditError::Permissions {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
                file
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => OpenOptions::new()
                .read(true)
                .append(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(open_error)?,
            Err(error) => return Err(open_error(error)),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(AuditError::Locked(path.to_path_buf())),
            Err(TryLockError::Error(error)) => return Err(open_error(error)),
        }
        let (seq, prev) = read_tail(&mut file, path)?;
        Ok(Self::with_sink(Box::new(file), seq, prev))
    }

    /// A new log writing to `sink`.
    #[cfg(test)]
    pub(crate) fn in_memory(sink: Box<dyn Write + Send>) -> Self {
        Self::with_sink(sink, 0, GENESIS.to_owned())
    }

    /// A log writing to `sink`, continuing a chain at `seq` and `prev`.
    fn with_sink(sink: Box<dyn Write + Send>, seq: u64, prev: String) -> Self {
        Self {
            chain: Mutex::new(Chain {
                sink,
                seq,
                prev,
                failed: false,
            }),
        }
    }

    /// Append one record and return its sequence number. A failed append latches: every later
    /// record fails too.
    fn record(&self, entry: &Entry<'_>) -> Result<u64, AuditError> {
        let mut chain = self.chain.lock().unwrap_or_else(PoisonError::into_inner);
        if chain.failed {
            return Err(AuditError::Failed);
        }
        let seq = chain.seq.checked_add(1).ok_or(AuditError::Exhausted)?;
        let mut record = Map::new();
        record.insert("seq".to_owned(), json!(seq));
        record.insert(
            "ts".to_owned(),
            json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
        );
        record.insert("prev".to_owned(), json!(chain.prev));
        record.insert("phase".to_owned(), json!(entry.phase.name()));
        record.insert("method".to_owned(), json!(entry.call.method));
        record.insert("tool".to_owned(), json!(entry.call.tool));
        record.insert("capability".to_owned(), json!(entry.call.capability));
        record.insert("args_digest".to_owned(), json!(entry.call.args_digest));
        record.insert("outcome".to_owned(), json!(entry.outcome.name()));
        record.insert("error_code".to_owned(), json!(entry.error_code));
        record.insert(
            "result_digest".to_owned(),
            json!(entry.result.map(|(digest, _)| digest)),
        );
        record.insert(
            "result_bytes".to_owned(),
            json!(entry.result.map(|(_, bytes)| bytes)),
        );
        record.insert("resource_ids".to_owned(), json!(entry.call.resource_ids));
        record.insert("intent_seq".to_owned(), json!(entry.intent_seq));
        let mut record = Value::Object(record);
        let hash = sha256_hex(canonical_json(&record).as_bytes());
        if let Some(map) = record.as_object_mut() {
            map.insert("hash".to_owned(), json!(hash));
        }
        let mut line = canonical_json(&record).into_bytes();
        line.push(b'\n');
        match chain.sink.write_all(&line).and_then(|()| chain.sink.flush()) {
            Ok(()) => {
                chain.seq = seq;
                chain.prev = hash;
                Ok(seq)
            }
            Err(error) => {
                chain.failed = true;
                Err(AuditError::Write(error))
            }
        }
    }

    /// Write the intent record of `call` and return the guard that writes its result.
    ///
    /// # Errors
    /// When the record cannot be appended: the call must not run.
    pub(crate) fn begin(self: &Arc<Self>, call: CallInfo) -> Result<Audited, AuditError> {
        let intent_seq = self.record(&Entry {
            phase: Phase::Intent,
            call: &call,
            outcome: Outcome::Intent,
            error_code: None,
            result: None,
            intent_seq: None,
        })?;
        Ok(Audited {
            audit: Arc::clone(self),
            call,
            intent_seq,
            done: false,
        })
    }
}

/// A call whose intent is on record. [`Audited::finish`] writes its result; a call dropped
/// before that (the client cancelled it) is recorded as an error with code `cancelled`.
pub(crate) struct Audited {
    audit: Arc<Audit>,
    call: CallInfo,
    intent_seq: u64,
    done: bool,
}

impl Audited {
    /// Record how the call ended.
    ///
    /// # Errors
    /// When the record cannot be appended: the caller must withhold the result.
    pub(crate) fn finish(mut self, result: &Result<Value, RpcError>) -> Result<(), AuditError> {
        self.done = true;
        let verdict = judge(&self.call, result);
        self.audit
            .record(&Entry {
                phase: Phase::Result,
                call: &self.call,
                outcome: verdict.outcome,
                error_code: verdict.error_code.as_deref(),
                result: Some((&verdict.digest, verdict.bytes)),
                intent_seq: Some(self.intent_seq),
            })
            .map(drop)
    }
}

impl Drop for Audited {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let (digest, bytes) = digest_value(&Value::Null);
        let written = self.audit.record(&Entry {
            phase: Phase::Result,
            call: &self.call,
            outcome: Outcome::Error,
            error_code: Some(CANCELLED),
            result: Some((&digest, bytes)),
            intent_seq: Some(self.intent_seq),
        });
        if let Err(error) = written {
            tracing::error!(%error, "the audit log could not record a cancelled call");
        }
    }
}

impl CallInfo {
    /// What to record for a request, or `None` for methods that read nothing (`initialize`,
    /// `ping`, the list methods). `tools/call` and `resources/read` are the data paths.
    pub(crate) fn for_request(method: &str, params: Option<&Value>, native: Option<&Native>) -> Option<Self> {
        match method {
            "tools/call" => Some(Self::for_tool(params, native)),
            "resources/read" => Some(Self::for_resource(params, native)),
            _ => None,
        }
    }

    fn for_tool(params: Option<&Value>, native: Option<&Native>) -> Self {
        let object = params.and_then(Value::as_object);
        let name = object
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str);
        let arguments = object
            .and_then(|object| object.get("arguments"))
            .filter(|arguments| !arguments.is_null());
        let empty = Value::Object(Map::new());
        let arguments = arguments.unwrap_or(&empty);
        let (tool, capability, refusal) = match (name, native) {
            (None, _) => (UNKNOWN_TOOL, "none", None),
            (Some(name), Some(native)) => match catalog::find(name) {
                Some(entry) if native.is_enabled(entry.capability) => {
                    (entry.name, entry.capability.name(), None)
                }
                Some(entry) => (
                    entry.name,
                    entry.capability.name(),
                    Some("capability_not_granted"),
                ),
                None => (UNKNOWN_TOOL, "none", Some("unknown_tool")),
            },
            (Some(name), None) => match Tool::from_name(name) {
                Some(tool) => (tool.name(), "compat", None),
                None => (UNKNOWN_TOOL, "none", Some("unknown_tool")),
            },
        };
        let mut ids = Vec::new();
        collect_ids(arguments, 0, &mut ids);
        Self {
            method: "tools/call",
            tool,
            capability,
            args_digest: digest_value(arguments).0,
            resource_ids: finish_ids(ids),
            refusal,
        }
    }

    fn for_resource(params: Option<&Value>, native: Option<&Native>) -> Self {
        let (capability, refusal) = match native {
            Some(native) if native.is_enabled(Capability::Inspect) => (Capability::Inspect.name(), None),
            Some(_) => (Capability::Inspect.name(), Some("capability_not_granted")),
            None => ("none", Some("method_not_found")),
        };
        let mut ids = Vec::new();
        if let Some(uri) = params
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
        {
            ids.extend(uri.split('/').filter_map(opaque_id));
        }
        Self {
            method: "resources/read",
            tool: "resources/read",
            capability,
            args_digest: digest_value(params.unwrap_or(&Value::Null)).0,
            resource_ids: finish_ids(ids),
            refusal,
        }
    }
}

/// `text` when it is a canonical hyphenated UUID: an opaque id that carries no content.
fn opaque_id(text: &str) -> Option<String> {
    (text.len() == 36 && uuid::Uuid::parse_str(text).is_ok()).then(|| text.to_ascii_lowercase())
}

fn collect_ids(value: &Value, depth: usize, ids: &mut Vec<String>) {
    if depth > MAX_ID_DEPTH {
        return;
    }
    match value {
        Value::String(text) => ids.extend(opaque_id(text)),
        Value::Array(items) => items.iter().for_each(|item| collect_ids(item, depth + 1, ids)),
        Value::Object(map) => map.values().for_each(|item| collect_ids(item, depth + 1, ids)),
        _ => {}
    }
}

fn finish_ids(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids.dedup();
    ids.truncate(MAX_RESOURCE_IDS);
    ids
}

/// `text` when it is a stable error code (lowercase letters, digits and `_ . : -`, at most 64
/// bytes); anything else could carry content.
fn stable_code(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let first_ok = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    (first_ok
        && bytes.len() <= 64
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b':' | b'-')
        }))
    .then_some(text)
}

fn rpc_code(code: i64) -> &'static str {
    match code {
        INVALID_PARAMS => "invalid_params",
        METHOD_NOT_FOUND => "method_not_found",
        SERVER_BUSY => "server_busy",
        -32002 => "not_found",
        -32603 => "internal_error",
        _ => "rpc_error",
    }
}

/// Classify a finished call. The result and any error text are digested, never stored.
fn judge(call: &CallInfo, result: &Result<Value, RpcError>) -> Verdict {
    match result {
        Err(error) => {
            let (digest, bytes) = digest_value(&error.to_value());
            let (outcome, code) = match call.refusal {
                Some(code) => (Outcome::Refused, code),
                None => (Outcome::Error, rpc_code(error.code)),
            };
            Verdict {
                outcome,
                error_code: Some(code.to_owned()),
                digest,
                bytes,
            }
        }
        Ok(value) => {
            let (digest, bytes) = digest_value(value);
            if value.get("isError") != Some(&Value::Bool(true)) {
                return Verdict {
                    outcome: Outcome::Ok,
                    error_code: None,
                    digest,
                    bytes,
                };
            }
            // native tools carry `structuredContent.error.{status,code}`; compat tools only text
            let failure = value.pointer("/structuredContent/error");
            let status = failure
                .and_then(|failure| failure.get("status"))
                .and_then(Value::as_u64);
            let code = failure
                .and_then(|failure| failure.get("code"))
                .and_then(Value::as_str)
                .and_then(stable_code)
                .unwrap_or("tool_error");
            Verdict {
                outcome: if matches!(status, Some(401 | 403)) {
                    Outcome::Refused
                } else {
                    Outcome::Error
                },
                error_code: Some(code.to_owned()),
                digest,
                bytes,
            }
        }
    }
}

/// `value` as JSON text with object keys sorted at every level.
fn canonical_json(value: &Value) -> String {
    fn render(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    if let Some(member) = map.get(key) {
                        render(member, out);
                    }
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    render(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    render(value, &mut out);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The SHA-256 (hex) and the length of the canonical JSON of `value`.
fn digest_value(value: &Value) -> (String, usize) {
    let text = canonical_json(value);
    (sha256_hex(text.as_bytes()), text.len())
}

/// The hash a record must carry: the digest of its canonical JSON without `hash`.
fn line_hash(record: &Value) -> Option<String> {
    let mut map = record.as_object()?.clone();
    map.remove("hash");
    Some(sha256_hex(canonical_json(&Value::Object(map)).as_bytes()))
}

/// The sequence number and hash of the last line of `file`, checked against the line's own
/// content. An empty file starts a new chain.
fn read_tail(file: &mut File, path: &Path) -> Result<(u64, String), AuditError> {
    let open_error = |source| AuditError::Open {
        path: path.to_path_buf(),
        source,
    };
    let length = file.metadata().map_err(open_error)?.len();
    if length == 0 {
        return Ok((0, GENESIS.to_owned()));
    }
    let window = length.min(MAX_LINE_BYTES as u64 + 1);
    file.seek(SeekFrom::Start(length - window)).map_err(open_error)?;
    let mut tail = Vec::new();
    Read::take(&mut *file, window)
        .read_to_end(&mut tail)
        .map_err(open_error)?;
    let broken = |reason| AuditError::BrokenTail { reason };
    let Some(body) = tail.strip_suffix(b"\n") else {
        return Err(broken("it has no line end: a write was cut short"));
    };
    let line = match body.iter().rposition(|byte| *byte == b'\n') {
        Some(at) => &body[at + 1..],
        None if window < length => return Err(broken("it is longer than a record can be")),
        None => body,
    };
    let record: Value = serde_json::from_slice(line).map_err(|_| broken("it is not JSON"))?;
    let seq = record
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| broken("it has no sequence number"))?;
    let hash = record
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| broken("it has no hash"))?;
    if line_hash(&record).as_deref() != Some(hash) {
        return Err(broken("its hash does not match its content"));
    }
    Ok((seq, hash.to_owned()))
}

/// What [`verify`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verification {
    /// Lines that verified before the first break (all of them when intact).
    pub(crate) entries: u64,
    /// Hash of the last verified line (the genesis value for an empty log).
    pub(crate) last_hash: String,
    /// The first broken line (1-based) and why.
    pub(crate) broken: Option<(u64, &'static str)>,
}

/// Recompute every hash of the log at `path` and check every link.
///
/// # Errors
/// When the file cannot be opened or read.
pub(crate) fn verify(path: &Path) -> io::Result<Verification> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut found = Verification {
        entries: 0,
        last_hash: GENESIS.to_owned(),
        broken: None,
    };
    let mut line = Vec::new();
    let mut number = 0_u64;
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(found);
        }
        number += 1;
        let broke = |found: Verification, reason| Verification {
            broken: Some((number, reason)),
            ..found
        };
        if line.pop() != Some(b'\n') {
            let reason = if read > MAX_LINE_BYTES {
                "the line is longer than a record can be"
            } else {
                "the last line is cut short (no line end)"
            };
            return Ok(broke(found, reason));
        }
        let Ok(record) = serde_json::from_slice::<Value>(&line) else {
            return Ok(broke(found, "the line is not JSON"));
        };
        if !record.is_object() {
            return Ok(broke(found, "the line is not a JSON object"));
        }
        if record.get("seq").and_then(Value::as_u64) != Some(found.entries + 1) {
            return Ok(broke(
                found,
                "the sequence number is out of order (a line was removed, added or moved)",
            ));
        }
        if record.get("prev").and_then(Value::as_str) != Some(found.last_hash.as_str()) {
            return Ok(broke(found, "the line does not link to the line before it"));
        }
        let hash = record.get("hash").and_then(Value::as_str);
        if hash.is_none() || line_hash(&record).as_deref() != hash {
            return Ok(broke(
                found,
                "the hash does not match the content (the line was edited)",
            ));
        }
        found.last_hash = hash.unwrap_or_default().to_owned();
        found.entries += 1;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    const SCRAPE_TOOL: &str = "firecrawl_scrape"; // wire-compat: MCP tool name
    const MAP_TOOL: &str = "firecrawl_map"; // wire-compat: MCP tool name

    /// A call of a compatibility tool, as the dispatcher would describe it.
    pub(super) fn compat_call(tool: &str, arguments: &Value) -> CallInfo {
        let params = json!({ "name": tool, "arguments": arguments });
        CallInfo::for_request("tools/call", Some(&params), None).unwrap()
    }

    /// Run `calls` successful calls through `audit`.
    fn run_calls(audit: &Arc<Audit>, calls: usize) {
        for index in 0..calls {
            let call = compat_call(SCRAPE_TOOL, &json!({ "n": index }));
            let guard = audit.begin(call).unwrap();
            guard.finish(&Ok(json!({ "isError": false }))).unwrap();
        }
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }

    fn fresh_log(calls: usize) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Audit::open(&path).unwrap());
        run_calls(&audit, calls);
        drop(audit);
        (dir, path)
    }

    #[test]
    fn a_new_log_is_private_and_its_chain_verifies_after_n_calls() {
        let (_dir, path) = fresh_log(5);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let found = verify(&path).unwrap();
        assert_eq!(found.entries, 10);
        assert_eq!(found.broken, None);
        let all = lines(&path);
        let last: Value = serde_json::from_str(all.last().unwrap()).unwrap();
        assert_eq!(last["hash"], json!(found.last_hash));
        let first: Value = serde_json::from_str(&all[0]).unwrap();
        assert_eq!(first["prev"], json!(GENESIS));
        assert_eq!(first["seq"], json!(1));
        assert_eq!(first["phase"], json!("intent"));
        let second: Value = serde_json::from_str(&all[1]).unwrap();
        assert_eq!(second["phase"], json!("result"));
        assert_eq!(second["intent_seq"], json!(1));
        assert_eq!(second["prev"], first["hash"]);
        // the line's hash is the SHA-256 of its canonical JSON without the hash member
        let mut bare = first.as_object().unwrap().clone();
        let claimed = bare.remove("hash").unwrap();
        assert_eq!(
            claimed,
            json!(hex::encode(Sha256::digest(
                canonical_json(&Value::Object(bare)).as_bytes()
            )))
        );
    }

    #[test]
    fn an_empty_log_verifies_with_the_genesis_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        drop(Audit::open(&path).unwrap());
        assert_eq!(
            verify(&path).unwrap(),
            Verification {
                entries: 0,
                last_hash: GENESIS.to_owned(),
                broken: None
            }
        );
    }

    #[test]
    fn an_edited_field_is_found_at_its_line() {
        let (_dir, path) = fresh_log(3);
        let mut all = lines(&path);
        all[2] = all[2].replace("\"outcome\":\"intent\"", "\"outcome\":\"ok\"");
        assert_ne!(all[2], lines(&path)[2]);
        write_lines(&path, &all);
        let found = verify(&path).unwrap();
        assert_eq!(found.broken.map(|(line, _)| line), Some(3));
        assert_eq!(found.entries, 2);
    }

    #[test]
    fn an_edited_line_with_a_recomputed_hash_breaks_the_next_link() {
        let (_dir, path) = fresh_log(3);
        let mut all = lines(&path);
        let mut record: Value = serde_json::from_str(&all[1]).unwrap();
        record["outcome"] = json!("refused");
        let hash = line_hash(&record).unwrap();
        record["hash"] = json!(hash);
        all[1] = canonical_json(&record);
        write_lines(&path, &all);
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(3));
    }

    #[test]
    fn a_deleted_middle_line_is_found() {
        let (_dir, path) = fresh_log(3);
        let mut all = lines(&path);
        all.remove(2);
        write_lines(&path, &all);
        let found = verify(&path).unwrap();
        assert_eq!(found.broken.map(|(line, _)| line), Some(3));
        assert_eq!(found.entries, 2);
    }

    #[test]
    fn reordered_lines_are_found() {
        let (_dir, path) = fresh_log(3);
        let mut all = lines(&path);
        all.swap(2, 3);
        write_lines(&path, &all);
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(3));
    }

    #[test]
    fn a_truncated_last_line_is_found_and_refuses_a_restart() {
        let (_dir, path) = fresh_log(2);
        let size = std::fs::metadata(&path).unwrap().len();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(size - 20).unwrap();
        drop(file);
        let found = verify(&path).unwrap();
        assert_eq!(found.broken.map(|(line, _)| line), Some(4));
        assert_eq!(found.entries, 3);
        assert!(matches!(Audit::open(&path), Err(AuditError::BrokenTail { .. })));
        // a line cut after its newline-free prefix, then a newline, is not valid JSON either
        let mut text = std::fs::read(&path).unwrap();
        text.push(b'\n');
        std::fs::write(&path, text).unwrap();
        assert_eq!(verify(&path).unwrap().broken.map(|(line, _)| line), Some(4));
        assert!(matches!(Audit::open(&path), Err(AuditError::BrokenTail { .. })));
    }

    #[test]
    fn a_log_with_a_forged_last_line_refuses_to_continue() {
        let (_dir, path) = fresh_log(1);
        let mut all = lines(&path);
        all[1] = all[1].replace("\"phase\":\"result\"", "\"phase\":\"intent\"");
        write_lines(&path, &all);
        assert!(matches!(Audit::open(&path), Err(AuditError::BrokenTail { .. })));
    }

    #[test]
    fn restarting_continues_the_chain() {
        let (_dir, path) = fresh_log(2);
        let before = verify(&path).unwrap();
        let audit = Arc::new(Audit::open(&path).unwrap());
        run_calls(&audit, 2);
        drop(audit);
        let after = verify(&path).unwrap();
        assert_eq!((after.entries, after.broken), (8, None));
        let all = lines(&path);
        let fifth: Value = serde_json::from_str(&all[4]).unwrap();
        assert_eq!(fifth["seq"], json!(5));
        assert_eq!(fifth["prev"], json!(before.last_hash));
    }

    #[test]
    fn a_second_process_on_the_same_file_is_refused() {
        let (_dir, path) = fresh_log(0);
        let held = Audit::open(&path).unwrap();
        assert!(matches!(Audit::open(&path), Err(AuditError::Locked(_))));
        drop(held);
        assert!(Audit::open(&path).is_ok());
    }

    #[test]
    fn unsafe_paths_are_refused_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-dir").join("audit.jsonl");
        assert!(matches!(Audit::open(&missing), Err(AuditError::ParentMissing(_))));
        assert!(matches!(Audit::open(dir.path()), Err(AuditError::NotRegular(_))));

        let target = dir.path().join("target.jsonl");
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.jsonl");
        symlink(&target, &link).unwrap();
        assert!(matches!(Audit::open(&link), Err(AuditError::Symlink(_))));
        let dangling = dir.path().join("dangling.jsonl");
        symlink(dir.path().join("elsewhere.jsonl"), &dangling).unwrap();
        assert!(matches!(Audit::open(&dangling), Err(AuditError::Symlink(_))));
        assert!(!dir.path().join("elsewhere.jsonl").exists());

        for mode in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(Audit::open(&target), Err(AuditError::Permissions { .. })),
                "mode {mode:o}"
            );
        }
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Audit::open(&target).is_ok());
    }

    #[test]
    fn an_unwritable_location_fails_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = Audit::open(&locked.join("audit.jsonl"));
        let privileged = std::fs::write(locked.join("probe"), b"").is_ok();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !privileged {
            assert!(matches!(outcome, Err(AuditError::Open { .. })));
        }

        // an existing file the process cannot append to
        let path = dir.path().join("readonly.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let outcome = Audit::open(&path);
        if std::fs::OpenOptions::new().append(true).open(&path).is_err() {
            assert!(matches!(outcome, Err(AuditError::Open { .. })));
        }
    }

    /// A sink that accepts `allowed` writes and fails every later one.
    struct FlakySink {
        allowed: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for FlakySink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.allowed == 0 {
                return Err(io::Error::other("disk gone"));
            }
            self.allowed -= 1;
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_write_latches_and_every_later_record_fails() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let sink = FlakySink {
            allowed: 1,
            written: Arc::clone(&written),
        };
        let audit = Arc::new(Audit::with_sink(Box::new(sink), 0, GENESIS.to_owned()));
        let guard = audit.begin(compat_call(MAP_TOOL, &json!({}))).unwrap();
        assert!(matches!(guard.finish(&Ok(json!({}))), Err(AuditError::Write(_))));
        assert!(matches!(
            audit.begin(compat_call(MAP_TOOL, &json!({}))),
            Err(AuditError::Failed)
        ));
        // only the first record reached the sink
        assert_eq!(
            written
                .lock()
                .unwrap()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
    }

    #[test]
    fn calls_are_described_by_digests_and_opaque_ids_only() {
        let id = "0192f3a0-7b1c-7cde-8a40-1234567890ab";
        let call = compat_call(
            SCRAPE_TOOL,
            &json!({ "url": "https://canary.invalid/secret", "ids": [id, "not-an-id"], "n": 1 }),
        );
        assert_eq!(call.tool, SCRAPE_TOOL);
        assert_eq!(call.capability, "compat");
        assert_eq!(call.resource_ids, vec![id.to_owned()]);
        assert_eq!(call.refusal, None);
        assert_eq!(call.args_digest.len(), 64);
        assert!(!format!("{call:?}").contains("canary"));
        let unknown = compat_call("some_page_text_name", &json!({}));
        assert_eq!((unknown.tool, unknown.refusal), ("unknown", Some("unknown_tool")));
    }

    #[test]
    fn only_stable_codes_are_recorded() {
        for good in ["not_found", "http_404", "external_processing_disabled", "a.b:c-d"] {
            assert_eq!(stable_code(good), Some(good));
        }
        for bad in ["", "Has Spaces", "https://x", "_lead", &"a".repeat(65), "naïve"] {
            assert_eq!(stable_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn results_are_classified_without_keeping_text() {
        let call = compat_call(SCRAPE_TOOL, &json!({}));
        let ok = judge(&call, &Ok(json!({ "content": [], "isError": false })));
        assert_eq!((ok.outcome, ok.error_code), (Outcome::Ok, None));
        let failed = judge(
            &call,
            &Ok(json!({ "content": [{"text": "canary"}], "isError": true })),
        );
        assert_eq!(
            (failed.outcome, failed.error_code.as_deref()),
            (Outcome::Error, Some("tool_error"))
        );
        let denied = judge(
            &call,
            &Ok(
                json!({ "isError": true, "structuredContent": { "error": { "status": 403, "code": "external_processing_disabled", "message": "canary" } } }),
            ),
        );
        assert_eq!(
            (denied.outcome, denied.error_code.as_deref()),
            (Outcome::Refused, Some("external_processing_disabled"))
        );
        let hostile = judge(
            &call,
            &Ok(
                json!({ "isError": true, "structuredContent": { "error": { "status": 500, "code": "Canary Text!" } } }),
            ),
        );
        assert_eq!(hostile.error_code.as_deref(), Some("tool_error"));
        let invalid = judge(&call, &Err(RpcError::invalid_params("canary")));
        assert_eq!(
            (invalid.outcome, invalid.error_code.as_deref()),
            (Outcome::Error, Some("invalid_params"))
        );
        let unknown = compat_call("nope", &json!({}));
        let refused = judge(&unknown, &Err(RpcError::invalid_params("unknown tool: nope")));
        assert_eq!(
            (refused.outcome, refused.error_code.as_deref()),
            (Outcome::Refused, Some("unknown_tool"))
        );
    }
}
