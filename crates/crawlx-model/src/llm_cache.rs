//! Record, replay and call-cap wrapper around any [`LlmExtractor`] (katana
//! `-ai-record`, `-ai-replay`, `-ai-max-calls`).
//!
//! [`RecordingLlm`] overrides only [`LlmExtractor::complete`], so every product method layered on
//! it (`json`, `summary`, ...) is covered. It runs in one of three [`CacheMode`]s:
//!
//! * `Off`: pass every call to the inner client; only the [`CallCap`] applies.
//! * `Record`: answer from the recording when the request was seen before (this run or an earlier
//!   one, nothing is sent and the cap is not charged); otherwise charge the cap, call the inner
//!   client and append the reply to the recording before returning it. Concurrent identical
//!   requests share one inner call.
//! * `Replay`: answer only from the recording; a request that is not in it fails with
//!   [`LlmError::NotRecorded`]. The inner client is never touched, so no network is used.
//!
//! # Recording format
//!
//! JSON Lines, one entry per answered request, appended in call order:
//!
//! ```text
//! {"v":1,"request":"<64 lowercase hex>","response":<JSON>,"usage":{"prompt_tokens":N,"completion_tokens":M}}
//! ```
//!
//! `request` is [`request_hash`]: the BLAKE3 (key-derivation mode, context
//! `crawlx llm_cache request v1`) of the length-prefixed system prompt, the length-prefixed user
//! prompt and the key-sorted canonical JSON of the schema (or a `0` marker without one). An entry
//! holds only that hash, the model's JSON answer and the token counts: the prompts themselves,
//! the endpoint, the model name and the API key are never written. A hand-edited file is checked
//! like a live answer is by the caller, so entries are untrusted data; a later entry for the same
//! request replaces an earlier one. The file is created with mode `0600` on Unix.

use crate::llm::{Completion, LlmError, LlmExtractor, TokenUsage};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::OnceCell;

/// Version written to and required from every recording entry (`"v"`).
pub const FORMAT_VERSION: u32 = 1;

/// Key-derivation context of [`request_hash`].
const HASH_CONTEXT: &str = "crawlx llm_cache request v1";

/// Length of [`request_hash`] output (lowercase hex of a 32-byte digest).
const HASH_HEX_LEN: usize = 64;

/// Failures while opening or reading a recording.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LlmCacheError {
    /// The recording could not be read or the record file could not be opened.
    #[error("llm recording {}: {source}", path.display())]
    Io {
        /// The recording path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// A line of the recording is not a valid entry.
    #[error("llm recording {} line {line}: {reason}", path.display())]
    Corrupt {
        /// The recording path.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What is wrong with the line.
        reason: String,
    },
}

/// The per-run call budget is spent.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("LLM call cap of {max} reached")]
pub struct CallCapExceeded {
    /// The cap that was reached.
    pub max: u64,
}

impl From<CallCapExceeded> for LlmError {
    fn from(e: CallCapExceeded) -> Self {
        Self::CallCapExceeded { max: e.max }
    }
}

/// Per-run budget of inner LLM calls. Counting is atomic: under any interleaving exactly `max`
/// acquisitions succeed.
#[derive(Debug)]
pub struct CallCap {
    max: Option<u64>,
    used: AtomicU64,
}

impl CallCap {
    /// No limit (calls are still counted).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max: None,
            used: AtomicU64::new(0),
        }
    }

    /// At most `max` calls; `0` allows none.
    #[must_use]
    pub const fn limited(max: u64) -> Self {
        Self {
            max: Some(max),
            used: AtomicU64::new(0),
        }
    }

    /// Katana's `-ai-max-calls` convention: `0` means unlimited, any other value is the limit.
    #[must_use]
    pub const fn from_flag(max_calls: u64) -> Self {
        if max_calls == 0 {
            Self::unlimited()
        } else {
            Self::limited(max_calls)
        }
    }

    /// The limit, `None` when unlimited.
    #[must_use]
    pub const fn max(&self) -> Option<u64> {
        self.max
    }

    /// Calls charged so far.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Charge one call.
    ///
    /// # Errors
    /// [`CallCapExceeded`] when the limit is already reached; the counter is left unchanged.
    pub fn acquire(&self) -> Result<(), CallCapExceeded> {
        let max = self.max;
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| match max {
                Some(m) if n >= m => None,
                _ => Some(n.saturating_add(1)),
            })
            .map(drop)
            .map_err(|_| CallCapExceeded {
                max: max.unwrap_or(u64::MAX),
            })
    }
}

/// An [`LlmExtractor`] with no endpoint: every call fails with [`LlmError::NotConfigured`]. It is
/// the inner client of a replay-only [`RecordingLlm`], which never calls it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Offline;

#[async_trait]
impl LlmExtractor for Offline {
    async fn complete(
        &self,
        _system: &str,
        _user: &str,
        _schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        Err(LlmError::NotConfigured)
    }
}

/// What a [`RecordingLlm`] does with a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheMode {
    /// Pass through to the inner client (the call cap still applies).
    Off,
    /// Serve known requests from the recording, call the inner client for the rest and append.
    Record,
    /// Serve only from the recording; never call the inner client.
    Replay,
}

/// Append-only recording file shared by concurrent calls.
struct Sink {
    path: PathBuf,
    file: Mutex<File>,
}

impl Sink {
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let mut file = self.file.lock();
        file.write_all(line)?;
        file.flush()
    }
}

#[derive(Serialize)]
struct EntryRef<'a> {
    v: u32,
    request: &'a str,
    response: &'a Value,
    usage: UsageRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    v: u32,
    request: String,
    response: Value,
    usage: UsageRecord,
}

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
struct UsageRecord {
    prompt_tokens: u64,
    completion_tokens: u64,
}

type Cell = Arc<OnceCell<Completion<Value>>>;

/// Records, replays and caps the calls of an inner [`LlmExtractor`]. See the [module
/// docs](self).
pub struct RecordingLlm<L> {
    inner: L,
    mode: CacheMode,
    cap: CallCap,
    cells: Mutex<BTreeMap<String, Cell>>,
    sink: Option<Arc<Sink>>,
}

impl<L> std::fmt::Debug for RecordingLlm<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingLlm")
            .field("mode", &self.mode)
            .field("cap", &self.cap)
            .field("entries", &self.cells.lock().len())
            .finish_non_exhaustive()
    }
}

fn corrupt(path: &Path, line: usize, reason: impl Into<String>) -> LlmCacheError {
    LlmCacheError::Corrupt {
        path: path.to_owned(),
        line,
        reason: reason.into(),
    }
}

fn io_error(path: &Path, source: io::Error) -> LlmCacheError {
    LlmCacheError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Parse the text of a recording into request hash -> answer.
fn parse_recording(path: &Path, text: &str) -> Result<BTreeMap<String, Completion<Value>>, LlmCacheError> {
    let mut out = BTreeMap::new();
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let n = idx.saturating_add(1);
        let entry: Entry = serde_json::from_str(line).map_err(|e| corrupt(path, n, e.to_string()))?;
        if entry.v != FORMAT_VERSION {
            return Err(corrupt(path, n, format!("unsupported entry version {}", entry.v)));
        }
        let well_formed = entry.request.len() == HASH_HEX_LEN
            && entry
                .request
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed {
            return Err(corrupt(path, n, "request is not a 64-digit lowercase hex hash"));
        }
        out.insert(
            entry.request,
            Completion {
                value: entry.response,
                usage: TokenUsage {
                    prompt_tokens: entry.usage.prompt_tokens,
                    completion_tokens: entry.usage.completion_tokens,
                },
            },
        );
    }
    Ok(out)
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn initialised(entries: BTreeMap<String, Completion<Value>>) -> BTreeMap<String, Cell> {
    entries
        .into_iter()
        .map(|(key, completion)| (key, Arc::new(OnceCell::new_with(Some(completion)))))
        .collect()
}

impl<L> RecordingLlm<L> {
    /// Pass every call to `inner`, subject to `cap`; nothing is recorded.
    #[must_use]
    pub fn passthrough(inner: L, cap: CallCap) -> Self {
        Self {
            inner,
            mode: CacheMode::Off,
            cap,
            cells: Mutex::new(BTreeMap::new()),
            sink: None,
        }
    }

    /// Record to `path`: requests already in the file are answered from it, new answers are
    /// appended. A missing file is created (mode `0600` on Unix).
    ///
    /// # Errors
    /// [`LlmCacheError::Io`] when the file cannot be read or opened for appending,
    /// [`LlmCacheError::Corrupt`] when an existing entry is malformed.
    pub fn record(inner: L, path: &Path, cap: CallCap) -> Result<Self, LlmCacheError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io_error(path, e)),
        };
        let known = parse_recording(path, &text)?;
        let mut file = open_append(path).map_err(|e| io_error(path, e))?;
        if !text.is_empty() && !text.ends_with('\n') {
            // A crash left the last entry without its newline: do not glue the next one to it.
            file.write_all(b"\n").map_err(|e| io_error(path, e))?;
        }
        Ok(Self::with_sink(
            inner,
            cap,
            known,
            Sink {
                path: path.to_owned(),
                file: Mutex::new(file),
            },
        ))
    }

    fn with_sink(inner: L, cap: CallCap, known: BTreeMap<String, Completion<Value>>, sink: Sink) -> Self {
        Self {
            inner,
            mode: CacheMode::Record,
            cap,
            cells: Mutex::new(initialised(known)),
            sink: Some(Arc::new(sink)),
        }
    }

    /// Answer only from the recording at `path`; `inner` is kept for type uniformity and is
    /// never called (use [`Offline`] when no endpoint is configured).
    ///
    /// # Errors
    /// [`LlmCacheError::Io`] when the file cannot be read (including when it does not exist),
    /// [`LlmCacheError::Corrupt`] when an entry is malformed.
    pub fn replay(inner: L, path: &Path) -> Result<Self, LlmCacheError> {
        let text = std::fs::read_to_string(path).map_err(|e| io_error(path, e))?;
        let known = parse_recording(path, &text)?;
        Ok(Self {
            inner,
            mode: CacheMode::Replay,
            cap: CallCap::unlimited(),
            cells: Mutex::new(initialised(known)),
            sink: None,
        })
    }

    /// The mode this wrapper runs in.
    #[must_use]
    pub const fn mode(&self) -> CacheMode {
        self.mode
    }

    /// The wrapped client.
    #[must_use]
    pub const fn inner(&self) -> &L {
        &self.inner
    }

    /// The call budget (counts inner calls only: recorded answers are free).
    #[must_use]
    pub const fn cap(&self) -> &CallCap {
        &self.cap
    }

    /// Number of answers currently held (loaded from the recording plus answered this run).
    #[must_use]
    pub fn recorded_len(&self) -> usize {
        self.cells.lock().values().filter(|c| c.initialized()).count()
    }

    async fn append(&self, key: &str, completion: &Completion<Value>) -> Result<(), LlmError> {
        let Some(sink) = &self.sink else {
            return Ok(());
        };
        let entry = EntryRef {
            v: FORMAT_VERSION,
            request: key,
            response: &completion.value,
            usage: UsageRecord {
                prompt_tokens: completion.usage.prompt_tokens,
                completion_tokens: completion.usage.completion_tokens,
            },
        };
        let mut line = serde_json::to_vec(&entry)
            .map_err(|e| LlmError::RecordingFailed(format!("cannot encode entry: {e}")))?;
        line.push(b'\n');
        let sink = Arc::clone(sink);
        tokio::task::spawn_blocking(move || {
            sink.write_line(&line)
                .map_err(|e| format!("cannot append to {}: {}", sink.path.display(), e.kind()))
        })
        .await
        .map_err(|e| LlmError::RecordingFailed(format!("writer task failed: {e}")))?
        .map_err(LlmError::RecordingFailed)
    }
}

#[async_trait]
impl<L: LlmExtractor> LlmExtractor for RecordingLlm<L> {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        match self.mode {
            CacheMode::Off => {
                self.cap.acquire()?;
                self.inner.complete(system, user, schema).await
            }
            CacheMode::Replay => {
                let key = request_hash(system, user, schema);
                let hit = self.cells.lock().get(&key).and_then(|c| c.get().cloned());
                hit.ok_or(LlmError::NotRecorded { request: key })
            }
            CacheMode::Record => {
                let key = request_hash(system, user, schema);
                let cell = Arc::clone(self.cells.lock().entry(key.clone()).or_default());
                cell.get_or_try_init(|| async {
                    self.cap.acquire()?;
                    let completion = self.inner.complete(system, user, schema).await?;
                    self.append(&key, &completion).await?;
                    Ok::<_, LlmError>(completion)
                })
                .await
                .cloned()
            }
        }
    }

    fn max_input_chars(&self) -> usize {
        self.inner.max_input_chars()
    }

    /// Replay mode never calls the inner client, so it cannot transcribe.
    fn can_transcribe(&self) -> bool {
        self.mode != CacheMode::Replay && self.inner.can_transcribe()
    }

    /// Audio is not recorded (a recording holds JSON replies): `Off` and `Record` forward to the
    /// inner client under the call cap, `Replay` has no endpoint.
    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        if self.mode == CacheMode::Replay {
            return Err(LlmError::NotConfigured);
        }
        self.cap.acquire()?;
        self.inner.transcribe(audio, file_name, content_type).await
    }
}

/// Canonical JSON of `value` with object keys sorted, appended to `out`.
fn write_canonical(out: &mut String, value: &Value) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::from(key.as_str()).to_string());
                out.push(':');
                if let Some(v) = map.get(key) {
                    write_canonical(out, v);
                }
            }
            out.push('}');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// The recording key of a request: 64 lowercase hex digits of the BLAKE3 digest of the
/// length-prefixed `system`, the length-prefixed `user` and the canonical (key-sorted) JSON of
/// `schema`. Equal requests hash equally across runs, platforms and JSON key order; moving text
/// between `system` and `user` changes the hash.
#[must_use]
pub fn request_hash(system: &str, user: &str, schema: Option<&Value>) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(HASH_CONTEXT);
    for part in [system, user] {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    match schema {
        None => {
            hasher.update(&[0]);
        }
        Some(schema) => {
            hasher.update(&[1]);
            let mut canonical = String::new();
            write_canonical(&mut canonical, schema);
            hasher.update(canonical.as_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::llm::mock_llm::MockLlm;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn echo() -> MockLlm {
        MockLlm::from_fn(|call| Ok(json!({ "echo": call.user })))
    }

    /// Replies after a delay so concurrent callers overlap; counts inner calls.
    struct Slow {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl LlmExtractor for Slow {
        async fn complete(
            &self,
            _system: &str,
            user: &str,
            _schema: Option<&Value>,
        ) -> Result<Completion<Value>, LlmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(Completion {
                value: json!({ "slow": user }),
                usage: TokenUsage::default(),
            })
        }
    }

    #[tokio::test]
    async fn llm_cache_record_then_replay_is_identical_with_zero_inner_calls() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let schema = json!({"type":"object","properties":{"a":{"type":"string"}}});

        let rec = RecordingLlm::record(echo(), &file, CallCap::unlimited()).unwrap();
        let first = rec.complete("sys", "one", Some(&schema)).await.unwrap();
        let second = rec.complete("sys", "two", None).await.unwrap();
        let again = rec.complete("sys", "one", Some(&schema)).await.unwrap();
        assert_eq!(again, first, "a repeated request is served from the recording");
        assert_eq!(
            rec.inner().calls().len(),
            2,
            "the repeat did not reach the inner client"
        );
        assert_eq!(rec.cap().used(), 2);
        drop(rec);

        let replay = RecordingLlm::replay(MockLlm::scripted(vec![]), &file).unwrap();
        assert_eq!(replay.mode(), CacheMode::Replay);
        assert_eq!(replay.recorded_len(), 2);
        assert_eq!(replay.complete("sys", "two", None).await.unwrap(), second);
        assert_eq!(replay.complete("sys", "one", Some(&schema)).await.unwrap(), first);
        assert!(
            replay.inner().calls().is_empty(),
            "replay never calls the inner client"
        );
    }

    #[tokio::test]
    async fn llm_cache_record_resumes_an_existing_recording_without_charging_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let rec = RecordingLlm::record(echo(), &file, CallCap::unlimited()).unwrap();
        let known = rec.complete("s", "known", None).await.unwrap();
        drop(rec);

        let rec = RecordingLlm::record(echo(), &file, CallCap::limited(1)).unwrap();
        assert_eq!(rec.complete("s", "known", None).await.unwrap(), known);
        assert_eq!(rec.cap().used(), 0);
        rec.complete("s", "fresh", None).await.unwrap();
        assert_eq!(rec.cap().used(), 1);
        assert_eq!(rec.inner().calls().len(), 1);
        let text = std::fs::read_to_string(&file).unwrap();
        assert_eq!(text.lines().count(), 2, "one earlier entry plus one new entry");
    }

    #[tokio::test]
    async fn llm_cache_cap_is_enforced_and_typed() {
        let capped = RecordingLlm::passthrough(echo(), CallCap::limited(2));
        capped.complete("s", "a", None).await.unwrap();
        capped.complete("s", "a", None).await.unwrap();
        let err = capped.complete("s", "a", None).await.unwrap_err();
        assert_eq!(err, LlmError::CallCapExceeded { max: 2 });
        assert_eq!(
            capped.inner().calls().len(),
            2,
            "the refused call never reached the client"
        );
        assert_eq!(capped.cap().used(), 2);

        let none = RecordingLlm::passthrough(echo(), CallCap::limited(0));
        assert!(matches!(
            none.complete("s", "a", None).await,
            Err(LlmError::CallCapExceeded { max: 0 })
        ));
        assert!(none.inner().calls().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn llm_cache_cap_admits_exactly_max_calls_under_contention() {
        let llm = Arc::new(RecordingLlm::passthrough(echo(), CallCap::limited(5)));
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..64 {
            let llm = Arc::clone(&llm);
            tasks.spawn(async move { llm.complete("s", &format!("u{i}"), None).await });
        }
        let mut ok = 0;
        let mut refused = 0;
        while let Some(done) = tasks.join_next().await {
            match done.unwrap() {
                Ok(_) => ok += 1,
                Err(LlmError::CallCapExceeded { max: 5 }) => refused += 1,
                Err(other) => panic!("unexpected error {other}"),
            }
        }
        assert_eq!((ok, refused), (5, 59));
        assert_eq!(llm.cap().used(), 5);
        assert_eq!(llm.inner().calls().len(), 5);
    }

    #[test]
    fn llm_cache_flag_zero_means_unlimited() {
        assert_eq!(CallCap::from_flag(0).max(), None);
        assert_eq!(CallCap::from_flag(100).max(), Some(100));
        let cap = CallCap::from_flag(0);
        for _ in 0..1000 {
            cap.acquire().unwrap();
        }
        assert_eq!(cap.used(), 1000);
    }

    #[tokio::test]
    async fn llm_cache_replay_miss_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let rec = RecordingLlm::record(echo(), &file, CallCap::unlimited()).unwrap();
        rec.complete("s", "seen", None).await.unwrap();
        drop(rec);

        let replay = RecordingLlm::replay(Offline, &file).unwrap();
        let err = replay.complete("s", "unseen", None).await.unwrap_err();
        assert_eq!(
            err,
            LlmError::NotRecorded {
                request: request_hash("s", "unseen", None)
            }
        );
        assert_eq!(replay.cap().used(), 0, "a miss is not a call");
    }

    #[tokio::test]
    async fn llm_cache_concurrent_identical_requests_share_one_inner_call() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let slow = Slow {
            calls: AtomicUsize::new(0),
        };
        let llm = Arc::new(RecordingLlm::record(slow, &file, CallCap::limited(1)).unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let llm = Arc::clone(&llm);
            tasks.spawn(async move { llm.complete("s", "same", None).await });
        }
        while let Some(done) = tasks.join_next().await {
            assert_eq!(done.unwrap().unwrap().value, json!({"slow":"same"}));
        }
        assert_eq!(llm.inner().calls.load(Ordering::SeqCst), 1);
        assert_eq!(llm.cap().used(), 1);
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn llm_cache_off_mode_passes_through_and_writes_nothing() {
        let llm = RecordingLlm::passthrough(echo(), CallCap::unlimited());
        assert_eq!(llm.mode(), CacheMode::Off);
        llm.complete("s", "x", None).await.unwrap();
        llm.complete("s", "x", None).await.unwrap();
        assert_eq!(llm.inner().calls().len(), 2, "passthrough does not deduplicate");
        assert_eq!(llm.recorded_len(), 0);
    }

    #[tokio::test]
    async fn llm_cache_inner_error_is_not_recorded_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let flaky = MockLlm::scripted(vec![
            Err(LlmError::Status { status: 503 }),
            Ok(json!({"ok": true})),
        ]);
        let llm = RecordingLlm::record(flaky, &file, CallCap::unlimited()).unwrap();
        assert_eq!(
            llm.complete("s", "u", None).await.unwrap_err(),
            LlmError::Status { status: 503 }
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "");
        assert_eq!(
            llm.complete("s", "u", None).await.unwrap().value,
            json!({"ok": true})
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn llm_cache_recording_file_format_is_stable_and_holds_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let mock = MockLlm::from_fn(|_| Ok(json!({"b": 2, "a": [1, "x"]})));
        let llm = RecordingLlm::record(mock, &file, CallCap::unlimited()).unwrap();
        llm.complete(
            "Bearer sk-secret-system",
            "api_key=sk-secret-user",
            Some(&json!({"type":"object"})),
        )
        .await
        .unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let hash = request_hash(
            "Bearer sk-secret-system",
            "api_key=sk-secret-user",
            Some(&json!({"type":"object"})),
        );
        assert_eq!(
            text,
            format!(
                "{{\"v\":1,\"request\":\"{hash}\",\"response\":{{\"a\":[1,\"x\"],\"b\":2}},\
                 \"usage\":{{\"prompt_tokens\":12,\"completion_tokens\":5}}}}\n"
            )
        );
        assert!(
            !text.contains("sk-secret") && !text.contains("Bearer"),
            "prompts and keys are never written"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn llm_cache_record_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        drop(RecordingLlm::record(echo(), &file, CallCap::unlimited()).unwrap());
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn llm_cache_request_hash_is_pinned() {
        // Computed independently with the reference `blake3` implementation (derive-key mode).
        assert_eq!(
            request_hash("system", "user", None),
            "563ea92c72aa3d33a60af92f371e49bde9f1a44dd841ce80cbbecf10793ba048"
        );
        assert_eq!(
            request_hash("system", "user", Some(&json!({"type":"object","required":["a"]}))),
            "264522894d2c4d0524fd7de9569c75ee851f8aa863dbdcb01352550a59303fab"
        );
    }

    #[test]
    fn llm_cache_request_hash_is_canonical() {
        let a = json!({"type":"object","properties":{"x":{"type":"string"},"y":{"type":"number"}}});
        let b = json!({"properties":{"y":{"type":"number"},"x":{"type":"string"}},"type":"object"});
        assert_eq!(request_hash("s", "u", Some(&a)), request_hash("s", "u", Some(&b)));
        assert_ne!(request_hash("s", "u", Some(&a)), request_hash("s", "u", None));
        assert_ne!(request_hash("ab", "c", None), request_hash("a", "bc", None));
        assert_ne!(request_hash("s", "u", None), request_hash("s", "v", None));
        assert_eq!(request_hash("s", "u", None).len(), 64);
    }

    #[test]
    fn llm_cache_corrupt_recordings_are_typed_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let hash = request_hash("s", "u", None);
        let ok = format!(
            "{{\"v\":1,\"request\":\"{hash}\",\"response\":1,\"usage\":{{\"prompt_tokens\":0,\"completion_tokens\":0}}}}"
        );
        let cases = [
            (format!("{ok}\nnot json\n"), 2, "expected"),
            (ok.replace("\"v\":1", "\"v\":2"), 1, "unsupported entry version 2"),
            (ok.replace(&hash, "XYZ"), 1, "64-digit lowercase hex"),
            (
                ok.replace("\"v\":1", "\"v\":1,\"extra\":true"),
                1,
                "unknown field",
            ),
        ];
        for (text, line, needle) in cases {
            std::fs::write(&file, &text).unwrap();
            for result in [
                RecordingLlm::replay(Offline, &file).map(drop),
                RecordingLlm::record(Offline, &file, CallCap::unlimited()).map(drop),
            ] {
                match result {
                    Err(LlmCacheError::Corrupt { line: l, reason, .. }) => {
                        assert_eq!(l, line, "{text}");
                        assert!(reason.contains(needle), "{reason} vs {needle}");
                    }
                    other => panic!("expected Corrupt, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn llm_cache_replay_of_a_missing_file_and_record_into_a_directory_fail() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.jsonl");
        assert!(matches!(
            RecordingLlm::replay(Offline, &missing),
            Err(LlmCacheError::Io { .. })
        ));
        assert!(!missing.exists(), "replay never creates the file");
        assert!(matches!(
            RecordingLlm::record(Offline, dir.path(), CallCap::unlimited()),
            Err(LlmCacheError::Io { .. })
        ));
    }

    #[tokio::test]
    async fn llm_cache_record_after_a_torn_last_line_starts_a_new_line() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ai.jsonl");
        let hash = request_hash("s", "old", None);
        std::fs::write(
            &file,
            format!("{{\"v\":1,\"request\":\"{hash}\",\"response\":1,\"usage\":{{\"prompt_tokens\":0,\"completion_tokens\":0}}}}"),
        )
        .unwrap();
        let llm = RecordingLlm::record(echo(), &file, CallCap::unlimited()).unwrap();
        llm.complete("s", "new", None).await.unwrap();
        drop(llm);
        let replay = RecordingLlm::replay(Offline, &file).unwrap();
        assert_eq!(replay.recorded_len(), 2);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn llm_cache_write_failure_fails_the_call_and_is_not_cached() {
        let full = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap();
        let sink = Sink {
            path: PathBuf::from("/dev/full"),
            file: Mutex::new(full),
        };
        let llm = RecordingLlm::with_sink(echo(), CallCap::unlimited(), BTreeMap::new(), sink);
        let err = llm.complete("s", "u", None).await.unwrap_err();
        assert!(
            matches!(&err, LlmError::RecordingFailed(m) if m.contains("/dev/full")),
            "{err}"
        );
        assert_eq!(llm.recorded_len(), 0, "an unrecorded answer is not served later");
    }
}
