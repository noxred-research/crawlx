//! Bounded declarative queue import. Never executes source-language code or object formats.
//!
//! Exporters must attach exact source release/commit and exported identity material.
//! Source keys stay in volatile parsing memory and become tenant-keyed digests.
use super::{IdentityDialectV1, RequestEnvelopeV1, MAX_REQUEST_BATCH, MAX_REQUEST_BATCH_BYTES};
use crate::hash::Digest;
use crate::orchestration::{LoaderCursorV1, RequestBatchV1};
use crate::url::CanonicalUrl;
use crate::{CrawlRunId, TenantId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

/// Exact source snapshots accepted by the clean-room importer.
pub const SOURCE_PINS: [(&str, &str, &str); 4] = [
    (
        "js_actor_3_18",
        "3.18.2",
        "78da0622762e1b569b5cb0b56e8eb06a0a010d93",
    ),
    (
        "py_actor_1_11",
        "1.11.0",
        "c6695f149649807f14de43694fcc073a9b1bd4ca",
    ),
    (
        "python_spider_2_19",
        "2.19.0",
        "8026deeaac371a5d9a3edbe4886d58f61139d464",
    ),
    (
        "go_collector_2_2",
        "2.2.0",
        "fe55a16e8d16a006df76b5edc57cfaf83ae0b3ea",
    ),
];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Export {
    version: u16,
    source: Source,
    requests: Vec<Row>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    dialect: IdentityDialectV1,
    release: String,
    commit: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Row {
    url: Url,
    #[serde(default = "get")]
    method: String,
    /// The source runtime computed this key using its own pinned semantics.
    source_key: String,
    #[serde(default)]
    explicit_key: bool,
    #[serde(default)]
    always_enqueue: bool,
    #[serde(default)]
    dont_filter: bool,
    #[serde(default)]
    allow_url_revisit: bool,
    #[serde(default)]
    depth: u16,
    #[serde(default)]
    priority: i32,
    #[serde(default = "route")]
    route: String,
    #[serde(default)]
    metadata: BTreeMap<String, serde_json::Value>,
}
fn get() -> String {
    "GET".into()
}
fn route() -> String {
    "default".into()
}

/// Decode a pinned upstream JSON export into bounded immutable native proposals.
///
/// The supplied canonicalizer must use the admitted run's URL policy. The correlation
/// key must be tenant-scoped and operator-managed. `batch_id` must be the stable
/// tenant-keyed native batch identity, not a raw caller idempotency key. Only source
/// dedupe-bypass rows include it, so retries reuse identities while distinct batches
/// create distinct work. Proposals still require native scope/robots/authorization/effect
/// admission; this function grants no traffic authority.
/// HEAD proposals preserve their method for bodyless native HTTP execution; importing
/// them does not grant browser, delegated or body-bearing execution capabilities.
/// Raw pickle, gob, module paths, callback code, inline bodies and unknown keys are rejected.
///
/// # Errors
/// Rejects oversized bytes/rows, invalid JSON, incorrect pins, unsupported semantics,
/// credentials in URLs and methods other than GET or HEAD without an existing journal adapter.
pub fn decode_export<F>(
    bytes: &[u8],
    tenant_key: &[u8; 32],
    batch_id: Digest,
    mut canonicalize: F,
) -> Result<Vec<RequestEnvelopeV1>, ImportError>
where
    F: FnMut(&Url) -> Result<CanonicalUrl, ImportError>,
{
    if bytes.len() > MAX_REQUEST_BATCH_BYTES {
        return Err(ImportError::Limit);
    }
    let export: Export = serde_json::from_slice(bytes).map_err(|_| ImportError::Format)?;
    if export.version != 1 || export.requests.len() > MAX_REQUEST_BATCH {
        return Err(ImportError::Limit);
    }
    let pin = match export.source.dialect {
        IdentityDialectV1::JsActor318 => SOURCE_PINS[0],
        IdentityDialectV1::PyActor111 => SOURCE_PINS[1],
        IdentityDialectV1::PythonSpider219 => SOURCE_PINS[2],
        IdentityDialectV1::GoCollector22 => SOURCE_PINS[3],
        _ => return Err(ImportError::SourcePin),
    };
    if export.source.release != pin.1 || export.source.commit != pin.2 {
        return Err(ImportError::SourcePin);
    }
    decode_rows(
        export,
        tenant_key,
        batch_id,
        Digest::keyed(tenant_key, "crawlx/source-request-export/v1", bytes),
        &mut canonicalize,
    )
}

fn decode_rows<F>(
    export: Export,
    tenant_key: &[u8; 32],
    batch_id: Digest,
    source_digest: Digest,
    canonicalize: &mut F,
) -> Result<Vec<RequestEnvelopeV1>, ImportError>
where
    F: FnMut(&Url) -> Result<CanonicalUrl, ImportError>,
{
    let mut requests = Vec::with_capacity(export.requests.len());
    for (ordinal, row) in export.requests.into_iter().enumerate() {
        if !matches!(row.method.as_str(), "GET" | "HEAD") {
            return Err(ImportError::JournalRequired);
        }
        if row.source_key.is_empty()
            || row.source_key.len() > 4096
            || !matches!(row.url.scheme(), "http" | "https")
            || row.url.host_str().is_none()
            || !row.url.username().is_empty()
            || row.url.password().is_some()
        {
            return Err(ImportError::Request);
        }
        if (row.always_enqueue && export.source.dialect != IdentityDialectV1::PyActor111)
            || (row.dont_filter && export.source.dialect != IdentityDialectV1::PythonSpider219)
            || (row.allow_url_revisit && export.source.dialect != IdentityDialectV1::GoCollector22)
            || (row.always_enqueue && row.explicit_key)
        {
            return Err(ImportError::DialectConflict);
        }
        let bypass_source_dedupe = row.always_enqueue || row.dont_filter || row.allow_url_revisit;
        let material = if bypass_source_dedupe {
            serde_json::to_vec(&(batch_id, source_digest, ordinal, &row.source_key))
                .map_err(|_| ImportError::Request)?
        } else {
            row.source_key.into_bytes()
        };
        let mut envelope = RequestEnvelopeV1::new(canonicalize(&row.url)?, row.method, row.depth, None);
        envelope.dialect = export.source.dialect;
        envelope.source_key = Some(Digest::keyed(
            tenant_key,
            "crawlx/imported-request-key/v1",
            &material,
        ));
        envelope.route = row.route;
        envelope.metadata = row.metadata;
        envelope.priority = row.priority;
        envelope.validate().map_err(|_| ImportError::Request)?;
        requests.push(envelope);
    }
    Ok(requests)
}

/// Authority supplied by an authenticated caller, never deserialized from an export.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ImportAdmissionV1 {
    /// Authenticated tenant.
    pub tenant: TenantId,
    /// Existing admitted run.
    pub run: CrawlRunId,
    /// Principal already admitted to that run.
    pub principal: String,
    /// Tenant-keyed native retry identity.
    pub batch_id: Digest,
    /// Current native producer generation.
    pub producer_epoch: u64,
}

impl ImportAdmissionV1 {
    /// Bind an import proposal to separately authenticated native authority.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        principal: String,
        batch_id: Digest,
        producer_epoch: u64,
    ) -> Self {
        Self {
            tenant,
            run,
            principal,
            batch_id,
            producer_epoch,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointExport {
    version: u16,
    source: String,
    producer_epoch: u64,
    expected_cursor: Option<LoaderCursorV1>,
    end_position: u64,
    export: Export,
}

/// Compile a trusted JSON queue checkpoint into one native atomic append proposal.
///
/// The export contains the complete immutable bounded source list, not source object
/// graphs. The authenticated caller supplies the live epoch and persisted cursor.
/// Source changes, stale cursors and stale epochs fail before any mutation. Only the
/// uncommitted interval is proposed; already completed entries are never revived.
/// The returned batch must still pass live scope, robots, route and authorization
/// admission, then `FrontierRepo::append_batch` for transactional epoch/cursor checks.
///
/// # Errors
/// Returns a bounded import error for malformed JSON, source pins, changed source,
/// stale authority, incompatible cursors, unsafe methods or native batch limits.
pub fn decode_checkpoint_export<F>(
    bytes: &[u8],
    tenant_key: &[u8; 32],
    admission: ImportAdmissionV1,
    current_cursor: Option<&LoaderCursorV1>,
    mut canonicalize: F,
) -> Result<RequestBatchV1, ImportError>
where
    F: FnMut(&Url) -> Result<CanonicalUrl, ImportError>,
{
    if bytes.len() > MAX_REQUEST_BATCH_BYTES {
        return Err(ImportError::Limit);
    }
    let checkpoint: CheckpointExport = serde_json::from_slice(bytes).map_err(|_| ImportError::Format)?;
    if checkpoint.version != 1
        || !super::safe_id(&checkpoint.source)
        || admission.producer_epoch == 0
        || checkpoint.producer_epoch != admission.producer_epoch
    {
        return Err(ImportError::Checkpoint);
    }
    let source_bytes = serde_json::to_vec(&checkpoint.export).map_err(|_| ImportError::Format)?;
    let source_digest = Digest::keyed(tenant_key, "crawlx/checkpoint-request-export/v1", &source_bytes);
    let start = checkpoint
        .expected_cursor
        .as_ref()
        .map_or(0, |cursor| cursor.position);
    let end = checkpoint.end_position;
    let row_count = u64::try_from(checkpoint.export.requests.len()).map_err(|_| ImportError::Limit)?;
    if checkpoint.export.version != 1
        || checkpoint.export.requests.len() > MAX_REQUEST_BATCH
        || end > row_count
        || end < start
        || checkpoint
            .expected_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.source != checkpoint.source || cursor.source_digest != source_digest)
        || (checkpoint.expected_cursor.as_ref() != current_cursor
            && !current_cursor.is_some_and(|cursor| {
                cursor.source == checkpoint.source
                    && cursor.source_digest == source_digest
                    && cursor.position == end
            }))
    {
        return Err(ImportError::Checkpoint);
    }
    // An exact end-position retry is only a replay candidate. append_batch must
    // find its original receipt; a different batch identity still fails cursor CAS.
    let source = &checkpoint.export.source;
    let pin = match source.dialect {
        IdentityDialectV1::JsActor318 => SOURCE_PINS[0],
        IdentityDialectV1::PyActor111 => SOURCE_PINS[1],
        IdentityDialectV1::PythonSpider219 => SOURCE_PINS[2],
        IdentityDialectV1::GoCollector22 => SOURCE_PINS[3],
        _ => return Err(ImportError::SourcePin),
    };
    if source.release != pin.1 || source.commit != pin.2 {
        return Err(ImportError::SourcePin);
    }
    // Decode the complete snapshot before slicing so unsupported committed rows
    // cannot hide executable or malformed source semantics during resume.
    let requests = decode_rows(
        checkpoint.export,
        tenant_key,
        admission.batch_id,
        source_digest,
        &mut canonicalize,
    )?;
    let skip = usize::try_from(start).map_err(|_| ImportError::Checkpoint)?;
    let take = usize::try_from(end - start).map_err(|_| ImportError::Checkpoint)?;
    let mut batch = RequestBatchV1::new(
        admission.tenant,
        admission.run,
        admission.principal,
        admission.batch_id,
        requests.into_iter().skip(skip).take(take).collect(),
    );
    batch.producer_epoch = admission.producer_epoch;
    batch.expected_cursor = checkpoint.expected_cursor;
    batch.next_cursor = Some(LoaderCursorV1::new(checkpoint.source, source_digest, end));
    batch.validate().map_err(|_| ImportError::Checkpoint)?;
    Ok(batch)
}

/// Import failure names a bounded code, never raw source content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImportError {
    /// Byte/row/version ceiling exceeded.
    #[error("request import limit exceeded")]
    Limit,
    /// Native importer accepts strict JSON only.
    #[error("invalid declarative request export")]
    Format,
    /// Source release or commit does not match its own dialect.
    #[error("request export source pin mismatch")]
    SourcePin,
    /// A source-language option conflicts with this dialect.
    #[error("request export identity options conflict")]
    DialectConflict,
    /// Unsafe method needs the existing safety/journal path.
    #[error("request method requires admitted effect journal")]
    JournalRequired,
    /// URL, exported key or metadata is invalid.
    #[error("invalid imported request")]
    Request,
    /// Live producer, immutable source or expected committed position differs.
    #[error("request checkpoint conflicts with admitted frontier")]
    Checkpoint,
}

#[cfg(test)]
mod checkpoint_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::url::RouteTemplate;
    use serde_json::{json, Value};

    fn canonical(raw: &Url) -> Result<CanonicalUrl, ImportError> {
        Ok(CanonicalUrl {
            url: raw.clone(),
            key: Digest::of("test/canonical", raw.as_str().as_bytes()),
            origin: raw.origin().ascii_serialization(),
            route_template: RouteTemplate(raw.path().into()),
            params: Vec::new(),
        })
    }

    fn admission() -> ImportAdmissionV1 {
        ImportAdmissionV1::new(
            TenantId::new(),
            CrawlRunId::new(),
            "anonymous".into(),
            Digest::of("test/batch", b"one"),
            1,
        )
    }

    fn checkpoint(pin: (&str, &str, &str)) -> Value {
        json!({
            "version":1,"source":"fixture","producerEpoch":1,
            "expectedCursor":null,"endPosition":1,
            "export":{"version":1,
                "source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
                "requests":[
                    {"url":"https://fixture.test/a?resource=1","sourceKey":"private-one"},
                    {"url":"https://fixture.test/b?resource=2","sourceKey":"private-two","method":"HEAD"}
                ]}
        })
    }

    fn decode(
        value: &Value,
        authority: ImportAdmissionV1,
        current: Option<&LoaderCursorV1>,
    ) -> Result<RequestBatchV1, ImportError> {
        decode_checkpoint_export(
            &serde_json::to_vec(value).unwrap(),
            &[7; 32],
            authority,
            current,
            canonical,
        )
    }

    #[test]
    fn four_pinned_snapshots_resume_only_uncommitted_interval() {
        for pin in SOURCE_PINS {
            let mut value = checkpoint(pin);
            let first = decode(&value, admission(), None).unwrap();
            assert_eq!(first.requests.len(), 1);
            assert_eq!(first.requests[0].url.url.query(), Some("resource=1"));
            let current = first.next_cursor.unwrap();
            value["expectedCursor"] = serde_json::to_value(&current).unwrap();
            value["endPosition"] = json!(2);
            let second = decode(&value, admission(), Some(&current)).unwrap();
            assert_eq!(second.requests.len(), 1);
            assert_eq!(second.requests[0].method, "HEAD");
            assert_eq!(second.expected_cursor.as_ref(), Some(&current));
            assert_eq!(second.next_cursor.as_ref().unwrap().position, 2);
            let serialized = serde_json::to_string(&second).unwrap();
            assert!(!serialized.contains("private-one"));
            assert!(!serialized.contains("private-two"));
        }
    }

    #[test]
    fn stale_epoch_cursor_source_and_tenant_key_fail_before_append() {
        let mut value = checkpoint(SOURCE_PINS[2]);
        let first = decode(&value, admission(), None).unwrap();
        let current = first.next_cursor.unwrap();
        value["expectedCursor"] = serde_json::to_value(&current).unwrap();
        value["endPosition"] = json!(2);
        let mut stale = admission();
        stale.producer_epoch = 2;
        assert_eq!(
            decode(&value, stale, Some(&current)),
            Err(ImportError::Checkpoint)
        );
        assert_eq!(decode(&value, admission(), None), Err(ImportError::Checkpoint));
        value["export"]["requests"][1]["url"] = json!("https://fixture.test/changed");
        assert_eq!(
            decode(&value, admission(), Some(&current)),
            Err(ImportError::Checkpoint)
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            decode_checkpoint_export(&bytes, &[8; 32], admission(), Some(&current), canonical),
            Err(ImportError::Checkpoint)
        );
    }

    #[test]
    fn committed_rows_cannot_hide_unsafe_or_unknown_semantics() {
        let mut value = checkpoint(SOURCE_PINS[0]);
        let current = decode(&value, admission(), None).unwrap().next_cursor.unwrap();
        value["expectedCursor"] = serde_json::to_value(&current).unwrap();
        value["export"]["requests"][0]["method"] = json!("POST");
        assert!(decode(&value, admission(), Some(&current)).is_err());
        value = checkpoint(SOURCE_PINS[0]);
        value["export"]["requests"][0]["callback"] = json!("private-callback");
        let error = decode(&value, admission(), None).unwrap_err().to_string();
        assert!(!error.contains("private-callback"));
        assert!(!error.contains("callback"));
    }

    #[test]
    fn non_http_and_binary_graphs_are_never_imported() {
        let mut value = checkpoint(SOURCE_PINS[0]);
        value["export"]["requests"][0]["url"] = json!("file:///private/source");
        assert_eq!(decode(&value, admission(), None), Err(ImportError::Request));
        for bytes in [b"pickle".as_slice(), b"gob", b"\x80\x04N."] {
            assert_eq!(
                decode_checkpoint_export(bytes, &[7; 32], admission(), None, canonical),
                Err(ImportError::Format)
            );
        }
    }
}
