//! Bounded declarative queue import. Never executes source-language code or object formats.
//!
//! Exporters must attach exact source release/commit and exported identity material.
//! Source keys stay in volatile parsing memory and become tenant-keyed digests.
use super::{IdentityDialectV1, RequestEnvelopeV1, MAX_REQUEST_BATCH, MAX_REQUEST_BATCH_BYTES};
use crate::hash::Digest;
use crate::url::CanonicalUrl;
use serde::Deserialize;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Export {
    version: u16,
    source: Source,
    requests: Vec<Row>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    dialect: IdentityDialectV1,
    release: String,
    commit: String,
}
#[derive(Deserialize)]
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
    let source_digest = Digest::keyed(tenant_key, "crawlx/source-request-export/v1", bytes);
    let mut requests = Vec::with_capacity(export.requests.len());
    for (ordinal, row) in export.requests.into_iter().enumerate() {
        if !matches!(row.method.as_str(), "GET" | "HEAD") {
            return Err(ImportError::JournalRequired);
        }
        if row.source_key.is_empty()
            || row.source_key.len() > 4096
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
}
