//! Pinned, offline contract-to-fixture compilation and golden comparison.
//!
//! Contracts use a closed JSON schema subset, not executable source or remote references.
//! Golden exports are authored snapshots in the existing differential wire shape. A passing
//! result establishes local fixture agreement only: external runtime parity and reference
//! performance remain unavailable. Diagnostics contain counts and codes, never captured bytes.

use crate::differential::{CrawlxRun, DifferentialRunner, Ledger, Thresholds, UpstreamExport, Verdict};
use crawlx_core::hash::Digest;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_BYTES: usize = 262_144;
const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 16_384;
const MAX_ITEMS: usize = 1_024;
const MAX_PAGES: usize = 128;
const MAX_TEXT: usize = 4_096;
const DOMAIN: &str = "crawlx/migration-contract-fixture/v1";

/// Failure without untrusted input, URLs, parser messages, or captured content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContractError {
    /// Input or work exceeds a fixed compiler bound.
    #[error("contract input exceeds a fixed bound")]
    Limit,
    /// Bytes do not match the caller's trusted content pin.
    #[error("contract fixture pin mismatch")]
    Pin,
    /// JSON, schema, URL, source revision, or a setting is invalid or unsupported.
    #[error("invalid declarative contract fixture")]
    Invalid,
    /// Caller cancelled before publication; no partial result is returned.
    #[error("contract evaluation cancelled")]
    Cancelled,
}

/// One closed schema node. Objects reject all undeclared fields; no references are resolved.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Schema {
    Object {
        properties: BTreeMap<String, Schema>,
        required: Vec<String>,
    },
    Array {
        items: Box<Schema>,
        max_items: usize,
    },
    String {
        max_length: usize,
    },
    Integer,
    Number,
    Boolean,
    Null,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    version: u16,
    source_revision: String,
    origin: String,
    urls: Vec<String>,
    item_count: Count,
    item_schema: Schema,
    privacy: Privacy,
    thresholds: Policy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Count {
    min: usize,
    max: usize,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Privacy {
    Retained,
    MetadataOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    markdown_page: f64,
    markdown_corpus: f64,
    links: f64,
    metadata: f64,
    block_f1: f64,
    max_evaluation_micros: u64,
}

/// Compiled immutable fixture. Debug deliberately hides contract and golden contents.
#[must_use]
pub struct CompiledFixture {
    contract: Contract,
    golden: UpstreamExport,
    origin: Url,
    urls: BTreeSet<String>,
    pin: Digest,
}

impl fmt::Debug for CompiledFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompiledFixture([redacted])")
    }
}

/// Why a measured local assertion failed. No subject strings leave the harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Failure {
    /// Succeeded URLs differ from the exact contract set, including resource queries.
    UrlSet,
    /// Item count lies outside the inclusive pinned interval.
    ItemCount,
    /// At least one item violates the closed schema.
    ItemSchema,
    /// Existing differential comparison found an undocumented difference.
    GoldenDifference,
    /// Content appeared in a metadata-only capture.
    Privacy,
    /// Actual local evaluation time exceeded the pinned local ceiling.
    EvaluationTime,
}

/// Explicitly unavailable external evidence; never inferred from an authored golden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExternalEvidence {
    /// No pinned external runtime capture or measured runtime performance was supplied.
    ExternalRequired,
}

/// Privacy-safe measurements from one completed local comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[must_use]
pub struct ContractReport {
    /// Digest of the exact compiled contract bytes.
    pub contract_pin: Digest,
    /// Number of succeeded native pages, not a runtime throughput metric.
    pub pages: usize,
    /// Number of native emitted items.
    pub items: usize,
    /// Number of items that fail schema validation.
    pub schema_failures: usize,
    /// Number of findings from the existing differential engine.
    pub differential_findings: usize,
    /// Measured monotonic local parsing, assertion, and comparison duration.
    pub evaluation_micros: u64,
    /// Pinned ceiling applied to this local measurement.
    pub max_evaluation_micros: u64,
    /// Stable failure codes in evaluation order.
    pub failures: Vec<Failure>,
    /// External runtime and reference performance are not claimed.
    pub external_evidence: ExternalEvidence,
}

impl ContractReport {
    /// Whether every local assertion and measured local ceiling passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Pin exact fixture bytes with the existing domain-separated content digest.
///
/// Pins must come from trusted fixture bytes, not from untrusted input being checked.
#[must_use]
pub fn fixture_pin(bytes: &[u8]) -> Digest {
    Digest::of(DOMAIN, bytes)
}

/// Compile a pinned contract and pinned authored golden without I/O or code execution.
///
/// JSON is capped at 256 KiB, depth 24, and 16,384 structural nodes per input. The schema
/// subset supports closed objects, bounded arrays and strings, and scalar JSON types.
/// URLs must be absolute HTTP(S), without credentials or fragments, on the pinned origin.
///
/// # Errors
/// Returns a redacted error on pin mismatch, unsupported data, fixed bounds, or cancellation.
pub fn compile_fixture(
    contract_bytes: &[u8],
    golden_bytes: &[u8],
    pins: [Digest; 2],
    cancel: &CancellationToken,
) -> Result<CompiledFixture, ContractError> {
    check_cancel(cancel)?;
    for (bytes, pin) in [(contract_bytes, pins[0]), (golden_bytes, pins[1])] {
        if bytes.len() > MAX_BYTES {
            return Err(ContractError::Limit);
        }
        if fixture_pin(bytes) != pin {
            return Err(ContractError::Pin);
        }
    }
    let contract: Contract = parse(contract_bytes, cancel)?;
    if contract.version != 1
        || contract.source_revision.len() != 40
        || !contract.source_revision.bytes().all(|b| b.is_ascii_hexdigit())
        || contract.urls.len() > MAX_PAGES
        || contract.item_count.min > contract.item_count.max
        || contract.item_count.max > MAX_ITEMS
    {
        return Err(ContractError::Invalid);
    }
    contract.item_schema.validate(0)?;
    contract.thresholds.validate()?;
    let origin = safe_url(&contract.origin)?;
    if origin.path() != "/" || origin.query().is_some() {
        return Err(ContractError::Invalid);
    }
    let mut urls = BTreeSet::new();
    for raw in &contract.urls {
        check_cancel(cancel)?;
        let url = same_origin(raw, &origin)?;
        if !urls.insert(url.to_string()) {
            return Err(ContractError::Invalid);
        }
    }
    let golden: UpstreamExport = parse(golden_bytes, cancel)?;
    validate_golden(&golden, &origin)?;
    let mut golden_urls = BTreeSet::new();
    for page in &golden.data {
        check_cancel(cancel)?;
        if page.metadata.status_code.is_some_and(|status| status >= 400)
            || !golden_urls.insert(same_origin(&page.metadata.source_url, &origin)?.to_string())
        {
            return Err(ContractError::Invalid);
        }
        if contract.privacy == Privacy::MetadataOnly
            && (page.markdown.is_some()
                || page.metadata.title.is_some()
                || page.metadata.description.is_some())
        {
            return Err(ContractError::Invalid);
        }
    }
    if golden_urls != urls {
        return Err(ContractError::Invalid);
    }
    let fixture = CompiledFixture {
        contract,
        golden,
        origin,
        urls,
        pin: pins[0],
    };
    check_cancel(cancel)?;
    Ok(fixture)
}

impl CompiledFixture {
    /// Compare native run JSON and emitted-item array with the compiled golden.
    ///
    /// Uses existing native and reference differential DTOs without changing their semantics.
    /// Every returned result reports external evidence as `external_required`. Captures stay
    /// in memory; reports contain no URLs, item values, terminal messages, or markdown.
    /// Cancellation returns no partial measurements. The existing synchronous comparator is
    /// one bounded, non-preemptible section, checked immediately before and after invocation.
    ///
    /// # Errors
    /// Returns a redacted error for malformed/oversized captures or cancellation.
    pub fn evaluate(
        &self,
        native_bytes: &[u8],
        item_bytes: &[u8],
        cancel: &CancellationToken,
    ) -> Result<ContractReport, ContractError> {
        let start = Instant::now();
        let native: CrawlxRun = parse(native_bytes, cancel)?;
        let items: Vec<Value> = parse(item_bytes, cancel)?;
        validate_native(&native, &self.origin)?;
        if items.len() > MAX_ITEMS {
            return Err(ContractError::Limit);
        }
        let mut failures = Vec::new();
        let mut urls = BTreeSet::new();
        for page in &native.pages {
            check_cancel(cancel)?;
            if !urls.insert(same_origin(&page.url, &self.origin)?.to_string()) {
                failures.push(Failure::UrlSet);
            }
        }
        if urls != self.urls && !failures.contains(&Failure::UrlSet) {
            failures.push(Failure::UrlSet);
        }
        if !(self.contract.item_count.min..=self.contract.item_count.max).contains(&items.len()) {
            failures.push(Failure::ItemCount);
        }
        let mut schema_failures = 0;
        for item in &items {
            check_cancel(cancel)?;
            if !self.contract.item_schema.matches(item, cancel)? {
                schema_failures += 1;
            }
        }
        if schema_failures != 0 {
            failures.push(Failure::ItemSchema);
        }
        if self.contract.privacy == Privacy::MetadataOnly
            && (!items.is_empty() || native.pages.iter().any(has_content))
        {
            failures.push(Failure::Privacy);
        }
        check_cancel(cancel)?;
        let differential = DifferentialRunner::new(Ledger::default())
            .with_label("migration-contract")
            .with_thresholds(self.contract.thresholds.differential())
            .compare(&self.golden, &self.origin, &native, &self.origin);
        check_cancel(cancel)?;
        if differential.verdict() != Verdict::Pass {
            failures.push(Failure::GoldenDifference);
        }
        let evaluation_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        if evaluation_micros > self.contract.thresholds.max_evaluation_micros {
            failures.push(Failure::EvaluationTime);
        }
        Ok(ContractReport {
            contract_pin: self.pin,
            pages: native.pages.len(),
            items: items.len(),
            schema_failures,
            differential_findings: differential.findings.len(),
            evaluation_micros,
            max_evaluation_micros: self.contract.thresholds.max_evaluation_micros,
            failures,
            external_evidence: ExternalEvidence::ExternalRequired,
        })
    }
}

impl Policy {
    fn validate(&self) -> Result<(), ContractError> {
        if [
            self.markdown_page,
            self.markdown_corpus,
            self.links,
            self.metadata,
            self.block_f1,
        ]
        .iter()
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
            || self.max_evaluation_micros == 0
            || self.max_evaluation_micros > 60_000_000
        {
            return Err(ContractError::Invalid);
        }
        Ok(())
    }

    fn differential(&self) -> Thresholds {
        Thresholds {
            markdown_page: self.markdown_page,
            markdown_corpus: self.markdown_corpus,
            links: self.links,
            metadata: self.metadata,
            block_f1: self.block_f1,
        }
    }
}

impl Schema {
    fn validate(&self, depth: usize) -> Result<(), ContractError> {
        if depth > 8 {
            return Err(ContractError::Limit);
        }
        match self {
            Self::Object { properties, required } => {
                let names: BTreeSet<_> = required.iter().collect();
                if properties.len() > 64
                    || names.len() != required.len()
                    || required.iter().any(|key| !properties.contains_key(key))
                    || properties.keys().any(|key| key.is_empty() || key.len() > 128)
                {
                    return Err(ContractError::Invalid);
                }
                for child in properties.values() {
                    child.validate(depth + 1)?;
                }
            }
            Self::Array { items, max_items } => {
                if *max_items > MAX_ITEMS {
                    return Err(ContractError::Limit);
                }
                items.validate(depth + 1)?;
            }
            Self::String { max_length } if *max_length > MAX_TEXT => return Err(ContractError::Limit),
            Self::String { .. } | Self::Integer | Self::Number | Self::Boolean | Self::Null => {}
        }
        Ok(())
    }

    fn matches(&self, value: &Value, cancel: &CancellationToken) -> Result<bool, ContractError> {
        check_cancel(cancel)?;
        Ok(match self {
            Self::Object { properties, required } => {
                let Some(object) = value.as_object() else {
                    return Ok(false);
                };
                if required.iter().any(|key| !object.contains_key(key)) {
                    return Ok(false);
                }
                for (key, value) in object {
                    let Some(schema) = properties.get(key) else {
                        return Ok(false);
                    };
                    if !schema.matches(value, cancel)? {
                        return Ok(false);
                    }
                }
                true
            }
            Self::Array { items, max_items } => {
                let Some(array) = value.as_array() else {
                    return Ok(false);
                };
                if array.len() > *max_items {
                    return Ok(false);
                }
                for value in array {
                    if !items.matches(value, cancel)? {
                        return Ok(false);
                    }
                }
                true
            }
            Self::String { max_length } => value.as_str().is_some_and(|s| s.chars().count() <= *max_length),
            Self::Integer => value.is_i64() || value.is_u64(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
        })
    }
}

fn check_cancel(cancel: &CancellationToken) -> Result<(), ContractError> {
    if cancel.is_cancelled() {
        Err(ContractError::Cancelled)
    } else {
        Ok(())
    }
}

fn safe_url(raw: &str) -> Result<Url, ContractError> {
    let url = Url::parse(raw).map_err(|_| ContractError::Invalid)?;
    if raw.len() > MAX_TEXT
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ContractError::Invalid);
    }
    Ok(url)
}

fn same_origin(raw: &str, origin: &Url) -> Result<Url, ContractError> {
    let url = safe_url(raw)?;
    if url.origin() != origin.origin() {
        return Err(ContractError::Invalid);
    }
    Ok(url)
}

fn has_content(page: &crate::differential::CrawlxPage) -> bool {
    page.markdown.is_some() || page.title.is_some() || page.description.is_some()
}

fn validate_native(run: &CrawlxRun, origin: &Url) -> Result<(), ContractError> {
    if run.pages.len() > MAX_PAGES || run.frontier.len() > MAX_ITEMS || run.access_log.is_some() {
        return Err(ContractError::Limit);
    }
    for page in &run.pages {
        same_origin(&page.url, origin)?;
        validate_page(page.markdown.as_deref(), &page.links, origin)?;
    }
    for row in &run.frontier {
        same_origin(&row.url, origin)?;
    }
    Ok(())
}

fn validate_golden(run: &UpstreamExport, origin: &Url) -> Result<(), ContractError> {
    if run.data.len() > MAX_PAGES
        || run.errors.errors.len() > MAX_ITEMS
        || run.errors.robots_blocked.len() > MAX_ITEMS
        || run.access_log.is_some()
    {
        return Err(ContractError::Limit);
    }
    for page in &run.data {
        same_origin(&page.metadata.source_url, origin)?;
        if let Some(url) = &page.metadata.url {
            same_origin(url, origin)?;
        }
        validate_page(page.markdown.as_deref(), &page.links, origin)?;
    }
    for error in &run.errors.errors {
        same_origin(&error.url, origin)?;
    }
    for url in &run.errors.robots_blocked {
        same_origin(url, origin)?;
    }
    Ok(())
}

fn validate_page(markdown: Option<&str>, links: &[String], origin: &Url) -> Result<(), ContractError> {
    if markdown.is_some_and(|text| text.len() > MAX_TEXT) || links.len() > MAX_PAGES {
        return Err(ContractError::Limit);
    }
    for link in links {
        same_origin(link, origin)?;
    }
    Ok(())
}

fn parse<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<T, ContractError> {
    check_cancel(cancel)?;
    if bytes.len() > MAX_BYTES {
        return Err(ContractError::Limit);
    }
    let mut depth = 0_usize;
    let mut nodes = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if index % 1_024 == 0 {
            check_cancel(cancel)?;
        }
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                nodes += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                nodes += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(ContractError::Invalid)?;
            }
            b',' => nodes += 1,
            _ => {}
        }
        if depth > MAX_DEPTH || nodes > MAX_NODES {
            return Err(ContractError::Limit);
        }
    }
    let strict: StrictValue = serde_json::from_slice(bytes).map_err(|_| ContractError::Invalid)?;
    check_cancel(cancel)?;
    serde_json::from_value(strict.0).map_err(|_| ContractError::Invalid)
}

// Reject duplicate keys before converting into any existing (intentionally permissive) DTO.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded declarative JSON")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                let number =
                    serde_json::Number::from_f64(value).ok_or_else(|| E::custom("invalid number"))?;
                Ok(StrictValue(Value::Number(number)))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    values.insert(key, map.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
