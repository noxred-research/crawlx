//! Pinned, declarative extraction configuration imports.
//!
//! These profiles translate explicitly supplied settings, not Python/Go objects or
//! implicit upstream defaults. The report preserves source/native differences. No
//! import reads files, evaluates code, initializes providers, or grants fetch authority.
//! `source-import convert` emits the same `CreateCrawl` consumed by native runners.
//! Article-only CSV/XML/TEI exports require the offline extraction serializer and
//! cannot be silently substituted for `CreateCrawl.output.formats`.

use crate::{
    extraction::{
        ArticleAlgorithmV1, CommentPolicyV1, ContentFallbackV1, ContentFocusV1, ExtractionPolicyV1,
        NlpCapabilityV1, RequiredMetadataV1,
    },
    hash::Digest,
    CoreError, CrawlMode, CreateCrawl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Maximum declarative JSON bytes, before any filesystem or provider operation.
pub const MAX_MANIFEST_BYTES: usize = 1_048_576;
/// Source family with one immutable release per dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExtractionSourceV1 {
    /// Precision-oriented text extraction library, Apache-2.0 source, not webpage rights.
    #[serde(rename = "text-precision")]
    PrecisionText,
    /// News-article extraction library, MIT package with a separate Apache-2.0 notice.
    #[serde(rename = "news-article")]
    NewsArticle,
    /// Surface-discovery crawler flag set, MIT source with separately licensed data.
    #[serde(rename = "surface-flags")]
    SurfaceFlags,
}
impl ExtractionSourceV1 {
    /// Exact source release; no floating tags or version ranges.
    #[must_use]
    pub const fn release(self) -> &'static str {
        match self {
            Self::PrecisionText => "2.3.1",
            Self::NewsArticle => "0.9.6.1",
            Self::SurfaceFlags => "1.8.0",
        }
    }
    /// Package license, never a license for scraped content or external models.
    #[must_use]
    pub const fn license(self) -> &'static str {
        match self {
            Self::PrecisionText => "Apache-2.0",
            Self::NewsArticle => "MIT; Apache-2.0 portions",
            Self::SurfaceFlags => "MIT",
        }
    }
    /// Pinned feature ledger: `ID<TAB>upstream feature` per line, `#` starts a comment.
    fn inventory(self) -> &'static str {
        match self {
            Self::PrecisionText => include_str!("../data/extraction-inventories/text-precision.tsv"),
            Self::NewsArticle => include_str!("../data/extraction-inventories/news-article.tsv"),
            Self::SurfaceFlags => include_str!("../data/extraction-inventories/surface-remaining.tsv"),
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::PrecisionText => "TP-",
            Self::NewsArticle => "NA-",
            Self::SurfaceFlags => "SR-",
        }
    }
}
/// Explicit source surface. CLI and library defaults are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtractionDialectV1 {
    /// Public function/configuration keyword names, not an object ABI.
    Library,
    /// Registered long CLI names without leading dashes, not shell arguments.
    Cli,
    /// Literal settings-file names; file inclusion is never evaluated.
    Settings,
}
/// Strict versioned wrapper exported by a trusted operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtractionManifestV1 {
    /// Manifest schema, exactly one.
    pub version: u16,
    /// Explicit pinned source family.
    pub source: ExtractionSourceV1,
    /// Exact release returned by `source.release()`.
    pub source_version: String,
    /// Explicit naming dialect; never inferred from filename or option spelling.
    pub dialect: ExtractionDialectV1,
    /// Every supplied key receives a typed disposition, including nested keys.
    pub options: BTreeMap<String, Value>,
    /// Whole inventory families that must be equivalent, beyond individual settings.
    #[serde(default)]
    pub required_inventory: Vec<String>,
    /// Explicit native reviewed lifecycle, never imported Python callbacks.
    #[serde(default)]
    pub pipeline: crate::extensions::ExtensionPipelineV1,
    /// Explicit native retention-aware datasets, never Python cache paths.
    #[serde(default)]
    pub datasets: crate::dataset::DatasetConfigV1,
}
/// Typed mapping state; unresolved requested behavior blocks conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportStateV1 {
    /// Executable native setting with documented semantic differences.
    Translated,
    /// Unknown, unsafe, contradictory, or unrepresentable setting.
    Rejected,
    /// Explicit authorized connector or resource is required; none is requested here.
    ExternalRequired,
    /// Full source-family semantics or licensed data are not established.
    DecisionNeeded,
}
/// One option or inventory disposition. Raw values and credentials are never echoed.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ExtractionDispositionV1 {
    /// Source option path or complete pinned inventory ID.
    pub id: String,
    /// Typed executable/unavailable disposition.
    pub state: ImportStateV1,
    /// Existing native field or API, if one exists.
    pub target: Option<&'static str>,
    /// Honest semantic difference, rejection reason, or missing prerequisite.
    pub reason: &'static str,
    /// Supplied option or explicitly required inventory family.
    pub requested: bool,
}
impl ExtractionDispositionV1 {
    /// Construct a requested rejection without exposing raw option values.
    #[must_use]
    pub fn rejected(id: String, target: &'static str, reason: &'static str) -> Self {
        Self {
            id,
            state: ImportStateV1::Rejected,
            target: Some(target),
            reason,
            requested: true,
        }
    }
}
/// Machine-readable, source-pinned report. No quality measurements are inferred.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ExtractionImportReportV1 {
    /// Report schema.
    pub version: u16,
    /// Selected source family.
    pub source: ExtractionSourceV1,
    /// Selected source surface.
    pub dialect: ExtractionDialectV1,
    /// Exact selected release.
    pub source_version: &'static str,
    /// Package/source license; model/content rights remain independent.
    pub license: &'static str,
    /// Always false; imports are native configuration, not SDK emulation.
    pub sdk_abi_compatible: bool,
    /// All explicitly requested behavior has an executable native mapping.
    pub convertible: bool,
    /// Digest of canonical explicit settings only after successful conversion.
    /// Unresolved/rejected manifests return null, avoiding fingerprints of rejected secrets.
    pub options_digest: Option<Digest>,
    /// Explicit source/native defaults and threshold-unit differences.
    pub differences: Vec<&'static str>,
    /// All supplied options, nested settings, and pinned inventory IDs.
    pub dispositions: Vec<ExtractionDispositionV1>,
    /// Complete advertised option/dialect catalog, including explicitly unavailable categories.
    pub option_catalog: BTreeMap<&'static str, &'static str>,
    /// Exact research-ledger rows, not measured runtime evidence or compatibility claims.
    pub inventory_evidence: BTreeMap<String, String>,
}
/// Import errors preserve JSON and native validation error chains.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtractionImportError {
    /// JSON malformed, duplicate-keyed, or outside the strict wrapper schema.
    #[error("invalid declarative extraction manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// Unsupported release/dialect/schema or resource bounds.
    #[error("extraction manifest rejected: {0}")]
    Manifest(&'static str),
    /// Supplied native pipeline or dataset configuration failed validation.
    #[error("native extraction configuration rejected: {0}")]
    Native(#[from] CoreError),
    /// Reviewed native extension validation failed.
    #[error("native extension configuration rejected: {0}")]
    Extension(#[from] crate::extensions::ExtensionError),
    /// Native dataset destination validation failed.
    #[error("native dataset configuration rejected: {0}")]
    Dataset(#[from] crate::StoreError),
    /// Conversion attempted despite an unresolved required option.
    #[error("extraction conversion has unresolved requested behavior")]
    Unavailable,
}

// Deserialize recursively before schema conversion so duplicate nested keys never
// acquire last-key-wins semantics. The serde recursion guard remains enabled.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("declarative JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = a.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let UniqueValue(value) = a.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
/// Parse bounded JSON only. Duplicate keys, wrong releases, and unknown wrapper fields fail.
///
/// # Errors
/// Returns a typed parse, bounds, release, or native lifecycle validation error.
pub fn parse_manifest(bytes: &[u8]) -> Result<ExtractionManifestV1, ExtractionImportError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ExtractionImportError::Manifest("manifest exceeds one MiB"));
    }
    let UniqueValue(value) = serde_json::from_slice(bytes)?;
    validate_json(&value, 0)?;
    let manifest: ExtractionManifestV1 = serde_json::from_value(value)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}
fn validate_json(value: &Value, depth: usize) -> Result<(), ExtractionImportError> {
    let mut nodes = 0;
    validate_json_node(value, depth, &mut nodes)
}
fn validate_json_node(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ExtractionImportError> {
    *nodes = nodes.saturating_add(1);
    if *nodes > 4096 {
        return Err(ExtractionImportError::Manifest(
            "JSON exceeds 4096 declarative nodes",
        ));
    }
    if depth > 16 {
        return Err(ExtractionImportError::Manifest("JSON nesting exceeds sixteen"));
    }
    match value {
        Value::Object(map) => {
            if map.len() > 256 {
                return Err(ExtractionImportError::Manifest("object exceeds 256 keys"));
            }
            for (key, value) in map {
                if key.len() > 128 {
                    return Err(ExtractionImportError::Manifest(
                        "option identifier exceeds 128 bytes",
                    ));
                }
                validate_json_node(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 256 {
                return Err(ExtractionImportError::Manifest("array exceeds 256 values"));
            }
            for value in values {
                validate_json_node(value, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > 65_536 => {
            return Err(ExtractionImportError::Manifest("string exceeds 64 KiB"));
        }
        _ => {}
    }
    Ok(())
}
fn validate_manifest(m: &ExtractionManifestV1) -> Result<(), ExtractionImportError> {
    if m.version != 1 || m.source_version != m.source.release() {
        return Err(ExtractionImportError::Manifest(
            "schema or exact source release mismatch",
        ));
    }
    if m.options.len() > 128
        || m.required_inventory.len() > 128
        || m.required_inventory.iter().any(|id| id.len() > 16)
        || (m.source == ExtractionSourceV1::SurfaceFlags && m.dialect != ExtractionDialectV1::Cli)
    {
        return Err(ExtractionImportError::Manifest(
            "unsupported dialect or excessive option/inventory count",
        ));
    }
    if crate::extensions::json_size(m)? > MAX_MANIFEST_BYTES {
        return Err(ExtractionImportError::Manifest("manifest exceeds one MiB"));
    }
    let mut nodes = 1;
    for (key, value) in &m.options {
        if key.len() > 128 {
            return Err(ExtractionImportError::Manifest(
                "option identifier exceeds 128 bytes",
            ));
        }
        validate_json_node(value, 2, &mut nodes)?;
    }
    m.pipeline.validate()?;
    m.datasets.validate()?;
    Ok(())
}

/// Return the complete IDs from the pinned ledger, including the surface residual gap IDs.
#[must_use]
pub fn inventory_ids(source: ExtractionSourceV1) -> BTreeSet<String> {
    source
        .inventory()
        .lines()
        .filter_map(|line| {
            let id = line.split('\t').next()?.trim();
            (id.starts_with(source.prefix())
                && id.len() <= 8
                && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && id.bytes().any(|b| b.is_ascii_digit()))
            .then(|| id.to_owned())
        })
        .collect()
}

struct Translation {
    crawl: Option<CreateCrawl>,
    policy: ExtractionPolicyV1,
    dispositions: Vec<ExtractionDispositionV1>,
    targets: BTreeSet<&'static str>,
}
impl Translation {
    fn record(&mut self, id: &str, state: ImportStateV1, target: Option<&'static str>, reason: &'static str) {
        self.dispositions.push(ExtractionDispositionV1 {
            id: id.to_owned(),
            state,
            target,
            reason,
            requested: true,
        });
    }
    fn translated(&mut self, id: &str, target: &'static str, valid: bool, reason: &'static str) {
        if !valid {
            self.record(
                id,
                ImportStateV1::Rejected,
                Some(target),
                "invalid type, unsupported value, or native bound exceeded",
            );
        } else if !self.targets.insert(target) {
            self.record(
                id,
                ImportStateV1::Rejected,
                Some(target),
                "multiple source options address the same native field; remove ambiguous aliases",
            );
        } else {
            self.record(id, ImportStateV1::Translated, Some(target), reason);
        }
    }
    fn unavailable(&mut self, id: &str, state: ImportStateV1, reason: &'static str) {
        self.record(id, state, None, reason);
    }
}
fn number(value: &Value, min: u64, max: u64) -> Option<u64> {
    value.as_u64().filter(|n| (min..=max).contains(n))
}
fn source_milliseconds(value: &Value, fractional: bool, min_ms: u32) -> Option<u32> {
    let millis = if let Some(seconds) = value.as_u64() {
        u32::try_from(seconds.checked_mul(1000)?).ok()?
    } else {
        if !fractional {
            return None;
        }
        let encoded = match value {
            Value::String(text) => std::borrow::Cow::Borrowed(text.as_str()),
            Value::Number(number) => std::borrow::Cow::Owned(number.to_string()),
            _ => return None,
        };
        let (whole, fraction) = encoded.split_once('.').unwrap_or((encoded.as_ref(), ""));
        if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let fraction = fraction.trim_end_matches('0');
        if fraction.len() > 3 {
            return None;
        }
        let mut fraction_ms = if fraction.is_empty() {
            0
        } else {
            fraction.parse::<u32>().ok()?
        };
        for _ in fraction.len()..3 {
            fraction_ms = fraction_ms.checked_mul(10)?;
        }
        whole
            .parse::<u32>()
            .ok()?
            .checked_mul(1000)?
            .checked_add(fraction_ms)?
    };
    (min_ms..=300_000).contains(&millis).then_some(millis)
}
fn strings(value: &Value) -> Option<Vec<String>> {
    if let Some(text) = value
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= 4096)
    {
        return Some(vec![text.to_owned()]);
    }
    value
        .as_array()
        .filter(|values| !values.is_empty() && values.len() <= 64)?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096)
                .map(str::to_owned)
        })
        .collect()
}
fn source_seed(m: &ExtractionManifestV1) -> Option<url::Url> {
    let mut seeds = m
        .options
        .iter()
        .filter(|(key, _)| canonical_key(m.source, m.dialect, key) == Some("url"));
    let (_, value) = seeds.next()?;
    if seeds.next().is_some() {
        return None;
    }
    let value = value.as_str().or_else(|| {
        value
            .as_array()
            .filter(|values| values.len() == 1)?
            .first()?
            .as_str()
    })?;
    if m.source == ExtractionSourceV1::SurfaceFlags && value.contains(',') {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && value.len() <= 4096)
        .then_some(url)
}
const NATIVE_DIFFERENCE: &str = "explicit native configuration; safety, redaction, retention, and origin admission remain authoritative; no upstream algorithm equivalence";

/// Inspect all options and return a native request only when every requested setting maps.
///
/// Required whole inventory families remain decision-needed: a single option cannot
/// prove every behavior grouped into a ledger row. No hidden provider is configured.
///
/// # Errors
/// Returns malformed manifest, bounds, release, or explicit native lifecycle errors.
pub fn inspect_manifest(
    m: &ExtractionManifestV1,
) -> Result<(ExtractionImportReportV1, Option<CreateCrawl>), ExtractionImportError> {
    validate_manifest(m)?;
    let mut t = Translation {
        crawl: source_seed(m).map(CreateCrawl::new),
        policy: ExtractionPolicyV1::default(),
        dispositions: Vec::new(),
        targets: BTreeSet::new(),
    };
    t.policy.nlp = NlpCapabilityV1::Off;
    if m.source == ExtractionSourceV1::NewsArticle {
        t.policy.algorithm = ArticleAlgorithmV1::ArticleGravityV1;
    }
    if let Some(crawl) = &mut t.crawl {
        crawl.mode = CrawlMode::Static;
        crawl.extensions = m.pipeline.clone();
        crawl.datasets = m.datasets.clone();
    }
    for (key, value) in &m.options {
        translate_option(m.source, m.dialect, key, value, &mut t);
    }
    if m.pipeline.configured() {
        t.record(
            "pipeline",
            ImportStateV1::Translated,
            Some("extensions"),
            "explicit reviewed native lifecycle; source callbacks are not evaluated",
        );
    }
    if !m.datasets.stores.is_empty() || !m.datasets.feeds.is_empty() || !m.datasets.kv_stores.is_empty() {
        t.record(
            "datasets",
            ImportStateV1::Translated,
            Some("datasets"),
            "explicit native retention-aware destinations; source caches are not imported",
        );
    }
    if t.crawl.is_none() {
        t.unavailable("native.seedUrl", ImportStateV1::Rejected, "one credential-free HTTP(S) source URL is required; file paths, URL lists, fragments, and references are not native seeds");
    }
    if t.policy.validate().is_err() {
        t.unavailable(
            "native.extract.content",
            ImportStateV1::Rejected,
            "conflicting native content bounds or unsupported selector policy",
        );
    }
    if let Some(crawl) = &mut t.crawl {
        crawl.extract.content = Some(std::mem::take(&mut t.policy));
    }
    let native_valid = t.crawl.as_mut().is_some_and(|crawl| crawl.normalize().is_ok());
    if !native_valid && t.crawl.is_some() {
        t.unavailable(
            "native.contract",
            ImportStateV1::Rejected,
            "converted native CreateCrawl did not pass normalization and validation",
        );
    }
    let ids = inventory_ids(m.source);
    for id in &ids {
        t.dispositions.push(ExtractionDispositionV1 { id: id.clone(), state: ImportStateV1::DecisionNeeded, target: None,
            reason: "complete source-family equivalence is not established by one translated setting; see pinned inventory for exact residuals",
            requested: m.required_inventory.contains(id) });
    }
    for id in &m.required_inventory {
        if !ids.contains(id) {
            t.unavailable(
                id,
                ImportStateV1::Rejected,
                "inventory ID is absent from the exact pinned source ledger",
            );
        }
    }
    let convertible = native_valid
        && t.dispositions
            .iter()
            .all(|d| !d.requested || d.state == ImportStateV1::Translated);
    let differences = vec![
        "Only explicitly supplied settings are translated; omitted settings retain native defaults, not source defaults.",
        "The precision-text MIN_EXTRACTED_SIZE=250 is a candidate threshold; native minMainChars=40 is a final Unicode-scalar quality gate. They are not interchangeable.",
        "The news-article min_word_count=300 and min_sent_count=7 are not Unicode-scalar counts. Native minMainChars does not emulate these gates.",
        "The news-article max_keywords defaults to 35 in library and 10 in CLI. Native default NLP is disabled in imported profiles unless explicitly selected through a supported native contract.",
        "Sentence-tokenizer, language-identification and fingerprint data need separately licensed pinned resources. Imports never download models or silently substitute Unicode rules for the tokenizer.",
        "Native dates use explicit referenceDate/locale only; source wall-clock future-date defaults are not reproduced.",
        "Native robots, TLS verification, checked proxies, retention and private-address admission remain enabled; no upstream unsafe default is inherited.",
        "Native JSON envelopes, CSV safety and XML/TEI schemas differ from upstream formats; CreateCrawl cannot express offline article serializers.",
        "No measured precision, recall, macro-F1, model breadth, or upstream SDK/ABI compatibility is claimed.",
    ];
    let report = ExtractionImportReportV1 {
        version: 1,
        source: m.source,
        dialect: m.dialect,
        source_version: m.source.release(),
        license: m.source.license(),
        sdk_abi_compatible: false,
        convertible,
        options_digest: if convertible {
            Some(Digest::of(
                "crawlx.extraction-import.explicit-options.v1",
                &serde_json::to_vec(&m.options)?,
            ))
        } else {
            None
        },
        differences,
        dispositions: t.dispositions,
        option_catalog: option_catalog(m.source, m.dialect).iter().copied().collect(),
        inventory_evidence: m
            .source
            .inventory()
            .lines()
            .filter_map(|line| {
                let (id, feature) = line.split_once('\t')?;
                ids.contains(id).then(|| (id.to_owned(), feature.to_owned()))
            })
            .collect(),
    };
    Ok((report, if convertible { t.crawl } else { None }))
}

fn translate_option(
    source: ExtractionSourceV1,
    dialect: ExtractionDialectV1,
    key: &str,
    value: &Value,
    t: &mut Translation,
) {
    // Registered CLI spellings are explicit aliases. No permissive case folding,
    // leading-dash removal, executable command strings, or settingsfile inclusion.
    let canonical = canonical_key(source, dialect, key);
    let Some(canonical) = canonical else {
        t.unavailable(key, ImportStateV1::Rejected, "unknown option for exact pinned source dialect; executable source, pickle, callbacks, templates, and includes are forbidden");
        report_nested(key, value, t);
        return;
    };
    if matches!(canonical, "url") {
        t.translated(key, "seedUrl", t.crawl.is_some(), "credential-free HTTP(S) seed; redirects and all discovered resources still require native admission");
        report_nested(key, value, t);
        return;
    }
    let boolean = value.as_bool().or_else(|| {
        if source == ExtractionSourceV1::PrecisionText && dialect == ExtractionDialectV1::Settings {
            match value.as_str() {
                Some("on") => Some(true),
                Some("off") => Some(false),
                _ => None,
            }
        } else {
            None
        }
    });
    match canonical {
        "fast" => {
            if let Some(v) = boolean { t.policy.fallback = if v { ContentFallbackV1::None } else { ContentFallbackV1::Bounded }; }
            t.translated(key, "extract.content.fallback", boolean.is_some(), "fast=true disables native fallback, not a Python extractor ABI");
        }
        "precision" | "recall" => {
            if boolean == Some(true) { t.policy.focus = if canonical == "precision" { ContentFocusV1::Precision } else { ContentFocusV1::Recall }; }
            t.translated(key, "extract.content.focus", boolean.is_some(), "native fixed-point profile; source selection thresholds differ; conflicting flags are rejected");
        }
        "comments" => {
            if let Some(v) = boolean { t.policy.comments = if v { CommentPolicyV1::Separate } else { CommentPolicyV1::Drop }; }
            t.translated(key, "extract.content.comments", boolean.is_some(), "comments are separate output, never silently appended to main article");
        }
        "no_comments" => {
            if let Some(v) = boolean { t.policy.comments = if v { CommentPolicyV1::Drop } else { CommentPolicyV1::Separate }; }
            t.translated(key, "extract.content.comments", boolean.is_some(), "native comments use separate blocks and separate retention-aware output");
        }
        "tables" | "no_tables" | "images" => {
            if let Some(v) = boolean { if canonical == "images" { t.policy.images = v; } else { t.policy.tables = if canonical == "no_tables" { !v } else { v }; } }
            let target = if canonical == "images" { "extract.content.images" } else { "extract.content.tables" };
            t.translated(key, target, boolean.is_some(), "structural keep/drop policy; image references never authorize media downloads");
        }
        "author_blacklist" => {
            let names = value.as_array().filter(|values| values.is_empty()).map(|_| Vec::new())
                .or_else(|| strings(value));
            let valid = names.as_ref().is_some_and(|names| names.iter().all(|name| {
                !name.trim().is_empty() && name.len() <= 256
                    && !name.chars().any(|c| c.is_control() && !c.is_whitespace())
            }));
            if valid { if let Some(names) = names { t.policy.excluded_authors = names; } }
            t.translated(key, "extract.content.excludedAuthors", valid,
                "native exact Unicode-lowercase/whitespace-normalized name exclusion across recognized author evidence; no regex, substring or fuzzy match; acquisition remains accounted");
        }
        "only_with_metadata" => {
            if boolean == Some(true) { t.policy.required_metadata = vec![RequiredMetadataV1::Title, RequiredMetadataV1::Url, RequiredMetadataV1::PublishedDate]; }
            t.translated(key, "extract.content.requiredMetadata", boolean.is_some(), "native title/URL/publication-date quality requirements; rejection is not a failed HTTP fetch");
        }
        "with_metadata" => {
            t.translated(key, "output.formats.metadata", boolean == Some(true), "native extraction always collects bounded provenance metadata; disabling source metadata is not representable");
            if boolean == Some(true) { if let Some(crawl) = &mut t.crawl { if !crawl.output.formats.contains(&crate::config::OutputFormat::Metadata) { crawl.output.formats.push(crate::config::OutputFormat::Metadata); } } }
        }
        "prune_xpath" | "read_more_link" => {
            let expressions = strings(value);
            let valid = expressions.is_some();
            if let Some(expressions) = expressions {
                let selectors = expressions.into_iter().map(|expression| crate::selectors::SelectorV1::Xpath { expression }).collect();
                if canonical == "prune_xpath" { t.policy.selectors.exclude = selectors; } else { t.policy.selectors.read_more = selectors; }
            }
            let target = if canonical == "prune_xpath" { "extract.content.selectors.exclude" } else { "extract.content.selectors.readMore" };
            t.translated(key, target, valid, "bounded static XPath; read-more emits intents only, never parser-side requests; syntax compilation precedes conversion");
        }
        "language" => {
            let text = value.as_str().filter(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_lowercase()));
            if let Some(text) = text { t.policy.target_language = Some(text.to_owned()); }
            t.translated(key, "extract.content.targetLanguage", text.is_some(), "strict declared-language quality target only; no language-identification model and no automatic tokenizer download");
        }
        "max_text" | "max_summary" | "max_summary_sent" | "max_keywords" => {
            let (target, limit) = match canonical {
                "max_text" => ("extract.content.maxOutputChars", 16_777_216),
                "max_summary" => ("extract.content.summaryMaxChars", 20_000),
                "max_summary_sent" => ("extract.content.summarySentences", 20),
                _ => ("extract.content.keywords", 35),
            };
            let n = number(value, u64::from(canonical == "max_text"), limit).and_then(|n| usize::try_from(n).ok());
            if let Some(n) = n { match canonical {
                "max_text" => t.policy.max_output_chars = n,
                "max_summary" => t.policy.summary_max_chars = n,
                "max_summary_sent" => t.policy.summary_sentences = n,
                _ => t.policy.keywords = n,
            } }
            t.translated(key, target, n.is_some(), "native Unicode scalar/count bound; NLP remains disabled, not a silent sentence-tokenizer replacement");
        }
        "skip_nlp" => {
            t.translated(key, "extract.content.nlp", boolean == Some(true), "skip-nlp=true maps to off; source NLP requires pinned licensed tokenizer resources and is not silently emulated");
        }
        "follow_meta_refresh" => {
            if let (Some(enabled), Some(crawl)) = (boolean, &mut t.crawl) {
                let policy = crawl.acquisition.get_or_insert_with(Default::default);
                policy.meta_refresh = enabled.then(crate::acquisition::MetaRefreshPolicyV1::default);
            }
            t.translated(key, "acquisition.metaRefresh", boolean.is_some(),
                "native opt-in static bodyless GET; only first matching bounded case-insensitive tag, malformed first content never selects a later tag; relative observed URL and one immediate transition under unchanged checked admission and shared parent allowance; failed targets never fall back to original success; other NA-30 HTTP/binary/probe requirements remain open");
        }
        "fetch_images" | "skip_fetch_images" => {
            let disabled = boolean == Some(canonical == "skip_fetch_images");
            t.translated(key, "scope.discovery.mediaProbes", disabled, "offline/reference-only image policy; source dimension-ranking default is not equivalent to native reference ranking");
        }
        "output_format" => {
            let format = value.as_str();
            let native = match (source, format) {
                (ExtractionSourceV1::PrecisionText, Some("markdown")) => Some(crate::config::OutputFormat::Markdown),
                (ExtractionSourceV1::PrecisionText, Some("html")) => Some(crate::config::OutputFormat::Html),
                _ => None,
            };
            if let Some(format) = native { if let Some(crawl) = &mut t.crawl { crawl.output.formats = vec![format]; } }
            t.translated(key, "output.formats", native.is_some(), "native page rendition, not source envelope; article JSON/text/CSV/XML/TEI require explicit offline serializer, not a CreateCrawl format");
        }
        "timeout" | "delay" => {
            let min_ms = if canonical == "timeout" { 100 } else { 50 };
            let n = source_milliseconds(value, source != ExtractionSourceV1::SurfaceFlags, min_ms);
            if let Some(n) = n { if let Some(crawl) = &mut t.crawl { if canonical == "timeout" { crawl.fetch.timeout_ms = n; } else { crawl.politeness.delay_ms = n; } } }
            let target = if canonical == "timeout" { "fetch.timeoutMs" } else { "politeness.delayMs" };
            t.translated(key, target, n.is_some(), "source seconds converted exactly to checked native milliseconds; sub-millisecond values and unsafe zero delays are rejected; combined native governor limits remain active");
        }
        "max_file_size" => {
            let n = number(value, 1024, 67_108_864);
            if let Some(n) = n { if let Some(crawl) = &mut t.crawl { crawl.fetch.max_response_bytes = n; } }
            t.translated(key, "fetch.maxResponseBytes", n.is_some(), "native bounded decoded-response limit, not Unicode output scalars; source codec/size behavior differs");
        }
        "depth" | "max_domain_pages" | "threads" | "retry" => {
            let limit = match canonical { "depth" => 100, "max_domain_pages" => 1_000_000, "threads" => 256, _ => 10 };
            let n = number(value, u64::from(canonical != "retry"), limit);
            if let (Some(n), Some(crawl)) = (n, &mut t.crawl) { match canonical {
                "depth" => { if let Ok(n) = u16::try_from(n) { crawl.scope.max_discovery_depth = n; } }
                "max_domain_pages" => { if let Ok(n) = u32::try_from(n) { crawl.scope.max_pages_per_host = Some(n); } }
                "threads" => { if let Ok(n) = u16::try_from(n) { crawl.politeness.max_concurrency = n; } }
                _ => { if let Ok(n) = u8::try_from(n) { crawl.fetch.retries = n; } }
            } }
            let target = match canonical { "depth" => "scope.maxDiscoveryDepth", "max_domain_pages" => "scope.maxPagesPerHost", "threads" => "politeness.maxConcurrency", _ => "fetch.retries" };
            t.translated(key, target, n.is_some(), NATIVE_DIFFERENCE);
        }
        "user_agent" => {
            let text = value.as_str().filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control));
            if let (Some(text), Some(crawl)) = (text, &mut t.crawl) { crawl.fetch.user_agent = Some(text.to_owned()); }
            t.translated(key, "fetch.userAgent", text.is_some(), "single explicit agent string; no ambient environment selection or randomized upstream UA pool");
        }
        "verify" | "insecure_ssl" | "ssrf" | "private_hosts" | "robots" => {
            let safe = boolean == Some(matches!(canonical, "verify" | "ssrf" | "robots"));
            let target = match canonical { "robots" => "safety.respectRobots", "ssrf" | "private_hosts" => "safety.allowPrivateNetworks", _ => "fetch.skipTlsVerification" };
            t.translated(key, target, safe, "intentional security difference: verified TLS, robots and checked-address egress cannot be disabled by imported settings");
        }
        "disable_redirects" => {
            if let (Some(v), Some(crawl)) = (boolean, &mut t.crawl) { crawl.fetch.follow_redirects = !v; }
            t.translated(key, "fetch.followRedirects", boolean.is_some(), "native per-hop checked redirects; source redirect caps remain distinct");
        }
        "headless" | "hybrid" => {
            if let (Some(v), Some(crawl)) = (boolean, &mut t.crawl) {
                crawl.mode = if !v { CrawlMode::Static } else if canonical == "headless" { CrawlMode::Dynamic } else { CrawlMode::Hybrid };
            }
            t.translated(key, "mode", boolean.is_some(), "native dynamic/hybrid planes, not rod topology; conflicting mode options are rejected");
        }
        "no_scope" => {
            if let (Some(v), Some(crawl)) = (boolean, &mut t.crawl) {
                crawl.scope.host_scope = if v { crate::config::HostScope::None } else { crate::config::HostScope::Rdn };
            }
            t.translated(key, "scope.hostScope", boolean.is_some(), "host discovery scope only; private-address, credential, robots and checked-egress authority remain enforced");
        }
        "path_climb" | "ignore_query" | "forms" | "form_fill" | "kb" | "secrets" | "kb_endpoints" | "out_of_scope" => {
            if let (Some(v), Some(crawl)) = (boolean, &mut t.crawl) { match canonical {
                "path_climb" => crawl.scope.path_climb = v,
                "ignore_query" => crawl.scope.ignore_query_params = v,
                "forms" => crawl.extract.forms = v,
                "form_fill" => crawl.extract.form_fill.enabled = v,
                "kb" => crawl.extract.knowledge_base = v,
                "secrets" => crawl.extract.detect_secrets = v,
                "kb_endpoints" => crawl.extract.kb_endpoints = v,
                _ => crawl.output.include_out_of_scope = v,
            } }
            let target = match canonical {
                "path_climb" => "scope.pathClimb", "ignore_query" => "scope.ignoreQueryParams",
                "forms" => "extract.forms", "form_fill" => "extract.formFill.enabled",
                "kb" => "extract.knowledgeBase", "secrets" => "extract.detectSecrets",
                "kb_endpoints" => "extract.kbEndpoints", _ => "output.includeOutOfScope",
            };
            t.translated(key, target, boolean.is_some(), "native deterministic rules/catalog, not upstream model/provider breadth; non-GET forms stay metadata-only and off-scope output grants no fetch authority");
        }
        "global_rps" | "global_rpm" | "host_rps" | "host_rpm" => {
            let n = number(value, 1, 1_000_000).and_then(|n| u32::try_from(n).ok());
            if let (Some(n), Some(crawl)) = (n, &mut t.crawl) { match canonical {
                "global_rps" => crawl.politeness.global_rps = Some(n),
                "global_rpm" => crawl.politeness.global_rpm = Some(n),
                "host_rps" => crawl.politeness.per_host_rps = Some(n),
                _ => crawl.politeness.per_host_rpm = Some(n),
            } }
            let target = match canonical { "global_rps" => "politeness.globalRps", "global_rpm" => "politeness.globalRpm",
                "host_rps" => "politeness.perHostRps", _ => "politeness.perHostRpm" };
            t.translated(key, target, n.is_some(), "native combined per-origin and global budgets apply together; no upstream precedence override disables another limit");
        }
        "strategy" => {
            let strategy = match value.as_str() {
                Some("breadth-first") => Some(crate::config::CrawlStrategy::BreadthFirst),
                Some("depth-first") => Some(crate::config::CrawlStrategy::DepthFirst),
                _ => None,
            };
            if let (Some(strategy), Some(crawl)) = (strategy, &mut t.crawl) { crawl.scope.strategy = strategy; }
            t.translated(key, "scope.strategy", strategy.is_some(), "native durable frontier ordering and ties; not Go callback scheduling or source priority-score equivalence");
        }
        "external_urls" => {
            t.translated(key, "scope.allowExternalLinks", boolean == Some(false), "off is preserved; source fuzzy-domain/external exceptions cannot widen native admission");
        }
        "proxy" | "cookies" | "headers" | "credentials" | "recorded_flow" => {
            t.unavailable(key, ImportStateV1::Rejected, "identity/proxy/auth import requires the explicit native request-identity reference contract; literal secrets, ambient references and arbitrary proxy settings are not imported");
        }
        "solver" | "news_search" | "trends" | "archived" => {
            t.unavailable(key, ImportStateV1::ExternalRequired, "explicit authorized connector/provider resource required; import performs no external requests and installs no hidden fallback");
        }
        "requests_params" | "top_image_settings" | "date_params" => {
            t.unavailable(key, ImportStateV1::DecisionNeeded, "source object has nested semantics without a complete native equivalence contract; every nested field is reported and conversion fails");
        }
        "source_mode" => {
            use crate::discovery::{DiscoveryModeV1, DiscoverySourceV1, SourceDiscoveryPolicyV1};
            let sources = match key {
                "feed" => Some(vec![DiscoverySourceV1::Feeds]),
                "sitemap" => Some(vec![DiscoverySourceV1::Sitemap]),
                "crawl" => Some(vec![DiscoverySourceV1::Html, DiscoverySourceV1::Categories]),
                "explore" | "probe" => Some(vec![DiscoverySourceV1::Sitemap, DiscoverySourceV1::Html, DiscoverySourceV1::Categories]),
                _ => None,
            };
            let valid = boolean == Some(true) && sources.is_some();
            if let (Some(sources), Some(crawl)) = (sources, &mut t.crawl) {
                if valid {
                    crawl.scope.sources = sources;
                    let mut policy = SourceDiscoveryPolicyV1::default();
                    if key == "probe" { policy.mode = DiscoveryModeV1::Probe; }
                    crawl.scope.discovery = Some(policy);
                }
            }
            t.translated(key, "scope.sources", valid, "explicit bounded native source stages; no hidden search-provider fallback, guessed paths, or external connectors; multiple discovery mode flags are rejected");
        }
        "formatting" | "links" => {
            if let Some(value) = boolean {
                if canonical == "links" { t.policy.links = value; } else { t.policy.formatting = value; }
            }
            let target = if canonical == "links" { "extract.content.links" } else { "extract.content.formatting" };
            t.translated(key, target, boolean.is_some(),
                "explicit native structural HTML/Markdown keep flag; canonical plain text and discovery authority stay unchanged; null/format-dependent auto mode is not silently inferred");
        }
        "sentence_tokenizer" => t.unavailable(key, ImportStateV1::ExternalRequired, "licensed checksum-pinned compatible sentence-tokenizer resource required; no fake tokenizer or runtime model download"),
        _ => {
            t.unavailable(key, ImportStateV1::DecisionNeeded, "advertised pinned option has no complete executable source-semantic mapping; it is not ignored or silently approximated");
        }
    }
    report_nested(key, value, t);
}
fn report_nested(prefix: &str, value: &Value, t: &mut Translation) {
    match value {
        Value::Object(map) => {
            for (index, (key, value)) in map.iter().enumerate() {
                let path = if key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                {
                    format!("{prefix}.{key}")
                } else {
                    format!("{prefix}.[invalid-key-{index}]")
                };
                t.unavailable(
                    &path,
                    ImportStateV1::Rejected,
                    "nested source setting is not executable through this profile; no key is ignored",
                );
                report_nested(&path, value, t);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if value.is_object() || value.is_array() {
                    report_nested(&format!("{prefix}[{index}]"), value, t);
                }
            }
        }
        _ => {}
    }
}

// The explicit dialect catalog doubles as the machine-readable fixture matrix.
// Alias spellings below are source names, never deprecated native aliases.
const PRECISION_TEXT_LIBRARY: &[(&str, &str)] = &[
    ("url", "url"),
    ("fast", "fast"),
    ("no_fallback", "fast"),
    ("favor_precision", "precision"),
    ("favor_recall", "recall"),
    ("include_comments", "comments"),
    ("include_tables", "tables"),
    ("include_images", "images"),
    ("include_links", "links"),
    ("include_formatting", "formatting"),
    ("output_format", "output_format"),
    ("with_metadata", "with_metadata"),
    ("only_with_metadata", "only_with_metadata"),
    ("target_language", "language"),
    ("prune_xpath", "prune_xpath"),
    ("date_extraction_params", "date_params"),
    ("record_id", "unavailable"),
    ("url_blacklist", "unavailable"),
    ("author_blacklist", "author_blacklist"),
    ("deduplicate", "unavailable"),
    ("settingsfile", "unavailable"),
    ("config", "unavailable"),
    ("options", "unavailable"),
    ("tei_validation", "unavailable"),
];
const PRECISION_TEXT_SETTINGS: &[(&str, &str)] = &[
    ("url", "url"),
    ("DOWNLOAD_TIMEOUT", "timeout"),
    ("MAX_FILE_SIZE", "max_file_size"),
    ("MIN_FILE_SIZE", "unavailable"),
    ("SLEEP_TIME", "delay"),
    ("USER_AGENTS", "unavailable"),
    ("COOKIE", "cookies"),
    ("MAX_REDIRECTS", "unavailable"),
    ("SSRF_PROTECTION", "ssrf"),
    ("INSECURE_SSL_FALLBACK", "insecure_ssl"),
    ("MIN_EXTRACTED_SIZE", "unavailable"),
    ("MIN_OUTPUT_SIZE", "unavailable"),
    ("MIN_OUTPUT_COMM_SIZE", "unavailable"),
    ("MAX_TREE_SIZE", "unavailable"),
    ("EXTRACTION_TIMEOUT", "unavailable"),
    ("MIN_DUPLCHECK_SIZE", "unavailable"),
    ("MAX_REPETITIONS", "unavailable"),
    ("EXTENSIVE_DATE_SEARCH", "unavailable"),
    ("EXTERNAL_URLS", "external_urls"),
    ("PROXY_URL", "proxy"),
    ("http_proxy", "proxy"),
];
const PRECISION_TEXT_CLI: &[(&str, &str)] = &[
    ("URL", "url"),
    ("input-file", "unavailable"),
    ("input-dir", "unavailable"),
    ("parallel", "threads"),
    ("blacklist", "unavailable"),
    ("list", "unavailable"),
    ("output-dir", "unavailable"),
    ("backup-dir", "unavailable"),
    ("keep-dirs", "unavailable"),
    ("feed", "source_mode"),
    ("sitemap", "source_mode"),
    ("crawl", "source_mode"),
    ("explore", "source_mode"),
    ("probe", "source_mode"),
    ("archived", "archived"),
    ("url-filter", "unavailable"),
    ("fast", "fast"),
    ("formatting", "formatting"),
    ("links", "links"),
    ("images", "images"),
    ("no-comments", "no_comments"),
    ("no-tables", "no_tables"),
    ("only-with-metadata", "only_with_metadata"),
    ("with-metadata", "with_metadata"),
    ("target-language", "language"),
    ("deduplicate", "unavailable"),
    ("config-file", "unavailable"),
    ("precision", "precision"),
    ("recall", "recall"),
    ("output-format", "output_format"),
    ("csv", "unavailable"),
    ("html", "unavailable"),
    ("json", "unavailable"),
    ("markdown", "unavailable"),
    ("xml", "unavailable"),
    ("xmltei", "unavailable"),
    ("validate-tei", "unavailable"),
    ("verbose", "unavailable"),
    ("version", "unavailable"),
    ("help", "unavailable"),
    ("u", "url"),
    ("i", "unavailable"),
    ("b", "unavailable"),
    ("o", "unavailable"),
    ("f", "fast"),
    ("v", "unavailable"),
];
const NEWS_ARTICLE_LIBRARY: &[(&str, &str)] = &[
    ("url", "url"),
    ("language", "language"),
    ("min_word_count", "unavailable"),
    ("min_sent_count", "unavailable"),
    ("max_title", "unavailable"),
    ("max_text", "max_text"),
    ("max_keywords", "max_keywords"),
    ("max_authors", "unavailable"),
    ("max_summary", "max_summary"),
    ("max_summary_sent", "max_summary_sent"),
    ("max_file_memo", "unavailable"),
    ("top_image_settings", "top_image_settings"),
    ("memorize_articles", "unavailable"),
    ("memoize_articles", "unavailable"),
    ("disable_category_cache", "unavailable"),
    ("use_cached_categories", "unavailable"),
    ("fetch_images", "fetch_images"),
    ("follow_meta_refresh", "follow_meta_refresh"),
    ("allow_private_hosts", "private_hosts"),
    ("clean_article_html", "unavailable"),
    ("http_success_only", "unavailable"),
    ("requests_params", "requests_params"),
    ("number_threads", "threads"),
    ("verbose", "unavailable"),
    ("thread_timeout_seconds", "unavailable"),
    ("allow_binary_content", "unavailable"),
    ("ignored_content_types_defaults", "unavailable"),
    ("honor_robots_txt", "robots"),
    ("browser_user_agent", "user_agent"),
    ("request_timeout", "timeout"),
    ("proxies", "proxy"),
    ("headers", "headers"),
    ("cookies", "cookies"),
    ("verify", "verify"),
    ("read_more_link", "read_more_link"),
    ("input_html", "unavailable"),
    ("title", "unavailable"),
    ("authors", "unavailable"),
    ("meta_lang", "unavailable"),
    ("use_meta_language", "unavailable"),
    ("nlp", "sentence_tokenizer"),
    ("punkt", "sentence_tokenizer"), // wire-compat: source option key
    ("only_homepage", "source_mode"),
    ("only_in_path", "source_mode"),
    ("dry", "source_mode"),
    ("google_news", "news_search"), // wire-compat: source option key
    ("popular_urls", "unavailable"),
    ("hot", "trends"),
    ("before_request", "unavailable"),
    ("after_response", "unavailable"),
    ("on_error", "unavailable"),
    ("cloudscraper", "unavailable"), // wire-compat: source option key
    ("save", "unavailable"),
    ("pickle", "unavailable"),
    ("MIN_WORD_COUNT", "unavailable"),
    ("MIN_SENT_COUNT", "unavailable"),
    ("MAX_TITLE", "unavailable"),
    ("MAX_TEXT", "max_text"),
    ("MAX_KEYWORDS", "max_keywords"),
    ("MAX_AUTHORS", "unavailable"),
    ("MAX_SUMMARY", "max_summary"),
    ("MAX_SUMMARY_SENT", "max_summary_sent"),
    ("MAX_FILE_MEMO", "unavailable"),
];
const NEWS_ARTICLE_CLI: &[(&str, &str)] = &[
    ("url", "url"),
    ("urls-from-file", "unavailable"),
    ("urls-from-stdin", "unavailable"),
    ("html-from-file", "unavailable"),
    ("language", "language"),
    ("output-format", "output_format"),
    ("output-file", "unavailable"),
    ("read-more-link", "read_more_link"),
    ("skip-fetch-images", "skip_fetch_images"),
    ("follow-meta-refresh", "follow_meta_refresh"),
    ("browser-user-agent", "user_agent"),
    ("proxy", "proxy"),
    ("request-timeout", "timeout"),
    ("cookies", "cookies"),
    ("skip-ssl-verify", "insecure_ssl"),
    ("max-nr-keywords", "max_keywords"),
    ("skip-nlp", "skip_nlp"),
    ("help", "unavailable"),
    ("u", "url"),
    ("uf", "unavailable"),
    ("us", "unavailable"),
    ("hf", "unavailable"),
    ("l", "language"),
    ("of", "output_format"),
    ("o", "unavailable"),
    ("ua", "user_agent"),
];
const SURFACE_FLAGS: &[(&str, &str)] = &[
    ("u", "url"),
    ("list", "url"),
    ("resume", "unavailable"),
    ("exclude", "unavailable"),
    ("resolvers", "unavailable"),
    ("depth", "depth"),
    ("crawl-duration", "unavailable"),
    ("max-domain-pages", "max_domain_pages"),
    ("js-crawl", "unavailable"),
    ("jsluice", "unavailable"), // wire-compat: source flag name
    ("known-files", "unavailable"),
    ("path-climb", "path_climb"),
    ("disable-redirects", "disable_redirects"),
    ("max-response-size", "max_file_size"),
    ("timeout", "timeout"),
    ("time-stable", "unavailable"),
    ("retry", "retry"),
    ("proxy", "proxy"),
    ("headers", "headers"),
    ("tls-impersonate", "unavailable"),
    ("automatic-form-fill", "form_fill"),
    ("form-extraction", "forms"),
    ("form-config", "unavailable"),
    ("tech-detect", "unavailable"),
    ("field-config", "unavailable"),
    ("knowledge-base", "kb"),
    ("kb", "kb"),
    ("kb-secrets", "secrets"),
    ("kb-validate-secrets", "solver"),
    ("kb-endpoints", "kb_endpoints"),
    ("config", "unavailable"),
    ("strategy", "strategy"),
    ("ignore-query-params", "ignore_query"),
    ("filter-similar", "unavailable"),
    ("filter-similar-threshold", "unavailable"),
    ("health-check", "unavailable"),
    ("error-log", "unavailable"),
    ("pprof-server", "unavailable"),
    ("headless", "headless"),
    ("hybrid", "hybrid"),
    ("system-chrome", "unavailable"),
    ("system-chrome-path", "unavailable"),
    ("show-browser", "unavailable"),
    ("headless-options", "unavailable"),
    ("no-sandbox", "unavailable"),
    ("chrome-data-dir", "unavailable"),
    ("no-incognito", "unavailable"),
    ("chrome-ws-url", "unavailable"),
    ("xhr-extraction", "unavailable"),
    ("max-failure-count", "unavailable"),
    ("enable-diagnostics", "unavailable"),
    ("page-load-strategy", "unavailable"),
    ("dom-wait-time", "unavailable"),
    ("captcha-solver-provider", "solver"),
    ("captcha-solver-key", "solver"),
    ("auto-login", "credentials"),
    ("recorded-flow", "recorded_flow"),
    ("crawl-scope", "unavailable"),
    ("crawl-out-scope", "unavailable"),
    ("field-scope", "unavailable"),
    ("no-scope", "no_scope"),
    ("display-out-scope", "out_of_scope"),
    ("match-regex", "unavailable"),
    ("filter-regex", "unavailable"),
    ("field", "unavailable"),
    ("store-field", "unavailable"),
    ("extension-match", "unavailable"),
    ("extension-filter", "unavailable"),
    ("no-default-ext-filter", "unavailable"),
    ("match-condition", "unavailable"),
    ("filter-condition", "unavailable"),
    ("disable-unique-filter", "unavailable"),
    ("page-content-similar", "unavailable"),
    ("similarity-deduplication", "unavailable"),
    ("page-content-similar-mode", "unavailable"),
    ("page-content-similar-distance", "unavailable"),
    ("page-content-similar-threshold", "unavailable"),
    ("page-content-similar-budget", "unavailable"),
    ("filter-page-type", "unavailable"),
    ("concurrency", "threads"),
    ("parallelism", "unavailable"),
    ("delay", "delay"),
    ("rate-limit", "global_rps"),
    ("rate-limit-minute", "global_rpm"),
    ("host-rate-limit", "host_rps"),
    ("host-rate-limit-minute", "host_rpm"),
    ("update", "unavailable"),
    ("disable-update-check", "unavailable"),
    ("output", "unavailable"),
    ("output-template", "unavailable"),
    ("store-response", "unavailable"),
    ("store-response-dir", "unavailable"),
    ("no-clobber", "unavailable"),
    ("store-field-dir", "unavailable"),
    ("omit-raw", "unavailable"),
    ("omit-body", "unavailable"),
    ("list-output-fields", "unavailable"),
    ("exclude-output-fields", "unavailable"),
    ("jsonl", "unavailable"),
    ("no-color", "unavailable"),
    ("silent", "unavailable"),
    ("verbose", "unavailable"),
    ("debug", "unavailable"),
    ("version", "unavailable"),
    ("help", "unavailable"),
    ("e", "unavailable"),
    ("r", "unavailable"),
    ("d", "depth"),
    ("ct", "unavailable"),
    ("mdp", "max_domain_pages"),
    ("jc", "unavailable"),
    ("jsl", "unavailable"),
    ("kf", "unavailable"),
    ("pc", "path_climb"),
    ("dr", "disable_redirects"),
    ("mrs", "max_file_size"),
    ("H", "headers"),
    ("tlsi", "unavailable"),
    ("aff", "form_fill"),
    ("fx", "forms"),
    ("fc", "unavailable"),
    ("td", "unavailable"),
    ("flc", "unavailable"),
    ("s", "strategy"),
    ("iqp", "ignore_query"),
    ("fsu", "unavailable"),
    ("fst", "unavailable"),
    ("hc", "unavailable"),
    ("elog", "unavailable"),
    ("hl", "headless"),
    ("hh", "hybrid"),
    ("sc", "unavailable"),
    ("scp", "unavailable"),
    ("sb", "unavailable"),
    ("ho", "unavailable"),
    ("nos", "unavailable"),
    ("cdd", "unavailable"),
    ("noi", "unavailable"),
    ("cwu", "unavailable"),
    ("xhr", "unavailable"),
    ("mfc", "unavailable"),
    ("ed", "unavailable"),
    ("pls", "unavailable"),
    ("dwt", "unavailable"),
    ("csp", "solver"),
    ("csk", "solver"),
    ("al", "credentials"),
    ("rf", "recorded_flow"),
    ("cs", "unavailable"),
    ("cos", "unavailable"),
    ("fs", "unavailable"),
    ("ns", "no_scope"),
    ("do", "out_of_scope"),
    ("mr", "unavailable"),
    ("fr", "unavailable"),
    ("f", "unavailable"),
    ("sf", "unavailable"),
    ("em", "unavailable"),
    ("ef", "unavailable"),
    ("ndef", "unavailable"),
    ("mdc", "unavailable"),
    ("fdc", "unavailable"),
    ("duf", "unavailable"),
    ("pcs", "unavailable"),
    ("sdd", "unavailable"),
    ("pcsm", "unavailable"),
    ("pcsd", "unavailable"),
    ("pcst", "unavailable"),
    ("pcsn", "unavailable"),
    ("fpt", "unavailable"),
    ("c", "threads"),
    ("p", "unavailable"),
    ("rd", "delay"),
    ("rl", "global_rps"),
    ("rlm", "global_rpm"),
    ("hrl", "host_rps"),
    ("hrlm", "host_rpm"),
    ("up", "unavailable"),
    ("duc", "unavailable"),
    ("o", "unavailable"),
    ("ot", "unavailable"),
    ("sr", "unavailable"),
    ("srd", "unavailable"),
    ("ncb", "unavailable"),
    ("sfd", "unavailable"),
    ("or", "unavailable"),
    ("ob", "unavailable"),
    ("lof", "unavailable"),
    ("eof", "unavailable"),
    ("j", "unavailable"),
    ("nc", "unavailable"),
    ("v", "unavailable"),
];
/// Enumerate every advertised profile option and its canonical capability category.
/// Entries may be explicitly unavailable; catalog membership is not a support claim.
#[must_use]
pub fn option_catalog(
    source: ExtractionSourceV1,
    dialect: ExtractionDialectV1,
) -> &'static [(&'static str, &'static str)] {
    match (source, dialect) {
        (ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Library) => PRECISION_TEXT_LIBRARY,
        (ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Cli) => PRECISION_TEXT_CLI,
        (ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Settings) => PRECISION_TEXT_SETTINGS,
        (ExtractionSourceV1::NewsArticle, ExtractionDialectV1::Cli) => NEWS_ARTICLE_CLI,
        (ExtractionSourceV1::NewsArticle, _) => NEWS_ARTICLE_LIBRARY,
        (ExtractionSourceV1::SurfaceFlags, ExtractionDialectV1::Cli) => SURFACE_FLAGS,
        (ExtractionSourceV1::SurfaceFlags, _) => &[],
    }
}
fn canonical_key(
    source: ExtractionSourceV1,
    dialect: ExtractionDialectV1,
    key: &str,
) -> Option<&'static str> {
    option_catalog(source, dialect)
        .iter()
        .find_map(|&(name, canonical)| (name == key).then_some(canonical))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;
    fn manifest(source: ExtractionSourceV1, dialect: ExtractionDialectV1) -> ExtractionManifestV1 {
        let key = match (source, dialect) {
            (ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Cli) => "URL",
            (ExtractionSourceV1::SurfaceFlags, ExtractionDialectV1::Cli) => "u",
            _ => "url",
        };
        serde_json::from_value(json!({"version":1,"source":source,"sourceVersion":source.release(),"dialect":dialect,"options":{key:"https://fixture.test/story"}})).unwrap()
    }
    #[test]
    fn author_exclusion_import_rejects_invalid_bounds_without_echoing_values() {
        let mut input = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Library);
        for names in [json!(["Émilie Durand", "Alex Example"]), json!([])] {
            input.options.insert("author_blacklist".into(), names);
            let (report, crawl) = inspect_manifest(&input).unwrap();
            assert!(report.convertible);
            crawl.unwrap().extract.content.unwrap().validate().unwrap();
        }
        for names in [
            json!(["  "]),
            json!(["x".repeat(257)]),
            json!(vec!["name"; 65]),
            json!(42),
            json!(["invalid\u{0000}name"]),
        ] {
            input.options.insert("author_blacklist".into(), names);
            let (report, crawl) = inspect_manifest(&input).unwrap();
            assert!(!report.convertible);
            assert!(crawl.is_none());
            let encoded = serde_json::to_string(&report).unwrap();
            assert!(!encoded.contains("invalid\\u0000name"));
        }
    }
    #[test]
    fn complete_inventory_includes_hyphenated_rows_and_surface_gaps() {
        assert_eq!(inventory_ids(ExtractionSourceV1::PrecisionText).len(), 38);
        assert_eq!(inventory_ids(ExtractionSourceV1::NewsArticle).len(), 40);
        let surface = inventory_ids(ExtractionSourceV1::SurfaceFlags);
        assert_eq!(surface.len(), 44);
        assert!(surface.contains("SR-G12"));
    }
    #[test]
    fn every_advertised_option_receives_a_disposition_without_execution() {
        for source in [
            ExtractionSourceV1::PrecisionText,
            ExtractionSourceV1::NewsArticle,
            ExtractionSourceV1::SurfaceFlags,
        ] {
            for dialect in [
                ExtractionDialectV1::Library,
                ExtractionDialectV1::Cli,
                ExtractionDialectV1::Settings,
            ] {
                if source == ExtractionSourceV1::SurfaceFlags && dialect != ExtractionDialectV1::Cli {
                    continue;
                }
                for &(key, _) in option_catalog(source, dialect) {
                    let mut m = manifest(source, dialect);
                    m.options
                        .insert(key.to_owned(), json!({"unsafe_nested":"never execute"}));
                    let (report, native) = inspect_manifest(&m).unwrap();
                    assert!(report.dispositions.iter().any(|d| d.id == key && d.requested));
                    assert!(!report.convertible);
                    assert!(native.is_none());
                    for id in inventory_ids(source) {
                        assert!(report.dispositions.iter().any(|d| d.id == id));
                    }
                }
            }
        }
    }
    #[test]
    fn exact_pins_unknown_keys_duplicate_json_and_nested_values_fail_closed() {
        assert!(parse_manifest(br#"{"version":1,"source":"text-precision","sourceVersion":"2.3.1","dialect":"library","options":{"url":"https://fixture.test","fast":true,"fast":false}}"#).is_err());
        assert!(parse_manifest(br#"{"version":1,"source":"news-article","sourceVersion":"0.9.6.1","dialect":"library","options":{"requests_params":{"timeout":1,"timeout":2}}}"#).is_err());
        let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Library);
        m.source_version = "latest".into();
        assert!(inspect_manifest(&m).is_err());
        m.source_version = "2.3.1".into();
        m.options.insert("python_import".into(), json!("os.system"));
        assert!(!inspect_manifest(&m).unwrap().0.convertible);
    }
    #[test]
    fn required_inventory_is_not_faked_by_one_option_mapping() {
        let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Library);
        m.options.insert("fast".into(), json!(true));
        m.required_inventory.push("TP-04".into());
        let (report, native) = inspect_manifest(&m).unwrap();
        assert!(!report.convertible);
        assert!(native.is_none());
        assert!(report
            .dispositions
            .iter()
            .any(|d| d.id == "TP-04" && d.requested && d.state == ImportStateV1::DecisionNeeded));
    }
    #[test]
    fn threshold_units_and_unsafe_provider_settings_are_never_silently_coerced() {
        for (source, key, value) in [
            (ExtractionSourceV1::NewsArticle, "min_word_count", json!(300)),
            (
                ExtractionSourceV1::NewsArticle,
                "allow_private_hosts",
                json!(true),
            ),
            (
                ExtractionSourceV1::NewsArticle,
                "proxies",
                json!({"https":"http://user:secret@proxy.test"}),
            ),
            (ExtractionSourceV1::NewsArticle, "nlp", json!(true)),
            (
                ExtractionSourceV1::SurfaceFlags,
                "captcha-solver-provider",
                json!("task-api"),
            ),
            (
                ExtractionSourceV1::PrecisionText,
                "output_format",
                json!("pickle"),
            ),
        ] {
            let mut m = manifest(
                source,
                if source == ExtractionSourceV1::SurfaceFlags {
                    ExtractionDialectV1::Cli
                } else {
                    ExtractionDialectV1::Library
                },
            );
            m.options.insert(key.into(), value);
            let (report, native) = inspect_manifest(&m).unwrap();
            assert!(!report.convertible);
            assert!(native.is_none());
            assert!(!serde_json::to_string(&report).unwrap().contains("user:secret"));
        }
    }
    #[test]
    fn conflicting_focus_and_aliases_fail_before_io() {
        let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Library);
        m.options.insert("favor_precision".into(), json!(true));
        m.options.insert("favor_recall".into(), json!(true));
        assert!(!inspect_manifest(&m).unwrap().0.convertible);
    }
    #[test]
    fn native_settings_remain_runnable_and_seconds_are_checked() {
        let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Settings);
        m.options.insert("DOWNLOAD_TIMEOUT".into(), json!(30));
        m.options.insert("MAX_FILE_SIZE".into(), json!(20_000_000));
        m.options.insert("INSECURE_SSL_FALLBACK".into(), json!(false));
        let (report, crawl) = inspect_manifest(&m).unwrap();
        assert!(report.convertible);
        let crawl = crawl.unwrap();
        assert_eq!(crawl.fetch.timeout_ms, 30_000);
        assert_eq!(crawl.fetch.max_response_bytes, 20_000_000);
        assert!(!crawl.fetch.skip_tls_verification);
        m.options.insert("DOWNLOAD_TIMEOUT".into(), json!(u64::MAX));
        assert!(!inspect_manifest(&m).unwrap().0.convertible);
    }
    #[test]
    fn news_article_settings_preserve_native_bounds_and_disable_unavailable_side_effects() {
        let mut m = manifest(ExtractionSourceV1::NewsArticle, ExtractionDialectV1::Library);
        m.options.extend([
            ("max_text".into(), json!(100_000)),
            ("max_keywords".into(), json!(35)),
            ("max_summary".into(), json!(5000)),
            ("max_summary_sent".into(), json!(5)),
            ("fetch_images".into(), json!(false)),
            ("honor_robots_txt".into(), json!(true)),
            ("read_more_link".into(), json!("//a[@rel='next']")),
        ]);
        let (report, request) = inspect_manifest(&m).unwrap();
        assert!(report.convertible);
        let request = request.unwrap();
        let content = request.extract.content.unwrap();
        assert_eq!(content.algorithm, ArticleAlgorithmV1::ArticleGravityV1);
        assert_eq!(content.max_output_chars, 100_000);
        assert_eq!(content.keywords, 35);
        assert_eq!(content.nlp, NlpCapabilityV1::Off);
        assert_eq!(content.selectors.read_more.len(), 1);
        assert!(request
            .scope
            .discovery
            .as_ref()
            .is_none_or(|p| p.media_probes == 0 && p.connectors.is_empty()));
    }
    #[test]
    fn precision_text_all_discovery_modes_have_executable_native_stages_without_external_fallbacks() {
        for mode in ["feed", "sitemap", "crawl", "explore", "probe"] {
            let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Cli);
            m.options.insert(mode.into(), json!(true));
            let (report, request) = inspect_manifest(&m).unwrap();
            assert!(report.convertible, "{mode}");
            let request = request.unwrap();
            assert!(!request.scope.sources.is_empty());
            let discovery = request.scope.discovery.unwrap();
            assert!(discovery.connectors.is_empty());
            assert!(discovery.conventional_paths.is_empty());
            assert_eq!(
                discovery.mode == crate::discovery::DiscoveryModeV1::Probe,
                mode == "probe"
            );
        }
    }
    #[test]
    fn surface_residual_aliases_execute_native_mode_scope_delay_and_combined_rate_controls() {
        for (key, expected) in [("hl", CrawlMode::Dynamic), ("hh", CrawlMode::Hybrid)] {
            let mut m = manifest(ExtractionSourceV1::SurfaceFlags, ExtractionDialectV1::Cli);
            m.options.extend([
                (key.into(), json!(true)),
                ("ns".into(), json!(true)),
                ("rd".into(), json!(2)),
                ("rl".into(), json!(10)),
                ("hrlm".into(), json!(30)),
            ]);
            let (report, request) = inspect_manifest(&m).unwrap();
            assert!(report.convertible);
            let request = request.unwrap();
            assert_eq!(request.mode, expected);
            assert_eq!(request.scope.host_scope, crate::config::HostScope::None);
            assert_eq!(request.politeness.delay_ms, 2000);
            assert_eq!(request.politeness.global_rps, Some(10));
            assert_eq!(request.politeness.per_host_rpm, Some(30));
        }
        let mut m = manifest(ExtractionSourceV1::SurfaceFlags, ExtractionDialectV1::Cli);
        m.options
            .extend([("hl".into(), json!(true)), ("hh".into(), json!(true))]);
        assert!(!inspect_manifest(&m).unwrap().0.convertible);
    }
    #[test]
    fn literal_settings_and_fractional_seconds_preserve_units_without_float_casts() {
        let mut m = manifest(ExtractionSourceV1::PrecisionText, ExtractionDialectV1::Settings);
        m.options.extend([
            ("SSRF_PROTECTION".into(), json!("on")),
            ("INSECURE_SSL_FALLBACK".into(), json!("off")),
            ("EXTERNAL_URLS".into(), json!("off")),
            ("SLEEP_TIME".into(), json!(5.0)),
        ]);
        let (report, request) = inspect_manifest(&m).unwrap();
        assert!(report.convertible);
        assert_eq!(request.unwrap().politeness.delay_ms, 5000);
        assert_eq!(source_milliseconds(&json!(0.125), true, 50), Some(125));
        assert_eq!(source_milliseconds(&json!("1.250"), true, 50), Some(1250));
        assert_eq!(source_milliseconds(&json!(0.125), false, 50), None);
        assert_eq!(source_milliseconds(&json!(0.0001), true, 50), None);
        assert_eq!(source_milliseconds(&json!(u64::MAX), true, 50), None);
        m.options.insert("INSECURE_SSL_FALLBACK".into(), json!("on"));
        assert!(!inspect_manifest(&m).unwrap().0.convertible);
    }
}
