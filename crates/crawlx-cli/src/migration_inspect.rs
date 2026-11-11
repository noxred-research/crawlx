//! Bounded declarative source imports, not source SDKs or execution runtimes.
//!
//! A trusted source exporter supplies JSON only. No module, shell, script, package,
//! template, pickle, gob or browser callback is loaded or executed here.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use crawlx_core::{extensions::ExtensionPipelineV1, CreateCrawl};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io::Write, path::PathBuf, process::ExitCode};
use tokio::io::AsyncReadExt;

const MAX_MANIFEST_BYTES: usize = 1_048_576;
/// Offline source migration; preserves `crawlx migrate` database semantics.
#[derive(Debug, Args)]
pub struct SourceImportArgs {
    /// Inspect or convert an exported declarative manifest.
    #[command(subcommand)]
    pub command: SourceImportCommand,
}
/// No operation evaluates source code or initializes networking/telemetry.
#[derive(Debug, Subcommand)]
pub enum SourceImportCommand {
    /// Print all inventory dispositions; exit two for requested unmapped behavior.
    Inspect(ManifestArgs),
    /// Emit a native CreateCrawl JSON config only when all requested options map.
    Convert(ManifestArgs),
}
/// Explicit caller-owned bounded JSON input.
#[derive(Debug, Args)]
pub struct ManifestArgs {
    /// Regular exported JSON file, at most one MiB; symlinks/special files refused.
    pub manifest: PathBuf,
}
/// Separately version-pinned input formats; these are not execution runtimes.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SourceDialectV1 {
    /// JavaScript actor-style crawler options, pinned release 3.18.2.
    JsActor,
    /// Python actor-style crawler options, pinned release 1.11.0.
    PyActor,
    /// Python spider-style settings, pinned release 2.19.0.
    PythonSpider,
    /// Go collector-style options, pinned release 2.2.0.
    GoCollector,
    /// Compatibility-API request options, pinned self-hosted inventory.
    CompatApi,
    /// Adaptive Python fetcher options, pinned release 0.4.15.
    AdaptivePy,
    /// LLM-oriented Python crawler options, pinned release 0.9.5.
    LlmPy,
    /// Seed-list batch crawler properties, pinned release 1.21; inspection only, not a seed-directory loader.
    SeedlistBatch,
    /// Released topology-stream crawler settings 3.5.1, never the separate 4.0 snapshot.
    TopologyStream,
    /// Bean-configured archival crawler 3.18.0; inspection only, not a CXML/Groovy loader.
    BeanConfig,
    /// Browser-driven YAML crawler 1.15.2; literal single-seed depth-zero subset.
    BrowserYaml,
}
impl SourceDialectV1 {
    fn version(self) -> &'static str {
        match self {
            Self::JsActor => "3.18.2",
            Self::PyActor => "1.11.0",
            Self::PythonSpider => "2.19.0",
            Self::GoCollector => "2.2.0",
            Self::CompatApi => "2.11.162",
            Self::AdaptivePy => "0.4.15",
            Self::LlmPy => "0.9.5",
            Self::SeedlistBatch => "1.21",
            Self::TopologyStream => "3.5.1",
            Self::BeanConfig => "3.18.0",
            Self::BrowserYaml => "1.15.2",
        }
    }
    /// Feature IDs of the pinned upstream release, one per line (`#` starts a comment).
    fn inventory(self) -> &'static str {
        match self {
            Self::JsActor | Self::PyActor => {
                include_str!("../data/source-inventories/js-py-actor.txt")
            }
            Self::PythonSpider => include_str!("../data/source-inventories/python-spider.txt"),
            Self::GoCollector => include_str!("../data/source-inventories/go-collector.txt"),
            Self::CompatApi => include_str!("../data/source-inventories/compat-api.txt"),
            Self::AdaptivePy => include_str!("../data/source-inventories/adaptive-py.txt"),
            Self::LlmPy => include_str!("../data/source-inventories/llm-py.txt"),
            Self::SeedlistBatch => include_str!("../data/source-inventories/seedlist-batch.txt"),
            Self::TopologyStream => include_str!("../data/source-inventories/topology-stream.txt"),
            Self::BeanConfig => include_str!("../data/source-inventories/bean-config.txt"),
            Self::BrowserYaml => include_str!("../data/source-inventories/browser-yaml.txt"),
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::JsActor => "CJ",
            Self::PyActor => "CP",
            Self::PythonSpider => "SC",
            Self::GoCollector => "CO",
            Self::CompatApi => "FC",
            Self::AdaptivePy => "SP",
            Self::LlmPy => "C4",
            Self::SeedlistBatch => "NUT-",
            Self::TopologyStream => "STC-",
            Self::BeanConfig => "HER-",
            Self::BrowserYaml => "BTR-",
        }
    }
    fn key(self, key: &str) -> Option<(&'static str, &'static str)> {
        match (self, key) {
            // Source option names below are the external formats' own keys.
            (Self::JsActor, "startUrls") => Some(("seedUrl", "CJ10")), // wire-compat: source option name
            (Self::PyActor, "start_urls") => Some(("seedUrl", "CP01")), // wire-compat: source option name
            (Self::PythonSpider | Self::AdaptivePy, "start_urls") => Some((
                // wire-compat: source option name
                "seedUrl",
                if matches!(self, Self::PythonSpider) {
                    "SC01"
                } else {
                    "SP26"
                },
            )),
            (Self::GoCollector, "URL") => Some(("seedUrl", "CO02")), // wire-compat: source option name
            (Self::CompatApi | Self::LlmPy, "url") => Some((
                // wire-compat: source option name
                "seedUrl",
                if matches!(self, Self::CompatApi) {
                    "FC01"
                } else {
                    "C401"
                },
            )),
            (Self::JsActor, "maxRequestsPerCrawl") => Some(("limits.urls", "CJ01")), // wire-compat: source option name
            (Self::PyActor, "max_requests_per_crawl") => Some(("limits.urls", "CP01")), // wire-compat: source option name
            (Self::PythonSpider, "CLOSESPIDER_PAGECOUNT") => Some(("limits.urls", "SC01")), // wire-compat: source option name
            (Self::GoCollector, "MaxRequests") => Some(("limits.urls", "CO05")), // wire-compat: source option name
            (Self::CompatApi, "limit") => Some(("limits.urls", "FC01")), // wire-compat: source option name
            (Self::JsActor, "maxCrawlDepth") => Some(("scope.maxDiscoveryDepth", "CJ09")), // wire-compat: source option name
            (Self::PyActor, "max_crawl_depth") => Some(("scope.maxDiscoveryDepth", "CP01")), // wire-compat: source option name
            (Self::PythonSpider, "DEPTH_LIMIT") => Some(("scope.maxDiscoveryDepth", "SC01")), // wire-compat: source option name
            (Self::GoCollector, "MaxDepth") => Some(("scope.maxDiscoveryDepth", "CO05")), // wire-compat: source option name
            (Self::GoCollector, "UserAgent") => Some(("fetch.userAgent", "CO01")), // wire-compat: source option name
            (Self::GoCollector, "MaxBodySize") => Some(("fetch.maxResponseBytes", "CO15")), // wire-compat: source option name
            // Pinned browser-yaml CLI options [B5] and crawl scope [B7].
            // Positive depths need prefix/www/scheme/redirect semantics which
            // native scope does not implement; only explicit depth zero maps.
            (Self::BrowserYaml, "url" | "seeds") => Some(("seedUrl", "BTR-02")), // wire-compat: source option name
            (Self::BrowserYaml, "depth") => Some(("scope.maxDiscoveryDepth", "BTR-03")), // wire-compat: source option name
            _ => None,
        }
    }
}
/// Trusted-exporter JSON schema; unknown wrapper fields fail before inspection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceManifestV1 {
    /// Exactly one.
    pub version: u16,
    /// Source dialect, never inferred from filenames.
    pub source: SourceDialectV1,
    /// Exact pinned source release.
    pub source_version: String,
    /// Literal exported source options. Every key gets a disposition.
    pub options: BTreeMap<String, Value>,
    /// Exported process environment of the source run (full variable names to text values) for
    /// dialects that read configuration from it. Programmatic `options` override it, as in the
    /// source's own construction order.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Explicit inventory behaviors required in addition to supplied options.
    #[serde(default)]
    pub required_inventory: Vec<String>,
    /// Optional native reviewed lifecycle selected by the trusted exporter.
    #[serde(default)]
    pub pipeline: ExtensionPipelineV1,
    /// Explicit native accepted-item namespaces and feeds; never inferred from source code.
    #[serde(default)]
    pub datasets: crawlx_core::dataset::DatasetConfigV1,
    /// Exported deprecated symbol names and their canonical source names.
    /// These declarations never load a source class or create native runtime aliases.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, String>,
}
/// One exact option or inventory row, with no raw content or credentials.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportDispositionV1 {
    /// Source inventory ID or supplied option name.
    pub id: String,
    /// native, translated, external_required, decision_needed, rejected or missing_evidence.
    pub state: &'static str,
    /// Exact native field/symbol, if executable.
    pub target: Option<&'static str>,
    /// Conservative source-semantic difference or failure cause.
    pub reason: &'static str,
    /// True only for supplied options and explicitly required inventory rows.
    pub requested: bool,
}
/// Complete report; unused inventory rows never become false compatibility claims.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReportV1 {
    /// Report schema version.
    pub version: u16,
    /// Exact explicitly selected source dialect.
    pub source: SourceDialectV1,
    /// Pinned source release, never inferred from an input filename.
    pub source_version: &'static str,
    /// Independently pinned source commit for the four request identity dialects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<&'static str>,
    /// No source-language API or ABI compatibility is claimed.
    pub sdk_abi_compatible: bool,
    /// Every supplied option and every source inventory row.
    pub dispositions: Vec<ImportDispositionV1>,
    /// For a dialect with environment configuration: every supported variable with its effective
    /// source, whether supplied or not, plus every supplied variable the release does not read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvDispositionV1>,
    /// Digest (hex) of the redacted, normalized native request: present only when
    /// the import is convertible, so a digest always names a config that was actually validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    /// All requested behavior has an executable native contract.
    pub convertible: bool,
}
/// One supported environment variable of the pinned collector release, reported whether or not
/// it is supplied.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvDispositionV1 {
    /// Full variable name as supplied or supported.
    pub key: String,
    /// Inventory row the variable belongs to (empty for a variable the release does not read).
    pub inventory: &'static str,
    /// native, translated, decision_needed or rejected.
    pub state: &'static str,
    /// Exact native field, if executable.
    pub target: Option<&'static str>,
    /// Where the effective value comes from: `env`, `options` (a programmatic option for the same
    /// setting overrides the variable) or `unset`.
    pub source: &'static str,
    /// Conservative source-semantic difference or failure cause; never a value.
    pub reason: &'static str,
    /// True when the variable was supplied.
    pub requested: bool,
}
impl EnvDispositionV1 {
    fn new(
        key: String,
        inventory: &'static str,
        state: &'static str,
        source: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            key,
            inventory,
            state,
            target: None,
            source,
            reason,
            requested: false,
        }
    }
}
/// What a supported environment variable becomes.
enum EnvMap {
    /// A native request field.
    Native(&'static str),
    /// The switch that would disable robots.txt: only the safe value is accepted.
    RobotsSwitch,
    /// No native counterpart; supplying it is reported and refused.
    Unmapped(&'static str),
}
struct EnvEntry {
    suffix: &'static str,
    inventory: &'static str,
    map: EnvMap,
}
/// Prefix of the environment variables the pinned collector release reads.
const COLLECTOR_ENV_PREFIX: &str = "COLLY_"; // wire-compat: environment variable prefix of the pinned release
/// Every variable of the pinned release, in report order.
const COLLECTOR_ENV: &[EnvEntry] = &[
    EnvEntry {
        suffix: "ALLOWED_DOMAINS",
        inventory: "CO05",
        map: EnvMap::Unmapped(
            "a literal domain list is not translated: native host scope is a typed rule, not an allow list",
        ),
    },
    EnvEntry {
        suffix: "CACHE_DIR",
        inventory: "CO27",
        map: EnvMap::Unmapped(
            "a collector cache directory has no native counterpart; use the native cache policy",
        ),
    },
    EnvEntry {
        suffix: "DETECT_CHARSET",
        inventory: "CO16",
        map: EnvMap::Unmapped("charset detection is native and always bounded; there is no switch"),
    },
    EnvEntry {
        suffix: "DISABLE_COOKIES",
        inventory: "CO22",
        map: EnvMap::Unmapped("cookies are bound to authorized sessions natively; there is no global switch"),
    },
    EnvEntry {
        suffix: "DISALLOWED_DOMAINS",
        inventory: "CO05",
        map: EnvMap::Unmapped(
            "a literal domain list is not translated: native host scope is a typed rule, not a deny list",
        ),
    },
    EnvEntry {
        suffix: "FOLLOW_REDIRECTS",
        inventory: "CO21",
        map: EnvMap::Native("fetch.followRedirects"),
    },
    EnvEntry {
        suffix: "IGNORE_ROBOTSTXT",
        inventory: "CO28",
        map: EnvMap::RobotsSwitch,
    },
    EnvEntry {
        suffix: "MAX_BODY_SIZE",
        inventory: "CO15",
        map: EnvMap::Native("fetch.maxResponseBytes"),
    },
    EnvEntry {
        suffix: "MAX_DEPTH",
        inventory: "CO05",
        map: EnvMap::Native("scope.maxDiscoveryDepth"),
    },
    EnvEntry {
        suffix: "MAX_REQUESTS",
        inventory: "CO05",
        map: EnvMap::Native("limits.urls"),
    },
    EnvEntry {
        suffix: "PARSE_HTTP_ERROR_RESPONSE",
        inventory: "CO17",
        map: EnvMap::Unmapped(
            "error-status bodies are handled by the native acquisition policy; there is no switch",
        ),
    },
    EnvEntry {
        suffix: "TRACE_HTTP",
        inventory: "CO33",
        map: EnvMap::Unmapped("request tracing is native telemetry, not a collector switch"),
    },
    EnvEntry {
        suffix: "USER_AGENT",
        inventory: "CO01",
        map: EnvMap::Native("fetch.userAgent"),
    },
];
/// The booleans the source language's parser accepts.
fn go_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}
/// A variable's text as the literal of its native target; `None` when it does not parse.
fn env_value(target: &str, raw: &str) -> Option<Value> {
    match target {
        "limits.urls" | "scope.maxDiscoveryDepth" | "fetch.maxResponseBytes" => {
            raw.parse::<u64>().ok().map(Value::from)
        }
        "fetch.followRedirects" => go_bool(raw).map(Value::Bool),
        "fetch.userAgent" => Some(Value::String(raw.to_owned())),
        _ => None,
    }
}
/// Whether `value` is a bounded literal the native `target` field can hold exactly. Unlimited
/// source values (`0` for a limit) and values the request would silently clamp are refused.
fn literal_valid(source: SourceDialectV1, target: &str, value: &Value) -> bool {
    match target {
        "seedUrl" => value
            .as_str()
            .or_else(|| {
                value
                    .as_array()
                    .filter(|a| a.len() == 1)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
            })
            .and_then(|s| url::Url::parse(s).ok())
            .is_some_and(|u| {
                matches!(u.scheme(), "http" | "https") && u.username().is_empty() && u.password().is_none()
            }),
        "limits.urls" => value.as_u64().is_some_and(|n| (1..=1_000_000).contains(&n)),
        "scope.maxDiscoveryDepth" if matches!(source, SourceDialectV1::BrowserYaml) => {
            value.as_u64() == Some(0)
        }
        "scope.maxDiscoveryDepth" => value.as_u64().is_some_and(|n| (1..=100).contains(&n)),
        "fetch.userAgent" => value
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)),
        "fetch.maxResponseBytes" => value
            .as_u64()
            .is_some_and(|n| (1_024..=64 * 1_024 * 1_024).contains(&n)),
        "fetch.followRedirects" => value.is_boolean(),
        _ => false,
    }
}
fn inspect_aliases(
    manifest: &SourceManifestV1,
    dispositions: &mut Vec<ImportDispositionV1>,
    valid: &mut bool,
) -> anyhow::Result<bool> {
    let mut queue_alias = false;
    if manifest.aliases.len() > 32 {
        bail!("source alias count exceeds limit");
    }
    for (alias, canonical) in &manifest.aliases {
        if alias.is_empty()
            || alias.len() > 128
            || !alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!("invalid source alias identifier");
        }
        let supported = matches!(manifest.source, SourceDialectV1::JsActor)
            && matches!(alias.as_str(), "RequestQueueV1" | "RequestQueueV2") // wire-compat: deprecated source queue symbols
            && canonical == "RequestQueue"; // wire-compat: canonical source queue symbol
        let state = if supported && !queue_alias {
            queue_alias = true;
            "translated"
        } else {
            *valid = false;
            "rejected"
        };
        dispositions.push(ImportDispositionV1 {
            id: alias.clone(),
            state,
            target: supported.then_some("CreateCrawl.orchestration.queue"),
            reason: if state == "translated" {
                "deprecated queue spelling resolves once to the bounded native fenced queue; no source class or native alias is installed"
            } else {
                "obsolete, conflicting or executable alias cannot be imported; handlers require separately reviewed declarative native recipes"
            },
            requested: true,
        });
    }
    Ok(queue_alias)
}

/// Inspect every option without evaluating code or returning option values.
///
/// # Errors
/// Fails for malformed schema, source version mismatch, limits or invalid pipeline.
/// Unmapped requested behavior is represented in the report, never silently dropped.
pub fn inspect(manifest: &SourceManifestV1) -> anyhow::Result<(ImportReportV1, Option<CreateCrawl>)> {
    if manifest.version != 1
        || manifest.source_version != manifest.source.version()
        || manifest.options.len() > 128
        || manifest.required_inventory.len() > 256
    {
        bail!("unsupported import schema/source version or manifest limits");
    }
    if crawlx_core::extensions::json_size(manifest)? > MAX_MANIFEST_BYTES {
        bail!("import manifest exceeds one MiB");
    }
    manifest.pipeline.validate()?;
    manifest.datasets.validate()?;
    let mut dispositions = Vec::new();
    let mut mapped = BTreeMap::new();
    let mut fields = BTreeMap::<&str, Value>::new();
    let mut valid = true;
    if manifest.pipeline.configured() {
        dispositions.push(ImportDispositionV1 { id:"pipeline".into(), state:"native",
            target:Some("CreateCrawl.extensions"),
            reason:"reviewed compiled native pipeline with fixed versions and capability ceilings, not source callbacks", requested:true });
    }
    if !manifest.datasets.stores.is_empty()
        || !manifest.datasets.feeds.is_empty()
        || !manifest.datasets.kv_stores.is_empty()
    {
        dispositions.push(ImportDispositionV1 {
            id: "datasets".into(),
            state: "native",
            target: Some("CreateCrawl.datasets"),
            reason: "explicit native retention-aware namespaces and registered destination references",
            requested: true,
        });
    }
    for (key, value) in &manifest.options {
        if key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'_' | b'-')
                    || (b == b'.'
                        && matches!(
                            manifest.source,
                            SourceDialectV1::SeedlistBatch
                                | SourceDialectV1::TopologyStream
                                | SourceDialectV1::BeanConfig
                                | SourceDialectV1::BrowserYaml
                        ))
            })
        {
            bail!("invalid source option identifier");
        }
        let Some((target, inventory)) = manifest.source.key(key) else {
            valid = false;
            dispositions.push(ImportDispositionV1 {
                id: key.clone(),
                state: "rejected",
                target: None,
                reason: match manifest.source {
                    SourceDialectV1::SeedlistBatch => "seed directories, per-iteration fetchlists and plugin properties have no literal native seed/global-limit mapping; no files or JVM classes are loaded",
                    SourceDialectV1::TopologyStream => "topology/spout inputs and queue caps are not native seeds/global crawl limits; YAML, classes and snapshot-only settings are not imported",
                    SourceDialectV1::BeanConfig => "ReadSource beans, ordered hop rules and graceful document limits are not literal native seeds/depth/hard URL limits; CXML and Groovy are not loaded",
                    SourceDialectV1::BrowserYaml => "only one literal url/seeds and explicit depth zero map; page/dedupe caps, scope overrides, behaviors, endpoints and credentials are not imported",
                    _ => "unknown or unmapped source option; arbitrary callbacks and runtime plugins are never imported",
                },
                requested: true,
            });
            continue;
        };
        let value_valid = literal_valid(manifest.source, target, value);
        if !value_valid {
            valid = false;
            dispositions.push(ImportDispositionV1 {
                id: key.clone(),
                state: "rejected",
                target: Some(target),
                reason:
                    "literal value exceeds the executable native mapping or uses unbounded source semantics",
                requested: true,
            });
            continue;
        }
        if fields.contains_key(target) {
            valid = false;
            dispositions.push(ImportDispositionV1 {
                id: key.clone(),
                state: "rejected",
                target: Some(target),
                reason: "multiple supplied options target one native field; source alias precedence must be resolved explicitly",
                requested: true,
            });
            continue;
        }
        fields.insert(target, value.clone());
        mapped.insert(inventory, target);
        dispositions.push(ImportDispositionV1 { id: key.clone(), state: "translated", target: Some(target),
            reason: "bounded native declarative contract; native safety/admission remains authoritative, not SDK equivalence", requested: true });
    }
    // Environment configuration (programmatic options already won above: construction reads
    // the environment first, then applies explicit options over it).
    if manifest.env.len() > 64
        || manifest.env.keys().any(|k| {
            k.is_empty() || k.len() > 128 || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        bail!("invalid source environment identifier or too many variables");
    }
    let mut env_rows = Vec::new();
    if matches!(manifest.source, SourceDialectV1::GoCollector) {
        for entry in COLLECTOR_ENV {
            let key = format!("{COLLECTOR_ENV_PREFIX}{}", entry.suffix);
            let Some(raw) = manifest.env.get(&key) else {
                env_rows.push(EnvDispositionV1::new(
                    key,
                    entry.inventory,
                    "decision_needed",
                    "unset",
                    "not supplied; the native default applies",
                ));
                continue;
            };
            let mut row = EnvDispositionV1::new(key, entry.inventory, "rejected", "env", "");
            row.requested = true;
            match entry.map {
                EnvMap::Unmapped(reason) => {
                    row.reason = reason;
                    valid = false;
                }
                EnvMap::RobotsSwitch => match go_bool(raw) {
                    Some(false) => {
                        row.state = "native";
                        row.reason = "robots.txt is always honored natively; false keeps that";
                    }
                    Some(true) => {
                        row.reason = "ignoring robots.txt is never imported; a native request needs an authorization record for that";
                        valid = false;
                    }
                    None => {
                        row.reason = "value is not a boolean literal";
                        valid = false;
                    }
                },
                EnvMap::Native(target) => {
                    row.target = Some(target);
                    match env_value(target, raw).filter(|v| literal_valid(manifest.source, target, v)) {
                        None => {
                            row.reason =
                                "value is unlimited, out of range or not a literal of the expected type";
                            valid = false;
                        }
                        Some(_) if fields.contains_key(target) => {
                            row.state = "translated";
                            row.source = "options";
                            row.reason = "overridden by the programmatic option for the same setting";
                        }
                        Some(value) => {
                            fields.insert(target, value);
                            mapped.insert(entry.inventory, target);
                            row.state = "translated";
                            row.reason = "bounded native declarative contract; native safety/admission remains authoritative";
                        }
                    }
                }
            }
            env_rows.push(row);
        }
        for key in manifest.env.keys() {
            if !COLLECTOR_ENV
                .iter()
                .any(|e| key.strip_prefix(COLLECTOR_ENV_PREFIX) == Some(e.suffix))
            {
                let mut row = EnvDispositionV1::new(
                    key.clone(),
                    "",
                    "rejected",
                    "env",
                    "not a variable of the pinned release; only the listed variables are read",
                );
                row.requested = true;
                valid = false;
                env_rows.push(row);
            }
        }
    } else if !manifest.env.is_empty() {
        valid = false;
        dispositions.push(ImportDispositionV1 {
            id: "env".into(),
            state: "rejected",
            target: None,
            reason: "this source dialect defines no environment configuration",
            requested: true,
        });
    }
    let queue_alias = inspect_aliases(manifest, &mut dispositions, &mut valid)?;
    let seed = fields.get("seedUrl").and_then(|v| {
        v.as_str().or_else(|| {
            v.as_array()
                .filter(|a| a.len() == 1)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        })
    });
    let mut crawl = seed
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| {
            matches!(u.scheme(), "http" | "https") && u.username().is_empty() && u.password().is_none()
        })
        .map(CreateCrawl::new);
    if let Some(crawl) = &mut crawl {
        crawl.mode = if matches!(manifest.source, SourceDialectV1::BrowserYaml) {
            // This is browser acquisition, not browser-yaml behavior/archive parity.
            crawlx_core::CrawlMode::Dynamic
        } else {
            crawlx_core::CrawlMode::Static
        };
        crawl.extensions = manifest.pipeline.clone();
        crawl.datasets = manifest.datasets.clone();
        if queue_alias {
            crawl.orchestration = Some(crawlx_core::orchestration::OrchestrationConfigV1::default());
        }
        if manifest.pipeline.requires_document() {
            crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
        }
        if let Some(v) = fields.get("limits.urls") {
            if let Some(n) = v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| (1..=1_000_000).contains(n))
            {
                crawl.limits.urls = n;
            } else {
                valid = false;
            }
        }
        if let Some(v) = fields.get("scope.maxDiscoveryDepth") {
            // Zero is finite only for the explicit browser-yaml depth-zero subset.
            if let Some(n) = v.as_u64().and_then(|n| u16::try_from(n).ok()).filter(|n| {
                if matches!(manifest.source, SourceDialectV1::BrowserYaml) {
                    *n == 0
                } else {
                    (1..=100).contains(n)
                }
            }) {
                crawl.scope.max_discovery_depth = n;
            } else {
                valid = false;
            }
        }
        if let Some(s) = fields.get("fetch.userAgent").and_then(Value::as_str) {
            crawl.fetch.user_agent = Some(s.to_owned());
        }
        if let Some(n) = fields.get("fetch.maxResponseBytes").and_then(Value::as_u64) {
            crawl.fetch.max_response_bytes = n;
        }
        if let Some(b) = fields.get("fetch.followRedirects").and_then(Value::as_bool) {
            crawl.fetch.follow_redirects = b;
        }
        if matches!(manifest.source, SourceDialectV1::BrowserYaml) {
            // Omitted depth means unlimited upstream; never substitute native ten.
            if !fields.contains_key("scope.maxDiscoveryDepth") {
                valid = false;
                dispositions.push(ImportDispositionV1 {
                    id: "source-scope".into(),
                    state: "rejected",
                    target: None,
                    reason: "browser-yaml requires explicit depth zero; default unlimited depth and positive-depth prefix scope have no equivalent native mapping",
                    requested: true,
                });
            }
            // Depth zero is one seed, with no independent sitemap seed expansion.
            crawl.limits.urls = 1;
            crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
            crawl.scope.known_files.clear();
        }
        if crawl.normalize().is_err() {
            valid = false;
        }
    } else {
        valid = false;
    }
    if !valid {
        dispositions.push(ImportDispositionV1 { id: "native-contract".into(), state: "rejected", target: None,
            reason: "one credential-free HTTP(S) seed and bounded literal numeric options are required; native config must validate", requested: true });
    }
    let mut inventory_ids = std::collections::BTreeSet::new();
    for line in manifest.source.inventory().lines() {
        let id = line.trim();
        if !id.starts_with(manifest.source.prefix())
            || id.len() > 8
            || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !id.bytes().any(|b| b.is_ascii_digit())
        {
            continue;
        }
        inventory_ids.insert(id.to_owned());
    }
    for id in &inventory_ids {
        let requested = manifest.required_inventory.contains(id);
        // A mapped option never establishes an entire multi-feature inventory row.
        let target = mapped.get(id.as_str()).copied();
        let state = if requested {
            "missing_evidence"
        } else {
            "decision_needed"
        };
        if requested {
            valid = false;
        }
        dispositions.push(ImportDispositionV1 {
            id: id.clone(),
            state,
            target,
            reason: "full inventory family parity is not established by an individual option mapping",
            requested,
        });
    }
    for id in &manifest.required_inventory {
        if !inventory_ids.contains(id) {
            valid = false;
            dispositions.push(ImportDispositionV1 {
                id: "unknown-inventory-id".into(),
                state: "rejected",
                target: None,
                reason: "required inventory identifier is absent from the pinned dialect inventory",
                requested: true,
            });
        }
    }
    // Over the redacted form, so no value of a header or cookie can influence it; present only
    // for a conversion that will actually be produced.
    let config_digest = if valid {
        crawl
            .as_ref()
            .and_then(|c| c.redacted().digest().ok())
            .map(|d| d.to_string())
    } else {
        None
    };
    Ok((
        ImportReportV1 {
            version: 1,
            source: manifest.source,
            source_version: manifest.source.version(),
            source_commit: match manifest.source {
                SourceDialectV1::JsActor => Some(crawlx_core::request::import::SOURCE_PINS[0].2),
                SourceDialectV1::PyActor => Some(crawlx_core::request::import::SOURCE_PINS[1].2),
                SourceDialectV1::PythonSpider => Some(crawlx_core::request::import::SOURCE_PINS[2].2),
                SourceDialectV1::GoCollector => Some(crawlx_core::request::import::SOURCE_PINS[3].2),
                _ => None,
            },
            sdk_abi_compatible: false,
            dispositions,
            env: env_rows,
            config_digest,
            convertible: valid,
        },
        if valid { crawl } else { None },
    ))
}
/// Offline inspect/convert dispatch; no telemetry, update check, network or durable spool.
///
/// # Errors
/// Fails for unreadable/nonregular/oversized JSON, malformed schemas or output errors.
/// Requested unmapped behavior prints the report and returns exit code two.
pub async fn run(args: SourceImportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let (input, convert) = match args.command {
        SourceImportCommand::Inspect(a) => (a, false),
        SourceImportCommand::Convert(a) => (a, true),
    };
    let metadata = tokio::fs::symlink_metadata(&input.manifest)
        .await
        .context("reading import manifest metadata")?;
    if !metadata.file_type().is_file() || metadata.len() > u64::try_from(MAX_MANIFEST_BYTES)? {
        bail!("import manifest must be a regular file no larger than one MiB");
    }
    let mut bytes = Vec::new();
    tokio::fs::File::open(&input.manifest)
        .await?
        .take(u64::try_from(MAX_MANIFEST_BYTES + 1)?)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        bail!("import manifest exceeds one MiB");
    }
    // This discriminator grants no compatibility or execution capability. Each
    // selected adapter subsequently parses the complete strict wrapper itself.
    #[derive(Deserialize)]
    struct Source<'a> {
        #[serde(borrow)]
        source: std::borrow::Cow<'a, str>,
        #[serde(default, borrow)]
        format: Option<std::borrow::Cow<'a, str>>,
    }
    let source: Source<'_> = serde_json::from_slice(&bytes).context("reading import source dialect")?;
    if source.format.as_deref() == Some("neutral-export-v1") {
        return crate::migration_dialects::run_manifest(&bytes, convert, out).await;
    }
    if matches!(
        source.source.as_ref(),
        "text-precision" | "news-article" | "surface-flags"
    ) {
        return crate::extraction_import::run_manifest(&bytes, convert, out).await;
    }
    let manifest: SourceManifestV1 =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid declarative import manifest"))?;
    let (report, crawl) = inspect(&manifest)?;
    if convert && report.convertible {
        serde_json::to_writer_pretty(&mut *out, &crawl.context("validated import lacks native config")?)?;
    } else {
        serde_json::to_writer_pretty(&mut *out, &report)?;
    }
    writeln!(out)?;
    Ok(if report.convertible {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn bundled_inventories_hold_the_pinned_identifier_counts() {
        let expected = [
            (SourceDialectV1::JsActor, 38),
            (SourceDialectV1::PyActor, 40),
            (SourceDialectV1::PythonSpider, 50),
            (SourceDialectV1::GoCollector, 38),
            (SourceDialectV1::CompatApi, 43),
            (SourceDialectV1::AdaptivePy, 48),
            (SourceDialectV1::LlmPy, 50),
            (SourceDialectV1::SeedlistBatch, 40),
            (SourceDialectV1::TopologyStream, 38),
            (SourceDialectV1::BeanConfig, 40),
            (SourceDialectV1::BrowserYaml, 46),
        ];
        for (dialect, count) in expected {
            let prefix = dialect.prefix();
            let ids: std::collections::BTreeSet<&str> = dialect
                .inventory()
                .lines()
                .map(str::trim)
                .filter(|id| {
                    id.starts_with(prefix)
                        && id.len() <= 8
                        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        && id.bytes().any(|b| b.is_ascii_digit())
                })
                .collect();
            assert_eq!(ids.len(), count, "{prefix}");
        }
    }
    use serde_json::json;
    #[test]
    fn unknown_option_fails_conversion_and_is_reported() {
        let manifest = serde_json::from_value(
            json!({"version":1,"source":"python-spider","sourceVersion":"2.19.0",
            "options":{"start_urls":["https://fixture.test/"],"DOWNLOADER_MIDDLEWARES":{"evil.Plugin":1}}}),
        )
        .unwrap();
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(!report.convertible);
        assert!(crawl.is_none());
        assert!(report
            .dispositions
            .iter()
            .any(|d| d.id == "DOWNLOADER_MIDDLEWARES" && d.state == "rejected"));
        assert!(report.dispositions.iter().any(|d| d.id == "SC16"));
    }
    #[test]
    fn converted_recipe_runs_real_native_fixture_parser_and_pipeline() {
        let manifest = serde_json::from_value(
            json!({"version":1,"source":"go-collector","sourceVersion":"2.2.0",
            "options":{"URL":"https://fixture.test/","MaxRequests":4,"MaxDepth":2}}),
        )
        .unwrap();
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(report.convertible);
        let crawl = crawl.unwrap();
        assert_eq!(
            crawl.scope.strategy,
            crawlx_core::config::CrawlStrategy::BreadthFirst
        );
        let options = crawlx_extract::ExtractOptions {
            content: Some(crawlx_core::extraction::ExtractionPolicyV1::default()),
            ..Default::default()
        };
        let doc = crawlx_extract::Extractor::extract_bytes_with_projection(b"<html><head><title>Fixture article</title></head><body><article><p>Native declarative parsing preserves authored article text and applies reviewed item policies without executing imported callbacks.</p></article></body></html>",
            &crawl.seed_url, &options, &|_| None).unwrap();
        let item = crawlx_worker::extensions::transform_document(
            &crawl.extensions,
            "default",
            doc.article.as_ref().unwrap(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(item["title"], "Fixture article");
    }
    #[test]
    fn wrapper_unknown_fields_fail_before_conversion() {
        assert!(
            serde_json::from_value::<SourceManifestV1>(json!({"version":1,"source":"python-spider",
            "sourceVersion":"2.19.0","options":{},"pythonModule":"evil"}))
            .is_err()
        );
    }

    fn collector(options: serde_json::Value, env: serde_json::Value) -> SourceManifestV1 {
        serde_json::from_value(
            json!({"version":1,"source":"go-collector","sourceVersion":"2.2.0",
            "options":options,"env":env}),
        )
        .unwrap()
    }
    /// An exported environment: every key is a supported suffix under the release's prefix.
    fn env(pairs: &[(&str, &str)]) -> serde_json::Value {
        serde_json::Value::Object(
            pairs
                .iter()
                .map(|(suffix, value)| (format!("{COLLECTOR_ENV_PREFIX}{suffix}"), json!(value)))
                .collect(),
        )
    }
    fn env_row<'a>(report: &'a ImportReportV1, suffix: &str) -> &'a EnvDispositionV1 {
        let key = format!("{COLLECTOR_ENV_PREFIX}{suffix}");
        report.env.iter().find(|row| row.key == key).unwrap()
    }

    #[test]
    fn report_lists_every_supported_env_key_even_when_none_is_supplied() {
        let (report, crawl) = inspect(&collector(json!({"URL":"https://fixture.test/"}), json!({}))).unwrap();
        assert!(report.convertible && crawl.is_some());
        assert_eq!(report.env.len(), 13);
        for entry in COLLECTOR_ENV {
            let row = env_row(&report, entry.suffix);
            assert_eq!((row.source, row.requested), ("unset", false), "{}", entry.suffix);
        }
    }

    #[test]
    fn env_values_translate_and_a_programmatic_option_overrides_them() {
        let manifest = collector(
            json!({"URL":"https://fixture.test/","MaxDepth":4}),
            env(&[
                ("MAX_DEPTH", "9"),
                ("MAX_REQUESTS", "25"),
                ("USER_AGENT", "fixture-agent/1"),
                ("MAX_BODY_SIZE", "65536"),
                ("FOLLOW_REDIRECTS", "false"),
                ("IGNORE_ROBOTSTXT", "false"),
            ]),
        );
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(report.convertible, "{:?}", report.env);
        let crawl = crawl.unwrap();
        assert_eq!(
            crawl.scope.max_discovery_depth, 4,
            "the option beats the environment"
        );
        assert_eq!(crawl.limits.urls, 25);
        assert_eq!(crawl.fetch.user_agent.as_deref(), Some("fixture-agent/1"));
        assert_eq!(crawl.fetch.max_response_bytes, 65_536);
        assert!(!crawl.fetch.follow_redirects);
        assert_eq!(env_row(&report, "MAX_DEPTH").source, "options");
        assert_eq!(env_row(&report, "MAX_REQUESTS").source, "env");
        assert_eq!(env_row(&report, "MAX_REQUESTS").state, "translated");
        assert_eq!(env_row(&report, "IGNORE_ROBOTSTXT").state, "native");
        // the report carries no values
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("fixture-agent"), "{text}");
    }

    #[test]
    fn unsafe_unlimited_unparsable_and_unmapped_env_values_are_rejected_with_a_complete_report() {
        for (suffix, value) in [
            ("IGNORE_ROBOTSTXT", "true"),
            ("MAX_DEPTH", "0"),
            ("MAX_REQUESTS", "0"),
            ("MAX_BODY_SIZE", "0"),
            ("MAX_BODY_SIZE", "1099511627776"),
            ("MAX_DEPTH", "deep"),
            ("FOLLOW_REDIRECTS", "maybe"),
            ("CACHE_DIR", "/tmp/cache"),
            ("TRACE_HTTP", "true"),
            ("NO_SUCH_KEY", "1"),
        ] {
            let (report, crawl) = inspect(&collector(
                json!({"URL":"https://fixture.test/"}),
                env(&[(suffix, value)]),
            ))
            .unwrap();
            assert!(!report.convertible, "{suffix}={value}");
            assert!(
                crawl.is_none() && report.config_digest.is_none(),
                "{suffix}={value}"
            );
            assert_eq!(env_row(&report, suffix).state, "rejected", "{suffix}={value}");
            assert!(report.env.len() >= 13, "every supported key is still listed");
            if value.len() > 4 {
                assert!(
                    !serde_json::to_string(&report).unwrap().contains(value),
                    "{suffix}: value echoed"
                );
            }
        }
    }

    #[test]
    fn a_variable_outside_the_pinned_prefix_is_rejected() {
        let manifest = collector(
            json!({"URL":"https://fixture.test/"}),
            json!({"OTHER_MAX_DEPTH":"3"}),
        );
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(!report.convertible && crawl.is_none());
        let row = report.env.iter().find(|r| r.key == "OTHER_MAX_DEPTH").unwrap();
        assert_eq!((row.state, row.requested), ("rejected", true));
    }

    #[test]
    fn env_is_refused_for_dialects_that_have_none() {
        let manifest: SourceManifestV1 = serde_json::from_value(json!({"version":1,"source":"python-spider",
            "sourceVersion":"2.19.0","options":{"start_urls":["https://fixture.test/"]},
            "env":env(&[("MAX_DEPTH", "2")])}))
        .unwrap();
        let (report, _) = inspect(&manifest).unwrap();
        assert!(!report.convertible);
        assert!(report.env.is_empty());
        assert!(report
            .dispositions
            .iter()
            .any(|d| d.id == "env" && d.state == "rejected"));
    }

    #[test]
    fn convertible_imports_carry_a_stable_config_digest_that_follows_the_effective_config() {
        let base = |extra: serde_json::Value| {
            let mut options = json!({"URL":"https://fixture.test/","MaxRequests":4});
            options
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            inspect(&collector(options, json!({}))).unwrap().0
        };
        let a = base(json!({}));
        let b = base(json!({}));
        let c = base(json!({"MaxDepth":2}));
        let digest = a.config_digest.clone().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(Some(&digest), b.config_digest.as_ref());
        assert_ne!(Some(&digest), c.config_digest.as_ref());
        // the same effective config reached through the environment has the same digest
        let via_env = inspect(&collector(
            json!({"URL":"https://fixture.test/"}),
            env(&[("MAX_REQUESTS", "4")]),
        ))
        .unwrap()
        .0;
        assert_eq!(via_env.config_digest.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn every_unknown_option_is_reported_not_just_the_first() {
        let (report, crawl) = inspect(&collector(
            json!({"URL":"https://fixture.test/","OnResponse":"cb","WithTransport":"t","MaxDepth":0}),
            json!({}),
        ))
        .unwrap();
        assert!(!report.convertible && crawl.is_none() && report.config_digest.is_none());
        for id in ["OnResponse", "WithTransport", "MaxDepth"] {
            assert!(
                report
                    .dispositions
                    .iter()
                    .any(|d| d.id == id && d.state == "rejected"),
                "{id}"
            );
        }
    }

    #[test]
    fn deprecated_queue_symbol_resolves_once_without_runtime_aliases() {
        for alias in ["RequestQueueV1", "RequestQueueV2"] {
            // wire-compat: deprecated source queue names
            let manifest: SourceManifestV1 = serde_json::from_value(json!({
                "version":1,"source":"js-actor","sourceVersion":"3.18.2",
                "options":{"startUrls":["https://fixture.test/"]},
                "aliases":{alias:"RequestQueue"}
            }))
            .unwrap(); // wire-compat: canonical source queue name
            let (report, crawl) = inspect(&manifest).unwrap();
            assert!(report.convertible);
            assert!(crawl.unwrap().orchestration.is_some());
            assert_eq!(report.source_version, "3.18.2");
            assert_eq!(
                report.source_commit,
                Some(crawlx_core::request::import::SOURCE_PINS[0].2)
            );
            assert_eq!(
                report.dispositions.iter().filter(|row| row.id == alias).count(),
                1
            );
        }
    }

    #[test]
    fn duplicate_queue_aliases_and_executable_handlers_are_all_reported() {
        let manifest: SourceManifestV1 = serde_json::from_value(json!({
            "version":1,"source":"js-actor","sourceVersion":"3.18.2",
            "options":{"startUrls":["https://fixture.test/"]},
            "aliases":{"RequestQueueV1":"RequestQueue","RequestQueueV2":"RequestQueue",
                "handlePageFunction":"private-callback-value"}
        }))
        .unwrap(); // wire-compat: exported deprecated symbol names
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(!report.convertible && crawl.is_none());
        assert!(report
            .dispositions
            .iter()
            .any(|row| row.id == "RequestQueueV2" && row.state == "rejected")); // wire-compat
        assert!(report
            .dispositions
            .iter()
            .any(|row| row.id == "handlePageFunction" && row.state == "rejected")); // wire-compat
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("private-callback-value"));
    }
}
