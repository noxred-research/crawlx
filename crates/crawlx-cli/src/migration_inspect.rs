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
/// Separately version-pinned source families; these are not execution runtimes.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceDialectV1 {
    /// Crawlee JavaScript 3.18.2.
    CrawleeJs,
    /// Crawlee Python 1.11.0.
    CrawleePython,
    /// Scrapy 2.19.0.
    Scrapy,
    /// Colly 2.2.0.
    Colly,
    /// Firecrawl pinned self-hosted inventory.
    Firecrawl,
    /// Scrapling 0.4.15.
    Scrapling,
    /// Crawl4AI 0.9.5.
    Crawl4ai,
    /// Apache Nutch 1.21; inspection only, not a seed-directory loader.
    Nutch,
    /// Released StormCrawler 3.5.1, never the separate 4.0 snapshot.
    Stormcrawler,
    /// Heritrix 3.18.0; inspection only, not a CXML/Groovy loader.
    Heritrix,
    /// Browsertrix Crawler 1.15.2; literal single-seed depth-zero subset.
    Browsertrix,
}
impl SourceDialectV1 {
    fn version(self) -> &'static str {
        match self {
            Self::CrawleeJs => "3.18.2",
            Self::CrawleePython => "1.11.0",
            Self::Scrapy => "2.19.0",
            Self::Colly => "2.2.0",
            Self::Firecrawl => "2.11.162",
            Self::Scrapling => "0.4.15",
            Self::Crawl4ai => "0.9.5",
            Self::Nutch => "1.21",
            Self::Stormcrawler => "3.5.1",
            Self::Heritrix => "3.18.0",
            Self::Browsertrix => "1.15.2",
        }
    }
    /// Feature IDs of the pinned upstream release, one per line (`#` starts a comment).
    fn inventory(self) -> &'static str {
        match self {
            Self::CrawleeJs | Self::CrawleePython => {
                include_str!("../data/source-inventories/crawlee.txt")
            }
            Self::Scrapy => include_str!("../data/source-inventories/scrapy.txt"),
            Self::Colly => include_str!("../data/source-inventories/colly.txt"),
            Self::Firecrawl => include_str!("../data/source-inventories/firecrawl.txt"),
            Self::Scrapling => include_str!("../data/source-inventories/scrapling.txt"),
            Self::Crawl4ai => include_str!("../data/source-inventories/crawl4ai.txt"),
            Self::Nutch => include_str!("../data/source-inventories/nutch.txt"),
            Self::Stormcrawler => include_str!("../data/source-inventories/stormcrawler.txt"),
            Self::Heritrix => include_str!("../data/source-inventories/heritrix.txt"),
            Self::Browsertrix => include_str!("../data/source-inventories/browsertrix.txt"),
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::CrawleeJs => "CJ",
            Self::CrawleePython => "CP",
            Self::Scrapy => "SC",
            Self::Colly => "CO",
            Self::Firecrawl => "FC",
            Self::Scrapling => "SP",
            Self::Crawl4ai => "C4",
            Self::Nutch => "NUT-",
            Self::Stormcrawler => "STC-",
            Self::Heritrix => "HER-",
            Self::Browsertrix => "BTR-",
        }
    }
    fn key(self, key: &str) -> Option<(&'static str, &'static str)> {
        match (self, key) {
            (Self::CrawleeJs, "startUrls") => Some(("seedUrl", "CJ10")),
            (Self::CrawleePython, "start_urls") => Some(("seedUrl", "CP01")),
            (Self::Scrapy | Self::Scrapling, "start_urls") => Some((
                "seedUrl",
                if matches!(self, Self::Scrapy) {
                    "SC01"
                } else {
                    "SP26"
                },
            )),
            (Self::Colly, "URL") => Some(("seedUrl", "CO02")),
            (Self::Firecrawl | Self::Crawl4ai, "url") => Some((
                "seedUrl",
                if matches!(self, Self::Firecrawl) {
                    "FC01"
                } else {
                    "C401"
                },
            )),
            (Self::CrawleeJs, "maxRequestsPerCrawl") => Some(("limits.urls", "CJ01")),
            (Self::CrawleePython, "max_requests_per_crawl") => Some(("limits.urls", "CP01")),
            (Self::Scrapy, "CLOSESPIDER_PAGECOUNT") => Some(("limits.urls", "SC01")),
            (Self::Colly, "MaxRequests") => Some(("limits.urls", "CO05")),
            (Self::Firecrawl, "limit") => Some(("limits.urls", "FC01")),
            (Self::CrawleeJs, "maxCrawlDepth") => Some(("scope.maxDiscoveryDepth", "CJ09")),
            (Self::CrawleePython, "max_crawl_depth") => Some(("scope.maxDiscoveryDepth", "CP01")),
            (Self::Scrapy, "DEPTH_LIMIT") => Some(("scope.maxDiscoveryDepth", "SC01")),
            (Self::Colly, "MaxDepth") => Some(("scope.maxDiscoveryDepth", "CO05")),
            // Pinned Browsertrix CLI options [B5] and crawl scope [B7].
            // Positive depths need prefix/www/scheme/redirect semantics which
            // native scope does not implement; only explicit depth zero maps.
            (Self::Browsertrix, "url" | "seeds") => Some(("seedUrl", "BTR-02")),
            (Self::Browsertrix, "depth") => Some(("scope.maxDiscoveryDepth", "BTR-03")),
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
    /// Explicit inventory behaviors required in addition to supplied options.
    #[serde(default)]
    pub required_inventory: Vec<String>,
    /// Optional native reviewed lifecycle selected by the trusted exporter.
    #[serde(default)]
    pub pipeline: ExtensionPipelineV1,
    /// Explicit native accepted-item namespaces and feeds; never inferred from source code.
    #[serde(default)]
    pub datasets: crawlx_core::dataset::DatasetConfigV1,
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
    /// No source-language API or ABI compatibility is claimed.
    pub sdk_abi_compatible: bool,
    /// Every supplied option and every source inventory row.
    pub dispositions: Vec<ImportDispositionV1>,
    /// All requested behavior has an executable native contract.
    pub convertible: bool,
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
    let mut fields = BTreeMap::<&str, &Value>::new();
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
                            SourceDialectV1::Nutch
                                | SourceDialectV1::Stormcrawler
                                | SourceDialectV1::Heritrix
                                | SourceDialectV1::Browsertrix
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
                    SourceDialectV1::Nutch => "Nutch seed directories, per-iteration fetchlists and plugin properties have no literal native seed/global-limit mapping; no files or JVM classes are loaded",
                    SourceDialectV1::Stormcrawler => "StormCrawler topology/spout inputs and queue caps are not native seeds/global crawl limits; YAML, classes and snapshot-only settings are not imported",
                    SourceDialectV1::Heritrix => "Heritrix ReadSource beans, ordered hop rules and graceful document limits are not literal native seeds/depth/hard URL limits; CXML and Groovy are not loaded",
                    SourceDialectV1::Browsertrix => "only one literal url/seeds and explicit depth zero map; page/dedupe caps, scope overrides, behaviors, endpoints and credentials are not imported",
                    _ => "unknown or unmapped source option; arbitrary callbacks and runtime plugins are never imported",
                },
                requested: true,
            });
            continue;
        };
        let value_valid = match target {
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
                    matches!(u.scheme(), "http" | "https")
                        && u.username().is_empty()
                        && u.password().is_none()
                }),
            "limits.urls" => value.as_u64().is_some_and(|n| (1..=1_000_000).contains(&n)),
            "scope.maxDiscoveryDepth" if matches!(manifest.source, SourceDialectV1::Browsertrix) => {
                value.as_u64() == Some(0)
            }
            "scope.maxDiscoveryDepth" => value.as_u64().is_some_and(|n| (1..=100).contains(&n)),
            _ => false,
        };
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
        if matches!(manifest.source, SourceDialectV1::Browsertrix) && fields.contains_key(target) {
            valid = false;
            dispositions.push(ImportDispositionV1 {
                id: key.clone(),
                state: "rejected",
                target: Some(target),
                reason: "mixed source aliases require upstream precedence; only one literal seed option is supported",
                requested: true,
            });
            continue;
        }
        fields.insert(target, value);
        mapped.insert(inventory, target);
        dispositions.push(ImportDispositionV1 { id: key.clone(), state: "translated", target: Some(target),
            reason: "bounded native declarative contract; native safety/admission remains authoritative, not SDK equivalence", requested: true });
    }
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
        crawl.mode = if matches!(manifest.source, SourceDialectV1::Browsertrix) {
            // This is browser acquisition, not Browsertrix behavior/archive parity.
            crawlx_core::CrawlMode::Dynamic
        } else {
            crawlx_core::CrawlMode::Static
        };
        crawl.extensions = manifest.pipeline.clone();
        crawl.datasets = manifest.datasets.clone();
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
            // Zero is finite only for the explicit Browsertrix depth-zero subset.
            if let Some(n) = v.as_u64().and_then(|n| u16::try_from(n).ok()).filter(|n| {
                if matches!(manifest.source, SourceDialectV1::Browsertrix) {
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
        if matches!(manifest.source, SourceDialectV1::Browsertrix) {
            // Omitted depth means unlimited upstream; never substitute native ten.
            if !fields.contains_key("scope.maxDiscoveryDepth") {
                valid = false;
                dispositions.push(ImportDispositionV1 {
                    id: "source-scope".into(),
                    state: "rejected",
                    target: None,
                    reason: "Browsertrix requires explicit depth zero; default unlimited depth and positive-depth prefix scope have no equivalent native mapping",
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
    Ok((
        ImportReportV1 {
            version: 1,
            sdk_abi_compatible: false,
            dispositions,
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
    }
    let source: Source<'_> = serde_json::from_slice(&bytes).context("reading import source dialect")?;
    if matches!(source.source.as_ref(), "trafilatura" | "newspaper4k" | "katana") {
        return crate::extraction_import::run_manifest(&bytes, convert, out).await;
    }
    let manifest: SourceManifestV1 =
        serde_json::from_slice(&bytes).context("reading declarative import manifest")?;
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
            (SourceDialectV1::CrawleeJs, 38),
            (SourceDialectV1::CrawleePython, 40),
            (SourceDialectV1::Scrapy, 50),
            (SourceDialectV1::Colly, 38),
            (SourceDialectV1::Firecrawl, 43),
            (SourceDialectV1::Scrapling, 48),
            (SourceDialectV1::Crawl4ai, 50),
            (SourceDialectV1::Nutch, 40),
            (SourceDialectV1::Stormcrawler, 38),
            (SourceDialectV1::Heritrix, 40),
            (SourceDialectV1::Browsertrix, 46),
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
        let manifest = serde_json::from_value(json!({"version":1,"source":"scrapy","sourceVersion":"2.19.0",
            "options":{"start_urls":["https://fixture.test/"],"DOWNLOADER_MIDDLEWARES":{"evil.Plugin":1}}}))
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
        let manifest = serde_json::from_value(json!({"version":1,"source":"colly","sourceVersion":"2.2.0",
            "options":{"URL":"https://fixture.test/","MaxRequests":4,"MaxDepth":2}}))
        .unwrap();
        let (report, crawl) = inspect(&manifest).unwrap();
        assert!(report.convertible);
        let crawl = crawl.unwrap();
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
            serde_json::from_value::<SourceManifestV1>(json!({"version":1,"source":"scrapy",
            "sourceVersion":"2.19.0","options":{},"pythonModule":"evil"}))
            .is_err()
        );
    }
}
