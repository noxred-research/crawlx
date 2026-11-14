//! Offline, release-pinned neutral exports. These proposals never grant execution authority.
//!
//! JSON is the only interchange accepted here. Source runtimes, object graphs, commands,
//! local paths, profile plaintext and dynamically loaded components are never opened.

use anyhow::bail;
use crawlx_core::{
    archive_behaviors::{RecipeReferenceV1, RecipeV1},
    config::{CrawlMode, HostScope, QueryPolicy, RetentionMode, SitemapMode},
    counters::RunStatus,
    extensions::{ExtensionConfigV1, ExtensionPipelineV1, ExtensionSpecV1},
    hash::Digest,
    orchestration::{LoaderCursorV1, OrchestrationConfigV1, RequestBatchV1},
    request::RequestEnvelopeV1,
    session_binding::ProfileLeaseV1,
    CrawlRunId, CreateCrawl, TenantId, Timestamp,
};
use crawlx_extract::item_loader::{translate_struct_tags, StructTagManifestV1};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, io::Write, process::ExitCode};
use url::Url;

const MAX_BYTES: usize = 1_048_576;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 1000;
const MAX_SETTINGS: usize = 128;
const MAX_DEPTH: usize = 20;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Family {
    JsActor,
    PyActor,
    PythonSpider,
    GoCollector,
    SeedlistBatch,
    TopologyStream,
    BeanConfig,
    BrowserYaml,
}
impl Family {
    const fn pin(self) -> &'static str {
        match self {
            Self::JsActor => "3.18.2",
            Self::PyActor => "1.11.0",
            Self::PythonSpider => "2.19.0",
            Self::GoCollector => "2.2.0",
            Self::SeedlistBatch => "1.21",
            Self::TopologyStream => "3.5.1",
            Self::BeanConfig => "3.18.0",
            Self::BrowserYaml => "1.15.2",
        }
    }
    const fn inventory(self) -> &'static str {
        match self {
            Self::SeedlistBatch => include_str!("../data/source-inventories/seedlist-batch.txt"),
            Self::JsActor | Self::PyActor => include_str!("../data/source-inventories/js-py-actor.txt"),
            Self::PythonSpider => include_str!("../data/source-inventories/python-spider.txt"),
            Self::GoCollector => include_str!("../data/source-inventories/go-collector.txt"),
            Self::TopologyStream => include_str!("../data/source-inventories/topology-stream.txt"),
            Self::BeanConfig => include_str!("../data/source-inventories/bean-config.txt"),
            Self::BrowserYaml => include_str!("../data/source-inventories/browser-yaml.txt"),
        }
    }
    fn row(self, setting: &str) -> &'static str {
        match (self, setting) {
            (Self::JsActor, _) => "CJ13",
            (Self::PyActor, _) => "CP01",
            (Self::PythonSpider, _) => "SC48",
            (Self::GoCollector, "fields") => "CO13",
            (Self::GoCollector, _) => "CO02",
            (Self::SeedlistBatch, "seeds" | "queue" | "state") => "NUT-01",
            (Self::SeedlistBatch, "profile" | "credentials") => "NUT-08",
            (Self::SeedlistBatch, "proxy" | "insecureTls") => "NUT-09",
            (Self::SeedlistBatch, "robots") => "NUT-10",
            (Self::SeedlistBatch, "flow" | "recipes") => "NUT-14",
            (Self::SeedlistBatch, "scope" | "rules" | "checker") => "NUT-15",
            (Self::SeedlistBatch, "normalizers") => "NUT-16",
            (Self::SeedlistBatch, "binary" | "segments") => "NUT-32",
            (Self::SeedlistBatch, "lifecycle") => "NUT-36",
            (Self::SeedlistBatch, "jvm") => "NUT-37",
            (Self::SeedlistBatch, "registry" | "components" | "pipeline") => "NUT-38",
            (Self::SeedlistBatch, "testRegistry") => "NUT-39",
            (Self::SeedlistBatch, "file.content.ignored") => "NUT-40",
            (Self::TopologyStream, "seeds" | "topology") => "STC-01",
            (Self::TopologyStream, "queue" | "politeness") => "STC-06",
            (Self::TopologyStream, "recipes" | "flow") => "STC-15",
            (Self::TopologyStream, "robots") => "STC-17",
            (Self::TopologyStream, "proxy") => "STC-20",
            (Self::TopologyStream, "scope" | "rules" | "normalizers") => "STC-25",
            (Self::TopologyStream, _) => "STC-38",
            (Self::BeanConfig, "seeds" | "profileTemplate") => "HER-01",
            (Self::BeanConfig, "lifecycle") => "HER-02",
            (Self::BeanConfig, "patch") => "HER-04",
            (Self::BeanConfig, "rules") => "HER-06",
            (Self::BeanConfig, "scope" | "geo") => "HER-07",
            (Self::BeanConfig, "queue" | "state") => "HER-09",
            (Self::BeanConfig, "overlays" | "politeness") => "HER-12",
            (Self::BeanConfig, "robots") => "HER-13",
            (Self::BeanConfig, "login" | "flow" | "recipes") => "HER-22",
            (Self::BeanConfig, "profile" | "cookies") => "HER-23",
            (Self::BeanConfig, "legacyArchive") => "HER-29",
            (Self::BeanConfig, "history") => "HER-31",
            (Self::BeanConfig, "binary" | "checkpoint") => "HER-33",
            (Self::BeanConfig, _) => "HER-40",
            (Self::BrowserYaml, "seeds" | "precedence") => "BTR-02",
            (Self::BrowserYaml, "scope" | "rules") => "BTR-03",
            (Self::BrowserYaml, "normalizers") => "BTR-04",
            (Self::BrowserYaml, "flow" | "recipes") => "BTR-15",
            (Self::BrowserYaml, "profile") => "BTR-21",
            (Self::BrowserYaml, "storageState" | "cookies") => "BTR-23",
            (Self::BrowserYaml, "proxy") => "BTR-25",
            (Self::BrowserYaml, "index") => "BTR-32",
            (Self::BrowserYaml, "state" | "checkpoint") => "BTR-35",
            (Self::BrowserYaml, "dryRun" | "retention") => "BTR-41",
            (Self::BrowserYaml, "originOverride") => "BTR-42",
            (Self::BrowserYaml, "indexCommand") => "BTR-45",
            (Self::SeedlistBatch, _) => "NUT-35",
            (Self::BrowserYaml, _) => "BTR-02",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    format: String,
    version: u16,
    source: Family,
    source_version: String,
    #[serde(default)]
    admitted_config: Option<CreateCrawl>,
    context: Binding,
    exported_context: Binding,
    seeds: Vec<Seed>,
    #[serde(default)]
    options: BTreeMap<String, Value>,
    #[serde(default)]
    required_inventory: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    tenant: TenantId,
    run: CrawlRunId,
    principal: String,
    producer_epoch: u64,
    #[serde(default)]
    parent_fence: Option<(i64, i64)>,
    #[serde(default)]
    expected_cursor: Option<LoaderCursorV1>,
    #[serde(default)]
    profile_fence: Option<i64>,
    #[serde(default)]
    profile_generation: Option<u64>,
    as_of: Timestamp,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Seed {
    url: Url,
    #[serde(default)]
    depth: u16,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    header_control: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, Value>,
    #[serde(default)]
    options: BTreeMap<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Disposition {
    // Only fixed schema names and numeric positions enter paths, never source map keys.
    path: String,
    inventory: &'static str,
    state: &'static str,
    target: Option<&'static str>,
    reason: &'static str,
    requested: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    version: u16,
    source: Family,
    source_version: &'static str,
    sdk_abi_compatible: bool,
    convertible: bool,
    transactional_import_required: bool,
    live_authorization_required: bool,
    external_evidence: [&'static str; 4],
    dispositions: Vec<Disposition>,
}
impl Report {
    fn add(
        &mut self,
        path: String,
        setting: &str,
        state: &'static str,
        target: Option<&'static str>,
        reason: &'static str,
    ) {
        self.dispositions.push(Disposition {
            path,
            inventory: self.source.row(setting),
            state,
            target,
            reason,
            requested: true,
        });
        if state != "translated" {
            self.convertible = false;
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Converted {
    report: Report,
    // Every source seed has its own real config proposal. These are not independent runs.
    native_proposals: Vec<CreateCrawl>,
    batch: RequestBatchV1,
    recipes: Vec<RecipeV1>,
    profile_references: Vec<ProfileLeaseV1>,
    lifecycle: Option<RunStatus>,
    commands: Vec<CommandProjection>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandProjection {
    kind: &'static str,
    config: Option<CreateCrawl>,
    parser: Option<crawlx_core::extraction::ParserPipelineV1>,
    retained_input_required: bool,
}

/// Inspect or convert one bounded, pinned `neutral-export-v1` JSON manifest offline.
///
/// Inspection emits no source values. Conversion emits only complete native proposals;
/// an authenticated caller must rebind tenant/run/principal, revalidate live fences and
/// authorization, and atomically append requests with their cursor. Nothing is executed.
/// Exit two means requested behavior cannot map exactly; unavailable reference fixtures
/// remain explicit `external_required` dispositions rather than false compatibility.
///
/// # Errors
/// Returns fixed value-free errors for malformed, duplicate-keyed, oversized or wrongly
/// pinned JSON, and I/O errors if the supplied writer fails.
pub async fn run_manifest(bytes: &[u8], convert: bool, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let converted = inspect(bytes)?;
    let success = converted.report.convertible;
    let admission_only = converted
        .report
        .dispositions
        .iter()
        .filter(|row| row.requested)
        .all(|row| {
            row.state == "translated"
                || (row.state == "decision_needed" && row.path.starts_with("admittedConfig"))
        });
    if convert && (success || admission_only) {
        // inspect already counted this exact compact serialization (plus newline) under the cap.
        serde_json::to_writer(&mut *out, &converted)?;
    } else {
        charge(pretty_size(&converted.report)?, 1)?;
        serde_json::to_writer_pretty(&mut *out, &converted.report)?;
    }
    writeln!(out)?;
    Ok(if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Counted serialized size of `value`; never materializes the serialization.
fn counted(value: &impl Serialize) -> anyhow::Result<usize> {
    crawlx_core::extensions::json_size(value)
        .map_err(|_| anyhow::anyhow!("neutral export output cannot be sized"))
}

/// Counted pretty-printed size of `value`; never materializes the serialization.
fn pretty_size(value: &impl Serialize) -> anyhow::Result<usize> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("output length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer_pretty(&mut counter, value)
        .map_err(|_| anyhow::anyhow!("neutral export output cannot be sized"))?;
    Ok(counter.0)
}

/// Checked running total; fails with a fixed value-free error above `MAX_OUTPUT_BYTES`.
fn charge(total: usize, add: usize) -> anyhow::Result<usize> {
    total
        .checked_add(add)
        .filter(|size| *size <= MAX_OUTPUT_BYTES)
        .ok_or_else(|| anyhow::anyhow!("neutral export output exceeds byte cap"))
}

fn inspect(bytes: &[u8]) -> anyhow::Result<Converted> {
    if bytes.len() > MAX_BYTES {
        bail!("neutral export exceeds byte cap");
    }
    let UniqueValue(value) =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid neutral export JSON"))?;
    if !bounded(&value, 0) {
        bail!("neutral export exceeds structural cap");
    }
    let manifest: Manifest =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid neutral export schema"))?;
    if manifest.format != "neutral-export-v1"
        || manifest.version != 1
        || manifest.source_version != manifest.source.pin()
    {
        bail!("unsupported neutral export format or release");
    }
    if manifest.seeds.is_empty()
        || manifest.seeds.len() > MAX_ROWS
        || manifest.options.len() > MAX_SETTINGS
        || manifest.required_inventory.len() > 200
    {
        bail!("neutral export exceeds row or setting cap");
    }
    let mut report = Report {
        version: 1,
        source: manifest.source,
        source_version: manifest.source.pin(),
        sdk_abi_compatible: false,
        convertible: true,
        transactional_import_required: true,
        live_authorization_required: true,
        external_evidence: [
            "pinned source-runtime exporter",
            "independent reference fixtures",
            "licensed geo dataset",
            "binary format specification and reference fixture",
        ],
        dispositions: Vec::new(),
    };
    for row in manifest
        .source
        .inventory()
        .lines()
        .filter(|row| !row.starts_with('#') && !row.is_empty())
    {
        let requested = manifest.required_inventory.iter().any(|required| required == row);
        report.dispositions.push(Disposition {
            path: row.to_owned(),
            inventory: row,
            state: if requested {
                "missing_evidence"
            } else {
                "decision_needed"
            },
            target: None,
            reason: "setting conversion is not whole-inventory or independent-runtime parity",
            requested,
        });
        if requested {
            report.convertible = false;
        }
    }
    for (index, row) in manifest.required_inventory.iter().enumerate() {
        if !manifest.source.inventory().lines().any(|known| known == row) {
            report.add(
                format!("requiredInventory[{index}]"),
                "requiredInventory",
                "rejected",
                None,
                "unknown required inventory identifier",
            );
        }
    }
    let context = &manifest.context;
    if context != &manifest.exported_context
        || !safe_id(&context.principal)
        || context.producer_epoch == 0
        || context
            .parent_fence
            .is_some_and(|(row, fence)| row <= 0 || fence <= 0)
    {
        report.add(
            "context".into(),
            "state",
            "rejected",
            None,
            "tenant, run, principal, producer epoch, fence or restart binding mismatch",
        );
    }
    // Cursor binding excludes the cursor itself: restart does not create a circular digest.
    let source_rows: Vec<_> = manifest
        .seeds
        .iter()
        .map(|seed| {
            (
                &seed.url,
                seed.depth,
                seed.priority,
                &seed.header_control,
                &seed.metadata,
                immutable_options(&seed.options),
            )
        })
        .collect();
    let source_digest = Digest::of_value(
        "crawlx/neutral-export/v1",
        &(
            manifest.source,
            manifest.source_version.as_str(),
            source_rows,
            immutable_options(&manifest.options),
        ),
    )?;
    let total = u64::try_from(manifest.seeds.len())?;
    let start = context
        .expected_cursor
        .as_ref()
        .map_or(0, |cursor| cursor.position);
    if start > total {
        report.add(
            "context.expectedCursor.position".into(),
            "state",
            "rejected",
            None,
            "restart position exceeds immutable input length",
        );
    }
    if context
        .expected_cursor
        .as_ref()
        .is_some_and(|cursor| cursor.source != "neutral-export-v1" || cursor.source_digest != source_digest)
    {
        report.add(
            "context.expectedCursor".into(),
            "state",
            "rejected",
            None,
            "restart cursor requires the same immutable export digest and loader",
        );
    }
    let mut native_proposals = Vec::with_capacity(manifest.seeds.len());
    let mut output_size = 0_usize;
    let mut requests = Vec::with_capacity(manifest.seeds.len());
    let mut recipes = Vec::new();
    let mut profiles = Vec::new();
    let mut lifecycle = None;
    let mut commands = Vec::new();
    for (index, seed) in manifest.seeds.into_iter().enumerate() {
        let (recipes_start, profiles_start, commands_start, dispositions_start) = (
            recipes.len(),
            profiles.len(),
            commands.len(),
            report.dispositions.len(),
        );
        if !safe_url(&seed.url) || seed.depth > 100 || seed.options.len() > MAX_SETTINGS {
            report.add(
                format!("seeds[{index}]"),
                "seeds",
                "rejected",
                None,
                "seed requires bounded credential-free HTTP(S), finite depth and settings",
            );
            continue;
        }
        let mut config = CreateCrawl::new(seed.url.clone());
        config.mode = CrawlMode::Static;
        config.dynamic.enabled = false;
        if matches!(manifest.source, Family::BrowserYaml) {
            browser_queue(&mut config).map_err(anyhow::Error::msg)?;
        }
        config.scope.query_policy = QueryPolicy::KeepAll;
        config.scope.sitemap = SitemapMode::Skip;
        config.scope.known_files.clear();
        config.scope.max_discovery_depth = 0;
        if config.normalize().is_err() {
            bail!("native default configuration unavailable");
        }
        apply_options(
            &manifest.options,
            "options",
            &mut config,
            &mut report,
            &mut recipes,
            &mut profiles,
            &mut lifecycle,
            context,
        )?;
        // The neutral contract explicitly defines global settings first, seed settings last.
        apply_options(
            &seed.options,
            &format!("seeds[{index}].options"),
            &mut config,
            &mut report,
            &mut recipes,
            &mut profiles,
            &mut lifecycle,
            context,
        )?;
        for key in ["overlays", "command"] {
            if let Some(value) = seed.options.get(key).or_else(|| manifest.options.get(key)) {
                let result = if key == "overlays" {
                    overlays(value, &mut config)
                } else {
                    command(value, &mut config, &mut commands)
                };
                match result {
                    Ok(target) => report.add(
                        format!("seeds[{index}].effective.{key}"),
                        key,
                        "translated",
                        Some(target),
                        "effective native projection after explicit source precedence",
                    ),
                    Err(reason) => report.add(
                        format!("seeds[{index}].effective.{key}"),
                        key,
                        "rejected",
                        None,
                        reason,
                    ),
                }
            }
        }
        if seed.depth > config.scope.max_discovery_depth {
            report.add(
                format!("seeds[{index}].depth"),
                "scope",
                "rejected",
                None,
                "queued depth exceeds the effective per-seed discovery ceiling",
            );
        }
        if config.retention.mode == RetentionMode::Zdr && !profiles.is_empty() {
            report.add(
                format!("seeds[{index}].profile"),
                "profile",
                "rejected",
                None,
                "zero-data retention cannot import persistent profile references",
            );
        }
        let before = config.clone();
        if config.normalize().is_err() || config != before {
            report.add(
                format!("seeds[{index}].native"),
                "seeds",
                "rejected",
                None,
                "native validation rejected or would clamp the requested semantics",
            );
        }
        let options = CanonicalizeOptions::from_scope(&config.scope, [0; 32]);
        let canonical = Canonicalizer::canonicalize(seed.url.as_str(), &seed.url, &options)
            .map_err(|_| anyhow::anyhow!("invalid neutral seed identity"))?;
        let mut request =
            RequestEnvelopeV1::get(canonical, seed.depth, context.parent_fence.map(|(id, _)| id));
        request.priority = seed.priority;
        request.header_control = seed.header_control;
        request.metadata = seed.metadata;
        if request.validate().is_err() {
            report.add(
                format!("seeds[{index}].metadata"),
                "seeds",
                "rejected",
                None,
                "native request metadata or priority validation failed",
            );
        }
        report.add(
            format!("seeds[{index}]"),
            "seeds",
            "translated",
            Some("RequestEnvelopeV1; CreateCrawl"),
            "exact seed proposal; per-seed settings override exported global settings",
        );
        // Global settings are re-applied per seed, so recipes, profiles and command config
        // clones amplify with the seed count. Count them before retaining another iteration.
        output_size = charge(
            output_size,
            counted(&(
                &config,
                &recipes[recipes_start..],
                &profiles[profiles_start..],
                &commands[commands_start..],
                &report.dispositions[dispositions_start..],
            ))?,
        )?;
        native_proposals.push(config);
        if u64::try_from(index)? >= start {
            requests.push(request);
        }
    }
    if native_proposals.len() > 1 {
        if native_proposals[0].scope.max_discovery_depth > 0
            && !native_proposals[0].scope.crawl_entire_domain
            && native_proposals
                .iter()
                .any(|config| config.seed_url.path() != native_proposals[0].seed_url.path())
        {
            report.add(
                "seeds.relativeScope".into(),
                "scope",
                "rejected",
                None,
                "different seed-relative discovery prefixes need distinct native per-seed policy support",
            );
        }
        let mut first = native_proposals[0].clone();
        for config in native_proposals.iter().skip(1) {
            first.seed_url = config.seed_url.clone();
            if &first != config {
                report.add(
                    "seeds.policy".into(),
                    "scope",
                    "rejected",
                    None,
                    "native shared-run batches cannot execute different per-seed policies",
                );
                break;
            }
        }
    }
    let mut batch = RequestBatchV1::new(
        context.tenant,
        context.run,
        context.principal.clone(),
        Digest::of_value(
            "crawlx/neutral-batch/v1",
            &(
                context.tenant,
                context.run,
                &context.principal,
                context.producer_epoch,
                context.parent_fence,
                &context.expected_cursor,
                source_digest,
                start,
                total,
            ),
        )?,
        requests,
    );
    batch.producer_epoch = context.producer_epoch;
    batch.parent_fence = context.parent_fence;
    batch.expected_cursor = context.expected_cursor.clone();
    batch.next_cursor = Some(LoaderCursorV1::new(
        "neutral-export-v1".into(),
        source_digest,
        total,
    ));
    if batch.validate().is_err() {
        report.add(
            "batch".into(),
            "state",
            "rejected",
            None,
            "native atomic batch validation failed",
        );
    }
    let append_limit = native_proposals
        .first()
        .and_then(|config| config.orchestration.as_ref())
        .map_or(256, |policy| policy.queue.batch_size);
    if batch.requests.len() > usize::try_from(append_limit)? {
        report.add(
            "batch.size".into(),
            "queue",
            "rejected",
            None,
            "batch exceeds the effective native atomic append size; export a bounded cursor interval",
        );
    }
    let admitted = manifest.admitted_config.as_ref();
    if let Some(admitted) = admitted {
        if !matches!(admitted.mode, CrawlMode::Static | CrawlMode::Hybrid) {
            report.add(
                "admittedConfig.mode".into(),
                "state",
                "rejected",
                None,
                "native request batches cannot execute in browser-only Dynamic mode",
            );
        }
        for proposal in &native_proposals {
            let mut effective = proposal.clone();
            effective.seed_url = admitted.seed_url.clone();
            if &effective != admitted {
                report.add(
                    "admittedConfig.policy".into(),
                    "state",
                    "decision_needed",
                    None,
                    "current admitted run configuration must exactly match every effective native proposal",
                );
                break;
            }
        }
        match crawlx_policy::ScopePolicy::new(admitted) {
            Ok(scope) => {
                for (index, request) in batch.requests.iter().enumerate() {
                    if !scope.decide(&request.url, request.depth).is_admitted() {
                        report.add(
                            format!("batch.requests[{index}].scope"),
                            "scope",
                            "rejected",
                            None,
                            "actual native ScopePolicy rejects request under the admitted shared run",
                        );
                    }
                }
            }
            Err(_) => report.add(
                "admittedConfig.scope".into(),
                "scope",
                "rejected",
                None,
                "actual native ScopePolicy compilation failed",
            ),
        }
    } else {
        report.add("admittedConfig".into(), "state", "decision_needed", None,
            "supply exact admitted native configuration; proposals alone are not an executable shared-run batch");
    }

    let converted = Converted {
        report,
        native_proposals,
        batch,
        recipes,
        profile_references: profiles,
        lifecycle,
        commands,
    };
    // Exact compact size plus the trailing newline must fit the same cap.
    charge(counted(&converted)?, 1)?;
    Ok(converted)
}
fn immutable_options(options: &BTreeMap<String, Value>) -> BTreeMap<&str, &Value> {
    // Authority and restart state are validated separately and never feed their own digest.
    options
        .iter()
        .filter(|(key, _)| key.as_str() != "state")
        .map(|(key, value)| (key.as_str(), value))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn apply_options(
    options: &BTreeMap<String, Value>,
    base: &str,
    config: &mut CreateCrawl,
    report: &mut Report,
    recipes: &mut Vec<RecipeV1>,
    profiles: &mut Vec<ProfileLeaseV1>,
    lifecycle: &mut Option<RunStatus>,
    context: &Binding,
) -> anyhow::Result<()> {
    for (index, (key, value)) in options.iter().enumerate() {
        let path = format!("{base}[{index}]");
        let mapped = match key.as_str() {
            "scope" => scope(value, config),
            "rules" => rules(value, config),
            "queue" => queue(value, config),
            "politeness" => politeness(value, config),
            "robots" => robots(value, config),
            "normalizers" => normalizers(value, report, &path),
            "retention" => retention(value, config),
            "dryRun" => match value.as_bool() {
                Some(false) => Ok("CreateCrawl.output"),
                _ => Err("dry-run source persistence is not zero-data retention or native inspection"),
            },
            "pipeline" | "topology" | "registry" | "components" => {
                pipeline(value, config, report, &path, key)
            }
            "flow" => flow(value, recipes, config, report, &path),
            "recipes" => recipe_references(value, config),
            "profile" => profile(value, profiles, context, config),
            "proxy" => proxy(value, config, report, &path),
            "lifecycle" => lifecycle_projection(value, lifecycle),
            "precedence" => if value.as_str() == Some("global-then-seed") {
                Ok("CreateCrawl")
            } else { Err("only explicit global-then-seed neutral precedence is supported") },
            "state" => if serde_json::from_value::<Binding>(value.clone()).is_ok_and(|state| &state == context) {
                Ok("RequestBatchV1.producerEpoch; expectedCursor; parentFence")
            } else { Err("restart state must match the complete tenant and fence binding") },
            "checker" => checker(value, config),
            "fields" if matches!(report.source, Family::GoCollector) => {
                struct_tag_fields(value, config, report, &path)
            }
            "insecureTls" => tls_exception(value, config),
            "originOverride" => {
                report.add(path, key, "decision_needed", None,
                    "offline input cannot prove current authorization for both authorities or insecure TLS");
                continue;
            }
            "index" if value.get("tenant").is_some_and(|tenant| serde_json::from_value::<TenantId>(tenant.clone()).ok() != Some(context.tenant))
                || value.get("run").is_some_and(|run| serde_json::from_value::<CrawlRunId>(run.clone()).ok() != Some(context.run)) => {
                report.add(path, key, "rejected", None, "foreign tenant or run cannot supply an archive index");
                continue;
            }
            "binary" | "segments" | "checkpoint" | "legacyArchive" | "history" | "geo" | "index" | "exporterFixture" | "referenceFixture" => {
                report.add(path, key, "external_required", None,
                    "pinned format specification, independent fixture, licensed data or retained payload closure is required");
                continue;
            }
            "indexCommand" => Err("index mutations need authenticated tenant-scoped payload closure and committed native catalog"),
            "storageState" | "cookies" | "credentials" => Err("raw secrets, cookie jars and storage state cannot enter migration output"),
            "jvm" => {
                let count = value.as_object().map(Map::len)
                    .or_else(|| value.as_array().map(Vec::len)).unwrap_or(1);
                for option in 0..count {
                    report.add(format!("{path}.tunables[{option}]"), key, "rejected", None,
                        "process flag has no exact native worker resource-control mapping");
                }
                Err("process flags are not native worker resource controls")
            }
            "testRegistry" => Err("test-only and support components are not production capabilities"),
            "file.content.ignored" => Err("upstream placeholder has no implemented source behavior"),
            "profileTemplate" => template(value, config),
            "login" => recipe_references(value, config),
            "patch" => patch(value, config),
            "overlays" | "command" => Ok("effective post-precedence native projection"),
            _ => {
                if let Some(rows) = value.as_array() {
                    for (component, _) in rows.iter().enumerate() {
                        report.add(format!("{path}.unsupported[{component}]"), key, "rejected", None,
                            "unsupported source class, normalizer, script or command");
                    }
                }
                Err("unsupported source option, executable component, normalizer, script or command")
            }
        };
        match mapped {
            Ok(target) => report.add(
                path,
                key,
                "translated",
                Some(target),
                "bounded native declarative mapping; no authority granted",
            ),
            Err(reason) => report.add(path, key, "rejected", None, reason),
        }
    }
    Ok(())
}

/// The exported struct-tag manifest of a collector as an item loader of `config`'s extraction
/// policy. Each field is a row at its position; one that cannot be translated exactly makes the
/// option, and with it the import, unconvertible: nothing is dropped or zero-filled.
fn struct_tag_fields(
    value: &Value,
    config: &mut CreateCrawl,
    report: &mut Report,
    path: &str,
) -> Result<&'static str, &'static str> {
    const TARGET: &str = "CreateCrawl.extract.content.item_loader";
    let tags: StructTagManifestV1 = serde_json::from_value(value.clone())
        .map_err(|_| "the option is not a version 1 struct-tag manifest; nothing is guessed from it")?;
    let translation = translate_struct_tags(&tags);
    for (position, row) in translation.rows.iter().enumerate() {
        if !row.translated {
            report.add(
                format!("{path}.fields[{position}]"),
                "fields",
                "rejected",
                None,
                row.reason,
            );
        }
    }
    let loader = translation
        .loader
        .ok_or("at least one tagged field cannot be translated exactly; no item loader is produced")?;
    config
        .extract
        .content
        .get_or_insert_with(crawlx_core::extraction::ExtractionPolicyV1::default)
        .item_loader = Some(loader);
    Ok(TARGET)
}

fn object<'a>(value: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, &'static str> {
    let object = value.as_object().ok_or("setting must be a bounded object")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unknown setting field; no fields are silently dropped");
    }
    Ok(object)
}
fn number(value: Option<&Value>, min: u64, max: u64) -> Result<u64, &'static str> {
    value
        .and_then(Value::as_u64)
        .filter(|n| (min..=max).contains(n))
        .ok_or("setting requires an explicit finite integer within native bounds")
}

fn scope(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["kind", "depth", "semantics"])?;
    if fields.get("semantics").and_then(Value::as_str) != Some("native-v1") {
        return Err("source www, scheme, redirect and extra-hop differences require explicit native-v1 export semantics");
    }
    let depth = number(fields.get("depth"), 0, 100)?;
    config.scope.max_discovery_depth = u16::try_from(depth).map_err(|_| "depth overflow")?;
    config.scope.allow_subdomains = false;
    config.scope.allow_external_links = false;
    config.scope.crawl_entire_domain = false;
    config.scope.host_scope = HostScope::Fqdn;
    match fields.get("kind").and_then(Value::as_str) {
        Some("page") if depth == 0 => {}
        Some("host") => config.scope.crawl_entire_domain = true,
        Some("domain") => {
            config.scope.host_scope = HostScope::Rdn;
            config.scope.crawl_entire_domain = true;
        }
        Some("prefix") => {}
        _ => return Err("scope kind requires unsupported fragment, extra-hop or unconstrained semantics"),
    }
    Ok("CreateCrawl.scope")
}

fn rules(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 100)
        .ok_or("rules require at most one hundred ordered predicates")?;
    let mut includes = Vec::new();
    let mut excludes = Vec::new();
    let mut saw_accept = false;
    for row in rows {
        let fields = object(row, &["decision", "kind", "value"])?;
        let decision = fields
            .get("decision")
            .and_then(Value::as_str)
            .ok_or("rule decision required")?;
        let text = fields
            .get("value")
            .and_then(Value::as_str)
            .filter(|text| text.len() <= 512)
            .ok_or("bounded rule predicate required")?;
        let pattern = match fields.get("kind").and_then(Value::as_str) {
            Some("url-regex") => text.to_owned(),
            Some("url-prefix") => format!("^{}", escape(text)),
            Some("surt-prefix") => surt_pattern(text)?,
            _ => return Err("unsupported ordered rule class, status predicate, normalizer or geo component"),
        };
        match decision {
            "reject" if !saw_accept => excludes.push(pattern),
            "accept" => { saw_accept = true; includes.push(pattern); }
            _ => return Err("only hard-deny-first union predicates map exactly; last-decision and PASS chains are unsupported"),
        }
    }
    crawlx_url::scope::PathFilter::new(&includes, &excludes)
        .map_err(|_| "rule regex exceeds native compilation bounds")?;
    config.scope.url_include = includes;
    config.scope.url_exclude = excludes;
    Ok("CreateCrawl.scope.urlExclude; urlInclude")
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if ".+*?()|[]{}^$\\".contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}
fn surt_pattern(text: &str) -> Result<String, &'static str> {
    let (labels, path) = text
        .split_once(")")
        .ok_or("SURT requires explicit closed host and path")?;
    let labels = labels.trim_end_matches(',');
    let parts: Vec<&str> = labels.split(',').collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|label| label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        || !path.starts_with('/')
        || path.contains(['?', '#'])
    {
        return Err("SURT wildcard, credentials, port, query or open-host forms are unsupported");
    }
    let host = parts.into_iter().rev().collect::<Vec<_>>().join(".");
    Ok(format!("^https?://{}{}", escape(&host), escape(path)))
}

fn queue(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let policy: OrchestrationConfigV1 = serde_json::from_value(value.clone())
        .map_err(|_| "queue requires exact native orchestration schema")?;
    policy
        .validate()
        .map_err(|_| "invalid finite queue, attempt, scheduling or admission bounds")?;
    config.orchestration = Some(policy);
    Ok("CreateCrawl.orchestration")
}
fn politeness(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["delayMs", "perOriginConcurrency", "robotsFloor"])?;
    if fields.get("robotsFloor").and_then(Value::as_bool) != Some(true) {
        return Err("robots and Retry-After floors cannot be disabled or capped");
    }
    config.politeness.delay_ms =
        u32::try_from(number(fields.get("delayMs"), 50, 60_000)?).map_err(|_| "delay overflow")?;
    config.politeness.max_in_flight_per_origin =
        u8::try_from(number(fields.get("perOriginConcurrency"), 1, 8)?)
            .map_err(|_| "concurrency overflow")?;
    Ok("CreateCrawl.politeness")
}
fn robots(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    if value.as_str() == Some("obey") {
        config.safety.respect_robots_txt = true;
        return Ok("CreateCrawl.safety.respectRobotsTxt");
    }
    let fields = object(value, &["obey", "authorizationRecordRef"])?;
    let obey = fields
        .get("obey")
        .and_then(Value::as_bool)
        .ok_or("explicit robots policy required")?;
    if !obey {
        let record = authorization(fields)?;
        if config
            .safety
            .authorization_record_ref
            .is_some_and(|existing| existing != record)
        {
            return Err("conflicting authorization references cannot replace existing exception authority");
        }
        config.safety.authorization_record_ref = Some(record);
    }
    config.safety.respect_robots_txt = obey;
    Ok("CreateCrawl.safety; current authorization must be revalidated at admission")
}

fn authorization(
    fields: &Map<String, Value>,
) -> Result<crawlx_core::ids::AuthorizationRecordId, &'static str> {
    serde_json::from_value(
        fields.get("authorizationRecordRef").cloned().ok_or(
            "explicit authorization record reference required; offline conversion grants no exception",
        )?,
    )
    .map_err(|_| "invalid native authorization record reference")
}

fn tls_exception(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["enabled", "authorizationRecordRef"])?;
    let enabled = fields
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or("explicit TLS exception setting required")?;
    if enabled {
        let record = authorization(fields)?;
        if config
            .safety
            .authorization_record_ref
            .is_some_and(|existing| existing != record)
        {
            return Err("conflicting authorization references cannot replace existing exception authority");
        }
        config.safety.authorization_record_ref = Some(record);
    }
    config.fetch.skip_tls_verification = enabled;
    Ok("CreateCrawl.fetch.skipTlsVerification; current authorization must be revalidated")
}
fn template(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["scope", "queue", "politeness", "robots", "retention"])?;
    for (key, value) in fields {
        match key.as_str() {
            "scope" => {
                scope(value, config)?;
            }
            "queue" => {
                queue(value, config)?;
            }
            "politeness" => {
                politeness(value, config)?;
            }
            "robots" => {
                robots(value, config)?;
            }
            "retention" => {
                retention(value, config)?;
            }
            _ => return Err("unsupported profile template field"),
        }
    }
    Ok("CreateCrawl; typed pre-admission profile template")
}

fn patch(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["phase", "revision", "settings"])?;
    if fields.get("phase").and_then(Value::as_str) != Some("pre-admission") {
        return Err(
            "live runtime patches require a native revision-audited mutation API, not offline configuration",
        );
    }
    number(fields.get("revision"), 1, u64::from(u32::MAX))?;
    template(
        fields.get("settings").ok_or("typed patch settings required")?,
        config,
    )?;
    Ok("CreateCrawl; immutable pre-admission revisioned patch")
}

fn overlays(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 32)
        .ok_or("bounded overlay array required")?;
    for row in rows {
        let fields = object(
            row,
            &[
                "origin",
                "delayMs",
                "perOriginConcurrency",
                "maxDiscoveryDepth",
                "maxPendingEntries",
                "maxResponseBytes",
            ],
        )?;
        if fields.get("origin").and_then(Value::as_str)
            != Some(config.seed_url.origin().ascii_serialization().as_str())
        {
            return Err("only an exact seed-origin overlay maps; arbitrary runtime sheets and predicates remain unsupported");
        }
        if fields.contains_key("delayMs") {
            config.politeness.delay_ms = u32::try_from(number(
                fields.get("delayMs"),
                u64::from(config.politeness.delay_ms),
                60_000,
            )?)
            .map_err(|_| "delay overflow")?;
        }
        if fields.contains_key("perOriginConcurrency") {
            config.politeness.max_in_flight_per_origin = u8::try_from(number(
                fields.get("perOriginConcurrency"),
                1,
                u64::from(config.politeness.max_in_flight_per_origin),
            )?)
            .map_err(|_| "concurrency overflow")?;
        }
        if fields.contains_key("maxDiscoveryDepth") {
            config.scope.max_discovery_depth = u16::try_from(number(
                fields.get("maxDiscoveryDepth"),
                0,
                u64::from(config.scope.max_discovery_depth),
            )?)
            .map_err(|_| "depth overflow")?;
        }
        if fields.contains_key("maxResponseBytes") {
            config.fetch.max_response_bytes = number(
                fields.get("maxResponseBytes"),
                1024,
                config.fetch.max_response_bytes,
            )?;
        }
        if fields.contains_key("maxPendingEntries") {
            let policy = config
                .orchestration
                .get_or_insert_with(OrchestrationConfigV1::default);
            policy.queue.max_pending_entries = number(
                fields.get("maxPendingEntries"),
                1,
                policy.queue.max_pending_entries,
            )?;
            policy.validate().map_err(|_| "invalid narrowed queue")?;
        }
    }
    Ok("CreateCrawl.scope; politeness; fetch; orchestration; narrowing only")
}

fn command(
    value: &Value,
    config: &mut CreateCrawl,
    commands: &mut Vec<CommandProjection>,
) -> Result<&'static str, &'static str> {
    let fields = object(value, &["kind", "pipeline"])?;
    let mut projection = CommandProjection {
        kind: "settings",
        config: None,
        parser: None,
        retained_input_required: false,
    };
    match fields.get("kind").and_then(Value::as_str) {
        Some("crawl") if !fields.contains_key("pipeline") => {
            projection.kind = "crawl";
            projection.config = Some(config.clone());
        }
        Some("fetch") if !fields.contains_key("pipeline") => {
            if config.scrape.is_some() {
                return Err("native fetch cannot execute browser recipes");
            }
            config.mode = CrawlMode::Static;
            config.acquisition = None;
            config.protocol = crawlx_core::protocol::ProtocolConfigV1::default();
            config.dynamic.enabled = false;
            config.scope.max_discovery_depth = 0;
            config.scope.sitemap = SitemapMode::Skip;
            config.scope.known_files.clear();
            projection.kind = "fetch";
            projection.config = Some(config.clone());
        }
        Some("parse") => {
            let pipeline: crawlx_core::extraction::ParserPipelineV1 = serde_json::from_value(
                fields
                    .get("pipeline")
                    .cloned()
                    .ok_or("explicit parser pipeline required")?,
            )
            .map_err(|_| "invalid native parser pipeline schema")?;
            pipeline
                .validate()
                .map_err(|_| "invalid native parser pipeline stage or resource bounds")?;
            projection.kind = "parse";
            projection.parser = Some(pipeline);
            projection.retained_input_required = true;
        }
        Some("settings") if !fields.contains_key("pipeline") => {
            projection.config = Some(config.clone());
        }
        _ => {
            return Err(
                "shell, runspider, custom command, source module and process execution are prohibited",
            )
        }
    }
    commands.push(projection);
    Ok("CreateCrawl or ParserPipelineV1; closed offline command projection")
}

fn checker(value: &Value, config: &CreateCrawl) -> Result<&'static str, &'static str> {
    let fields = object(value, &["rules", "cases"])?;
    let mut check_config = CreateCrawl::new(config.seed_url.clone());
    rules(
        fields
            .get("rules")
            .ok_or("checker requires explicit ordered URL rules")?,
        &mut check_config,
    )?;
    let filter =
        crawlx_url::scope::PathFilter::new(&check_config.scope.url_include, &check_config.scope.url_exclude)
            .map_err(|_| "checker rule compilation failed")?;
    let cases = fields
        .get("cases")
        .and_then(Value::as_array)
        .filter(|cases| !cases.is_empty() && cases.len() <= 100)
        .ok_or("checker requires a bounded nonempty decision corpus")?;
    for case in cases {
        let case = object(case, &["url", "expected"])?;
        let url = case
            .get("url")
            .and_then(Value::as_str)
            .and_then(|url| Url::parse(url).ok())
            .filter(safe_url)
            .ok_or("checker requires credential-free HTTP(S) URLs")?;
        let accepted = !filter.matches_exclude(url.as_str()) && filter.matches_include(url.as_str());
        if case.get("expected").and_then(Value::as_bool) != Some(accepted) {
            return Err("native ordered URL checker disagrees with expected source decision");
        }
    }
    Ok("crawlx_url::PathFilter; actual offline decision corpus checked")
}

fn normalizers(value: &Value, report: &mut Report, path: &str) -> Result<&'static str, &'static str> {
    let rows = value.as_array().ok_or("normalizers require a bounded array")?;
    let mut unsupported = false;
    for (index, row) in rows.iter().enumerate() {
        let supported = row.as_str() == Some("preserve-resource-query") && rows.len() == 1;
        report.add(
            format!("{path}.normalizers[{index}]"),
            "normalizers",
            if supported { "translated" } else { "rejected" },
            supported.then_some("CreateCrawl.scope.queryPolicy=keep_all"),
            "resource queries stay intact; arbitrary normalization chains cannot rewrite identity",
        );
        unsupported |= !supported;
    }
    if unsupported {
        return Err("unsupported source normalizer chain");
    }
    Ok("CreateCrawl.scope.queryPolicy=keep_all")
}
fn retention(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    match value.as_str() {
        Some("standard") => config.retention.mode = RetentionMode::Standard,
        Some("zdr") => config.retention.mode = RetentionMode::Zdr,
        _ => return Err("unknown retention policy"),
    }
    Ok("CreateCrawl.retention.mode")
}

fn pipeline(
    value: &Value,
    config: &mut CreateCrawl,
    report: &mut Report,
    path: &str,
    key: &str,
) -> Result<&'static str, &'static str> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 32)
        .ok_or("component graph exceeds native stage cap")?;
    let mut pipeline = ExtensionPipelineV1::default();
    let mut failed = false;
    for (index, row) in rows.iter().enumerate() {
        let mapped = object(row, &["kind", "order", "registry"]).and_then(|fields| {
            if fields.get("registry").and_then(Value::as_str) != Some("production") {
                return Err(
                    "component requires explicit production registry; tests and class loaders are refused",
                );
            }
            let kind = match fields.get("kind").and_then(Value::as_str) {
                Some("read-only") => ExtensionConfigV1::ReadOnly {},
                Some("require-quality") => ExtensionConfigV1::RequireQuality {},
                Some("trim-title") => ExtensionConfigV1::TrimTitle {},
                Some("require-title") => ExtensionConfigV1::RequireTitle {},
                _ => {
                    return Err("unsupported component, script, class, stream edge or source registry entry")
                }
            };
            let order = fields
                .get("order")
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok())
                .ok_or("explicit finite component order required")?;
            Ok(ExtensionSpecV1::new(kind, order))
        });
        match mapped {
            Ok(spec) => {
                pipeline.extensions.push(spec);
                report.add(
                    format!("{path}.components[{index}]"),
                    key,
                    "translated",
                    Some("ExtensionSpecV1"),
                    "reviewed production component and native stage",
                );
            }
            Err(reason) => {
                failed = true;
                report.add(
                    format!("{path}.components[{index}]"),
                    key,
                    "rejected",
                    None,
                    reason,
                );
            }
        }
    }
    if failed {
        return Err("one or more source graph components cannot map exactly");
    }
    pipeline
        .validate()
        .map_err(|_| "native component stage or descriptor validation failed")?;
    config.extensions = pipeline;
    Ok("CreateCrawl.extensions")
}

fn flow(
    value: &Value,
    recipes: &mut Vec<RecipeV1>,
    config: &mut CreateCrawl,
    output: &mut Report,
    path: &str,
) -> Result<&'static str, &'static str> {
    let fields = object(value, &["id", "version", "recording"])?;
    let id = fields
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| safe_id(id))
        .ok_or("recipe id required")?;
    let version = u32::try_from(number(fields.get("version"), 1, u64::from(u32::MAX))?)
        .map_err(|_| "recipe revision overflow")?;
    let bytes = serde_json::to_vec(fields.get("recording").ok_or("recording required")?)
        .map_err(|_| "invalid recording")?;
    let (report, candidate) = crate::flow_import::inspect(&bytes, id.to_owned(), version)
        .map_err(|_| "recording schema or bounds invalid")?;
    let mut raw_input = false;
    for step in &report.dispositions {
        let input = fields
            .get("recording")
            .and_then(|recording| recording.get("steps"))
            .and_then(Value::as_array)
            .and_then(|steps| {
                usize::try_from(step.source_index)
                    .ok()
                    .and_then(|index| steps.get(index))
            })
            .and_then(|step| step.get("type"))
            .and_then(Value::as_str)
            == Some("change");
        if input {
            raw_input = true;
            output.add(format!("{path}.steps[{}]", step.source_index), "flow", "rejected", None,
                "literal input values may contain login secrets; use an approved credential-referencing native login plan");
        } else {
            output.add(
                format!("{path}.steps[{}]", step.source_index),
                "flow",
                if step.state == "translated" {
                    "translated"
                } else {
                    "rejected"
                },
                step.target,
                step.reason,
            );
        }
    }
    if !report.convertible || raw_input {
        return Err("recording contains unsupported steps or literal input; no steps are silently dropped");
    }
    let recipe = candidate.ok_or("recording has no complete native recipe")?;
    if recipe
        .entry_url
        .as_ref()
        .is_some_and(|entry| entry != &config.seed_url)
    {
        return Err("recorded initial navigation must match the exact seed URL");
    }
    let reference =
        RecipeReferenceV1::for_recipe(&recipe).map_err(|_| "invalid recorded recipe reference")?;
    select_recipe(reference, config)?;
    recipes.push(recipe);
    Ok("RecipeV1; CreateCrawl.scrape.options.archiveBehavior")
}
fn recipe_references(value: &Value, config: &mut CreateCrawl) -> Result<&'static str, &'static str> {
    let references: Vec<RecipeReferenceV1> =
        serde_json::from_value(value.clone()).map_err(|_| "invalid immutable recipe references")?;
    if references.len() > 1 || references.iter().any(|reference| reference.validate().is_err()) {
        return Err("native scrape jobs accept exactly one immutable recipe reference");
    }
    if let Some(reference) = references.into_iter().next() {
        select_recipe(reference, config)?;
    }
    Ok("CreateCrawl.scrape.options.archiveBehavior")
}

fn select_recipe(reference: RecipeReferenceV1, config: &mut CreateCrawl) -> Result<(), &'static str> {
    if config.retention.mode == RetentionMode::Zdr {
        return Err("native recipe provenance is unavailable under zero-data retention");
    }
    let options = crawlx_core::scrape::ScrapeOptions {
        archive_behavior: Some(reference),
        ..crawlx_core::scrape::ScrapeOptions::default()
    };
    options
        .validate()
        .map_err(|_| "invalid native recipe selection")?;
    config.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
        crawlx_core::scrape::JobKind::Crawl,
        options,
    ));
    browser_queue(config)?;
    Ok(())
}

fn browser_queue(config: &mut CreateCrawl) -> Result<(), &'static str> {
    let mut acquisition = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    acquisition.backend_ids = vec!["native_browser".into()];
    acquisition.fallback_backend_ids.clear();
    acquisition
        .validate()
        .map_err(|_| "invalid browser-only acquisition policy")?;
    let protocol: crawlx_core::protocol::ProtocolConfigV1 = serde_json::from_value(serde_json::json!({
        "schemaVersion":1,"routes":[{
            "id":"neutral_browser","schemes":["http","https"],"origin":null,
            "pathPattern":null,"schedulerMetadata":{},"backend":"browser",
            "delegateId":null,"requiredCapabilities":["checked_egress","bounded_body","cancellation","session_actor"],
            "maxBodyBytes":8_388_608,"maxElapsedMs":60_000,"policyRevision":"neutral-v1"
        }]
    })).map_err(|_| "invalid native browser protocol route")?;
    protocol
        .validate_public()
        .map_err(|_| "native browser protocol route unavailable")?;
    protocol
        .validate_acquisition(&acquisition)
        .map_err(|_| "browser acquisition route mismatch")?;
    config.mode = CrawlMode::Hybrid;
    config.dynamic.enabled = true;
    config.acquisition = Some(acquisition);
    config.protocol = protocol;
    Ok(())
}

/// The `proxy` option: a bounded named registry, an explicit default and an ordered rule list.
///
/// Every rule is judged on its own row (`<option>.rules[i]`): a well-formed, safe rule becomes a
/// native `fetch.proxyRules` entry in source order; a malformed one is `rejected`; one that asks
/// for something the native plane never grants (a direct or alternate fallback, an unverified
/// proxy transport) is `restricted`. Nothing is applied unless every rule converts, so a
/// restricted rule can never leave a partial, weaker routing table behind.
fn proxy(
    value: &Value,
    config: &mut CreateCrawl,
    report: &mut Report,
    path: &str,
) -> Result<&'static str, &'static str> {
    let fields = object(value, &["named", "default", "rules"])?;
    let named = fields
        .get("named")
        .and_then(Value::as_object)
        .filter(|named| named.len() <= 16)
        .ok_or("bounded named proxy registry required")?;
    let default = fields
        .get("default")
        .and_then(Value::as_str)
        .filter(|name| safe_id(name))
        .ok_or("explicit named proxy default required; no direct fallback")?;
    let rules: &[Value] = match fields.get("rules") {
        None => &[],
        Some(rules) => rules
            .as_array()
            .filter(|rules| rules.len() <= crawlx_core::transport_policy::MAX_PROXY_RULES)
            .ok_or("proxy rules are a bounded array")?,
    };
    // Every named entry is checked, including unused entries; none may hide credentials.
    for (name, value) in named {
        let url = value
            .as_str()
            .and_then(|text| Url::parse(text).ok())
            .ok_or("proxy URL required")?;
        if !safe_id(name)
            || !matches!(url.scheme(), "http" | "https" | "socks5")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("proxy registry contains unsafe protocol, credentials or authority");
        }
    }
    let url = named
        .get(default)
        .and_then(Value::as_str)
        .ok_or("named proxy default absent")?;
    let default = Url::parse(url).map_err(|_| "invalid proxy")?;
    let mut converted = Vec::with_capacity(rules.len());
    let mut refused = false;
    for (index, rule) in rules.iter().enumerate() {
        match proxy_rule(rule, index, named) {
            Ok(rule) => converted.push(rule),
            Err((state, reason)) => {
                report.add(format!("{path}.rules[{index}]"), "proxy", state, None, reason);
                refused = true;
            }
        }
    }
    if refused {
        return Err("a proxy rule is restricted or rejected; no routing table is applied");
    }
    // Native validation (names, host patterns, proxy shape) on a plain static probe, so the
    // emitted rules are exactly what a normalized native configuration holds.
    let mut probe = CreateCrawl::new(config.seed_url.clone());
    probe.mode = CrawlMode::Static;
    probe.dynamic.enabled = false;
    probe.fetch.proxy_rules = converted;
    probe
        .normalize()
        .map_err(|_| "proxy rules do not satisfy the native rule bounds")?;
    let translated = !probe.fetch.proxy_rules.is_empty();
    config.fetch.proxy = Some(default);
    config.fetch.proxy_rules = probe.fetch.proxy_rules;
    Ok(if translated {
        "CreateCrawl.fetch.proxyRules and fetch.proxy; URL plane, first matching rule, no direct fallback"
    } else {
        "CreateCrawl.fetch.proxy; no direct fallback"
    })
}

/// One neutral proxy rule: `{"name"?, "hosts": [pattern, ...], "proxy": <named proxy>,
/// "fallback"?: "deny", "insecure"?: false}`. `Err` is the row state and its reason.
fn proxy_rule(
    value: &Value,
    index: usize,
    named: &Map<String, Value>,
) -> Result<crawlx_core::transport_policy::ProxyRule, (&'static str, &'static str)> {
    let rejected = |reason| ("rejected", reason);
    let fields = object(value, &["name", "hosts", "proxy", "fallback", "insecure"]).map_err(rejected)?;
    let hosts: Vec<String> = fields
        .get("hosts")
        .and_then(Value::as_array)
        .and_then(|hosts| {
            hosts
                .iter()
                .map(|host| host.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or(rejected("a rule needs a bounded list of host patterns"))?;
    let target = fields
        .get("proxy")
        .and_then(Value::as_str)
        .and_then(|name| named.get(name))
        .and_then(Value::as_str)
        .and_then(|text| Url::parse(text).ok())
        .ok_or(rejected("a rule names a proxy of the registry"))?;
    let name = match fields.get("name") {
        None => format!("rule-{}", index + 1),
        Some(name) => name
            .as_str()
            .map(str::to_owned)
            .ok_or(rejected("a rule name is text"))?,
    };
    match fields.get("fallback") {
        None => {}
        Some(fallback) if fallback.as_str() == Some("deny") => {}
        Some(_) => {
            return Err((
                "restricted",
                "a fallback to a direct or alternate route is never admitted; a selected rule fails closed",
            ))
        }
    }
    match fields.get("insecure") {
        None | Some(Value::Bool(false)) => {}
        Some(Value::Bool(true)) => {
            return Err((
                "restricted",
                "an unverified proxy transport or skipped host-key check is restricted; it needs its own authorization",
            ))
        }
        Some(_) => return Err(rejected("insecure is a boolean")),
    }
    Ok(crawlx_core::transport_policy::ProxyRule::new(name, hosts, target))
}

fn profile(
    value: &Value,
    profiles: &mut Vec<ProfileLeaseV1>,
    context: &Binding,
    config: &CreateCrawl,
) -> Result<&'static str, &'static str> {
    let fields = object(
        value,
        &[
            "identity",
            "generation",
            "allowed_origins",
            "lease_fence",
            "expires_at",
        ],
    )?;
    let identity = fields.get("identity").ok_or("profile identity required")?;
    object(
        identity,
        &[
            "tenant",
            "run",
            "principal",
            "session",
            "acquisition",
            "backend_build",
            "egress",
            "identity_policy",
            "profile",
        ],
    )?;
    let lease: ProfileLeaseV1 =
        serde_json::from_value(value.clone()).map_err(|_| "invalid native profile reference")?;
    let origin = config.seed_url.origin().ascii_serialization();
    if lease.identity.tenant != context.tenant
        || lease.identity.run != context.run
        || lease.identity.principal.0 != context.principal
        || lease.generation == 0
        || lease.identity.profile.is_none()
        || lease.lease_fence <= 0
        || context.profile_fence != Some(lease.lease_fence)
        || context.profile_generation != Some(lease.generation)
        || lease.expires_at <= context.as_of
        || !lease.allowed_origins.contains(&origin)
        || lease.allowed_origins.len() > 64
        || config.retention.mode == RetentionMode::Zdr
        || lease.allowed_origins.iter().any(|origin| {
            Url::parse(origin).map_or(true, |url| {
                !safe_url(&url) || url.origin().ascii_serialization() != *origin
            })
        })
    {
        return Err("profile reference requires matching tenant, principal, run, origin, generation, live fence and unchanged expiry");
    }
    profiles.push(lease);
    Ok("ProfileLeaseV1; live encrypted profile authority revalidation required")
}
fn lifecycle_projection(
    value: &Value,
    lifecycle: &mut Option<RunStatus>,
) -> Result<&'static str, &'static str> {
    let fields = object(value, &["operation"])?;
    let status = match fields.get("operation").and_then(Value::as_str) {
        Some("create" | "build") => RunStatus::Queued,
        Some("launch" | "resume") => RunStatus::Running,
        Some("pause") => RunStatus::Paused,
        Some("cancel" | "terminate") => RunStatus::Cancelled,
        Some("status") => return Ok("RunStatus; authenticated read projection"),
        _ => {
            return Err(
                "filesystem, rescan, deletion, scripts and arbitrary runtime mutation are unsupported",
            )
        }
    };
    if lifecycle.is_some_and(|existing| existing != status) {
        return Err("conflicting lifecycle transitions cannot be collapsed into one native status");
    }
    *lifecycle = Some(status);
    Ok("RunStatus; authenticated lifecycle transition required")
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn safe_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.as_str().len() <= 8192
        && url.fragment().is_none()
        && !url.query_pairs().any(|(key, _)| {
            let key = key.to_ascii_lowercase();
            [
                "password",
                "passwd",
                "secret",
                "token",
                "cookie",
                "session",
                "authorization",
                "credential",
                "api_key",
                "apikey",
            ]
            .iter()
            .any(|part| key.contains(part))
        })
}
fn bounded(value: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match value {
        Value::Object(fields) => {
            fields.len() <= MAX_ROWS
                && fields
                    .iter()
                    .all(|(key, value)| key.len() <= 128 && bounded(value, depth + 1))
        }
        Value::Array(rows) => rows.len() <= MAX_ROWS && rows.iter().all(|value| bounded(value, depth + 1)),
        Value::String(text) => text.len() <= 16_384,
        _ => true,
    }
}

// Reject duplicates recursively before interpreting any source precedence or native DTO.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("unique-keyed declarative JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| UniqueValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = access.next_element()? {
                    if values.len() >= MAX_ROWS {
                        return Err(serde::de::Error::custom("array cap"));
                    }
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if values.contains_key(&key) || values.len() >= MAX_ROWS {
                        return Err(serde::de::Error::custom("duplicate key or map cap"));
                    }
                    let UniqueValue(value) = access.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn fixture(source: &str, version: &str) -> Value {
        let context = json!({
            "tenant": "00000000-0000-0000-0000-000000000001",
            "run": "00000000-0000-0000-0000-000000000002",
            "principal": "anonymous", "producerEpoch": 1,
            "asOf": "2026-01-01T00:00:00Z"
        });
        json!({"format":"neutral-export-v1", "version":1, "source":source,
            "sourceVersion":version, "context":context, "exportedContext":context,
            "seeds":[{"url":"https://example.test/a?id=1"},{"url":"https://example.test/a/b?id=2"}]})
    }
    fn inspect_value(value: &Value) -> Converted {
        let mut value = value.clone();
        let proposed = inspect(&serde_json::to_vec(&value).unwrap()).unwrap();
        if value.get("admittedConfig").is_none() {
            if let Some(config) = proposed.native_proposals.first() {
                value["admittedConfig"] = serde_json::to_value(config).unwrap();
            }
        }
        inspect(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    #[test]
    fn all_pins_preserve_batch_identity_queries_and_inventory() {
        for (family, pin, count) in [
            ("seedlist-batch", "1.21", 40),
            ("topology-stream", "3.5.1", 38),
            ("bean-config", "3.18.0", 40),
            ("browser-yaml", "1.15.2", 46),
        ] {
            let converted = inspect_value(&fixture(family, pin));
            assert!(converted.report.convertible);
            assert_eq!(converted.batch.requests.len(), 2);
            assert_eq!(converted.native_proposals.len(), 2);
            assert_eq!(
                converted
                    .report
                    .dispositions
                    .iter()
                    .filter(|row| !row.requested)
                    .count(),
                count
            );
            assert_ne!(
                converted.batch.requests[0].url.key,
                converted.batch.requests[1].url.key
            );
            assert_eq!(converted.batch.requests[0].url.url.query(), Some("id=1"));
            assert_eq!(converted.batch.next_cursor.unwrap().position, 2);
        }
    }
    #[test]
    fn foreign_tenant_epoch_fence_and_cursor_are_refused() {
        for field in ["tenant", "producerEpoch", "parentFence", "expectedCursor"] {
            let mut value = fixture("seedlist-batch", "1.21");
            value["exportedContext"][field] = match field {
                "tenant" => json!("00000000-0000-0000-0000-000000000099"),
                "producerEpoch" => json!(2),
                "parentFence" => json!([1, 2]),
                _ => json!({"source":"neutral-export-v1","sourceDigest":"00".repeat(32),"position":1}),
            };
            assert!(!inspect_value(&value).report.convertible);
        }
    }
    #[test]
    fn unsupported_classes_are_all_reported_without_values() {
        let mut value = fixture("topology-stream", "3.5.1");
        value["options"] = json!({"topology":[
            {"kind":"CANARY_ONE","registry":"production","order":1},
            {"class":"CANARY_TWO"}, {"script":"CANARY_THREE"}]});
        let converted = inspect_value(&value);
        assert!(!converted.report.convertible);
        assert_eq!(
            converted
                .report
                .dispositions
                .iter()
                .filter(|row| row.path.contains("components["))
                .count(),
            6
        );
        assert!(!serde_json::to_string(&converted.report)
            .unwrap()
            .contains("CANARY"));
    }
    #[tokio::test]
    async fn blocked_conversion_never_prints_secrets_or_partial_native_config() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["options"] =
            json!({"storageState":{"cookie":"SECRET_CANARY"},"secret-key-CANARY":"SECRET_CANARY"});
        let mut output = Vec::new();
        let code = run_manifest(&serde_json::to_vec(&value).unwrap(), true, &mut output)
            .await
            .unwrap();
        assert_eq!(code, ExitCode::from(2));
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("CANARY"));
        assert!(!text.contains("nativeProposals"));
        assert!(!text.contains("example.test"));
    }
    #[test]
    fn binary_geo_and_reference_evidence_stays_external() {
        let mut value = fixture("bean-config", "3.18.0");
        value["options"] = json!({"binary":"opaque", "geo":"licensed", "referenceFixture":"absent"});
        let converted = inspect_value(&value);
        assert!(!converted.report.convertible);
        assert_eq!(
            converted
                .report
                .dispositions
                .iter()
                .filter(|row| row.state == "external_required")
                .count(),
            6
        );
    }
    #[test]
    fn per_seed_precedence_maps_exact_depth_and_refuses_mixed_policies() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["options"] = json!({"scope":{"kind":"host","depth":2,"semantics":"native-v1"}});
        value["seeds"][0]["options"] = json!({"scope":{"kind":"page","depth":0,"semantics":"native-v1"}});
        let converted = inspect_value(&value);
        assert_eq!(converted.native_proposals[0].scope.max_discovery_depth, 0);
        assert_eq!(converted.native_proposals[1].scope.max_discovery_depth, 2);
        assert!(!converted.report.convertible);
    }
    #[test]
    fn duplicate_nested_unknown_and_oversized_inputs_fail_without_content() {
        assert!(inspect(br#"{"options":{"x":1,"x":2}}"#).is_err());
        let mut value = fixture("bean-config", "3.18.0");
        value["unexpected"] = json!("CANARY");
        assert!(!inspect(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap()
            .to_string()
            .contains("CANARY"));
        assert!(inspect(&vec![b' '; MAX_BYTES + 1]).is_err());
        let mut value = fixture("seedlist-batch", "1.21");
        value["sourceVersion"] = json!("latest");
        assert!(inspect(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    fn amplifying_fixture() -> Value {
        let mut value = fixture("bean-config", "3.18.0");
        value["seeds"] = Value::Array(
            (0..MAX_ROWS)
                .map(|index| json!({"url": format!("https://example.test/a?id={index}")}))
                .collect(),
        );
        let rules: Vec<Value> = (0..100)
            .map(|index| {
                let mut text = format!("https://example.test/{index:03}/");
                text.push_str(&"a".repeat(512 - text.len()));
                json!({"decision":"reject","kind":"url-prefix","value":text})
            })
            .collect();
        value["options"] = json!({"rules":rules, "command":{"kind":"settings"}});
        value
    }

    #[test]
    fn repeated_global_config_and_command_clones_fail_at_the_output_cap() {
        let bytes = serde_json::to_vec(&amplifying_fixture()).unwrap();
        assert!(bytes.len() <= MAX_BYTES);
        let error = inspect(&bytes).err().unwrap().to_string();
        assert_eq!(error, "neutral export output exceeds byte cap");
    }

    #[tokio::test]
    async fn output_cap_failure_writes_no_partial_output() {
        let bytes = serde_json::to_vec(&amplifying_fixture()).unwrap();
        for convert in [true, false] {
            let mut output = Vec::new();
            assert!(run_manifest(&bytes, convert, &mut output).await.is_err());
            assert!(output.is_empty());
        }
    }

    #[tokio::test]
    async fn ordinary_batches_retain_every_seed_within_the_output_cap() {
        let mut value = amplifying_fixture();
        value["options"] = json!({});
        let converted = inspect(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(converted.native_proposals.len(), MAX_ROWS);
        assert_eq!(converted.batch.requests.len(), MAX_ROWS);

        value["seeds"].as_array_mut().unwrap().truncate(200);
        let mut output = Vec::new();
        let _exit = run_manifest(&serde_json::to_vec(&value).unwrap(), true, &mut output)
            .await
            .unwrap();
        assert!(output.len() <= MAX_OUTPUT_BYTES);
        assert_eq!(output.last(), Some(&b'\n'));
        let emitted: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(emitted["nativeProposals"].as_array().unwrap().len(), 200);
        assert_eq!(emitted["batch"]["requests"].as_array().unwrap().len(), 200);
    }
    #[test]
    fn rules_require_hard_denies_before_accepts_and_preserve_queries() {
        let mut value = fixture("bean-config", "3.18.0");
        value["options"] = json!({"rules":[
            {"decision":"reject","kind":"url-prefix","value":"https://example.test/admin"},
            {"decision":"accept","kind":"surt-prefix","value":"test,example,)/"}]});
        let converted = inspect_value(&value);
        assert!(converted.report.convertible);
        assert_eq!(
            converted.native_proposals[0].scope.url_exclude[0],
            "^https://example\\.test/admin"
        );
        value["options"]["rules"].as_array_mut().unwrap().reverse();
        assert!(!inspect_value(&value).report.convertible);
    }

    #[test]
    fn restart_cursor_resumes_remaining_rows_without_changing_batch_source() {
        let mut value = fixture("seedlist-batch", "1.21");
        let initial = inspect_value(&value);
        let mut cursor = initial.batch.next_cursor.unwrap();
        cursor.position = 1;
        value["context"]["expectedCursor"] = serde_json::to_value(&cursor).unwrap();
        value["exportedContext"] = value["context"].clone();
        let resumed = inspect_value(&value);
        assert!(resumed.report.convertible);
        assert_eq!(resumed.batch.requests.len(), 1);
        assert_eq!(resumed.batch.requests[0].url.url.path(), "/a/b");
        assert_eq!(
            resumed.batch.next_cursor.unwrap().source_digest,
            cursor.source_digest
        );
    }

    #[test]
    fn common_request_pins_share_native_envelopes() {
        for (family, pin) in [
            ("js-actor", "3.18.2"),
            ("py-actor", "1.11.0"),
            ("python-spider", "2.19.0"),
            ("go-collector", "2.2.0"),
        ] {
            let converted = inspect_value(&fixture(family, pin));
            assert!(converted.report.convertible);
            assert_eq!(converted.batch.requests.len(), 2);
        }
    }

    #[test]
    fn finite_queue_pacing_and_reviewed_components_become_native_config() {
        let mut value = fixture("topology-stream", "3.5.1");
        value["options"] = json!({
            "queue": serde_json::to_value(OrchestrationConfigV1::default()).unwrap(),
            "politeness": {"delayMs":500,"perOriginConcurrency":2,"robotsFloor":true},
            "topology":[{"kind":"read-only","order":1,"registry":"production"}],
            "robots":"obey"
        });
        let converted = inspect_value(&value);
        assert!(converted.report.convertible);
        assert_eq!(converted.native_proposals[0].politeness.delay_ms, 500);
        assert_eq!(converted.native_proposals[0].extensions.extensions.len(), 1);
        assert!(converted.native_proposals[0].orchestration.is_some());
        value["options"]["politeness"]["robotsFloor"] = json!(false);
        assert!(!inspect_value(&value).report.convertible);
    }

    #[test]
    fn secret_url_queries_and_deep_documents_fail_closed() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["seeds"][0]["url"] = json!("https://example.test/?token=CANARY");
        let converted = inspect_value(&value);
        assert!(!converted.report.convertible);
        assert!(!serde_json::to_string(&converted.report)
            .unwrap()
            .contains("CANARY"));
        let mut deep = json!(true);
        for _ in 0..25 {
            deep = json!([deep]);
        }
        value["options"] = deep;
        assert!(inspect(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn profile_binding_requires_tenant_principal_generation_fence_and_expiry() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["options"] = json!({"profile":{
            "identity":{"tenant":value["context"]["tenant"],"run":value["context"]["run"],
                "principal":"foreign","session":"00000000-0000-0000-0000-000000000003",
                "acquisition":"00".repeat(32),"backend_build":"00".repeat(32),
                "egress":"00".repeat(32),"identity_policy":"00".repeat(32),
                "profile":"00".repeat(32)},
            "generation":1,"lease_fence":1,"expires_at":"2025-01-01T00:00:00Z",
            "allowed_origins":["https://example.test"]
        }});
        assert!(!inspect_value(&value).report.convertible);
    }

    #[test]
    fn cursor_intervals_have_distinct_receipts_and_retries_are_stable() {
        let mut value = fixture("seedlist-batch", "1.21");
        let first = inspect_value(&value);
        assert_eq!(first.batch.batch_id, inspect_value(&value).batch.batch_id);
        let mut cursor = first.batch.next_cursor.clone().unwrap();
        cursor.position = 1;
        value["context"]["expectedCursor"] = serde_json::to_value(&cursor).unwrap();
        value["exportedContext"] = value["context"].clone();
        let next = inspect_value(&value);
        assert_ne!(first.batch.batch_id, next.batch.batch_id);
        assert_eq!(next.batch.batch_id, inspect_value(&value).batch.batch_id);
    }

    #[test]
    fn missing_or_different_admitted_config_is_not_executable() {
        let mut value = fixture("seedlist-batch", "1.21");
        let initial = inspect(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!initial.report.convertible);
        assert!(initial
            .report
            .dispositions
            .iter()
            .any(|row| row.state == "decision_needed" && row.path == "admittedConfig"));
        let mut admitted = initial.native_proposals[0].clone();
        admitted.scope.max_discovery_depth = 3;
        value["admittedConfig"] = serde_json::to_value(admitted).unwrap();
        assert!(
            !inspect(&serde_json::to_vec(&value).unwrap())
                .unwrap()
                .report
                .convertible
        );
    }

    #[test]
    fn browser_batch_has_explicit_browser_only_policy_and_native_scope_acceptance() {
        let converted = inspect_value(&fixture("browser-yaml", "1.15.2"));
        let config = &converted.native_proposals[0];
        assert_eq!(config.mode, CrawlMode::Hybrid);
        assert_eq!(
            config.acquisition.as_ref().unwrap().backend_ids,
            ["native_browser"]
        );
        assert!(config
            .acquisition
            .as_ref()
            .unwrap()
            .fallback_backend_ids
            .is_empty());
        assert_eq!(
            config.protocol.routes[0].backend,
            crawlx_core::protocol::ProtocolBackendV1::Browser
        );
        let scope = crawlx_policy::ScopePolicy::new(config).unwrap();
        assert!(converted
            .batch
            .requests
            .iter()
            .all(|request| scope.decide(&request.url, request.depth).is_admitted()));
    }

    #[test]
    fn exceptions_require_explicit_authorization_references() {
        let mut value = fixture("seedlist-batch", "1.21");
        value["options"] = json!({"insecureTls":true});
        assert!(!inspect_value(&value).report.convertible);
        value["options"] = json!({"insecureTls":{"enabled":true,
            "authorizationRecordRef":"00000000-0000-0000-0000-000000000004"}});
        let converted = inspect_value(&value);
        assert!(converted.report.convertible);
        assert!(converted.native_proposals[0].fetch.skip_tls_verification);
        assert!(converted.native_proposals[0]
            .safety
            .authorization_record_ref
            .is_some());
    }

    fn proxy_options(rules: Value) -> Value {
        json!({"proxy":{
            "named":{"eu":"http://eu.proxy.test:3128","us":"socks5://us.proxy.test:1080"},
            "default":"eu","rules":rules}})
    }

    fn states(converted: &Converted, needle: &str) -> Vec<(&'static str, &'static str)> {
        converted
            .report
            .dispositions
            .iter()
            .filter(|row| row.path.contains(needle))
            .map(|row| (row.state, row.inventory))
            .collect()
    }

    #[test]
    fn ordered_proxy_rules_convert_in_source_order_and_select_stably() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["options"] = proxy_options(json!([
            {"name":"shop","hosts":["Shop.example.test","*.cdn.example.test"],"proxy":"us"},
            {"hosts":["*.example.test"],"proxy":"eu","fallback":"deny"}
        ]));
        let converted = inspect_value(&value);
        assert!(
            converted.report.convertible,
            "{:?}",
            states(&converted, "options")
        );
        let config = &converted.native_proposals[0];
        let rules = &config.fetch.proxy_rules;
        assert_eq!(
            rules.iter().map(|rule| rule.name.as_str()).collect::<Vec<_>>(),
            ["shop", "rule-2"]
        );
        assert_eq!(rules[0].hosts, ["shop.example.test", "*.cdn.example.test"]);
        assert_eq!(rules[0].proxy.as_str(), "socks5://us.proxy.test:1080");
        assert_eq!(
            config.fetch.proxy.as_ref().map(Url::as_str),
            Some("http://eu.proxy.test:3128/")
        );
        // The first matching rule wins however often it is asked; unmatched hosts take the default.
        let pick = |host| {
            crawlx_core::transport_policy::select_proxy_rule(rules, host).map(|rule| rule.name.as_str())
        };
        for _ in 0..4 {
            assert_eq!(pick("shop.example.test"), Some("shop"));
            assert_eq!(pick("a.cdn.example.test"), Some("shop"));
            assert_eq!(pick("www.example.test"), Some("rule-2"));
            assert_eq!(pick("elsewhere.test"), None);
        }
        let mut native = config.clone();
        native.normalize().unwrap();
        assert_eq!(native.fetch.proxy_rules, *rules);
        // The same manifest converts to the same table.
        assert_eq!(
            inspect_value(&value).native_proposals[0].fetch.proxy_rules,
            *rules
        );
    }

    #[test]
    fn unsafe_proxy_rules_are_restricted_and_leave_no_partial_table() {
        let unsafe_rules = [
            json!({"name":"loose","hosts":["a.test"],"proxy":"us","fallback":"direct"}),
            json!({"name":"skip","hosts":["a.test"],"proxy":"us","insecure":true}),
        ];
        for unsafe_rule in unsafe_rules {
            let mut value = fixture("browser-yaml", "1.15.2");
            value["options"] = proxy_options(json!([
                {"name":"fine","hosts":["b.test"],"proxy":"eu"},
                unsafe_rule
            ]));
            let converted = inspect(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(!converted.report.convertible);
            let rows = states(&converted, "rules[");
            // One restricted row per seed proposal, all at the offending rule, none for `fine`.
            assert_eq!(rows.len(), converted.native_proposals.len(), "{rows:?}");
            assert!(
                rows.iter().all(|row| *row == ("restricted", "BTR-25")),
                "{rows:?}"
            );
            for proposal in &converted.native_proposals {
                assert!(proposal.fetch.proxy_rules.is_empty());
                assert!(proposal.fetch.proxy.is_none());
            }
        }
    }

    #[test]
    fn malformed_proxy_rules_are_rejected_not_restricted() {
        for rule in [
            json!({"hosts":["a.test"],"proxy":"missing"}),
            json!({"hosts":[],"proxy":"eu"}),
            json!({"hosts":["a.test"],"proxy":"eu","unknown":1}),
            json!({"hosts":["not a host"],"proxy":"eu"}),
        ] {
            let mut value = fixture("browser-yaml", "1.15.2");
            value["options"] = proxy_options(json!([rule]));
            let converted = inspect(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(!converted.report.convertible);
            assert!(
                states(&converted, "options")
                    .iter()
                    .all(|(state, _)| *state == "rejected"),
                "{:?}",
                states(&converted, "options")
            );
            assert!(converted
                .native_proposals
                .iter()
                .all(|p| p.fetch.proxy_rules.is_empty()));
        }
    }

    #[test]
    fn commands_templates_and_narrowing_overlays_emit_real_native_dtos() {
        let mut value = fixture("python-spider", "2.19.0");
        value["options"] = json!({
            "profileTemplate":{"scope":{"kind":"host","depth":3,"semantics":"native-v1"}},
            "overlays":[{"origin":"https://example.test","delayMs":500,"maxDiscoveryDepth":2}],
            "command":{"kind":"settings"}
        });
        let converted = inspect_value(&value);
        assert!(converted.report.convertible);
        assert_eq!(converted.native_proposals[0].scope.max_discovery_depth, 2);
        assert_eq!(
            converted.commands[0].config.as_ref().unwrap().politeness.delay_ms,
            500
        );
        value["options"]["command"] = json!({"kind":"parse",
            "pipeline":serde_json::to_value(crawlx_core::extraction::ParserPipelineV1::default()).unwrap()});
        let converted = inspect_value(&value);
        assert!(converted.report.convertible);
        assert!(converted.commands[0].parser.is_some());
        assert!(converted.commands[0].retained_input_required);
        value["options"]["command"] = json!({"kind":"shell"});
        assert!(!inspect_value(&value).report.convertible);
    }

    #[tokio::test]
    async fn memory_store_commits_replays_and_fences_native_cursor_intervals() {
        use crawlx_core::repo::{FrontierRepo, RunRepo};
        use crawlx_core::time::ManualClock;
        use std::sync::Arc;
        let mut value = fixture("seedlist-batch", "1.21");
        let mut policy = OrchestrationConfigV1::default();
        policy.queue.producer_mode = crawlx_core::orchestration::ProducerModeV1::Continuous;
        value["options"] = json!({"queue":serde_json::to_value(policy).unwrap()});
        let initial = inspect_value(&value);
        assert!(initial.report.convertible);
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let store = crawlx_storage::MemoryStore::with_clock(Arc::new(ManualClock::new(now)));
        let mut run =
            crawlx_storage::testkit::crawl_run(initial.batch.tenant, initial.native_proposals[0].clone());
        run.id = initial.batch.run;
        run.created_at = now;
        store.create(&run, None).await.unwrap();
        let first = store.append_batch(initial.batch.clone()).await.unwrap();
        assert_eq!(first.inserted.len(), 2);
        assert_eq!(store.append_batch(initial.batch.clone()).await.unwrap(), first);
        let cursor = initial.batch.next_cursor.clone().unwrap();
        assert_eq!(
            store.loader_cursor(run.id, "neutral-export-v1").await.unwrap(),
            Some(cursor.clone())
        );
        value["context"]["expectedCursor"] = serde_json::to_value(&cursor).unwrap();
        value["exportedContext"] = value["context"].clone();
        let next = inspect_value(&value);
        assert!(next.report.convertible);
        assert_ne!(next.batch.batch_id, initial.batch.batch_id);
        assert!(next.batch.requests.is_empty());
        let receipt = store.append_batch(next.batch.clone()).await.unwrap();
        assert!(receipt.inserted.is_empty());
        assert_eq!(store.append_batch(next.batch.clone()).await.unwrap(), receipt);
        let mut stale = next.batch.clone();
        stale.producer_epoch = 2;
        assert!(store.append_batch(stale).await.is_err());
        let mut foreign = next.batch;
        foreign.tenant = TenantId(uuid::Uuid::from_u128(99));
        assert!(store.append_batch(foreign).await.is_err());
    }

    #[test]
    fn recorded_literal_input_is_refused_without_secret_output() {
        let mut value = fixture("browser-yaml", "1.15.2");
        value["seeds"].as_array_mut().unwrap().truncate(1);
        value["options"] = json!({"flow":{"id":"owned-flow","version":1,"recording":{"steps":[
            {"type":"navigate","url":"https://example.test/a?id=1"},
            {"type":"change","selectors":[["input"]],"value":"SECRET_CANARY"}
        ]}}});
        let converted = inspect_value(&value);
        assert!(!converted.report.convertible);
        assert!(!serde_json::to_string(&converted.report)
            .unwrap()
            .contains("CANARY"));
        assert!(converted.recipes.is_empty());
    }
}
