//! Offline archive codecs and isolated replay/QA dispatch. Codec operations never refetch live content.

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand, ValueEnum};
use crawlx_core::archive::{
    ArchiveCapture, ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveFormat, ArchiveManifestV1,
    ArchiveOmissionV1, ArchiveRepresentation,
};
use crawlx_core::config::{Retention, RetentionMode};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{PageRecord, PageRepo, RunRepo};
use crawlx_core::{CrawlRunId, TenantId, Timestamp};
use crawlx_storage::archive::collection::{ApprovedLocalDependency, ArchiveCollection};
use crawlx_storage::archive::resolver::RecordLocation;
use crawlx_storage::archive::{cdxj, retained, wacz, warc, ArchiveError, Limits};
use crawlx_telemetry::redact::Redactor;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Native offline archive commands.
#[derive(Args, Debug)]
pub struct ArchiveArgs {
    /// Archive operation. Replay/QA use a separate isolated, no-live-fallback runtime.
    #[command(subcommand)]
    pub command: ArchiveCommand,
}

/// Archive format operations and isolated replay/QA.
#[derive(Subcommand, Debug)]
pub enum ArchiveCommand {
    /// Export retention-approved resources of a real recorded run.
    Export(ArchiveExportArgs),
    /// Validate an archive and install an immutable privacy-approved local copy.
    Import(ArchiveImportArgs),
    /// Validate actual formats, fixities, dependencies and member ranges.
    Inspect(ArchiveInspectArgs),
    /// Replay validated archive content on an isolated owned loopback origin.
    Replay(crate::archive_replay::ReplayArgs),
    /// Compare an isolated archive replay against supplied evidence.
    Qa(crate::archive_replay::QaArgs),
}

/// Export container selection.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FormatArg {
    /// WACZ ZIP64 file.
    Wacz,
    /// Directory containing archive/data.warc.gz, indexes/index.cdxj and a manifest.
    Warc,
}

/// Arguments for an offline recorded-run export.
#[derive(Args, Debug)]
pub struct ArchiveExportArgs {
    /// Real PostgreSQL run UUID or local report.json/directory from crawl --output.
    pub source: String,
    /// Required owning tenant UUID; checked against the run and every artifact index row.
    #[arg(long)]
    pub tenant: TenantId,
    /// Output WACZ file or new WARC bundle directory. Must not exist.
    #[arg(long)]
    pub out: PathBuf,
    /// Output container.
    #[arg(long, value_enum, default_value = "wacz")]
    pub format: FormatArg,
    /// Refuse incomplete source capture before staging. Current page-only exports cannot satisfy this.
    #[arg(long)]
    pub require_complete: bool,
    /// Filesystem artifact root; defaults next to report.json or ./crawlx-artifacts for PostgreSQL.
    #[arg(long)]
    pub artifacts_dir: Option<PathBuf>,
    /// PostgreSQL metadata connection only; no live content requests occur.
    #[arg(long, env = "CRAWLX_DATABASE_URL")]
    pub database_url: Option<String>,
    /// Maximum encoded output bytes, at most 1 GiB.
    #[arg(long, default_value_t = 1_073_741_824)]
    pub max_bytes: u64,
}

/// Validated import is opt-in content retention, never a ZDR exception.
#[derive(Args, Debug)]
pub struct ArchiveImportArgs {
    /// WACZ, plain WARC, or record-at-a-time gzip WARC.
    pub input: PathBuf,
    /// New immutable output: byte-identical copy alone, self-contained WACZ with explicit dependencies.
    #[arg(long)]
    pub out: PathBuf,
    /// Refuse durable import before any staging or destination write.
    #[arg(long)]
    pub zero_data_retention: bool,
    /// Explicit local dependency authority; nonempty dependencies produce a self-contained WACZ.
    #[command(flatten)]
    pub dependencies: ArchiveDependencyArgs,
}

/// Validation and optional bounded payload retrieval.
#[derive(Args, Debug)]
pub struct ArchiveInspectArgs {
    /// WACZ, plain WARC, or record-at-a-time gzip WARC.
    pub input: PathBuf,
    /// Zero-based record ordinal in primary/dependency, filename and physical member order.
    #[arg(long)]
    pub record: Option<usize>,
    /// Write the selected actual payload, after the text-only privacy gate. Must not exist.
    #[arg(long, requires = "record")]
    pub payload_out: Option<PathBuf>,
    /// Explicit local dependency authority.
    #[command(flatten)]
    pub dependencies: ArchiveDependencyArgs,
}

/// Explicit local dependency capabilities. A record URI is never a filesystem or network grant.
#[derive(Args, Debug, Default)]
pub struct ArchiveDependencyArgs {
    /// Owning tenant UUID. Required for dependencies; checked against native package bindings.
    #[arg(long)]
    pub tenant: Option<TenantId>,
    /// Authorized dependency root directory. Symlinks and traversal beneath this root are refused.
    #[arg(long)]
    pub dependency_root: Option<PathBuf>,
    /// Relative local WARC/WACZ dependency file. Repeat in the same order as SHA-256 pins.
    #[arg(long = "dependency")]
    pub files: Vec<PathBuf>,
    /// Exact whole-file SHA-256 for each --dependency, in matching order.
    #[arg(long = "dependency-sha256")]
    pub sha256: Vec<String>,
}

impl ArchiveDependencyArgs {
    fn approve(&self, limits: Limits, primary_bytes: u64) -> anyhow::Result<Vec<ApprovedLocalDependency>> {
        if self.files.len() >= limits.resources {
            bail!("archive dependency source count exceeds bound");
        }
        if self.files.len() != self.sha256.len() {
            bail!("each --dependency requires one matching --dependency-sha256");
        }
        if self.files.is_empty() {
            if self.dependency_root.is_some() {
                bail!("--dependency-root requires at least one --dependency");
            }
            return Ok(Vec::new());
        }
        let tenant = self
            .tenant
            .ok_or_else(|| anyhow!("--dependency requires --tenant"))?;
        let root = self
            .dependency_root
            .as_deref()
            .ok_or_else(|| anyhow!("--dependency requires --dependency-root"))?;
        let mut remaining = limits
            .total_bytes
            .checked_sub(primary_bytes)
            .ok_or_else(|| anyhow!("archive primary exceeds byte bound"))?;
        let mut dependencies = Vec::with_capacity(self.files.len());
        for (path, hash) in self.files.iter().zip(&self.sha256) {
            let mut source_limits = limits;
            source_limits.total_bytes = remaining;
            let approved = ApprovedLocalDependency::open(tenant, root, path, hash, source_limits)?;
            remaining = remaining
                .checked_sub(approved.encoded_bytes())
                .ok_or_else(|| anyhow!("archive dependency byte bound exceeded"))?;
            dependencies.push(approved);
        }
        Ok(dependencies)
    }
}

#[derive(Deserialize)]
struct LocalRequest {
    retention: Retention,
}
#[derive(Deserialize)]
struct LocalReport {
    run_id: CrawlRunId,
    request: LocalRequest,
    pages: Vec<PageRecord>,
}

struct Source {
    run: CrawlRunId,
    pages: Vec<PageRecord>,
    traffic: Vec<crawlx_storage::archive::recorded::RecordedTraffic>,
    created: Timestamp,
    /// Catalog custody and keys for sealed artifacts; `None` keeps the plain retained read.
    custody: Option<(
        std::sync::Arc<dyn crawlx_storage::ArtifactCustody>,
        std::sync::Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>,
    )>,
    artifacts: PathBuf,
}

/// Read one retained artifact, decrypting a sealed one when custody is configured. Runs inside
/// `spawn_blocking`, so blocking on the runtime handle is allowed here.
fn read_retained(
    source: &Source,
    artifact: &crawlx_core::ArtifactRef,
    tenant: TenantId,
    now: Timestamp,
    limits: Limits,
) -> Result<retained::RetainedText, ArchiveError> {
    match &source.custody {
        None => retained::read(&source.artifacts, artifact, tenant, source.run, now, limits),
        Some((custody, keys)) => tokio::runtime::Handle::current().block_on(retained::read_sealed(
            &source.artifacts,
            artifact,
            tenant,
            source.run,
            now,
            limits,
            custody.as_ref(),
            keys.as_ref(),
        )),
    }
}

fn retention_gate(retention: &Retention, created: Timestamp, now: Timestamp) -> anyhow::Result<()> {
    if retention.mode == RetentionMode::Zdr {
        bail!("retention_denied: durable archives are forbidden for zero-data-retention runs");
    }
    let days = match retention.mode {
        RetentionMode::Extended => retention.days.clamp(31, 365),
        _ => retention.days.clamp(1, 30),
    };
    let expiry = created
        .checked_add_signed(chrono::Duration::days(i64::from(days)))
        .ok_or_else(|| anyhow!("retention expiry overflow"))?;
    if expiry <= now {
        bail!("retention_denied: source run has expired");
    }
    Ok(())
}

async fn source(args: &ArchiveExportArgs, limits: Limits, now: Timestamp) -> anyhow::Result<Source> {
    if let Ok(run) = args.source.parse::<CrawlRunId>() {
        let pg = crate::inspect::connect(args.database_url.as_deref()).await?;
        let stored = crawlx_storage::tenant::scope(args.tenant, RunRepo::get(&pg, run)).await?;
        if stored.tenant != args.tenant {
            bail!("archive tenant does not own source run");
        }
        retention_gate(&stored.config.retention, stored.created_at, now)?;
        let mut pages = Vec::new();
        let mut after = 0i64;
        loop {
            let batch = crawlx_storage::tenant::scope(
                args.tenant,
                PageRepo::committed_page_keyset(&pg, run, after, 64),
            )
            .await?;
            let Some(last) = batch.last() else {
                break;
            };
            let next = last.frontier_id;
            if next <= after {
                bail!("archive page keyset did not advance");
            }
            if pages.len().saturating_add(batch.len()) as u64 > u64::from(limits.records.saturating_sub(1)) {
                bail!("archive page count exceeds bound");
            }
            pages.extend(batch);
            after = next;
        }
        let traffic = crawlx_storage::tenant::scope(
            args.tenant,
            crawlx_storage::archive::recorded::traffic(&pg, args.tenant, run, limits.records),
        )
        .await?;
        // Sealed artifacts decrypt through the catalog when a key provider is set.
        let custody =
            match crawlx_worker::config::artifact_keys_from_lookup(&|name| std::env::var(name).ok()).await? {
                Some(keys) => {
                    let (custody, _) =
                        crawlx_worker::config::read_only_custody_from_lookup(&pg, &|_| None).await?;
                    Some((custody, keys))
                }
                None => None,
            };
        return Ok(Source {
            run,
            pages,
            traffic,
            created: stored.created_at,
            custody,
            artifacts: args
                .artifacts_dir
                .clone()
                .unwrap_or_else(|| "./crawlx-artifacts".into()),
        });
    }
    let (report_path, bytes) = retained::read_local_report(Path::new(&args.source))
        .context("opening bounded regular recorded run report")?;
    let local: LocalReport =
        serde_json::from_slice(&bytes).context("reading run identity and retention from report")?;
    // ZDR refusal precedes even the artifact directory lookup and all staging.
    if local.request.retention.mode == RetentionMode::Zdr {
        bail!("retention_denied: durable archives are forbidden for zero-data-retention runs");
    }
    if local.pages.len() as u64 > u64::from(limits.records.saturating_sub(1)) {
        bail!("archive page count exceeds bound");
    }
    if local.pages.iter().any(|page| page.run != local.run_id) {
        bail!("report contains a foreign run page");
    }
    let created = local
        .pages
        .iter()
        .map(|p| p.fetched_at)
        .min()
        .ok_or_else(|| anyhow!("recorded run has no pages"))?;
    retention_gate(&local.request.retention, created, now)?;
    Ok(Source {
        run: local.run_id,
        pages: local.pages,
        traffic: Vec::new(),
        created,
        custody: None,
        artifacts: args
            .artifacts_dir
            .clone()
            .unwrap_or_else(|| report_path.parent().unwrap_or(Path::new(".")).join("artifacts")),
    })
}

fn approved_text(bytes: &[u8]) -> anyhow::Result<String> {
    let text = std::str::from_utf8(bytes)
        .context("binary archive capability unavailable: retained payload is not UTF-8")?;
    let redactor = Redactor::new();
    Ok(redactor.scrub_session_queries(&redactor.scrub(text)).into_owned())
}
fn approved_url(value: &str) -> anyhow::Result<String> {
    let mut url = url::Url::parse(value)?;
    url.set_username("")
        .map_err(|()| anyhow!("archive URL cannot carry userinfo"))?;
    url.set_password(None)
        .map_err(|()| anyhow!("archive URL cannot carry userinfo"))?;
    url.set_fragment(None);
    // Percent-encoded query names must not bypass the SESSION/credential exclusion.
    // Drop the query rather than serializing its original sensitive bytes elsewhere.
    if !warc::retention_safe_url(url.as_str()) {
        url.set_query(None);
    }
    approved_text(url.as_str().as_bytes())
}
fn record_id(
    tenant: TenantId,
    run: CrawlRunId,
    ordinal: u64,
    event: &str,
    date: Timestamp,
    stored: &[u8],
) -> String {
    let payload = Digest::of("crawlx/archive-stored-identity/v1", stored);
    let digest = Digest::of(
        "crawlx/archive-record/v1",
        format!(
            "{tenant}/{run}/archive-text-v1/{ordinal}/{event}/{date}/{}",
            payload.to_hex()
        )
        .as_bytes(),
    );
    let mut bytes = digest.truncate16();
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!("<urn:uuid:{}>", uuid::Uuid::from_bytes(bytes))
}
fn fields(id: String, kind: &str, date: Timestamp, mime: &str, target: Option<&str>) -> warc::RecordHeader {
    let mut fields = BTreeMap::from([
        ("WARC-Record-ID".into(), id),
        ("WARC-Type".into(), kind.into()),
        ("WARC-Date".into(), warc::date(date)),
        ("Content-Type".into(), mime.into()),
    ]);
    if let Some(target) = target {
        fields.insert("WARC-Target-URI".into(), target.into());
    }
    warc::RecordHeader {
        fields,
        payload_offset: 0,
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn export_recorded(
    args: ArchiveExportArgs,
    mut source: Source,
    config: ArchiveConfigV1,
    limits: Limits,
    now: Timestamp,
) -> anyhow::Result<ArchiveManifestV1> {
    if args.out.exists() {
        bail!("archive output already exists");
    }
    if !source.artifacts.is_dir() {
        bail!("recorded artifact store is unavailable");
    }
    source.pages.sort_by(|a, b| {
        a.fetched_at
            .cmp(&b.fetched_at)
            .then(a.frontier_id.cmp(&b.frontier_id))
            .then(a.url.url.as_str().cmp(b.url.url.as_str()))
    });
    let stage = tempfile::tempdir_in(parent(&args.out))?;
    std::fs::create_dir(stage.path().join("archive"))?;
    std::fs::create_dir(stage.path().join("indexes"))?;
    std::fs::create_dir(stage.path().join("pages"))?;
    std::fs::create_dir(stage.path().join("crawlx"))?;
    let warc_path = stage.path().join("archive/data.warc.gz");
    let cdx_path = stage.path().join("indexes/index.cdxj");
    let pages_path = stage.path().join("pages/pages.jsonl");
    let manifest_path = stage.path().join("crawlx/manifest.json");
    let mut output = File::create(&warc_path)?;
    let mut pages = File::create(&pages_path)?;
    pages.write_all(
        b"{\"format\":\"json-pages-1.0\",\"id\":\"pages\",\"title\":\"Retained page renditions\"}\n",
    )?;
    let mut sorter = cdxj::Sorter::new()?;
    let mut manifest = ArchiveManifestV1::available(args.tenant, source.run, source.created);
    let info = b"software: crawlx native offline archive codec\r\nformat: WARC File Format 1.1\r\nconformsTo: https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/\r\n";
    warc::write_record(
        &mut output,
        &fields(
            record_id(args.tenant, source.run, 0, "warcinfo", source.created, info),
            "warcinfo",
            source.created,
            "application/warc-fields",
            None,
        ),
        &mut std::io::Cursor::new(info),
        info.len() as u64,
        limits,
    )?;
    let mut ordinal = 1u64;
    for page in &source.pages {
        let target = approved_url(page.url.url.as_str())?;
        let mut entry_point = false;
        for (kind, artifact, mime, representation) in [
            (
                "html",
                page.html.as_ref(),
                "text/html; charset=utf-8",
                ArchiveRepresentation::ProtocolResource,
            ),
            (
                "markdown",
                page.markdown.as_ref(),
                "text/markdown; charset=utf-8",
                ArchiveRepresentation::ExtractedText,
            ),
        ] {
            let event = format!("page:{}:{kind}", page.frontier_id);
            let Some(artifact) = artifact else {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    event,
                    "retained_representation_unavailable",
                ));
                continue;
            };
            if ordinal >= u64::from(limits.records) {
                bail!("archive record count exceeds bound");
            }
            let bytes = match read_retained(&source, artifact, args.tenant, now, limits) {
                Ok(bytes) => bytes,
                Err(ArchiveError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    manifest
                        .omissions
                        .push(ArchiveOmissionV1::new(event, "retained_object_missing"));
                    continue;
                }
                Err(ArchiveError::Limit(_)) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        event,
                        "retained_representation_over_limit",
                    ));
                    continue;
                }
                Err(ArchiveError::CapabilityUnavailable(reason)) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(event, reason));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let text = match approved_text(&bytes.bytes) {
                Ok(text) => text,
                Err(_) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        event,
                        "raw_binary_privacy_capability_unavailable",
                    ));
                    continue;
                }
            };
            let facts = ArchiveCaptureFactsV1::retained(
                &event,
                page.fetched_at,
                representation,
                format!("retained_page_{kind}"),
            );
            let mut header = fields(
                record_id(
                    args.tenant,
                    source.run,
                    ordinal,
                    &event,
                    page.fetched_at,
                    text.as_bytes(),
                ),
                "resource",
                page.fetched_at,
                mime,
                Some(&target),
            );
            header
                .fields
                .insert("WARC-Crawlx-Capture-Facts".into(), serde_json::to_string(&facts)?);
            let record = warc::write_record(
                &mut output,
                &header,
                &mut std::io::Cursor::new(text.as_bytes()),
                text.len() as u64,
                limits,
            )?;
            sorter.push(cdxj::Entry::from_record(&record, "data.warc.gz")?.line(&record)?)?;
            manifest.records += 1;
            ordinal += 1;
            entry_point = true;
        }
        if entry_point {
            serde_json::to_writer(
                &mut pages,
                &serde_json::json!({"url": target, "ts":warc::date(page.fetched_at),
                "id":format!("page-{}", page.frontier_id), "title":approved_text(page.title.as_deref().unwrap_or("").as_bytes())?}),
            )?;
            pages.write_all(b"\n")?;
        }
    }
    for event in &source.traffic {
        let Some(url) = event.url.as_ref() else {
            manifest.omissions.push(ArchiveOmissionV1::new(
                format!("traffic:{}", event.event_id),
                "retained_traffic_url_unavailable",
            ));
            continue;
        };
        let target = approved_url(url)?;
        for (role, artifact) in [
            ("request", event.request_body.as_ref()),
            ("response", event.response_body.as_ref()),
        ] {
            let source_event = format!("traffic:{}:{role}", event.event_id);
            let Some(artifact) = artifact else {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    source_event,
                    "retained_traffic_body_unavailable",
                ));
                continue;
            };
            if ordinal >= u64::from(limits.records) {
                bail!("archive record count exceeds bound");
            }
            let retained = match read_retained(&source, artifact, args.tenant, now, limits) {
                Ok(retained) => retained,
                Err(ArchiveError::CapabilityUnavailable(_)) | Err(ArchiveError::Limit(_)) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        source_event,
                        "traffic_body_privacy_capability_or_bound_unavailable",
                    ));
                    continue;
                }
                Err(ArchiveError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        source_event,
                        "retained_traffic_object_missing",
                    ));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let text = match approved_text(&retained.bytes) {
                Ok(text) => text,
                Err(_) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        source_event,
                        "raw_binary_privacy_capability_unavailable",
                    ));
                    continue;
                }
            };
            let facts = ArchiveCaptureFactsV1::retained(
                &source_event,
                event.captured_at,
                ArchiveRepresentation::ProtocolResource,
                format!("retained_traffic_{role}_body"),
            );
            let mut header = fields(
                record_id(
                    args.tenant,
                    source.run,
                    ordinal,
                    &source_event,
                    event.captured_at,
                    text.as_bytes(),
                ),
                "resource",
                event.captured_at,
                &retained.content_type,
                Some(&target),
            );
            header
                .fields
                .insert("WARC-Crawlx-Capture-Facts".into(), serde_json::to_string(&facts)?);
            let record = warc::write_record(
                &mut output,
                &header,
                &mut std::io::Cursor::new(text.as_bytes()),
                text.len() as u64,
                limits,
            )?;
            sorter.push(cdxj::Entry::from_record(&record, "data.warc.gz")?.line(&record)?)?;
            manifest.records += 1;
            ordinal += 1;
        }
    }
    if manifest.records == 0 {
        bail!("no retention-approved text artifacts are available for export");
    }
    output.flush()?;
    pages.flush()?;
    sorter.finish(&mut File::create(&cdx_path)?)?;
    // This final content-bearing manifest is created only after every WARC/index/page resource succeeds.
    serde_json::to_writer_pretty(File::create(&manifest_path)?, &manifest)?;
    let total = [&warc_path, &cdx_path, &pages_path, &manifest_path]
        .into_iter()
        .try_fold(0u64, |sum, path| -> anyhow::Result<u64> {
            sum.checked_add(path.metadata()?.len())
                .ok_or_else(|| anyhow!("archive bundle size overflow"))
        })?;
    if total > limits.total_bytes {
        bail!("archive bundle exceeds total byte bound");
    }
    match config.format {
        ArchiveFormat::Warc => {
            std::fs::rename(stage.path(), &args.out).context("publishing complete WARC bundle")?;
        }
        ArchiveFormat::Wacz => {
            let mut file = tempfile::NamedTempFile::new_in(parent(&args.out))?;
            let files = vec![
                ("archive/data.warc.gz".into(), warc_path),
                ("indexes/index.cdxj".into(), cdx_path),
                ("pages/pages.jsonl".into(), pages_path),
                ("crawlx/manifest.json".into(), manifest_path),
            ];
            wacz::write(file.as_file_mut(), &files, &warc::date(source.created), limits)?;
            file.as_file_mut().sync_all()?;
            file.persist_noclobber(&args.out)
                .map_err(|error| error.error)
                .context("publishing complete WACZ")?;
        }
        _ => bail!("unsupported archive format"),
    }
    Ok(manifest)
}

struct Validated {
    collection: ArchiveCollection,
    records: Vec<RecordLocation>,
}
fn validate(path: &Path, limits: Limits, dependencies: &ArchiveDependencyArgs) -> anyhow::Result<Validated> {
    if path.to_str().is_some_and(|path| path.contains("://")) {
        bail!("capability_unavailable: external HTTP dependencies have no network fallback");
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > limits.total_bytes {
        bail!("archive primary exceeds bound or is not a regular file");
    }
    let approved = dependencies.approve(limits, metadata.len())?;
    let collection = ArchiveCollection::open(path, dependencies.tenant, approved, limits)?;
    let records = collection.records();
    Ok(Validated { collection, records })
}
fn atomic_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(parent(path))?;
    file.write_all(bytes)?;
    file.as_file_mut().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    Ok(())
}
fn safe_json(value: &serde_json::Value, name: Option<&str>) -> bool {
    let redactor = Redactor::new();
    if name.is_some_and(|key| redactor.is_sensitive_name(key)) {
        return value.is_null();
    }
    match value {
        serde_json::Value::Object(fields) => fields.iter().all(|(key, value)| safe_json(value, Some(key))),
        serde_json::Value::Array(values) => values.iter().all(|value| safe_json(value, name)),
        serde_json::Value::String(text) => {
            if matches!(name, Some("hash" | "digest" | "payload_digest"))
                && text
                    .strip_prefix("sha256:")
                    .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return true;
            }
            if url::Url::parse(text).is_ok() && !warc::retention_safe_url(text) {
                return false;
            }
            redactor.scrub(text) == *text && redactor.scrub_session_queries(text) == *text
        }
        _ => true,
    }
}
fn approve_package_metadata(validated: &mut Validated, limits: Limits) -> anyhow::Result<()> {
    validated.collection.primary_metadata(&mut |name, entry| {
        let mut bytes = Vec::new();
        if name.ends_with(".gz") {
            flate2::read::MultiGzDecoder::new(entry)
                .take(limits.record_bytes + 1)
                .read_to_end(&mut bytes)?;
        } else {
            entry.take(limits.record_bytes + 1).read_to_end(&mut bytes)?;
        }
        if bytes.len() as u64 > limits.record_bytes {
            return Err(ArchiveError::Limit("import metadata privacy review bytes"));
        }
        if name.ends_with(".cdxj") || name.ends_with(".cdx") || name.ends_with(".cdx.gz") {
            let text =
                std::str::from_utf8(&bytes).map_err(|_| ArchiveError::Invalid("non-UTF8 index metadata"))?;
            for line in text.lines() {
                let mut parts = line.splitn(3, ' ');
                parts.next().ok_or(ArchiveError::Invalid("CDXJ key missing"))?;
                parts.next().ok_or(ArchiveError::Invalid("CDXJ time missing"))?;
                let value =
                    serde_json::from_str(parts.next().ok_or(ArchiveError::Invalid("CDXJ JSON missing"))?)?;
                if !safe_json(&value, None) {
                    return Err(ArchiveError::Invalid(
                        "retention_denied: imported index contains sensitive data",
                    ));
                }
            }
        } else if name.ends_with(".jsonl") {
            for line in BufReader::new(bytes.as_slice()).lines() {
                if !safe_json(&serde_json::from_str(&line?)?, None) {
                    return Err(ArchiveError::Invalid(
                        "retention_denied: imported page list contains sensitive data",
                    ));
                }
            }
        } else if name.ends_with(".json") {
            if !safe_json(&serde_json::from_slice(&bytes)?, None) {
                return Err(ArchiveError::Invalid(
                    "retention_denied: imported metadata contains sensitive data",
                ));
            }
        } else {
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                ArchiveError::CapabilityUnavailable("raw_binary_metadata_privacy_policy_unavailable")
            })?;
            let redactor = Redactor::new();
            if redactor.scrub(text) != text || redactor.scrub_session_queries(text) != text {
                return Err(ArchiveError::Invalid(
                    "retention_denied: imported resource contains sensitive data",
                ));
            }
        }
        Ok(())
    })?;
    Ok(())
}

fn inspect_archive(args: ArchiveInspectArgs) -> anyhow::Result<serde_json::Value> {
    let limits = Limits::default();
    let mut validated = validate(&args.input, limits, &args.dependencies)?;
    let mut result = serde_json::json!({"format":if validated.collection.primary_package().is_some() {"wacz/1.1.1"} else {"warc/1.1"},
        "valid":true,"records":validated.records.len(),"dependencies":validated.collection.dependency_count(),
        "unknownRecordTypes":validated.records.iter().filter(|location| !location.record.known_type).count(),
        "indexed":validated.collection.primary_package().map(|p| p.indexed),"pages":validated.collection.primary_package().map(|p| p.pages)});
    if let Some(index) = args.record {
        let location = validated
            .records
            .get(index)
            .ok_or_else(|| anyhow!("archive record ordinal unavailable"))?;
        let record = &location.record;
        result["record"] = serde_json::json!({"ordinal":index,"id":approved_text(record.id.as_bytes())?,
            "type":approved_text(record.record_type.as_bytes())?,"url":record.target.as_ref().map(|url| approved_url(url)).transpose()?,
            "offset":record.offset,"length":record.length,"digest":record.payload_digest,"date":record.date});
        result["record"]["source"] = serde_json::Value::from(location.source);
        result["record"]["member"] = serde_json::Value::from(approved_text(location.filename.as_bytes())?);
        if let Some(path) = args.payload_out {
            let resolved = validated.collection.payload(&record.id)?;
            result["payloadSource"] = serde_json::json!({"id":approved_text(resolved.source.id.as_bytes())?,
                "date":resolved.source.date,"mime":resolved.source.mime,"status":resolved.source.status});
            let body = resolved.bytes;
            let text = approved_text(&body)?;
            atomic_bytes(&path, text.as_bytes())?;
            result["payloadTransformed"] = serde_json::Value::Bool(text.as_bytes() != body);
        }
    }
    Ok(result)
}

fn import_archive(args: ArchiveImportArgs) -> anyhow::Result<serde_json::Value> {
    if args.zero_data_retention {
        bail!("retention_denied: durable archive import is forbidden under zero data retention");
    }
    if args.out.exists() {
        bail!("archive import destination already exists");
    }
    let limits = Limits::default();
    let mut validated = validate(&args.input, limits, &args.dependencies)?;
    if !validated.collection.retention_approved() {
        bail!("retention_denied: import requires text-only secret-free records; binary or credential-bearing input needs a separate approved capability");
    }
    let dependencies = validated.collection.dependency_count();
    let rewritten = dependencies > 0 || !validated.collection.raw_copy_approved();
    if rewritten && args.dependencies.tenant.is_none() {
        bail!("retention_denied: opaque ZIP metadata requires --tenant for a closed WACZ rewrite");
    }
    let mut destination = tempfile::NamedTempFile::new_in(parent(&args.out))?;
    let (copied, format) = if !rewritten {
        approve_package_metadata(&mut validated, limits)?;
        let copied = validated.collection.copy_primary(destination.as_file_mut())?;
        (
            copied,
            if validated.collection.primary_package().is_some() {
                "wacz/1.1.1"
            } else {
                "warc/1.1"
            },
        )
    } else {
        // Source package extras are deliberately excluded; only approved physical records survive.
        let scratch = tempfile::tempdir_in(parent(&args.out))?;
        validated
            .collection
            .write_closed_wacz(destination.as_file_mut(), scratch.path())?;
        (destination.as_file().metadata()?.len(), "wacz/1.1.1")
    };
    destination.as_file_mut().sync_all()?;
    destination
        .persist_noclobber(&args.out)
        .map_err(|error| error.error)?;
    Ok(
        serde_json::json!({"format":format,"imported":true,"records":validated.records.len(),"bytes":copied,
        "materializedDependencies":dependencies,"containerRewritten":rewritten,"contentExecuted":false}),
    )
}

/// Execute an offline archive operation. Blocking codec/file work runs on Tokio's blocking pool.
///
/// # Errors
/// Returns source, privacy, retention, validation, bounds or publication errors without partial final manifests.
pub async fn execute(args: ArchiveArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    execute_with_clock(args, out, &crawlx_core::time::SystemClock).await
}

/// Execute with an injected retention clock. Capture dates and IDs still derive from recorded events.
///
/// # Errors
/// Returns the same admission, validation and I/O errors as [`execute`].
pub async fn execute_with_clock(
    args: ArchiveArgs,
    out: &mut dyn Write,
    clock: &dyn crawlx_core::Clock,
) -> anyhow::Result<ExitCode> {
    let result = match args.command {
        ArchiveCommand::Export(args) => {
            let mut config = ArchiveConfigV1::default();
            config.max_bytes = args.max_bytes;
            config.format = match args.format {
                FormatArg::Warc => ArchiveFormat::Warc,
                FormatArg::Wacz => ArchiveFormat::Wacz,
            };
            config.capture = if args.require_complete {
                ArchiveCapture::RequireComplete
            } else {
                ArchiveCapture::Available
            };
            config.validate().map_err(anyhow::Error::msg)?;
            let mut limits = Limits::default();
            limits.total_bytes = config.max_bytes;
            let now = clock.now();
            let source = source(&args, limits, now).await?;
            if config.capture == ArchiveCapture::RequireComplete {
                bail!("capability_unavailable: retained pages cannot prove complete original wire and subresource capture");
            }
            serde_json::to_value(
                tokio::task::spawn_blocking(move || export_recorded(args, source, config, limits, now))
                    .await??,
            )?
        }
        ArchiveCommand::Inspect(args) => tokio::task::spawn_blocking(move || inspect_archive(args)).await??,
        ArchiveCommand::Import(args) => tokio::task::spawn_blocking(move || import_archive(args)).await??,
        ArchiveCommand::Replay(args) => return crate::archive_replay::replay(args, out).await,
        ArchiveCommand::Qa(args) => return crate::archive_replay::qa(args, out).await,
    };
    serde_json::to_writer_pretty(&mut *out, &result)?;
    writeln!(out)?;
    Ok(ExitCode::SUCCESS)
}
