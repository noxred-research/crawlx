//! Bounded archive finalization over committed retained resources, never live URLs.
//!
//! One resource job runs at a time (zero queued bodies). Source bytes pass a fail-closed
//! privacy gate before any archive spool. Each gzip shard commits before its catalog row;
//! the final package commits before manifest publication. Stable ordinals permit recovery.

use crate::{Stores, WorkerError};
use crawlx_core::archive::{
    ArchiveCapture, ArchiveCaptureFactsV1, ArchiveFormat, ArchiveManifestV1, ArchiveOmissionV1,
    ArchiveRepresentation,
};
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveExportV1, ArchiveReadV1, ArchiveRecordV1};
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::CrawlRun;
use crawlx_core::{ArtifactRef, Clock};
use crawlx_storage::archive::{cdxj, rollover, staging::StagedFile, wacz, warc, ArchiveError, Limits};
use crawlx_telemetry::redact::Redactor;
use std::io::Write as _;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

mod binary;
mod evidence;
mod history;
mod payload;
mod resource;
pub(crate) use history::{conditional_baseline, ArchiveBaseline};

#[cfg(test)]
mod tests;

static ARCHIVE_WRITERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Whether the terminal coordinator may commit its run transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finalization {
    /// Archive disabled or already published.
    Ready,
    /// Another current archive lease owns finalization; retry without ending the run.
    Busy,
    /// Permanent archive failure; the run must not claim successful output.
    Failed,
}

fn stopped() -> WorkerError {
    WorkerError::PolicyDenied("archive finalization cancelled".into())
}
fn codec(error: ArchiveError) -> WorkerError {
    WorkerError::Archive(error)
}
fn joined(error: tokio::task::JoinError) -> WorkerError {
    WorkerError::ArchiveTask(error)
}
fn json(error: serde_json::Error) -> WorkerError {
    WorkerError::Archive(ArchiveError::Json(error))
}
fn approved_target(value: &str) -> Result<String, WorkerError> {
    let mut target =
        url::Url::parse(value).map_err(|_| WorkerError::PolicyDenied("archive target invalid".into()))?;
    target
        .set_username("")
        .map_err(|()| WorkerError::PolicyDenied("archive target userinfo invalid".into()))?;
    target
        .set_password(None)
        .map_err(|()| WorkerError::PolicyDenied("archive target userinfo invalid".into()))?;
    target.set_fragment(None);
    let redactor = Redactor::new();
    if target.as_str().len() > 8192 || !redactor.is_clean_text(target.as_str()) {
        return Err(WorkerError::PolicyDenied(
            "archive target failed privacy approval".into(),
        ));
    }
    Ok(target.into())
}
fn identifier(export: &ArchiveExportV1, ordinal: u64) -> String {
    let digest = Digest::of(
        "crawlx/archive-record/v1",
        format!("{}/{}/{ordinal}", export.tenant, export.id).as_bytes(),
    );
    format!("<urn:uuid:{}>", uuid::Uuid::from_bytes(digest.truncate16()))
}
fn limits(export: &ArchiveExportV1) -> Limits {
    let mut limits = Limits::default();
    limits.record_bytes = export.config.max_record_bytes;
    limits.total_bytes = export.config.max_bytes;
    limits.expanded_bytes = export.config.max_bytes;
    limits.records = export.config.max_records;
    limits
}

/// Publish a retained run's archive before its terminal transition. Disabled by default.
///
/// A coordinator calls this only after its URL plane and all Session Actors stop. It may
/// call again after any crash: committed source ordinals and writer fencing are durable.
///
/// # Errors
/// Refuses ZDR, expired sources, unavailable completeness, unapproved bytes, cancellation,
/// missing committed shards, codec limits, stale fences or object/catalog persistence errors.
pub(crate) async fn finalize(
    stores: &Stores,
    run: &CrawlRun,
    clock: Arc<dyn Clock>,
    cancel: &CancellationToken,
    terminal_reason: crawlx_core::counters::TerminalReason,
) -> Result<Finalization, WorkerError> {
    let Some(config) = run.config.output.archive.as_ref() else {
        return Ok(Finalization::Ready);
    };
    // These gates precede both reads and spool creation, including recovery.
    if run.config.retention.mode == RetentionMode::Zdr {
        return Err(WorkerError::PolicyDenied(
            "durable archive forbidden for zdr".into(),
        ));
    }
    config
        .validate()
        .map_err(|reason| WorkerError::Config(reason.into()))?;
    if config.capture == ArchiveCapture::RequireComplete {
        return Err(WorkerError::PolicyDenied(
            "complete original wire capture capability unavailable".into(),
        ));
    }
    let expires = (run.config.retention.days != 0)
        .then(|| run.created_at + chrono::Duration::days(i64::from(run.config.retention.days)));
    if expires.is_some_and(|expiry| expiry <= clock.now()) {
        return Err(WorkerError::PolicyDenied("archive source expired".into()));
    }
    if cancel.is_cancelled() {
        return Err(stopped());
    }
    let pending = ArchiveExportV1::pending(
        run.tenant,
        run.id,
        config.clone(),
        run.created_at,
        expires,
        terminal_reason,
    );
    stores.archives.begin(&pending).await?;
    if let ArchiveReadV1::Available(row) = stores.archives.get(run.tenant, pending.id, clock.now()).await? {
        if row.state == ArchiveExportState::Published {
            return Ok(Finalization::Ready);
        }
        if row.state == ArchiveExportState::Failed {
            return Ok(Finalization::Failed);
        }
    }
    let _writer = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(stopped()),
        permit = ARCHIVE_WRITERS.acquire() => permit.map_err(|_| WorkerError::PolicyDenied("archive writer admission closed".into()))?,
    };
    let Some(export) = stores.archives.claim(run.tenant, pending.id, clock.now()).await? else {
        return Ok(Finalization::Busy);
    };
    // Packaging writes sealed artifacts under the claimed export's fence (the catalog has no owner column).
    let producer = crawlx_core::custody::CustodyLease::for_archive_export(
        export.tenant,
        export.run,
        export.id,
        crawlx_core::WorkerId(export.id),
        export.fence,
    );
    let work = crawlx_core::custody::with_producer(
        producer,
        finalize_claimed(stores, run, &export, config, Arc::clone(&clock), cancel),
    );
    // The heartbeat is polled beside the packaging, not in the body of a `select!` arm: an arm
    // that awaited the catalog would leave `work` suspended inside its open publication
    // transaction while the renewal waits for the export row that transaction locks.
    let heartbeat = keep_export_alive(stores, run, &export, &*clock);
    tokio::pin!(work, heartbeat);
    tokio::select! {
        biased;
        result = &mut work => result,
        ended = &mut heartbeat => ended,
    }
}

/// Renew the claimed export's lease every 30 s. Returns only when the renewal fails: with the
/// export's final state when publication committed while its transport response was pending,
/// else with the renewal error.
async fn keep_export_alive(
    stores: &Stores,
    run: &CrawlRun,
    export: &ArchiveExportV1,
    clock: &dyn Clock,
) -> Result<Finalization, WorkerError> {
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(30));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        heartbeat.tick().await;
        if let Err(error) = stores
            .archives
            .renew(export.tenant, export.id, export.fence, clock.now())
            .await
        {
            // Publication can commit while its transport response remains pending.
            if let ArchiveReadV1::Available(row) =
                stores.archives.get(run.tenant, export.id, clock.now()).await?
            {
                if row.state == ArchiveExportState::Published {
                    return Ok(Finalization::Ready);
                }
                if row.state == ArchiveExportState::Failed {
                    return Ok(Finalization::Failed);
                }
            }
            return Err(error.into());
        }
    }
}

async fn finalize_claimed(
    stores: &Stores,
    run: &CrawlRun,
    export: &ArchiveExportV1,
    config: &crawlx_core::archive::ArchiveConfigV1,
    clock: Arc<dyn Clock>,
    cancel: &CancellationToken,
) -> Result<Finalization, WorkerError> {
    let mut manifest = ArchiveManifestV1::available(run.tenant, run.id, run.created_at);
    let mut after = 0i64;
    let mut scanned = 0u32;
    // Replay the same selection and omissions after recovery, including records already committed.
    let mut committed_records = 0u64;
    let mut recorder = resource::Recorder {
        stores,
        run,
        export,
        clock: clock.as_ref(),
        cancel,
        committed_bytes: export.bytes,
    };
    loop {
        if cancel.is_cancelled() {
            return Err(stopped());
        }
        // Descriptors only, one page per batch; no collection-sized page/body Vec.
        let pages = stores.pages.committed_page_keyset(run.id, after, 1).await?;
        let Some(page) = pages.into_iter().next() else {
            break;
        };
        scanned = scanned.saturating_add(1);
        if scanned > config.max_records || committed_records >= u64::from(config.max_records) {
            manifest.omissions.push(ArchiveOmissionV1::new(
                "run",
                "remaining_retained_resources_not_evaluated_record_budget",
            ));
            break;
        }
        after = page.frontier_id;
        let target = match approved_target(page.url.url.as_str()) {
            Ok(target) => target,
            Err(_) => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    format!("page:{after}"),
                    "target_privacy_approval_failed",
                ));
                continue;
            }
        };
        let raw_body: Option<ArtifactRef> = page
            .metadata
            .pointer("/acquisition/wireBody")
            .filter(|value| !value.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(json)?;
        let raw_mime = page.content_type.as_deref().unwrap_or("text/plain");
        let request = stores.frontier.get_request(run.id, page.frontier_id).await?;
        for (slot, kind, source, mime, representation) in [
            (
                0u64,
                "response_body",
                raw_body.as_ref(),
                raw_mime,
                ArchiveRepresentation::ProtocolResource,
            ),
            (
                1u64,
                "html",
                page.html.as_ref(),
                "text/html",
                ArchiveRepresentation::RenderedDom,
            ),
            (
                2u64,
                "markdown",
                page.markdown.as_ref(),
                "text/markdown",
                ArchiveRepresentation::ExtractedText,
            ),
        ] {
            if committed_records >= u64::from(config.max_records) {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    "run",
                    "remaining_retained_resources_not_evaluated_record_budget",
                ));
                break;
            }
            let ordinal = u64::try_from(page.frontier_id)
                .ok()
                .and_then(|id| id.checked_mul(8))
                .and_then(|id| id.checked_add(slot))
                .filter(|id| i64::try_from(*id).is_ok())
                .ok_or_else(|| WorkerError::Config("archive event ordinal overflow".into()))?;
            let event = format!("page:{after}:{kind}");
            let mut facts = ArchiveCaptureFactsV1::retained(
                event,
                page.fetched_at,
                representation,
                format!("retained_page_{kind}"),
            );
            if kind == "response_body" {
                facts.capture_source = if page
                    .metadata
                    .pointer("/acquisition/backend/backendId")
                    .and_then(serde_json::Value::as_str)
                    == Some("native_http")
                {
                    "retained_native_decoded_response_body"
                } else {
                    "retained_decoded_response_body"
                }
                .into();
                facts.body_state = if run.config.capture.response_bodies
                    == crawlx_core::config::ResponseBodies::Full
                    && page
                        .metadata
                        .pointer("/acquisition/truncated")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false)
                {
                    "complete"
                } else {
                    "unknown"
                }
                .into();
                facts.transformations = vec![
                    "decoded_body_not_original_wire".into(),
                    "unchanged_privacy_approved_text".into(),
                ];
            }
            let event = facts.source_event.clone();
            match recorder
                .record(resource::ResourceInput {
                    ordinal,
                    source,
                    capture: None,
                    target: &target,
                    mime,
                    facts,
                    history_source: Some((&request, &page)),
                })
                .await?
            {
                resource::RecordOutcome::Existing | resource::RecordOutcome::Committed => {
                    committed_records = committed_records.saturating_add(1)
                }
                resource::RecordOutcome::Omitted(reason) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(event, reason))
                }
            }
        }
    }
    let mut traffic_after = 0u64;
    let mut traffic_scanned = 0u32;
    loop {
        if cancel.is_cancelled() {
            return Err(stopped());
        }
        if committed_records >= u64::from(config.max_records) || traffic_scanned >= config.max_records {
            manifest.omissions.push(ArchiveOmissionV1::new(
                "traffic",
                "remaining_resources_not_evaluated_record_budget",
            ));
            break;
        }
        let descriptors = stores
            .archives
            .traffic_keyset(run.tenant, run.id, traffic_after, 1)
            .await?;
        let Some(traffic) = descriptors.into_iter().next() else {
            break;
        };
        traffic_after = traffic.event_id;
        traffic_scanned = traffic_scanned.saturating_add(1);
        let target = match traffic.url.as_deref().map(approved_target) {
            Some(Ok(target)) => target,
            Some(Err(_)) | None => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    format!("traffic:{traffic_after}"),
                    "retained_target_missing_or_privacy_approval_failed",
                ));
                continue;
            }
        };
        for (slot, kind, source) in [
            (0u64, "request", traffic.request_body.as_ref()),
            (1u64, "response", traffic.response_body.as_ref()),
        ] {
            if committed_records >= u64::from(config.max_records) {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    "traffic",
                    "remaining_resources_not_evaluated_record_budget",
                ));
                break;
            }
            let ordinal = traffic
                .event_id
                .checked_mul(8)
                .and_then(|id| id.checked_add(4))
                .and_then(|id| id.checked_add(slot))
                .filter(|id| i64::try_from(*id).is_ok())
                .ok_or_else(|| WorkerError::Config("archive traffic ordinal overflow".into()))?;
            let facts = ArchiveCaptureFactsV1::retained(
                format!("traffic:{traffic_after}:{kind}"),
                traffic.captured_at,
                ArchiveRepresentation::ProtocolResource,
                "retained_journal_body",
            );
            let event = facts.source_event.clone();
            match recorder
                .record(resource::ResourceInput {
                    ordinal,
                    source,
                    capture: None,
                    target: &target,
                    mime: "text/plain",
                    facts,
                    history_source: None,
                })
                .await?
            {
                resource::RecordOutcome::Existing | resource::RecordOutcome::Committed => {
                    committed_records = committed_records.saturating_add(1)
                }
                resource::RecordOutcome::Omitted(reason) => {
                    manifest.omissions.push(ArchiveOmissionV1::new(event, reason))
                }
            }
        }
    }
    evidence::record(&mut recorder, &mut manifest, &mut committed_records).await?;
    let ArchiveReadV1::Available(current_export) =
        stores.archives.get(run.tenant, export.id, clock.now()).await?
    else {
        return Err(WorkerError::Config(
            "archive custody disappeared during finalization".into(),
        ));
    };
    manifest.custody = current_export.custody;
    if let Err(error) = package(stores, &current_export, &mut manifest, Arc::clone(&clock), cancel).await {
        if let WorkerError::Archive(reason) = &error {
            let failure = if matches!(
                reason,
                ArchiveError::Limit(_) | ArchiveError::RecordExceedsRollover { .. }
            ) {
                crawlx_core::archive_catalog::ArchiveFailureV1::LimitExceeded
            } else if manifest.records == 0 {
                crawlx_core::archive_catalog::ArchiveFailureV1::CaptureUnavailable
            } else {
                crawlx_core::archive_catalog::ArchiveFailureV1::InvalidCapture
            };
            stores
                .archives
                .fail(run.tenant, export.id, export.fence, failure, clock.now())
                .await?;
            return Ok(Finalization::Failed);
        }
        return Err(error);
    }
    Ok(Finalization::Ready)
}

struct PackageWriter {
    warc: rollover::Writer,
    pages: StagedFile,
    facts: StagedFile,
    sorter: cdxj::Sorter,
    has_revisits: bool,
}

struct PackageFiles {
    archive: StagedFile,
    index: Option<StagedFile>,
}

impl PackageWriter {
    fn open(rollover_bytes: Option<u64>, limits: Limits) -> Result<Self, ArchiveError> {
        let mut pages = StagedFile::new()?;
        pages.file_mut().write_all(
            b"{\"format\":\"json-pages-1.0\",\"id\":\"crawlx\",\"title\":\"Retained representations\"}\n",
        )?;
        Ok(Self {
            warc: rollover::Writer::new(rollover_bytes, limits)?,
            pages,
            facts: StagedFile::new()?,
            sorter: cdxj::Sorter::new()?,
            has_revisits: false,
        })
    }
    fn append(
        &mut self,
        shard: &StagedFile,
        record: &ArchiveRecordV1,
        limits: Limits,
    ) -> Result<(), ArchiveError> {
        let mut summary = warc::inspect_shard(shard.reader()?, limits)?;
        if summary.id != record.record_id
            || summary.offset != record.offset
            || summary.length != record.length
            || summary.payload_digest != record.payload_digest
            || summary.target.as_deref() != Some(record.target.as_str())
        {
            return Err(ArchiveError::Invalid("committed shard catalog mismatch"));
        }
        self.has_revisits |= summary.record_type == "revisit";
        let filename = self.warc.append(&mut shard.reader()?, &mut summary)?;
        self.sorter
            .push(cdxj::Entry::from_record(&summary, &filename)?.line(&summary)?)?;
        serde_json::to_writer(self.facts.file_mut(), &record.facts)?;
        self.facts.file_mut().write_all(b"\n")?;
        serde_json::to_writer(
            self.pages.file_mut(),
            &serde_json::json!({"id":record.record_id,
            "url":record.target,"ts":warc::date(record.facts.captured_at),"title":"Retained representation"}),
        )?;
        self.pages.file_mut().write_all(b"\n")?;
        Ok(())
    }
    fn finish(
        mut self,
        manifest: &ArchiveManifestV1,
        format: ArchiveFormat,
        limits: Limits,
    ) -> Result<PackageFiles, ArchiveError> {
        let mut warc_files = self.warc.finish()?;
        self.pages.file_mut().flush()?;
        self.facts.file_mut().flush()?;
        let mut index = StagedFile::new()?;
        self.sorter.finish(index.file_mut())?;
        let mut manifest_file = StagedFile::new()?;
        serde_json::to_writer(manifest_file.file_mut(), manifest)?;
        if format == ArchiveFormat::Warc {
            let archive = warc_files
                .into_iter()
                .next()
                .ok_or(ArchiveError::Invalid("missing WARC file"))?
                .1;
            let package_bytes = archive.file().metadata()?.len();
            let index_bytes = index.file().metadata()?.len();
            if package_bytes
                .checked_add(index_bytes)
                .is_none_or(|bytes| bytes > limits.total_bytes)
            {
                return Err(ArchiveError::Limit("WARC plus adjacent index bytes"));
            }
            if self.has_revisits {
                warc::inspect(archive.reader()?, true, limits)?;
            }
            return Ok(PackageFiles {
                archive,
                index: Some(index),
            });
        }
        warc_files.extend([
            ("indexes/index.cdxj".into(), index),
            ("pages/pages.jsonl".into(), self.pages),
            ("metadata/capture-facts.jsonl".into(), self.facts),
            ("metadata/crawlx-manifest.json".into(), manifest_file),
        ]);
        // Logical package names remain separate from trusted descriptor-only source paths.
        let files = warc_files
            .iter()
            .map(|(name, source)| (name.clone(), source.path().to_owned()))
            .collect::<Vec<_>>();
        let mut archive = StagedFile::new()?;
        wacz::write(archive.file_mut(), &files, &warc::date(manifest.created), limits)?;
        archive.file().sync_all()?;
        if self.has_revisits {
            wacz::inspect(archive.reader()?, limits)?;
        }
        Ok(PackageFiles { archive, index: None })
    }
}

async fn append_record(
    stores: &Stores,
    export: &ArchiveExportV1,
    source_run: crawlx_core::CrawlRunId,
    record: ArchiveRecordV1,
    mut writer: PackageWriter,
) -> Result<PackageWriter, WorkerError> {
    let shard = tokio::task::spawn_blocking(StagedFile::new)
        .await
        .map_err(joined)??;
    stores
        .artifacts
        .copy_archive_with_custody(
            export.tenant,
            source_run,
            &record.artifact,
            &record.custody,
            shard.path(),
            export.config.max_record_bytes.saturating_add(131_072),
        )
        .await?;
    let codec_limits = limits(export);
    let writer = tokio::task::spawn_blocking(move || {
        writer.append(&shard, &record, codec_limits)?;
        Ok::<_, ArchiveError>(writer)
    })
    .await
    .map_err(joined)?
    .map_err(codec)?;
    Ok(writer)
}

async fn package(
    stores: &Stores,
    export: &ArchiveExportV1,
    manifest: &mut ArchiveManifestV1,
    clock: Arc<dyn Clock>,
    cancel: &CancellationToken,
) -> Result<(), WorkerError> {
    let rollover_bytes = export.config.rollover_bytes;
    let codec_limits = limits(export);
    let mut writer = tokio::task::spawn_blocking(move || PackageWriter::open(rollover_bytes, codec_limits))
        .await
        .map_err(joined)?
        .map_err(codec)?;
    let mut after = None;
    let mut included = std::collections::BTreeSet::new();
    loop {
        if cancel.is_cancelled() {
            return Err(stopped());
        }
        stores
            .archives
            .renew(export.tenant, export.id, export.fence, clock.now())
            .await?;
        let rows = stores
            .archives
            .records(export.tenant, export.id, after, 1, clock.now())
            .await?;
        let Some(record) = rows.into_iter().next() else {
            break;
        };
        after = Some(record.ordinal);
        if let Some(dependency) = &record.dependency {
            if dependency.export != export.id && included.insert((dependency.export, dependency.ordinal)) {
                let Some((source_run, baseline)) =
                    payload::dependency(stores, export, &record, clock.now()).await?
                else {
                    return Err(codec(ArchiveError::Invalid(
                        "archive dependency closure unavailable",
                    )));
                };
                writer = append_record(stores, export, source_run, baseline, writer).await?;
                manifest.materialized_dependencies = manifest
                    .materialized_dependencies
                    .checked_add(1)
                    .ok_or_else(|| WorkerError::Config("archive dependency count overflow".into()))?;
            }
        }
        writer = append_record(stores, export, export.run, record, writer).await?;
        manifest.records = manifest
            .records
            .checked_add(1)
            .ok_or_else(|| WorkerError::Config("archive record count overflow".into()))?;
    }
    if manifest.records == 0 {
        return Err(codec(ArchiveError::Invalid(
            "no approved retained archive resources",
        )));
    }
    let final_manifest = manifest.clone();
    let format = export.config.format;
    let codec_limits = limits(export);
    let final_files =
        tokio::task::spawn_blocking(move || writer.finish(&final_manifest, format, codec_limits))
            .await
            .map_err(joined)?
            .map_err(codec)?;
    let content_type = if format == ArchiveFormat::Warc {
        "application/warc"
    } else {
        "application/wacz+zip"
    };
    stores
        .archives
        .renew(export.tenant, export.id, export.fence, clock.now())
        .await?;
    let artifact: ArtifactRef = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(stopped()),
        result = stores.artifacts.put_archive_file_with_custody(export.run, content_type, final_files.archive.path(), export.config.max_bytes, &export.custody) => result?,
    };
    let index = if let Some(index_file) = &final_files.index {
        Some(
            stores
                .artifacts
                .put_archive_file_with_custody(
                    export.run,
                    "application/cdxj",
                    index_file.path(),
                    export.config.max_bytes,
                    &export.custody,
                )
                .await?,
        )
    } else {
        None
    };
    crawlx_storage::chaos::pause("archive.before_manifest_publish").await;
    stores
        .archives
        .publish(
            export.tenant,
            export.id,
            export.fence,
            &artifact,
            index.as_ref(),
            manifest,
            clock.now(),
        )
        .await?;
    Ok(())
}
