//! One-at-a-time approved resource streaming, shared by retained pages and journal captures.

use super::{codec, identifier, joined, json, limits, stopped};
use crate::{Stores, WorkerError};
use crawlx_core::archive::ArchiveCaptureFactsV1;
use crawlx_core::archive_catalog::{ArchiveExportV1, ArchiveRecordV1};
use crawlx_core::custody::FrozenArchiveSource;
use crawlx_core::orchestration::QueuedRequestV1;
use crawlx_core::repo::{CrawlRun, PageRecord};
use crawlx_core::{ArtifactRef, Clock};
use crawlx_storage::archive::{staging::StagedFile, warc, ArchiveError};
use crawlx_storage::custody::frozen_archive::with_terminal_grant;
use crawlx_telemetry::redact::Redactor;
use std::collections::BTreeMap;
use std::io::Cursor;
use tokio_util::sync::CancellationToken;

pub(super) struct ResourceInput<'a> {
    pub ordinal: u64,
    pub source: Option<&'a ArtifactRef>,
    pub capture: Option<&'a crawlx_core::browser_capture::CaptureArtifact>,
    pub target: &'a str,
    pub mime: &'a str,
    pub facts: ArchiveCaptureFactsV1,
    pub history_source: Option<(&'a QueuedRequestV1, &'a PageRecord)>,
}

pub(super) enum RecordOutcome {
    Existing,
    Committed,
    Omitted(&'static str),
}

pub(super) struct Recorder<'a> {
    pub stores: &'a Stores,
    pub run: &'a CrawlRun,
    pub export: &'a ArchiveExportV1,
    pub clock: &'a dyn Clock,
    pub cancel: &'a CancellationToken,
    pub committed_bytes: u64,
}

impl Recorder<'_> {
    pub(super) async fn record(
        &mut self,
        mut input: ResourceInput<'_>,
    ) -> Result<RecordOutcome, WorkerError> {
        if self.cancel.is_cancelled() {
            return Err(stopped());
        }
        let existing = self
            .stores
            .archives
            .records(
                self.run.tenant,
                self.export.id,
                input.ordinal.checked_sub(1),
                1,
                self.clock.now(),
            )
            .await?;
        if existing.first().is_some_and(|row| row.ordinal == input.ordinal) {
            return Ok(RecordOutcome::Existing);
        }
        let Some(source) = input.source else {
            return Ok(RecordOutcome::Omitted(
                "approved_retained_representation_unavailable",
            ));
        };
        let source_custody = match self
            .stores
            .artifacts
            .archive_custody(
                self.run.tenant,
                self.run.id,
                source,
                self.export.config.max_record_bytes,
            )
            .await
        {
            Ok(custody) => custody,
            Err(crawlx_core::StoreError::NotFound { .. } | crawlx_core::StoreError::RetentionDenied(_)) => {
                return Ok(RecordOutcome::Omitted(
                    "retained_body_missing_expired_or_disallowed",
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let binary = super::binary::approved(self.run, &input);
        if source_custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive && !binary {
            return Ok(RecordOutcome::Omitted(
                "sensitive_capture_not_approved_for_archive",
            ));
        }
        if binary && source_custody.sensitivity != crawlx_core::repo::Sensitivity::Sensitive {
            return Ok(RecordOutcome::Omitted("screenshot_sensitive_custody_required"));
        }
        self.stores
            .archives
            .narrow_custody(
                self.run.tenant,
                self.export.id,
                self.export.fence,
                &source_custody,
                self.clock.now(),
            )
            .await?;
        let read = if binary {
            self.stores
                .artifacts
                .read_archive_sensitive(
                    self.run.tenant,
                    self.run.id,
                    source,
                    &source_custody,
                    self.export.config.max_record_bytes,
                )
                .await
        } else {
            self.stores
                .artifacts
                .read_archive_content(
                    self.run.tenant,
                    self.run.id,
                    source,
                    self.export.config.max_record_bytes,
                )
                .await
        };
        let body = match read {
            Ok(body) => body,
            Err(crawlx_core::StoreError::NotFound { .. } | crawlx_core::StoreError::RetentionDenied(_)) => {
                return Ok(RecordOutcome::Omitted(
                    "retained_body_missing_expired_or_disallowed",
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let body = if binary {
            let capture = input
                .capture
                .ok_or_else(|| WorkerError::Config("approved screenshot descriptor missing".into()))?;
            let expected = (capture.bytes, capture.width, capture.height);
            tokio::task::spawn_blocking(move || {
                super::binary::validate_png(&body, expected.0, expected.1, expected.2)?;
                Ok::<_, ArchiveError>(body)
            })
            .await
            .map_err(joined)?
            .map_err(codec)?
        } else {
            body
        };
        // Retention custody alone is insufficient: fail closed before any chunk spool.
        if !binary && !std::str::from_utf8(&body).is_ok_and(|text| Redactor::new().is_clean_text(text)) {
            return Ok(RecordOutcome::Omitted(
                "body_privacy_or_binary_capability_unavailable",
            ));
        }
        if input.mime.len() > 256 || input.mime.chars().any(char::is_control) {
            return Ok(RecordOutcome::Omitted("retained_media_type_unavailable"));
        }
        if !binary && input.facts.body_state == "complete" {
            let expected = input
                .history_source
                .and_then(|(_, page)| page.metadata.pointer("/acquisition/decodedBytes"))
                .and_then(serde_json::Value::as_u64);
            if expected != u64::try_from(body.len()).ok() {
                input.facts.body_state = "unknown".into();
            }
        }
        let payload_key = input
            .history_source
            .map(|(request, page)| super::payload::key(self.run, request, page, &input.facts, input.mime))
            .transpose()?
            .flatten();
        let baseline = if let Some(key) = &payload_key {
            self.stores
                .archives
                .payload_source(
                    self.run.tenant,
                    self.export.id,
                    key,
                    &warc::digest(&body),
                    self.clock.now(),
                )
                .await?
                .filter(|source| source.export != self.export.id || source.ordinal < input.ordinal)
        } else {
            None
        };
        let mut header = warc::RecordHeader {
            payload_offset: 0,
            fields: BTreeMap::from([
                ("WARC-Type".into(), "resource".into()),
                ("WARC-Record-ID".into(), identifier(self.export, input.ordinal)),
                ("WARC-Date".into(), warc::date(input.facts.captured_at)),
                ("WARC-Target-URI".into(), input.target.into()),
                ("Content-Type".into(), input.mime.into()),
                (
                    "Crawlx-Capture-Facts".into(),
                    serde_json::to_string(&input.facts).map_err(json)?,
                ),
            ]),
        };
        if let Some(source) = &baseline {
            // wire-compat: the WARC 1.1 identical-payload profile resolves the stored source.
            header.fields.insert("WARC-Type".into(), "revisit".into());
            header.fields.insert(
                "WARC-Profile".into(),
                "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest".into(),
            );
            header
                .fields
                .insert("WARC-Refers-To".into(), source.record_id.clone());
            header
                .fields
                .insert("WARC-Refers-To-Target-URI".into(), source.target.clone());
            header
                .fields
                .insert("WARC-Refers-To-Date".into(), warc::date(source.facts.captured_at));
            header
                .fields
                .insert("WARC-Payload-Digest".into(), source.payload_digest.clone());
        }
        let body = if baseline.is_some() { Vec::new() } else { body };
        let mut codec_limits = limits(self.export);
        codec_limits.total_bytes = self.export.config.max_record_bytes.saturating_add(131_072);
        let stop = self.cancel.clone();
        // Move the sole body allocation into the writer. No duplicate full body buffer.
        let (summary, shard) = tokio::task::spawn_blocking(move || {
            if stop.is_cancelled() {
                return Err(ArchiveError::Invalid("archive cancelled"));
            }
            let length = u64::try_from(body.len()).map_err(|_| ArchiveError::Limit("record bytes"))?;
            let mut output = StagedFile::new()?;
            let summary = warc::write_record(
                output.file_mut(),
                &header,
                &mut Cursor::new(body),
                length,
                codec_limits,
            )?;
            output.file().sync_all()?;
            Ok::<_, ArchiveError>((summary, output))
        })
        .await
        .map_err(joined)?
        .map_err(codec)?;
        // Leave bounded space for the index, omission ledger and container metadata. The final
        // encoded writer still enforces the exact cap; this is not a completeness claim.
        let reserve = (self.export.config.max_bytes / 8).min(4_194_304);
        if self
            .committed_bytes
            .checked_add(summary.length)
            .is_none_or(|bytes| bytes > self.export.config.max_bytes.saturating_sub(reserve))
        {
            return Ok(RecordOutcome::Omitted("remaining_encoded_archive_byte_budget"));
        }
        crawlx_storage::chaos::pause("archive.before_shard_commit").await;
        let terminal = super::run_is_terminal(self.stores, self.run.id).await?;
        let sources = vec![FrozenArchiveSource::new(source.clone(), source_custody)];
        let artifact = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(stopped()),
            result = with_terminal_grant(
                self.stores.custody.as_deref(),
                terminal,
                self.export,
                &source_custody,
                sources,
                self.stores.artifacts.put_archive_file_with_custody(self.run.id, "application/warc", shard.path(),
                    self.export.config.max_record_bytes.saturating_add(131_072), &source_custody),
            ) => result??,
        };
        crawlx_storage::chaos::pause("archive.after_shard_commit").await;
        let mut record = ArchiveRecordV1::resource(
            self.export.id,
            input.ordinal,
            summary.id,
            artifact,
            summary.offset,
            summary.length,
            summary.payload_digest,
            input.target.into(),
            input.facts,
            input.mime.into(),
        );
        record.custody = source_custody;
        if source_custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
            record.source_artifact = Some(source.clone());
        }
        record.payload_key = payload_key;
        record.dependency = baseline.map(|source| {
            crawlx_core::archive_catalog::ArchiveDependencyV1::new(source.export, source.ordinal)
        });
        let history = input
            .history_source
            .map(|(request, page)| super::history::captured_history(self.run, request, page, &record))
            .transpose()?
            .flatten();
        self.stores
            .archives
            .commit_record(
                self.run.tenant,
                self.export.fence,
                &record,
                history.as_ref(),
                self.clock.now(),
            )
            .await?;
        self.committed_bytes = self
            .committed_bytes
            .checked_add(record.length)
            .ok_or_else(|| WorkerError::Config("archive byte counter overflow".into()))?;
        Ok(RecordOutcome::Committed)
    }
}
