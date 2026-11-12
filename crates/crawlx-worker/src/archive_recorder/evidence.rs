//! Archive browser evidence by retained references, preserving phase and epoch provenance.

use super::resource::{RecordOutcome, Recorder, ResourceInput};
use super::{approved_target, stopped};
use crate::browser_evidence::{BlockedEvent, EvidenceEvent, EvidencePhase, BLOCKED_EVENT, EVENT};
use crate::WorkerError;
use crawlx_core::archive::{
    ArchiveCaptureFactsV1, ArchiveManifestV1, ArchiveOmissionV1, ArchiveRepresentation,
};
use crawlx_core::block_rules::BlockRuleKind;
use crawlx_core::browser_capture::{CaptureCompleteness, CaptureKind};

/// Convert opt-in browser evidence events without refetching any live resource, and turn every
/// resource the run's block rules blocked into an omission that names the rule kind.
pub(super) async fn record(
    recorder: &mut Recorder<'_>,
    manifest: &mut ArchiveManifestV1,
    committed_records: &mut u64,
) -> Result<(), WorkerError> {
    let durable = recorder.run.config.capture.browser.durable();
    let blocked_rules = recorder.run.config.dynamic.block_rules.is_some();
    if !durable && !blocked_rules {
        return Ok(());
    }
    let mut after = 0;
    let mut scanned = 0u32;
    let mut budget_noted = false;
    let mut listed = BlockedListing::default();
    loop {
        if recorder.cancel.is_cancelled() {
            return Err(stopped());
        }
        let events = recorder
            .stores
            .events
            .list_after(recorder.run.id, after, 1)
            .await?;
        let Some(event) = events.into_iter().next() else {
            break;
        };
        after = event.seq;
        if event.kind == BLOCKED_EVENT {
            if blocked_rules {
                listed.record(
                    manifest,
                    event.seq,
                    event.payload,
                    recorder.export.config.max_records,
                );
            }
            continue;
        }
        if event.kind != EVENT || !durable {
            continue;
        }
        if *committed_records >= u64::from(recorder.export.config.max_records)
            || scanned >= recorder.export.config.max_records
        {
            if !budget_noted {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    "browser_evidence",
                    "remaining_resources_not_evaluated_record_budget",
                ));
                budget_noted = true;
            }
            if !blocked_rules {
                break;
            }
            // only blocked-resource events can still add anything
            continue;
        }
        scanned = scanned.saturating_add(1);
        let source_event = format!("browser_evidence:{}", event.seq);
        let evidence = match serde_json::from_value::<EvidenceEvent>(event.payload) {
            Ok(evidence) if evidence.version == 1 => evidence,
            _ => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    source_event,
                    "browser_evidence_descriptor_unavailable",
                ));
                continue;
            }
        };
        let Some(capture) = evidence.capture else {
            manifest.omissions.push(ArchiveOmissionV1::new(
                source_event,
                "browser_evidence_capture_unavailable",
            ));
            continue;
        };
        if evidence.unavailable.is_some() || capture.descriptor.kind != evidence.requested_kind {
            manifest.omissions.push(ArchiveOmissionV1::new(
                source_event,
                "browser_evidence_descriptor_inconsistent",
            ));
            continue;
        }
        let target = match approved_target(&capture.descriptor.source_url) {
            Ok(target) => target,
            Err(_) => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    source_event,
                    "target_privacy_approval_failed",
                ));
                continue;
            }
        };
        let phase = match evidence.phase {
            EvidencePhase::Initial => "initial",
            EvidencePhase::Final => "final",
        };
        let representation = match capture.descriptor.kind {
            CaptureKind::Text => ArchiveRepresentation::ExtractedText,
            CaptureKind::Screenshot => ArchiveRepresentation::Screenshot,
            CaptureKind::Mhtml | CaptureKind::Pdf | CaptureKind::Download => {
                ArchiveRepresentation::ProtocolResource
            }
            _ => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    source_event,
                    "unsupported_browser_evidence_kind",
                ));
                continue;
            }
        };
        let mut facts = ArchiveCaptureFactsV1::retained(
            &source_event,
            evidence.captured_at,
            representation,
            format!("browser_evidence_{phase}"),
        );
        facts.body_state = match capture.completeness {
            CaptureCompleteness::Complete if !capture.descriptor.truncated => "complete",
            CaptureCompleteness::Clipped => "prefix",
            _ => "unknown",
        }
        .into();
        facts.redaction_revision = "browser-evidence-v1".into();
        facts.transformations = vec![
            "browser_generated_not_original_wire".into(),
            "typed_artifact_policy_approved".into(),
            format!("phase:{phase}"),
            format!("session:{}", evidence.session),
            format!("observation:{}", evidence.observation),
            format!(
                "epoch:{}:{}:{}",
                evidence.epoch.navigation_seq, evidence.epoch.document_seq, evidence.epoch.mutation_seq
            ),
        ];
        // Separate namespace from page/traffic ordinals; event order is immutable on replay.
        let ordinal = (1u64 << 62)
            .checked_add(event.seq)
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| WorkerError::Config("archive browser evidence ordinal overflow".into()))?;
        match recorder
            .record(ResourceInput {
                ordinal,
                source: Some(&capture.artifact),
                target: &target,
                mime: &capture.descriptor.content_type,
                facts,
                history_source: None,
                capture: Some(&capture),
            })
            .await?
        {
            RecordOutcome::Existing | RecordOutcome::Committed => {
                *committed_records = committed_records.saturating_add(1);
            }
            RecordOutcome::Omitted(reason) => {
                manifest
                    .omissions
                    .push(ArchiveOmissionV1::new(source_event, reason));
            }
        }
    }
    Ok(())
}

/// The blocked resources already listed as omissions, so a resource blocked on several pages of a
/// run is listed once per rule kind, and the listing stays inside the record budget.
#[derive(Default)]
struct BlockedListing {
    seen: std::collections::BTreeSet<(BlockRuleKind, String)>,
    full: bool,
}

impl BlockedListing {
    fn record(
        &mut self,
        manifest: &mut ArchiveManifestV1,
        seq: u64,
        payload: serde_json::Value,
        max_listed: u32,
    ) {
        let source = format!("browser_blocked:{seq}");
        let event = match serde_json::from_value::<BlockedEvent>(payload) {
            Ok(event) if event.version == 1 => event,
            _ => {
                manifest.omissions.push(ArchiveOmissionV1::new(
                    source,
                    "blocked_resources_descriptor_unavailable",
                ));
                return;
            }
        };
        let limit = usize::try_from(max_listed).unwrap_or(usize::MAX);
        for (index, resource) in event.blocked.resources.iter().enumerate() {
            let key = (resource.kind, resource.url.clone());
            if self.seen.contains(&key) {
                continue;
            }
            if self.seen.len() >= limit {
                if !self.full {
                    self.full = true;
                    manifest.omissions.push(ArchiveOmissionV1::new(
                        "browser_blocked",
                        "remaining_blocked_resources_not_listed_record_budget",
                    ));
                }
                return;
            }
            self.seen.insert(key);
            let mut omission =
                ArchiveOmissionV1::new(format!("{source}:{index}"), resource.kind.omission_reason());
            if let Ok(target) = approved_target(&resource.url) {
                omission = omission.with_target(target);
            }
            manifest.omissions.push(omission);
        }
        if event.blocked.dropped > 0 {
            manifest.omissions.push(ArchiveOmissionV1::new(
                source,
                "blocked_resources_beyond_session_log_not_listed",
            ));
        }
    }
}
