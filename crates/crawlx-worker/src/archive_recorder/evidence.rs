//! Archive browser evidence by retained references, preserving phase and epoch provenance.

use super::resource::{RecordOutcome, Recorder, ResourceInput};
use super::{approved_target, stopped};
use crate::browser_evidence::{EvidenceEvent, EvidencePhase, EVENT};
use crate::WorkerError;
use crawlx_core::archive::{
    ArchiveCaptureFactsV1, ArchiveManifestV1, ArchiveOmissionV1, ArchiveRepresentation,
};
use crawlx_core::browser_capture::{CaptureCompleteness, CaptureKind};

/// Convert opt-in browser evidence events without refetching any live resource.
pub(super) async fn record(
    recorder: &mut Recorder<'_>,
    manifest: &mut ArchiveManifestV1,
    committed_records: &mut u64,
) -> Result<(), WorkerError> {
    if !recorder.run.config.capture.browser.durable() {
        return Ok(());
    }
    let mut after = 0;
    let mut scanned = 0u32;
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
        if event.kind != EVENT {
            continue;
        }
        if *committed_records >= u64::from(recorder.export.config.max_records)
            || scanned >= recorder.export.config.max_records
        {
            manifest.omissions.push(ArchiveOmissionV1::new(
                "browser_evidence",
                "remaining_resources_not_evaluated_record_budget",
            ));
            break;
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
