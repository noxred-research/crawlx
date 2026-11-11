//! Opt-in, run-scoped browser evidence retention and observation provenance.

use crate::{RunContext, SessionHandle, WorkerError};
use async_trait::async_trait;
use crawlx_core::browser_capture::{
    BrowserCaptureSink, BrowserEvidenceConfig, CaptureArtifact, CaptureDescriptor, CaptureKind, CaptureSpec,
};
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::config::RetentionMode;
use crawlx_core::error::{Classify, ErrorClass};
use crawlx_core::observation::ObservationBundle;
use crawlx_core::page_op::{PageOp, PageOpResult, PdfSpec, ShotSpec};
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::request_controls::RequestControls;
use crawlx_core::secret::{ArtifactSink, Redacted, Redactor};
use crawlx_core::{ArtifactRef, CrawlRunId, StoreError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PIXELS: u64 = 16 * 1024 * 1024;
pub(crate) const EVENT: &str = "browser.evidence";

/// Observation boundary that produced a resource, not an inferred page lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidencePhase {
    Initial,
    Final,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Unavailable {
    PolicyDenied,
    BrowserOperationFailed,
    UnexpectedResult,
}

/// Only approved descriptors and references enter the event log; never raw capture bytes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceEvent {
    pub version: u16,
    pub phase: EvidencePhase,
    pub session: crawlx_core::SessionId,
    pub epoch: crawlx_core::ObservationEpoch,
    pub observation: u64,
    pub captured_at: crawlx_core::Timestamp,
    pub requested_kind: CaptureKind,
    pub capture: Option<CaptureArtifact>,
    pub unavailable: Option<Unavailable>,
}

struct EvidenceSink {
    run: CrawlRunId,
    artifacts: Arc<dyn ArtifactStore>,
    runs: Arc<dyn RunRepo>,
    controls: RequestControls,
    retention: RetentionMode,
    config: BrowserEvidenceConfig,
    captcha: CaptchaSecrets,
    key: [u8; 32],
}

impl std::fmt::Debug for EvidenceSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceSink")
            .field("run", &self.run)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

/// Build the same run-scoped policy authority for every browser context.
pub(crate) fn sink(rc: &RunContext) -> Arc<dyn BrowserCaptureSink> {
    Arc::new(EvidenceSink {
        run: rc.run,
        artifacts: Arc::clone(&rc.stores.artifacts),
        runs: Arc::clone(&rc.stores.runs),
        controls: rc.controls.clone(),
        retention: rc.crawl.retention.mode,
        config: rc.crawl.capture.browser.clone(),
        captcha: rc.captcha_secrets.clone(),
        key: rc.seed.derive("traffic-redaction", &[rc.run.0.as_bytes()]),
    })
}

impl EvidenceSink {
    fn permits(&self, kind: CaptureKind) -> Result<bool, StoreError> {
        if self.retention == RetentionMode::Zdr || self.controls.secret_values().next().is_some() {
            return Ok(false);
        }
        if self
            .captcha
            .has_values()
            .map_err(|_| StoreError::RetentionDenied("browser evidence secret registry unavailable".into()))?
        {
            return Ok(false);
        }
        let config = &self.config;
        Ok(match kind {
            CaptureKind::Mhtml => config.mhtml,
            CaptureKind::Pdf => config.pdf,
            CaptureKind::Text | CaptureKind::Screenshot => config.phase_resources,
            CaptureKind::Download => !config.downloads.is_empty(),
            _ => false,
        })
    }

    fn safe_source(&self, source: &[u8]) -> Result<bool, StoreError> {
        if source.len() > MAX_SOURCE_BYTES {
            return Ok(false);
        }
        crate::capture::check_run_secrets(source, &self.controls, Some(&self.captcha))?;
        let Ok(text) = std::str::from_utf8(source) else {
            return Ok(false);
        };
        if !crawlx_extract::secrets::detect(&self.key, &[], text).is_empty() {
            return Ok(false);
        }
        let approved = Redactor::new().redact_artifact(source)?;
        Ok(approved.as_ref() == source)
    }
}

#[async_trait]
impl BrowserCaptureSink for EvidenceSink {
    async fn authorize(&self, kind: CaptureKind) -> Result<bool, StoreError> {
        self.permits(kind)
    }

    async fn authorize_source(&self, source: &[u8]) -> Result<bool, StoreError> {
        if self.retention == RetentionMode::Zdr
            || !self.config.durable()
            || self.controls.secret_values().next().is_some()
            || self.captcha.has_values().map_err(|_| {
                StoreError::RetentionDenied("browser evidence secret registry unavailable".into())
            })?
        {
            return Ok(false);
        }
        self.safe_source(source)
    }

    async fn store(
        &self,
        descriptor: &CaptureDescriptor,
        bytes: &Redacted<Vec<u8>>,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        if !self.permits(descriptor.kind)?
            || u64::try_from(bytes.as_ref().len()).map_or(true, |len| len > MAX_BYTES)
            || descriptor.content_type.len() > 256
            || descriptor.content_type.chars().any(char::is_control)
            || descriptor.source_url.len() > 8192
            || !self.safe_source(descriptor.source_url.as_bytes())?
            || descriptor.filename.as_deref().is_some_and(|name| {
                name.is_empty()
                    || name.len() > 255
                    || name.contains(['/', '\\'])
                    || name.chars().any(char::is_control)
            })
        {
            return Ok(None);
        }
        if let Some(filename) = &descriptor.filename {
            if !self.safe_source(filename.as_bytes())? {
                return Ok(None);
            }
        }
        if descriptor.kind == CaptureKind::Download
            && !self.config.downloads.iter().any(|request| {
                request.url.as_str() == descriptor.source_url
                    && u64::try_from(bytes.as_ref().len()).is_ok_and(|len| len <= request.max_bytes)
            })
        {
            return Ok(None);
        }
        let mime = descriptor.content_type.split(';').next().unwrap_or("").trim();
        let supported = match descriptor.kind {
            CaptureKind::Text => mime == "text/plain",
            CaptureKind::Mhtml => mime == "multipart/related",
            CaptureKind::Screenshot => matches!(mime, "image/png" | "image/jpeg"),
            CaptureKind::Pdf => mime == "application/pdf",
            CaptureKind::Download => !mime.is_empty(),
            _ => false,
        };
        if !supported {
            return Ok(None);
        }
        crate::capture::check_run_secrets(bytes.as_ref(), &self.controls, Some(&self.captcha))?;
        let approved = if descriptor.kind == CaptureKind::Text {
            let scrubbed = crate::capture::scrub_admitted(bytes.as_ref(), self.controls.secret_values())?;
            let scrubbed: &[u8] = scrubbed.value();
            Redactor::new().redact_artifact(scrubbed)?
        } else {
            // Never rewrite encoded images, multipart snapshots, PDF or attachments.
            Redactor::new().verify_binary(bytes.as_ref())?
        };
        // The browser reports byte count and geometry for its approved representation.
        // A rewrite would invalidate that descriptor; refuse instead of mislabelling bytes.
        if approved.as_ref() != bytes.as_ref() {
            return Ok(None);
        }
        crate::capture::check_run_secrets(approved.as_ref(), &self.controls, Some(&self.captcha))?;
        // Recheck the live registry immediately before crossing the typed storage boundary.
        if !self.permits(descriptor.kind)? {
            return Ok(None);
        }
        let run = self.runs.get(self.run).await?;
        if run.config.retention.mode == RetentionMode::Zdr {
            return Ok(None);
        }
        let class = if descriptor.kind == CaptureKind::Text {
            Sensitivity::Content
        } else {
            Sensitivity::Sensitive
        };
        let days = if descriptor.kind == CaptureKind::Screenshot {
            run.config.retention.days.min(3)
        } else {
            run.config.retention.days
        };
        let expires_at = run
            .created_at
            .checked_add_signed(chrono::Duration::days(i64::from(days)))
            .ok_or_else(|| StoreError::RetentionDenied("browser evidence deadline unavailable".into()))?;
        if !self.permits(descriptor.kind)? {
            return Ok(None);
        }
        ArtifactSink::over(self.artifacts.as_ref())
            .put_until(self.run, class, &descriptor.content_type, &approved, expires_at)
            .await
            .map(Some)
    }
}

/// Capture explicitly requested resources at a real observation boundary.
///
/// Browser failures become unavailable events. Event storage failures propagate.
///
/// # Errors
/// Returns event persistence failures; capture failures remain typed unavailable outcomes.
pub(crate) async fn observe(
    handle: &SessionHandle,
    rc: &RunContext,
    bundle: &ObservationBundle,
    phase: EvidencePhase,
) -> Result<(), WorkerError> {
    let config = &rc.crawl.capture.browser;
    if config.phase_resources {
        capture(
            handle,
            rc,
            bundle,
            phase,
            CaptureKind::Text,
            PageOp::Capture(CaptureSpec::Text { max_bytes: MAX_BYTES }),
        )
        .await?;
        capture(
            handle,
            rc,
            bundle,
            phase,
            CaptureKind::Screenshot,
            PageOp::Capture(CaptureSpec::Screenshot {
                shot: ShotSpec::default(),
                max_bytes: MAX_BYTES,
                max_pixels: MAX_PIXELS,
            }),
        )
        .await?;
    }
    if config.mhtml {
        capture(
            handle,
            rc,
            bundle,
            phase,
            CaptureKind::Mhtml,
            PageOp::Capture(CaptureSpec::Mhtml { max_bytes: MAX_BYTES }),
        )
        .await?;
    }
    if config.pdf {
        capture(
            handle,
            rc,
            bundle,
            phase,
            CaptureKind::Pdf,
            PageOp::Capture(CaptureSpec::Pdf {
                spec: PdfSpec {
                    format: None,
                    landscape: false,
                    scale: 1.0,
                },
                max_bytes: MAX_BYTES,
            }),
        )
        .await?;
    }
    // Explicit attachment requests run once, after the session's final observation.
    if phase == EvidencePhase::Final {
        for download in &config.downloads {
            capture(
                handle,
                rc,
                bundle,
                phase,
                CaptureKind::Download,
                PageOp::Download(download.clone()),
            )
            .await?;
        }
    }
    Ok(())
}

async fn capture(
    handle: &SessionHandle,
    rc: &RunContext,
    bundle: &ObservationBundle,
    phase: EvidencePhase,
    kind: CaptureKind,
    operation: PageOp,
) -> Result<(), WorkerError> {
    let policy = sink(rc);
    let (capture, unavailable) = match policy.authorize(kind).await {
        Ok(true) => match handle.page_op(operation).await {
            Ok(PageOpResult::Capture(capture)) if capture.descriptor.kind == kind => (Some(capture), None),
            Ok(_) => (None, Some(Unavailable::UnexpectedResult)),
            Err(error) if error.class() == ErrorClass::PolicyDenied => {
                (None, Some(Unavailable::PolicyDenied))
            }
            Err(_) => (None, Some(Unavailable::BrowserOperationFailed)),
        },
        Ok(false) | Err(_) => (None, Some(Unavailable::PolicyDenied)),
    };
    let event = EvidenceEvent {
        version: 1,
        phase,
        session: bundle.session_id,
        epoch: bundle.epoch,
        observation: bundle.seq,
        captured_at: rc.clock.now(),
        requested_kind: kind,
        capture,
        unavailable,
    };
    let payload = serde_json::to_value(event)
        .map_err(|_| StoreError::Serialization("browser evidence event encoding failed".into()))?;
    rc.stores.events.append(rc.run, EVENT, payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn policy_refuses_missing_opt_in_zdr_controls_live_captcha_and_oversize_source() {
        let dir = tempfile::tempdir().unwrap();
        let stores = crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let mut policy = EvidenceSink {
            run: CrawlRunId::new(),
            artifacts: Arc::clone(&stores.artifacts),
            runs: Arc::clone(&stores.runs),
            controls: RequestControls::default(),
            retention: RetentionMode::Standard,
            config: BrowserEvidenceConfig::default(),
            captcha: CaptchaSecrets::default(),
            key: [3; 32],
        };
        assert!(!policy.authorize(CaptureKind::Text).await.unwrap());
        assert!(!policy.authorize_source(b"<h1>ordinary</h1>").await.unwrap());
        let mut config = BrowserEvidenceConfig::default();
        config.phase_resources = true;
        policy.config = config;
        assert!(policy.authorize(CaptureKind::Text).await.unwrap());
        assert!(policy.authorize_source(b"<h1>ordinary</h1>").await.unwrap());
        assert!(!policy.authorize(CaptureKind::Pdf).await.unwrap());
        assert!(!policy.authorize(CaptureKind::Mhtml).await.unwrap());
        assert!(!policy.authorize(CaptureKind::Download).await.unwrap());
        assert!(!policy
            .authorize_source(&vec![b'a'; MAX_SOURCE_BYTES + 1])
            .await
            .unwrap());
        assert!(!policy
            .authorize_source(b"password=unregistered-private-value")
            .await
            .unwrap());
        policy.retention = RetentionMode::Zdr;
        assert!(!policy.authorize(CaptureKind::Text).await.unwrap());
        assert!(!policy.authorize_source(b"ordinary").await.unwrap());
        policy.retention = RetentionMode::Standard;
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch
            .extra_headers
            .insert("x-api-key", "opaque-evidence-control-q7m2");
        policy.controls = RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        assert!(!policy.authorize(CaptureKind::Screenshot).await.unwrap());
        assert!(!policy.authorize_source(b"ordinary").await.unwrap());
        policy.controls = RequestControls::default();
        let registry = policy.captcha.clone();
        registry
            .register(crawlx_core::SecretOr::secret("live-evidence-captcha-q7m2".into()))
            .unwrap();
        assert!(!policy.authorize(CaptureKind::Screenshot).await.unwrap());
        assert!(!policy.authorize_source(b"ordinary").await.unwrap());
    }
}
