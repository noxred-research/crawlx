//! Offline reparse of exact retained acquisition bytes, never a cache-triggered fetch.
//!
//! Run, committed request principal, source representation, current custody and original
//! truncation are checked before the bounded artifact read. The API holds no fetcher/browser.
//! Native blocking parsers are not advertised as preemptible or allocation-fallible.

use std::sync::Arc;

use crawlx_core::{
    acquisition::AcquisitionResultV1,
    config::RetentionMode,
    extraction::ExtractionPolicyV1,
    hash::Digest,
    repo::{ArtifactStore, FrontierRepo, PageRepo, RunRepo, Sensitivity},
    time::Clock,
    ArtifactRef, CrawlRunId, StoreError, TenantId,
};
use crawlx_extract::{
    pipeline::{ParserPipeline, PipelineError, PipelineInput, PipelineOutput},
    ExtractOptions,
};
use tokio_util::sync::CancellationToken;

/// Retained representation to parse. Cleaned HTML/Markdown are not original source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetainedRepresentation {
    /// Retention-approved transport-decoded wire body.
    WireBody,
    /// Retention-approved settled serialized DOM.
    RenderedDom,
}

/// Authenticated caller scope. Construct only after the normal tenant authorization check.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReparseIntent {
    /// Existing owning tenant.
    pub tenant: TenantId,
    /// Original run, not a new retention window.
    pub run: CrawlRunId,
    /// Existing committed frontier request.
    pub frontier_id: i64,
    /// Original admitted principal; never inferred from source content.
    pub principal: String,
    /// Exact original representation to use.
    pub representation: RetainedRepresentation,
}

impl ReparseIntent {
    /// Bind an offline request to its original tenant, run, principal and representation.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        frontier_id: i64,
        principal: String,
        representation: RetainedRepresentation,
    ) -> Self {
        Self {
            tenant,
            run,
            frontier_id,
            principal,
            representation,
        }
    }
}

/// Original-run privacy projector. `None` retains an unchanged safe string.
/// Construct from trusted privacy policy, not from retained source metadata.
pub type ReparsePrivacy = dyn Fn(&str) -> Result<Option<String>, StoreError> + Send + Sync;

/// Build the projector from original operational policy and an authority-issued secret snapshot.
/// This never resolves credential references or loads a remote model. The caller must obtain
/// `snapshot` from the original run authority; an empty invented registry is not permitted.
///
/// # Errors
/// Refuses ZDR. Later registry/scanner failures propagate through the fallible projector.
pub fn privacy_from_original_run(
    run: &crawlx_core::repo::CrawlRun,
    snapshot: &crawlx_core::custody::RunSecretSnapshot,
) -> Result<Arc<ReparsePrivacy>, ReparseError> {
    if run.config.retention.mode == RetentionMode::Zdr {
        return Err(ReparseError::Retention);
    }
    if snapshot.version.tenant != run.tenant || snapshot.version.run != run.id {
        return Err(ReparseError::Scope);
    }
    let pii = run
        .config
        .scrape
        .as_ref()
        .and_then(|job| job.options.redact_pii.as_ref())
        .map(crate::scrape::guard::redact_options);
    let secrets = snapshot.secrets.clone();
    Ok(Arc::new(move |source| {
        let source = secrets
            .redact(source)
            .map_err(|_| StoreError::RetentionDenied("original secret registry unavailable".into()))?;
        let source = crawlx_core::secret::Redactor::new()
            .redact_text(&source)
            .into_inner();
        let source = if let Some(options) = &pii {
            crawlx_extract::parse::redact::redact(&source, options).text
        } else {
            source
        };
        Ok(Some(source))
    }))
}

/// Dependencies deliberately exclude acquisition, DNS and browser interfaces.
pub struct ReparseServices<'a> {
    /// Tenant/retention authority.
    pub runs: &'a dyn RunRepo,
    /// Committed source binding.
    pub pages: &'a dyn PageRepo,
    /// Original principal binding.
    pub frontier: &'a dyn FrontierRepo,
    /// Typed custody-aware bounded local artifact reader.
    pub artifacts: &'a dyn ArtifactStore,
    /// Injected expiry clock.
    pub clock: &'a dyn Clock,
}

/// New parser result alongside immutable original-source provenance.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReparseOutput {
    /// Original retained artifact, not a newly fetched body.
    pub source: ArtifactRef,
    /// Original source representation.
    pub representation: RetainedRepresentation,
    /// Known old parser output version; absent means it was not recorded.
    pub previous_record_version: Option<String>,
    /// New policy digest, also present on output.
    pub parser_digest: Digest,
    /// New parsed content. Persist only through the normal original-run retention boundary.
    pub output: PipelineOutput,
}

/// Reparse refusal. Source loss and truncation are not treated as empty success.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReparseError {
    /// Cross-tenant, wrong principal or unsupported request binding.
    #[error("retained source scope mismatch")]
    Scope,
    /// ZDR cannot recover retained source bytes.
    #[error("retained reparse denied by retention policy")]
    Retention,
    /// Source/page or exact representation was never retained or has been erased.
    #[error("retained reparse source unavailable")]
    SourceUnavailable,
    /// Original source is incomplete; never silently reparse a prefix as a full document.
    #[error("retained reparse source was truncated")]
    Truncated,
    /// Current custody, fixity, deadline or repository validation failed.
    #[error("retained source validation failed")]
    Store(#[source] StoreError),
    /// Cooperative cancellation; a running native blocking parser may still be dropping bytes.
    #[error("retained reparse cancelled")]
    Cancelled,
    /// New parser refused the source.
    #[error("retained source parsing failed")]
    Parse(#[source] PipelineError),
    /// Blocking worker did not complete normally.
    #[error("retained parser task failed")]
    Task(#[source] tokio::task::JoinError),
}

fn source_from_acquisition(
    acquisition: &AcquisitionResultV1,
    intent: &ReparseIntent,
) -> Result<ArtifactRef, ReparseError> {
    if acquisition.schema_version != 1 || acquisition.run != intent.run || acquisition.tenant != intent.tenant
    {
        return Err(ReparseError::Scope);
    }
    if acquisition.truncated {
        return Err(ReparseError::Truncated);
    }
    match intent.representation {
        RetainedRepresentation::WireBody => acquisition.wire_body.clone(),
        RetainedRepresentation::RenderedDom => acquisition.rendered_dom.clone(),
    }
    .ok_or(ReparseError::SourceUnavailable)
}

impl ReparseServices<'_> {
    /// Validate original scope, read retained bytes under current custody, then run new parser.
    /// No links are followed and OCR is disabled. Cancellation does not detach owned input
    /// from its blocking closure: memory stays owned there until the parser actually exits.
    ///
    /// # Errors
    /// Refuses foreign principal/tenant, ZDR, missing/expired/truncated sources, cancellation,
    /// custody/fixity/size failures and native parser failures. No failure falls back to network.
    pub async fn run(
        &self,
        intent: &ReparseIntent,
        pipeline: ParserPipeline,
        privacy: Arc<ReparsePrivacy>,
        cancel: &CancellationToken,
    ) -> Result<ReparseOutput, ReparseError> {
        if cancel.is_cancelled() {
            return Err(ReparseError::Cancelled);
        }
        let run = self
            .runs
            .get_metadata(intent.run)
            .await
            .map_err(ReparseError::Store)?;
        if run.tenant != intent.tenant || intent.frontier_id <= 0 {
            return Err(ReparseError::Scope);
        }
        if run.retention.mode == RetentionMode::Zdr {
            return Err(ReparseError::Retention);
        }
        let request = self
            .frontier
            .get_request(intent.run, intent.frontier_id)
            .await
            .map_err(ReparseError::Store)?;
        if request.principal != intent.principal {
            return Err(ReparseError::Scope);
        }
        let page = self
            .pages
            .get_committed(intent.run, intent.frontier_id)
            .await
            .map_err(ReparseError::Store)?
            .ok_or(ReparseError::SourceUnavailable)?;
        if page.run != intent.run || page.frontier_id != intent.frontier_id {
            return Err(ReparseError::Scope);
        }
        let acquisition: AcquisitionResultV1 = serde_json::from_value(
            page.metadata
                .get("acquisition")
                .cloned()
                .ok_or(ReparseError::SourceUnavailable)?,
        )
        .map_err(|_| ReparseError::SourceUnavailable)?;
        let source = source_from_acquisition(&acquisition, intent)?;
        let limit = pipeline.spec().limits.max_input_bytes;
        let custody = self
            .artifacts
            .archive_custody(intent.tenant, intent.run, &source, limit)
            .await
            .map_err(ReparseError::Store)?;
        custody.validate(self.clock.now()).map_err(ReparseError::Store)?;
        let bytes = match custody.sensitivity {
            Sensitivity::Content => {
                self.artifacts
                    .read_archive_content(intent.tenant, intent.run, &source, limit)
                    .await
            }
            Sensitivity::Sensitive => {
                self.artifacts
                    .read_archive_sensitive(intent.tenant, intent.run, &source, &custody, limit)
                    .await
            }
            _ => return Err(ReparseError::Retention),
        }
        .map_err(ReparseError::Store)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
            return Err(ReparseError::SourceUnavailable);
        }
        custody.validate(self.clock.now()).map_err(ReparseError::Store)?;
        if cancel.is_cancelled() {
            return Err(ReparseError::Cancelled);
        }
        let previous_record_version = page
            .metadata
            .get("parserRecordVersion")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let url = page.url.url;
        let content_type = match intent.representation {
            RetainedRepresentation::RenderedDom => Some("text/html; charset=utf-8".to_owned()),
            RetainedRepresentation::WireBody => page.content_type,
        };
        let parser_digest = *pipeline.digest();
        let task_cancel = cancel.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            if task_cancel.is_cancelled() {
                return Err(ReparseError::Cancelled);
            }
            let options = ExtractOptions {
                content: Some(ExtractionPolicyV1::default()),
                ..ExtractOptions::default()
            };
            let projection_error = std::sync::Mutex::new(None);
            let project = |source: &str| match privacy(source) {
                Ok(value) => value,
                Err(error) => {
                    if let Ok(mut failure) = projection_error.lock() {
                        *failure = Some(error);
                    }
                    Some(String::new())
                }
            };
            let mut input = PipelineInput::new(&bytes)
                .with_page_url(&url)
                .with_page_options(&options)
                .with_projection(&project);
            if let Some(content_type) = &content_type {
                input = input.with_content_type(content_type);
            }
            let output = pipeline.run(input).map_err(ReparseError::Parse)?;
            if let Some(error) = projection_error.into_inner().map_err(|_| {
                ReparseError::Store(StoreError::RetentionDenied(
                    "reparse privacy projection failed".into(),
                ))
            })? {
                return Err(ReparseError::Store(error));
            }
            if task_cancel.is_cancelled() {
                return Err(ReparseError::Cancelled);
            }
            Ok(output)
        });
        let output = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                task.abort();
                return Err(ReparseError::Cancelled);
            }
            result = &mut task => result.map_err(ReparseError::Task)??,
        };
        // Recheck current custody after CPU work; expiry does not become a new retention grant.
        self.artifacts
            .archive_custody(intent.tenant, intent.run, &source, limit)
            .await
            .map_err(ReparseError::Store)?
            .validate(self.clock.now())
            .map_err(ReparseError::Store)?;
        Ok(ReparseOutput {
            source,
            representation: intent.representation,
            previous_record_version,
            parser_digest,
            output,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::{
        acquisition::BackendCapabilitiesV1, archive_catalog::ArchiveCustodyV1, custody::RunSecretSnapshot,
    };
    use uuid::Uuid;

    fn intent() -> ReparseIntent {
        ReparseIntent::new(
            TenantId(Uuid::from_u128(1)),
            CrawlRunId(Uuid::from_u128(2)),
            7,
            "anonymous".into(),
            RetainedRepresentation::WireBody,
        )
    }

    fn acquisition(intent: &ReparseIntent) -> AcquisitionResultV1 {
        AcquisitionResultV1::new(
            intent.run,
            intent.tenant,
            url::Url::parse("https://example.test/").unwrap(),
            Digest::of("request", b"7"),
            BackendCapabilitiesV1::native_http("native_fixture", "1"),
        )
    }

    #[test]
    fn original_source_scope_loss_and_truncation_refuse_without_acquisition() {
        let intent = intent();
        let mut acquisition = acquisition(&intent);
        assert!(matches!(
            source_from_acquisition(&acquisition, &intent),
            Err(ReparseError::SourceUnavailable)
        ));
        let source = ArtifactRef {
            id: crawlx_core::ArtifactId(Uuid::from_u128(3)),
            digest: Digest::of("source", b"retained"),
        };
        acquisition.wire_body = Some(source.clone());
        assert_eq!(source_from_acquisition(&acquisition, &intent).unwrap(), source);
        acquisition.truncated = true;
        assert!(matches!(
            source_from_acquisition(&acquisition, &intent),
            Err(ReparseError::Truncated)
        ));
        acquisition.truncated = false;
        acquisition.tenant = TenantId(Uuid::from_u128(99));
        assert!(matches!(
            source_from_acquisition(&acquisition, &intent),
            Err(ReparseError::Scope)
        ));
        let expiry = chrono::DateTime::from_timestamp(100, 0).unwrap();
        assert!(ArchiveCustodyV1::sensitive(expiry).validate(expiry).is_err());
    }

    #[test]
    fn original_snapshot_projector_redacts_and_zdr_refuses() {
        let intent = intent();
        let config = crawlx_core::config::CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        let mut run = crawlx_core::repo::CrawlRun {
            id: intent.run,
            tenant: intent.tenant,
            status: serde_json::from_str("\"running\"").unwrap(),
            terminal_reason: None,
            config,
            config_digest: Digest::of("config", b"fixture"),
            seed: crawlx_core::seed::CrawlSeed(1),
            policy_version: 1,
            counters: Default::default(),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            started_at: None,
            finished_at: None,
            trace_id: None,
        };
        let epoch = crawlx_core::custody::SecretEpoch::new(intent.tenant, intent.run, Uuid::from_u128(5), 1);
        let secrets = crawlx_core::captcha::CaptchaSecrets::default();
        secrets
            .register(crawlx_core::SecretOr::secret(
                "original-registry-canary-q7v9".to_owned(),
            ))
            .unwrap();
        let snapshot = RunSecretSnapshot::new(epoch, secrets);
        let project = privacy_from_original_run(&run, &snapshot).unwrap();
        let output = project("source original-registry-canary-q7v9").unwrap().unwrap();
        assert!(!output.contains("original-registry-canary-q7v9"));
        run.config.retention.mode = RetentionMode::Zdr;
        assert!(matches!(
            privacy_from_original_run(&run, &snapshot),
            Err(ReparseError::Retention)
        ));
    }
}
