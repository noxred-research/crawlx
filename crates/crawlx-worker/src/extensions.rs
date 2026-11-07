//! Reviewed native lifecycle execution. No host callbacks, raw page handles or eval.
//!
//! Replacement requests are proposals only. Callers must reenter native admission
//! and append a new identity, never fetch a mutated already-leased request.

use crate::runtime::CpuPool;
use crawlx_core::{
    extensions::{
        document_item, json_size, ExtensionConfigV1, ExtensionError, ExtensionFailurePolicyV1,
        ExtensionPipelineV1, ExtensionStageV1, HandlerV1, MAX_EXTENSION_BYTES,
    },
    extraction::{DocumentEnvelopeV1, QualityStatusV1},
    request::RequestEnvelopeV1,
};
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Typed preparation result. This is not network or browser authority.
#[derive(Debug)]
#[non_exhaustive]
pub struct RequestPreparationV1 {
    /// Replacement proposal; append only after full native admission.
    pub replacement: Option<RequestEnvelopeV1>,
    /// Explicit label handler, distinct from learned URL route templates.
    pub route: HandlerV1,
}
/// One request's bounded lifecycle. Drop releases all owned transient state.
#[derive(Debug)]
pub struct RequestLifecycle {
    pipeline: ExtensionPipelineV1,
    entered: Vec<String>,
    cleanup: Vec<String>,
    closed: bool,
    prepared: bool,
    policy_denied: bool,
}
impl RequestLifecycle {
    /// Resolve compiled descriptors before any work.
    ///
    /// # Errors
    /// Refuses unknown registry versions, capabilities, labels or excess limits.
    pub fn new(pipeline: &ExtensionPipelineV1) -> Result<Self, ExtensionError> {
        pipeline.validate()?;
        Ok(Self {
            pipeline: pipeline.clone(),
            entered: Vec::with_capacity(pipeline.extensions.len()),
            cleanup: Vec::new(),
            closed: false,
            prepared: false,
            policy_denied: false,
        })
    }
    /// Execute request middleware forward. Return replacements without executing them.
    ///
    /// # Errors
    /// Refuses cancellation, deadline, policy denial, invalid requests and closed lifecycle.
    pub fn before_acquisition(
        &mut self,
        request: &RequestEnvelopeV1,
        cancellation: &CancellationToken,
    ) -> Result<RequestPreparationV1, ExtensionError> {
        if self.policy_denied {
            return Err(ExtensionError::PolicyDenied);
        }
        if self.closed || self.prepared {
            return Err(ExtensionError::Closed);
        }
        self.prepared = true;
        if cancellation.is_cancelled() {
            return Err(ExtensionError::Cancelled);
        }
        request.validate().map_err(|_| ExtensionError::Rejected)?;
        let route = self.pipeline.route(&request.route)?;
        let mut replacement = None;
        let request_bytes = json_size(request)?;
        for entry in self.pipeline.ordered() {
            if !matches!(
                entry.stage,
                ExtensionStageV1::RequestProposed | ExtensionStageV1::BeforeAcquisition
            ) {
                continue;
            }
            let started = Instant::now();
            guard(cancellation, started, entry.limits.deadline_ms)?;
            if request_bytes > entry.limits.input_bytes {
                return Err(ExtensionError::Limit);
            }
            self.entered.push(entry.id.clone());
            match &entry.config {
                ExtensionConfigV1::ReadOnly {} if !matches!(request.method.as_str(), "GET" | "HEAD") => {
                    self.policy_denied = true;
                    return Err(ExtensionError::PolicyDenied);
                }
                ExtensionConfigV1::ReplaceRequest { request: proposed }
                    if !same_intent(proposed, request) =>
                {
                    if replacement.is_some() || json_size(proposed)? > entry.limits.output_bytes {
                        return Err(ExtensionError::Limit);
                    }
                    replacement = Some(proposed.as_ref().clone());
                }
                _ => {}
            }
            guard(cancellation, started, entry.limits.deadline_ms)?;
        }
        Ok(RequestPreparationV1 { replacement, route })
    }
    /// Seal once and release transient stage state in reverse entry order.
    /// Policy denial is sticky and cannot be replaced by terminal annotations.
    #[must_use]
    pub fn finalize(&mut self, policy_denied: bool) -> bool {
        self.policy_denied |= policy_denied;
        if self.closed {
            return false;
        }
        self.closed = true;
        self.entered.reverse();
        self.cleanup = std::mem::take(&mut self.entered);
        true
    }
    /// Ordered cleanup receipt, bounded by descriptor count.
    #[must_use]
    pub fn cleanup_order(&self) -> &[String] {
        &self.cleanup
    }
    /// Terminal policy denial survives every finalization call.
    #[must_use]
    pub fn policy_denied(&self) -> bool {
        self.policy_denied
    }
}
impl Drop for RequestLifecycle {
    fn drop(&mut self) {
        let _ = self.finalize(false);
    }
}
fn guard(cancel: &CancellationToken, started: Instant, deadline_ms: u32) -> Result<(), ExtensionError> {
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    if started.elapsed() >= Duration::from_millis(u64::from(deadline_ms)) {
        return Err(ExtensionError::Deadline);
    }
    Ok(())
}
fn same_intent(a: &RequestEnvelopeV1, b: &RequestEnvelopeV1) -> bool {
    // Provenance is assigned by native admission, never by a replacement descriptor.
    a.url.url == b.url.url
        && a.method == b.method
        && a.header_control == b.header_control
        && a.body == b.body
        && a.route == b.route
        && a.metadata == b.metadata
        && a.priority == b.priority
        && a.dialect == b.dialect
        && a.source_key == b.source_key
        && a.revisit_generation == b.revisit_generation
        && a.session_generation == b.session_generation
        && a.not_before == b.not_before
}
fn candidate_failure(policy: ExtensionFailurePolicyV1) -> ExtensionError {
    match policy {
        ExtensionFailurePolicyV1::Reject => ExtensionError::Rejected,
        ExtensionFailurePolicyV1::Fail => ExtensionError::Failed,
        _ => ExtensionError::Failed,
    }
}
/// Shared borrowed-envelope native item pipeline, suitable inside an existing CPU job.
///
/// # Errors
/// Refuses unknown labels, cancellation, deadlines, rejected candidates and byte limits.
/// Output is ephemeral content, not an accepted durable item or a delivery destination.
pub fn transform_document(
    pipeline: &ExtensionPipelineV1,
    label: &str,
    document: &DocumentEnvelopeV1,
    cancel: &CancellationToken,
) -> Result<Option<Value>, ExtensionError> {
    pipeline.validate()?;
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    if pipeline.route(label)? == HandlerV1::Skip {
        return Ok(None);
    }
    if document.privacy_projection_version != Some(1) {
        return Err(ExtensionError::Rejected);
    }
    if document.quality.status != QualityStatusV1::Accepted {
        return Err(pipeline
            .extensions
            .iter()
            .find(|e| matches!(e.config, ExtensionConfigV1::RequireQuality {}))
            .map_or(ExtensionError::Rejected, |e| candidate_failure(e.failure_policy)));
    }
    let mut item = document_item(document, MAX_EXTENSION_BYTES)?;
    let mut item_bytes = json_size(&item)?;
    let mut entries = pipeline.ordered();
    if pipeline.reverse_response {
        entries.reverse();
    }
    for stage in [ExtensionStageV1::Parse, ExtensionStageV1::Item] {
        for entry in entries.iter().filter(|e| e.stage == stage) {
            let started = Instant::now();
            guard(cancel, started, entry.limits.deadline_ms)?;
            if entry.limits.items == 0 || item_bytes > entry.limits.input_bytes {
                return Err(ExtensionError::Limit);
            }
            match &entry.config {
                ExtensionConfigV1::RequireQuality {}
                    if document.quality.status != QualityStatusV1::Accepted =>
                {
                    return Err(candidate_failure(entry.failure_policy));
                }
                ExtensionConfigV1::TrimTitle {} => {
                    if let Some(Value::String(title)) = item.get_mut("title") {
                        let start = title.len().saturating_sub(title.trim_start().len());
                        let end = title.trim_end().len();
                        if start >= end {
                            title.clear();
                        } else {
                            title.truncate(end);
                            title.drain(..start);
                        }
                    }
                    item_bytes = json_size(&item)?;
                }
                ExtensionConfigV1::RequireTitle {}
                    if item
                        .get("title")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty) =>
                {
                    return Err(candidate_failure(entry.failure_policy));
                }
                _ => {}
            }
            if item_bytes > entry.limits.output_bytes {
                return Err(ExtensionError::Limit);
            }
            guard(cancel, started, entry.limits.deadline_ms)?;
        }
    }
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    Ok(Some(item))
}
/// Run the pure pipeline through the shared worker CPU pool without cloning a body.
/// Cancellation never releases a running blocking closure's CPU permit early.
///
/// # Errors
/// Returns typed transform failures, cancellation or CPU task failure. Trusted work
/// checks cancellation at each bounded stage and remains charged until it exits.
pub async fn process_document(
    pool: &CpuPool,
    pipeline: ExtensionPipelineV1,
    label: String,
    document: DocumentEnvelopeV1,
    cancel: CancellationToken,
) -> Result<Option<Value>, ExtensionError> {
    pipeline.validate()?;
    if cancel.is_cancelled() {
        return Err(ExtensionError::Cancelled);
    }
    let deadline_ms = pipeline
        .extensions
        .iter()
        .map(|e| u64::from(e.limits.deadline_ms))
        .sum::<u64>()
        .max(1000);
    let token = cancel.child_token();
    let _cancel_on_drop = token.clone().drop_guard();
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ExtensionError::Cancelled),
        result = tokio::time::timeout(Duration::from_millis(deadline_ms),
            pool.run(move || transform_document(&pipeline, &label, &document, &token))) => {
            result.map_err(|_| ExtensionError::Deadline)?.map_err(|_| ExtensionError::Task)?
        }
    }
}

/// Store one transformed candidate through the typed content/privacy gateway.
/// Dataset append is explicit; undeclared namespaces never receive implicit writes.
///
/// # Errors
/// Returns serialization, retention, schema, expiry or artifact backend failures.
pub async fn store_candidate(
    artifacts: &dyn crawlx_core::repo::ArtifactStore,
    run: &crawlx_core::repo::CrawlRun,
    page: i64,
    candidate: &Value,
    extractor: &str,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: &crawlx_core::captcha::CaptchaSecrets,
) -> Result<
    (
        crawlx_core::ArtifactRef,
        Option<crawlx_core::dataset::AcceptedBatchV1>,
        Vec<crawlx_core::dataset::DeliveryBatchV1>,
    ),
    crawlx_core::StoreError,
> {
    use crawlx_core::{
        dataset::{AcceptedBatchV1, AcceptedItemV1},
        secret::ArtifactSink,
        StoreError,
    };
    if json_size(candidate).map_err(|_| StoreError::Serialization("invalid item JSON".into()))?
        > MAX_EXTENSION_BYTES
    {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let mut projected = candidate.clone();
    project_candidate(&mut projected, controls, captcha)?;
    let mut bytes = serde_json::to_vec(&projected).map_err(|e| StoreError::Serialization(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_EXTENSION_BYTES {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let approved = crawlx_core::secret::Redactor::new().redact_artifact(&bytes)?;
    if approved.as_ref().len() > MAX_EXTENSION_BYTES {
        return Err(StoreError::Conflict("extension item byte limit".into()));
    }
    let size = u64::try_from(approved.as_ref().len())
        .map_err(|_| StoreError::Conflict("extension item byte limit".into()))?;
    let artifact = ArtifactSink::over(artifacts)
        .put_dataset(
            run.id,
            page,
            "extension_item",
            "application/vnd.crawlx.item+json",
            &approved,
        )
        .await?;
    let Some(dataset) = &run.config.extensions.dataset else {
        return Ok((artifact, None, Vec::new()));
    };
    let declaration = run
        .config
        .datasets
        .stores
        .iter()
        .find(|s| &s.name == dataset)
        .ok_or_else(|| StoreError::Conflict("extension dataset not declared".into()))?;
    if declaration.schema_version != "document_item_v1" {
        return Err(StoreError::Conflict("extension dataset schema mismatch".into()));
    }
    let content = artifacts.dataset_content(run.id, page, &artifact, size).await?;
    let expires = content
        .expires_at()
        .or_else(|| {
            run.created_at
                .checked_add_signed(chrono::Duration::days(i64::from(run.config.retention.days)))
        })
        .ok_or_else(|| StoreError::RetentionDenied("item expiry unavailable".into()))?;
    let mut item = AcceptedItemV1::new(
        format!("request-{page}"),
        "native_pipeline_v1".into(),
        declaration.schema_version.clone(),
        extractor.replace('/', "."),
        content,
        size,
    );
    item.expires_at = Some(expires);
    let outbox =
        crate::delivery::prepare_item_feeds(artifacts, run, page, dataset, &artifact, approved.as_ref())
            .await?;
    Ok((
        artifact,
        Some(AcceptedBatchV1::new(dataset.clone(), vec![item])),
        outbox,
    ))
}

fn project_candidate(
    value: &mut Value,
    controls: &crawlx_core::request_controls::RequestControls,
    captcha: &crawlx_core::captcha::CaptchaSecrets,
) -> Result<(), crawlx_core::StoreError> {
    fn strings(value: &mut Value, controls: &crawlx_core::request_controls::RequestControls) {
        let scrub = |text: &str| {
            String::from_utf8_lossy(
                &crawlx_telemetry::Redactor::new().scrub_bytes(text.as_bytes(), controls.secret_values()),
            )
            .into_owned()
        };
        match value {
            Value::String(text) => *text = scrub(text),
            Value::Array(values) => {
                for value in values {
                    strings(value, controls);
                }
            }
            Value::Object(fields) => {
                *fields = std::mem::take(fields)
                    .into_iter()
                    .map(|(key, mut value)| {
                        strings(&mut value, controls);
                        (scrub(&key), value)
                    })
                    .collect();
            }
            _ => {}
        }
    }
    strings(value, controls);
    captcha.redact_json(value).map_err(|_| {
        crawlx_core::StoreError::RetentionDenied("item dynamic-secret projection unavailable".into())
    })?;
    let valid = value.as_object().is_some_and(|fields| {
        fields.len() == 5
            && fields
                .get("title")
                .is_some_and(|v| v.is_null() || v.as_str().is_some())
            && fields
                .get("language")
                .is_some_and(|v| v.is_null() || v.as_str().is_some())
            && fields.get("extractor").and_then(Value::as_str).is_some()
            && fields.get("quality").and_then(Value::as_str) == Some("accepted")
            && fields.get("authors").is_some_and(|v| {
                v.is_null()
                    || v.as_array()
                        .is_some_and(|a| a.len() <= 64 && a.iter().all(Value::is_string))
            })
    });
    if !valid {
        return Err(crawlx_core::StoreError::Conflict(
            "projected item schema rejected".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #[tokio::test]
    async fn split_markup_credentials_and_live_tokens_are_projected_before_item_schema() {
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch.extra_headers.insert("x-custom", "hdrCanary742");
        fetch
            .cookies
            .push(crawlx_core::request_controls::FetchCookie::new(
                "session",
                "cookieCanary853",
            ));
        let controls = crawlx_core::request_controls::RequestControls::resolve(&fetch, "fixture.test", None)
            .await
            .unwrap();
        let captcha = crawlx_core::captcha::CaptchaSecrets::default();
        captcha
            .register(crawlx_core::secret::SecretOr::secret("captchaCanary953".into()))
            .unwrap();
        let base = url::Url::parse("https://fixture.test/article").unwrap();
        let options = crawlx_extract::ExtractOptions {
            content: Some(crawlx_core::extraction::ExtractionPolicyV1::default()),
            acquisition_validation: Some(crate::acquisition::context(
                &crawlx_core::acquisition::AcquisitionPolicyV1::default(),
                Some(200),
                false,
            )),
            ..crawlx_extract::ExtractOptions::default()
        };
        let doc = crate::acquisition::extract_document_with_secrets(
            b"<html><body><article><h1>hdrCanary<span>742</span> cookieCanary<i>853</i> captchaCanary<b>953</b></h1><p>A complete native privacy fixture paragraph with enough text for article selection.</p></article></body></html>",
            &base, &options, &controls, &captcha).unwrap();
        let mut item = transform_document(
            &ExtensionPipelineV1::default(),
            "default",
            doc.article.as_ref().unwrap(),
            &CancellationToken::new(),
        )
        .unwrap()
        .unwrap();
        project_candidate(&mut item, &controls, &captcha).unwrap();
        let encoded = serde_json::to_string(&item).unwrap();
        for secret in ["hdrCanary742", "cookieCanary853", "captchaCanary953"] {
            assert!(!doc.text.contains(secret));
            assert!(!encoded.contains(secret));
        }
        assert_eq!(item["quality"], "accepted");
    }
    use super::*;
    use crawlx_core::{
        extensions::ExtensionSpecV1,
        extraction::{ArticleMetadataV1, QualityOutcomeV1},
        hash::Digest,
    };
    fn document(title: &str) -> DocumentEnvelopeV1 {
        let mut metadata = ArticleMetadataV1::default();
        metadata.title.value = Some(title.into());
        let mut document = DocumentEnvelopeV1::new(
            Digest([0; 32]),
            Digest([0; 32]),
            "fixture".into(),
            0,
            Vec::new(),
            metadata,
            QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), 0, 0, 0),
        );
        document.privacy_projection_version = Some(1);
        document
    }
    fn request(path: &str) -> RequestEnvelopeV1 {
        let url = url::Url::parse(&format!("https://fixture.test/{path}")).unwrap();
        let canonical = crawlx_url::Canonicalizer::canonicalize_detailed(
            url.as_str(),
            &url,
            &crawlx_url::CanonicalizeOptions::default(),
        )
        .unwrap();
        RequestEnvelopeV1::get(canonical.url, 0, None)
    }
    #[test]
    fn replacement_is_a_proposal_and_does_not_rewrite_or_repeat_the_leased_intent() {
        let original = request("old");
        let mut pipeline = ExtensionPipelineV1::default();
        let proposed = request("new");
        pipeline.extensions.push(ExtensionSpecV1::new(
            ExtensionConfigV1::ReplaceRequest {
                request: Box::new(proposed.clone()),
            },
            0,
        ));
        let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
        let prepared = lifecycle
            .before_acquisition(&original, &CancellationToken::new())
            .unwrap();
        assert_eq!(original.url.url.path(), "/old");
        assert_eq!(prepared.replacement.unwrap().url.url.path(), "/new");
        let mut admitted = proposed;
        admitted.parent = Some(42);
        admitted.depth = 1;
        let mut next = RequestLifecycle::new(&pipeline).unwrap();
        assert!(next
            .before_acquisition(&admitted, &CancellationToken::new())
            .unwrap()
            .replacement
            .is_none());
    }
    #[test]
    fn request_policy_denial_wins_after_close_and_cancellation() {
        let mut pipeline = ExtensionPipelineV1::default();
        pipeline
            .extensions
            .push(ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 0));
        let mut request = request("write");
        request.method = "POST".into();
        let cancel = CancellationToken::new();
        let mut lifecycle = RequestLifecycle::new(&pipeline).unwrap();
        assert!(matches!(
            lifecycle.before_acquisition(&request, &cancel),
            Err(ExtensionError::PolicyDenied)
        ));
        assert!(lifecycle.finalize(false));
        cancel.cancel();
        assert!(matches!(
            lifecycle.before_acquisition(&request, &cancel),
            Err(ExtensionError::PolicyDenied)
        ));
    }
    #[test]
    fn forward_and_reverse_order_changes_real_candidate_result() {
        let mut pipeline = ExtensionPipelineV1::default();
        pipeline.extensions = vec![
            ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0),
            ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 1),
        ];
        pipeline.extensions[1].failure_policy = ExtensionFailurePolicyV1::Reject;
        let cancel = CancellationToken::new();
        assert!(matches!(
            transform_document(&pipeline, "default", &document("  "), &cancel),
            Err(ExtensionError::Rejected)
        ));
        pipeline.reverse_response = true;
        let item = transform_document(&pipeline, "default", &document("  "), &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(item["title"], "");
    }
    #[test]
    fn unknown_label_and_cancel_do_not_fall_back() {
        let pipeline = ExtensionPipelineV1::default();
        let cancel = CancellationToken::new();
        assert!(matches!(
            transform_document(&pipeline, "missing", &document("x"), &cancel),
            Err(ExtensionError::UnknownRoute)
        ));
        cancel.cancel();
        assert!(matches!(
            transform_document(&pipeline, "default", &document("x"), &cancel),
            Err(ExtensionError::Cancelled)
        ));
    }
    #[test]
    fn finalization_runs_once_and_preserves_policy_denial() {
        let mut lifecycle = RequestLifecycle::new(&ExtensionPipelineV1::default()).unwrap();
        lifecycle.entered = vec!["first".into(), "second".into()];
        assert!(lifecycle.finalize(true));
        assert!(!lifecycle.finalize(false));
        assert!(lifecycle.policy_denied());
        assert_eq!(lifecycle.cleanup_order(), &["second", "first"]);
    }
    #[test]
    fn deadline_is_typed_without_sleep_or_network() {
        let started = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            guard(&CancellationToken::new(), started, 1),
            Err(ExtensionError::Deadline)
        ));
    }
}
