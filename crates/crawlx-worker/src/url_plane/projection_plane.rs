//! Operator-approved search projection of a finalized article envelope.
//!
//! The projection consumes only canonical envelope metadata and finalized text. A produced record
//! is content, so it goes through the ordinary candidate store (artifact custody and, when the run
//! declares a dataset, an accepted item); only its typed status and policy digest enter page
//! metadata.

use super::*;
use crate::source_dispatch::{SourceArticleInput, SourceProjectionOutcomeV1};
use crawlx_core::dataset::{AcceptedBatchV1, DeliveryBatchV1};

/// What a projection contributes to one request's commit.
#[derive(Default)]
pub(super) struct ProjectionCommit {
    /// Structural status for `pages.metadata`; never content.
    pub status: Option<serde_json::Value>,
    /// Accepted item batch, when a dataset is declared.
    pub accepted: Vec<AcceptedBatchV1>,
    /// Delivery intents of the accepted item.
    pub outbox: Vec<DeliveryBatchV1>,
}

impl UrlPlaneRunner {
    /// Project the finalized article, if the operator configured a projection policy.
    ///
    /// # Errors
    /// Returns the run lookup or candidate-store failure. A policy that cannot be honoured is a
    /// typed `unavailable` status, never a fabricated field.
    pub(super) async fn project_article(
        &self,
        entry: &FrontierEntry,
        doc: &Document,
    ) -> Result<ProjectionCommit, WorkerError> {
        let Some(dispatcher) = self.source_dispatch.as_ref().filter(|d| d.projection_requested()) else {
            return Ok(ProjectionCommit::default());
        };
        let (Some(envelope), Some(captcha)) = (doc.article.as_ref(), self.captcha_secrets.as_ref()) else {
            return Ok(ProjectionCommit {
                status: Some(
                    serde_json::json!({"version":1,"status":"unavailable","reason":"article_unavailable"}),
                ),
                ..ProjectionCommit::default()
            });
        };
        let controls = &self.fetcher.config().controls;
        let privacy = |text: &str| -> Result<String, StoreError> {
            let redactor = crawlx_core::secret::Redactor::new();
            let scrubbed = redactor.scrub_bytes(text.as_bytes(), controls.secret_values());
            let scrubbed = String::from_utf8_lossy(&scrubbed).into_owned();
            captcha
                .redact_if_present(&scrubbed)
                .map(std::borrow::Cow::into_owned)
                .map_err(|_| StoreError::RetentionDenied("projection secret registry unavailable".into()))
        };
        let outcome = dispatcher
            .project_article(SourceArticleInput {
                envelope,
                text: &doc.text,
                document_id: format!("{}:{}", self.run, entry.id),
                parent_id: entry
                    .discovered_from
                    .map(|parent| format!("{}:{parent}", self.run)),
                retention: self.crawl.retention.mode,
                privacy: &privacy,
            })
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        match outcome {
            SourceProjectionOutcomeV1::NotConfigured => Ok(ProjectionCommit::default()),
            SourceProjectionOutcomeV1::Unavailable { reason, fields } => Ok(ProjectionCommit {
                status: Some(serde_json::json!({
                    "version":1,"status":"unavailable","reason":reason.as_str(),"fields":fields.len(),
                })),
                ..ProjectionCommit::default()
            }),
            SourceProjectionOutcomeV1::Produced {
                record,
                policy_digest,
            } => {
                let candidate = serde_json::to_value(&record)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                let run = self.deps.runs.get(self.run).await?;
                let (_, accepted, outbox) = crate::extensions::store_candidate(
                    self.deps.artifacts.as_ref(),
                    &self.cpu_pool,
                    &run,
                    entry.id,
                    &candidate,
                    "source-projection",
                    controls,
                    captcha,
                )
                .await?;
                Ok(ProjectionCommit {
                    status: Some(serde_json::json!({
                        "version":1,"status":"produced","policyDigest":policy_digest,
                    })),
                    accepted: accepted.into_iter().collect(),
                    outbox,
                })
            }
        }
    }
}
