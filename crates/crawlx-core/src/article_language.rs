//! Pure, bounded article language service contract. Implementations belong to the worker/model layer.
use crate::hash::Digest;
use serde::{Deserialize, Serialize};

/// Selection policy; omission preserves declared-only legacy language evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LanguageModeV1 {
    /// Never invoke a detector.
    #[default]
    DeclaredOnly,
    /// Use valid declared language, otherwise the injected approved detector.
    DeclaredThenDetect,
    /// Request detected evidence even when a declaration exists.
    Detect,
}
/// One uncalibrated model probability; not an authorization signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct LanguageScoreV1 {
    /// ISO two/three-letter label from the pinned model.
    pub language: String,
    /// Finite hierarchical-softmax probability, not measured calibration confidence.
    pub probability: f64,
}
impl LanguageScoreV1 {
    /// Validate a language probability.
    /// # Errors
    /// Rejects unsupported labels and non-finite/out-of-range probability values.
    pub fn new(language: String, probability: f64) -> Result<Self, LanguageDetectionErrorV1> {
        if !(2..=3).contains(&language.len())
            || !language.bytes().all(|b| b.is_ascii_lowercase())
            || !probability.is_finite()
            || !(0.0..=1.0).contains(&probability)
        {
            return Err(LanguageDetectionErrorV1::Malformed);
        }
        Ok(Self {
            language,
            probability,
        })
    }
}
/// Versioned, content-sensitive detector evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct LanguageDetectionV1 {
    /// Digest of the approved resource manifest, not a caller-provided model name.
    pub bundle_digest: Digest,
    /// At most 176 labels, descending probability then immutable label order.
    pub scores: Vec<LanguageScoreV1>,
    /// The detector consumed a bounded prefix rather than all input text.
    pub truncated: bool,
}
impl LanguageDetectionV1 {
    /// Construct bounded evidence from a verified backend.
    /// # Errors
    /// Rejects excessive, duplicate or malformed labels/probabilities.
    pub fn new(
        bundle_digest: Digest,
        scores: Vec<LanguageScoreV1>,
        truncated: bool,
    ) -> Result<Self, LanguageDetectionErrorV1> {
        let mut seen = std::collections::BTreeSet::new();
        if scores.len() > 176
            || scores
                .windows(2)
                .any(|pair| pair[0].probability < pair[1].probability)
            || scores.iter().any(|score| {
                !seen.insert(&score.language)
                    || !(2..=3).contains(&score.language.len())
                    || !score.language.bytes().all(|b| b.is_ascii_lowercase())
                    || !score.probability.is_finite()
                    || !(0.0..=1.0).contains(&score.probability)
            })
        {
            return Err(LanguageDetectionErrorV1::Malformed);
        }
        Ok(Self {
            bundle_digest,
            scores,
            truncated,
        })
    }
}
/// Missing or refused local language capability; no implicit network fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LanguageDetectionErrorV1 {
    /// No approved bundle/runtime is installed.
    #[error("article language model unavailable")]
    Unavailable,
    /// Bound exceeded before inference.
    #[error("article language resource limit exceeded")]
    ResourceLimit,
    /// Bundle or runtime output violated the pinned contract.
    #[error("article language model evidence malformed")]
    Malformed,
}
/// Worker-injected synchronous capability. Pure extraction never loads or downloads a model.
pub trait ArticleLanguageDetector: Send + Sync {
    /// Identify language using a bounded, already privacy-projected text sample.
    /// # Errors
    /// Returns typed unavailable/resource/malformed failures without exposing input content.
    fn detect(&self, text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1>;
    /// Exact installed approved resource manifest.
    fn bundle_digest(&self) -> Digest;
}

/// Cloneable transient model handle. Never serialized in a crawl policy.
#[derive(Clone)]
pub struct ArticleLanguageHandle(std::sync::Arc<dyn ArticleLanguageDetector>);
impl ArticleLanguageHandle {
    /// Bind a trusted operator-created detector.
    #[must_use]
    pub fn new(detector: std::sync::Arc<dyn ArticleLanguageDetector>) -> Self {
        Self(detector)
    }
    /// Borrow the installed detector without copying model/body data.
    #[must_use]
    pub fn detector(&self) -> &dyn ArticleLanguageDetector {
        self.0.as_ref()
    }
}
impl std::fmt::Debug for ArticleLanguageHandle {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("ArticleLanguageHandle")
            .field("bundle_digest", &self.0.bundle_digest())
            .finish_non_exhaustive()
    }
}
impl PartialEq for ArticleLanguageHandle {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ArticleLanguageHandle {}
