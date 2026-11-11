//! Bounded capture/replay bridge for the pinned article language detector across the isolated
//! parser boundary.
//!
//! The parser helper never loads a model, downloads one or opens a network connection. Language
//! detection of an isolated parse is a two-pass exchange that keeps the native selection and
//! quality code unchanged:
//!
//! 1. The helper parses with [`LanguageCapture::handle`], a detector whose bundle digest equals
//!    the original handle's. Its single `detect` call stores the finalized input once in a
//!    byte-admitted [`CapturedLanguage`] and returns the native `Unavailable` error. If a capture
//!    happened, the helper sends the [`LanguageCallV1`] (bundle digest, input digest, text) instead
//!    of a final document and keeps the [`LanguageHold`] until the reply arrived.
//! 2. The parent runs [`LanguageCallV1::run`] against the original pinned detector exactly once.
//!    Bundle and input digests are verified before inference. The result or one of the three
//!    original detector errors comes back as a bounded [`LanguageReplyV1`].
//! 3. The helper parses the same body with the same options and dedupe snapshot using
//!    [`LanguageReplay::handle`]. It verifies the exact finalized input digest and replays the
//!    result or error to the native selection code; [`LanguageReplay::finish`] then proves the
//!    replay was consumed exactly once.
//!
//! Capture and replay allow at most one callback each. Failures that are not detector semantics
//! (budget, size, digest, call count) are never shown to the native code as detector results; they
//! surface as a static, content-free [`LanguageBridgeError`] so the caller fails the parse typed.
use crawlx_core::{
    article_language::{
        ArticleLanguageDetector, ArticleLanguageHandle, LanguageDetectionErrorV1, LanguageDetectionV1,
    },
    hash::Digest,
    parser_memory::{Budgeted, ByteAdmissionError, ByteBudget, BytePermit},
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Largest finalized detector input the bridge captures or runs, in bytes.
pub const MAX_LANGUAGE_TEXT_BYTES: usize = 16 * 1024 * 1024;

/// Domain tag of the finalized-input digest.
const INPUT_DOMAIN: &str = "crawlx.extract.language_input.v1";

/// Failures of the bridge itself. Static messages; never any input content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LanguageBridgeError {
    /// The shared byte budget refused the captured copy.
    #[error("language input byte admission failed")]
    Budget(#[source] ByteAdmissionError),
    /// The allocator refused the admitted copy.
    #[error("language input allocation failed")]
    Allocation,
    /// The finalized input exceeds [`MAX_LANGUAGE_TEXT_BYTES`].
    #[error("language input too large")]
    TextTooLarge,
    /// The detector was called more than once.
    #[error("language detector called more than once")]
    TooManyCalls,
    /// The call names a bundle other than the pinned detector's.
    #[error("language bundle digest mismatch")]
    BundleMismatch,
    /// The finalized input differs from the captured one.
    #[error("language input digest mismatch")]
    InputDigestMismatch,
    /// A replayed result was never requested by the second parse.
    #[error("language replay was not consumed")]
    NotConsumed,
}

/// One of the three original detector errors, in wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LanguageErrorV1 {
    /// No approved bundle/runtime is installed.
    Unavailable,
    /// A bound was exceeded before inference.
    ResourceLimit,
    /// The detector output violated the pinned contract.
    Malformed,
}

impl From<LanguageDetectionErrorV1> for LanguageErrorV1 {
    fn from(error: LanguageDetectionErrorV1) -> Self {
        match error {
            LanguageDetectionErrorV1::Unavailable => Self::Unavailable,
            LanguageDetectionErrorV1::ResourceLimit => Self::ResourceLimit,
            _ => Self::Malformed,
        }
    }
}

impl From<LanguageErrorV1> for LanguageDetectionErrorV1 {
    fn from(error: LanguageErrorV1) -> Self {
        match error {
            LanguageErrorV1::Unavailable => Self::Unavailable,
            LanguageErrorV1::ResourceLimit => Self::ResourceLimit,
            LanguageErrorV1::Malformed => Self::Malformed,
        }
    }
}

/// Detector result or original error, as transported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LanguageOutcomeV1 {
    /// A validated detector result.
    Detected {
        /// At most 176 finite, ordered scores.
        detection: LanguageDetectionV1,
    },
    /// An original detector error.
    Failed {
        /// The original error.
        error: LanguageErrorV1,
    },
}

impl LanguageOutcomeV1 {
    fn into_result(self, bundle: Digest) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
        match self {
            Self::Detected { detection } => validate_detection(detection, bundle),
            Self::Failed { error } => Err(error.into()),
        }
    }
}

/// `NeedLanguage` payload: the finalized detector input, sensitive and bounded.
///
/// `Debug` prints digests and length, never the text. The byte permit that admitted the text in
/// the helper travels separately as [`LanguageHold`]; it is never serialized.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct LanguageCallV1 {
    /// Digest of the pinned detector bundle the helper's handle carried.
    pub bundle_digest: Digest,
    /// Digest of `text` under the language-input domain.
    pub input_digest: Digest,
    /// The finalized text passed to `detect`. The receiver charges its decode cost.
    pub text: String,
}

impl LanguageCallV1 {
    /// Assemble a call, computing the input digest of `text`.
    #[must_use]
    pub fn new(bundle_digest: Digest, text: String) -> Self {
        Self {
            bundle_digest,
            input_digest: input_digest(&text),
            text,
        }
    }

    /// Run the original pinned detector once, on the calling (CPU) thread.
    ///
    /// # Errors
    /// Bundle mismatch, oversized text and input digest mismatch are typed errors returned
    /// before any inference. Detector errors and malformed detector results are not bridge
    /// errors: they travel inside the reply with their original semantics.
    pub fn run(
        &self,
        detector: &dyn ArticleLanguageDetector,
    ) -> Result<LanguageReplyV1, LanguageBridgeError> {
        if self.bundle_digest != detector.bundle_digest() {
            return Err(LanguageBridgeError::BundleMismatch);
        }
        if self.text.len() > MAX_LANGUAGE_TEXT_BYTES {
            return Err(LanguageBridgeError::TextTooLarge);
        }
        if input_digest(&self.text) != self.input_digest {
            return Err(LanguageBridgeError::InputDigestMismatch);
        }
        let outcome = match detector
            .detect(&self.text)
            .and_then(|detection| validate_detection(detection, self.bundle_digest))
        {
            Ok(detection) => LanguageOutcomeV1::Detected { detection },
            Err(error) => LanguageOutcomeV1::Failed { error: error.into() },
        };
        Ok(LanguageReplyV1::new(
            self.bundle_digest,
            self.input_digest,
            outcome,
        ))
    }
}

impl std::fmt::Debug for LanguageCallV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("LanguageCallV1")
            .field("bundle_digest", &self.bundle_digest)
            .field("input_digest", &self.input_digest)
            .field("text_bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed serializer of a [`CapturedLanguage`]; JSON identical to [`LanguageCallV1`].
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanguageCallRefV1<'a> {
    bundle_digest: Digest,
    input_digest: Digest,
    text: &'a str,
}

impl std::fmt::Debug for LanguageCallRefV1<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("LanguageCallRefV1")
            .field("bundle_digest", &self.bundle_digest)
            .field("input_digest", &self.input_digest)
            .field("text_bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// Parent answer to a [`LanguageCallV1`], bounded by the detector's 176-score contract.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct LanguageReplyV1 {
    /// Bundle the original detector ran under.
    pub bundle_digest: Digest,
    /// Digest of the input that detector consumed.
    pub input_digest: Digest,
    /// Result or original error.
    pub outcome: LanguageOutcomeV1,
}

impl LanguageReplyV1 {
    /// Assemble a reply.
    #[must_use]
    pub const fn new(bundle_digest: Digest, input_digest: Digest, outcome: LanguageOutcomeV1) -> Self {
        Self {
            bundle_digest,
            input_digest,
            outcome,
        }
    }
}

impl std::fmt::Debug for LanguageReplyV1 {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.outcome {
            LanguageOutcomeV1::Detected { .. } => "detected",
            LanguageOutcomeV1::Failed { .. } => "failed",
        };
        out.debug_struct("LanguageReplyV1")
            .field("bundle_digest", &self.bundle_digest)
            .field("input_digest", &self.input_digest)
            .field("outcome", &kind)
            .finish_non_exhaustive()
    }
}

/// Finalized detector input owned by the helper, admitted against the byte budget before copy.
///
/// Not serializable. `Debug` is redacted.
#[must_use = "a captured input must be sent to the parent"]
pub struct CapturedLanguage {
    bundle_digest: Digest,
    input_digest: Digest,
    text: Budgeted<String>,
}

impl CapturedLanguage {
    /// Pinned bundle digest of the capturing detector.
    #[must_use]
    pub const fn bundle_digest(&self) -> Digest {
        self.bundle_digest
    }

    /// Digest of the captured text.
    #[must_use]
    pub const fn input_digest(&self) -> Digest {
        self.input_digest
    }

    /// Borrowed serializer; the text is neither copied nor released.
    #[must_use]
    pub fn wire(&self) -> LanguageCallRefV1<'_> {
        LanguageCallRefV1 {
            bundle_digest: self.bundle_digest,
            input_digest: self.input_digest,
            text: self.text.value(),
        }
    }

    /// Move the text into the wire DTO without copying; the admission permit stays alive in the
    /// returned [`LanguageHold`], which MUST outlive the send and the reply wait.
    #[must_use = "the hold keeps the captured input's byte admission alive"]
    pub fn into_wire(self) -> (LanguageCallV1, LanguageHold) {
        let (text, permit) = self.text.into_parts();
        (
            LanguageCallV1 {
                bundle_digest: self.bundle_digest,
                input_digest: self.input_digest,
                text,
            },
            LanguageHold(permit),
        )
    }
}

impl std::fmt::Debug for CapturedLanguage {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("CapturedLanguage")
            .field("bundle_digest", &self.bundle_digest)
            .field("input_digest", &self.input_digest)
            .field("text_bytes", &self.text.value().len())
            .finish_non_exhaustive()
    }
}

/// Admission of a captured input, retained until its result was sent or the reply received.
#[derive(Debug)]
#[must_use = "dropping the hold releases the captured input's byte admission"]
pub struct LanguageHold(BytePermit);

impl LanguageHold {
    /// Admitted bytes.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.0.bytes()
    }
}

enum CaptureState {
    Idle,
    Captured(CapturedLanguage),
    Failed(LanguageBridgeError),
    Taken,
}

struct CaptureDetector {
    bundle: Digest,
    budget: Arc<ByteBudget>,
    state: Mutex<CaptureState>,
}

impl CaptureDetector {
    fn capture(&self, text: &str) -> Result<CapturedLanguage, LanguageBridgeError> {
        if text.len() > MAX_LANGUAGE_TEXT_BYTES {
            return Err(LanguageBridgeError::TextTooLarge);
        }
        // Charge before the clone exists.
        let permit = self
            .budget
            .try_reserve(text.len())
            .map_err(LanguageBridgeError::Budget)?;
        let mut copy = String::new();
        copy.try_reserve_exact(text.len())
            .map_err(|_| LanguageBridgeError::Allocation)?;
        copy.push_str(text);
        Ok(CapturedLanguage {
            bundle_digest: self.bundle,
            input_digest: input_digest(text),
            text: Budgeted::new(copy, permit),
        })
    }
}

impl ArticleLanguageDetector for CaptureDetector {
    fn detect(&self, text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
        let mut state = lock(&self.state);
        match &*state {
            CaptureState::Idle => {
                *state = match self.capture(text) {
                    Ok(captured) => CaptureState::Captured(captured),
                    Err(error) => CaptureState::Failed(error),
                };
            }
            // Second call: drop the first capture (releases its admission) and remember why.
            CaptureState::Captured(_) => *state = CaptureState::Failed(LanguageBridgeError::TooManyCalls),
            CaptureState::Failed(_) | CaptureState::Taken => {}
        }
        Err(LanguageDetectionErrorV1::Unavailable)
    }

    fn bundle_digest(&self) -> Digest {
        self.bundle
    }
}

/// First-pass detector owner: pinned bundle digest, one bounded capture, native `Unavailable`.
#[derive(Clone)]
pub struct LanguageCapture(Arc<CaptureDetector>);

impl LanguageCapture {
    /// Bind to the original handle's bundle digest and the budget that admits the capture.
    #[must_use]
    pub fn new(bundle_digest: Digest, budget: Arc<ByteBudget>) -> Self {
        Self(Arc::new(CaptureDetector {
            bundle: bundle_digest,
            budget,
            state: Mutex::new(CaptureState::Idle),
        }))
    }

    /// Detector handle for `ExtractOptions::language_detector`, with the same bundle digest as
    /// the original handle.
    #[must_use]
    pub fn handle(&self) -> ArticleLanguageHandle {
        ArticleLanguageHandle::new(Arc::clone(&self.0) as Arc<dyn ArticleLanguageDetector>)
    }

    /// Take the capture after the first parse. `Ok(None)` means the parse never called the
    /// detector, so its document is final.
    ///
    /// # Errors
    /// The first failure of the callback: budget, allocation, size or more than one call.
    pub fn take(&self) -> Result<Option<CapturedLanguage>, LanguageBridgeError> {
        match std::mem::replace(&mut *lock(&self.0.state), CaptureState::Taken) {
            CaptureState::Idle | CaptureState::Taken => Ok(None),
            CaptureState::Captured(captured) => Ok(Some(captured)),
            CaptureState::Failed(error) => Err(error),
        }
    }
}

impl std::fmt::Debug for LanguageCapture {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("LanguageCapture")
            .field("bundle_digest", &self.0.bundle)
            .finish_non_exhaustive()
    }
}

enum ReplayState {
    Pending(LanguageOutcomeV1),
    Consumed,
    Failed(LanguageBridgeError),
}

struct ReplayDetector {
    bundle: Digest,
    input: Digest,
    state: Mutex<ReplayState>,
}

impl ArticleLanguageDetector for ReplayDetector {
    fn detect(&self, text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
        let mut state = lock(&self.state);
        match std::mem::replace(&mut *state, ReplayState::Consumed) {
            ReplayState::Pending(outcome) => {
                if input_digest(text) == self.input {
                    outcome.into_result(self.bundle)
                } else {
                    *state = ReplayState::Failed(LanguageBridgeError::InputDigestMismatch);
                    Err(LanguageDetectionErrorV1::Unavailable)
                }
            }
            ReplayState::Consumed => {
                *state = ReplayState::Failed(LanguageBridgeError::TooManyCalls);
                Err(LanguageDetectionErrorV1::Unavailable)
            }
            failed @ ReplayState::Failed(_) => {
                *state = failed;
                Err(LanguageDetectionErrorV1::Unavailable)
            }
        }
    }

    fn bundle_digest(&self) -> Digest {
        self.bundle
    }
}

/// Second-pass detector owner: replays one verified result or error.
#[derive(Clone)]
pub struct LanguageReplay(Arc<ReplayDetector>);

impl LanguageReplay {
    /// Bind to the parent's reply. The detector reports the reply's bundle digest.
    #[must_use]
    pub fn new(reply: LanguageReplyV1) -> Self {
        Self(Arc::new(ReplayDetector {
            bundle: reply.bundle_digest,
            input: reply.input_digest,
            state: Mutex::new(ReplayState::Pending(reply.outcome)),
        }))
    }

    /// Detector handle for `ExtractOptions::language_detector`.
    #[must_use]
    pub fn handle(&self) -> ArticleLanguageHandle {
        ArticleLanguageHandle::new(Arc::clone(&self.0) as Arc<dyn ArticleLanguageDetector>)
    }

    /// Prove the second parse consumed the reply exactly once with the captured input.
    ///
    /// # Errors
    /// Input digest mismatch, more than one call, or no call at all.
    pub fn finish(&self) -> Result<(), LanguageBridgeError> {
        match &*lock(&self.0.state) {
            ReplayState::Consumed => Ok(()),
            ReplayState::Pending(_) => Err(LanguageBridgeError::NotConsumed),
            ReplayState::Failed(error) => Err(*error),
        }
    }
}

impl std::fmt::Debug for LanguageReplay {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("LanguageReplay")
            .field("bundle_digest", &self.0.bundle)
            .field("input_digest", &self.0.input)
            .finish_non_exhaustive()
    }
}

fn input_digest(text: &str) -> Digest {
    Digest::of(INPUT_DOMAIN, text.as_bytes())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Re-apply the detector result contract (at most 176 finite ordered unique scores) and pin the
/// bundle; any violation is the original `Malformed` error.
fn validate_detection(
    detection: LanguageDetectionV1,
    bundle: Digest,
) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
    let LanguageDetectionV1 {
        bundle_digest,
        scores,
        truncated,
        ..
    } = detection;
    if bundle_digest != bundle {
        return Err(LanguageDetectionErrorV1::Malformed);
    }
    LanguageDetectionV1::new(bundle_digest, scores, truncated)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{Document, ExtractOptions, Extractor};
    use crawlx_core::{
        article_language::{LanguageModeV1, LanguageScoreV1},
        extraction::ExtractionPolicyV1,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use url::Url;

    const HTML: &str = "<html><main><p>The village library opened its reading room before sunrise. Volunteers helped the children choose books about rivers, birds, and distant planets.</p></main></html>";
    const DECLARED_HTML: &str = "<html lang='en'><main><p>The village library opened its reading room before sunrise. Volunteers helped the children choose books about rivers, birds, and distant planets.</p></main></html>";

    struct Fake {
        bundle: Digest,
        calls: AtomicUsize,
        result: Result<LanguageDetectionV1, LanguageDetectionErrorV1>,
    }

    impl Fake {
        fn new(bundle: Digest, result: Result<LanguageDetectionV1, LanguageDetectionErrorV1>) -> Arc<Self> {
            Arc::new(Self {
                bundle,
                calls: AtomicUsize::new(0),
                result,
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ArticleLanguageDetector for Fake {
        fn detect(&self, _text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result.clone()
        }
        fn bundle_digest(&self) -> Digest {
            self.bundle
        }
    }

    fn bundle() -> Digest {
        Digest::of("test.bundle", b"pinned")
    }

    fn detection(pairs: &[(&str, f64)]) -> LanguageDetectionV1 {
        let scores = pairs
            .iter()
            .map(|(language, probability)| {
                LanguageScoreV1::new((*language).to_owned(), *probability).unwrap()
            })
            .collect();
        LanguageDetectionV1::new(bundle(), scores, false).unwrap()
    }

    fn policy(mode: LanguageModeV1) -> ExtractionPolicyV1 {
        let mut policy = ExtractionPolicyV1::default();
        policy.language_mode = mode;
        policy.language_bundle_digest = Some(bundle());
        policy.reference_date = Some("2026-11-04".parse().unwrap());
        policy
    }

    fn extract(html: &str, policy: &ExtractionPolicyV1, handle: Option<ArticleLanguageHandle>) -> Document {
        let options = ExtractOptions {
            content: Some(policy.clone()),
            language_detector: handle,
            ..ExtractOptions::default()
        };
        Extractor::extract(
            html,
            &Url::parse("https://fixture.invalid/article").unwrap(),
            &options,
        )
        .unwrap()
    }

    fn budget() -> Arc<ByteBudget> {
        Arc::new(ByteBudget::new(1 << 20))
    }

    /// Full two-pass exchange; returns the replayed document and the parent detector's call count.
    fn bridged(html: &str, policy: &ExtractionPolicyV1, parent: &Arc<Fake>) -> Document {
        let capture = LanguageCapture::new(bundle(), budget());
        let first = extract(html, policy, Some(capture.handle()));
        assert!(
            first
                .article
                .as_ref()
                .unwrap()
                .metadata
                .language_model_unavailable
        );
        assert_eq!(parent.calls(), 0, "capture pass must not run inference");
        let (call, hold) = capture
            .take()
            .unwrap()
            .expect("detector input captured")
            .into_wire();
        let reply = call.run(parent.as_ref()).unwrap();
        drop((call, hold));
        let replay = LanguageReplay::new(reply);
        let second = extract(html, policy, Some(replay.handle()));
        replay.finish().unwrap();
        second
    }

    fn assert_parity(result: Result<LanguageDetectionV1, LanguageDetectionErrorV1>) {
        let policy = policy(LanguageModeV1::Detect);
        let native_fake = Fake::new(bundle(), result.clone());
        let native = extract(
            HTML,
            &policy,
            Some(ArticleLanguageHandle::new(
                Arc::clone(&native_fake) as Arc<dyn ArticleLanguageDetector>
            )),
        );
        let parent = Fake::new(bundle(), result);
        let replayed = bridged(HTML, &policy, &parent);
        assert_eq!(native_fake.calls(), 1);
        assert_eq!(parent.calls(), 1);
        assert_eq!(native, replayed);
    }

    #[test]
    fn replayed_detection_equals_native_language_and_quality() {
        let result = Ok(detection(&[("en", 0.95), ("de", 0.03)]));
        assert_parity(result);
        let parent = Fake::new(bundle(), Ok(detection(&[("en", 0.95), ("de", 0.03)])));
        let document = bridged(HTML, &policy(LanguageModeV1::Detect), &parent);
        let metadata = &document.article.unwrap().metadata;
        assert_eq!(metadata.language.value.as_deref(), Some("en"));
        assert_eq!(metadata.language_model_digest, Some(bundle()));
        assert!(!metadata.language_model_unavailable);
    }

    #[test]
    fn uncertain_and_truncated_detections_match_native() {
        assert_parity(Ok(detection(&[("en", 0.5), ("de", 0.45)])));
        let mut truncated = detection(&[("en", 0.99)]);
        truncated.truncated = true;
        assert_parity(Ok(truncated));
    }

    #[test]
    fn the_three_original_errors_replay_with_native_semantics() {
        for error in [
            LanguageDetectionErrorV1::Unavailable,
            LanguageDetectionErrorV1::ResourceLimit,
            LanguageDetectionErrorV1::Malformed,
        ] {
            assert_parity(Err(error));
        }
    }

    #[test]
    fn malformed_detector_output_becomes_original_malformed() {
        let mut too_many = detection(&[("en", 0.5)]);
        too_many.scores = (0..177)
            .map(|index| {
                let label = format!(
                    "{}{}",
                    char::from(b'a' + u8::try_from(index / 26).unwrap()),
                    char::from(b'a' + u8::try_from(index % 26).unwrap())
                );
                LanguageScoreV1::new(label, 0.001).unwrap()
            })
            .collect();
        let mut out_of_range = detection(&[("en", 0.5)]);
        out_of_range.scores[0].probability = 2.0;
        let mut wrong_bundle = detection(&[("en", 0.5)]);
        wrong_bundle.bundle_digest = Digest::of("test.bundle", b"other");
        for bad in [too_many, out_of_range, wrong_bundle] {
            let parent = Fake::new(bundle(), Ok(bad));
            let call = LanguageCallV1::new(bundle(), "text".to_owned());
            let reply = call.run(parent.as_ref()).unwrap();
            assert_eq!(
                reply.outcome,
                LanguageOutcomeV1::Failed {
                    error: LanguageErrorV1::Malformed
                }
            );
        }
        // The helper re-validates a tampered reply before the native code sees it.
        let call = LanguageCallV1::new(bundle(), "text".to_owned());
        let mut forged = detection(&[("en", 0.5)]);
        forged.scores[0].probability = f64::NAN;
        let replay = LanguageReplay::new(LanguageReplyV1::new(
            bundle(),
            call.input_digest,
            LanguageOutcomeV1::Detected { detection: forged },
        ));
        assert_eq!(
            replay.handle().detector().detect("text"),
            Err(LanguageDetectionErrorV1::Malformed)
        );
        replay.finish().unwrap();
    }

    #[test]
    fn bundle_and_input_mismatch_are_typed_before_inference() {
        let parent = Fake::new(bundle(), Ok(detection(&[("en", 0.9)])));
        let other = LanguageCallV1::new(Digest::of("test.bundle", b"other"), "text".to_owned());
        assert_eq!(
            other.run(parent.as_ref()),
            Err(LanguageBridgeError::BundleMismatch)
        );
        let mut tampered = LanguageCallV1::new(bundle(), "text".to_owned());
        tampered.text.push('!');
        assert_eq!(
            tampered.run(parent.as_ref()),
            Err(LanguageBridgeError::InputDigestMismatch)
        );
        let oversized = LanguageCallV1::new(bundle(), "x".repeat(MAX_LANGUAGE_TEXT_BYTES + 1));
        assert_eq!(
            oversized.run(parent.as_ref()),
            Err(LanguageBridgeError::TextTooLarge)
        );
        assert_eq!(parent.calls(), 0);
    }

    #[test]
    fn replay_rejects_other_input_second_call_and_missing_call() {
        let call = LanguageCallV1::new(bundle(), "text".to_owned());
        let parent = Fake::new(bundle(), Ok(detection(&[("en", 0.9)])));
        let reply = call.run(parent.as_ref()).unwrap();

        let replay = LanguageReplay::new(reply.clone());
        assert_eq!(replay.finish(), Err(LanguageBridgeError::NotConsumed));
        assert_eq!(
            replay.handle().detector().detect("other"),
            Err(LanguageDetectionErrorV1::Unavailable)
        );
        assert_eq!(replay.finish(), Err(LanguageBridgeError::InputDigestMismatch));

        let replay = LanguageReplay::new(reply);
        assert!(replay.handle().detector().detect("text").is_ok());
        assert!(replay.finish().is_ok());
        assert_eq!(
            replay.handle().detector().detect("text"),
            Err(LanguageDetectionErrorV1::Unavailable)
        );
        assert_eq!(replay.finish(), Err(LanguageBridgeError::TooManyCalls));
    }

    #[test]
    fn declared_only_and_declared_language_never_call_the_detector() {
        for (mode, html) in [
            (LanguageModeV1::DeclaredOnly, HTML),
            (LanguageModeV1::DeclaredThenDetect, DECLARED_HTML),
        ] {
            let capture = LanguageCapture::new(bundle(), budget());
            let document = extract(html, &policy(mode), Some(capture.handle()));
            assert!(!document.article.unwrap().metadata.language_model_unavailable);
            assert!(capture.take().unwrap().is_none());
        }
    }

    #[test]
    fn capture_has_the_original_bundle_and_calls_at_most_once() {
        let capture = LanguageCapture::new(bundle(), budget());
        let handle = capture.handle();
        assert_eq!(handle.detector().bundle_digest(), bundle());
        assert_eq!(
            handle.detector().detect("one"),
            Err(LanguageDetectionErrorV1::Unavailable)
        );
        assert_eq!(
            handle.detector().detect("two"),
            Err(LanguageDetectionErrorV1::Unavailable)
        );
        assert_eq!(capture.take().unwrap_err(), LanguageBridgeError::TooManyCalls);
        assert!(capture.take().unwrap().is_none());
    }

    #[test]
    fn capture_charges_before_copy_and_holds_until_released() {
        let shared = Arc::new(ByteBudget::new(5));
        let capture = LanguageCapture::new(bundle(), Arc::clone(&shared));
        assert!(capture.handle().detector().detect("hello").is_err());
        assert_eq!(shared.used(), 5);
        let captured = capture.take().unwrap().unwrap();
        assert_eq!(captured.wire().text, "hello");
        let (call, hold) = captured.into_wire();
        assert_eq!((call.text.as_str(), hold.bytes(), shared.used()), ("hello", 5, 5));
        drop(hold);
        assert_eq!(shared.used(), 0);

        let capture = LanguageCapture::new(bundle(), Arc::clone(&shared));
        assert!(capture.handle().detector().detect("hello!").is_err());
        match capture.take().unwrap_err() {
            LanguageBridgeError::Budget(error) => assert_eq!((error.requested, error.limit), (6, 5)),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(shared.used(), 0);

        let capture = LanguageCapture::new(bundle(), budget());
        let huge = "x".repeat(MAX_LANGUAGE_TEXT_BYTES + 1);
        assert!(capture.handle().detector().detect(&huge).is_err());
        assert_eq!(capture.take().unwrap_err(), LanguageBridgeError::TextTooLarge);
    }

    #[test]
    fn wire_roundtrips_rejects_unknown_fields_and_redacts_debug() {
        let capture = LanguageCapture::new(bundle(), budget());
        assert!(capture.handle().detector().detect("secret body").is_err());
        let captured = capture.take().unwrap().unwrap();
        let borrowed = serde_json::to_value(captured.wire()).unwrap();
        let debug = format!("{captured:?} {:?}", captured.wire());
        assert!(!debug.contains("secret"));
        let (call, _hold) = captured.into_wire();
        assert_eq!(serde_json::to_value(&call).unwrap(), borrowed);
        assert!(!format!("{call:?}").contains("secret"));
        let back: LanguageCallV1 = serde_json::from_value(borrowed.clone()).unwrap();
        assert_eq!(back, call);
        let mut extra = borrowed;
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<LanguageCallV1>(extra).is_err());

        let parent = Fake::new(bundle(), Ok(detection(&[("en", 0.9)])));
        let reply = call.run(parent.as_ref()).unwrap();
        let json = serde_json::to_string(&reply).unwrap();
        assert_eq!(serde_json::from_str::<LanguageReplyV1>(&json).unwrap(), reply);
        let failed = LanguageReplyV1::new(
            bundle(),
            reply.input_digest,
            LanguageOutcomeV1::Failed {
                error: LanguageErrorV1::ResourceLimit,
            },
        );
        let json = serde_json::to_string(&failed).unwrap();
        assert_eq!(serde_json::from_str::<LanguageReplyV1>(&json).unwrap(), failed);
        assert!(serde_json::from_str::<LanguageReplyV1>(&json.replace("resource_limit", "other")).is_err());
    }
}
