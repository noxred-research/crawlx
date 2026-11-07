//! Select declared/detected evidence from an explicitly injected, pinned local capability.
use crawlx_core::{
    article_language::{ArticleLanguageDetector, LanguageModeV1},
    extraction::{ArticleMetadataV1, ExtractionPolicyV1, MetadataEvidenceV1, MetadataValueV1},
};

pub(crate) fn select(
    metadata: &mut ArticleMetadataV1,
    policy: &ExtractionPolicyV1,
    detector: Option<&dyn ArticleLanguageDetector>,
    text: &str,
) {
    metadata.declared_language.clone_from(&metadata.language.value);
    if policy.language_mode == LanguageModeV1::DeclaredOnly
        || (policy.language_mode == LanguageModeV1::DeclaredThenDetect && metadata.language.value.is_some())
    {
        return;
    }
    let Some(detector) =
        detector.filter(|detector| Some(detector.bundle_digest()) == policy.language_bundle_digest)
    else {
        unavailable(metadata, policy);
        return;
    };
    metadata.language_model_digest = Some(detector.bundle_digest());
    let Ok(result) = detector.detect(text) else {
        unavailable(metadata, policy);
        return;
    };
    let mut labels = std::collections::BTreeSet::new();
    if result.bundle_digest != detector.bundle_digest()
        || result.scores.len() > 176
        || result
            .scores
            .windows(2)
            .any(|pair| pair[0].probability < pair[1].probability)
        || result.scores.iter().any(|score| {
            !score.probability.is_finite()
                || !(0.0..=1.0).contains(&score.probability)
                || !(2..=3).contains(&score.language.len())
                || !score.language.bytes().all(|b| b.is_ascii_lowercase())
                || !labels.insert(&score.language)
        })
    {
        unavailable(metadata, policy);
        return;
    }
    let mut evidence = Vec::with_capacity(2);
    for (index, score) in result.scores.iter().take(2).enumerate() {
        let raw = format!("{} {:.8}", score.language, score.probability);
        evidence.push(MetadataEvidenceV1::new("pinned_language_model_v1", &raw, index));
    }
    let minimum = f64::from(policy.language_min_probability_millis) / 1000.0;
    let margin = f64::from(policy.language_min_margin_millis) / 1000.0;
    let second = result.scores.get(1).map_or(0.0, |score| score.probability);
    let selected = result
        .scores
        .first()
        .filter(|score| score.probability >= minimum && score.probability - second >= margin)
        .map(|score| score.language.clone());
    let unknown = selected.is_none();
    metadata.detected_language = MetadataValueV1::new(selected.clone(), evidence, unknown, result.truncated);
    metadata.language.value = selected;
    metadata.language.uncertain |= unknown
        || result.truncated
        || metadata
            .declared_language
            .as_deref()
            .zip(metadata.language.value.as_deref())
            .is_some_and(|(declared, detected)| declared.split('-').next() != Some(detected));
    for item in &metadata.detected_language.evidence {
        if metadata.language.evidence.len() == 32 {
            metadata.language.truncated = true;
            break;
        }
        metadata.language.evidence.push(item.clone());
    }
}
fn unavailable(metadata: &mut ArticleMetadataV1, policy: &ExtractionPolicyV1) {
    metadata.language_model_unavailable = true;
    metadata.detected_language.uncertain = true;
    if policy.language_mode == LanguageModeV1::Detect || metadata.language.value.is_none() {
        metadata.language.value = None;
        metadata.language.uncertain = true;
    }
}
