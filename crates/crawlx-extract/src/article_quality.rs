//! Content-only gates. Acquisition outcomes never change here.
use crawlx_core::extraction::{
    ArticleMetadataV1, ExtractionPolicyV1, NlpCapabilityV1, QualityOutcomeV1, QualityReasonV1,
    QualityStatusV1, RequiredMetadataV1,
};

fn normalized_author(name: &str) -> impl Iterator<Item = char> + '_ {
    name.split_whitespace().flat_map(|word| {
        word.chars()
            .flat_map(char::to_lowercase)
            .chain(std::iter::once(' '))
    })
}

/// Check before privacy projection so scrubbing cannot turn an excluded author
/// into an accepted article. Preserve evidence; only ingestion eligibility changes.
pub(crate) fn author_excluded(policy: &ExtractionPolicyV1, metadata: &ArticleMetadataV1) -> bool {
    if policy.excluded_authors.is_empty() {
        return false;
    }
    metadata
        .authors
        .value
        .iter()
        .flatten()
        .map(String::as_str)
        .chain(
            metadata
                .authors
                .evidence
                .iter()
                .map(|evidence| evidence.raw.as_str()),
        )
        .any(|name| {
            policy
                .excluded_authors
                .iter()
                .any(|excluded| normalized_author(name).eq(normalized_author(excluded)))
        })
}

pub(crate) fn evaluate(
    policy: &ExtractionPolicyV1,
    metadata: &ArticleMetadataV1,
    main: &str,
    blocks: usize,
    operations: usize,
    partial: bool,
    author_excluded: bool,
) -> QualityOutcomeV1 {
    let mut reasons = Vec::new();
    let chars = main.chars().count();
    if chars < policy.min_main_chars {
        reasons.push(QualityReasonV1::TooShort);
    }
    if policy.required_metadata.iter().any(|field| match field {
        RequiredMetadataV1::Title => metadata.title.value.is_none(),
        RequiredMetadataV1::Author => metadata.authors.value.is_none(),
        RequiredMetadataV1::PublishedDate => metadata.published.value.is_none(),
        RequiredMetadataV1::Language => metadata.language.value.is_none(),
        RequiredMetadataV1::Url => false, // Extractor requires a parsed caller URL.
        _ => true,
    }) {
        reasons.push(QualityReasonV1::MissingRequiredMetadata);
    }
    if author_excluded {
        reasons.push(QualityReasonV1::AuthorExcluded);
    }
    if let Some(target) = &policy.target_language {
        match metadata.language.value.as_deref() {
            None => reasons.push(QualityReasonV1::LanguageUnknown),
            Some(language)
                if !language.eq_ignore_ascii_case(target)
                    && (target.contains('-')
                        || !language
                            .split('-')
                            .next()
                            .is_some_and(|base| base.eq_ignore_ascii_case(target))) =>
            {
                reasons.push(QualityReasonV1::LanguageMismatch)
            }
            Some(_) => {}
        }
    }
    if partial {
        reasons.push(QualityReasonV1::ResourceLimit);
    }
    let unavailable = policy.nlp == NlpCapabilityV1::SentenceModel || metadata.language_model_unavailable;
    if unavailable {
        reasons.push(QualityReasonV1::ModelUnavailable);
    }
    let status = if unavailable {
        QualityStatusV1::Unavailable
    } else if partial {
        QualityStatusV1::Partial
    } else if reasons.is_empty() {
        QualityStatusV1::Accepted
    } else {
        QualityStatusV1::Rejected
    };
    QualityOutcomeV1::new(status, reasons, chars, blocks, operations)
}

/// Content-dedupe stage: the normalized title and body were already admitted in this cache
/// scope. Only an otherwise accepted document reaches this call; it becomes rejected for
/// ingestion while its counts and the acquisition stay recorded.
pub(crate) fn mark_duplicate_main(outcome: &mut QualityOutcomeV1) {
    if !outcome.reasons.contains(&QualityReasonV1::DuplicateMain) {
        outcome.reasons.push(QualityReasonV1::DuplicateMain);
    }
    outcome.status = QualityStatusV1::Rejected;
}
