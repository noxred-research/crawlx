//! Bodyless method validation must not invent document evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::acquisition::{ValidationCategoryV1, ValidationContextV1};
use crawlx_extract::validation::{validate_acquisition, ValidationInput};

fn head_context() -> ValidationContextV1 {
    let mut context = ValidationContextV1::default();
    context.method_head = true;
    context.transport_succeeded = true;
    context.target_status = Some(200);
    context.policy.required_selectors = vec!["#article".into()];
    context.policy.minimum_text_bytes = 100;
    context
}

#[test]
fn head_never_uses_body_or_dom_to_satisfy_document_expectations() {
    let context = head_context();
    let body = b"<form id=challenge-form><input type=password></form>";
    let document = scraper::Html::parse_document(std::str::from_utf8(body).unwrap());
    let result = validate_acquisition(&ValidationInput {
        context: &context,
        content_type: Some("text/html"),
        headers: &[],
        body,
        document: Some(&document),
    });
    assert_eq!(result.category, ValidationCategoryV1::Valid);
    assert!(result.content_accepted);
    assert_eq!(result.signals, ["body_expectations_unobserved_head"]);
}

#[test]
fn head_retains_status_and_mime_failures_without_body_failures() {
    for (status, mime, expected) in [
        (Some(200), "text/html", ValidationCategoryV1::Valid),
        (Some(304), "text/html", ValidationCategoryV1::Valid),
        (
            Some(200),
            "application/json",
            ValidationCategoryV1::ContentMismatch,
        ),
        (Some(401), "text/html", ValidationCategoryV1::AuthRequired),
        (Some(429), "text/html", ValidationCategoryV1::RateLimited),
        (Some(503), "text/html", ValidationCategoryV1::TargetError),
        (None, "text/html", ValidationCategoryV1::Indeterminate),
    ] {
        let mut context = head_context();
        context.target_status = status;
        context.policy.expected_content_types = vec!["text/html".into()];
        let result = validate_acquisition(&ValidationInput {
            context: &context,
            content_type: Some(mime),
            headers: &[],
            body: &[],
            document: None,
        });
        assert_eq!(result.category, expected, "{status:?}");
        assert!(result
            .signals
            .iter()
            .any(|signal| signal == "body_expectations_unobserved_head"));
        assert!(!result.signals.iter().any(|signal| matches!(
            signal.as_str(),
            "required_selector_missing" | "minimum_text_not_met" | "matching_cached_body_unavailable"
        )));
    }
}

#[test]
fn head_does_not_hide_invalid_rules_and_get_still_requires_body_evidence() {
    let mut context = head_context();
    context.policy.required_selectors = vec!["[".into()];
    let result = validate_acquisition(&ValidationInput {
        context: &context,
        content_type: Some("text/html"),
        headers: &[],
        body: &[],
        document: None,
    });
    assert_eq!(result.category, ValidationCategoryV1::Indeterminate);
    assert!(!result.content_accepted);

    context = head_context();
    context.method_head = false;
    let result = validate_acquisition(&ValidationInput {
        context: &context,
        content_type: Some("text/html"),
        headers: &[],
        body: b"short",
        document: None,
    });
    assert_eq!(result.category, ValidationCategoryV1::ContentMismatch);
    assert!(!result.content_accepted);
    assert!(result
        .signals
        .iter()
        .any(|signal| signal == "required_selector_missing"));
    assert!(result
        .signals
        .iter()
        .any(|signal| signal == "minimum_text_not_met"));

    context.target_status = Some(304);
    let result = validate_acquisition(&ValidationInput {
        context: &context,
        content_type: Some("text/html"),
        headers: &[],
        body: &[],
        document: None,
    });
    assert_eq!(result.category, ValidationCategoryV1::Indeterminate);
    assert!(result
        .signals
        .iter()
        .any(|signal| signal == "matching_cached_body_unavailable"));
}
