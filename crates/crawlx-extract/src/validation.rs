//! Deterministic response validation over borrowed response bytes and an existing HTML DOM.
//!
//! Clean-room native rules, not upstream challenge/stealth code.
//! No network, clock, fetcher, model, or secret resolution is used here.

use crawlx_core::acquisition::{
    AcquisitionPolicyError, RetryClassV1, ValidationCategoryV1 as Category, ValidationContextV1,
    ValidationOutcomeV1, ValidationPolicyV1,
};
use scraper::{Html, Selector};

/// Borrowed, bounded acquisition evidence. The caller retains body ownership.
pub struct ValidationInput<'a> {
    /// Body-free transport facts and requested checks.
    pub context: &'a ValidationContextV1,
    /// Observed Content-Type; browser DOM does not change response MIME evidence.
    pub content_type: Option<&'a str>,
    /// Observed response headers, not request headers.
    pub headers: &'a [(String, String)],
    /// Decoded response prefix or serialized DOM.
    pub body: &'a [u8],
    /// Already parsed DOM, when this is an HTML representation.
    pub document: Option<&'a Html>,
}

/// Compile all bounded selectors during admission, before any network request.
///
/// # Errors
/// Returns unsupported rule/version/bounds or invalid CSS syntax.
pub fn compile_policy(policy: &ValidationPolicyV1) -> Result<Vec<Selector>, AcquisitionPolicyError> {
    policy.validate()?;
    policy
        .required_selectors
        .iter()
        .map(|selector| {
            Selector::parse(selector).map_err(|_| AcquisitionPolicyError("invalid required selector"))
        })
        .collect()
}

/// Classify response evidence with fixed precedence and stable signal identifiers.
///
/// Truncation never proves selector absence. A contact CAPTCHA or an article discussing
/// anti-bot software is not sufficient challenge evidence. HEAD never reads body/DOM evidence:
/// configured body checks emit `body_expectations_unobserved_head`, not selector/text success.
/// A GET 304 requires an owned matching cache body; HEAD 304 does not require or prove one.
/// Supplied HTML never gains invented target provenance.
#[must_use]
pub fn validate_acquisition(input: &ValidationInput<'_>) -> ValidationOutcomeV1 {
    let ctx = input.context;
    let mut signals = Vec::with_capacity(12);
    let mut signal = |code: &str| signals.push(code.to_owned());
    let rules = compile_policy(&ctx.policy);
    if rules.is_err() {
        signal("invalid_validation_rules");
    }
    if ctx.policy_blocked {
        signal("policy_denied");
    }
    if ctx.cancelled {
        signal("cancelled");
    }
    if !ctx.transport_succeeded {
        signal("transport_incomplete");
    }
    if ctx.truncated {
        signal("body_truncated");
    }
    let status = ctx.target_status;
    if ctx.method_head && status.is_none() {
        signal("target_status_unavailable");
    }
    let auth = matches!(status, Some(401 | 407));
    let limited = status == Some(429);
    let target_error = status.is_some_and(|s| s >= 400);
    if auth {
        signal("target_authentication");
    }
    if limited {
        signal("target_rate_limit");
    }
    if target_error {
        signal("target_error_status");
    }
    let header_challenge = input.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("cf-mitigated") && value.trim().eq_ignore_ascii_case("challenge")
    });
    if header_challenge {
        signal("authoritative_challenge_header");
    }
    let mut text_bytes = 0usize;
    let mut expected_structure = false;
    let mut challenge_structure = false;
    let mut login_form = false;
    if let Some(doc) = input.document.filter(|_| !ctx.method_head) {
        // Read text without a full-document String allocation. Script/style/template text is not content.
        for node in doc.tree.nodes() {
            if let Some(text) = node.value().as_text() {
                let hidden = node.ancestors().any(|parent| {
                    parent.value().as_element().is_some_and(|el| {
                        matches!(el.name(), "script" | "style" | "template" | "noscript")
                            || el.attr("hidden").is_some()
                    })
                });
                if !hidden {
                    text_bytes = text_bytes.saturating_add(text.trim().len());
                }
            }
            if let Some(el) = node.value().as_element() {
                let id = el.attr("id").unwrap_or("");
                if matches!(
                    id,
                    "challenge-form" | "cf-challenge-running" | "cf-chl-widget" | "challenge-stage"
                ) || el
                    .attr("action")
                    .is_some_and(|value| value.contains("/cdn-cgi/challenge-platform/"))
                {
                    challenge_structure = true;
                }
                if el.name() == "article" {
                    expected_structure = true;
                }
                if el.name() == "input"
                    && el
                        .attr("type")
                        .is_some_and(|v| v.eq_ignore_ascii_case("password"))
                {
                    login_form = true;
                }
            }
        }
    } else if !ctx.method_head {
        text_bytes = input
            .body
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .count();
    }
    if login_form {
        signal("login_form_present");
    }
    if challenge_structure {
        signal("challenge_structure_present");
    }
    let missing_selector = !ctx.method_head
        && match (&rules, input.document) {
            (Ok(selectors), Some(doc)) => selectors
                .iter()
                .any(|selector| doc.select(selector).next().is_none()),
            (Ok(selectors), None) => !selectors.is_empty(),
            (Err(_), _) => false,
        };
    if missing_selector {
        signal("required_selector_missing");
    }
    let short_text =
        !ctx.method_head && text_bytes < usize::try_from(ctx.policy.minimum_text_bytes).unwrap_or(usize::MAX);
    if short_text {
        signal("minimum_text_not_met");
    }
    if ctx.method_head && (ctx.policy.minimum_text_bytes > 0 || !ctx.policy.required_selectors.is_empty()) {
        signal("body_expectations_unobserved_head");
    }
    let mime = input
        .content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    let wrong_mime = !ctx.policy.expected_content_types.is_empty()
        && !ctx
            .policy
            .expected_content_types
            .iter()
            .any(|expected| mime.is_some_and(|actual| actual.eq_ignore_ascii_case(expected)));
    if wrong_mime {
        signal("unexpected_content_type");
    }
    // Structure alone does not reject ordinary articles or embedded contact widgets.
    let structural_challenge =
        challenge_structure && (missing_selector || short_text || (!expected_structure && text_bytes < 1024));
    if structural_challenge {
        signal("challenge_missing_expected_content");
    }
    let bodyless =
        ctx.method_head || status == Some(204) || (status == Some(304) && ctx.cached_body_available);
    let empty = !ctx.method_head && input.body.iter().all(u8::is_ascii_whitespace);
    if empty && !bodyless {
        signal("unexpected_empty_body");
    }
    let missing_cached_body = status == Some(304) && !ctx.method_head && !ctx.cached_body_available;
    if missing_cached_body {
        signal("matching_cached_body_unavailable");
    }
    let category = if ctx.policy_blocked {
        Category::PolicyBlocked
    } else if ctx.cancelled {
        Category::Indeterminate
    } else if !ctx.transport_succeeded {
        Category::TransportError
    } else if auth {
        Category::AuthRequired
    } else if limited {
        Category::RateLimited
    } else if status.is_some_and(|value| value >= 500) {
        Category::TargetError
    } else if header_challenge || structural_challenge {
        Category::Challenge
    } else if target_error {
        Category::TargetError
    } else if rules.is_err() || (ctx.method_head && status.is_none()) || missing_cached_body {
        Category::Indeterminate
    } else if wrong_mime {
        Category::ContentMismatch
    } else if ctx.truncated {
        Category::Indeterminate
    } else if missing_selector || short_text {
        Category::ContentMismatch
    } else if empty && !bodyless {
        Category::Empty
    } else {
        Category::Valid
    };
    let retry = match category {
        Category::TransportError => Some(RetryClassV1::Transport),
        Category::TargetError if status.is_some_and(|s| s >= 500) => Some(RetryClassV1::Target5xx),
        Category::RateLimited => Some(RetryClassV1::RateLimit),
        Category::Challenge => Some(RetryClassV1::Challenge),
        Category::ContentMismatch | Category::Empty => Some(RetryClassV1::ContentMismatch),
        _ => None,
    };
    let mut outcome = ValidationOutcomeV1::indeterminate();
    outcome.rule_set_version = ctx.policy.rule_set_version;
    outcome.category = category;
    outcome.signals = signals;
    outcome.retry_disposition = retry;
    outcome.content_accepted = category == Category::Valid;
    outcome
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn classify(
        status: u16,
        html: &str,
        truncated: bool,
        policy: ValidationPolicyV1,
        headers: Vec<(String, String)>,
    ) -> ValidationOutcomeV1 {
        let doc = Html::parse_document(html);
        let mut ctx = ValidationContextV1::default();
        ctx.policy = policy;
        ctx.target_status = Some(status);
        ctx.transport_succeeded = true;
        ctx.truncated = truncated;
        validate_acquisition(&ValidationInput {
            context: &ctx,
            content_type: Some("text/html; charset=utf-8"),
            headers: &headers,
            body: html.as_bytes(),
            document: Some(&doc),
        })
    }
    #[test]
    fn labeled_negative_controls_and_status_precedence() {
        let fixtures = [
            (
                200,
                "<article><h1>CAPTCHA and CDN research</h1><p>How anti-bot detection works.</p></article>",
                Category::Valid,
            ),
            (
                200, // wire-compat: page markup class of a checkbox widget (next line)
                "<main><h1>Contact</h1><form><div class='g-recaptcha'></div></form></main>",
                Category::Valid,
            ), // wire-compat: page markup class of a checkbox widget
            (
                200,
                "<article>News</article><form><input type=password></form>",
                Category::Valid,
            ),
            (
                200,
                "<form id=challenge-form>Verify you are human</form>",
                Category::Challenge,
            ),
            (
                200,
                "<main><form id=challenge-form>Verify you are human</form></main>",
                Category::Challenge,
            ),
            (
                429,
                "<form id=challenge-form>Verify you are human</form>",
                Category::RateLimited,
            ),
            (401, "<main>Sign in</main>", Category::AuthRequired),
            (503, "<main>Unavailable</main>", Category::TargetError),
            (204, "", Category::Valid),
            (200, "", Category::Empty),
        ];
        for (status, body, category) in fixtures {
            assert_eq!(
                classify(status, body, false, ValidationPolicyV1::default(), vec![]).category,
                category,
                "{status}: {body}"
            );
        }
        assert_eq!(
            classify(
                200,
                "<article>News</article>",
                false,
                ValidationPolicyV1::default(),
                vec![("cf-mitigated".into(), "challenge".into())]
            )
            .category,
            Category::Challenge
        );
    }
    #[test]
    fn incomplete_prefix_never_proves_absence_or_complete_body() {
        let mut policy = ValidationPolicyV1::default();
        policy.required_selectors = vec!["#expected".into()];
        assert_eq!(
            classify(200, "<main>Prefix</main>", true, policy.clone(), vec![]).category,
            Category::Indeterminate
        );
        assert_eq!(
            classify(200, "<main>Prefix</main>", false, policy.clone(), vec![]).category,
            Category::ContentMismatch
        );
        assert_eq!(
            classify(200, "<main id=expected>Prefix</main>", true, policy, vec![]).category,
            Category::Indeterminate
        );
        let mut mime = ValidationPolicyV1::default();
        mime.expected_content_types = vec!["application/json".into()];
        assert_eq!(
            classify(200, "<main>HTML</main>", false, mime, vec![]).category,
            Category::ContentMismatch
        );
        assert_eq!(
            classify(304, "", false, ValidationPolicyV1::default(), vec![]).category,
            Category::Indeterminate
        );
    }

    #[test]
    fn head_and_owned_cache_304_do_not_require_body_and_policy_wins() {
        let mut context = ValidationContextV1::default();
        context.transport_succeeded = true;
        context.target_status = Some(304);
        let classify = |context: &ValidationContextV1| {
            validate_acquisition(&ValidationInput {
                context,
                content_type: None,
                headers: &[],
                body: b"",
                document: None,
            })
        };
        assert_eq!(classify(&context).category, Category::Indeterminate);
        context.cached_body_available = true;
        assert_eq!(classify(&context).category, Category::Valid);
        context.target_status = Some(200);
        context.method_head = true;
        assert_eq!(classify(&context).category, Category::Valid);
        context.policy_blocked = true;
        context.target_status = Some(429);
        let blocked = classify(&context);
        assert_eq!(blocked.category, Category::PolicyBlocked);
        assert!(!blocked.content_accepted);
        assert!(blocked.signals.iter().any(|signal| signal == "target_rate_limit"));
    }
}
