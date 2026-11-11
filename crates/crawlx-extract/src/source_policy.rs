//! Explicit freshness, encoded-reference and local-provider policy. No implicit acquisition.

use crawlx_core::{
    article_language::{ArticleLanguageDetector, LanguageDetectionErrorV1, LanguageDetectionV1},
    hash::Digest,
};
use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use url::Url;

/// Freshness from authored timestamps only; this is not HTTP cache validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceFreshness {
    /// No trustworthy authored comparison exists.
    Unknown,
    /// Authored modification time exceeds the supplied baseline.
    Modified,
    /// Authored modification time is not newer than the baseline.
    NotNewer,
    /// Incomplete source cannot establish freshness.
    Truncated,
}

/// Compare injected authored timestamps. Unknown stays unknown; wall time is never consulted.
#[must_use]
pub fn freshness(modified_ms: Option<i64>, baseline_ms: Option<i64>, truncated: bool) -> SourceFreshness {
    if truncated {
        return SourceFreshness::Truncated;
    }
    match modified_ms.zip(baseline_ms) {
        Some((modified, baseline)) if modified >= 0 && baseline >= 0 => {
            if modified > baseline {
                SourceFreshness::Modified
            } else {
                SourceFreshness::NotNewer
            }
        }
        _ => SourceFreshness::Unknown,
    }
}

/// Authored representation, never guessed recursively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceEncoding {
    /// Already decoded HTML attribute or literal reference.
    Literal,
    /// Exactly one layer of percent-encoded UTF-8.
    PercentEncoded,
    /// Exactly one XML entity layer; custom entities are prohibited.
    XmlEscaped,
}

/// Source policy failures never include rejected source content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourcePolicyError {
    /// Malformed, unsafe-scheme, credential-bearing or unsupported authored reference.
    #[error("invalid authored reference")]
    Reference,
    /// Finite input/output/operation limit exceeded.
    #[error("source policy budget exceeded")]
    Limit,
    /// Pinned local language capability missing, refused or malformed.
    #[error("source language capability failed")]
    Language(#[source] LanguageDetectionErrorV1),
}

/// Resolve one bounded authored URL layer. The result is a proposal, not egress authority.
///
/// # Errors
/// Refuses invalid encodings, non-HTTP(S), credentials and references longer than 4096 bytes.
pub fn reference(base: &Url, source: &str, encoding: ReferenceEncoding) -> Result<Url, SourcePolicyError> {
    if source.len() > 4096 {
        return Err(SourcePolicyError::Limit);
    }
    let decoded;
    let source = match encoding {
        ReferenceEncoding::Literal => source,
        ReferenceEncoding::XmlEscaped => {
            decoded = quick_xml::escape::unescape(source)
                .map_err(|_| SourcePolicyError::Reference)?
                .into_owned();
            decoded.as_str()
        }
        ReferenceEncoding::PercentEncoded => {
            let bytes = source.as_bytes();
            let mut output = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                if bytes[index] == b'%' {
                    let digits = bytes
                        .get(index + 1..index + 3)
                        .ok_or(SourcePolicyError::Reference)?;
                    let high = char::from(digits[0])
                        .to_digit(16)
                        .ok_or(SourcePolicyError::Reference)?;
                    let low = char::from(digits[1])
                        .to_digit(16)
                        .ok_or(SourcePolicyError::Reference)?;
                    output.push(u8::try_from(high * 16 + low).map_err(|_| SourcePolicyError::Reference)?);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            decoded = String::from_utf8(output).map_err(|_| SourcePolicyError::Reference)?;
            decoded.as_str()
        }
    };
    if source.chars().any(char::is_control) {
        return Err(SourcePolicyError::Reference);
    }
    let mut url = base
        .join(source.trim())
        .map_err(|_| SourcePolicyError::Reference)?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return Err(SourcePolicyError::Reference);
    }
    url.set_fragment(None);
    Ok(url)
}

/// Relationship purpose is descriptive, never permission to navigate or submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HopKind {
    /// Ordinary authored hyperlink.
    Link,
    /// Embedded document/image/object reference.
    Embed,
    /// Script or stylesheet reference needed by the authored document.
    Prerequisite,
    /// Form action proposal only; method/safety admission still applies independently.
    FormActionProposal,
}

/// Bounded original-tree source relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceHop {
    /// Resolved HTTP(S) proposal.
    pub url: Url,
    /// Descriptive hop purpose.
    pub kind: HopKind,
    /// Lowercase source tag.
    pub tag: String,
    /// Original tree preorder node ordinal, not a fabricated byte offset.
    pub source_node: usize,
    /// Bounded normalized anchor text.
    pub anchor: String,
    /// Anchor cap omitted a suffix.
    pub anchor_truncated: bool,
}

/// Default hop bounds for page extraction: finite count, tree work and anchor text.
pub const DEFAULT_MAX_HOPS: usize = 4096;
/// Default node/text operations spent collecting hops from one owned document.
pub const DEFAULT_MAX_HOP_OPERATIONS: usize = 2_000_000;
/// Default UTF-8 bytes kept per hop anchor.
pub const DEFAULT_MAX_ANCHOR_BYTES: usize = 256;

/// Finalized privacy projection: `Some` replaces a value, `None` keeps it.
pub type HopProjection<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Apply the run's existing finalized privacy projector before hop storage.
/// A rewritten URL is withheld because a projected destination is not authored authority.
#[must_use]
pub fn project_hops(hops: Vec<SourceHop>, project: Option<HopProjection<'_>>) -> Vec<SourceHop> {
    let Some(project) = project else { return hops };
    hops.into_iter()
        .filter_map(|mut hop| {
            if project(hop.url.as_str()).is_some_and(|value| value != hop.url.as_str()) {
                return None;
            }
            if let Some(anchor) = project(&hop.anchor) {
                hop.anchor = anchor;
            }
            Some(hop)
        })
        .collect()
}

/// Extract typed hops from an already owned DOM; no second parse or fetch occurs.
///
/// # Errors
/// Refuses invalid bounds. Hop-count and finite work caps stop collection explicitly; the
/// returned flag reports omitted relations. Anchor caps are recorded per hop.
pub fn hops(
    document: &Html,
    base: &Url,
    max_hops: usize,
    max_operations: usize,
    max_anchor_bytes: usize,
) -> Result<(Vec<SourceHop>, bool), SourcePolicyError> {
    if max_hops > 100_000 || max_operations == 0 || max_anchor_bytes > 4096 {
        return Err(SourcePolicyError::Limit);
    }
    let mut output = Vec::new();
    let mut operations = 0_usize;
    for (source_node, node) in document.tree.root().descendants().enumerate() {
        operations = operations.checked_add(1).ok_or(SourcePolicyError::Limit)?;
        if operations > max_operations {
            return Ok((output, true));
        }
        let Some(element) = ElementRef::wrap(node) else {
            continue;
        };
        let (attribute, kind) = match element.value().name() {
            "a" | "area" => ("href", HopKind::Link),
            "img" | "iframe" | "frame" | "embed" => ("src", HopKind::Embed),
            "object" => ("data", HopKind::Embed),
            "script" => ("src", HopKind::Prerequisite),
            "link"
                if element.value().attr("rel").is_some_and(|rel| {
                    rel.split_ascii_whitespace()
                        .any(|token| token.eq_ignore_ascii_case("stylesheet"))
                }) =>
            {
                ("href", HopKind::Prerequisite)
            }
            "form" => ("action", HopKind::FormActionProposal),
            _ => continue,
        };
        let Some(raw) = element.value().attr(attribute) else {
            continue;
        };
        let Ok(url) = reference(base, raw, ReferenceEncoding::Literal) else {
            continue;
        };
        if output.len() >= max_hops {
            return Ok((output, true));
        }
        let mut anchor = String::new();
        let mut anchor_truncated = false;
        if kind == HopKind::Link {
            'text: for text in element.text() {
                for word in text.split_whitespace() {
                    operations = operations
                        .checked_add(word.len().saturating_add(1))
                        .ok_or(SourcePolicyError::Limit)?;
                    if operations > max_operations {
                        return Ok((output, true));
                    }
                    let separator = usize::from(!anchor.is_empty());
                    if anchor.len().saturating_add(separator).saturating_add(word.len()) > max_anchor_bytes {
                        anchor_truncated = true;
                        break 'text;
                    }
                    if separator != 0 {
                        anchor.push(' ');
                    }
                    anchor.push_str(word);
                }
            }
        }
        output.push(SourceHop {
            url,
            kind,
            tag: element.value().name().to_owned(),
            source_node,
            anchor,
            anchor_truncated,
        });
    }
    Ok((output, false))
}

/// Invoke only an explicitly installed digest-pinned local detector on already approved text.
/// Missing provider never becomes an implicit model download, network request or default language.
///
/// # Errors
/// Refuses missing/wrong provider, byte excess and malformed/digest-mismatched provider results.
pub fn detect_language(
    text: &str,
    max_bytes: usize,
    approved_bundle: Digest,
    provider: Option<&dyn ArticleLanguageDetector>,
) -> Result<LanguageDetectionV1, SourcePolicyError> {
    if text.len() > max_bytes || max_bytes > 1024 * 1024 {
        return Err(SourcePolicyError::Limit);
    }
    let provider = provider
        .filter(|provider| provider.bundle_digest() == approved_bundle)
        .ok_or(SourcePolicyError::Language(LanguageDetectionErrorV1::Unavailable))?;
    let detected = provider.detect(text).map_err(SourcePolicyError::Language)?;
    if detected.bundle_digest != approved_bundle {
        return Err(SourcePolicyError::Language(LanguageDetectionErrorV1::Malformed));
    }
    LanguageDetectionV1::new(detected.bundle_digest, detected.scores, detected.truncated)
        .map_err(SourcePolicyError::Language)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    struct LocalProvider {
        bundle: Digest,
        returned: Digest,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl ArticleLanguageDetector for LocalProvider {
        fn bundle_digest(&self) -> Digest {
            self.bundle
        }
        fn detect(&self, _text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            LanguageDetectionV1::new(
                self.returned,
                vec![crawlx_core::article_language::LanguageScoreV1::new(
                    "en".into(),
                    0.9,
                )?],
                false,
            )
        }
    }

    #[test]
    fn pinned_provider_runs_only_after_capability_and_byte_checks() {
        let bundle = Digest::of("bundle", b"approved");
        let provider = LocalProvider {
            bundle,
            returned: bundle,
            calls: Default::default(),
        };
        let detected = detect_language("approved text", 100, bundle, Some(&provider)).unwrap();
        assert_eq!(detected.scores[0].language, "en");
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(detect_language("too long", 1, bundle, Some(&provider)).is_err());
        assert!(detect_language("text", 100, Digest::of("bundle", b"other"), Some(&provider)).is_err());
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        let malformed = LocalProvider {
            bundle,
            returned: Digest::of("bundle", b"wrong"),
            calls: Default::default(),
        };
        assert!(detect_language("text", 100, bundle, Some(&malformed)).is_err());
    }

    #[test]
    fn authored_encoded_url_corpus_decodes_once() {
        let base = Url::parse("https://example.test/root/").unwrap();
        for (source, encoding, expected) in [
            (
                "../a%2Fb?q=a%26b#part",
                ReferenceEncoding::Literal,
                "https://example.test/a%2Fb?q=a%26b",
            ),
            (
                "https%3A%2F%2Fexample.test%2Fa%3Fx%3D1%26y%3D2",
                ReferenceEncoding::PercentEncoded,
                "https://example.test/a?x=1&y=2",
            ),
            (
                "/a?x=1&amp;y=2",
                ReferenceEncoding::XmlEscaped,
                "https://example.test/a?x=1&y=2",
            ),
            (
                "/a%252Fb",
                ReferenceEncoding::Literal,
                "https://example.test/a%252Fb",
            ),
        ] {
            assert_eq!(reference(&base, source, encoding).unwrap().as_str(), expected);
        }
        for source in [
            "javascript:alert(1)",
            "data:text/plain,x",
            "https://user:secret@example.test/",
            "%00",
            "%zz",
        ] {
            assert!(reference(&base, source, ReferenceEncoding::PercentEncoded).is_err());
        }
    }

    #[test]
    fn form_and_embed_are_only_typed_proposals() {
        let document = Html::parse_document("<a href='/a'>hello world</a><form method='post' action='/destroy'></form><iframe src='/frame'></iframe>");
        let (output, truncated) = hops(
            &document,
            &Url::parse("https://example.test/").unwrap(),
            4,
            1000,
            5,
        )
        .unwrap();
        assert!(!truncated);
        assert_eq!(output[0].kind, HopKind::Link);
        assert!(output[0].anchor_truncated);
        assert_eq!(output[1].kind, HopKind::FormActionProposal);
        assert_eq!(output[2].kind, HopKind::Embed);
        assert!(output[0].source_node < output[1].source_node);
        let (capped, truncated) = hops(
            &document,
            &Url::parse("https://example.test/").unwrap(),
            1,
            1000,
            5,
        )
        .unwrap();
        assert_eq!(capped.len(), 1);
        assert!(truncated);
        let projected = project_hops(
            output,
            Some(&|value: &str| {
                value
                    .contains("destroy")
                    .then(|| "https://example.test/redacted".to_owned())
                    .or_else(|| (value == "hello").then(|| "[REDACTED]".to_owned()))
            }),
        );
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[0].anchor, "[REDACTED]");
        assert!(!serde_json::to_string(&projected)
            .unwrap()
            .contains("form_action_proposal"));
    }

    #[test]
    fn missing_language_stays_unknown_and_freshness_is_not_clock_guessing() {
        assert!(detect_language("unknown", 100, Digest::of("bundle", b"approved"), None).is_err());
        assert_eq!(freshness(None, Some(100), false), SourceFreshness::Unknown);
        assert_eq!(freshness(Some(200), Some(100), true), SourceFreshness::Truncated);
        assert_eq!(freshness(Some(200), Some(100), false), SourceFreshness::Modified);
    }
}
