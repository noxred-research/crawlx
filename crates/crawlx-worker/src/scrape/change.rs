//! The `changeTracking` format: the page against the previous stored scrape of the same URL.
//!
//! The baseline is the newest stored scrape of the tenant for the URL that asked for
//! `changeTracking` with the same `tag`, is cacheable (so not `storeInCache: false`, not a
//! zero-data-retention run, and a 2xx answer) and whose markdown artifact is still readable.
//! `changeStatus` compares markdown:
//!
//! * `new`: no baseline;
//! * `removed`: the page answers `404` or `410` and a baseline exists;
//! * `same`: the markdown equals the baseline's, ignoring the `src` of embedded `<iframe>` tags
//!   (their per-request tokens would make every fetch a change);
//! * `changed`: it differs. Then `git-diff` (the default mode) adds `diff{text,json}`, and the
//!   `json` mode runs the LLM extraction over the baseline and the current markdown with the
//!   requested schema and prompt and adds `json{field: {previous, current}}`.
//!
//! `visibility` is `visible` when the link graph or a sitemap still reaches the URL, `hidden`
//! when nothing does or the page is gone (see [`super::visibility`]).

use crate::scrape::llm::{charge, failure};
use crate::scrape::{rfc3339, ScrapeFailure};
use crawlx_core::repo::{ArtifactStore, PageRepo, RunRepo};
use crawlx_core::scrape::{ChangeMode, ChangeStatus, ChangeTrackingResult, ScrapeDocument};
use crawlx_core::{CanonicalUrl, StoreError, TenantId, Timestamp};
use crawlx_extract::diff::{json_diff, markdown_diff};
use crawlx_model::llm::{LlmExtractor, TokenUsage};
use serde_json::{json, Value};
use std::borrow::Cow;

/// Stored scrapes of the URL examined for a baseline.
const CANDIDATES: u32 = 32;

/// The previous stored scrape a page is compared with.
pub(crate) struct Baseline {
    markdown: String,
    at: Timestamp,
}

/// What the request asked of the format.
pub(crate) struct Request<'a> {
    pub modes: &'a [ChangeMode],
    pub schema: Option<&'a Value>,
    pub prompt: Option<&'a str>,
}

/// The newest usable baseline of `url` for `tag`.
///
/// # Errors
/// [`StoreError`] when listing the stored pages or reading an artifact fails (an artifact that
/// no longer exists only disqualifies its page).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn baseline(
    pages: &dyn PageRepo,
    artifacts: &dyn ArtifactStore,
    runs: &dyn RunRepo,
    tenant: TenantId,
    url: &CanonicalUrl,
    tag: Option<&str>,
    expected_identity: crawlx_core::hash::Digest,
    now: Timestamp,
) -> Result<Option<Baseline>, StoreError> {
    for page in pages.recent_for_url(tenant, url, CANDIDATES).await? {
        let Some(doc) = ScrapeDocument::from_page_metadata(&page.metadata) else {
            continue;
        };
        if doc.not_cacheable
            || doc.options_digest != expected_identity
            || doc.change_tracking.is_none()
            || doc.change_tag.as_deref() != tag
        {
            continue;
        }
        let owner = match runs.get(page.run).await {
            Ok(owner) => owner,
            Err(StoreError::NotFound { .. }) => continue,
            Err(error) => return Err(error),
        };
        if owner.tenant != tenant
            || owner.config.retention.mode == crawlx_core::config::RetentionMode::Zdr
            || owner.config.retention.days == 0
            || owner.created_at + chrono::Duration::days(i64::from(owner.config.retention.days)) <= now
        {
            continue;
        }
        let Some(markdown) = &page.markdown else {
            continue;
        };
        match artifacts.get(markdown).await {
            Ok(bytes) => {
                return Ok(Some(Baseline {
                    markdown: String::from_utf8_lossy(&bytes).into_owned(),
                    at: page.fetched_at,
                }))
            }
            Err(StoreError::NotFound { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// The `changeTracking` result of a page whose markdown is `markdown` and HTTP status `status`.
/// `visible` says whether the link graph still reaches the page ([`super::visibility`]); a page
/// that answers `404`/`410` is `hidden` whatever the graph says.
///
/// # Errors
/// An LLM failure of the `json` mode, as [`ScrapeFailure`].
pub(crate) async fn track(
    llm: Option<&dyn LlmExtractor>,
    baseline: Option<Baseline>,
    status: u16,
    visible: bool,
    markdown: &str,
    request: &Request<'_>,
    doc: &mut ScrapeDocument,
) -> Result<ChangeTrackingResult, ScrapeFailure> {
    let mut result = ChangeTrackingResult {
        previous_scrape_at: None,
        change_status: ChangeStatus::New,
        visibility: if visible && !matches!(status, 404 | 410) {
            "visible"
        } else {
            "hidden"
        }
        .to_owned(),
        diff: None,
        json: None,
    };
    let Some(previous) = baseline else {
        return Ok(result);
    };
    result.previous_scrape_at = Some(rfc3339(previous.at));
    if matches!(status, 404 | 410) {
        result.change_status = ChangeStatus::Removed;
        return Ok(result);
    }
    if without_iframe_src(&previous.markdown) == without_iframe_src(markdown) {
        result.change_status = ChangeStatus::Same;
        return Ok(result);
    }
    result.change_status = ChangeStatus::Changed;
    let modes = request.modes;
    if modes.is_empty() || modes.contains(&ChangeMode::GitDiff) {
        let d = markdown_diff(&previous.markdown, markdown);
        result.diff = Some(json!({ "text": d.text, "json": d.json }));
    }
    if modes.contains(&ChangeMode::Json) {
        if let Some(llm) = llm {
            let mut usage = TokenUsage::default();
            let before = llm
                .json(&previous.markdown, request.schema, request.prompt)
                .await
                .map_err(|e| failure(&e))?;
            usage.add(before.usage);
            let now = llm
                .json(markdown, request.schema, request.prompt)
                .await
                .map_err(|e| failure(&e))?;
            usage.add(now.usage);
            charge(doc, usage);
            result.json = Some(json_diff(&before.value, &now.value));
        }
    }
    Ok(result)
}

/// `text` with the value of the `src` attribute of every `<iframe …>` tag blanked.
///
/// Embedded frames carry per-request tokens (challenge widgets, session ids), so two fetches of an
/// unchanged page differ in them; the comparison of `changeTracking` ignores those values, the
/// diff and the stored markdown keep them.
fn without_iframe_src(text: &str) -> Cow<'_, str> {
    const TAG: &[u8] = b"<iframe";
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut copied = 0;
    let mut i = 0;
    while i + TAG.len() <= bytes.len() {
        let is_tag = bytes[i] == b'<'
            && bytes[i..i + TAG.len()].eq_ignore_ascii_case(TAG)
            && bytes
                .get(i + TAG.len())
                .is_none_or(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'));
        if !is_tag {
            i += 1;
            continue;
        }
        let (end, src) = iframe_src_value(&text[i..]);
        if let Some((from, to)) = src {
            out.push_str(&text[copied..i + from]);
            copied = i + to;
        }
        i += end;
    }
    if copied == 0 {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[copied..]);
    Cow::Owned(out)
}

/// Tag end and byte range of its `src` value (without quotes), including truncated tags.
fn iframe_src_value(tag: &str) -> (usize, Option<(usize, usize)>) {
    let bytes = tag.as_bytes();
    let skip_space = |mut k: usize| {
        while bytes.get(k).is_some_and(u8::is_ascii_whitespace) {
            k += 1;
        }
        k
    };
    let mut i = b"<iframe".len();
    let mut src = None;
    while i < bytes.len() {
        i = skip_space(i);
        match bytes.get(i) {
            Some(b'>') => return (i + 1, src),
            Some(b'/') => {
                i += 1;
                continue;
            }
            None => break,
            Some(_) => {}
        }
        let name = i;
        while bytes
            .get(i)
            .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(b, b'=' | b'/' | b'>'))
        {
            i += 1;
        }
        let is_src = bytes[name..i].eq_ignore_ascii_case(b"src");
        i = skip_space(i);
        if bytes.get(i) != Some(&b'=') {
            continue;
        }
        i = skip_space(i + 1);
        let quote = bytes.get(i).copied().filter(|b| matches!(b, b'"' | b'\''));
        if quote.is_some() {
            i += 1;
        }
        let start = i;
        while bytes.get(i).is_some_and(|b| match quote {
            Some(quote) => *b != quote,
            None => !b.is_ascii_whitespace() && *b != b'>',
        }) {
            i += 1;
        }
        if is_src && src.is_none() && start < i {
            src = Some((start, i));
        }
        if quote.is_some() && i < bytes.len() {
            i += 1;
        }
    }
    (bytes.len(), src)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::scrape::ScrapeOptions;

    fn doc() -> ScrapeDocument {
        ScrapeDocument::new(
            "https://a.test/".to_owned(),
            "https://a.test/".to_owned(),
            200,
            ScrapeOptions::default().cache_digest(),
        )
    }

    fn baseline_of(markdown: &str) -> Baseline {
        Baseline {
            markdown: markdown.to_owned(),
            at: chrono::Utc::now(),
        }
    }

    fn request() -> Request<'static> {
        Request {
            modes: &[],
            schema: None,
            prompt: None,
        }
    }

    #[tokio::test]
    async fn status_follows_the_markdown_comparison() {
        let mut d = doc();
        let new = track(None, None, 200, true, "a", &request(), &mut d)
            .await
            .unwrap();
        assert_eq!(new.visibility, "visible");
        assert_eq!(new.change_status, ChangeStatus::New);
        assert!(new.previous_scrape_at.is_none());

        let same = track(None, Some(baseline_of("a")), 200, true, "a", &request(), &mut d)
            .await
            .unwrap();
        assert_eq!(same.change_status, ChangeStatus::Same);
        assert!(same.previous_scrape_at.is_some() && same.diff.is_none());

        let changed = track(
            None,
            Some(baseline_of("a\n")),
            200,
            false,
            "b\n",
            &request(),
            &mut d,
        )
        .await
        .unwrap();
        assert_eq!(changed.change_status, ChangeStatus::Changed);
        assert_eq!(changed.visibility, "hidden", "nothing links to the page");
        assert!(changed.diff.unwrap()["text"].as_str().unwrap().contains("+b"));

        for gone in [404, 410] {
            let removed = track(None, Some(baseline_of("a")), gone, true, "", &request(), &mut d)
                .await
                .unwrap();
            assert_eq!(removed.change_status, ChangeStatus::Removed);
            assert_eq!(
                removed.visibility, "hidden",
                "a gone page is hidden even when linked"
            );
        }
        let first_404 = track(None, None, 404, true, "", &request(), &mut d)
            .await
            .unwrap();
        assert_eq!(
            first_404.change_status,
            ChangeStatus::New,
            "nothing to remove without a baseline"
        );
    }

    #[test]
    fn iframe_src_is_blanked_in_every_tag_spelling() {
        let blanked = |s: &str| without_iframe_src(s).into_owned();
        assert_eq!(
            blanked(r#"a <iframe src="https://x.test/1?t=9" width=3></iframe> b"#),
            r#"a <iframe src="" width=3></iframe> b"#
        );
        assert_eq!(blanked("<IFRAME class=c SRC = 'u'>"), "<IFRAME class=c SRC = ''>");
        assert_eq!(blanked("<iframe src=u/1 id=x>"), "<iframe src= id=x>");
        assert_eq!(blanked("<iframe\n src=\"u\"\n>"), "<iframe\n src=\"\"\n>");
        // other tags and other attributes are left alone
        assert_eq!(
            blanked(r#"<img src="u"> <iframe data-src="u">"#),
            r#"<img src="u"> <iframe data-src="u">"#
        );
        assert_eq!(blanked(r#"<iframes src="u">"#), r#"<iframes src="u">"#);
        assert_eq!(blanked("<iframe src=\"u"), "<iframe src=\"");
        for (input, expected) in [
            ("<iframe SRC='u", "<iframe SRC='"),
            ("<iframe src=u", "<iframe src="),
            ("<iframe src=\"u>", "<iframe src=\""),
            ("<iframe src='u>", "<iframe src='"),
            ("<iframe src=\"u>v\" id=x>", "<iframe src=\"\" id=x>"),
            ("<iframe title='a>b' src=u>", "<iframe title='a>b' src=>"),
            (
                "<iframe title=\" src='keep'\" src=u>",
                "<iframe title=\" src='keep'\" src=>",
            ),
            ("<iframe/src=u>", "<iframe/src=>"),
            ("<iframe src=u'v id=x>", "<iframe src= id=x>"),
            ("é <iframe src='雪", "é <iframe src='"),
            ("<iframe src=>", "<iframe src=>"),
            ("<iframe src=\"", "<iframe src=\""),
            ("<iframe src=", "<iframe src="),
            ("<iframe", "<iframe"),
            ("<iframe data-src=u", "<iframe data-src=u"),
            ("<iframe src=u><IFRAME SRC='v", "<iframe src=><IFRAME SRC='"),
        ] {
            assert_eq!(blanked(input), expected, "{input:?}");
        }
        assert!(matches!(without_iframe_src("no tags"), Cow::Borrowed(_)));
    }

    #[tokio::test]
    async fn a_changed_iframe_src_alone_is_not_a_change() {
        let mut d = doc();
        let framed = |src: &str, text: &str| format!("{text}\n\n<iframe src=\"{src}\"></iframe>\n");
        let same = track(
            None,
            Some(baseline_of(&framed("https://c.test/?token=1", "Pricing"))),
            200,
            true,
            &framed("https://c.test/?token=2", "Pricing"),
            &request(),
            &mut d,
        )
        .await
        .unwrap();
        assert_eq!(same.change_status, ChangeStatus::Same);
        let changed = track(
            None,
            Some(baseline_of(&framed("https://c.test/?token=1", "Pricing"))),
            200,
            true,
            &framed("https://c.test/?token=2", "New pricing"),
            &request(),
            &mut d,
        )
        .await
        .unwrap();
        assert_eq!(changed.change_status, ChangeStatus::Changed);
        assert!(changed.diff.unwrap()["text"]
            .as_str()
            .unwrap()
            .contains("token=2"));
    }
}
