//! The `changeTracking` format: the page against the previous stored scrape of the same URL.
//!
//! The baseline is the newest stored scrape of the tenant for the URL that asked for
//! `changeTracking` with the same `tag`, is cacheable (so not `storeInCache: false`, not a
//! zero-data-retention run, and a 2xx answer) and whose markdown artifact is still readable.
//! `changeStatus` compares markdown:
//!
//! * `new`: no baseline;
//! * `removed`: the page answers `404` or `410` and a baseline exists;
//! * `same`: the markdown equals the baseline's;
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
    if previous.markdown == markdown {
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
}
