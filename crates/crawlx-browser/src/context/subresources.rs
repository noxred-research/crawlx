//! `PageOp::MeasureSubresources`: a digest of every image, stylesheet, script and font the page
//! loaded, for recrawl completeness. Bytes are read one resource at a time from the browser's
//! response buffer, digested and dropped; only the digest and the privacy-approved target leave.

use super::CdpContext;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use crawlx_core::browser::BrowserError;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{MAX_RECRAWL_RESOURCES, MAX_RECRAWL_TARGET_BYTES};
use crawlx_core::page_op::{MeasuredSubresource, MAX_MEASURED_SUBRESOURCES};
use crawlx_core::secret::Redactor;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// Domain separation of a subresource digest.
const DIGEST_DOMAIN: &str = "crawlx/recrawl-subresource/v1";
/// Target of a subresource whose URL failed privacy approval; it is never measured.
const WITHHELD_TARGET: &str = "urn:crawlx:withheld-subresource";
/// Target standing for subresources the resource tree held beyond the inspection bound.
const UNINSPECTED_TARGET: &str = "urn:crawlx:uninspected-subresources";
/// Resource types a recrawl compares (`Network.ResourceType` names in the resource tree).
const MEASURED_TYPES: [&str; 4] = ["Image", "Stylesheet", "Script", "Font"];
/// Largest response read and digested.
const RESOURCE_BYTES: usize = 4 * 1024 * 1024;
/// Largest total of the responses one measurement reads.
const TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Resource tree entries inspected; the rest is reported as uninspected.
const TREE_ENTRIES: usize = 4096;
/// Longest accepted URL.
const URL_BYTES: usize = 8192;
const DEADLINE: Duration = Duration::from_secs(30);

/// One resource-tree entry of a measured type.
struct Entry {
    frame: String,
    url: String,
    /// The browser reported the load as failed or cancelled.
    failed: bool,
}

/// What a resource URL becomes in a report.
enum Target {
    /// Not a network resource (`data:`, `blob:`, ...): part of the document itself.
    Inline,
    /// The URL failed privacy approval.
    Withheld,
    Approved(String),
}

fn approve(url: &str) -> Target {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return Target::Inline;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Target::Inline;
    }
    if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        return Target::Withheld;
    }
    parsed.set_fragment(None);
    if parsed.as_str().len() > URL_BYTES || !Redactor::new().is_clean_text(parsed.as_str()) {
        return Target::Withheld;
    }
    Target::Approved(parsed.into())
}

/// `target` cut to one byte over the recrawl target bound, at a character boundary, so the
/// report states that it was too long instead of tracking a prefix as if it were the URL.
fn bounded(mut target: String) -> String {
    let mut end = MAX_RECRAWL_TARGET_BYTES + 1;
    if target.len() > end {
        while !target.is_char_boundary(end) {
            end -= 1;
        }
        target.truncate(end);
    }
    target
}

fn collect(tree: &Value, out: &mut Vec<Entry>, seen: &mut usize) -> Result<(), BrowserError> {
    let frame = tree
        .get("frame")
        .and_then(|frame| frame.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| BrowserError::Unsupported("subresource tree frame is unavailable".to_owned()))?;
    for entry in tree
        .get("resources")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        *seen = seen.saturating_add(1);
        if *seen > TREE_ENTRIES {
            return Ok(());
        }
        let measured = entry
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| MEASURED_TYPES.contains(&kind));
        let Some(url) = entry.get("url").and_then(Value::as_str).filter(|_| measured) else {
            continue;
        };
        out.push(Entry {
            frame: frame.to_owned(),
            url: url.to_owned(),
            failed: entry.get("failed").and_then(Value::as_bool) == Some(true)
                || entry.get("canceled").and_then(Value::as_bool) == Some(true),
        });
    }
    for child in tree
        .get("childFrames")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        collect(child, out, seen)?;
    }
    Ok(())
}

impl CdpContext {
    /// `PageOp::MeasureSubresources`. Entries are sorted by target; a resource the browser no
    /// longer holds, one that failed, one over the size bounds and one whose URL failed privacy
    /// approval is listed without a digest, never left out. Resources beyond
    /// [`MAX_RECRAWL_RESOURCES`] are listed without a digest as well, so a page that no baseline
    /// can hold is visible as such.
    pub(super) async fn measure_subresources(&self) -> Result<Vec<MeasuredSubresource>, BrowserError> {
        tokio::time::timeout(DEADLINE, self.measure_subresources_impl())
            .await
            .map_err(|_| BrowserError::Timeout(30_000))?
    }

    async fn measure_subresources_impl(&self) -> Result<Vec<MeasuredSubresource>, BrowserError> {
        let (_, session) = self.session_for(None)?;
        let tree = session.send("Page.getResourceTree", json!({})).await?;
        let mut entries = Vec::new();
        let mut seen = 0usize;
        collect(
            tree.get("frameTree")
                .ok_or_else(|| BrowserError::Unsupported("subresource tree is unavailable".to_owned()))?,
            &mut entries,
            &mut seen,
        )?;
        // target -> where the identity of its response is looked up; `None` is never measured
        let mut targets: BTreeMap<String, Option<(String, String)>> = BTreeMap::new();
        for entry in entries {
            let target = match approve(&entry.url) {
                Target::Inline => continue,
                Target::Withheld => (WITHHELD_TARGET.to_owned(), false),
                Target::Approved(target) if target.len() > MAX_RECRAWL_TARGET_BYTES => {
                    (bounded(target), false)
                }
                Target::Approved(target) => (target, !entry.failed),
            };
            let source = target.1.then_some((entry.frame, entry.url));
            match targets.entry(target.0) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(source);
                }
                // one target loaded twice (two frames) is measured once, from the first frame
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    if slot.get().is_none() || source.is_none() {
                        slot.insert(None);
                    }
                }
            }
        }
        if seen > TREE_ENTRIES {
            targets.insert(UNINSPECTED_TARGET.to_owned(), None);
        }
        let mut remaining = TOTAL_BYTES;
        let mut measured = Vec::with_capacity(targets.len().min(MAX_MEASURED_SUBRESOURCES));
        for (index, (target, source)) in targets.into_iter().enumerate() {
            if index >= MAX_MEASURED_SUBRESOURCES {
                break;
            }
            let digest = match source {
                Some((frame, url)) if index < MAX_RECRAWL_RESOURCES => {
                    self.digest_response(&frame, &url, &mut remaining).await
                }
                _ => None,
            };
            measured.push(MeasuredSubresource { target, digest });
        }
        Ok(measured)
    }

    /// The digest of the response the browser received for `url` in `frame`; `None` when its
    /// identity is unknown or ambiguous, the browser no longer holds the body, or the body
    /// exceeds `remaining` or the per-resource bound.
    async fn digest_response(&self, frame: &str, url: &str, remaining: &mut usize) -> Option<Digest> {
        let (owner, request_id) = self
            .state
            .lock()
            .resource_requests
            .get(frame)
            .and_then(|requests| requests.get(url))
            .cloned()
            .flatten()?;
        let reply = self
            .ctl
            .client
            .call(
                "Network.getResponseBody",
                Some(&owner),
                json!({ "requestId": request_id }),
            )
            .await
            .ok()?;
        let content = reply.get("body").and_then(Value::as_str)?;
        let limit = RESOURCE_BYTES.min(*remaining);
        let digest = if reply.get("base64Encoded").and_then(Value::as_bool) == Some(true) {
            if content.len() > limit.div_ceil(3).saturating_mul(4) {
                return None;
            }
            let bytes = STANDARD.decode(content).ok()?;
            (bytes.len() <= limit).then(|| (bytes.len(), Digest::of(DIGEST_DOMAIN, &bytes)))?
        } else {
            (content.len() <= limit)
                .then(|| (content.len(), Digest::of(DIGEST_DOMAIN, content.as_bytes())))?
        };
        *remaining = remaining.saturating_sub(digest.0);
        Some(digest.1)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn urls_are_approved_without_credentials_or_fragments_and_inline_data_is_not_a_resource() {
        let Target::Approved(target) = approve("https://user:pw@a.test/i.png?x=1#frag") else {
            panic!("a plain URL is approved");
        };
        assert_eq!(target, "https://a.test/i.png?x=1");
        assert!(matches!(approve("data:image/png;base64,AAAA"), Target::Inline));
        assert!(matches!(approve("blob:https://a.test/id"), Target::Inline));
        assert!(matches!(approve("not a url"), Target::Inline));
    }

    #[test]
    fn an_over_long_target_is_cut_one_byte_over_the_bound_at_a_character_boundary() {
        let long = format!("https://a.test/{}", "é".repeat(200));
        let cut = bounded(long);
        assert!(cut.len() > MAX_RECRAWL_TARGET_BYTES && cut.len() <= MAX_RECRAWL_TARGET_BYTES + 1);
        assert_eq!(bounded("https://a.test/x.png".to_owned()), "https://a.test/x.png");
    }

    #[test]
    fn only_measured_types_of_every_frame_are_collected_with_their_load_state() {
        let tree = json!({
            "frame": {"id": "main"},
            "resources": [
                {"url": "https://a.test/a.png", "type": "Image"},
                {"url": "https://a.test/page", "type": "Document"},
                {"url": "https://a.test/api", "type": "XHR"},
                {"url": "https://a.test/b.css", "type": "Stylesheet", "failed": true},
            ],
            "childFrames": [{
                "frame": {"id": "child"},
                "resources": [{"url": "https://a.test/c.js", "type": "Script"}],
            }],
        });
        let mut entries = Vec::new();
        let mut seen = 0;
        collect(&tree, &mut entries, &mut seen).unwrap();
        let listed: Vec<(&str, &str, bool)> = entries
            .iter()
            .map(|entry| (entry.frame.as_str(), entry.url.as_str(), entry.failed))
            .collect();
        assert_eq!(
            listed,
            [
                ("main", "https://a.test/a.png", false),
                ("main", "https://a.test/b.css", true),
                ("child", "https://a.test/c.js", false),
            ]
        );
    }
}
