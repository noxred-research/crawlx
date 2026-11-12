//! Rule-based request blocking for the browser plane (`dynamic.blockRules`) and the record of
//! what the rules blocked.
//!
//! A rule list decides per request, before it leaves the browser, from facts the browser knows
//! about the request alone: the URL, whether it loads a document and whether it comes from a
//! child frame. Every blocked request is reported with the kind of rule that matched it, so an
//! archive can say why a resource is absent instead of silently omitting it.
//!
//! Kinds, in the order they are checked:
//!
//! * `urls`: `*`-wildcard patterns over the whole request URL; any request.
//! * `frames`: the same patterns, applied only to documents loaded by a child frame (iframe).
//! * `text`: case-insensitive substrings of the request URL; any request.
//! * `allowOnly`: when non-empty, every request that is not the main-frame navigation and that
//!   matches none of these `*`-wildcard patterns is blocked. The page being visited is governed by
//!   scope and robots policy, not by block rules.
//!
//! Only `http` and `https` requests are considered; other schemes never reach the network.

use serde::{Deserialize, Serialize};

/// Most entries in one rule list.
pub const MAX_RULES_PER_LIST: usize = 64;
/// Longest rule entry in bytes.
pub const MAX_RULE_LEN: usize = 512;
/// Most blocked resources one browser context keeps between two drains.
pub const MAX_BLOCKED_RESOURCES: usize = 256;

/// `dynamic.blockRules`: which requests of the browser plane are blocked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct BlockRulesV1 {
    /// `*`-wildcard patterns over the full request URL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// `*`-wildcard patterns that apply only to documents loaded by a child frame.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames: Vec<String>,
    /// Case-insensitive substrings of the request URL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text: Vec<String>,
    /// When non-empty, subresource and child-frame requests matching none of these `*`-wildcard
    /// patterns are blocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_only: Vec<String>,
}

/// Which kind of rule blocked a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BlockRuleKind {
    /// A `urls` pattern matched.
    Url,
    /// A `frames` pattern matched a child-frame document.
    Frame,
    /// A `text` substring occurs in the URL.
    Text,
    /// `allowOnly` is set and no pattern of it matched.
    AllowOnly,
}

impl BlockRuleKind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Frame => "frame",
            Self::Text => "text",
            Self::AllowOnly => "allow_only",
        }
    }

    /// Archive omission reason of a resource this kind of rule blocked.
    #[must_use]
    pub const fn omission_reason(self) -> &'static str {
        match self {
            Self::Url => "blocked_by_url_rule",
            Self::Frame => "blocked_by_frame_rule",
            Self::Text => "blocked_by_text_rule",
            Self::AllowOnly => "blocked_by_allow_only_rule",
        }
    }
}

/// What the browser knows about one request when it decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestFacts<'a> {
    /// Absolute request URL.
    pub url: &'a str,
    /// The request loads a document.
    pub document: bool,
    /// The request comes from a frame other than the page's main frame.
    pub child_frame: bool,
}

impl BlockRulesV1 {
    /// Does the list block nothing?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty() && self.frames.is_empty() && self.text.is_empty() && self.allow_only.is_empty()
    }

    /// Entries over all four lists.
    #[must_use]
    pub fn len(&self) -> usize {
        self.urls.len() + self.frames.len() + self.text.len() + self.allow_only.len()
    }

    /// Check the list shape.
    ///
    /// # Errors
    /// Returns the reason when a list is too long or an entry is empty, too long or contains a
    /// control character.
    pub fn validate(&self) -> Result<(), String> {
        for (list, name) in [
            (&self.urls, "urls"),
            (&self.frames, "frames"),
            (&self.text, "text"),
            (&self.allow_only, "allowOnly"),
        ] {
            if list.len() > MAX_RULES_PER_LIST {
                return Err(format!("{name}: at most {MAX_RULES_PER_LIST} entries"));
            }
            if let Some(bad) = list.iter().find(|entry| {
                entry.is_empty() || entry.len() > MAX_RULE_LEN || entry.chars().any(char::is_control)
            }) {
                return Err(format!(
                    "{name}: entries are 1 to {MAX_RULE_LEN} bytes without control characters (got {} bytes)",
                    bad.len()
                ));
            }
        }
        Ok(())
    }

    /// The kind of rule that blocks the request, `None` when it may go ahead.
    #[must_use]
    pub fn decide(&self, request: &RequestFacts<'_>) -> Option<BlockRuleKind> {
        let scheme_ok = request
            .url
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case("https://"))
            || request
                .url
                .get(..7)
                .is_some_and(|head| head.eq_ignore_ascii_case("http://"));
        if !scheme_ok {
            return None;
        }
        if self
            .urls
            .iter()
            .any(|pattern| wildcard_matches(pattern, request.url))
        {
            return Some(BlockRuleKind::Url);
        }
        if request.child_frame
            && request.document
            && self
                .frames
                .iter()
                .any(|pattern| wildcard_matches(pattern, request.url))
        {
            return Some(BlockRuleKind::Frame);
        }
        if !self.text.is_empty() {
            let lowered = request.url.to_lowercase();
            if self
                .text
                .iter()
                .any(|needle| lowered.contains(&needle.to_lowercase()))
            {
                return Some(BlockRuleKind::Text);
            }
        }
        let navigation = request.document && !request.child_frame;
        if !self.allow_only.is_empty()
            && !navigation
            && !self
                .allow_only
                .iter()
                .any(|pattern| wildcard_matches(pattern, request.url))
        {
            return Some(BlockRuleKind::AllowOnly);
        }
        None
    }
}

/// `*` matches any run of characters (also none); every other character matches itself.
/// Linear in the product of both lengths at worst, never exponential.
fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&byte) if byte == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

/// One request the rules blocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct BlockedResourceV1 {
    /// Request URL after the capture plane's URL redaction.
    pub url: String,
    /// The rule kind that blocked it.
    pub kind: BlockRuleKind,
    /// The browser's resource type of the request (`Document`, `Image`, ...).
    pub resource_type: String,
}

impl BlockedResourceV1 {
    /// Describe one blocked request.
    #[must_use]
    pub fn new(url: String, kind: BlockRuleKind, resource_type: String) -> Self {
        Self {
            url,
            kind,
            resource_type,
        }
    }
}

/// What the rules blocked since the last drain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct BlockedResources {
    /// Blocked resources, one per distinct (URL, kind), in the order they were blocked, at most
    /// [`MAX_BLOCKED_RESOURCES`].
    pub resources: Vec<BlockedResourceV1>,
    /// Distinct blocked resources that did not fit and are not listed.
    pub dropped: u64,
}

impl BlockedResources {
    /// Record `resource` unless an identical one is already listed; counts it as dropped when the
    /// list is full.
    pub fn push(&mut self, resource: BlockedResourceV1) {
        if self
            .resources
            .iter()
            .any(|known| known.kind == resource.kind && known.url == resource.url)
        {
            return;
        }
        if self.resources.len() >= MAX_BLOCKED_RESOURCES {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.resources.push(resource);
        }
    }

    /// Nothing was blocked and nothing was dropped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty() && self.dropped == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn rules() -> BlockRulesV1 {
        BlockRulesV1 {
            urls: vec!["*/ads/*".into()],
            frames: vec!["https://embed.test/*".into()],
            text: vec!["Tracker".into()],
            allow_only: Vec::new(),
            ..BlockRulesV1::default()
        }
    }

    fn facts(url: &str, document: bool, child_frame: bool) -> RequestFacts<'_> {
        RequestFacts {
            url,
            document,
            child_frame,
        }
    }

    #[test]
    fn wildcard_is_literal_except_star() {
        assert!(wildcard_matches("*", ""));
        assert!(wildcard_matches("a*c", "abc"));
        assert!(wildcard_matches("a*c", "ac"));
        assert!(wildcard_matches("*b*", "abc"));
        assert!(!wildcard_matches("a*c", "abd"));
        assert!(!wildcard_matches("abc", "ab"));
        assert!(wildcard_matches("a?c", "a?c"));
        assert!(!wildcard_matches("a?c", "abc"));
        let hostile = format!("{}b", "a*".repeat(200));
        assert!(!wildcard_matches(&hostile, &"a".repeat(400)));
    }

    #[test]
    fn each_rule_kind_blocks_exactly_what_it_names() {
        let rules = rules();
        assert_eq!(
            rules.decide(&facts("https://site.test/ads/x.png", false, false)),
            Some(BlockRuleKind::Url)
        );
        // frame rules never block a subresource or the main document
        assert_eq!(
            rules.decide(&facts("https://embed.test/logo.png", false, true)),
            None
        );
        assert_eq!(rules.decide(&facts("https://embed.test/", true, false)), None);
        assert_eq!(
            rules.decide(&facts("https://embed.test/", true, true)),
            Some(BlockRuleKind::Frame)
        );
        assert_eq!(
            rules.decide(&facts("https://site.test/js/TRACKER.js", false, false)),
            Some(BlockRuleKind::Text)
        );
        assert_eq!(
            rules.decide(&facts("https://site.test/index.html", true, false)),
            None
        );
        assert_eq!(
            rules.decide(&facts("data:text/plain,tracker", false, false)),
            None
        );
    }

    #[test]
    fn allow_only_spares_the_navigation_and_blocks_the_rest() {
        let rules = BlockRulesV1 {
            allow_only: vec!["https://site.test/*".into()],
            ..BlockRulesV1::default()
        };
        assert_eq!(rules.decide(&facts("https://other.test/", true, false)), None);
        assert_eq!(
            rules.decide(&facts("https://site.test/a.png", false, false)),
            None
        );
        assert_eq!(
            rules.decide(&facts("https://cdn.test/a.png", false, false)),
            Some(BlockRuleKind::AllowOnly)
        );
        assert_eq!(
            rules.decide(&facts("https://other.test/", true, true)),
            Some(BlockRuleKind::AllowOnly)
        );
    }

    #[test]
    fn validation_bounds_lists_and_entries() {
        assert!(rules().validate().is_ok());
        let mut long = rules();
        long.urls = vec!["a".repeat(MAX_RULE_LEN + 1)];
        assert!(long.validate().is_err());
        let mut empty_entry = rules();
        empty_entry.text = vec![String::new()];
        assert!(empty_entry.validate().is_err());
        let mut many = rules();
        many.frames = vec!["a".into(); MAX_RULES_PER_LIST + 1];
        assert!(many.validate().is_err());
    }

    #[test]
    fn blocked_log_dedupes_and_counts_overflow() {
        let mut log = BlockedResources::default();
        let one = BlockedResourceV1::new("https://a.test/x".into(), BlockRuleKind::Url, "Image".into());
        log.push(one.clone());
        log.push(one);
        assert_eq!(log.resources.len(), 1);
        for n in 0..MAX_BLOCKED_RESOURCES {
            log.push(BlockedResourceV1::new(
                format!("https://a.test/{n}"),
                BlockRuleKind::Text,
                "Script".into(),
            ));
        }
        assert_eq!(log.resources.len(), MAX_BLOCKED_RESOURCES);
        assert_eq!(log.dropped, 1);
    }

    #[test]
    fn config_keeps_the_default_wire_form_and_round_trips_rules() {
        use crate::config::Dynamic;
        let plain = serde_json::to_value(Dynamic::default()).unwrap();
        assert!(
            plain.get("blockRules").is_none(),
            "absent rules must not change digests"
        );
        let dynamic = Dynamic {
            block_rules: Some(rules()),
            ..Dynamic::default()
        };
        let wire = serde_json::to_value(&dynamic).unwrap();
        assert_eq!(wire["blockRules"]["urls"][0], "*/ads/*");
        assert!(wire["blockRules"].get("allowOnly").is_none());
        assert_eq!(serde_json::from_value::<Dynamic>(wire).unwrap(), dynamic);
        assert!(serde_json::from_value::<BlockRulesV1>(serde_json::json!({ "url": ["x"] })).is_err());
    }
}
