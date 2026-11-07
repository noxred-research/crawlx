//! Route templates: path segments that identify an object become slots.
//!
//! Static rules replace numeric, UUID, hash/hex, date/timestamp (katana's
//! fingerprint patterns), base64-ish and slug-with-id segments
//! by `:id`. [`RouteTemplater::learn`] additionally discovers slots from
//! observed sibling paths (≥ `min_distinct` distinct values at one position
//! whose sets of following segments are identical → `:slug`).
//! Output is deterministic: all state lives in ordered collections.

use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::url::RouteTemplate;

use crate::fingerprint::segment_placeholder;
use crate::params::looks_like_id;

/// Slot for statically recognised identifiers.
pub const ID_SLOT: &str = ":id";
/// Slot for learned sibling slots.
pub const LEARNED_SLOT: &str = ":slug";

const DEFAULT_MIN_DISTINCT: usize = 5;
const MAX_LEARN_PATHS: usize = 100_000;
const MAX_LEARN_DEPTH: usize = 16;

/// Applies static slot rules plus learned slots.
#[derive(Clone, Debug)]
pub struct RouteTemplater {
    min_distinct: usize,
    /// Templated-prefix key (`a/b`) → literal siblings that stay literal.
    learned: BTreeMap<String, BTreeSet<String>>,
}

impl Default for RouteTemplater {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTemplater {
    /// Templater with static rules only.
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_distinct: DEFAULT_MIN_DISTINCT,
            learned: BTreeMap::new(),
        }
    }

    /// Distinct sibling values needed to learn a slot (minimum 2).
    #[must_use]
    pub fn with_min_distinct(mut self, n: usize) -> Self {
        self.min_distinct = n.max(2);
        self
    }

    /// Number of learned slot positions.
    #[must_use]
    pub fn learned_len(&self) -> usize {
        self.learned.len()
    }

    /// Distinct sibling values needed to learn a slot.
    #[must_use]
    pub const fn min_distinct(&self) -> usize {
        self.min_distinct
    }

    /// The learned rules: templated prefix (`a/b`) → literal siblings that stay literal; every
    /// other segment at that position renders as [`LEARNED_SLOT`]. What a crawl persists so a
    /// resumed run templates the same URLs the same way.
    #[must_use]
    pub const fn learned(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.learned
    }

    /// Replace the learned rules with a persisted set (the inverse of [`Self::learned`]).
    #[must_use]
    pub fn with_learned(mut self, learned: BTreeMap<String, BTreeSet<String>>) -> Self {
        self.learned = learned;
        self
    }

    /// Template a URL path (`/invoice/8472` → `/invoice/:id`). A query or
    /// fragment suffix, if present, is ignored.
    #[must_use]
    pub fn template(&self, path: &str) -> RouteTemplate {
        let path = path.split(['?', '#']).next().unwrap_or("");
        if path.len() <= 1 {
            return RouteTemplate("/".to_owned());
        }
        let mut out = String::with_capacity(path.len());
        let mut prefix = String::new();
        let rest = path.strip_prefix('/').unwrap_or(path);
        for seg in rest.split('/') {
            out.push('/');
            let templ = self.template_segment(&prefix, seg);
            out.push_str(&templ);
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(&templ);
        }
        RouteTemplate(out)
    }

    fn template_segment(&self, prefix: &str, seg: &str) -> String {
        if seg.is_empty() {
            return String::new();
        }
        if let Some(s) = static_slot(seg) {
            return s;
        }
        if let Some(lits) = self.learned.get(prefix) {
            if !lits.contains(seg) {
                return LEARNED_SLOT.to_owned();
            }
        }
        seg.to_owned()
    }

    /// Learn slots from observed sibling paths. May be called repeatedly.
    pub fn learn<I, S>(&mut self, paths: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rows: Vec<Vec<String>> = Vec::new();
        for p in paths.into_iter().take(MAX_LEARN_PATHS) {
            let p = p.as_ref().split(['?', '#']).next().unwrap_or("");
            let t = self.template(p);
            let segs: Vec<String> =
                t.0.split('/')
                    .skip(1)
                    .filter(|s| !s.is_empty())
                    .take(MAX_LEARN_DEPTH)
                    .map(str::to_owned)
                    .collect();
            if !segs.is_empty() {
                rows.push(segs);
            }
        }
        for depth in 0..MAX_LEARN_DEPTH {
            // prefix key → child → set of following segments (its "structure")
            let mut children: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
            let mut all_children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for segs in &rows {
                let Some(child) = segs.get(depth) else { continue };
                if child.starts_with(':') {
                    continue;
                }
                let prefix = segs[..depth].join("/");
                let next = segs.get(depth + 1).cloned().unwrap_or_default();
                children
                    .entry(prefix.clone())
                    .or_default()
                    .entry(child.clone())
                    .or_default()
                    .insert(next);
                all_children.entry(prefix).or_default().insert(child.clone());
            }
            if all_children.is_empty() {
                break;
            }
            let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (prefix, by_child) in &children {
                // siblings with an identical structure form one candidate group
                let mut by_structure: BTreeMap<&BTreeSet<String>, BTreeSet<&String>> = BTreeMap::new();
                for (child, structure) in by_child {
                    by_structure.entry(structure).or_default().insert(child);
                }
                for members in by_structure.values() {
                    if members.len() >= self.min_distinct {
                        groups
                            .entry(prefix.clone())
                            .or_default()
                            .extend(members.iter().map(|m| (*m).clone()));
                    }
                }
            }
            for (prefix, group) in &groups {
                let seen = all_children.get(prefix).cloned().unwrap_or_default();
                let entry = self.learned.entry(prefix.clone()).or_default();
                entry.retain(|l| !group.contains(l));
                entry.extend(seen.into_iter().filter(|c| !group.contains(c)));
            }
            for segs in &mut rows {
                let prefix = segs.iter().take(depth).cloned().collect::<Vec<_>>().join("/");
                if let (Some(group), Some(seg)) = (groups.get(&prefix), segs.get_mut(depth)) {
                    if group.contains(seg) {
                        *seg = LEARNED_SLOT.to_owned();
                    }
                }
            }
        }
    }
}

/// Static rule for one segment; returns the slot form (extension kept).
fn static_slot(seg: &str) -> Option<String> {
    if let Some((stem, ext)) = seg.rsplit_once('.') {
        if !stem.is_empty()
            && (1..=5).contains(&ext.len())
            && ext.bytes().all(|b| b.is_ascii_alphanumeric())
            && is_id_segment(stem)
        {
            return Some(format!("{ID_SLOT}.{ext}"));
        }
    }
    is_id_segment(seg).then(|| ID_SLOT.to_owned())
}

/// Does the whole segment (no extension) denote an object identifier?
/// Katana's anchored patterns (`crate::fingerprint::segment_placeholder`:
/// uuid, hashes, ≥ 8-char hex with a hex letter, dates, timestamps, numbers)
/// are tried first, then the base64-ish and slug-with-id rules.
#[must_use]
pub fn is_id_segment(seg: &str) -> bool {
    let b = seg.as_bytes();
    if b.is_empty() {
        return false;
    }
    if segment_placeholder(seg).is_some() {
        return true;
    }
    if is_base64ish(b) {
        return true;
    }
    slug_with_id(seg)
}

fn is_base64ish(b: &[u8]) -> bool {
    b.len() >= 20
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        && b.iter().any(u8::is_ascii_digit)
        && b.iter().any(u8::is_ascii_uppercase)
        && b.iter().any(u8::is_ascii_lowercase)
}

fn slug_with_id(seg: &str) -> bool {
    if !seg
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        return false;
    }
    let tokens: Vec<&str> = seg.split(['-', '_']).filter(|t| !t.is_empty()).collect();
    if tokens.len() < 2 {
        return false;
    }
    // dates and other all-numeric compounds: 2024-05-01
    if tokens.iter().all(|t| t.bytes().all(|c| c.is_ascii_digit())) {
        return true;
    }
    let id_token = |t: &str| {
        (t.len() >= 3 && t.bytes().all(|c| c.is_ascii_digit())) || (t.len() >= 8 && looks_like_id(t))
    };
    tokens.first().is_some_and(|t| id_token(t)) || tokens.last().is_some_and(|t| id_token(t))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn t(p: &str) -> String {
        RouteTemplater::new().template(p).0
    }

    #[test]
    fn static_examples() {
        assert_eq!(t("/invoice/8472"), "/invoice/:id");
        assert_eq!(t("/u/550e8400-e29b-41d4-a716-446655440000/x"), "/u/:id/x");
        assert_eq!(t("/"), "/");
        assert_eq!(t(""), "/");
        assert_eq!(t("/a/b/"), "/a/b/");
        assert_eq!(t("/obj/0123456789abcdef0123"), "/obj/:id");
        assert_eq!(t("/s/Zk3pQ9xV7mR2tB8wL4nHq1"), "/s/:id");
        assert_eq!(t("/blog/my-first-post-8472"), "/blog/:id");
        assert_eq!(t("/blog/8472-my-first-post"), "/blog/:id");
        assert_eq!(t("/files/8472.pdf"), "/files/:id.pdf");
        assert_eq!(t("/archive/2024-05-01/"), "/archive/:id/");
        assert_eq!(t("/docs/getting-started"), "/docs/getting-started");
        assert_eq!(t("/top-10-movies"), "/top-10-movies");
        assert_eq!(
            t("/internationalization-and-localization-guide"),
            "/internationalization-and-localization-guide"
        );
        assert_eq!(t("/a//b"), "/a//b");
        assert_eq!(t("/v2/api"), "/v2/api");
    }

    #[test]
    fn learns_sibling_slots() {
        let mut tpl = RouteTemplater::new();
        let paths: Vec<String> = ["alice", "bob", "carol", "dave", "erin", "frank"]
            .iter()
            .flat_map(|u| [format!("/user/{u}"), format!("/user/{u}/posts")])
            .chain(["/user/settings".to_owned(), "/about".to_owned()])
            .collect();
        tpl.learn(&paths);
        assert_eq!(tpl.template("/user/zed").0, "/user/:slug");
        assert_eq!(tpl.template("/user/zed/posts").0, "/user/:slug/posts");
        assert_eq!(tpl.template("/user/settings").0, "/user/settings");
        assert_eq!(tpl.template("/about").0, "/about");
        // deterministic
        let mut tpl2 = RouteTemplater::new();
        let mut rev = paths.clone();
        rev.reverse();
        tpl2.learn(&rev);
        assert_eq!(tpl.learned, tpl2.learned);
    }

    #[test]
    fn fewer_than_threshold_is_not_learned() {
        let mut tpl = RouteTemplater::new();
        tpl.learn(["/c/a", "/c/b", "/c/d"]);
        assert_eq!(tpl.template("/c/zzz").0, "/c/zzz");
        assert_eq!(tpl.learned_len(), 0);
    }
}
