//! Volatile-region detection used by `crawlx-state` masks and by
//! the observer's `MutationStats.volatile_permille`.
//!
//! Two AX snapshots of the same document are compared slot by slot. A slot is
//! `(role, ancestor-role path)`; within a slot, nodes are paired by exact text
//! first and by order second, so an inserted sibling does not flag every node
//! after it.

use crate::bundle::{key_from_parts, normalize_name, AxIndex};
use crawlx_core::hash::Digest;
use crawlx_core::observation::{AxNode, AxSnapshot};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Why a region is considered volatile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum VolatileReason {
    /// Inside (or being) an `aria-live` region or a `timer`/`log`/`status`/`marquee` role.
    AriaLive,
    /// Text matches a clock, date or relative-time pattern.
    ClockLike,
    /// Text differs only in digits (counters, badges, progress).
    Counter,
    /// Text changed between the two snapshots with nothing explaining it.
    NoActionDiff,
}

/// A node (by stable key) that should be masked in state fingerprints.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VolatileHint {
    /// `crate::bundle::node_key` of the node in the newer snapshot.
    pub node_key: Digest,
    /// Why the node was flagged.
    pub reason: VolatileReason,
}

static CLOCK_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?ix)
        \b\d{1,2}:\d{2}(:\d{2})?(\s?[ap]\.?m\.?)?\b
        | \b\d{4}-\d{2}-\d{2}\b
        | \b\d{1,2}/\d{1,2}/\d{2,4}\b
        | \b(\d+|an?)\s*(sec|second|min|minute|hour|hr|day|week|month|year)s?\s+ago\b
        | \bjust\s+now\b
        | \bin\s+\d+\s*(sec|second|min|minute|hour|day)s?\b
        ",
    )
    .ok()
});

/// Does `text` look like a time, date or relative time?
#[must_use]
pub fn looks_clock_like(text: &str) -> bool {
    CLOCK_RE.as_ref().is_some_and(|re| re.is_match(text))
}

fn live_value(n: &AxNode) -> Option<&str> {
    ["live", "aria-live", "container-live"]
        .iter()
        .find_map(|k| n.properties.get(*k))
        .map(String::as_str)
}

fn is_live_node(n: &AxNode) -> bool {
    if matches!(
        n.role.to_ascii_lowercase().as_str(),
        "timer" | "log" | "status" | "marquee"
    ) {
        return true;
    }
    live_value(n).is_some_and(|v| {
        let v = v.trim();
        !v.is_empty() && !v.eq_ignore_ascii_case("off")
    })
}

fn node_text(n: &AxNode) -> String {
    let mut s = n.name.clone().unwrap_or_default();
    if let Some(v) = &n.value {
        s.push('\u{1f}');
        s.push_str(v);
    }
    s
}

/// One text change at a slot.
struct Changed<'a> {
    next: &'a AxNode,
    prev_text: String,
    next_text: String,
}

/// Structural difference of two snapshots.
struct AxDiff<'a> {
    changed: Vec<Changed<'a>>,
    /// Nodes only in the newer snapshot.
    added: Vec<&'a AxNode>,
    /// Nodes only in the older snapshot (judged against the *older* index).
    removed: Vec<&'a AxNode>,
}

type SlotMap<'a> = BTreeMap<(String, Vec<String>), Vec<(&'a AxNode, String)>>;

fn slots<'a>(idx: &AxIndex<'a>) -> SlotMap<'a> {
    let mut map: SlotMap<'a> = BTreeMap::new();
    for n in &idx.snapshot().nodes {
        if n.ignored {
            continue;
        }
        let key = (n.role.to_ascii_lowercase(), idx.ancestor_roles(n));
        map.entry(key).or_default().push((n, node_text(n)));
    }
    map
}

fn diff<'a>(prev_idx: &AxIndex<'a>, next_idx: &AxIndex<'a>) -> AxDiff<'a> {
    let prev_slots = slots(prev_idx);
    let mut next_slots = slots(next_idx);
    let mut out = AxDiff {
        changed: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
    };
    for (key, prev_nodes) in prev_slots {
        let mut next_nodes = next_slots.remove(&key).unwrap_or_default();
        // pair identical texts first
        let mut prev_rest: Vec<(&AxNode, String)> = Vec::new();
        for (pn, pt) in prev_nodes {
            if let Some(pos) = next_nodes.iter().position(|(_, nt)| *nt == pt) {
                next_nodes.remove(pos);
            } else {
                prev_rest.push((pn, pt));
            }
        }
        let paired = prev_rest.len().min(next_nodes.len());
        let mut prev_iter = prev_rest.into_iter();
        let mut next_iter = next_nodes.into_iter();
        for _ in 0..paired {
            if let (Some((_, pt)), Some((nn, nt))) = (prev_iter.next(), next_iter.next()) {
                out.changed.push(Changed {
                    next: nn,
                    prev_text: pt,
                    next_text: nt,
                });
            }
        }
        out.removed.extend(prev_iter.map(|(n, _)| n));
        out.added.extend(next_iter.map(|(n, _)| n));
    }
    for (_, rest) in next_slots {
        out.added.extend(rest.into_iter().map(|(n, _)| n));
    }
    out
}

fn classify(c: &Changed<'_>, next_idx: &AxIndex<'_>) -> VolatileReason {
    if is_live_node(c.next) || next_idx.ancestors(c.next).any(is_live_node) {
        return VolatileReason::AriaLive;
    }
    if looks_clock_like(&c.prev_text) || looks_clock_like(&c.next_text) {
        return VolatileReason::ClockLike;
    }
    if normalize_name(&c.prev_text) == normalize_name(&c.next_text) {
        return VolatileReason::Counter;
    }
    VolatileReason::NoActionDiff
}

/// Compares two snapshots for volatile regions.
#[derive(Clone, Copy, Debug, Default)]
pub struct VolatileDetector;

impl VolatileDetector {
    /// Hints for nodes whose text changed from `prev` to `next`, sorted and
    /// deduplicated. Call it for snapshots with no action between them: an
    /// otherwise unexplained change is then reported as
    /// [`VolatileReason::NoActionDiff`]. Unchanged nodes are never flagged.
    #[must_use]
    pub fn compare(prev: &AxSnapshot, next: &AxSnapshot) -> Vec<VolatileHint> {
        let (pi, ni) = (AxIndex::new(prev), AxIndex::new(next));
        let d = diff(&pi, &ni);
        let mut hints: Vec<VolatileHint> = d
            .changed
            .iter()
            .map(|c| VolatileHint {
                node_key: key_from_parts(
                    &c.next.role,
                    &ni.ancestor_roles(c.next),
                    c.next.name.as_deref().unwrap_or(""),
                ),
                reason: classify(c, &ni),
            })
            .collect();
        // nodes appearing inside a live region are volatile too
        hints.extend(
            d.added
                .iter()
                .filter(|n| is_live_node(n) || ni.ancestors(n).any(is_live_node))
                .map(|n| VolatileHint {
                    node_key: ni.node_key(n),
                    reason: VolatileReason::AriaLive,
                }),
        );
        hints.sort();
        hints.dedup();
        hints
    }

    /// Share (0..=1000) of AX changes between `prev` and `next` that fall in
    /// regions that are volatile for a reason other than "changed with no
    /// action" (live regions, clocks, counters). `0` when nothing changed.
    #[must_use]
    pub fn volatile_permille(prev: &AxSnapshot, next: &AxSnapshot) -> u16 {
        let (pi, ni) = (AxIndex::new(prev), AxIndex::new(next));
        let d = diff(&pi, &ni);
        let total = d.changed.len() + d.added.len() + d.removed.len();
        if total == 0 {
            return 0;
        }
        let volatile_changed = d
            .changed
            .iter()
            .filter(|c| classify(c, &ni) != VolatileReason::NoActionDiff)
            .count();
        let in_live = |n: &&AxNode, idx: &AxIndex<'_>| is_live_node(n) || idx.ancestors(n).any(is_live_node);
        let volatile_added = d.added.iter().filter(|n| in_live(n, &ni)).count();
        let volatile_removed = d.removed.iter().filter(|n| in_live(n, &pi)).count();
        let v = volatile_changed + volatile_added + volatile_removed;
        u16::try_from(v * 1000 / total).unwrap_or(1000).min(1000)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::bundle::node_key;
    use crate::bundle::testutil::{node, snapshot};

    fn page(clock: &str, status: &str, headline: &str) -> AxSnapshot {
        let mut live = node("5", Some("1"), "generic", "");
        live.properties.insert("live".to_owned(), "polite".to_owned());
        snapshot(vec![
            node("1", None, "RootWebArea", "app"),
            node("2", Some("1"), "heading", headline),
            node("3", Some("1"), "StaticText", clock),
            node("4", Some("1"), "button", "Save"),
            live,
            node("6", Some("5"), "StaticText", status),
        ])
    }

    #[test]
    fn unchanged_nodes_are_not_flagged() {
        let a = page("Updated 10:00", "ok", "Dashboard");
        assert!(VolatileDetector::compare(&a, &a.clone()).is_empty());
        assert_eq!(VolatileDetector::volatile_permille(&a, &a.clone()), 0);
    }

    #[test]
    fn clock_text_is_flagged_clock_like_with_stable_key() {
        let a = page("Updated 10:00", "ok", "Dashboard");
        let b = page("Updated 10:01", "ok", "Dashboard");
        let hints = VolatileDetector::compare(&a, &b);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].reason, VolatileReason::ClockLike);
        assert_eq!(hints[0].node_key, node_key(&b.nodes[2], &b));
        assert_eq!(hints[0].node_key, node_key(&a.nodes[2], &a));
    }

    #[test]
    fn aria_live_region_text_is_flagged() {
        let a = page("Updated 10:00", "Saved draft", "Dashboard");
        let b = page("Updated 10:00", "Saving", "Dashboard");
        let hints = VolatileDetector::compare(&a, &b);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].reason, VolatileReason::AriaLive);
        assert_eq!(hints[0].node_key, node_key(&b.nodes[5], &b));
    }

    #[test]
    fn counter_and_unexplained_text_changes() {
        let a = page("x", "ok", "5 items");
        let b = page("x", "ok", "6 items");
        let h = VolatileDetector::compare(&a, &b);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].reason, VolatileReason::Counter);

        let c = page("x", "ok", "Welcome back");
        let h = VolatileDetector::compare(&a, &c);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].reason, VolatileReason::NoActionDiff);
    }

    #[test]
    fn inserted_sibling_does_not_flag_following_nodes() {
        let mk = |items: &[&str]| {
            let mut v = vec![node("1", None, "RootWebArea", "app")];
            for (i, t) in items.iter().enumerate() {
                v.push(node(&format!("i{i}"), Some("1"), "link", t));
            }
            snapshot(v)
        };
        let a = mk(&["Alpha", "Beta", "Gamma"]);
        let b = mk(&["Alpha", "New", "Beta", "Gamma"]);
        assert!(VolatileDetector::compare(&a, &b).is_empty());
    }

    #[test]
    fn permille_counts_volatile_share() {
        // one clock tick (volatile) + one unexplained heading change = 500
        let a = page("Updated 10:00", "ok", "Dashboard");
        let b = page("Updated 10:01", "ok", "Reports");
        assert_eq!(VolatileDetector::volatile_permille(&a, &b), 500);
    }

    #[test]
    fn clock_patterns() {
        assert!(looks_clock_like("Last seen 5 minutes ago"));
        assert!(looks_clock_like("2026-10-16"));
        assert!(looks_clock_like("09:41:07 PM"));
        assert!(looks_clock_like("just now"));
        assert!(!looks_clock_like("Add to cart"));
    }
}
