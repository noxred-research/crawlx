//! Security-crawl-maze scorer (`crawl_maze_score`).
//!
//! Ported in spirit from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md: a run is
//! scored by which expected endpoints were *requested*, taken from the gym's server-side ledger (what actually hit the server) or from any JSON
//! run artifact (every string that parses as a URL or path). The expected list is the
//! fixture manifest's `expected.crawl_maze` ([`MazeTarget`]); an endpoint counts as found
//! when `prefix + target.path` equals a requested path, query string ignored.

use crate::gym::ledger::{Ledger, LedgerEvent};
use crate::gym::manifest::{MazePlane, MazeTarget};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// Prefix the upstream blueprint serves its `.found` endpoints under.
pub const UPSTREAM_PREFIX: &str = "/test";

/// Found/expected counts of one bucket.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct Tally {
    /// Expected endpoints that were requested.
    pub found: u32,
    /// Expected endpoints in the bucket.
    pub expected: u32,
}

impl Tally {
    fn add(&mut self, found: bool) {
        self.expected += 1;
        if found {
            self.found += 1;
        }
    }
}

/// Result of scoring one run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct MazeScore {
    /// Path prefix the expected endpoints were served under (`/g32/test`, `/test`).
    pub prefix: String,
    /// Found/expected per blueprint category (`css`, `headers`, `html`, `javascript`, `misc`).
    pub per_category: BTreeMap<String, Tally>,
    /// Found/expected per expected plane.
    pub per_plane: BTreeMap<MazePlane, Tally>,
    /// Expected endpoints that were requested, in manifest order.
    pub found: Vec<String>,
    /// Expected endpoints that were not requested, in manifest order.
    pub missing: Vec<String>,
    /// `found.len()`.
    pub total: u32,
    /// Number of expected endpoints.
    pub expected: u32,
}

impl MazeScore {
    /// Expected endpoints of `plane` in the given categories that were not requested.
    #[must_use]
    pub fn missing_in(&self, targets: &[MazeTarget], plane: MazePlane, categories: &[&str]) -> Vec<String> {
        let missing: BTreeSet<&str> = self.missing.iter().map(String::as_str).collect();
        targets
            .iter()
            .filter(|t| t.plane == plane && categories.contains(&t.category.as_str()))
            .filter(|t| missing.contains(t.path.as_str()))
            .map(|t| t.path.clone())
            .collect()
    }

    /// Percentage found, rounded like the reference report.
    #[must_use]
    pub fn percent(&self) -> u32 {
        if self.expected == 0 {
            return 0;
        }
        (self.total * 100) / self.expected
    }

    /// Markdown report: a per-category table and the missing list.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "crawl-maze score: {}/{} ({}%) under `{}`\n",
            self.total,
            self.expected,
            self.percent(),
            self.prefix
        );
        s.push_str("| category | found | expected |\n|---|---:|---:|\n");
        for (c, t) in &self.per_category {
            let _ = writeln!(s, "| {c} | {} | {} |", t.found, t.expected);
        }
        s.push_str("\n| plane | found | expected |\n|---|---:|---:|\n");
        for (p, t) in &self.per_plane {
            let _ = writeln!(s, "| {p:?} | {} | {} |", t.found, t.expected);
        }
        if !self.missing.is_empty() {
            s.push_str("\nmissing:\n");
            for m in &self.missing {
                let _ = writeln!(s, "- `{m}`");
            }
        }
        s
    }
}

/// Path component of a requested URL or path, query and fragment removed.
fn path_of(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.starts_with('/') {
        let end = s.find(['?', '#']).unwrap_or(s.len());
        return Some(s[..end].to_owned());
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return url::Url::parse(s).ok().map(|u| u.path().to_owned());
    }
    None
}

/// Score `requested` (URLs or paths; queries ignored) against `targets` served under `prefix`.
#[must_use]
pub fn score<'a, I>(requested: I, targets: &[MazeTarget], prefix: &str) -> MazeScore
where
    I: IntoIterator<Item = &'a str>,
{
    let hit: BTreeSet<String> = requested.into_iter().filter_map(path_of).collect();
    let mut out = MazeScore {
        prefix: prefix.to_owned(),
        per_category: BTreeMap::new(),
        per_plane: BTreeMap::new(),
        found: Vec::new(),
        missing: Vec::new(),
        total: 0,
        expected: 0,
    };
    for t in targets {
        let ok = hit.contains(&format!("{prefix}{}", t.path));
        out.per_category.entry(t.category.clone()).or_default().add(ok);
        out.per_plane.entry(t.plane).or_default().add(ok);
        if ok {
            out.found.push(t.path.clone());
        } else {
            out.missing.push(t.path.clone());
        }
    }
    out.total = u32::try_from(out.found.len()).unwrap_or(u32::MAX);
    out.expected = u32::try_from(targets.len()).unwrap_or(u32::MAX);
    out
}

/// Score the gym ledger: every `op` row of `fixture`, any method.
#[must_use]
pub fn score_ledger(ledger: &Ledger, fixture: &str, targets: &[MazeTarget], prefix: &str) -> MazeScore {
    let entries = ledger.entries_for(fixture);
    let paths = entries.iter().filter_map(|e| match &e.event {
        LedgerEvent::Op { path, .. } => Some(path.as_str()),
        _ => None,
    });
    score(paths, targets, prefix)
}

/// Every string in a JSON document that is a URL or an absolute path (a run report, a page
/// list, a ledger dump, a frontier export), deduplicated.
#[must_use]
pub fn paths_in_json(value: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![value];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::String(s) => {
                if let Some(p) = path_of(s) {
                    out.insert(p);
                }
            }
            serde_json::Value::Array(items) => stack.extend(items.iter()),
            serde_json::Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn targets() -> Vec<MazeTarget> {
        vec![
            MazeTarget {
                path: "/html/body/a/href.found".into(),
                category: "html".into(),
                plane: MazePlane::Static,
                page: String::new(),
                deferred_reason: None,
            },
            MazeTarget {
                path: "/javascript/interactive/js-post.found".into(),
                category: "javascript".into(),
                plane: MazePlane::Browser,
                page: String::new(),
                deferred_reason: None,
            },
        ]
    }

    #[test]
    fn urls_and_paths_count_once_and_queries_are_ignored() {
        let s = score(
            [
                "http://h:1/test/html/body/a/href.found?x=1",
                "/test/html/body/a/href.found",
                "/test/html/body/a/href.html",
            ],
            &targets(),
            UPSTREAM_PREFIX,
        );
        assert_eq!((s.total, s.expected), (1, 2));
        assert_eq!(s.per_category["html"].found, 1);
        assert_eq!(s.per_category["javascript"].found, 0);
        assert_eq!(s.per_plane[&MazePlane::Browser].expected, 1);
        assert_eq!(s.missing, vec!["/javascript/interactive/js-post.found"]);
        assert_eq!(s.percent(), 50);
        assert!(s.render_markdown().contains("| html | 1 | 1 |"));
        assert_eq!(
            s.missing_in(&targets(), MazePlane::Browser, &["javascript"]),
            vec!["/javascript/interactive/js-post.found"]
        );
        assert!(s.missing_in(&targets(), MazePlane::Static, &["html"]).is_empty());
    }

    #[test]
    fn json_walk_collects_every_url_and_path() {
        let v = serde_json::json!({
            "pages": [{"url": {"url": "http://h:1/g32/test/a.found"}}, {"path": "/g32/test/b.found#frag"}],
            "note": "not a url",
            "n": 3
        });
        let got = paths_in_json(&v);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            vec!["/g32/test/a.found", "/g32/test/b.found"]
        );
    }
}
