//! Query-identity gate (G12 `query-identity`): resource-merge and tracking-duplicate metrics over
//! the frontier rows of a run, and the session-value grep gate over everything a run produced.
//!
//! * [`QueryIdentityMetrics`] counts, for one resource family (`/path?id=N`), how many distinct
//!   resources collapsed onto one frontier key (`merge_count`), how many resources never got a
//!   row (`missing_resources`) and how many extra rows exist only because of a tracking or
//!   session parameter (`tracking_duplicates`). The gate requires all three to be zero.
//!   [`QueryIdentityMetrics::checks`] renders them as scorecard [`Check`]s so a scorecard check
//!   list can adopt them without recomputing anything.
//! * [`SessionValueGate`] and [`ArtifactScan`] search artifact bytes for the literal session
//!   values a fixture injects into its links, in the plain and the hex encodings.

use crate::scorecard::Check;
use crawlx_core::hash::Digest;
use crawlx_core::repo::FrontierEntry;
use crawlx_core::ParamClass;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// One resource family of a fixture: pages at `path` identified by the query parameter `id_param`.
#[derive(Clone, Copy, Debug)]
pub struct ResourceFamily<'a> {
    /// URL path of the resource pages, e.g. `/g12/invoice`.
    pub path: &'a str,
    /// Query parameter that carries the resource id, e.g. `id`.
    pub id_param: &'a str,
    /// Ids the fixture links to with their own URL: every one must own a distinct frontier key.
    pub expected_ids: &'a BTreeSet<String>,
}

/// The G12 gate metrics of one run.
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Debug)]
#[non_exhaustive]
pub struct QueryIdentityMetrics {
    /// Number of expected resources.
    pub resources: usize,
    /// Distinct expected resources that share a frontier key with another one (per key: ids - 1).
    pub merge_count: usize,
    /// Expected resources with no frontier row at all.
    pub missing_resources: usize,
    /// Resource rows beyond one per id whose URL differs only by tracking or session parameters.
    pub tracking_duplicates: usize,
}

/// Whether `name=value` is a tracking or session parameter by the built-in classifier table.
fn is_noise(name: &str, value: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        crawlx_url::params::builtin_class(&lower, name, value),
        Some(ParamClass::Tracking | ParamClass::Session)
    )
}

impl QueryIdentityMetrics {
    /// Compute the metrics of `family` from the frontier `rows` of a run.
    ///
    /// A row belongs to the family when its path is `family.path`, it carries `family.id_param`
    /// and every other query parameter it still has is a tracking or session parameter. Rows
    /// with another parameter (a sort, an action) are other views of the resource and are not
    /// counted.
    #[must_use]
    pub fn from_frontier(rows: &[FrontierEntry], family: &ResourceFamily<'_>) -> Self {
        let mut family_rows = 0_usize;
        let mut ids_seen: BTreeSet<String> = BTreeSet::new();
        let mut ids_by_key: BTreeMap<Digest, BTreeSet<String>> = BTreeMap::new();
        for row in rows.iter().filter(|r| r.url.url.path() == family.path) {
            let mut id = None;
            let mut plain = true;
            for (name, value) in row.url.url.query_pairs() {
                if name == family.id_param {
                    id = Some(value.into_owned());
                } else if !is_noise(&name, &value) {
                    plain = false;
                }
            }
            let Some(id) = id.filter(|_| plain) else {
                continue;
            };
            family_rows += 1;
            if family.expected_ids.contains(&id) {
                ids_by_key.entry(row.url.key).or_default().insert(id.clone());
            }
            ids_seen.insert(id);
        }
        let merge_count = ids_by_key.values().map(|ids| ids.len().saturating_sub(1)).sum();
        let reached: BTreeSet<&String> = ids_by_key.values().flatten().collect();
        Self {
            resources: family.expected_ids.len(),
            merge_count,
            missing_resources: family.expected_ids.len().saturating_sub(reached.len()),
            tracking_duplicates: family_rows.saturating_sub(ids_seen.len()),
        }
    }

    /// Whether the gate holds: no merge, no missing resource, no tracking duplicate.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.merge_count == 0 && self.missing_resources == 0 && self.tracking_duplicates == 0
    }

    /// The metrics as scorecard checks, each required to be `0`.
    #[must_use]
    pub fn checks(&self) -> Vec<Check> {
        [
            ("distinct_resource_merge_count", self.merge_count),
            ("missing_resource_count", self.missing_resources),
            ("tracking_duplicate_frontier_entries", self.tracking_duplicates),
        ]
        .into_iter()
        .map(|(name, actual)| Check {
            name: name.to_owned(),
            expected: "== 0".to_owned(),
            actual: actual.to_string(),
            passed: actual == 0,
        })
        .collect()
    }
}

/// Literal session values that must not appear in any artifact of a run.
#[derive(Clone, Debug, Default)]
pub struct SessionValueGate {
    patterns: Vec<(String, Vec<u8>)>,
}

impl SessionValueGate {
    /// A gate for `values`, matched as the plain bytes and as lower- and upper-case hex.
    /// Empty values are ignored: they would match everything.
    #[must_use]
    pub fn new(values: &[&str]) -> Self {
        let mut gate = Self::default();
        for value in values.iter().filter(|v| !v.is_empty()) {
            let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
            gate = gate
                .with_pattern(format!("{value} (plain)"), value.as_bytes().to_vec())
                .with_pattern(format!("{value} (hex)"), hex.clone().into_bytes())
                .with_pattern(format!("{value} (HEX)"), hex.to_uppercase().into_bytes());
        }
        gate
    }

    /// Add an extra encoding of a value (base64 forms, for example). An empty pattern is ignored.
    #[must_use]
    pub fn with_pattern(mut self, label: String, bytes: Vec<u8>) -> Self {
        if !bytes.is_empty() {
            self.patterns.push((label, bytes));
        }
        self
    }

    /// Number of patterns the gate searches for.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Label of the first pattern found in `bytes`.
    #[must_use]
    pub fn find(&self, bytes: &[u8]) -> Option<&str> {
        self.patterns
            .iter()
            .find(|(_, pattern)| bytes.windows(pattern.len()).any(|w| w == pattern.as_slice()))
            .map(|(label, _)| label.as_str())
    }
}

/// Result of scanning the artifacts of a run with a [`SessionValueGate`].
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct ArtifactScan {
    /// Number of artifacts inspected.
    pub checked: u64,
    /// One entry per leak: `source: pattern label`.
    pub leaks: Vec<String>,
}

impl ArtifactScan {
    /// Inspect `bytes` of the artifact named `source`.
    pub fn inspect(&mut self, gate: &SessionValueGate, source: &str, bytes: &[u8]) {
        self.checked += 1;
        if let Some(label) = gate.find(bytes) {
            self.leaks.push(format!("{source}: {label}"));
        }
    }

    /// Whether at least one artifact was inspected and none leaked.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.checked > 0 && self.leaks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::QueryPolicy;
    use crawlx_core::ids::CrawlRunId;
    use crawlx_core::repo::FrontierStatus;
    use crawlx_url::{CanonicalizeOptions, Canonicalizer};

    fn row(raw: &str, policy: QueryPolicy, id: i64) -> FrontierEntry {
        let options = CanonicalizeOptions {
            query_policy: policy,
            ..CanonicalizeOptions::default()
        };
        let base = url::Url::parse("http://127.0.0.1/g12/").unwrap();
        FrontierEntry {
            id,
            run: CrawlRunId::new(),
            url: Canonicalizer::canonicalize(raw, &base, &options).unwrap(),
            depth: 1,
            status: FrontierStatus::Succeeded,
            denial_reason: None,
            attempts: 1,
            discovered_from: Some(0),
        }
    }

    fn expected() -> BTreeSet<String> {
        ["1", "2", "3"].map(str::to_owned).into()
    }

    fn family(expected: &BTreeSet<String>) -> ResourceFamily<'_> {
        ResourceFamily {
            path: "/g12/invoice",
            id_param: "id",
            expected_ids: expected,
        }
    }

    #[test]
    fn classified_links_pass_the_gate() {
        let rows: Vec<_> = [
            "invoice?id=1",
            "invoice?id=2",
            "invoice?id=3",
            "invoice?id=1&utm_source=news",
            "invoice?id=3&sessionid=abc123",
            "invoice?id=1&sort=asc",
        ]
        .iter()
        .zip(1..)
        .map(|(raw, id)| row(raw, QueryPolicy::Classify, id))
        .collect();
        // The classifier collapses the tracking and session variants onto the plain rows; the
        // frontier would hold one row per key, which is what the real crawl hands over.
        let mut unique: BTreeMap<_, _> = BTreeMap::new();
        for r in rows {
            unique.entry(r.url.key).or_insert(r);
        }
        let rows: Vec<_> = unique.into_values().collect();
        let expected = expected();
        let m = QueryIdentityMetrics::from_frontier(&rows, &family(&expected));
        assert_eq!(
            m,
            QueryIdentityMetrics {
                resources: 3,
                merge_count: 0,
                missing_resources: 0,
                tracking_duplicates: 0
            }
        );
        assert!(m.passed());
        assert!(m.checks().iter().all(|c| c.passed), "{:?}", m.checks());
    }

    #[test]
    fn a_tracking_variant_that_keeps_its_own_row_is_a_duplicate() {
        // `keep_all` leaves the tracking and session parameters in the URL: two extra rows.
        let rows = vec![
            row("invoice?id=1", QueryPolicy::KeepAll, 1),
            row("invoice?id=2", QueryPolicy::KeepAll, 2),
            row("invoice?id=3", QueryPolicy::KeepAll, 3),
            row("invoice?id=1&utm_source=news", QueryPolicy::KeepAll, 4),
            row("invoice?id=3&sessionid=zz", QueryPolicy::KeepAll, 5),
        ];
        let expected = expected();
        let m = QueryIdentityMetrics::from_frontier(&rows, &family(&expected));
        assert_eq!(m.tracking_duplicates, 2, "{m:?}");
        assert_eq!(m.merge_count, 0);
        assert!(!m.passed());
        let failed: Vec<_> = m
            .checks()
            .into_iter()
            .filter(|c| !c.passed)
            .map(|c| c.name)
            .collect();
        assert_eq!(failed, ["tracking_duplicate_frontier_entries"]);
    }

    #[test]
    fn two_resources_on_one_key_are_a_merge() {
        let one = row("invoice?id=1", QueryPolicy::Classify, 1);
        let mut two = row("invoice?id=2", QueryPolicy::Classify, 2);
        two.url.key = one.url.key;
        let three = row("invoice?id=3", QueryPolicy::Classify, 3);
        let expected = expected();
        let m = QueryIdentityMetrics::from_frontier(&[one, two, three], &family(&expected));
        assert_eq!(m.merge_count, 1, "{m:?}");
        assert_eq!(m.tracking_duplicates, 0);
        assert!(!m.passed());
        assert!(m
            .checks()
            .iter()
            .any(|c| c.name == "distinct_resource_merge_count" && !c.passed));
    }

    #[test]
    fn a_merge_is_not_masked_by_a_tracking_duplicate() {
        let one = row("invoice?id=1", QueryPolicy::Classify, 1);
        let mut two = row("invoice?id=2", QueryPolicy::Classify, 2);
        two.url.key = one.url.key;
        let three = row("invoice?id=3", QueryPolicy::Classify, 3);
        let three_utm = row("invoice?id=3&utm_source=news", QueryPolicy::KeepAll, 4);
        let expected = expected();
        let m = QueryIdentityMetrics::from_frontier(&[one, two, three, three_utm], &family(&expected));
        assert_eq!(m.merge_count, 1, "{m:?}");
        assert_eq!(m.tracking_duplicates, 1, "{m:?}");
    }

    #[test]
    fn strip_all_leaves_every_resource_without_a_row() {
        let rows: Vec<_> = (1..=3)
            .map(|i| row(&format!("invoice?id={i}"), QueryPolicy::StripAll, i))
            .collect();
        let expected = expected();
        let m = QueryIdentityMetrics::from_frontier(&rows, &family(&expected));
        assert_eq!(m.missing_resources, 3, "{m:?}");
        assert!(!m.passed());
    }

    #[test]
    fn other_views_and_other_paths_are_not_counted() {
        let rows = vec![
            row("invoice?id=1", QueryPolicy::Classify, 1),
            row("invoice?id=1&sort=asc", QueryPolicy::KeepAll, 2),
            row("invoice?id=1&action=delete", QueryPolicy::KeepAll, 3),
            row("list?page=2", QueryPolicy::Classify, 4),
        ];
        let expected: BTreeSet<String> = ["1".to_owned()].into();
        let m = QueryIdentityMetrics::from_frontier(&rows, &family(&expected));
        assert!(m.passed(), "{m:?}");
    }

    #[test]
    fn the_gate_finds_plain_and_hex_session_values_and_nothing_else() {
        let gate = SessionValueGate::new(&["sess_canary_42", ""]);
        assert_eq!(gate.pattern_count(), 3, "the empty value is ignored");
        assert!(gate.find(b"https://x/?sessionid=sess_canary_42&b=1").is_some());
        let hex: String = "sess_canary_42".bytes().map(|b| format!("{b:02X}")).collect();
        assert!(gate.find(format!("<{hex}>").as_bytes()).is_some());
        assert!(gate.find(b"https://x/?id=1&sessionid=").is_none());
        let mut scan = ArtifactScan::default();
        assert!(!scan.is_clean(), "an empty scan is not evidence");
        scan.inspect(&gate, "ok", b"nothing here");
        assert!(scan.is_clean());
        scan.inspect(&gate, "bad", b"x sess_canary_42 y");
        assert_eq!(scan.checked, 2);
        assert_eq!(scan.leaks, ["bad: sess_canary_42 (plain)"]);
    }
}
