//! AX-recall differential against the Node oracle.
//!
//! `runner.mjs --discover` visits every fixture page listed in a [`DiscoveryJob`] and
//! records, per role-locator element, whether the driver's actionability checks pass.
//! Each element carries a join key crawlx recomputes from its own observation
//! ([`element_keys`]): `"<frame path>::#<dom id>"` or `"<frame path>::<role>|<name>"`
//! with the frame path being the chain of frame URL path+query values from the main
//! frame, so keys never depend on the gym port.
//!
//! [`compare_discovery`] joins the two sides: recall of crawlx's candidate discovery over
//! the oracle-actionable elements, and capability parity per fixture — every
//! oracle-actionable element is either a crawlx candidate or a reported
//! `unsupported_surface` (G23 canvas panels and the like; never silently missed).

use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crawlx_core::ids::FrameId;
use crawlx_core::observation::ObservationBundle;
use crawlx_elements::Discovery;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Recall gate of the differential (within 2 pp of the oracle).
pub const RECALL_FLOOR: f64 = 0.95;

/// Minimum oracle-actionable elements the recall figure must rest on.
pub const MIN_ORACLE_ELEMENTS: usize = 200;

/// Settle margin added to a fixture's latest timer reveal before either side observes.
const SETTLE_MARGIN_MS: u64 = 500;

/// One fixture page of a discovery job.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DiscoveryFixture {
    /// Fixture id (`g01`, `div-buttons`, ...).
    pub id: String,
    /// Absolute entry URL under the gym.
    pub url: String,
    /// Milliseconds both sides wait after network idle before enumerating, so timer-revealed
    /// controls (`reveal_after_ms`) are visible to both or to neither.
    pub settle_ms: u64,
}

/// Input of `runner.mjs --discover`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DiscoveryJob {
    /// Gym base URL (`http://127.0.0.1:PORT`).
    pub gym: String,
    /// Pages to visit, in catalog order.
    pub fixtures: Vec<DiscoveryFixture>,
}

/// Wait both sides apply to `manifest` before enumerating: the latest timer reveal plus a margin.
#[must_use]
pub fn settle_ms(manifest: &FixtureManifest) -> u64 {
    manifest
        .controls
        .iter()
        .filter_map(|c| c.reveal_after_ms)
        .max()
        .unwrap_or(0)
        + SETTLE_MARGIN_MS
}

/// The discovery job for `manifests` served under `base_url`.
#[must_use]
pub fn discovery_job(manifests: &[FixtureManifest], base_url: &str) -> DiscoveryJob {
    DiscoveryJob {
        gym: base_url.trim_end_matches('/').to_owned(),
        fixtures: manifests
            .iter()
            .map(|m| DiscoveryFixture {
                id: m.id.clone(),
                url: m.entry_url(base_url),
                settle_ms: settle_ms(m),
            })
            .collect(),
    }
}

/// Write the discovery job as JSON to `path` (creating parent directories).
///
/// # Errors
/// I/O or JSON failures.
pub fn write_discovery_job(job: &DiscoveryJob, path: &Path) -> Result<(), BenchError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BenchError::io(parent, e))?;
    }
    let text = serde_json::to_string_pretty(job)?;
    std::fs::write(path, text).map_err(|e| BenchError::io(path, e))
}

/// One role-locator element the oracle enumerated.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OracleElement {
    /// Join key (see the module documentation).
    pub key: String,
    /// Frame path the element lives in.
    pub frame: String,
    /// `id` attribute; `None` when the element has none.
    #[serde(default)]
    pub dom_id: Option<String>,
    /// Role locator that found it.
    pub role: String,
    /// Normalized accessible text.
    #[serde(default)]
    pub name: String,
    /// Lowercase tag name.
    #[serde(default)]
    pub tag: String,
    /// `true` when the driver's actionability checks passed (`click({ trial: true })`).
    pub actionable: bool,
    /// Verdict label (`actionable`, `not_actionable`, `oracle_gap`).
    #[serde(default)]
    pub verdict: String,
    /// Why the checks failed; `None` for actionable elements.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One fixture page of a discovery report.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DiscoveredFixture {
    /// Fixture id.
    pub id: String,
    /// URL the driver visited.
    pub url: String,
    /// Settle wait the driver applied.
    #[serde(default)]
    pub settle_ms: u64,
    /// Navigation or enumeration failure; the fixture then contributes no elements.
    #[serde(default)]
    pub error: Option<String>,
    /// Every role-locator element, actionable or not.
    pub elements: Vec<OracleElement>,
}

impl DiscoveredFixture {
    /// Keys of the elements the driver found actionable, sorted.
    #[must_use]
    pub fn actionable_keys(&self) -> BTreeSet<&str> {
        self.elements
            .iter()
            .filter(|e| e.actionable)
            .map(|e| e.key.as_str())
            .collect()
    }
}

/// Output of `runner.mjs --discover`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DiscoveryReport {
    /// Oracle driver (one of [`super::DRIVERS`]).
    pub driver: String,
    /// Installed package version of the driver.
    pub driver_version: String,
    /// Always `"discovery"`.
    #[serde(default)]
    pub mode: String,
    /// Gym base URL the driver was pointed at.
    #[serde(default)]
    pub gym: String,
    /// ISO-8601 start timestamp.
    #[serde(default)]
    pub started: String,
    /// ISO-8601 end timestamp.
    #[serde(default)]
    pub finished: String,
    /// One entry per job fixture, in job order.
    pub fixtures: Vec<DiscoveredFixture>,
}

impl DiscoveryReport {
    /// Parse and validate a discovery result file.
    ///
    /// # Errors
    /// [`BenchError::Json`] for malformed JSON, [`BenchError::Oracle`] for an unknown driver or
    /// a file that is not a discovery report.
    pub fn parse(json: &str) -> Result<Self, BenchError> {
        let r: Self = serde_json::from_str(json)?;
        if !super::DRIVERS.contains(&r.driver.as_str()) {
            return Err(BenchError::Oracle(format!(
                "unknown oracle driver `{}`",
                r.driver
            )));
        }
        if r.mode != "discovery" {
            return Err(BenchError::Oracle(format!(
                "not a discovery report (mode `{}`)",
                r.mode
            )));
        }
        Ok(r)
    }

    /// Load a discovery result file from disk.
    ///
    /// # Errors
    /// I/O or parse failures.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        Self::parse(&text)
    }

    /// The fixture entry with this id.
    #[must_use]
    pub fn fixture(&self, id: &str) -> Option<&DiscoveredFixture> {
        self.fixtures.iter().find(|f| f.id == id)
    }
}

/// crawlx's side of one fixture page: join keys of its candidates and of its reported
/// unsupported surfaces, computed by [`element_keys`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CrawlxElements {
    /// Keys of every discovery-ladder candidate.
    pub discovered: BTreeSet<String>,
    /// Keys of every `unsupported_surface` report.
    pub unsupported: BTreeSet<String>,
}

/// Path+query of a frame URL without its origin; `about:srcdoc` and friends stay as they are.
#[must_use]
pub fn frame_path_of(url: &str) -> String {
    let no_fragment = url.split('#').next().unwrap_or(url);
    match no_fragment.find("://") {
        Some(p) => {
            let rest = &no_fragment[p + 3..];
            match rest.find('/') {
                Some(s) => rest[s..].to_owned(),
                None => "/".to_owned(),
            }
        }
        None => no_fragment.to_owned(),
    }
}

/// Collapsed, lowercased, truncated text used in the id-less join key (mirrors `normalizeName`).
#[must_use]
pub fn normalize_name(text: &str) -> String {
    let collapsed: Vec<&str> = text.split_whitespace().collect();
    let joined = collapsed.join(" ").to_lowercase();
    joined.chars().take(64).collect()
}

/// The join key of an element (mirrors `elementKey` in `runner.mjs`).
#[must_use]
pub fn element_key(frame_path: &str, dom_id: Option<&str>, role: &str, name: &str) -> String {
    match dom_id {
        Some(id) if !id.is_empty() => format!("{frame_path}::#{id}"),
        _ => format!("{frame_path}::{}|{}", role.to_lowercase(), normalize_name(name)),
    }
}

/// Frame path (`/g05/ > /g05/frame1.html > about:srcdoc`) of `frame` within `bundle`.
fn frame_path(bundle: &ObservationBundle, frame: &FrameId) -> String {
    let mut chain = Vec::new();
    let mut cur = Some(frame);
    while let Some(id) = cur {
        let Some(info) = bundle.frames.iter().find(|f| &f.id == id) else {
            break;
        };
        chain.push(frame_path_of(&info.url));
        cur = info.parent.as_ref();
    }
    chain.reverse();
    chain.join(" > ")
}

/// Join keys of `discovery`'s candidates and unsupported surfaces within `bundle`.
#[must_use]
pub fn element_keys(bundle: &ObservationBundle, discovery: &Discovery) -> CrawlxElements {
    let mut out = CrawlxElements::default();
    for c in &discovery.candidates {
        let d = &c.descriptor;
        let frame = frame_path(bundle, &d.locator.frame);
        let name = d.accessible_name.as_deref().or(d.text.as_deref()).unwrap_or("");
        out.discovered.insert(element_key(
            &frame,
            d.attributes.get("id").map(String::as_str),
            &d.role,
            name,
        ));
    }
    for s in &discovery.unsupported {
        let frame = frame_path(bundle, &s.locator.frame);
        let dom = bundle.dom_supplement.nodes.get(&s.locator.backend_node_id.0);
        let dom_id = dom.and_then(|n| n.attributes.get("id")).map(String::as_str);
        let (role, name) = bundle
            .ax
            .nodes
            .iter()
            .find(|n| n.locator.backend_node_id == s.locator.backend_node_id)
            .map_or((s.kind.as_str().to_owned(), String::new()), |n| {
                (n.role.clone(), n.name.clone().unwrap_or_default())
            });
        out.unsupported.insert(element_key(&frame, dom_id, &role, &name));
    }
    out
}

/// Parity of one fixture page.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FixtureParity {
    /// Fixture id.
    pub id: String,
    /// Oracle-actionable elements on the page.
    pub oracle_actionable: usize,
    /// Of those, crawlx candidates.
    pub discovered: usize,
    /// Of those, reported as `unsupported_surface` (counted as parity, not as recall).
    pub unsupported: usize,
    /// Oracle-actionable keys crawlx neither discovered nor reported, sorted.
    pub missed: Vec<String>,
    /// Oracle-side failure, when the driver could not enumerate the page.
    #[serde(default)]
    pub oracle_error: Option<String>,
}

impl FixtureParity {
    /// `true` when every oracle-actionable element was discovered or reported.
    #[must_use]
    pub fn parity(&self) -> bool {
        self.missed.is_empty()
    }
}

/// Outcome of [`compare_discovery`].
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct DiscoveryComparison {
    /// Oracle driver and version the comparison is against.
    pub driver: String,
    /// Driver package version.
    pub driver_version: String,
    /// Per fixture, in report order.
    pub fixtures: Vec<FixtureParity>,
    /// Oracle-actionable elements across all fixtures.
    pub oracle_actionable: usize,
    /// Of those, crawlx candidates.
    pub discovered: usize,
    /// `discovered / oracle_actionable` (1.0 when the oracle set is empty).
    pub recall: f64,
    /// Fixtures that lack parity, sorted.
    pub parity_failures: Vec<String>,
    /// Fixtures the oracle could not enumerate (driver error), sorted.
    pub oracle_errors: Vec<String>,
}

impl DiscoveryComparison {
    /// `true` when the recall floor holds over enough elements and every fixture has parity.
    #[must_use]
    pub fn passes(&self) -> bool {
        self.oracle_actionable >= MIN_ORACLE_ELEMENTS
            && self.recall >= RECALL_FLOOR
            && self.parity_failures.is_empty()
            && self.oracle_errors.is_empty()
    }
}

/// Join crawlx's elements (`ours`, keyed by fixture id) with the oracle's discovery report
/// (`theirs`). Fixtures present on one side only are skipped: the oracle enumerates what
/// the job asked for, and the caller observes the same job.
#[must_use]
pub fn compare_discovery(
    ours: &BTreeMap<String, CrawlxElements>,
    theirs: &DiscoveryReport,
) -> DiscoveryComparison {
    let mut fixtures = Vec::new();
    let mut total = 0usize;
    let mut found = 0usize;
    for fx in &theirs.fixtures {
        let Some(mine) = ours.get(&fx.id) else {
            continue;
        };
        let actionable = fx.actionable_keys();
        let discovered = actionable
            .iter()
            .filter(|k| mine.discovered.contains(**k))
            .count();
        let unsupported = actionable
            .iter()
            .filter(|k| !mine.discovered.contains(**k) && mine.unsupported.contains(**k))
            .count();
        let missed: Vec<String> = actionable
            .iter()
            .filter(|k| !mine.discovered.contains(**k) && !mine.unsupported.contains(**k))
            .map(|k| (*k).to_owned())
            .collect();
        total += actionable.len();
        found += discovered;
        fixtures.push(FixtureParity {
            id: fx.id.clone(),
            oracle_actionable: actionable.len(),
            discovered,
            unsupported,
            missed,
            oracle_error: fx.error.clone(),
        });
    }
    let parity_failures = fixtures
        .iter()
        .filter(|f| !f.parity())
        .map(|f| f.id.clone())
        .collect();
    let oracle_errors = fixtures
        .iter()
        .filter(|f| f.oracle_error.is_some())
        .map(|f| f.id.clone())
        .collect();
    // usize → f64 is exact for any element count a page can hold
    #[allow(clippy::cast_precision_loss)]
    let recall = if total == 0 {
        1.0
    } else {
        found as f64 / total as f64
    };
    DiscoveryComparison {
        driver: theirs.driver.clone(),
        driver_version: theirs.driver_version.clone(),
        fixtures,
        oracle_actionable: total,
        discovered: found,
        recall,
        parity_failures,
        oracle_errors,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn element(key: &str, actionable: bool) -> OracleElement {
        OracleElement {
            key: key.to_owned(),
            frame: "/g01/".to_owned(),
            dom_id: None,
            role: "button".to_owned(),
            name: String::new(),
            tag: "button".to_owned(),
            actionable,
            verdict: if actionable {
                "actionable"
            } else {
                "not_actionable"
            }
            .to_owned(),
            reason: None,
        }
    }

    fn report(fixtures: Vec<DiscoveredFixture>) -> DiscoveryReport {
        DiscoveryReport {
            driver: "reference".to_owned(),
            driver_version: "1.56.1".to_owned(),
            mode: "discovery".to_owned(),
            gym: "http://127.0.0.1:1".to_owned(),
            started: String::new(),
            finished: String::new(),
            fixtures,
        }
    }

    #[test]
    fn keys_match_the_runner_self_test_vectors() {
        assert_eq!(
            frame_path_of("http://127.0.0.1:4321/g05/frame1.html?x=1#top"),
            "/g05/frame1.html?x=1"
        );
        assert_eq!(frame_path_of("about:srcdoc"), "about:srcdoc");
        assert_eq!(frame_path_of("http://h"), "/");
        assert_eq!(
            element_key("/g01/", Some("c1"), "button", "ignored"),
            "/g01/::#c1"
        );
        assert_eq!(
            element_key("/g01/", Some(""), "link", "  Read\n More "),
            "/g01/::link|read more"
        );
        assert_eq!(normalize_name(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn recall_and_parity_are_computed_per_fixture() {
        let theirs = report(vec![
            DiscoveredFixture {
                id: "g01".to_owned(),
                url: String::new(),
                settle_ms: 500,
                error: None,
                elements: vec![
                    element("/g01/::#a", true),
                    element("/g01/::#b", true),
                    element("/g01/::#c", true),
                    element("/g01/::#hidden", false),
                ],
            },
            DiscoveredFixture {
                id: "g23".to_owned(),
                url: String::new(),
                settle_ms: 500,
                error: None,
                elements: vec![element("/g23/::#panel", true)],
            },
            DiscoveredFixture {
                id: "skipped".to_owned(),
                url: String::new(),
                settle_ms: 500,
                error: None,
                elements: vec![element("/skipped/::#z", true)],
            },
        ]);
        let mut ours = BTreeMap::new();
        ours.insert(
            "g01".to_owned(),
            CrawlxElements {
                discovered: ["/g01/::#a", "/g01/::#b"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                unsupported: BTreeSet::new(),
            },
        );
        ours.insert(
            "g23".to_owned(),
            CrawlxElements {
                discovered: BTreeSet::new(),
                unsupported: ["/g23/::#panel"].into_iter().map(str::to_owned).collect(),
            },
        );
        let cmp = compare_discovery(&ours, &theirs);
        assert_eq!(cmp.fixtures.len(), 2, "unknown fixtures are skipped");
        assert_eq!(cmp.oracle_actionable, 4);
        assert_eq!(cmp.discovered, 2);
        assert!((cmp.recall - 0.5).abs() < 1e-12);
        assert_eq!(cmp.parity_failures, vec!["g01".to_owned()]);
        assert_eq!(cmp.fixtures[0].missed, vec!["/g01/::#c".to_owned()]);
        assert_eq!(cmp.fixtures[1].unsupported, 1);
        assert!(cmp.fixtures[1].parity(), "unsupported_surface counts as parity");
        assert!(!cmp.passes());
    }

    #[test]
    fn passes_needs_the_floor_the_sample_size_and_parity() {
        let elements: Vec<OracleElement> = (0..MIN_ORACLE_ELEMENTS)
            .map(|i| element(&format!("/g/::#{i}"), true))
            .collect();
        let theirs = report(vec![DiscoveredFixture {
            id: "g".to_owned(),
            url: String::new(),
            settle_ms: 500,
            error: None,
            elements,
        }]);
        let all: BTreeSet<String> = (0..MIN_ORACLE_ELEMENTS).map(|i| format!("/g/::#{i}")).collect();
        let mut ours = BTreeMap::new();
        ours.insert(
            "g".to_owned(),
            CrawlxElements {
                discovered: all.clone(),
                unsupported: BTreeSet::new(),
            },
        );
        assert!(compare_discovery(&ours, &theirs).passes());
        let mut short = theirs.clone();
        short.fixtures[0].elements.pop();
        assert!(
            !compare_discovery(&ours, &short).passes(),
            "199 elements is below the floor"
        );
        let mut errored = theirs.clone();
        errored.fixtures[0].error = Some("timeout".to_owned());
        assert!(!compare_discovery(&ours, &errored).passes());
    }

    #[test]
    fn job_and_report_round_trip_and_reports_are_validated() {
        let manifest = FixtureManifest::embedded("g19").unwrap();
        let job = discovery_job(std::slice::from_ref(&manifest), "http://127.0.0.1:9/");
        assert_eq!(job.gym, "http://127.0.0.1:9");
        assert_eq!(job.fixtures[0].url, "http://127.0.0.1:9/g19/");
        assert_eq!(
            job.fixtures[0].settle_ms,
            7000 + SETTLE_MARGIN_MS,
            "latest timer reveal plus margin"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/job.json");
        write_discovery_job(&job, &path).unwrap();
        let back: DiscoveryJob = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, job);
        let json = serde_json::to_string(&report(Vec::new())).unwrap();
        assert!(DiscoveryReport::parse(&json).is_ok());
        assert!(DiscoveryReport::parse(&json.replace("reference", "other")).is_err());
        assert!(DiscoveryReport::parse(&json.replace("\"discovery\"", "\"matrix\"")).is_err());
    }
}
