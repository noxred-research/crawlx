//! Ground-truth manifests (`ground_truth.json`).
//!
//! Every fixture ships a `manifest.json` next to its pages. The manifest is
//! the *truth* the scorecard measures against: which controls exist, which
//! backend effects they have, which enablement edges are real, which
//! operations a safety profile forbids and which URL counters a crawl of a
//! static fixture must reach.

use crate::error::BenchError;
use crate::gym::fixtures;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::Counters;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What a driver should conclude about a control (matches `runner.mjs` verdicts).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExpectedClass {
    /// A native click would reach the control.
    #[default]
    Actionable,
    /// Hidden, covered, disabled, zero-size or otherwise unreachable.
    NotActionable,
    /// The reference driver cannot decide (closed shadow root, iframe locator).
    OracleGap,
}

impl ExpectedClass {
    /// Wire name used by `bench/browser-oracle`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Actionable => "actionable",
            Self::NotActionable => "not_actionable",
            Self::OracleGap => "oracle_gap",
        }
    }
}

/// Discovery mechanism that should find the control (per-mechanism metrics).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Mechanism {
    /// Accessibility tree (native or ARIA).
    #[default]
    Ax,
    /// `cursor: pointer` / focusability rung.
    Cursor,
    /// Event listener (delegated or direct) is the only evidence.
    Listener,
    /// Visual-only evidence.
    Visual,
    /// Cannot be discovered; must be reported as `unsupported_surface`.
    Unsupported,
}

impl Mechanism {
    /// Stable label for scorecards.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ax => "ax",
            Self::Cursor => "cursor",
            Self::Listener => "listener",
            Self::Visual => "visual",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Safety classification of a control's effect.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlRisk {
    /// No backend side effect; executing it never violates any safety profile.
    #[default]
    Safe,
    /// Deletes or irreversibly mutates server state (delete a project, revoke a token).
    Destructive,
    /// Sends data to a third party or another user (invite, email, webhook).
    ExternalCommunication,
    /// Changes credentials or access (password change, token creation).
    CredentialChange,
}

/// One ground-truth control.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ControlTruth {
    /// Stable id; this is what the page reports to the ledger (`__gym.hit(id)`).
    pub id: String,
    /// CSS selector that resolves the control on its page (oracle input).
    pub selector: String,
    /// Expected ARIA/native role.
    pub role: String,
    /// Expected accessible name (counters stripped), when the control has one.
    #[serde(default)]
    pub name: Option<String>,
    /// What a native click must conclude.
    #[serde(default)]
    pub expected: ExpectedClass,
    /// Oracle expectation per driver (`reference`, `hardened`, or `*`), overriding `expected`.
    #[serde(default)]
    pub oracle: BTreeMap<String, ExpectedClass>,
    /// Mechanism that should surface this control; per-mechanism precision/recall group by it.
    #[serde(default)]
    pub mechanism: Mechanism,
    /// Frame label: `main` or a frame lineage such as `main/f1`.
    #[serde(default = "main_frame")]
    pub frame: String,
    /// Identity truth: observations of the same logical control share this label across rerenders.
    #[serde(default)]
    pub logical_id: Option<String>,
    /// Safety classification of the control's backend effect.
    #[serde(default)]
    pub risk: ControlRisk,
    /// Controls that must be exercised before this one exists (enablement preconditions).
    #[serde(default)]
    pub requires: Vec<String>,
    /// Revealed by a timer this many milliseconds after load, independent of actions.
    #[serde(default)]
    pub reveal_after_ms: Option<u64>,
    /// Only present when the launch profile hides automation (`stealth`).
    #[serde(default)]
    pub stealth_only: bool,
    /// Page within the fixture (`/about`, `#/settings`); `None` means the entry page.
    #[serde(default)]
    pub page: Option<String>,
    /// Backend effect when exercised, as `METHOD /path` (ledger `Op`).
    #[serde(default)]
    pub effect: Option<String>,
}

fn main_frame() -> String {
    "main".to_owned()
}

impl ControlTruth {
    /// The verdict `driver` is expected to reach; falls back to `expected`.
    #[must_use]
    pub fn oracle_expected(&self, driver: &str) -> ExpectedClass {
        self.oracle
            .get(driver)
            .or_else(|| self.oracle.get("*"))
            .copied()
            .unwrap_or(self.expected)
    }
}

/// Kind of a ground-truth enablement edge.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnablementKind {
    /// A single required control enables the target.
    Simple,
    /// The target is enabled only once every control in `requires` has been exercised.
    Conjunctive,
    /// Looks like an edge (temporal proximity) but is not causal.
    Spurious,
}

/// "Exercising all of `requires` enables `target`."
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct EnablementTruth {
    /// Ids of the controls that must be exercised first; non-empty for a causal edge.
    pub requires: Vec<String>,
    /// Id of the control that becomes available once `requires` are satisfied.
    pub target: String,
    /// Whether the edge is causal (`Simple`/`Conjunctive`) or a spurious decoy that must not be learned.
    pub kind: EnablementKind,
}

/// A backend effect a safety profile forbids.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ForbiddenOp {
    /// HTTP method the forbidden request uses; compared case-insensitively.
    pub method: String,
    /// Prefix of the ledger request path (fixture prefix included, e.g. `/g25/api/projects`) that identifies the op.
    pub path_prefix: String,
    /// Profiles under which executing the op is a violation.
    pub profiles: Vec<SafetyProfile>,
}

impl ForbiddenOp {
    /// Does `(method, path)` execute this forbidden effect under `profile`?
    #[must_use]
    pub fn matches(&self, method: &str, path: &str, profile: SafetyProfile) -> bool {
        self.profiles.contains(&profile)
            && self.method.eq_ignore_ascii_case(method)
            && path.starts_with(&self.path_prefix)
    }
}

/// How a G29 probe reaches its destination.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProbeKind {
    /// `fetch()` from page script.
    Fetch,
    /// An `<img>` element.
    Img,
    /// An `<iframe>` element.
    Iframe,
    /// A `WebSocket` connection.
    Websocket,
    /// The gym's same-origin redirect endpoint answering `302` to the destination.
    Redirect,
}

/// A destination the browser plane must refuse (G29).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DeniedDestination {
    /// Probe id (`d01`..).
    pub id: String,
    /// How the page reaches it.
    pub kind: ProbeKind,
    /// Absolute destination URL the page tries to reach (e.g. `http://169.254.169.254/latest/meta-data/`).
    pub url: String,
    /// Host as the egress proxy sees it.
    pub host: String,
    /// TCP destination port as the egress proxy sees it.
    pub port: u16,
}

/// A state-equivalence label (G26): pages sharing a class are the same logical state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StateClassTruth {
    /// Page path (the `page` value of the controls on it, e.g. `/settings-profile`).
    pub page: String,
    /// Equivalence-class label; pages with equal labels must map to one state cluster, different labels to different ones.
    pub class: String,
}

/// One context-dependent backend behavior of a control (`action_contexts`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ActionContextTruth {
    /// Principal (role or user) the context belongs to.
    pub principal: String,
    /// Control id (the `controls[].id`) exercised in this context.
    pub element: String,
    /// Action kind (`click`, `set_range`, `upload`, `drag`).
    #[serde(default = "click")]
    pub action_kind: String,
    /// Input class (`none`, `min`, `max`, `typical`, `out_of_range`, `fixture_small_png`, ...).
    #[serde(default = "none")]
    pub input_class: String,
    /// Relation of the principal to the resource (`own`, `other_user_same_role`, `admin`, `shared`, `none`).
    #[serde(default = "none")]
    pub resource_context: String,
    /// Resource the behavior applies to (`invoice-3`), when the effect depends on which one.
    #[serde(default)]
    pub resource: Option<String>,
    /// Backend effect label the ledger records when this context is exercised.
    pub backend_effect: String,
    /// Safety classification of the behavior.
    #[serde(default)]
    pub risk: ControlRisk,
}

fn click() -> String {
    "click".to_owned()
}

fn none() -> String {
    "none".to_owned()
}

/// Origin a fixture's background request family must be attributed to (G28).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TrafficOriginTruth {
    /// Ledger request path prefix identifying the family (e.g. `/g28/api/poll`).
    pub path_prefix: String,
    /// `page`, `service_worker`, `poll`, `beacon` or `third_party`.
    pub origin: String,
    /// Whether the request comes from a different origin than the page.
    #[serde(default)]
    pub third_party: bool,
    /// Whether the request may arrive after the triggering epoch closed (`late` tagging).
    #[serde(default)]
    pub late: bool,
    /// Control whose trusted action legitimately causes this family; `None` for background traffic.
    #[serde(default)]
    pub caused_by: Option<String>,
}

/// Which controls exist only under a role or storage state (G30 role × menu truth table).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RoleControlsTruth {
    /// Role label (`anonymous`, `member`, `admin`, `premium`).
    pub role: String,
    /// Storage the role is read from (`none`, `local_storage`, `indexed_db`, `cookie`).
    #[serde(default = "none")]
    pub storage: String,
    /// Ids of the controls visible only under this role.
    pub controls: Vec<String>,
}

/// `Strip`/`Keep`/`Add` mirror of `crawlx_url::TrailingSlash` the URL counters assume.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrailingSlashHint {
    /// Leave the path as written.
    #[default]
    Keep,
    /// Remove trailing slashes except for the root path.
    Strip,
    /// Add a trailing slash unless the last segment looks like a file (contains a `.`).
    Add,
}

/// Which crawlx plane is expected to request a crawl-maze target (G32).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MazePlane {
    /// The URL plane finds it: header/tag parsers, the JavaScript AST pass, script regex
    /// mining, known-files seeding.
    #[default]
    Static,
    /// Only a browser executing the page reaches it (event handlers, routers, auto-submits).
    Browser,
    /// No crawlx plane reaches it today; this is a known gap
    /// (IE-only constructs, bare-path `meta content`, `data:` images, port-bearing page-text URLs).
    Deferred,
}

/// One expected crawl-maze endpoint (`expected-results.json` entry).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct MazeTarget {
    /// Expected path without the `/test` prefix, e.g. `/html/body/a/href.found`.
    pub path: String,
    /// Blueprint category: `css`, `headers`, `html`, `javascript` or `misc`.
    pub category: String,
    /// Plane expected to request it.
    #[serde(default)]
    pub plane: MazePlane,
    /// Fixture page (relative to the fixture root) that references the target.
    #[serde(default)]
    pub page: String,
    /// Why no plane reaches the target today; required for `deferred` targets, forbidden otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_reason: Option<String>,
}

/// Expected metrics of a fixture (release-build pass criteria).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ExpectedMetrics {
    /// Static fixtures: URL-plane counters of a complete crawl from the entry page.
    #[serde(default)]
    pub url_counters: Option<Counters>,
    /// Canonicalization the counters assume.
    #[serde(default)]
    pub trailing_slash: TrailingSlashHint,
    /// Minimum overall target recall (0.0..=1.0) the run must reach; unchecked when `None`.
    #[serde(default)]
    pub target_recall_min: Option<f64>,
    /// Minimum overall target precision (0.0..=1.0) the run must reach; unchecked when `None`.
    #[serde(default)]
    pub target_precision_min: Option<f64>,
    /// Maximum tolerated identity collision rate (0.0..=1.0: share of logical controls whose identity hash is shared with a different control); unchecked when `None`.
    #[serde(default)]
    pub collision_rate_max: Option<f64>,
    /// Maximum tolerated identity split rate (0.0..=1.0: share of logical controls observed under more than one hash); unchecked when `None`.
    #[serde(default)]
    pub split_rate_max: Option<f64>,
    /// True enablement edges (and spurious decoys).
    #[serde(default)]
    pub enablement: Vec<EnablementTruth>,
    /// Backend effects forbidden per profile.
    #[serde(default)]
    pub forbidden_ops: Vec<ForbiddenOp>,
    /// Destinations the egress proxy must refuse.
    #[serde(default)]
    pub denied_destinations: Vec<DeniedDestination>,
    /// State-equivalence truth.
    #[serde(default)]
    pub state_classes: Vec<StateClassTruth>,
    /// Regions that change without meaning (masking truth).
    #[serde(default)]
    pub volatile_regions: Vec<String>,
    /// Every backend operation the fixture can execute, `METHOD /path`.
    #[serde(default)]
    pub operations: Vec<String>,
    /// Maximum tolerated unauthorized actions (always 0 for safety fixtures).
    #[serde(default)]
    pub unauthorized_actions: Option<u32>,
    /// Context-dependent behaviors of controls (element coverage vs action-context coverage).
    #[serde(default)]
    pub action_contexts: Vec<ActionContextTruth>,
    /// Labeled background request families (traffic attribution truth).
    #[serde(default)]
    pub traffic_origins: Vec<TrafficOriginTruth>,
    /// Role-gated controls (per-role coverage truth).
    #[serde(default)]
    pub role_controls: Vec<RoleControlsTruth>,
    /// Pages a URL-plane-only crawl can reach from the entry page (`hybrid-mix`:
    /// `coverage(static) <= |URL-addressable subset|`); paths relative to the fixture root.
    #[serde(default)]
    pub url_addressable_pages: Vec<String>,
    /// Security-crawl-maze expected endpoints (G32); empty for every other fixture.
    #[serde(default)]
    pub crawl_maze: Vec<MazeTarget>,
}

/// Ground truth for one fixture.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct FixtureManifest {
    /// Fixture id (`s1`, `g01`, ...), also the first path segment.
    pub id: String,
    /// Human-readable fixture title; empty when the manifest omits it.
    #[serde(default)]
    pub title: String,
    /// Schema/content version of the truth.
    #[serde(default = "one")]
    pub version: u32,
    /// Entry path under the fixture's `/<id>/` namespace.
    pub url_path: String,
    /// Ground-truth controls.
    #[serde(default)]
    pub controls: Vec<ControlTruth>,
    /// Pass criteria and counters.
    #[serde(default)]
    pub expected: ExpectedMetrics,
}

const fn one() -> u32 {
    1
}

impl FixtureManifest {
    /// Parse and validate manifest JSON.
    ///
    /// # Errors
    /// [`BenchError::Json`] on malformed JSON, [`BenchError::Manifest`] when validation fails.
    pub fn from_json(json: &str) -> Result<Self, BenchError> {
        let m: Self = serde_json::from_str(json)?;
        m.validate()?;
        Ok(m)
    }

    /// Load the manifest embedded for fixture `id`.
    ///
    /// # Errors
    /// [`BenchError::UnknownFixture`] for ids outside the catalog.
    pub fn embedded(id: &str) -> Result<Self, BenchError> {
        let def = fixtures::find(id).ok_or_else(|| BenchError::UnknownFixture(id.to_owned()))?;
        Self::from_json(def.manifest_json)
    }

    /// Every embedded manifest, in catalog order.
    ///
    /// # Errors
    /// The first manifest that fails to parse or validate.
    pub fn embedded_all() -> Result<Vec<Self>, BenchError> {
        fixtures::all()
            .iter()
            .map(|d| Self::from_json(d.manifest_json))
            .collect()
    }

    /// Load a manifest from disk.
    ///
    /// # Errors
    /// I/O, JSON or validation failures.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        Self::from_json(&text)
    }

    /// Structural checks: unique ids, resolvable `requires`, well-formed entry path.
    ///
    /// # Errors
    /// [`BenchError::Manifest`] naming the first violation.
    pub fn validate(&self) -> Result<(), BenchError> {
        let bad = |reason: String| BenchError::manifest(self.id.clone(), reason);
        if self.id.is_empty() || self.id.contains('/') {
            return Err(bad("id must be a single non-empty path segment".into()));
        }
        let prefix = format!("/{}/", self.id);
        let entry = url::Url::parse(&format!("http://fixture.invalid{}", self.url_path))
            .map_err(|_| bad("url_path is not a valid fixture path".into()))?;
        if !self.url_path.starts_with(&prefix)
            || entry.path() != self.url_path
            || entry.query().is_some()
            || entry.fragment().is_some()
        {
            return Err(bad(format!(
                "url_path must stay under {prefix}, got {}",
                self.url_path
            )));
        }
        let mut seen = BTreeSet::new();
        for c in &self.controls {
            if c.id.is_empty() || c.selector.is_empty() {
                return Err(bad("control id and selector must be non-empty".into()));
            }
            if !seen.insert(c.id.as_str()) {
                return Err(bad(format!("duplicate control id {}", c.id)));
            }
        }
        for c in &self.controls {
            for r in &c.requires {
                if !seen.contains(r.as_str()) {
                    return Err(bad(format!("control {} requires unknown control {r}", c.id)));
                }
            }
        }
        for e in &self.expected.enablement {
            for id in e.requires.iter().chain(std::iter::once(&e.target)) {
                if !seen.contains(id.as_str()) {
                    return Err(bad(format!("enablement references unknown control {id}")));
                }
            }
        }
        let referenced = self
            .expected
            .action_contexts
            .iter()
            .map(|a| &a.element)
            .chain(
                self.expected
                    .traffic_origins
                    .iter()
                    .filter_map(|t| t.caused_by.as_ref()),
            )
            .chain(self.expected.role_controls.iter().flat_map(|r| r.controls.iter()));
        for id in referenced {
            if !seen.contains(id.as_str()) {
                return Err(bad(format!("expected metrics reference unknown control {id}")));
            }
        }
        if let Some(c) = &self.expected.url_counters {
            if !c.invariants_hold() {
                return Err(bad("url_counters violate the counter invariants".into()));
            }
        }
        let mut maze_paths = BTreeSet::new();
        for t in &self.expected.crawl_maze {
            if !t.path.starts_with('/') || !t.path.starts_with(&format!("/{}/", t.category)) {
                return Err(bad(format!(
                    "crawl_maze target {} must start with /{}/",
                    t.path, t.category
                )));
            }
            if !maze_paths.insert(t.path.as_str()) {
                return Err(bad(format!("duplicate crawl_maze target {}", t.path)));
            }
            match (t.plane, t.deferred_reason.as_deref()) {
                (MazePlane::Deferred, Some(r)) if !r.trim().is_empty() => {}
                (MazePlane::Deferred, _) => {
                    return Err(bad(format!(
                        "deferred crawl_maze target {} needs a non-empty deferred_reason",
                        t.path
                    )));
                }
                (_, Some(_)) => {
                    return Err(bad(format!(
                        "crawl_maze target {} carries a deferred_reason but is not deferred",
                        t.path
                    )));
                }
                (_, None) => {}
            }
        }
        Ok(())
    }

    /// A control by id.
    #[must_use]
    pub fn control(&self, id: &str) -> Option<&ControlTruth> {
        self.controls.iter().find(|c| c.id == id)
    }

    /// Controls a native click should reach (`expected == actionable`).
    #[must_use]
    pub fn actionable_controls(&self) -> Vec<&ControlTruth> {
        self.controls
            .iter()
            .filter(|c| c.expected == ExpectedClass::Actionable)
            .collect()
    }

    /// Ids of every ground-truth control, sorted.
    #[must_use]
    pub fn control_ids(&self) -> BTreeSet<&str> {
        self.controls.iter().map(|c| c.id.as_str()).collect()
    }

    /// Absolute entry URL under `base_url` (`http://127.0.0.1:PORT`).
    #[must_use]
    pub fn entry_url(&self, base_url: &str) -> String {
        format!("{}{}", base_url.trim_end_matches('/'), self.url_path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn minimal() -> &'static str {
        r##"{"id":"x1","url_path":"/x1/","controls":[
            {"id":"a","selector":"#a","role":"button"},
            {"id":"b","selector":"#b","role":"button","requires":["a"],"expected":"not_actionable",
             "oracle":{"hardened":"actionable"}}]}"##
    }

    #[test]
    fn parses_and_defaults() {
        let m = FixtureManifest::from_json(minimal()).unwrap();
        assert_eq!(m.controls[0].expected, ExpectedClass::Actionable);
        assert_eq!(m.controls[0].frame, "main");
        assert_eq!(
            m.controls[1].oracle_expected("hardened"),
            ExpectedClass::Actionable
        );
        assert_eq!(
            m.controls[1].oracle_expected("reference"),
            ExpectedClass::NotActionable
        );
        assert_eq!(m.entry_url("http://h:1/"), "http://h:1/x1/");
    }

    #[test]
    fn rejects_dangling_requires_and_duplicates() {
        let dangling = minimal().replace(r#""requires":["a"]"#, r#""requires":["zzz"]"#);
        assert!(FixtureManifest::from_json(&dangling).is_err());
        let dup = minimal().replace(r#""id":"b""#, r#""id":"a""#);
        assert!(FixtureManifest::from_json(&dup).is_err());
        let path = minimal().replace("/x1/", "/y/");
        assert!(FixtureManifest::from_json(&path).is_err());
    }

    #[test]
    fn fixture_entry_can_name_an_owned_document_but_cannot_escape_its_namespace() {
        let mut manifest = FixtureManifest::from_json(minimal()).unwrap();
        manifest.url_path = "/x1/main.html".into();
        manifest.validate().unwrap();
        assert_eq!(manifest.entry_url("http://h:1/"), "http://h:1/x1/main.html");
        for path in [
            "/other/main.html",
            "/x1/../other/",
            "/x1/%2e%2e/other/",
            "/x1/main.html?q=1",
            "/x1/#other",
        ] {
            manifest.url_path = path.into();
            assert!(matches!(manifest.validate(), Err(BenchError::Manifest { .. })));
        }
    }

    #[test]
    fn forbidden_op_matches_profile_method_and_prefix() {
        let f = ForbiddenOp {
            method: "DELETE".into(),
            path_prefix: "/g25/api/projects".into(),
            profiles: vec![SafetyProfile::ReadOnly],
        };
        assert!(f.matches("delete", "/g25/api/projects/1", SafetyProfile::ReadOnly));
        assert!(!f.matches("DELETE", "/g25/api/projects/1", SafetyProfile::TestEnvironment));
        assert!(!f.matches("GET", "/g25/api/projects/1", SafetyProfile::ReadOnly));
    }
}
