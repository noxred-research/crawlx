//! Scorecards: the metrics computed from a run's rows plus the gym ledger.
//!
//! The ledger is the ground truth for *what happened* (which handlers ran, which backend
//! effects were reached, whether a forbidden effect executed). The run rows are what the
//! crawler recorded; they are compared against the manifest's truth for discovery,
//! identity, enablement and state metrics. A metric whose inputs are absent is `None`
//! (never a fabricated `0.0`).

use crate::error::BenchError;
use crate::gym::ledger::{Ledger, LedgerEvent};
use crate::gym::manifest::{ControlTruth, EnablementKind, ExpectedClass, FixtureManifest, Mechanism};
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::ActionStatus;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::ids::{ActionContextId, CrawlRunId, EdgeId, StateClusterId};
use crawlx_core::observation::SettleReport;
use crawlx_core::repo::{
    ActionJournal, ActionRecord, EdgeRecord, EdgeStore, LedgerRepo, LedgerRow, StateRepo,
};
use crawlx_core::traffic::TrustLane;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// `score.json` schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// One candidate the crawler produced, labelled against ground truth by the harness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DiscoveredTarget {
    /// Matched ground-truth control id, or `None` for a false positive.
    pub control: Option<String>,
    /// Mechanism (ladder rung) that surfaced it.
    pub mechanism: Mechanism,
}

/// A replay of an enablement edge.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct ReplayAttempt {
    /// The edge's `p_success` when the replay was chosen.
    pub p_success: f64,
    /// Did the replay restore the target's availability?
    pub restored: bool,
}

/// Proposal bookkeeping (strategies/arbiter side).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ProposalCounts {
    /// Total proposals the arbiter received.
    pub total: u64,
    /// Dropped for a stale epoch or failed revalidation.
    pub stale_dropped: u64,
}

/// Everything a scorecard needs besides the manifest and the gym ledger.
#[derive(Clone, Debug)]
pub struct RunRows {
    /// Id of the fixture the run exercised (equals the manifest id and the ledger label).
    pub fixture: String,
    /// Seed the gym rendered the fixture with; every run of the same fixture and seed is identical.
    pub seed: u64,
    /// Ablation variant id (`A0`..`A12`) or any label.
    pub variant: String,
    /// Safety profile the run executed under; decides which forbidden ops count as violations.
    pub profile: SafetyProfile,
    /// The run used the `stealth` launch profile (`stealth_only` controls become targets).
    pub stealth: bool,
    /// Candidates the crawler surfaced; false positives carry `control: None`.
    pub discovered: Vec<DiscoveredTarget>,
    /// Controls reported as `unsupported_surface`.
    pub unsupported_reported: Vec<String>,
    /// `(identity hash, logical control)` for every labelled observation across rerenders.
    pub identity_observations: Vec<(ElementIdentityHash, String)>,
    /// Persisted action-journal rows of the run.
    pub actions: Vec<ActionRecord>,
    /// Persisted enablement-graph edges of the run.
    pub edges: Vec<EdgeRecord>,
    /// Edges whose most recent replay failed.
    pub failed_replay_edges: BTreeSet<EdgeId>,
    /// Build the edges must be verified against; `None` disables the build-drift criterion.
    pub current_build: Option<String>,
    /// Replay attempts of enablement edges; only attempts with `p_success >= 0.8` are scored.
    pub replays: Vec<ReplayAttempt>,
    /// Recorded enablement edges as `(source control, target control)`.
    pub recorded_edges: Vec<(String, String)>,
    /// `(page label, cluster)` for every observed state; page labels are fixture-relative paths.
    pub state_assignments: Vec<(String, StateClusterId)>,
    /// One settle report per observation; the quiescence timeout rate counts those with `settle_timeout`.
    pub settles: Vec<SettleReport>,
    /// Proposal totals for the stale-proposal rate.
    pub proposals: ProposalCounts,
    /// Per-lane network epoch counts `(trusted_ui, diagnostic)`.
    pub network_epochs: Option<(u64, u64)>,
    /// The crawler's own action-context ledger (claims; scoring never trusts it for coverage).
    pub claimed: Vec<LedgerRow>,
    /// Element labels for [`Self::claimed`]: identity hash to control id.
    pub element_labels: BTreeMap<ElementIdentityHash, String>,
}

impl RunRows {
    /// Empty rows for `fixture`.
    #[must_use]
    pub fn new(fixture: &str, seed: u64, variant: &str, profile: SafetyProfile) -> Self {
        Self {
            fixture: fixture.to_owned(),
            seed,
            variant: variant.to_owned(),
            profile,
            stealth: false,
            discovered: Vec::new(),
            unsupported_reported: Vec::new(),
            identity_observations: Vec::new(),
            actions: Vec::new(),
            edges: Vec::new(),
            failed_replay_edges: BTreeSet::new(),
            current_build: None,
            replays: Vec::new(),
            recorded_edges: Vec::new(),
            state_assignments: Vec::new(),
            settles: Vec::new(),
            proposals: ProposalCounts::default(),
            network_epochs: None,
            claimed: Vec::new(),
            element_labels: BTreeMap::new(),
        }
    }

    /// Load the persisted rows of `run` (actions, edges, the action-context ledger, states).
    ///
    /// Harness-labelled inputs (`discovered`, `identity_observations`, `settles`, ...) stay
    /// empty; fill them from the driver that knows the selectors.
    ///
    /// # Errors
    /// Repository failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect(
        run: CrawlRunId,
        fixture: &str,
        seed: u64,
        variant: &str,
        profile: SafetyProfile,
        journal: &dyn ActionJournal,
        edges: &dyn EdgeStore,
        ledger: &dyn LedgerRepo,
        states: &dyn StateRepo,
    ) -> Result<Self, BenchError> {
        let mut rows = Self::new(fixture, seed, variant, profile);
        rows.actions = journal.list(run, None).await?;
        rows.edges = edges.list(run).await?;
        rows.claimed = ledger.list(run).await?;
        let prefix = format!("/{fixture}");
        let clusters: Vec<(String, StateClusterId)> = states
            .list_states(run)
            .await?
            .into_iter()
            .map(|s| {
                let path = s.url.url.path();
                let rel = path.strip_prefix(prefix.as_str()).unwrap_or(path);
                let rel = if rel.is_empty() { "/" } else { rel };
                let label = match s.url.url.query() {
                    Some(q) => format!("{rel}?{q}"),
                    None => rel.to_owned(),
                };
                (label, s.cluster)
            })
            .collect();
        rows.state_assignments = clusters;
        Ok(rows)
    }

    /// Label [`Self::edges`] as `(source control, target control)` pairs in
    /// [`Self::recorded_edges`]: an edge's source is an action-context id, resolved to its
    /// element through the journal rows and the crawler's ledger; source and target elements
    /// map to controls through [`Self::element_labels`]. Edges whose source or target has no
    /// label are not scorable and are skipped; the result is sorted and unique.
    pub fn label_recorded_edges(&mut self) {
        let element_of: BTreeMap<ActionContextId, ElementIdentityHash> = self
            .actions
            .iter()
            .map(|a| &a.key)
            .chain(self.claimed.iter().map(|r| &r.key))
            .map(|k| (k.id(), k.element))
            .collect();
        let mut pairs: BTreeSet<(String, String)> = self.recorded_edges.drain(..).collect();
        for e in &self.edges {
            let Some(src) = element_of.get(&e.source).and_then(|h| self.element_labels.get(h)) else {
                continue;
            };
            let Some(dst) = self.element_labels.get(&e.target) else {
                continue;
            };
            pairs.insert((src.clone(), dst.clone()));
        }
        self.recorded_edges = pairs.into_iter().collect();
    }
}

/// Precision, recall and F1 with explicit counts.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct Prf {
    /// True positives: distinct ground-truth items that were found.
    pub tp: u64,
    /// False positives: candidates that matched no ground-truth item.
    pub fp: u64,
    /// False negatives: ground-truth items that were not found.
    pub fn_: u64,
    /// `tp / (tp + fp)` in `[0, 1]`; `1.0` when nothing was predicted and nothing was missed, `0.0` when nothing was predicted but items were missed.
    pub precision: f64,
    /// `tp / (tp + fn_)` in `[0, 1]`; `1.0` when there is nothing to find.
    pub recall: f64,
    /// Harmonic mean of precision and recall in `[0, 1]`; `0.0` when both are zero.
    pub f1: f64,
}

impl Prf {
    /// From counts. No predictions and nothing to find is vacuously perfect.
    #[must_use]
    pub fn from_counts(tp: u64, fp: u64, fn_: u64) -> Self {
        let precision = if tp + fp == 0 {
            if fn_ == 0 {
                1.0
            } else {
                0.0
            }
        } else {
            tp as f64 / (tp + fp) as f64
        };
        let recall = if tp + fn_ == 0 {
            1.0
        } else {
            tp as f64 / (tp + fn_) as f64
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        Self {
            tp,
            fp,
            fn_,
            precision,
            recall,
            f1,
        }
    }
}

/// Interactive-target discovery.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct TargetMetrics {
    /// Precision/recall over all actionable, supported ground-truth controls.
    pub overall: Prf,
    /// Precision by the mechanism that surfaced a candidate, recall by the truth mechanism.
    pub by_mechanism: BTreeMap<String, Prf>,
    /// Controls the manifest marks [`Mechanism::Unsupported`]; the crawler must report them as `unsupported_surface`.
    pub unsupported_expected: u64,
    /// Distinct expected-unsupported controls the crawler actually reported as `unsupported_surface`.
    pub unsupported_reported: u64,
    /// Ids of ground-truth targets the crawler did not discover, sorted.
    pub missed: Vec<String>,
}

/// Action-context coverage and the time-to-coverage curve.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct CoverageMetrics {
    /// Ground-truth controls the run could exercise.
    pub gt_total: u64,
    /// Headline: distinct controls whose handler ran from a trusted event.
    pub trusted: f64,
    /// Distinct controls whose handler ran from any event.
    pub all_lanes: f64,
    /// Ids of controls whose handler ran from a trusted event, sorted.
    pub exercised: Vec<String>,
    /// Ids of ground-truth controls never exercised from a trusted event, sorted.
    pub missing: Vec<String>,
    /// Interaction counts at which coverage first reached 50/80/95%.
    pub t50: Option<u64>,
    /// Interaction count at which coverage first reached 80%; `None` if it never did.
    pub t80: Option<u64>,
    /// Interaction count at which coverage first reached 95%; `None` if it never did.
    pub t95: Option<u64>,
    /// Normalized area under coverage-vs-interaction-count in `[0, 1]`.
    pub auc: f64,
    /// Distinct backend operations reached over the manifest's operations.
    pub backend_operation_coverage: Option<f64>,
    /// Coverage by the crawler's own claims, when labelled (cross-check only).
    pub claimed: Option<f64>,
}

/// Identity stability.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct IdentityMetrics {
    /// Share in `[0, 1]` of logical controls whose identity hash is shared with a different logical control.
    pub collision_rate: f64,
    /// Share in `[0, 1]` of logical controls observed under more than one identity hash.
    pub split_rate: f64,
    /// Share in `[0, 1]` of labelled controls whose claimed action-context key is shared with a
    /// different control; `0.0` when no claimed key is labelled.
    #[serde(default)]
    pub key_collision_rate: f64,
}

/// Enablement-graph quality.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct EnablementMetrics {
    /// Replays of edges that had `p_success >= 0.8` when chosen.
    pub replays_attempted: u64,
    /// Attempted replays that restored the target's availability.
    pub replays_succeeded: u64,
    /// For edges with `p_success >= 0.8`.
    pub replay_success: Option<f64>,
    /// Distinct `(source, target)` edges the crawler recorded.
    pub recorded: u64,
    /// Recorded edges absent from the manifest's causal enablement truth.
    pub spurious: u64,
    /// `spurious / recorded`; `None` when no edge was recorded.
    pub false_edge_rate: Option<f64>,
    /// True edges recovered over true edges.
    pub recall: Option<f64>,
}

/// State clustering quality.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct StateMetrics {
    /// Labelled page pairs of different truth classes placed in the same cluster.
    pub false_merge_pairs: u64,
    /// Labelled page pairs of the same truth class placed in different clusters.
    pub false_split_pairs: u64,
    /// `false_merge_pairs` over all different-class page pairs, in `[0, 1]`; `0.0` when there are none.
    pub false_merge_rate: f64,
    /// `false_split_pairs` over all same-class page pairs, in `[0, 1]`; `0.0` when there are none.
    pub false_split_rate: f64,
    /// False merges whose two states expose different control sets (hide a reachable action).
    pub merges_hiding_actions: u64,
}

/// Lane shares over actions.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct LaneMetrics {
    /// Actions executed on the trusted-UI lane.
    pub trusted: u64,
    /// Actions executed on the diagnostic lane.
    pub diagnostic: u64,
    /// `trusted / (trusted + diagnostic)` in `[0, 1]`.
    pub trusted_share: f64,
    /// `diagnostic / (trusted + diagnostic)` in `[0, 1]`.
    pub diagnostic_share: f64,
}

/// Safety outcome from the ledger.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct SafetyMetrics {
    /// Click rows + form rows + mutating backend ops.
    pub executed: u64,
    /// Executed mutating effects that a forbidden-op rule of the manifest forbids under the run's profile.
    pub unauthorized: u64,
    /// `unauthorized / executed`; acceptance threshold is exactly 0.
    pub unauthorized_action_rate: f64,
    /// `METHOD path` of every unauthorized effect, in ledger order.
    pub violations: Vec<String>,
}

/// `unknown` outcome handling.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct UnknownMetrics {
    /// Actions whose status is `Unknown` or that carry a reconcile resolution.
    pub unknown_total: u64,
    /// Unknown-outcome actions that ended `Reconciled` with a resolution.
    pub reconciled: u64,
    /// `reconciled / unknown_total` in `[0, 1]`; `1.0` when no outcome was unknown.
    pub resolution_rate: f64,
    /// Non-idempotent actions executed again without a `not_applied` reconciliation.
    pub repeated_non_idempotent: u64,
}

/// A manifest threshold evaluated against a metric.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct Check {
    /// Metric name (`target_recall`, `identity_split_rate`, `unauthorized_actions`, ...).
    pub name: String,
    /// Threshold rendered as text, e.g. `>= 0.700`.
    pub expected: String,
    /// Measured value rendered as text.
    pub actual: String,
    /// Whether `actual` satisfies `expected`.
    pub passed: bool,
}

/// The complete scorecard of one run (`score.json`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct Scorecard {
    /// [`SCHEMA_VERSION`] the document was written with.
    pub schema_version: u32,
    /// Id of the fixture that was scored.
    pub fixture: String,
    /// Seed the fixture was rendered with.
    pub seed: u64,
    /// Ablation variant id (`A0`..`A12`) or free-form label of the run.
    pub variant: String,
    /// Safety profile the run executed under.
    pub profile: SafetyProfile,
    /// Interactive-target discovery metrics.
    pub targets: TargetMetrics,
    /// Action-context coverage computed from the gym ledger.
    pub coverage: CoverageMetrics,
    /// Identity stability; `None` without labelled identity observations.
    pub identity: Option<IdentityMetrics>,
    /// Enablement-graph quality; `None` without recorded edges, eligible replays or truth edges.
    pub enablement: Option<EnablementMetrics>,
    /// Share of active edges (`support > 0`) whose last replay failed or that were not verified on the current build; `None` without active edges.
    pub stale_edge_rate: Option<f64>,
    /// State clustering quality; `None` without state truth or observed states.
    pub states: Option<StateMetrics>,
    /// Share of settle reports that hit the settle timeout; `None` without settles.
    pub quiescence_timeout_rate: Option<f64>,
    /// Share of proposals dropped as stale; `None` without proposals.
    pub stale_proposal_rate: Option<f64>,
    /// Trusted vs diagnostic lane shares; `None` when no action carries a lane.
    pub lanes: Option<LaneMetrics>,
    /// Trusted share of network epochs in `[0, 1]`; `None` without epoch counts.
    pub network_epoch_trusted_share: Option<f64>,
    /// Safety outcome computed from the ledger.
    pub safety: SafetyMetrics,
    /// Measured unknown-outcome handling, including measured zeros; `None` in evidence that omitted it.
    pub unknown: Option<UnknownMetrics>,
    /// Filled by [`Scorecard::with_run_to_run`].
    pub run_to_run_jaccard: Option<f64>,
    /// Manifest thresholds evaluated against the metrics above.
    pub checks: Vec<Check>,
}

/// `|A ∩ B| / |A ∪ B|`; two empty sets are identical (1.0).
#[must_use]
pub fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> f64 {
    let union = a.union(b).count();
    if union == 0 {
        return 1.0;
    }
    a.intersection(b).count() as f64 / union as f64
}

fn ratio(num: u64, den: u64) -> Option<f64> {
    (den > 0).then(|| num as f64 / den as f64)
}

fn is_mutating(method: &str) -> bool {
    !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
}

fn gt_targets(manifest: &FixtureManifest, stealth: bool) -> Vec<&ControlTruth> {
    manifest
        .controls
        .iter()
        .filter(|c| c.expected == ExpectedClass::Actionable)
        .filter(|c| c.mechanism != Mechanism::Unsupported)
        .filter(|c| stealth || !c.stealth_only)
        .collect()
}

fn target_metrics(manifest: &FixtureManifest, rows: &RunRows) -> TargetMetrics {
    let truth = gt_targets(manifest, rows.stealth);
    let truth_ids: BTreeSet<&str> = truth.iter().map(|c| c.id.as_str()).collect();
    let found: BTreeSet<&str> = rows
        .discovered
        .iter()
        .filter_map(|d| d.control.as_deref())
        .filter(|id| truth_ids.contains(id))
        .collect();
    let fp = rows
        .discovered
        .iter()
        .filter(|d| d.control.as_deref().is_none_or(|id| !truth_ids.contains(id)))
        .count() as u64;
    let overall = Prf::from_counts(found.len() as u64, fp, (truth_ids.len() - found.len()) as u64);

    let mut by_mechanism = BTreeMap::new();
    let mechanisms: BTreeSet<Mechanism> = truth
        .iter()
        .map(|c| c.mechanism)
        .chain(rows.discovered.iter().map(|d| d.mechanism))
        .collect();
    for m in mechanisms {
        let truth_m: BTreeSet<&str> = truth
            .iter()
            .filter(|c| c.mechanism == m)
            .map(|c| c.id.as_str())
            .collect();
        let tp_m = truth_m.iter().filter(|id| found.contains(**id)).count() as u64;
        let surfaced: Vec<&DiscoveredTarget> = rows.discovered.iter().filter(|d| d.mechanism == m).collect();
        let correct = surfaced
            .iter()
            .filter(|d| d.control.as_deref().is_some_and(|id| truth_ids.contains(id)))
            .map(|d| d.control.as_deref().unwrap_or(""))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let fp_m = surfaced.len() as u64
            - surfaced
                .iter()
                .filter(|d| d.control.as_deref().is_some_and(|id| truth_ids.contains(id)))
                .count() as u64;
        // Precision uses the mechanism that surfaced the candidate; recall the truth mechanism.
        let precision = Prf::from_counts(correct, fp_m, 0).precision;
        let recall = Prf::from_counts(tp_m, 0, truth_m.len() as u64 - tp_m).recall;
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        by_mechanism.insert(
            m.as_str().to_owned(),
            Prf {
                tp: tp_m,
                fp: fp_m,
                fn_: truth_m.len() as u64 - tp_m,
                precision,
                recall,
                f1,
            },
        );
    }
    let unsupported: BTreeSet<&str> = manifest
        .controls
        .iter()
        .filter(|c| c.mechanism == Mechanism::Unsupported)
        .map(|c| c.id.as_str())
        .collect();
    let reported = rows
        .unsupported_reported
        .iter()
        .filter(|id| unsupported.contains(id.as_str()))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    TargetMetrics {
        overall,
        by_mechanism,
        unsupported_expected: unsupported.len() as u64,
        unsupported_reported: reported,
        missed: truth_ids.difference(&found).map(|s| (*s).to_owned()).collect(),
    }
}

fn coverage_metrics(manifest: &FixtureManifest, rows: &RunRows, ledger: &Ledger) -> CoverageMetrics {
    let truth = gt_targets(manifest, rows.stealth);
    let truth_ids: BTreeSet<&str> = truth.iter().map(|c| c.id.as_str()).collect();
    let clicks = ledger.clicks(&manifest.id);
    let mut trusted_set: BTreeSet<&str> = BTreeSet::new();
    let mut any_set: BTreeSet<&str> = BTreeSet::new();
    let mut curve: Vec<f64> = Vec::with_capacity(clicks.len());
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (id, trusted) in &clicks {
        let id = id.as_str();
        if truth_ids.contains(id) {
            any_set.insert(id);
            if *trusted {
                trusted_set.insert(id);
            }
            seen.insert(id);
        }
        curve.push(if truth_ids.is_empty() {
            1.0
        } else {
            seen.len() as f64 / truth_ids.len() as f64
        });
    }
    let total = truth_ids.len() as u64;
    let frac = |n: usize| if total == 0 { 1.0 } else { n as f64 / total as f64 };
    let reach = |p: f64| curve.iter().position(|c| *c >= p).map(|i| i as u64 + 1);
    let auc = if curve.is_empty() {
        0.0
    } else {
        curve.iter().sum::<f64>() / curve.len() as f64
    };

    let expected_ops: BTreeSet<String> = manifest.expected.operations.iter().cloned().collect();
    let backend_operation_coverage = if expected_ops.is_empty() {
        None
    } else {
        let hit: BTreeSet<String> = ledger
            .ops(&manifest.id)
            .into_iter()
            .map(|(m, p)| format!("{m} {p}"))
            .collect();
        let reached = expected_ops.iter().filter(|op| op_reached(op, &hit)).count();
        Some(reached as f64 / expected_ops.len() as f64)
    };

    let claimed = if rows.element_labels.is_empty() || rows.claimed.is_empty() || total == 0 {
        None
    } else {
        let labels: BTreeSet<&str> = rows
            .claimed
            .iter()
            .filter(|r| r.trusted_exercised > 0)
            .filter_map(|r| rows.element_labels.get(&r.key.element).map(String::as_str))
            .filter(|id| truth_ids.contains(id))
            .collect();
        Some(frac(labels.len()))
    };

    CoverageMetrics {
        gt_total: total,
        trusted: frac(trusted_set.len()),
        all_lanes: frac(any_set.len()),
        exercised: trusted_set.iter().map(|s| (*s).to_owned()).collect(),
        missing: truth_ids
            .iter()
            .filter(|id| !trusted_set.contains(**id))
            .map(|s| (*s).to_owned())
            .collect(),
        t50: reach(0.5),
        t80: reach(0.8),
        t95: reach(0.95),
        auc,
        backend_operation_coverage,
        claimed,
    }
}

/// An expected op `METHOD /path` is reached by an exact ledger op or by a ledger op whose
/// path starts with it (ops like `DELETE /g25/api/projects` cover `/projects/7`).
fn op_reached(expected: &str, hit: &BTreeSet<String>) -> bool {
    hit.iter().any(|h| h == expected || h.starts_with(expected))
}

fn identity_metrics(rows: &RunRows) -> Option<IdentityMetrics> {
    if rows.identity_observations.is_empty() {
        return None;
    }
    let (collision_rate, split_rate) = crawlx_elements::rates(&rows.identity_observations);
    let key_collision_rate = key_collision_rate(rows);
    // the scorecard is the only producer of these three gauges.
    let metrics = crawlx_telemetry::Metrics::global();
    metrics
        .gauge(crawlx_telemetry::metrics::names::IDENTITY_COLLISION_RATE)
        .set(collision_rate, &[]);
    metrics
        .gauge(crawlx_telemetry::metrics::names::IDENTITY_SPLIT_RATE)
        .set(split_rate, &[]);
    metrics
        .gauge(crawlx_telemetry::metrics::names::KEYS_COLLISION_RATE)
        .set(key_collision_rate, &[]);
    Some(IdentityMetrics {
        collision_rate,
        split_rate,
        key_collision_rate,
    })
}

/// Key collision: share of labelled controls whose claimed action-context key
/// (`ActionContextKey::id`, so element identity plus principal, route, kind, input class,
/// resource context and state cluster) is also claimed for a different control. Labels
/// come from [`RunRows::element_labels`] and from the harness's identity observations,
/// which may label one hash with several controls when identities collide. `0.0` when no
/// claimed key is labelled.
fn key_collision_rate(rows: &RunRows) -> f64 {
    let mut labels: BTreeMap<&ElementIdentityHash, BTreeSet<&str>> = BTreeMap::new();
    for (hash, control) in &rows.identity_observations {
        labels.entry(hash).or_default().insert(control.as_str());
    }
    for (hash, control) in &rows.element_labels {
        labels.entry(hash).or_default().insert(control.as_str());
    }
    let mut by_key: BTreeMap<ActionContextId, BTreeSet<&str>> = BTreeMap::new();
    for row in &rows.claimed {
        if let Some(controls) = labels.get(&row.key.element) {
            by_key
                .entry(row.key.id())
                .or_default()
                .extend(controls.iter().copied());
        }
    }
    let mut keyed: BTreeSet<&str> = BTreeSet::new();
    let mut collided: BTreeSet<&str> = BTreeSet::new();
    for controls in by_key.values() {
        keyed.extend(controls.iter().copied());
        if controls.len() > 1 {
            collided.extend(controls.iter().copied());
        }
    }
    if keyed.is_empty() {
        0.0
    } else {
        collided.len() as f64 / keyed.len() as f64
    }
}

fn enablement_metrics(manifest: &FixtureManifest, rows: &RunRows) -> Option<EnablementMetrics> {
    let truth_pairs: BTreeSet<(&str, &str)> = manifest
        .expected
        .enablement
        .iter()
        .filter(|e| e.kind != EnablementKind::Spurious)
        .flat_map(|e| e.requires.iter().map(move |r| (r.as_str(), e.target.as_str())))
        .collect();
    let eligible: Vec<&ReplayAttempt> = rows.replays.iter().filter(|r| r.p_success >= 0.8).collect();
    if rows.recorded_edges.is_empty() && eligible.is_empty() && truth_pairs.is_empty() {
        return None;
    }
    let recorded: BTreeSet<(&str, &str)> = rows
        .recorded_edges
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let spurious = recorded.iter().filter(|p| !truth_pairs.contains(*p)).count() as u64;
    let recovered = truth_pairs.iter().filter(|p| recorded.contains(*p)).count() as u64;
    Some(EnablementMetrics {
        replays_attempted: eligible.len() as u64,
        replays_succeeded: eligible.iter().filter(|r| r.restored).count() as u64,
        replay_success: ratio(
            eligible.iter().filter(|r| r.restored).count() as u64,
            eligible.len() as u64,
        ),
        recorded: recorded.len() as u64,
        spurious,
        false_edge_rate: ratio(spurious, recorded.len() as u64),
        recall: ratio(recovered, truth_pairs.len() as u64),
    })
}

fn stale_edge_rate(rows: &RunRows) -> Option<f64> {
    let active: Vec<&EdgeRecord> = rows.edges.iter().filter(|e| e.support > 0).collect();
    let stale = active
        .iter()
        .filter(|e| {
            rows.failed_replay_edges.contains(&e.id)
                || rows
                    .current_build
                    .as_ref()
                    .is_some_and(|b| e.last_verified_build.as_ref() != Some(b))
        })
        .count() as u64;
    ratio(stale, active.len() as u64)
}

fn state_metrics(manifest: &FixtureManifest, rows: &RunRows) -> Option<StateMetrics> {
    let classes: BTreeMap<&str, &str> = manifest
        .expected
        .state_classes
        .iter()
        .map(|s| (s.page.as_str(), s.class.as_str()))
        .collect();
    if classes.is_empty() || rows.state_assignments.is_empty() {
        return None;
    }
    // One representative cluster per labelled page (the first observed); pages without truth are ignored.
    let mut states: BTreeMap<&str, &StateClusterId> = BTreeMap::new();
    for (page, cluster) in &rows.state_assignments {
        if classes.contains_key(page.as_str()) {
            states.entry(page.as_str()).or_insert(cluster);
        }
    }
    let controls_of = |page: &str| -> BTreeSet<&str> {
        manifest
            .controls
            .iter()
            .filter(|c| c.page.as_deref() == Some(page))
            .map(|c| c.id.as_str())
            .collect()
    };
    let pages: Vec<&str> = states.keys().copied().collect();
    let (mut diff_pairs, mut same_pairs, mut merges, mut splits, mut hiding) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for (i, a) in pages.iter().enumerate() {
        for b in &pages[i + 1..] {
            let same_class = classes[a] == classes[b];
            let same_cluster = states[a] == states[b];
            if same_class {
                same_pairs += 1;
                if !same_cluster {
                    splits += 1;
                }
            } else {
                diff_pairs += 1;
                if same_cluster {
                    merges += 1;
                    if controls_of(a) != controls_of(b) {
                        hiding += 1;
                    }
                }
            }
        }
    }
    Some(StateMetrics {
        false_merge_pairs: merges,
        false_split_pairs: splits,
        false_merge_rate: ratio(merges, diff_pairs).unwrap_or(0.0),
        false_split_rate: ratio(splits, same_pairs).unwrap_or(0.0),
        merges_hiding_actions: hiding,
    })
}

fn lane_metrics(rows: &RunRows) -> Option<LaneMetrics> {
    let trusted = rows
        .actions
        .iter()
        .filter(|a| a.lane == Some(TrustLane::TrustedUi))
        .count() as u64;
    let diagnostic = rows
        .actions
        .iter()
        .filter(|a| a.lane == Some(TrustLane::Diagnostic))
        .count() as u64;
    let total = trusted + diagnostic;
    (total > 0).then(|| LaneMetrics {
        trusted,
        diagnostic,
        trusted_share: trusted as f64 / total as f64,
        diagnostic_share: diagnostic as f64 / total as f64,
    })
}

fn safety_metrics(manifest: &FixtureManifest, rows: &RunRows, ledger: &Ledger) -> SafetyMetrics {
    let mut executed = 0u64;
    let mut violations: Vec<String> = Vec::new();
    for e in ledger.entries_for(&manifest.id) {
        match &e.event {
            LedgerEvent::Click { .. } | LedgerEvent::FormSubmit { .. } => executed += 1,
            LedgerEvent::Op { method, path, .. } if is_mutating(method) => {
                executed += 1;
                if manifest
                    .expected
                    .forbidden_ops
                    .iter()
                    .any(|f| f.matches(method, path, rows.profile))
                {
                    violations.push(format!("{method} {path}"));
                }
            }
            _ => {}
        }
    }
    let unauthorized = violations.len() as u64;
    SafetyMetrics {
        executed,
        unauthorized,
        unauthorized_action_rate: if executed == 0 {
            0.0
        } else {
            unauthorized as f64 / executed as f64
        },
        violations,
    }
}

fn unknown_metrics(rows: &RunRows) -> UnknownMetrics {
    let unknown_total = rows
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Unknown || a.reconcile_resolution.is_some())
        .count() as u64;
    let repeated = rows
        .actions
        .iter()
        .filter(|a| a.attempt > 1 && !a.key.action_kind.is_idempotent())
        .filter(|a| a.reconcile_resolution != Some(crawlx_core::counters::ReconcileResolution::NotApplied))
        .count() as u64;
    let reconciled = rows
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Reconciled && a.reconcile_resolution.is_some())
        .count() as u64;
    UnknownMetrics {
        unknown_total,
        reconciled,
        resolution_rate: if unknown_total == 0 {
            1.0
        } else {
            reconciled as f64 / unknown_total as f64
        },
        repeated_non_idempotent: repeated,
    }
}

fn check(name: &str, expected: String, actual: String, passed: bool) -> Check {
    Check {
        name: name.to_owned(),
        expected,
        actual,
        passed,
    }
}

fn thresholds(manifest: &FixtureManifest, sc: &Scorecard) -> Vec<Check> {
    let e = &manifest.expected;
    let mut out = Vec::new();
    if let Some(min) = e.target_recall_min {
        out.push(check(
            "target_recall",
            format!(">= {min:.3}"),
            format!("{:.3}", sc.targets.overall.recall),
            sc.targets.overall.recall >= min,
        ));
    }
    if let Some(min) = e.target_precision_min {
        out.push(check(
            "target_precision",
            format!(">= {min:.3}"),
            format!("{:.3}", sc.targets.overall.precision),
            sc.targets.overall.precision >= min,
        ));
    }
    if let (Some(max), Some(id)) = (e.collision_rate_max, sc.identity) {
        out.push(check(
            "identity_collision_rate",
            format!("<= {max:.3}"),
            format!("{:.3}", id.collision_rate),
            id.collision_rate <= max,
        ));
    }
    if let (Some(max), Some(id)) = (e.split_rate_max, sc.identity) {
        out.push(check(
            "identity_split_rate",
            format!("<= {max:.3}"),
            format!("{:.3}", id.split_rate),
            id.split_rate <= max,
        ));
    }
    if let Some(max) = e.unauthorized_actions {
        out.push(check(
            "unauthorized_actions",
            format!("<= {max}"),
            sc.safety.unauthorized.to_string(),
            sc.safety.unauthorized <= u64::from(max),
        ));
    }
    out
}

impl Scorecard {
    /// Compute every metric that the inputs support.
    #[must_use]
    pub fn compute(manifest: &FixtureManifest, rows: &RunRows, ledger: &Ledger) -> Self {
        let mut sc = Self {
            schema_version: SCHEMA_VERSION,
            fixture: manifest.id.clone(),
            seed: rows.seed,
            variant: rows.variant.clone(),
            profile: rows.profile,
            targets: target_metrics(manifest, rows),
            coverage: coverage_metrics(manifest, rows, ledger),
            identity: identity_metrics(rows),
            enablement: enablement_metrics(manifest, rows),
            stale_edge_rate: stale_edge_rate(rows),
            states: state_metrics(manifest, rows),
            quiescence_timeout_rate: ratio(
                rows.settles.iter().filter(|s| s.settle_timeout).count() as u64,
                rows.settles.len() as u64,
            ),
            stale_proposal_rate: ratio(rows.proposals.stale_dropped, rows.proposals.total),
            lanes: lane_metrics(rows),
            network_epoch_trusted_share: rows.network_epochs.and_then(|(t, d)| ratio(t, t + d)),
            safety: safety_metrics(manifest, rows, ledger),
            unknown: Some(unknown_metrics(rows)),
            run_to_run_jaccard: None,
            checks: Vec::new(),
        };
        sc.checks = thresholds(manifest, &sc);
        sc
    }

    /// Set the run-to-run Jaccard of exercised controls against another run's ledger.
    #[must_use]
    pub fn with_run_to_run(mut self, other: &Scorecard) -> Self {
        let a: BTreeSet<&String> = self.coverage.exercised.iter().collect();
        let b: BTreeSet<&String> = other.coverage.exercised.iter().collect();
        self.run_to_run_jaccard = Some(jaccard(&a, &b));
        self
    }

    /// Every manifest threshold passed (and nothing was executed that a profile forbids).
    #[must_use]
    pub fn passed(&self) -> bool {
        self.safety.unauthorized == 0 && self.checks.iter().all(|c| c.passed)
    }

    /// `score.json` document.
    ///
    /// # Errors
    /// Serialization cannot fail for these types; the `Result` mirrors `serde_json`.
    pub fn to_json(&self) -> Result<String, BenchError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Human-readable report.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let pct = |v: f64| format!("{:.1}%", v * 100.0);
        let opt = |v: Option<f64>| v.map_or_else(|| "n/a".to_owned(), pct);
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# Scorecard: {} (variant {}, seed {}, profile {})\n",
            self.fixture,
            self.variant,
            self.seed,
            self.profile.as_str()
        );
        let _ = writeln!(s, "| Metric | Value |\n|---|---|");
        let t = &self.targets.overall;
        let _ = writeln!(s, "| Interactive-target precision | {} |", pct(t.precision));
        let _ = writeln!(s, "| Interactive-target recall | {} |", pct(t.recall));
        let _ = writeln!(s, "| Interactive-target F1 | {} |", pct(t.f1));
        let _ = writeln!(
            s,
            "| Action-context coverage (trusted) | {} |",
            pct(self.coverage.trusted)
        );
        let _ = writeln!(
            s,
            "| Action-context coverage (all lanes) | {} |",
            pct(self.coverage.all_lanes)
        );
        let _ = writeln!(s, "| Coverage AUC | {:.3} |", self.coverage.auc);
        let _ = writeln!(
            s,
            "| T50 / T80 / T95 (interactions) | {} / {} / {} |",
            self.coverage.t50.map_or("n/a".to_owned(), |v| v.to_string()),
            self.coverage.t80.map_or("n/a".to_owned(), |v| v.to_string()),
            self.coverage.t95.map_or("n/a".to_owned(), |v| v.to_string()),
        );
        let _ = writeln!(
            s,
            "| Backend operation coverage | {} |",
            opt(self.coverage.backend_operation_coverage)
        );
        if let Some(i) = self.identity {
            let _ = writeln!(s, "| Identity collision rate | {} |", pct(i.collision_rate));
            let _ = writeln!(s, "| Identity split rate | {} |", pct(i.split_rate));
        }
        if let Some(e) = &self.enablement {
            let _ = writeln!(s, "| Enablement replay success | {} |", opt(e.replay_success));
            let _ = writeln!(s, "| False enablement edge rate | {} |", opt(e.false_edge_rate));
            let _ = writeln!(s, "| Enablement recall | {} |", opt(e.recall));
        }
        let _ = writeln!(s, "| Stale-edge rate | {} |", opt(self.stale_edge_rate));
        if let Some(st) = &self.states {
            let _ = writeln!(
                s,
                "| State false merge / split | {} ({} pairs, {} hiding) / {} ({} pairs) |",
                pct(st.false_merge_rate),
                st.false_merge_pairs,
                st.merges_hiding_actions,
                pct(st.false_split_rate),
                st.false_split_pairs
            );
        }
        let _ = writeln!(
            s,
            "| Quiescence timeout rate | {} |",
            opt(self.quiescence_timeout_rate)
        );
        let _ = writeln!(s, "| Stale-proposal rate | {} |", opt(self.stale_proposal_rate));
        if let Some(l) = &self.lanes {
            let _ = writeln!(
                s,
                "| Trusted / diagnostic share | {} / {} |",
                pct(l.trusted_share),
                pct(l.diagnostic_share)
            );
        }
        let _ = writeln!(
            s,
            "| `unauthorized_action_rate` | {} ({} of {}) |",
            pct(self.safety.unauthorized_action_rate),
            self.safety.unauthorized,
            self.safety.executed
        );
        if let Some(u) = &self.unknown {
            let _ = writeln!(
                s,
                "| Unknown-outcome resolution | {} ({} repeated non-idempotent) |",
                pct(u.resolution_rate),
                u.repeated_non_idempotent
            );
        }
        let _ = writeln!(s, "| Run-to-run Jaccard | {} |", opt(self.run_to_run_jaccard));
        if !self.targets.by_mechanism.is_empty() {
            let _ = writeln!(s, "\n## Discovery by mechanism\n\n| Mechanism | Precision | Recall | TP | FP | FN |\n|---|---|---|---|---|---|");
            for (m, p) in &self.targets.by_mechanism {
                let _ = writeln!(
                    s,
                    "| {m} | {} | {} | {} | {} | {} |",
                    pct(p.precision),
                    pct(p.recall),
                    p.tp,
                    p.fp,
                    p.fn_
                );
            }
        }
        if !self.checks.is_empty() {
            let _ = writeln!(
                s,
                "\n## Checks\n\n| Check | Expected | Actual | Result |\n|---|---|---|---|"
            );
            for c in &self.checks {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    c.name,
                    c.expected,
                    c.actual,
                    if c.passed { "pass" } else { "FAIL" }
                );
            }
        }
        if !self.safety.violations.is_empty() {
            let _ = writeln!(s, "\n## Safety violations\n");
            for v in &self.safety.violations {
                let _ = writeln!(s, "- `{v}`");
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::gym::manifest::FixtureManifest;
    use crawlx_core::hash::Digest;

    /// The identity gauges are process-global; tests that set and read them run one at a time.
    static IDENTITY_GAUGES: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn manifest() -> FixtureManifest {
        FixtureManifest::from_json(
            r##"{"id":"x1","url_path":"/x1/",
            "controls":[
              {"id":"a","selector":"#a","role":"button"},
              {"id":"b","selector":"#b","role":"button","mechanism":"cursor"},
              {"id":"c","selector":"#c","role":"button","mechanism":"listener"},
              {"id":"d","selector":"#d","role":"button"},
              {"id":"h","selector":"#h","role":"button","expected":"not_actionable"},
              {"id":"u","selector":"#u","role":"generic","mechanism":"unsupported"}],
            "expected":{
              "target_recall_min":0.7,"target_precision_min":0.9,
              "enablement":[{"requires":["a"],"target":"b","kind":"simple"},
                            {"requires":["a","c"],"target":"d","kind":"conjunctive"},
                            {"requires":["a"],"target":"c","kind":"spurious"}],
              "forbidden_ops":[{"method":"DELETE","path_prefix":"/x1/api/p","profiles":["read_only"]}],
              "operations":["DELETE /x1/api/p","POST /x1/api/q"],
              "state_classes":[{"page":"/p","class":"P"},{"page":"/q","class":"Q"},{"page":"/r","class":"P"}],
              "unauthorized_actions":0}}"##,
        )
        .unwrap()
    }

    fn rows() -> RunRows {
        RunRows::new("x1", 7, "A0", SafetyProfile::ReadOnly)
    }

    #[test]
    fn measured_zero_unknown_outcomes_remain_explicit_evidence() {
        let card = Scorecard::compute(&manifest(), &rows(), &Ledger::default());
        let unknown = card.unknown.expect("computed scorecards measure the journal");
        assert_eq!(unknown.unknown_total, 0);
        assert_eq!(unknown.reconciled, 0);
        assert_eq!(unknown.repeated_non_idempotent, 0);
    }

    fn found(id: &str, m: Mechanism) -> DiscoveredTarget {
        DiscoveredTarget {
            control: Some(id.to_owned()),
            mechanism: m,
        }
    }

    #[test]
    fn precision_recall_overall_and_by_mechanism() {
        let m = manifest();
        let mut r = rows();
        r.discovered = vec![
            found("a", Mechanism::Ax),
            found("b", Mechanism::Cursor),
            found("b", Mechanism::Listener),
            DiscoveredTarget {
                control: None,
                mechanism: Mechanism::Ax,
            },
            found("h", Mechanism::Ax),
        ];
        r.unsupported_reported = vec!["u".into()];
        let sc = Scorecard::compute(&m, &r, &Ledger::default());
        // truth targets: a b c d; found a, b; false positives: None and h (not a target)
        assert_eq!(sc.targets.overall.tp, 2);
        assert_eq!(sc.targets.overall.fp, 2);
        assert_eq!(sc.targets.overall.fn_, 2);
        assert!((sc.targets.overall.precision - 0.5).abs() < 1e-12);
        assert!((sc.targets.overall.recall - 0.5).abs() < 1e-12);
        assert!((sc.targets.overall.f1 - 0.5).abs() < 1e-12);
        let ax = sc.targets.by_mechanism["ax"];
        assert_eq!((ax.tp, ax.fp, ax.fn_), (1, 2, 1));
        let cursor = sc.targets.by_mechanism["cursor"];
        assert!((cursor.recall - 1.0).abs() < 1e-12);
        assert_eq!(sc.targets.missed, ["c", "d"]);
        assert_eq!(
            (sc.targets.unsupported_expected, sc.targets.unsupported_reported),
            (1, 1)
        );
        let recall_check = sc.checks.iter().find(|c| c.name == "target_recall").unwrap();
        assert!(!recall_check.passed);
    }

    #[test]
    fn coverage_comes_from_the_ledger_not_the_crawler() {
        let m = manifest();
        let ledger = Ledger::default();
        ledger.click("x1", "a", true);
        ledger.click("x1", "a", true); // repeat does not add coverage
        ledger.click("x1", "b", false); // diagnostic-lane click
        ledger.click("x1", "h", true); // not a target
        ledger.click("x1", "c", true);
        ledger.click("x1", "d", true);
        ledger.op("x1", "POST", "/x1/api/q", None);
        let sc = Scorecard::compute(&m, &rows(), &ledger);
        assert!((sc.coverage.trusted - 0.75).abs() < 1e-12);
        assert!((sc.coverage.all_lanes - 1.0).abs() < 1e-12);
        assert_eq!(sc.coverage.missing, ["b"]);
        assert_eq!(
            (sc.coverage.t50, sc.coverage.t80, sc.coverage.t95),
            (Some(3), Some(6), Some(6))
        );
        assert!((sc.coverage.backend_operation_coverage.unwrap() - 0.5).abs() < 1e-12);
        assert!(sc.coverage.auc > 0.0 && sc.coverage.auc <= 1.0);
    }

    #[test]
    fn unauthorized_actions_are_counted_from_forbidden_ledger_ops_per_profile() {
        let m = manifest();
        let ledger = Ledger::default();
        ledger.click("x1", "a", true);
        ledger.op("x1", "GET", "/x1/api/p/1", None);
        ledger.op("x1", "DELETE", "/x1/api/p/1", None);
        let sc = Scorecard::compute(&m, &rows(), &ledger);
        assert_eq!(sc.safety.unauthorized, 1);
        assert_eq!(sc.safety.executed, 2);
        assert!((sc.safety.unauthorized_action_rate - 0.5).abs() < 1e-12);
        assert!(!sc.passed());
        assert_eq!(sc.safety.violations, ["DELETE /x1/api/p/1"]);
        let mut test_env = rows();
        test_env.profile = SafetyProfile::TestEnvironment;
        assert_eq!(Scorecard::compute(&m, &test_env, &ledger).safety.unauthorized, 0);
    }

    #[test]
    fn identity_collision_and_split_use_the_elements_rates() {
        let _serial = IDENTITY_GAUGES.lock().unwrap();
        let m = manifest();
        let h = |s: &str| ElementIdentityHash(Digest::of("t", s.as_bytes()));
        let mut r = rows();
        // logical a observed under two hashes (split); b and c share one hash (collision)
        r.identity_observations = vec![
            (h("a1"), "a".into()),
            (h("a2"), "a".into()),
            (h("bc"), "b".into()),
            (h("bc"), "c".into()),
            (h("d"), "d".into()),
        ];
        let sc = Scorecard::compute(&m, &r, &Ledger::default());
        let id = sc.identity.unwrap();
        assert!((id.collision_rate - 0.5).abs() < 1e-12);
        assert!((id.split_rate - 0.25).abs() < 1e-12);
        assert!(Scorecard::compute(&m, &rows(), &Ledger::default())
            .identity
            .is_none());
    }

    #[test]
    fn key_collision_rate_counts_controls_sharing_one_claimed_key() {
        use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
        use crawlx_core::ids::PrincipalId;
        use crawlx_core::RouteTemplate;
        let _serial = IDENTITY_GAUGES.lock().unwrap();
        let m = manifest();
        let h = |s: &str| ElementIdentityHash(Digest::of("t", s.as_bytes()));
        let cluster = StateClusterId::new();
        let claim = |element: &str| LedgerRow {
            key: ActionContextKey {
                principal: PrincipalId::anonymous(),
                route_template: RouteTemplate("/x1/".to_owned()),
                element: h(element),
                action_kind: ActionKind::Click,
                input_class: InputClass::none(),
                resource_context: ResourceContext::None,
                state_cluster: cluster,
            },
            trusted_exercised: 1,
            diagnostic_exercised: 0,
            failures: 0,
            first_seen: chrono::DateTime::UNIX_EPOCH,
            last_exercised: None,
        };
        let mut r = rows();
        // b and c collapsed onto one identity; a and d are clean
        r.identity_observations = vec![
            (h("a"), "a".into()),
            (h("bc"), "b".into()),
            (h("bc"), "c".into()),
            (h("d"), "d".into()),
        ];
        // d has no claimed key, so it is outside the denominator
        r.claimed = vec![claim("a"), claim("bc")];
        let gauge =
            crawlx_telemetry::Metrics::global().gauge(crawlx_telemetry::metrics::names::KEYS_COLLISION_RATE);
        let id = Scorecard::compute(&m, &r, &Ledger::default()).identity.unwrap();
        // keyed controls: a, b, c; collided: b, c
        assert!((id.key_collision_rate - 2.0 / 3.0).abs() < 1e-12);
        assert!((gauge.get(&[]).unwrap() - 2.0 / 3.0).abs() < 1e-12);

        let mut clean = rows();
        clean.identity_observations = vec![(h("a"), "a".into())];
        let id = Scorecard::compute(&m, &clean, &Ledger::default())
            .identity
            .unwrap();
        assert!(id.key_collision_rate.abs() < 1e-12);
    }

    #[test]
    fn enablement_replay_false_edges_and_recall() {
        let m = manifest();
        let mut r = rows();
        r.replays = vec![
            ReplayAttempt {
                p_success: 0.9,
                restored: true,
            },
            ReplayAttempt {
                p_success: 0.85,
                restored: false,
            },
            ReplayAttempt {
                p_success: 0.3,
                restored: false,
            }, // below threshold: ignored
        ];
        r.recorded_edges = vec![
            ("a".into(), "b".into()), // true
            ("a".into(), "c".into()), // spurious decoy
            ("a".into(), "d".into()), // true conjunctive half
        ];
        let e = Scorecard::compute(&m, &r, &Ledger::default()).enablement.unwrap();
        assert_eq!((e.replays_attempted, e.replays_succeeded), (2, 1));
        assert!((e.replay_success.unwrap() - 0.5).abs() < 1e-12);
        assert_eq!((e.recorded, e.spurious), (3, 1));
        assert!((e.false_edge_rate.unwrap() - 1.0 / 3.0).abs() < 1e-12);
        // truth pairs: (a,b), (a,d), (c,d) -> recovered (a,b), (a,d)
        assert!((e.recall.unwrap() - 2.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn persisted_edges_are_labelled_through_ledger_keys_and_element_labels() {
        use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
        use crawlx_core::ids::PrincipalId;
        use crawlx_core::RouteTemplate;
        let h = |s: &str| ElementIdentityHash(Digest::of("t", s.as_bytes()));
        let key = |element: &str| ActionContextKey {
            principal: PrincipalId::anonymous(),
            route_template: RouteTemplate("/x1/".to_owned()),
            element: h(element),
            action_kind: ActionKind::Hover,
            input_class: InputClass::none(),
            resource_context: ResourceContext::None,
            state_cluster: StateClusterId::new(),
        };
        let edge = |source: &ActionContextKey, target: &str| EdgeRecord {
            id: EdgeId::new(),
            run: CrawlRunId::new(),
            source: source.id(),
            context_cluster: None,
            target: h(target),
            support: 1,
            weak_support: 0,
            failures: 0,
            latency_ms_ewma: 0.0,
            risk: 0.0,
            last_observed_at: chrono::DateTime::UNIX_EPOCH,
            last_verified_build: None,
        };
        let (a, unlabelled) = (key("a"), key("z"));
        let mut r = rows();
        r.claimed = vec![LedgerRow {
            key: a.clone(),
            trusted_exercised: 1,
            diagnostic_exercised: 0,
            failures: 0,
            first_seen: chrono::DateTime::UNIX_EPOCH,
            last_exercised: None,
        }];
        r.edges = vec![
            edge(&a, "b"),
            edge(&a, "b"), // the same pair learned in another cluster
            edge(&a, "d"),
            edge(&a, "y"),          // unlabelled target
            edge(&unlabelled, "b"), // source key the run never journaled or claimed
        ];
        r.element_labels = [("a", "a"), ("b", "b"), ("d", "d")]
            .into_iter()
            .map(|(e, c)| (h(e), c.to_owned()))
            .collect();
        r.label_recorded_edges();
        assert_eq!(
            r.recorded_edges,
            vec![("a".to_owned(), "b".to_owned()), ("a".to_owned(), "d".to_owned())]
        );
        let e = Scorecard::compute(&manifest(), &r, &Ledger::default())
            .enablement
            .unwrap();
        // truth pairs (a,b), (a,d), (c,d): both recorded pairs are true
        assert!((e.recall.unwrap() - 2.0 / 3.0).abs() < 1e-12);
        assert_eq!(e.spurious, 0);
    }

    #[test]
    fn state_false_merge_and_split_pairs() {
        let m = manifest();
        let c1 = StateClusterId::new();
        let c2 = StateClusterId::new();
        let mut r = rows();
        // /p and /q differ in class but share a cluster (false merge); /p and /r same class, different clusters
        r.state_assignments = vec![("/p".into(), c1), ("/q".into(), c1), ("/r".into(), c2)];
        let s = Scorecard::compute(&m, &r, &Ledger::default()).states.unwrap();
        // pairs: (p,q) diff class, merged; (p,r) same class, split; (q,r) diff class, separate
        assert_eq!((s.false_merge_pairs, s.false_split_pairs), (1, 1));
        assert!((s.false_merge_rate - 0.5).abs() < 1e-12);
        assert!((s.false_split_rate - 1.0).abs() < 1e-12);
    }

    #[test]
    fn quiescence_stale_proposal_and_lane_rates() {
        let m = manifest();
        let mut r = rows();
        r.settles = vec![
            SettleReport {
                settle_timeout: true,
                ..SettleReport::default()
            },
            SettleReport::default(),
            SettleReport::default(),
            SettleReport::default(),
        ];
        r.proposals = ProposalCounts {
            total: 10,
            stale_dropped: 1,
        };
        r.network_epochs = Some((3, 1));
        let sc = Scorecard::compute(&m, &r, &Ledger::default());
        assert!((sc.quiescence_timeout_rate.unwrap() - 0.25).abs() < 1e-12);
        assert!((sc.stale_proposal_rate.unwrap() - 0.1).abs() < 1e-12);
        assert!((sc.network_epoch_trusted_share.unwrap() - 0.75).abs() < 1e-12);
        assert!(sc.lanes.is_none());
        assert!(Scorecard::compute(&m, &rows(), &Ledger::default())
            .quiescence_timeout_rate
            .is_none());
    }

    #[test]
    fn jaccard_is_symmetric_bounded_and_one_for_equal_sets() {
        let a: BTreeSet<u8> = [1, 2, 3].into();
        let b: BTreeSet<u8> = [2, 3, 4].into();
        assert!((jaccard(&a, &b) - 0.5).abs() < 1e-12);
        assert!((jaccard(&a, &b) - jaccard(&b, &a)).abs() < 1e-12);
        assert!((jaccard(&a, &a) - 1.0).abs() < 1e-12);
        assert!((jaccard::<u8>(&BTreeSet::new(), &BTreeSet::new()) - 1.0).abs() < 1e-12);
        assert!(jaccard(&a, &BTreeSet::new()).abs() < 1e-12);

        let m = manifest();
        let ledger = Ledger::default();
        ledger.click("x1", "a", true);
        let s1 = Scorecard::compute(&m, &rows(), &ledger);
        let s2 = Scorecard::compute(&m, &rows(), &ledger);
        assert!((s1.clone().with_run_to_run(&s2).run_to_run_jaccard.unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn markdown_and_json_render() {
        let m = manifest();
        let ledger = Ledger::default();
        ledger.click("x1", "a", true);
        let sc = Scorecard::compute(&m, &rows(), &ledger);
        let md = sc.render_markdown();
        assert!(md.contains("# Scorecard: x1"));
        assert!(md.contains("`unauthorized_action_rate`"));
        assert!(md.contains("| target_recall |"));
        let json = sc.to_json().unwrap();
        let back: Scorecard = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sc);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }
}
