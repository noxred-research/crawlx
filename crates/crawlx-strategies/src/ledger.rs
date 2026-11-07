//! The action-context coverage ledger.
//!
//! [`InMemoryLedger`] is the in-memory view over `action_contexts`. Only
//! `trusted_ui` executions count toward coverage claims; diagnostic-lane
//! executions are counted separately and never make a key "exercised". The
//! ledger is rebuildable from `LedgerRow`s, so it cannot claim an action the
//! journal does not show.
//!
//! Under `targetIsolation = per_role_replica` every role
//! acts on its own application instance, so a key whose `resource_context` refers to
//! another principal's resources (`other_user_same_role`, `higher_role`, `shared`)
//! can never be observed by this run. Such keys are [`CoverageStatus::NotObservable`]:
//! they stay in the denominator but are neither "uncovered" nor frontier work.

use crawlx_core::config::TargetIsolation;
pub use crawlx_core::identity::CoverageStatus;
use crawlx_core::repo::LedgerRow;
use crawlx_core::{
    ActionContextId, ActionContextKey, ActionKind, PrincipalId, RouteTemplate, StateClusterId, Timestamp,
    TrustLane,
};
use crawlx_state::OutcomeClass;
use serde::Serialize;
use std::collections::BTreeMap;

/// EWMA smoothing for the cold-start gain and latency estimates.
const EWMA_ALPHA: f32 = 0.2;
/// Prior for "new keys per exercised key" before any evidence.
const COLD_START_PRIOR: f32 = 1.0;
/// Planning bound for fine-grained contexts of one principal, element and action kind.
pub const MAX_CONTEXTS_PER_ELEMENT: u32 = 64;

/// Read access the strategies and the arbiter need. `Send + Sync` so a frozen
/// `DecisionContext` can be shared by concurrently running strategies.
pub trait LedgerView: Send + Sync {
    /// `2^(−n)` for `n` trusted attempts of exactly this key; `1.0` when never exercised.
    fn novelty(&self, key: &ActionContextKey) -> f32;
    /// Apply the ledger's route-level state coarsening to a new coverage key.
    fn normalize_key(&self, _key: &mut ActionContextKey) {}
    /// Cold-start share of `expected_coverage_gain`: `1 − exp(−0.5·ĝ)` with
    /// `ĝ` the EWMA of new keys per exercised key in the same
    /// `(principal, action_kind)` family. The graph-derived part is added by
    /// [`crate::utility`].
    fn expected_gain(&self, key: &ActionContextKey) -> f32;
    /// Trusted-lane executions of the key.
    fn trusted_attempts(&self, key: &ActionContextKey) -> u32;
    /// Diagnostic-lane executions of the key.
    fn diagnostic_attempts(&self, key: &ActionContextKey) -> u32;
    /// Failed executions in either lane; failures never count as trusted coverage.
    fn failed_attempts(&self, key: &ActionContextKey) -> u32;
    /// Known keys of `cluster` that no trusted execution has exercised.
    fn unexercised_in_cluster(&self, cluster: StateClusterId) -> u32;
    /// Known keys anywhere that no trusted execution has exercised.
    fn unexercised_total(&self) -> u32;
    /// Clusters with unexercised keys, in cluster-id order.
    fn unexercised_by_cluster(&self) -> Vec<(StateClusterId, u32)>;
    /// Smoothed latency of actions of `kind`, if any was observed.
    fn latency_ms(&self, kind: ActionKind) -> Option<u32>;
}

/// Per-route share of the coverage summary.
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Debug)]
pub struct RouteCoverage {
    /// Known keys of the route (the denominator).
    pub keys_total: u32,
    /// Keys of the route with at least one `trusted_ui` execution.
    pub keys_exercised_trusted: u32,
    /// Keys of the route exercised only in the diagnostic lane; never counted as covered.
    pub keys_diagnostic_only: u32,
    /// Keys of the route this run cannot observe (`per_role_replica`).
    pub keys_not_observable: u32,
    /// Keys explicitly coarsened to route-level state.
    pub keys_coarsened: u32,
}

impl RouteCoverage {
    /// Keys that are known, observable and never exercised.
    #[must_use]
    pub const fn keys_uncovered(&self) -> u32 {
        self.keys_total
            .saturating_sub(self.keys_exercised_trusted)
            .saturating_sub(self.keys_diagnostic_only)
            .saturating_sub(self.keys_not_observable)
    }
}

/// Coverage claim for one principal (or all principals).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Debug)]
pub struct CoverageSummary {
    /// Known keys (the denominator).
    pub keys_total: u32,
    /// Keys with at least one `trusted_ui` execution (the only coverage claim).
    pub keys_exercised_trusted: u32,
    /// Keys exercised only in the diagnostic lane; never counted as covered.
    pub keys_diagnostic_only: u32,
    /// Keys this run cannot observe (`per_role_replica`); never "uncovered".
    pub keys_not_observable: u32,
    /// Keys explicitly coarsened to route-level state.
    pub keys_coarsened: u32,
    /// Per-route breakdown of the counters above.
    pub per_route: BTreeMap<RouteTemplate, RouteCoverage>,
}

impl CoverageSummary {
    /// Keys that are known, observable and never exercised.
    #[must_use]
    pub const fn keys_uncovered(&self) -> u32 {
        self.keys_total
            .saturating_sub(self.keys_exercised_trusted)
            .saturating_sub(self.keys_diagnostic_only)
            .saturating_sub(self.keys_not_observable)
    }
}

#[derive(Clone, Debug)]
struct Entry {
    key: ActionContextKey,
    trusted: u32,
    diagnostic: u32,
    failures: u32,
    first_seen: Timestamp,
    last_exercised: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug)]
struct FamilyStat {
    new_keys_ewma: f32,
}

/// Ledger over `BTreeMap`s: every iteration is deterministic.
#[derive(Clone, Debug)]
pub struct InMemoryLedger {
    entries: BTreeMap<ActionContextId, Entry>,
    now: Timestamp,
    registered: u64,
    registered_at_last_exercise: u64,
    families: BTreeMap<(PrincipalId, ActionKind), FamilyStat>,
    latency: BTreeMap<ActionKind, f32>,
    /// Observable keys without a trusted execution, per cluster.
    unexercised: BTreeMap<StateClusterId, u32>,
    isolation: TargetIsolation,
    context_counts: BTreeMap<PrincipalId, BTreeMap<(crawlx_core::ElementIdentityHash, ActionKind), u32>>,
    coarsened: u32,
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryLedger {
    /// Create an empty ledger for a shared target (every context observable).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            now: Timestamp::default(),
            registered: 0,
            registered_at_last_exercise: 0,
            families: BTreeMap::new(),
            latency: BTreeMap::new(),
            unexercised: BTreeMap::new(),
            isolation: TargetIsolation::Shared,
            context_counts: BTreeMap::new(),
            coarsened: 0,
        }
    }

    /// Set the run's `targetIsolation`; under `per_role_replica` cross-principal keys become
    /// [`CoverageStatus::NotObservable`] and leave the unexercised index.
    #[must_use]
    pub fn with_isolation(mut self, isolation: TargetIsolation) -> Self {
        if self.isolation != isolation {
            self.isolation = isolation;
            self.unexercised.clear();
            for e in self.entries.values() {
                if e.trusted == 0 && Self::observable_under(isolation, &e.key) {
                    *self.unexercised.entry(e.key.state_cluster).or_default() += 1;
                }
            }
        }
        self
    }

    /// The `targetIsolation` the ledger classifies keys under.
    #[must_use]
    pub const fn isolation(&self) -> TargetIsolation {
        self.isolation
    }

    const fn observable_under(isolation: TargetIsolation, key: &ActionContextKey) -> bool {
        key.is_observable(isolation)
    }

    /// Can this run observe `key`? `false` only for cross-principal contexts under
    /// `per_role_replica`.
    #[must_use]
    pub const fn is_observable(&self, key: &ActionContextKey) -> bool {
        Self::observable_under(self.isolation, key)
    }

    /// Coverage status of `key`; `None` when the key is not known.
    #[must_use]
    pub fn status(&self, key: &ActionContextKey) -> Option<CoverageStatus> {
        self.entries.get(&key.id()).map(|e| self.status_of(e))
    }

    fn status_of(&self, e: &Entry) -> CoverageStatus {
        CoverageStatus::classify(&e.key, self.isolation, e.trusted, e.diagnostic)
    }

    /// Rebuild from persisted `action_contexts` rows.
    #[must_use]
    pub fn from_rows(rows: impl IntoIterator<Item = LedgerRow>) -> Self {
        let mut l = Self::new();
        for r in rows {
            let id = r.key.id();
            let exercised = r.trusted_exercised > 0;
            let cluster = r.key.state_cluster;
            if r.first_seen > l.now {
                l.now = r.first_seen;
            }
            if let Some(t) = r.last_exercised {
                if t > l.now {
                    l.now = t;
                }
            }
            let entry = Entry {
                key: r.key,
                trusted: r.trusted_exercised,
                diagnostic: r.diagnostic_exercised,
                failures: r.failures,
                first_seen: r.first_seen,
                last_exercised: r.last_exercised,
            };
            if l.entries.insert(id, entry).is_none() {
                let key = &l.entries[&id].key;
                *l.context_counts
                    .entry(key.principal.clone())
                    .or_default()
                    .entry((key.element, key.action_kind))
                    .or_default() += 1;
                l.coarsened += u32::from(key.is_coarsened());
                l.registered += 1;
                if !exercised {
                    *l.unexercised.entry(cluster).or_default() += 1;
                }
            }
        }
        l.registered_at_last_exercise = l.registered;
        l
    }

    /// Clock used for `first_seen` / `last_exercised` of later records.
    pub fn advance(&mut self, now: Timestamp) {
        if now > self.now {
            self.now = now;
        }
    }

    /// Declare a key as known (a visible, actionable candidate). Returns
    /// `true` when the key is new. Registration is what makes the coverage
    /// denominator exact.
    pub fn register(&mut self, key: &ActionContextKey) -> bool {
        let id = key.id();
        if self.entries.contains_key(&id) {
            return false;
        }
        *self
            .context_counts
            .entry(key.principal.clone())
            .or_default()
            .entry((key.element, key.action_kind))
            .or_default() += 1;
        self.coarsened += u32::from(key.is_coarsened());
        self.entries.insert(
            id,
            Entry {
                key: key.clone(),
                trusted: 0,
                diagnostic: 0,
                failures: 0,
                first_seen: self.now,
                last_exercised: None,
            },
        );
        self.registered += 1;
        if self.is_observable(key) {
            *self.unexercised.entry(key.state_cluster).or_default() += 1;
        }
        true
    }

    /// Number of explicitly route-coarsened keys, including restored rows.
    #[must_use]
    pub const fn coarsened_total(&self) -> u32 {
        self.coarsened
    }

    /// Record one execution. `lane = trusted_ui` counts toward coverage; any
    /// other lane goes to the diagnostic counter. A 4xx/5xx main operation
    /// counts as a failure. Returns `true` when this execution first exercised
    /// the key in the trusted lane.
    pub fn record(&mut self, key: &ActionContextKey, outcome: &OutcomeClass, lane: TrustLane) -> bool {
        self.record_inner(key, lane, outcome.status_class >= 4)
    }

    /// Record an execution the browser rejected (no outcome class exists).
    pub fn record_failure(&mut self, key: &ActionContextKey, _lane: TrustLane) -> bool {
        self.register(key);
        if let Some(entry) = self.entries.get_mut(&key.id()) {
            entry.failures = entry.failures.saturating_add(1);
            entry.last_exercised = Some(self.now);
        }
        false
    }

    fn record_inner(&mut self, key: &ActionContextKey, lane: TrustLane, failed: bool) -> bool {
        self.register(key);
        let id = key.id();
        let now = self.now;
        let mut first_trusted = false;
        if let Some(e) = self.entries.get_mut(&id) {
            match lane {
                TrustLane::TrustedUi => {
                    first_trusted = e.trusted == 0;
                    e.trusted = e.trusted.saturating_add(1);
                }
                TrustLane::Diagnostic => e.diagnostic = e.diagnostic.saturating_add(1),
            }
            if failed {
                e.failures = e.failures.saturating_add(1);
            }
            e.last_exercised = Some(now);
        }
        if lane == TrustLane::TrustedUi {
            if first_trusted && self.is_observable(key) {
                if let Some(n) = self.unexercised.get_mut(&key.state_cluster) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.unexercised.remove(&key.state_cluster);
                    }
                }
            }
            let new_keys = (self.registered - self.registered_at_last_exercise) as f32;
            self.registered_at_last_exercise = self.registered;
            let fam = self
                .families
                .entry((key.principal.clone(), key.action_kind))
                .or_insert(FamilyStat {
                    new_keys_ewma: COLD_START_PRIOR,
                });
            fam.new_keys_ewma = (1.0 - EWMA_ALPHA) * fam.new_keys_ewma + EWMA_ALPHA * new_keys;
        }
        first_trusted
    }

    /// Fold a latency sample for `kind` into its EWMA.
    pub fn record_latency(&mut self, kind: ActionKind, ms: u32) {
        let sample = ms as f32;
        let e = self.latency.entry(kind).or_insert(sample);
        *e = (1.0 - EWMA_ALPHA) * *e + EWMA_ALPHA * sample;
    }

    /// Is the key id known, observable and not yet exercised by a trusted execution?
    #[must_use]
    pub fn unexercised_id(&self, id: ActionContextId) -> bool {
        self.entries
            .get(&id)
            .is_some_and(|e| e.trusted == 0 && self.is_observable(&e.key))
    }

    /// Is the key known?
    #[must_use]
    pub fn contains(&self, key: &ActionContextKey) -> bool {
        self.entries.contains_key(&key.id())
    }

    /// Number of known keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no key is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Coverage claim for `principal` (all principals when `None`). Only
    /// trusted executions are counted as covered; cross-principal keys under
    /// `per_role_replica` are counted as `not_observable`, never as uncovered.
    #[must_use]
    pub fn coverage(&self, principal: Option<&PrincipalId>) -> CoverageSummary {
        let mut out = CoverageSummary::default();
        for e in self.entries.values() {
            if principal.is_some_and(|p| *p != e.key.principal) {
                continue;
            }
            let route = out.per_route.entry(e.key.route_template.clone()).or_default();
            out.keys_total += 1;
            route.keys_total += 1;
            if e.key.is_coarsened() {
                out.keys_coarsened += 1;
                route.keys_coarsened += 1;
            }
            match self.status_of(e) {
                CoverageStatus::Exercised => {
                    out.keys_exercised_trusted += 1;
                    route.keys_exercised_trusted += 1;
                }
                CoverageStatus::DiagnosticOnly => {
                    out.keys_diagnostic_only += 1;
                    route.keys_diagnostic_only += 1;
                }
                CoverageStatus::NotObservable => {
                    out.keys_not_observable += 1;
                    route.keys_not_observable += 1;
                }
                CoverageStatus::Uncovered => {}
                _ => {}
            }
        }
        out
    }

    /// Every known key with its coverage status, in key-id order.
    pub fn statuses(&self) -> impl Iterator<Item = (&ActionContextKey, CoverageStatus)> {
        self.entries.values().map(|e| (&e.key, self.status_of(e)))
    }

    /// Rows for `LedgerRepo::upsert`, in key-id order.
    #[must_use]
    pub fn rows(&self) -> Vec<LedgerRow> {
        self.entries
            .values()
            .map(|e| LedgerRow {
                key: e.key.clone(),
                trusted_exercised: e.trusted,
                diagnostic_exercised: e.diagnostic,
                failures: e.failures,
                first_seen: e.first_seen,
                last_exercised: e.last_exercised,
            })
            .collect()
    }

    /// Every known key with its trusted-attempt count, in key-id order.
    pub fn keys(&self) -> impl Iterator<Item = (&ActionContextKey, u32)> {
        self.entries.values().map(|e| (&e.key, e.trusted))
    }

    /// Re-key every entry of `from` after a cluster split: `successor` names the
    /// cluster an entry moves to, exactly what the store did to `action_contexts`. Counters
    /// are conserved: an entry that lands on an id the ledger already holds is merged into
    /// it. Returns `(old id, new id)` for every moved entry, in old-id order.
    pub fn rekey_cluster(
        &mut self,
        from: StateClusterId,
        successor: impl Fn(&ActionContextKey) -> StateClusterId,
    ) -> Vec<(ActionContextId, ActionContextId)> {
        let old_ids: Vec<ActionContextId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.key.state_cluster == from)
            .map(|(id, _)| *id)
            .collect();
        let mut moved = Vec::with_capacity(old_ids.len());
        for old in old_ids {
            let Some(mut entry) = self.entries.remove(&old) else {
                continue;
            };
            let unexercised = entry.trusted == 0 && self.is_observable(&entry.key);
            if unexercised {
                if let Some(n) = self.unexercised.get_mut(&from) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        self.unexercised.remove(&from);
                    }
                }
            }
            entry.key.state_cluster = successor(&entry.key);
            let to = entry.key.state_cluster;
            let new = entry.key.id();
            let observable = self.is_observable(&entry.key);
            match self.entries.get_mut(&new) {
                Some(existing) => {
                    let was_unexercised = existing.trusted == 0 && observable;
                    existing.trusted = existing.trusted.saturating_add(entry.trusted);
                    existing.diagnostic = existing.diagnostic.saturating_add(entry.diagnostic);
                    existing.failures = existing.failures.saturating_add(entry.failures);
                    existing.first_seen = existing.first_seen.min(entry.first_seen);
                    existing.last_exercised = existing.last_exercised.max(entry.last_exercised);
                    let now_exercised = existing.trusted > 0;
                    if was_unexercised && now_exercised {
                        if let Some(n) = self.unexercised.get_mut(&to) {
                            *n = n.saturating_sub(1);
                            if *n == 0 {
                                self.unexercised.remove(&to);
                            }
                        }
                    }
                    self.registered = self.registered.saturating_sub(1);
                    self.registered_at_last_exercise = self.registered_at_last_exercise.min(self.registered);
                }
                None => {
                    if unexercised {
                        *self.unexercised.entry(to).or_default() += 1;
                    }
                    self.entries.insert(new, entry);
                }
            }
            moved.push((old, new));
        }
        moved
    }
}

impl LedgerView for InMemoryLedger {
    fn normalize_key(&self, key: &mut ActionContextKey) {
        // Existing fine-grained keys never change identity or inherit another state's evidence.
        // Only new keys after the 64-context planning default lose the state dimension.
        if !self.entries.contains_key(&key.id())
            && self
                .context_counts
                .get(&key.principal)
                .and_then(|counts| counts.get(&(key.element, key.action_kind)))
                .is_some_and(|count| *count >= MAX_CONTEXTS_PER_ELEMENT)
        {
            key.state_cluster = key.coarsened_cluster();
        }
    }

    fn novelty(&self, key: &ActionContextKey) -> f32 {
        let n = self.trusted_attempts(key);
        // 2^(-n); saturates to 0 long before u32 matters
        0.5_f32.powi(i32::try_from(n.min(64)).unwrap_or(64))
    }

    fn expected_gain(&self, key: &ActionContextKey) -> f32 {
        let g = self
            .families
            .get(&(key.principal.clone(), key.action_kind))
            .map_or(COLD_START_PRIOR, |f| f.new_keys_ewma);
        1.0 - (-0.5 * g).exp()
    }

    fn trusted_attempts(&self, key: &ActionContextKey) -> u32 {
        self.entries.get(&key.id()).map_or(0, |e| e.trusted)
    }

    fn diagnostic_attempts(&self, key: &ActionContextKey) -> u32 {
        self.entries.get(&key.id()).map_or(0, |e| e.diagnostic)
    }

    fn failed_attempts(&self, key: &ActionContextKey) -> u32 {
        self.entries.get(&key.id()).map_or(0, |e| e.failures)
    }

    fn unexercised_in_cluster(&self, cluster: StateClusterId) -> u32 {
        self.unexercised.get(&cluster).copied().unwrap_or(0)
    }

    fn unexercised_total(&self) -> u32 {
        self.unexercised.values().sum()
    }

    fn unexercised_by_cluster(&self) -> Vec<(StateClusterId, u32)> {
        self.unexercised.iter().map(|(c, n)| (*c, *n)).collect()
    }

    fn latency_ms(&self, kind: ActionKind) -> Option<u32> {
        self.latency.get(&kind).map(|v| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "rounded and clamped into [0, u32::MAX] first"
            )]
            let ms = v.round().clamp(0.0, 4.0e9) as u32;
            ms
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;
    use crawlx_core::{ElementIdentityHash, InputClass, ResourceContext};

    pub(crate) fn key(route: &str, element: &str, kind: ActionKind, cluster: u128) -> ActionContextKey {
        ActionContextKey {
            principal: PrincipalId("member".into()),
            route_template: RouteTemplate(route.into()),
            element: ElementIdentityHash(Digest::of("test", element.as_bytes())),
            action_kind: kind,
            input_class: InputClass::none(),
            resource_context: ResourceContext::None,
            state_cluster: StateClusterId(uuid::Uuid::from_u128(cluster)),
        }
    }

    fn outcome(status: u8) -> OutcomeClass {
        OutcomeClass {
            after_route_template: RouteTemplate("/a".into()),
            after_cluster_family: None,
            network_operation_digest: None,
            status_class: status,
            unreliable: false,
        }
    }

    #[test]
    fn coverage_counts_trusted_only() {
        let mut l = InMemoryLedger::new();
        let a = key("/a", "a", ActionKind::Click, 1);
        let b = key("/a", "b", ActionKind::Click, 1);
        let c = key("/b", "c", ActionKind::Click, 2);
        for k in [&a, &b, &c] {
            assert!(l.register(k));
        }
        assert!(!l.register(&a), "re-registering is a no-op");
        l.record(&a, &outcome(2), TrustLane::TrustedUi);
        l.record(&b, &outcome(2), TrustLane::Diagnostic);
        let s = l.coverage(None);
        assert_eq!(s.keys_total, 3);
        assert_eq!(s.keys_exercised_trusted, 1);
        assert_eq!(s.keys_diagnostic_only, 1, "diagnostic-only keys are not covered");
        assert_eq!(s.per_route[&RouteTemplate("/a".into())].keys_total, 2);
        assert_eq!(s.per_route[&RouteTemplate("/a".into())].keys_exercised_trusted, 1);
        assert_eq!(s.per_route[&RouteTemplate("/b".into())].keys_exercised_trusted, 0);
        // a later trusted execution of b moves it out of the diagnostic-only bucket
        l.record(&b, &outcome(2), TrustLane::TrustedUi);
        let s = l.coverage(None);
        assert_eq!((s.keys_exercised_trusted, s.keys_diagnostic_only), (2, 0));
        // principal filter
        assert_eq!(l.coverage(Some(&PrincipalId("other".into()))).keys_total, 0);
        assert_eq!(l.coverage(Some(&PrincipalId("member".into()))).keys_total, 3);
    }

    #[test]
    fn novelty_halves_per_trusted_attempt_and_ignores_diagnostic() {
        let mut l = InMemoryLedger::new();
        let k = key("/a", "a", ActionKind::Click, 1);
        assert!((l.novelty(&k) - 1.0).abs() < 1e-6);
        l.record(&k, &outcome(2), TrustLane::Diagnostic);
        assert!((l.novelty(&k) - 1.0).abs() < 1e-6);
        l.record(&k, &outcome(2), TrustLane::TrustedUi);
        assert!((l.novelty(&k) - 0.5).abs() < 1e-6);
        l.record(&k, &outcome(2), TrustLane::TrustedUi);
        assert!((l.novelty(&k) - 0.25).abs() < 1e-6);
    }

    #[test]
    fn rows_round_trip_and_unexercised_index() {
        let mut l = InMemoryLedger::new();
        let a = key("/a", "a", ActionKind::Click, 1);
        let b = key("/a", "b", ActionKind::Hover, 1);
        l.register(&a);
        l.register(&b);
        l.record(&a, &outcome(5), TrustLane::TrustedUi);
        let rows = l.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|r| r.failures).sum::<u32>(),
            1,
            "5xx counts as failure"
        );
        let back = InMemoryLedger::from_rows(rows);
        assert_eq!(back.trusted_attempts(&a), 1);
        assert_eq!(back.trusted_attempts(&b), 0);
        assert_eq!(back.unexercised_total(), 1);
        assert_eq!(back.unexercised_in_cluster(a.state_cluster), 1);
        assert_eq!(back.coverage(None), l.coverage(None));
    }

    #[test]
    fn rekey_cluster_moves_entries_conserves_counters_and_merges_collisions() {
        let mut l = InMemoryLedger::new();
        let a = key("/a", "a", ActionKind::Click, 1);
        let b = key("/a", "b", ActionKind::Click, 1);
        let c = key("/a", "c", ActionKind::Click, 1);
        let other = key("/b", "d", ActionKind::Click, 2);
        for k in [&a, &b, &c, &other] {
            l.register(k);
        }
        l.record(&a, &outcome(2), TrustLane::TrustedUi);
        l.record(&b, &outcome(5), TrustLane::Diagnostic);
        // `c` already exists under successor 11 (as if seen there first): the moved entry merges
        let c_under_11 = key("/a", "c", ActionKind::Click, 11);
        l.register(&c_under_11);
        let before = l.coverage(None);
        assert_eq!(l.unexercised_in_cluster(a.state_cluster), 2);

        let to_10 = [&b.element, &a.element];
        let moved = l.rekey_cluster(a.state_cluster, |k| {
            if to_10.contains(&&k.element) {
                StateClusterId(uuid::Uuid::from_u128(10))
            } else {
                StateClusterId(uuid::Uuid::from_u128(11))
            }
        });
        assert_eq!(moved.len(), 3);
        assert!(moved.iter().all(|(old, new)| old != new));
        assert!(moved.windows(2).all(|w| w[0].0 < w[1].0), "old-id order");
        assert_eq!(
            l.unexercised_in_cluster(a.state_cluster),
            0,
            "nothing stays on the source"
        );
        assert_eq!(
            l.unexercised_in_cluster(StateClusterId(uuid::Uuid::from_u128(10))),
            1
        );
        assert_eq!(
            l.unexercised_in_cluster(StateClusterId(uuid::Uuid::from_u128(11))),
            1
        );
        assert_eq!(
            l.unexercised_in_cluster(other.state_cluster),
            1,
            "other clusters untouched"
        );
        let a10 = key("/a", "a", ActionKind::Click, 10);
        let b10 = key("/a", "b", ActionKind::Click, 10);
        assert_eq!(l.trusted_attempts(&a10), 1);
        assert_eq!(l.diagnostic_attempts(&b10), 1);
        assert!(!l.contains(&a) && !l.contains(&b) && !l.contains(&c));
        assert!(l.contains(&c_under_11));
        // one key fewer (the collision merged), every counter conserved
        let after = l.coverage(None);
        assert_eq!(after.keys_total, before.keys_total - 1);
        assert_eq!(after.keys_exercised_trusted, before.keys_exercised_trusted);
        assert_eq!(after.keys_diagnostic_only, before.keys_diagnostic_only);
        assert_eq!(l.len(), 4);
    }

    #[test]
    fn cold_start_gain_tracks_new_keys_per_exercise() {
        let mut l = InMemoryLedger::new();
        let k = key("/a", "a", ActionKind::Click, 1);
        let before = l.expected_gain(&k);
        l.register(&k);
        // nothing new appeared between executions: gain decays
        for _ in 0..10 {
            l.record(&k, &outcome(2), TrustLane::TrustedUi);
        }
        assert!(l.expected_gain(&k) < before);
        assert!(l.expected_gain(&k) >= 0.0);
    }

    #[test]
    fn latency_is_smoothed() {
        let mut l = InMemoryLedger::new();
        assert_eq!(l.latency_ms(ActionKind::Click), None);
        l.record_latency(ActionKind::Click, 1000);
        l.record_latency(ActionKind::Click, 2000);
        assert_eq!(l.latency_ms(ActionKind::Click), Some(1200));
    }

    #[test]
    fn per_role_replica_marks_cross_principal_keys_not_observable_instead_of_uncovered() {
        let mut own = key("/docs", "own", ActionKind::Click, 1);
        own.resource_context = ResourceContext::Own;
        let none = key("/docs", "none", ActionKind::Click, 1);
        let mut other = key("/docs", "other", ActionKind::Click, 1);
        other.resource_context = ResourceContext::OtherUserSameRole;
        let mut shared = key("/docs", "shared", ActionKind::Click, 1);
        shared.resource_context = ResourceContext::Shared;
        let mut higher = key("/admin", "higher", ActionKind::Click, 2);
        higher.resource_context = ResourceContext::HigherRole;
        let keys = [&own, &none, &other, &shared, &higher];

        // shared target: every context is observable, so all five are plain uncovered work
        let mut shared_target = InMemoryLedger::new();
        for k in keys {
            assert!(shared_target.register(k));
        }
        let s = shared_target.coverage(None);
        assert_eq!(
            (s.keys_total, s.keys_not_observable, s.keys_uncovered()),
            (5, 0, 5)
        );
        assert_eq!(shared_target.unexercised_total(), 5);
        assert_eq!(shared_target.status(&other), Some(CoverageStatus::Uncovered));

        // per-role replicas: the three cross-principal contexts cannot be observed
        let mut replica = InMemoryLedger::new().with_isolation(TargetIsolation::PerRoleReplica);
        for k in keys {
            assert!(replica.register(k));
        }
        for k in [&other, &shared, &higher] {
            assert_eq!(replica.status(k), Some(CoverageStatus::NotObservable), "{k:?}");
            assert!(!replica.is_observable(k));
            assert!(!replica.unexercised_id(k.id()), "not frontier work");
        }
        assert_eq!(replica.status(&own), Some(CoverageStatus::Uncovered));
        assert_eq!(replica.status(&none), Some(CoverageStatus::Uncovered));
        assert_eq!(replica.status(&key("/x", "unknown", ActionKind::Click, 9)), None);
        let s = replica.coverage(None);
        assert_eq!(s.keys_total, 5, "not-observable keys stay in the denominator");
        assert_eq!(s.keys_not_observable, 3);
        assert_eq!(s.keys_uncovered(), 2, "own/none are the only uncovered keys");
        let docs = &s.per_route[&RouteTemplate("/docs".into())];
        assert_eq!(
            (docs.keys_total, docs.keys_not_observable, docs.keys_uncovered()),
            (4, 2, 2)
        );
        assert_eq!(replica.unexercised_total(), 2);
        assert_eq!(replica.unexercised_in_cluster(own.state_cluster), 2);
        assert_eq!(replica.unexercised_in_cluster(higher.state_cluster), 0);
        assert_eq!(
            replica
                .statuses()
                .filter(|(_, s)| *s == CoverageStatus::NotObservable)
                .count(),
            3
        );
        // exercising an observable key still moves it out of the uncovered bucket
        assert!(replica.record(&own, &outcome(2), TrustLane::TrustedUi));
        assert_eq!(replica.status(&own), Some(CoverageStatus::Exercised));
        assert_eq!(replica.unexercised_total(), 1);

        // the same rows restored from storage classify identically (rows carry no status)
        let back = InMemoryLedger::from_rows(replica.rows()).with_isolation(TargetIsolation::PerRoleReplica);
        assert_eq!(back.coverage(None), replica.coverage(None));
        assert_eq!(back.unexercised_total(), 1);
        assert_eq!(back.isolation(), TargetIsolation::PerRoleReplica);
        // and switching back to a shared view re-exposes them as uncovered
        let shared_view = back.with_isolation(TargetIsolation::Shared);
        assert_eq!(shared_view.coverage(None).keys_not_observable, 0);
        assert_eq!(shared_view.unexercised_total(), 4);
    }
    #[test]
    fn coarsening_drops_only_new_state_dimensions_and_survives_row_replay() {
        let mut ledger = InMemoryLedger::new();
        for cluster in 1..=u128::from(MAX_CONTEXTS_PER_ELEMENT) {
            let mut candidate = key("/items", "delete", ActionKind::Click, cluster);
            candidate.resource_context = ResourceContext::Own;
            ledger.normalize_key(&mut candidate);
            assert!(!candidate.is_coarsened(), "{cluster}");
            assert!(ledger.register(&candidate));
        }
        let mut overflow = key("/items", "delete", ActionKind::Click, 65);
        overflow.resource_context = ResourceContext::Own;
        ledger.normalize_key(&mut overflow);
        assert!(overflow.is_coarsened());
        assert!(ledger.register(&overflow));
        let mut next = overflow.clone();
        next.state_cluster = StateClusterId(uuid::Uuid::from_u128(66));
        ledger.normalize_key(&mut next);
        assert_eq!(next, overflow);
        assert!(!ledger.register(&next));
        assert_eq!(ledger.len(), 65);
        assert!(ledger.record(&overflow, &outcome(2), TrustLane::TrustedUi));
        // Existing exact keys neither change id nor inherit the overflow execution.
        let mut old = key("/items", "delete", ActionKind::Click, 1);
        old.resource_context = ResourceContext::Own;
        let old_id = old.id();
        ledger.normalize_key(&mut old);
        assert_eq!(old.id(), old_id);
        assert_eq!(ledger.trusted_attempts(&old), 0);
        for resource in [
            ResourceContext::None,
            ResourceContext::OtherUserSameRole,
            ResourceContext::HigherRole,
            ResourceContext::Shared,
        ] {
            let mut distinct = overflow.clone();
            distinct.resource_context = resource;
            distinct.state_cluster = StateClusterId(uuid::Uuid::from_u128(99));
            ledger.normalize_key(&mut distinct);
            assert!(distinct.is_coarsened());
            assert_ne!(distinct.id(), overflow.id());
            assert!(ledger.register(&distinct));
            assert_eq!(ledger.trusted_attempts(&distinct), 0);
        }
        let mut partition = overflow.clone();
        partition.input_class = InputClass::new("email", "invalid");
        ledger.normalize_key(&mut partition);
        assert_ne!(partition.id(), overflow.id());
        let mut route = overflow.clone();
        route.route_template = RouteTemplate("/other".to_owned());
        ledger.normalize_key(&mut route);
        assert_ne!(route.state_cluster, overflow.state_cluster);
        assert_ne!(route.id(), overflow.id());
        let mut principal = old.clone();
        principal.principal = PrincipalId("admin".to_owned());
        ledger.normalize_key(&mut principal);
        assert!(!principal.is_coarsened(), "each role owns its own bound");
        assert_ne!(principal.id(), old.id());
        let restored = InMemoryLedger::from_rows(ledger.rows());
        assert_eq!(restored.rows(), ledger.rows());
        assert_eq!(restored.coverage(None), ledger.coverage(None));
        let summary = restored.coverage(None);
        assert_eq!(summary.keys_total, 69);
        assert_eq!(summary.keys_exercised_trusted, 1);
        assert_eq!(summary.keys_coarsened, 5);
        let mut resumed = key("/items", "delete", ActionKind::Click, 999);
        resumed.resource_context = ResourceContext::Own;
        restored.normalize_key(&mut resumed);
        assert_eq!(resumed, overflow);
    }

    #[test]
    fn browser_rejected_attempts_do_not_claim_coverage() {
        let mut ledger = InMemoryLedger::new();
        let candidate = key("/items", "delete", ActionKind::Click, 1);
        assert!(!ledger.record_failure(&candidate, TrustLane::TrustedUi));
        assert!(!ledger.record_failure(&candidate, TrustLane::Diagnostic));
        let summary = ledger.coverage(None);
        assert_eq!(summary.keys_total, 1);
        assert_eq!(summary.keys_exercised_trusted, 0);
        assert_eq!(summary.keys_diagnostic_only, 0);
        assert_eq!(summary.keys_uncovered(), 1);
        assert_eq!(ledger.rows()[0].failures, 2);
        assert_eq!(ledger.failed_attempts(&candidate), 2);
        let restored = InMemoryLedger::from_rows(ledger.rows());
        assert_eq!(restored.failed_attempts(&candidate), 2);
        assert_eq!(restored.coverage(None), summary);
    }
}
