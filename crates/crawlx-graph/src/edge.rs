//! Enablement edges and the planning cost function.
//!
//! An edge says: in context `C`, the action `X` revealed target `T` with
//! probability `p`. Edge identity is the triple `(source, context, target)`;
//! the `EdgeId` is derived from it, so ids never depend on wall time or RNG.

use crate::decay;
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, EdgeId, RouteTemplate, StateClusterId, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Samples kept for the rolling latency median.
const LATENCY_WINDOW: usize = 9;

/// Where an edge applies. Lookup order is exact cluster, then route
/// template, then principal-global; edges never silently widen.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum EdgeContext {
    /// Observed in exactly this state cluster.
    Cluster(StateClusterId),
    /// Generalized across the clusters of one route template.
    RouteTemplate(RouteTemplate),
    /// Applies anywhere for the principal (never created implicitly).
    PrincipalGlobal,
}

/// What an edge reveals or leads to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum EdgeTarget {
    /// A control with this durable identity became visible.
    Identity(ElementIdentityHash),
    /// The action moved the page into this state cluster.
    Cluster(StateClusterId),
}

/// Planning weights for [`EnablementEdge::edge_cost`].
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct CostParams {
    /// Weight of the normalised latency term (`p50 / latency_cap_ms`, capped at 1).
    pub lambda_lat: f64,
    /// Weight of the edge `risk` term (`risk` is `0` for reversible actions).
    pub lambda_risk: f64,
    /// Weight of the staleness term derived from the edge's age.
    pub lambda_stale: f64,
    /// Latency that saturates the latency term, in milliseconds.
    pub latency_cap_ms: f64,
    /// Added for route-template edges.
    pub route_penalty: f64,
    /// Added for principal-global edges.
    pub global_penalty: f64,
    /// Added while an edge is `unverified` after a build change.
    pub unverified_penalty: f64,
}

impl Default for CostParams {
    fn default() -> Self {
        Self {
            lambda_lat: 0.5,
            lambda_risk: 2.0,
            lambda_stale: 0.5,
            latency_cap_ms: 5000.0,
            route_penalty: 0.15,
            global_penalty: 0.40,
            unverified_penalty: 0.5,
        }
    }
}

/// One probabilistic enablement edge.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct EnablementEdge {
    /// Deterministic id derived from `(source, context, target)` by [`derive_edge_id`].
    pub id: EdgeId,
    /// The action context (identity, kind, input class, resource context).
    pub source: ActionContextId,
    /// Where the edge applies: exact cluster, route template or principal-global.
    pub context: EdgeContext,
    /// What the action revealed or led to.
    pub target: EdgeTarget,
    /// Strong credits: no confounder in the settle window.
    pub support: u32,
    /// Confounded credits; each counts half.
    pub weak_support: u32,
    /// Observations where the action ran but the target did not follow.
    pub failures: u32,
    /// Consecutive failures since the last credit (retirement rule).
    pub consecutive_failures: u32,
    /// Rolling median of observed latencies, in milliseconds (`0` before any sample).
    pub p50_latency_ms: u32,
    /// Rolling window the median is taken from (not persisted).
    pub(crate) latency_window: Vec<u32>,
    /// `0` for reveal, navigation and reversible actions.
    pub risk: f32,
    /// Timestamp of the first observation of this edge.
    pub first_seen: Timestamp,
    /// Timestamp of the latest observation; the age for decay counts from here.
    pub last_seen: Timestamp,
    /// Application build id the edge last succeeded against, if known.
    pub last_verified_build: Option<String>,
    /// Set by a detected build change; remains usable at extra cost.
    pub unverified: bool,
}

impl EnablementEdge {
    /// A fresh edge with no evidence yet.
    #[must_use]
    pub fn new(source: ActionContextId, context: EdgeContext, target: EdgeTarget, now: Timestamp) -> Self {
        Self {
            id: derive_edge_id(source, &context, &target),
            source,
            context,
            target,
            support: 0,
            weak_support: 0,
            failures: 0,
            consecutive_failures: 0,
            p50_latency_ms: 0,
            latency_window: Vec::new(),
            risk: 0.0,
            first_seen: now,
            last_seen: now,
            last_verified_build: None,
            unverified: false,
        }
    }

    /// `support + 0.5 * weak_support`.
    #[must_use]
    pub fn effective_support(&self) -> f64 {
        f64::from(self.support) + 0.5 * f64::from(self.weak_support)
    }

    /// Raw number of observations (strong, weak and failed).
    #[must_use]
    pub fn trials(&self) -> u32 {
        self.support
            .saturating_add(self.weak_support)
            .saturating_add(self.failures)
    }

    /// Days since this edge was last observed.
    #[must_use]
    pub fn age_days(&self, now: Timestamp) -> f64 {
        decay::age_days(self.last_seen, now)
    }

    /// Laplace probability `(s + 1) / (s + f + 2)` with `s`, `f` decayed by
    /// `0.5^(age_days / 14)`.
    #[must_use]
    pub fn p_success(&self, now: Timestamp) -> f64 {
        decay::decayed_p(
            self.effective_support(),
            f64::from(self.failures),
            self.age_days(now),
        )
    }

    /// Penalty for the context level (exact 0, route +0.15, global +0.40).
    #[must_use]
    pub fn ctx_penalty(&self, params: &CostParams) -> f64 {
        match self.context {
            EdgeContext::Cluster(_) => 0.0,
            EdgeContext::RouteTemplate(_) => params.route_penalty,
            EdgeContext::PrincipalGlobal => params.global_penalty,
        }
    }

    /// `-ln p + λ_lat·min(1, p50/5000) + λ_risk·risk + λ_stale·age + ctx_penalty`
    /// (plus the unverified surcharge). Non-negative because `p < 1`.
    #[must_use]
    pub fn edge_cost(&self, now: Timestamp, params: &CostParams) -> f64 {
        let p = self.p_success(now);
        let lat = (f64::from(self.p50_latency_ms) / params.latency_cap_ms).min(1.0);
        let stale = decay::staleness(self.age_days(now));
        let unverified = if self.unverified {
            params.unverified_penalty
        } else {
            0.0
        };
        -p.ln()
            + params.lambda_lat * lat
            + params.lambda_risk * f64::from(self.risk.max(0.0))
            + params.lambda_stale * stale
            + self.ctx_penalty(params)
            + unverified
    }

    /// Fold a latency sample into the rolling median.
    pub(crate) fn record_latency(&mut self, ms: u32) {
        if self.latency_window.len() == LATENCY_WINDOW {
            self.latency_window.remove(0);
        }
        self.latency_window.push(ms);
        let mut sorted = self.latency_window.clone();
        sorted.sort_unstable();
        self.p50_latency_ms = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
    }

    /// Positive evidence: `weak` credits count half.
    pub(crate) fn credit(
        &mut self,
        weak: bool,
        latency_ms: Option<u32>,
        build: Option<&str>,
        now: Timestamp,
    ) {
        if weak {
            self.weak_support = self.weak_support.saturating_add(1);
        } else {
            self.support = self.support.saturating_add(1);
        }
        self.consecutive_failures = 0;
        self.last_seen = now;
        if let Some(ms) = latency_ms {
            self.record_latency(ms);
        }
        self.last_verified_build = build.map(str::to_owned);
        self.unverified = false;
    }

    /// Negative evidence.
    pub(crate) fn fail(&mut self, now: Timestamp) {
        self.failures = self.failures.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_seen = now;
    }
}

/// Deterministic edge id from `(source, context, target)`.
#[must_use]
pub fn derive_edge_id(source: ActionContextId, context: &EdgeContext, target: &EdgeTarget) -> EdgeId {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(&source.0);
    match context {
        EdgeContext::Cluster(c) => {
            b.push(0);
            b.extend_from_slice(c.0.as_bytes());
        }
        EdgeContext::RouteTemplate(r) => {
            b.push(1);
            b.extend_from_slice(r.0.as_bytes());
        }
        EdgeContext::PrincipalGlobal => b.push(2),
    }
    match target {
        EdgeTarget::Identity(h) => {
            b.push(0);
            b.extend_from_slice(&h.0 .0);
        }
        EdgeTarget::Cluster(c) => {
            b.push(1);
            b.extend_from_slice(c.0.as_bytes());
        }
    }
    EdgeId(Uuid::from_bytes(
        Digest::of("crawlx/graph/edge-id/v1", &b).truncate16(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{act, cluster, hash, t0};
    use chrono::Duration;

    fn edge() -> EnablementEdge {
        EnablementEdge::new(
            act(1),
            EdgeContext::Cluster(cluster(1)),
            EdgeTarget::Identity(hash(1)),
            t0(),
        )
    }

    #[test]
    fn p_success_laplace_and_decay() {
        let mut e = edge();
        e.support = 4;
        assert!((e.p_success(t0()) - 5.0 / 6.0).abs() < 1e-12);
        // 14 days later: s = 2, p = 3/4.
        assert!((e.p_success(t0() + Duration::days(14)) - 0.75).abs() < 1e-9);
        e.failures = 2;
        // 14 days later: s = 2, f = 1, p = 3/5.
        assert!((e.p_success(t0() + Duration::days(14)) - 0.6).abs() < 1e-9);
    }

    #[test]
    fn weak_support_counts_half() {
        let mut e = edge();
        e.weak_support = 4;
        // s = 2 -> p = 3/4.
        assert!((e.p_success(t0()) - 0.75).abs() < 1e-12);
        e.support = 2;
        // s = 4 -> p = 5/6.
        assert!((e.p_success(t0()) - 5.0 / 6.0).abs() < 1e-12);
    }

    #[test]
    fn cost_terms_hand_computed() {
        let p = CostParams::default();
        let mut e = edge();
        e.support = 2; // p = 3/4
        e.p50_latency_ms = 2500; // 0.5 * 0.5
        e.risk = 0.25; // 2.0 * 0.25
        let now = t0() + Duration::days(15); // decays s to 2 * 0.5^(15/14)
        let age = 15.0;
        let pp = decay::decayed_p(2.0, 0.0, age);
        let expect = -pp.ln() + 0.5 * 0.5 + 2.0 * 0.25 + 0.5 * 0.5;
        assert!((e.edge_cost(now, &p) - expect).abs() < 1e-9);

        let mut route = e.clone();
        route.context = EdgeContext::RouteTemplate(RouteTemplate("/a".into()));
        let mut global = e.clone();
        global.context = EdgeContext::PrincipalGlobal;
        let base = e.edge_cost(now, &p);
        assert!((route.edge_cost(now, &p) - base - 0.15).abs() < 1e-12);
        assert!((global.edge_cost(now, &p) - base - 0.40).abs() < 1e-12);
    }

    #[test]
    fn cost_is_nonnegative_even_for_perfect_edge() {
        let mut e = edge();
        e.support = 100_000;
        assert!(e.edge_cost(t0(), &CostParams::default()) >= 0.0);
    }

    #[test]
    fn latency_median_window() {
        let mut e = edge();
        for ms in [100, 900, 200] {
            e.record_latency(ms);
        }
        assert_eq!(e.p50_latency_ms, 200);
    }

    #[test]
    fn edge_id_is_deterministic_and_context_sensitive() {
        let a = edge();
        let b = edge();
        assert_eq!(a.id, b.id);
        let mut c = edge();
        c.context = EdgeContext::PrincipalGlobal;
        assert_ne!(a.id, derive_edge_id(c.source, &c.context, &c.target));
    }
}
