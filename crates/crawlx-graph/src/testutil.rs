//! Shared test helpers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::update::{Confounders, TransitionObservation};
use crate::EnablementGraph;
use chrono::{TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, CrawlRunId, StateClusterId, Timestamp, TrustLane};
use uuid::Uuid;

pub fn t0() -> Timestamp {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

pub fn act(n: u8) -> ActionContextId {
    ActionContextId([n; 16])
}

pub fn hash(n: u8) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("test", &[n]))
}

pub fn cluster(n: u128) -> StateClusterId {
    StateClusterId(Uuid::from_u128(n))
}

pub fn graph() -> EnablementGraph {
    EnablementGraph::new(CrawlRunId(Uuid::from_u128(0xC0FFEE)))
}

/// A clean trusted-lane transition with no baseline or confounders.
pub fn obs(
    source: ActionContextId,
    before: StateClusterId,
    after: StateClusterId,
    revealed: &[ElementIdentityHash],
    now: Timestamp,
) -> TransitionObservation {
    TransitionObservation {
        source,
        family: None,
        before_cluster: before,
        after_cluster: after,
        revealed: revealed.to_vec(),
        baseline_revealed: Vec::new(),
        confounders: Confounders::default(),
        latency_ms: 100,
        lane: TrustLane::TrustedUi,
        now,
    }
}
