//! `state_split`.
//!
//! A 5k-member cluster whose members answered one action context with two different
//! outcomes (70/30 over the observed members) is checked for the contradiction and split:
//! `check` ranks the contexts, seeds the two groups from the observed members and assigns
//! every unobserved member to the seed group with the higher mean similarity; `apply`
//! recomputes both prototypes and emits the superseded memberships. No database is
//! involved (same scope as the `state_match` gate).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]

mod common;

use crawlx_core::url::RouteTemplate;
use crawlx_core::{ActionContextId, StateClusterId, StateId, Timestamp};
use crawlx_state::{
    Cluster, Fingerprinter, MaskBuilder, MaskConfig, Member, OutcomeClass, Prototype, SplitPlan, Splitter,
    StateProfile,
};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::Arc;

const MEMBERS: usize = 5_000;
/// Members with a recorded outcome for the contradicting context (2% of the cluster).
const OBSERVED: usize = 100;

/// Profiles of `n` similar 200-node pages on one route (same `route_key`, so scoring
/// compares MinHash/SimHash instead of short-circuiting on the route).
fn profiles(n: usize) -> Vec<Arc<StateProfile>> {
    let fp = Fingerprinter::default();
    (0..n)
        .map(|i| {
            let bundle = common::big_page(200, i).bundle("/orders");
            let masks = MaskBuilder::build(&bundle, &[], &MaskConfig::default());
            Arc::new(fp.profile(&bundle, &masks))
        })
        .collect()
}

fn cluster_of(profiles: &[Arc<StateProfile>]) -> Cluster {
    let mut ids = common::cluster_ids();
    let prototype = Prototype::from_profile(&profiles[0]);
    let members: Vec<Member> = profiles
        .iter()
        .enumerate()
        .map(|(i, p)| Member {
            state: common::state_id(u128::try_from(i).unwrap() + 1),
            profile: Arc::clone(p),
            similarity: 1.0,
        })
        .collect();
    Cluster {
        id: ids(),
        version: 1,
        prototype,
        size: u32::try_from(members.len()).unwrap(),
        members,
        near_of: None,
        superseded_by: Vec::new(),
    }
}

fn outcome(route: &str) -> OutcomeClass {
    OutcomeClass {
        after_route_template: RouteTemplate(route.to_owned()),
        after_cluster_family: None,
        network_operation_digest: None,
        status_class: 2,
        unreliable: false,
    }
}

/// Outcomes of the first `OBSERVED` members: context 7 splits 70/30 (`/ok` vs `/denied`);
/// context 9 has a single dissenter and must be ignored by the thresholds.
fn outcomes() -> Vec<(StateId, ActionContextId, OutcomeClass)> {
    let mut out = Vec::with_capacity(OBSERVED * 2);
    for i in 0..OBSERVED {
        let state = common::state_id(u128::try_from(i).unwrap() + 1);
        let route = if i % 10 < 7 { "/ok" } else { "/denied" };
        out.push((state, ActionContextId([7; 16]), outcome(route)));
        let noise = if i == 0 { "/timeout" } else { "/ok" };
        out.push((state, ActionContextId([9; 16]), outcome(noise)));
    }
    out
}

fn state_split(c: &mut Criterion) {
    let profiles = profiles(MEMBERS);
    let cluster = cluster_of(&profiles);
    let outcomes = outcomes();
    let splitter = Splitter::default();

    let mut g = c.benchmark_group("state_split");
    g.sample_size(30)
        .measurement_time(std::time::Duration::from_secs(10));
    g.bench_with_input(
        BenchmarkId::new("check/members", MEMBERS),
        &cluster,
        |b, cluster| {
            b.iter(|| {
                let plan = splitter.check(black_box(cluster), black_box(&outcomes)).unwrap();
                (plan.groups[0].len(), plan.groups[1].len())
            });
        },
    );

    let plan: SplitPlan = splitter.check(&cluster, &outcomes).unwrap();
    assert_eq!(plan.groups[0].len() + plan.groups[1].len(), MEMBERS);
    g.bench_with_input(BenchmarkId::new("apply/members", MEMBERS), &plan, |b, plan| {
        b.iter_batched(
            common::cluster_ids,
            |mut ids| {
                let mut mint = || -> StateClusterId { ids() };
                let result = Splitter::apply(black_box(plan), &mut mint, Timestamp::default());
                (result.clusters.len(), result.superseded.len())
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

criterion_group!(benches, state_split);
criterion_main!(benches);
