//! Hand-computed URL graph contracts; no browser, network, randomness or wall clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::hash::Digest;
use crawlx_core::url_graph::*;
use crawlx_core::{CrawlRunId, TenantId};

fn tenant(value: u128) -> TenantId {
    TenantId(uuid::Uuid::from_u128(value))
}
fn run(value: u128) -> CrawlRunId {
    CrawlRunId(uuid::Uuid::from_u128(value))
}
fn node(value: u8) -> UrlHandleV1 {
    UrlHandleV1(Digest([value; 32]))
}
fn policy() -> UrlGraphPolicyV1 {
    UrlGraphPolicyV1::new(Digest([4; 32]), Digest([5; 32]), 1, 8500)
}
fn graph() -> UrlGraphSnapshotV1 {
    UrlGraphSnapshotV1::empty(tenant(1), run(2), policy())
}
fn batch(source: u8, edges: &[(u8, u32)]) -> UrlGraphBatchV1 {
    UrlGraphBatchV1::new(
        node(source),
        edges
            .iter()
            .map(|(target, cost)| UrlGraphEdgeV1::new(node(source), node(*target), None, *cost))
            .collect(),
    )
    .unwrap()
}

#[test]
fn hand_computed_rank_preserves_orphans_and_breaks_ties_by_handle() {
    let mut graph = graph();
    graph.replace(&batch(1, &[(2, 7)])).unwrap();
    graph.replace(&batch(3, &[])).unwrap();
    let inverted = graph.invert().unwrap();
    assert!(inverted[&node(1)].is_empty());
    assert_eq!(inverted[&node(2)][0].source, node(1));
    assert!(inverted[&node(3)].is_empty());
    let ranks = graph.rank().unwrap();
    let rows: Vec<_> = ranks.rows.iter().map(|row| (row.node, row.score)).collect();
    assert_eq!(rows, [(node(2), 522_222), (node(1), 238_889), (node(3), 238_889)]);
    assert_eq!(
        ranks.rows.iter().map(|row| row.score).sum::<u64>(),
        URL_GRAPH_RANK_MASS
    );
    let costs = graph.costs(&[node(1)]).unwrap();
    assert_eq!(costs[&node(1)], Some(0));
    assert_eq!(costs[&node(2)], Some(7));
    assert_eq!(costs[&node(3)], None);
}

#[test]
fn rank_counts_unique_targets_not_anchor_multiplicity() {
    let mut graph = graph();
    let one = batch(1, &[(2, 1)]);
    graph.replace(&one).unwrap();
    let expected = graph.rank().unwrap().rows;
    let anchors = UrlGraphBatchV1::new(
        node(1),
        vec![
            UrlGraphEdgeV1::new(node(1), node(2), Some(Digest([1; 32])), 1),
            UrlGraphEdgeV1::new(node(1), node(2), Some(Digest([2; 32])), 1),
        ],
    )
    .unwrap();
    graph.replace(&anchors).unwrap();
    assert_eq!(graph.rank().unwrap().rows, expected);
    assert_eq!(graph.invert().unwrap()[&node(2)].len(), 2);
}

#[test]
fn replacement_is_idempotent_retains_isolated_nodes_and_uses_shortest_positive_cost() {
    let mut graph = graph();
    graph.replace(&batch(1, &[(3, 10), (2, 2)])).unwrap();
    graph.replace(&batch(2, &[(3, 3)])).unwrap();
    assert_eq!(graph.costs(&[node(1)]).unwrap()[&node(3)], Some(5));
    let revision = graph.revision;
    assert!(!graph.replace(&batch(2, &[(3, 3)])).unwrap());
    assert_eq!(graph.revision, revision);
    graph.replace(&batch(1, &[])).unwrap();
    graph.replace(&batch(2, &[])).unwrap();
    assert_eq!(graph.nodes, [node(1), node(2), node(3)]);
    assert!(graph.edges.is_empty());
    assert_eq!(graph.costs(&[node(1)]).unwrap()[&node(3)], None);
    assert!(graph.costs(&[node(9)]).is_err());
}

#[test]
fn handles_restart_stably_but_never_correlate_tenants_runs_or_anchors() {
    let root = [7; 32];
    let handles = UrlGraphHandles::new(&root, tenant(1), run(2));
    let url = "https://fixture.test/private?token=never-persist";
    let anchor = "never-persist-anchor";
    let key = handles.url(url).unwrap();
    assert_eq!(
        key,
        UrlGraphHandles::new(&root, tenant(1), run(2)).url(url).unwrap()
    );
    assert_ne!(
        key,
        UrlGraphHandles::new(&root, tenant(3), run(2)).url(url).unwrap()
    );
    assert_ne!(
        key,
        UrlGraphHandles::new(&root, tenant(1), run(3)).url(url).unwrap()
    );
    assert_ne!(key.0, handles.anchor(url).unwrap());
    let batch = UrlGraphBatchV1::new(
        key,
        vec![UrlGraphEdgeV1::new(
            key,
            key,
            Some(handles.anchor(anchor).unwrap()),
            1,
        )],
    )
    .unwrap();
    let serialized = serde_json::to_string(&batch).unwrap();
    assert!(!serialized.contains("never-persist"));
    assert!(!serialized.contains("fixture.test"));
    assert_eq!(
        serde_json::from_str::<UrlGraphBatchV1>(&serialized).unwrap(),
        batch
    );
}

#[test]
fn malformed_and_unbounded_graph_work_fails_without_mutating_snapshot() {
    assert!(UrlGraphPolicyV1::new(Digest([0; 32]), Digest([0; 32]), 65, 8500)
        .validate()
        .is_err());
    assert!(UrlGraphPolicyV1::new(Digest([0; 32]), Digest([0; 32]), 1, 10001)
        .validate()
        .is_err());
    assert!(UrlGraphBatchV1::new(node(1), vec![UrlGraphEdgeV1::new(node(1), node(2), None, 0)]).is_err());
    assert!(UrlGraphBatchV1::new(node(1), vec![UrlGraphEdgeV1::new(node(2), node(3), None, 1)]).is_err());
    let too_many = vec![UrlGraphEdgeV1::new(node(1), node(2), None, 1); MAX_URL_GRAPH_BATCH + 1];
    assert!(UrlGraphBatchV1::new(node(1), too_many).is_err());
    let mut graph = graph();
    graph.revision = i64::MAX.unsigned_abs();
    let before = graph.clone();
    assert_eq!(graph.replace(&batch(1, &[])), Err(UrlGraphError::Overflow));
    assert_eq!(graph, before);
    graph.revision = 0;
    graph.nodes = vec![node(2), node(1)];
    assert!(graph.rank().is_err());
    assert!(UrlGraphHandles::new(&[1; 32], tenant(1), run(2))
        .anchor(&"x".repeat(4097))
        .is_err());
}

#[test]
fn empty_graph_and_exact_ties_have_stable_results() {
    let mut graph = graph();
    assert!(graph.rank().unwrap().rows.is_empty());
    graph.replace(&batch(2, &[(1, 1)])).unwrap();
    graph.replace(&batch(1, &[(2, 1)])).unwrap();
    let ranks = graph.rank().unwrap();
    assert_eq!(
        ranks
            .rows
            .iter()
            .map(|row| (row.node, row.score))
            .collect::<Vec<_>>(),
        [(node(1), 500_000), (node(2), 500_000)]
    );
    let encoded = serde_json::to_string(&graph).unwrap();
    let restarted: UrlGraphSnapshotV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(restarted.rank().unwrap(), ranks);
    assert_eq!(
        restarted.costs(&[node(1)]).unwrap(),
        graph.costs(&[node(1)]).unwrap()
    );
}

#[test]
fn cache_validation_rejects_foreign_stale_incomplete_and_noncanonical_results() {
    let mut graph = graph();
    graph.replace(&batch(1, &[(2, 1)])).unwrap();
    let ranks = graph.rank().unwrap();
    ranks.validate_for(&graph).unwrap();
    let mut malformed = ranks.clone();
    malformed.tenant = tenant(3);
    assert!(malformed.validate_for(&graph).is_err());
    let mut malformed = ranks.clone();
    malformed.rows.pop();
    assert!(malformed.validate_for(&graph).is_err());
    let mut malformed = ranks.clone();
    malformed.rows.reverse();
    assert!(malformed.validate_for(&graph).is_err());
    let mut malformed = ranks.clone();
    malformed.rows[0].score = 0;
    assert!(malformed.validate_for(&graph).is_err());
    let mut malformed = ranks.clone();
    malformed.rows[1].node = malformed.rows[0].node;
    assert!(malformed.validate_for(&graph).is_err());
    graph.policy.model = Digest([9; 32]);
    assert!(ranks.validate_for(&graph).is_err());
    graph.policy = policy();
    graph.replace(&batch(2, &[(1, 1)])).unwrap();
    assert!(ranks.validate_for(&graph).is_err());
}

#[test]
fn node_capacity_rejects_growth_without_partial_evidence() {
    let mut graph = graph();
    graph.nodes = (0..MAX_URL_GRAPH_NODES)
        .map(|value| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&u64::try_from(value).unwrap().to_be_bytes());
            UrlHandleV1(Digest(bytes))
        })
        .collect();
    graph.validate().unwrap();
    let before = graph.clone();
    assert_eq!(graph.replace(&batch(255, &[])), Err(UrlGraphError::Limit));
    assert_eq!(graph, before);
}
