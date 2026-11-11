//! Split correctness incl. conservation of `action_contexts` totals:
//! `StateRepo::apply_split` supersedes a cluster, moves every member to exactly one
//! successor and re-keys the coverage ledger without losing or duplicating a count, in
//! memory and in PostgreSQL (the latter skips without `CRAWLX_TEST_DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::identity::ActionContextKey;
use crawlx_core::repo::*;
use crawlx_core::{
    ActionContextId, ActionId, CrawlRunId, SessionId, StateClusterId, StateId, StoreError, TenantId, WorkerId,
};
use crawlx_storage::testkit::{
    allow_verdict, crawl_run, create_crawl, new_state, proposal, sessions, signature,
};
use crawlx_storage::{LeaseRepo, MemoryStore, Pg, StoreConfig};
use std::collections::{BTreeMap, BTreeSet};

fn epoch(m: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: m,
    }
}

/// Counters of one ledger row, the quantity a split must conserve.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct Counts {
    trusted: u32,
    diagnostic: u32,
    failures: u32,
}

impl Counts {
    fn of(row: &LedgerRow) -> Self {
        Self {
            trusted: row.trusted_exercised,
            diagnostic: row.diagnostic_exercised,
            failures: row.failures,
        }
    }

    fn add(self, o: Self) -> Self {
        Self {
            trusted: self.trusted + o.trusted,
            diagnostic: self.diagnostic + o.diagnostic,
            failures: self.failures + o.failures,
        }
    }
}

/// Id of the context key with its cluster slot cleared: what stays constant across a re-key.
fn cluster_free(key: &ActionContextKey) -> ActionContextId {
    ActionContextKey {
        state_cluster: StateClusterId(uuid::Uuid::nil()),
        ..key.clone()
    }
    .id()
}

trait SplitStore: StateRepo + LedgerRepo + ActionJournal + EventRepo {}
impl<S: StateRepo + LedgerRepo + ActionJournal + EventRepo + ?Sized> SplitStore for S {}

/// Seed one cluster with six states, four ledger rows and action evidence, split it 3/3 and
/// check conservation, exact successor mapping and the supersession record.
async fn split_conserves_action_contexts(store: &dyn SplitStore, run: CrawlRunId, session: SessionId) {
    let source = StateClusterId::new();
    // s1..s6 at increasing epochs; T1 pins `before_state` to the newest state not newer
    // than the intend epoch, so each action below lands on a chosen state
    let mut states = Vec::new();
    for i in 1..=6u64 {
        let s = new_state(session, source, i == 1, i, epoch(10 * i));
        store.put_state(&s).await.unwrap();
        states.push(s);
    }
    let state_at = |i: u64| states[usize::try_from(i).unwrap() - 1].id;

    // ledger rows keyed to the source cluster with known counters
    let keys: Vec<ActionContextKey> = (1..=4).map(|n| proposal("anonymous", source, n).key).collect();
    let now = Utc::now();
    for (n, key) in keys.iter().enumerate() {
        let n = u32::try_from(n).unwrap();
        LedgerRepo::upsert(
            store,
            run,
            &LedgerRow {
                key: key.clone(),
                trusted_exercised: 3 - n.min(3),
                diagnostic_exercised: n % 3,
                failures: n % 2,
                first_seen: now,
                last_exercised: Some(now),
            },
        )
        .await
        .unwrap();
    }

    // action evidence: k1 ran from s2 and s3 (group B), k2 from s1 (group A), k3 never ran,
    // k4 once from s5 (A) and once from s4 (B): a tie that falls to the first successor
    let mut acted: Vec<(ActionId, usize)> = Vec::new();
    for (n, from) in [(1_usize, 2_u64), (1, 3), (2, 1), (4, 5), (4, 4)] {
        let id = store
            .propose(
                run,
                session,
                &proposal("anonymous", source, u32::try_from(n).unwrap()),
                &allow_verdict(),
            )
            .await
            .unwrap();
        store.intend(id, session, epoch(10 * from + 1)).await.unwrap();
        assert_eq!(
            ActionJournal::get(store, id).await.unwrap().before_state,
            Some(state_at(from)),
            "evidence setup pins the intended state"
        );
        acted.push((id, n));
    }

    let before: Vec<LedgerRow> = LedgerRepo::list(store, run).await.unwrap();
    assert_eq!(before.len(), 4);
    let before_by_key: BTreeMap<_, _> = before
        .iter()
        .map(|r| (cluster_free(&r.key), Counts::of(r)))
        .collect();
    let total_before = before.iter().map(Counts::of).fold(Counts::default(), Counts::add);
    let clusters_before = StateRepo::list_clusters(store, run).await.unwrap();
    assert_eq!(clusters_before.len(), 1);
    assert_eq!(clusters_before[0].2, 6);

    let a = StateClusterId::new();
    let b = StateClusterId::new();
    let member = |i: u64| SplitMember {
        state: state_at(i),
        similarity: 0.95,
    };
    let split = ClusterSplitRecord {
        run,
        source,
        source_version: 1,
        successors: vec![
            SplitSuccessor {
                cluster: a,
                version: 2,
                prototype: state_at(1),
                signature: signature(1),
                members: vec![member(1), member(5), member(6)],
            },
            SplitSuccessor {
                cluster: b,
                version: 2,
                prototype: state_at(2),
                signature: signature(2),
                members: vec![member(2), member(3), member(4)],
            },
        ],
        decided_at: now,
    };
    let applied = store.apply_split(&split).await.unwrap();
    assert_eq!(
        applied,
        SplitApplied {
            memberships_moved: 6,
            action_contexts_rekeyed: 4
        }
    );

    // every member lands in exactly one successor; the source is superseded
    let listed = StateRepo::list_states(store, run).await.unwrap();
    assert_eq!(listed.len(), 6);
    let cluster_of: BTreeMap<StateId, StateClusterId> = listed.iter().map(|s| (s.id, s.cluster)).collect();
    for i in [1, 5, 6] {
        assert_eq!(cluster_of[&state_at(i)], a, "s{i}");
    }
    for i in [2, 3, 4] {
        assert_eq!(cluster_of[&state_at(i)], b, "s{i}");
    }
    let prototypes: BTreeSet<StateId> = listed.iter().filter(|s| s.cluster_is_new).map(|s| s.id).collect();
    assert_eq!(prototypes, [state_at(1), state_at(2)].into_iter().collect());
    let clusters: BTreeMap<StateClusterId, u32> = StateRepo::list_clusters(store, run)
        .await
        .unwrap()
        .into_iter()
        .map(|(id, _, n)| (id, n))
        .collect();
    assert_eq!(clusters, [(a, 3), (b, 3)].into_iter().collect());
    assert!(!clusters.contains_key(&source));

    // conservation: same row count, every row maps to exactly one successor, every
    // cluster-free key keeps its counters, totals over both successors equal the old total
    let after: Vec<LedgerRow> = LedgerRepo::list(store, run).await.unwrap();
    assert_eq!(after.len(), before.len());
    let mut mapped: BTreeMap<ActionContextId, StateClusterId> = BTreeMap::new();
    for row in &after {
        assert!(
            row.key.state_cluster == a || row.key.state_cluster == b,
            "row still keyed to {:?}",
            row.key.state_cluster
        );
        assert_eq!(
            Counts::of(row),
            before_by_key[&cluster_free(&row.key)],
            "counters of {:?} changed",
            row.key.element
        );
        assert!(
            mapped
                .insert(cluster_free(&row.key), row.key.state_cluster)
                .is_none(),
            "a context was duplicated across successors"
        );
    }
    assert_eq!(mapped.len(), before.len(), "a context was lost");
    let total_after = after.iter().map(Counts::of).fold(Counts::default(), Counts::add);
    assert_eq!(total_after, total_before);
    let per_cluster = |c: StateClusterId| {
        after
            .iter()
            .filter(|r| r.key.state_cluster == c)
            .map(Counts::of)
            .fold(Counts::default(), Counts::add)
    };
    assert_eq!(per_cluster(a).add(per_cluster(b)), total_before);

    // the successor follows the actions' before-states: k1 -> B, k2 -> A, k3 (no actions)
    // and k4 (1:1 tie) -> A (first successor)
    let expect: BTreeMap<ActionContextId, StateClusterId> = [(1, b), (2, a), (3, a), (4, a)]
        .into_iter()
        .map(|(n, c)| (cluster_free(&keys[n - 1]), c))
        .collect();
    assert_eq!(mapped, expect);

    // journaled actions read the re-keyed context
    for (id, n) in &acted {
        let rec = ActionJournal::get(store, *id).await.unwrap();
        assert_eq!(
            rec.key.state_cluster,
            expect[&cluster_free(&keys[n - 1])],
            "action of k{n}"
        );
    }

    // supersession record
    let events = store.list_after(run, 0, 100).await.unwrap();
    let split_events: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "state_cluster_split")
        .collect();
    assert_eq!(split_events.len(), 1);
    let payload = &split_events[0].payload;
    assert_eq!(payload["source"], serde_json::json!(source));
    assert_eq!(payload["source_version"], 1);
    assert_eq!(payload["memberships_moved"], 6);
    assert_eq!(payload["action_contexts_rekeyed"], 4);
    assert_eq!(payload["successors"].as_array().unwrap().len(), 2);

    // a stale plan against the superseded source is refused and changes nothing
    assert!(matches!(
        store.apply_split(&split).await,
        Err(StoreError::Conflict(_))
    ));
    // a plan that drops a member is refused
    let mut partial = ClusterSplitRecord {
        source: a,
        successors: vec![SplitSuccessor {
            cluster: StateClusterId::new(),
            version: 3,
            prototype: state_at(1),
            signature: signature(1),
            members: vec![member(1), member(5)],
        }],
        ..split.clone()
    };
    partial.source_version = 2;
    assert!(matches!(
        store.apply_split(&partial).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(LedgerRepo::list(store, run).await.unwrap().len(), 4);
    assert_eq!(StateRepo::list_clusters(store, run).await.unwrap().len(), 2);
}

#[tokio::test]
async fn memory_split_rekeys_action_contexts_and_conserves_totals() {
    let store = MemoryStore::new();
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    store.create_sessions(&ss).await.unwrap();
    store
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    split_conserves_action_contexts(&store, run.id, ss[0].id).await;
}

#[tokio::test]
async fn pg_split_rekeys_action_contexts_and_conserves_totals() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("SKIP: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema),
            max_connections: 8,
            ..StoreConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.expect("tenant");
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    pg.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    pg.create_sessions(&ss).await.unwrap();
    let lease = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .expect("a lease");
    split_conserves_action_contexts(&pg, run.id, lease.session.id).await;

    // the PostgreSQL rows themselves: superseded source, successor rows, one active
    // membership per state, `context_hash` recomputed from the re-keyed key
    let status: (String, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT status, superseded_by FROM state_clusters WHERE run_id = $1 AND version = 1")
            .bind(run.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert_eq!(status.0, "superseded");
    assert!(status.1.is_some());
    let active_per_state: Vec<i64> = sqlx::query_scalar(
        "SELECT count(*) FROM state_cluster_membership m JOIN states s ON s.state_id = m.state_id \
         WHERE s.run_id = $1 AND m.active GROUP BY m.state_id",
    )
    .bind(run.id.0)
    .fetch_all(pg.pool())
    .await
    .unwrap();
    assert_eq!(active_per_state, vec![1; 6]);
    let superseded_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM state_cluster_membership m JOIN states s ON s.state_id = m.state_id \
         WHERE s.run_id = $1 AND NOT m.active",
    )
    .bind(run.id.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert_eq!(superseded_rows, 6, "old memberships are superseded, not deleted");
    for row in LedgerRepo::list(&pg, run.id).await.unwrap() {
        let hash: Vec<u8> = sqlx::query_scalar(
            "SELECT context_hash FROM action_contexts WHERE run_id = $1 AND state_cluster_id = $2 AND identity_hash = $3",
        )
        .bind(run.id.0)
        .bind(row.key.state_cluster.0)
        .bind(row.key.element.0 .0.to_vec())
        .fetch_one(pg.pool())
        .await
        .unwrap();
        assert_eq!(
            hash,
            row.key.id().0.to_vec(),
            "context_hash follows the re-keyed key"
        );
    }
    pg.drop_schema().await.expect("drop schema");
}
