//! Split on contradiction through the worker: four look-alike pages
//! (`/items?v=1..4`, one route, one cluster) whose "Next" button lands on `/alpha` for two of
//! them and on `/beta` for the other two. After the fourth outcome `RunClusters::try_split`
//! finds the contradiction, persists it through `StateRepo::apply_split` (memberships moved,
//! `action_contexts` re-keyed, `states.splits` counted, `state_cluster_split` event) and
//! applies it to the in-memory index with the same successor ids, so later observations
//! attach to a successor the store knows. Runs over the in-memory store and, when
//! `CRAWLX_TEST_DATABASE_URL` is set, over PostgreSQL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{canonical, proposal_for, rig_core, RigCore};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::counters::ActionStatus;
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::{LedgerRepo, NewState, RunRepo, StateRepo};
use crawlx_core::{SafetyProfile, StateClusterId, SystemClock, TenantId};
use crawlx_observe::spec;
use crawlx_safety::Adjudication;
use crawlx_state::OutcomeClass;
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};
use crawlx_strategies::InMemoryLedger;
use crawlx_worker::{StateAnalyzer, Stores};
use std::collections::BTreeSet;
use std::sync::Arc;

fn items_page(v: u8, lands_on: &str) -> FakePage {
    // one `Next` link with one href on every page; where it actually lands differs
    FakePage::new(&format!("https://example.test/items?v={v}"))
        .title("Items")
        .node(FakeAxSpec::link("next", "Next", "/next"))
        .node(FakeAxSpec::link("home", "Home", "/"))
        .on_click("next", vec![FakeEffect::Navigate(lands_on.to_owned())])
}

/// Home links to four item pages that look identical; `Next` goes to `/alpha` on v=1,2 and
/// to `/beta` on v=3,4.
fn site() -> FakeScript {
    FakeScript::new()
        .page(FakePage::new("https://example.test/").title("Home").nodes(
            (1..=4).map(|v| FakeAxSpec::link(format!("l{v}"), format!("Items {v}"), format!("/items?v={v}"))),
        ))
        .page(items_page(1, "/alpha"))
        .page(items_page(2, "/alpha"))
        .page(items_page(3, "/beta"))
        .page(items_page(4, "/beta"))
        .page(
            FakePage::new("https://example.test/alpha")
                .title("Alpha")
                .node(FakeAxSpec::new("h", "heading").name("Alpha landed"))
                .node(FakeAxSpec::link("home", "Home", "/")),
        )
        .page(
            FakePage::new("https://example.test/beta")
                .title("Beta")
                .node(FakeAxSpec::new("h", "heading").name("Beta landed"))
                .node(FakeAxSpec::textbox("note", "Note"))
                .node(FakeAxSpec::button("save", "Save"))
                .node(FakeAxSpec::link("home", "Home", "/")),
        )
}

/// Observe the current page through the run's analyzer and persist the state, what the
/// driver does at the start of a round.
async fn observe_state(r: &RigCore) -> (Arc<crawlx_core::observation::ObservationBundle>, NewState) {
    let bundle = r.handle.observe(spec::after_action()).await.unwrap();
    let state = StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await
    .state;
    r.stores.states.put_state(&state).await.unwrap();
    (bundle, state)
}

async fn split_scenario(r: &RigCore) {
    let mut source: Option<StateClusterId> = None;
    let mut befores = Vec::new();
    let mut key_id = None;
    let mut applied = None;
    for v in 1..=4u8 {
        r.handle
            .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                canonical(&format!("https://example.test/items?v={v}")),
                0,
                None,
            ))
            .await
            .unwrap();
        let (bundle, state) = observe_state(r).await;
        let cluster = *source.get_or_insert(state.cluster);
        assert_eq!(
            state.cluster, cluster,
            "the four item pages share one cluster (v={v})"
        );
        befores.push(state.id);
        let (p, c) = proposal_for(
            &bundle,
            "Next",
            ActionKind::Click,
            cluster,
            &r.principal,
            &r.rc.seed_origin(),
            r.rc.crawl.safety.profile,
        );
        let key = p.key.clone();
        key_id.get_or_insert(key.id());
        let Adjudication::Allow(admitted) = r.rc.kernel.adjudicate(p, &c) else {
            panic!("allow");
        };
        let out = r
            .handle
            .execute(admitted, QuiescencePolicy::default())
            .await
            .unwrap();
        assert_eq!(out.status, ActionStatus::Succeeded, "{out:?}");
        let after = out.after.expect("after observation");
        let after_state = out.after_state.expect("after state");
        assert_eq!(after.url.url.path(), if v <= 2 { "/alpha" } else { "/beta" });
        let outcome = OutcomeClass {
            after_route_template: after.route.template.clone(),
            after_cluster_family: Some(after_state.cluster),
            network_operation_digest: None,
            status_class: 0,
            unreliable: false,
        };
        r.rc.clusters.note_outcome(state.id, cluster, key.id(), &outcome);
        let split =
            r.rc.clusters
                .try_split(r.stores.states.as_ref(), r.run, cluster, r.rc.clock.now())
                .await
                .unwrap();
        if v < 4 {
            assert!(
                split.is_none(),
                "no contradiction before the runner-up has two observations (v={v})"
            );
        } else {
            applied = Some(split.expect("the fourth outcome splits the cluster"));
        }
    }
    let source = source.unwrap();
    let split = applied.unwrap();
    let key_id = key_id.unwrap();

    // the plan: two successors, alpha-landing members first, every member moved once
    assert_eq!(split.source, source);
    assert_eq!(split.successors.len(), 2);
    assert_eq!(split.members.len(), 4);
    assert_eq!(split.successor_of_state(befores[0]), Some(split.successors[0]));
    assert_eq!(split.successor_of_state(befores[1]), Some(split.successors[0]));
    assert_eq!(split.successor_of_state(befores[2]), Some(split.successors[1]));
    assert_eq!(split.successor_of_state(befores[3]), Some(split.successors[1]));
    assert_eq!(split.evidence.action_context, key_id);
    assert_eq!(split.evidence.total, 4);
    // two actions from each successor's members: the tie goes to the first successor
    assert_eq!(split.successor_of_context(key_id), split.successors[0]);
    assert_eq!(split.applied.memberships_moved, 4);
    assert_eq!(split.applied.action_contexts_rekeyed, 1);
    assert_eq!(r.rc.clusters.splits_applied(), 1);

    // the store: the source is gone, both successors are active with two members each and
    // every item state sits in exactly one successor
    let clusters = StateRepo::list_clusters(r.stores.states.as_ref(), r.run)
        .await
        .unwrap();
    assert!(clusters.iter().all(|(id, _, _)| *id != source), "{clusters:?}");
    for s in &split.successors {
        let (_, _, size) = clusters
            .iter()
            .find(|(id, _, _)| id == s)
            .expect("successor listed");
        assert_eq!(*size, 2);
    }
    let states = StateRepo::list_states(r.stores.states.as_ref(), r.run)
        .await
        .unwrap();
    for b in &befores {
        let st = states.iter().find(|s| s.id == *b).unwrap();
        assert_eq!(Some(st.cluster), split.successor_of_state(*b));
    }
    // the landing pages' clusters are untouched (alpha and beta differ in affordances)
    let landing: BTreeSet<StateClusterId> = states
        .iter()
        .filter(|s| s.url.url.path() != "/items")
        .map(|s| s.cluster)
        .collect();
    assert_eq!(landing.len(), 2, "{landing:?}");
    assert_eq!(r.rc.clusters.len(), 4, "two successors + alpha + beta");

    // the ledger row of the key was re-keyed to the first successor, counters conserved
    let rows = LedgerRepo::list(r.stores.ledger.as_ref(), r.run).await.unwrap();
    let next_rows: Vec<_> = rows
        .iter()
        .filter(|row| row.key.action_kind == ActionKind::Click && row.key.route_template.0 == "/items")
        .collect();
    assert_eq!(next_rows.len(), 1, "{rows:?}");
    assert_eq!(next_rows[0].key.state_cluster, split.successors[0]);
    assert_eq!(next_rows[0].trusted_exercised, 4);
    assert!(rows.iter().all(|row| row.key.state_cluster != source));
    // the in-memory ledger follows the same rule
    let mut ledger = InMemoryLedger::new();
    let old_key = crawlx_core::ActionContextKey {
        state_cluster: source,
        ..next_rows[0].key.clone()
    };
    ledger.register(&old_key);
    let moved = ledger.rekey_cluster(source, |k| split.successor_of_context(k.id()));
    assert_eq!(moved.len(), 1);
    assert_eq!(moved[0].0, key_id);
    assert!(ledger.contains(&next_rows[0].key));

    // the supersession is in the event stream
    let events = r.stores.events.list_after(r.run, 0, 10_000).await.unwrap();
    let ev = events
        .iter()
        .find(|e| e.kind == "state_cluster_split")
        .expect("state_cluster_split event");
    assert_eq!(ev.payload["source"], serde_json::json!(source));
    assert_eq!(ev.payload["memberships_moved"], serde_json::json!(4));

    // a fifth observation of an item page attaches to a successor the store knows, and the
    // persisted split is never re-applied
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://example.test/items?v=1"),
            0,
            None,
        ))
        .await
        .unwrap();
    let (_, again) = observe_state(r).await;
    assert!(split.successors.contains(&again.cluster), "{again:?}");
    assert!(!again.cluster_is_new);
    assert!(r
        .rc
        .clusters
        .try_split(r.stores.states.as_ref(), r.run, source, r.rc.clock.now())
        .await
        .unwrap()
        .is_none());
    assert_eq!(r.rc.clusters.splits_applied(), 1);
    let _ = r.stores.runs.get(r.run).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contradicting_cluster_is_split_persisted_and_rekeyed_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_core(stores, dir, fake.clone(), fake, SafetyProfile::ReadOnly).await;
    split_scenario(&r).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contradicting_cluster_is_split_persisted_and_rekeyed_in_postgres() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("CRAWLX_TEST_DATABASE_URL not set; skipping");
        return;
    };
    let schema = format!("t_split_{}", uuid::Uuid::now_v7().simple());
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(schema),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_core(stores, dir, fake.clone(), fake, SafetyProfile::ReadOnly).await;
    split_scenario(&r).await;
}
