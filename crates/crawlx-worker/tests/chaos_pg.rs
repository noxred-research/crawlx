//! The failpoint drills over PostgreSQL (`--features chaos`; skipped without
//! `CRAWLX_TEST_DATABASE_URL`): the actor dies at each of the four boundaries, T2 is one
//! transaction (nothing partial is ever visible: no `transitions` row, no `network_epochs`
//! row, `action_contexts` counters unchanged while the row is `intended`), the reaper flips
//! `intended -> unknown`, and a fresh actor reconciles.
#![cfg(feature = "chaos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{proposal_for, rig_core, RigCore};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::{SafetyProfile, SystemClock, TenantId};
use crawlx_safety::Adjudication;
use crawlx_scheduler::{Reaper, ReaperConfig};
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use crawlx_worker::chaos;
use crawlx_worker::{SessionError, ShutdownReason, StateAnalyzer, Stores};
use std::sync::{Arc, LazyLock};

/// The failpoint table is process-global: drills run one at a time.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Clone, Copy, Debug)]
struct Point {
    name: &'static str,
    performed: usize,
    /// Whether T2 is durable when the actor dies.
    committed: bool,
}

/// Over PostgreSQL `during_outcome_tx` fires with the T2 future started and uncommitted, so
/// dropping it leaves nothing of T2 (`sqlx` rolls an open transaction back on drop).
const POINTS: [Point; 4] = [
    Point {
        name: chaos::AFTER_INTENT_BEFORE_PERFORM,
        performed: 0,
        committed: false,
    },
    Point {
        name: chaos::AFTER_PERFORM_BEFORE_OUTCOME,
        performed: 1,
        committed: false,
    },
    Point {
        name: chaos::DURING_OUTCOME_TX,
        performed: 1,
        committed: false,
    },
    Point {
        name: chaos::AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL,
        performed: 1,
        committed: true,
    },
];

fn site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("about", "About", "/about"))
                .on_click("about", vec![FakeEffect::Navigate("/about".into())]),
        )
        .page(
            FakePage::new("https://example.test/about")
                .title("About")
                .node(FakeAxSpec::link("home", "Home", "/")),
        )
}

async fn pg() -> Option<Pg> {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return None;
    };
    let schema = format!("t_chaos_{}", uuid::Uuid::now_v7().simple());
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
    Some(pg)
}

async fn rig(pg: &Pg) -> RigCore {
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), TenantId::new());
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
    let fake = Arc::new(FakeBackend::new(site()));
    rig_core(stores, dir, fake.clone(), fake, SafetyProfile::ReadOnly).await
}

async fn count(pg: &Pg, sql: &str, id: uuid::Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(pg.pool())
        .await
        .unwrap()
}

/// `(transitions, network_epochs, succeeded + failed + unknown of the action's context)`.
async fn t2_footprint(pg: &Pg, action: crawlx_core::ActionId) -> (i64, i64, i64) {
    let transitions = count(
        pg,
        "SELECT count(*) FROM transitions WHERE action_id = $1",
        action.0,
    )
    .await;
    let epochs = count(
        pg,
        "SELECT count(*) FROM network_epochs WHERE action_id = $1",
        action.0,
    )
    .await;
    let counters = count(
        pg,
        "SELECT (c.succeeded + c.failed + c.unknown)::bigint FROM action_contexts c JOIN actions a ON a.context_id = c.context_id WHERE a.action_id = $1",
        action.0,
    )
    .await;
    (transitions, epochs, counters)
}

async fn drill(pg: &Pg, point: Point) {
    chaos::reset();
    chaos::configure(&format!("{}=panic", point.name));
    let r = rig(pg).await;
    let bundle = r
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let analyzer = StateAnalyzer::new(
        r.rc.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    );
    let state = analyzer.analyze(&bundle).await.state;
    r.stores.states.put_state(&state).await.unwrap();
    let (p, c) = proposal_for(
        &bundle,
        "About",
        ActionKind::Click,
        state.cluster,
        &r.principal,
        &r.rc.seed_origin(),
        SafetyProfile::ReadOnly,
    );
    let key = p.key.clone();
    let admitted = match r.rc.kernel.adjudicate(p, &c) {
        Adjudication::Allow(a) => a,
        other => panic!("expected allow, got {:?}", other.verdict()),
    };

    let err = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::ActorGone), "{point:?}: {err:?}");
    assert_eq!(chaos::hits(point.name), 1, "{point:?}");
    chaos::configure("");

    let actions = ActionJournal::list(pg, r.run, None).await.unwrap();
    assert_eq!(actions.len(), 1, "{point:?}");
    let id = actions[0].id;
    assert!(pg.eligible_actions(r.run, None, 100).await.unwrap().is_empty());
    assert_eq!(r.performed_total(), point.performed, "{point:?}");
    let footprint = t2_footprint(pg, id).await;
    if point.committed {
        assert_eq!(actions[0].status, ActionStatus::Succeeded, "{point:?}");
        assert_eq!(footprint, (1, 1, 1), "{point:?}: all of T2");
    } else {
        assert_eq!(actions[0].status, ActionStatus::Intended, "{point:?}");
        assert_eq!(footprint, (0, 0, 0), "{point:?}: nothing of T2 is visible");
    }

    // the holder stopped heartbeating: the reaper flips intended -> unknown (and nothing else)
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 hour' WHERE session_id = $1",
    )
    .bind(r.session.0)
    .execute(pg.pool())
    .await
    .unwrap();
    let summary = Reaper::new(
        Arc::new(pg.clone()),
        Arc::new(pg.clone()),
        ReaperConfig::default(),
    )
    .run_once()
    .await
    .unwrap();
    let handle = r.fresh_actor(None).await;
    if point.committed {
        assert!(summary.actions_unknown.is_empty(), "{summary:?}");
        let err = handle.reconcile(id).await.unwrap_err();
        assert!(matches!(err, SessionError::NotReconcilable(_)), "{err:?}");
        assert_eq!(
            ActionJournal::get(pg, id).await.unwrap().status,
            ActionStatus::Succeeded
        );
    } else {
        assert_eq!(summary.actions_unknown, vec![id], "{summary:?}");
        assert_eq!(
            ActionJournal::get(pg, id).await.unwrap().status,
            ActionStatus::Unknown
        );
        assert!(pg.eligible_actions(r.run, None, 100).await.unwrap().is_empty());
        // `mark_unknown` bumped the context's `unknown` counter; still no transition or epoch
        assert_eq!(t2_footprint(pg, id).await, (0, 0, 1), "{point:?}");
        let resolution = handle.reconcile(id).await.unwrap();
        let rec = ActionJournal::get(pg, id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Reconciled);
        assert_eq!(rec.reconcile_resolution, Some(resolution.resolution));
        let eligible = pg.eligible_actions(r.run, None, 100).await.unwrap();
        if resolution.resolution == ReconcileResolution::NotApplied {
            assert_eq!(eligible.len(), 1);
            assert_eq!(eligible[0].key, key);
        } else {
            assert!(eligible.is_empty(), "{:?}", resolution.resolution);
        }
    }
    assert_eq!(
        r.performed_total(),
        point.performed,
        "{point:?}: nothing ran during recovery"
    );
    assert_eq!(
        count(
            pg,
            "SELECT count(*) FROM actions WHERE run_id = $1 AND status = 'intended'",
            r.run.0
        )
        .await,
        0
    );
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    chaos::reset();
}

#[tokio::test]
async fn every_failpoint_over_postgres_leaves_t2_atomic_and_recovers() {
    let _serial = SERIAL.lock().await;
    let Some(pg) = pg().await else {
        return;
    };
    for point in POINTS {
        drill(&pg, point).await;
    }
    pg.drop_schema().await.unwrap();
}
