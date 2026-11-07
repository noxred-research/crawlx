//! PostgreSQL integration tests. Each test runs in its own schema on
//! `CRAWLX_TEST_DATABASE_URL`; without that variable every test returns early.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, NaiveDate, TimeZone as _, Utc};
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{ActionStatus, ReconcileResolution, RunStatus, TerminalReason};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{ActionReceipt, SettleReport};
use crawlx_core::repo::*;
use crawlx_core::safety::SafetyDecision;
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin, TrustLane, UnattributedReason};
use crawlx_core::{
    ArtifactId, ArtifactRef, CrawlRunId, NetworkEpochId, PrincipalId, SessionId, StateClusterId, StoreError,
    SystemClock, TenantId, WorkerId,
};
use crawlx_storage::artifacts::{ArtifactBlobs, FsArtifactStore, MemBlobs, MemoryArtifactStore};
use crawlx_storage::audit::{export_key, merkle_root, MerkleExport, MERKLE_DOMAIN};
use crawlx_storage::retention::RetentionSweeper;
use crawlx_storage::testkit::{
    allow_verdict, canonical_url, crawl_run, create_crawl, new_state, proposal, sessions, verdict,
};
use crawlx_storage::{LeaseRepo, Pg, PgConfig, TrailReads};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Serializes the tests that assert exact deltas on the process-global metrics registry.
static METRICS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn trusted_rows(kind: &str) -> u64 {
    Metrics::global()
        .counter(names::EXPORT_TRUSTED_ROWS)
        .get(&[("kind", kind)])
}

struct Env {
    pg: Pg,
    tenant: TenantId,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let schema = format!("t_{}", uuid_simple());
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(schema),
            max_connections: 12,
            ..PgConfig::default()
        },
    )
    .await
    .expect("connect");
    let pg = pg.with_delivery_buffer(Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(Arc::new(
        SystemClock,
    ))));
    pg.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.expect("tenant");
    Some(Env { pg, tenant })
}

fn uuid_simple() -> String {
    CrawlRunId::new().0.simple().to_string()
}

impl Env {
    async fn run(&self, roles: &[&str], runs: u8) -> CrawlRun {
        let run = crawl_run(self.tenant, create_crawl("https://example.test/", roles, runs));
        self.pg.create(&run, None).await.expect("create run");
        run
    }

    /// A run with one pending session that has been claimed (running).
    async fn running_session(&self, run: &CrawlRun, n_roles: u16, runs: u16) -> Vec<SessionLeaseView> {
        let ss = sessions(run.id, n_roles, runs);
        self.pg.create_sessions(&ss).await.expect("sessions");
        let mut out = Vec::new();
        for _ in &ss {
            let lease = self
                .pg
                .claim_session(run.id, WorkerId::new(), true)
                .await
                .expect("claim")
                .expect("a lease");
            out.push(SessionLeaseView { lease });
        }
        out
    }

    async fn count(&self, sql: &str, run: CrawlRunId) -> i64 {
        sqlx::query_scalar(sql)
            .bind(run.0)
            .fetch_one(self.pg.pool())
            .await
            .expect("count")
    }

    async fn teardown(self) {
        self.pg.drop_schema().await.expect("drop schema");
    }
}

struct SessionLeaseView {
    lease: crawlx_storage::SessionLease,
}

macro_rules! env {
    () => {
        match setup().await {
            Some(e) => e,
            None => {
                eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
                return;
            }
        }
    };
}

fn epoch(n: u64, d: u64, m: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: n,
        document_seq: d,
        mutation_seq: m,
    }
}

#[tokio::test]
async fn replay_enqueue_is_atomic_and_leaseable() {
    let env = env!();
    let source = env.run(&[], 1).await;
    assert_eq!(env.pg.replay_spec(source.id).await.unwrap(), None);
    let replay = crawl_run(env.tenant, source.config.clone());
    let slots = sessions(replay.id, 1, 1);
    let spec = serde_json::json!({
        "sourceRunId": source.id,
        "actionIds": [crawlx_core::ActionId::new()],
        "transitionIds": [crawlx_core::TransitionId::new()],
        "role": "anonymous",
        "mode": "verify",
    });
    let mut invalid = slots.clone();
    let mut duplicate = slots[0].clone();
    duplicate.id = SessionId::new();
    invalid.push(duplicate);
    assert!(env.pg.create_replay(&replay, &invalid, &spec).await.is_err());
    assert_eq!(
        env.count("SELECT count(*) FROM crawl_runs WHERE run_id = $1", replay.id)
            .await,
        0
    );
    assert!(env.pg.list_sessions(replay.id).await.unwrap().is_empty());
    assert!(matches!(
        env.pg.claim_session(replay.id, WorkerId::new(), false).await,
        Err(StoreError::NotFound { entity: "crawl_run", id }) if id == replay.id.to_string()
    ));
    env.pg.create_replay(&replay, &slots, &spec).await.unwrap();
    let lease = env
        .pg
        .claim_session(replay.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.id, slots[0].id);
    assert_eq!(env.pg.replay_spec(replay.id).await.unwrap(), Some(spec.clone()));
    let row: (String, Option<uuid::Uuid>) =
        sqlx::query_as("SELECT run_kind, replay_of FROM crawl_runs WHERE run_id = $1")
            .bind(replay.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(row, ("replay".to_owned(), Some(source.id.0)));
    assert!(env.pg.create_replay(&replay, &slots, &spec).await.is_err());
    assert_eq!(RunRepo::get(&env.pg, source.id).await.unwrap(), source);
    env.teardown().await;
}

#[tokio::test]
async fn replay_enqueue_rejects_foreign_or_missing_sources_and_sessions() {
    let env = env!();
    let foreign = TenantId::new();
    env.pg.ensure_tenant(foreign, "foreign").await.unwrap();
    let source = crawl_run(foreign, create_crawl("https://example.test/", &[], 1));
    env.pg.create(&source, None).await.unwrap();
    let replay = crawl_run(env.tenant, source.config.clone());
    let slots = sessions(replay.id, 1, 1);
    for source_id in [source.id, CrawlRunId::new()] {
        let spec = serde_json::json!({"sourceRunId": source_id});
        assert!(matches!(
            env.pg.create_replay(&replay, &slots, &spec).await,
            Err(StoreError::NotFound { .. })
        ));
    }
    let source = env.run(&[], 1).await;
    let spec = serde_json::json!({"sourceRunId": source.id});
    assert!(env
        .pg
        .create_replay(&replay, &sessions(source.id, 1, 1), &spec)
        .await
        .is_err());
    assert!(matches!(
        RunRepo::get(&env.pg, replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        env.pg.replay_spec(replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    env.teardown().await;
}

#[tokio::test]
async fn migrations_apply_from_empty_and_are_idempotent() {
    let env = env!();
    env.pg.migrate().await.expect("second run is a no-op");
    let tables: Vec<String> = sqlx::query_scalar("SELECT table_name::text FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")
        .fetch_all(env.pg.pool())
        .await
        .unwrap();
    for t in [
        "tenants",
        "api_keys",
        "idempotency_keys",
        "authorization_records",
        "crawl_runs",
        "crawl_sessions",
        "url_frontier",
        "pages",
        "states",
        "state_clusters",
        "state_cluster_membership",
        "elements",
        "action_contexts",
        "actions",
        "transitions",
        "enablement_edges",
        "network_epochs",
        "traffic_events",
        "model_decisions",
        "identity_aliases",
        "safety_decisions",
        "approvals",
        "checkpoints",
        "workflow_runs",
        "artifacts",
        "crawl_events",
        "webhook_deliveries",
        "audit_events",
        "workers",
        "origin_leases",
    ] {
        assert!(
            tables.iter().any(|x| x == t),
            "missing table {t}; have {tables:?}"
        );
    }
    let session_cols: Vec<String> = sqlx::query_scalar("SELECT column_name::text FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'crawl_sessions'")
        .fetch_all(env.pg.pool())
        .await
        .unwrap();
    assert!(
        session_cols.contains(&"launch_profile".to_owned())
            && session_cols.contains(&"console_capture".to_owned())
    );
    let action_cols: Vec<String> = sqlx::query_scalar("SELECT column_name::text FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'actions'")
        .fetch_all(env.pg.pool())
        .await
        .unwrap();
    assert!(
        action_cols.contains(&"hold".to_owned()) && action_cols.contains(&"reconcile_resolution".to_owned())
    );
    let generated: Option<String> = sqlx::query_scalar("SELECT generation_expression FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'enablement_edges' AND column_name = 'p_success'")
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert!(generated.is_some(), "p_success is a generated column");
    env.teardown().await;
}

#[tokio::test]
#[allow(clippy::field_reassign_with_default)] // BufferLimits is non-exhaustive outside its crate.
async fn literal_controls_never_enter_postgres_config_and_expire_fail_closed() {
    let env = env!();
    let clock = Arc::new(crawlx_core::time::ManualClock::new(Utc::now()));
    let mut limits = crawlx_storage::BufferLimits::default();
    limits.ttl = std::time::Duration::from_secs(1);
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::new(clock.clone(), limits));
    let pg = env.pg.clone().with_delivery_buffer(buffer);
    let mut config = create_crawl("https://example.test/", &[], 1);
    config
        .fetch
        .extra_headers
        .insert("x-password", "pg-password-canary");
    config.fetch.extra_headers.insert("x-reference", "env://TOKEN");
    config
        .fetch
        .cookies
        .push(crawlx_core::request_controls::FetchCookie::new(
            "session",
            "pg-cookie-canary",
        ));
    let source = crawl_run(env.tenant, config.clone());
    pg.create(&source, None).await.unwrap();
    let replay = crawl_run(env.tenant, config.clone());
    pg.create_replay(
        &replay,
        &sessions(replay.id, 1, 1),
        &serde_json::json!({"sourceRunId": source.id}),
    )
    .await
    .unwrap();
    for run in [&source, &replay] {
        let stored: serde_json::Value = sqlx::query_scalar("SELECT config FROM crawl_runs WHERE run_id=$1")
            .bind(run.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
        let bytes = stored.to_string();
        assert!(!bytes.contains("pg-password-canary") && !bytes.contains("pg-cookie-canary"));
        assert_eq!(stored["fetch"]["extraHeaders"]["x-reference"], "env://TOKEN");
        assert_eq!(
            RunRepo::get(&pg, run.id).await.unwrap().config.fetch.cookies[0].value,
            "[redacted]"
        );
        assert_eq!(pg.get_for_execution(run.id).await.unwrap().config, config);
    }
    clock.advance_ms(2_000);
    for run in [&source, &replay] {
        assert!(RunRepo::get(&pg, run.id).await.is_ok());
        assert!(pg.get_metadata(run.id).await.is_ok());
        assert!(matches!(
            pg.get_for_execution(run.id).await,
            Err(StoreError::RetentionDenied(_))
        ));
    }
    env.teardown().await;
}

#[tokio::test]
async fn run_roundtrip_status_and_idempotency() {
    let env = env!();
    let run = env.run(&["admin", "member"], 2).await;
    assert_eq!(RunRepo::get(&env.pg, run.id).await.unwrap(), run);
    env.pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    assert!(RunRepo::get(&env.pg, run.id).await.unwrap().started_at.is_some());
    assert!(
        matches!(
            env.pg.set_status(run.id, RunStatus::Completed, None).await,
            Err(StoreError::Conflict(_))
        ),
        "terminal needs a reason"
    );
    env.pg
        .set_status(
            run.id,
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    assert!(matches!(
        env.pg.set_status(run.id, RunStatus::Running, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));

    let second = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    env.pg.create(&second, Some("key-1")).await.unwrap();
    let again = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    assert!(matches!(
        env.pg.create(&again, Some("key-1")).await,
        Err(StoreError::Conflict(_))
    ));
    let (found, _) = env
        .pg
        .lookup_idempotency(env.tenant, "key-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found, second.id);
    assert!(
        RunRepo::get(&env.pg, again.id).await.is_err(),
        "the failed create left no run behind"
    );

    let mut counters = run.counters;
    counters.urls.discovered = 3;
    counters.urls.admitted = 3;
    env.pg.update_counters(run.id, counters).await.unwrap();
    assert_eq!(
        RunRepo::get(&env.pg, run.id)
            .await
            .unwrap()
            .counters
            .urls
            .discovered,
        3
    );
    env.teardown().await;
}

#[tokio::test]
async fn sessions_roundtrip_with_browser_info() {
    let env = env!();
    let run = env.run(&["a"], 1).await;
    let ss = sessions(run.id, 1, 1);
    env.pg.create_sessions(&ss).await.unwrap();
    let info = crawlx_core::observation::BrowserBuildInfo {
        chromium_version: "130.0".to_owned(),
        cdp_revision: "r1".to_owned(),
        user_agent: "ua".to_owned(),
        pinned: true,
        launch_profile: crawlx_core::LaunchProfile::Standard,
        console_capture: true,
        attached: false,
    };
    env.pg.set_session_browser(ss[0].id, &info).await.unwrap();
    let listed = env.pg.list_sessions(run.id).await.unwrap();
    assert_eq!(listed[0].browser.as_ref(), Some(&info));
    env.pg
        .set_session_status(ss[0].id, SessionStatus::Cancelled)
        .await
        .unwrap();
    assert!(matches!(
        env.pg.set_session_status(ss[0].id, SessionStatus::Running).await,
        Err(StoreError::IllegalTransition { .. })
    ));
    assert!(matches!(
        env.pg.create_sessions(&sessions(CrawlRunId::new(), 1, 1)).await,
        Err(StoreError::NotFound { .. })
    ));
    env.teardown().await;
}

#[tokio::test]
async fn discover_dedupes_and_records_denials() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let u = canonical_url("https://example.test/a");
    let (o1, id1) = env.pg.discover(run.id, &u, 0, None, None).await.unwrap();
    assert_eq!((o1, id1.is_some()), (DiscoveryOutcome::Admitted, true));
    let (o2, id2) = env.pg.discover(run.id, &u, 1, id1, None).await.unwrap();
    assert_eq!((o2, id2), (DiscoveryOutcome::Duplicate, None));
    let blocked = canonical_url("https://example.test/admin");
    let (o3, _) = env
        .pg
        .discover(
            run.id,
            &blocked,
            1,
            id1,
            Some((FrontierStatus::PolicyBlocked, "deny-list".to_owned())),
        )
        .await
        .unwrap();
    assert_eq!(o3, DiscoveryOutcome::PolicyBlocked);
    let (o4, _) = env
        .pg
        .discover(
            run.id,
            &canonical_url("https://example.test/r"),
            1,
            id1,
            Some((FrontierStatus::RobotsBlocked, "robots".to_owned())),
        )
        .await
        .unwrap();
    assert_eq!(o4, DiscoveryOutcome::RobotsBlocked);
    assert!(env
        .pg
        .discover(
            run.id,
            &canonical_url("https://example.test/x"),
            1,
            None,
            Some((FrontierStatus::Failed, String::new()))
        )
        .await
        .is_err());
    assert_eq!(env.pg.pending_count(run.id).await.unwrap(), 1);
    let listed = FrontierRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(listed.len(), 3);
    assert_eq!(listed[0].url, u, "the canonical URL round-trips");
    assert_eq!(listed[1].status, FrontierStatus::PolicyBlocked);
    assert_eq!(listed[1].denial_reason.as_deref(), Some("deny-list"));

    // concurrent discovery of the same URL admits exactly once
    let shared = canonical_url("https://example.test/shared");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pg = env.pg.clone();
        let shared = shared.clone();
        let run = run.id;
        tasks.push(tokio::spawn(async move {
            pg.discover(run, &shared, 1, None, None).await.unwrap().0
        }));
    }
    let mut admitted = 0;
    for t in tasks {
        if t.await.unwrap() == DiscoveryOutcome::Admitted {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 1);
    env.teardown().await;
}

/// `CRAWLX_LEASE_CLAIMERS` / `CRAWLX_LEASE_ROWS` (64 claimers over
/// 100k rows in the scaled `chaos-weekly` variant; 8 / 60 by default).
fn lease_scale() -> (usize, usize) {
    let env = |name: &str, default: usize| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    (env("CRAWLX_LEASE_CLAIMERS", 8), env("CRAWLX_LEASE_ROWS", 60))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frontier_lease_is_exclusive_across_claimers() {
    let env = env!();
    let (claimers, rows) = lease_scale();
    let run = env.run(&[], 1).await;
    // discovery in 16 lanes: 100k single-row inserts would otherwise dominate the test
    let started = std::time::Instant::now();
    let mut lanes = tokio::task::JoinSet::new();
    for lane in 0..16usize {
        let pg = env.pg.clone();
        let run = run.id;
        lanes.spawn(async move {
            for i in (lane..rows).step_by(16) {
                pg.discover(
                    run,
                    &canonical_url(&format!("https://example.test/p{i}")),
                    1,
                    None,
                    None,
                )
                .await
                .unwrap();
            }
        });
    }
    while let Some(r) = lanes.join_next().await {
        r.unwrap();
    }
    let discovered = started.elapsed();
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..claimers {
        let pg = env.pg.clone();
        let run = run.id;
        tasks.push(tokio::spawn(async move {
            let worker = WorkerId::new();
            let mut mine = Vec::new();
            let mut calls = 0u64;
            loop {
                let batch = pg.lease_batch_fenced(run, worker, 4).await.unwrap();
                calls += 1;
                if batch.is_empty() {
                    break;
                }
                mine.extend(batch.into_iter().map(|(e, t)| (e.id, t)));
            }
            (mine, calls)
        }));
    }
    let mut all = Vec::new();
    let mut calls = 0u64;
    for t in tasks {
        let (mine, n) = t.await.unwrap();
        all.extend(mine);
        calls += n;
    }
    let leased = started.elapsed();
    let ids: BTreeSet<i64> = all.iter().map(|(i, _)| *i).collect();
    let tokens: BTreeSet<i64> = all.iter().map(|(_, t)| *t).collect();
    let duplicates = all.len() - ids.len();
    eprintln!(
        "lease scale: {claimers} claimers, {rows} rows: discovered in {discovered:?}, leased in {leased:?} \
         ({calls} lease calls, {:.3} ms per call), duplicates = {duplicates}",
        leased.as_secs_f64() * 1000.0 / calls as f64
    );
    assert_eq!(all.len(), rows, "every row leased");
    assert_eq!(duplicates, 0, "no row leased twice");
    assert_eq!(tokens.len(), rows, "fencing tokens are unique");

    // fenced completion: a stale token cannot complete a re-leased row
    let (id, token) = all[0];
    assert!(matches!(
        env.pg
            .complete_fenced(id, token + 10_000, FrontierStatus::Succeeded, None)
            .await,
        Err(StoreError::LeaseLost)
    ));
    env.pg
        .complete_fenced(id, token, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(matches!(
        env.pg.complete(id, FrontierStatus::Failed, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));
    env.teardown().await;
}

#[tokio::test]
async fn frontier_reap_requeues_then_fails_after_max_attempts() {
    let env = env!();
    let run = env.run(&[], 1).await;
    env.pg
        .discover(run.id, &canonical_url("https://example.test/a"), 0, None, None)
        .await
        .unwrap();
    let w = WorkerId::new();
    for attempt in 1..=2u16 {
        let batch = env.pg.lease_batch(run.id, w, 1).await.unwrap();
        assert_eq!(batch[0].attempts, attempt);
        let r = env
            .pg
            .reap_frontier(Utc::now() + Duration::seconds(120), 2)
            .await
            .unwrap();
        assert_eq!((r.requeued, r.failed), if attempt < 2 { (1, 0) } else { (0, 1) });
    }
    assert_eq!(
        FrontierRepo::list(&env.pg, run.id).await.unwrap()[0].status,
        FrontierStatus::Failed
    );

    env.pg
        .discover(run.id, &canonical_url("https://example.test/b"), 0, None, None)
        .await
        .unwrap();
    let b = env.pg.lease_batch_fenced(run.id, w, 1).await.unwrap();
    assert!(env
        .pg
        .retry_fenced(b[0].0.id, b[0].1, Utc::now() + Duration::seconds(360))
        .await
        .unwrap());
    assert!(
        env.pg.lease_batch(run.id, w, 1).await.unwrap().is_empty(),
        "backoff delays the retry"
    );
    env.teardown().await;
}

#[tokio::test]
async fn t1_t2_round_trip() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let leases = env.running_session(&run, 1, 1).await;
    let session = leases[0].lease.session.id;
    let cluster = StateClusterId::new();
    let before = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    env.pg.put_state(&before).await.unwrap();
    env.pg.put_state(&before).await.unwrap(); // idempotent

    let p = proposal("anonymous", cluster, 1);
    let v = allow_verdict();
    let id = env.pg.propose(run.id, session, &p, &v).await.unwrap();
    let rec = ActionJournal::get(&env.pg, id).await.unwrap();
    assert_eq!((rec.status, rec.attempt, rec.seq), (ActionStatus::Proposed, 0, 1));
    assert_eq!(rec.key, p.key);
    assert_eq!(rec.lane, Some(Fidelity::ScriptedNavigation.lane()));
    assert_eq!(
        env.pg
            .eligible_actions(run.id, Some(session), 10)
            .await
            .unwrap()
            .len(),
        1
    );

    env.pg.intend(id, session, epoch(1, 1, 3)).await.unwrap();
    let rec = ActionJournal::get(&env.pg, id).await.unwrap();
    assert_eq!(rec.status, ActionStatus::Intended);
    assert_eq!(
        rec.before_state,
        Some(before.id),
        "T1 pins the newest state not newer than the epoch"
    );
    assert!(
        env.pg
            .eligible_actions(run.id, Some(session), 10)
            .await
            .unwrap()
            .is_empty(),
        "intended is not schedulable"
    );
    assert!(matches!(
        env.pg.intend(id, session, epoch(1, 1, 3)).await,
        Err(StoreError::IllegalTransition { .. })
    ));

    let after = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    let now = Utc::now();
    let outcome = OutcomeRecord {
        status: ActionStatus::Succeeded,
        receipt: Some(ActionReceipt {
            network_epoch: NetworkEpochId::new(),
            fidelity: Fidelity::ScriptedNavigation,
            lane: Fidelity::ScriptedNavigation.lane(),
            started_at: now,
            finished_at: now,
        }),
        settle: Some(SettleReport {
            waited_ms: 12,
            network_idle: true,
            mutation_idle: true,
            navigation_settled: true,
            settle_timeout: false,
            postcondition: None,
            ..SettleReport::default()
        }),
        after_state: Some(after.clone()),
        traffic: (0..2)
            .map(|i| TrafficEvent {
                seq: i,
                epoch_id: None,
                unattributed_reason: None,
                origin: TrafficOrigin::Page,
                method: "GET".to_owned(),
                url: format!("https://example.test/api/{i}?x=1"),
                status: Some(200),
                request_headers: vec![("accept".to_owned(), "*/*".to_owned())],
                response_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                request_body: None,
                response_body: Some(ArtifactRef {
                    id: ArtifactId::new(),
                    digest: Digest::of("t", b"b"),
                }),
                third_party: false,
                late: false,
                protocol: None,
                started_at: now,
                finished_at: Some(now),
            })
            .collect(),
        error: None,
        finished_at: now,
    };
    env.pg.finish(id, outcome).await.unwrap();

    let rec = ActionJournal::get(&env.pg, id).await.unwrap();
    assert_eq!(rec.status, ActionStatus::Succeeded);
    assert_eq!(
        env.count("SELECT count(*) FROM transitions WHERE run_id = $1", run.id)
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM network_epochs WHERE run_id = $1", run.id)
            .await,
        1
    );
    assert_eq!(
        env.count("SELECT count(*) FROM traffic_events WHERE run_id = $1", run.id)
            .await,
        2
    );
    assert_eq!(
        env.count("SELECT count(*) FROM states WHERE run_id = $1", run.id)
            .await,
        2
    );
    assert_eq!(env.count("SELECT count(*) FROM state_cluster_membership m JOIN states s ON s.state_id = m.state_id WHERE s.run_id = $1", run.id).await, 2);
    let unique_ops: i32 =
        sqlx::query_scalar("SELECT unique_operations FROM network_epochs WHERE run_id = $1")
            .bind(run.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(unique_ops, 2);
    let t_after: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT after_state_id FROM transitions WHERE run_id = $1")
            .bind(run.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(t_after, Some(after.id.0));

    let states = env.pg.list_states(run.id).await.unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].signature, before.signature);
    assert_eq!(states[0].url, before.url);
    assert!(states[0].cluster_is_new && !states[1].cluster_is_new);
    let clusters = env.pg.list_clusters(run.id).await.unwrap();
    assert_eq!(clusters.len(), 1);
    assert_eq!((clusters[0].0, clusters[0].2), (cluster, 2));

    let ledger = LedgerRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(
        (
            ledger[0].trusted_exercised,
            ledger[0].diagnostic_exercised,
            ledger[0].failures
        ),
        (0, 1, 0),
        "scripted navigation is the diagnostic lane"
    );
    let events = env.pg.list_after(run.id, 0, 10).await.unwrap();
    assert_eq!(
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        vec!["action.finished"]
    );
    assert_eq!(events[0].seq, 1);
    assert!(
        matches!(
            env.pg.finish(id, outcome_failed()).await,
            Err(StoreError::IllegalTransition { .. })
        ),
        "a finished action cannot finish again"
    );
    env.teardown().await;
}

fn outcome_failed() -> OutcomeRecord {
    OutcomeRecord {
        status: ActionStatus::Failed,
        receipt: None,
        settle: None,
        after_state: None,
        traffic: Vec::new(),
        error: Some("boom".to_owned()),
        finished_at: Utc::now(),
    }
}

#[tokio::test]
async fn status_trigger_rejects_proposed_to_succeeded() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let leases = env.running_session(&run, 1, 1).await;
    let session = leases[0].lease.session.id;
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();

    let err = sqlx::query("UPDATE actions SET status = 'succeeded' WHERE action_id = $1")
        .bind(id.0)
        .execute(env.pg.pool())
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("illegal actions.status transition proposed -> succeeded"),
        "{err}"
    );

    let err = env.pg.finish(id, outcome_failed()).await.unwrap_err();
    assert!(
        matches!(err, StoreError::IllegalTransition { ref from, ref to } if from == "proposed" && to == "failed"),
        "{err:?}"
    );

    // every illegal edge of the machine is rejected by the trigger, every legal one accepted
    let all = [
        ActionStatus::Proposed,
        ActionStatus::Intended,
        ActionStatus::Succeeded,
        ActionStatus::Failed,
        ActionStatus::Unknown,
        ActionStatus::Reconciled,
    ];
    for from in all {
        for to in all {
            if from == to || (from == ActionStatus::Reconciled && to == ActionStatus::Intended) {
                continue; // identity is a no-op; reconciled -> intended needs the attempt bump, tested via intend()
            }
            let id = env
                .pg
                .propose(
                    run.id,
                    session,
                    &proposal("anonymous", StateClusterId::new(), 7),
                    &allow_verdict(),
                )
                .await
                .unwrap();
            // walk to `from` with raw updates along a legal path
            let path: &[&str] = match from {
                ActionStatus::Proposed => &[],
                ActionStatus::Intended => &["intended"],
                ActionStatus::Succeeded => &["intended", "succeeded"],
                ActionStatus::Failed => &["intended", "failed"],
                ActionStatus::Unknown => &["intended", "unknown"],
                ActionStatus::Reconciled => &["intended", "unknown", "reconciled"],
            };
            for step in path {
                sqlx::query("UPDATE actions SET status = $2::text::action_status WHERE action_id = $1")
                    .bind(id.0)
                    .bind(*step)
                    .execute(env.pg.pool())
                    .await
                    .unwrap();
            }
            let res = sqlx::query("UPDATE actions SET status = $2::text::action_status WHERE action_id = $1")
                .bind(id.0)
                .bind(to.as_str())
                .execute(env.pg.pool())
                .await;
            assert_eq!(res.is_ok(), from.can_transition_to(to), "{from:?} -> {to:?}");
        }
    }
    env.teardown().await;
}

#[tokio::test]
async fn mark_unknown_only_touches_expired_leases() {
    let env = env!();
    let run = env.run(&["a", "b"], 1).await;
    let leases = env.running_session(&run, 2, 1).await;
    let (sa, sb) = (leases[0].lease.session.id, leases[1].lease.session.id);
    let cluster = StateClusterId::new();
    let mut ids = Vec::new();
    for (s, n) in [(sa, 1), (sb, 2)] {
        let id = env
            .pg
            .propose(run.id, s, &proposal("anonymous", cluster, n), &allow_verdict())
            .await
            .unwrap();
        env.pg.intend(id, s, epoch(1, 1, 0)).await.unwrap();
        ids.push(id);
    }
    // expire only session a's lease
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 minute' WHERE session_id = $1",
    )
    .bind(sa.0)
    .execute(env.pg.pool())
    .await
    .unwrap();
    let flipped = env.pg.mark_unknown(Utc::now()).await.unwrap();
    assert_eq!(flipped, vec![ids[0]]);
    assert_eq!(
        ActionJournal::get(&env.pg, ids[0]).await.unwrap().status,
        ActionStatus::Unknown
    );
    assert_eq!(
        ActionJournal::get(&env.pg, ids[1]).await.unwrap().status,
        ActionStatus::Intended,
        "live lease untouched"
    );
    assert!(
        env.pg.mark_unknown(Utc::now()).await.unwrap().is_empty(),
        "idempotent"
    );
    // unknown is never rescheduled and is reconciled only through `reconcile`
    assert!(env
        .pg
        .eligible_actions(run.id, None, 10)
        .await
        .unwrap()
        .is_empty());
    env.teardown().await;
}

#[tokio::test]
async fn reaper_flow_recover_reconcile_and_retry() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let lease = env.running_session(&run, 1, 1).await.remove(0).lease;
    let session = lease.session.id;
    let cluster = StateClusterId::new();
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(id, session, epoch(1, 1, 0)).await.unwrap();

    // the holder dies: lease expires, reap marks the session recovering (never pending) and the action unknown
    let report = env.pg.reap(Utc::now() + Duration::seconds(300)).await.unwrap();
    assert_eq!(report.sessions_recovering, vec![session]);
    assert_eq!(report.actions_unknown, vec![id]);
    assert_eq!(
        env.pg.list_sessions(run.id).await.unwrap()[0].status,
        SessionStatus::Recovering
    );
    assert!(
        matches!(env.pg.heartbeat(&lease).await, Err(StoreError::LeaseLost)),
        "the old holder is fenced"
    );
    assert!(matches!(
        env.pg.release(&lease, SessionStatus::Completed).await,
        Err(StoreError::LeaseLost)
    ));

    // a new worker re-claims the recovering session; it stays recovering until reconciliation is done
    let w2 = WorkerId::new();
    let l2 = env
        .pg
        .claim_session(run.id, w2, false)
        .await
        .unwrap()
        .expect("recovering session is re-claimable");
    assert_eq!(l2.session.status, SessionStatus::Recovering);
    assert!(l2.fencing_token > lease.fencing_token);
    assert!(
        env.pg
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .is_none(),
        "live lease is exclusive"
    );
    env.pg.heartbeat(&l2).await.unwrap();

    env.pg
        .reconcile(
            id,
            Reconciliation {
                resolution: ReconcileResolution::NotApplied,
                evidence: serde_json::json!({"probe": "absent"}),
                reconciled_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, id).await.unwrap().status,
        ActionStatus::Reconciled
    );
    assert_eq!(
        env.pg.eligible_actions(run.id, None, 10).await.unwrap().len(),
        1,
        "not_applied is re-eligible"
    );
    env.pg
        .set_session_status(session, SessionStatus::Running)
        .await
        .unwrap();
    env.pg.intend(id, session, epoch(1, 1, 0)).await.unwrap();
    let rec = ActionJournal::get(&env.pg, id).await.unwrap();
    assert_eq!(
        (rec.status, rec.attempt),
        (ActionStatus::Intended, 1),
        "attempt increments after not_applied"
    );
    assert!(
        matches!(
            env.pg
                .reconcile(
                    id,
                    Reconciliation {
                        resolution: ReconcileResolution::Applied,
                        evidence: serde_json::json!({}),
                        reconciled_at: Utc::now()
                    }
                )
                .await,
            Err(StoreError::IllegalTransition { .. })
        ),
        "intended cannot be reconciled directly"
    );

    // `applied` and `indeterminate` are never re-eligible
    for resolution in [ReconcileResolution::Applied, ReconcileResolution::Indeterminate] {
        let other = env
            .pg
            .propose(
                run.id,
                session,
                &proposal("anonymous", cluster, 9),
                &allow_verdict(),
            )
            .await
            .unwrap();
        env.pg.intend(other, session, epoch(1, 1, 0)).await.unwrap();
        sqlx::query("UPDATE actions SET status = 'unknown' WHERE action_id = $1")
            .bind(other.0)
            .execute(env.pg.pool())
            .await
            .unwrap();
        env.pg
            .reconcile(
                other,
                Reconciliation {
                    resolution,
                    evidence: serde_json::json!({}),
                    reconciled_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        assert!(
            !env.pg
                .eligible_actions(run.id, None, 10)
                .await
                .unwrap()
                .iter()
                .any(|a| a.id == other),
            "{resolution:?}"
        );
        assert!(matches!(
            env.pg.intend(other, session, epoch(1, 1, 0)).await,
            Err(StoreError::IllegalTransition { .. })
        ));
    }
    env.teardown().await;
}

#[tokio::test]
async fn held_actions_cannot_be_intended() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let denied = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &verdict(SafetyDecision::Deny),
        )
        .await
        .unwrap();
    assert!(matches!(
        env.pg.intend(denied, session, epoch(1, 1, 0)).await,
        Err(StoreError::Conflict(_))
    ));
    assert!(env
        .pg
        .eligible_actions(run.id, None, 10)
        .await
        .unwrap()
        .is_empty());
    let decision: String = sqlx::query_scalar("SELECT verdict FROM safety_decisions WHERE action_id = $1")
        .bind(denied.0)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert_eq!(decision, "deny");
    env.teardown().await;
}

/// Span-to-row join: a run records the trace id of its `crawl` span, an action
/// proposed inside a span tree carries that tree's trace id, and rows written outside any
/// span have none.
#[tokio::test]
async fn trace_ids_join_runs_and_actions_to_their_span() {
    use tracing::Instrument as _;

    let env = env!();
    let run = env.run(&[], 1).await;
    assert_eq!(RunRepo::get(&env.pg, run.id).await.unwrap().trace_id, None);
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let cluster = StateClusterId::new();
    let bare = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, bare).await.unwrap().trace_id,
        None,
        "no span, no trace"
    );

    let telemetry = crawlx_telemetry::TelemetryConfig {
        filter: Some("info".to_owned()),
        ..crawlx_telemetry::TelemetryConfig::default()
    };
    let _guard = tracing::subscriber::set_default(
        crawlx_telemetry::build_subscriber(&telemetry, std::io::sink).unwrap(),
    );
    let crawl = tracing::info_span!("crawl");
    let trace = crawlx_telemetry::trace_id::trace_id_of(&crawl).unwrap();
    env.pg.set_trace_id(run.id, trace).await.unwrap();
    env.pg.set_trace_id(run.id, trace).await.unwrap(); // idempotent
    assert_eq!(RunRepo::get(&env.pg, run.id).await.unwrap().trace_id, Some(trace));
    let traced = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 2),
            &allow_verdict(),
        )
        .instrument(crawl)
        .await
        .unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, traced).await.unwrap().trace_id,
        Some(trace)
    );
    let listed = ActionJournal::list(&env.pg, run.id, None).await.unwrap();
    assert_eq!(
        listed.iter().map(|a| (a.id, a.trace_id)).collect::<Vec<_>>(),
        vec![(bare, None), (traced, Some(trace))]
    );
    assert!(matches!(
        env.pg.set_trace_id(CrawlRunId::new(), trace).await,
        Err(StoreError::NotFound { .. })
    ));
    let malformed = sqlx::query("UPDATE actions SET trace_id = 'not-hex' WHERE action_id = $1")
        .bind(bare.0)
        .execute(env.pg.pool())
        .await;
    assert!(
        malformed.is_err(),
        "the CHECK constraint rejects a malformed trace id"
    );
    env.teardown().await;
}

#[tokio::test]
async fn round_robin_barrier_never_grants_a_higher_slot_early() {
    let env = env!();
    let run = env.run(&["a", "b", "c"], 2).await;
    env.pg.create_sessions(&sessions(run.id, 3, 2)).await.unwrap();

    // eight concurrent claimers on a fresh run: exactly slot 0 is granted
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pg = env.pg.clone();
        let run = run.id;
        tasks.push(tokio::spawn(async move {
            pg.claim_session(run, WorkerId::new(), false).await.unwrap()
        }));
    }
    let mut granted = Vec::new();
    for t in tasks {
        if let Some(l) = t.await.unwrap() {
            granted.push(l);
        }
    }
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].session.schedule_slot, 0);

    let mut current = granted.remove(0);
    for expected_slot in 1..6u32 {
        assert!(
            env.pg
                .claim_session(run.id, WorkerId::new(), false)
                .await
                .unwrap()
                .is_none(),
            "slot {expected_slot} waits for slot {}",
            expected_slot - 1
        );
        // a recovering predecessor also blocks
        env.pg.release(&current, SessionStatus::Completed).await.unwrap();
        let next = env
            .pg
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .expect("next slot");
        assert_eq!(next.session.schedule_slot, expected_slot);
        current = next;
    }
    env.pg.release(&current, SessionStatus::Failed).await.unwrap();
    assert!(env
        .pg
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .is_none());

    // with the barrier lifted all slots are grantable at once
    let par = env.run(&["a", "b"], 1).await;
    env.pg.create_sessions(&sessions(par.id, 2, 1)).await.unwrap();
    assert!(env
        .pg
        .claim_session(par.id, WorkerId::new(), true)
        .await
        .unwrap()
        .is_some());
    assert!(env
        .pg
        .claim_session(par.id, WorkerId::new(), true)
        .await
        .unwrap()
        .is_some());
    let active = env.pg.active_runs().await.unwrap();
    assert!(active.is_empty(), "no pending sessions left anywhere: {active:?}");
    env.teardown().await;
}

#[tokio::test]
async fn session_claims_skip_live_prefixes_and_locked_serial_heads() {
    let env = env!();
    let run = env.run(&["a"], 1).await;
    let sessions = sessions(run.id, 1, 4096);
    env.pg.create_sessions(&sessions).await.unwrap();
    sqlx::query(
        "UPDATE crawl_sessions SET status = CASE WHEN schedule_slot % 2 = 0 THEN 'running' ELSE 'recovering' END, \
         lease_expires_at = now() + interval '1 hour' WHERE run_id = $1 AND schedule_slot < 4095",
    )
    .bind(run.id.0)
    .execute(env.pg.pool())
    .await
    .unwrap();
    sqlx::query("ANALYZE crawl_sessions")
        .execute(env.pg.pool())
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN SELECT c.session_id FROM crawl_sessions c \
         WHERE c.run_id = $1 AND c.status IN ('pending','recovering') \
           AND COALESCE(c.lease_expires_at, '-infinity'::timestamptz) < now() \
         ORDER BY COALESCE(c.lease_expires_at, '-infinity'::timestamptz), c.schedule_slot \
         LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .bind(run.id.0)
    .fetch_all(env.pg.pool())
    .await
    .unwrap();
    assert!(
        plan.iter().any(|line| line.contains("crawl_sessions_ready")),
        "{plan:?}"
    );
    assert!(!plan.iter().any(|line| line.contains("Sort")), "{plan:?}");
    assert!(env
        .pg
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .is_none());
    let lease = env
        .pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.schedule_slot, 4095);
    assert!(env
        .pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .is_none());

    // A locked pending head cannot let a serial claimant skip to its successor.
    let serial = env.run(&["a"], 2).await;
    let serial_sessions = crawlx_storage::testkit::sessions(serial.id, 1, 2);
    env.pg.create_sessions(&serial_sessions).await.unwrap();
    let mut tx = env.pg.pool().begin().await.unwrap();
    sqlx::query("SELECT session_id FROM crawl_sessions WHERE session_id = $1 FOR UPDATE")
        .bind(serial_sessions[0].id.0)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(env
        .pg
        .claim_session(serial.id, WorkerId::new(), false)
        .await
        .unwrap()
        .is_none());
    let parallel = env
        .pg
        .claim_session(serial.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parallel.session.schedule_slot, 1);
    tx.rollback().await.unwrap();

    // Expired recovering rows remain eligible and receive a fresh fence.
    sqlx::query(
        "UPDATE crawl_sessions SET lease_expires_at = now() - interval '1 second' \
         WHERE session_id = $1",
    )
    .bind(sessions[1].id.0)
    .execute(env.pg.pool())
    .await
    .unwrap();
    let recovery = env
        .pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovery.session.id, sessions[1].id);
    assert_eq!(recovery.session.status, SessionStatus::Recovering);
    assert!(recovery.fencing_token > lease.fencing_token);
    assert!(env
        .pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .is_none());
    env.teardown().await;
}

#[tokio::test]
async fn release_to_recovering_flips_intended_actions() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let lease = env.running_session(&run, 1, 1).await.remove(0).lease;
    let session = lease.session.id;
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(id, session, epoch(1, 1, 0)).await.unwrap();
    assert!(env.pg.release(&lease, SessionStatus::Pending).await.is_err());
    env.pg.release(&lease, SessionStatus::Recovering).await.unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, id).await.unwrap().status,
        ActionStatus::Unknown
    );
    let again = env
        .pg
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap();
    assert!(
        again.is_some(),
        "graceful release makes the session immediately re-claimable"
    );
    env.teardown().await;
}

#[tokio::test]
async fn route_coarsened_contexts_persist_an_explicit_flag_and_stable_key() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let mut key = proposal("anonymous", StateClusterId::new(), 1).key;
    key.state_cluster = key.coarsened_cluster();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap();
    let row = LedgerRow {
        key: key.clone(),
        trusted_exercised: 0,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: now,
        last_exercised: None,
    };
    LedgerRepo::upsert(&env.pg, run.id, &row).await.unwrap();
    LedgerRepo::upsert(&env.pg, run.id, &row).await.unwrap();
    let stored: bool =
        sqlx::query_scalar("SELECT coarsened FROM action_contexts WHERE run_id = $1 AND context_hash = $2")
            .bind(run.id.0)
            .bind(key.id().0.to_vec())
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert!(stored, "coarsening must not be silent in durable coverage rows");
    let rows = LedgerRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(rows, vec![row]);
    assert!(rows[0].key.is_coarsened());
    let corpus = crawlx_storage::TrustedCorpus::new(env.pg.clone());
    let coverage = corpus.coverage(run.id).await.unwrap();
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].key, key);
    assert_eq!(
        coverage[0].trusted_exercised, 0,
        "a discovered coarsened key is not an exercised context"
    );
    env.teardown().await;
}

#[tokio::test]
async fn pages_edges_ledger_events_and_audit_roundtrip() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let u = canonical_url("https://example.test/a");
    let (_, fid) = env.pg.discover(run.id, &u, 0, None, None).await.unwrap();
    let page = PageRecord {
        run: run.id,
        frontier_id: fid.unwrap(),
        url: u.clone(),
        status: 200,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", b"c"),
        title: Some("Title".to_owned()),
        markdown: Some(ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("t", b"m"),
        }),
        html: None,
        metadata: serde_json::json!({"og:title": "x"}),
        links: vec!["https://example.test/b".to_owned()],
        fetched_at: Utc::now(),
        lane: crawlx_core::TrustLane::Diagnostic,
    };
    PageRepo::put(&env.pg, &page).await.unwrap();
    PageRepo::put(&env.pg, &page).await.unwrap(); // upsert
    let pages = PageRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(
        (pages[0].title.as_deref(), pages[0].status, &pages[0].links),
        (Some("Title"), 200, &page.links)
    );
    assert_eq!(pages[0].markdown, page.markdown);
    assert_eq!(pages[0].url, u);

    // ledger absolute upsert + edge upsert keyed on the ledger context
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let p = proposal("anonymous", StateClusterId::new(), 1);
    let now = Utc::now();
    let row = LedgerRow {
        key: p.key.clone(),
        trusted_exercised: 2,
        diagnostic_exercised: 1,
        failures: 1,
        first_seen: now,
        last_exercised: Some(now),
    };
    LedgerRepo::upsert(&env.pg, run.id, &row).await.unwrap();
    LedgerRepo::upsert(&env.pg, run.id, &row).await.unwrap();
    let listed = LedgerRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].trusted_exercised,
            listed[0].diagnostic_exercised,
            listed[0].failures
        ),
        (2, 1, 1)
    );
    assert_eq!(listed[0].key, p.key);

    let edge = EdgeRecord {
        id: crawlx_core::EdgeId::new(),
        run: run.id,
        source: p.key.id(),
        context_cluster: None,
        target: p.key.element,
        support: 3,
        weak_support: 2,
        failures: 1,
        latency_ms_ewma: 12.5,
        risk: 0.25,
        last_observed_at: now,
        last_verified_build: Some("130".to_owned()),
    };
    EdgeStore::upsert(&env.pg, &edge).await.unwrap();
    let mut edge2 = edge.clone();
    edge2.id = crawlx_core::EdgeId::new();
    edge2.support = 4;
    EdgeStore::upsert(&env.pg, &edge2).await.unwrap(); // same key (cluster NULL): one row
    let edges = EdgeStore::list(&env.pg, run.id).await.unwrap();
    assert_eq!(edges.len(), 1, "NULL cluster does not defeat the unique key");
    assert_eq!(
        (edges[0].id, edges[0].support, edges[0].weak_support),
        (edge.id, 4, 2)
    );
    let p_success: f64 = sqlx::query_scalar("SELECT p_success FROM enablement_edges WHERE run_id = $1")
        .bind(run.id.0)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert!(
        (p_success - (4.0 + 1.0 + 1.0) / (4.0 + 1.0 + 1.0 + 2.0)).abs() < 1e-9,
        "{p_success}"
    );
    let mut orphan = edge.clone();
    orphan.source = proposal("other", StateClusterId::new(), 99).key.id();
    assert!(matches!(
        EdgeStore::upsert(&env.pg, &orphan).await,
        Err(StoreError::NotFound { .. })
    ));

    // events: monotonic per run
    for i in 0..3 {
        assert_eq!(
            env.pg
                .append(run.id, "k", serde_json::json!({ "i": i }))
                .await
                .unwrap(),
            i + 1
        );
    }
    let page2 = env.pg.list_after(run.id, 1, 10).await.unwrap();
    assert_eq!(page2.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);

    // safety audit
    let v = verdict(SafetyDecision::Deny);
    SafetyAudit::record(&env.pg, run.id, session, &v, "denied: out of scope")
        .await
        .unwrap();
    SafetyAudit::record(&env.pg, run.id, session, &v, "again")
        .await
        .unwrap(); // idempotent on decision id
    assert_eq!(
        env.count("SELECT count(*) FROM safety_decisions WHERE run_id = $1", run.id)
            .await,
        1
    );
    env.teardown().await;
}

#[tokio::test]
async fn zdr_write_gate_and_artifact_store() {
    let _guard = METRICS_LOCK.lock().await;
    let env = env!();
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Zdr;
    cfg.retention.days = 0;
    let zdr = crawl_run(env.tenant, cfg);
    env.pg.create(&zdr, None).await.unwrap();
    let standard = env.run(&[], 1).await;

    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(env.pg.clone());
    let fs = FsArtifactStore::open(dir.path(), runs.clone(), Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(env.pg.clone()));

    for class in [
        Sensitivity::Content,
        Sensitivity::Sensitive,
        Sensitivity::CredentialBearing,
    ] {
        assert!(
            matches!(
                fs.put(zdr.id, class, "text/html", b"x").await,
                Err(StoreError::RetentionDenied(_))
            ),
            "{class:?}"
        );
    }
    fs.put(zdr.id, Sensitivity::Metadata, "application/json", b"{}")
        .await
        .expect("metadata is allowed under zdr");

    let r = fs
        .put(standard.id, Sensitivity::Content, "text/markdown", b"# hello")
        .await
        .unwrap();
    assert_eq!(fs.get(&r).await.unwrap(), b"# hello");
    let key = format!("content/{}/{}/{}", env.tenant, standard.id, r.digest.to_hex());
    assert!(
        dir.path().join(&key).is_file(),
        "object lives at {{class}}/{{tenant}}/{{run}}/{{blake3}}"
    );
    let row_kind: String = sqlx::query_scalar("SELECT kind FROM artifacts WHERE artifact_id = $1")
        .bind(r.id.0)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert_eq!(row_kind, "markdown");

    // retention sweeper removes expired uses; shared objects survive until the last use is gone
    let r2 = fs
        .put(standard.id, Sensitivity::Content, "text/markdown", b"# hello")
        .await
        .unwrap();
    assert_ne!(r.id, r2.id);
    sqlx::query("UPDATE artifacts SET expires_at = now() - interval '1 hour' WHERE artifact_id = $1")
        .bind(r.id.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    // The database revokes the first use immediately; advancing also expires the second use.
    let sweeper = RetentionSweeper::new(env.pg.clone()).with_artifacts(Arc::new(fs));
    let report = sweeper.sweep(Utc::now() + Duration::days(8)).await.unwrap();
    assert!(report.artifacts_deleted >= 2);
    assert!(
        !dir.path().join(&key).exists(),
        "object removed once no use remains"
    );
    env.teardown().await;
}

/// RB-08: a non-metadata artifact row of a ZDR run (one that got past the write gate) is a
/// zero-data-retention violation. The sweeper counts it under `crawlx.zdr.violations` the
/// first time it sees the row, not again on the next sweep; the gate counts every refusal.
#[tokio::test]
async fn sweeper_counts_each_zdr_artifact_row_once() {
    let _guard = METRICS_LOCK.lock().await;
    let env = env!();
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Zdr;
    cfg.retention.days = 0;
    let zdr = crawl_run(env.tenant, cfg);
    env.pg.create(&zdr, None).await.unwrap();
    let violations = Metrics::global().counter(names::ZDR_VIOLATIONS);
    let before = violations.get(&[]);

    let mem = MemoryArtifactStore::in_memory(Arc::new(env.pg.clone()), Arc::new(SystemClock));
    assert!(matches!(
        mem.put(zdr.id, Sensitivity::Content, "text/html", b"x").await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert_eq!(violations.get(&[]), before + 1, "the gate counts its refusal");

    let sweeper = RetentionSweeper::new(env.pg.clone());
    sweeper.sweep(Utc::now()).await.unwrap();
    assert_eq!(
        violations.get(&[]),
        before + 1,
        "no zdr content row: nothing to count"
    );

    // a content row written behind the gate's back
    let rogue = ArtifactId::new();
    sqlx::query(
        "INSERT INTO artifacts (artifact_id, tenant_id, run_id, kind, bucket, object_key, size_bytes, content_digest, content_type, sensitivity) \
         VALUES ($1, $2, $3, 'html', 'fs', $4, 1, '\\x00'::bytea, 'text/html', 'content')",
    )
    .bind(rogue.0)
    .bind(env.tenant.0)
    .bind(zdr.id.0)
    .bind(format!("content/{}/{}/rogue", env.tenant, zdr.id))
    .execute(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(sweeper.zdr_violations().await.unwrap(), vec![rogue]);
    sweeper.sweep(Utc::now()).await.unwrap();
    assert_eq!(
        violations.get(&[]),
        before + 2,
        "the row is counted on first sight"
    );
    sweeper.sweep(Utc::now()).await.unwrap();
    assert_eq!(violations.get(&[]), before + 2, "and not again while it lingers");
    // a fresh sweeper has no memory of it
    RetentionSweeper::new(env.pg.clone())
        .sweep(Utc::now())
        .await
        .unwrap();
    assert_eq!(violations.get(&[]), before + 3);
    env.teardown().await;
}

/// Retention compliance test: an artifact past `expires_at` is counted by
/// `retention_overdue_artifacts` (the SQL behind `crawlx.retention.overdue_artifacts{kind}`)
/// until the sweeper runs; after the sweep the count and the gauge are 0 and the object is gone.
#[tokio::test]
async fn retention_overdue_artifacts_counts_until_the_sweeper_runs_then_zero() {
    let env = env!();
    let t0 = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
    let clock = Arc::new(crawlx_core::time::ManualClock::new(t0));
    let run = env.run(&[], 1).await; // standard retention, 7 days (testkit default)
    let days = i64::from(run.config.retention.days);
    assert!(days > 0, "the testkit run must have a finite retention");
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(env.pg.clone());
    let fs = FsArtifactStore::open(dir.path(), runs, clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(env.pg.clone()));
    let r = fs
        .put(run.id, Sensitivity::Content, "text/markdown", b"# overdue")
        .await
        .unwrap();
    let key = format!("content/{}/{}/{}", env.tenant, run.id, r.digest.to_hex());
    assert!(dir.path().join(&key).is_file());
    let sweeper = RetentionSweeper::new(env.pg.clone()).with_artifacts(Arc::new(fs));

    // before expiry nothing is overdue
    assert!(sweeper.overdue_artifacts(t0).await.unwrap().is_empty());

    // past expiry, before any sweep: the artifact is overdue and still present
    let later = t0 + Duration::days(days) + Duration::hours(1);
    clock.advance_ms((later - t0).num_milliseconds());
    let overdue = sweeper.overdue_artifacts(later).await.unwrap();
    assert_eq!(overdue.get("standard").copied(), Some(1), "{overdue:?}");
    assert!(dir.path().join(&key).is_file(), "not swept yet");

    // the sweep removes it; the count and the published gauge drop to 0
    let report = sweeper.sweep(later).await.unwrap();
    assert_eq!(report.artifacts_deleted, 1);
    assert!(!dir.path().join(&key).exists(), "object removed by the sweep");
    assert!(sweeper.overdue_artifacts(later).await.unwrap().is_empty());
    let gauge = crawlx_telemetry::Metrics::global()
        .gauge(crawlx_telemetry::metrics::names::RETENTION_OVERDUE_ARTIFACTS);
    for kind in ["standard", "extended", "zdr"] {
        assert_eq!(gauge.get(&[("kind", kind)]), Some(0.0), "{kind}");
    }
    assert_eq!(
        env.count(
            "SELECT count(*) FROM artifacts WHERE run_id = $1 AND deleted_at IS NULL",
            run.id
        )
        .await,
        0
    );
    env.teardown().await;
}

#[tokio::test]
async fn sweeper_purges_expired_runs_and_chains_the_audit_log() {
    let env = env!();
    let mut run = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    run.created_at = Utc::now() - Duration::days(30);
    run.status = RunStatus::Completed;
    run.terminal_reason = Some(TerminalReason::FrontierExhausted);
    env.pg.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    env.pg.create_sessions(&ss).await.unwrap();
    env.pg
        .discover(run.id, &canonical_url("https://example.test/a"), 0, None, None)
        .await
        .unwrap();
    env.pg.append(run.id, "k", serde_json::json!({})).await.unwrap();
    let fresh = env.run(&[], 1).await; // not expired: must survive
    let report = RetentionSweeper::new(env.pg.clone())
        .sweep(Utc::now())
        .await
        .unwrap();
    assert_eq!(report.runs_purged, 1);
    assert!(matches!(
        RunRepo::get(&env.pg, run.id).await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(
        env.count("SELECT count(*) FROM crawl_sessions WHERE run_id = $1", run.id)
            .await,
        0
    );
    assert_eq!(
        env.count("SELECT count(*) FROM url_frontier WHERE run_id = $1", run.id)
            .await,
        0
    );
    assert!(RunRepo::get(&env.pg, fresh.id).await.is_ok());
    let audit: Vec<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT prev_hash, entry_hash FROM audit_events ORDER BY audit_id")
            .fetch_all(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].0, vec![0u8; 32], "chain starts from the zero hash");
    env.teardown().await;
}

#[tokio::test]
async fn traffic_partitions_are_created_ahead_and_zdr_redacts_traffic() {
    let env = env!();
    let created = crawlx_storage::retention::ensure_traffic_partitions(&env.pg, Utc::now(), 3)
        .await
        .unwrap();
    assert!(
        created.len() <= 2,
        "migrate already created the current and next two months: {created:?}"
    );
    let again = crawlx_storage::retention::ensure_traffic_partitions(&env.pg, Utc::now(), 3)
        .await
        .unwrap();
    assert!(again.is_empty());

    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Zdr;
    cfg.retention.days = 0;
    let run = crawl_run(env.tenant, cfg);
    env.pg.create(&run, None).await.unwrap();
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(id, session, epoch(1, 1, 0)).await.unwrap();
    let now = Utc::now();
    let mut o = outcome_failed();
    o.status = ActionStatus::Succeeded;
    o.receipt = Some(ActionReceipt {
        network_epoch: NetworkEpochId::new(),
        fidelity: Fidelity::ScriptedNavigation,
        lane: crawlx_core::TrustLane::Diagnostic,
        started_at: now,
        finished_at: now,
    });
    o.traffic = vec![TrafficEvent {
        seq: 0,
        epoch_id: None,
        unattributed_reason: None,
        origin: TrafficOrigin::WebSocket,
        method: "GET".to_owned(),
        url: "https://example.test/secret?token=abc".to_owned(),
        status: Some(101),
        request_headers: vec![("authorization".to_owned(), "x".to_owned())],
        response_headers: vec![],
        request_body: None,
        response_body: None,
        third_party: true,
        late: false,
        protocol: None,
        started_at: now,
        finished_at: None,
    }];
    env.pg.finish(id, o).await.unwrap();
    let row: (Option<String>, Option<serde_json::Value>, String, i32) = sqlx::query_as(
        "SELECT url_redacted, request_headers, origin, status FROM traffic_events WHERE run_id = $1",
    )
    .bind(run.id.0)
    .fetch_one(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(
        (row.0, row.1, row.2.as_str(), row.3),
        (None, None, "websocket", 101)
    );
    env.teardown().await;
}

/// Migration 0010: a traffic row outside every epoch is legal only with an
/// explicit `unattributed_reason`; T2 rejects one without, and the verifier reads both
/// columns back through `TrailReads`.
#[tokio::test]
async fn traffic_without_an_epoch_needs_an_explicit_reason() {
    let env = env!();
    let run = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    env.pg.create(&run, None).await.unwrap();
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let now = Utc::now();
    let event = |reason| TrafficEvent {
        seq: 1,
        epoch_id: None,
        unattributed_reason: reason,
        origin: TrafficOrigin::FetchPlane,
        method: "GET".to_owned(),
        url: "https://example.test/sitemap.xml".to_owned(),
        status: Some(200),
        request_headers: vec![],
        response_headers: vec![],
        request_body: None,
        response_body: None,
        third_party: false,
        late: false,
        protocol: None,
        started_at: now,
        finished_at: Some(now),
    };

    // no receipt, no epoch, no reason: rejected before anything is written
    let bad = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(bad, session, epoch(1, 1, 0)).await.unwrap();
    let mut o = outcome_failed();
    o.traffic = vec![event(None)];
    assert!(matches!(
        env.pg.finish(bad, o).await,
        Err(StoreError::Conflict(msg)) if msg.contains("unattributed reason")
    ));
    assert_eq!(
        env.count("SELECT count(*) FROM traffic_events WHERE run_id = $1", run.id)
            .await,
        0
    );

    // with a reason the row lands with a NULL epoch
    let mut o = outcome_failed();
    o.traffic = vec![event(Some(UnattributedReason::NotApplicable))];
    env.pg.finish(bad, o).await.unwrap();
    let rows = TrailReads::new(env.pg.clone())
        .traffic_attribution(run.id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].epoch, None);
    assert_eq!(
        rows[0].unattributed_reason,
        Some(UnattributedReason::NotApplicable)
    );
    let decisions = TrailReads::new(env.pg.clone())
        .safety_decision_ids(run.id)
        .await
        .unwrap();
    assert_eq!(
        decisions.len(),
        1,
        "the propose() verdict has its safety_decisions row"
    );

    // under a trusted action, the receipt epoch attributes epoch-less events (lane trusted_ui)
    // while an explicitly unattributed one stays on the diagnostic lane
    let trusted = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 2),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(trusted, session, epoch(1, 1, 1)).await.unwrap();
    let mut o = outcome_failed();
    o.status = ActionStatus::Succeeded;
    let receipt_epoch = NetworkEpochId::new();
    o.receipt = Some(ActionReceipt {
        network_epoch: receipt_epoch,
        fidelity: Fidelity::NativePointer,
        lane: TrustLane::TrustedUi,
        started_at: now,
        finished_at: now,
    });
    let mut unattributed = event(Some(UnattributedReason::NotApplicable));
    unattributed.seq = 2;
    o.traffic = vec![event(None), unattributed];
    env.pg.finish(trusted, o).await.unwrap();
    let lanes: Vec<(Option<uuid::Uuid>, String)> = sqlx::query_as(
        "SELECT epoch_id, lane::text FROM traffic_events WHERE run_id = $1 AND epoch_id = $2 OR (run_id = $1 AND unattributed_reason IS NOT NULL AND seq = 2) ORDER BY seq",
    )
    .bind(run.id.0)
    .bind(receipt_epoch.0)
    .fetch_all(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(
        lanes,
        vec![
            (Some(receipt_epoch.0), "trusted_ui".to_owned()),
            (None, "diagnostic".to_owned())
        ]
    );
    env.teardown().await;
}

#[tokio::test]
async fn in_memory_artifact_store_enforces_the_same_gate() {
    let _guard = METRICS_LOCK.lock().await;
    let env = env!();
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Zdr;
    cfg.retention.days = 0;
    let zdr = crawl_run(env.tenant, cfg);
    env.pg.create(&zdr, None).await.unwrap();
    let mem = MemoryArtifactStore::in_memory(Arc::new(env.pg.clone()), Arc::new(SystemClock));
    assert!(matches!(
        mem.put(zdr.id, Sensitivity::Sensitive, "image/webp", b"png")
            .await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(mem.blobs().is_empty(), "a denied write leaves nothing behind");
    let _ = (PrincipalId::anonymous(), SessionId::new());
    env.teardown().await;
}

/// A succeeded outcome with a receipt at `fidelity`, `after` as the new state and one page request.
fn succeeded_outcome(fidelity: Fidelity, after: Option<NewState>, url: &str) -> OutcomeRecord {
    let now = Utc::now();
    OutcomeRecord {
        status: ActionStatus::Succeeded,
        receipt: Some(ActionReceipt {
            network_epoch: NetworkEpochId::new(),
            fidelity,
            lane: fidelity.lane(),
            started_at: now,
            finished_at: now,
        }),
        settle: Some(SettleReport::default()),
        after_state: after,
        traffic: vec![TrafficEvent {
            seq: 0,
            epoch_id: None,
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: url.to_owned(),
            status: Some(200),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: now,
            finished_at: Some(now),
        }],
        error: None,
        finished_at: now,
    }
}

#[tokio::test]
async fn trust_lane_constraints_reject_mismatch_and_mutation() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let leases = env.running_session(&run, 1, 1).await;
    let session = leases[0].lease.session.id;
    let cluster = StateClusterId::new();
    let s0 = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    env.pg.put_state(&s0).await.unwrap();

    // proposed as a scripted navigation (diagnostic); the executor's receipt says native pointer
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    // before T2 the lane is only a plan and may still change
    sqlx::query("UPDATE actions SET lane = 'trusted_ui', fidelity = 'native_keyboard' WHERE action_id = $1")
        .bind(id.0)
        .execute(env.pg.pool())
        .await
        .expect("lane is mutable before T2");
    env.pg.intend(id, session, epoch(1, 1, 3)).await.unwrap();
    let s1 = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    env.pg
        .finish(
            id,
            succeeded_outcome(Fidelity::NativePointer, Some(s1), "https://example.test/a"),
        )
        .await
        .unwrap();
    let rec = ActionJournal::get(&env.pg, id).await.unwrap();
    assert_eq!(
        (rec.fidelity, rec.lane),
        (Some(Fidelity::NativePointer), Some(TrustLane::TrustedUi)),
        "T2 records the receipt's fidelity and lane"
    );
    let epoch_lane: String = sqlx::query_scalar("SELECT lane::text FROM network_epochs WHERE action_id = $1")
        .bind(id.0)
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
    assert_eq!(epoch_lane, "trusted_ui");

    // an epoch whose lane differs from its action's lane cannot be inserted
    let r = sqlx::query(
        "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at) \
         VALUES ($1, $2, $3, $4, 'diagnostic', now())",
    )
    .bind(NetworkEpochId::new().0)
    .bind(run.id.0)
    .bind(session.0)
    .bind(id.0)
    .execute(env.pg.pool())
    .await;
    let msg = r.expect_err("lane mismatch").to_string();
    assert!(msg.contains("differs from actions.lane"), "{msg}");
    // an epoch's lane is immutable
    let r = sqlx::query("UPDATE network_epochs SET lane = 'diagnostic' WHERE action_id = $1")
        .bind(id.0)
        .execute(env.pg.pool())
        .await;
    let msg = r.expect_err("epoch lane immutable").to_string();
    assert!(
        msg.contains("network_epochs.lane is immutable") || msg.contains("differs from actions.lane"),
        "{msg}"
    );
    // ... also for an epoch that has no owning action
    let loose = NetworkEpochId::new();
    sqlx::query(
        "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at) \
         VALUES ($1, $2, $3, NULL, 'diagnostic', now())",
    )
    .bind(loose.0)
    .bind(run.id.0)
    .bind(session.0)
    .execute(env.pg.pool())
    .await
    .unwrap();
    let r = sqlx::query("UPDATE network_epochs SET lane = 'trusted_ui' WHERE epoch_id = $1")
        .bind(loose.0)
        .execute(env.pg.pool())
        .await;
    let msg = r.expect_err("epoch lane immutable").to_string();
    assert!(msg.contains("network_epochs.lane is immutable"), "{msg}");
    // after T2 the action's lane and fidelity are immutable
    let r = sqlx::query(
        "UPDATE actions SET lane = 'diagnostic', fidelity = 'synthetic_dom_event' WHERE action_id = $1",
    )
    .bind(id.0)
    .execute(env.pg.pool())
    .await;
    let msg = r.expect_err("action lane immutable").to_string();
    assert!(msg.contains("immutable after T2"), "{msg}");
    let r = sqlx::query("UPDATE actions SET fidelity = 'native_text_input' WHERE action_id = $1")
        .bind(id.0)
        .execute(env.pg.pool())
        .await;
    let msg = r.expect_err("fidelity immutable").to_string();
    assert!(msg.contains("immutable after T2"), "{msg}");
    // unrelated columns still update
    sqlx::query("UPDATE actions SET params = '{\"x\":1}' WHERE action_id = $1")
        .bind(id.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    env.teardown().await;
}

#[tokio::test]
async fn trusted_corpus_applies_lane_and_reachability() {
    use crawlx_storage::trusted::{LaneFilter, TrafficQuery, TrustedCorpus};
    let _guard = METRICS_LOCK.lock().await;
    let env = env!();
    let run = env.run(&[], 1).await;
    let leases = env.running_session(&run, 1, 1).await;
    let session = leases[0].lease.session.id;
    let cluster = StateClusterId::new();
    let s0 = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    env.pg.put_state(&s0).await.unwrap();

    // A1: s0 -> s1 through a synthetic click (diagnostic)
    let a1 = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(a1, session, epoch(1, 1, 1)).await.unwrap();
    let s1 = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    env.pg
        .finish(
            a1,
            succeeded_outcome(
                Fidelity::SyntheticDomEvent,
                Some(s1.clone()),
                "https://example.test/diag",
            ),
        )
        .await
        .unwrap();
    // A2: s1 -> s2 through a native click: trusted lane, but from a state only a synthetic click reached
    let a2 = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 2),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(a2, session, epoch(1, 1, 6)).await.unwrap();
    let s2 = new_state(session, cluster, false, 3, epoch(1, 1, 9));
    env.pg
        .finish(
            a2,
            succeeded_outcome(
                Fidelity::NativePointer,
                Some(s2.clone()),
                "https://example.test/unreachable",
            ),
        )
        .await
        .unwrap();
    // A3: s0 -> s3 through a native click: trusted and reachable
    let a3 = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 3),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(a3, session, epoch(1, 1, 0)).await.unwrap();
    assert_eq!(
        ActionJournal::get(&env.pg, a3).await.unwrap().before_state,
        Some(s0.id)
    );
    let s3 = new_state(session, cluster, false, 4, epoch(1, 1, 12));
    env.pg
        .finish(
            a3,
            succeeded_outcome(
                Fidelity::NativePointer,
                Some(s3.clone()),
                "https://example.test/trusted",
            ),
        )
        .await
        .unwrap();

    let reachable: BTreeSet<uuid::Uuid> =
        sqlx::query_scalar("SELECT state_id FROM trusted_reachable_states WHERE run_id = $1")
            .bind(run.id.0)
            .fetch_all(env.pg.pool())
            .await
            .unwrap()
            .into_iter()
            .collect();
    assert_eq!(
        reachable,
        [s0.id.0, s3.id.0].into_iter().collect(),
        "s1 is diagnostic-only and s2 hangs off it"
    );

    let rows_before = (
        trusted_rows("coverage"),
        trusted_rows("traffic"),
        trusted_rows("export"),
    );
    let corpus = TrustedCorpus::new(env.pg.clone());
    let rows = corpus.coverage(run.id).await.unwrap();
    assert_eq!(rows.len(), 3);
    let by_key = |n: u32| {
        let key = proposal("anonymous", cluster, n).key;
        rows.iter().find(|r| r.key == key).expect("row")
    };
    let (r1, r2, r3) = (by_key(1), by_key(2), by_key(3));
    assert_eq!(
        (
            r1.trusted_exercised,
            r1.diagnostic_exercised,
            r1.trusted_unreachable
        ),
        (0, 1, 0)
    );
    assert!(r1.is_diagnostic_only());
    assert_eq!(
        (
            r2.trusted_exercised,
            r2.diagnostic_exercised,
            r2.trusted_unreachable
        ),
        (0, 0, 1)
    );
    assert!(
        r2.is_diagnostic_only(),
        "trusted input from an unreachable state does not count"
    );
    assert_eq!(r2.exercised(TrustLane::Diagnostic), 1);
    assert_eq!(
        (
            r3.trusted_exercised,
            r3.diagnostic_exercised,
            r3.trusted_unreachable
        ),
        (1, 0, 0)
    );
    assert!(!r3.is_diagnostic_only());
    // the raw ledger counts A2 as trusted: the corpus is the stricter view
    let ledger = LedgerRepo::list(&env.pg, run.id).await.unwrap();
    assert_eq!(ledger.iter().map(|r| r.trusted_exercised).sum::<u32>(), 2);

    let trusted = corpus
        .traffic(run.id, LaneFilter::TrustedUi, &TrafficQuery::default())
        .await
        .unwrap();
    assert_eq!(trusted.len(), 2);
    assert!(trusted.iter().all(|t| t.lane == TrustLane::TrustedUi));
    let reachable_flags: Vec<(Option<&str>, bool)> = trusted
        .iter()
        .map(|t| (t.url_redacted.as_deref(), t.trusted_reachable))
        .collect();
    assert_eq!(
        reachable_flags,
        vec![
            (Some("https://example.test/unreachable"), false),
            (Some("https://example.test/trusted"), true)
        ]
    );
    let diagnostic = corpus
        .traffic(run.id, LaneFilter::Diagnostic, &TrafficQuery::default())
        .await
        .unwrap();
    assert_eq!(diagnostic.len(), 1);
    assert_eq!(diagnostic[0].lane, TrustLane::Diagnostic);
    assert_eq!(diagnostic[0].action, Some(a1));
    let both = corpus
        .traffic(run.id, LaneFilter::Both, &TrafficQuery::default())
        .await
        .unwrap();
    assert_eq!(
        both.len(),
        3,
        "lane=all is explicit and every row carries its lane"
    );
    let by_role = corpus
        .traffic(
            run.id,
            LaneFilter::Both,
            &TrafficQuery {
                role: Some("nobody"),
                ..TrafficQuery::default()
            },
        )
        .await
        .unwrap();
    assert!(by_role.is_empty());
    let export = corpus.export(run.id).await.unwrap();
    assert_eq!(export.len(), 1, "diagnostic_rows_in_trusted_export = 0");
    assert_eq!(export[0].action, Some(a3));
    assert!(export[0].is_corpus_eligible());
    // every row served by the corpus is counted under its kind
    assert_eq!(
        (
            trusted_rows("coverage"),
            trusted_rows("traffic"),
            trusted_rows("export"),
        ),
        (rows_before.0 + 3, rows_before.1 + 6, rows_before.2 + 1),
        "coverage 3 rows; traffic 2 + 1 + 3 + 0 rows; export 1 row"
    );
    env.teardown().await;
}

/// Every `Pg` repository method is timed under `crawlx.db.query.duration{op}` and refreshes
/// `crawlx.db.pool.in_use`. Other tests in this binary also `intend` without taking
/// `METRICS_LOCK`, so the histogram count is a lower bound; the gauge is a snapshot.
#[tokio::test]
async fn journal_writes_are_timed_and_publish_the_pool_gauge() {
    let _guard = METRICS_LOCK.lock().await;
    let env = env!();
    let run = env.run(&[], 1).await;
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let cluster = StateClusterId::new();
    env.pg
        .put_state(&new_state(session, cluster, true, 1, epoch(1, 1, 0)))
        .await
        .unwrap();
    let id = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    let metrics = Metrics::global();
    let intend = metrics.histogram(names::DB_QUERY_DURATION);
    let before = intend
        .snapshot(&[("op", "journal.intend")])
        .map_or(0, |s| s.count);
    env.pg.intend(id, session, epoch(1, 1, 3)).await.unwrap();
    let after = intend
        .snapshot(&[("op", "journal.intend")])
        .expect("journal.intend was observed");
    assert!(after.count > before, "{} <= {before}", after.count);
    assert!(after.sum > 0.0, "a round trip takes time");
    assert_eq!(
        after.buckets.last().map(|(_, n)| *n),
        Some(after.count),
        "the +Inf bucket holds every observation"
    );
    let in_use = metrics
        .gauge(names::DB_POOL_IN_USE)
        .get(&[])
        .expect("the pool gauge is set after every repository call");
    assert!(
        in_use >= 0.0 && in_use <= f64::from(env.pg.config().max_connections),
        "pool.in_use = {in_use}"
    );
    env.teardown().await;
}

#[tokio::test]
async fn inspect_repo_reads_epochs_navigations_and_transitions() {
    use crawlx_storage::InspectRepo;

    let env = env!();
    let run = env.run(&[], 1).await;
    let leases = env.running_session(&run, 1, 1).await;
    let session = leases[0].lease.session.id;
    let cluster = StateClusterId::new();
    let s0 = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    env.pg.put_state(&s0).await.unwrap();
    let repo = InspectRepo::new(env.pg.clone());
    assert!(repo.epochs(run.id).await.unwrap().is_empty());
    assert!(repo.navigations(run.id).await.unwrap().is_empty());
    assert!(repo.transitions(run.id).await.unwrap().is_empty());

    // the worker's navigation audit row sits next to an unrelated event kind
    let nav_payload = serde_json::json!({ "url": "https://example.test/", "status": 200 });
    EventRepo::append(&env.pg, run.id, "lease", serde_json::json!({}))
        .await
        .unwrap();
    let nav_seq = EventRepo::append(&env.pg, run.id, "navigation", nav_payload.clone())
        .await
        .unwrap();

    // A1: s0 -> s1 (diagnostic); A2: s0 -> no new state (trusted)
    let a1 = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(a1, session, epoch(1, 1, 1)).await.unwrap();
    let s1 = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    let o1 = succeeded_outcome(
        Fidelity::SyntheticDomEvent,
        Some(s1.clone()),
        "https://example.test/diag",
    );
    let e1 = o1.receipt.as_ref().unwrap().network_epoch;
    env.pg.finish(a1, o1).await.unwrap();
    let a2 = env
        .pg
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 2),
            &allow_verdict(),
        )
        .await
        .unwrap();
    env.pg.intend(a2, session, epoch(1, 1, 6)).await.unwrap();
    let o2 = succeeded_outcome(Fidelity::NativePointer, None, "https://example.test/trusted");
    let e2 = o2.receipt.as_ref().unwrap().network_epoch;
    env.pg.finish(a2, o2).await.unwrap();

    let navigations = repo.navigations(run.id).await.unwrap();
    assert_eq!(navigations.len(), 1, "only `navigation` events");
    assert_eq!(navigations[0].seq, nav_seq);
    assert_eq!(navigations[0].payload, nav_payload);

    let epochs = repo.epochs(run.id).await.unwrap();
    assert_eq!(
        epochs
            .iter()
            .map(|e| (e.epoch, e.action, e.lane, e.session))
            .collect::<Vec<_>>(),
        vec![
            (e1, Some(a1), TrustLane::Diagnostic, session),
            (e2, Some(a2), TrustLane::TrustedUi, session)
        ]
    );
    assert!(epochs.iter().all(|e| e.request_count == 1 && !e.settle_timeout));

    let transitions = repo.transitions(run.id).await.unwrap();
    assert_eq!(transitions.len(), 2);
    let t1 = &transitions[0];
    assert_eq!(
        (t1.action, t1.session, t1.lane),
        (a1, session, TrustLane::Diagnostic)
    );
    assert_eq!(t1.before_state, s0.id);
    assert_eq!(t1.after_state, Some(s1.id));
    assert_eq!(t1.network_epoch, Some(e1));
    assert!(t1.settle_report.is_object());
    let t2 = &transitions[1];
    assert_eq!(
        (t2.action, t2.lane, t2.after_state),
        (a2, TrustLane::TrustedUi, None)
    );

    assert_eq!(repo.transition_action(run.id, t1.id).await.unwrap(), Some(a1));
    assert_eq!(
        repo.transition_action(CrawlRunId::new(), t1.id).await.unwrap(),
        None,
        "a transition of another run is not found"
    );
    assert_eq!(
        repo.transition_action(run.id, crawlx_core::TransitionId::new())
            .await
            .unwrap(),
        None
    );
    assert!(repo.epochs(CrawlRunId::new()).await.unwrap().is_empty());
    env.teardown().await;
}

#[tokio::test]
async fn orphan_objects_are_collected_after_the_grace_period() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(env.pg.clone());
    let fs = Arc::new(
        FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
            .await
            .unwrap()
            .with_index(Arc::new(env.pg.clone())),
    );
    let referenced = fs
        .put(run.id, Sensitivity::Content, "text/html", b"<p>kept</p>")
        .await
        .unwrap();
    let referenced_key = fs.row(referenced.id).await.unwrap().unwrap().object_key;
    // simulate a crash between the object PUT and the row insert
    let orphan_key = format!("content/{}/{}/{}", env.tenant, run.id, "f".repeat(64));
    crawlx_storage::ArtifactBlobs::put(fs.blobs(), &orphan_key, b"orphan")
        .await
        .unwrap();
    let sweeper = RetentionSweeper::new(env.pg.clone()).with_artifacts(fs.clone());
    // within the grace period the orphan survives (a concurrent writer may be between PUT and row)
    assert_eq!(
        sweeper
            .collect_orphans(Utc::now(), Duration::hours(1))
            .await
            .unwrap(),
        0
    );
    assert!(dir.path().join(&orphan_key).is_file());
    // after it, the orphan goes and the referenced object never does
    let later = Utc::now() + Duration::hours(2);
    assert_eq!(
        sweeper.collect_orphans(later, Duration::hours(1)).await.unwrap(),
        1
    );
    assert!(!dir.path().join(&orphan_key).exists());
    assert!(dir.path().join(&referenced_key).is_file());
    assert_eq!(fs.get(&referenced).await.unwrap(), b"<p>kept</p>");
    assert_eq!(
        sweeper.collect_orphans(later, Duration::hours(1)).await.unwrap(),
        0,
        "idempotent"
    );
    // the same through a sweep with an orphan grace configured
    crawlx_storage::ArtifactBlobs::put(fs.blobs(), &orphan_key, b"orphan again")
        .await
        .unwrap();
    let report = RetentionSweeper::new(env.pg.clone())
        .with_artifacts(fs.clone())
        .with_orphan_grace(Duration::hours(1))
        .sweep(later)
        .await
        .unwrap();
    assert_eq!(report.orphans_collected, 1);
    assert!(dir.path().join(&referenced_key).is_file());
    env.teardown().await;
}

#[tokio::test]
async fn identity_aliases_round_trip_in_postgres() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let h = |s: &str| crawlx_core::ElementIdentityHash(Digest::of("t", s.as_bytes()));
    let a = IdentityAlias {
        alias: h("minted"),
        canonical: h("known"),
        from_version: 1,
        to_version: 1,
        score: 0.71,
    };
    assert!(matches!(
        env.pg.record_alias(CrawlRunId::new(), &a).await,
        Err(StoreError::Conflict(_))
    ));
    env.pg.record_alias(run.id, &a).await.unwrap();
    env.pg
        .record_alias(run.id, &IdentityAlias { score: 0.65, ..a })
        .await
        .unwrap();
    let b = IdentityAlias {
        alias: h("v2"),
        canonical: h("known"),
        from_version: 2,
        to_version: 1,
        score: 1.0,
    };
    env.pg.record_alias(run.id, &b).await.unwrap();
    let mut expected = vec![a, b];
    expected.sort_by_key(|x| x.alias);
    assert_eq!(env.pg.aliases_of(run.id, h("known")).await.unwrap(), expected);
    assert!(env.pg.aliases_of(run.id, h("minted")).await.unwrap().is_empty());
    assert_eq!(
        env.count("SELECT count(*) FROM identity_aliases WHERE run_id = $1", run.id)
            .await,
        2
    );
    assert_eq!(
        env.count(
            "SELECT count(*) FROM elements WHERE run_id = $1 AND identity_version = 2",
            run.id
        )
        .await,
        1,
    );
    env.teardown().await;
}

/// Every session a worker launches records `browser_build` and `cdp_revision`.
/// Two roles x two runs are claimed and launched through the storage API; the session repo
/// must then report no session without a build, and the row count must equal what started.
#[tokio::test]
async fn every_session_records_browser_build_and_cdp_revision() {
    let env = env!();
    let run = env.run(&["a", "b"], 2).await;
    let started = env.running_session(&run, 2, 2).await;
    assert_eq!(started.len(), 4);
    let pinned = crawlx_storage::testkit::browser_build("155.0.8059.84", "1.3");
    for s in &started {
        // what the Session Actor does once the browser context is up
        env.pg
            .set_session_browser(s.lease.session.id, &pinned)
            .await
            .unwrap();
    }

    let listed = env.pg.list_sessions(run.id).await.unwrap();
    assert_eq!(listed.len(), started.len(), "every started session is listed");
    let without_build: Vec<SessionId> = listed
        .iter()
        .filter(|s| {
            s.browser
                .as_ref()
                .is_none_or(|b| b.chromium_version.is_empty() || b.cdp_revision.is_empty())
        })
        .map(|s| s.id)
        .collect();
    assert!(
        without_build.is_empty(),
        "sessions without a build: {without_build:?}"
    );
    for s in &listed {
        let b = s.browser.as_ref().unwrap();
        assert_eq!(
            (b.chromium_version.as_str(), b.cdp_revision.as_str()),
            ("155.0.8059.84", "1.3")
        );
        assert!(b.pinned);
    }
    // the columns themselves, not the row mapper's defaults
    assert_eq!(
        env.count(
            "SELECT count(*) FROM crawl_sessions WHERE run_id = $1 AND (browser_build IS NULL OR cdp_revision IS NULL)",
            run.id,
        )
        .await,
        0
    );
    assert_eq!(
        env.count("SELECT count(*) FROM crawl_sessions WHERE run_id = $1", run.id)
            .await,
        4
    );

    // the audit is not vacuous: a session that never launched is reported
    let other = env.run(&["a"], 1).await;
    let idle = env.running_session(&other, 1, 1).await;
    assert_eq!(idle.len(), 1);
    let listed = env.pg.list_sessions(other.id).await.unwrap();
    assert_eq!(listed.iter().filter(|s| s.browser.is_none()).count(), 1);
    assert_eq!(
        env.count(
            "SELECT count(*) FROM crawl_sessions WHERE run_id = $1 AND (browser_build IS NULL OR cdp_revision IS NULL)",
            other.id,
        )
        .await,
        1
    );
    env.teardown().await;
}

/// With the policies of migration 0012 a non-owner role sees only the rows of
/// `app.tenant_id`, on `crawl_runs` and through it on a run-scoped table. The owner (the
/// test user, like the worker role) is not filtered, so the test switches to a NOLOGIN role
/// created on the fly; it stays in the cluster, which is harmless.
#[tokio::test]
async fn row_level_security_isolates_two_tenants() {
    let env = env!();
    let t1 = env.tenant;
    let t2 = TenantId::new();
    env.pg.ensure_tenant(t2, "other").await.unwrap();
    let run1 = env.run(&["admin"], 1).await;
    let run2 = crawl_run(t2, create_crawl("https://other.test/", &["admin"], 1));
    env.pg.create(&run2, None).await.unwrap();
    env.pg.create_sessions(&sessions(run1.id, 1, 1)).await.unwrap();
    env.pg.create_sessions(&sessions(run2.id, 1, 1)).await.unwrap();

    let mut conn = env.pg.pool().acquire().await.unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    for sql in [
        "DO $$ BEGIN CREATE ROLE crawlx_rls_test NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$"
            .to_owned(),
        format!("GRANT USAGE ON SCHEMA {schema} TO crawlx_rls_test"),
        format!("GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO crawlx_rls_test"),
    ] {
        sqlx::query(&sql).execute(&mut *conn).await.unwrap();
    }
    async fn runs(conn: &mut sqlx::PgConnection) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
        sqlx::query_scalar("SELECT tenant_id FROM crawl_runs ORDER BY tenant_id")
            .fetch_all(conn)
            .await
    }
    async fn session_runs(conn: &mut sqlx::PgConnection) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
        sqlx::query_scalar("SELECT run_id FROM crawl_sessions ORDER BY run_id")
            .fetch_all(conn)
            .await
    }
    // the owner is not filtered (no FORCE ROW LEVEL SECURITY; see the migration header)
    assert_eq!(runs(&mut conn).await.unwrap().len(), 2);
    assert_eq!(session_runs(&mut conn).await.unwrap().len(), 2);

    sqlx::query("SET ROLE crawlx_rls_test")
        .execute(&mut *conn)
        .await
        .unwrap();
    // no tenant setting: fail closed
    assert!(runs(&mut conn).await.unwrap().is_empty());
    assert!(session_runs(&mut conn).await.unwrap().is_empty());
    // an empty setting (what RESET leaves behind) is treated the same
    sqlx::query("SET app.tenant_id = ''")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(runs(&mut conn).await.unwrap().is_empty());

    sqlx::query("SELECT set_config('app.tenant_id', $1, false)")
        .bind(t1.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(runs(&mut conn).await.unwrap(), vec![t1.0]);
    assert_eq!(session_runs(&mut conn).await.unwrap(), vec![run1.id.0]);
    // the invoker-security view is filtered the same way (no rows, but no permission error)
    let errors: i64 = sqlx::query_scalar("SELECT count(*) FROM run_errors")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(errors, 0);

    sqlx::query("SELECT set_config('app.tenant_id', $1, false)")
        .bind(t2.0.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(runs(&mut conn).await.unwrap(), vec![t2.0]);
    assert_eq!(session_runs(&mut conn).await.unwrap(), vec![run2.id.0]);

    sqlx::query("RESET ROLE").execute(&mut *conn).await.unwrap();
    sqlx::query("RESET app.tenant_id")
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(runs(&mut conn).await.unwrap().len(), 2);
    // every run-scoped table has the policy
    let unprotected: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         JOIN information_schema.columns col ON col.table_schema = n.nspname AND col.table_name = c.relname AND col.column_name = 'run_id' \
         WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity ORDER BY 1",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert!(
        unprotected.is_empty(),
        "tables with run_id but no RLS: {unprotected:?}"
    );
    conn.close().await.unwrap();
    env.teardown().await;
}

/// The daily Merkle export folds the tenant's `entry_hash` leaves of one UTC
/// day in `(occurred_at, audit_id)` order and writes `audit/{tenant}/{day}.json`; the root
/// recomputes from the table and from the documented tree shape.
#[tokio::test]
async fn audit_merkle_export_recomputes_root() {
    let env = env!();
    let other = TenantId::new();
    env.pg.ensure_tenant(other, "other").await.unwrap();
    let day = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
    let at = |d: NaiveDate, h: u32| Utc.from_utc_datetime(&d.and_hms_opt(h, 0, 0).unwrap());
    let next = day.succ_opt().unwrap();
    let mut ids = Vec::new();
    // inserted out of time order so the export must sort by occurred_at, not audit_id
    for (tenant, when, fill) in [
        (env.tenant, at(day, 10), 0xa1u8),
        (env.tenant, at(day, 11), 0xa2),
        (env.tenant, at(day, 9), 0xa3),
        (env.tenant, at(next, 0), 0xb1),
        (other, at(day, 12), 0xc1),
    ] {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, occurred_at, prev_hash, entry_hash) \
             VALUES ($1, NULL, 'test', 'run.created', '{}', $2, $3, $4) RETURNING audit_id",
        )
        .bind(tenant.0)
        .bind(when)
        .bind(vec![0u8; 32])
        .bind(vec![fill; 32])
        .fetch_one(env.pg.pool())
        .await
        .unwrap();
        ids.push(id);
    }
    let blobs = Arc::new(MemBlobs::default());
    let export = MerkleExport::new(env.pg.clone(), blobs.clone());
    let rec = export.export_day(env.tenant, day).await.unwrap();
    assert_eq!(rec.count, 3);
    assert_eq!((rec.first_id, rec.last_id), (Some(ids[2]), Some(ids[1])));

    // the documented shape: H(H(a3, a1), H(a2, a2)) in occurred_at order
    let node = |l: [u8; 32], r: [u8; 32]| Digest::of(MERKLE_DOMAIN, &[l.as_slice(), r.as_slice()].concat());
    let (a1, a2, a3) = ([0xa1u8; 32], [0xa2u8; 32], [0xa3u8; 32]);
    assert_eq!(rec.root, Some(node(node(a3, a1).0, node(a2, a2).0)));
    // and the generic fold over the leaves read back from the table
    let leaves: Vec<Digest> = export
        .leaves(env.tenant, day)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    assert_eq!(merkle_root(&leaves), rec.root);

    let key = export_key(env.tenant, day);
    assert_eq!(key, format!("audit/{}/2026-01-15.json", env.tenant));
    let stored: serde_json::Value =
        serde_json::from_slice(&ArtifactBlobs::get(&*blobs, &key).await.unwrap().unwrap()).unwrap();
    assert_eq!(stored["count"], 3);
    assert_eq!(stored["day"], "2026-01-15");
    assert_eq!(stored["root"], rec.root.unwrap().to_hex());
    assert_eq!(export.stored(env.tenant, day).await.unwrap(), Some(rec.clone()));

    let mut want = vec![env.tenant, other];
    want.sort();
    assert_eq!(export.tenants_with_events(day).await.unwrap(), want);
    let all = export.export_all(day).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().find(|e| e.tenant == other).unwrap().count, 1);

    let empty = export
        .export_day(env.tenant, day.succ_opt().unwrap().succ_opt().unwrap())
        .await
        .unwrap();
    assert_eq!((empty.count, empty.root, empty.first_id), (0, None, None));
    env.teardown().await;
}

/// `outcome_counts` mirrors `JournalOutcomes::tally`: rows by outcome, where a row that ever
/// went through `unknown` counts as an unknown outcome whatever it became.
#[tokio::test]
async fn outcome_counts_tally_the_rows_by_outcome() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let cluster = StateClusterId::new();
    let outcome = |status| OutcomeRecord {
        status,
        receipt: None,
        settle: None,
        after_state: None,
        traffic: Vec::new(),
        error: None,
        finished_at: Utc::now(),
    };
    let mut ids = Vec::new();
    for n in 1..=6 {
        ids.push(
            env.pg
                .propose(
                    run.id,
                    session,
                    &proposal("anonymous", cluster, n),
                    &allow_verdict(),
                )
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        env.pg.outcome_counts(run.id).await.unwrap(),
        JournalOutcomes::default(),
        "proposals carry no outcome"
    );
    // a: succeeded, b: failed, c: only proposed, d/e/f: in flight when the holder dies
    for (id, status) in [(ids[0], ActionStatus::Succeeded), (ids[1], ActionStatus::Failed)] {
        env.pg.intend(id, session, epoch(1, 1, 0)).await.unwrap();
        env.pg.finish(id, outcome(status)).await.unwrap();
    }
    for id in &ids[3..] {
        env.pg.intend(*id, session, epoch(1, 1, 0)).await.unwrap();
    }
    let flipped = env
        .pg
        .mark_unknown(Utc::now() + Duration::seconds(300))
        .await
        .unwrap();
    assert_eq!(flipped.len(), 3);
    for (id, resolution) in [
        (ids[4], ReconcileResolution::Applied),
        (ids[5], ReconcileResolution::NotApplied),
    ] {
        env.pg
            .reconcile(
                id,
                Reconciliation {
                    resolution,
                    evidence: serde_json::json!({}),
                    reconciled_at: Utc::now(),
                },
            )
            .await
            .unwrap();
    }
    // f was not applied: it runs again and succeeds, but its history stays an unknown outcome
    env.pg.intend(ids[5], session, epoch(1, 1, 0)).await.unwrap();
    env.pg
        .finish(ids[5], outcome(ActionStatus::Succeeded))
        .await
        .unwrap();
    assert_eq!(
        env.pg.outcome_counts(run.id).await.unwrap(),
        JournalOutcomes::new(2, 1, 3)
    );
    let rows = ActionJournal::list(&env.pg, run.id, None).await.unwrap();
    assert_eq!(JournalOutcomes::tally(&rows), JournalOutcomes::new(2, 1, 3));
    assert_eq!(
        env.pg.outcome_counts(CrawlRunId::new()).await.unwrap(),
        JournalOutcomes::default(),
        "another run's rows are not counted"
    );
    env.teardown().await;
}

/// A leased row is not pending but still open: the frontier is exhausted only when no row is
/// pending or leased, and a row handed back unfetched is pending again without a spent attempt.
#[tokio::test]
async fn a_leased_row_is_open_and_a_released_row_is_pending_again() {
    let env = env!();
    let run = env.run(&[], 1).await;
    for page in ["a", "b"] {
        env.pg
            .discover(
                run.id,
                &canonical_url(&format!("https://example.test/{page}")),
                0,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let counts = || async {
        (
            env.pg.pending_count(run.id).await.unwrap(),
            env.pg.open_count(run.id).await.unwrap(),
        )
    };
    assert_eq!(counts().await, (2, 2));

    let w = WorkerId::new();
    let batch = env.pg.lease_batch_fenced(run.id, w, 2).await.unwrap();
    assert_eq!(counts().await, (0, 2), "leased rows are open, not pending");
    assert!(batch.iter().all(|(e, _)| e.attempts == 1));

    env.pg.give_back(batch[0].0.id, batch[0].1).await.unwrap();
    assert_eq!(counts().await, (1, 2));
    let again = env.pg.lease_batch(run.id, w, 1).await.unwrap();
    assert_eq!(
        (again[0].id, again[0].attempts),
        (batch[0].0.id, 1),
        "a release is not an attempt"
    );

    env.pg
        .complete(batch[1].0.id, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(matches!(
        env.pg.give_back(batch[1].0.id, batch[1].1).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        env.pg.give_back(i64::MAX, 1).await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(counts().await, (0, 1));
    env.pg
        .complete(again[0].id, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    assert_eq!(
        counts().await,
        (0, 0),
        "nothing left in flight: the frontier is exhausted"
    );
    env.teardown().await;
}

/// A URL lease lives as long as its holder renews it, and only its holder (the fencing token it
/// was granted) renews, completes or hands the row back: once the reaper has returned the row, a
/// stalled holder can touch nothing, whoever leases the row next.
#[tokio::test]
async fn a_frontier_lease_is_renewed_and_finished_only_under_its_fencing_token() {
    let env = env!();
    let run = env.run(&[], 1).await;
    for page in ["a", "b"] {
        env.pg
            .discover(
                run.id,
                &canonical_url(&format!("https://example.test/{page}")),
                0,
                None,
                None,
            )
            .await
            .unwrap();
    }
    assert_eq!(env.pg.url_batch_ttl(), std::time::Duration::from_secs(60));
    let holder = WorkerId::new();
    let batch = env.pg.lease_batch_fenced(run.id, holder, 2).await.unwrap();
    let ((a, fa), (b, fb)) = (&batch[0], &batch[1]);
    let (a, b) = (a.id, b.id);
    assert_ne!(fa, fb, "every lease has a token of its own");
    let expiry = |id: i64| {
        let pool = env.pg.pool().clone();
        async move {
            sqlx::query_scalar::<_, chrono::DateTime<Utc>>(
                "SELECT lease_expires_at FROM url_frontier WHERE frontier_id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    // both leases are about to run out
    sqlx::query("UPDATE url_frontier SET lease_expires_at = now() + interval '10 seconds' WHERE run_id = $1")
        .bind(run.id.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    let soon = expiry(a).await;

    // a heartbeat renews the rows of the holder that present their token, and only those
    assert!(env
        .pg
        .heartbeat_frontier(WorkerId::new(), &[(a, *fa), (b, *fb)])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        env.pg
            .heartbeat_frontier(holder, &[(a, fa + 10_000), (b, *fb)])
            .await
            .unwrap(),
        vec![b]
    );
    assert_eq!(expiry(a).await, soon, "a stale token renews nothing");
    assert!(
        expiry(b).await > soon + Duration::seconds(30),
        "renewed to the full TTL"
    );

    // the reaper returns the row that was not renewed
    let reaped = env
        .pg
        .reap_frontier(Utc::now() + Duration::seconds(30), 5)
        .await
        .unwrap();
    assert_eq!((reaped.requeued, reaped.failed), (1, 0));
    assert_eq!(env.pg.pending_count(run.id).await.unwrap(), 1);

    // the stalled holder keeps its token and can do nothing with it
    assert!(env
        .pg
        .heartbeat_frontier(holder, &[(a, *fa)])
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        env.pg
            .complete_fenced(a, *fa, FrontierStatus::Succeeded, None)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        env.pg.give_back(a, *fa).await,
        Err(StoreError::LeaseLost)
    ));

    // and not after another worker leased the row either
    let again = env
        .pg
        .lease_batch_fenced(run.id, WorkerId::new(), 1)
        .await
        .unwrap();
    assert_eq!((again[0].0.id, again[0].0.attempts), (a, 2));
    assert!(again[0].1 > *fa, "a new lease, a newer token");
    assert!(matches!(
        env.pg.complete_fenced(a, *fa, FrontierStatus::Failed, None).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        env.pg.give_back(a, *fa).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        env.pg.open_count(run.id).await.unwrap(),
        2,
        "the new holder keeps the row"
    );
    env.pg
        .complete_fenced(a, again[0].1, FrontierStatus::Succeeded, None)
        .await
        .unwrap();

    // the holder of the renewed row finishes it; finishing twice is a lost lease
    assert!(matches!(
        env.pg.complete_fenced(b, *fb, FrontierStatus::Leased, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));
    env.pg
        .complete_fenced(b, *fb, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    assert!(matches!(
        env.pg.complete_fenced(b, *fb, FrontierStatus::Failed, None).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        env.pg
            .complete_fenced(i64::MAX, 1, FrontierStatus::Failed, None)
            .await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(env.pg.open_count(run.id).await.unwrap(), 0);
    env.teardown().await;
}

/// `state_counts` tallies the rows of one run by status, and splits out the rows the URL
/// counters hold as duplicates by their `dedupe:` reason: the same numbers as
/// `FrontierStateCounts::tally` over the rows.
#[tokio::test]
async fn state_counts_tally_the_frontier_rows_of_one_run() {
    let env = env!();
    let run = env.run(&[], 1).await;
    let other = env.run(&[], 1).await;
    assert_eq!(
        env.pg.state_counts(run.id).await.unwrap(),
        FrontierStateCounts::default()
    );
    let url = |name: &str| canonical_url(&format!("https://example.test/{name}"));
    let blocked = |status, why: &str| Some((status, why.to_owned()));
    // the first six leave the lease below, `pending` is left in the queue
    for (name, denial) in [
        ("leased", None),
        ("ok", None),
        ("dup", None),
        ("bad", None),
        ("gone", None),
        ("stopped", None),
        ("pending", None),
        (
            "scope",
            blocked(FrontierStatus::PolicyBlocked, "excluded_path:/x"),
        ),
        (
            "shape",
            blocked(FrontierStatus::PolicyBlocked, "dedupe:fingerprint"),
        ),
        ("robots", blocked(FrontierStatus::RobotsBlocked, "robots")),
    ] {
        env.pg
            .discover(run.id, &url(name), 0, None, denial)
            .await
            .unwrap();
    }
    env.pg
        .discover(other.id, &url("pending"), 0, None, None)
        .await
        .unwrap();
    let rows = FrontierRepo::list(&env.pg, run.id).await.unwrap();
    let id = |name: &str| {
        rows.iter()
            .find(|e| e.url.url.path() == format!("/{name}"))
            .unwrap()
            .id
    };
    let leased = env.pg.lease_batch(run.id, WorkerId::new(), 6).await.unwrap();
    assert_eq!(leased.len(), 6);
    for (name, status, why) in [
        ("ok", FrontierStatus::Succeeded, None),
        ("dup", FrontierStatus::Succeeded, Some("dedupe:content_exact")),
        ("bad", FrontierStatus::Failed, Some("http_500")),
        ("gone", FrontierStatus::Unreachable, Some("dns")),
        ("stopped", FrontierStatus::Abandoned, Some("run_stopped")),
    ] {
        env.pg
            .complete(id(name), status, why.map(str::to_owned))
            .await
            .unwrap();
    }

    let counts = env.pg.state_counts(run.id).await.unwrap();
    assert_eq!(
        counts,
        FrontierStateCounts {
            pending: 1,
            leased: 1,
            succeeded: 2,
            failed: 1,
            unreachable: 1,
            abandoned: 1,
            policy_blocked: 2,
            robots_blocked: 1,
            succeeded_duplicate: 1,
            policy_blocked_duplicate: 1,
        }
    );
    assert_eq!(
        counts,
        FrontierStateCounts::tally(&FrontierRepo::list(&env.pg, run.id).await.unwrap())
    );
    assert_eq!(counts.admitted(), 1 + 1 + 1 + 1 + 1 + 1);
    assert_eq!(counts.blocked_by_policy(), 1);
    assert_eq!(counts.deduplicated(), 2);
    assert_eq!(
        env.pg.state_counts(CrawlRunId::new()).await.unwrap(),
        FrontierStateCounts::default()
    );
    env.teardown().await;
}

#[tokio::test]
async fn zdr_metadata_stays_ephemeral_and_consumers_fail_closed_after_expiry() {
    let mut env = env!();
    let now = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
    let clock = Arc::new(crawlx_core::time::ManualClock::new(now));
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(clock.clone()));
    env.pg = env.pg.with_delivery_buffer(buffer.clone());
    let mut cfg = create_crawl("https://example.test/", &[], 1);
    cfg.retention.mode = RetentionMode::Zdr;
    cfg.retention.days = 0;
    let run = crawl_run(env.tenant, cfg);
    env.pg.create(&run, None).await.unwrap();
    let session = env.running_session(&run, 1, 1).await.remove(0).lease.session.id;
    let marker = "zdr-canary-confidential";
    let cluster = StateClusterId::new();
    let mut state = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    state.url = canonical_url("https://example.test/zdr-canary-confidential?token=zdr-canary-confidential");
    state.observed_at = now;
    state.artifacts.push((
        marker.to_owned(),
        ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("test/artifact", marker.as_bytes()),
        },
    ));
    state
        .masks
        .masked_node_keys
        .push(Digest::of("test/mask", marker.as_bytes()));
    state
        .masks
        .reasons
        .push(crawlx_core::state::MaskReason::Configured);
    env.pg.put_state(&state).await.unwrap();
    assert_eq!(env.pg.list_states(run.id).await.unwrap()[0], state);
    let mut duplicate = state.clone();
    duplicate.url = canonical_url("https://example.test/not-the-original");
    env.pg.put_state(&duplicate).await.unwrap();
    assert_eq!(env.pg.list_states(run.id).await.unwrap()[0], state);

    let mut p = proposal("anonymous", cluster, 1);
    p.key.route_template.0 = format!("/{marker}");
    p.key.input_class.0 = marker.to_owned();
    let action = env
        .pg
        .propose(run.id, session, &p, &allow_verdict())
        .await
        .unwrap();
    assert_eq!(ActionJournal::get(&env.pg, action).await.unwrap().key, p.key);
    assert_eq!(LedgerRepo::list(&env.pg, run.id).await.unwrap()[0].key, p.key);
    assert_eq!(
        crawlx_storage::TrustedCorpus::new(env.pg.clone())
            .coverage(run.id)
            .await
            .unwrap()[0]
            .key,
        p.key
    );
    env.pg.intend(action, session, epoch(1, 1, 0)).await.unwrap();
    let mut outcome = outcome_failed();
    outcome.error = Some(marker.to_owned());
    outcome.finished_at = now;
    crawlx_storage::retention::ensure_traffic_partitions(&env.pg, now, 1)
        .await
        .unwrap();
    let body = ArtifactRef {
        id: ArtifactId::new(),
        digest: Digest::of("test/body", marker.as_bytes()),
    };
    outcome.traffic.push(TrafficEvent {
        seq: 0,
        epoch_id: None,
        unattributed_reason: Some(UnattributedReason::NotApplicable),
        origin: TrafficOrigin::Page,
        method: "POST".to_owned(),
        url: format!("https://example.test/{marker}?token={marker}"),
        status: Some(500),
        request_headers: vec![("authorization".to_owned(), marker.to_owned())],
        response_headers: vec![("set-cookie".to_owned(), marker.to_owned())],
        request_body: Some(body.clone()),
        response_body: Some(body),
        third_party: false,
        late: false,
        protocol: None,
        started_at: now,
        finished_at: Some(now),
    });
    env.pg.finish(action, outcome).await.unwrap();

    let payload =
        serde_json::json!({"url": state.url.url, "headers": {"authorization": marker}, "content": marker});
    EventRepo::append(&env.pg, run.id, "navigation", payload.clone())
        .await
        .unwrap();
    EventRepo::append(
        &env.pg,
        run.id,
        "page",
        serde_json::json!({"pageId": 0, "content": marker}),
    )
    .await
    .unwrap();
    EventRepo::append(&env.pg, run.id, marker, serde_json::json!({"content": marker}))
        .await
        .unwrap();
    let metadata = EventRepo::list_metadata_after(&env.pg, run.id, 0, 100)
        .await
        .unwrap();
    assert!(metadata
        .iter()
        .any(|event| event.kind == "page" && event.payload["pageId"] == 0));
    assert!(!serde_json::to_string(&metadata).unwrap().contains(marker));
    let events = EventRepo::list_after(&env.pg, run.id, 0, 100).await.unwrap();
    assert!(events
        .iter()
        .any(|event| event.kind == "navigation" && event.payload == payload));
    let inspect = crawlx_storage::InspectRepo::new(env.pg.clone());
    assert_eq!(inspect.navigations(run.id).await.unwrap()[0].payload, payload);

    let model = ModelDecisionRecord {
        id: crawlx_core::ModelDecisionId::new(),
        run: run.id,
        session: Some(session),
        kind: ModelDecisionKind::Plan,
        mode: crawlx_core::config::System1Mode::Shadow,
        provider: marker.to_owned(),
        model: marker.to_owned(),
        model_version: marker.to_owned(),
        calibration_version: Some(marker.to_owned()),
        confidence: Some(0.5),
        output: serde_json::json!({"prompt": marker, "content": marker, "evidence": marker}),
        prompt_digest: Digest::of("test/prompt", marker.as_bytes()),
        latency_ms: Some(12),
        breaker_state: Some(marker.to_owned()),
        created_at: now,
    };
    ModelDecisionRepo::record(&env.pg, &model).await.unwrap();
    let mut duplicate_model = model.clone();
    duplicate_model.output = serde_json::json!({"replacement": "must not replace original"});
    ModelDecisionRepo::record(&env.pg, &duplicate_model)
        .await
        .unwrap();
    assert_eq!(
        ModelDecisionRepo::list(&env.pg, run.id).await.unwrap(),
        vec![model]
    );

    for table in [
        "states",
        "actions",
        "action_contexts",
        "model_decisions",
        "crawl_events",
        "traffic_events",
    ] {
        let sql =
            format!("SELECT COALESCE(jsonb_agg(to_jsonb(t))::text, '') FROM {table} t WHERE run_id = $1");
        let durable: String = sqlx::query_scalar(&sql)
            .bind(run.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
        assert!(
            !durable.contains(marker),
            "{table} persisted confidential content"
        );
    }
    let durable: (Option<serde_json::Value>, serde_json::Value, serde_json::Value) =
        sqlx::query_as("SELECT observed_url, masks, artifacts FROM states WHERE state_id = $1")
            .bind(state.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(durable, (None, serde_json::json!([]), serde_json::json!([])));
    let bodies: (Option<uuid::Uuid>, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT body_artifact_id, request_body_artifact_id FROM traffic_events WHERE run_id = $1",
    )
    .bind(run.id.0)
    .fetch_one(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(bodies, (None, None));

    clock.advance_ms(3_600_001);
    buffer
        .sweep(now + Duration::hours(1) + Duration::seconds(1))
        .await
        .unwrap();
    assert!(matches!(
        env.pg.list_states(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        ActionJournal::get(&env.pg, action).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        LedgerRepo::list(&env.pg, run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        EventRepo::list_after(&env.pg, run.id, 0, 100).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        inspect.navigations(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        ModelDecisionRepo::list(&env.pg, run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let summary = LedgerRepo::summary(&env.pg, run.id).await.unwrap();
    assert_eq!((summary.discovered, summary.exercised_trusted), (1, 0));
    let metadata = EventRepo::list_metadata_after(&env.pg, run.id, 0, 100)
        .await
        .unwrap();
    assert!(metadata
        .iter()
        .any(|event| event.kind == "page" && event.payload["pageId"] == 0));
    assert!(!serde_json::to_string(&metadata).unwrap().contains(marker));
    for table in [
        "states",
        "actions",
        "action_contexts",
        "model_decisions",
        "crawl_events",
        "traffic_events",
    ] {
        let sql =
            format!("SELECT COALESCE(jsonb_agg(to_jsonb(t))::text, '') FROM {table} t WHERE run_id = $1");
        let durable: String = sqlx::query_scalar(&sql)
            .bind(run.id.0)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
        assert!(!durable.contains(marker), "{table} leaked after expiry");
    }
    env.teardown().await;
}
