//! Round-robin multi-role runs over the lease loop: `per_role_replica` marks
//! cross-principal contexts `not_observable`, and a role session killed mid-turn resumes from
//! its checkpoint without disturbing the turn order or re-executing anything blindly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role, TargetIsolation};
use crawlx_core::counters::{ActionStatus, PlaneCounters, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{
    ActionJournal, CheckpointRepo, CrawlRun, CrawlSession, EventRepo, LedgerRepo, LedgerRow, SessionStatus,
};
use crawlx_core::{
    ActionContextKey, ActionId, ActionKind, Clock, CrawlRunId, CreateCrawl, ElementIdentityHash, InputClass,
    PrincipalId, ResourceContext, RouteTemplate, SessionId, StateClusterId, SystemClock,
};
use crawlx_fetch::StaticResolver;
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_strategies::{CoverageStatus, InMemoryLedger};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::run::build_report;
use crawlx_worker::{EgressConfig, RunReport, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SEED_URL: &str = "https://example.test/";
// Metrics are process-global: another run must not change this fixture's baselines.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

fn cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        idle_exit_after: Some(Duration::from_millis(600)),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn role(name: &str, replica: Option<&str>) -> Role {
    Role {
        name: name.to_owned(),
        credential_ref: None,
        login_plan: None,
        replica_base_url: replica.map(|u| url::Url::parse(u).unwrap()),
    }
}

fn two_role_crawl(isolation: TargetIsolation) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(SEED_URL).unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_020);
    c.limits.interactions = 1_000;
    c.limits.states = 1_000;
    c.target_isolation = isolation;
    let replica = (isolation == TargetIsolation::PerRoleReplica).then_some(SEED_URL);
    c.roles = vec![role("alice", replica), role("bob", replica)];
    c
}

/// What the API does: persist a queued run and its sessions.
async fn enqueue(stores: &Stores, mut crawl: CreateCrawl) -> CrawlRunId {
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    run.id
}

/// `n` pages, each linking to every other page: `n·(n−1)` click keys per role.
fn mesh(n: usize) -> FakeScript {
    let path = |i: usize| if i == 0 { "/".to_owned() } else { format!("/p{i}") };
    let mut script = FakeScript::new();
    for i in 0..n {
        let mut page = FakePage::new(&format!("https://example.test{}", path(i))).title(format!("Page {i}"));
        for j in (0..n).filter(|j| *j != i) {
            let key = format!("to{j}");
            page = page
                .node(FakeAxSpec::link(key.clone(), format!("Go to {j}"), path(j)))
                .on_click(&key, vec![FakeEffect::Navigate(path(j))]);
        }
        script = script.page(page);
    }
    script
}

fn cross_principal_row(principal: &str, element: &str, context: ResourceContext) -> LedgerRow {
    LedgerRow {
        key: ActionContextKey {
            principal: PrincipalId(principal.to_owned()),
            route_template: RouteTemplate("/invoices/{id}".to_owned()),
            element: ElementIdentityHash(Digest::of("test", element.as_bytes())),
            action_kind: ActionKind::Click,
            input_class: InputClass::none(),
            resource_context: context,
            state_cluster: StateClusterId::new(),
        },
        trusted_exercised: 0,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: SystemClock.now(),
        last_exercised: None,
    }
}

/// Exercised keys of one principal in the report's ledger.
fn exercised_keys(report: &RunReport, principal: &str) -> usize {
    report
        .ledger
        .iter()
        .filter(|r| r.key.principal.0 == principal && r.trusted_exercised > 0)
        .count()
}

fn status_of(rows: &[CrawlSession], id: SessionId) -> SessionStatus {
    rows.iter().find(|s| s.id == id).unwrap().status
}

#[tokio::test]
async fn per_role_replica_reports_cross_principal_contexts_as_not_observable_never_uncovered() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let run = enqueue(&stores, two_role_crawl(TargetIsolation::PerRoleReplica)).await;
    // keys the resource registry would attribute to another principal's resources: bob's view of
    // alice's invoice, the team-shared invoice and the admin-only one
    let seeded = [
        cross_principal_row("bob", "open-alices-invoice", ResourceContext::OtherUserSameRole),
        cross_principal_row("bob", "open-shared-invoice", ResourceContext::Shared),
        cross_principal_row("alice", "open-admin-invoice", ResourceContext::HigherRole),
    ];
    for row in &seeded {
        LedgerRepo::upsert(store.as_ref(), run, row).await.unwrap();
    }

    // the barrier is lifted under `per_role_replica`; this worker still runs one session at a
    // time because two sessions of one run sharing `RunClusters` race the cluster rows of the
    // in-memory store (`state_cluster … not found` on the second session's first state)
    let worker_cfg = WorkerConfig {
        max_sessions: 1,
        ..cfg(dir.path())
    };
    run_with(
        worker_cfg,
        stores.clone(),
        Some(Arc::new(
            FakeBackend::builder()
                .script(mesh(3))
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        )),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let report = build_report(&stores, run).await.unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?} {:#?}",
        report.terminal_reason,
        report.sessions
    );
    assert!(
        report
            .sessions
            .iter()
            .all(|s| s.status == SessionStatus::Completed),
        "{:?}",
        report.sessions
    );
    for principal in ["alice", "bob"] {
        assert!(
            exercised_keys(&report, principal) >= 1,
            "{principal} exercised nothing"
        );
    }
    // the worker's own classification of its ledger under the run's isolation
    assert_eq!(report.coverage.keys_not_observable, 3);
    let ledger = InMemoryLedger::from_rows(report.ledger.iter().cloned())
        .with_isolation(TargetIsolation::PerRoleReplica);
    for row in &seeded {
        assert_eq!(
            ledger.status(&row.key),
            Some(CoverageStatus::NotObservable),
            "{:?}",
            row.key.resource_context
        );
    }
    let by_status: BTreeMap<&str, usize> = ledger.statuses().fold(BTreeMap::new(), |mut m, (_, s)| {
        *m.entry(s.as_str()).or_default() += 1;
        m
    });
    assert_eq!(by_status.get("not_observable"), Some(&3), "{by_status:?}");
    // never "uncovered": the uncovered bucket holds exactly the observable, unexercised keys
    let observable_uncovered = ledger
        .statuses()
        .filter(|(k, s)| *s == CoverageStatus::Uncovered && !seeded.iter().any(|r| r.key == **k))
        .count();
    assert_eq!(
        usize::try_from(report.coverage.keys_uncovered()).unwrap(),
        observable_uncovered
    );
    assert_eq!(
        report.coverage.keys_total,
        report.coverage.keys_exercised_trusted
            + report.coverage.keys_diagnostic_only
            + report.coverage.keys_not_observable
            + report.coverage.keys_uncovered()
    );
    // per principal: bob's two cross-principal keys, alice's one
    assert_eq!(
        ledger
            .coverage(Some(&PrincipalId("bob".into())))
            .keys_not_observable,
        2
    );
    assert_eq!(
        ledger
            .coverage(Some(&PrincipalId("alice".into())))
            .keys_not_observable,
        1
    );
    // the same rows on a shared target are ordinary uncovered work
    let shared = InMemoryLedger::from_rows(report.ledger.iter().cloned());
    assert_eq!(shared.coverage(None).keys_not_observable, 0);
    assert_eq!(shared.status(&seeded[0].key), Some(CoverageStatus::Uncovered));
    assert_eq!(
        shared.coverage(None).keys_uncovered(),
        report.coverage.keys_uncovered() + 3
    );
}

/// Round metrics on a clean shared-target run: bob's turn waits for alice's, so a round
/// wait is observed for `bob`, and no role is abandoned for a fatal or recovery reason.
#[tokio::test]
async fn a_clean_round_robin_run_records_the_second_roles_wait_and_abandons_nobody() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let run = enqueue(&stores, two_role_crawl(TargetIsolation::Shared)).await;
    let m = Metrics::global();
    let wait_count = |role: &str| {
        m.histogram(names::SESSION_ROUND_WAIT)
            .snapshot(&[("role", role)])
            .map_or(0, |s| s.count)
    };
    let abandoned = || {
        (
            m.counter(names::ROLES_ABANDONED)
                .get(&[("reason", "fatal_error")]),
            m.counter(names::ROLES_ABANDONED)
                .get(&[("reason", "recovery_exhausted")]),
        )
    };
    let (bob_before, abandoned_before) = (wait_count("bob"), abandoned());

    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(Arc::new(
            FakeBackend::builder()
                .script(mesh(3))
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        )),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let report = build_report(&stores, run).await.unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert!(
        report
            .sessions
            .iter()
            .all(|s| s.status == SessionStatus::Completed),
        "{:?}",
        report.sessions
    );
    assert!(
        wait_count("bob") > bob_before,
        "bob's turn waited for alice's: {bob_before} -> {}",
        wait_count("bob")
    );
    assert_eq!(abandoned(), abandoned_before, "a clean run abandons no role");
}

#[tokio::test]
async fn a_role_session_killed_mid_turn_resumes_from_its_checkpoint_in_turn_order() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let run = enqueue(&stores, two_role_crawl(TargetIsolation::Shared)).await;
    // Keep the handoff fixture small: browser pacing also applies to FakeBackend, and
    // every mesh link has pointer and keyboard actions. Three pages leave work after
    // bob's second action without making alice's full turn dominate the wait deadline.
    let script = mesh(3);
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    let alice = sessions.iter().find(|s| s.role.0 == "alice").unwrap().clone();
    let bob = sessions.iter().find(|s| s.role.0 == "bob").unwrap().clone();
    assert!(alice.schedule_slot < bob.schedule_slot);

    // worker 1: alice's turn completes; bob's turn is killed after it has performed actions
    let cancel = CancellationToken::new();
    let worker = {
        let cancel = cancel.clone();
        let stores = stores.clone();
        let script = script.clone();
        let cfg = WorkerConfig {
            idle_exit_after: None,
            ..cfg(dir.path())
        };
        tokio::spawn(async move {
            run_with(
                cfg,
                stores,
                Some(Arc::new(
                    FakeBackend::builder()
                        .script(script)
                        .clock(Arc::new(crawlx_core::SystemClock))
                        .build(),
                )),
                cancel,
            )
            .await
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let bob_succeeded = ActionJournal::list(store.as_ref(), run, Some(ActionStatus::Succeeded))
            .await
            .unwrap()
            .into_iter()
            .filter(|a| a.session == bob.id)
            .count();
        if bob_succeeded >= 2 {
            let now = stores.runs.list_sessions(run).await.unwrap();
            assert_eq!(status_of(&now, alice.id), SessionStatus::Completed, "{now:?}");
            assert_eq!(status_of(&now, bob.id), SessionStatus::Running, "{now:?}");
            break;
        }
        let now = stores.runs.list_sessions(run).await.unwrap();
        assert!(
            !status_of(&now, bob.id).is_terminal(),
            "bob finished before the kill: {now:?}"
        );
        assert!(tokio::time::Instant::now() < deadline, "bob never acted: {now:?}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(30), worker)
        .await
        .expect("worker 1 drained in time")
        .unwrap()
        .unwrap();

    // mid-turn: alice is terminal, bob is handed over, the run is still open
    let after_kill = stores.runs.list_sessions(run).await.unwrap();
    assert_eq!(status_of(&after_kill, alice.id), SessionStatus::Completed);
    assert_eq!(status_of(&after_kill, bob.id), SessionStatus::Recovering);
    assert_eq!(stores.runs.get(run).await.unwrap().status, RunStatus::Running);
    let checkpoint = CheckpointRepo::list(store.as_ref(), bob.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.reason == "shutdown")
        .max_by_key(|c| c.action_seq)
        .expect("bob's turn was checkpointed on shutdown");
    let journal = ActionJournal::list(store.as_ref(), run, None).await.unwrap();
    let before: BTreeMap<ActionId, (ActionStatus, u64)> =
        journal.iter().map(|a| (a.id, (a.status, a.seq))).collect();
    let bob_seq_before = journal
        .iter()
        .filter(|a| a.session == bob.id)
        .map(|a| a.seq)
        .max()
        .unwrap();
    assert!(bob_seq_before >= 2);
    assert!(checkpoint.action_seq <= bob_seq_before + 1, "{checkpoint:?}");
    let budget_before = EventRepo::list_after(store.as_ref(), run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.kind == "session.budget" && e.payload["session_id"] == bob.id.0.to_string())
        .expect("bob's original quota and deadline are durable before the kill");

    // worker 2: resumes bob's turn; alice's finished turn is never re-leased
    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(Arc::new(
            FakeBackend::builder()
                .script(script)
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        )),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let report = build_report(&stores, run).await.unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert_eq!(status_of(&report.sessions, alice.id), SessionStatus::Completed);
    assert_eq!(status_of(&report.sessions, bob.id), SessionStatus::Completed);
    let budgets_after: Vec<_> = EventRepo::list_after(store.as_ref(), run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "session.budget" && e.payload["session_id"] == bob.id.0.to_string())
        .collect();
    assert_eq!(budgets_after.len(), 1, "recovery must not allocate a fresh slice");
    assert_eq!(
        budgets_after[0].payload, budget_before.payload,
        "recovery preserves both quota and absolute deadline"
    );
    let bob_spent = report
        .actions
        .iter()
        .filter(|a| a.session == bob.id && a.intended_at.is_some())
        .fold(0_u64, |n, a| n + u64::from(a.attempt.max(1)));
    assert!(
        bob_spent <= budget_before.payload["interactions"].as_u64().unwrap(),
        "pre-kill and resumed actions share one lifetime slice"
    );

    // turn order: every action of alice's turn precedes every action of bob's turn, and the
    // resumed turn adds only bob's actions (alice's finished turn is never re-leased)
    let last_alice = report
        .actions
        .iter()
        .filter(|a| a.session == alice.id)
        .map(|a| a.proposed_at)
        .max()
        .expect("alice acted");
    let first_bob = report
        .actions
        .iter()
        .filter(|a| a.session == bob.id)
        .map(|a| a.proposed_at)
        .min()
        .expect("bob acted");
    assert!(
        last_alice <= first_bob,
        "bob's turn started before alice's turn ended"
    );

    // no action was re-executed blindly: every pre-kill action keeps its status, nothing is
    // left intended/unknown, and the resumed turn continues bob's sequence after the checkpoint
    let mut resumed = 0;
    for a in &report.actions {
        match before.get(&a.id) {
            Some((status, seq)) => {
                assert_eq!(
                    (a.status, a.seq),
                    (*status, *seq),
                    "pre-kill action changed: {a:?}"
                );
            }
            None => {
                assert_eq!(a.session, bob.id, "only bob proposes after the kill: {a:?}");
                assert!(a.seq > bob_seq_before, "{a:?} does not continue bob's sequence");
                assert!(a.seq > checkpoint.action_seq, "{a:?} precedes the checkpoint");
                resumed += 1;
            }
        }
        assert!(
            !matches!(a.status, ActionStatus::Intended | ActionStatus::Unknown),
            "left in flight: {a:?}"
        );
        if a.status == ActionStatus::Reconciled {
            assert!(a.reconcile_resolution.is_some(), "{a:?}");
        }
    }
    assert!(resumed >= 1, "bob's resumed turn performed nothing");

    // both roles are covered
    for principal in ["alice", "bob"] {
        assert!(
            exercised_keys(&report, principal) >= 1,
            "{principal} has no exercised key"
        );
    }
}
