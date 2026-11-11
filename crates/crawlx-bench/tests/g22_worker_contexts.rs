//! G22: real worker scheduling, reviewer-granted approvals and server-grounded context recall.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_bench::gym::ledger::LedgerEvent;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{CrawlMode, DestructiveActions, Role, SafetyProfile, StrategyName};
use crawlx_core::counters::{ActionStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::safety::RiskClass;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{ActionContextId, ApprovalId, CoreError, SystemClock, Timestamp, TrustLane};
use crawlx_safety::{
    ApprovalError, ApprovalRecord, ApprovalRequest, ApprovalState, ApprovalStore, InMemoryApprovalStore,
};
use crawlx_storage::MemoryStore;
use crawlx_strategies::InMemoryLedger;
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayRunner, StepVerdict};
use crawlx_worker::{run_local_with, Gates, LocalRun, Stores};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

struct FixtureSecrets;

#[async_trait]
impl SecretResolver for FixtureSecrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        let user = reference
            .0
            .strip_prefix("fixture://")
            .ok_or_else(|| CoreError::CredentialUnavailable(reference.0.clone()))?;
        if !matches!(user, "alice" | "bob" | "admin") {
            return Err(CoreError::CredentialUnavailable(reference.0.clone()));
        }
        Ok(SecretOr::secret(format!("{user}:gym-pass")))
    }
}

// This explicit test reviewer approves only this fixture's destructive click requests.
// It delegates all binding, expiry and atomic single-use checks to the real approval store.
// The worker cannot construct an admitted action from this reviewer's decision alone.
struct FixtureReviewer {
    store: InMemoryApprovalStore,
    issued: Mutex<Vec<ApprovalId>>,
}

impl FixtureReviewer {
    fn new() -> Self {
        Self {
            store: InMemoryApprovalStore::new(Arc::new(SystemClock)),
            issued: Mutex::new(Vec::new()),
        }
    }
}

impl ApprovalStore for FixtureReviewer {
    fn issue(&self, request: ApprovalRequest) -> Result<(), ApprovalError> {
        if request.risk != RiskClass::Destructive
            || !request.summary.contains("kind=click")
            || !["alice", "bob", "admin"]
                .iter()
                .any(|principal| request.summary.contains(&format!("principal={principal} ")))
        {
            return Err(ApprovalError::Unavailable);
        }
        let id = request.approval_id;
        let now = request.created_at;
        self.store.issue(request)?;
        self.issued.lock().unwrap().push(id);
        self.store.approve(id, "g22-fixture-reviewer", now)
    }

    fn find_open(
        &self,
        key: ActionContextId,
        risk: RiskClass,
        params: &Digest,
        now: Timestamp,
    ) -> Result<Option<ApprovalRecord>, ApprovalError> {
        self.store.find_open(key, risk, params, now)
    }

    fn get(&self, id: ApprovalId) -> Result<Option<ApprovalRecord>, ApprovalError> {
        self.store.get(id)
    }

    fn approve(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError> {
        self.store.approve(id, by, now)
    }

    fn deny(&self, id: ApprovalId, by: &str, now: Timestamp) -> Result<(), ApprovalError> {
        self.store.deny(id, by, now)
    }

    fn consume(
        &self,
        id: ApprovalId,
        key: ActionContextId,
        risk: RiskClass,
        params: &Digest,
        now: Timestamp,
    ) -> Result<(), ApprovalError> {
        self.store.consume(id, key, risk, params, now)
    }
}

fn role(base: &str, principal: &str) -> Role {
    // Native, authenticated setup toggles both real resources before each role's turn.
    // Six serial turns alternate archived/active; each principal therefore sees both states.
    // Setup never clicks Delete. The ordinary strategies must discover and schedule it.
    let plan = json!({"steps": [
        {"action": "navigate", "value": format!("{base}/__gym/snapshot?checkpoint=g22-login")},
        {"action": "navigate", "value": format!("{base}/g22/")},
        {"action": "click", "selector": "#login-admin"},
        {"action": "wait", "value": "1s"},
        {"action": "click", "selector": "#archive"},
        {"action": "wait", "value": "1s"},
        {"action": "click", "selector": "#pick-2"},
        {"action": "click", "selector": "#archive"},
        {"action": "wait", "value": "1s"},
        {"action": "click", "selector": format!("#login-{principal}")},
        {"action": "wait", "value": "1s"},
        {"action": "navigate", "value": format!("{base}/g22/worker.html")},
        {"action": "wait", "value": "1s"}
    ]});
    Role {
        name: principal.to_owned(),
        credential_ref: Some(CredentialRef(format!("fixture://{principal}"))),
        login_plan: Some(format!("recorded:{plan}")),
        replica_base_url: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g22_worker_covers_contexts_consumes_approvals_and_replay_halts_at_destructive_prefix() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("g22").unwrap();
    let mut crawl = crawl_request(
        &manifest,
        &gym.base_url,
        20_261_104,
        SafetyProfile::TestEnvironment,
    )
    .unwrap();
    crawl.seed_url = url::Url::parse(&format!("{}/g22/worker.html", gym.base_url)).unwrap();
    crawl.mode = CrawlMode::Dynamic;
    crawl.roles = ["alice", "bob", "admin"]
        .into_iter()
        .map(|principal| role(&gym.base_url, principal))
        .collect();
    crawl.runs_per_role = 2;
    crawl.safety.destructive_actions = DestructiveActions::Approval;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::StateNovelty];
    crawl.limits.interactions = 100;
    crawl.limits.states = 200;
    crawl.limits.duration_seconds = 180;
    let dir = tempfile::tempdir().unwrap();
    let mut config = worker_config(&manifest, dir.path()).unwrap();
    // Explicit test-only gate status, never a production default or fabricated gate evidence.
    config.gates = Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let memory = Arc::new(MemoryStore::new());
    let mut stores = Stores::over_memory(memory.clone(), dir.path()).await.unwrap();
    let reviewer = Arc::new(FixtureReviewer::new());
    let local = LocalRun::new(crawl, config.clone())
        .with_stores(stores.clone())
        .with_secrets(Arc::new(FixtureSecrets))
        .with_approval_store(reviewer.clone());
    let local = authorize_fixture(local);
    // Replay must re-read the same live fixture authority, not reopen an empty
    // memory repository or trust only the source run's admission snapshot.
    stores = stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(
        local
            .authorization
            .clone()
            .expect("verified fixture authorization"),
    )));
    let report = run_local_with(local.with_stores(stores.clone())).await.unwrap();
    assert_eq!(report.sessions.len(), 6, "{report:?}");
    assert!(report.status.is_terminal(), "{report:?}");
    assert!(
        matches!(
            report.terminal_reason,
            Some(TerminalReason::LimitReached | TerminalReason::FrontierExhausted)
        ),
        "context recall requires complete role turns, not a clock cut: {:?}; sessions: {:?}",
        report.terminal_reason,
        report.sessions
    );

    // Backend effects are independent of the click beacon and worker claims.
    let effects: Vec<_> = gym
        .ledger()
        .entries_for("g22")
        .into_iter()
        .filter_map(|entry| match entry.event {
            LedgerEvent::Effect {
                principal,
                effect,
                resource,
                ..
            } if effect.starts_with("delete:") => Some((principal, resource, effect)),
            _ => None,
        })
        .collect();
    assert!(
        !effects.is_empty(),
        "the fixture reviewer admitted no real server effect"
    );
    let mut captured: Vec<_> = memory
        .traffic_of_run(report.run_id)
        .into_iter()
        .filter(|(_, event)| event.method == "DELETE" && event.url.contains("/g22/api/items/"))
        .collect();
    captured.sort_by_key(|(_, event)| event.started_at);
    assert_eq!(
        captured.len(),
        effects.len(),
        "every server effect must join captured traffic"
    );
    let mut delete_elements = BTreeSet::new();
    let mut delete_keys = BTreeSet::new();
    let mut observed = BTreeSet::new();
    let mut curve = Vec::new();
    let mut last_delete = None;
    for ((action_id, event), (principal, resource, effect)) in captured.iter().zip(&effects) {
        let action = report
            .actions
            .iter()
            .find(|action| action.id == *action_id)
            .unwrap();
        assert_eq!(action.status, ActionStatus::Succeeded, "{action:?}");
        assert_eq!(action.lane, Some(TrustLane::TrustedUi));
        assert_eq!(&action.key.principal.0, principal);
        assert!(!event.late && event.unattributed_reason.is_none(), "{event:?}");
        assert!(report
            .ledger
            .iter()
            .any(|row| row.key == action.key && row.trusted_exercised > 0));
        delete_elements.insert(action.key.element);
        delete_keys.insert(action.key.id());
        observed.insert((principal.clone(), resource.clone(), effect.clone()));
        curve.push(observed.len());
        last_delete = Some(action.id);
    }
    assert_eq!(
        delete_elements.len(),
        1,
        "Delete's element identity must never change"
    );
    let delete_clicks: Vec<_> = gym
        .ledger()
        .clicks("g22")
        .into_iter()
        .filter(|(control, _)| control == "delete")
        .collect();
    assert_eq!(delete_clicks.len(), captured.len());
    assert!(
        delete_clicks.iter().all(|(_, trusted)| *trusted),
        "no synthetic Delete may count"
    );
    let expected: BTreeSet<_> = manifest
        .expected
        .action_contexts
        .iter()
        .map(|context| {
            (
                context.principal.clone(),
                context.resource.clone().unwrap(),
                context.backend_effect.clone(),
            )
        })
        .collect();
    assert_eq!(expected.len(), 12);
    let covered = observed.intersection(&expected).count();
    let recall = f64::from(u32::try_from(covered).unwrap()) / 12.0;
    assert_eq!(curve[0], 1, "element coverage saturates before context recall");
    assert!(
        recall >= 0.9,
        "G22 action-context recall >= 0.9: {recall}; missing {:?}",
        expected.difference(&observed).collect::<Vec<_>>()
    );
    assert!(
        delete_keys.len() >= covered,
        "distinct server behaviors must not collapse into one coverage key"
    );
    assert!(
        curve.iter().skip(1).any(|count| *count > 1),
        "remaining contexts were never scheduled"
    );
    eprintln!("G22 element coverage after first Delete=1.0; context recall after first Delete={:.6}; metric gap={:.6}; final context recall={recall:.6}; threshold=0.9; contexts={covered}/12", 1.0 / 12.0, 1.0 - 1.0 / 12.0);

    // Rebuilding the strategy ledger from durable rows cannot cover parked requests.
    // Successful native actions, not proposal counts or issued approvals, are authoritative.
    let mut succeeded: BTreeMap<ActionContextId, u32> = BTreeMap::new();
    for action in &report.actions {
        if action.status == ActionStatus::Succeeded && action.lane == Some(TrustLane::TrustedUi) {
            *succeeded.entry(action.key.id()).or_default() += 1;
        }
    }
    for row in &report.ledger {
        assert_eq!(
            row.trusted_exercised,
            succeeded.get(&row.key.id()).copied().unwrap_or(0),
            "{row:?}"
        );
    }
    let rebuilt = InMemoryLedger::from_rows(report.ledger.clone());
    assert_eq!(rebuilt.coverage(None), report.coverage);
    let issued = reviewer.issued.lock().unwrap().clone();
    let consumed: Vec<_> = issued
        .iter()
        .filter_map(|id| reviewer.get(*id).unwrap())
        .filter(|record| matches!(record.state, ApprovalState::Consumed { .. }))
        .collect();
    assert!(!consumed.is_empty());
    assert!(
        delete_keys
            .iter()
            .all(|key| consumed.iter().any(|record| record.request.action_key == *key)),
        "each destructive context needs its own consumed approval"
    );

    // Request the complete path through the last Delete. A fresh kernel must halt
    // at its first destructive step, without reusing any consumed source approval.
    let before_replay = gym.ledger().count_ops("DELETE", "/g22/api/items");
    let target = last_delete.unwrap();
    let plan = ReplayPlan::load(&stores, report.run_id, target).await.unwrap();
    let source_path: Vec<_> = plan.steps.iter().map(|step| step.action.id).collect();
    assert_eq!(
        source_path.last(),
        Some(&target),
        "the full last-Delete path must be retained"
    );
    let first_delete = plan
        .steps
        .iter()
        .find(|step| captured.iter().any(|(id, _)| *id == step.action.id))
        .expect("the source path must contain a server-grounded Delete");
    let first_delete_id = first_delete.action.id;
    let first_delete_key = first_delete.action.key.id();
    // Capture precedes every native login setup. Bind its unique server-issued checkpoint
    // through captured traffic to this exact source session, not a principal or run index.
    let checkpoint_url = format!("{}/__gym/snapshot?checkpoint=g22-login", gym.base_url);
    let (_, checkpoint) = memory
        .traffic_of_run(report.run_id)
        .into_iter()
        .filter_map(|(action_id, event)| {
            let action = report.actions.iter().find(|action| action.id == action_id)?;
            if action.session != plan.session.id || event.url != checkpoint_url {
                return None;
            }
            event
                .response_headers
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-gym-checkpoint"))
                .map(|(_, checkpoint)| (action.seq, checkpoint))
        })
        .min_by_key(|(seq, _)| *seq)
        .expect("source session's pre-login fixture checkpoint must join captured traffic");
    let source_evidence = gym.ledger().entries();
    assert!(
        gym.restore_checkpoint(&checkpoint),
        "missing source checkpoint {checkpoint}"
    );
    assert_eq!(
        gym.ledger().entries(),
        source_evidence,
        "restore must preserve source custody"
    );
    assert!(
        consumed.iter().all(|record| matches!(
            reviewer.get(record.request.approval_id).unwrap().unwrap().state,
            ApprovalState::Consumed { .. }
        )),
        "fixture restoration must not revive consumed source approvals"
    );
    let replay = ReplayRunner::run(
        config,
        plan,
        ReplayMode::Reproduce,
        None,
        Some(Arc::new(FixtureSecrets)),
    )
    .await
    .unwrap();
    let stopped = replay.steps.last().expect("replay must report its blocking step");
    assert_eq!(stopped.verdict, StepVerdict::Denied, "{replay:?}");
    assert_eq!(
        stopped.action, first_delete_id,
        "the first source Delete must halt replay"
    );
    assert!(
        consumed
            .iter()
            .any(|record| record.request.action_key == first_delete_key),
        "the blocked source Delete must have consumed its own approval"
    );
    let replayed_path: Vec<_> = replay.steps.iter().map(|step| step.action).collect();
    assert_eq!(
        replayed_path,
        source_path[..replayed_path.len()],
        "replay must execute the untrimmed source prefix without skipping steps"
    );
    for step in &replay.steps {
        let source = report
            .actions
            .iter()
            .find(|action| action.id == step.action)
            .unwrap();
        if delete_elements.contains(&source.key.element) {
            assert_eq!(
                step.verdict,
                StepVerdict::Denied,
                "no destructive replay may execute"
            );
        }
    }
    assert!(!replay.ok, "denied destructive replay must not claim a match");
    assert_eq!(gym.ledger().count_ops("DELETE", "/g22/api/items"), before_replay);
    assert_eq!(
        stores.journal.list(report.run_id, None).await.unwrap(),
        report.actions,
        "replay must not rewrite source actions"
    );
    let after_replay = gym.ledger().entries();
    assert_eq!(
        after_replay[..source_evidence.len()],
        source_evidence,
        "source server evidence must remain an unchanged prefix"
    );
    for record in &consumed {
        assert_eq!(
            reviewer.get(record.request.approval_id).unwrap().as_ref(),
            Some(record),
            "replay must not alter consumed source approvals"
        );
    }
    assert_eq!(
        InMemoryLedger::from_rows(report.ledger.clone()).coverage(None),
        report.coverage
    );
    gym.shutdown().await;
}
