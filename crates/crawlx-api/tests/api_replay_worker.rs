//! Replay requests execute through the API router, durable lease dispatch and session actor.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use axum::http::StatusCode;
use common::{env, Env};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::{ActionStatus, RunStatus, TerminalReason};
use crawlx_core::repo::{RunEvent, SessionStatus};
use crawlx_core::{ActionId, Clock, CrawlRunId, CreateCrawl, StoreError, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_policy::AuthorizationRecord;
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{
    run_local_with, EgressConfig, LocalRun, StaticAuthorizationSource, Stores, WorkerConfig,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const HOME: &str = "https://app.example.test/";
const NEXT: &str = "https://app.example.test/next";
const LATER: &str = "https://app.example.test/later";

fn config(dir: &Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        max_sessions: 1,
        authorization_recheck: Duration::ZERO,
        idle_exit_after: Some(Duration::from_millis(100)),
        ..WorkerConfig::default()
    }
}

fn backend(script: FakeScript) -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// The first action is a non-idempotent POST. Each page exposes exactly one next action.
fn site(diverged: bool) -> FakeScript {
    let mut next = FakePage::new(NEXT)
        .title("Saved")
        .node(FakeAxSpec::link("next", "Next", "/later"))
        .on_click("next", vec![FakeEffect::Navigate("/later".to_owned())])
        .on(
            crawlx_core::ActionKind::KeyboardActivate,
            "next",
            vec![FakeEffect::Navigate("/later".to_owned())],
        );
    if diverged {
        for index in 0..40 {
            next = next.node(FakeAxSpec::button(
                format!("changed-{index}"),
                format!("Unrecorded action {index}"),
            ));
        }
    }
    FakeScript::new()
        .page(
            FakePage::new(HOME)
                .title("Edit")
                .node(
                    FakeAxSpec::button("save", "Save")
                        .live_attr("form-method", "post")
                        .live_attr("form-action", "/next"),
                )
                .on_click("save", vec![FakeEffect::Navigate("/next".to_owned())])
                .on(
                    crawlx_core::ActionKind::KeyboardActivate,
                    "save",
                    vec![FakeEffect::Navigate("/next".to_owned())],
                ),
        )
        .page(next)
        .page(
            FakePage::new(LATER)
                .title("Later")
                .node(FakeAxSpec::link("unrelated", "Unrelated later action", "/end"))
                .on_click("unrelated", vec![FakeEffect::Navigate("/end".to_owned())])
                .on(
                    crawlx_core::ActionKind::KeyboardActivate,
                    "unrelated",
                    vec![FakeEffect::Navigate("/end".to_owned())],
                ),
        )
        .page(FakePage::new("https://app.example.test/end").title("End"))
}

struct Recorded {
    env: Env,
    stores: Stores,
    dir: tempfile::TempDir,
    source: CrawlRunId,
    actions: Vec<ActionId>,
    source_effects: Vec<String>,
    transitions: Vec<Value>,
    source_snapshot: Value,
    authorization: StaticAuthorizationSource,
    record: AuthorizationRecord,
}

impl Recorded {
    async fn new() -> Self {
        let env = env();
        let dir = tempfile::tempdir().unwrap();
        let now = SystemClock.now();
        let record = AuthorizationRecord {
            verified_at: Some(now),
            ..crawlx_policy::testkit::sample_record(env.tenant, now, &["https://app.example.test"])
        };
        env.api.add_authorization(record.clone());
        let authorization = StaticAuthorizationSource::new(record.clone());
        let mut stores = Stores::over_memory(env.store.clone(), dir.path())
            .await
            .unwrap()
            .with_authorization_source(Arc::new(authorization.clone()));
        stores.tenant = env.tenant;
        stores.artifacts = env.artifacts.clone();
        let mut crawl = CreateCrawl::new(url::Url::parse(HOME).unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(20_261_104);
        crawl.safety.profile = SafetyProfile::TestEnvironment;
        crawl.safety.authorization_record_ref = Some(record.id);
        crawl.limits.interactions = 3;
        crawl.limits.states = 20;
        let source_backend = backend(site(false));
        let report = run_local_with(
            LocalRun::new(crawl, config(dir.path()))
                .with_stores(stores.clone())
                .with_authorization(record.clone())
                .with_backend(source_backend.clone()),
        )
        .await
        .unwrap();
        assert_eq!(report.status, RunStatus::Completed);
        let source = report.run_id;
        let mut actions: Vec<_> = report
            .actions
            .iter()
            .filter(|action| action.status == ActionStatus::Succeeded)
            .collect();
        actions.sort_by_key(|action| action.seq);
        assert_eq!(actions.len(), 3, "source must record an unrelated later action");
        assert_eq!(actions[0].key.route_template.0, "/");
        assert_eq!(actions[1].key.route_template.0, "/next", "{actions:#?}");
        assert_eq!(actions[2].key.route_template.0, "/later");
        let source_effects = performed(&source_backend);
        assert_eq!(source_effects.len(), 3);
        assert!(source_effects[0].ends_with(":save"));
        assert!(source_effects[1].ends_with(":next"));
        let actions: Vec<_> = actions.into_iter().map(|action| action.id).collect();
        let (status, _, body) = env
            .get(&format!(
                "/v1/crawls/{source}/transitions?lane=trusted_ui&status=succeeded&limit=100"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let transitions: Vec<_> = actions
            .iter()
            .map(|action| {
                body["data"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|transition| transition["action"]["id"] == json!(action))
                    .expect("the actor journal has an API transition")
                    .clone()
            })
            .collect();
        let source_snapshot = snapshot(&stores, source).await;
        Self {
            env,
            stores,
            dir,
            source,
            actions,
            source_effects,
            transitions,
            source_snapshot,
            authorization,
            record,
        }
    }

    fn request(&self, mode: &str, stop: bool) -> Value {
        json!({
            "sourceRunId": self.source,
            "role": "anonymous",
            "path": {"transitionIds": [self.transitions[0]["id"], self.transitions[1]["id"]]},
            "mode": mode,
            "stopOnDivergence": stop,
            "allowBuildMismatch": true,
        })
    }

    async fn enqueue(&self, mode: &str, stop: bool) -> CrawlRunId {
        let (status, _, body) = self.env.post("/v1/replays", &self.request(mode, stop)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let run = CrawlRunId(body["id"].as_str().unwrap().parse().unwrap());
        assert_ne!(run, self.source);
        assert_eq!(self.stores.runs.get(run).await.unwrap().status, RunStatus::Queued);
        let sessions = self.stores.runs.list_sessions(run).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].status, SessionStatus::Pending);
        let spec = self.stores.runs.replay_spec(run).await.unwrap().unwrap();
        assert_eq!(spec["actionIds"], json!(&self.actions[..2]));
        assert_eq!(
            spec["transitionIds"],
            self.request(mode, stop)["path"]["transitionIds"]
        );
        assert_eq!(
            spec["afterStateIds"],
            json!([self.transitions[0]["after"], self.transitions[1]["after"]])
        );
        assert!(
            spec["afterStateIds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|state| !state.is_null()),
            "the API must preserve the actor's exact recorded afterstates"
        );
        run
    }

    async fn dispatch(&self, backend: Arc<FakeBackend>) {
        run_with(
            config(self.dir.path()),
            self.stores.clone(),
            Some(backend),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    }

    async fn events(&self, run: CrawlRunId) -> Vec<RunEvent> {
        self.stores.events.list_after(run, 0, 1_000).await.unwrap()
    }

    async fn assert_source_unchanged(&self) {
        assert_eq!(snapshot(&self.stores, self.source).await, self.source_snapshot);
    }
}

async fn snapshot(stores: &Stores, run: CrawlRunId) -> Value {
    json!({
        "run": stores.runs.get(run).await.unwrap(),
        "sessions": stores.runs.list_sessions(run).await.unwrap(),
        "actions": stores.journal.list(run, None).await.unwrap(),
        "events": stores.events.list_after(run, 0, 1_000).await.unwrap(),
        "states": stores.states.list_states(run).await.unwrap(),
        "edges": stores.edges.list(run).await.unwrap(),
    })
}

fn performed(backend: &FakeBackend) -> Vec<String> {
    backend
        .context_handles()
        .iter()
        .flat_map(|context| context.performed_keys())
        .collect()
}

fn completed_report(events: &[RunEvent]) -> &Value {
    let reports: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "replay.completed")
        .collect();
    assert_eq!(reports.len(), 1, "exactly one durable replay report: {events:?}");
    &reports[0].payload
}

fn assert_step_events(recorded: &Recorded, events: &[RunEvent], count: usize) {
    for kind in ["replay.step_started", "replay.step_completed"] {
        let steps: Vec<_> = events.iter().filter(|event| event.kind == kind).collect();
        assert_eq!(steps.len(), count, "{kind}: {events:?}");
        for (index, event) in steps.iter().enumerate() {
            assert_eq!(event.payload["index"], json!(index));
            assert_eq!(event.payload["sourceActionId"], json!(recorded.actions[index]));
            assert_eq!(
                event.payload["sourceTransitionId"],
                recorded.transitions[index]["id"]
            );
            if kind == "replay.step_completed" {
                assert_eq!(event.payload["result"]["action"], json!(recorded.actions[index]));
            }
        }
    }
}

#[tokio::test]
async fn api_reproduce_executes_only_selected_transitions_on_the_enqueued_run() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("reproduce", true).await;
    let backend = backend(site(false));
    recorded.dispatch(backend.clone()).await;
    assert_eq!(performed(&backend), recorded.source_effects[..2]);
    assert_eq!(backend.open_contexts(), 0);
    assert_eq!(
        recorded.stores.runs.get(replay).await.unwrap().status,
        RunStatus::Completed
    );
    let sessions = recorded.stores.runs.list_sessions(replay).await.unwrap();
    assert!(sessions
        .iter()
        .all(|session| session.status == SessionStatus::Completed));
    let actions = recorded.stores.journal.list(replay, None).await.unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.status == ActionStatus::Succeeded)
            .count(),
        2
    );
    assert!(actions
        .iter()
        .all(|action| action.run == replay && action.session == sessions[0].id));
    let events = recorded.events(replay).await;
    assert_step_events(&recorded, &events, 2);
    let report = completed_report(&events);
    assert_eq!(report["ok"], true);
    assert_eq!(report["verify"], false);
    assert_eq!(report["steps"].as_array().unwrap().len(), 2);
    assert!(report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["result"] == "executed"));
    let (status, _, body) = recorded.env.get(&format!("/v1/crawls/{replay}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "completed");
    recorded.assert_source_unchanged().await;
}

#[tokio::test]
async fn api_verify_matches_the_recorded_selected_path() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("verify", true).await;
    let backend = backend(site(false));
    recorded.dispatch(backend.clone()).await;
    let events = recorded.events(replay).await;
    assert_step_events(&recorded, &events, 2);
    let report = completed_report(&events);
    assert_eq!(report["verify"], true);
    assert_eq!(report["ok"], true, "{report}");
    assert!(report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["result"] == "matched"));
    assert_eq!(performed(&backend), recorded.source_effects[..2]);
    recorded.assert_source_unchanged().await;
}

#[tokio::test]
async fn api_verify_stop_on_divergence_controls_whether_remaining_selected_steps_execute() {
    let recorded = Recorded::new().await;
    for stop in [true, false] {
        let replay = recorded.enqueue("verify", stop).await;
        let backend = backend(site(true));
        recorded.dispatch(backend.clone()).await;
        let events = recorded.events(replay).await;
        let count = if stop { 1 } else { 2 };
        assert_step_events(&recorded, &events, count);
        let report = completed_report(&events);
        assert_eq!(report["ok"], false, "{report}");
        assert_eq!(report["steps"][0]["result"], "diverged", "{report}");
        assert_eq!(report["steps"].as_array().unwrap().len(), count);
        assert_eq!(performed(&backend), recorded.source_effects[..count]);
        assert!(recorded
            .stores
            .runs
            .get(replay)
            .await
            .unwrap()
            .status
            .is_terminal());
    }
    recorded.assert_source_unchanged().await;
}

/// Cancel only after the real store commits step completion. No timing-dependent browser race.
struct CancelAfterFirstCommit {
    inner: Arc<dyn crawlx_core::repo::EventRepo>,
    run: CrawlRunId,
    cancel: CancellationToken,
}

#[async_trait]
impl crawlx_core::repo::EventRepo for CancelAfterFirstCommit {
    async fn append(&self, run: CrawlRunId, kind: &str, payload: Value) -> Result<u64, StoreError> {
        let first = run == self.run && kind == "replay.step_completed" && payload["index"] == 0;
        let seq = self.inner.append(run, kind, payload).await?;
        if first {
            self.cancel.cancel();
        }
        Ok(seq)
    }

    async fn list_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        self.inner.list_after(run, after_seq, limit).await
    }
}

#[tokio::test]
async fn api_replay_drain_and_restart_restore_checkpoint_without_repeating_committed_post() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("reproduce", true).await;
    let cancel = CancellationToken::new();
    let mut draining = recorded.stores.clone();
    draining.events = Arc::new(CancelAfterFirstCommit {
        inner: recorded.stores.events.clone(),
        run: replay,
        cancel: cancel.clone(),
    });
    let first = backend(site(false));
    run_with(config(recorded.dir.path()), draining, Some(first.clone()), cancel)
        .await
        .unwrap();
    assert_eq!(performed(&first), recorded.source_effects[..1]);
    assert_eq!(first.open_contexts(), 0);
    let session = recorded
        .stores
        .runs
        .list_sessions(replay)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(session.status, SessionStatus::Recovering);
    let checkpoint = recorded
        .stores
        .checkpoints
        .latest(session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(checkpoint.run, replay);
    assert_eq!(checkpoint.action_seq, 1);
    let before_restart = recorded.events(replay).await;
    assert_step_events(&recorded, &before_restart, 1);
    assert!(!before_restart
        .iter()
        .any(|event| event.kind == "replay.completed"));

    let second = backend(site(false));
    recorded.dispatch(second.clone()).await;
    assert_eq!(
        performed(&second),
        recorded.source_effects[1..2],
        "the committed POST must not be replayed"
    );
    assert!(second
        .context_handles()
        .iter()
        .any(|context| context.navigations().contains(&NEXT.to_owned())));
    assert_eq!(second.open_contexts(), 0);
    assert_eq!(
        recorded.stores.runs.get(replay).await.unwrap().status,
        RunStatus::Completed
    );
    let events = recorded.events(replay).await;
    assert_step_events(&recorded, &events, 2);
    assert_eq!(completed_report(&events)["ok"], true);
    let actions = recorded.stores.journal.list(replay, None).await.unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.status == ActionStatus::Succeeded)
            .count(),
        2
    );
    recorded.assert_source_unchanged().await;
}

#[tokio::test]
async fn api_replay_drain_during_action_admission_resumes_without_losing_the_selected_step() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("reproduce", true).await;
    let cancel = CancellationToken::new();
    let first = backend(site(false));
    let worker = tokio::spawn(run_with(
        config(recorded.dir.path()),
        recorded.stores.clone(),
        Some(first.clone()),
        cancel.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let actions = recorded.stores.journal.list(replay, None).await.unwrap();
            if actions
                .iter()
                .any(|action| action.status == ActionStatus::Proposed)
            {
                assert!(actions
                    .iter()
                    .all(|action| action.status == ActionStatus::Proposed));
                assert!(
                    performed(&first).is_empty(),
                    "admission has not dispatched an effect"
                );
                cancel.cancel();
                break;
            }
            assert!(!worker.is_finished(), "worker stopped before admission");
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replay reaches its first action admission");
    worker.await.unwrap().unwrap();
    let session = recorded
        .stores
        .runs
        .list_sessions(replay)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(session.status, SessionStatus::Recovering);
    assert_eq!(first.open_contexts(), 0);
    assert!(performed(&first).is_empty());

    let resumed = backend(site(false));
    recorded.dispatch(resumed.clone()).await;
    assert_eq!(performed(&resumed), recorded.source_effects[..2]);
    assert_eq!(
        recorded.stores.runs.get(replay).await.unwrap().status,
        RunStatus::Completed
    );
    assert_eq!(completed_report(&recorded.events(replay).await)["ok"], true);
    recorded.assert_source_unchanged().await;
}

/// Park after durable completion so runtime destruction models a process dying at that boundary.
struct ParkAfterFirstCommit {
    inner: Arc<dyn crawlx_core::repo::EventRepo>,
    run: CrawlRunId,
    committed: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl crawlx_core::repo::EventRepo for ParkAfterFirstCommit {
    async fn append(&self, run: CrawlRunId, kind: &str, payload: Value) -> Result<u64, StoreError> {
        let first = run == self.run && kind == "replay.step_completed" && payload["index"] == 0;
        let seq = self.inner.append(run, kind, payload).await?;
        if first {
            self.committed.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(seq)
    }

    async fn list_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        self.inner.list_after(run, after_seq, limit).await
    }
}

#[tokio::test]
async fn api_replay_worker_kill_reaps_lease_and_skips_the_committed_non_idempotent_action() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("reproduce", true).await;
    let committed = Arc::new(tokio::sync::Notify::new());
    let mut doomed = recorded.stores.clone();
    doomed.events = Arc::new(ParkAfterFirstCommit {
        inner: recorded.stores.events.clone(),
        run: replay,
        committed: committed.clone(),
    });
    let first = backend(site(false));
    let killed_backend = first.clone();
    let cfg = config(recorded.dir.path());
    tokio::task::spawn_blocking(move || {
        // Destroy the entire runtime, not just run_with's task: supervised actor/session tasks
        // otherwise outlive their caller. The shared store survives, like a process-external DB.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let worker = tokio::spawn(run_with(
                cfg,
                doomed,
                Some(killed_backend),
                CancellationToken::new(),
            ));
            tokio::time::timeout(Duration::from_secs(10), committed.notified())
                .await
                .expect("worker committed the first selected action");
            worker.abort();
            assert!(worker.await.unwrap_err().is_cancelled());
        });
        drop(runtime);
    })
    .await
    .unwrap();
    assert_eq!(performed(&first), recorded.source_effects[..1]);
    let session = recorded
        .stores
        .runs
        .list_sessions(replay)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(session.status, SessionStatus::Running);
    assert!(recorded
        .stores
        .checkpoints
        .latest(session.id)
        .await
        .unwrap()
        .is_some());
    let committed_actions = recorded.stores.journal.list(replay, None).await.unwrap();
    assert_eq!(committed_actions.len(), 1);
    assert_eq!(committed_actions[0].status, ActionStatus::Succeeded);
    assert!(committed_actions[0].before_state.is_some());
    let transitions = recorded.env.store.transitions(replay);
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].action, committed_actions[0].id);
    assert!(transitions[0].after.is_some());
    recorded
        .env
        .store
        .expire_session_lease(session.id, SystemClock.now() - chrono::Duration::hours(1));

    let second = backend(site(false));
    recorded.dispatch(second.clone()).await;
    assert_eq!(
        performed(&second),
        recorded.source_effects[1..2],
        "status={:?}; sessions={:#?}; events={:#?}",
        recorded.stores.runs.get(replay).await.unwrap().status,
        recorded.stores.runs.list_sessions(replay).await.unwrap(),
        recorded.events(replay).await,
    );
    assert_eq!(
        recorded.stores.runs.get(replay).await.unwrap().status,
        RunStatus::Completed
    );
    let events = recorded.events(replay).await;
    assert_step_events(&recorded, &events, 2);
    assert_eq!(completed_report(&events)["ok"], true);
    let actions = recorded.stores.journal.list(replay, None).await.unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.status == ActionStatus::Succeeded)
            .count(),
        2
    );
    recorded.assert_source_unchanged().await;
}

#[tokio::test]
async fn api_replay_refuses_a_target_outside_the_authorization_record() {
    let recorded = Recorded::new().await;
    let mut request = recorded.request("reproduce", true);
    request["target"] = json!({"baseUrl": "https://outside.example.test/"});
    let (status, _, body) = recorded.env.post("/v1/replays", &request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let backend = backend(site(false));
    recorded.dispatch(backend.clone()).await;
    assert!(
        backend.context_handles().is_empty(),
        "a denied target must not reach a browser"
    );
    recorded.assert_source_unchanged().await;
}

#[tokio::test]
async fn api_replay_worker_rereads_revocation_after_http_enqueue_and_before_browser_execution() {
    let recorded = Recorded::new().await;
    let replay = recorded.enqueue("reproduce", true).await;
    assert!(recorded
        .authorization
        .revoke(recorded.record.id, SystemClock.now(), "test revocation"));
    let backend = backend(site(false));
    recorded.dispatch(backend.clone()).await;
    let run = recorded.stores.runs.get(replay).await.unwrap();
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert!(backend.context_handles().is_empty());
    assert!(recorded
        .stores
        .journal
        .list(replay, None)
        .await
        .unwrap()
        .is_empty());
    assert!(!recorded
        .events(replay)
        .await
        .iter()
        .any(|event| event.kind == "replay.step_started"));
    recorded.assert_source_unchanged().await;
}
