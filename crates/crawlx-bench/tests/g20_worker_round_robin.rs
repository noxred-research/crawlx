//! Shared-workspace proof through the real worker and Chromium, not an HTTP-only replay.
//! The fixture server supplies resource ownership; captured epochs supply journal action attribution.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_bench::gym::ledger::LedgerEvent;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::trail::{verify_trail, TrailStore};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::{
    CrawlMode, ExternalCommunication, ResponseBodies, Role, SafetyProfile, StrategyName,
};
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::repo::SessionStatus;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::traffic::TrustLane;
use crawlx_core::CoreError;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, LocalRun, Stores};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct WorkspaceSecrets;

#[async_trait]
impl SecretResolver for WorkspaceSecrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        match reference.0.as_str() {
            "fixture://alice" => Ok(SecretOr::secret("alice:gym-pass".to_owned())),
            "fixture://bob" => Ok(SecretOr::secret("bob:gym-pass".to_owned())),
            _ => Err(CoreError::CredentialUnavailable(reference.0.clone())),
        }
    }
}

fn workspace_role(base: &str, name: &str) -> Role {
    // G20's real login endpoint sets a separate authenticated cookie in each role's browser context.
    // The recorded native click uses the same fixture login control as the full G20 matrix.
    let steps = json!({"steps": [
        {"action": "navigate", "value": format!("{base}/g20/")},
        {"action": "click", "selector": format!("#login-{name}")},
        {"action": "wait", "value": "1s"},
        {"action": "navigate", "value": format!("{base}/g20/roundtrip.html")},
        {"action": "wait", "value": "1s"}
    ]});
    Role {
        name: name.to_owned(),
        credential_ref: Some(CredentialRef(format!("fixture://{name}"))),
        login_plan: Some(format!("recorded:{steps}")),
        replica_base_url: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g20_worker_round_robin_attributes_every_shared_workflow_effect() {
    // Follow the repository's browser integration convention: absent Chromium is a reported skip.
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("g20").unwrap();
    let mut crawl = crawl_request(
        &manifest,
        &gym.base_url,
        20_261_104,
        SafetyProfile::TestEnvironment,
    )
    .unwrap();
    crawl.seed_url = url::Url::parse(&format!("{}/g20/roundtrip.html", gym.base_url)).unwrap();
    crawl.mode = CrawlMode::Dynamic;
    crawl.roles = vec![
        workspace_role(&gym.base_url, "alice"),
        workspace_role(&gym.base_url, "bob"),
    ];
    crawl.runs_per_role = 2;
    crawl.limits.interactions = 40;
    crawl.limits.states = 100;
    crawl.limits.duration_seconds = 120;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs];
    crawl.safety.external_communication = ExternalCommunication::TestSinks;
    crawl.capture.response_bodies = ResponseBodies::TextCapped;
    let dir = tempfile::tempdir().unwrap();
    let config = worker_config(&manifest, dir.path()).unwrap();
    let memory = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(memory.clone(), dir.path()).await.unwrap();
    let local = LocalRun::new(crawl, config)
        .with_stores(stores.clone())
        .with_secrets(Arc::new(WorkspaceSecrets));
    let mut local = authorize_fixture(local);
    local
        .authorization
        .as_mut()
        .unwrap()
        .test_sinks
        .insert("webhook".into(), format!("{}/g20/api/invoices", gym.base_url));
    let report = run_local_with(local).await.unwrap();
    assert_eq!(report.status, RunStatus::Completed, "{report:?}");
    let mut sessions: Vec<_> = report.sessions.iter().collect();
    sessions.sort_by_key(|session| session.schedule_slot);
    assert_eq!(
        sessions
            .iter()
            .map(|session| (session.role.0.as_str(), session.run_index))
            .collect::<Vec<_>>(),
        vec![("alice", 1), ("bob", 1), ("alice", 2), ("bob", 2)]
    );
    assert!(sessions
        .iter()
        .all(|session| session.status == SessionStatus::Completed));

    // Click beacons can interleave with backend handling on another server task. Keep the
    // server API stream only; each workflow awaits its API calls and turns never overlap.
    let entries: Vec<_> = gym
        .ledger()
        .entries_for("g20")
        .into_iter()
        .filter(|entry| match &entry.event {
            LedgerEvent::Op { path, .. } => path.starts_with("/g20/api/"),
            LedgerEvent::Effect { .. } => true,
            _ => false,
        })
        .collect();
    let traffic = memory.traffic_of_run(report.run_id);
    let epochs = memory.network_epochs(report.run_id);
    let mut attributed = BTreeMap::new();
    let mut resources = BTreeMap::new();
    let mut bodies = BTreeMap::new();
    // Count all server-observed cross-principal effects, including unexpected extra operations.
    // Never derive the denominator from worker claims or only the requests that joined.
    let cross_effects = u32::try_from(
        entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.event,
                    LedgerEvent::Effect { resource_context, .. }
                        if matches!(resource_context.as_str(), "shared" | "other_user_same_role" | "admin")
                )
            })
            .count(),
    )
    .unwrap();
    let mut attributed_cross_effects = 0_u32;
    let mut cross_actions = BTreeSet::new();
    // Each workflow request carries a distinct non-secret query marker. It is recorded by the
    // server and capture backend independently; the marker never supplies an action id or owner.
    for (step, principal, round, behavior, context) in [
        ("create", "alice", 1, "create:ok", "own"),
        ("review-view", "bob", 1, "view:ok", "shared"),
        ("review-comment", "bob", 1, "comment:ok", "shared"),
        ("review-response", "bob", 1, "create:ok", "own"),
        ("observe-comment", "alice", 2, "view:ok", "own"),
        ("observe-response", "alice", 2, "view:ok", "shared"),
    ] {
        let query = format!("roundtrip={step}");
        let server_ops: Vec<_> = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| match &entry.event {
                LedgerEvent::Op {
                    method,
                    path,
                    query: Some(found),
                    ..
                } if found == &query => Some((index, method, path)),
                _ => None,
            })
            .collect();
        assert_eq!(server_ops.len(), 1, "{step}: server operations {server_ops:?}");
        let (index, method, path) = server_ops[0];
        // Backend handling is synchronous: the next API-stream row is its independently
        // inferred principal, resource and outcome, not a browser beacon claiming those facts.
        let LedgerEvent::Effect {
            principal: owner,
            effect,
            resource,
            resource_context,
        } = &entries[index + 1].event
        else {
            panic!("{step}: missing backend effect")
        };
        assert_eq!(
            (owner.as_str(), effect.as_str(), resource_context.as_str()),
            (principal, behavior, context),
            "{step}"
        );
        resources.insert(step, resource.clone());
        let captured: Vec<_> = traffic
            .iter()
            .filter(|(_, event)| {
                let url = url::Url::parse(&event.url).unwrap();
                event.method == *method && url.path() == path && url.query() == Some(query.as_str())
            })
            .collect();
        assert_eq!(captured.len(), 1, "{step}: captured traffic {captured:?}");
        let (action_id, event) = captured[0];
        assert_eq!(event.status, Some(200), "{step}");
        assert!(!event.late, "{step}: attribution arrived after settle");
        assert!(event.unattributed_reason.is_none(), "{step}: {event:?}");
        let action = report
            .actions
            .iter()
            .find(|action| action.id == *action_id)
            .expect("captured action exists in worker journal");
        assert_eq!(action.status, ActionStatus::Succeeded, "{step}: {action:?}");
        assert_eq!(action.lane, Some(TrustLane::TrustedUi), "{step}");
        assert_eq!(action.key.principal.0, principal, "{step}");
        let session = report
            .sessions
            .iter()
            .find(|session| session.id == action.session)
            .unwrap();
        assert_eq!(
            (session.role.0.as_str(), session.run_index),
            (principal, round),
            "{step}"
        );
        assert!(
            epochs.iter().any(|epoch| epoch.action == *action_id
                && Some(epoch.id) == event.epoch_id
                && epoch.session == session.id
                && epoch.lane == TrustLane::TrustedUi),
            "{step}: missing attributed network epoch"
        );
        assert!(
            report
                .ledger
                .iter()
                .any(|row| row.key == action.key && row.trusted_exercised > 0),
            "{step}: journal action has no trusted action-context ledger row"
        );
        let body = event
            .response_body
            .as_ref()
            .expect("fixture JSON response captured");
        let body: Value = serde_json::from_slice(&stores.artifacts.get(body).await.unwrap()).unwrap();
        bodies.insert(step, body);
        attributed.insert(step, *action_id);
        if context == "shared" {
            attributed_cross_effects += 1;
            cross_actions.insert(*action_id);
        }
    }
    assert_eq!(resources["create"], resources["review-view"]);
    assert_eq!(resources["create"], resources["review-comment"]);
    assert_eq!(resources["create"], resources["observe-comment"]);
    assert_eq!(resources["review-response"], resources["observe-response"]);
    assert_eq!(attributed["review-view"], attributed["review-comment"]);
    assert_eq!(attributed["review-comment"], attributed["review-response"]);
    assert_eq!(attributed["observe-comment"], attributed["observe-response"]);
    assert_ne!(attributed["review-comment"], attributed["observe-response"]);
    let workflow: Vec<_> = ["create", "review-comment", "observe-response"]
        .into_iter()
        .map(|step| {
            report
                .actions
                .iter()
                .find(|action| action.id == attributed[step])
                .unwrap()
        })
        .collect();
    for pair in workflow.windows(2) {
        assert!(pair[0].finished_at.unwrap() <= pair[1].intended_at.unwrap());
    }
    // Alice's round-two captured response proves she actually received Bob's round-one comment.
    assert_eq!(bodies["observe-comment"]["invoice"]["comments"][0]["by"], "bob");
    assert_eq!(
        bodies["observe-comment"]["invoice"]["comments"][0]["text"],
        "Reviewed by Bob in round one"
    );
    assert_eq!(bodies["observe-response"]["invoice"]["owner"], "bob");
    assert_eq!(cross_effects, 3, "nonempty server-grounded denominator");
    assert_eq!(
        cross_actions.len(),
        2,
        "both principals have distinct cross-principal action ids"
    );
    assert_eq!(attributed_cross_effects, cross_effects);
    let cross_principal_attribution_rate = f64::from(attributed_cross_effects) / f64::from(cross_effects);
    assert!((cross_principal_attribution_rate - 1.0).abs() < f64::EPSILON);
    let clicks = gym.ledger().clicks("g20");
    let workflow_clicks: Vec<_> = clicks
        .iter()
        .filter(|(control, _)| control.starts_with("roundtrip-"))
        .collect();
    assert_eq!(
        workflow_clicks.len(),
        3,
        "one native click for each workflow turn"
    );
    assert!(workflow_clicks.iter().all(|(_, trusted)| *trusted));
    let trail = verify_trail(
        report.run_id,
        TrailStore::Memory {
            store: &memory,
            artifacts: Some(stores.artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(trail.is_clean(), "{trail}");
    gym.shutdown().await;
}
