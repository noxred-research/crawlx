//! The per-action protocol against `FakeBackend` and the in-memory journal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::{canonical, proposal_for, rig, rig_core, rig_with, Rig, RigCore};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::{ArtifactStore, CheckpointRecord, CheckpointRepo, Sensitivity, StateRepo};
use crawlx_core::safety::RiskClass;
use crawlx_core::{ArtifactRef, CrawlRunId, SafetyProfile, SessionId, StoreError, TrustLane};
use crawlx_observe::spec;
use crawlx_scheduler::CheckpointReason;
use crawlx_storage::MemoryStore;
use crawlx_worker::actor::{DropReason, SessionState};
use crawlx_worker::{SessionError, Stores};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn two_page_site() -> FakeScript {
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

#[tokio::test]
async fn unsupported_browser_handler_returns_typed_error_instead_of_default() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let mut request =
        crawlx_core::request::RequestEnvelopeV1::get(canonical("https://example.test/about"), 0, None);
    request.route = "unsupported".into();
    assert!(matches!(
        r.handle.navigate(request).await,
        Err(SessionError::Extension(
            crawlx_core::extensions::ExtensionError::UnknownRoute
        ))
    ));
    let bundle = r.handle.observe(spec::cheap()).await.unwrap();
    assert_eq!(
        bundle.url.url.as_str(),
        common::SEED,
        "refused route must not navigate"
    );
}

fn mutation_site() -> FakeScript {
    FakeScript::new().page(
        FakePage::new(common::SEED)
            .node(FakeAxSpec::button("save", "Save"))
            .on_click(
                "save",
                vec![FakeEffect::SetStorage(BTreeMap::from([(
                    "saved".to_owned(),
                    "true".to_owned(),
                )]))],
            ),
    )
}

const CHECKPOINT_OUTAGE: &str = "injected checkpoint persistence failure";

struct FailingCheckpoints {
    artifacts: Arc<dyn ArtifactStore>,
    checkpoints: Arc<dyn CheckpointRepo>,
    fail: AtomicBool,
    fail_artifacts: bool,
}

#[async_trait]
impl ArtifactStore for FailingCheckpoints {
    async fn put(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        if self.fail_artifacts && self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable(CHECKPOINT_OUTAGE.to_owned()));
        }
        self.artifacts.put(run, class, content_type, bytes).await
    }

    async fn put_until(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
        deadline: crawlx_core::Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        if self.fail_artifacts && self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable(CHECKPOINT_OUTAGE.to_owned()));
        }
        self.artifacts
            .put_until(run, class, content_type, bytes, deadline)
            .await
    }

    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        self.artifacts.get(artifact).await
    }
}

#[async_trait]
impl CheckpointRepo for FailingCheckpoints {
    async fn put(&self, checkpoint: &CheckpointRecord) -> Result<(), StoreError> {
        if !self.fail_artifacts && self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable(CHECKPOINT_OUTAGE.to_owned()));
        }
        self.checkpoints.put(checkpoint).await
    }

    async fn latest(&self, session: SessionId) -> Result<Option<CheckpointRecord>, StoreError> {
        self.checkpoints.latest(session).await
    }

    async fn list(&self, session: SessionId) -> Result<Vec<CheckpointRecord>, StoreError> {
        self.checkpoints.list(session).await
    }
}

async fn mutation_rig_with_checkpoint_outage(fail_artifacts: bool) -> (Rig, Arc<FailingCheckpoints>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let failing = Arc::new(FailingCheckpoints {
        artifacts: stores.artifacts.clone(),
        checkpoints: stores.checkpoints.clone(),
        fail: AtomicBool::new(false),
        fail_artifacts,
    });
    stores.artifacts = failing.clone();
    stores.checkpoints = failing.clone();
    let fake = Arc::new(
        FakeBackend::builder()
            .script(mutation_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let RigCore {
        stores,
        backend,
        rc,
        handle,
        run,
        session,
        principal,
        dir,
    } = rig_core(stores, dir, fake.clone(), fake, SafetyProfile::TestEnvironment).await;
    (
        Rig {
            store,
            stores,
            backend,
            rc,
            handle,
            run,
            session,
            principal,
            dir,
            flaky: None,
        },
        failing,
    )
}

async fn observe_cluster(
    r: &Rig,
) -> (
    Arc<crawlx_core::observation::ObservationBundle>,
    crawlx_core::StateClusterId,
) {
    let bundle = r.handle.observe(spec::after_action()).await.unwrap();
    let state = crawlx_worker::StateAnalyzer::new(
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
    r.store.put_state(&state).await.unwrap();
    (bundle, state.cluster)
}

#[tokio::test]
async fn happy_path_journals_proposed_intended_succeeded_with_a_transition() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    let out = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();

    assert_eq!(out.status, ActionStatus::Succeeded);
    assert!(out.dropped.is_none());
    assert_eq!(out.receipt.as_ref().unwrap().lane, TrustLane::TrustedUi);
    let after = out.after.expect("after observation");
    assert_eq!(after.url.url.path(), "/about");

    let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), out.action_id)
        .await
        .unwrap();
    assert_eq!(rec.status, ActionStatus::Succeeded);
    assert_eq!(rec.lane, Some(TrustLane::TrustedUi));
    assert_eq!(rec.attempt, 0);
    assert!(rec.intended_at.is_some() && rec.finished_at.is_some());
    assert!(rec.before_state.is_some(), "before-state links the transition");
    // the T2 transaction persisted the after-state
    let states = r.store.list_states(r.run).await.unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[1].url.url.path(), "/about");
    assert!(out.after_state.is_some());
    // proposed -> intended -> succeeded is the only legal path; the events show T2
    let events = crawlx_core::repo::EventRepo::list_after(r.store.as_ref(), r.run, 0, 100)
        .await
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "action.finished"));
    // the coverage ledger counts the trusted execution
    let ledger = crawlx_core::repo::LedgerRepo::list(r.store.as_ref(), r.run)
        .await
        .unwrap();
    assert_eq!(ledger.iter().map(|l| l.trusted_exercised).sum::<u32>(), 1);
    assert_eq!(
        r.backend.context_handles()[0].performed(),
        vec![ActionKind::Click]
    );
}

#[tokio::test]
async fn stale_epoch_is_dropped_without_touching_the_browser() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    // the page navigates away after the proposal was derived
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://example.test/about"),
            0,
            None,
        ))
        .await
        .unwrap();
    let out = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.dropped, Some(DropReason::StaleEpoch));
    assert_eq!(out.status, ActionStatus::Proposed);
    assert!(r.backend.context_handles()[0].performed().is_empty());
    let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), out.action_id)
        .await
        .unwrap();
    assert_eq!(rec.status, ActionStatus::Proposed, "never intended");
}

#[tokio::test]
async fn revalidation_failures_are_dropped() {
    for (script, want) in [
        (two_page_site().detached("about"), DropReason::NotActionable),
        (two_page_site().obscured("about"), DropReason::NotActionable),
        (
            two_page_site().identity_changed("about"),
            DropReason::IdentityChanged,
        ),
        (two_page_site().stale("about"), DropReason::StaleEpoch),
    ] {
        let r = rig(script, SafetyProfile::ReadOnly).await;
        let (bundle, cluster) = observe_cluster(&r).await;
        let (p, c) = r.proposal(&bundle, "About", cluster);
        let out = r
            .handle
            .execute(r.admit(p, &c), QuiescencePolicy::default())
            .await
            .unwrap();
        assert_eq!(out.dropped, Some(want));
        assert!(r.backend.context_handles()[0].performed().is_empty());
    }
}

#[tokio::test]
async fn kernel_confirm_denial_drops_the_action() {
    // between admission and confirmation the control is renamed: the kernel's identity digest no
    // longer matches what it classified, so the action is dropped before T1
    let script = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .node(FakeAxSpec::link("go", "Open", "/open"))
            .node(FakeAxSpec::button("rename", "Rename"))
            .on_click(
                "rename",
                vec![FakeEffect::SetName {
                    key: "go".into(),
                    name: "Delete account".into(),
                }],
            ),
    );
    let r = rig(script, SafetyProfile::TestEnvironment).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (open, open_ctx) = r.proposal(&bundle, "Open", cluster);
    let admitted_open = r.admit(open, &open_ctx);
    let (rename, rename_ctx) = r.proposal(&bundle, "Rename", cluster);
    let renamed = r
        .handle
        .execute(r.admit(rename, &rename_ctx), QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(renamed.status, ActionStatus::Succeeded);
    let out = r
        .handle
        .execute(admitted_open, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.dropped, Some(DropReason::ConfirmDenied));
    assert_eq!(
        r.backend.context_handles()[0].performed(),
        vec![ActionKind::Click],
        "only the rename ran"
    );
    let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), out.action_id)
        .await
        .unwrap();
    assert_eq!(rec.status, ActionStatus::Proposed);
}

#[tokio::test]
async fn t1_failure_halts_mutation_then_recovers_when_storage_is_back() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(two_page_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_with(fake.clone(), fake, true, SafetyProfile::ReadOnly).await;
    let flaky = r.flaky.clone().unwrap();
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    flaky.fail_intend.store(true, Ordering::SeqCst);
    let err = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::HaltedStorage(_)), "{err:?}");
    assert_eq!(r.handle.state(), SessionState::HaltedStorage);
    assert!(
        r.backend.context_handles()[0].performed().is_empty(),
        "no perform after a T1 failure"
    );

    // storage heals: the next action probes, leaves HaltedStorage and runs
    flaky.fail_intend.store(false, Ordering::SeqCst);
    let bundle = r.handle.observe(spec::after_action()).await.unwrap();
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let out = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.status, ActionStatus::Succeeded);
    assert_eq!(r.handle.state(), SessionState::Ready);
}

#[tokio::test]
async fn t2_failure_is_retried_three_times_then_halts_with_the_action_intended() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(two_page_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_with(fake.clone(), fake, true, SafetyProfile::ReadOnly).await;
    let flaky = r.flaky.clone().unwrap();
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    flaky.fail_finish.store(true, Ordering::SeqCst);
    let err = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::HaltedStorage(_)), "{err:?}");
    assert_eq!(flaky.finish_attempts.load(Ordering::SeqCst), 3);
    assert_eq!(r.handle.state(), SessionState::HaltedStorage);
    let rows = r.actions().await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].status,
        ActionStatus::Intended,
        "left for the reaper to flip to unknown"
    );
}

fn crashing_site() -> FakeScript {
    two_page_site().crash_on(crawlx_browser::fake::action_key(ActionKind::Click, "about"))
}

#[tokio::test]
async fn crash_after_intent_becomes_unknown_and_reconcile_not_applied_makes_it_eligible_again() {
    for coarsened in [false, true] {
        let fake = Arc::new(
            FakeBackend::builder()
                .script(crashing_site())
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        );
        let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
        let (bundle, cluster) = observe_cluster(&r).await;
        // the proposal declares the navigation it expects: its absence is strong negative evidence
        let (mut p, c) = r.proposal(&bundle, "About", cluster);
        if coarsened {
            p.key.state_cluster = p.key.coarsened_cluster();
        }
        p.expected.navigates_to = Some("/about".to_owned());
        let key = p.key.clone();
        let err = r
            .handle
            .execute(r.admit(p, &c), QuiescencePolicy::default())
            .await
            .unwrap_err();
        let SessionError::CrashedDuringAction(id) = err else {
            panic!("{err:?}")
        };
        let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), id)
            .await
            .unwrap();
        assert_eq!(rec.status, ActionStatus::Unknown);
        assert!(
            r.store.eligible_actions(r.run, None).is_empty(),
            "unknown actions are never eligible"
        );

        // the actor recovered (the fake context survives); the click never took effect
        fake.script_handle().lock().crash_on_action = None;
        let resolution = r.handle.reconcile(id).await.unwrap();
        assert_eq!(resolution.resolution, ReconcileResolution::NotApplied);
        let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), id)
            .await
            .unwrap();
        assert_eq!(rec.status, ActionStatus::Reconciled);
        let eligible = r.store.eligible_actions(r.run, None);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].key, key);

        // re-executing under the same id bumps the attempt and succeeds
        let bundle = r.handle.observe(spec::after_action()).await.unwrap();
        let (p, c) = r.proposal(&bundle, "About", cluster);
        let mut p = p;
        if coarsened {
            p.key.state_cluster = p.key.coarsened_cluster();
        }
        let out = r
            .handle
            .execute_retry(r.admit(p, &c), QuiescencePolicy::default(), id)
            .await
            .unwrap();
        assert_eq!(out.action_id, id);
        let rec = crawlx_core::repo::ActionJournal::get(r.store.as_ref(), id)
            .await
            .unwrap();
        assert_eq!((rec.status, rec.attempt), (ActionStatus::Succeeded, 1));
    }
}

#[tokio::test]
async fn crash_after_intent_with_a_visible_effect_reconciles_as_applied_and_stays_ineligible() {
    // the click navigated before the browser died: the session is no longer in the before-cluster
    let fake = Arc::new(
        FakeBackend::builder()
            .script(crashing_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (mut p, c) = r.proposal(&bundle, "About", cluster);
    p.expected.navigates_to = Some("/about".to_owned());
    let err = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap_err();
    let SessionError::CrashedDuringAction(id) = err else {
        panic!("{err:?}")
    };
    fake.script_handle().lock().crash_on_action = None;
    // the recovered page shows the effect
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://example.test/about"),
            0,
            None,
        ))
        .await
        .unwrap();
    let resolution = r.handle.reconcile(id).await.unwrap();
    assert_eq!(resolution.resolution, ReconcileResolution::Applied);
    assert!(
        r.store.eligible_actions(r.run, None).is_empty(),
        "an applied action is never retried"
    );
}

#[tokio::test]
async fn a_mutation_persists_a_restore_point_before_perform() {
    let r = rig(mutation_site(), SafetyProfile::TestEnvironment).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let storage_before = r.handle.storage_digest().await.unwrap();
    let (p, c) = r.proposal(&bundle, "Save", cluster);
    let admitted = r.admit(p, &c);
    assert_eq!(admitted.risk(), RiskClass::PersistentWriteOwn);

    let out = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.status, ActionStatus::Succeeded);
    assert_eq!(
        r.backend.context_handles()[0].performed(),
        vec![ActionKind::Click]
    );
    assert_ne!(r.handle.storage_digest().await.unwrap(), storage_before);
    let checkpoints = CheckpointRepo::list(r.store.as_ref(), r.session).await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].reason, CheckpointReason::PreMutation.as_str());
    assert_eq!(checkpoints[0].action_seq, 0);
    r.handle.restore(checkpoints[0].id).await.unwrap();
    assert_eq!(r.handle.storage_digest().await.unwrap(), storage_before);
}

#[tokio::test]
async fn a_failed_required_checkpoint_halts_before_intent_or_mutation() {
    for fail_artifacts in [true, false] {
        for previous_checkpoint in [false, true] {
            let (r, failing) = mutation_rig_with_checkpoint_outage(fail_artifacts).await;
            let (bundle, cluster) = observe_cluster(&r).await;
            let previous = if previous_checkpoint {
                Some(r.handle.checkpoint(CheckpointReason::Pause).await.unwrap())
            } else {
                None
            };
            let (p, c) = r.proposal(&bundle, "Save", cluster);
            let admitted = r.admit(p, &c);
            assert_eq!(admitted.risk(), RiskClass::PersistentWriteOwn);
            failing.fail.store(true, Ordering::SeqCst);

            let error = r
                .handle
                .execute(admitted, QuiescencePolicy::default())
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    SessionError::HaltedStorage(StoreError::Unavailable(message))
                        if message == CHECKPOINT_OUTAGE
                ),
                "{error:?}; fail_artifacts={fail_artifacts}"
            );
            assert_eq!(r.handle.state(), SessionState::HaltedStorage);
            assert!(r.backend.context_handles()[0].performed().is_empty());
            let actions = r.actions().await;
            assert_eq!(actions.len(), 1);
            assert_eq!(actions[0].status, ActionStatus::Proposed, "never intended");
            assert!(actions[0].intended_at.is_none());
            assert!(actions[0].finished_at.is_none(), "never committed");
            let checkpoints = CheckpointRepo::list(r.store.as_ref(), r.session).await.unwrap();
            assert_eq!(
                checkpoints
                    .iter()
                    .map(|checkpoint| checkpoint.id)
                    .collect::<Vec<_>>(),
                previous.into_iter().collect::<Vec<_>>(),
                "a stale restore point cannot replace the required checkpoint"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn checkpoints_are_written_every_fifty_actions() {
    // one page whose control toggles forever: 120 trusted actions
    // Exercise the full cadence without sleeping through 120 browser admission intervals.
    let script = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .node(FakeAxSpec::link("l", "Self", "/"))
            .on_click("l", vec![FakeEffect::Nothing]),
    );
    let r = rig(script, SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    for i in 1..=120u32 {
        let bundle = if i == 1 {
            bundle.clone()
        } else {
            r.handle.observe(spec::after_action()).await.unwrap()
        };
        let (p, c) = proposal_for(
            &bundle,
            "Self",
            ActionKind::Click,
            cluster,
            &r.principal,
            &r.rc.seed_origin(),
            SafetyProfile::ReadOnly,
        );
        let out = r
            .handle
            .execute(r.admit(p, &c), QuiescencePolicy::default())
            .await
            .unwrap();
        assert_eq!(out.status, ActionStatus::Succeeded, "action {i}");
    }
    let cps = CheckpointRepo::list(r.store.as_ref(), r.session).await.unwrap();
    let mut seqs: Vec<(u64, String)> = cps.iter().map(|c| (c.action_seq, c.reason.clone())).collect();
    seqs.sort();
    assert_eq!(
        seqs.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        vec![50, 100],
        "cadence checkpoints at actions 50 and 100: {seqs:?}"
    );
    assert!(seqs
        .iter()
        .all(|(_, why)| why == CheckpointReason::CadenceActions.as_str()));
    // restore from the newest checkpoint navigates back to its URL with storage re-imported
    let report = r.handle.restore(cps[0].id).await.unwrap();
    assert_eq!(report.url, "https://example.test/");
}

#[tokio::test]
async fn newest_three_checkpoints_are_kept() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let _ = observe_cluster(&r).await;
    for _ in 0..5 {
        r.handle.checkpoint(CheckpointReason::Pause).await.unwrap();
    }
    assert_eq!(
        CheckpointRepo::list(r.store.as_ref(), r.session)
            .await
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn pause_blocks_execute_and_resume_restores_it() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    r.handle.pause().await.unwrap();
    r.handle.wait_state(|s| s == SessionState::Paused).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let err = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(
        matches!(err, SessionError::NotReady { state: "paused" }),
        "{err:?}"
    );
    r.handle.resume().await.unwrap();
    assert_eq!(
        r.handle.wait_state(|s| s == SessionState::Ready).await,
        SessionState::Ready
    );
    // a pause checkpoint exists
    assert!(!CheckpointRepo::list(r.store.as_ref(), r.session)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn shutdown_checkpoints_and_closes_the_context() {
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let _ = observe_cluster(&r).await;
    r.handle
        .shutdown(crawlx_worker::actor::ShutdownReason::Graceful)
        .await
        .unwrap();
    assert!(r.backend.context_handles()[0].closed());
    let cps = CheckpointRepo::list(r.store.as_ref(), r.session).await.unwrap();
    assert_eq!(cps[0].reason, CheckpointReason::Shutdown.as_str());
    assert!(
        r.handle.observe(spec::cheap()).await.is_err(),
        "the actor is gone"
    );
}
