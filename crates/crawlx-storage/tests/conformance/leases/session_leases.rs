#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Session leases: round trips, the replay enqueue, the round-robin barrier, claims past live
//! leases, graceful release and the fencing token of the holder.

use super::support::{epoch, lease_all, new_run, tenant, Raw, V};
use crate::rig::Rig;
use chrono::Duration;
use crawlx_core::counters::ActionStatus;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{ActionJournal, RunRepo, SessionKind, SessionStatus};
use crawlx_core::{CrawlRunId, SessionId, StateClusterId, StoreError, WorkerId};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions};
use crawlx_storage::{LeaseRepo, SessionLease};

/// Keep the PostgreSQL regression's plan assertion: a deep live prefix does not force a
/// sort. Other engines have different planner and index shapes; the same case exercises
/// their observable guarantee by claiming exactly the ready tail and never a live prefix.
async fn assert_ready_claim_plan(rig: &Rig, run: CrawlRunId) {
    let raw = Raw::new(rig);
    if raw.kind() == crawlx_storage::BackendKind::Postgres {
        raw.run("ANALYZE crawl_sessions", &[]).await;
        let now = raw.now().await;
        let plan: Vec<String> = raw
            .rows(
                "EXPLAIN SELECT c.session_id FROM crawl_sessions c \
                     WHERE c.run_id = $1 AND c.status IN ('pending','recovering') \
                       AND COALESCE(c.lease_expires_at, '-infinity'::timestamptz) < $2 \
                     ORDER BY COALESCE(c.lease_expires_at, '-infinity'::timestamptz), c.schedule_slot \
                     LIMIT 1 FOR UPDATE SKIP LOCKED",
                &[V::Uuid(run.0), V::Ts(now)],
            )
            .await
            .iter()
            .map(|row| row.text("QUERY PLAN"))
            .collect();
        assert!(
            plan.iter().any(|line| line.contains("crawl_sessions_ready")),
            "{plan:?}"
        );
        assert!(!plan.iter().any(|line| line.contains("Sort")), "{plan:?}");
    }
}

conformance! { databases:
    sessions_roundtrip_with_browser_info,
    replay_enqueue_is_atomic_and_leaseable,
    replay_enqueue_rejects_foreign_or_missing_sources_and_sessions,
    round_robin_barrier_never_grants_a_higher_slot_early,
    session_claims_skip_live_prefixes_and_locked_serial_heads,
    release_to_recovering_flips_intended_actions,
    a_session_lease_is_renewed_and_released_only_under_its_fencing_token,
}

conformance! { all:
    session_kinds_roundtrip_through_scheduler_leases,
}

db_case! {
    async fn sessions_roundtrip_with_browser_info<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &["a"], 1).await;
        let ss = sessions(run.id, 1, 1);
        store.create_sessions(&ss).await.unwrap();
        let info = BrowserBuildInfo {
            chromium_version: "130.0".to_owned(),
            cdp_revision: "r1".to_owned(),
            user_agent: "ua".to_owned(),
            pinned: true,
            launch_profile: crawlx_core::LaunchProfile::Standard,
            console_capture: true,
            attached: false,
        };
        store.set_session_browser(ss[0].id, &info).await.unwrap();
        let listed = store.list_sessions(run.id).await.unwrap();
        assert_eq!(listed[0].browser.as_ref(), Some(&info));
        store
            .set_session_status(ss[0].id, SessionStatus::Cancelled)
            .await
            .unwrap();
        assert!(matches!(
            store.set_session_status(ss[0].id, SessionStatus::Running).await,
            Err(StoreError::IllegalTransition { .. })
        ));
        assert!(matches!(
            store.create_sessions(&sessions(CrawlRunId::new(), 1, 1)).await,
            Err(StoreError::NotFound { .. })
        ));
    }
}

async fn session_kinds_roundtrip_through_scheduler_leases(rig: &Rig) {
    async fn run<S: RunRepo + LeaseRepo>(rig: &Rig, store: &S) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &["a"], 2).await;
        let mut slots = sessions(run.id, 1, 2);
        slots[1].kind = SessionKind::HttpCoordinator;
        store.create_sessions(&slots).await.unwrap();
        assert_eq!(store.list_sessions(run.id).await.unwrap(), slots);
        for slot in &slots {
            let lease = store
                .claim_session(run.id, WorkerId::new(), false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(lease.session.kind, slot.kind);
            assert!(lease.session.browser.is_none());
            store.release(&lease, SessionStatus::Completed).await.unwrap();
        }
    }
    rig.migrate().await;
    on_store!(rig, run);
}

db_case! {
    async fn replay_enqueue_is_atomic_and_leaseable<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let source = new_run(store, tenant, &[], 1).await;
        assert_eq!(store.replay_spec(source.id).await.unwrap(), None);
        let replay = crawl_run(tenant, source.config.clone());
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
        assert!(store.create_replay(&replay, &invalid, &spec).await.is_err());
        let runs_named = "SELECT count(*) AS n FROM crawl_runs WHERE run_id = $1";
        assert_eq!(raw.count(runs_named, &[V::Uuid(replay.id.0)]).await, 0);
        assert!(store.list_sessions(replay.id).await.unwrap().is_empty());
        assert!(matches!(
            store.claim_session(replay.id, WorkerId::new(), false).await,
            Err(StoreError::NotFound { entity: "crawl_run", id }) if id == replay.id.to_string()
        ));
        store.create_replay(&replay, &slots, &spec).await.unwrap();
        let lease = store
            .claim_session(replay.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.session.id, slots[0].id);
        assert_eq!(store.replay_spec(replay.id).await.unwrap(), Some(spec.clone()));
        let row = raw
            .one(
                "SELECT run_kind, replay_of FROM crawl_runs WHERE run_id = $1",
                &[V::Uuid(replay.id.0)],
            )
            .await;
        assert_eq!(
            (row.text("run_kind"), row.opt_uuid("replay_of")),
            ("replay".to_owned(), Some(source.id.0))
        );
        assert!(store.create_replay(&replay, &slots, &spec).await.is_err());
        assert_eq!(RunRepo::get(store, source.id).await.unwrap(), source);
    }
}

db_case! {
    async fn replay_enqueue_rejects_foreign_or_missing_sources_and_sessions<B>(rig, store) {
        let tenant_of_replay = tenant(rig).await;
        let foreign = tenant(rig).await;
        let source = crawl_run(foreign, create_crawl("https://example.test/", &[], 1));
        store.create(&source, None).await.unwrap();
        let replay = crawl_run(tenant_of_replay, source.config.clone());
        let slots = sessions(replay.id, 1, 1);
        for source_id in [source.id, CrawlRunId::new()] {
            let spec = serde_json::json!({"sourceRunId": source_id});
            assert!(matches!(
                store.create_replay(&replay, &slots, &spec).await,
                Err(StoreError::NotFound { .. })
            ));
        }
        let source = new_run(store, tenant_of_replay, &[], 1).await;
        let spec = serde_json::json!({"sourceRunId": source.id});
        assert!(store
            .create_replay(&replay, &sessions(source.id, 1, 1), &spec)
            .await
            .is_err());
        assert!(matches!(
            RunRepo::get(store, replay.id).await,
            Err(StoreError::NotFound { .. })
        ));
        assert!(matches!(
            store.replay_spec(replay.id).await,
            Err(StoreError::NotFound { .. })
        ));
    }
}

db_case! {
    async fn round_robin_barrier_never_grants_a_higher_slot_early<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &["a", "b", "c"], 2).await;
        store.create_sessions(&sessions(run.id, 3, 2)).await.unwrap();

        // eight concurrent claimers on a fresh run: exactly slot 0 is granted
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let run = run.id;
            tasks.push(tokio::spawn(async move {
                store.claim_session(run, WorkerId::new(), false).await.unwrap()
            }));
        }
        let mut granted = Vec::new();
        for task in tasks {
            if let Some(lease) = task.await.unwrap() {
                granted.push(lease);
            }
        }
        assert_eq!(granted.len(), 1);
        assert_eq!(granted[0].session.schedule_slot, 0);

        let mut current = granted.remove(0);
        for expected_slot in 1..6u32 {
            assert!(
                store
                    .claim_session(run.id, WorkerId::new(), false)
                    .await
                    .unwrap()
                    .is_none(),
                "slot {expected_slot} waits for slot {}",
                expected_slot - 1
            );
            store.release(&current, SessionStatus::Completed).await.unwrap();
            let next = store
                .claim_session(run.id, WorkerId::new(), false)
                .await
                .unwrap()
                .expect("next slot");
            assert_eq!(next.session.schedule_slot, expected_slot);
            current = next;
        }
        store.release(&current, SessionStatus::Failed).await.unwrap();
        assert!(store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .is_none());

        // with the barrier lifted all slots are grantable at once
        let parallel = new_run(store, tenant, &["a", "b"], 1).await;
        store.create_sessions(&sessions(parallel.id, 2, 1)).await.unwrap();
        for _ in 0..2 {
            assert!(store
                .claim_session(parallel.id, WorkerId::new(), true)
                .await
                .unwrap()
                .is_some());
        }
        let active = store.active_runs().await.unwrap();
        assert!(active.is_empty(), "no pending sessions left anywhere: {active:?}");
    }
}

db_case! {
    async fn session_claims_skip_live_prefixes_and_locked_serial_heads<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &["a"], 1).await;
        let slots = sessions(run.id, 1, 4096);
        store.create_sessions(&slots).await.unwrap();
        // 4095 sessions hold a live lease (alternating `running` and `recovering`); the
        // claim must reach the one ready session without walking the live prefix
        let hour_ahead = raw.now().await + Duration::hours(1);
        raw.run(
            "UPDATE crawl_sessions SET status = CASE WHEN schedule_slot % 2 = 0 THEN 'running' ELSE 'recovering' END, \
             lease_expires_at = $1 WHERE run_id = $2 AND schedule_slot < 4095",
            &[V::Ts(hour_ahead), V::Uuid(run.id.0)],
        )
        .await;
        assert_ready_claim_plan(rig, run.id).await;
        assert!(store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .is_none());
        let lease = store
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.session.schedule_slot, 4095);
        assert!(store
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .is_none());

        // A busy serial head never lets a serial claimant skip to its successor, and a
        // parallel claimant still gets the successor: the head is leased and running.
        let busy = new_run(store, tenant, &["a"], 2).await;
        let busy_sessions = sessions(busy.id, 1, 2);
        store.create_sessions(&busy_sessions).await.unwrap();
        let head = store
            .claim_session(busy.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.session.schedule_slot, 0);
        assert!(store
            .claim_session(busy.id, WorkerId::new(), false)
            .await
            .unwrap()
            .is_none());
        let successor = store
            .claim_session(busy.id, WorkerId::new(), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(successor.session.schedule_slot, 1);

        // PostgreSQL and MariaDB also have row locks: a pending head locked by another
        // transaction is skipped, not waited for, and still blocks its successor for a
        // serial claimant. SQLite has no row locks (a writer locks the whole database), so
        // the leased head above is the observable guarantee there.
        let serial = new_run(store, tenant, &["a"], 2).await;
        let serial_sessions = sessions(serial.id, 1, 2);
        store.create_sessions(&serial_sessions).await.unwrap();
        if let Some(locked) = raw.hold_session_lock(serial_sessions[0].id.0).await {
            assert!(store
                .claim_session(serial.id, WorkerId::new(), false)
                .await
                .unwrap()
                .is_none());
            let parallel = store
                .claim_session(serial.id, WorkerId::new(), true)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(parallel.session.schedule_slot, 1);
            locked.release().await;
        }

        // Expired recovering rows remain eligible and receive a fresh fence.
        let past = raw.now().await - Duration::seconds(1);
        raw.run(
            "UPDATE crawl_sessions SET lease_expires_at = $1 WHERE session_id = $2",
            &[V::Ts(past), V::Uuid(slots[1].id.0)],
        )
        .await;
        let recovery = store
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovery.session.id, slots[1].id);
        assert_eq!(recovery.session.status, SessionStatus::Recovering);
        assert!(recovery.fencing_token > lease.fencing_token);
        assert!(store
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .is_none());
    }
}

db_case! {
    async fn release_to_recovering_flips_intended_actions<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let lease = lease_all(store, &run, 1, 1).await.remove(0);
        let session = lease.session.id;
        let id = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", StateClusterId::new(), 1),
                &allow_verdict(),
            )
            .await
            .unwrap();
        store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
        assert!(store.release(&lease, SessionStatus::Pending).await.is_err());
        store.release(&lease, SessionStatus::Recovering).await.unwrap();
        assert_eq!(
            ActionJournal::get(store, id).await.unwrap().status,
            ActionStatus::Unknown
        );
        let again = store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap();
        assert!(
            again.is_some(),
            "graceful release makes the session immediately re-claimable"
        );
    }
}

db_case! {
    async fn a_session_lease_is_renewed_and_released_only_under_its_fencing_token<B>(rig, store) {
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let first = lease_all(store, &run, 1, 1).await.remove(0);
        let session = first.session.id;

        // only the holder presenting its own token and identity renews or releases
        store.heartbeat(&first).await.unwrap();
        let wrong_token = SessionLease {
            fencing_token: first.fencing_token + 1,
            ..first.clone()
        };
        let wrong_owner = SessionLease {
            worker: WorkerId::new(),
            ..first.clone()
        };
        for stranger in [&wrong_token, &wrong_owner] {
            assert!(matches!(store.heartbeat(stranger).await, Err(StoreError::LeaseLost)));
            assert!(matches!(
                store.release(stranger, SessionStatus::Completed).await,
                Err(StoreError::LeaseLost)
            ));
        }

        // the lease runs out: the reaper makes the session `recovering` and fences the holder
        let later = store.now().await.unwrap() + Duration::seconds(600);
        let report = store.reap(later).await.unwrap();
        assert_eq!(report.sessions_recovering, vec![session]);
        assert!(matches!(store.heartbeat(&first).await, Err(StoreError::LeaseLost)));
        assert!(matches!(
            store.release(&first, SessionStatus::Completed).await,
            Err(StoreError::LeaseLost)
        ));

        // a new holder gets a newer token; the stalled holder stays fenced out, also now
        let second = store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .expect("the recovering session is leased again");
        assert_eq!(second.session.id, session);
        assert!(second.fencing_token > first.fencing_token);
        assert!(matches!(store.heartbeat(&first).await, Err(StoreError::LeaseLost)));
        assert!(matches!(
            store.release(&first, SessionStatus::Failed).await,
            Err(StoreError::LeaseLost)
        ));
        store.heartbeat(&second).await.unwrap();
        store.release(&second, SessionStatus::Completed).await.unwrap();
        assert!(
            matches!(
                store.release(&second, SessionStatus::Completed).await,
                Err(StoreError::LeaseLost)
            ),
            "a finished session has no holder"
        );
        assert_eq!(
            store.list_sessions(run.id).await.unwrap()[0].status,
            SessionStatus::Completed
        );
    }
}
