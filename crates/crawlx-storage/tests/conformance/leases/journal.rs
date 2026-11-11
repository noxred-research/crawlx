#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The T1/T2 action journal under leases: the intent and outcome transactions, the status
//! machine and the lane constraints the schema enforces on every engine, the reaper's
//! `unknown` flip and reconciliation, and the outcome counts.

use super::support::{epoch, lease_all, new_run, tenant, Raw, V};
use chrono::{Duration, Utc};
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{ActionReceipt, RuntimeLocator, SettleReport};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{
    ActionJournal, ActionRecord, EventRepo, JournalOutcomes, LedgerRepo, OutcomeRecord, Reconciliation,
    RunRepo, StateRepo,
};
use crawlx_core::safety::SafetyDecision;
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin, TrustLane};
use crawlx_core::{
    ArtifactId, ArtifactRef, AxNodeId, BackendNodeId, BrowserAction, FrameId, NetworkEpochId, StateClusterId,
    StoreError, TabId,
};
use crawlx_storage::testkit::{allow_verdict, new_state, proposal, verdict};
use crawlx_storage::LeaseRepo;

conformance! { databases:
    t1_t2_round_trip,
    status_trigger_rejects_proposed_to_succeeded,
    mark_unknown_only_touches_expired_leases,
    reaper_flow_recover_reconcile_and_retry,
    held_actions_cannot_be_intended,
    trust_lane_constraints_reject_mismatch_and_mutation,
    lane_totality_holds_for_every_fidelity_and_receipt_lane,
}

conformance! { all: outcome_counts_tally_the_rows_by_outcome }

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

fn succeeded_outcome(
    fidelity: Fidelity,
    after: Option<crawlx_core::repo::NewState>,
    url: &str,
) -> OutcomeRecord {
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

db_case! {
    async fn t1_t2_round_trip<B>(rig, store) {
        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await[0].session.id;
        let cluster = StateClusterId::new();
        let before = new_state(session, cluster, true, 1, epoch(1, 1, 0));
        store.put_state(&before).await.unwrap();
        store.put_state(&before).await.unwrap(); // idempotent

        let p = proposal("anonymous", cluster, 1);
        let v = allow_verdict();
        let id = store.propose(run.id, session, &p, &v).await.unwrap();
        let rec = ActionJournal::get(store, id).await.unwrap();
        assert_eq!((rec.status, rec.attempt, rec.seq), (ActionStatus::Proposed, 0, 1));
        assert_eq!(rec.key, p.key);
        assert_eq!(rec.lane, Some(Fidelity::ScriptedNavigation.lane()));
        assert_eq!(
            store
                .eligible_actions(run.id, Some(session), 10)
                .await
                .unwrap()
                .len(),
            1
        );

        store.intend(id, session, epoch(1, 1, 3)).await.unwrap();
        let rec = ActionJournal::get(store, id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Intended);
        assert_eq!(
            rec.before_state,
            Some(before.id),
            "T1 pins the newest state not newer than the epoch"
        );
        assert!(
            store
                .eligible_actions(run.id, Some(session), 10)
                .await
                .unwrap()
                .is_empty(),
            "intended is not schedulable"
        );
        assert!(matches!(
            store.intend(id, session, epoch(1, 1, 3)).await,
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
        store.finish(id, outcome).await.unwrap();

        let rec = ActionJournal::get(store, id).await.unwrap();
        assert_eq!(rec.status, ActionStatus::Succeeded);
        let run_bind = [V::Uuid(run.id.0)];
        for (table, expected) in [
            ("transitions", 1),
            ("network_epochs", 1),
            ("traffic_events", 2),
            ("states", 2),
        ] {
            assert_eq!(
                raw.count(&format!("SELECT count(*) AS n FROM {table} WHERE run_id = $1"), &run_bind)
                    .await,
                expected,
                "{table}"
            );
        }
        assert_eq!(
            raw.count(
                "SELECT count(*) AS n FROM state_cluster_membership m JOIN states s ON s.state_id = m.state_id \
                 WHERE s.run_id = $1",
                &run_bind
            )
            .await,
            2
        );
        let epoch_row = raw
            .one(
                "SELECT unique_operations FROM network_epochs WHERE run_id = $1",
                &run_bind,
            )
            .await;
        assert_eq!(epoch_row.i32("unique_operations"), 2);
        let transition = raw
            .one("SELECT after_state_id FROM transitions WHERE run_id = $1", &run_bind)
            .await;
        assert_eq!(transition.opt_uuid("after_state_id"), Some(after.id.0));

        let states = store.list_states(run.id).await.unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].signature, before.signature);
        assert_eq!(states[0].url, before.url);
        assert!(states[0].cluster_is_new && !states[1].cluster_is_new);
        let clusters = store.list_clusters(run.id).await.unwrap();
        assert_eq!(clusters.len(), 1);
        assert_eq!((clusters[0].0, clusters[0].2), (cluster, 2));

        let ledger = LedgerRepo::list(store, run.id).await.unwrap();
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
        let events = EventRepo::list_after(store, run.id, 0, 10).await.unwrap();
        assert_eq!(
            events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
            vec!["action.finished"]
        );
        assert_eq!(events[0].seq, 1);
        assert!(
            matches!(
                store.finish(id, outcome_failed()).await,
                Err(StoreError::IllegalTransition { .. })
            ),
            "a finished action cannot finish again"
        );
    }
}

db_case! {
    /// The status machine lives in the schema: a raw `UPDATE` along an illegal edge is refused
    /// with `illegal actions.status transition A -> B` (which the repositories map to
    /// `StoreError::IllegalTransition`), and every legal edge is accepted.
    async fn status_trigger_rejects_proposed_to_succeeded<B>(rig, store) {
        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await[0].session.id;
        let id = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", StateClusterId::new(), 1),
                &allow_verdict(),
            )
            .await
            .unwrap();

        let err = raw
            .exec(
                "UPDATE actions SET status = 'succeeded' WHERE action_id = $1",
                &[V::Uuid(id.0)],
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("illegal actions.status transition proposed -> succeeded"),
            "{err}"
        );

        let err = store.finish(id, outcome_failed()).await.unwrap_err();
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
        let set_status = "UPDATE actions SET status = $1::text::action_status WHERE action_id = $2";
        for from in all {
            for to in all {
                if from == to || (from == ActionStatus::Reconciled && to == ActionStatus::Intended) {
                    continue; // identity is a no-op; reconciled -> intended needs the attempt bump, tested via intend()
                }
                let id = store
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
                    raw.run(set_status, &[V::Text(step), V::Uuid(id.0)]).await;
                }
                let res = raw.exec(set_status, &[V::Text(to.as_str()), V::Uuid(id.0)]).await;
                assert_eq!(res.is_ok(), from.can_transition_to(to), "{from:?} -> {to:?}");
            }
        }
    }
}

db_case! {
    async fn mark_unknown_only_touches_expired_leases<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &["a", "b"], 1).await;
        let leases = lease_all(store, &run, 2, 1).await;
        let (sa, sb) = (leases[0].session.id, leases[1].session.id);
        let cluster = StateClusterId::new();
        let mut ids = Vec::new();
        for (s, n) in [(sa, 1), (sb, 2)] {
            let id = store
                .propose(run.id, s, &proposal("anonymous", cluster, n), &allow_verdict())
                .await
                .unwrap();
            store.intend(id, s, epoch(1, 1, 0)).await.unwrap();
            ids.push(id);
        }
        // expire only session a's lease
        let minute_ago = raw.now().await - Duration::minutes(1);
        raw.run(
            "UPDATE crawl_sessions SET lease_expires_at = $1 WHERE session_id = $2",
            &[V::Ts(minute_ago), V::Uuid(sa.0)],
        )
        .await;
        let flipped = store.mark_unknown(store.now().await.unwrap()).await.unwrap();
        assert_eq!(flipped, vec![ids[0]]);
        assert_eq!(
            ActionJournal::get(store, ids[0]).await.unwrap().status,
            ActionStatus::Unknown
        );
        assert_eq!(
            ActionJournal::get(store, ids[1]).await.unwrap().status,
            ActionStatus::Intended,
            "live lease untouched"
        );
        assert!(
            store.mark_unknown(store.now().await.unwrap()).await.unwrap().is_empty(),
            "idempotent"
        );
        // unknown is never rescheduled and is reconciled only through `reconcile`
        assert!(store
            .eligible_actions(run.id, None, 10)
            .await
            .unwrap()
            .is_empty());
    }
}

db_case! {
    async fn reaper_flow_recover_reconcile_and_retry<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let lease = lease_all(store, &run, 1, 1).await.remove(0);
        let session = lease.session.id;
        let cluster = StateClusterId::new();
        let id = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", cluster, 1),
                &allow_verdict(),
            )
            .await
            .unwrap();
        store.intend(id, session, epoch(1, 1, 0)).await.unwrap();

        // the holder dies: lease expires, reap marks the session recovering (never pending) and the action unknown
        let later = store.now().await.unwrap() + Duration::seconds(300);
        let report = store.reap(later).await.unwrap();
        assert_eq!(report.sessions_recovering, vec![session]);
        assert_eq!(report.actions_unknown, vec![id]);
        assert_eq!(
            store.list_sessions(run.id).await.unwrap()[0].status,
            crawlx_core::repo::SessionStatus::Recovering
        );
        assert!(
            matches!(store.heartbeat(&lease).await, Err(StoreError::LeaseLost)),
            "the old holder is fenced"
        );
        assert!(matches!(
            store
                .release(&lease, crawlx_core::repo::SessionStatus::Completed)
                .await,
            Err(StoreError::LeaseLost)
        ));

        // a new worker re-claims the recovering session; it stays recovering until reconciliation is done
        let w2 = crawlx_core::WorkerId::new();
        let l2 = store
            .claim_session(run.id, w2, false)
            .await
            .unwrap()
            .expect("recovering session is re-claimable");
        assert_eq!(l2.session.status, crawlx_core::repo::SessionStatus::Recovering);
        assert!(l2.fencing_token > lease.fencing_token);
        assert!(
            store
                .claim_session(run.id, crawlx_core::WorkerId::new(), false)
                .await
                .unwrap()
                .is_none(),
            "live lease is exclusive"
        );
        store.heartbeat(&l2).await.unwrap();

        store
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
            ActionJournal::get(store, id).await.unwrap().status,
            ActionStatus::Reconciled
        );
        assert_eq!(
            store.eligible_actions(run.id, None, 10).await.unwrap().len(),
            1,
            "not_applied is re-eligible"
        );
        store
            .set_session_status(session, crawlx_core::repo::SessionStatus::Running)
            .await
            .unwrap();
        store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
        let rec = ActionJournal::get(store, id).await.unwrap();
        assert_eq!(
            (rec.status, rec.attempt),
            (ActionStatus::Intended, 1),
            "attempt increments after not_applied"
        );
        assert!(
            matches!(
                store
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
            let other = store
                .propose(
                    run.id,
                    session,
                    &proposal("anonymous", cluster, 9),
                    &allow_verdict(),
                )
                .await
                .unwrap();
            store.intend(other, session, epoch(1, 1, 0)).await.unwrap();
            raw.run(
                "UPDATE actions SET status = 'unknown' WHERE action_id = $1",
                &[V::Uuid(other.0)],
            )
            .await;
            store
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
                !store
                    .eligible_actions(run.id, None, 10)
                    .await
                    .unwrap()
                    .iter()
                    .any(|a| a.id == other),
                "{resolution:?}"
            );
            assert!(matches!(
                store.intend(other, session, epoch(1, 1, 0)).await,
                Err(StoreError::IllegalTransition { .. })
            ));
        }
    }
}

db_case! {
    async fn held_actions_cannot_be_intended<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
        let denied = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", StateClusterId::new(), 1),
                &verdict(SafetyDecision::Deny),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.intend(denied, session, epoch(1, 1, 0)).await,
            Err(StoreError::Conflict(_))
        ));
        assert!(store
            .eligible_actions(run.id, None, 10)
            .await
            .unwrap()
            .is_empty());
        let decision = raw
            .one(
                "SELECT verdict FROM safety_decisions WHERE action_id = $1",
                &[V::Uuid(denied.0)],
            )
            .await;
        assert_eq!(decision.text("verdict"), "deny");
    }
}

all_case! {
    /// `outcome_counts` tallies the rows by outcome: a row that ever went through `unknown`
    /// counts as an unknown outcome whatever it became.
    async fn outcome_counts_tally_the_rows_by_outcome<B>(rig, store) {
        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
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
                store
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
            store.outcome_counts(run.id).await.unwrap(),
            JournalOutcomes::default(),
            "proposals carry no outcome"
        );
        // a: succeeded, b: failed, c: only proposed, d/e/f: in flight when the holder dies
        for (id, status) in [(ids[0], ActionStatus::Succeeded), (ids[1], ActionStatus::Failed)] {
            store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
            store.finish(id, outcome(status)).await.unwrap();
        }
        for id in &ids[3..] {
            store.intend(*id, session, epoch(1, 1, 0)).await.unwrap();
        }
        let flipped = store
            .mark_unknown(store.now().await.unwrap() + Duration::seconds(300))
            .await
            .unwrap();
        assert_eq!(flipped.len(), 3);
        for (id, resolution) in [
            (ids[4], ReconcileResolution::Applied),
            (ids[5], ReconcileResolution::NotApplied),
        ] {
            store
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
        store.intend(ids[5], session, epoch(1, 1, 0)).await.unwrap();
        store
            .finish(ids[5], outcome(ActionStatus::Succeeded))
            .await
            .unwrap();
        assert_eq!(
            store.outcome_counts(run.id).await.unwrap(),
            JournalOutcomes::new(2, 1, 3)
        );
        let rows = ActionJournal::list(store, run.id, None).await.unwrap();
        assert_eq!(JournalOutcomes::tally(&rows), JournalOutcomes::new(2, 1, 3));
        assert_eq!(
            store
                .outcome_counts(crawlx_core::CrawlRunId::new())
                .await
                .unwrap(),
            JournalOutcomes::default(),
            "another run's rows are not counted"
        );
    }
}

db_case! {
    /// The lane of an action is a plan before T2 and evidence after it: an epoch carries the
    /// lane of its action, neither can be rewritten once recorded, and the pair of lane and
    /// fidelity is refused by the schema whenever it breaks the trust rule.
    async fn trust_lane_constraints_reject_mismatch_and_mutation<B>(rig, store) {
        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await[0].session.id;
        let cluster = StateClusterId::new();
        let s0 = new_state(session, cluster, true, 1, epoch(1, 1, 0));
        store.put_state(&s0).await.unwrap();

        // proposed as a scripted navigation (diagnostic); the executor's receipt says native pointer
        let id = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", cluster, 1),
                &allow_verdict(),
            )
            .await
            .unwrap();
        // before T2 the lane is only a plan and may still change
        raw.exec(
            "UPDATE actions SET lane = 'trusted_ui', fidelity = 'native_keyboard' WHERE action_id = $1",
            &[V::Uuid(id.0)],
        )
        .await
        .expect("lane is mutable before T2");
        store.intend(id, session, epoch(1, 1, 3)).await.unwrap();
        let s1 = new_state(session, cluster, false, 2, epoch(1, 1, 5));
        store
            .finish(
                id,
                succeeded_outcome(Fidelity::NativePointer, Some(s1), "https://example.test/a"),
            )
            .await
            .unwrap();
        let rec = ActionJournal::get(store, id).await.unwrap();
        assert_eq!(
            (rec.fidelity, rec.lane),
            (Some(Fidelity::NativePointer), Some(TrustLane::TrustedUi)),
            "T2 records the receipt's fidelity and lane"
        );
        let epoch_lane = raw
            .one(
                "SELECT lane::text AS lane FROM network_epochs WHERE action_id = $1",
                &[V::Uuid(id.0)],
            )
            .await;
        assert_eq!(epoch_lane.text("lane"), "trusted_ui");

        // an epoch whose lane differs from its action's lane cannot be inserted
        let now = raw.now().await;
        let msg = raw
            .exec(
                "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at) \
                 VALUES ($1, $2, $3, $4, 'diagnostic', $5)",
                &[
                    V::Uuid(NetworkEpochId::new().0),
                    V::Uuid(run.id.0),
                    V::Uuid(session.0),
                    V::Uuid(id.0),
                    V::Ts(now),
                ],
            )
            .await
            .expect_err("lane mismatch")
            .to_string();
        assert!(msg.contains("differs from actions.lane"), "{msg}");
        // an epoch's lane is immutable
        let msg = raw
            .exec(
                "UPDATE network_epochs SET lane = 'diagnostic' WHERE action_id = $1",
                &[V::Uuid(id.0)],
            )
            .await
            .expect_err("epoch lane immutable")
            .to_string();
        assert!(
            msg.contains("network_epochs.lane is immutable") || msg.contains("differs from actions.lane"),
            "{msg}"
        );
        // ... also for an epoch that has no owning action
        let loose = NetworkEpochId::new();
        raw.run(
            "INSERT INTO network_epochs (epoch_id, run_id, session_id, action_id, lane, started_at) \
             VALUES ($1, $2, $3, NULL, 'diagnostic', $4)",
            &[V::Uuid(loose.0), V::Uuid(run.id.0), V::Uuid(session.0), V::Ts(now)],
        )
        .await;
        let msg = raw
            .exec(
                "UPDATE network_epochs SET lane = 'trusted_ui' WHERE epoch_id = $1",
                &[V::Uuid(loose.0)],
            )
            .await
            .expect_err("epoch lane immutable")
            .to_string();
        assert!(msg.contains("network_epochs.lane is immutable"), "{msg}");
        // after T2 the action's lane and fidelity are immutable
        let msg = raw
            .exec(
                "UPDATE actions SET lane = 'diagnostic', fidelity = 'synthetic_dom_event' WHERE action_id = $1",
                &[V::Uuid(id.0)],
            )
            .await
            .expect_err("action lane immutable")
            .to_string();
        assert!(msg.contains("immutable after T2"), "{msg}");
        let msg = raw
            .exec(
                "UPDATE actions SET fidelity = 'native_text_input' WHERE action_id = $1",
                &[V::Uuid(id.0)],
            )
            .await
            .expect_err("fidelity immutable")
            .to_string();
        assert!(msg.contains("immutable after T2"), "{msg}");
        // unrelated columns still update
        raw.run(
            "UPDATE actions SET params = '{\"x\":1}' WHERE action_id = $1",
            &[V::Uuid(id.0)],
        )
        .await;

        // before T2 a pair that breaks the trust rule is refused by the table itself
        let planned = store
            .propose(
                run.id,
                session,
                &proposal("anonymous", cluster, 2),
                &allow_verdict(),
            )
            .await
            .unwrap();
        for (lane, fidelity) in [("diagnostic", "native_pointer"), ("trusted_ui", "synthetic_dom_event")] {
            let msg = raw
                .exec(
                    &format!("UPDATE actions SET lane = '{lane}', fidelity = '{fidelity}' WHERE action_id = $1"),
                    &[V::Uuid(planned.0)],
                )
                .await
                .expect_err("lane_matches_fidelity must refuse the row")
                .to_string();
            assert!(msg.contains("lane_matches_fidelity"), "{msg}");
        }
    }
}

/// Every fidelity, in declaration order.
const FIDELITIES: [Fidelity; 8] = [
    Fidelity::NativePointer,
    Fidelity::NativeKeyboard,
    Fidelity::NativeTextInput,
    Fidelity::FileChooser,
    Fidelity::ScriptedNavigation,
    Fidelity::SyntheticDomEvent,
    Fidelity::ScriptedScroll,
    Fidelity::FetchPlane,
];

/// The rule the schema enforces, written independently of `Fidelity::lane`. The `match`
/// makes the list exhaustive at compile time.
const fn is_native(f: Fidelity) -> bool {
    match f {
        Fidelity::NativePointer | Fidelity::NativeKeyboard | Fidelity::NativeTextInput => true,
        Fidelity::FileChooser
        | Fidelity::ScriptedNavigation
        | Fidelity::SyntheticDomEvent
        | Fidelity::ScriptedScroll
        | Fidelity::FetchPlane => false,
    }
}

fn locator() -> RuntimeLocator {
    RuntimeLocator {
        tab: TabId("tab-1".into()),
        frame: FrameId("frame-main".into()),
        backend_node_id: BackendNodeId(1),
        object_id: None,
        ax_node_id: Some(AxNodeId("ax1".into())),
        epoch: ObservationEpoch {
            navigation_seq: 1,
            document_seq: 1,
            mutation_seq: 0,
        },
    }
}

/// Proposals of every planned-fidelity class the testkit can build.
fn proposal_of(kind: u8, cluster: StateClusterId, n: u32) -> ActionProposal {
    let mut p = proposal("anonymous", cluster, n);
    p.action = match kind % 4 {
        0 => return p, // scripted navigation (diagnostic plan)
        1 => BrowserAction::Hover { target: locator() },
        2 => BrowserAction::KeyboardActivate { target: locator() },
        _ => BrowserAction::Keys { sequence: Vec::new() },
    };
    p
}

/// The totality rule for one stored row: `lane` and `fidelity` are present and the lane is
/// the lane of the fidelity (`trusted_ui` exactly for the three native fidelities).
fn assert_total(rec: &ActionRecord, what: &str) {
    let fidelity = rec.fidelity.unwrap_or_else(|| panic!("{what}: no fidelity"));
    let lane = rec.lane.unwrap_or_else(|| panic!("{what}: no lane"));
    assert_eq!(
        lane == TrustLane::TrustedUi,
        is_native(fidelity),
        "{what}: lane {lane:?} for fidelity {fidelity:?}"
    );
    assert_eq!(lane, fidelity.lane(), "{what}: stored lane vs derived lane");
}

db_case! {
    /// For every action any journal stores, in every status it can reach, `lane` is present,
    /// `fidelity` is present and the lane is the lane of the fidelity, whatever fidelity the
    /// receipt names and whatever lane the receipt's own (possibly lying) field says.
    async fn lane_totality_holds_for_every_fidelity_and_receipt_lane<B>(rig, store) {
        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
        let cluster = StateClusterId::new();
        let mut receipts: Vec<Option<(Fidelity, bool)>> = vec![None];
        for fidelity in FIDELITIES {
            receipts.push(Some((fidelity, false)));
            receipts.push(Some((fidelity, true)));
        }
        let mut stored = 0usize;
        for kind in 0..4u8 {
            for receipt in &receipts {
                stored += 1;
                let n = u32::try_from(stored).unwrap();
                let id = store
                    .propose(run.id, session, &proposal_of(kind, cluster, n), &allow_verdict())
                    .await
                    .unwrap();
                // totality holds the moment the row exists (status `proposed`) ...
                assert_total(&ActionJournal::get(store, id).await.unwrap(), "proposed");
                store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
                assert_total(&ActionJournal::get(store, id).await.unwrap(), "intended");
                let now = Utc::now();
                store
                    .finish(
                        id,
                        OutcomeRecord {
                            status: ActionStatus::Succeeded,
                            receipt: receipt.map(|(fidelity, lies)| {
                                let truth = fidelity.lane();
                                let lane = if lies {
                                    match truth {
                                        TrustLane::TrustedUi => TrustLane::Diagnostic,
                                        _ => TrustLane::TrustedUi,
                                    }
                                } else {
                                    truth
                                };
                                ActionReceipt {
                                    network_epoch: NetworkEpochId::new(),
                                    fidelity,
                                    lane,
                                    started_at: now,
                                    finished_at: now,
                                }
                            }),
                            settle: None,
                            after_state: None,
                            traffic: Vec::new(),
                            error: None,
                            finished_at: now,
                        },
                    )
                    .await
                    .unwrap();
                let rec = ActionJournal::get(store, id).await.unwrap();
                assert_total(&rec, "finished");
                // ... and a receipt decides the final lane through its fidelity, never its own lane field
                if let Some((fidelity, _)) = receipt {
                    assert_eq!(rec.fidelity, Some(*fidelity));
                }
            }
        }
        // after the whole sequence every stored row still satisfies the rule
        let listed = ActionJournal::list(store, run.id, None).await.unwrap();
        assert_eq!(listed.len(), stored);
        for rec in &listed {
            assert_total(rec, "listed");
        }
        // and nothing stored anywhere in the schema breaks it
        let violations = raw
            .count(
                "SELECT count(*) AS n FROM actions WHERE (lane = 'trusted_ui') <> \
                 (fidelity IN ('native_pointer','native_keyboard','native_text_input'))",
                &[],
            )
            .await;
        assert_eq!(violations, 0, "stored actions that break lane totality");
        let nulls = raw
            .count(
                "SELECT count(*) AS n FROM actions WHERE lane IS NULL OR fidelity IS NULL",
                &[],
            )
            .await;
        assert_eq!(nulls, 0, "stored actions without a lane or fidelity");
    }
}
