//! `MemoryStore` / `InMemoryJournal` honor the same contracts as the PostgreSQL repositories.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::counters::{ActionStatus, ReconcileResolution, RunStatus, TerminalReason};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{ActionReceipt, SettleReport};
use crawlx_core::repo::*;
use crawlx_core::safety::SafetyDecision;
use crawlx_core::time::ManualClock;
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin, TrustLane};
use crawlx_core::{Clock, NetworkEpochId, StateClusterId, StoreError, TenantId, WorkerId};
use crawlx_storage::testkit::{
    allow_verdict, canonical_url, crawl_run, create_crawl, new_state, proposal, sessions, signature, verdict,
};
use crawlx_storage::{InMemoryJournal, LeaseRepo, MemoryStore};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::sync::Arc;

/// Serializes the tests that assert deltas on the process-global metrics registry.
static METRICS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn epoch(m: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: m,
    }
}

async fn running(store: &MemoryStore) -> (CrawlRun, crawlx_core::SessionId) {
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    let ss = sessions(run.id, 1, 1);
    store.create_sessions(&ss).await.unwrap();
    store
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    (run, ss[0].id)
}

#[tokio::test]
async fn session_kinds_roundtrip_through_scheduler_leases() {
    let store = MemoryStore::new();
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 2));
    store.create(&run, None).await.unwrap();
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

#[test]
fn legacy_session_json_defaults_to_browser_without_using_launch_state() {
    let session = sessions(crawlx_core::CrawlRunId::new(), 1, 1).remove(0);
    let mut value = serde_json::to_value(&session).unwrap();
    value.as_object_mut().unwrap().remove("kind");
    let decoded: CrawlSession = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, session);
    assert_eq!(decoded.kind, SessionKind::Browser);
    assert!(decoded.browser.is_none());
}

#[tokio::test]
#[allow(clippy::field_reassign_with_default)] // BufferLimits is non-exhaustive outside its crate.
async fn literal_controls_stay_volatile_and_expire_for_runs_and_replays() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let store = MemoryStore::with_clock(clock.clone());
    let mut limits = crawlx_storage::BufferLimits::default();
    limits.ttl = std::time::Duration::from_secs(1);
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::new(clock.clone(), limits));
    store.set_dataset_delivery(buffer);
    let mut config = create_crawl("https://example.test/", &[], 1);
    config
        .fetch
        .extra_headers
        .insert("x-password", "journal-password-canary");
    config.fetch.extra_headers.insert("x-reference", "env://TOKEN");
    config
        .fetch
        .cookies
        .push(crawlx_core::request_controls::FetchCookie::new(
            "session",
            "journal-cookie-canary",
        ));
    let source = crawl_run(TenantId::new(), config.clone());
    store.create(&source, None).await.unwrap();
    let replay = crawl_run(source.tenant, config.clone());
    store
        .create_replay(
            &replay,
            &sessions(replay.id, 1, 1),
            &serde_json::json!({"sourceRunId": source.id}),
        )
        .await
        .unwrap();
    for run in [&source, &replay] {
        let durable = RunRepo::get(&store, run.id).await.unwrap();
        assert_eq!(
            durable.config.fetch.extra_headers.get("x-password"),
            Some("[redacted]")
        );
        assert_eq!(
            durable.config.fetch.extra_headers.get("x-reference"),
            Some("env://TOKEN")
        );
        assert_eq!(durable.config.fetch.cookies[0].value, "[redacted]");
        let rows = store.dump_run(run.id);
        assert!(!rows.contains("journal-password-canary") && !rows.contains("journal-cookie-canary"));
        assert_eq!(store.get_for_execution(run.id).await.unwrap().config, config);
    }
    clock.advance_ms(2_000);
    for run in [&source, &replay] {
        assert!(RunRepo::get(&store, run.id).await.is_ok());
        assert!(store.get_metadata(run.id).await.is_ok());
        assert!(matches!(
            store.get_for_execution(run.id).await,
            Err(StoreError::RetentionDenied(_))
        ));
    }
}

#[tokio::test]
async fn literal_controls_require_volatile_storage_but_references_do_not() {
    let store = MemoryStore::new();
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.fetch.extra_headers.insert("authorization", "env://TOKEN");
    let reference = crawl_run(TenantId::new(), config.clone());
    store.create(&reference, None).await.unwrap();
    assert_eq!(store.get_for_execution(reference.id).await.unwrap(), reference);
    config.fetch.extra_headers.insert("x-password", "literal-secret");
    let literal = crawl_run(reference.tenant, config);
    assert!(matches!(
        store.create(&literal, None).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        RunRepo::get(&store, literal.id).await,
        Err(StoreError::NotFound { .. })
    ));
}

#[tokio::test]
async fn replay_enqueue_is_atomic_and_leaseable() {
    let store = MemoryStore::new();
    let source = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&source, None).await.unwrap();
    assert_eq!(store.replay_spec(source.id).await.unwrap(), None);
    let replay = crawl_run(source.tenant, source.config.clone());
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
    duplicate.id = crawlx_core::SessionId::new();
    invalid.push(duplicate);
    assert!(store.create_replay(&replay, &invalid, &spec).await.is_err());
    assert!(matches!(
        RunRepo::get(&store, replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(store.list_sessions(replay.id).await.unwrap().is_empty());
    assert!(store
        .claim_session(replay.id, WorkerId::new(), false)
        .await
        .unwrap()
        .is_none());
    store.create_replay(&replay, &slots, &spec).await.unwrap();
    let lease = store
        .claim_session(replay.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.id, slots[0].id);
    assert_eq!(store.replay_spec(replay.id).await.unwrap(), Some(spec.clone()));
    assert!(store.create_replay(&replay, &slots, &spec).await.is_err());
    assert_eq!(RunRepo::get(&store, source.id).await.unwrap(), source);
}

#[tokio::test]
async fn replay_enqueue_rejects_foreign_or_missing_sources_and_sessions() {
    let store = MemoryStore::new();
    let source = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&source, None).await.unwrap();
    let replay = crawl_run(TenantId::new(), source.config.clone());
    let slots = sessions(replay.id, 1, 1);
    for source_id in [source.id, crawlx_core::CrawlRunId::new()] {
        let spec = serde_json::json!({"sourceRunId": source_id});
        assert!(matches!(
            store.create_replay(&replay, &slots, &spec).await,
            Err(StoreError::NotFound { .. })
        ));
    }
    let replay = crawl_run(source.tenant, source.config.clone());
    let spec = serde_json::json!({"sourceRunId": source.id});
    assert!(store.create_replay(&replay, &slots, &spec).await.is_err());
    assert!(matches!(
        RunRepo::get(&store, replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        store.replay_spec(replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
}

#[tokio::test]
async fn t1_t2_round_trip_in_memory() {
    let store = MemoryStore::new();
    let (run, session) = running(&store).await;
    let cluster = StateClusterId::new();
    let before = new_state(session, cluster, true, 1, epoch(0));
    store.put_state(&before).await.unwrap();
    store.put_state(&before).await.unwrap();

    let id = store
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    store.intend(id, session, epoch(2)).await.unwrap();
    assert_eq!(
        ActionJournal::get(&store, id).await.unwrap().before_state,
        Some(before.id)
    );

    let after = new_state(session, cluster, false, 2, epoch(4));
    let now = Utc::now();
    store
        .finish(
            id,
            OutcomeRecord {
                status: ActionStatus::Succeeded,
                receipt: Some(ActionReceipt {
                    network_epoch: NetworkEpochId::new(),
                    fidelity: Fidelity::NativePointer,
                    lane: Fidelity::NativePointer.lane(),
                    started_at: now,
                    finished_at: now,
                }),
                settle: Some(SettleReport::default()),
                after_state: Some(after),
                traffic: vec![TrafficEvent {
                    seq: 0,
                    epoch_id: None,
                    unattributed_reason: None,
                    origin: TrafficOrigin::Page,
                    method: "GET".to_owned(),
                    url: "https://example.test/api".to_owned(),
                    status: Some(200),
                    request_headers: vec![],
                    response_headers: vec![],
                    request_body: None,
                    response_body: None,
                    third_party: false,
                    late: false,
                    protocol: None,
                    started_at: now,
                    finished_at: None,
                }],
                error: None,
                finished_at: now,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        ActionJournal::get(&store, id).await.unwrap().status,
        ActionStatus::Succeeded
    );
    assert_eq!(store.traffic(id).len(), 1);
    assert_eq!(store.list_states(run.id).await.unwrap().len(), 2);
    assert_eq!(store.list_clusters(run.id).await.unwrap()[0].2, 2);
    let ledger = LedgerRepo::list(&store, run.id).await.unwrap();
    assert_eq!(
        (ledger[0].trusted_exercised, ledger[0].diagnostic_exercised),
        (1, 0),
        "the ledger follows the lane of the executor's receipt (native pointer is trusted), not the proposed fidelity"
    );
    let rec = ActionJournal::get(&store, id).await.unwrap();
    assert_eq!(rec.lane, Some(TrustLane::TrustedUi));
    assert_eq!(rec.fidelity, Some(Fidelity::NativePointer));
    // trail mirrors
    let transitions = store.transitions(run.id);
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].action, id);
    assert_eq!(transitions[0].before, before.id);
    assert!(transitions[0].after.is_some());
    assert_eq!(transitions[0].lane, TrustLane::TrustedUi);
    let epochs = store.network_epochs(run.id);
    assert_eq!(epochs.len(), 1);
    assert_eq!(epochs[0].action, id);
    assert_eq!(Some(epochs[0].id), transitions[0].network_epoch);
    assert_eq!(epochs[0].request_count, 1);
    assert_eq!(store.list_after(run.id, 0, 10).await.unwrap().len(), 1);
    assert!(matches!(
        store
            .finish(
                id,
                OutcomeRecord {
                    status: ActionStatus::Failed,
                    receipt: None,
                    settle: None,
                    after_state: None,
                    traffic: vec![],
                    error: None,
                    finished_at: now
                }
            )
            .await,
        Err(StoreError::IllegalTransition { .. })
    ));
}

#[tokio::test]
async fn failed_t2_leaves_nothing_behind() {
    let store = MemoryStore::new();
    let (run, session) = running(&store).await;
    let id = store
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    store.intend(id, session, epoch(0)).await.unwrap();
    // a non-new cluster that does not exist makes the after-state write fail: T2 is all-or-nothing
    let bad = new_state(session, StateClusterId::new(), false, 3, epoch(1));
    let now = Utc::now();
    let res = store
        .finish(
            id,
            OutcomeRecord {
                status: ActionStatus::Succeeded,
                receipt: None,
                settle: None,
                after_state: Some(bad),
                traffic: vec![],
                error: None,
                finished_at: now,
            },
        )
        .await;
    assert!(matches!(res, Err(StoreError::NotFound { .. })));
    assert_eq!(
        ActionJournal::get(&store, id).await.unwrap().status,
        ActionStatus::Intended
    );
    assert!(store.list_states(run.id).await.unwrap().is_empty());
}

/// Migration 0010 mirror: an epoch-less traffic row needs an explicit reason.
#[tokio::test]
async fn traffic_without_an_epoch_needs_an_explicit_reason_in_memory() {
    let store = MemoryStore::new();
    let (run, session) = running(&store).await;
    let id = store
        .propose(
            run.id,
            session,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    store.intend(id, session, epoch(0)).await.unwrap();
    let now = Utc::now();
    let event = |reason| TrafficEvent {
        seq: 1,
        epoch_id: None,
        unattributed_reason: reason,
        origin: TrafficOrigin::FetchPlane,
        method: "GET".to_owned(),
        url: "https://example.test/robots.txt".to_owned(),
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
    let outcome = |t| OutcomeRecord {
        status: ActionStatus::Failed,
        receipt: None,
        settle: None,
        after_state: None,
        traffic: vec![t],
        error: None,
        finished_at: now,
    };
    assert!(matches!(
        store.finish(id, outcome(event(None))).await,
        Err(StoreError::Conflict(msg)) if msg.contains("unattributed reason")
    ));
    assert_eq!(
        ActionJournal::get(&store, id).await.unwrap().status,
        ActionStatus::Intended,
        "a rejected T2 writes nothing"
    );
    assert!(store.traffic_of_run(run.id).is_empty());

    store
        .finish(
            id,
            outcome(event(Some(
                crawlx_core::traffic::UnattributedReason::NotApplicable,
            ))),
        )
        .await
        .unwrap();
    let rows = store.traffic_of_run(run.id);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, id);
    assert_eq!(
        rows[0].1.unattributed_reason,
        Some(crawlx_core::traffic::UnattributedReason::NotApplicable)
    );
    assert_eq!(
        store.safety_decision_ids(run.id).len(),
        1,
        "propose() recorded the verdict"
    );
}

#[tokio::test]
async fn status_machine_holds_and_unknown_requires_reconcile() {
    let journal = InMemoryJournal::new();
    let store = journal.store().clone();
    let (run, session) = running(&store).await;
    let cluster = StateClusterId::new();
    let id = journal
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            journal
                .finish(
                    id,
                    OutcomeRecord {
                        status: ActionStatus::Succeeded,
                        receipt: None,
                        settle: None,
                        after_state: None,
                        traffic: vec![],
                        error: None,
                        finished_at: Utc::now()
                    }
                )
                .await,
            Err(StoreError::IllegalTransition { .. })
        ),
        "proposed -> succeeded is illegal"
    );
    journal.intend(id, session, epoch(0)).await.unwrap();
    assert!(
        journal.mark_unknown(Utc::now()).await.unwrap().is_empty(),
        "live lease: nothing to flip"
    );
    store.expire_session_lease(session, Utc::now() - chrono::Duration::seconds(1));
    assert_eq!(journal.mark_unknown(Utc::now()).await.unwrap(), vec![id]);
    assert!(
        matches!(
            journal.intend(id, session, epoch(0)).await,
            Err(StoreError::IllegalTransition { .. })
        ),
        "unknown is not re-run"
    );
    journal
        .reconcile(
            id,
            Reconciliation {
                resolution: ReconcileResolution::NotApplied,
                evidence: serde_json::json!({}),
                reconciled_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    assert_eq!(store.eligible_actions(run.id, None).len(), 1);
    // the reaped session is `running` with an expired lease only until the reaper runs
    store.reap(Utc::now()).await.unwrap();
    store
        .claim_session(run.id, WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    store
        .set_session_status(session, SessionStatus::Running)
        .await
        .unwrap();
    journal.intend(id, session, epoch(0)).await.unwrap();
    assert_eq!(journal.get(id).await.unwrap().attempt, 1);

    let denied = journal
        .propose(
            run.id,
            session,
            &proposal("anonymous", cluster, 2),
            &verdict(SafetyDecision::Deny),
        )
        .await
        .unwrap();
    assert!(matches!(
        journal.intend(denied, session, epoch(0)).await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn frontier_runs_and_idempotency() {
    let store = Arc::new(MemoryStore::new());
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, Some("k")).await.unwrap();
    let again = crawl_run(run.tenant, create_crawl("https://example.test/", &[], 1));
    assert!(matches!(
        store.create(&again, Some("k")).await,
        Err(StoreError::Conflict(_))
    ));

    let u = canonical_url("https://example.test/a");
    assert_eq!(
        store.discover(run.id, &u, 0, None, None).await.unwrap().0,
        DiscoveryOutcome::Admitted
    );
    assert_eq!(
        store.discover(run.id, &u, 1, None, None).await.unwrap(),
        (DiscoveryOutcome::Duplicate, None)
    );
    assert_eq!(
        store
            .discover(
                run.id,
                &canonical_url("https://example.test/b"),
                1,
                None,
                Some((FrontierStatus::RobotsBlocked, "robots".to_owned()))
            )
            .await
            .unwrap()
            .0,
        DiscoveryOutcome::RobotsBlocked
    );
    let w = WorkerId::new();
    let batch = store.lease_batch(run.id, w, 10).await.unwrap();
    assert_eq!(batch.len(), 1);
    assert!(store.lease_batch(run.id, w, 10).await.unwrap().is_empty());
    store
        .complete(batch[0].id, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(matches!(
        store.complete(batch[0].id, FrontierStatus::Failed, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));

    store
        .set_status(
            run.id,
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.set_status(run.id, RunStatus::Running, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));
}

#[tokio::test]
async fn edges_need_a_ledger_context_and_upsert_by_key() {
    let store = MemoryStore::new();
    let (run, _) = running(&store).await;
    let p = proposal("anonymous", StateClusterId::new(), 1);
    let now = Utc::now();
    let edge = EdgeRecord {
        id: crawlx_core::EdgeId::new(),
        run: run.id,
        source: p.key.id(),
        context_cluster: None,
        target: p.key.element,
        support: 1,
        weak_support: 0,
        failures: 0,
        latency_ms_ewma: 1.0,
        risk: 0.0,
        last_observed_at: now,
        last_verified_build: None,
    };
    assert!(matches!(
        EdgeStore::upsert(&store, &edge).await,
        Err(StoreError::NotFound { .. })
    ));
    LedgerRepo::upsert(
        &store,
        run.id,
        &LedgerRow {
            key: p.key.clone(),
            trusted_exercised: 1,
            diagnostic_exercised: 0,
            failures: 0,
            first_seen: now,
            last_exercised: Some(now),
        },
    )
    .await
    .unwrap();
    EdgeStore::upsert(&store, &edge).await.unwrap();
    let mut second = edge.clone();
    second.id = crawlx_core::EdgeId::new();
    second.support = 5;
    EdgeStore::upsert(&store, &second).await.unwrap();
    let edges = EdgeStore::list(&store, run.id).await.unwrap();
    assert_eq!((edges.len(), edges[0].id, edges[0].support), (1, edge.id, 5));
}

#[tokio::test]
async fn identity_aliases_round_trip_in_memory() {
    use crawlx_core::hash::Digest;
    use crawlx_core::ElementIdentityHash;
    let store = MemoryStore::new();
    let (run, _) = running(&store).await;
    let h = |s: &str| ElementIdentityHash(Digest::of("t", s.as_bytes()));
    let a = IdentityAlias {
        alias: h("minted"),
        canonical: h("known"),
        from_version: 1,
        to_version: 1,
        score: 0.71,
    };
    assert!(matches!(
        store.record_alias(crawlx_core::CrawlRunId::new(), &a).await,
        Err(StoreError::NotFound { .. })
    ));
    store.record_alias(run.id, &a).await.unwrap();
    // the same pair again keeps the first score
    store
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
    store.record_alias(run.id, &b).await.unwrap();
    let mut expected = vec![a, b];
    expected.sort_by_key(|x| x.alias);
    assert_eq!(store.aliases_of(run.id, h("known")).await.unwrap(), expected);
    assert!(store.aliases_of(run.id, h("minted")).await.unwrap().is_empty());
}

#[tokio::test]
async fn apply_split_counts_one_state_split() {
    let _guard = METRICS_LOCK.lock().await;
    let store = MemoryStore::new();
    let (run, session) = running(&store).await;
    let source = StateClusterId::new();
    let state = new_state(session, source, true, 1, epoch(10));
    store.put_state(&state).await.unwrap();
    let successor = StateClusterId::new();
    let split = ClusterSplitRecord {
        run: run.id,
        source,
        source_version: 1,
        successors: vec![SplitSuccessor {
            cluster: successor,
            version: 2,
            prototype: state.id,
            signature: signature(1),
            members: vec![SplitMember {
                state: state.id,
                similarity: 1.0,
            }],
        }],
        decided_at: Utc::now(),
    };
    let splits = Metrics::global().counter(names::STATES_SPLITS);
    let before = splits.get(&[]);
    store.apply_split(&split).await.unwrap();
    assert_eq!(splits.get(&[]), before + 1, "one applied split counts once");
    // a refused re-application (the source is superseded) does not count
    assert!(matches!(
        store.apply_split(&split).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(splits.get(&[]), before + 1);
}

#[tokio::test]
async fn zdr_write_gate_counts_every_refusal() {
    use crawlx_core::config::RetentionMode;
    use crawlx_storage::retention::zdr_write_gate;
    let _guard = METRICS_LOCK.lock().await;
    let violations = Metrics::global().counter(names::ZDR_VIOLATIONS);
    let before = violations.get(&[]);
    zdr_write_gate(RetentionMode::Zdr, Sensitivity::Metadata).unwrap();
    zdr_write_gate(RetentionMode::Standard, Sensitivity::Content).unwrap();
    assert_eq!(violations.get(&[]), before, "allowed writes are not violations");
    for class in [
        Sensitivity::Content,
        Sensitivity::Sensitive,
        Sensitivity::CredentialBearing,
    ] {
        assert!(matches!(
            zdr_write_gate(RetentionMode::Zdr, class),
            Err(StoreError::RetentionDenied(_))
        ));
    }
    assert_eq!(violations.get(&[]), before + 3);
}

/// `outcome_counts` is the source of the run's interaction counters: rows by outcome, where a
/// row that ever went through `unknown` counts as an unknown outcome whatever it became.
#[tokio::test]
async fn outcome_counts_tally_the_rows_by_outcome() {
    let journal = InMemoryJournal::new();
    let store = journal.store().clone();
    let (run, session) = running(&store).await;
    let cluster = StateClusterId::new();
    let outcome = |status| OutcomeRecord {
        status,
        receipt: None,
        settle: None,
        after_state: None,
        traffic: vec![],
        error: None,
        finished_at: Utc::now(),
    };
    let mut ids = Vec::new();
    for n in 1..=6 {
        ids.push(
            journal
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
        journal.outcome_counts(run.id).await.unwrap(),
        JournalOutcomes::default(),
        "proposals carry no outcome"
    );
    // a: succeeded, b: failed, c: only proposed, d/e/f: in flight when the holder dies
    for (id, status) in [(ids[0], ActionStatus::Succeeded), (ids[1], ActionStatus::Failed)] {
        journal.intend(id, session, epoch(0)).await.unwrap();
        journal.finish(id, outcome(status)).await.unwrap();
    }
    for id in &ids[3..] {
        journal.intend(*id, session, epoch(0)).await.unwrap();
    }
    store.expire_session_lease(session, Utc::now() - chrono::Duration::seconds(1));
    assert_eq!(journal.mark_unknown(Utc::now()).await.unwrap().len(), 3);
    for (id, resolution) in [
        (ids[4], ReconcileResolution::Applied),
        (ids[5], ReconcileResolution::NotApplied),
    ] {
        journal
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
    journal.intend(ids[5], session, epoch(0)).await.unwrap();
    journal
        .finish(ids[5], outcome(ActionStatus::Succeeded))
        .await
        .unwrap();
    assert_eq!(
        journal.outcome_counts(run.id).await.unwrap(),
        JournalOutcomes::new(2, 1, 3)
    );
    let rows = journal.list(run.id, None).await.unwrap();
    assert_eq!(JournalOutcomes::tally(&rows), JournalOutcomes::new(2, 1, 3));
    assert_eq!(
        journal
            .outcome_counts(crawlx_core::CrawlRunId::new())
            .await
            .unwrap(),
        JournalOutcomes::default(),
        "another run's rows are not counted"
    );
}

/// A leased row is not pending but still open: the frontier is exhausted only when no row is
/// pending or leased, and a row handed back unfetched is pending again without a spent attempt.
#[tokio::test]
async fn a_leased_row_is_open_and_a_released_row_is_pending_again_in_memory() {
    let store = MemoryStore::new();
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    for page in ["a", "b"] {
        store
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
            store.pending_count(run.id).await.unwrap(),
            store.open_count(run.id).await.unwrap(),
        )
    };
    assert_eq!(counts().await, (2, 2));

    let w = WorkerId::new();
    let batch = store.lease_batch_fenced(run.id, w, 2).await.unwrap();
    assert_eq!(counts().await, (0, 2), "leased rows are open, not pending");
    assert!(batch.iter().all(|(e, _)| e.attempts == 1));

    store.give_back(batch[0].0.id, batch[0].1).await.unwrap();
    assert_eq!(counts().await, (1, 2));
    let again = store.lease_batch(run.id, w, 1).await.unwrap();
    assert_eq!(
        (again[0].id, again[0].attempts),
        (batch[0].0.id, 1),
        "a release is not an attempt"
    );

    store
        .complete(batch[1].0.id, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(matches!(
        store.give_back(batch[1].0.id, batch[1].1).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        store.give_back(i64::MAX, 1).await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(counts().await, (0, 1));
    store
        .complete(again[0].id, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    assert_eq!(
        counts().await,
        (0, 0),
        "nothing left in flight: the frontier is exhausted"
    );
}

/// A URL lease lives as long as its holder renews it, and only its holder (the fencing token it
/// was granted) renews, completes or hands the row back: once the reaper has returned the row, a
/// stalled holder can touch nothing, whoever leases the row next.
#[tokio::test]
async fn a_frontier_lease_is_renewed_and_finished_only_under_its_fencing_token_in_memory() {
    let clock = ManualClock::new(Utc::now());
    let store = MemoryStore::with_clock(Arc::new(clock.clone())).with_ttls(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(60),
    );
    assert_eq!(store.url_batch_ttl(), std::time::Duration::from_secs(60));
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    for page in ["a", "b"] {
        store
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
    let holder = WorkerId::new();
    let batch = store.lease_batch_fenced(run.id, holder, 2).await.unwrap();
    let ((a, fa), (b, fb)) = (&batch[0], &batch[1]);
    let (a, b) = (a.id, b.id);
    assert_ne!(fa, fb, "every lease has a token of its own");

    // a heartbeat renews the rows of the holder that present their token, and only those
    clock.advance_ms(50_000);
    assert!(store
        .heartbeat_frontier(WorkerId::new(), &[(a, *fa), (b, *fb)])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .heartbeat_frontier(holder, &[(a, fa + 10_000), (b, *fb)])
            .await
            .unwrap(),
        vec![b]
    );

    // the first row ran out its 60 s, the renewed one has 60 s from the heartbeat
    clock.advance_ms(20_000);
    let reaped = store.reap_frontier(clock.now(), 5).await.unwrap();
    assert_eq!((reaped.requeued, reaped.failed), (1, 0));
    assert_eq!(store.pending_count(run.id).await.unwrap(), 1);

    // the stalled holder keeps its token and can do nothing with it
    assert!(store
        .heartbeat_frontier(holder, &[(a, *fa)])
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        store
            .complete_fenced(a, *fa, FrontierStatus::Succeeded, None)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        store.give_back(a, *fa).await,
        Err(StoreError::LeaseLost)
    ));

    // and not after another worker leased the row either
    let next = WorkerId::new();
    let again = store.lease_batch_fenced(run.id, next, 1).await.unwrap();
    assert_eq!((again[0].0.id, again[0].0.attempts), (a, 2));
    assert!(again[0].1 > *fa, "a new lease, a newer token");
    assert!(matches!(
        store.complete_fenced(a, *fa, FrontierStatus::Failed, None).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        store.give_back(a, *fa).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        store.open_count(run.id).await.unwrap(),
        2,
        "the new holder keeps the row"
    );
    store
        .complete_fenced(a, again[0].1, FrontierStatus::Succeeded, None)
        .await
        .unwrap();

    // the holder of the renewed row finishes it; finishing twice is a lost lease
    assert!(matches!(
        store.complete_fenced(b, *fb, FrontierStatus::Leased, None).await,
        Err(StoreError::IllegalTransition { .. })
    ));
    store
        .complete_fenced(b, *fb, FrontierStatus::Failed, Some("http_500".to_owned()))
        .await
        .unwrap();
    assert!(matches!(
        store.complete_fenced(b, *fb, FrontierStatus::Failed, None).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        store
            .complete_fenced(i64::MAX, 1, FrontierStatus::Failed, None)
            .await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(store.open_count(run.id).await.unwrap(), 0);
}

/// `state_counts` tallies the rows of one run by status, and splits out the rows the URL
/// counters hold as duplicates by their `dedupe:` reason.
#[tokio::test]
async fn state_counts_tally_the_frontier_rows_of_one_run_in_memory() {
    let store = MemoryStore::new();
    let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
    let other = crawl_run(TenantId::new(), create_crawl("https://other.test/", &[], 1));
    store.create(&run, None).await.unwrap();
    store.create(&other, None).await.unwrap();
    assert_eq!(
        store.state_counts(run.id).await.unwrap(),
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
        store.discover(run.id, &url(name), 0, None, denial).await.unwrap();
    }
    store
        .discover(other.id, &url("pending"), 0, None, None)
        .await
        .unwrap();
    let rows = FrontierRepo::list(&store, run.id).await.unwrap();
    let id = |name: &str| {
        rows.iter()
            .find(|e| e.url.url.path() == format!("/{name}"))
            .unwrap()
            .id
    };
    let leased = store.lease_batch(run.id, WorkerId::new(), 6).await.unwrap();
    assert_eq!(leased.len(), 6);
    for (name, status, why) in [
        ("ok", FrontierStatus::Succeeded, None),
        ("dup", FrontierStatus::Succeeded, Some("dedupe:content_exact")),
        ("bad", FrontierStatus::Failed, Some("http_500")),
        ("gone", FrontierStatus::Unreachable, Some("dns")),
        ("stopped", FrontierStatus::Abandoned, Some("run_stopped")),
    ] {
        store
            .complete(id(name), status, why.map(str::to_owned))
            .await
            .unwrap();
    }

    let counts = store.state_counts(run.id).await.unwrap();
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
        FrontierStateCounts::tally(&FrontierRepo::list(&store, run.id).await.unwrap())
    );
    // pending + leased + the page that is not a duplicate + failed + unreachable + abandoned
    assert_eq!(counts.admitted(), 1 + 1 + 1 + 1 + 1 + 1);
    assert_eq!(counts.blocked_by_policy(), 1);
    assert_eq!(counts.deduplicated(), 2);
}
