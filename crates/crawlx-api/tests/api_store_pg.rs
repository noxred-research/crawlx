#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `PgApiStore` and `PgEraser` over PostgreSQL (skipped without `CRAWLX_TEST_DATABASE_URL`).
//! Row-level checks use raw SQL, which is why these tests live outside `src/`.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use crawlx_api::pg::{PgApiStore, PgEraser};
use crawlx_api::store::{
    ApiStore, ApprovalDecision, ArtifactSource, AuthorizationInsert, DecideOutcome, DeliveryResult,
    DeliveryStatus, Eraser, IdemBegin, KeyRecord, Scope, StoreResult, StoredResponse, TrafficFilter,
    TransitionFilter, WebhookDelivery,
};
use crawlx_core::counters::ActionStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{ActionReceipt, SettleReport};
use crawlx_core::repo::{ActionJournal, CrawlRun, OutcomeRecord, RunRepo, StateRepo};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin, TrustLane};
use crawlx_core::{
    ActionId, ApprovalId, ArtifactId, ArtifactRef, AuthorizationRecordId, CrawlRunId, NetworkEpochId,
    SessionId, StateClusterId, StoreError, TenantId, Timestamp, WorkerId,
};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AuthorizationRecord, AuthzFailure, OwnershipProof};
use crawlx_storage::testkit::{
    allow_verdict, crawl_run, create_crawl, new_state, proposal, sessions, verdict,
};
use crawlx_storage::{CoverageRow, LeaseRepo, Pg, PgConfig};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;
struct Env {
    pg: Pg,
    tenant: TenantId,
    store: PgApiStore,
}

async fn setup() -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("api_{}", CrawlRunId::new().0.simple())),
            max_connections: 8,
            ..PgConfig::default()
        },
    )
    .await
    .expect("connect");
    pg.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "test").await.expect("tenant");
    let store = PgApiStore::new(pg.clone());
    Some(Env { pg, tenant, store })
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

fn now_ms() -> Timestamp {
    chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

fn approval_verdict() -> SafetyVerdict {
    let mut v = verdict(SafetyDecision::ApprovalRequired);
    v.approval = Some(ApprovalId::new());
    v
}

impl Env {
    async fn run(&self) -> CrawlRun {
        let run = crawl_run(self.tenant, create_crawl("https://example.test/", &[], 1));
        self.pg.create(&run, None).await.expect("create run");
        run
    }

    /// One session of `run`, claimed (running); its role is `role0`.
    async fn session(&self, run: CrawlRunId) -> SessionId {
        let ss = sessions(run, 1, 1);
        self.pg.create_sessions(&ss).await.expect("sessions");
        let lease = self
            .pg
            .claim_session(run, WorkerId::new(), true)
            .await
            .expect("claim")
            .expect("a lease");
        lease.session.id
    }

    async fn key(&self, prefix: &str) -> Uuid {
        let key = KeyRecord {
            key_id: Uuid::now_v7(),
            tenant: self.tenant,
            prefix: prefix.to_owned(),
            hash: [1; 32],
            scopes: Scope::all_set(),
            expires_at: None,
            revoked: false,
        };
        self.store.key_insert(&key, "test").await.expect("key");
        key.key_id
    }

    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        principal: &str,
        n: u32,
        v: &SafetyVerdict,
    ) -> ActionId {
        self.pg
            .propose(run, session, &proposal(principal, StateClusterId::new(), n), v)
            .await
            .expect("propose")
    }

    async fn count(&self, table: &str, run: CrawlRunId) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE run_id = $1"))
            .bind(run.0)
            .fetch_one(self.pg.pool())
            .await
            .unwrap()
    }

    async fn hold(&self, action: ActionId) -> String {
        sqlx::query_scalar("SELECT hold FROM actions WHERE action_id = $1")
            .bind(action.0)
            .fetch_one(self.pg.pool())
            .await
            .unwrap()
    }

    async fn teardown(self) {
        let Self { pg, store, .. } = self;
        drop(store);
        pg.drop_schema().await.expect("drop schema");
    }
}

#[tokio::test]
async fn keys_insert_lookup_touch() {
    let env = env!();
    let key = KeyRecord {
        key_id: Uuid::now_v7(),
        tenant: env.tenant,
        prefix: "abcd1234".to_owned(),
        hash: [7; 32],
        scopes: BTreeSet::from([Scope::CrawlsRead, Scope::CrawlsWrite]),
        expires_at: Some(now_ms() + Duration::days(1)),
        revoked: false,
    };
    assert_eq!(env.store.key_by_prefix("abcd1234").await.unwrap(), None);
    env.store.key_insert(&key, "acme").await.unwrap();
    assert_eq!(
        env.store.key_by_prefix("abcd1234").await.unwrap(),
        Some(key.clone())
    );

    // idempotent on prefix: the first insert wins
    let other = KeyRecord {
        key_id: Uuid::now_v7(),
        hash: [9; 32],
        ..key.clone()
    };
    env.store.key_insert(&other, "acme").await.unwrap();
    assert_eq!(
        env.store.key_by_prefix("abcd1234").await.unwrap(),
        Some(key.clone())
    );

    // unknown scopes are ignored
    sqlx::query("UPDATE api_keys SET scopes = scopes || ARRAY['bogus:scope'] WHERE key_id = $1")
        .bind(key.key_id)
        .execute(env.pg.pool())
        .await
        .unwrap();
    assert_eq!(
        env.store.key_by_prefix("abcd1234").await.unwrap(),
        Some(key.clone())
    );

    let at = now_ms();
    env.store.key_touch(key.key_id, at).await.unwrap();
    let touched: Option<Timestamp> =
        sqlx::query_scalar("SELECT last_used_at FROM api_keys WHERE key_id = $1")
            .bind(key.key_id)
            .fetch_one(env.pg.pool())
            .await
            .unwrap();
    assert_eq!(touched, Some(at));

    // a key of a tenant that does not exist yet creates the tenant; revoked is preserved
    let revoked = KeyRecord {
        key_id: Uuid::now_v7(),
        tenant: TenantId::new(),
        prefix: "revoked1".to_owned(),
        hash: [3; 32],
        scopes: Scope::all_set(),
        expires_at: None,
        revoked: true,
    };
    env.store.key_insert(&revoked, "other").await.unwrap();
    assert_eq!(env.store.key_by_prefix("revoked1").await.unwrap(), Some(revoked));
    env.teardown().await;
}

#[tokio::test]
async fn idempotency_lifecycle() {
    let env = env!();
    let (tenant, now) = (env.tenant, now_ms());
    let hash = Digest::of("t", b"one");
    let other = Digest::of("t", b"two");
    let s = &env.store;

    assert_eq!(
        s.idem_begin(tenant, "k1", hash, now).await.unwrap(),
        IdemBegin::Started
    );
    assert_eq!(
        s.idem_begin(tenant, "k1", hash, now).await.unwrap(),
        IdemBegin::InProgress
    );
    assert_eq!(
        s.idem_begin(tenant, "k1", other, now).await.unwrap(),
        IdemBegin::Mismatch
    );

    let run = CrawlRunId::new();
    let stored = StoredResponse {
        status: 202,
        body: json!({"id": run.0.to_string()}),
        run_id: Some(run),
    };
    s.idem_complete(tenant, "k1", &stored).await.unwrap();
    assert_eq!(
        s.idem_begin(tenant, "k1", hash, now).await.unwrap(),
        IdemBegin::Replay(stored.clone())
    );
    assert_eq!(
        s.idem_begin(tenant, "k1", other, now).await.unwrap(),
        IdemBegin::Mismatch
    );

    // release only drops in-progress claims
    s.idem_release(tenant, "k1").await.unwrap();
    assert_eq!(
        s.idem_begin(tenant, "k1", hash, now).await.unwrap(),
        IdemBegin::Replay(stored)
    );
    assert_eq!(
        s.idem_begin(tenant, "k2", hash, now).await.unwrap(),
        IdemBegin::Started
    );
    s.idem_release(tenant, "k2").await.unwrap();
    assert_eq!(
        s.idem_begin(tenant, "k2", other, now).await.unwrap(),
        IdemBegin::Started
    );

    // another tenant has its own namespace
    let tenant2 = TenantId::new();
    env.pg.ensure_tenant(tenant2, "two").await.unwrap();
    assert_eq!(
        s.idem_begin(tenant2, "k1", other, now).await.unwrap(),
        IdemBegin::Started
    );

    // after 24 h the row is expired and replaced
    let later = now + Duration::hours(25);
    assert_eq!(
        s.idem_begin(tenant, "k1", other, later).await.unwrap(),
        IdemBegin::Started
    );
    assert_eq!(
        s.idem_begin(tenant, "k1", other, later).await.unwrap(),
        IdemBegin::InProgress
    );
    env.teardown().await;
}

#[tokio::test]
async fn an_in_progress_claim_names_the_run_it_announced() {
    let env = env!();
    let (tenant, now) = (env.tenant, now_ms());
    let hash = Digest::of("t", b"one");
    let s = &env.store;

    assert_eq!(s.idem_run(tenant, "k").await.unwrap(), None, "unknown key");
    assert_eq!(
        s.idem_begin(tenant, "k", hash, now).await.unwrap(),
        IdemBegin::Started
    );
    assert_eq!(
        s.idem_run(tenant, "k").await.unwrap(),
        None,
        "no run announced yet"
    );
    let run = CrawlRunId::new();
    s.idem_link_run(tenant, "k", run).await.unwrap();
    assert_eq!(s.idem_run(tenant, "k").await.unwrap(), Some(run));
    assert_eq!(
        s.idem_begin(tenant, "k", hash, now).await.unwrap(),
        IdemBegin::InProgress,
        "a repeat in flight is refused and can name the run"
    );

    // completing the claim keeps the run, and a finished claim is not relinked
    let stored = StoredResponse {
        status: 200,
        body: json!({"id": run.0.to_string()}),
        run_id: Some(run),
    };
    s.idem_complete(tenant, "k", &stored).await.unwrap();
    s.idem_link_run(tenant, "k", CrawlRunId::new()).await.unwrap();
    assert_eq!(s.idem_run(tenant, "k").await.unwrap(), Some(run));

    // another tenant has its own namespace
    let tenant2 = TenantId::new();
    env.pg.ensure_tenant(tenant2, "two").await.unwrap();
    assert_eq!(s.idem_run(tenant2, "k").await.unwrap(), None);
    env.teardown().await;
}

#[tokio::test]
async fn approvals_decide_flow() {
    let env = env!();
    let approver = env.key("approver").await;
    let run = env.run().await;
    let session = env.session(run.id).await;
    let s = &env.store;

    let v1 = approval_verdict();
    let a1 = env.propose(run.id, session, "alice", 1, &v1).await;
    let ap1 = v1.approval.unwrap();

    let list = s.approvals_list(run.id).await.unwrap();
    assert_eq!(list.len(), 1);
    let rec = &list[0];
    assert_eq!((rec.id, rec.run, rec.action), (ap1, run.id, a1));
    assert_eq!(rec.decision, ApprovalDecision::Pending);
    assert_eq!(rec.risk_class, "navigation_reveal");
    assert_eq!(rec.summary["role"], "alice");
    assert_eq!(
        (rec.decided_by, rec.decided_at, rec.consumed_at),
        (None, None, None)
    );
    assert_eq!(env.hold(a1).await, "awaiting_approval");
    assert_eq!(s.approval_get(run.id, ap1).await.unwrap().as_ref(), Some(rec));
    assert_eq!(s.approval_get(run.id, ApprovalId::new()).await.unwrap(), None);
    assert_eq!(s.approval_get(CrawlRunId::new(), ap1).await.unwrap(), None);

    let now = now_ms();
    assert!(matches!(
        s.approval_decide(
            run.id,
            ApprovalId::new(),
            ApprovalDecision::Approved,
            approver,
            None,
            now
        )
        .await
        .unwrap(),
        DecideOutcome::NotFound
    ));
    assert!(matches!(
        s.approval_decide(run.id, ap1, ApprovalDecision::Pending, approver, None, now)
            .await,
        Err(StoreError::Conflict(_))
    ));

    // approve: Applied, the action is released
    let DecideOutcome::Applied(applied) = s
        .approval_decide(
            run.id,
            ap1,
            ApprovalDecision::Approved,
            approver,
            Some("looks fine"),
            now,
        )
        .await
        .unwrap()
    else {
        panic!("expected Applied")
    };
    assert_eq!(applied.decision, ApprovalDecision::Approved);
    assert_eq!(applied.decided_by, Some(approver));
    assert_eq!(applied.decided_at, Some(now));
    assert_eq!(applied.reason.as_deref(), Some("looks fine"));
    assert_eq!(env.hold(a1).await, "none");

    // same decision again: Unchanged; the other one: NotPending
    assert_eq!(
        s.approval_decide(run.id, ap1, ApprovalDecision::Approved, approver, None, now)
            .await
            .unwrap(),
        DecideOutcome::Unchanged(applied.clone())
    );
    assert_eq!(
        s.approval_decide(run.id, ap1, ApprovalDecision::Denied, approver, None, now)
            .await
            .unwrap(),
        DecideOutcome::NotPending(applied.clone())
    );
    assert_eq!(env.hold(a1).await, "none");

    // deny: the hold becomes `denied`
    let v2 = approval_verdict();
    let a2 = env.propose(run.id, session, "alice", 2, &v2).await;
    let ap2 = v2.approval.unwrap();
    let out = s
        .approval_decide(run.id, ap2, ApprovalDecision::Denied, approver, Some("no"), now)
        .await
        .unwrap();
    assert!(matches!(&out, DecideOutcome::Applied(r) if r.decision == ApprovalDecision::Denied));
    assert_eq!(env.hold(a2).await, "denied");

    // expired: still pending in the table but past `expires_at`
    let v3 = approval_verdict();
    let a3 = env.propose(run.id, session, "alice", 3, &v3).await;
    let ap3 = v3.approval.unwrap();
    let out = s
        .approval_decide(
            run.id,
            ap3,
            ApprovalDecision::Approved,
            approver,
            None,
            now + Duration::days(2),
        )
        .await
        .unwrap();
    assert!(matches!(&out, DecideOutcome::NotPending(r) if r.decision == ApprovalDecision::Pending));
    assert_eq!(env.hold(a3).await, "awaiting_approval");

    // consumed: the same decision stays Unchanged, a different one is NotPending
    let v4 = approval_verdict();
    let a4 = env.propose(run.id, session, "alice", 4, &v4).await;
    let ap4 = v4.approval.unwrap();
    s.approval_decide(run.id, ap4, ApprovalDecision::Approved, approver, None, now)
        .await
        .unwrap();
    sqlx::query("UPDATE approvals SET consumed_at = now() WHERE approval_id = $1")
        .bind(ap4.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        s.approval_decide(run.id, ap4, ApprovalDecision::Approved, approver, None, now)
            .await
            .unwrap(),
        DecideOutcome::Unchanged(_)
    ));
    assert!(matches!(
        s.approval_decide(run.id, ap4, ApprovalDecision::Denied, approver, None, now)
            .await
            .unwrap(),
        DecideOutcome::NotPending(_)
    ));
    assert_eq!(env.hold(a4).await, "none");

    // consumed while still pending
    let v5 = approval_verdict();
    env.propose(run.id, session, "alice", 5, &v5).await;
    let ap5 = v5.approval.unwrap();
    sqlx::query("UPDATE approvals SET consumed_at = now() WHERE approval_id = $1")
        .bind(ap5.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        s.approval_decide(run.id, ap5, ApprovalDecision::Approved, approver, None, now)
            .await
            .unwrap(),
        DecideOutcome::NotPending(_)
    ));

    let ids: Vec<ApprovalId> = s
        .approvals_list(run.id)
        .await
        .unwrap()
        .iter()
        .map(|a| a.id)
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!((ids.len(), ids), (5, sorted));
    env.teardown().await;
}

#[tokio::test]
async fn transitions_and_traffic() {
    let env = env!();
    let run = env.run().await;
    let session = env.session(run.id).await;
    let epoch = |m| ObservationEpoch {
        navigation_seq: 1,
        document_seq: 1,
        mutation_seq: m,
    };
    let cluster = StateClusterId::new();
    let before = new_state(session, cluster, true, 1, epoch(0));
    env.pg.put_state(&before).await.unwrap();
    let p = proposal("anonymous", cluster, 1);
    let action = env
        .pg
        .propose(run.id, session, &p, &allow_verdict())
        .await
        .unwrap();
    env.pg.intend(action, session, epoch(3)).await.unwrap();

    let after = new_state(session, cluster, false, 2, epoch(5));
    let now = now_ms();
    let net_epoch = NetworkEpochId::new();
    let ev = |seq: u64, origin: TrafficOrigin| TrafficEvent {
        seq,
        epoch_id: None,
        unattributed_reason: None,
        origin,
        method: "GET".to_owned(),
        url: format!("https://example.test/api/{seq}"),
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
    };
    env.pg
        .finish(
            action,
            OutcomeRecord {
                status: ActionStatus::Succeeded,
                receipt: Some(ActionReceipt {
                    network_epoch: net_epoch,
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
                traffic: vec![
                    ev(0, TrafficOrigin::Page),
                    ev(1, TrafficOrigin::WebSocket),
                    ev(2, TrafficOrigin::Page),
                ],
                error: None,
                finished_at: now,
            },
        )
        .await
        .unwrap();
    let s = &env.store;

    let all = s
        .transitions_list(run.id, &TransitionFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 1);
    let t = &all[0];
    assert_eq!(
        (t.session, t.role.as_str(), t.before, t.after),
        (session, "role0", before.id, Some(after.id))
    );
    assert_eq!(
        (t.network_epoch, t.lane),
        (Some(net_epoch), TrustLane::Diagnostic)
    );
    assert!(t.settle.as_ref().is_some_and(Value::is_object));
    let a = &t.action;
    assert_eq!(
        (a.id, a.seq, a.kind.as_str(), a.status),
        (action, 1, "navigate", ActionStatus::Succeeded)
    );
    assert_eq!(
        (a.lane, a.fidelity.as_deref()),
        (Some(TrustLane::Diagnostic), Some("scripted_navigation"))
    );
    assert_eq!((a.strategy.as_str(), a.strategy_version), ("interaction_bfs", 1));
    assert_eq!(a.context_id.len(), 32);
    assert!(a.context_id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        (a.risk_class.as_deref(), a.safety_verdict.as_deref()),
        (Some("navigation_reveal"), Some("allow"))
    );

    let n = |f: TransitionFilter| {
        let s = s.clone();
        async move { s.transitions_list(run.id, &f).await.unwrap().len() }
    };
    let base = TransitionFilter::default;
    assert_eq!(
        n(TransitionFilter {
            session: Some(session),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            session: Some(SessionId::new()),
            ..base()
        })
        .await,
        0
    );
    assert_eq!(
        n(TransitionFilter {
            role: Some("role0".into()),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            role: Some("other".into()),
            ..base()
        })
        .await,
        0
    );
    assert_eq!(
        n(TransitionFilter {
            lane: Some(TrustLane::Diagnostic),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            lane: Some(TrustLane::TrustedUi),
            ..base()
        })
        .await,
        0
    );
    assert_eq!(
        n(TransitionFilter {
            status: Some(ActionStatus::Succeeded),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            status: Some(ActionStatus::Failed),
            ..base()
        })
        .await,
        0
    );
    assert_eq!(
        n(TransitionFilter {
            from_state: Some(before.id),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            from_state: Some(after.id),
            ..base()
        })
        .await,
        0
    );
    assert_eq!(
        n(TransitionFilter {
            to_state: Some(after.id),
            ..base()
        })
        .await,
        1
    );
    assert_eq!(
        n(TransitionFilter {
            to_state: Some(before.id),
            ..base()
        })
        .await,
        0
    );
    assert!(s
        .transitions_list(CrawlRunId::new(), &base())
        .await
        .unwrap()
        .is_empty());

    let traffic = s.traffic_list(run.id, &TrafficFilter::default()).await.unwrap();
    assert_eq!(traffic.len(), 3);
    let ids: Vec<&str> = traffic.iter().map(|t| t.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(ids, sorted, "ids are unique and sort in list order");
    let first = &traffic[0];
    assert_eq!((first.epoch_id, first.action), (Some(net_epoch), Some(action)));
    assert_eq!(
        (first.lane, first.role.as_deref(), first.origin),
        (TrustLane::Diagnostic, Some("role0"), TrafficOrigin::Page)
    );
    assert_eq!(
        (first.method.as_deref(), first.url.as_str(), first.status),
        (Some("GET"), "https://example.test/api/0", Some(200))
    );
    assert_eq!(
        (first.third_party, first.late, first.response_body.clone()),
        (false, false, None)
    );
    assert_eq!(first.request_headers.as_array().map(Vec::len), Some(1));
    assert_eq!(first.occurred_at, now);
    assert_eq!(traffic[1].origin, TrafficOrigin::WebSocket);

    let tn = |f: TrafficFilter| {
        let s = s.clone();
        async move { s.traffic_list(run.id, &f).await.unwrap().len() }
    };
    let tbase = TrafficFilter::default;
    assert_eq!(
        tn(TrafficFilter {
            origin: Some(TrafficOrigin::Page),
            ..tbase()
        })
        .await,
        2
    );
    assert_eq!(
        tn(TrafficFilter {
            origin: Some(TrafficOrigin::WebSocket),
            ..tbase()
        })
        .await,
        1
    );
    assert_eq!(
        tn(TrafficFilter {
            origin: Some(TrafficOrigin::FetchPlane),
            ..tbase()
        })
        .await,
        0
    );
    assert_eq!(
        tn(TrafficFilter {
            lane: Some(TrustLane::Diagnostic),
            ..tbase()
        })
        .await,
        3
    );
    assert_eq!(
        tn(TrafficFilter {
            lane: Some(TrustLane::TrustedUi),
            ..tbase()
        })
        .await,
        0
    );
    assert_eq!(
        tn(TrafficFilter {
            role: Some("role0".into()),
            ..tbase()
        })
        .await,
        3
    );
    assert_eq!(
        tn(TrafficFilter {
            role: Some("nobody".into()),
            ..tbase()
        })
        .await,
        0
    );
    assert_eq!(
        tn(TrafficFilter {
            epoch: Some(net_epoch),
            ..tbase()
        })
        .await,
        3
    );
    assert_eq!(
        tn(TrafficFilter {
            epoch: Some(NetworkEpochId::new()),
            ..tbase()
        })
        .await,
        0
    );
    env.teardown().await;
}

#[tokio::test]
async fn coverage_rows_carry_denials_per_context() {
    let env = env!();
    let run = env.run().await;
    let session = env.session(run.id).await;
    let deny = || verdict(SafetyDecision::Deny);
    env.propose(run.id, session, "alice", 1, &deny()).await;
    env.propose(run.id, session, "alice", 2, &deny()).await;
    env.propose(run.id, session, "bob", 3, &deny()).await;
    env.propose(run.id, session, "carol", 4, &allow_verdict()).await;
    let denied_only = |rows: &[CoverageRow]| -> BTreeMap<String, u64> {
        let mut m = BTreeMap::new();
        for r in rows.iter().filter(|r| r.is_denied_only()) {
            *m.entry(r.key.principal.0.clone()).or_default() += 1;
        }
        m
    };
    let rows = env.store.coverage(run.id).await.unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        denied_only(&rows),
        BTreeMap::from([("alice".to_owned(), 2), ("bob".to_owned(), 1)])
    );
    sqlx::query("UPDATE action_contexts SET succeeded = 1 WHERE run_id = $1 AND principal = 'bob'")
        .bind(run.id.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    let rows = env.store.coverage(run.id).await.unwrap();
    assert_eq!(denied_only(&rows), BTreeMap::from([("alice".to_owned(), 2)]));
    let bob = rows.iter().find(|r| r.key.principal.0 == "bob").unwrap();
    assert_eq!(
        bob.exercised(TrustLane::Diagnostic),
        1,
        "a success outside T2 is not trusted"
    );
    assert!(env.store.coverage(CrawlRunId::new()).await.unwrap().is_empty());
    env.teardown().await;
}

#[tokio::test]
async fn active_runs() {
    let env = env!();
    let (r1, r2, r3, r4) = (env.run().await, env.run().await, env.run().await, env.run().await);
    assert_eq!(env.store.active_run_count(env.tenant).await.unwrap(), 4);
    assert_eq!(env.store.active_run_count(TenantId::new()).await.unwrap(), 0);
    env.store.run_created(env.tenant, r1.id).await.unwrap();
    let set = |id: CrawlRunId, sql: &'static str| {
        let pool = env.pg.pool().clone();
        async move { sqlx::query(sql).bind(id.0).execute(&pool).await.unwrap() }
    };
    set(r2.id, "UPDATE crawl_runs SET status = 'completed', terminal_reason = 'frontier_exhausted' WHERE run_id = $1").await;
    set(r3.id, "UPDATE crawl_runs SET status = 'paused' WHERE run_id = $1").await;
    set(
        r4.id,
        "UPDATE crawl_runs SET status = 'cancelling' WHERE run_id = $1",
    )
    .await;
    assert_eq!(env.store.active_run_count(env.tenant).await.unwrap(), 2);

    env.teardown().await;
}

#[tokio::test]
async fn authorization_records_round_trip() {
    let env = env!();
    let creator = env.key("authkey1").await;
    let (from, to) = (now_ms(), now_ms() + Duration::days(30));
    // a row as a direct SQL insert (or a pre-lifecycle local registration) leaves it: the body
    // is the record JSON, the lifecycle lives in columns
    let mut sample = sample_record(env.tenant, from, &["https://example.test"]);
    sample.version = 2;
    sample.valid_from = from;
    sample.valid_to = to;
    let id = sample.id;
    let body = serde_json::to_value(&sample).unwrap();
    sqlx::query(
        "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, created_by) \
         VALUES ($1, $2, 2, $3, $4, $5, $6, $7)",
    )
    .bind(id.0)
    .bind(env.tenant.0)
    .bind(&body)
    .bind(sample.body_digest().unwrap().0.to_vec())
    .bind(from)
    .bind(to)
    .bind(creator)
    .execute(env.pg.pool())
    .await
    .unwrap();

    let rec = env
        .store
        .authorization_get(env.tenant, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rec, sample,
        "an unverified, unrevoked row reads back as the record"
    );
    assert_eq!(rec.evidence.kind, "signed_scope_letter");

    // lifecycle columns are merged into the record
    let (verified, revoked) = (now_ms(), now_ms() + Duration::minutes(1));
    sqlx::query(
        "UPDATE authorization_records SET verified_at = $2, revoked_at = $3, revoked_reason = 'over' WHERE record_id = $1",
    )
    .bind(id.0)
    .bind(verified)
    .bind(revoked)
    .execute(env.pg.pool())
    .await
    .unwrap();
    let rec = env
        .store
        .authorization_get(env.tenant, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (rec.verified_at, rec.revoked_at, rec.revoked_reason.as_deref()),
        (Some(verified), Some(revoked), Some("over"))
    );
    assert_eq!(rec.body_digest().unwrap(), sample.body_digest().unwrap());

    assert_eq!(
        env.store.authorization_get(TenantId::new(), id).await.unwrap(),
        None
    );
    assert_eq!(
        env.store
            .authorization_get(env.tenant, AuthorizationRecordId::new())
            .await
            .unwrap(),
        None
    );
    env.teardown().await;
}

/// The authorization lifecycle of an [`ApiStore`]; the in-memory and the PostgreSQL store must
/// behave alike. `runs` creates the run a digest is bound to, `creator` is an existing API key of
/// `tenant`.
async fn authorization_lifecycle(store: &dyn ApiStore, runs: &dyn RunRepo, tenant: TenantId, creator: Uuid) {
    let at = now_ms();
    let mut record = sample_record(tenant, at, &["https://example.test"]);
    record.ownership = Some(OwnershipProof::DnsTxt {});
    let id = record.id;
    let digest = record.body_digest().unwrap();
    let proof = json!({"kind": "dns_txt", "checkedAt": at, "hosts": ["example.test"]});
    assert!(store.authorization_entry(tenant, id).await.unwrap().is_none());

    // create, replay, taken
    let created = store
        .authorization_create(tenant, creator, &record, &proof, at)
        .await
        .unwrap();
    assert_eq!(created, AuthorizationInsert::Created);
    let replay = store
        .authorization_create(
            tenant,
            creator,
            &record,
            &json!({"other": true}),
            at + Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(replay, AuthorizationInsert::Replayed);
    let mut changed = record.clone();
    changed.title = "another engagement".to_owned();
    let taken = store
        .authorization_create(tenant, creator, &changed, &proof, at)
        .await
        .unwrap();
    assert_eq!(taken, AuthorizationInsert::Taken);
    let mut theirs = record.clone();
    theirs.tenant = TenantId::new();
    let taken = store
        .authorization_create(theirs.tenant, creator, &theirs, &proof, at)
        .await
        .unwrap();
    assert_eq!(taken, AuthorizationInsert::Taken, "the id is global");

    // what is stored: the record as created, verified, with the policy digest and the evidence
    let entry = store.authorization_entry(tenant, id).await.unwrap().unwrap();
    assert_eq!(entry.body_digest, digest);
    assert_eq!(
        entry.verification,
        Some(proof.clone()),
        "a replay kept the first proof"
    );
    assert_eq!(
        entry.record,
        AuthorizationRecord {
            verified_at: Some(at),
            ..record.clone()
        }
    );
    assert_eq!(entry.record.body_digest().unwrap(), digest);
    assert_eq!(
        store.authorization_get(tenant, id).await.unwrap(),
        Some(entry.record.clone())
    );

    // another tenant sees and changes nothing
    let other = TenantId::new();
    assert!(store.authorization_entry(other, id).await.unwrap().is_none());
    assert!(store.authorization_get(other, id).await.unwrap().is_none());
    assert!(store
        .authorization_revoke(other, id, creator, None, at)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .authorization_mark_verified(other, id, &proof, at)
        .await
        .unwrap()
        .is_none());

    // re-verification replaces the evidence, not the body
    let later = at + Duration::hours(2);
    let renewed = json!({"kind": "dns_txt", "checkedAt": later, "hosts": ["example.test"]});
    let entry = store
        .authorization_mark_verified(tenant, id, &renewed, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entry.verification, Some(renewed));
    assert_eq!(entry.record.verified_at, Some(later));
    assert_eq!(entry.body_digest, digest);

    // revocation: the first one stands
    let t1 = at + Duration::hours(3);
    let first = store
        .authorization_revoke(tenant, id, creator, Some("engagement over"), t1)
        .await
        .unwrap()
        .unwrap();
    assert!(first.first);
    assert_eq!(first.entry.record.revoked_at, Some(t1));
    assert_eq!(
        first.entry.record.revoked_reason.as_deref(),
        Some("engagement over")
    );
    assert_eq!(first.entry.record.check_active(t1), Err(AuthzFailure::Revoked));
    assert_eq!(
        first.entry.body_digest, digest,
        "revoking never changes the digest"
    );
    let second = store
        .authorization_revoke(
            tenant,
            id,
            creator,
            Some("another reason"),
            t1 + Duration::hours(1),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!second.first);
    assert_eq!(second.entry, first.entry);
    assert_eq!(
        store.authorization_get(tenant, id).await.unwrap(),
        Some(first.entry.record)
    );
    assert!(store
        .authorization_revoke(tenant, AuthorizationRecordId::new(), creator, None, t1)
        .await
        .unwrap()
        .is_none());

    // a run is bound to the digest of the body it was admitted under
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    runs.create(&run, None).await.unwrap();
    assert_eq!(store.authorization_run_digest(run.id).await.unwrap(), None);
    store.authorization_bind_run(run.id, digest).await.unwrap();
    assert_eq!(
        store.authorization_run_digest(run.id).await.unwrap(),
        Some(digest)
    );
    let ghost = CrawlRunId::new();
    assert!(matches!(
        store.authorization_bind_run(ghost, digest).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        store.authorization_run_digest(ghost).await,
        Err(StoreError::NotFound { .. })
    ));
}

/// The in-memory store runs the same lifecycle (this file is otherwise PostgreSQL only).
#[tokio::test]
async fn authorization_lifecycle_in_memory() {
    let runs = Arc::new(crawlx_storage::MemoryStore::new());
    let store = crawlx_api::MemoryApiStore::new(runs.clone());
    authorization_lifecycle(&store, runs.as_ref(), TenantId::new(), Uuid::now_v7()).await;
}

#[tokio::test]
async fn authorization_lifecycle_on_postgres() {
    let env = env!();
    let creator = env.key("authkey2").await;
    authorization_lifecycle(&env.store, &env.pg, env.tenant, creator).await;
    // the digest is a column of the run row
    let digest: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT authorization_body_digest FROM crawl_runs WHERE tenant_id = $1 AND authorization_body_digest IS NOT NULL",
    )
    .bind(env.tenant.0)
    .fetch_optional(env.pg.pool())
    .await
    .unwrap();
    assert_eq!(digest.map(|d| d.len()), Some(32));
    env.teardown().await;
}

#[tokio::test]
async fn audit_events_are_chained() {
    let env = env!();
    let run = env.run().await;
    env.store
        .audit_append(
            env.tenant,
            Some(run.id),
            "key:1",
            "approval.decided",
            json!({"a": 1}),
        )
        .await
        .unwrap();
    env.store
        .audit_append(env.tenant, None, "key:1", "key.created", json!({"b": 2}))
        .await
        .unwrap();
    let rows = sqlx::query("SELECT run_id, actor, event, prev_hash, entry_hash FROM audit_events WHERE tenant_id = $1 ORDER BY audit_id")
        .bind(env.tenant.0)
        .fetch_all(env.pg.pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<Option<Uuid>, _>("run_id"), Some(run.id.0));
    assert_eq!(rows[1].get::<Option<Uuid>, _>("run_id"), None);
    assert_eq!(rows[1].get::<String, _>("event"), "key.created");
    assert_eq!(
        rows[1].get::<Vec<u8>, _>("prev_hash"),
        rows[0].get::<Vec<u8>, _>("entry_hash")
    );
    env.teardown().await;
}

async fn add_event(env: &Env, run: CrawlRunId, seq: i64) {
    sqlx::query(
        "INSERT INTO crawl_events (run_id, seq, type, payload) VALUES ($1, $2, 'page.crawled', '{}')",
    )
    .bind(run.0)
    .bind(seq)
    .execute(env.pg.pool())
    .await
    .unwrap();
}

fn delivery(run: CrawlRunId, seq: u64, url: &str, due: Timestamp) -> WebhookDelivery {
    WebhookDelivery {
        id: Uuid::now_v7(),
        run,
        event_seq: seq,
        event_type: "page.crawled".to_owned(),
        url: url.to_owned(),
        status: DeliveryStatus::Pending,
        attempts: 0,
        next_attempt_at: due,
        delivered_at: None,
        last_status: None,
        last_error: None,
    }
}

#[tokio::test]
async fn webhook_outbox_lifecycle() {
    let env = env!();
    let run = env.run().await;
    let plain = env.run().await;
    sqlx::query(r#"UPDATE crawl_runs SET config = config || '{"output": {"webhook": {"url": "https://hook.test/h"}}}'::jsonb WHERE run_id = $1"#)
        .bind(run.id.0)
        .execute(env.pg.pool())
        .await
        .unwrap();
    for seq in 1..=3 {
        add_event(&env, run.id, seq).await;
    }
    let s = &env.store;
    assert_eq!(s.webhook_runs().await.unwrap(), vec![run.id]);
    s.webhook_watch(plain.id).await.unwrap();
    assert_eq!(s.webhook_runs().await.unwrap(), vec![run.id]);
    assert_eq!(s.webhook_cursor(run.id).await.unwrap(), 0);

    let t0 = now_ms();
    let due = t0 - Duration::seconds(10);
    let (a, b) = ("https://hook.test/a", "https://hook.test/b");
    assert!(s.webhook_enqueue(&delivery(run.id, 1, a, due)).await.unwrap());
    assert!(!s.webhook_enqueue(&delivery(run.id, 1, a, due)).await.unwrap());
    assert!(s.webhook_enqueue(&delivery(run.id, 1, b, due)).await.unwrap());
    assert!(s.webhook_enqueue(&delivery(run.id, 2, a, due)).await.unwrap());
    assert!(s.webhook_enqueue(&delivery(run.id, 3, a, due)).await.unwrap());
    assert_eq!(s.webhook_cursor(run.id).await.unwrap(), 3);
    assert_eq!(s.webhook_cursor(plain.id).await.unwrap(), 0);
    let listed = s.webhook_list(run.id).await.unwrap();
    assert_eq!(
        listed.iter().map(|d| d.event_seq).collect::<Vec<_>>(),
        vec![1, 1, 2, 3]
    );
    assert!(listed
        .iter()
        .all(|d| d.status == DeliveryStatus::Pending && d.attempts == 0));
    assert_eq!(listed[0].next_attempt_at, due);

    // claiming defers the rows by the lease
    let first = s.webhook_claim_due(t0, 2, 60).await.unwrap();
    let second = s.webhook_claim_due(t0, 10, 60).await.unwrap();
    assert_eq!((first.len(), second.len()), (2, 2));
    let claimed: BTreeSet<Uuid> = first.iter().chain(&second).map(|d| d.id).collect();
    assert_eq!(claimed.len(), 4, "no row claimed twice");
    assert!(first
        .iter()
        .all(|d| d.next_attempt_at == t0 + Duration::seconds(60)));
    assert!(s.webhook_claim_due(t0, 10, 60).await.unwrap().is_empty());

    // once the lease lapsed the rows are due again
    let again = s
        .webhook_claim_due(t0 + Duration::seconds(61), 10, 60)
        .await
        .unwrap();
    assert_eq!(again.len(), 4);
    let (delivered, retry, dead, untouched) = (&again[0], &again[1], &again[2], &again[3]);

    let at = t0 + Duration::seconds(62);
    s.webhook_record(delivered.id, &DeliveryResult::Delivered { status: 200, at })
        .await
        .unwrap();
    let next = t0 + Duration::seconds(300);
    s.webhook_record(
        retry.id,
        &DeliveryResult::Retry {
            status: Some(503),
            error: "boom".to_owned(),
            next_attempt_at: next,
        },
    )
    .await
    .unwrap();
    s.webhook_record(
        dead.id,
        &DeliveryResult::Dead {
            status: None,
            error: "gone".to_owned(),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        s.webhook_record(Uuid::now_v7(), &DeliveryResult::Delivered { status: 200, at })
            .await,
        Err(StoreError::NotFound { .. })
    ));

    let by_id = |rows: &[WebhookDelivery], id: Uuid| rows.iter().find(|d| d.id == id).unwrap().clone();
    let listed = s.webhook_list(run.id).await.unwrap();
    let d = by_id(&listed, delivered.id);
    assert_eq!(
        (d.status, d.attempts, d.delivered_at, d.last_status),
        (DeliveryStatus::Delivered, 1, Some(at), Some(200))
    );
    let r = by_id(&listed, retry.id);
    assert_eq!(
        (r.status, r.attempts, r.next_attempt_at),
        (DeliveryStatus::Pending, 1, next)
    );
    assert_eq!(
        (r.last_status, r.last_error.as_deref()),
        (Some(503), Some("boom"))
    );
    let x = by_id(&listed, dead.id);
    assert_eq!(
        (x.status, x.attempts, x.last_status, x.last_error.as_deref()),
        (DeliveryStatus::Dead, 1, None, Some("gone"))
    );
    assert_eq!(by_id(&listed, untouched.id).attempts, 0);
    assert_eq!(s.webhook_dead_count(run.id).await.unwrap(), 1);
    assert_eq!(s.webhook_dead_count(plain.id).await.unwrap(), 0);

    // only pending rows are claimable
    let due_later = s
        .webhook_claim_due(t0 + Duration::hours(1), 10, 60)
        .await
        .unwrap();
    let ids: BTreeSet<Uuid> = due_later.iter().map(|d| d.id).collect();
    assert_eq!(ids, BTreeSet::from([retry.id, untouched.id]));
    env.teardown().await;
}

struct StubArtifacts(Arc<AtomicUsize>);

#[async_trait]
impl ArtifactSource for StubArtifacts {
    async fn row(&self, _id: ArtifactId) -> StoreResult<Option<crawlx_storage::ArtifactRow>> {
        Ok(None)
    }
    async fn read(&self, artifact: &ArtifactRef) -> StoreResult<Vec<u8>> {
        Err(StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        })
    }
    async fn put_evidence(&self, _run: CrawlRunId, _bytes: &[u8]) -> StoreResult<ArtifactRef> {
        Err(StoreError::Backend(
            "artifact writes are unavailable in the erasure-only test".to_owned(),
        ))
    }
    async fn put_login_flow(
        &self,
        _run: CrawlRunId,
        _bytes: &crawlx_core::secret::Redacted<Vec<u8>>,
        _deadline: crawlx_core::Timestamp,
    ) -> StoreResult<ArtifactRef> {
        Err(StoreError::Unavailable(
            "artifact writes are unavailable in the erasure-only test".to_owned(),
        ))
    }
    async fn purge_run(&self, _run: CrawlRunId) -> StoreResult<u64> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}

#[tokio::test]
async fn eraser_removes_run_rows() {
    let env = env!();
    let approver = env.key("eraser01").await;
    let run = env.run().await;
    let keep = env.run().await;
    let session = env.session(run.id).await;
    let v = approval_verdict();
    env.propose(run.id, session, "alice", 1, &v).await;
    env.store
        .approval_decide(
            run.id,
            v.approval.unwrap(),
            ApprovalDecision::Approved,
            approver,
            None,
            now_ms(),
        )
        .await
        .unwrap();
    add_event(&env, run.id, 1).await;
    add_event(&env, keep.id, 1).await;
    let due = now_ms();
    env.store
        .webhook_enqueue(&delivery(run.id, 1, "https://hook.test/a", due))
        .await
        .unwrap();
    env.store
        .webhook_enqueue(&delivery(keep.id, 1, "https://hook.test/a", due))
        .await
        .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let eraser = PgEraser::new(env.pg.clone(), Some(Arc::new(StubArtifacts(calls.clone()))));
    for table in [
        "crawl_runs",
        "approvals",
        "actions",
        "crawl_sessions",
        "webhook_deliveries",
        "crawl_events",
    ] {
        assert!(
            env.count(table, run.id).await > 0,
            "{table} has rows before erase"
        );
    }
    let deleted = eraser.erase(run.id).await.unwrap();
    assert!(deleted >= 6, "deleted {deleted}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for table in [
        "crawl_runs",
        "approvals",
        "actions",
        "crawl_sessions",
        "webhook_deliveries",
        "crawl_events",
    ] {
        assert_eq!(env.count(table, run.id).await, 0, "{table} is empty after erase");
    }
    assert_eq!(
        env.count("webhook_deliveries", keep.id).await,
        1,
        "other runs are untouched"
    );
    assert_eq!(env.count("crawl_runs", keep.id).await, 1);
    assert!(matches!(
        eraser.erase(run.id).await,
        Err(StoreError::NotFound { .. })
    ));

    // without an artifact source the rows are still purged
    assert!(PgEraser::new(env.pg.clone(), None).erase(keep.id).await.is_ok());
    env.teardown().await;
}
