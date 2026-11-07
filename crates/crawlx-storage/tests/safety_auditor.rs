//! Independent auditor integration coverage; uses isolated schemas and real limited logins.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::counters::RunStatus;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ActionJournal, EventRepo, RunRepo};
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_core::{ActionId, ApprovalId, CrawlRunId, StateClusterId, TenantId, WorkerId};
use crawlx_storage::testkit::{allow_verdict, crawl_run, create_crawl, proposal, sessions, verdict};
use crawlx_storage::{
    ApiKeyRow, DeliveryBuffer, LeaseRepo, NewAuthorization, Pg, PgApiRepo, PgConfig, SafetyAuditor,
};
use std::sync::Arc;

async fn action(pg: &Pg, tenant: TenantId, unknown: bool) -> (CrawlRunId, ActionId) {
    let run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    pg.create(&run, None).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    let lease = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let action = pg
        .propose(
            run.id,
            lease.session.id,
            &proposal("anonymous", StateClusterId::new(), 1),
            &allow_verdict(),
        )
        .await
        .unwrap();
    pg.intend(action, lease.session.id, ObservationEpoch::default())
        .await
        .unwrap();
    if unknown {
        sqlx::query("UPDATE actions SET status='unknown' WHERE action_id=$1")
            .bind(action.0)
            .execute(pg.pool())
            .await
            .unwrap();
    }
    (run.id, action)
}

fn login_url(base: &str, role: &str, password: &str, schema: &str) -> String {
    let mut url = url::Url::parse(base).unwrap();
    url.set_username(role).unwrap();
    url.set_password(Some(password)).unwrap();
    // PostgreSQL startup options preserve the isolated schema for every pooled connection.
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    url.to_string()
}

async fn opted_in_zdr_action(pg: &Pg, tenant: TenantId) -> (CrawlRunId, ActionId, Arc<DeliveryBuffer>) {
    let now = chrono::Utc::now();
    let mut record = crawlx_policy::testkit::sample_record(tenant, now, &["https://example.test"]);
    record
        .test_sinks
        .insert("webhook".into(), "https://example.test/fixture-hook".into());
    let body = serde_json::to_value(&record).unwrap();
    let digest = record.body_digest().unwrap();
    let repo = PgApiRepo::new(pg.clone());
    let key = uuid::Uuid::now_v7();
    repo.key_insert(
        &ApiKeyRow {
            key_id: key,
            tenant,
            prefix: key.simple().to_string(),
            hash: [7; 32],
            scopes: vec!["authorizations:write".into()],
            expires_at: None,
            revoked: false,
        },
        "auditor-fixture",
    )
    .await
    .unwrap();
    repo.authorization_create(&NewAuthorization {
        tenant,
        id: record.id,
        version: 1,
        body: &body,
        body_digest: &digest.0,
        valid_from: record.valid_from,
        valid_to: record.valid_to,
        created_by: key,
        verified_at: now,
        verification: &serde_json::json!({"kind": "fixture"}),
    })
    .await
    .unwrap();
    let buffer = Arc::new(DeliveryBuffer::with_defaults(Arc::new(crawlx_core::SystemClock)));
    let live = pg.clone().with_delivery_buffer(buffer.clone());
    let mut config = create_crawl("https://example.test/private-zdr-sink-canary", &[], 1);
    config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    config.retention.days = 0;
    config.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    config.safety.external_communication = crawlx_core::config::ExternalCommunication::TestSinks;
    config.safety.destructive_actions = crawlx_core::config::DestructiveActions::Approval;
    config.safety.authorization_record_ref = Some(record.id);
    let run = crawl_run(tenant, config);
    live.create(&run, None).await.unwrap();
    repo.authorization_bind_run(run.id, digest).await.unwrap();
    live.set_status(run.id, RunStatus::Running, None).await.unwrap();
    live.create_sessions(&sessions(run.id, 1, 1)).await.unwrap();
    let lease = live
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let mut decision = allow_verdict();
    decision.risk_class = RiskClass::ExternalCommunication;
    let action = live
        .propose(
            run.id,
            lease.session.id,
            &proposal("anonymous", StateClusterId::new(), 1),
            &decision,
        )
        .await
        .unwrap();
    live.intend(action, lease.session.id, ObservationEpoch::default())
        .await
        .unwrap();
    (run.id, action, buffer)
}

#[tokio::test]
async fn privileged_bypass_pauses_only_affected_run_with_independent_identities() {
    let Ok(base) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let schema = format!("auditor_{suffix}");
    let pg = Pg::connect(
        &base,
        PgConfig {
            schema: Some(schema.clone()),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let reader = format!("audit_read_{suffix}");
    let pauser = format!("audit_pause_{suffix}");
    let password = uuid::Uuid::now_v7().simple().to_string();
    for (login, capability) in [
        (&reader, "crawlx_safety_reader"),
        (&pauser, "crawlx_safety_pauser"),
    ] {
        sqlx::query(&format!("CREATE ROLE {login} LOGIN INHERIT PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"))
            .execute(pg.pool()).await.unwrap();
        sqlx::query(&format!("GRANT {capability} TO {login}"))
            .execute(pg.pool())
            .await
            .unwrap();
    }
    let tenant = TenantId::new();
    let other = TenantId::new();
    pg.ensure_tenant(tenant, "auditor-test").await.unwrap();
    pg.ensure_tenant(other, "other-tenant").await.unwrap();
    let (bad_run, bad_action) = action(&pg, tenant, false).await;
    let (valid_run, valid_action) = action(&pg, tenant, false).await;
    let (other_run, _) = action(&pg, other, true).await;

    // A legitimate pending approval is proposed, not proof that an action executed.
    let session: uuid::Uuid = sqlx::query_scalar("SELECT session_id FROM actions WHERE action_id=$1")
        .bind(valid_action.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    let mut pending = verdict(SafetyDecision::ApprovalRequired);
    pending.risk_class = RiskClass::Destructive;
    pending.approval = Some(ApprovalId::new());
    pg.propose(
        valid_run,
        session.into(),
        &proposal("anonymous", StateClusterId::new(), 2),
        &pending,
    )
    .await
    .unwrap();

    let reader_url = login_url(&base, &reader, &password, &schema);
    let pause_url = login_url(&base, &pauser, &password, &schema);
    let auditor = SafetyAuditor::connect(&reader_url, &pause_url).await.unwrap();
    let read_pool = sqlx::PgPool::connect(&reader_url).await.unwrap();
    let pause_pool = sqlx::PgPool::connect(&pause_url).await.unwrap();
    assert!(sqlx::query("UPDATE crawl_runs SET status='paused'")
        .execute(&read_pool)
        .await
        .is_err());
    assert!(sqlx::query("SELECT * FROM actions")
        .execute(&pause_pool)
        .await
        .is_err());
    assert!(SafetyAuditor::connect(&base, &base).await.is_err());

    // An uncommitted change in another transaction must not manufacture a violation.
    let mut transient = pg.pool().begin().await.unwrap();
    sqlx::query("UPDATE safety_decisions SET verdict='deny' WHERE action_id=$1")
        .bind(valid_action.0)
        .execute(&mut *transient)
        .await
        .unwrap();
    let clean = auditor.audit().await.unwrap();
    assert_eq!(clean.checked, 3);
    assert!(clean.violations.is_empty());
    transient.rollback().await.unwrap();

    // Privileged test path deliberately bypasses the actor and kernel persistence contract.
    sqlx::query("UPDATE safety_decisions SET verdict='deny' WHERE action_id=$1")
        .bind(bad_action.0)
        .execute(pg.pool())
        .await
        .unwrap();
    let report = auditor.audit().await.unwrap();
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].action, bad_action);
    assert_eq!(report.violations[0].reason, "denied_action_intended");
    assert_eq!(report.paused, vec![bad_run]);
    for (run, expected) in [
        (bad_run, "paused"),
        (valid_run, "running"),
        (other_run, "running"),
    ] {
        let status: String = sqlx::query_scalar("SELECT status::text FROM crawl_runs WHERE run_id=$1")
            .bind(run.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
        assert_eq!(status, expected);
    }
    let (subject, previous, hash): (serde_json::Value, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT subject,prev_hash,entry_hash FROM audit_events WHERE run_id=$1 AND event='safety.invariant_violation'",
    ).bind(bad_run.0).fetch_one(pg.pool()).await.unwrap();
    let entry = serde_json::json!({"tenant":tenant,"run":bad_run,"actor":"safety_auditor","event":"safety.invariant_violation","subject":subject});
    let bytes = [previous.as_slice(), entry.to_string().as_bytes()].concat();
    assert_eq!(hash, Digest::of("crawlx/audit-chain/v1", &bytes).0);
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM crawl_events WHERE run_id=$1 AND type='paused' AND payload->>'reason'='denied_action_intended'")
        .bind(bad_run.0).fetch_one(pg.pool()).await.unwrap();
    assert_eq!(events, 1);
    assert!(auditor.audit().await.unwrap().paused.is_empty());

    // An apparently allowing decision still cannot override an independent hard-deny class.
    sqlx::query(
        "UPDATE safety_decisions SET verdict='allow',risk_class='financial_transaction' WHERE action_id=$1",
    )
    .bind(bad_action.0)
    .execute(pg.pool())
    .await
    .unwrap();
    assert_eq!(
        auditor.audit().await.unwrap().violations[0].reason,
        "hard_deny_class_intended"
    );

    // Test-environment communication still requires an opted-in verified authorization sink.
    sqlx::query("UPDATE crawl_runs SET safety_profile='test_environment' WHERE run_id=$1")
        .bind(bad_run.0)
        .execute(pg.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE safety_decisions SET profile='test_environment',risk_class='external_communication' WHERE action_id=$1")
        .bind(bad_action.0).execute(pg.pool()).await.unwrap();
    assert_eq!(
        auditor.audit().await.unwrap().violations[0].reason,
        "verified_sink_missing_at_intent"
    );

    // Approval validity is evaluated at intent, never at the auditor's later wall time.
    sqlx::query("UPDATE crawl_runs SET config=jsonb_set(config,'{safety,destructiveActions}','\"approval\"') WHERE run_id=$1")
        .bind(bad_run.0).execute(pg.pool()).await.unwrap();
    sqlx::query(
        "UPDATE safety_decisions SET verdict='approval_required',risk_class='destructive' WHERE action_id=$1",
    )
    .bind(bad_action.0)
    .execute(pg.pool())
    .await
    .unwrap();
    assert_eq!(
        auditor.audit().await.unwrap().violations[0].reason,
        "approval_missing_at_intent"
    );
    sqlx::query(
        "INSERT INTO approvals(approval_id,run_id,action_id,safety_decision_id,risk_class,summary,decision,decided_at,consumed_at,expires_at) \
         SELECT $1,a.run_id,a.action_id,a.safety_decision_id,'destructive','{}','approved', \
           a.intended_at-interval '1 second',a.intended_at-interval '1 second',a.intended_at+interval '1 microsecond' \
         FROM actions a WHERE a.action_id=$2",
    ).bind(ApprovalId::new().0).bind(bad_action.0).execute(pg.pool()).await.unwrap();
    assert!(auditor.audit().await.unwrap().violations.is_empty());

    // Durable safety opt-ins remain auditable after every volatile ZDR byte expires.
    let (zdr_run, zdr_action, buffer) = opted_in_zdr_action(&pg, tenant).await;
    let durable: serde_json::Value = sqlx::query_scalar("SELECT config FROM crawl_runs WHERE run_id=$1")
        .bind(zdr_run.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert!(!durable.to_string().contains("private-zdr-sink-canary"));
    assert!(auditor.audit().await.unwrap().violations.is_empty());
    buffer
        .sweep(chrono::Utc::now() + chrono::Duration::hours(2))
        .await
        .unwrap();
    assert!(auditor.audit().await.unwrap().violations.is_empty());

    sqlx::query(
        "UPDATE safety_decisions SET risk_class='destructive',verdict='approval_required' WHERE action_id=$1",
    )
    .bind(zdr_action.0)
    .execute(pg.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO approvals(approval_id,run_id,action_id,safety_decision_id,risk_class,summary,decision,decided_at,consumed_at,expires_at) \
         SELECT $1,a.run_id,a.action_id,a.safety_decision_id,'destructive','{}','approved', \
           a.intended_at-interval '1 second',a.intended_at-interval '1 second',a.intended_at+interval '1 microsecond' \
         FROM actions a WHERE a.action_id=$2",
    ).bind(ApprovalId::new().0).bind(zdr_action.0).execute(pg.pool()).await.unwrap();
    assert!(auditor.audit().await.unwrap().violations.is_empty());

    // Disabling the same durable opt-in must still detect and pause the real violation.
    sqlx::query(
        "UPDATE safety_decisions SET risk_class='external_communication',verdict='allow' WHERE action_id=$1",
    )
    .bind(zdr_action.0)
    .execute(pg.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE crawl_runs SET config=jsonb_set(config,'{safety,externalCommunication}','\"deny\"') WHERE run_id=$1")
        .bind(zdr_run.0).execute(pg.pool()).await.unwrap();
    let denied = auditor.audit().await.unwrap();
    assert_eq!(denied.paused, vec![zdr_run]);
    assert_eq!(denied.violations[0].action, zdr_action);
    assert_eq!(denied.violations[0].reason, "verified_sink_missing_at_intent");
    let paused = EventRepo::list_after(&pg, zdr_run, 0, 100).await.unwrap();
    assert_eq!(paused.len(), 1);
    assert_eq!(paused[0].kind, "paused");
    assert!(paused[0].payload.get("digest").is_some());
    assert!(!paused[0].payload.to_string().contains("private-zdr-sink-canary"));

    drop(auditor);
    read_pool.close().await;
    pause_pool.close().await;
    let admin = sqlx::PgPool::connect(&base).await.unwrap();
    pg.drop_schema().await.unwrap();
    for login in [&reader, &pauser] {
        sqlx::query(&format!("DROP ROLE {login}"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
