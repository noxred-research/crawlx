//! Dedicated bootstrap ownership against PostgreSQL and optional volatile Redis.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_core::counters::RunStatus;
use crawlx_core::custody::{CustodyLease, CustodySource, RunSecretAuthority};
use crawlx_core::repo::RunRepo;
use crawlx_core::{CrawlRunId, SecretOr, StoreError, TenantId, WorkerId};
use crawlx_storage::custody::bootstrap::{
    BootstrapAuthorization, BootstrapClaim, BootstrapLease, BootstrapProducerAuthorizer,
    PgBootstrapAuthority, BOOTSTRAP_PRODUCER_TTL, MAX_BOOTSTRAP_PRODUCER_TTL,
};
use crawlx_storage::custody::PgSecretAuthority;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{LeaseRepo, Pg, PgConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// This adapter is a test-only admitted context, never a production substitute
// for the worker's RunContext and AuthorizationGuard boundary.
struct AdmittedContext {
    tenant: TenantId,
    run: CrawlRunId,
    worker: WorkerId,
    available: AtomicBool,
    cancellation: CancellationToken,
}

#[async_trait]
impl BootstrapProducerAuthorizer for AdmittedContext {
    async fn authorize(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
    ) -> Result<BootstrapAuthorization, StoreError> {
        if tenant != self.tenant || run != self.run {
            return Err(StoreError::AccessDenied("bootstrap context mismatch".into()));
        }
        if !self.available.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable(
                "bootstrap authorization unavailable".into(),
            ));
        }
        if self.cancellation.is_cancelled() {
            return Err(StoreError::LeaseLost);
        }
        Ok(BootstrapAuthorization::new(
            self.worker,
            self.cancellation.clone(),
        ))
    }
}

struct Fixture {
    pg: Pg,
    peer: Pg,
    tenant: TenantId,
    run: CrawlRunId,
    context: Arc<AdmittedContext>,
    other_context: Arc<AdmittedContext>,
    first: PgBootstrapAuthority,
    second: PgBootstrapAuthority,
}

async fn fixture() -> Option<Fixture> {
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let config = PgConfig {
        schema: Some(format!("bootstrap_{}", Uuid::now_v7().simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&database, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let peer = Pg::connect(&database, config).await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "bootstrap-authority-regression")
        .await
        .unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["anonymous"], 1));
    pg.create(&run, None).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let context = Arc::new(AdmittedContext {
        tenant,
        run: run.id,
        worker: WorkerId::new(),
        available: AtomicBool::new(true),
        cancellation: CancellationToken::new(),
    });
    let other_context = Arc::new(AdmittedContext {
        tenant,
        run: run.id,
        worker: WorkerId::new(),
        available: AtomicBool::new(true),
        cancellation: CancellationToken::new(),
    });
    for worker in [context.worker, other_context.worker] {
        sqlx::query("INSERT INTO workers(worker_id,hostname,version,capacity,last_heartbeat_at) VALUES($1,'bootstrap-test','test','{}',clock_timestamp())")
            .bind(worker.0).execute(pg.pool()).await.unwrap();
    }
    let first = PgBootstrapAuthority::new(pg.clone(), context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
    let second =
        PgBootstrapAuthority::new(peer.clone(), other_context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
    Some(Fixture {
        pg,
        peer,
        tenant,
        run: run.id,
        context,
        other_context,
        first,
        second,
    })
}

async fn acquired(authority: &PgBootstrapAuthority, f: &Fixture) -> BootstrapLease {
    match authority.claim(f.tenant, f.run).await.unwrap() {
        BootstrapClaim::Acquired(lease) => lease,
        other => panic!("expected acquisition, got {other:?}"),
    }
}

async fn expire(f: &Fixture) {
    sqlx::query("UPDATE run_bootstrap_producers SET leased_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND run_id=$2")
        .bind(f.tenant.0).bind(f.run.0).execute(f.pg.pool()).await.unwrap();
}

async fn bind_authorization(f: &Fixture) -> Uuid {
    let key = Uuid::now_v7();
    let record = Uuid::now_v7();
    sqlx::query("INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,ARRAY['crawl:write'])")
        .bind(key).bind(f.tenant.0).bind(format!("bootstrap-{key}")).bind([1u8; 32].as_slice())
        .execute(f.pg.pool()).await.unwrap();
    sqlx::query("INSERT INTO authorization_records(record_id,tenant_id,body,body_digest,valid_from,valid_to,created_by) VALUES($1,$2,'{}',$3,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '2 minutes',$4)")
        .bind(record).bind(f.tenant.0).bind([7u8; 32].as_slice()).bind(key)
        .execute(f.pg.pool()).await.unwrap();
    sqlx::query(
        "UPDATE crawl_runs SET authorization_record_id=$2,authorization_body_digest=$3 WHERE run_id=$1",
    )
    .bind(f.run.0)
    .bind(record)
    .bind([7u8; 32].as_slice())
    .execute(f.pg.pool())
    .await
    .unwrap();
    record
}

#[tokio::test]
async fn competing_real_workers_receive_one_exclusive_persisted_fence() {
    let Some(f) = fixture().await else {
        return;
    };
    let (first, second) = tokio::join!(f.first.claim(f.tenant, f.run), f.second.claim(f.tenant, f.run));
    let (owner, observer) = match (first.unwrap(), second.unwrap()) {
        (BootstrapClaim::Acquired(lease), BootstrapClaim::Busy { .. }) => (lease, &f.first),
        (BootstrapClaim::Busy { .. }, BootstrapClaim::Acquired(lease)) => (lease, &f.second),
        other => panic!("expected one owner and one busy result, got {other:?}"),
    };
    assert!(matches!(
        observer.claim(f.tenant, f.run).await.unwrap(),
        BootstrapClaim::Busy { .. }
    ));
    let stored: (Uuid, i64, i64) =
        sqlx::query_as("SELECT owner,fence,progress FROM run_bootstrap_producers WHERE run_id=$1")
            .bind(f.run.0)
            .fetch_one(f.peer.pool())
            .await
            .unwrap();
    assert_eq!(stored, (owner.custody().worker.0, owner.custody().fence, 0));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM run_bootstrap_producers WHERE run_id=$1")
        .bind(f.run.0)
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    let sequence_owned: bool =
        sqlx::query_scalar("SELECT pg_get_serial_sequence('run_bootstrap_producers','fence') IS NOT NULL")
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert!(sequence_owned);
    assert!(matches!(owner.custody().source, CustodySource::Bootstrap(_)));
}

#[tokio::test]
async fn expiry_never_revives_old_fence_and_takeover_keeps_progress() {
    let Some(f) = fixture().await else {
        return;
    };
    let first = acquired(&f.first, &f).await;
    let first = f.first.checkpoint(&first, 3).await.unwrap();
    assert!(f.first.checkpoint(&first, 2).await.is_err());
    expire(&f).await;
    assert!(f.first.renew(&first).await.is_err());
    assert!(f.first.complete(&first, 3).await.is_err());
    assert!(f.first.release(&first).await.is_err());
    let next = acquired(&f.second, &f).await;
    assert_eq!(next.progress(), 3);
    assert!(next.custody().fence > first.custody().fence);
    assert_eq!(next.custody().source, first.custody().source);
    assert_ne!(next.custody().worker, first.custody().worker);
    assert!(f.first.renew(&first).await.is_err());
    assert!(f.first.checkpoint(&first, 4).await.is_err());
    assert!(f.first.complete(&first, 3).await.is_err());
    let next = f.second.checkpoint(&next, 4).await.unwrap();
    assert_eq!(next.progress(), 4);
    let completed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT completed_at FROM run_bootstrap_producers WHERE run_id=$1")
            .bind(f.run.0)
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert!(completed.is_none());
}

#[tokio::test]
async fn seed_presence_and_partial_work_never_imply_completion() {
    let Some(f) = fixture().await else {
        return;
    };
    sqlx::query("INSERT INTO url_frontier(run_id,canonical_key,canonical_url,origin,depth,via,status) VALUES($1,$2,'https://example.test/','https://example.test',0,'seed','succeeded')")
        .bind(f.run.0).bind([9u8; 32].as_slice()).execute(f.pg.pool()).await.unwrap();
    let lease = acquired(&f.first, &f).await;
    assert_eq!(lease.progress(), 0);
    assert!(f.first.complete(&lease, 1).await.is_err());
    let lease = f.first.checkpoint(&lease, 1).await.unwrap();
    f.first.release(&lease).await.unwrap();
    let next = acquired(&f.second, &f).await;
    assert_eq!(next.progress(), 1);
    assert!(next.custody().fence > lease.custody().fence);
    assert!(f.first.checkpoint(&lease, 2).await.is_err());
    assert!(f.first.complete(&lease, 1).await.is_err());
    assert!(matches!(
        f.first.claim(f.tenant, f.run).await.unwrap(),
        BootstrapClaim::Busy { .. }
    ));
}

#[tokio::test]
async fn explicit_joined_completion_survives_new_clients_and_cannot_reopen() {
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let lease = f.first.checkpoint(&lease, 4).await.unwrap();
    f.first.complete(&lease, 4).await.unwrap();
    let reopened =
        PgBootstrapAuthority::new(f.peer.clone(), f.other_context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
    match reopened.claim(f.tenant, f.run).await.unwrap() {
        BootstrapClaim::Completed {
            progress,
            completed_at,
        } => {
            assert_eq!(progress, 4);
            assert!(completed_at <= f.pg.now().await.unwrap());
        }
        other => panic!("expected durable completion, got {other:?}"),
    }
    assert!(f.first.renew(&lease).await.is_err());
    assert!(f.first.checkpoint(&lease, 5).await.is_err());
    assert!(f.first.release(&lease).await.is_err());
    assert!(sqlx::query("UPDATE run_bootstrap_producers SET state='running',completed_at=NULL,fence=nextval('run_bootstrap_producer_fence'),leased_at=clock_timestamp(),expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1")
        .bind(f.run.0).execute(f.pg.pool()).await.is_err());
}

#[tokio::test]
async fn renewal_preserves_fence_and_uses_bounded_absolute_expiry() {
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let renewed = f.first.renew(&lease).await.unwrap();
    assert_eq!(renewed.custody().source, lease.custody().source);
    assert_eq!(renewed.custody().worker, lease.custody().worker);
    assert_eq!(renewed.custody().fence, lease.custody().fence);
    assert!(renewed.expires_at() >= lease.expires_at());
    let bounded: bool = sqlx::query_scalar("SELECT expires_at>leased_at AND expires_at<=leased_at+interval '5 minutes' FROM run_bootstrap_producers WHERE run_id=$1")
        .bind(f.run.0).fetch_one(f.pg.pool()).await.unwrap();
    assert!(bounded);
    for ttl in [
        Duration::ZERO,
        Duration::from_nanos(1),
        MAX_BOOTSTRAP_PRODUCER_TTL + Duration::from_secs(1),
    ] {
        assert!(PgBootstrapAuthority::new(f.pg.clone(), f.context.clone(), ttl).is_err());
    }
}

#[tokio::test]
async fn unavailable_or_mismatched_authorization_never_creates_or_mutates_ownership() {
    let Some(f) = fixture().await else {
        return;
    };
    f.context.available.store(false, Ordering::SeqCst);
    assert!(f.first.claim(f.tenant, f.run).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM run_bootstrap_producers")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    f.context.available.store(true, Ordering::SeqCst);
    assert!(f.first.claim(TenantId::new(), f.run).await.is_err());
    assert!(f.first.claim(f.tenant, CrawlRunId::new()).await.is_err());
    let lease = acquired(&f.first, &f).await;
    f.context.available.store(false, Ordering::SeqCst);
    assert!(f.first.renew(&lease).await.is_err());
    assert!(f.first.checkpoint(&lease, 1).await.is_err());
    assert!(f.first.complete(&lease, 0).await.is_err());
    assert!(f.first.release(&lease).await.is_err());
    let stored: (String, i64) =
        sqlx::query_as("SELECT state,progress FROM run_bootstrap_producers WHERE run_id=$1")
            .bind(f.run.0)
            .fetch_one(f.pg.pool())
            .await
            .unwrap();
    assert_eq!(stored, ("running".into(), 0));
}

#[tokio::test]
async fn worker_registration_and_heartbeat_never_equal_ownership() {
    let Some(f) = fixture().await else {
        return;
    };
    sqlx::query("DELETE FROM workers WHERE worker_id=$1")
        .bind(f.context.worker.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f.first.claim(f.tenant, f.run).await.is_err());
    sqlx::query("UPDATE workers SET draining=true,last_heartbeat_at=clock_timestamp() WHERE worker_id=$1")
        .bind(f.other_context.worker.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f.second.claim(f.tenant, f.run).await.is_err());
    sqlx::query("UPDATE workers SET draining=false WHERE worker_id=$1")
        .bind(f.other_context.worker.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    let lease = acquired(&f.second, &f).await;
    sqlx::query("UPDATE workers SET draining=true WHERE worker_id=$1")
        .bind(f.other_context.worker.0)
        .execute(f.pg.pool())
        .await
        .unwrap();
    assert!(f.second.renew(&lease).await.is_err());
    assert!(f.second.complete(&lease, 0).await.is_err());
}

#[tokio::test]
async fn cancellation_purge_run_expiry_and_status_stop_every_fenced_mutation() {
    for change in [
        "cancel_requested_at=clock_timestamp()",
        "purge_requested_at=clock_timestamp()",
        "expires_at=clock_timestamp()-interval '1 second'",
        "deadline_at=clock_timestamp()-interval '1 second'",
        "status='pausing'",
    ] {
        let Some(f) = fixture().await else {
            return;
        };
        let lease = acquired(&f.first, &f).await;
        sqlx::query(&format!("UPDATE crawl_runs SET {change} WHERE run_id=$1"))
            .bind(f.run.0)
            .execute(f.pg.pool())
            .await
            .unwrap();
        assert!(f.first.claim(f.tenant, f.run).await.is_err(), "{change}");
        assert!(f.first.renew(&lease).await.is_err(), "{change}");
        assert!(f.first.checkpoint(&lease, 1).await.is_err(), "{change}");
        assert!(f.first.complete(&lease, 0).await.is_err(), "{change}");
        assert!(f.first.release(&lease).await.is_err(), "{change}");
    }
}

#[tokio::test]
async fn current_authorization_revocation_expiry_future_window_and_digest_mismatch_fail_closed() {
    for change in [
        "record_revoked",
        "run_digest_mismatch",
        "record_expired",
        "record_not_yet_valid",
    ] {
        let Some(f) = fixture().await else {
            return;
        };
        let record = if matches!(change, "record_expired" | "record_not_yet_valid") {
            // Authorization evidence is immutable. Insert the desired invalid
            // window instead of changing an admitted record's validity columns.
            let record = bind_authorization(&f).await;
            let lease = acquired(&f.first, &f).await;
            let key: Uuid =
                sqlx::query_scalar("SELECT created_by FROM authorization_records WHERE record_id=$1")
                    .bind(record)
                    .fetch_one(f.pg.pool())
                    .await
                    .unwrap();
            let replacement = Uuid::now_v7();
            let (start, end) = if change == "record_expired" {
                (-120i32, -60i32)
            } else {
                (60i32, 120i32)
            };
            sqlx::query("INSERT INTO authorization_records(record_id,tenant_id,body,body_digest,valid_from,valid_to,created_by) VALUES($1,$2,'{}',$3,clock_timestamp()+make_interval(secs=>$4),clock_timestamp()+make_interval(secs=>$5),$6)")
                .bind(replacement).bind(f.tenant.0).bind([7u8; 32].as_slice()).bind(f64::from(start)).bind(f64::from(end)).bind(key)
                .execute(f.pg.pool()).await.unwrap();
            sqlx::query("UPDATE crawl_runs SET authorization_record_id=$2 WHERE run_id=$1")
                .bind(f.run.0)
                .bind(replacement)
                .execute(f.pg.pool())
                .await
                .unwrap();
            assert!(f.first.claim(f.tenant, f.run).await.is_err(), "{change}");
            assert!(f.first.renew(&lease).await.is_err(), "{change}");
            assert!(f.first.checkpoint(&lease, 1).await.is_err(), "{change}");
            assert!(f.first.complete(&lease, 0).await.is_err(), "{change}");
            assert!(f.first.release(&lease).await.is_err(), "{change}");
            continue;
        } else {
            bind_authorization(&f).await
        };
        let lease = acquired(&f.first, &f).await;
        if change == "record_revoked" {
            sqlx::query("UPDATE authorization_records SET revoked_at=clock_timestamp() WHERE record_id=$1")
                .bind(record)
                .execute(f.pg.pool())
                .await
                .unwrap();
        } else {
            sqlx::query("UPDATE crawl_runs SET authorization_body_digest=$2 WHERE run_id=$1")
                .bind(f.run.0)
                .bind([8u8; 32].as_slice())
                .execute(f.pg.pool())
                .await
                .unwrap();
        }
        assert!(f.second.claim(f.tenant, f.run).await.is_err());
        assert!(f.first.renew(&lease).await.is_err());
        assert!(f.first.checkpoint(&lease, 1).await.is_err());
        assert!(f.first.complete(&lease, 0).await.is_err());
        assert!(f.first.release(&lease).await.is_err());
    }
}

#[tokio::test]
async fn unavailable_database_never_yields_a_lease_or_completion() {
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    // Independent PostgreSQL peer keeps the durable row observable after this
    // authority's backend becomes unavailable. No process-local fallback exists.
    f.pg.pool().close().await;
    assert!(f.first.renew(&lease).await.is_err());
    assert!(f.first.checkpoint(&lease, 1).await.is_err());
    assert!(f.first.complete(&lease, 0).await.is_err());
    assert!(f.first.release(&lease).await.is_err());
    assert!(f.first.claim(f.tenant, f.run).await.is_err());
    let state: String = sqlx::query_scalar("SELECT state FROM run_bootstrap_producers WHERE run_id=$1")
        .bind(f.run.0)
        .fetch_one(f.peer.pool())
        .await
        .unwrap();
    assert_eq!(state, "running");
    assert!(matches!(
        f.second.claim(f.tenant, f.run).await.unwrap(),
        BootstrapClaim::Busy { .. }
    ));
}

async fn wait_for_blocked(pg: &Pg, blocker: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker)
            .fetch_one(pg.pool())
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("operation did not block on the held PostgreSQL lock");
}

async fn authority_lock(f: &Fixture) -> (sqlx::Transaction<'static, sqlx::Postgres>, i32) {
    let mut tx = f.peer.pool().begin().await.unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('crawlx/secret-authority/v1:' || $1::uuid::text || ':' || $2::uuid::text,0))")
        .bind(f.tenant.0).bind(f.run.0).execute(&mut *tx).await.unwrap();
    (tx, pid)
}

#[tokio::test]
async fn captured_token_cancels_claim_while_waiting_for_authority_lock() {
    let Some(f) = fixture().await else {
        return;
    };
    let (blocker, pid) = authority_lock(&f).await;
    let authority = f.first.clone();
    let tenant = f.tenant;
    let run = f.run;
    let operation = tokio::spawn(async move { authority.claim(tenant, run).await });
    wait_for_blocked(&f.peer, pid).await;
    f.context.cancellation.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .expect("cancelled claim kept waiting for its authority lock")
        .unwrap();
    assert!(matches!(result, Err(StoreError::LeaseLost)));
    blocker.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM run_bootstrap_producers")
        .fetch_one(f.peer.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn captured_token_cancels_checkpoint_while_waiting_for_authority_lock() {
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let (blocker, pid) = authority_lock(&f).await;
    let authority = f.first.clone();
    let operation = tokio::spawn(async move { authority.checkpoint(&lease, 1).await });
    wait_for_blocked(&f.peer, pid).await;
    f.context.cancellation.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .expect("cancelled checkpoint kept waiting for its authority lock")
        .unwrap();
    assert!(matches!(result, Err(StoreError::LeaseLost)));
    blocker.rollback().await.unwrap();
    let progress: i64 = sqlx::query_scalar("SELECT progress FROM run_bootstrap_producers WHERE run_id=$1")
        .bind(f.run.0)
        .fetch_one(f.peer.pool())
        .await
        .unwrap();
    assert_eq!(progress, 0);
}

#[tokio::test]
async fn issued_bootstrap_custody_and_all_lease_clones_reject_captured_cancellation() {
    let Ok(redis_url) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        return;
    };
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let copied_custody = lease.custody().clone();
    let authority = PgSecretAuthority::open(f.pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let initial = authority.initialize(&copied_custody).await.unwrap();
    let registered = authority
        .register(
            &copied_custody,
            initial.version,
            Uuid::now_v7(),
            &SecretOr::secret("before-cancel".into()),
        )
        .await
        .unwrap();
    authority.snapshot(lease.custody()).await.unwrap();
    f.context.cancellation.cancel();
    assert!(matches!(
        authority.initialize(&copied_custody).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        authority.snapshot(lease.custody()).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        authority
            .register(
                &copied_custody,
                registered.version,
                Uuid::now_v7(),
                &SecretOr::secret("after-cancel".into())
            )
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(f.first.renew(&lease).await.is_err());
    assert!(f.first.checkpoint(&lease, 1).await.is_err());
    assert!(f.first.complete(&lease, 0).await.is_err());
    assert!(f.first.release(&lease).await.is_err());
    let stored: (i64, Option<Uuid>) =
        sqlx::query_as("SELECT epoch,pending_operation FROM run_secret_authority WHERE run_id=$1")
            .bind(f.run.0)
            .fetch_one(f.peer.pool())
            .await
            .unwrap();
    assert_eq!(stored, (registered.version.epoch, None));
    // Changing a session descriptor into a bootstrap descriptor cannot strip
    // the mandatory local capability and reuse a valid database fence.
    let mut unbound = CustodyLease::new(
        f.tenant,
        f.run,
        crawlx_core::SessionId::new(),
        lease.custody().worker,
        lease.custody().fence,
    );
    unbound.source = lease.custody().source;
    assert!(matches!(
        authority.snapshot(&unbound).await,
        Err(StoreError::LeaseLost)
    ));
}

#[tokio::test]
async fn captured_cancellation_during_custody_row_lock_wait_never_stages_registration() {
    let Ok(redis_url) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        return;
    };
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let authority = PgSecretAuthority::open(f.pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let initial = authority.initialize(lease.custody()).await.unwrap().version;
    let mut blocker = f.peer.pool().begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT run_id FROM run_secret_authority WHERE run_id=$1 FOR UPDATE")
        .bind(f.run.0)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let operation = tokio::spawn(async move {
        authority
            .register(
                lease.custody(),
                initial,
                Uuid::now_v7(),
                &SecretOr::secret("blocked-cancel".into()),
            )
            .await
    });
    wait_for_blocked(&f.peer, pid).await;
    f.context.cancellation.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .expect("cancelled registration kept waiting for its custody row lock")
        .unwrap();
    assert!(matches!(result, Err(StoreError::LeaseLost)));
    blocker.rollback().await.unwrap();
    let stored: (i64, Option<Uuid>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT epoch,pending_operation,pending_commitment FROM run_secret_authority WHERE run_id=$1",
    )
    .bind(f.run.0)
    .fetch_one(f.peer.pool())
    .await
    .unwrap();
    assert_eq!(stored, (initial.epoch, None, None));
}

#[tokio::test]
async fn captured_cancellation_during_custody_advisory_lock_wait_fails_before_mutation() {
    let Ok(redis_url) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        return;
    };
    let Some(f) = fixture().await else {
        return;
    };
    let lease = acquired(&f.first, &f).await;
    let authority = PgSecretAuthority::open(f.pg.clone(), &redis_url, Duration::from_secs(60))
        .await
        .unwrap();
    let initial = authority.initialize(lease.custody()).await.unwrap().version;
    let (blocker, pid) = authority_lock(&f).await;
    let operation = tokio::spawn(async move {
        authority
            .register(
                lease.custody(),
                initial,
                Uuid::now_v7(),
                &SecretOr::secret("blocked-advisory".into()),
            )
            .await
    });
    wait_for_blocked(&f.peer, pid).await;
    f.context.cancellation.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .expect("cancelled registration kept waiting for its authority lock")
        .unwrap();
    assert!(matches!(result, Err(StoreError::LeaseLost)));
    blocker.rollback().await.unwrap();
    let stored: (i64, Option<Uuid>) =
        sqlx::query_as("SELECT epoch,pending_operation FROM run_secret_authority WHERE run_id=$1")
            .bind(f.run.0)
            .fetch_one(f.peer.pool())
            .await
            .unwrap();
    assert_eq!(stored, (initial.epoch, None));
}

#[tokio::test]
async fn nonsuperuser_table_owner_claims_unscoped_while_api_role_keeps_tenant_isolation() {
    let Some(f) = fixture().await else {
        return;
    };
    let database = std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(f.pg.pool())
        .await
        .unwrap();
    let owner = format!("bootstrap_owner_{}", Uuid::now_v7().simple());
    let api = format!("bootstrap_api_{}", Uuid::now_v7().simple());
    let mut admin = f.pg.pool().acquire().await.unwrap();
    for sql in [
        format!("CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT"),
        format!("CREATE ROLE {api} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT"),
        format!("GRANT {owner}, {api} TO CURRENT_USER"),
        format!("GRANT USAGE, CREATE ON SCHEMA {schema} TO {owner}"),
        format!("GRANT USAGE ON SCHEMA {schema} TO {api}"),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {api}"),
        format!("GRANT USAGE ON ALL SEQUENCES IN SCHEMA {schema} TO {api}"),
    ] {
        sqlx::query(&sql).execute(&mut *admin).await.unwrap();
    }
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname=$1 AND c.relkind IN ('r','p') ORDER BY c.relname",
    )
    .bind(&schema)
    .fetch_all(&mut *admin)
    .await
    .unwrap();
    for table in tables {
        sqlx::query(&format!("ALTER TABLE {schema}.{table} OWNER TO {owner}"))
            .execute(&mut *admin)
            .await
            .unwrap();
    }
    // SET ROLE changes PostgreSQL's effective privilege/RLS identity. The pool
    // has exactly one connection; every worker transaction below uses this
    // real, non-superuser, non-BYPASSRLS table owner without app.tenant_id.
    let worker_pg = Pg::connect_existing(
        &database,
        PgConfig {
            schema: Some(schema.clone()),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    let mut connection = worker_pg.pool().acquire().await.unwrap();
    sqlx::query(&format!("SET ROLE {owner}"))
        .execute(&mut *connection)
        .await
        .unwrap();
    let identity: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT current_user::text,r.rolsuper,r.rolbypassrls,\
         c.relowner=r.oid FROM pg_roles r CROSS JOIN pg_class c \
         WHERE r.rolname=current_user AND c.oid='run_bootstrap_producers'::regclass",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    assert_eq!(identity, (owner.clone(), false, false, true));
    let setting: Option<String> = sqlx::query_scalar("SELECT current_setting('app.tenant_id',true)")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert!(setting.is_none_or(|value| value.is_empty()));
    drop(connection);
    let authority =
        PgBootstrapAuthority::new(worker_pg.clone(), f.context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
    let lease = acquired(&authority, &f).await;
    let lease = authority.checkpoint(&lease, 1).await.unwrap();
    let _renewed = authority.renew(&lease).await.unwrap();
    let other_tenant = TenantId::new();
    worker_pg
        .ensure_tenant(other_tenant, "owner-other-tenant")
        .await
        .unwrap();
    let other_run = crawl_run(
        other_tenant,
        create_crawl("https://other.test/", &["anonymous"], 1),
    );
    worker_pg.create(&other_run, None).await.unwrap();
    worker_pg
        .set_status(other_run.id, RunStatus::Running, None)
        .await
        .unwrap();
    let other_context = Arc::new(AdmittedContext {
        tenant: other_tenant,
        run: other_run.id,
        worker: f.context.worker,
        available: AtomicBool::new(true),
        cancellation: CancellationToken::new(),
    });
    let other_authority =
        PgBootstrapAuthority::new(worker_pg.clone(), other_context, BOOTSTRAP_PRODUCER_TTL).unwrap();
    assert!(matches!(
        other_authority.claim(other_tenant, other_run.id).await.unwrap(),
        BootstrapClaim::Acquired(_)
    ));
    for (tenant, run) in [(f.tenant, f.run), (other_tenant, other_run.id)] {
        sqlx::query("INSERT INTO run_secret_authority(tenant_id,run_id,incarnation,epoch,expires_at) VALUES($1,$2,$3,0,clock_timestamp()+interval '1 minute')")
            .bind(tenant.0).bind(run.0).bind(Uuid::now_v7())
            .execute(worker_pg.pool()).await.unwrap();
    }
    for table in [
        "run_secret_authority",
        "artifact_key_custody",
        "run_artifact_exposures",
        "run_custody_producers",
        "run_bootstrap_producers",
        "run_secret_authority_renewals",
    ] {
        let flags: (bool, bool, bool) = sqlx::query_as(
            "SELECT c.relrowsecurity,c.relforcerowsecurity,c.relowner=r.oid \
             FROM pg_class c CROSS JOIN pg_roles r WHERE c.oid=$1::regclass AND r.rolname=current_user",
        )
        .bind(table)
        .fetch_one(worker_pg.pool())
        .await
        .unwrap();
        assert_eq!(flags, (true, false, true), "{table}");
        sqlx::query(&format!("SELECT tenant_id FROM {table}"))
            .fetch_all(worker_pg.pool())
            .await
            .unwrap();
    }
    sqlx::query(&format!("SET ROLE {api}"))
        .execute(&mut *admin)
        .await
        .unwrap();
    for table in ["run_bootstrap_producers", "run_secret_authority"] {
        let tenants: Vec<Uuid> = sqlx::query_scalar(&format!("SELECT tenant_id FROM {table}"))
            .fetch_all(&mut *admin)
            .await
            .unwrap();
        assert!(tenants.is_empty(), "{table}: unscoped API must fail closed");
    }
    sqlx::query("SET app.tenant_id = ''")
        .execute(&mut *admin)
        .await
        .unwrap();
    for table in ["run_bootstrap_producers", "run_secret_authority"] {
        let tenants: Vec<Uuid> = sqlx::query_scalar(&format!("SELECT tenant_id FROM {table}"))
            .fetch_all(&mut *admin)
            .await
            .unwrap();
        assert!(tenants.is_empty(), "{table}: reset tenant must fail closed");
    }
    for tenant in [f.tenant, other_tenant] {
        sqlx::query("SELECT set_config('app.tenant_id',$1,false)")
            .bind(tenant.to_string())
            .execute(&mut *admin)
            .await
            .unwrap();
        for table in ["run_bootstrap_producers", "run_secret_authority"] {
            let tenants: Vec<Uuid> = sqlx::query_scalar(&format!("SELECT tenant_id FROM {table}"))
                .fetch_all(&mut *admin)
                .await
                .unwrap();
            assert_eq!(tenants, vec![tenant.0], "{table}");
        }
        let hidden_tenant = if tenant == f.tenant {
            other_tenant
        } else {
            f.tenant
        };
        let result = sqlx::query("INSERT INTO run_bootstrap_producers(producer_id,tenant_id,run_id,owner,state,leased_at,expires_at) VALUES($1,$2,$3,$4,'running',clock_timestamp(),clock_timestamp()+interval '1 minute')")
            .bind(Uuid::now_v7()).bind(hidden_tenant.0).bind(CrawlRunId::new().0).bind(f.context.worker.0)
            .execute(&mut *admin).await;
        assert_eq!(
            result.unwrap_err().as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    sqlx::query("RESET ROLE").execute(&mut *admin).await.unwrap();
    worker_pg.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut *admin)
        .await
        .unwrap();
    sqlx::query(&format!("DROP ROLE {owner}, {api}"))
        .execute(&mut *admin)
        .await
        .unwrap();
}
