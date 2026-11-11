//! Bootstrap producer ownership on every engine: one exclusive persisted fence per run, takeover
//! after expiry with a strictly newer fence and the same cursor, explicit completion, and
//! fail-closed behavior whenever the worker, the run or its authorization stops being eligible.
//! Ported from the PostgreSQL-only `bootstrap_authority.rs`; the cases that observe
//! PostgreSQL's own lock waits, role switching or a second independent pool stay there.
//!
//! The case that needs the volatile secret registry skips when `CRAWLX_TEST_SECRET_REDIS_URL`
//! is not set.

use crate::rig::Rig;
use async_trait::async_trait;
use chrono::{DateTime, Duration as TimeDelta, Utc};
use crawlx_core::counters::RunStatus;
use crawlx_core::custody::{CustodyLease, CustodySource, RunSecretAuthority};
use crawlx_core::{CrawlRunId, SecretOr, StoreError, SystemClock, TenantId, WorkerId};
use crawlx_storage::custody::bootstrap::{
    BootstrapAuthority, BootstrapAuthorization, BootstrapClaim, BootstrapLease, BootstrapProducerAuthorizer,
    BOOTSTRAP_PRODUCER_TTL, MAX_BOOTSTRAP_PRODUCER_TTL,
};
use crawlx_storage::custody::SecretAuthority;
use crawlx_storage::sql::Sql;
use crawlx_storage::testkit::tenancy::Handle;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{BackendKind, CoreRepos, Database, DeliveryBuffer, Store};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

conformance! { databases:
    competing_workers_receive_one_exclusive_persisted_fence,
    expiry_never_revives_old_fence_and_takeover_keeps_progress,
    seed_presence_and_partial_work_never_imply_completion,
    explicit_joined_completion_survives_new_clients_and_cannot_reopen,
    renewal_preserves_fence_and_uses_bounded_absolute_expiry,
    unavailable_or_mismatched_authorization_never_creates_or_mutates_ownership,
    worker_registration_and_heartbeat_never_equal_ownership,
    cancellation_purge_run_expiry_and_status_stop_every_fenced_mutation,
    current_authorization_revocation_expiry_future_window_and_digest_mismatch_fail_closed,
    issued_bootstrap_custody_and_all_lease_clones_reject_captured_cancellation,
}

/// Run `$body` with `$store` bound to the concrete store of the rig's engine.
macro_rules! on_store {
    ($rig:expr, |$store:ident| $body:expr) => {{
        let database = $rig.database();
        match database.kind() {
            BackendKind::MariaDb => {
                let $store = database.mariadb_store().unwrap().clone();
                $body
            }
            BackendKind::Sqlite => {
                let $store = database.sqlite_store().unwrap().clone();
                $body
            }
            _ => {
                let $store = database.postgres().unwrap().clone();
                $body
            }
        }
    }};
}

// This adapter is a test-only admitted context, never a production substitute for the
// worker's run context and authorization boundary.
struct AdmittedContext {
    tenant: TenantId,
    run: CrawlRunId,
    worker: WorkerId,
    available: AtomicBool,
    cancellation: CancellationToken,
}

impl AdmittedContext {
    fn new(tenant: TenantId, run: CrawlRunId) -> Arc<Self> {
        Arc::new(Self {
            tenant,
            run,
            worker: WorkerId::new(),
            available: AtomicBool::new(true),
            cancellation: CancellationToken::new(),
        })
    }
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

/// A running run, two registered workers and an authority per worker.
struct Fixture<B: Sql> {
    database: Database,
    db: Handle,
    tenant: TenantId,
    run: CrawlRunId,
    context: Arc<AdmittedContext>,
    other_context: Arc<AdmittedContext>,
    first: BootstrapAuthority<B>,
    second: BootstrapAuthority<B>,
    store: Store<B>,
}

impl<B: Sql> Fixture<B> {
    async fn new(rig: &Rig, store: Store<B>) -> Self {
        rig.migrate().await;
        let delivery = Arc::new(DeliveryBuffer::with_defaults(Arc::new(SystemClock)));
        let repos = CoreRepos::open(rig.database(), Some(delivery)).unwrap();
        let tenant = TenantId::new();
        rig.insert_tenant(tenant.0).await.unwrap();
        let run = crawl_run(tenant, create_crawl("https://example.test/", &["anonymous"], 1));
        repos.runs.create(&run, None).await.unwrap();
        repos
            .runs
            .set_status(run.id, RunStatus::Running, None)
            .await
            .unwrap();
        let db = Handle::operator(rig).unwrap();
        let now = rig.database().db_now().await.unwrap();
        let context = AdmittedContext::new(tenant, run.id);
        let other_context = AdmittedContext::new(tenant, run.id);
        for worker in [context.worker, other_context.worker] {
            db.run(&format!(
                "INSERT INTO workers (worker_id, hostname, version, capacity, last_heartbeat_at) \
                 VALUES ({}, 'bootstrap-test', 'test', '{{}}', {})",
                db.id(worker.0),
                db.ts(now)
            ))
            .await
            .unwrap();
        }
        let first = BootstrapAuthority::new(store.clone(), context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
        let second =
            BootstrapAuthority::new(store.clone(), other_context.clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
        Self {
            database: rig.database().clone(),
            db,
            tenant,
            run: run.id,
            context,
            other_context,
            first,
            second,
            store,
        }
    }

    /// The database's own clock: lease arithmetic never uses the test's.
    async fn now(&self) -> DateTime<Utc> {
        self.database.db_now().await.unwrap()
    }

    async fn acquired(&self, authority: &BootstrapAuthority<B>) -> BootstrapLease {
        match authority.claim(self.tenant, self.run).await.unwrap() {
            BootstrapClaim::Acquired(lease) => lease,
            other => panic!("expected acquisition, got {other:?}"),
        }
    }

    fn run_filter(&self) -> String {
        format!("run_id = {}", self.db.id(self.run.0))
    }

    /// Whether the producer row of this run satisfies `condition`.
    async fn producer_has(&self, condition: &str) -> bool {
        let filter = format!("{} AND {condition}", self.run_filter());
        self.db.count("run_bootstrap_producers", &filter).await.unwrap() == 1
    }

    async fn producer_rows(&self) -> i64 {
        self.db.count("run_bootstrap_producers", "1 = 1").await.unwrap()
    }

    /// Move the producer row's lease into the past, as an expired lease.
    async fn expire(&self) {
        let now = self.now().await;
        self.db
            .run(&format!(
                "UPDATE run_bootstrap_producers SET leased_at = {}, expires_at = {} WHERE tenant_id = {} AND run_id = {}",
                self.db.ts(now - TimeDelta::seconds(2)),
                self.db.ts(now - TimeDelta::seconds(1)),
                self.db.id(self.tenant.0),
                self.db.id(self.run.0)
            ))
            .await
            .unwrap();
    }

    /// Admit the run under a freshly inserted, valid authorization record.
    async fn bind_authorization(&self) -> (Uuid, Uuid) {
        let key = Uuid::now_v7();
        let record = Uuid::now_v7();
        let scopes = if self.db.kind() == BackendKind::Postgres {
            "ARRAY['crawl:write']"
        } else {
            "'[\"crawl:write\"]'"
        };
        self.db
            .run(&format!(
                "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES ({}, {}, 'bootstrap-{key}', {}, {scopes})",
                self.db.id(key),
                self.db.id(self.tenant.0),
                self.db.bytes(&[1; 32]),
            ))
            .await
            .unwrap();
        self.insert_record(record, key, -60, 120).await;
        self.db
            .run(&format!(
                "UPDATE crawl_runs SET authorization_record_id = {}, authorization_body_digest = {} WHERE run_id = {}",
                self.db.id(record),
                self.db.bytes(&[7; 32]),
                self.db.id(self.run.0)
            ))
            .await
            .unwrap();
        (record, key)
    }

    /// An authorization record valid from `from` to `to` seconds around the database clock.
    async fn insert_record(&self, record: Uuid, key: Uuid, from: i64, to: i64) {
        let now = self.now().await;
        self.db
            .run(&format!(
                "INSERT INTO authorization_records (record_id, tenant_id, body, body_digest, valid_from, valid_to, created_by) \
                 VALUES ({}, {}, '{{}}', {}, {}, {}, {})",
                self.db.id(record),
                self.db.id(self.tenant.0),
                self.db.bytes(&[7; 32]),
                self.db.ts(now + TimeDelta::seconds(from)),
                self.db.ts(now + TimeDelta::seconds(to)),
                self.db.id(key),
            ))
            .await
            .unwrap();
    }

    /// Every fenced mutation of `lease` through the first authority is refused.
    async fn assert_fenced(&self, lease: &BootstrapLease, what: &str) {
        assert!(self.first.renew(lease).await.is_err(), "{what}");
        assert!(self.first.checkpoint(lease, 1).await.is_err(), "{what}");
        assert!(self.first.complete(lease, 0).await.is_err(), "{what}");
        assert!(self.first.release(lease).await.is_err(), "{what}");
    }
}

async fn competing_workers_receive_one_exclusive_persisted_fence(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
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
        assert_eq!(f.producer_rows().await, 1);
        assert!(
            f.producer_has(&format!("fence = {} AND progress = 0", owner.custody().fence))
                .await
        );
        assert!(matches!(owner.custody().source, CustodySource::Bootstrap(_)));
    });
}

async fn expiry_never_revives_old_fence_and_takeover_keeps_progress(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        let first = f.acquired(&f.first).await;
        let first = f.first.checkpoint(&first, 3).await.unwrap();
        assert!(
            f.first.checkpoint(&first, 2).await.is_err(),
            "progress never regresses"
        );
        f.expire().await;
        assert!(f.first.renew(&first).await.is_err());
        assert!(f.first.complete(&first, 3).await.is_err());
        assert!(f.first.release(&first).await.is_err());
        let next = f.acquired(&f.second).await;
        assert_eq!(next.progress(), 3);
        assert!(next.custody().fence > first.custody().fence);
        assert_eq!(next.custody().source, first.custody().source);
        assert_ne!(next.custody().worker, first.custody().worker);
        assert!(f.first.renew(&first).await.is_err());
        assert!(f.first.checkpoint(&first, 4).await.is_err());
        assert!(f.first.complete(&first, 3).await.is_err());
        let next = f.second.checkpoint(&next, 4).await.unwrap();
        assert_eq!(next.progress(), 4);
        assert!(f.producer_has("state = 'running' AND completed_at IS NULL").await);
    });
}

async fn seed_presence_and_partial_work_never_imply_completion(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        f.db
            .run(&format!(
                "INSERT INTO url_frontier (tenant_id, run_id, canonical_key, canonical_url, origin, depth, via, status) \
                 VALUES ({}, {}, {}, 'https://example.test/', 'https://example.test', 0, 'seed', 'succeeded')",
                f.db.id(f.tenant.0),
                f.db.id(f.run.0),
                f.db.bytes(&[9; 32])
            ))
            .await
            .unwrap();
        let lease = f.acquired(&f.first).await;
        assert_eq!(lease.progress(), 0);
        assert!(f.first.complete(&lease, 1).await.is_err());
        let lease = f.first.checkpoint(&lease, 1).await.unwrap();
        f.first.release(&lease).await.unwrap();
        let next = f.acquired(&f.second).await;
        assert_eq!(next.progress(), 1);
        assert!(next.custody().fence > lease.custody().fence);
        assert!(f.first.checkpoint(&lease, 2).await.is_err());
        assert!(f.first.complete(&lease, 1).await.is_err());
        assert!(matches!(
            f.first.claim(f.tenant, f.run).await.unwrap(),
            BootstrapClaim::Busy { .. }
        ));
    });
}

async fn explicit_joined_completion_survives_new_clients_and_cannot_reopen(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        let lease = f.acquired(&f.first).await;
        let lease = f.first.checkpoint(&lease, 4).await.unwrap();
        f.first.complete(&lease, 4).await.unwrap();
        let reopened =
            BootstrapAuthority::new(f.store.clone(), f.other_context.clone(), BOOTSTRAP_PRODUCER_TTL)
                .unwrap();
        match reopened.claim(f.tenant, f.run).await.unwrap() {
            BootstrapClaim::Completed {
                progress,
                completed_at,
            } => {
                assert_eq!(progress, 4);
                assert!(completed_at <= f.now().await);
            }
            other => panic!("expected durable completion, got {other:?}"),
        }
        assert!(f.first.renew(&lease).await.is_err());
        assert!(f.first.checkpoint(&lease, 5).await.is_err());
        assert!(f.first.release(&lease).await.is_err());
        // the database itself refuses to reopen a completed row, even under a newer fence
        let now = f.now().await;
        let reopen = format!(
            "UPDATE run_bootstrap_producers SET state = 'running', completed_at = NULL, fence = fence + 1000000, \
             leased_at = {}, expires_at = {} WHERE run_id = {}",
            f.db.ts(now),
            f.db.ts(now + TimeDelta::minutes(1)),
            f.db.id(f.run.0)
        );
        assert!(
            f.db.run(&reopen).await.is_err(),
            "a completed bootstrap cannot be reopened"
        );
        assert!(f.producer_has("state = 'completed' AND progress = 4").await);
    });
}

async fn renewal_preserves_fence_and_uses_bounded_absolute_expiry(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        let lease = f.acquired(&f.first).await;
        let renewed = f.first.renew(&lease).await.unwrap();
        assert_eq!(renewed.custody().source, lease.custody().source);
        assert_eq!(renewed.custody().worker, lease.custody().worker);
        assert_eq!(renewed.custody().fence, lease.custody().fence);
        assert!(renewed.expires_at() >= lease.expires_at());
        // the stored window is positive and never longer than five minutes
        let bounded = match f.db.kind() {
            BackendKind::Sqlite => "expires_at > leased_at AND expires_at <= leased_at + 300000000",
            BackendKind::MariaDb => "expires_at > leased_at AND expires_at <= leased_at + INTERVAL 5 MINUTE",
            _ => "expires_at > leased_at AND expires_at <= leased_at + INTERVAL '5 minutes'",
        };
        assert!(f.producer_has(bounded).await);
        for ttl in [
            Duration::ZERO,
            Duration::from_nanos(1),
            MAX_BOOTSTRAP_PRODUCER_TTL + Duration::from_secs(1),
        ] {
            assert!(BootstrapAuthority::new(f.store.clone(), f.context.clone(), ttl).is_err());
        }
    });
}

async fn unavailable_or_mismatched_authorization_never_creates_or_mutates_ownership(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        f.context.available.store(false, Ordering::SeqCst);
        assert!(f.first.claim(f.tenant, f.run).await.is_err());
        assert_eq!(f.producer_rows().await, 0);
        f.context.available.store(true, Ordering::SeqCst);
        assert!(f.first.claim(TenantId::new(), f.run).await.is_err());
        assert!(f.first.claim(f.tenant, CrawlRunId::new()).await.is_err());
        let lease = f.acquired(&f.first).await;
        f.context.available.store(false, Ordering::SeqCst);
        f.assert_fenced(&lease, "unavailable authorization").await;
        assert!(f.producer_has("state = 'running' AND progress = 0").await);
    });
}

async fn worker_registration_and_heartbeat_never_equal_ownership(rig: &Rig) {
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        let worker_filter = |context: &AdmittedContext| format!("worker_id = {}", f.db.id(context.worker.0));
        f.db.run(&format!(
            "DELETE FROM workers WHERE {}",
            worker_filter(&f.context)
        ))
        .await
        .unwrap();
        assert!(
            f.first.claim(f.tenant, f.run).await.is_err(),
            "an unregistered worker"
        );
        let drain = |value: &str| {
            format!(
                "UPDATE workers SET draining = {value} WHERE {}",
                worker_filter(&f.other_context)
            )
        };
        f.db.run(&drain("true")).await.unwrap();
        assert!(
            f.second.claim(f.tenant, f.run).await.is_err(),
            "a draining worker"
        );
        f.db.run(&drain("false")).await.unwrap();
        let lease = f.acquired(&f.second).await;
        f.db.run(&drain("true")).await.unwrap();
        assert!(f.second.renew(&lease).await.is_err());
        assert!(f.second.complete(&lease, 0).await.is_err());
    });
}

async fn cancellation_purge_run_expiry_and_status_stop_every_fenced_mutation(rig: &Rig) {
    for change in ["cancel", "purge", "run_expiry", "deadline", "pausing"] {
        on_store!(rig, |store| {
            let f = Fixture::new(rig, store).await;
            let lease = f.acquired(&f.first).await;
            let now = f.now().await;
            let past = f.db.ts(now - TimeDelta::seconds(1));
            let assignment = match change {
                "cancel" => format!("cancel_requested_at = {}", f.db.ts(now)),
                "purge" => format!("purge_requested_at = {}", f.db.ts(now)),
                "run_expiry" => format!("expires_at = {past}"),
                "deadline" => format!("deadline_at = {past}"),
                _ => "status = 'pausing'".to_owned(),
            };
            f.db.run(&format!(
                "UPDATE crawl_runs SET {assignment} WHERE run_id = {}",
                f.db.id(f.run.0)
            ))
            .await
            .unwrap();
            assert!(f.first.claim(f.tenant, f.run).await.is_err(), "{change}");
            f.assert_fenced(&lease, change).await;
        });
    }
}

async fn current_authorization_revocation_expiry_future_window_and_digest_mismatch_fail_closed(rig: &Rig) {
    for change in [
        "record_revoked",
        "run_digest_mismatch",
        "record_expired",
        "record_not_yet_valid",
    ] {
        on_store!(rig, |store| {
            let f = Fixture::new(rig, store).await;
            let (record, key) = f.bind_authorization().await;
            let lease = f.acquired(&f.first).await;
            match change {
                "record_revoked" => {
                    let now = f.now().await;
                    f.db.run(&format!(
                        "UPDATE authorization_records SET revoked_at = {} WHERE record_id = {}",
                        f.db.ts(now),
                        f.db.id(record)
                    ))
                    .await
                    .unwrap();
                }
                "run_digest_mismatch" => {
                    f.db.run(&format!(
                        "UPDATE crawl_runs SET authorization_body_digest = {} WHERE run_id = {}",
                        f.db.bytes(&[8; 32]),
                        f.db.id(f.run.0)
                    ))
                    .await
                    .unwrap();
                }
                _ => {
                    // authorization evidence is immutable: point the run at a record whose
                    // window is already over, or has not started
                    let (from, to) = if change == "record_expired" {
                        (-120, -60)
                    } else {
                        (60, 120)
                    };
                    let replacement = Uuid::now_v7();
                    f.insert_record(replacement, key, from, to).await;
                    f.db.run(&format!(
                        "UPDATE crawl_runs SET authorization_record_id = {} WHERE run_id = {}",
                        f.db.id(replacement),
                        f.db.id(f.run.0)
                    ))
                    .await
                    .unwrap();
                }
            }
            assert!(f.second.claim(f.tenant, f.run).await.is_err(), "{change}");
            f.assert_fenced(&lease, change).await;
        });
    }
}

async fn issued_bootstrap_custody_and_all_lease_clones_reject_captured_cancellation(rig: &Rig) {
    let Ok(redis_url) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        eprintln!("skipped: CRAWLX_TEST_SECRET_REDIS_URL is not set");
        return;
    };
    on_store!(rig, |store| {
        let f = Fixture::new(rig, store).await;
        let lease = f.acquired(&f.first).await;
        let copied_custody = lease.custody().clone();
        let authority = SecretAuthority::open(f.store.clone(), &redis_url, Duration::from_secs(60))
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
        f.assert_fenced(&lease, "captured cancellation").await;
        // the refused calls changed nothing: same epoch, no staged operation
        let filter = format!(
            "{} AND epoch = {} AND pending_operation IS NULL",
            f.run_filter(),
            registered.version.epoch
        );
        assert_eq!(f.db.count("run_secret_authority", &filter).await.unwrap(), 1);
        // changing a session descriptor into a bootstrap descriptor cannot strip the mandatory
        // local capability and reuse a valid database fence
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
    });
}
