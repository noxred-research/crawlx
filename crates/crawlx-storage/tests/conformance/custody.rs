//! Custody, origin admission and profile cases: producer and bootstrap fences, renewable use
//! windows under a frozen ceiling, sealed artifact publication with the epoch check, deployment
//! wide origin capacity and pacing, and fenced profile generations.
//!
//! Cases that need the volatile secret registry skip when `CRAWLX_TEST_SECRET_REDIS_URL` is
//! not set. Every other case runs on SQLite, and on MariaDB and PostgreSQL when their test
//! servers are configured.

use crate::rig::Rig;
use async_trait::async_trait;
use chrono::{DateTime, Duration as TimeDelta, Utc};
use crawlx_core::acquisition::BackendCapabilitiesV1;
use crawlx_core::config::LaunchProfile;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::{ArtifactReadState, CustodyLease, CustodySource, RunSecretAuthority, SecretEpoch};
use crawlx_core::hash::Digest;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::origin::OriginAdmission;
use crawlx_core::repo::{RunRepo, Sensitivity};
use crawlx_core::{ArtifactId, CrawlRunId, SecretOr, StoreError, SystemClock, TenantId, WorkerId};
use crawlx_storage::custody::bootstrap::{
    BootstrapAuthority, BootstrapAuthorization, BootstrapClaim, BootstrapProducerAuthorizer,
    BOOTSTRAP_PRODUCER_TTL,
};
use crawlx_storage::custody::{
    encrypted_object_key, ArtifactKeyEnvelope, ArtifactProducerAuthorizer, CiphertextIdentity,
    SecretAuthority, CIPHERTEXT_DIGEST_DOMAIN,
};
use crawlx_storage::leases::SessionLease;
use crawlx_storage::profiles::{BrowserProfileRepo, ProfileCipher, ProfileFiles, ProfileScopeV1};
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{
    is_stale_epoch, tenant, ArtifactRow, BackendKind, CoreRepos, DeliveryBuffer, FenceSeq,
    MariaOriginAdmission, PgOriginAdmission, SqliteOriginAdmission, Store,
};
use crawlx_storage::{AdminOps, WorkerRegistry};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

conformance! { databases:
    authenticated_producers_are_fenced_and_revocable,
    bootstrap_ownership_is_exclusive_and_takeover_advances_the_fence,
    durable_renewal_commits_once_and_never_changes_redis_retention,
    frozen_ceiling_never_grows_after_run_policy_is_relaxed,
    sealed_publication_checks_the_epoch_and_blocks_catalog_growth,
    origin_feedback_coalesces_waves_and_start_checks_other_workers_cooldown,
    origin_capacity_is_shared_across_handles_and_tenants_but_not_across_origins,
    cancelled_origin_waiter_releases_nothing_and_the_next_waiter_proceeds,
    origin_waiters_proceed_one_at_a_time,
    origin_spacing_uses_the_maximum_of_the_previous_and_current_operation,
    run_origin_limit_is_shared_and_fences_admitted_starts,
    reserved_capacity_paces_the_actual_start_instead_of_the_reservation,
    profile_generations_are_fenced_and_never_overwritten,
    custody_profile_generations_register_every_secret_and_fail_closed,
    registry_projection_excludes_stale_draining_and_restarted_workers,
    historical_recovery_preserves_registration_retry_and_exact_absolute_expiry,
    unapplied_pending_barrier_blocks_use_and_cannot_extend_retention,
    old_deadline_recovery_requires_surviving_exact_remote_renewal_proof,
    old_deadline_without_applied_renewal_never_recreates_lost_registry,
    delayed_remote_command_is_refused_and_corrupt_historical_receipt_denies_recovery,
    queued_lifetime_mutation_cannot_execute_after_fence_loss_cancel_or_purge,
    renewal_denies_stale_lease_nonpositive_extension_and_run_ceiling,
    renewal_obeys_authorization_deadline_revocation_cancel_and_purge,
    pending_renewal_blocks_real_publication_reads_and_terminal_finalization,
    surviving_key_without_exact_renewal_proof_cannot_recover_after_old_deadline,
    changed_secret_set_never_receives_requested_renewal,
    renewal_rejects_requests_larger_than_the_configured_use_window,
    overlong_absolute_window_is_rejected_before_pending_barrier,
    expired_use_authority_never_resurrects_even_with_surviving_redis_values,
    renewal_registration_race_requires_current_epoch_without_losing_retry_identity,
    lost_redis_registry_never_rebuilds_during_a_durable_renewal,
    paused_redis_response_cannot_renew_a_cancelled_producer_or_change_physical_expiry,
    original_retention_above_one_day_requires_both_explicit_permissions_and_operator_ceiling,
    terminal_retained_projector_uses_only_surviving_original_secret_values,
    retained_source_projector_refuses_zdr_even_with_live_secret_values,
    competing_live_renewals_request_refresh_instead_of_failing_valid_producer_work,
    feed_finalizer_claim_seals_terminal_output_only_while_it_owns_the_unfinished_finalization,
    recovery_seals_the_feeds_of_a_run_that_already_ended_under_the_claim,
}

const DEADLINE: Duration = Duration::from_secs(20);

// ---- environment ------------------------------------------------------------------------

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

fn redis_url() -> Option<String> {
    let url = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL")
        .ok()
        .filter(|url| !url.is_empty());
    if url.is_none() {
        eprintln!("skipped: CRAWLX_TEST_SECRET_REDIS_URL is not set");
    }
    url
}

fn kind(rig: &Rig) -> BackendKind {
    rig.database().kind()
}

/// A tenant with one running run and its repositories.
struct World {
    tenant: TenantId,
    run: CrawlRunId,
    repos: CoreRepos,
    sessions: Vec<crawlx_core::repo::CrawlSession>,
}

async fn world(rig: &Rig) -> World {
    world_with(rig, false).await
}

async fn world_with(rig: &Rig, zdr: bool) -> World {
    rig.migrate().await;
    let delivery = Arc::new(DeliveryBuffer::with_defaults(Arc::new(SystemClock)));
    let repos = CoreRepos::open(rig.database(), Some(delivery)).unwrap();
    let tenant = TenantId::new();
    rig.insert_tenant(tenant.0).await.unwrap();
    let mut config = create_crawl("https://example.test/", &["role0"], 2);
    if zdr {
        config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
        config.retention.days = 0;
    }
    let run = crawl_run(tenant, config);
    repos.runs.create(&run, None).await.unwrap();
    let slots = sessions(run.id, 1, 2);
    repos.runs.create_sessions(&slots).await.unwrap();
    repos
        .runs
        .set_status(run.id, RunStatus::Running, None)
        .await
        .unwrap();
    World {
        tenant,
        run: run.id,
        repos,
        sessions: slots,
    }
}

// ---- raw SQL: what the repositories wrote, changed and read back without them -----------

enum V<'a> {
    Uuid(Uuid),
    Text(&'a str),
    Bytes(&'a [u8]),
    Ts(DateTime<Utc>),
    I64(i64),
}

macro_rules! bind_values {
    ($query:expr, $args:expr, $ts:expr) => {{
        let mut query = $query;
        for arg in $args {
            query = match arg {
                V::Uuid(v) => query.bind(*v),
                V::Text(v) => query.bind(*v),
                V::Bytes(v) => query.bind(*v),
                V::Ts(v) => query.bind(($ts)(*v)),
                V::I64(v) => query.bind(*v),
            };
        }
        query
    }};
}

/// Raw statements in `$n` template notation (PostgreSQL casts allowed).
struct Raw<'a>(&'a Rig);

impl Raw<'_> {
    fn text(&self, template: &str) -> String {
        crawlx_storage::sql::Built::expand(kind(self.0), template)
            .text()
            .to_owned()
    }

    /// The arguments in the order the engine binds them: MariaDB binds positionally, so the
    /// arguments follow the placeholders' order of appearance (a template may use `$2` first).
    fn bound<'a>(&self, template: &str, args: &'a [V<'a>]) -> Vec<&'a V<'a>> {
        if kind(self.0) != BackendKind::MariaDb {
            return args.iter().collect();
        }
        let mut order = Vec::new();
        let mut quoted = false;
        let bytes = template.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\'' => quoted = !quoted,
                b'$' if !quoted && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                    let mut n = 0_usize;
                    while let Some(d) = bytes.get(i + 1).filter(|d| d.is_ascii_digit()) {
                        n = n * 10 + usize::from(d - b'0');
                        i += 1;
                    }
                    order.push(&args[n - 1]);
                }
                _ => {}
            }
            i += 1;
        }
        order
    }

    async fn exec(&self, template: &str, args: &[V<'_>]) -> u64 {
        let args = self.bound(template, args);
        let sql = self.text(template);
        let database = self.0.database();
        match kind(self.0) {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .execute(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .rows_affected()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .execute(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .rows_affected()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .execute(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .rows_affected(),
        }
    }

    /// Run a statement that must fail and return the driver error text.
    async fn refuse(&self, template: &str, args: &[V<'_>]) -> String {
        let args = self.bound(template, args);
        let sql = self.text(template);
        let database = self.0.database();
        let result = match kind(self.0) {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .execute(database.sqlite_pool().unwrap())
                .await
                .map(drop)
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .execute(database.mariadb_pool().unwrap())
                .await
                .map(drop)
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .execute(database.postgres().unwrap().pool())
                .await
                .map(drop),
        };
        result
            .expect_err("the database must refuse this statement")
            .to_string()
    }

    /// The first column of the first row as an integer.
    async fn int(&self, template: &str, args: &[V<'_>]) -> i64 {
        let args = self.bound(template, args);
        use sqlx::Row as _;
        let sql = self.text(template);
        let database = self.0.database();
        match kind(self.0) {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_one(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_one(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_one(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap(),
        }
    }

    /// The first column of the first row as a timestamp.
    async fn ts(&self, template: &str, args: &[V<'_>]) -> DateTime<Utc> {
        let args = self.bound(template, args);
        use sqlx::Row as _;
        let sql = self.text(template);
        let database = self.0.database();
        match kind(self.0) {
            BackendKind::Sqlite => {
                let micros = bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_one(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap();
                DateTime::from_timestamp_micros(micros).unwrap()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_one(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .try_get::<chrono::NaiveDateTime, _>(0)
                .unwrap()
                .and_utc()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_one(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .try_get::<DateTime<Utc>, _>(0)
                .unwrap(),
        }
    }

    /// The first column of the first row as bytes.
    async fn bytes(&self, template: &str, args: &[V<'_>]) -> Vec<u8> {
        let args = self.bound(template, args);
        use sqlx::Row as _;
        let sql = self.text(template);
        let database = self.0.database();
        match kind(self.0) {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_one(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .try_get::<Vec<u8>, _>(0)
                .unwrap()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_one(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .try_get::<Vec<u8>, _>(0)
                .unwrap()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_one(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .try_get::<Vec<u8>, _>(0)
                .unwrap(),
        }
    }
}

/// An `api_keys` row of `tenant`; returns its id.
async fn api_key(rig: &Rig, tenant: TenantId) -> Uuid {
    let key = Uuid::now_v7();
    let scopes = if kind(rig) == BackendKind::Postgres {
        "ARRAY['crawl:write']"
    } else {
        "'[\"crawl:write\"]'"
    };
    Raw(rig)
        .exec(
            &format!(
                "INSERT INTO api_keys(key_id,tenant_id,prefix,key_hash,scopes) VALUES($1,$2,$3,$4,{scopes})"
            ),
            &[
                V::Uuid(key),
                V::Uuid(tenant.0),
                V::Text(&format!("custody-{key}")),
                V::Bytes(&[1; 32]),
            ],
        )
        .await;
    key
}

/// A registered, non-draining worker.
async fn worker(rig: &Rig) -> WorkerId {
    let id = WorkerId::new();
    let now = rig.database().db_now().await.unwrap();
    Raw(rig)
        .exec(
            "INSERT INTO workers(worker_id,hostname,version,capacity,last_heartbeat_at) VALUES($1,'custody-test','test','{}',$2)",
            &[V::Uuid(id.0), V::Ts(now)],
        )
        .await;
    id
}

/// One session of the run held by a fresh worker under a fresh fence: the lease the claim
/// would have granted.
async fn leased_session(rig: &Rig, world: &World, slot: usize) -> SessionLease {
    let session = world.sessions[slot].clone();
    let worker = worker(rig).await;
    let fence = rig.database().next_fence(FenceSeq::Lease).await.unwrap();
    let expires_at = rig.database().db_now().await.unwrap() + TimeDelta::minutes(5);
    Raw(rig)
        .exec(
            "UPDATE crawl_sessions SET status='running',lease_owner=$1,lease_expires_at=$2,fencing_token=$3 WHERE session_id=$4",
            &[V::Uuid(worker.0), V::Ts(expires_at), V::I64(fence), V::Uuid(session.id.0)],
        )
        .await;
    SessionLease {
        session,
        worker,
        fencing_token: fence,
        expires_at,
    }
}

fn custody_lease(world: &World, lease: &SessionLease) -> CustodyLease {
    CustodyLease::new(
        world.tenant,
        world.run,
        lease.session.id,
        lease.worker,
        lease.fencing_token,
    )
}

// ---- producer fence ---------------------------------------------------------------------

struct KeyAuthorizer(Uuid);

#[async_trait]
impl ArtifactProducerAuthorizer for KeyAuthorizer {
    async fn authorize(&self, _tenant: TenantId, _run: CrawlRunId) -> Result<Uuid, StoreError> {
        Ok(self.0)
    }
}

async fn authenticated_producers_are_fenced_and_revocable(rig: &Rig) {
    let world = world(rig).await;
    let key = api_key(rig, world.tenant).await;
    let authorizer = KeyAuthorizer(key);
    on_store!(rig, |store| {
        let authority = SecretAuthority::finalized_reads(store);
        let first = authority
            .acquire_authenticated_producer(&authorizer, world.tenant, world.run, Duration::from_secs(30))
            .await
            .unwrap();
        let second = authority
            .acquire_authenticated_producer(&authorizer, world.tenant, world.run, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(first.fence > 0 && second.fence > first.fence, "fences only grow");
        assert!(matches!(first.source, CustodySource::AuthenticatedProducer(_)));
        // release is exact: another owner or fence is refused, the real one is idempotent
        let CustodySource::AuthenticatedProducer(producer) = first.source else {
            panic!("producer source");
        };
        let forged = CustodyLease::for_authenticated_producer(
            world.tenant,
            world.run,
            producer,
            first.worker,
            first.fence + 1000,
        );
        assert!(matches!(
            authority.release_authenticated_producer(&forged).await,
            Err(StoreError::LeaseLost)
        ));
        authority.release_authenticated_producer(&first).await.unwrap();
        authority.release_authenticated_producer(&first).await.unwrap();
        // a revoked key mints nothing
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE api_keys SET revoked_at=$2 WHERE key_id=$1",
                &[V::Uuid(key), V::Ts(now)],
            )
            .await;
        assert!(matches!(
            authority
                .acquire_authenticated_producer(&authorizer, world.tenant, world.run, Duration::from_secs(30))
                .await,
            Err(StoreError::AccessDenied(_))
        ));
        // a stopped run mints nothing either
        let other = api_key(rig, world.tenant).await;
        world
            .repos
            .runs
            .set_status(world.run, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
            .await
            .unwrap();
        assert!(matches!(
            authority
                .acquire_authenticated_producer(
                    &KeyAuthorizer(other),
                    world.tenant,
                    world.run,
                    Duration::from_secs(30)
                )
                .await,
            Err(StoreError::LeaseLost)
        ));
    });
}

// ---- bootstrap fence --------------------------------------------------------------------

struct Context {
    tenant: TenantId,
    run: CrawlRunId,
    worker: WorkerId,
    cancellation: CancellationToken,
}

#[async_trait]
impl BootstrapProducerAuthorizer for Context {
    async fn authorize(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
    ) -> Result<BootstrapAuthorization, StoreError> {
        if tenant != self.tenant || run != self.run {
            return Err(StoreError::AccessDenied("bootstrap context mismatch".into()));
        }
        Ok(BootstrapAuthorization::new(
            self.worker,
            self.cancellation.clone(),
        ))
    }
}

async fn bootstrap_ownership_is_exclusive_and_takeover_advances_the_fence(rig: &Rig) {
    let world = world(rig).await;
    let contexts = [worker(rig).await, worker(rig).await].map(|worker| {
        Arc::new(Context {
            tenant: world.tenant,
            run: world.run,
            worker,
            cancellation: CancellationToken::new(),
        })
    });
    on_store!(rig, |store| {
        let first =
            BootstrapAuthority::new(store.clone(), contexts[0].clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
        let second =
            BootstrapAuthority::new(store.clone(), contexts[1].clone(), BOOTSTRAP_PRODUCER_TTL).unwrap();
        let BootstrapClaim::Acquired(lease) = first.claim(world.tenant, world.run).await.unwrap() else {
            panic!("the first claim acquires");
        };
        // exclusive: neither the owner nor a peer may claim a live row
        assert!(matches!(
            second.claim(world.tenant, world.run).await.unwrap(),
            BootstrapClaim::Busy { .. }
        ));
        assert!(matches!(
            first.claim(world.tenant, world.run).await.unwrap(),
            BootstrapClaim::Busy { .. }
        ));
        let lease = first.checkpoint(&lease, 3).await.unwrap();
        assert_eq!(lease.progress(), 3);
        assert!(
            first.checkpoint(&lease, 2).await.is_err(),
            "progress never regresses"
        );
        // expiry lets a peer take over with a strictly newer fence and the same cursor
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE run_bootstrap_producers SET leased_at=$3,expires_at=$4 WHERE tenant_id=$1 AND run_id=$2",
                &[
                    V::Uuid(world.tenant.0),
                    V::Uuid(world.run.0),
                    V::Ts(now - TimeDelta::seconds(2)),
                    V::Ts(now - TimeDelta::seconds(1)),
                ],
            )
            .await;
        let BootstrapClaim::Acquired(taken) = second.claim(world.tenant, world.run).await.unwrap() else {
            panic!("an expired row is taken over");
        };
        assert!(taken.custody().fence > lease.custody().fence);
        assert_eq!(taken.progress(), 3, "the durable cursor survives takeover");
        // the old fence is dead
        assert!(matches!(first.renew(&lease).await, Err(StoreError::LeaseLost)));
        assert!(matches!(
            first.checkpoint(&lease, 4).await,
            Err(StoreError::LeaseLost)
        ));
        let taken = second.checkpoint(&taken, 4).await.unwrap();
        let taken = second.renew(&taken).await.unwrap();
        second.complete(&taken, 4).await.unwrap();
        match first.claim(world.tenant, world.run).await.unwrap() {
            BootstrapClaim::Completed { progress, .. } => assert_eq!(progress, 4),
            other => panic!("expected completion, got {other:?}"),
        }
    });
}

// ---- renewable use windows --------------------------------------------------------------

fn target(from: DateTime<Utc>, seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(from.timestamp_millis() + seconds * 1000).unwrap()
}

async fn redis_connection(url: &str) -> redis::aio::MultiplexedConnection {
    redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

/// Redis' absolute expiry of the run's registry, milliseconds.
async fn physical_expiry(connection: &mut redis::aio::MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("PEXPIRETIME")
        .arg(key)
        .query_async(connection)
        .await
        .unwrap()
}

fn registry_key(world: &World) -> String {
    format!("crawlx:secrets:{{{}:{}}}", world.tenant, world.run)
}

async fn durable_renewal_commits_once_and_never_changes_redis_retention(rig: &Rig) {
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let session = leased_session(rig, &world, 0).await;
    let lease = custody_lease(&world, &session);
    let mut redis = redis_connection(&url).await;
    on_store!(rig, |store| {
        let authority = SecretAuthority::open(store.clone(), &url, Duration::from_secs(60))
            .await
            .unwrap();
        let initial = authority.initialize(&lease).await.unwrap();
        let ceiling = Raw(rig)
            .ts("SELECT retention_ceiling FROM run_secret_authority", &[])
            .await;
        let physical = physical_expiry(&mut redis, &registry_key(&world)).await;
        assert_eq!(physical, ceiling.timestamp_millis() - 2000);
        let window = authority.renewal_window(&lease).await.unwrap();
        assert_eq!(window.version, initial.version);
        assert_eq!(window.retention_ceiling, ceiling);
        let now = rig.database().db_now().await.unwrap();
        // enter a shorter remaining use window without changing the original policy
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, 10))],
            )
            .await;
        let deadline = target(now, 50);
        let operation = Uuid::now_v7();
        let renewed = authority
            .renew_authority(&lease, initial.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(renewed.version, initial.version);
        assert_eq!(
            Raw(rig)
                .ts("SELECT expires_at FROM run_secret_authority", &[])
                .await,
            deadline
        );
        assert_eq!(physical_expiry(&mut redis, &registry_key(&world)).await, physical);
        // a fresh authority (as after process loss) recovers the durable receipt exactly
        let recovered_authority = SecretAuthority::open(store.clone(), &url, Duration::from_secs(3600))
            .await
            .unwrap();
        recovered_authority
            .renew_authority(&lease, initial.version, operation, deadline)
            .await
            .unwrap();
        assert!(recovered_authority
            .renew_authority(&lease, initial.version, Uuid::now_v7(), target(now, 120))
            .await
            .is_err());
        // a registration after the renewal keeps the receipt recoverable at the newer epoch
        let registered = authority
            .register(
                &lease,
                initial.version,
                Uuid::now_v7(),
                &SecretOr::secret("renewed-registry-value".into()),
            )
            .await
            .unwrap();
        let recovered = authority
            .renew_authority(&lease, initial.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(recovered.version, registered.version);
        assert_eq!(physical_expiry(&mut redis, &registry_key(&world)).await, physical);
        assert_eq!(
            Raw(rig)
                .int("SELECT count(*) FROM run_secret_authority_renewals", &[])
                .await,
            1
        );
        assert!(authority
            .renew_authority(&lease, initial.version, operation, target(deadline, 1))
            .await
            .is_err());
        assert_eq!(
            Raw(rig)
                .ts("SELECT expires_at FROM run_secret_authority", &[])
                .await,
            deadline
        );
    });
}

async fn frozen_ceiling_never_grows_after_run_policy_is_relaxed(rig: &Rig) {
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let session = leased_session(rig, &world, 0).await;
    let lease = custody_lease(&world, &session);
    let mut redis = redis_connection(&url).await;
    on_store!(rig, |store| {
        let authority = SecretAuthority::open(store, &url, Duration::from_secs(60))
            .await
            .unwrap();
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET expires_at=$1,deadline_at=$1",
                &[V::Ts(target(now, 45))],
            )
            .await;
        let initial = authority.initialize(&lease).await.unwrap();
        let original = Raw(rig)
            .ts("SELECT retention_ceiling FROM run_secret_authority", &[])
            .await;
        // relaxing the run's own policy afterwards must not raise the frozen ceiling
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET expires_at=$1,deadline_at=$1",
                &[V::Ts(target(now, 3600))],
            )
            .await;
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, 10))],
            )
            .await;
        assert!(authority
            .renew_authority(&lease, initial.version, Uuid::now_v7(), target(original, 1))
            .await
            .is_err());
        authority
            .renew_authority(&lease, initial.version, Uuid::now_v7(), original)
            .await
            .unwrap();
        assert_eq!(
            physical_expiry(&mut redis, &registry_key(&world)).await,
            original.timestamp_millis() - 2000
        );
    });
}

// ---- sealed artifact publication ----------------------------------------------------------

fn ciphertext() -> CiphertextIdentity {
    CiphertextIdentity::new(Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &[7; 196]), 196).unwrap()
}

async fn artifact_row(rig: &Rig, lease: &CustodyLease) -> ArtifactRow {
    let id = ArtifactId::new();
    ArtifactRow {
        id,
        tenant: lease.tenant,
        run: lease.run,
        kind: "html".into(),
        bucket: "encrypted-artifacts".into(),
        object_key: encrypted_object_key(lease.tenant, lease.run, id, ciphertext().digest),
        size_bytes: 128,
        digest: Digest::of("crawlx/artifact/v1", &[7; 128]),
        content_type: "text/html".into(),
        sensitivity: Sensitivity::Content,
        created_at: rig.database().db_now().await.unwrap(),
        expires_at: None,
    }
}

fn envelope(row: &ArtifactRow) -> ArtifactKeyEnvelope {
    ArtifactKeyEnvelope::new(
        row.tenant,
        row.run,
        row.id,
        "key/custody-conformance".into(),
        vec![7; 256],
    )
    .unwrap()
}

async fn sealed_publication_checks_the_epoch_and_blocks_catalog_growth(rig: &Rig) {
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let session = leased_session(rig, &world, 0).await;
    let lease = custody_lease(&world, &session);
    on_store!(rig, |store| {
        let authority = SecretAuthority::open(store.clone(), &url, Duration::from_secs(60))
            .await
            .unwrap();
        let initial = authority.initialize(&lease).await.unwrap();
        let row = artifact_row(rig, &lease).await;
        let key = envelope(&row);
        authority
            .publish(&lease, initial.version, &row, &ciphertext(), &key)
            .await
            .unwrap();
        assert!(
            authority.finalize(initial.version).await.is_err(),
            "a running run cannot seal"
        );
        let next = authority
            .register(
                &lease,
                initial.version,
                Uuid::now_v7(),
                &SecretOr::secret("final-epoch-token-conformance".into()),
            )
            .await
            .unwrap();
        // a publication at the superseded epoch lost the race and changed nothing
        let stale = authority
            .publish(&lease, initial.version, &row, &ciphertext(), &key)
            .await
            .unwrap_err();
        assert!(is_stale_epoch(&stale), "{stale:?}");
        assert!(matches!(
            authority.read_state(row.tenant, row.run, row.id).await.unwrap(),
            ArtifactReadState::Live(_)
        ));
        // the exact immutable object is republished at the new epoch, then the run ends
        authority
            .publish(&lease, next.version, &row, &ciphertext(), &key)
            .await
            .unwrap();
        world
            .repos
            .runs
            .set_status(
                world.run,
                RunStatus::Completed,
                Some(TerminalReason::FrontierExhausted),
            )
            .await
            .unwrap();
        authority.finalize(next.version).await.unwrap();
        authority.finalize(next.version).await.unwrap();
        // the sealed authority reads without the volatile registry
        let durable = SecretAuthority::finalized_reads(store);
        assert!(matches!(
            durable.read_state(row.tenant, row.run, row.id).await.unwrap(),
            ArtifactReadState::Finalized(epoch) if epoch == next.version
        ));
        assert_eq!(
            durable
                .read_custody(row.tenant, row.run, row.id)
                .await
                .unwrap()
                .envelope,
            key
        );
        // the catalog of a sealed run cannot grow or change identity
        let another = artifact_row(rig, &lease).await;
        let raw = Raw(rig);
        let refusal = raw.refuse(
            "INSERT INTO artifacts(artifact_id,tenant_id,run_id,kind,bucket,object_key,size_bytes,content_digest,content_type,sensitivity,created_at) \
             VALUES($1,$2,$3,'html','b','late-object',1,$4,'text/html','content'::text::sensitivity_class,$5)",
            &[
                V::Uuid(another.id.0),
                V::Uuid(another.tenant.0),
                V::Uuid(another.run.0),
                V::Bytes(&[9; 32]),
                V::Ts(another.created_at),
            ],
        )
        .await;
        assert!(refusal.contains("sealed"), "{refusal}");
        let refusal = raw
            .refuse(
                "UPDATE artifacts SET object_key='changed-after-seal' WHERE artifact_id=$1",
                &[V::Uuid(row.id.0)],
            )
            .await;
        assert!(refusal.contains("sealed"), "{refusal}");
        assert!(authority
            .register(
                &lease,
                next.version,
                Uuid::now_v7(),
                &SecretOr::secret("late-secret".into())
            )
            .await
            .is_err());
    });
}

// ---- origin admission ---------------------------------------------------------------------

/// One independent admission service (its own pools, as another worker would have).
fn admission(rig: &Rig, limit: usize) -> Arc<dyn OriginAdmission> {
    let database = rig.database();
    match database.kind() {
        BackendKind::MariaDb => Arc::new(MariaOriginAdmission::new(
            database.mariadb_store().unwrap(),
            limit,
        )),
        BackendKind::Sqlite => Arc::new(SqliteOriginAdmission::new(
            database.sqlite_store().unwrap(),
            limit,
        )),
        _ => Arc::new(PgOriginAdmission::new(
            database.postgres().unwrap().clone(),
            limit,
        )),
    }
}

/// An admission service that also limits `run` to `run_limit` slots per origin.
fn run_admission(rig: &Rig, limit: usize, run: CrawlRunId, run_limit: usize) -> Arc<dyn OriginAdmission> {
    let database = rig.database();
    match database.kind() {
        BackendKind::MariaDb => Arc::new(
            MariaOriginAdmission::new(database.mariadb_store().unwrap(), limit).for_run(run, run_limit),
        ),
        BackendKind::Sqlite => Arc::new(
            SqliteOriginAdmission::new(database.sqlite_store().unwrap(), limit).for_run(run, run_limit),
        ),
        _ => Arc::new(
            PgOriginAdmission::new(database.postgres().unwrap().clone(), limit).for_run(run, run_limit),
        ),
    }
}

fn origin_name(rig: &Rig, label: &str) -> String {
    format!("https://{}-{label}-{}.test", kind(rig), Uuid::now_v7().simple())
}

/// The start the last admitted operation was spaced from: `next_allowed_at - last_spacing_us`.
async fn last_start(rig: &Rig, origin: &str) -> DateTime<Utc> {
    let allowed = Raw(rig)
        .ts(
            "SELECT next_allowed_at FROM origin_admission WHERE origin = $1",
            &[V::Text(origin)],
        )
        .await;
    let spacing = Raw(rig)
        .int(
            "SELECT last_spacing_us FROM origin_admission WHERE origin = $1",
            &[V::Text(origin)],
        )
        .await;
    allowed - TimeDelta::microseconds(spacing)
}

async fn throttle_delay(rig: &Rig, origin: &str) -> i64 {
    Raw(rig)
        .int(
            "SELECT throttle_delay_us FROM origin_admission WHERE origin = $1",
            &[V::Text(origin)],
        )
        .await
}

async fn origin_feedback_coalesces_waves_and_start_checks_other_workers_cooldown(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "feedback");
    let first = admission(rig, 2);
    let second = admission(rig, 2);
    first.cooldown(&origin, Duration::ZERO, true).await.unwrap();
    second.cooldown(&origin, Duration::ZERO, true).await.unwrap();
    assert_eq!(
        throttle_delay(rig, &origin).await,
        2_000_000,
        "a concurrent wave doubles only once"
    );
    // end the fixture's wave without sleeping two seconds; the next committed feedback doubles
    // the persisted baseline, not a worker-local counter
    let expired = rig.database().db_now().await.unwrap() - TimeDelta::seconds(1);
    Raw(rig)
        .exec(
            "UPDATE origin_admission SET cooldown_until=$2 WHERE origin=$1",
            &[V::Text(&origin), V::Ts(expired)],
        )
        .await;
    second.cooldown(&origin, Duration::ZERO, true).await.unwrap();
    assert_eq!(throttle_delay(rig, &origin).await, 4_000_000);
    Raw(rig)
        .exec(
            "UPDATE origin_admission SET cooldown_until=$2,throttle_decays_at=$2 WHERE origin=$1",
            &[V::Text(&origin), V::Ts(expired)],
        )
        .await;
    first.cooldown(&origin, Duration::ZERO, true).await.unwrap();
    assert_eq!(
        throttle_delay(rig, &origin).await,
        2_000_000,
        "a quiet window resets the persisted baseline"
    );
    first
        .cooldown(&origin, Duration::from_secs(120), false)
        .await
        .unwrap();
    second
        .cooldown(&origin, Duration::from_millis(1), false)
        .await
        .unwrap();
    assert!(
        second.cooldown_remaining(&origin).await.unwrap() > Duration::from_secs(110),
        "Retry-After is not capped or shortened by another worker"
    );
    assert!(
        timeout(Duration::from_millis(30), second.acquire(&origin, Duration::ZERO))
            .await
            .is_err()
    );
    let other = format!("{origin}-independent");
    drop(
        timeout(DEADLINE, second.acquire(&other, Duration::ZERO))
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(second.cooldown_remaining(&other).await.unwrap(), Duration::ZERO);
}

async fn origin_capacity_is_shared_across_handles_and_tenants_but_not_across_origins(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "capacity");
    let tenants = [TenantId::new(), TenantId::new()];
    for tenant in tenants {
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    let first = admission(rig, 2);
    let second = admission(rig, 2);
    let held_a = tenant::scope(tenants[0], first.acquire(&origin, Duration::ZERO))
        .await
        .unwrap();
    let held_b = tenant::scope(tenants[1], second.acquire(&origin, Duration::ZERO))
        .await
        .unwrap();
    let waiter = {
        let admission = second.clone();
        let origin = origin.clone();
        let tenant = tenants[1];
        tokio::spawn(async move { tenant::scope(tenant, admission.acquire(&origin, Duration::ZERO)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiter.is_finished(), "the deployment cap includes both tenants");
    let independent = format!("{origin}-independent");
    drop(
        timeout(DEADLINE, second.acquire(&independent, Duration::ZERO))
            .await
            .expect("an independent origin is not blocked")
            .unwrap(),
    );
    drop(held_a);
    drop(timeout(DEADLINE, waiter).await.unwrap().unwrap().unwrap());
    drop(held_b);
}

async fn cancelled_origin_waiter_releases_nothing_and_the_next_waiter_proceeds(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "cancel");
    let admission = admission(rig, 1);
    let held = admission.acquire(&origin, Duration::ZERO).await.unwrap();
    let cancelled = {
        let admission = admission.clone();
        let origin = origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    // the live predecessor stays held: a new caller still waits
    let survivor = {
        let admission = admission.clone();
        let origin = origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !survivor.is_finished(),
        "the cancelled waiter did not release the held slot"
    );
    drop(held);
    drop(timeout(DEADLINE, survivor).await.unwrap().unwrap().unwrap());
}

async fn origin_waiters_proceed_one_at_a_time(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "queue");
    let first = admission(rig, 1);
    let second = admission(rig, 1);
    let held = first.acquire(&origin, Duration::ZERO).await.unwrap();
    let waiters = [
        {
            let admission = first.clone();
            let origin = origin.clone();
            tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
        },
        {
            let admission = second.clone();
            let origin = origin.clone();
            tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
        },
    ];
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(waiters.iter().all(|waiter| !waiter.is_finished()));
    // a further caller waits as well, and ordinary writes still run meanwhile
    assert!(
        timeout(Duration::from_millis(30), first.acquire(&origin, Duration::ZERO))
            .await
            .is_err()
    );
    rig.insert_tenant(Uuid::now_v7()).await.unwrap();
    drop(held);
    // exactly one waiter is admitted at a time
    let (admitted, _, remaining) = timeout(DEADLINE, futures::future::select_all(waiters))
        .await
        .expect("a waiter is admitted once the permit is released");
    let permit = admitted.unwrap().unwrap();
    let mut remaining = remaining;
    let behind = remaining.pop().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !behind.is_finished(),
        "the second waiter stays behind the first permit"
    );
    drop(permit);
    drop(timeout(DEADLINE, behind).await.unwrap().unwrap().unwrap());
}

async fn origin_spacing_uses_the_maximum_of_the_previous_and_current_operation(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "spacing");
    let first = admission(rig, 2);
    let second = admission(rig, 2);
    let http = Duration::from_millis(250);
    let browser = Duration::from_millis(500);
    let held = first.acquire(&origin, http).await.unwrap();
    let a = last_start(rig, &origin).await;
    drop(held);
    let held = second.acquire(&origin, browser).await.unwrap();
    let b = last_start(rig, &origin).await;
    drop(held);
    let held = first.acquire(&origin, http).await.unwrap();
    let c = last_start(rig, &origin).await;
    drop(held);
    assert!((b - a).num_microseconds().unwrap() >= 500_000, "HTTP to browser");
    assert!((c - b).num_microseconds().unwrap() >= 500_000, "browser to HTTP");
    // a cancelled pacing wait must not advance a future reservation
    assert!(
        timeout(Duration::from_millis(20), second.acquire(&origin, browser))
            .await
            .is_err()
    );
    assert_eq!(last_start(rig, &origin).await, c);
    let held = second.acquire(&origin, browser).await.unwrap();
    let d = last_start(rig, &origin).await;
    assert!((d - c).num_microseconds().unwrap() >= 500_000);
    drop(held);
}

async fn run_origin_fence(rig: &Rig, run: CrawlRunId, origin: &str) -> i64 {
    Raw(rig)
        .int(
            "SELECT fencing_token FROM origin_leases WHERE run_id = $1 AND origin = $2",
            &[V::Uuid(run.0), V::Text(origin)],
        )
        .await
}

async fn run_origin_limit_is_shared_and_fences_admitted_starts(rig: &Rig) {
    let world = world(rig).await;
    let origin = origin_name(rig, "run");
    let first = run_admission(rig, 3, world.run, 1);
    let second = run_admission(rig, 3, world.run, 1);
    let held = first.acquire(&origin, Duration::ZERO).await.unwrap();
    let fence = run_origin_fence(rig, world.run, &origin).await;
    assert!(timeout(
        Duration::from_millis(300),
        second.acquire(&origin, Duration::ZERO)
    )
    .await
    .is_err());
    // a cancelled run-slot wait does not consume a global slot or change the fence
    assert_eq!(run_origin_fence(rig, world.run, &origin).await, fence);
    drop(held);
    let held = timeout(DEADLINE, second.acquire(&origin, Duration::ZERO))
        .await
        .unwrap()
        .unwrap();
    assert!(run_origin_fence(rig, world.run, &origin).await > fence);
    drop(held);
    // workers must agree on the deployment limit
    let mismatch = admission(rig, 4);
    assert!(matches!(
        mismatch.acquire(&origin, Duration::ZERO).await,
        Err(StoreError::Conflict(_))
    ));
}

async fn reserved_capacity_paces_the_actual_start_instead_of_the_reservation(rig: &Rig) {
    rig.migrate().await;
    let origin = origin_name(rig, "reserved");
    let admission = admission(rig, 2);
    let mut reserved = admission.reserve(&origin).await.unwrap();
    let started = Raw(rig)
        .int(
            match kind(rig) {
                BackendKind::Postgres => {
                    "SELECT (CASE WHEN isfinite(next_allowed_at) THEN 1 ELSE 0 END)::bigint FROM origin_admission WHERE origin = $1"
                }
                BackendKind::MariaDb => {
                    "SELECT CASE WHEN next_allowed_at > '1001-01-01' THEN 1 ELSE 0 END FROM origin_admission WHERE origin = $1"
                }
                _ => {
                    "SELECT CASE WHEN next_allowed_at > -62135596799000000 THEN 1 ELSE 0 END FROM origin_admission WHERE origin = $1"
                }
            },
            &[V::Text(&origin)],
        )
        .await;
    assert_eq!(
        started, 0,
        "a capacity reservation must not reserve a future start"
    );
    let browser = admission
        .acquire(&origin, Duration::from_millis(500))
        .await
        .unwrap();
    let first = last_start(rig, &origin).await;
    drop(browser);
    reserved.start(Duration::from_millis(250)).await.unwrap();
    let second = last_start(rig, &origin).await;
    assert!((second - first).num_microseconds().unwrap() >= 500_000);
    drop(reserved);
}

// ---- profile generations ------------------------------------------------------------------

fn profile_scope(tenant: TenantId, lease: &SessionLease) -> ProfileScopeV1 {
    ProfileScopeV1::new(
        tenant,
        lease.session.role.clone(),
        "fixture".into(),
        BTreeSet::from(["https://example.test".into()]),
        Digest::of("build", b"pinned"),
        Digest::of("egress", b"approved"),
    )
    .unwrap()
}

fn sealed(
    cipher: &ProfileCipher,
    scope: &ProfileScopeV1,
    generation: u64,
    now: DateTime<Utc>,
    secret: &[u8],
) -> Vec<u8> {
    cipher
        .seal(
            scope,
            generation,
            now + TimeDelta::minutes(5),
            ProfileFiles::new(
                BTreeMap::from([("Default/Cookies".into(), secret.to_vec())]),
                false,
            )
            .unwrap(),
        )
        .unwrap()
}

async fn profile_generations_are_fenced_and_never_overwritten(rig: &Rig) {
    let world = world(rig).await;
    let holder = leased_session(rig, &world, 0).await;
    let other = leased_session(rig, &world, 1).await;
    let now = rig.database().db_now().await.unwrap();
    // profiles outlive the run only within its retention: give the run an explicit horizon
    Raw(rig)
        .exec(
            "UPDATE crawl_runs SET expires_at=$2 WHERE run_id=$1",
            &[V::Uuid(world.run.0), V::Ts(now + TimeDelta::hours(1))],
        )
        .await;
    let cipher = ProfileCipher::new(&[9; 32]).unwrap();
    let scope = profile_scope(world.tenant, &holder);
    let first = sealed(&cipher, &scope, 1, now, b"profile-secret-canary");
    let pinned = Digest::of("crawlx/profile-bundle/v1", &first);
    on_store!(rig, |store| {
        let service = BrowserProfileRepo::new(&store, &cipher);
        service
            .import(&holder, &scope, &first, pinned, 0, true, false)
            .await
            .unwrap();
        // another live holder cannot acquire the generation
        assert!(
            service
                .acquire(&other, &profile_scope(world.tenant, &other), false)
                .await
                .is_err(),
            "a live holder blocks every other session"
        );
        // replaying the create is a generation conflict, never an overwrite
        assert!(service
            .import(&holder, &scope, &first, pinned, 0, true, false)
            .await
            .is_err());
        // the stored ciphertext is the sealed bundle and holds no plaintext
        let stored = Raw(rig)
            .bytes("SELECT encrypted_bundle FROM browser_profiles", &[])
            .await;
        assert_eq!(stored, first);
        assert!(!stored
            .windows(b"profile-secret-canary".len())
            .any(|window| window == b"profile-secret-canary"));
        // the next generation must name the exact previous one
        let second = sealed(&cipher, &scope, 2, now, b"second-generation");
        let second_pin = Digest::of("crawlx/profile-bundle/v1", &second);
        assert!(service
            .import(&holder, &scope, &second, second_pin, 0, true, false)
            .await
            .is_err());
        service
            .import(&holder, &scope, &second, second_pin, 1, true, false)
            .await
            .unwrap();
        assert!(
            service.export(&holder, &scope, 1, false).await.is_err(),
            "generation 1 is gone"
        );
        let (inspection, bytes) = service.export(&holder, &scope, 2, false).await.unwrap();
        assert_eq!(inspection.generation, 2);
        assert_eq!(bytes, second);
        // a lease whose fence is no longer current cannot touch the profile
        let mut stale = holder.clone();
        stale.fencing_token += 1000;
        assert!(service.export(&stale, &scope, 2, false).await.is_err());
        // delete needs the stored generation
        assert!(service.delete(&holder, &scope, 1).await.is_err());
        service.delete(&holder, &scope, 2).await.unwrap();
        assert_eq!(
            Raw(rig).int("SELECT count(*) FROM browser_profiles", &[]).await,
            0
        );
    });
}

fn custody_profile_document(canary: impl Fn(&str) -> String) -> Vec<u8> {
    let cookie = canary("cookie");
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "cookies": [{
            "name": "sid", "value": cookie, "domain": "example.test", "path": "/",
            "expires": -1, "size": cookie.len() + 3, "httpOnly": true, "secure": true, "session": true,
            "priority": "Medium", "sourceScheme": "Secure", "sourcePort": 443
        }],
        "origins": [{"origin": "https://example.test",
            "local": [["local-key", canary("local")]],
            "session": [["session-key", canary("session")]]}]
    }))
    .unwrap()
}

async fn custody_profile_generations_register_every_secret_and_fail_closed(rig: &Rig) {
    use crawlx_storage::artifact_key_crypto::{FileArtifactKeys, MemoryArtifactKeys};
    use crawlx_storage::custody::profiles::CustodyProfiles;
    use std::os::unix::fs::PermissionsExt as _;
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let session = leased_session(rig, &world, 0).await;
    let lease = custody_lease(&world, &session);
    let now = rig.database().db_now().await.unwrap();
    Raw(rig)
        .exec(
            "UPDATE crawl_runs SET expires_at=$2 WHERE run_id=$1",
            &[V::Uuid(world.run.0), V::Ts(now + TimeDelta::hours(1))],
        )
        .await;
    let expiry = now + TimeDelta::minutes(55);
    let canary = |label: &str| Digest::of("crawlx/profile-test-canary/v1", label.as_bytes()).to_string();
    let bytes = custody_profile_document(canary);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.key");
    std::fs::write(&path, format!("{}\n", "5a".repeat(32))).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = path.to_string_lossy().into_owned();
    let keys =
        FileArtifactKeys::from_lookup(&|name| (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| path.clone()))
            .unwrap()
            .unwrap();
    let scope = profile_scope(world.tenant, &session);
    on_store!(rig, |store| {
        let authority = SecretAuthority::open(store.clone(), &url, Duration::from_secs(120))
            .await
            .unwrap();
        authority.initialize(&lease).await.unwrap();
        let profiles = CustodyProfiles::new(&authority, &keys);
        // nothing stored yet: generation zero is "no profile", a later one is refused
        assert!(profiles
            .acquire(&session, &lease, &scope, 0, true)
            .await
            .unwrap()
            .is_none());
        assert!(profiles.acquire(&session, &lease, &scope, 1, true).await.is_err());
        // policy: approval, a ceiling inside the run, and durable keys are all required
        assert!(profiles
            .commit(&session, &lease, &scope, 0, expiry, false, &bytes)
            .await
            .is_err());
        assert!(profiles
            .commit(
                &session,
                &lease,
                &scope,
                0,
                expiry + TimeDelta::hours(2),
                true,
                &bytes
            )
            .await
            .is_err());
        assert!(profiles
            .commit(
                &session,
                &lease,
                &scope,
                0,
                now - TimeDelta::hours(2),
                true,
                &bytes
            )
            .await
            .is_err());
        let ephemeral = MemoryArtifactKeys::new().unwrap();
        assert!(CustodyProfiles::new(&authority, &ephemeral)
            .commit(&session, &lease, &scope, 0, expiry, true, &bytes)
            .await
            .is_err());
        assert_eq!(
            Raw(rig).int("SELECT count(*) FROM browser_profiles", &[]).await,
            0
        );
        // generation one registers every secret value in the run registry and stores only ciphertext
        let first = profiles
            .commit(&session, &lease, &scope, 0, expiry, true, &bytes)
            .await
            .unwrap();
        assert_eq!(first.generation, 1);
        let registered = authority.snapshot(&lease).await.unwrap();
        for label in ["cookie", "local", "session"] {
            assert!(registered
                .secrets
                .contains_bytes(canary(label).as_bytes())
                .unwrap());
        }
        let stored = Raw(rig)
            .bytes("SELECT encrypted_bundle FROM browser_profiles", &[])
            .await;
        let opaque = canary("cookie");
        assert!(!stored.windows(opaque.len()).any(|part| part == opaque.as_bytes()));
        assert_eq!(
            Raw(rig)
                .int("SELECT custody_epoch FROM browser_profiles", &[])
                .await,
            registered.version.epoch
        );
        let (inspection, restored) = profiles
            .acquire(&session, &lease, &scope, 1, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inspection.generation, 1);
        assert_eq!(restored.as_bytes(), bytes);
        // the next generation names the exact previous one and never overwrites it
        assert!(profiles
            .commit(&session, &lease, &scope, 0, expiry, true, &bytes)
            .await
            .is_err());
        assert!(profiles.acquire(&session, &lease, &scope, 2, true).await.is_err());
        let second = profiles
            .commit(&session, &lease, &scope, 1, expiry, true, &bytes)
            .await
            .unwrap();
        assert_eq!(second.generation, 2);
        assert_ne!(first.digest, second.digest);
        // every scope field and the producer fence are part of the identity
        let mut wrong = scope.clone();
        wrong.backend_build = Digest::of("build", b"other-build");
        assert!(profiles.acquire(&session, &lease, &wrong, 2, true).await.is_err());
        wrong = scope.clone();
        wrong.egress = Digest::of("egress", b"other-egress");
        assert!(profiles.acquire(&session, &lease, &wrong, 2, true).await.is_err());
        wrong = scope.clone();
        wrong.tenant = TenantId::new();
        assert!(profiles.acquire(&session, &lease, &wrong, 2, true).await.is_err());
        let mut stale = lease.clone();
        stale.fence += 1;
        assert!(profiles.acquire(&session, &stale, &scope, 2, true).await.is_err());
        // a flipped ciphertext byte fails authentication
        let mut tampered = Raw(rig)
            .bytes("SELECT encrypted_bundle FROM browser_profiles", &[])
            .await;
        tampered[30] ^= 1;
        Raw(rig)
            .exec(
                "UPDATE browser_profiles SET encrypted_bundle=$1",
                &[V::Bytes(&tampered)],
            )
            .await;
        assert!(profiles.acquire(&session, &lease, &scope, 2, true).await.is_err());
        // a zero-data-retention run keeps no profile
        Raw(rig).exec("DELETE FROM browser_profiles", &[]).await;
        let zdr = world_with(rig, true).await;
        let zsession = leased_session(rig, &zdr, 0).await;
        let zlease = custody_lease(&zdr, &zsession);
        let zscope = profile_scope(zdr.tenant, &zsession);
        authority.initialize(&zlease).await.unwrap();
        assert!(matches!(
            profiles
                .commit(&zsession, &zlease, &zscope, 0, expiry, true, &bytes)
                .await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert!(profiles
            .acquire(&zsession, &zlease, &zscope, 1, true)
            .await
            .is_err());
    });
}

// ---- worker registry ----------------------------------------------------------------------

fn browser_capabilities() -> BackendCapabilitiesV1 {
    BackendCapabilitiesV1::native_browser(BrowserBuildInfo {
        chromium_version: "registry-fixture-observed-build".into(),
        cdp_revision: "1.3".into(),
        user_agent: "registry-fixture".into(),
        pinned: false,
        launch_profile: LaunchProfile::Standard,
        console_capture: false,
        attached: false,
    })
}

async fn registry_projection_excludes_stale_draining_and_restarted_workers(rig: &Rig) {
    rig.migrate().await;
    let worker = WorkerId::new();
    let required = vec!["native_http".to_owned(), "native_browser".to_owned()];
    let age = Duration::from_secs(90);
    on_store!(rig, |store| {
        store.register_worker(worker, "fixture", "1").await.unwrap();
        store
            .publish_acquisition_capabilities(
                worker,
                &[
                    BackendCapabilitiesV1::native_http("fixture", "1"),
                    browser_capabilities(),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .eligible_acquisition_worker(&required, age)
                .await
                .unwrap()
                .unwrap()
                .worker,
            worker
        );
        // a draining worker takes no new work
        AdminOps::new(&store, "fixture")
            .drain_worker(worker)
            .await
            .unwrap();
        assert!(store
            .eligible_acquisition_worker(&required, age)
            .await
            .unwrap()
            .is_none());
        // a restarted worker publishes nothing until it says what it can do
        store.register_worker(worker, "fixture", "2").await.unwrap();
        assert!(store.live_acquisition_workers(age).await.unwrap().is_empty());
        store
            .publish_acquisition_capabilities(
                worker,
                &[
                    BackendCapabilitiesV1::native_http("fixture", "2"),
                    browser_capabilities(),
                ],
            )
            .await
            .unwrap();
        // a worker whose heartbeat is stale is not eligible
        let stale = rig.database().db_now().await.unwrap() - TimeDelta::seconds(91);
        Raw(rig)
            .exec(
                "UPDATE workers SET last_heartbeat_at = $2 WHERE worker_id=$1",
                &[V::Uuid(worker.0), V::Ts(stale)],
            )
            .await;
        assert!(store
            .eligible_acquisition_worker(&required, age)
            .await
            .unwrap()
            .is_none());
    });
}

// ---- renewal and recovery, against the real volatile registry ------------------------------

/// A run with a live producer lease, an authority over the engine's store and its registry.
struct Fx<B: crawlx_storage::sql::Sql> {
    store: Store<B>,
    authority: SecretAuthority<B>,
    lease: CustodyLease,
    redis: redis::aio::MultiplexedConnection,
    key: String,
    url: String,
    tenant: TenantId,
    run: CrawlRunId,
}

macro_rules! with_fixture {
    ($rig:expr, $ttl:expr, |$f:ident| $body:expr) => {
        with_fixture!($rig, false, $ttl, |$f| $body)
    };
    ($rig:expr, $zdr:expr, $ttl:expr, |$f:ident| $body:expr) => {{
        let Some(url) = redis_url() else { return };
        let world = world_with($rig, $zdr).await;
        let session = leased_session($rig, &world, 0).await;
        let lease = custody_lease(&world, &session);
        let redis = redis_connection(&url).await;
        on_store!($rig, |store| {
            let authority = SecretAuthority::open(store.clone(), &url, $ttl).await.unwrap();
            #[allow(unused_mut)]
            let mut $f = Fx {
                store: store.clone(),
                authority,
                lease: lease.clone(),
                redis: redis.clone(),
                key: registry_key(&world),
                url: url.clone(),
                tenant: world.tenant,
                run: world.run,
            };
            let _ = &world.repos;
            $body
        })
    }};
}

async fn expiry(rig: &Rig) -> DateTime<Utc> {
    Raw(rig)
        .ts("SELECT expires_at FROM run_secret_authority", &[])
        .await
}

async fn receipts(rig: &Rig) -> i64 {
    Raw(rig)
        .int("SELECT count(*) FROM run_secret_authority_renewals", &[])
        .await
}

async fn has_pending_barrier(rig: &Rig) -> bool {
    Raw(rig)
        .int(
            "SELECT count(*) FROM run_secret_authority WHERE pending_renewal_operation IS NOT NULL",
            &[],
        )
        .await
        > 0
}

async fn pending_barrier_is(rig: &Rig, operation: Uuid) -> bool {
    Raw(rig)
        .int(
            "SELECT count(*) FROM run_secret_authority WHERE pending_renewal_operation = $1",
            &[V::Uuid(operation)],
        )
        .await
        == 1
}

/// The later of the durable use deadline and the pending renewal deadline.
async fn effective_deadline(rig: &Rig) -> DateTime<Utc> {
    let greatest = if kind(rig) == BackendKind::Sqlite {
        "max"
    } else {
        "GREATEST"
    };
    Raw(rig)
        .ts(
            &format!("SELECT {greatest}(expires_at, pending_renewal_deadline) FROM run_secret_authority"),
            &[],
        )
        .await
}

/// Reproduce a migrated historical authority, whose physical expiry was its original use
/// deadline, and its durable pre-command renewal boundary.
async fn pending(
    rig: &Rig,
    redis: &mut redis::aio::MultiplexedConnection,
    key: &str,
    lease: &CustodyLease,
    expected: SecretEpoch,
    operation: Uuid,
    (previous, deadline): (DateTime<Utc>, DateTime<Utc>),
) {
    let raw = Raw(rig);
    raw.exec(
        "UPDATE run_secret_authority SET use_window_ms=NULL,retention_ceiling=expires_at",
        &[],
    )
    .await;
    let _: bool = redis::cmd("PEXPIREAT")
        .arg(key)
        .arg(previous.timestamp_millis() - 2000)
        .query_async(redis)
        .await
        .unwrap();
    raw.exec(
        "INSERT INTO run_secret_authority_renewals(tenant_id,run_id,operation,incarnation,secret_epoch,previous_deadline,deadline) VALUES($1,$2,$3,$4,$5,$6,$7)",
        &[
            V::Uuid(lease.tenant.0),
            V::Uuid(lease.run.0),
            V::Uuid(operation),
            V::Uuid(expected.incarnation),
            V::I64(expected.epoch),
            V::Ts(previous),
            V::Ts(deadline),
        ],
    )
    .await;
    raw.exec(
        "UPDATE run_secret_authority SET pending_renewal_operation=$1,pending_renewal_deadline=$2",
        &[V::Uuid(operation), V::Ts(deadline)],
    )
    .await;
}

async fn remote_renew(
    redis: &mut redis::aio::MultiplexedConnection,
    key: &str,
    expected: SecretEpoch,
    operation: Uuid,
    previous: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Vec<String> {
    redis::Script::new(include_str!("../../src/custody_redis.lua"))
        .key(key)
        .arg("renew")
        .arg(expected.incarnation.to_string())
        .arg(expected.epoch)
        .arg(operation.to_string())
        .arg(previous.timestamp_millis() - 2000)
        .arg(deadline.timestamp_millis() - 2000)
        .invoke_async(redis)
        .await
        .unwrap()
}

/// Fault-state fixture for a historical command that executed before its durable completion
/// reply was lost. Production cannot issue this mutation.
async fn historical_applied_receipt(
    redis: &mut redis::aio::MultiplexedConnection,
    key: &str,
    operation: Uuid,
    previous: DateTime<Utc>,
    deadline: DateTime<Utc>,
) {
    let _: () = redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(key)
        .arg("renewal_operation")
        .arg(operation.to_string())
        .arg("renewal_previous")
        .arg(previous.timestamp_millis() - 2000)
        .arg("renewal_deadline")
        .arg(deadline.timestamp_millis() - 2000)
        .ignore()
        .cmd("PEXPIREAT")
        .arg(key)
        .arg(deadline.timestamp_millis() - 2000)
        .ignore()
        .query_async(redis)
        .await
        .unwrap();
}

async fn key_exists(redis: &mut redis::aio::MultiplexedConnection, key: &str) -> bool {
    redis::cmd("EXISTS").arg(key).query_async(redis).await.unwrap()
}

async fn hmget(redis: &mut redis::aio::MultiplexedConnection, key: &str) -> (String, String, String) {
    redis::cmd("HMGET")
        .arg(key)
        .arg(&["operation", "value", "salt"])
        .query_async(redis)
        .await
        .unwrap()
}

#[derive(PartialEq, Debug)]
struct Durable {
    commitment: Vec<u8>,
    last_value_commitment: Vec<u8>,
}

async fn durable(rig: &Rig) -> Durable {
    let raw = Raw(rig);
    Durable {
        commitment: raw
            .bytes("SELECT commitment FROM run_secret_authority", &[])
            .await,
        last_value_commitment: raw
            .bytes("SELECT last_value_commitment FROM run_secret_authority", &[])
            .await,
    }
}

async fn secs_ago(rig: &Rig, seconds: i64) -> DateTime<Utc> {
    rig.database().db_now().await.unwrap() - TimeDelta::seconds(seconds)
}

async fn wait_until(rig: &Rig, instant: DateTime<Utc>) {
    let wait = (instant - rig.database().db_now().await.unwrap())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(wait + Duration::from_millis(25)).await;
}

async fn historical_recovery_preserves_registration_retry_and_exact_absolute_expiry(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let registration = Uuid::now_v7();
        let secret = SecretOr::secret("renewal-private-canary-719".into());
        let registered = f
            .authority
            .register(&f.lease, initial.version, registration, &secret)
            .await
            .unwrap();
        assert_eq!(
            Raw(rig)
                .int(
                    "SELECT count(*) FROM run_secret_authority WHERE last_operation = $1",
                    &[V::Uuid(registration)]
                )
                .await,
            1
        );
        let durable_before = durable(rig).await;
        let volatile_before = hmget(&mut f.redis, &f.key).await;
        let previous = expiry(rig).await;
        let deadline = target(previous, 3600);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            registered.version,
            operation,
            (previous, deadline),
        )
        .await;
        historical_applied_receipt(&mut f.redis, &f.key, operation, previous, deadline).await;
        let renewed = f
            .authority
            .renew_authority(&f.lease, registered.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(renewed.version, registered.version);
        assert!(renewed
            .secrets
            .contains_bytes(b"renewal-private-canary-719")
            .unwrap());
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            deadline.timestamp_millis() - 2000
        );
        assert_eq!(durable_before, durable(rig).await);
        assert_eq!(volatile_before, hmget(&mut f.redis, &f.key).await);
        tokio::time::sleep(Duration::from_millis(25)).await;
        f.authority
            .renew_authority(&f.lease, registered.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(expiry(rig).await, deadline);
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            deadline.timestamp_millis() - 2000
        );
        assert!(f
            .authority
            .renew_authority(&f.lease, registered.version, operation, target(deadline, 1))
            .await
            .is_err());
        let retried = f
            .authority
            .register(&f.lease, initial.version, registration, &secret)
            .await
            .unwrap();
        assert_eq!(retried.version, registered.version);
        // lost completion replies remain recoverable after another registration
        let current = f
            .authority
            .register(
                &f.lease,
                registered.version,
                Uuid::now_v7(),
                &SecretOr::secret("later-secret".into()),
            )
            .await
            .unwrap();
        let recovered = f
            .authority
            .renew_authority(&f.lease, registered.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(recovered.version, current.version);
        // a later historical renewal cannot release an old operation id for reuse
        let next = target(deadline, 1);
        let next_operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            current.version,
            next_operation,
            (deadline, next),
        )
        .await;
        historical_applied_receipt(&mut f.redis, &f.key, next_operation, deadline, next).await;
        f.authority
            .renew_authority(&f.lease, current.version, next_operation, next)
            .await
            .unwrap();
        f.authority
            .renew_authority(&f.lease, registered.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(expiry(rig).await, next);
    });
}

async fn unapplied_pending_barrier_blocks_use_and_cannot_extend_retention(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        assert_eq!(effective_deadline(rig).await, deadline);
        assert!(f.authority.snapshot(&f.lease).await.is_err());
        assert!(f.authority.initialize(&f.lease).await.is_err());
        assert!(f
            .authority
            .register(
                &f.lease,
                initial.version,
                Uuid::now_v7(),
                &SecretOr::secret("blocked".into())
            )
            .await
            .is_err());
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, target(deadline, 1))
            .await
            .is_err());
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
        assert_eq!(expiry(rig).await, previous);
        assert!(pending_barrier_is(rig, operation).await);
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            previous.timestamp_millis() - 2000
        );
    });
}

async fn old_deadline_recovery_requires_surviving_exact_remote_renewal_proof(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(5), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        historical_applied_receipt(&mut f.redis, &f.key, operation, previous, deadline).await;
        wait_until(rig, previous).await;
        assert!(f.authority.snapshot(&f.lease).await.is_err());
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        let recovered = f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .unwrap();
        assert_eq!(recovered.version, initial.version);
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            deadline.timestamp_millis() - 2000
        );
    });
}

async fn old_deadline_without_applied_renewal_never_recreates_lost_registry(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(5), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        wait_until(rig, previous).await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
        assert!(f.authority.initialize(&f.lease).await.is_err());
        assert!(!key_exists(&mut f.redis, &f.key).await);
        assert_eq!(effective_deadline(rig).await, deadline);
    });
}

async fn delayed_remote_command_is_refused_and_corrupt_historical_receipt_denies_recovery(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            remote_renew(
                &mut f.redis,
                &f.key,
                initial.version,
                operation,
                previous,
                deadline
            )
            .await[0],
            "denied"
        );
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            previous.timestamp_millis() - 2000
        );
        historical_applied_receipt(&mut f.redis, &f.key, operation, previous, deadline).await;
        let _: () = redis::cmd("HSET")
            .arg(&f.key)
            .arg("renewal_previous")
            .arg("corrupt")
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
        assert!(f.authority.snapshot(&f.lease).await.is_err());
        let _: () = redis::cmd("DEL")
            .arg(&f.key)
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
        assert!(!key_exists(&mut f.redis, &f.key).await);
    });
}

async fn queued_lifetime_mutation_cannot_execute_after_fence_loss_cancel_or_purge(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        // A queued registry command must refuse independently of whether the database can
        // still be reached; the registry itself cannot read the changed fence or state.
        let lapsed = secs_ago(rig, 1).await;
        Raw(rig)
            .exec("UPDATE crawl_sessions SET lease_expires_at=$1", &[V::Ts(lapsed)])
            .await;
        for stopped in ["cancel", "purge"] {
            let now = rig.database().db_now().await.unwrap();
            let sql = if stopped == "cancel" {
                "UPDATE crawl_runs SET cancel_requested_at=$1,purge_requested_at=NULL"
            } else {
                "UPDATE crawl_runs SET cancel_requested_at=NULL,purge_requested_at=$1"
            };
            Raw(rig).exec(sql, &[V::Ts(now)]).await;
            assert_eq!(
                remote_renew(
                    &mut f.redis,
                    &f.key,
                    initial.version,
                    operation,
                    previous,
                    deadline
                )
                .await,
                vec!["denied".to_string()],
            );
            assert_eq!(
                physical_expiry(&mut f.redis, &f.key).await,
                previous.timestamp_millis() - 2000
            );
            assert!(f
                .authority
                .renew_authority(&f.lease, initial.version, operation, deadline)
                .await
                .is_err());
        }
    });
}

async fn renewal_denies_stale_lease_nonpositive_extension_and_run_ceiling(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let exact = DateTime::from_timestamp_millis(previous.timestamp_millis()).unwrap();
        for deadline in [exact, exact - TimeDelta::seconds(1), target(previous, 86401)] {
            assert!(f
                .authority
                .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
                .await
                .is_err());
        }
        let deadline = target(previous, 60);
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET expires_at=$1",
                &[V::Ts(target(previous, 30))],
            )
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        Raw(rig).exec("UPDATE crawl_runs SET expires_at=NULL", &[]).await;
        let lapsed = secs_ago(rig, 1).await;
        Raw(rig)
            .exec("UPDATE crawl_sessions SET lease_expires_at=$1", &[V::Ts(lapsed)])
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        assert_eq!(expiry(rig).await, previous);
    });
}

/// An authorization record of the run valid until `valid_to`, created by a fresh key.
async fn authorize_run(rig: &Rig, tenant: TenantId, valid_to: DateTime<Utc>) -> Uuid {
    let key = api_key(rig, tenant).await;
    let record = Uuid::now_v7();
    let from = secs_ago(rig, 3600).await;
    Raw(rig)
        .exec(
            "INSERT INTO authorization_records(record_id,tenant_id,body,body_digest,valid_from,valid_to,created_by) VALUES($1,$2,'{}',$3,$4,$5,$6)",
            &[
                V::Uuid(record),
                V::Uuid(tenant.0),
                V::Bytes(&[5; 32]),
                V::Ts(from),
                V::Ts(valid_to),
                V::Uuid(key),
            ],
        )
        .await;
    Raw(rig)
        .exec(
            "UPDATE crawl_runs SET authorization_record_id=$1",
            &[V::Uuid(record)],
        )
        .await;
    record
}

async fn renewal_obeys_authorization_deadline_revocation_cancel_and_purge(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        authorize_run(rig, f.tenant, target(previous, 30)).await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        let allowed = target(previous, 10);
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), allowed)
            .await
            .is_err());
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec("UPDATE authorization_records SET revoked_at=$1", &[V::Ts(now)])
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
            .await
            .is_err());
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET authorization_record_id=NULL,cancel_requested_at=$1",
                &[V::Ts(now)],
            )
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
            .await
            .is_err());
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET cancel_requested_at=NULL,purge_requested_at=$1",
                &[V::Ts(now)],
            )
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(allowed, 1))
            .await
            .is_err());
    });
}

async fn pending_renewal_blocks_real_publication_reads_and_terminal_finalization(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let artifact = artifact_row(rig, &f.lease).await;
        let envelope = envelope(&artifact);
        f.authority
            .publish(&f.lease, initial.version, &artifact, &ciphertext(), &envelope)
            .await
            .unwrap();
        f.authority
            .read_state(artifact.tenant, artifact.run, artifact.id)
            .await
            .unwrap();
        let previous = expiry(rig).await;
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            Uuid::now_v7(),
            (previous, target(previous, 60)),
        )
        .await;
        assert!(f
            .authority
            .publish(&f.lease, initial.version, &artifact, &ciphertext(), &envelope)
            .await
            .is_err());
        assert!(f
            .authority
            .read_state(artifact.tenant, artifact.run, artifact.id)
            .await
            .is_err());
        f.store_status(rig, RunStatus::Completed).await;
        assert!(f.authority.finalize(initial.version).await.is_err());
    });
}

impl<B: crawlx_storage::sql::Sql> Fx<B>
where
    Store<B>: RunRepo,
{
    async fn store_status(&self, _rig: &Rig, status: RunStatus) {
        self.store
            .set_status(self.run, status, Some(TerminalReason::FrontierExhausted))
            .await
            .unwrap();
    }
}

async fn surviving_key_without_exact_renewal_proof_cannot_recover_after_old_deadline(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(5), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            initial.version,
            operation,
            (previous, deadline),
        )
        .await;
        // adversarial surviving backend: a long TTL alone is not renewal proof
        let _: bool = redis::cmd("PEXPIREAT")
            .arg(&f.key)
            .arg(deadline.timestamp_millis() - 2000)
            .query_async(&mut f.redis)
            .await
            .unwrap();
        wait_until(rig, previous).await;
        assert!(key_exists(&mut f.redis, &f.key).await);
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, operation, deadline)
            .await
            .is_err());
        assert_eq!(expiry(rig).await, previous);
    });
}

async fn changed_secret_set_never_receives_requested_renewal(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let registered = f
            .authority
            .register(
                &f.lease,
                initial.version,
                Uuid::now_v7(),
                &SecretOr::secret("first-secret".into()),
            )
            .await
            .unwrap();
        let previous = expiry(rig).await;
        let deadline = target(previous, 60);
        let operation = Uuid::now_v7();
        pending(
            rig,
            &mut f.redis,
            &f.key,
            &f.lease,
            registered.version,
            operation,
            (previous, deadline),
        )
        .await;
        // same lengths pass structural validation, but not the complete commitment
        let _: i64 = redis::cmd("HSET")
            .arg(&f.key)
            .arg("s1")
            .arg("other-secret")
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(f
            .authority
            .renew_authority(&f.lease, registered.version, operation, deadline)
            .await
            .is_err());
        assert_eq!(
            physical_expiry(&mut f.redis, &f.key).await,
            previous.timestamp_millis() - 2000
        );
        let metadata: bool = redis::cmd("HEXISTS")
            .arg(&f.key)
            .arg("renewal_operation")
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(!metadata);
    });
}

async fn renewal_rejects_requests_larger_than_the_configured_use_window(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET created_at=$1,deadline_at=$2,expires_at=$3 WHERE run_id=$4",
                &[
                    V::Ts(now - TimeDelta::hours(1)),
                    V::Ts(now + TimeDelta::hours(25)),
                    V::Ts(now + TimeDelta::days(3)),
                    V::Uuid(f.run.0),
                ],
            )
            .await;
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        let deadline = target(now, 24 * 60 * 60);
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .is_err());
        assert!(physical_expiry(&mut f.redis, &f.key).await < deadline.timestamp_millis() - 2000);
        assert!(!has_pending_barrier(rig).await);
    });
}

async fn overlong_absolute_window_is_rejected_before_pending_barrier(rig: &Rig) {
    with_fixture!(rig, crawlx_storage::custody::MAX_AUTHORITY_TTL, |f| {
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE crawl_runs SET deadline_at=$1,expires_at=$1 WHERE run_id=$2",
                &[V::Ts(now + TimeDelta::days(3)), V::Uuid(f.run.0)],
            )
            .await;
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let previous = expiry(rig).await;
        assert!(f
            .authority
            .renew_authority(
                &f.lease,
                initial.version,
                Uuid::now_v7(),
                target(previous, 60 * 60)
            )
            .await
            .is_err());
        assert!(!has_pending_barrier(rig).await);
        assert_eq!(expiry(rig).await, previous);
    });
}

async fn expired_use_authority_never_resurrects_even_with_surviving_redis_values(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        let physical = physical_expiry(&mut f.redis, &f.key).await;
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, -1))],
            )
            .await;
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(now, 30))
            .await
            .is_err());
        assert!(f.authority.initialize(&f.lease).await.is_err());
        assert!(f.authority.snapshot(&f.lease).await.is_err());
        assert_eq!(physical_expiry(&mut f.redis, &f.key).await, physical);
        assert_eq!(receipts(rig).await, 0);
    });
}

async fn renewal_registration_race_requires_current_epoch_without_losing_retry_identity(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, 10))],
            )
            .await;
        let registered = f
            .authority
            .register(
                &f.lease,
                initial.version,
                Uuid::now_v7(),
                &SecretOr::secret("registration-race-value".into()),
            )
            .await
            .unwrap();
        let deadline = target(now, 50);
        let error = f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline)
            .await
            .unwrap_err();
        assert!(is_stale_epoch(&error), "{error:?}");
        let renewed = f
            .authority
            .renew_authority(&f.lease, registered.version, Uuid::now_v7(), deadline)
            .await
            .unwrap();
        assert_eq!(renewed.version, registered.version);
        let physical = physical_expiry(&mut f.redis, &f.key).await;
        Raw(rig)
            .exec("UPDATE crawl_sessions SET fencing_token=fencing_token+1", &[])
            .await;
        assert!(matches!(
            f.authority
                .renew_authority(&f.lease, registered.version, Uuid::now_v7(), target(deadline, 1))
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(physical_expiry(&mut f.redis, &f.key).await, physical);
    });
}

async fn lost_redis_registry_never_rebuilds_during_a_durable_renewal(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, 10))],
            )
            .await;
        let _: i64 = redis::cmd("DEL")
            .arg(&f.key)
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(f
            .authority
            .renew_authority(&f.lease, initial.version, Uuid::now_v7(), target(now, 50))
            .await
            .is_err());
        assert!(!key_exists(&mut f.redis, &f.key).await);
        assert_eq!(expiry(rig).await, target(now, 10));
    });
}

async fn paused_redis_response_cannot_renew_a_cancelled_producer_or_change_physical_expiry(rig: &Rig) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        let previous = target(now, 10);
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(previous)],
            )
            .await;
        let physical = physical_expiry(&mut f.redis, &f.key).await;
        let source = url::Url::parse(&f.url).unwrap();
        let host = source.host_str().unwrap().to_owned();
        let port = source.port().unwrap_or(6379);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut endpoint = source;
        endpoint.set_host(Some("127.0.0.1")).unwrap();
        endpoint.set_port(Some(address.port())).unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let proxy = {
            let armed = Arc::clone(&armed);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let (client, _) = listener.accept().await.unwrap();
                let server = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .unwrap();
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let requests = tokio::io::copy(&mut client_read, &mut server_write);
                let responses = async {
                    let mut buffer = [0u8; 8192];
                    loop {
                        let count = server_read.read(&mut buffer).await?;
                        if count == 0 {
                            return Ok::<(), std::io::Error>(());
                        }
                        if armed.swap(false, Ordering::SeqCst) {
                            entered.add_permits(1);
                            release.acquire().await.unwrap().forget();
                        }
                        client_write.write_all(&buffer[..count]).await?;
                    }
                };
                let _ = tokio::try_join!(requests, responses);
            })
        };
        let authority = SecretAuthority::open(f.store.clone(), endpoint.as_str(), Duration::from_secs(60))
            .await
            .unwrap();
        let token = CancellationToken::new();
        let lease = f.lease.clone().with_cancellation(token.clone());
        armed.store(true, Ordering::SeqCst);
        let renewal = tokio::spawn(async move {
            authority
                .renew_authority(&lease, initial.version, Uuid::now_v7(), target(now, 50))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        token.cancel();
        release.add_permits(1);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), renewal)
                .await
                .unwrap()
                .unwrap(),
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(expiry(rig).await, previous);
        assert_eq!(physical_expiry(&mut f.redis, &f.key).await, physical);
        assert_eq!(receipts(rig).await, 0);
        proxy.abort();
        let _ = proxy.await;
    });
}

async fn original_retention_above_one_day_requires_both_explicit_permissions_and_operator_ceiling(rig: &Rig) {
    for (explicit_retention, explicit_authorization, maximum_hours, expected_hours) in [
        (false, false, 72_u64, 24_i64),
        (true, false, 72, 24),
        (false, true, 72, 24),
        (true, true, 72, 72),
        (true, true, 30, 30),
    ] {
        let rig = &fresh(rig).await;
        with_fixture!(rig, Duration::from_secs(60), |f| {
            let before = rig.database().db_now().await.unwrap();
            let permission = before + TimeDelta::hours(96);
            if explicit_retention {
                Raw(rig)
                    .exec(
                        "UPDATE crawl_runs SET expires_at=$1,deadline_at=NULL",
                        &[V::Ts(permission)],
                    )
                    .await;
            } else {
                Raw(rig)
                    .exec("UPDATE crawl_runs SET expires_at=NULL,deadline_at=NULL", &[])
                    .await;
            }
            if explicit_authorization {
                authorize_run(rig, f.tenant, permission).await;
            }
            let authority = SecretAuthority::open_with_policy(
                f.store.clone(),
                &f.url,
                Duration::from_secs(60),
                Duration::from_secs(maximum_hours * 3600),
            )
            .await
            .unwrap();
            authority.initialize(&f.lease).await.unwrap();
            let after = rig.database().db_now().await.unwrap();
            let ceiling = Raw(rig)
                .ts("SELECT retention_ceiling FROM run_secret_authority", &[])
                .await;
            let earliest = target(before + TimeDelta::hours(expected_hours), 0);
            assert!(ceiling >= earliest);
            assert!(ceiling <= after + TimeDelta::hours(expected_hours));
            assert_eq!(
                physical_expiry(&mut f.redis, &f.key).await,
                ceiling.timestamp_millis() - 2000
            );
        });
    }
}

/// A second, empty database of the same engine for a case that needs several independent runs.
async fn fresh(rig: &Rig) -> Rig {
    match rig.engine() {
        crawlx_storage::testkit::rig::Engine::Sqlite => Rig::sqlite().await,
        crawlx_storage::testkit::rig::Engine::MariaDb => Rig::mariadb().await.unwrap(),
        _ => Rig::postgres().await.unwrap(),
    }
}

async fn terminal_retained_projector_uses_only_surviving_original_secret_values(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let secret = SecretOr::secret(format!("retained-projector-{}", Uuid::now_v7()));
        let current = f
            .authority
            .register(&f.lease, initial.version, Uuid::now_v7(), &secret)
            .await
            .unwrap();
        assert!(f
            .authority
            .retained_snapshot(f.tenant, f.run, initial.version)
            .await
            .is_err());
        f.store_status(rig, RunStatus::Completed).await;
        f.authority.finalize(current.version).await.unwrap();
        let snapshot = f
            .authority
            .retained_snapshot(f.tenant, f.run, current.version)
            .await
            .unwrap();
        assert_eq!(snapshot.version, current.version);
        assert!(snapshot
            .secrets
            .contains_bytes(secret.expose().as_bytes())
            .unwrap());
        let physical = physical_expiry(&mut f.redis, &f.key).await;
        assert!(f
            .authority
            .retained_snapshot(TenantId::new(), f.run, current.version)
            .await
            .is_err());
        assert_eq!(physical_expiry(&mut f.redis, &f.key).await, physical);
        let _: i64 = redis::cmd("DEL")
            .arg(&f.key)
            .query_async(&mut f.redis)
            .await
            .unwrap();
        assert!(f
            .authority
            .retained_snapshot(f.tenant, f.run, current.version)
            .await
            .is_err());
        assert!(!key_exists(&mut f.redis, &f.key).await);
    });
}

async fn retained_source_projector_refuses_zdr_even_with_live_secret_values(rig: &Rig) {
    with_fixture!(rig, true, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        assert!(f
            .authority
            .retained_snapshot(f.tenant, f.run, initial.version)
            .await
            .is_err());
    });
}

async fn competing_live_renewals_request_refresh_instead_of_failing_valid_producer_work(rig: &Rig) {
    with_fixture!(rig, Duration::from_secs(60), |f| {
        let initial = f.authority.initialize(&f.lease).await.unwrap();
        let now = rig.database().db_now().await.unwrap();
        Raw(rig)
            .exec(
                "UPDATE run_secret_authority SET expires_at=$1",
                &[V::Ts(target(now, 10))],
            )
            .await;
        let peer = SecretAuthority::open(f.store.clone(), &f.url, Duration::from_secs(60))
            .await
            .unwrap();
        let deadline = target(now, 50);
        let physical = physical_expiry(&mut f.redis, &f.key).await;
        let (first, second) = tokio::join!(
            f.authority
                .renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline),
            peer.renew_authority(&f.lease, initial.version, Uuid::now_v7(), deadline),
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let refused = first.err().or_else(|| second.err()).unwrap();
        assert!(is_stale_epoch(&refused), "{refused:?}");
        assert_eq!(expiry(rig).await, deadline);
        assert_eq!(physical_expiry(&mut f.redis, &f.key).await, physical);
        assert_eq!(receipts(rig).await, 1);
    });
}

// ---- terminal feed finalization as a custody producer -----------------------------------

const FEED_BODY: &[u8] = b"[{\"n\":1}]\n";
const FEED_TTL: Duration = Duration::from_secs(60);

/// A sealed-writing artifact store over `store`: real file-backed envelopes, the shared secret
/// registry, and plaintext writes refused.
macro_rules! sealed_store {
    ($store:expr, $url:expr, $keys:expr) => {{
        use crawlx_storage::artifact_key_crypto::{ArtifactKeys, FileArtifactKeys};
        use crawlx_storage::{CustodyWrites, DbArtifactCustody, MemBlobs, ObjectArtifactStore};
        use std::os::unix::fs::PermissionsExt as _;
        let path = $keys.path().join("artifact.key");
        std::fs::write(&path, format!("{}\n", "5a".repeat(32))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = path.to_string_lossy().into_owned();
        let keys: Arc<dyn ArtifactKeys> = Arc::new(
            FileArtifactKeys::from_lookup(&|name| (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| path.clone()))
                .unwrap()
                .unwrap(),
        );
        let authority = SecretAuthority::open($store.clone(), $url, Duration::from_secs(120))
            .await
            .unwrap();
        ObjectArtifactStore::new(
            MemBlobs::default(),
            Arc::new($store.clone()),
            Arc::new(SystemClock),
        )
        .with_index(Arc::new($store.clone()))
        .with_custody(
            Arc::new(DbArtifactCustody::new(authority)),
            keys,
            CustodyWrites::Required,
        )
    }};
}

async fn finalizer_sql(rig: &Rig, run: CrawlRunId, statement: &str) {
    assert_eq!(Raw(rig).exec(statement, &[V::Uuid(run.0)]).await, 1);
}

async fn feed_finalizer_claim_seals_terminal_output_only_while_it_owns_the_unfinished_finalization(
    rig: &Rig,
) {
    use crawlx_core::custody::with_producer;
    use crawlx_core::orchestration::RequestCommitRepo as _;
    use crawlx_core::repo::ArtifactStore as _;
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let keys = tempfile::tempdir().unwrap();
    on_store!(rig, |store| {
        let artifacts = sealed_store!(store, &url, keys);
        let write = |lease: &CustodyLease| {
            let lease = lease.clone();
            let artifacts = &artifacts;
            let run = world.run;
            async move {
                with_producer(
                    lease,
                    artifacts.put(run, Sensitivity::Content, "application/json", FEED_BODY),
                )
                .await
            }
        };
        let (first_worker, second_worker) = (WorkerId::new(), WorkerId::new());
        // Nothing to finalize yet: no claim exists to hold.
        let early = store
            .claim_feed_finalizer(world.run, first_worker, FEED_TTL)
            .await;
        assert!(matches!(early, Err(StoreError::LeaseLost)), "{early:?}");
        store
            .begin_feed_finalization(world.run, Some(TerminalReason::FrontierExhausted))
            .await
            .unwrap();

        let first = store
            .claim_feed_finalizer(world.run, first_worker, FEED_TTL)
            .await
            .unwrap();
        let reference = write(&first).await.unwrap();
        assert_eq!(artifacts.get(&reference).await.unwrap(), FEED_BODY);
        // No producer at all is still refused, and one claim excludes every other claimant.
        let bare = artifacts
            .put(world.run, Sensitivity::Content, "application/json", FEED_BODY)
            .await;
        assert!(matches!(bare, Err(StoreError::Unavailable(_))), "{bare:?}");
        let busy = store
            .claim_feed_finalizer(world.run, second_worker, FEED_TTL)
            .await;
        assert!(matches!(busy, Err(StoreError::Conflict(_))), "{busy:?}");
        // A forged fence, owner or claim id is no authority.
        let CustodySource::FeedFinalization(source) = first.source else {
            panic!("unexpected producer source {:?}", first.source);
        };
        for forged in [
            CustodyLease::for_feed_finalization(
                world.tenant,
                world.run,
                source,
                first_worker,
                first.fence + 1,
            ),
            CustodyLease::for_feed_finalization(world.tenant, world.run, source, second_worker, first.fence),
            CustodyLease::for_feed_finalization(
                world.tenant,
                world.run,
                Uuid::now_v7(),
                first_worker,
                first.fence,
            ),
        ] {
            let refused = write(&forged).await;
            assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        }
        // Finalization exists because the run is cancelled, so a cancel request does not revoke it.
        let cancelled = format!(
            "UPDATE crawl_runs SET cancel_requested_at={} WHERE run_id=$1",
            rig_now_sql(rig)
        );
        finalizer_sql(rig, world.run, &cancelled).await;
        write(&first).await.unwrap();
        store.renew_feed_finalizer(&first, FEED_TTL).await.unwrap();

        // Release hands over at once; the old fence is dead and the new one is higher.
        store.release_feed_finalizer(&first).await.unwrap();
        let refused = write(&first).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        let second = store
            .claim_feed_finalizer(world.run, second_worker, FEED_TTL)
            .await
            .unwrap();
        assert!(second.fence > first.fence);
        let renewed = store.renew_feed_finalizer(&first, FEED_TTL).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        write(&second).await.unwrap();

        // An expired claim writes nothing and renews nothing; takeover raises the fence again.
        let expire = format!(
            "UPDATE crawl_runs SET feed_finalizer_expires_at={} WHERE run_id=$1",
            rig_past_sql(rig)
        );
        finalizer_sql(rig, world.run, &expire).await;
        let refused = write(&second).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        let renewed = store.renew_feed_finalizer(&second, FEED_TTL).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        let third = store
            .claim_feed_finalizer(world.run, first_worker, FEED_TTL)
            .await
            .unwrap();
        assert!(third.fence > second.fence);
        write(&third).await.unwrap();

        // A purge request revokes it like any other producer.
        let purge = format!(
            "UPDATE crawl_runs SET purge_requested_at={} WHERE run_id=$1",
            rig_now_sql(rig)
        );
        finalizer_sql(rig, world.run, &purge).await;
        let refused = write(&third).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        finalizer_sql(
            rig,
            world.run,
            "UPDATE crawl_runs SET purge_requested_at=NULL WHERE run_id=$1",
        )
        .await;
        write(&third).await.unwrap();

        // Completing the finalization ends the claim for good.
        store
            .finalize_run_feeds(
                world.run,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[],
            )
            .await
            .unwrap();
        let refused = write(&third).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        let renewed = store.renew_feed_finalizer(&third, FEED_TTL).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        let again = store
            .claim_feed_finalizer(world.run, second_worker, FEED_TTL)
            .await;
        assert!(matches!(again, Err(StoreError::LeaseLost)), "{again:?}");
    });
}

async fn recovery_seals_the_feeds_of_a_run_that_already_ended_under_the_claim(rig: &Rig) {
    use crawlx_core::custody::with_producer;
    use crawlx_core::orchestration::RequestCommitRepo as _;
    use crawlx_core::repo::ArtifactStore as _;
    let Some(url) = redis_url() else { return };
    let world = world(rig).await;
    let keys = tempfile::tempdir().unwrap();
    on_store!(rig, |store| {
        let artifacts = sealed_store!(store, &url, keys);
        world
            .repos
            .runs
            .set_status(
                world.run,
                RunStatus::Completed,
                Some(TerminalReason::FrontierExhausted),
            )
            .await
            .unwrap();
        let reason = store.begin_feed_finalization(world.run, None).await.unwrap();
        assert_eq!(reason, Some(TerminalReason::FrontierExhausted));
        let lease = store
            .claim_feed_finalizer(world.run, WorkerId::new(), FEED_TTL)
            .await
            .unwrap();
        let reference = with_producer(
            lease.clone(),
            artifacts.put(world.run, Sensitivity::Content, "application/json", FEED_BODY),
        )
        .await
        .unwrap();
        assert_eq!(artifacts.get(&reference).await.unwrap(), FEED_BODY);
        // The terminal run still refuses every other producer kind.
        let url_lease = CustodyLease::for_url(lease.tenant, world.run, 7, WorkerId::new(), 1);
        let refused = with_producer(
            url_lease,
            artifacts.put(world.run, Sensitivity::Content, "application/json", FEED_BODY),
        )
        .await;
        assert!(
            matches!(refused, Err(StoreError::RetentionDenied(_))),
            "{refused:?}"
        );
    });
}

fn rig_now_sql(rig: &Rig) -> &'static str {
    match kind(rig) {
        BackendKind::Postgres => "now()",
        BackendKind::MariaDb => "NOW(6)",
        _ => "CAST(unixepoch('subsec') * 1000000 AS INTEGER)",
    }
}

fn rig_past_sql(rig: &Rig) -> &'static str {
    match kind(rig) {
        BackendKind::Postgres => "(now() - interval '1 second')",
        BackendKind::MariaDb => "(NOW(6) - INTERVAL 1 SECOND)",
        _ => "(CAST(unixepoch('subsec') * 1000000 AS INTEGER) - 1000000)",
    }
}
