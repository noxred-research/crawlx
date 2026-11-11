//! Runtime enforcement of an authorization record.
//!
//! Admission checks a record once. A run lives for hours, so the worker keeps checking it:
//! [`AuthorizationGuard`] holds the record a run was admitted under, re-reads its lifecycle state
//! from an [`AuthorizationSource`] (the stored record in PostgreSQL, a test double elsewhere) at
//! most once per `recheck_interval` ([`WorkerConfig::authorization_recheck`]) and answers
//! [`AuthorizationGuard::check_now`] with the record's window and revocation. A record that is
//! revoked, expired, not yet valid or gone ends the run: the guard trips once (sticky), appends the
//! `authorization.revoked` event, cancels the run's token so in-flight sessions and the URL plane
//! stop at their next boundary, and every later check reports the same [`AuthorizationStop`]. The
//! run's terminal reason is then [`TerminalReason::AuthorizationRevoked`](crawlx_core::counters::TerminalReason).
//!
//! The record's *target* (origins, URL prefixes, excluded paths) is immutable, so the scope the
//! egress and scope policies enforce is taken from the record held at admission
//! ([`AuthorizationGuard::scope`]); only revocation, expiry and removal change while the run
//! lives.
//!
//! A referenced record without a stored, injected or supplied-file [`AuthorizationSource`] is
//! refused. Memory HEAD response disclosure retains the exact source used at admission and the
//! original body binding independently of the guard, so it survives run completion without
//! retaining the event repository. Every disclosure re-reads authority without using the
//! `recheck_interval` cache; missing records, failed reads, changed bodies and lost admission
//! verification deny access.

use crate::error::WorkerError;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::repo::EventRepo;
use crawlx_core::time::Timestamp;
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, StoreError, TenantId};
use crawlx_policy::{AuthorizationRecord, AuthzFailure, RecordScope};
use crawlx_safety::RecordNarrowing;
use crawlx_scheduler::HEARTBEAT_INTERVAL;
use crawlx_storage::{memory::HeadResponseAuthorizer, Pg};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Default for [`WorkerConfig::authorization_recheck`](crate::WorkerConfig): how long a worker
/// trusts the record state it last read ("within the cache TTL").
pub const DEFAULT_RECHECK_INTERVAL: Duration = Duration::from_secs(60);

/// What `record` narrows in the safety kernel: its `permittedRiskClasses` and `approvalRequired`.
#[must_use]
pub fn narrowing_of(record: &AuthorizationRecord) -> RecordNarrowing {
    RecordNarrowing::new(
        record.permitted_risk_classes.iter().copied(),
        record.approval_required.iter().copied(),
    )
}

/// Where a running worker reads the current state of a record.
#[async_trait]
pub trait AuthorizationSource: Send + Sync {
    /// The record `record` as it is stored now, lifecycle state (`revokedAt`, `revokedReason`,
    /// `verifiedAt`) included; `None` when no such record exists any more.
    ///
    /// # Errors
    /// [`WorkerError::Config`] when the stored record cannot be read as an
    /// [`AuthorizationRecord`] (the run is refused); any other error is a failed read, which the
    /// guard retries and does not treat as revocation.
    async fn fetch(&self, record: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError>;
}

/// The record store of a PostgreSQL deployment: `authorization_records`, with the lifecycle
/// columns merged into the body ([`Pg::authorization_record_body`]).
#[derive(Clone)]
pub struct PgAuthorizationSource {
    pg: Pg,
}

impl PgAuthorizationSource {
    /// A source reading through `pg`.
    #[must_use]
    pub const fn new(pg: Pg) -> Self {
        Self { pg }
    }
}

#[async_trait]
impl AuthorizationSource for PgAuthorizationSource {
    async fn fetch(&self, record: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        let Some(body) = self.pg.authorization_record_body(record).await? else {
            return Ok(None);
        };
        serde_json::from_value(body)
            .map(Some)
            .map_err(|e| WorkerError::Config(format!("authorization record {record} is unreadable: {e}")))
    }
}

/// An in-memory record store whose records a test (or an embedding program) can change while a
/// run is in flight: revoke one, move its window, remove it. Clones share the same records.
#[derive(Clone, Default)]
pub struct StaticAuthorizationSource {
    records: Arc<Mutex<BTreeMap<AuthorizationRecordId, AuthorizationRecord>>>,
}

impl StaticAuthorizationSource {
    /// A source holding `record`.
    #[must_use]
    pub fn new(record: AuthorizationRecord) -> Self {
        let source = Self::default();
        source.insert(record);
        source
    }

    /// Store `record`, replacing a record with the same id.
    pub fn insert(&self, record: AuthorizationRecord) {
        self.records.lock().insert(record.id, record);
    }

    /// Remove the record `id`; the next read finds it missing.
    pub fn remove(&self, id: AuthorizationRecordId) {
        self.records.lock().remove(&id);
    }

    /// Revoke the record `id` as of `at` with `reason`. Returns `false` when there is no such record.
    #[must_use = "false means there is no such record"]
    pub fn revoke(&self, id: AuthorizationRecordId, at: Timestamp, reason: &str) -> bool {
        self.update(id, |r| {
            r.revoked_at = Some(at);
            r.revoked_reason = Some(reason.to_owned());
        })
    }

    /// Apply `change` to the record `id`. Returns `false` when there is no such record.
    pub fn update(&self, id: AuthorizationRecordId, change: impl FnOnce(&mut AuthorizationRecord)) -> bool {
        match self.records.lock().get_mut(&id) {
            Some(record) => {
                change(record);
                true
            }
            None => false,
        }
    }
}

#[async_trait]
impl AuthorizationSource for StaticAuthorizationSource {
    async fn fetch(&self, record: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        Ok(self.records.lock().get(&record).cloned())
    }
}

/// Why a run lost its authorization.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationStop {
    /// The record is revoked, expired or not yet valid.
    #[error("authorization record {record}: {failure}")]
    Inactive {
        /// The record.
        record: AuthorizationRecordId,
        /// What is wrong with it.
        failure: AuthzFailure,
    },
    /// The record is no longer stored.
    #[error("authorization record {0} is not stored")]
    Missing(AuthorizationRecordId),
    /// The stored record cannot be read.
    #[error("authorization record {record} is unreadable: {detail}")]
    Unreadable {
        /// The record.
        record: AuthorizationRecordId,
        /// What the reader reported.
        detail: String,
    },
    /// The record the run was given is not the one its request names.
    #[error("authorization record {given} is not the record {referenced} the request names")]
    Mismatch {
        /// The record handed to the worker.
        given: AuthorizationRecordId,
        /// The record `safety.authorizationRecordRef` names.
        referenced: AuthorizationRecordId,
    },
}

impl AuthorizationStop {
    /// Stable machine-readable reason, the `reason` of the `authorization.revoked` event.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Inactive { failure, .. } => match failure {
                AuthzFailure::Revoked => "revoked",
                AuthzFailure::Expired => "expired",
                AuthzFailure::NotYetValid => "not_yet_valid",
                _ => "invalid",
            },
            Self::Missing(_) => "missing",
            Self::Unreadable { .. } => "unreadable",
            Self::Mismatch { .. } => "mismatch",
        }
    }

    /// The record the stop is about.
    #[must_use]
    pub const fn record(&self) -> AuthorizationRecordId {
        match self {
            Self::Inactive { record, .. } | Self::Missing(record) | Self::Unreadable { record, .. } => {
                *record
            }
            Self::Mismatch { given, .. } => *given,
        }
    }
}

/// What the record state of one run is, between re-reads.
struct State {
    /// The record as last read; its window and revocation answer the checks between re-reads.
    latest: AuthorizationRecord,
    /// When `latest` was last read from the source; `None` forces the next check to read.
    read_at: Option<Instant>,
    /// Set once, never cleared.
    stop: Option<AuthorizationStop>,
}

/// The per-run authorization guard: window, revocation and target of the run's record.
///
/// Cheap to share (`Arc`) between the lease loop, the URL plane and every session of a run.
pub struct AuthorizationGuard {
    run: CrawlRunId,
    record: AuthorizationRecord,
    scope: RecordScope,
    source: Arc<dyn AuthorizationSource>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn EventRepo>,
    recheck: Duration,
    state: Mutex<State>,
    /// Serializes re-reads so a burst of checks costs one read.
    refresh: tokio::sync::Mutex<()>,
    /// Cancelled when the guard trips.
    stopped: CancellationToken,
    /// Also cancelled when the guard trips: the run's own token, which the URL plane and the
    /// sessions already honour ([`Self::cancels`]).
    cancel_run: OnceLock<CancellationToken>,
}

/// Store-owned disclosure requirements, without the guard's event repository or cached state.
struct LocalHeadResponseAuthorizer {
    run: CrawlRunId,
    tenant: TenantId,
    record: AuthorizationRecordId,
    body_digest: Digest,
    require_verified: bool,
    source: Arc<dyn AuthorizationSource>,
    clock: Arc<dyn Clock>,
}

#[async_trait]
impl HeadResponseAuthorizer for LocalHeadResponseAuthorizer {
    async fn authorize(
        &self,
        run: CrawlRunId,
        tenant: TenantId,
        record: AuthorizationRecordId,
        _now: Timestamp,
    ) -> Result<(), StoreError> {
        if run != self.run || tenant != self.tenant || record != self.record {
            return Err(StoreError::AccessDenied(
                "HEAD response authorization binding does not match the admitted run".to_owned(),
            ));
        }
        let fresh = self
            .source
            .fetch(record)
            .await
            .map_err(|error| match error {
                WorkerError::Store(error) => error,
                error => StoreError::Database {
                    source: Box::new(error),
                    retryable: false,
                },
            })?
            .ok_or_else(|| {
                StoreError::AccessDenied("HEAD response authorization record is missing".to_owned())
            })?;
        if fresh.id != record
            || fresh.tenant != tenant
            || fresh.check_active(self.clock.now()).is_err()
            || (self.require_verified && fresh.verified_at.is_none())
        {
            return Err(StoreError::AccessDenied(
                "HEAD response authorization is no longer active for the admitted tenant".to_owned(),
            ));
        }
        let digest = fresh
            .body_digest()
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if digest != self.body_digest {
            return Err(StoreError::AccessDenied(
                "HEAD response authorization body changed since admission".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AuthorizationGuard {
    /// Admit `run` under the record `given`, or under the stored record `referenced` when the
    /// caller has none in hand. The record is read through `source` (so a revocation that already
    /// happened is seen) and checked at `clock.now()`. A refusal is recorded as the run's
    /// `authorization.revoked` event (with `"stage": "admission"`).
    ///
    /// `recheck` is how long a read stays trusted ([`DEFAULT_RECHECK_INTERVAL`]).
    ///
    /// # Errors
    /// [`WorkerError::Authorization`] when the record is missing, unreadable, revoked, expired,
    /// not yet valid or not the record the request names; a store failure otherwise.
    pub async fn admit(
        run: CrawlRunId,
        given: Option<AuthorizationRecord>,
        referenced: Option<AuthorizationRecordId>,
        source: Arc<dyn AuthorizationSource>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn EventRepo>,
        recheck: Duration,
    ) -> Result<Arc<Self>, WorkerError> {
        let admitted = Self::read_for_admission(given, referenced, source.as_ref(), clock.as_ref()).await;
        let (record, fresh) = match admitted {
            Ok(read) => read,
            Err(WorkerError::Authorization(stop)) => {
                tracing::warn!(run = %run, record = %stop.record(), reason = stop.reason(), "run refused: authorization");
                let payload = serde_json::json!({
                    "recordId": stop.record(),
                    "reason": stop.reason(),
                    "message": stop.to_string(),
                    "stage": "admission",
                });
                if let Err(e) = events.append(run, "authorization.revoked", payload).await {
                    tracing::warn!(run = %run, error = %e, "authorization.revoked event not recorded");
                }
                return Err(WorkerError::Authorization(stop));
            }
            Err(e) => return Err(e),
        };
        Ok(Arc::new(Self {
            run,
            scope: record.scope(),
            record,
            source,
            clock,
            events,
            recheck,
            state: Mutex::new(State {
                latest: fresh,
                read_at: Some(Instant::now()),
                stop: None,
            }),
            refresh: tokio::sync::Mutex::new(()),
            stopped: CancellationToken::new(),
            cancel_run: OnceLock::new(),
        }))
    }

    /// The record the run is bounded by and the stored state of it, when the record is usable now.
    async fn read_for_admission(
        given: Option<AuthorizationRecord>,
        referenced: Option<AuthorizationRecordId>,
        source: &dyn AuthorizationSource,
        clock: &dyn Clock,
    ) -> Result<(AuthorizationRecord, AuthorizationRecord), WorkerError> {
        let id = match (&given, referenced) {
            (Some(record), Some(referenced)) if record.id != referenced => {
                return Err(AuthorizationStop::Mismatch {
                    given: record.id,
                    referenced,
                }
                .into());
            }
            (Some(record), _) => record.id,
            (None, Some(referenced)) => referenced,
            (None, None) => {
                return Err(WorkerError::Config(
                    "an authorization guard needs a record or a record reference".to_owned(),
                ));
            }
        };
        let fresh = match source.fetch(id).await {
            Ok(Some(fresh)) => fresh,
            Ok(None) => return Err(AuthorizationStop::Missing(id).into()),
            Err(WorkerError::Config(detail)) => {
                return Err(AuthorizationStop::Unreadable { record: id, detail }.into());
            }
            Err(e) => return Err(e),
        };
        if let Err(failure) = fresh.check_active(clock.now()) {
            return Err(AuthorizationStop::Inactive { record: id, failure }.into());
        }
        // The source is authoritative for verification and the immutable admitted body.
        // A caller-supplied copy only selects the record; it cannot manufacture verification.
        let record = fresh.clone();
        Ok((record, fresh))
    }

    /// Cancel `token` (the run's cancellation token) when the guard trips, or now when it has.
    /// The first token bound wins.
    pub fn cancels(&self, token: CancellationToken) {
        if self.is_stopped() {
            token.cancel();
        }
        let _ = self.cancel_run.set(token);
    }

    /// The record the run was admitted under.
    #[must_use]
    pub const fn record(&self) -> &AuthorizationRecord {
        &self.record
    }

    /// Retain only live authority and immutable admission requirements for memory HEAD access.
    pub(crate) fn head_response_authorizer(&self) -> Result<Arc<dyn HeadResponseAuthorizer>, WorkerError> {
        Ok(Arc::new(LocalHeadResponseAuthorizer {
            run: self.run,
            tenant: self.record.tenant,
            record: self.record.id,
            body_digest: self.record.body_digest()?,
            require_verified: self.record.verified_at.is_some(),
            source: Arc::clone(&self.source),
            clock: Arc::clone(&self.clock),
        }))
    }

    /// Require the admitted record to belong to the run's tenant.
    ///
    /// # Errors
    /// [`AuthorizationStop::Inactive`] for a record owned by another tenant.
    pub fn check_tenant(&self, tenant: crawlx_core::TenantId) -> Result<(), AuthorizationStop> {
        if self.record.tenant != tenant {
            return Err(AuthorizationStop::Inactive {
                record: self.record.id,
                failure: AuthzFailure::TenantMismatch,
            });
        }
        Ok(())
    }

    /// The record's id.
    #[must_use]
    pub const fn record_id(&self) -> AuthorizationRecordId {
        self.record.id
    }

    /// The record's target: what every request of the run must stay inside.
    #[must_use]
    pub fn scope(&self) -> RecordScope {
        self.scope.clone()
    }

    /// What the record narrows in the safety kernel (`permittedRiskClasses`, `approvalRequired`).
    #[must_use]
    pub fn narrowing(&self) -> RecordNarrowing {
        narrowing_of(&self.record)
    }

    /// How long a read of the record is trusted.
    #[must_use]
    pub const fn recheck_interval(&self) -> Duration {
        self.recheck
    }

    /// A token that is cancelled when the guard trips, for tasks that want to `select!` on it.
    #[must_use]
    pub fn stopped_token(&self) -> CancellationToken {
        self.stopped.clone()
    }

    /// The stop the guard tripped on, if it has.
    #[must_use]
    pub fn stop(&self) -> Option<AuthorizationStop> {
        self.state.lock().stop.clone()
    }

    /// Has the guard tripped?
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.is_cancelled()
    }

    fn stale(&self) -> bool {
        self.state
            .lock()
            .read_at
            .is_none_or(|at| at.elapsed() >= self.recheck)
    }

    /// Check the record now: its window at `clock.now()` always, its stored state when the last
    /// read is older than the recheck interval. A failure trips the guard (once) and is then
    /// returned by every later call.
    ///
    /// A failed read of the source is not a revocation: the guard keeps the last state it read,
    /// whose window still applies, and reads again on the next call.
    ///
    /// # Errors
    /// The [`AuthorizationStop`] that ended the run's authorization.
    pub async fn check_now(&self) -> Result<(), AuthorizationStop> {
        if let Some(stop) = self.stop() {
            return Err(stop);
        }
        if self.stale() {
            let _one_reader = self.refresh.lock().await;
            if self.stale() {
                match self.source.fetch(self.record.id).await {
                    Ok(Some(fresh)) => {
                        let mut state = self.state.lock();
                        state.latest = fresh;
                        state.read_at = Some(Instant::now());
                    }
                    Ok(None) => return Err(self.trip(AuthorizationStop::Missing(self.record.id)).await),
                    Err(WorkerError::Config(detail)) => {
                        let stop = AuthorizationStop::Unreadable {
                            record: self.record.id,
                            detail,
                        };
                        return Err(self.trip(stop).await);
                    }
                    Err(e) => {
                        tracing::warn!(
                            run = %self.run,
                            record = %self.record.id,
                            error = %e,
                            "authorization record not re-read; keeping the last state"
                        );
                    }
                }
            }
        }
        let verdict = self.state.lock().latest.check_active(self.clock.now());
        match verdict {
            Ok(()) => Ok(()),
            Err(failure) => {
                let stop = AuthorizationStop::Inactive {
                    record: self.record.id,
                    failure,
                };
                Err(self.trip(stop).await)
            }
        }
    }

    /// Re-read authority before accepting a normal execution-clock stop.
    /// Unlike periodic checks, a failed read remains a failure rather than using cache.
    pub(crate) async fn check_execution_stop(&self) -> Result<(), WorkerError> {
        if let Some(stop) = self.stop() {
            return Err(stop.into());
        }
        let _one_reader = self.refresh.lock().await;
        let fresh = match self.source.fetch(self.record.id).await {
            Ok(Some(fresh)) => fresh,
            Ok(None) => return Err(self.trip(AuthorizationStop::Missing(self.record.id)).await.into()),
            Err(WorkerError::Config(detail)) => {
                return Err(self
                    .trip(AuthorizationStop::Unreadable {
                        record: self.record.id,
                        detail,
                    })
                    .await
                    .into());
            }
            Err(error) => return Err(error),
        };
        let verdict = fresh.check_active(self.clock.now());
        {
            let mut state = self.state.lock();
            state.latest = fresh;
            state.read_at = Some(Instant::now());
        }
        if let Err(failure) = verdict {
            return Err(self
                .trip(AuthorizationStop::Inactive {
                    record: self.record.id,
                    failure,
                })
                .await
                .into());
        }
        if let Some(stop) = self.stop() {
            return Err(stop.into());
        }
        Ok(())
    }

    /// Trip the guard on `stop`: the first caller records the event and cancels the run, every
    /// caller gets the stop that won.
    async fn trip(&self, stop: AuthorizationStop) -> AuthorizationStop {
        let (first, stop) = {
            let mut state = self.state.lock();
            match &state.stop {
                Some(existing) => (false, existing.clone()),
                None => {
                    state.stop = Some(stop.clone());
                    (true, stop)
                }
            }
        };
        if first {
            self.stopped.cancel();
            if let Some(token) = self.cancel_run.get() {
                token.cancel();
            }
            tracing::warn!(
                run = %self.run,
                record = %self.record.id,
                reason = stop.reason(),
                "authorization lost; stopping the run"
            );
            let payload = serde_json::json!({
                "recordId": self.record.id,
                "version": self.record.version,
                "reason": stop.reason(),
                "message": stop.to_string(),
            });
            if let Err(e) = self
                .events
                .append(self.run, "authorization.revoked", payload)
                .await
            {
                tracing::warn!(run = %self.run, error = %e, "authorization.revoked event not recorded");
            }
        }
        stop
    }

    /// Check the record every [`HEARTBEAT_INTERVAL`] (or every recheck interval when that is
    /// shorter) until it trips or the returned handle is dropped. The lease loop checks from its
    /// own iteration; a run with no lease loop (an in-process run) relies on this.
    #[must_use]
    pub fn watch(self: &Arc<Self>) -> AuthorizationWatch {
        let guard = Arc::clone(self);
        let done = CancellationToken::new();
        let stop_watching = done.clone();
        let period = self
            .recheck
            .min(HEARTBEAT_INTERVAL)
            .max(Duration::from_millis(10));
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stop_watching.cancelled() => return,
                    () = guard.stopped.cancelled() => return,
                    () = tokio::time::sleep(period) => {
                        if guard.check_now().await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        AuthorizationWatch { done, task }
    }
}

/// Handle of the task [`AuthorizationGuard::watch`] starts; dropping it stops the task.
pub struct AuthorizationWatch {
    done: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AuthorizationWatch {
    fn drop(&mut self) {
        self.done.cancel();
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::Duration as Span;
    use crawlx_core::{SystemClock, TenantId};
    use crawlx_storage::MemoryStore;

    fn record(valid_for: Span) -> AuthorizationRecord {
        let now = SystemClock.now();
        AuthorizationRecord {
            valid_from: now - Span::hours(1),
            valid_to: now + valid_for,
            ..crawlx_policy::testkit::sample_record(TenantId::new(), now, &["https://site.test"])
        }
    }

    async fn admit(
        source: &StaticAuthorizationSource,
        record: &AuthorizationRecord,
        recheck: Duration,
    ) -> Result<Arc<AuthorizationGuard>, WorkerError> {
        AuthorizationGuard::admit(
            CrawlRunId::new(),
            Some(record.clone()),
            Some(record.id),
            Arc::new(source.clone()),
            Arc::new(SystemClock),
            Arc::new(MemoryStore::new()),
            recheck,
        )
        .await
    }

    #[tokio::test]
    async fn execution_stop_rechecks_revocation_even_inside_the_cache_interval() {
        let live = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(live.clone());
        let guard = admit(&source, &live, Duration::from_secs(3600)).await.unwrap();
        assert!(source.revoke(live.id, SystemClock.now(), "execution ceiling"));
        guard.check_now().await.unwrap();
        assert!(matches!(
            guard.check_execution_stop().await,
            Err(WorkerError::Authorization(_)),
        ));
    }

    #[tokio::test]
    async fn head_disclosure_rechecks_expiry_after_the_authorization_read() {
        struct ExpiringRead {
            record: AuthorizationRecord,
            clock: Arc<crawlx_core::time::ManualClock>,
        }
        #[async_trait]
        impl AuthorizationSource for ExpiringRead {
            async fn fetch(
                &self,
                id: AuthorizationRecordId,
            ) -> Result<Option<AuthorizationRecord>, WorkerError> {
                assert_eq!(id, self.record.id);
                self.clock.advance_ms(1_000);
                Ok(Some(self.record.clone()))
            }
        }
        let now: Timestamp = "2030-01-01T00:00:00Z".parse().unwrap();
        let clock = Arc::new(crawlx_core::time::ManualClock::new(now));
        let mut record = crawlx_policy::testkit::sample_record(TenantId::new(), now, &["https://site.test"]);
        record.valid_from = now - Span::seconds(1);
        record.valid_to = now + Span::seconds(1);
        let run = CrawlRunId::new();
        let source = Arc::new(ExpiringRead {
            record: record.clone(),
            clock: clock.clone(),
        });
        let authorizer = LocalHeadResponseAuthorizer {
            run,
            tenant: record.tenant,
            record: record.id,
            body_digest: record.body_digest().unwrap(),
            require_verified: false,
            source,
            clock: clock.clone(),
        };
        assert!(record.check_active(now).is_ok());
        assert!(matches!(
            authorizer.authorize(run, record.tenant, record.id, now).await,
            Err(StoreError::AccessDenied(_))
        ));
        assert_eq!(clock.now(), record.valid_to);
    }

    struct FailingRead {
        source: StaticAuthorizationSource,
        unavailable: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl AuthorizationSource for FailingRead {
        async fn fetch(&self, id: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
            if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(crawlx_core::StoreError::Unavailable("fixture source failure".into()).into());
            }
            self.source.fetch(id).await
        }
    }

    #[tokio::test]
    async fn execution_stop_preserves_authorization_store_failure_instead_of_using_cache() {
        let live = record(Span::hours(1));
        let source = Arc::new(FailingRead {
            source: StaticAuthorizationSource::new(live.clone()),
            unavailable: std::sync::atomic::AtomicBool::new(false),
        });
        let guard = AuthorizationGuard::admit(
            CrawlRunId::new(),
            Some(live.clone()),
            Some(live.id),
            source.clone(),
            Arc::new(SystemClock),
            Arc::new(MemoryStore::new()),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        source
            .unavailable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            guard.check_execution_stop().await,
            Err(WorkerError::Store(crawlx_core::StoreError::Unavailable(_))),
        ));
        assert!(!guard.is_stopped(), "a failed read is not fabricated revocation");
    }

    #[tokio::test]
    async fn admission_refuses_missing_revoked_expired_and_future_records() {
        let live = record(Span::hours(1));
        let empty = StaticAuthorizationSource::default();
        let err = admit(&empty, &live, Duration::ZERO).await.err().unwrap();
        assert!(
            matches!(err, WorkerError::Authorization(AuthorizationStop::Missing(_))),
            "{err}"
        );

        let source = StaticAuthorizationSource::new(live.clone());
        assert!(source.revoke(live.id, SystemClock.now() - Span::seconds(1), "takedown"));
        let err = admit(&source, &live, Duration::ZERO).await.err().unwrap();
        match err {
            WorkerError::Authorization(stop) => assert_eq!(stop.reason(), "revoked"),
            other => panic!("{other}"),
        }

        let expired = record(-Span::minutes(1));
        let source = StaticAuthorizationSource::new(expired.clone());
        match admit(&source, &expired, Duration::ZERO).await.err().unwrap() {
            WorkerError::Authorization(stop) => assert_eq!(stop.reason(), "expired"),
            other => panic!("{other}"),
        }

        let mut future = record(Span::hours(2));
        future.valid_from = SystemClock.now() + Span::hours(1);
        let source = StaticAuthorizationSource::new(future.clone());
        match admit(&source, &future, Duration::ZERO).await.err().unwrap() {
            WorkerError::Authorization(stop) => assert_eq!(stop.reason(), "not_yet_valid"),
            other => panic!("{other}"),
        }
    }

    #[tokio::test]
    async fn a_record_other_than_the_referenced_one_is_refused() {
        let live = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(live.clone());
        let err = AuthorizationGuard::admit(
            CrawlRunId::new(),
            Some(live),
            Some(AuthorizationRecordId::new()),
            Arc::new(source),
            Arc::new(SystemClock),
            Arc::new(MemoryStore::new()),
            DEFAULT_RECHECK_INTERVAL,
        )
        .await
        .err()
        .unwrap();
        assert!(
            matches!(
                err,
                WorkerError::Authorization(AuthorizationStop::Mismatch { .. })
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn caller_copy_cannot_replace_stored_sink_verification_or_endpoints() {
        let stored = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(stored.clone());
        let mut supplied = stored.clone();
        supplied.verified_at = Some(SystemClock.now());
        supplied
            .test_sinks
            .insert("email".into(), "https://site.test/unapproved".into());
        let guard = admit(&source, &supplied, Duration::ZERO).await.unwrap();
        assert_eq!(guard.record().verified_at, None);
        assert!(guard.record().test_sinks.is_empty());
        assert_eq!(guard.record(), &stored);
        assert!(guard.check_tenant(stored.tenant).is_ok());
        assert!(matches!(
            guard.check_tenant(TenantId::new()),
            Err(AuthorizationStop::Inactive {
                failure: AuthzFailure::TenantMismatch,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn a_revocation_is_seen_only_after_the_recheck_interval() {
        let live = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(live.clone());
        let guard = admit(&source, &live, Duration::from_millis(150)).await.unwrap();
        guard.check_now().await.unwrap();
        assert!(source.revoke(live.id, SystemClock.now(), "operator"));
        // within the interval the guard trusts its last read
        guard.check_now().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let stop = guard.check_now().await.unwrap_err();
        assert_eq!(stop.reason(), "revoked");
        assert!(guard.is_stopped());
        assert!(guard.stopped_token().is_cancelled());
        // sticky
        assert_eq!(guard.check_now().await.unwrap_err(), stop);
    }

    #[tokio::test]
    async fn expiry_is_seen_at_the_instant_without_a_read() {
        let short = record(Span::milliseconds(150));
        let source = StaticAuthorizationSource::new(short.clone());
        let guard = admit(&source, &short, Duration::from_secs(3600)).await.unwrap();
        guard.check_now().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(guard.check_now().await.unwrap_err().reason(), "expired");
    }

    #[tokio::test]
    async fn removal_trips_the_guard_cancels_the_run_and_records_one_event() {
        let live = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(live.clone());
        let events = Arc::new(MemoryStore::new());
        let crawl = crawlx_storage::testkit::crawl_run(
            TenantId::new(),
            crawlx_core::CreateCrawl::new(url::Url::parse("https://site.test/").unwrap()),
        );
        let run = crawl.id;
        crawlx_core::repo::RunRepo::create(events.as_ref(), &crawl, None)
            .await
            .unwrap();
        let token = CancellationToken::new();
        let guard = AuthorizationGuard::admit(
            run,
            Some(live.clone()),
            Some(live.id),
            Arc::new(source.clone()),
            Arc::new(SystemClock),
            events.clone(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        guard.cancels(token.clone());
        source.remove(live.id);
        assert_eq!(guard.check_now().await.unwrap_err().reason(), "missing");
        assert_eq!(guard.check_now().await.unwrap_err().reason(), "missing");
        assert!(token.is_cancelled());
        let recorded = events.list_after(run, 0, 100).await.unwrap();
        let revoked: Vec<_> = recorded
            .iter()
            .filter(|e| e.kind == "authorization.revoked")
            .collect();
        assert_eq!(revoked.len(), 1, "the event is recorded once");
        assert_eq!(revoked[0].payload["reason"], "missing");
    }

    #[tokio::test]
    async fn the_watcher_trips_a_guard_nobody_else_is_checking() {
        let live = record(Span::hours(1));
        let source = StaticAuthorizationSource::new(live.clone());
        let guard = admit(&source, &live, Duration::from_millis(50)).await.unwrap();
        let _watch = guard.watch();
        assert!(source.revoke(live.id, SystemClock.now(), "operator"));
        tokio::time::timeout(Duration::from_secs(5), guard.stopped_token().cancelled())
            .await
            .expect("the watcher noticed the revocation");
        assert_eq!(guard.stop().unwrap().reason(), "revoked");
    }
}
