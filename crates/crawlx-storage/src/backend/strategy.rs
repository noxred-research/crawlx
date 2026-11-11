//! Concurrency primitives whose algorithm differs per engine.
//!
//! Repository SQL that only differs in fragments lives in the shared repositories and uses
//! [`crate::backend::Dialect`]. Primitives whose *algorithm* differs live here: claiming rows
//! under concurrency, fence tokens, transaction-scoped locks, write transactions and the
//! audit chain append. [`Concurrency`] is implemented once per engine and called through the
//! backend type parameter of [`crate::Store`], so there is no dynamic dispatch.
//!
//! Row-returning primitives hand back raw driver rows; the calling repository decodes them
//! with the shared column lists it already owns.

use crate::error::db;
use crawlx_core::hash::Digest;
use crawlx_core::StoreError;
use sqlx::{Database, Transaction};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use super::Backend;

/// Database time as the repositories carry it.
pub type Timestamp = chrono::DateTime<chrono::Utc>;

/// A driver row of backend `B`.
pub type Row<B> = <<B as Backend>::Db as Database>::Row;

/// A driver connection of backend `B`.
pub type Conn<B> = <<B as Backend>::Db as Database>::Connection;

/// A query of backend `B` whose binds the caller supplies through a closure.
pub type Query<'q, B> =
    sqlx::query::Query<'q, <B as Backend>::Db, <<B as Backend>::Db as Database>::Arguments>;

/// A named monotonic counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FenceSeq {
    /// Fencing tokens of session, frontier and origin leases (`lease_fence_seq`).
    Lease,
    /// Fence of run bootstrap producers (`run_bootstrap_producer_fence`).
    BootstrapProducer,
    /// Page ordinals of `actions.dataset_page` on engines whose column is not an identity
    /// (SQLite). PostgreSQL and MariaDB assign the column themselves and never draw it.
    ActionDatasetPage,
}

impl FenceSeq {
    /// The sequence name (a SQL identifier on PostgreSQL and MariaDB, a row key on SQLite).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lease => "lease_fence_seq",
            Self::BootstrapProducer => "run_bootstrap_producer_fence",
            Self::ActionDatasetPage => "actions.dataset_page",
        }
    }
}

/// Strength of a transaction-scoped lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockMode {
    /// Many holders, excluded by an exclusive holder.
    Shared,
    /// One holder.
    Exclusive,
}

/// A write transaction. Dropping it without [`WriteTx::commit`] rolls back and releases the
/// engine's write permit (the in-process writer permit on SQLite).
#[must_use = "a write transaction that is not committed is rolled back on drop"]
pub struct WriteTx<DB: Database> {
    // Field order matters: the transaction rolls back before the writer permit is released.
    tx: Transaction<'static, DB>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<DB: Database> WriteTx<DB> {
    /// Wrap `tx`; `permit` is held until the transaction ends.
    pub const fn new(tx: Transaction<'static, DB>, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self { tx, permit }
    }

    /// The connection statements run on.
    pub fn conn(&mut self) -> &mut DB::Connection {
        &mut self.tx
    }

    /// Commit and release the write permit.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the commit fails; the transaction is then rolled back.
    pub async fn commit(self) -> Result<(), StoreError> {
        let Self { tx, permit } = self;
        let result = tx.commit().await.map_err(db);
        drop(permit);
        result
    }

    /// Roll back explicitly and release the write permit.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the rollback statement fails.
    pub async fn rollback(self) -> Result<(), StoreError> {
        let Self { tx, permit } = self;
        let result = tx.rollback().await.map_err(db);
        drop(permit);
        result
    }
}

impl<DB: Database> Deref for WriteTx<DB> {
    type Target = Transaction<'static, DB>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl<DB: Database> DerefMut for WriteTx<DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl<DB: Database> std::fmt::Debug for WriteTx<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteTx")
            .field("serialized", &self.permit.is_some())
            .finish_non_exhaustive()
    }
}

/// Claim one session of a run (`crawl_sessions`) for `worker`.
#[derive(Clone, Copy, Debug)]
pub struct SessionClaim<'a> {
    /// The run to claim from.
    pub run: Uuid,
    /// The claiming worker.
    pub worker: Uuid,
    /// Lease length in seconds.
    pub ttl_secs: f64,
    /// Parallel runs probe every claimable session; serial runs inspect exactly the first
    /// unfinished slot and never grant its successor.
    pub parallel_roles: bool,
    /// Claim only this session.
    pub requested: Option<Uuid>,
    /// Acquisition backend ids the worker must advertise.
    pub required_backends: &'a [String],
    /// The run needs a worker with data capabilities.
    pub data_required: bool,
    /// Column list returned (`SESSION_COLS` plus the fence and expiry).
    pub columns: &'static str,
}

/// Claim a batch of pending frontier rows of a run for `worker`.
#[derive(Clone, Copy, Debug)]
pub struct FrontierClaim<'a> {
    /// The run to claim from.
    pub run: Uuid,
    /// The claiming worker.
    pub worker: Uuid,
    /// Most rows to claim.
    pub limit: i64,
    /// Lease length in seconds.
    pub ttl_secs: f64,
    /// Acquisition backend ids the worker must advertise.
    pub required_backends: &'a [String],
    /// The run needs a worker with data capabilities.
    pub data_required: bool,
    /// Traversal order: `breadth_first`, `depth_first` or `priority`.
    pub strategy: &'static str,
}

/// Claim due webhook deliveries.
#[derive(Clone, Copy, Debug)]
pub struct WebhookClaim<'a> {
    /// Deliveries due at or before this time are claimable.
    pub now: Timestamp,
    /// Most deliveries to claim.
    pub limit: i64,
    /// How far each claimed delivery is deferred, in seconds.
    pub lease_secs: f64,
    /// Comma separated column list of `webhook_deliveries` to return (`due_at` is appended).
    pub columns: &'a str,
}

/// Claim due monitors.
#[derive(Clone, Copy, Debug)]
pub struct MonitorClaim {
    /// Monitors due at or before this time are claimable.
    pub now: Timestamp,
    /// The new `claimed_until`.
    pub lease_until: Timestamp,
    /// Most monitors to claim.
    pub limit: i64,
    /// Column list of `monitors` to return.
    pub columns: &'static str,
}

/// Claim deliveries of one run's outbox for `worker`.
#[derive(Clone, Copy, Debug)]
pub struct OutboxClaim {
    /// Owning tenant.
    pub tenant: Uuid,
    /// The run.
    pub run: Uuid,
    /// The claiming worker.
    pub worker: Uuid,
    /// Most deliveries to claim.
    pub limit: i64,
    /// Lease length in seconds.
    pub lease_secs: f64,
}

/// One `traffic_events` row of an action's outcome.
#[derive(Clone, Debug)]
pub struct TrafficRow<'a> {
    /// When the request started.
    pub occurred_at: Timestamp,
    /// The network epoch the row is attributed to.
    pub epoch: Option<Uuid>,
    /// Why the row has no epoch (exactly one of `epoch` and `reason` is set).
    pub reason: Option<&'a str>,
    /// Sequence within the action's traffic.
    pub seq: i32,
    /// Traffic origin label.
    pub origin: &'a str,
    /// Whether the request left the page's site.
    pub third_party: bool,
    /// Whether the request finished after its epoch settled.
    pub late: bool,
    /// HTTP method.
    pub method: &'a str,
    /// Redacted URL; `None` for ZDR runs.
    pub url: Option<&'a str>,
    /// Digest of the URL.
    pub url_hash: Vec<u8>,
    /// Response status.
    pub status: Option<i32>,
    /// Request headers; `None` for ZDR runs.
    pub request_headers: Option<serde_json::Value>,
    /// Response headers; `None` for ZDR runs.
    pub response_headers: Option<serde_json::Value>,
    /// Response body artifact.
    pub body: Option<Uuid>,
    /// Request body artifact.
    pub request_body: Option<Uuid>,
    /// When the request finished.
    pub finished_at: Option<Timestamp>,
}

/// An append to the hash-chained `audit_events` log.
#[derive(Clone, Copy, Debug)]
pub struct AuditEntry<'a> {
    /// Owning tenant, when the event belongs to one.
    pub tenant: Option<Uuid>,
    /// The run, when the event belongs to one.
    pub run: Option<Uuid>,
    /// Who acted.
    pub actor: &'a str,
    /// What happened.
    pub event: &'a str,
    /// Event details; already reduced to a digest for ZDR runs.
    pub subject: &'a serde_json::Value,
}

/// Domain-separated hash of one audit entry chained to `prev`. Every engine hashes this
/// Rust-rendered text, so an operator can verify the chain with the same algorithm anywhere.
#[must_use]
pub fn audit_entry_hash(prev: &[u8], entry: &AuditEntry<'_>) -> Digest {
    let text = serde_json::json!({
        "tenant": entry.tenant,
        "run": entry.run,
        "actor": entry.actor,
        "event": entry.event,
        "subject": entry.subject,
    })
    .to_string();
    Digest::of("crawlx/audit-chain/v1", &[prev, text.as_bytes()].concat())
}

/// Head of an empty audit chain.
pub const EMPTY_AUDIT_HEAD: [u8; 32] = [0; 32];

/// The per-engine concurrency strategy.
pub trait Concurrency: Backend {
    /// Begin a transaction that will write. SQLite serializes writers in-process and takes the
    /// database write lock up front (`BEGIN IMMEDIATE`, retried with jitter on contention);
    /// the other engines begin normally.
    fn begin_write(pool: &Self::Pool) -> impl Future<Output = Result<WriteTx<Self::Db>, StoreError>> + Send;

    /// Begin a read-only transaction with a repeatable snapshot.
    fn begin_read(
        pool: &Self::Pool,
    ) -> impl Future<Output = Result<Transaction<'static, Self::Db>, StoreError>> + Send;

    /// The database clock, the only clock lease arithmetic uses. SQLite runs on one host, so
    /// its database clock is the process clock (millisecond resolution there).
    fn db_now(pool: &Self::Pool) -> impl Future<Output = Result<Timestamp, StoreError>> + Send;

    /// The next value of `seq`, strictly greater than every value handed out before. On
    /// SQLite the connection must belong to a write transaction.
    fn next_fence(
        conn: &mut Conn<Self>,
        seq: FenceSeq,
    ) -> impl Future<Output = Result<i64, StoreError>> + Send;

    /// Take a transaction-scoped lock named `key`, released at commit or rollback. SQLite
    /// returns at once: a write transaction already holds the database write lock.
    fn xact_lock(
        conn: &mut Conn<Self>,
        key: &str,
        mode: LockMode,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Claim at most one session; `None` when nothing is claimable.
    fn claim_sessions(
        pool: &Self::Pool,
        claim: SessionClaim<'_>,
    ) -> impl Future<Output = Result<Option<Row<Self>>, StoreError>> + Send;

    /// Claim a batch of frontier rows. Row order is unspecified; callers sort.
    fn claim_frontier_batch(
        pool: &Self::Pool,
        claim: FrontierClaim<'_>,
    ) -> impl Future<Output = Result<Vec<Row<Self>>, StoreError>> + Send;

    /// Claim due webhook deliveries; rows carry the delivery columns and `due_at`.
    fn claim_webhooks(
        pool: &Self::Pool,
        claim: WebhookClaim<'_>,
    ) -> impl Future<Output = Result<Vec<Row<Self>>, StoreError>> + Send;

    /// Claim due monitors. Row order is unspecified; callers sort.
    fn claim_monitors(
        pool: &Self::Pool,
        claim: MonitorClaim,
    ) -> impl Future<Output = Result<Vec<Row<Self>>, StoreError>> + Send;

    /// Claim deliveries of a run's outbox inside the caller's write transaction.
    fn claim_outbox(
        conn: &mut Conn<Self>,
        claim: OutboxClaim,
    ) -> impl Future<Output = Result<Vec<Row<Self>>, StoreError>> + Send;

    /// Retire up to 1000 expired outbox deliveries of a run; returns how many.
    fn expire_outbox(
        pool: &Self::Pool,
        tenant: Uuid,
        run: Uuid,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Run a fenced update and return the updated row, or `None` when the fence or lease no
    /// longer matches. `update` is the statement of the engine; engines without
    /// `UPDATE .. RETURNING` run it, treat zero matched rows as `None`, and read the row back
    /// with `reread` (statement and binder) inside the same transaction.
    fn fenced_update_returning<'q, U, R>(
        conn: &mut Conn<Self>,
        update: &'static str,
        bind_update: U,
        reread: Option<(&'static str, R)>,
    ) -> impl Future<Output = Result<Option<Row<Self>>, StoreError>> + Send
    where
        U: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send,
        R: FnOnce(Query<'q, Self>) -> Query<'q, Self> + Send;

    /// Extend the leases of URL rows held by `worker`: `leases` pairs a row id with the fencing
    /// token of the holder. Returns the ids of the rows extended (still leased, still the
    /// holder's, not yet expired), in no particular order.
    fn heartbeat_frontier(
        pool: &Self::Pool,
        worker: Uuid,
        ttl_secs: f64,
        leases: &[(i64, i64)],
    ) -> impl Future<Output = Result<Vec<i64>, StoreError>> + Send;

    /// Insert the traffic of one action inside the caller's write transaction. Rows without an
    /// epoch are stored in the `diagnostic` lane; the others in `lane`. PostgreSQL inserts the
    /// batch with one `UNNEST` statement, the other engines with chunked multi-row `VALUES`.
    fn insert_traffic(
        conn: &mut Conn<Self>,
        run: Uuid,
        lane: &str,
        rows: &[TrafficRow<'_>],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Append one event to the audit chain inside the caller's write transaction.
    fn append_audit_chain(
        conn: &mut Conn<Self>,
        entry: AuditEntry<'_>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn fence_sequences_have_stable_names() {
        assert_eq!(FenceSeq::Lease.name(), "lease_fence_seq");
        assert_eq!(FenceSeq::BootstrapProducer.name(), "run_bootstrap_producer_fence");
    }

    #[test]
    fn audit_hash_chains_and_is_domain_separated() {
        let subject = serde_json::json!({ "k": "v" });
        let entry = AuditEntry {
            tenant: None,
            run: None,
            actor: "operator",
            event: "purge",
            subject: &subject,
        };
        let first = audit_entry_hash(&EMPTY_AUDIT_HEAD, &entry);
        let second = audit_entry_hash(&first.0, &entry);
        assert_ne!(first, second);
        assert_eq!(first, audit_entry_hash(&EMPTY_AUDIT_HEAD, &entry));
        let text = r#"{"actor":"operator","event":"purge","run":null,"subject":{"k":"v"},"tenant":null}"#;
        let expected = Digest::of(
            "crawlx/audit-chain/v1",
            &[EMPTY_AUDIT_HEAD.as_slice(), text.as_bytes()].concat(),
        );
        assert_eq!(first, expected);
    }
}
