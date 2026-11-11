//! Rust replacements for the PostgreSQL triggers that fire on `crawl_runs` and
//! `authorization_records`.
//!
//! PostgreSQL revokes credential-bearing material inside `AFTER UPDATE` triggers when a run
//! turns terminal, is cancelled or purged, or when its authorization record is revoked.
//! MariaDB and SQLite carry no such trigger, so every statement that changes
//! `crawl_runs.status`, `cancel_requested_at` or `purge_requested_at` (and every one that
//! revokes an authorization record) must call the matching function here in the same
//! transaction. All of them are no-ops on PostgreSQL, whose triggers still run.
//!
//! The paths that change those columns, audited with `UPDATE crawl_runs SET status`:
//! `RunRepo::set_status` (this crate, `repos/run.rs`), the administrative pause, resume and
//! cancel (`admin.rs`), the retention sweeper's terminal failure and purge (`retention.rs`)
//! and the feed finalization terminal updates (`feed_finalization.rs`). Pause and resume only
//! move between the non-terminal `running` and `paused` states, which the triggers ignore.

use crate::backend::strategy::{Conn, Timestamp};
use crate::backend::{Backend, BackendKind, Dialect};
use crate::sql::{db_clock, stmt, Sql, SqlRow, Stmt};
use crawlx_core::CrawlRunId;
use crawlx_core::StoreError;
use uuid::Uuid;

/// Whether this engine relies on Rust for the trigger effects.
#[must_use]
pub(crate) fn in_rust<B: Backend>() -> bool {
    B::KIND != BackendKind::Postgres
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// Revoke credential recovery of `run` after its status, `cancel_requested_at` or
/// `purge_requested_at` changed: the effect of `expire_bound_session_secrets` (0028) and
/// `terminal_checkpoint_expiry` (0038).
///
/// Reads the run's current columns, so call it after the update, in the same transaction.
///
/// # Errors
/// Returns [`StoreError`] if a statement fails.
pub async fn settle_run<B: Sql>(conn: &mut Conn<B>, run: CrawlRunId) -> Result<(), StoreError> {
    if !in_rust::<B>() {
        return Ok(());
    }
    let Some(row) = stmt!(
        B,
        "SELECT status::text AS status, finished_at, cancel_requested_at, purge_requested_at \
         FROM crawl_runs WHERE run_id = $1"
    )
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    else {
        return Ok(());
    };
    let status = row.text("status")?;
    let terminal = is_terminal(&status);
    let requested =
        row.opt_ts("cancel_requested_at")?.is_some() || row.opt_ts("purge_requested_at")?.is_some();
    if !terminal && !requested {
        return Ok(());
    }
    let now = db_clock::<B>(conn).await?;
    expire_credentials::<B>(conn, run.0, now).await?;
    if terminal {
        // finished_at bounds the one-day recovery window a terminal run leaves
        let bound = row.opt_ts("finished_at")?.unwrap_or(now);
        bound_terminal::<B>(conn, run.0, bound).await?;
    }
    if status != "completed" || requested {
        // failed and cancelled runs, and any run with a cancel or purge request, drop the
        // retained browser profiles they own
        stmt!(B, "DELETE FROM browser_profiles WHERE owner_run = $1")
            .uuid(run.0)
            .execute(conn)
            .await?;
    }
    Ok(())
}

/// Credential-bearing artifacts, checkpoints and session bindings of `run` expire at `now`.
async fn expire_credentials<B: Sql>(conn: &mut Conn<B>, run: Uuid, now: Timestamp) -> Result<(), StoreError> {
    let artifact_expiry = <B::Dialect as Dialect>::least_ignoring_null(&["COALESCE(expires_at, $2)", "$2"]);
    let checkpoint_expiry = <B::Dialect as Dialect>::least_ignoring_null(&["expires_at", "$2"]);
    Stmt::<B>::dynamic(&format!(
        "UPDATE artifacts SET expires_at = {artifact_expiry} \
         WHERE run_id = $1 AND sensitivity = 'credential_bearing' AND deleted_at IS NULL"
    ))
    .uuid(run)
    .ts(now)
    .execute(conn)
    .await?;
    Stmt::<B>::dynamic(&format!(
        "UPDATE checkpoints SET expires_at = {checkpoint_expiry} WHERE run_id = $1"
    ))
    .uuid(run)
    .ts(now)
    .execute(conn)
    .await?;
    let stamp = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let binding = <B::Dialect as Dialect>::json_set(
        &<B::Dialect as Dialect>::json_set("binding", "state", "'retired'"),
        "expires_at",
        "$2",
    );
    Stmt::<B>::dynamic(&format!(
        "UPDATE session_bindings SET binding = {binding} WHERE run_id = $1"
    ))
    .uuid(run)
    .text(&stamp)
    .execute(conn)
    .await?;
    Ok(())
}

/// A terminal run's credential-bearing artifacts and checkpoints expire no later than
/// `bound` (its finish time).
async fn bound_terminal<B: Sql>(conn: &mut Conn<B>, run: Uuid, bound: Timestamp) -> Result<(), StoreError> {
    let expiry = <B::Dialect as Dialect>::least_ignoring_null(&["expires_at", "$2"]);
    Stmt::<B>::dynamic(&format!(
        "UPDATE artifacts SET expires_at = {expiry} WHERE run_id = $1 AND sensitivity = 'credential_bearing'"
    ))
    .uuid(run)
    .ts(bound)
    .execute(conn)
    .await?;
    Stmt::<B>::dynamic(&format!(
        "UPDATE checkpoints SET expires_at = {expiry} WHERE run_id = $1"
    ))
    .uuid(run)
    .ts(bound)
    .execute(conn)
    .await?;
    Ok(())
}

/// Revoke credential recovery of every run bound to `record` after the authorization record
/// was revoked: the effect of `revoke_retained_profiles` (0028).
///
/// # Errors
/// Returns [`StoreError`] if a statement fails.
pub async fn settle_authorization_revoked<B: Sql>(
    conn: &mut Conn<B>,
    record: Uuid,
) -> Result<(), StoreError> {
    if !in_rust::<B>() {
        return Ok(());
    }
    let now = db_clock::<B>(conn).await?;
    let checkpoint_expiry = <B::Dialect as Dialect>::least_ignoring_null(&["expires_at", "$2"]);
    stmt!(
        B,
        "DELETE FROM browser_profiles WHERE owner_run IN \
         (SELECT run_id FROM crawl_runs WHERE authorization_record_id = $1)"
    )
    .uuid(record)
    .execute(conn)
    .await?;
    stmt!(
        B,
        "UPDATE artifacts SET expires_at = $2 \
         WHERE sensitivity = 'credential_bearing' AND deleted_at IS NULL AND run_id IN \
         (SELECT run_id FROM crawl_runs WHERE authorization_record_id = $1)"
    )
    .uuid(record)
    .ts(now)
    .execute(conn)
    .await?;
    Stmt::<B>::dynamic(&format!(
        "UPDATE checkpoints SET expires_at = {checkpoint_expiry} WHERE run_id IN \
         (SELECT run_id FROM crawl_runs WHERE authorization_record_id = $1)"
    ))
    .uuid(record)
    .ts(now)
    .execute(conn)
    .await?;
    Ok(())
}
