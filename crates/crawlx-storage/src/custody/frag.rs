//! Statement fragments shared by the custody, bootstrap, frozen-archive, profile and origin
//! modules.
//!
//! Every function returns text for one engine. On PostgreSQL the text is exactly the
//! historical one (the PostgreSQL statements never changed), on the other engines it comes
//! from [`Dialect`] or from the engine's own spelling of the same rule. Templates keep the
//! PostgreSQL casts (`$3::uuid`, `status::text`): [`crate::sql`] drops them elsewhere.

use crate::backend::strategy::Conn;
use crate::backend::{Backend, BackendKind, Dialect, RowLock};
use crate::sql::{stmt, Sql, Stmt};
use crawlx_core::StoreError;

/// `true` on PostgreSQL.
pub(crate) fn is_pg<B: Backend>() -> bool {
    B::KIND == BackendKind::Postgres
}

/// `clock_timestamp()` of the engine.
pub(crate) fn clock<B: Backend>() -> &'static str {
    <B::Dialect as Dialect>::clock_timestamp()
}

/// ` FOR SHARE` / ` LOCK IN SHARE MODE` / nothing.
pub(crate) fn share<B: Backend>() -> &'static str {
    <B::Dialect as Dialect>::row_lock(RowLock::Share)
}

/// ` FOR UPDATE` / nothing (a SQLite write transaction holds the database write lock).
pub(crate) fn update<B: Backend>() -> &'static str {
    <B::Dialect as Dialect>::row_lock(RowLock::Update)
}

/// Shared lock on the rows of the listed join aliases. PostgreSQL names them, MariaDB locks
/// every table the statement reads (a superset of what the aliases name).
pub(crate) fn share_of<B: Backend>(aliases: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!(" FOR SHARE OF {aliases}"),
        _ => share::<B>().to_owned(),
    }
}

/// `NULL`-ignoring `LEAST`, with PostgreSQL's historical spelling.
pub(crate) fn least<B: Backend>(args: &[&str]) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("LEAST({})", args.join(",")),
        _ => <B::Dialect as Dialect>::least_ignoring_null(args),
    }
}

/// `NULL`-ignoring `GREATEST`, with PostgreSQL's historical spelling.
pub(crate) fn greatest<B: Backend>(args: &[&str]) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("GREATEST({})", args.join(",")),
        _ => <B::Dialect as Dialect>::greatest_ignoring_null(args),
    }
}

/// Hex text of the binary column `col`, with PostgreSQL's historical spelling.
pub(crate) fn hex<B: Backend>(col: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("encode({col},'hex')"),
        _ => <B::Dialect as Dialect>::hex(col),
    }
}

/// `(col->>'key')::bigint`: a JSON number member read as an integer.
pub(crate) fn json_bigint<B: Backend>(col: &str, key: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("({col}->>'{key}')::bigint"),
        BackendKind::MariaDb => format!("CAST(JSON_VALUE({col},'$.{key}') AS SIGNED)"),
        BackendKind::Sqlite => format!("CAST({col}->>'{key}' AS INTEGER)"),
    }
}

/// Text member `key` of the JSON column `col`, with PostgreSQL's historical spelling.
pub(crate) fn json_text<B: Backend>(col: &str, key: &str) -> String {
    <B::Dialect as Dialect>::json_text(col, key)
}

/// `a` differs from `b`, `NULL`s compared as equal, with PostgreSQL's historical spelling.
pub(crate) fn null_safe_ne<B: Backend>(a: &str, b: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("{a} IS DISTINCT FROM {b}"),
        _ => <B::Dialect as Dialect>::null_safe_ne(a, b),
    }
}

/// `a` equals `b`, `NULL`s compared as equal, with PostgreSQL's historical spelling.
pub(crate) fn null_safe_eq<B: Backend>(a: &str, b: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("{a} IS NOT DISTINCT FROM {b}"),
        _ => <B::Dialect as Dialect>::null_safe_eq(a, b),
    }
}

/// The trailing clause of an insert that leaves an existing row alone.
pub(crate) fn on_conflict_nothing<B: Backend>(target: &[&str]) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("ON CONFLICT({}) DO NOTHING", target.join(",")),
        _ => <B::Dialect as Dialect>::upsert_do_nothing(target),
    }
}

/// ` RETURNING <columns>` on engines that have it for updates, nothing elsewhere.
pub(crate) fn returning<B: Backend>(columns: &str) -> String {
    if <B::Dialect as Dialect>::UPDATE_RETURNING {
        format!(" RETURNING {columns}")
    } else {
        String::new()
    }
}

/// Settings every custody transaction applies before its first statement: bounded lock waits.
///
/// # Errors
/// Returns [`StoreError`] if the settings statement fails.
pub(crate) async fn bound_waits<B: Sql>(conn: &mut Conn<B>) -> Result<(), StoreError> {
    match B::KIND {
        BackendKind::Postgres => {
            stmt!(
                B,
                "SELECT set_config('lock_timeout','10s',true),set_config('statement_timeout','30s',true),set_config('idle_in_transaction_session_timeout','90s',true)"
            )
            .execute(conn)
            .await?;
        }
        BackendKind::MariaDb => {
            stmt!(B, "SET SESSION innodb_lock_wait_timeout = 10")
                .execute(conn)
                .await?;
        }
        BackendKind::Sqlite => {}
    }
    Ok(())
}

/// Run a fenced update and return the updated row, or `None` when the fence no longer
/// matches. Engines with `UPDATE .. RETURNING` run `update` (which carries the `RETURNING`
/// clause); the others run `update` without it, treat zero matched rows as `None` and read
/// the row back with `reread` inside the same transaction.
///
/// # Errors
/// Returns [`StoreError`] if a statement fails.
pub(crate) async fn update_returning<B: Sql>(
    conn: &mut Conn<B>,
    update: Stmt<'_, B>,
    reread: Stmt<'_, B>,
) -> Result<Option<B::Row>, StoreError> {
    if <B::Dialect as Dialect>::UPDATE_RETURNING {
        return update.fetch_optional(conn).await;
    }
    if update.execute(conn).await? == 0 {
        return Ok(None);
    }
    reread.fetch_optional(conn).await
}
