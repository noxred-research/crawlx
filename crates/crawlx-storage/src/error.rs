//! Mapping of `sqlx` errors to `crawlx_core::StoreError`.

use crawlx_core::StoreError;

/// Convert a `sqlx` error into the shared repository error.
///
/// Constraint violations (`kind()` of unique, foreign key, check, not null) are conflicts on
/// every engine. Retryability is decided per engine from its own codes: PostgreSQL keeps the
/// historical "retry anything unclassified" rule, SQLite retries `SQLITE_BUSY`/`LOCKED`
/// (extended codes masked to their primary code) and MariaDB retries lock wait timeouts,
/// deadlocks and statement timeouts (by server error number: the SQLSTATE of a lock wait
/// timeout is the generic `HY000`).
pub(crate) fn db(e: sqlx::Error) -> StoreError {
    match &e {
        sqlx::Error::RowNotFound => StoreError::NotFound {
            entity: "row",
            id: String::new(),
        },
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_) => {
            driver(e, true)
        }
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) => driver(e, false),
        sqlx::Error::Database(d) => {
            use sqlx::error::ErrorKind;
            if matches!(
                d.kind(),
                ErrorKind::UniqueViolation
                    | ErrorKind::ForeignKeyViolation
                    | ErrorKind::CheckViolation
                    | ErrorKind::NotNullViolation
            ) {
                return StoreError::Conflict(format!("{}: {}", d.constraint().unwrap_or("-"), d.message()));
            }
            if let Some(number) = mariadb_number(d.as_ref()) {
                return match number {
                    MARIADB_LOCK_WAIT_TIMEOUT | MARIADB_DEADLOCK | MARIADB_STATEMENT_TIMEOUT => {
                        driver(e, true)
                    }
                    _ => illegal_transition(d.message()).unwrap_or_else(|| driver(e, false)),
                };
            }
            if let Some(primary) = sqlite_primary(d.as_ref()) {
                return match primary {
                    SQLITE_BUSY | SQLITE_LOCKED => driver(e, true),
                    _ => illegal_transition(d.message()).unwrap_or_else(|| driver(e, false)),
                };
            }
            let code = d.code();
            match code.as_deref() {
                Some("P0001") => illegal_transition(d.message()).unwrap_or_else(|| driver(e, true)),
                Some(c) if c.starts_with("08") || c.starts_with("57P") => driver(e, true),
                _ => driver(e, true),
            }
        }
        _ => driver(e, true),
    }
}

const SQLITE_BUSY: i32 = 5;
const SQLITE_LOCKED: i32 = 6;
const MARIADB_LOCK_WAIT_TIMEOUT: u16 = 1205;
const MARIADB_DEADLOCK: u16 = 1213;
const MARIADB_STATEMENT_TIMEOUT: u16 = 1969;

/// The server error number of a MariaDB database error.
fn mariadb_number(error: &dyn sqlx::error::DatabaseError) -> Option<u16> {
    error
        .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
        .map(sqlx::mysql::MySqlDatabaseError::number)
}

/// The primary result code of a SQLite database error: the extended code (`517` busy
/// snapshot, `2067` unique, `1811` trigger abort) masked to its low byte.
fn sqlite_primary(error: &dyn sqlx::error::DatabaseError) -> Option<i32> {
    error.try_downcast_ref::<sqlx::sqlite::SqliteError>()?;
    let extended: i32 = error.code()?.parse().ok()?;
    Some(extended & 0xff)
}

/// The primary SQLite result code of `error`, `None` for other errors and engines.
pub(crate) fn sqlite_primary_code(error: &sqlx::Error) -> Option<i32> {
    match error {
        sqlx::Error::Database(d) => sqlite_primary(d.as_ref()),
        _ => None,
    }
}

fn driver(source: sqlx::Error, retryable: bool) -> StoreError {
    StoreError::Database {
        source: Box::new(source),
        retryable,
    }
}

/// Parse `illegal actions.status transition A -> B` raised by the trigger (`RAISE` on
/// PostgreSQL and SQLite, `SIGNAL` on MariaDB; the message text is identical).
fn illegal_transition(msg: &str) -> Option<StoreError> {
    let rest = msg.strip_prefix("illegal actions.status transition ")?;
    let (from, to) = rest.split_once(" -> ")?;
    Some(StoreError::IllegalTransition {
        from: from.to_owned(),
        to: to.to_owned(),
    })
}

pub(crate) fn not_found(entity: &'static str, id: impl std::fmt::Display) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn trigger_message_parses() {
        let e = illegal_transition("illegal actions.status transition proposed -> succeeded").unwrap();
        assert!(
            matches!(e, StoreError::IllegalTransition { ref from, ref to } if from == "proposed" && to == "succeeded")
        );
        assert!(illegal_transition("something else").is_none());
    }

    #[test]
    fn busy_codes_mask_to_their_primary_code() {
        // 517 = SQLITE_BUSY_SNAPSHOT, 261 = SQLITE_BUSY_RECOVERY, 262 = SQLITE_LOCKED_SHAREDCACHE-ish
        for extended in [5, 517, 261] {
            assert_eq!(extended & 0xff, SQLITE_BUSY);
        }
        assert_eq!(262 & 0xff, SQLITE_BUSY + 1);
        assert_eq!(2067 & 0xff, 19);
        assert_eq!(1811 & 0xff, 19);
    }

    #[test]
    fn driver_failures_keep_sources_without_displaying_them() {
        use std::error::Error;

        let unavailable = db(sqlx::Error::PoolClosed);
        assert!(unavailable.is_retryable());
        assert!(unavailable.source().unwrap().is::<sqlx::Error>());

        let decode = db(sqlx::Error::Decode(Box::new(std::io::Error::other(
            "sensitive driver detail",
        ))));
        assert!(!decode.is_retryable());
        assert!(decode.source().unwrap().is::<sqlx::Error>());
        assert!(!decode.to_string().contains("sensitive"));
    }
}
