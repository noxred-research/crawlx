//! Mapping of `sqlx` errors to `crawlx_core::StoreError`.

use crawlx_core::StoreError;

/// Convert a `sqlx` error into the shared repository error.
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
            let code = d.code();
            match code.as_deref() {
                Some("23505" | "23503" | "23514" | "23502") => {
                    StoreError::Conflict(format!("{}: {}", d.constraint().unwrap_or("-"), d.message()))
                }
                Some("P0001") => illegal_transition(d.message()).unwrap_or_else(|| driver(e, true)),
                Some(c) if c.starts_with("08") || c.starts_with("57P") => driver(e, true),
                _ => driver(e, true),
            }
        }
        _ => driver(e, true),
    }
}

fn driver(source: sqlx::Error, retryable: bool) -> StoreError {
    StoreError::Database {
        source: Box::new(source),
        retryable,
    }
}

/// Parse `illegal actions.status transition A -> B` raised by the trigger.
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
