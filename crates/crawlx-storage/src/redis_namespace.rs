//! Key namespace of the volatile Redis/Valkey instances (secret registry and zero-data-retention
//! delivery buffer).
//!
//! Several deployments, or CrawlX next to other products, can share one instance when each uses
//! its own key prefix (`CRAWLX_REDIS_KEY_PREFIX`, default `crawlx:`). A deployment only ever
//! touches keys under its own prefix: it never lists with `KEYS`, never flushes a database and
//! deletes only the keys it names. The logical database index, ACL user and password, and TLS
//! (`rediss://`) come from the connection URL.

use crawlx_core::StoreError;

/// Variable naming the key prefix.
pub const KEY_PREFIX_ENV: &str = "CRAWLX_REDIS_KEY_PREFIX";
/// Prefix used when none is configured.
pub const DEFAULT_KEY_PREFIX: &str = "crawlx:";

/// Check a key prefix and return it in its canonical form (ending in `:`).
///
/// A prefix is 1 to 64 characters of letters, digits and `_ . - :`. Braces are refused: a hash
/// tag inside the prefix would change how keys map to cluster slots.
///
/// # Errors
/// [`StoreError::Conflict`] for an empty or malformed prefix.
pub fn normalize_key_prefix(prefix: &str) -> Result<String, StoreError> {
    let trimmed = prefix.trim();
    let ok = (1..=64).contains(&trimmed.len())
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'));
    if !ok {
        return Err(StoreError::Conflict(format!(
            "{KEY_PREFIX_ENV} must be 1 to 64 characters of letters, digits and _ . - :"
        )));
    }
    Ok(if trimmed.ends_with(':') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}:")
    })
}

/// The prefix from `CRAWLX_REDIS_KEY_PREFIX`, or [`DEFAULT_KEY_PREFIX`].
///
/// # Errors
/// [`StoreError::Conflict`] for a malformed value.
pub fn key_prefix_from_env() -> Result<String, StoreError> {
    match std::env::var(KEY_PREFIX_ENV) {
        Ok(value) if !value.trim().is_empty() => normalize_key_prefix(&value),
        _ => Ok(DEFAULT_KEY_PREFIX.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn prefixes_are_checked_and_canonical() {
        assert_eq!(normalize_key_prefix("crawlx").unwrap(), "crawlx:");
        assert_eq!(normalize_key_prefix("team-a:crawlx:").unwrap(), "team-a:crawlx:");
        for bad in ["", "  ", "a b", "a{b}", "a/b", "é", &"x".repeat(65)] {
            assert!(normalize_key_prefix(bad).is_err(), "{bad:?}");
        }
    }
}
