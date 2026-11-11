//! Typed startup refusals.
//!
//! A refusal is raised before serving or leasing, never mid-run, and its text is stable:
//! tests assert it and wrappers print it as `refused: <code>: <message>`.

use crate::backend::BackendKind;
use crawlx_core::StoreError;
use std::path::Path;
use thiserror::Error;

/// Stable identifier of a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefusalCode {
    /// A second worker process opened the same SQLite file.
    SqliteSecondWorker,
    /// The SQLite file is on a network filesystem, or is an in-memory database.
    SqliteNotLocal,
    /// A request login was configured for SQLite, which has no database roles.
    SqliteNoRoles,
    /// A second tenant appeared in a SQLite deployment that did not accept that.
    SqliteMultiTenant,
    /// The independent safety auditor was requested on SQLite.
    SqliteSafetyAuditor,
    /// The server is not MariaDB, or older than 10.6.
    MariadbUnsupportedServer,
    /// The server is a multi-primary cluster.
    MariadbMultiPrimary,
    /// A server setting the storage code depends on has the wrong value.
    MariadbSettings,
    /// The request login holds privileges it must not hold.
    MariadbRequestLogin,
    /// The database URL scheme is unknown.
    Scheme,
    /// `serve` or `worker` started without artifact custody.
    CustodyMissing,
    /// The selected engine does not implement the requested capability yet.
    BackendUnimplemented,
}

impl RefusalCode {
    /// The stable machine name printed after `refused:`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SqliteSecondWorker => "sqlite_second_worker",
            Self::SqliteNotLocal => "sqlite_not_local",
            Self::SqliteNoRoles => "sqlite_no_roles",
            Self::SqliteMultiTenant => "sqlite_multi_tenant",
            Self::SqliteSafetyAuditor => "sqlite_safety_auditor",
            Self::MariadbUnsupportedServer => "mariadb_unsupported_server",
            Self::MariadbMultiPrimary => "mariadb_multi_primary",
            Self::MariadbSettings => "mariadb_settings",
            Self::MariadbRequestLogin => "mariadb_request_login",
            Self::Scheme => "scheme",
            Self::CustodyMissing => "custody_missing",
            Self::BackendUnimplemented => "backend_unimplemented",
        }
    }
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A startup refusal: a stable code and the exact operator-facing message.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("refused: {code}: {message}")]
#[non_exhaustive]
pub struct BackendRefusal {
    /// Which rule refused.
    pub code: RefusalCode,
    /// Operator-facing text without the `refused: <code>:` prefix.
    pub message: String,
}

/// What a worker that cannot seal artifacts is told (shared with the worker's startup check).
pub const CUSTODY_MISSING_MESSAGE: &str = "encrypted artifact custody is not configured: set exactly one of \
     CRAWLX_ARTIFACT_KMS_KEY_ID or CRAWLX_ARTIFACT_KEY_FILE, and CRAWLX_SECRET_REDIS_URL (or \
     CRAWLX_SECRET_REDIS_URL_FILE) naming the persistence-free secret registry";

impl BackendRefusal {
    fn new(code: RefusalCode, message: String) -> Self {
        Self { code, message }
    }

    /// A second `crawlx worker` opened the SQLite file at `path`.
    #[must_use]
    pub fn sqlite_second_worker(path: &Path) -> Self {
        Self::new(
            RefusalCode::SqliteSecondWorker,
            format!(
                "another crawlx worker already holds {}.worker.lock; sqlite supports exactly one worker \
                 process per database file; use mariadb or postgres for several workers",
                path.display()
            ),
        )
    }

    /// The SQLite database at `path` is not on a local filesystem that supports WAL.
    #[must_use]
    pub fn sqlite_not_local(path: &str) -> Self {
        Self::new(
            RefusalCode::SqliteNotLocal,
            format!(
                "{path} is not on a local filesystem that supports WAL; use a local path or choose mariadb \
                 or postgres"
            ),
        )
    }

    /// A request login URL was configured next to a SQLite `database_url`.
    #[must_use]
    pub fn sqlite_no_roles() -> Self {
        Self::new(
            RefusalCode::SqliteNoRoles,
            "sqlite has no database roles; remove CRAWLX_API_DATABASE_URL (the API uses the same file under \
             application-enforced tenancy)"
                .to_owned(),
        )
    }

    /// A staging or production SQLite database already has a tenant.
    #[must_use]
    pub fn sqlite_multi_tenant() -> Self {
        Self::new(
            RefusalCode::SqliteMultiTenant,
            "sqlite enforces tenant isolation in the application only; this database already has a tenant; \
             set CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1 to accept that, or use postgres"
                .to_owned(),
        )
    }

    /// `crawlx admin safety-audit` against SQLite.
    #[must_use]
    pub fn sqlite_safety_auditor() -> Self {
        Self::new(
            RefusalCode::SqliteSafetyAuditor,
            "the independent safety auditor needs two distinct database identities (reader and pauser); \
             sqlite has none"
                .to_owned(),
        )
    }

    /// The server reported `version`, which is not MariaDB 10.6 or newer.
    #[must_use]
    pub fn mariadb_unsupported_server(version: &str) -> Self {
        Self::new(
            RefusalCode::MariadbUnsupportedServer,
            format!("found {version}; mariadb 10.6 or newer is required (SKIP LOCKED, sequences)"),
        )
    }

    /// The server is a multi-primary cluster.
    #[must_use]
    pub fn mariadb_multi_primary() -> Self {
        Self::new(
            RefusalCode::MariadbMultiPrimary,
            "multi-primary cluster replication does not provide cluster-wide row locks; use a single primary"
                .to_owned(),
        )
    }

    /// `variable` must be `value` for the storage code to be correct.
    #[must_use]
    pub fn mariadb_settings(variable: &str, value: &str) -> Self {
        Self::new(
            RefusalCode::MariadbSettings,
            format!("{variable} must be {value}"),
        )
    }

    /// The request login holds `privilege`.
    #[must_use]
    pub fn mariadb_request_login(privilege: &str) -> Self {
        Self::new(
            RefusalCode::MariadbRequestLogin,
            format!("the request login must not hold {privilege}; see docs/ops/storage-backends.md"),
        )
    }

    /// The database URL uses an unknown scheme.
    #[must_use]
    pub fn scheme() -> Self {
        Self::new(
            RefusalCode::Scheme,
            "unsupported database url scheme; expected postgres, mariadb or sqlite".to_owned(),
        )
    }

    /// `serve` or `worker` without artifact custody.
    #[must_use]
    pub fn custody_missing() -> Self {
        Self::new(RefusalCode::CustodyMissing, CUSTODY_MISSING_MESSAGE.to_owned())
    }

    /// `engine` does not implement `capability` yet.
    #[must_use]
    pub fn unimplemented(engine: BackendKind, capability: &str) -> Self {
        Self::new(
            RefusalCode::BackendUnimplemented,
            format!("{capability} is not available on {engine} yet; use postgres"),
        )
    }
}

impl From<BackendRefusal> for StoreError {
    fn from(refusal: BackendRefusal) -> Self {
        Self::Conflict(refusal.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn messages_are_stable() {
        assert_eq!(
            BackendRefusal::scheme().to_string(),
            "refused: scheme: unsupported database url scheme; expected postgres, mariadb or sqlite"
        );
        assert_eq!(
            BackendRefusal::sqlite_second_worker(Path::new("/var/lib/crawlx/db.sqlite")).to_string(),
            "refused: sqlite_second_worker: another crawlx worker already holds \
             /var/lib/crawlx/db.sqlite.worker.lock; sqlite supports exactly one worker process per database \
             file; use mariadb or postgres for several workers"
        );
        assert_eq!(
            BackendRefusal::sqlite_not_local("/mnt/nfs/db").to_string(),
            "refused: sqlite_not_local: /mnt/nfs/db is not on a local filesystem that supports WAL; use a \
             local path or choose mariadb or postgres"
        );
        assert_eq!(
            BackendRefusal::sqlite_no_roles().to_string(),
            "refused: sqlite_no_roles: sqlite has no database roles; remove CRAWLX_API_DATABASE_URL (the API \
             uses the same file under application-enforced tenancy)"
        );
        assert_eq!(
            BackendRefusal::sqlite_multi_tenant().to_string(),
            "refused: sqlite_multi_tenant: sqlite enforces tenant isolation in the application only; this \
             database already has a tenant; set CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1 to accept that, or use \
             postgres"
        );
        assert_eq!(
            BackendRefusal::sqlite_safety_auditor().to_string(),
            "refused: sqlite_safety_auditor: the independent safety auditor needs two distinct database \
             identities (reader and pauser); sqlite has none"
        );
        assert_eq!(
            BackendRefusal::mariadb_unsupported_server("10.5.2-MariaDB").to_string(),
            "refused: mariadb_unsupported_server: found 10.5.2-MariaDB; mariadb 10.6 or newer is required \
             (SKIP LOCKED, sequences)"
        );
        assert_eq!(
            BackendRefusal::mariadb_multi_primary().to_string(),
            "refused: mariadb_multi_primary: multi-primary cluster replication does not provide cluster-wide \
             row locks; use a single primary"
        );
        assert_eq!(
            BackendRefusal::mariadb_settings("binlog_format", "ROW or MIXED").to_string(),
            "refused: mariadb_settings: binlog_format must be ROW or MIXED"
        );
        assert_eq!(
            BackendRefusal::mariadb_request_login("SUPER").to_string(),
            "refused: mariadb_request_login: the request login must not hold SUPER; see \
             docs/ops/storage-backends.md"
        );
        assert!(BackendRefusal::custody_missing()
            .to_string()
            .starts_with("refused: custody_missing: encrypted artifact custody is not configured"));
    }

    #[test]
    fn unimplemented_names_the_engine() {
        let refusal = BackendRefusal::unimplemented(BackendKind::Sqlite, "session claims");
        assert_eq!(
            refusal.to_string(),
            "refused: backend_unimplemented: session claims is not available on sqlite yet; use postgres"
        );
    }

    #[test]
    fn refusals_convert_to_store_conflicts() {
        let error = StoreError::from(BackendRefusal::scheme());
        assert!(matches!(&error, StoreError::Conflict(text) if text.starts_with("refused: scheme: ")));
    }
}
