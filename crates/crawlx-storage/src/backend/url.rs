//! Parsing of database URLs into an engine and a connection string.

use crate::backend::{BackendKind, BackendRefusal};
use std::fmt;

/// A database URL whose scheme selected an engine.
///
/// `Debug` and [`DatabaseUrl::redacted`] never include credentials or query parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl {
    kind: BackendKind,
    raw: String,
}

impl DatabaseUrl {
    /// Choose the engine from the scheme: `postgres`/`postgresql`, `mariadb`/`mysql` or
    /// `sqlite`. Schemes compare case-insensitively.
    ///
    /// # Errors
    /// Returns the `scheme` refusal for any other scheme or a string without one.
    pub fn parse(url: &str) -> Result<Self, BackendRefusal> {
        let scheme = url
            .split_once(':')
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .ok_or_else(BackendRefusal::scheme)?;
        let kind = match scheme.as_str() {
            "postgres" | "postgresql" => BackendKind::Postgres,
            "mariadb" | "mysql" => BackendKind::MariaDb,
            "sqlite" => BackendKind::Sqlite,
            _ => return Err(BackendRefusal::scheme()),
        };
        Ok(Self {
            kind,
            raw: url.to_owned(),
        })
    }

    /// The engine the scheme selected.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        self.kind
    }

    /// The URL as given. It may carry a password: pass it to the driver only, never to a log.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.raw
    }

    /// A form safe for logs and error messages: scheme, host, port and database or file
    /// path. Credentials and query parameters are dropped.
    #[must_use]
    pub fn redacted(&self) -> String {
        match self.kind {
            BackendKind::Sqlite => {
                let rest = self.raw.split_once(':').map_or("", |(_, rest)| rest);
                let path = rest.split_once('?').map_or(rest, |(path, _)| path);
                format!("sqlite:{path}")
            }
            BackendKind::Postgres | BackendKind::MariaDb => match url::Url::parse(&self.raw) {
                Ok(parsed) => {
                    let mut out = format!("{}://", parsed.scheme());
                    if let Some(host) = parsed.host_str() {
                        out.push_str(host);
                    }
                    if let Some(port) = parsed.port() {
                        out.push(':');
                        out.push_str(&port.to_string());
                    }
                    out.push_str(parsed.path());
                    out
                }
                Err(_) => format!("{}://<unparsable>", self.kind.scheme()),
            },
        }
    }

    /// Whether this is a SQLite in-memory database (`:memory:` or `mode=memory`).
    #[must_use]
    pub fn is_sqlite_memory(&self) -> bool {
        self.kind == BackendKind::Sqlite
            && (self.raw.contains(":memory:") || self.raw.contains("mode=memory"))
    }

    /// The filesystem path of a SQLite URL, when it names a file.
    #[must_use]
    pub fn sqlite_path(&self) -> Option<std::path::PathBuf> {
        if self.kind != BackendKind::Sqlite || self.is_sqlite_memory() {
            return None;
        }
        let rest = self.raw.split_once(':').map_or("", |(_, rest)| rest);
        let rest = rest.split_once('?').map_or(rest, |(path, _)| path);
        // `sqlite://x.db` and `sqlite:///abs/x.db` use authority syntax; `sqlite:x.db` and
        // `sqlite:/abs/x.db` do not; `sqlite:file:x.db` names a `file:` URI.
        let path = rest.strip_prefix("//").unwrap_or(rest);
        let path = path.strip_prefix("file:").unwrap_or(path);
        if path.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(path))
        }
    }

    /// The same URL with the database or file name replaced; used by test rigs.
    #[must_use]
    pub fn with_database(&self, database: &str) -> Option<Self> {
        match self.kind {
            BackendKind::Sqlite => Some(Self {
                kind: self.kind,
                raw: format!("sqlite://{database}"),
            }),
            BackendKind::Postgres | BackendKind::MariaDb => {
                let mut parsed = url::Url::parse(&self.raw).ok()?;
                parsed.set_path(&format!("/{database}"));
                Some(Self {
                    kind: self.kind,
                    raw: parsed.to_string(),
                })
            }
        }
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseUrl")
            .field("kind", &self.kind)
            .field("target", &self.redacted())
            .finish()
    }
}

impl fmt::Display for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::backend::RefusalCode;

    #[test]
    fn schemes_select_engines() {
        for (url, kind) in [
            ("postgres://u:p@h/db", BackendKind::Postgres),
            ("postgresql://u:p@h/db", BackendKind::Postgres),
            ("POSTGRES://u:p@h/db", BackendKind::Postgres),
            ("mariadb://u:p@h/db", BackendKind::MariaDb),
            ("mysql://u:p@h:3317/db", BackendKind::MariaDb),
            ("sqlite:///var/lib/crawlx/db.sqlite", BackendKind::Sqlite),
            ("sqlite:db.sqlite", BackendKind::Sqlite),
        ] {
            assert_eq!(DatabaseUrl::parse(url).unwrap().kind(), kind, "{url}");
        }
    }

    #[test]
    fn unknown_schemes_are_refused() {
        for url in ["oracle://h/db", "http://h/db", "file:/x.db", "nonsense", ""] {
            let refusal = DatabaseUrl::parse(url).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::Scheme, "{url}");
            assert_eq!(
                refusal.to_string(),
                "refused: scheme: unsupported database url scheme; expected postgres, mariadb or sqlite"
            );
        }
    }

    #[test]
    fn debug_and_display_never_show_credentials() {
        let url =
            DatabaseUrl::parse("mysql://crawlx:hunter2@db.internal:3317/crawlx?ssl-ca=/secret").unwrap();
        for text in [format!("{url:?}"), url.to_string(), url.redacted()] {
            assert!(!text.contains("hunter2"), "{text}");
            assert!(!text.contains("crawlx:"), "{text}");
            assert!(!text.contains("ssl-ca"), "{text}");
        }
        assert_eq!(url.redacted(), "mysql://db.internal:3317/crawlx");
        assert_eq!(
            url.expose(),
            "mysql://crawlx:hunter2@db.internal:3317/crawlx?ssl-ca=/secret"
        );
    }

    #[test]
    fn sqlite_paths_and_memory() {
        let memory = DatabaseUrl::parse("sqlite::memory:").unwrap();
        assert!(memory.is_sqlite_memory());
        assert!(memory.sqlite_path().is_none());
        assert!(DatabaseUrl::parse("sqlite://?mode=memory")
            .unwrap()
            .is_sqlite_memory());
        for (url, path) in [
            ("sqlite:///abs/x.db", "/abs/x.db"),
            ("sqlite:/abs/x.db", "/abs/x.db"),
            ("sqlite:x.db?mode=rwc", "x.db"),
            ("sqlite://x.db", "x.db"),
            ("sqlite:file:x.db", "x.db"),
        ] {
            let parsed = DatabaseUrl::parse(url).unwrap();
            assert!(!parsed.is_sqlite_memory());
            assert_eq!(
                parsed.sqlite_path().unwrap(),
                std::path::PathBuf::from(path),
                "{url}"
            );
        }
        assert_eq!(
            DatabaseUrl::parse("sqlite:///abs/x.db?mode=rwc")
                .unwrap()
                .redacted(),
            "sqlite:///abs/x.db"
        );
    }

    #[test]
    fn database_swap_keeps_credentials_out_of_view() {
        let url = DatabaseUrl::parse("mysql://crawlx:crawlx@127.0.0.1:3317/crawlx_test").unwrap();
        let swapped = url.with_database("t_abc").unwrap();
        assert_eq!(swapped.expose(), "mysql://crawlx:crawlx@127.0.0.1:3317/t_abc");
        assert_eq!(swapped.redacted(), "mysql://127.0.0.1:3317/t_abc");
    }
}
