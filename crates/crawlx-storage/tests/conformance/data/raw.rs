//! Raw statements for the data-plane cases: fixtures and read-backs that must not depend on
//! the repositories under test. A statement is written once in `$n` template notation
//! (PostgreSQL casts allowed, each placeholder used once and in order) and expanded for the
//! rig's engine.

use crate::rig::Rig;
use chrono::{DateTime, Utc};
use crawlx_core::Timestamp;
use crawlx_storage::backend::BackendKind;
use crawlx_storage::sql::Built;
use sqlx::Row as _;
use uuid::Uuid;

/// A value bound to a raw statement.
pub enum V<'a> {
    Uuid(Uuid),
    Text(&'a str),
    Bytes(&'a [u8]),
    Ts(Timestamp),
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

/// Raw statements against one rig.
pub struct Raw<'a>(pub &'a Rig);

impl Raw<'_> {
    fn text(&self, template: &str) -> String {
        Built::expand(self.0.kind().unwrap(), template).text().to_owned()
    }

    /// Run a statement; the rows it matched.
    pub async fn exec(&self, template: &str, args: &[V<'_>]) -> u64 {
        let sql = self.text(template);
        let database = self.0.database();
        match self.0.kind().unwrap() {
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

    /// The first column of the first row as a nullable timestamp.
    pub async fn timestamp(&self, template: &str, args: &[V<'_>]) -> Option<Timestamp> {
        let sql = self.text(template);
        let database = self.0.database();
        match self.0.kind().unwrap() {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_one(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .try_get::<Option<i64>, _>(0)
                .unwrap()
                .map(|micros| DateTime::from_timestamp_micros(micros).unwrap())
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_one(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .try_get::<Option<chrono::NaiveDateTime>, _>(0)
                .unwrap()
                .map(|naive| naive.and_utc())
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_one(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .try_get::<Option<DateTime<Utc>>, _>(0)
                .unwrap(),
        }
    }
}
