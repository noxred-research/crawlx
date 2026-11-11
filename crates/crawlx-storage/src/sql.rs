//! Typed statements shared by every engine.
//!
//! Repository SQL is written once, as a template with PostgreSQL-style `$n` placeholders and
//! `Dialect` fragments spliced in with `format!`. [`SqlCell`] expands the template per engine
//! the first time it is needed and keeps the result for the life of the process, so prepared
//! statement caching works and no statement text is rebuilt per call:
//!
//! * PostgreSQL keeps the template byte for byte.
//! * SQLite gets `?n`.
//! * MariaDB gets positional `?`; a placeholder that occurs twice or out of order is bound
//!   again in the order the text needs (see [`Built::order`]).
//! * On SQLite and MariaDB every `::type` cast outside string literals is dropped, so the
//!   template may keep the PostgreSQL casts (`$3::text::run_status`, `status::text`).
//!
//! A [`Stmt`] collects typed binds ([`Arg`]) and runs through [`Sql`], which owns the three
//! pieces that differ per engine: how a value is bound (timestamps are `timestamptz`,
//! naive UTC `DATETIME(6)` or integer microseconds; JSON is `jsonb` or text), how a column is
//! decoded ([`SqlRow`]) and how a statement reaches a pool or a connection.
//!
//! Every write on SQLite must start with `BEGIN IMMEDIATE`: use [`Store::begin_write`] for a
//! transaction and [`Stmt::execute_write`] / [`Stmt::fetch_optional_write`] for a lone
//! statement. A single-statement write on PostgreSQL and MariaDB runs on the pool directly.

use crate::backend::strategy::{Concurrency, Conn, Timestamp, WriteTx};
use crate::backend::{Backend, BackendKind, MariaBackend, PgBackend, SqliteBackend};
use crate::codec::{from_json_text, to_json_text, ts_from_micros};
use crate::error::db;
use crate::store::Store;
use crawlx_core::StoreError;
use sqlx::mysql::{MySql, MySqlRow};
use sqlx::postgres::{PgRow, Postgres};
use sqlx::sqlite::{Sqlite, SqliteRow};
use sqlx::{AssertSqlSafe, Row as _, SqlStr};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use uuid::Uuid;

/// One expanded statement: the text of an engine and the order MariaDB binds in.
#[derive(Clone, Debug)]
pub struct Built {
    sql: SqlStr,
    /// MariaDB only: the 1-based parameter bound at each `?`, in text order. Empty elsewhere.
    order: Vec<u16>,
    /// Highest parameter number (`$n`) the template uses.
    params: usize,
    /// Whether the driver may cache the prepared statement (the default).
    persistent: bool,
}

impl Built {
    /// The statement text for `kind` expanded from a template (see the module docs).
    #[must_use]
    pub fn expand(kind: BackendKind, template: &str) -> Self {
        let bytes = template.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 8);
        let mut order = Vec::new();
        let mut params = 0_usize;
        let mut quoted = false;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\'' {
                quoted = !quoted;
                out.push(b);
                i += 1;
                continue;
            }
            if quoted {
                out.push(b);
                i += 1;
                continue;
            }
            if b == b'$' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
                let mut j = i + 1;
                let mut n = 0_usize;
                while let Some(d) = bytes.get(j).filter(|c| c.is_ascii_digit()) {
                    n = n.saturating_mul(10).saturating_add(usize::from(d - b'0'));
                    j += 1;
                }
                params = params.max(n);
                match kind {
                    BackendKind::Sqlite => {
                        out.push(b'?');
                        out.extend_from_slice(n.to_string().as_bytes());
                    }
                    BackendKind::MariaDb => {
                        out.push(b'?');
                        order.push(u16::try_from(n).unwrap_or(u16::MAX));
                    }
                    _ => out.extend_from_slice(&bytes[i..j]),
                }
                i = j;
                continue;
            }
            if kind != BackendKind::Postgres
                && b == b':'
                && bytes.get(i + 1) == Some(&b':')
                && bytes
                    .get(i + 2)
                    .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            {
                let mut j = i + 2;
                while bytes
                    .get(j)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    j += 1;
                }
                if bytes.get(j) == Some(&b'[') && bytes.get(j + 1) == Some(&b']') {
                    j += 2;
                }
                i = j;
                continue;
            }
            out.push(b);
            i += 1;
        }
        let text = String::from_utf8_lossy(&out).into_owned();
        Self {
            sql: AssertSqlSafe(text).into_sql_str_owned(),
            order,
            params,
            persistent: true,
        }
    }

    /// The expanded statement text.
    #[must_use]
    pub fn text(&self) -> &str {
        self.sql.as_str()
    }
}

/// `into_sql_str` without importing the sealed-looking trait at every use.
trait IntoSqlStr {
    fn into_sql_str_owned(self) -> SqlStr;
}

impl IntoSqlStr for AssertSqlSafe<String> {
    fn into_sql_str_owned(self) -> SqlStr {
        use sqlx::SqlSafeStr as _;
        self.into_sql_str()
    }
}

/// A statement template expanded once per engine.
///
/// Declare one `static` per statement (the `stmt!` macro does) and ask for the engine's
/// expansion with [`SqlCell::get`].
#[derive(Debug, Default)]
pub struct SqlCell {
    pg: OnceLock<Built>,
    mariadb: OnceLock<Built>,
    sqlite: OnceLock<Built>,
}

impl SqlCell {
    /// An empty cell.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pg: OnceLock::new(),
            mariadb: OnceLock::new(),
            sqlite: OnceLock::new(),
        }
    }

    /// The expansion for `B`, built from `template` on first use.
    pub fn get<B: Backend>(&'static self, template: impl FnOnce() -> String) -> &'static Built {
        let cell = match B::KIND {
            BackendKind::Postgres => &self.pg,
            BackendKind::MariaDb => &self.mariadb,
            _ => &self.sqlite,
        };
        cell.get_or_init(|| Built::expand(B::KIND, &template()))
    }
}

/// A statement of a repository, expanded once per engine and executed through [`Stmt`].
///
/// `stmt!(B, "SELECT .. $1")` for plain text; `stmt!(B, format!("..{}..", B::Dialect::now()))`
/// when the text needs `Dialect` fragments. The expression is evaluated once per engine.
macro_rules! stmt {
    ($backend:ty, $template:expr) => {{
        static CELL: $crate::sql::SqlCell = $crate::sql::SqlCell::new();
        $crate::sql::Stmt::<$backend>::from_built(
            CELL.get::<$backend>(|| ::std::string::String::from($template)),
        )
    }};
}
pub(crate) use stmt;

/// One bound value. Borrowed data lives as long as the statement is being built.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Arg<'a> {
    /// `uuid` / `BINARY(16)` / 16-byte `BLOB`.
    Uuid(Uuid),
    /// Nullable [`Arg::Uuid`].
    OptUuid(Option<Uuid>),
    /// `smallint`.
    I16(i16),
    /// Nullable [`Arg::I16`].
    OptI16(Option<i16>),
    /// `integer`.
    I32(i32),
    /// Nullable [`Arg::I32`].
    OptI32(Option<i32>),
    /// `bigint`.
    I64(i64),
    /// Nullable [`Arg::I64`].
    OptI64(Option<i64>),
    /// `real`.
    F32(f32),
    /// Nullable [`Arg::F32`].
    OptF32(Option<f32>),
    /// `double precision`.
    F64(f64),
    /// Nullable [`Arg::F64`].
    OptF64(Option<f64>),
    /// `boolean`.
    Bool(bool),
    /// Nullable [`Arg::Bool`].
    OptBool(Option<bool>),
    /// `text`.
    Text(&'a str),
    /// Nullable [`Arg::Text`].
    OptText(Option<&'a str>),
    /// `bytea` / `BLOB`.
    Bytes(&'a [u8]),
    /// Nullable [`Arg::Bytes`].
    OptBytes(Option<&'a [u8]>),
    /// A point in time.
    Ts(Timestamp),
    /// Nullable [`Arg::Ts`].
    OptTs(Option<Timestamp>),
    /// A JSON value (`jsonb`, or compact JSON text).
    Json(&'a serde_json::Value),
    /// Nullable [`Arg::Json`].
    OptJson(Option<&'a serde_json::Value>),
    /// A `uuid[]` array parameter; PostgreSQL only (other engines expand a list into
    /// individual [`Arg::Uuid`] binds, see [`Stmt::uuid_list`]).
    UuidList(&'a [Uuid]),
    /// An `int8[]` array parameter; PostgreSQL only (other engines expand a list into
    /// individual [`Arg::I64`] binds, see [`Stmt::i64_list`]).
    I64List(&'a [i64]),
    /// A `text[]` array on PostgreSQL, a JSON array of strings elsewhere.
    TextList(&'a [String]),
    /// Nullable [`Arg::TextList`].
    OptTextList(Option<&'a [String]>),
}

/// Typed column access on a driver row. Every accessor fails with [`StoreError`] when the
/// column is missing, null (for the non-optional forms) or of another type.
#[allow(
    clippy::missing_errors_doc,
    reason = "one contract for every accessor, stated on the trait"
)]
pub trait SqlRow {
    /// A `uuid` column.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the column is missing, null or of another type. The same
    /// holds for every accessor of this trait.
    fn uuid(&self, col: &str) -> Result<Uuid, StoreError>;
    /// A nullable `uuid` column.
    fn opt_uuid(&self, col: &str) -> Result<Option<Uuid>, StoreError>;
    /// A `smallint` column.
    fn i16(&self, col: &str) -> Result<i16, StoreError>;
    /// A nullable `smallint` column.
    fn opt_i16(&self, col: &str) -> Result<Option<i16>, StoreError>;
    /// An `integer` column.
    fn i32(&self, col: &str) -> Result<i32, StoreError>;
    /// A nullable `integer` column.
    fn opt_i32(&self, col: &str) -> Result<Option<i32>, StoreError>;
    /// A `bigint` column.
    fn i64(&self, col: &str) -> Result<i64, StoreError>;
    /// A nullable `bigint` column.
    fn opt_i64(&self, col: &str) -> Result<Option<i64>, StoreError>;
    /// A `real` column.
    fn f32(&self, col: &str) -> Result<f32, StoreError>;
    /// A nullable `real` column.
    fn opt_f32(&self, col: &str) -> Result<Option<f32>, StoreError>;
    /// A `double precision` column.
    fn f64(&self, col: &str) -> Result<f64, StoreError>;
    /// A nullable `double precision` column.
    fn opt_f64(&self, col: &str) -> Result<Option<f64>, StoreError>;
    /// A `boolean` column.
    fn bool(&self, col: &str) -> Result<bool, StoreError>;
    /// A nullable `boolean` column.
    fn opt_bool(&self, col: &str) -> Result<Option<bool>, StoreError>;
    /// A `text` column.
    fn text(&self, col: &str) -> Result<String, StoreError>;
    /// A nullable `text` column.
    fn opt_text(&self, col: &str) -> Result<Option<String>, StoreError>;
    /// A `bytea` column.
    fn bytes(&self, col: &str) -> Result<Vec<u8>, StoreError>;
    /// A nullable `bytea` column.
    fn opt_bytes(&self, col: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// A timestamp column.
    fn ts(&self, col: &str) -> Result<Timestamp, StoreError>;
    /// A nullable timestamp column.
    fn opt_ts(&self, col: &str) -> Result<Option<Timestamp>, StoreError>;
    /// A JSON column.
    fn json(&self, col: &str) -> Result<serde_json::Value, StoreError>;
    /// A nullable JSON column (SQL `NULL`; a JSON `null` is `Some(Value::Null)`).
    fn opt_json(&self, col: &str) -> Result<Option<serde_json::Value>, StoreError>;
    /// A boolean that may be a computed expression: `boolean` on PostgreSQL, `0`/`1` of any
    /// integer width elsewhere. Use it for `a = b` style result columns; stored boolean
    /// columns read with [`SqlRow::bool`].
    fn flag(&self, col: &str) -> Result<bool, StoreError>;
    /// Nullable [`SqlRow::flag`].
    fn opt_flag(&self, col: &str) -> Result<Option<bool>, StoreError>;
    /// A `text[]` column on PostgreSQL, a JSON array of strings elsewhere.
    fn text_list(&self, col: &str) -> Result<Vec<String>, StoreError>;
    /// Nullable [`SqlRow::text_list`].
    fn opt_text_list(&self, col: &str) -> Result<Option<Vec<String>>, StoreError>;
}

macro_rules! plain_row_accessors {
    ($($name:ident, $opt:ident: $ty:ty;)+) => {$(
        fn $name(&self, col: &str) -> Result<$ty, StoreError> {
            self.try_get::<$ty, _>(col).map_err(db)
        }
        fn $opt(&self, col: &str) -> Result<Option<$ty>, StoreError> {
            self.try_get::<Option<$ty>, _>(col).map_err(db)
        }
    )+};
}

/// Integers of at most 32 bits: PostgreSQL columns are exact, MariaDB and SQLite decode through
/// `i64` and narrow with a range check, so `INT` and `BIGINT` columns both read.
macro_rules! narrow_row_accessors {
    ($($name:ident, $opt:ident: $ty:ty;)+) => {$(
        fn $name(&self, col: &str) -> Result<$ty, StoreError> {
            let wide = self.try_get::<i64, _>(col).map_err(db)?;
            <$ty>::try_from(wide).map_err(|_| StoreError::Serialization(format!("column {col} out of range")))
        }
        fn $opt(&self, col: &str) -> Result<Option<$ty>, StoreError> {
            self.try_get::<Option<i64>, _>(col)
                .map_err(db)?
                .map(|wide| {
                    <$ty>::try_from(wide)
                        .map_err(|_| StoreError::Serialization(format!("column {col} out of range")))
                })
                .transpose()
        }
    )+};
}

macro_rules! impl_sql_row {
    (
        $row:ty,
        ints: $ints:ident,
        ts: $ts:expr, opt_ts: $opt_ts:expr,
        json: $json:expr, opt_json: $opt_json:expr,
        flag: $flag:expr, opt_flag: $opt_flag:expr,
        list: $list:expr, opt_list: $opt_list:expr
    ) => {
        impl SqlRow for $row {
            plain_row_accessors! {
                uuid, opt_uuid: Uuid;
                i64, opt_i64: i64;
                f32, opt_f32: f32;
                f64, opt_f64: f64;
                bool, opt_bool: bool;
                text, opt_text: String;
                bytes, opt_bytes: Vec<u8>;
            }
            $ints! {
                i16, opt_i16: i16;
                i32, opt_i32: i32;
            }
            fn flag(&self, col: &str) -> Result<bool, StoreError> {
                ($flag)(self, col)
            }
            fn opt_flag(&self, col: &str) -> Result<Option<bool>, StoreError> {
                ($opt_flag)(self, col)
            }
            fn ts(&self, col: &str) -> Result<Timestamp, StoreError> {
                ($ts)(self, col)
            }
            fn opt_ts(&self, col: &str) -> Result<Option<Timestamp>, StoreError> {
                ($opt_ts)(self, col)
            }
            fn json(&self, col: &str) -> Result<serde_json::Value, StoreError> {
                ($json)(self, col)
            }
            fn opt_json(&self, col: &str) -> Result<Option<serde_json::Value>, StoreError> {
                ($opt_json)(self, col)
            }
            fn text_list(&self, col: &str) -> Result<Vec<String>, StoreError> {
                ($list)(self, col)
            }
            fn opt_text_list(&self, col: &str) -> Result<Option<Vec<String>>, StoreError> {
                ($opt_list)(self, col)
            }
        }
    };
}

macro_rules! direct_ints {
    ($($name:ident, $opt:ident: $ty:ty;)+) => {
        plain_row_accessors! { $($name, $opt: $ty;)+ }
    };
}

/// A MariaDB instant column. Stored columns are `DATETIME(6)`; the server reports its clock
/// functions (`SYSDATE(6)`) as `TIMESTAMP`, which sqlx only decodes as a zoned instant. Sessions
/// run in UTC, so both are the same instant.
fn maria_ts(row: &MySqlRow, col: &str) -> Result<Option<Timestamp>, StoreError> {
    match row.try_get::<Option<chrono::NaiveDateTime>, _>(col) {
        Ok(naive) => Ok(naive.map(|naive| naive.and_utc())),
        Err(sqlx::Error::ColumnDecode { .. }) => row.try_get::<Option<Timestamp>, _>(col).map_err(db),
        Err(other) => Err(db(other)),
    }
}

/// A JSON text column holding an array of strings.
fn text_array(text: &str) -> Result<Vec<String>, StoreError> {
    serde_json::from_str(text).map_err(|e| StoreError::Serialization(e.to_string()))
}

impl_sql_row!(
    PgRow,
    ints: direct_ints,
    ts: |row: &PgRow, col: &str| row.try_get::<Timestamp, _>(col).map_err(db),
    opt_ts: |row: &PgRow, col: &str| row.try_get::<Option<Timestamp>, _>(col).map_err(db),
    json: |row: &PgRow, col: &str| row.try_get::<serde_json::Value, _>(col).map_err(db),
    opt_json: |row: &PgRow, col: &str| row.try_get::<Option<serde_json::Value>, _>(col).map_err(db),
    flag: |row: &PgRow, col: &str| row.try_get::<bool, _>(col).map_err(db),
    opt_flag: |row: &PgRow, col: &str| row.try_get::<Option<bool>, _>(col).map_err(db),
    list: |row: &PgRow, col: &str| row.try_get::<Vec<String>, _>(col).map_err(db),
    opt_list: |row: &PgRow, col: &str| row.try_get::<Option<Vec<String>>, _>(col).map_err(db)
);

impl_sql_row!(
    MySqlRow,
    ints: narrow_row_accessors,
    ts: |row: &MySqlRow, col: &str| maria_ts(row, col)
        .and_then(|ts| ts.ok_or_else(|| StoreError::Serialization(format!("column {col} is NULL")))),
    opt_ts: |row: &MySqlRow, col: &str| maria_ts(row, col),
    json: |row: &MySqlRow, col: &str| from_json_text(&row.try_get::<String, _>(col).map_err(db)?),
    opt_json: |row: &MySqlRow, col: &str| row
        .try_get::<Option<String>, _>(col)
        .map_err(db)?
        .map(|text| from_json_text(&text))
        .transpose(),
    flag: |row: &MySqlRow, col: &str| row.try_get::<i64, _>(col).map(|v| v != 0).map_err(db),
    opt_flag: |row: &MySqlRow, col: &str| row
        .try_get::<Option<i64>, _>(col)
        .map(|v| v.map(|v| v != 0))
        .map_err(db),
    list: |row: &MySqlRow, col: &str| text_array(&row.try_get::<String, _>(col).map_err(db)?),
    opt_list: |row: &MySqlRow, col: &str| row
        .try_get::<Option<String>, _>(col)
        .map_err(db)?
        .map(|text| text_array(&text))
        .transpose()
);

impl_sql_row!(
    SqliteRow,
    ints: narrow_row_accessors,
    ts: |row: &SqliteRow, col: &str| ts_from_micros(row.try_get::<i64, _>(col).map_err(db)?),
    opt_ts: |row: &SqliteRow, col: &str| row
        .try_get::<Option<i64>, _>(col)
        .map_err(db)?
        .map(ts_from_micros)
        .transpose(),
    json: |row: &SqliteRow, col: &str| from_json_text(&row.try_get::<String, _>(col).map_err(db)?),
    opt_json: |row: &SqliteRow, col: &str| row
        .try_get::<Option<String>, _>(col)
        .map_err(db)?
        .map(|text| from_json_text(&text))
        .transpose(),
    flag: |row: &SqliteRow, col: &str| row.try_get::<i64, _>(col).map(|v| v != 0).map_err(db),
    opt_flag: |row: &SqliteRow, col: &str| row
        .try_get::<Option<i64>, _>(col)
        .map(|v| v.map(|v| v != 0))
        .map_err(db),
    list: |row: &SqliteRow, col: &str| text_array(&row.try_get::<String, _>(col).map_err(db)?),
    opt_list: |row: &SqliteRow, col: &str| row
        .try_get::<Option<String>, _>(col)
        .map_err(db)?
        .map(|text| text_array(&text))
        .transpose()
);

/// An engine's statement execution: binding, rows and the pool or connection to run on.
///
/// Implemented for the three backends in this module; repositories are generic over it and
/// reach it through [`Stmt`].
pub trait Sql: Concurrency {
    /// The driver row type, decoded through [`SqlRow`].
    type Row: SqlRow + Send + Sync + Unpin + 'static;

    /// Run on `conn`, returning the rows affected (matched, on MariaDB).
    fn execute<'a>(
        conn: &'a mut Conn<Self>,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<u64, StoreError>> + Send + 'a;

    /// Run on `conn`, returning every row.
    fn fetch_all<'a>(
        conn: &'a mut Conn<Self>,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<Vec<Self::Row>, StoreError>> + Send + 'a;

    /// Run on `conn`, returning the first row if any.
    fn fetch_optional<'a>(
        conn: &'a mut Conn<Self>,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<Option<Self::Row>, StoreError>> + Send + 'a;

    /// Run on the pool (tenant-scoped on PostgreSQL), returning the rows affected.
    fn execute_pool<'a>(
        pool: &'a Self::Pool,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<u64, StoreError>> + Send + 'a;

    /// Run on the pool, returning every row.
    fn fetch_all_pool<'a>(
        pool: &'a Self::Pool,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<Vec<Self::Row>, StoreError>> + Send + 'a;

    /// Run on the pool, returning the first row if any.
    fn fetch_optional_pool<'a>(
        pool: &'a Self::Pool,
        built: &'a Built,
        args: &'a [Arg<'a>],
    ) -> impl Future<Output = Result<Option<Self::Row>, StoreError>> + Send + 'a;
}

/// Check the bind count against the template and report the order to bind in.
fn plan<'b>(built: &'b Built, args: &[Arg<'_>]) -> Result<Plan<'b>, StoreError> {
    if built.order.is_empty() {
        if args.len() == built.params {
            return Ok(Plan::Sequential);
        }
    } else if args.len() == built.params {
        return Ok(Plan::Ordered(&built.order));
    }
    Err(StoreError::Backend(format!(
        "statement binds {} values for {} parameters",
        args.len(),
        built.params
    )))
}

enum Plan<'b> {
    Sequential,
    Ordered(&'b [u16]),
}

/// The argument bound at position `at` of `plan`.
fn nth<'x, 'a>(plan: &Plan<'_>, args: &'x [Arg<'a>], at: usize) -> Option<&'x Arg<'a>> {
    match plan {
        Plan::Sequential => args.get(at),
        Plan::Ordered(order) => order
            .get(at)
            .and_then(|n| usize::from(*n).checked_sub(1))
            .and_then(|index| args.get(index)),
    }
}

/// How many binds a statement makes: one per parameter, or one per `?` on MariaDB.
fn bind_count(plan: &Plan<'_>, args: &[Arg<'_>]) -> usize {
    match plan {
        Plan::Sequential => args.len(),
        Plan::Ordered(order) => order.len(),
    }
}

macro_rules! bind_arm {
    (
        $q:ident, $arg:expr,
        ts: $ts:expr, opt_ts: $opt_ts:expr,
        json: $json:expr, opt_json: $opt_json:expr,
        list: $list:expr,
        ilist: $ilist:expr,
        texts: $texts:expr, opt_texts: $opt_texts:expr
    ) => {
        match $arg {
            Arg::Uuid(v) => $q.bind(*v),
            Arg::OptUuid(v) => $q.bind(*v),
            Arg::I16(v) => $q.bind(*v),
            Arg::OptI16(v) => $q.bind(*v),
            Arg::I32(v) => $q.bind(*v),
            Arg::OptI32(v) => $q.bind(*v),
            Arg::I64(v) => $q.bind(*v),
            Arg::OptI64(v) => $q.bind(*v),
            Arg::F32(v) => $q.bind(*v),
            Arg::OptF32(v) => $q.bind(*v),
            Arg::F64(v) => $q.bind(*v),
            Arg::OptF64(v) => $q.bind(*v),
            Arg::Bool(v) => $q.bind(*v),
            Arg::OptBool(v) => $q.bind(*v),
            Arg::Text(v) => $q.bind(*v),
            Arg::OptText(v) => $q.bind(*v),
            Arg::Bytes(v) => $q.bind(*v),
            Arg::OptBytes(v) => $q.bind(*v),
            Arg::Ts(v) => $q.bind(($ts)(*v)),
            Arg::OptTs(v) => $q.bind(($opt_ts)(*v)),
            Arg::Json(v) => $q.bind(($json)(*v)),
            Arg::OptJson(v) => $q.bind(($opt_json)(*v)),
            Arg::UuidList(v) => $q.bind(($list)(*v)),
            Arg::I64List(v) => $q.bind(($ilist)(*v)),
            Arg::TextList(v) => $q.bind(($texts)(*v)),
            Arg::OptTextList(v) => $q.bind(($opt_texts)(*v)),
        }
    };
}

/// The error for an array bind on an engine without array parameters.
fn no_arrays() -> StoreError {
    StoreError::Backend("array parameters exist only on postgresql; expand the list".to_owned())
}

/// The JSON array text of a string list (MariaDB and SQLite keep lists as JSON text).
fn text_json(list: &[String]) -> String {
    serde_json::to_string(list).unwrap_or_else(|_| "[]".to_owned())
}

/// A value bound as it is (PostgreSQL encodes JSON, timestamps and arrays natively).
const fn same<T>(value: T) -> T {
    value
}

fn bind_pg(
    built: &Built,
    args: &[Arg<'_>],
) -> Result<sqlx::query::Query<'static, Postgres, <Postgres as sqlx::Database>::Arguments>, StoreError> {
    let plan = plan(built, args)?;
    let mut q = sqlx::query::<Postgres>(built.sql.clone()).persistent(built.persistent);
    for at in 0..bind_count(&plan, args) {
        let Some(arg) = nth(&plan, args, at) else {
            return Err(StoreError::Backend(
                "statement bind order out of range".to_owned(),
            ));
        };
        q = bind_arm!(
            q, arg,
            ts: |t: Timestamp| t,
            opt_ts: |t: Option<Timestamp>| t,
            json: same,
            opt_json: same,
            list: same,
            ilist: same,
            texts: same,
            opt_texts: same
        );
    }
    Ok(q)
}

/// The smallest `max_allowed_packet` any MariaDB pool of this process reported; `0` until one
/// did. The server drops the connection on a larger packet, which no retry can fix, so
/// [`bind_mariadb`] refuses such a statement before it is sent.
static MARIADB_MAX_PACKET: AtomicU64 = AtomicU64::new(0);

/// Per-bind framing allowance (type tag, length prefix, null bitmap) of the estimate.
const PACKET_BIND_OVERHEAD: usize = 16;

/// Fixed allowance for the packet header and the command.
const PACKET_FIXED_OVERHEAD: usize = 64;

/// A statement the MariaDB server would refuse for its size.
#[derive(Debug, thiserror::Error)]
#[error("statement of about {size} bytes exceeds the server limit max_allowed_packet of {limit} bytes")]
pub struct StatementTooLarge {
    /// The estimated size of the statement packet.
    pub size: u64,
    /// The server's `max_allowed_packet`.
    pub limit: u64,
}

/// Record the `max_allowed_packet` a MariaDB server reported at connect time. The smallest
/// value seen wins, so a statement is never sent that any known server would refuse.
pub(crate) fn note_mariadb_max_packet(limit: u64) {
    if limit == 0 {
        return;
    }
    // The update closure always returns `Some`, so `try_update` cannot fail.
    let _ = MARIADB_MAX_PACKET.try_update(Ordering::Relaxed, Ordering::Relaxed, |known| {
        Some(if known == 0 { limit } else { known.min(limit) })
    });
}

/// Counts the bytes a value serializes to without keeping them.
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The bytes one bound value adds to the statement packet, beyond [`PACKET_BIND_OVERHEAD`].
fn payload_len(arg: &Arg<'_>) -> usize {
    let json = |value: &serde_json::Value| {
        let mut count = ByteCount(0);
        // an unserializable value fails at bind time with its own error
        let _ = serde_json::to_writer(&mut count, value);
        count.0
    };
    let list = |list: &[String]| list.iter().map(|item| item.len() + 3).sum::<usize>() + 2;
    match arg {
        Arg::Text(v) | Arg::OptText(Some(v)) => v.len(),
        Arg::Bytes(v) | Arg::OptBytes(Some(v)) => v.len(),
        Arg::Json(v) | Arg::OptJson(Some(v)) => json(v),
        Arg::TextList(v) | Arg::OptTextList(Some(v)) => list(v),
        _ => 0,
    }
}

/// Refuse a statement larger than the server's `max_allowed_packet`.
fn check_mariadb_packet(built: &Built, plan: &Plan<'_>, args: &[Arg<'_>]) -> Result<(), StoreError> {
    let limit = MARIADB_MAX_PACKET.load(Ordering::Relaxed);
    if limit == 0 {
        return Ok(());
    }
    let mut size = built.text().len().saturating_add(PACKET_FIXED_OVERHEAD);
    for at in 0..bind_count(plan, args) {
        if let Some(arg) = nth(plan, args, at) {
            size = size
                .saturating_add(PACKET_BIND_OVERHEAD)
                .saturating_add(payload_len(arg));
        }
    }
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    if size > limit {
        return Err(StoreError::Database {
            source: Box::new(StatementTooLarge { size, limit }),
            retryable: false,
        });
    }
    Ok(())
}

fn bind_mariadb(
    built: &Built,
    args: &[Arg<'_>],
) -> Result<sqlx::query::Query<'static, MySql, <MySql as sqlx::Database>::Arguments>, StoreError> {
    let plan = plan(built, args)?;
    check_mariadb_packet(built, &plan, args)?;
    let mut q = sqlx::query::<MySql>(built.sql.clone()).persistent(built.persistent);
    for at in 0..bind_count(&plan, args) {
        let Some(arg) = nth(&plan, args, at) else {
            return Err(StoreError::Backend(
                "statement bind order out of range".to_owned(),
            ));
        };
        if matches!(arg, Arg::UuidList(_) | Arg::I64List(_)) {
            return Err(no_arrays());
        }
        q = match arg {
            Arg::UuidList(_) | Arg::I64List(_) => q,
            other => bind_arm!(
                q, other,
                ts: |t: Timestamp| t.naive_utc(),
                opt_ts: |t: Option<Timestamp>| t.map(|t| t.naive_utc()),
                json: |v: &serde_json::Value| to_json_text(v),
                opt_json: |v: Option<&serde_json::Value>| v.map(to_json_text),
                list: |_v: &[Uuid]| 0_i64,
                ilist: |_v: &[i64]| 0_i64,
                texts: |v: &[String]| text_json(v),
                opt_texts: |v: Option<&[String]>| v.map(text_json)
            ),
        };
    }
    Ok(q)
}

fn bind_sqlite(
    built: &Built,
    args: &[Arg<'_>],
) -> Result<sqlx::query::Query<'static, Sqlite, <Sqlite as sqlx::Database>::Arguments>, StoreError> {
    let plan = plan(built, args)?;
    let mut q = sqlx::query::<Sqlite>(built.sql.clone()).persistent(built.persistent);
    for at in 0..bind_count(&plan, args) {
        let Some(arg) = nth(&plan, args, at) else {
            return Err(StoreError::Backend(
                "statement bind order out of range".to_owned(),
            ));
        };
        if matches!(arg, Arg::UuidList(_) | Arg::I64List(_)) {
            return Err(no_arrays());
        }
        q = match arg {
            Arg::UuidList(_) | Arg::I64List(_) => q,
            other => bind_arm!(
                q, other,
                ts: |t: Timestamp| t.timestamp_micros(),
                opt_ts: |t: Option<Timestamp>| t.map(|t| t.timestamp_micros()),
                json: |v: &serde_json::Value| to_json_text(v),
                opt_json: |v: Option<&serde_json::Value>| v.map(to_json_text),
                list: |_v: &[Uuid]| 0_i64,
                ilist: |_v: &[i64]| 0_i64,
                texts: |v: &[String]| text_json(v),
                opt_texts: |v: Option<&[String]>| v.map(text_json)
            ),
        };
    }
    Ok(q)
}

macro_rules! impl_sql {
    ($backend:ty, $row:ty, $bind:ident, |$pool:ident| $executor:expr) => {
        impl Sql for $backend {
            type Row = $row;

            fn execute<'a>(
                conn: &'a mut Conn<Self>,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<u64, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.execute(conn)
                        .await
                        .map(|done| done.rows_affected())
                        .map_err(db)
                }
            }

            fn fetch_all<'a>(
                conn: &'a mut Conn<Self>,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<Vec<Self::Row>, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.fetch_all(conn).await.map_err(db)
                }
            }

            fn fetch_optional<'a>(
                conn: &'a mut Conn<Self>,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<Option<Self::Row>, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.fetch_optional(conn).await.map_err(db)
                }
            }

            fn execute_pool<'a>(
                $pool: &'a Self::Pool,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<u64, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.execute($executor)
                        .await
                        .map(|done| done.rows_affected())
                        .map_err(db)
                }
            }

            fn fetch_all_pool<'a>(
                $pool: &'a Self::Pool,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<Vec<Self::Row>, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.fetch_all($executor).await.map_err(db)
                }
            }

            fn fetch_optional_pool<'a>(
                $pool: &'a Self::Pool,
                built: &'a Built,
                args: &'a [Arg<'a>],
            ) -> impl Future<Output = Result<Option<Self::Row>, StoreError>> + Send + 'a {
                async move {
                    let q = $bind(built, args)?;
                    q.fetch_optional($executor).await.map_err(db)
                }
            }
        }
    };
}

impl_sql!(PgBackend, PgRow, bind_pg, |pool| pool);
impl_sql!(MariaBackend, MySqlRow, bind_mariadb, |pool| pool);
impl_sql!(SqliteBackend, SqliteRow, bind_sqlite, |pool| &pool.pool);

enum Source {
    Static(&'static Built),
    Owned(Box<Built>),
}

impl Source {
    fn get(&self) -> &Built {
        match self {
            Self::Static(built) => built,
            Self::Owned(built) => built,
        }
    }
}

/// A statement with its binds. Bind in parameter order (`$1`, `$2`, ..), then execute.
#[must_use = "a statement does nothing until it is executed"]
pub struct Stmt<'a, B: Sql> {
    source: Source,
    args: Vec<Arg<'a>>,
    engine: PhantomData<fn() -> B>,
}

impl<B: Sql> std::fmt::Debug for Stmt<'_, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stmt")
            .field("sql", &self.source.get().text())
            .field("binds", &self.args.len())
            .finish()
    }
}

macro_rules! bind_methods {
    ($($name:ident, $opt:ident: $ty:ty => $variant:ident, $opt_variant:ident;)+) => {$(
        #[doc = concat!("Bind a `", stringify!($ty), "`.")]
        pub fn $name(mut self, value: $ty) -> Self {
            self.args.push(Arg::$variant(value));
            self
        }

        #[doc = concat!("Bind an optional `", stringify!($ty), "`.")]
        pub fn $opt(mut self, value: Option<$ty>) -> Self {
            self.args.push(Arg::$opt_variant(value));
            self
        }
    )+};
}

impl<'a, B: Sql> Stmt<'a, B> {
    /// A statement over a cached expansion (see `stmt!`).
    pub fn from_built(built: &'static Built) -> Self {
        Self {
            source: Source::Static(built),
            args: Vec::with_capacity(built.params.max(1)),
            engine: PhantomData,
        }
    }

    /// A statement whose text depends on runtime data (the length of an `IN` list). `template`
    /// uses the same notation as `stmt!`; only literals and placeholder counts may be
    /// spliced into it, never caller text.
    pub fn dynamic(template: &str) -> Self {
        let built = Built::expand(B::KIND, template);
        Self {
            args: Vec::with_capacity(built.params.max(1)),
            source: Source::Owned(Box::new(built)),
            engine: PhantomData,
        }
    }

    /// Plan this statement for its own values: PostgreSQL uses an unnamed statement, so a
    /// prefix `LIKE` can use an index a cached generic plan could not.
    pub fn unnamed(mut self) -> Self {
        let mut built = self.source.get().clone();
        built.persistent = false;
        self.source = Source::Owned(Box::new(built));
        self
    }

    bind_methods! {
        uuid, opt_uuid: Uuid => Uuid, OptUuid;
        i16, opt_i16: i16 => I16, OptI16;
        i32, opt_i32: i32 => I32, OptI32;
        i64, opt_i64: i64 => I64, OptI64;
        f32, opt_f32: f32 => F32, OptF32;
        f64, opt_f64: f64 => F64, OptF64;
        bool, opt_bool: bool => Bool, OptBool;
        text, opt_text: &'a str => Text, OptText;
        bytes, opt_bytes: &'a [u8] => Bytes, OptBytes;
        ts, opt_ts: Timestamp => Ts, OptTs;
        json, opt_json: &'a serde_json::Value => Json, OptJson;
    }

    /// Bind a list of ids for `Dialect::in_list`: one array parameter on PostgreSQL, one
    /// bind per id elsewhere. The list is the last parameter of the statement.
    pub fn uuid_list(mut self, ids: &'a [Uuid]) -> Self {
        if B::KIND == BackendKind::Postgres {
            self.args.push(Arg::UuidList(ids));
        } else {
            self.args.extend(ids.iter().copied().map(Arg::Uuid));
        }
        self
    }

    /// Bind a list of `bigint` ids for [`in_ids`]-style membership: one array parameter on
    /// PostgreSQL, one bind per id elsewhere. The list is the last parameter of the statement.
    pub fn i64_list(mut self, ids: &'a [i64]) -> Self {
        if B::KIND == BackendKind::Postgres {
            self.args.push(Arg::I64List(ids));
        } else {
            self.args.extend(ids.iter().copied().map(Arg::I64));
        }
        self
    }

    /// Bind a list of strings: a `text[]` on PostgreSQL, a JSON array elsewhere.
    pub fn text_list(mut self, list: &'a [String]) -> Self {
        self.args.push(Arg::TextList(list));
        self
    }

    /// Bind an optional list of strings (see [`Stmt::text_list`]).
    pub fn opt_text_list(mut self, list: Option<&'a [String]>) -> Self {
        self.args.push(Arg::OptTextList(list));
        self
    }

    /// Whether a statement written with [`returning`] matched a row: PostgreSQL asks for a
    /// returned row, the others for `rows_affected` (rows matched, not changed).
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn matched(self, conn: &mut Conn<B>) -> Result<bool, StoreError> {
        if B::KIND == BackendKind::Postgres {
            Ok(self.fetch_optional(conn).await?.is_some())
        } else {
            Ok(self.execute(conn).await? > 0)
        }
    }

    /// [`Stmt::matched`] for a lone write on the pool (a write transaction on SQLite).
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn matched_write(self, pool: &B::Pool) -> Result<bool, StoreError> {
        if B::KIND == BackendKind::Postgres {
            Ok(self.fetch_optional_write(pool).await?.is_some())
        } else {
            Ok(self.execute_write(pool).await? > 0)
        }
    }

    /// Run on `conn`; the rows affected.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the statement fails or binds the wrong number of values.
    pub async fn execute(self, conn: &mut Conn<B>) -> Result<u64, StoreError> {
        B::execute(conn, self.source.get(), &self.args).await
    }

    /// Run on `conn`; every row.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_all(self, conn: &mut Conn<B>) -> Result<Vec<B::Row>, StoreError> {
        B::fetch_all(conn, self.source.get(), &self.args).await
    }

    /// Run on `conn`; the first row, if any.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_optional(self, conn: &mut Conn<B>) -> Result<Option<B::Row>, StoreError> {
        B::fetch_optional(conn, self.source.get(), &self.args).await
    }

    /// Run on `conn`; exactly one row.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when there is no row, otherwise see
    /// [`Stmt::execute`].
    pub async fn fetch_one(self, conn: &mut Conn<B>) -> Result<B::Row, StoreError> {
        self.fetch_optional(conn).await?.ok_or(StoreError::NotFound {
            entity: "row",
            id: String::new(),
        })
    }

    /// Read on the pool (tenant-scoped on PostgreSQL); every row.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_all_pool(self, pool: &B::Pool) -> Result<Vec<B::Row>, StoreError> {
        B::fetch_all_pool(pool, self.source.get(), &self.args).await
    }

    /// Read on the pool; the first row, if any.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_optional_pool(self, pool: &B::Pool) -> Result<Option<B::Row>, StoreError> {
        B::fetch_optional_pool(pool, self.source.get(), &self.args).await
    }

    /// Read on the pool; exactly one row.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when there is no row, otherwise see
    /// [`Stmt::execute`].
    pub async fn fetch_one_pool(self, pool: &B::Pool) -> Result<B::Row, StoreError> {
        self.fetch_optional_pool(pool).await?.ok_or(StoreError::NotFound {
            entity: "row",
            id: String::new(),
        })
    }

    /// Run one write on the pool: a write transaction on SQLite, the pool directly elsewhere.
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn execute_write(self, pool: &B::Pool) -> Result<u64, StoreError> {
        if B::KIND == BackendKind::Sqlite {
            let mut tx = B::begin_write(pool).await?;
            let done = self.execute(tx.conn()).await?;
            tx.commit().await?;
            Ok(done)
        } else {
            B::execute_pool(pool, self.source.get(), &self.args).await
        }
    }

    /// Run one write that returns a row on the pool (see [`Stmt::execute_write`]).
    ///
    /// # Errors
    /// See [`Stmt::execute`].
    pub async fn fetch_optional_write(self, pool: &B::Pool) -> Result<Option<B::Row>, StoreError> {
        if B::KIND == BackendKind::Sqlite {
            let mut tx = B::begin_write(pool).await?;
            let row = self.fetch_optional(tx.conn()).await?;
            tx.commit().await?;
            Ok(row)
        } else {
            B::fetch_optional_pool(pool, self.source.get(), &self.args).await
        }
    }
}

impl<B: Sql> Store<B> {
    /// Begin a transaction that will write (`BEGIN IMMEDIATE` behind the in-process writer
    /// gate on SQLite).
    ///
    /// # Errors
    /// Returns [`StoreError`] if the transaction cannot start.
    pub(crate) async fn begin_write(&self) -> Result<WriteTx<B::Db>, StoreError> {
        B::begin_write(&self.pool).await
    }

    /// Begin a read-only transaction with a repeatable snapshot, in the same shape as
    /// [`Store::begin_write`] (`conn()`, `commit()`); no writer permit is held.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the transaction cannot start.
    pub(crate) async fn begin_read(&self) -> Result<WriteTx<B::Db>, StoreError> {
        Ok(WriteTx::new(B::begin_read(&self.pool).await?, None))
    }
}

/// ` RETURNING cols` on PostgreSQL, nothing elsewhere (MariaDB has no `UPDATE .. RETURNING`
/// and SQLite statements read `rows_affected` through [`Stmt::matched`] instead). Splice it
/// at the end of an `UPDATE` and run the statement with [`Stmt::matched`].
#[must_use]
pub fn returning<B: Backend>(cols: &str) -> String {
    if B::KIND == BackendKind::Postgres {
        format!(" RETURNING {cols}")
    } else {
        String::new()
    }
}

/// The membership test for a list bound with [`Stmt::uuid_list`], in template notation:
/// `= ANY($first)` on PostgreSQL (one array parameter), `IN ($first, $first+1, ..)` with
/// `count` parameters elsewhere (`IN (NULL)` for none, which matches no row).
#[must_use]
pub fn in_ids<B: Backend>(first: usize, count: usize) -> String {
    if B::KIND == BackendKind::Postgres {
        return format!("= ANY(${first})");
    }
    if count == 0 {
        return "IN (NULL)".to_owned();
    }
    let list = (first..first + count)
        .map(|n| format!("${n}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("IN ({list})")
}

/// Database wall time inside the caller's transaction: `clock_timestamp()` on PostgreSQL,
/// `SYSDATE(6)` on MariaDB, microseconds from the process clock on SQLite.
///
/// SQLite reads the same process clock as `Database::db_now`: its SQL `'now'` has only
/// millisecond resolution, so an instant read there could precede one taken a moment
/// earlier at microsecond resolution.
///
/// # Errors
/// Returns [`StoreError`] if the query fails.
pub async fn db_clock<B: Sql>(conn: &mut Conn<B>) -> Result<Timestamp, StoreError> {
    if B::KIND == BackendKind::Sqlite {
        return Ok(crate::backend::sqlite::db_now());
    }
    let clock = <B::Dialect as crate::backend::Dialect>::clock_timestamp();
    let row = Stmt::<B>::dynamic(&format!("SELECT {clock} AS now"))
        .fetch_one(conn)
        .await?;
    row.ts("now")
}

/// Membership of a column in a bound list, in template notation: `= ANY($first)` on
/// PostgreSQL (one array parameter, see [`Stmt::uuid_list`]), `IN ($first, $first+1, ..)` on
/// the other engines (one parameter per element). `Dialect::in_list` is not usable in
/// templates: it emits engine placeholders, which the template expander does not renumber.
#[must_use]
pub fn in_list<B: Backend>(first: usize, count: usize) -> String {
    if B::KIND == BackendKind::Postgres {
        return format!("= ANY(${first})");
    }
    if count == 0 {
        return "IN (NULL)".to_owned();
    }
    let mut out = String::from("IN (");
    for offset in 0..count {
        if offset > 0 {
            out.push_str(", ");
        }
        out.push('$');
        out.push_str(&(first + offset).to_string());
    }
    out.push(')');
    out
}

/// Insert a row that must not exist yet and report whether this call created it.
///
/// `insert` is the statement with the engine's "do nothing on conflict" clause
/// (`Dialect::upsert_do_nothing`). PostgreSQL and SQLite report the rows it inserted. MariaDB
/// reports matched rows for the no-op update (a duplicate counts as one), so there `probe`
/// (a `SELECT` that finds the existing row) decides first.
///
/// # Errors
/// See [`Stmt::execute`].
pub async fn insert_once<B: Sql>(
    conn: &mut Conn<B>,
    probe: Stmt<'_, B>,
    insert: Stmt<'_, B>,
) -> Result<bool, StoreError> {
    if B::KIND == BackendKind::MariaDb {
        if probe.fetch_optional(&mut *conn).await?.is_some() {
            return Ok(false);
        }
        insert.execute(conn).await?;
        return Ok(true);
    }
    Ok(insert.execute(conn).await? > 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const TEMPLATE: &str = "UPDATE crawl_runs SET status = $2::text::run_status, note = '$3::x' \
         WHERE run_id = $1 AND status::text <> $2 AND x IS NOT $1::uuid";

    #[test]
    fn postgres_keeps_the_template_byte_for_byte() {
        let built = Built::expand(BackendKind::Postgres, TEMPLATE);
        assert_eq!(built.text(), TEMPLATE);
        assert!(built.order.is_empty());
        assert_eq!(built.params, 2);
    }

    #[test]
    fn sqlite_numbers_placeholders_and_drops_casts() {
        let built = Built::expand(BackendKind::Sqlite, TEMPLATE);
        assert_eq!(
            built.text(),
            "UPDATE crawl_runs SET status = ?2, note = '$3::x' WHERE run_id = ?1 AND status <> ?2 AND x IS NOT ?1"
        );
        assert_eq!(built.params, 2);
    }

    #[test]
    fn mariadb_is_positional_and_remembers_the_bind_order() {
        let built = Built::expand(BackendKind::MariaDb, TEMPLATE);
        assert_eq!(
            built.text(),
            "UPDATE crawl_runs SET status = ?, note = '$3::x' WHERE run_id = ? AND status <> ? AND x IS NOT ?"
        );
        assert_eq!(built.order, vec![2, 1, 2, 1]);
    }

    #[test]
    fn a_bind_count_mismatch_is_refused_before_it_reaches_the_driver() {
        let built = Built::expand(BackendKind::Sqlite, "SELECT $1, $2");
        let one = [Arg::I64(1)];
        assert!(plan(&built, &one).is_err());
        let two = [Arg::I64(1), Arg::I64(2)];
        assert!(plan(&built, &two).is_ok());
    }

    #[test]
    fn mariadb_reorders_binds_by_parameter_number() {
        let built = Built::expand(BackendKind::MariaDb, "SELECT $2, $1, $2");
        let args = [Arg::I64(10), Arg::I64(20)];
        let plan = plan(&built, &args).unwrap();
        let seen: Vec<i64> = (0..bind_count(&plan, &args))
            .map(|at| match nth(&plan, &args, at) {
                Some(Arg::I64(v)) => *v,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(seen, vec![20, 10, 20]);
    }
}
