//! SQL fragments that differ between the three engines.
//!
//! Repository SQL that is shared between engines is written once and assembled from these
//! fragments. Every function is pure and returns text only; callers bind values themselves.
//!
//! Rules every fragment follows:
//!
//! * A placeholder passed to a fragment occurs **once** in the result. MariaDB placeholders
//!   are positional (`?`) and cannot be reused, so a fragment never repeats an argument.
//! * Identifiers and JSON keys passed to a fragment are compile-time literals; fragments
//!   escape quotes defensively but never accept user input.
//! * The fragments do not reach for `||` string concatenation on MariaDB; use
//!   [`Dialect::concat`] instead (the session keeps `PIPES_AS_CONCAT`, but shared SQL does
//!   not depend on it).

use std::borrow::Cow;
use std::fmt::Write as _;

/// How strongly a statement locks the rows it selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowLock {
    /// No locking clause.
    None,
    /// `FOR UPDATE`.
    Update,
    /// `FOR UPDATE SKIP LOCKED`.
    UpdateSkipLocked,
    /// `FOR UPDATE NOWAIT`.
    UpdateNoWait,
    /// Shared row lock (`FOR SHARE`).
    Share,
}

/// Smallest representable "no time" sentinel on SQLite, microseconds since the epoch
/// (year 1). Bounded so that adding or subtracting any lease or spacing value cannot
/// overflow into a floating point number.
pub const SQLITE_NEG_INFINITY_MICROS: i64 = -62_135_596_800_000_000;

/// Largest "never" sentinel on SQLite, microseconds since the epoch
/// (9999-12-31T23:59:59.999999Z).
pub const SQLITE_POS_INFINITY_MICROS: i64 = 253_402_300_799_999_999;

/// MariaDB spelling of the "no time" sentinel, as a `DATETIME(6)` literal.
pub const MARIADB_NEG_INFINITY: &str = "1000-01-01 00:00:00.000000";

/// MariaDB spelling of the "never" sentinel, as a `DATETIME(6)` literal.
pub const MARIADB_POS_INFINITY: &str = "9999-12-31 23:59:59.999999";

/// Engine-specific SQL fragments (static dispatch; implemented by zero-sized types).
pub trait Dialect {
    /// `true` when a list of values is bound as one array parameter (`= ANY($n)`), `false`
    /// when [`Dialect::in_list`] expands one placeholder per value.
    const ARRAY_BINDS: bool;

    /// Most bind parameters one statement accepts.
    const MAX_BIND_PARAMS: usize;

    /// Whether `UPDATE .. RETURNING` exists.
    const UPDATE_RETURNING: bool;

    /// Placeholder number `n` (1-based). MariaDB ignores `n` and returns `?`.
    fn placeholder(n: usize) -> String;

    /// Transaction or statement time (`now()`).
    fn now() -> &'static str;

    /// Wall time inside the statement (`clock_timestamp()`).
    fn clock_timestamp() -> &'static str;

    /// `base` moved forward by the number of seconds bound at `secs` (a floating point
    /// placeholder).
    fn add_seconds(base: &str, secs: &str) -> String;

    /// `base` moved forward by the whole number of hours bound at `hours`.
    fn add_hours(base: &str, hours: &str) -> String;

    /// Sentinel that sorts before every real time.
    fn neg_infinity() -> &'static str;

    /// Sentinel that sorts after every real time.
    fn pos_infinity() -> &'static str;

    /// Trailing clause that leaves an existing row alone on a key conflict. `target` lists
    /// the conflict columns; MariaDB uses the first one for the no-op assignment (it never
    /// uses `INSERT IGNORE`, which swallows foreign key, check and `NOT NULL` errors).
    fn upsert_do_nothing(target: &[&str]) -> String;

    /// Trailing clause that overwrites `set` columns with the proposed values on a key
    /// conflict. `filter` limits the update to rows where it holds; it may use
    /// [`Dialect::excluded`] for the proposed value and bare column names for the stored
    /// one. MariaDB, which has no conditional update, keeps the stored value instead.
    fn upsert_update(target: &[&str], set: &[&str], filter: Option<&str>) -> String;

    /// The value proposed by the insert for `col`, usable in an upsert assignment or filter.
    fn excluded(col: &str) -> String;

    /// The locking clause (with a leading space) for `lock`, empty when the engine has no
    /// row locks (SQLite relies on its single writer).
    fn row_lock(lock: RowLock) -> &'static str;

    /// `col ->> 'key'`: the text of a top level JSON member (SQL `NULL` when absent).
    fn json_text(col: &str, key: &str) -> String;

    /// `col -> 'key'`: a top level JSON member as JSON.
    fn json_extract(col: &str, key: &str) -> String;

    /// `col` with the top level member `key` set to `value` (a JSON expression).
    fn json_set(col: &str, key: &str, value: &str) -> String;

    /// `base` with `patch` merged over it (RFC 7386 on MariaDB and SQLite, `||` on
    /// PostgreSQL; the three differ on nested objects, so use it for flat objects only).
    fn json_merge(base: &str, patch: &str) -> String;

    /// `col` without the top level member `key`.
    fn json_remove(col: &str, key: &str) -> String;

    /// Condition that `expr` (a JSON value) is not the JSON `null`.
    fn json_not_null(expr: &str) -> String;

    /// `NULL`-ignoring `LEAST`.
    fn least_ignoring_null(args: &[&str]) -> String;

    /// `NULL`-ignoring `GREATEST`.
    fn greatest_ignoring_null(args: &[&str]) -> String;

    /// `a` and `b` differ, treating two `NULL`s as equal.
    fn null_safe_ne(a: &str, b: &str) -> String;

    /// `a` and `b` are equal, treating two `NULL`s as equal.
    fn null_safe_eq(a: &str, b: &str) -> String;

    /// Lower-case hexadecimal text of a binary column.
    fn hex(col: &str) -> String;

    /// Condition that text `col` starts with the text bound at `prefix`.
    fn starts_with(col: &str, prefix: &str) -> String;

    /// Text concatenation of two expressions.
    fn concat(a: &str, b: &str) -> String;

    /// `col` as text when it is an enumerated type (PostgreSQL needs the cast).
    fn enum_text(col: &str) -> String;

    /// Condition that the optional parameter `placeholder` is `NULL`; `pg_type` is the type
    /// PostgreSQL needs to resolve an untyped parameter.
    fn optional_is_null(placeholder: &str, pg_type: &str) -> String;

    /// An identifier that is reserved on some engine (`key`, `rank`, `order`), spelled so
    /// every engine accepts it: backtick-quoted on MariaDB, as written elsewhere (so the
    /// PostgreSQL text stays byte-identical).
    fn reserved_ident(name: &str) -> String;

    /// `count(*)` of the rows of the group that satisfy `cond`.
    fn count_where(cond: &str) -> String;

    /// `expr` as a 64-bit integer (`sum()` of integers is a decimal on MariaDB).
    fn cast_i64(expr: &str) -> String;

    /// Membership of a column in a bound list. PostgreSQL returns `= ANY($first)` and
    /// ignores `count`; the others return `IN (p1, p2, ..)` with `count` placeholders.
    fn in_list(first: usize, count: usize) -> String;

    /// Most rows a multi-row `VALUES` insert of `columns` columns may carry.
    #[must_use]
    fn max_batch_rows(columns: usize) -> usize {
        Self::MAX_BIND_PARAMS / columns.max(1)
    }

    /// `VALUES (p1, p2), (p3, p4), ..` for `rows` rows of `columns` columns, numbered from
    /// placeholder `first`.
    #[must_use]
    fn values_rows(first: usize, rows: usize, columns: usize) -> String {
        let mut out = String::from("VALUES ");
        let mut n = first;
        for row in 0..rows {
            if row > 0 {
                out.push_str(", ");
            }
            out.push('(');
            for column in 0..columns {
                if column > 0 {
                    out.push_str(", ");
                }
                out.push_str(&Self::placeholder(n));
                n += 1;
            }
            out.push(')');
        }
        out
    }
}

/// Exclusive upper bound for a prefix range scan: every string starting with `prefix`
/// sorts below the returned value under byte-wise collation.
#[must_use]
pub fn prefix_upper_bound(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + 4);
    out.push_str(prefix);
    out.push(char::MAX);
    out
}

/// `col >= lower AND col < upper` for the prefix range scan bound by
/// [`prefix_upper_bound`]; identical on every engine.
#[must_use]
pub fn prefix_range(col: &str, lower: &str, upper: &str) -> String {
    format!("{col} >= {lower} AND {col} < {upper}")
}

/// Escape `'` for use inside a single-quoted SQL literal.
fn quote_literal(text: &str) -> Cow<'_, str> {
    if text.contains('\'') {
        Cow::Owned(text.replace('\'', "''"))
    } else {
        Cow::Borrowed(text)
    }
}

/// `NULL`-ignoring `LEAST`/`GREATEST` for engines whose scalar versions return `NULL` when
/// any argument is `NULL`: every argument is replaced by the first non-`NULL` value
/// starting at itself, which never changes the extremum of the non-`NULL` values.
fn null_ignoring(function: &str, args: &[&str]) -> String {
    match args {
        [] => "NULL".to_owned(),
        [only] => (*only).to_owned(),
        _ => {
            let mut out = String::from(function);
            out.push('(');
            for (index, _) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str("COALESCE(");
                out.push_str(args[index]);
                for (other, arg) in args.iter().enumerate() {
                    if other != index {
                        out.push_str(", ");
                        out.push_str(arg);
                    }
                }
                out.push(')');
            }
            out.push(')');
            out
        }
    }
}

fn columns(cols: &[&str]) -> String {
    cols.join(", ")
}

/// PostgreSQL fragments.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresDialect;

impl Dialect for PostgresDialect {
    const ARRAY_BINDS: bool = true;
    const MAX_BIND_PARAMS: usize = 65_535;
    const UPDATE_RETURNING: bool = true;

    fn placeholder(n: usize) -> String {
        format!("${n}")
    }

    fn now() -> &'static str {
        "now()"
    }

    fn clock_timestamp() -> &'static str {
        "clock_timestamp()"
    }

    fn add_seconds(base: &str, secs: &str) -> String {
        format!("{base} + make_interval(secs => {secs})")
    }

    fn add_hours(base: &str, hours: &str) -> String {
        format!("{base} + make_interval(hours => {hours})")
    }

    fn neg_infinity() -> &'static str {
        "'-infinity'::timestamptz"
    }

    fn pos_infinity() -> &'static str {
        "'infinity'::timestamptz"
    }

    fn upsert_do_nothing(target: &[&str]) -> String {
        format!("ON CONFLICT ({}) DO NOTHING", columns(target))
    }

    fn upsert_update(target: &[&str], set: &[&str], filter: Option<&str>) -> String {
        let assignments = set
            .iter()
            .map(|c| format!("{c} = {}", Self::excluded(c)))
            .collect::<Vec<_>>()
            .join(", ");
        let mut out = format!("ON CONFLICT ({}) DO UPDATE SET {assignments}", columns(target));
        if let Some(filter) = filter {
            let _ = write!(out, " WHERE {filter}");
        }
        out
    }

    fn excluded(col: &str) -> String {
        format!("EXCLUDED.{col}")
    }

    fn row_lock(lock: RowLock) -> &'static str {
        match lock {
            RowLock::None => "",
            RowLock::Update => " FOR UPDATE",
            RowLock::UpdateSkipLocked => " FOR UPDATE SKIP LOCKED",
            RowLock::UpdateNoWait => " FOR UPDATE NOWAIT",
            RowLock::Share => " FOR SHARE",
        }
    }

    fn json_text(col: &str, key: &str) -> String {
        format!("{col}->>'{}'", quote_literal(key))
    }

    fn json_extract(col: &str, key: &str) -> String {
        format!("{col}->'{}'", quote_literal(key))
    }

    fn json_set(col: &str, key: &str, value: &str) -> String {
        format!("jsonb_set({col}, '{{{}}}', {value})", quote_literal(key))
    }

    fn json_merge(base: &str, patch: &str) -> String {
        format!("({base} || {patch})")
    }

    fn json_remove(col: &str, key: &str) -> String {
        format!("({col} - '{}')", quote_literal(key))
    }

    fn json_not_null(expr: &str) -> String {
        format!("{expr} <> 'null'::jsonb")
    }

    fn least_ignoring_null(args: &[&str]) -> String {
        match args {
            [] => "NULL".to_owned(),
            _ => format!("LEAST({})", columns(args)),
        }
    }

    fn greatest_ignoring_null(args: &[&str]) -> String {
        match args {
            [] => "NULL".to_owned(),
            _ => format!("GREATEST({})", columns(args)),
        }
    }

    fn null_safe_ne(a: &str, b: &str) -> String {
        format!("{a} IS DISTINCT FROM {b}")
    }

    fn null_safe_eq(a: &str, b: &str) -> String {
        format!("{a} IS NOT DISTINCT FROM {b}")
    }

    fn hex(col: &str) -> String {
        format!("encode({col}, 'hex')")
    }

    fn starts_with(col: &str, prefix: &str) -> String {
        format!("starts_with({col}, {prefix})")
    }

    fn concat(a: &str, b: &str) -> String {
        format!("({a} || {b})")
    }

    fn enum_text(col: &str) -> String {
        format!("{col}::text")
    }

    fn optional_is_null(placeholder: &str, pg_type: &str) -> String {
        format!("{placeholder}::{pg_type} IS NULL")
    }

    fn reserved_ident(name: &str) -> String {
        name.to_owned()
    }

    fn count_where(cond: &str) -> String {
        format!("count(*) FILTER (WHERE {cond})")
    }

    fn cast_i64(expr: &str) -> String {
        format!("{expr}::bigint")
    }

    fn in_list(first: usize, _count: usize) -> String {
        format!("= ANY(${first})")
    }
}

/// MariaDB fragments.
#[derive(Clone, Copy, Debug, Default)]
pub struct MariaDbDialect;

impl Dialect for MariaDbDialect {
    const ARRAY_BINDS: bool = false;
    const MAX_BIND_PARAMS: usize = 65_535;
    const UPDATE_RETURNING: bool = false;

    fn placeholder(_n: usize) -> String {
        "?".to_owned()
    }

    fn now() -> &'static str {
        "NOW(6)"
    }

    fn clock_timestamp() -> &'static str {
        "SYSDATE(6)"
    }

    fn add_seconds(base: &str, secs: &str) -> String {
        format!("DATE_ADD({base}, INTERVAL ROUND({secs} * 1000000) MICROSECOND)")
    }

    fn add_hours(base: &str, hours: &str) -> String {
        format!("DATE_ADD({base}, INTERVAL {hours} HOUR)")
    }

    fn neg_infinity() -> &'static str {
        "'1000-01-01 00:00:00.000000'"
    }

    fn pos_infinity() -> &'static str {
        "'9999-12-31 23:59:59.999999'"
    }

    fn upsert_do_nothing(target: &[&str]) -> String {
        let column = target.first().copied().unwrap_or("1");
        format!("ON DUPLICATE KEY UPDATE {column} = {column}")
    }

    fn upsert_update(_target: &[&str], set: &[&str], filter: Option<&str>) -> String {
        let assignments = set
            .iter()
            .map(|c| match filter {
                None => format!("{c} = VALUES({c})"),
                Some(filter) => format!("{c} = IF({filter}, VALUES({c}), {c})"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("ON DUPLICATE KEY UPDATE {assignments}")
    }

    fn excluded(col: &str) -> String {
        format!("VALUES({col})")
    }

    fn row_lock(lock: RowLock) -> &'static str {
        match lock {
            RowLock::None => "",
            RowLock::Update => " FOR UPDATE",
            RowLock::UpdateSkipLocked => " FOR UPDATE SKIP LOCKED",
            RowLock::UpdateNoWait => " FOR UPDATE NOWAIT",
            RowLock::Share => " LOCK IN SHARE MODE",
        }
    }

    fn json_text(col: &str, key: &str) -> String {
        format!("JSON_VALUE({col}, '$.{}')", quote_literal(key))
    }

    fn json_extract(col: &str, key: &str) -> String {
        format!("JSON_EXTRACT({col}, '$.{}')", quote_literal(key))
    }

    fn json_set(col: &str, key: &str, value: &str) -> String {
        format!("JSON_SET({col}, '$.{}', {value})", quote_literal(key))
    }

    fn json_merge(base: &str, patch: &str) -> String {
        format!("JSON_MERGE_PATCH({base}, {patch})")
    }

    fn json_remove(col: &str, key: &str) -> String {
        format!("JSON_REMOVE({col}, '$.{}')", quote_literal(key))
    }

    fn json_not_null(expr: &str) -> String {
        format!("JSON_TYPE({expr}) <> 'NULL'")
    }

    fn least_ignoring_null(args: &[&str]) -> String {
        null_ignoring("LEAST", args)
    }

    fn greatest_ignoring_null(args: &[&str]) -> String {
        null_ignoring("GREATEST", args)
    }

    fn null_safe_ne(a: &str, b: &str) -> String {
        format!("NOT ({a} <=> {b})")
    }

    fn null_safe_eq(a: &str, b: &str) -> String {
        format!("({a} <=> {b})")
    }

    fn hex(col: &str) -> String {
        format!("LOWER(HEX({col}))")
    }

    fn starts_with(col: &str, prefix: &str) -> String {
        format!("LOCATE({prefix}, {col}) = 1")
    }

    fn concat(a: &str, b: &str) -> String {
        format!("CONCAT({a}, {b})")
    }

    fn enum_text(col: &str) -> String {
        col.to_owned()
    }

    fn optional_is_null(placeholder: &str, _pg_type: &str) -> String {
        format!("{placeholder} IS NULL")
    }

    fn reserved_ident(name: &str) -> String {
        format!("`{name}`")
    }

    fn count_where(cond: &str) -> String {
        format!("CAST(COALESCE(SUM(CASE WHEN {cond} THEN 1 ELSE 0 END), 0) AS SIGNED)")
    }

    fn cast_i64(expr: &str) -> String {
        format!("CAST({expr} AS SIGNED)")
    }

    fn in_list(first: usize, count: usize) -> String {
        in_placeholders::<Self>(first, count)
    }
}

/// SQLite fragments.
#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteDialect;

impl Dialect for SqliteDialect {
    const ARRAY_BINDS: bool = false;
    const MAX_BIND_PARAMS: usize = 32_766;
    const UPDATE_RETURNING: bool = true;

    fn placeholder(n: usize) -> String {
        format!("?{n}")
    }

    /// Millisecond resolution: `unixepoch('subsec')` carries no finer digits.
    fn now() -> &'static str {
        "CAST(unixepoch('subsec') * 1000000 AS INTEGER)"
    }

    fn clock_timestamp() -> &'static str {
        "CAST(unixepoch('subsec') * 1000000 AS INTEGER)"
    }

    fn add_seconds(base: &str, secs: &str) -> String {
        format!("{base} + CAST({secs} * 1000000 AS INTEGER)")
    }

    fn add_hours(base: &str, hours: &str) -> String {
        format!("{base} + CAST({hours} * 3600000000 AS INTEGER)")
    }

    fn neg_infinity() -> &'static str {
        "-62135596800000000"
    }

    fn pos_infinity() -> &'static str {
        "253402300799999999"
    }

    fn upsert_do_nothing(target: &[&str]) -> String {
        format!("ON CONFLICT ({}) DO NOTHING", columns(target))
    }

    fn upsert_update(target: &[&str], set: &[&str], filter: Option<&str>) -> String {
        let assignments = set
            .iter()
            .map(|c| format!("{c} = {}", Self::excluded(c)))
            .collect::<Vec<_>>()
            .join(", ");
        let mut out = format!("ON CONFLICT ({}) DO UPDATE SET {assignments}", columns(target));
        if let Some(filter) = filter {
            let _ = write!(out, " WHERE {filter}");
        }
        out
    }

    fn excluded(col: &str) -> String {
        format!("excluded.{col}")
    }

    fn row_lock(_lock: RowLock) -> &'static str {
        ""
    }

    fn json_text(col: &str, key: &str) -> String {
        format!("{col}->>'{}'", quote_literal(key))
    }

    fn json_extract(col: &str, key: &str) -> String {
        format!("{col}->'{}'", quote_literal(key))
    }

    fn json_set(col: &str, key: &str, value: &str) -> String {
        format!("json_set({col}, '$.{}', {value})", quote_literal(key))
    }

    fn json_merge(base: &str, patch: &str) -> String {
        format!("json_patch({base}, {patch})")
    }

    fn json_remove(col: &str, key: &str) -> String {
        format!("json_remove({col}, '$.{}')", quote_literal(key))
    }

    fn json_not_null(expr: &str) -> String {
        format!("json_type({expr}) <> 'null'")
    }

    fn least_ignoring_null(args: &[&str]) -> String {
        null_ignoring("min", args)
    }

    fn greatest_ignoring_null(args: &[&str]) -> String {
        null_ignoring("max", args)
    }

    fn null_safe_ne(a: &str, b: &str) -> String {
        format!("{a} IS NOT {b}")
    }

    fn null_safe_eq(a: &str, b: &str) -> String {
        format!("{a} IS {b}")
    }

    fn hex(col: &str) -> String {
        format!("lower(hex({col}))")
    }

    fn starts_with(col: &str, prefix: &str) -> String {
        format!("instr({col}, {prefix}) = 1")
    }

    fn concat(a: &str, b: &str) -> String {
        format!("({a} || {b})")
    }

    fn enum_text(col: &str) -> String {
        col.to_owned()
    }

    fn optional_is_null(placeholder: &str, _pg_type: &str) -> String {
        format!("{placeholder} IS NULL")
    }

    fn reserved_ident(name: &str) -> String {
        name.to_owned()
    }

    fn count_where(cond: &str) -> String {
        format!("count(*) FILTER (WHERE {cond})")
    }

    fn cast_i64(expr: &str) -> String {
        format!("CAST({expr} AS INTEGER)")
    }

    fn in_list(first: usize, count: usize) -> String {
        in_placeholders::<Self>(first, count)
    }
}

/// `IN (p, p, ..)` with `count` placeholders (`IN (NULL)` for none, which matches no row).
fn in_placeholders<D: Dialect>(first: usize, count: usize) -> String {
    if count == 0 {
        return "IN (NULL)".to_owned();
    }
    let mut out = String::from("IN (");
    for offset in 0..count {
        if offset > 0 {
            out.push_str(", ");
        }
        out.push_str(&D::placeholder(first + offset));
    }
    out.push(')');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn placeholders_follow_each_engine() {
        assert_eq!(PostgresDialect::placeholder(3), "$3");
        assert_eq!(MariaDbDialect::placeholder(3), "?");
        assert_eq!(SqliteDialect::placeholder(3), "?3");
    }

    #[test]
    fn upserts_never_use_insert_ignore() {
        assert_eq!(
            PostgresDialect::upsert_do_nothing(&["a", "b"]),
            "ON CONFLICT (a, b) DO NOTHING"
        );
        assert_eq!(
            SqliteDialect::upsert_do_nothing(&["a", "b"]),
            "ON CONFLICT (a, b) DO NOTHING"
        );
        let maria = MariaDbDialect::upsert_do_nothing(&["a", "b"]);
        assert_eq!(maria, "ON DUPLICATE KEY UPDATE a = a");
        assert!(!maria.to_ascii_uppercase().contains("IGNORE"));
    }

    #[test]
    fn conditional_upserts_keep_the_stored_value_on_mariadb() {
        let filter = format!("v <> {}", PostgresDialect::excluded("v"));
        assert_eq!(
            PostgresDialect::upsert_update(&["k"], &["v", "w"], Some(&filter)),
            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, w = EXCLUDED.w WHERE v <> EXCLUDED.v"
        );
        let filter = format!("v <> {}", MariaDbDialect::excluded("v"));
        assert_eq!(
            MariaDbDialect::upsert_update(&["k"], &["v"], Some(&filter)),
            "ON DUPLICATE KEY UPDATE v = IF(v <> VALUES(v), VALUES(v), v)"
        );
        assert_eq!(
            MariaDbDialect::upsert_update(&["k"], &["v"], None),
            "ON DUPLICATE KEY UPDATE v = VALUES(v)"
        );
        assert_eq!(
            SqliteDialect::upsert_update(&["k"], &["v"], None),
            "ON CONFLICT (k) DO UPDATE SET v = excluded.v"
        );
    }

    #[test]
    fn row_locks_match_the_engine_syntax() {
        assert_eq!(PostgresDialect::row_lock(RowLock::Share), " FOR SHARE");
        assert_eq!(MariaDbDialect::row_lock(RowLock::Share), " LOCK IN SHARE MODE");
        assert_eq!(SqliteDialect::row_lock(RowLock::UpdateSkipLocked), "");
        assert_eq!(
            MariaDbDialect::row_lock(RowLock::UpdateSkipLocked),
            " FOR UPDATE SKIP LOCKED"
        );
    }

    #[test]
    fn clocks_and_intervals() {
        assert_eq!(
            PostgresDialect::add_seconds("now()", "$1"),
            "now() + make_interval(secs => $1)"
        );
        assert_eq!(
            MariaDbDialect::add_seconds(MariaDbDialect::now(), "?"),
            "DATE_ADD(NOW(6), INTERVAL ROUND(? * 1000000) MICROSECOND)"
        );
        assert_eq!(
            SqliteDialect::add_seconds("lease_expires_at", "?1"),
            "lease_expires_at + CAST(?1 * 1000000 AS INTEGER)"
        );
        assert_eq!(MariaDbDialect::clock_timestamp(), "SYSDATE(6)");
    }

    #[test]
    fn sentinels_are_bounded_and_aligned() {
        assert_eq!(
            SqliteDialect::pos_infinity(),
            SQLITE_POS_INFINITY_MICROS.to_string()
        );
        assert_eq!(
            SqliteDialect::neg_infinity(),
            SQLITE_NEG_INFINITY_MICROS.to_string()
        );
        // adding a day of microseconds to either sentinel stays an integer
        assert!(SQLITE_POS_INFINITY_MICROS.checked_add(86_400_000_000).is_some());
        assert!(SQLITE_NEG_INFINITY_MICROS.checked_sub(86_400_000_000).is_some());
        assert_eq!(
            MariaDbDialect::neg_infinity(),
            format!("'{MARIADB_NEG_INFINITY}'")
        );
        assert_eq!(
            MariaDbDialect::pos_infinity(),
            format!("'{MARIADB_POS_INFINITY}'")
        );
    }

    #[test]
    fn json_fragments() {
        assert_eq!(PostgresDialect::json_text("config", "url"), "config->>'url'");
        assert_eq!(
            MariaDbDialect::json_text("config", "url"),
            "JSON_VALUE(config, '$.url')"
        );
        assert_eq!(SqliteDialect::json_text("config", "url"), "config->>'url'");
        assert_eq!(MariaDbDialect::json_text("c", "a'b"), "JSON_VALUE(c, '$.a''b')");
        assert_eq!(
            PostgresDialect::json_set("c", "k", "$1"),
            "jsonb_set(c, '{k}', $1)"
        );
        assert_eq!(MariaDbDialect::json_merge("a", "b"), "JSON_MERGE_PATCH(a, b)");
        assert_eq!(SqliteDialect::json_remove("c", "k"), "json_remove(c, '$.k')");
        assert_eq!(PostgresDialect::json_not_null("x"), "x <> 'null'::jsonb");
        assert_eq!(MariaDbDialect::json_not_null("x"), "JSON_TYPE(x) <> 'NULL'");
        assert_eq!(SqliteDialect::json_not_null("x"), "json_type(x) <> 'null'");
    }

    #[test]
    fn null_ignoring_extremes() {
        assert_eq!(PostgresDialect::least_ignoring_null(&["a", "b"]), "LEAST(a, b)");
        assert_eq!(
            MariaDbDialect::greatest_ignoring_null(&["a", "b", "c"]),
            "GREATEST(COALESCE(a, b, c), COALESCE(b, a, c), COALESCE(c, a, b))"
        );
        assert_eq!(
            SqliteDialect::least_ignoring_null(&["a", "b"]),
            "min(COALESCE(a, b), COALESCE(b, a))"
        );
        assert_eq!(SqliteDialect::least_ignoring_null(&["a"]), "a");
        assert_eq!(MariaDbDialect::least_ignoring_null(&[]), "NULL");
    }

    #[test]
    fn small_fragments() {
        assert_eq!(PostgresDialect::null_safe_ne("a", "b"), "a IS DISTINCT FROM b");
        assert_eq!(MariaDbDialect::null_safe_ne("a", "b"), "NOT (a <=> b)");
        assert_eq!(SqliteDialect::null_safe_ne("a", "b"), "a IS NOT b");
        assert_eq!(PostgresDialect::hex("h"), "encode(h, 'hex')");
        assert_eq!(MariaDbDialect::hex("h"), "LOWER(HEX(h))");
        assert_eq!(SqliteDialect::hex("h"), "lower(hex(h))");
        assert_eq!(PostgresDialect::enum_text("a.status"), "a.status::text");
        assert_eq!(SqliteDialect::enum_text("a.status"), "a.status");
        assert_eq!(
            PostgresDialect::optional_is_null("$4", "uuid"),
            "$4::uuid IS NULL"
        );
        assert_eq!(MariaDbDialect::optional_is_null("?", "uuid"), "? IS NULL");
        assert_eq!(MariaDbDialect::concat("a", "b"), "CONCAT(a, b)");
        assert_eq!(SqliteDialect::starts_with("k", "?1"), "instr(k, ?1) = 1");
        assert_eq!(MariaDbDialect::starts_with("k", "?"), "LOCATE(?, k) = 1");
    }

    #[test]
    fn list_membership_and_batches() {
        assert_eq!(PostgresDialect::in_list(2, 5), "= ANY($2)");
        assert_eq!(SqliteDialect::in_list(2, 3), "IN (?2, ?3, ?4)");
        assert_eq!(MariaDbDialect::in_list(1, 2), "IN (?, ?)");
        assert_eq!(MariaDbDialect::in_list(1, 0), "IN (NULL)");
        assert_eq!(SqliteDialect::values_rows(1, 2, 2), "VALUES (?1, ?2), (?3, ?4)");
        assert_eq!(PostgresDialect::values_rows(1, 2, 2), "VALUES ($1, $2), ($3, $4)");
        assert_eq!(SqliteDialect::max_batch_rows(2), 16_383);
        assert_eq!(MariaDbDialect::max_batch_rows(2), 32_767);
        assert_eq!(MariaDbDialect::max_batch_rows(0), 65_535);
    }

    #[test]
    fn prefix_ranges_are_engine_neutral() {
        assert_eq!(
            prefix_range("host_key", "$1", "$2"),
            "host_key >= $1 AND host_key < $2"
        );
        let upper = prefix_upper_bound("com.example");
        assert!(upper.as_str() > "com.example\u{10fffe}");
        assert!(upper.starts_with("com.example"));
    }
}
