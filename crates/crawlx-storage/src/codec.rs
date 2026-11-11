//! Small conversions between `crawlx-core` values and column representations.

use crate::error::db;
use chrono::Duration as ChronoDuration;
use crawlx_core::hash::Digest;
use crawlx_core::traffic::TrafficOrigin;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::StoreError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::Row;

/// Serialize to a JSON value.
pub(crate) fn to_json<T: Serialize>(v: &T) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(v).map_err(|e| StoreError::Serialization(e.to_string()))
}

/// Deserialize from a JSON value.
pub(crate) fn from_json<T: DeserializeOwned>(v: serde_json::Value) -> Result<T, StoreError> {
    serde_json::from_value(v).map_err(|e| StoreError::Serialization(e.to_string()))
}

/// The `snake_case` serde label of an enum value (matches the SQL enum labels).
pub(crate) fn label<T: Serialize>(v: &T) -> Result<String, StoreError> {
    match to_json(v)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(StoreError::Serialization(format!(
            "expected string label, got {other}"
        ))),
    }
}

/// Parse a `snake_case` serde label.
pub(crate) fn parse_label<T: DeserializeOwned>(s: &str) -> Result<T, StoreError> {
    from_json(serde_json::Value::String(s.to_owned()))
}

pub(crate) fn digest(bytes: &[u8]) -> Result<Digest, StoreError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::Serialization(format!("expected 32-byte digest, got {} bytes", bytes.len()))
    })?;
    Ok(Digest(arr))
}

pub(crate) fn digest16(bytes: &[u8]) -> Result<[u8; 16], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Serialization(format!("expected 16-byte id, got {} bytes", bytes.len())))
}

pub(crate) fn opt_digest(bytes: Option<Vec<u8>>) -> Result<Option<Digest>, StoreError> {
    bytes.map(|b| digest(&b)).transpose()
}

pub(crate) fn conv<T, U>(v: T, what: &'static str) -> Result<U, StoreError>
where
    U: TryFrom<T>,
{
    U::try_from(v).map_err(|_| StoreError::Serialization(format!("{what} out of range")))
}

/// Encode an unsigned 64-bit bit pattern in a signed SQL `BIGINT` slot.
///
/// Seeds and perceptual hashes use all 64 bits, unlike nonnegative counters.
/// The upper half maps explicitly to negative slots, preserving existing rows
/// without a wrapping numeric cast. Use `conv` instead for numeric quantities.
pub(crate) fn signed_bits(value: u64) -> Result<i64, StoreError> {
    const SIGN_BIT: u64 = 1 << 63;
    if value < SIGN_BIT {
        conv(value, "unsigned bit pattern")
    } else {
        let low: i64 = conv(value - SIGN_BIT, "unsigned bit pattern")?;
        Ok(i64::MIN + low)
    }
}

/// Decode the signed SQL slot used by `signed_bits`, preserving every bit.
pub(crate) fn unsigned_bits(value: i64) -> Result<u64, StoreError> {
    if value >= 0 {
        conv(value, "signed bit pattern")
    } else {
        let low: u64 = conv(value - i64::MIN, "signed bit pattern")?;
        Ok((1 << 63) + low)
    }
}

/// SQL label for a traffic origin (the `traffic_events.origin` check).
pub(crate) fn origin_label(o: TrafficOrigin) -> &'static str {
    match o {
        TrafficOrigin::Page => "page",
        TrafficOrigin::ServiceWorker => "service_worker",
        TrafficOrigin::WebSocket => "websocket",
        TrafficOrigin::EventSource => "event_source",
        TrafficOrigin::FetchPlane => "fetch_plane",
    }
}

pub(crate) fn canonical_to_json(u: &CanonicalUrl) -> Result<serde_json::Value, StoreError> {
    to_json(u)
}

pub(crate) fn get<'r, T>(row: &'r PgRow, col: &str) -> Result<T, StoreError>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row_get::<PgRow, T>(row, col)
}

/// Decode column `col` of a row of any engine.
pub(crate) fn row_get<'r, R, T>(row: &'r R, col: &str) -> Result<T, StoreError>
where
    R: Row,
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    T: sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    row.try_get::<T, _>(col).map_err(db)
}

/// Sentinel `"-infinity"` on SQLite: year 1, microseconds since the epoch. Bounded so that
/// adding or subtracting any lease or spacing value stays an integer.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) const SQLITE_NEG_INFINITY: i64 = crate::backend::dialect::SQLITE_NEG_INFINITY_MICROS;

/// Sentinel `"infinity"` on SQLite: 9999-12-31T23:59:59.999999Z in microseconds.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) const SQLITE_POS_INFINITY: i64 = crate::backend::dialect::SQLITE_POS_INFINITY_MICROS;

/// Microseconds since the epoch, the SQLite column representation of a timestamp.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn ts_to_micros(ts: chrono::DateTime<chrono::Utc>) -> i64 {
    ts.timestamp_micros()
}

/// Decode a SQLite timestamp column; the infinity sentinels decode to the extreme finite
/// times callers treat as "never" and "always".
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn ts_from_micros(micros: i64) -> Result<chrono::DateTime<chrono::Utc>, StoreError> {
    chrono::DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| StoreError::Serialization(format!("timestamp {micros} out of range")))
}

/// The MariaDB bind form of a timestamp. `DateTime<Utc>` binds as `TIMESTAMP`, whose range
/// ends in 2038 and silently stores out-of-range values as NULL; a naive UTC `DATETIME(6)`
/// value keeps the full range (including the `1000-01-01` and `9999-12-31` sentinels).
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn ts_to_naive(ts: chrono::DateTime<chrono::Utc>) -> chrono::NaiveDateTime {
    ts.naive_utc()
}

/// Decode a MariaDB `DATETIME(6)` column read as a naive UTC value.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn ts_from_naive(naive: chrono::NaiveDateTime) -> chrono::DateTime<chrono::Utc> {
    naive.and_utc()
}

/// The text a JSON value is stored as on engines without a JSON binary type. The same
/// rendering is hashed by the audit chain, so it must stay the compact `serde_json` form.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn to_json_text(value: &serde_json::Value) -> String {
    value.to_string()
}

/// Parse stored JSON text.
#[allow(
    dead_code,
    reason = "used by the SQLite and MariaDB repositories of later slices"
)]
pub(crate) fn from_json_text(text: &str) -> Result<serde_json::Value, StoreError> {
    serde_json::from_str(text).map_err(|e| StoreError::Serialization(e.to_string()))
}

/// Retention horizon of `days` days after `from`; `0` means no expiry.
pub(crate) fn expiry(
    from: chrono::DateTime<chrono::Utc>,
    days: u32,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if days == 0 {
        None
    } else {
        Some(from + ChronoDuration::days(i64::from(days)))
    }
}

/// Fixed-width little-endian packing of a MinHash signature.
pub(crate) fn pack_u64s(v: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 8);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

pub(crate) fn unpack_u64s(b: &[u8]) -> Result<Vec<u64>, StoreError> {
    if !b.len().is_multiple_of(8) {
        return Err(StoreError::Serialization(
            "minhash length is not a multiple of 8".to_owned(),
        ));
    }
    Ok(b.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::traffic::TrustLane;

    #[test]
    fn labels_roundtrip() {
        assert_eq!(label(&TrustLane::TrustedUi).unwrap(), "trusted_ui");
        assert_eq!(
            parse_label::<TrustLane>("diagnostic").unwrap(),
            TrustLane::Diagnostic
        );
        assert!(parse_label::<TrustLane>("nope").is_err());
    }

    #[test]
    fn u64_packing_roundtrips() {
        let v = vec![0, 1, u64::MAX, 0xdead_beef];
        assert_eq!(unpack_u64s(&pack_u64s(&v)).unwrap(), v);
        assert!(unpack_u64s(&[1, 2, 3]).is_err());
    }

    #[test]
    fn signed_sql_slots_preserve_all_unsigned_bits() {
        for value in [0, 1, (1 << 63) - 1, 1 << 63, u64::MAX] {
            assert_eq!(unsigned_bits(signed_bits(value).unwrap()).unwrap(), value);
        }
        assert_eq!(signed_bits(1 << 63).unwrap(), i64::MIN);
        assert_eq!(signed_bits(u64::MAX).unwrap(), -1);
        assert!(conv::<u64, i64>(u64::MAX, "counter").is_err());
        assert!(conv::<i64, u64>(-1, "counter").is_err());
    }

    #[test]
    fn timestamps_round_trip_on_every_representation() {
        let ts = chrono::DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap();
        assert_eq!(ts_from_micros(ts_to_micros(ts)).unwrap(), ts);
        assert_eq!(ts_from_naive(ts_to_naive(ts)), ts);
        // the sentinels are year 1 and year 9999 on both new engines
        let never = ts_from_micros(SQLITE_POS_INFINITY).unwrap();
        assert_eq!(never.to_rfc3339(), "9999-12-31T23:59:59.999999+00:00");
        let always = ts_from_micros(SQLITE_NEG_INFINITY).unwrap();
        assert_eq!(always.to_rfc3339(), "0001-01-01T00:00:00+00:00");
        assert!(ts_from_micros(i64::MAX).is_err());
        // a naive value past the TIMESTAMP range survives the MariaDB form
        let far = chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
            .unwrap()
            .and_hms_micro_opt(23, 59, 59, 999_999)
            .unwrap();
        assert_eq!(ts_to_naive(ts_from_naive(far)), far);
    }

    #[test]
    fn json_text_is_compact_and_lossless() {
        let value = serde_json::json!({ "b": [1, null, "x"], "a": "é𝄞" });
        let text = to_json_text(&value);
        assert_eq!(text, r#"{"a":"é𝄞","b":[1,null,"x"]}"#);
        assert_eq!(from_json_text(&text).unwrap(), value);
        assert!(from_json_text("{").is_err());
    }

    #[test]
    fn zero_days_means_no_expiry() {
        let now = chrono::Utc::now();
        assert!(expiry(now, 0).is_none());
        assert_eq!(expiry(now, 2).unwrap() - now, ChronoDuration::days(2));
    }
}
