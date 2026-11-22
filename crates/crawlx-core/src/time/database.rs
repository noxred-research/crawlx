//! Database column codecs for [`Timestamp`]: the same `TIMESTAMPTZ` (PostgreSQL) and
//! `TIMESTAMP`/`DATETIME` (MySQL, MariaDB) wire forms the former `chrono` codec used, by way of
//! the `time` crate codecs of sqlx.

use super::{NaiveDateTime, Timestamp};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::mysql::{MySqlTypeInfo, MySqlValueRef};
use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, MySql, Postgres, Type};
use time::{OffsetDateTime, PrimitiveDateTime};

impl From<Timestamp> for OffsetDateTime {
    fn from(value: Timestamp) -> Self {
        OffsetDateTime::from(value.utc())
    }
}

fn from_offset(value: OffsetDateTime) -> Result<Timestamp, BoxDynError> {
    Timestamp::from_time(value).ok_or_else(|| "timestamp out of range".into())
}

impl Type<Postgres> for Timestamp {
    fn type_info() -> PgTypeInfo {
        <OffsetDateTime as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <OffsetDateTime as Type<Postgres>>::compatible(ty)
    }
}

impl PgHasArrayType for Timestamp {
    fn array_type_info() -> PgTypeInfo {
        <OffsetDateTime as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <OffsetDateTime as PgHasArrayType>::array_compatible(ty)
    }
}

impl Encode<'_, Postgres> for Timestamp {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        Encode::<Postgres>::encode_by_ref(&OffsetDateTime::from(*self), buf)
    }

    fn size_hint(&self) -> usize {
        Encode::<Postgres>::size_hint(&OffsetDateTime::from(*self))
    }
}

impl<'r> Decode<'r, Postgres> for Timestamp {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        from_offset(<OffsetDateTime as Decode<Postgres>>::decode(value)?)
    }
}

impl Type<MySql> for Timestamp {
    fn type_info() -> MySqlTypeInfo {
        <OffsetDateTime as Type<MySql>>::type_info()
    }

    fn compatible(ty: &MySqlTypeInfo) -> bool {
        <OffsetDateTime as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for Timestamp {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        Encode::<MySql>::encode_by_ref(&OffsetDateTime::from(*self), buf)
    }
}

impl<'r> Decode<'r, MySql> for Timestamp {
    fn decode(value: MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
        from_offset(<OffsetDateTime as Decode<MySql>>::decode(value)?)
    }
}

/// A zoneless date and time is the MariaDB `DATETIME(6)` bind form of a timestamp (see the storage
/// codec): it keeps the full range, where `TIMESTAMP` ends in 2038.
impl Type<MySql> for NaiveDateTime {
    fn type_info() -> MySqlTypeInfo {
        <PrimitiveDateTime as Type<MySql>>::type_info()
    }

    fn compatible(ty: &MySqlTypeInfo) -> bool {
        <PrimitiveDateTime as Type<MySql>>::compatible(ty)
    }
}

impl Encode<'_, MySql> for NaiveDateTime {
    fn encode_by_ref(&self, buf: &mut Vec<u8>) -> Result<IsNull, BoxDynError> {
        Encode::<MySql>::encode_by_ref(&self.plain(), buf)
    }
}

impl<'r> Decode<'r, MySql> for NaiveDateTime {
    fn decode(value: MySqlValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::from_plain(<PrimitiveDateTime as Decode<MySql>>::decode(
            value,
        )?))
    }
}
