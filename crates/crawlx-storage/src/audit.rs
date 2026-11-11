//! Daily Merkle export of the `audit_events` chain.
//!
//! For one tenant and one UTC day the export reads the tenant's `audit_events`
//! rows in `(occurred_at, audit_id)` order, takes each row's `entry_hash`
//! (already `BLAKE3(prev_hash || canonical_json(row))`, see
//! [`crate::retention::append_audit`]) as a leaf, folds the leaves into a
//! BLAKE3 Merkle root and writes a small JSON record to the object store under
//! [`export_key`] (`audit/{tenant}/{yyyy-mm-dd}.json`).
//!
//! The export goes through the [`ArtifactBlobs`] seam, not through the
//! run-scoped `ArtifactStore`, because it belongs to a tenant and a day rather
//! than a run. Immutability of the written object is a property of the bucket:
//! production points the export at an object-lock (WORM) bucket; the artifact
//! orphan collector skips the `audit/` prefix so a shared bucket never reaps an
//! export.
//!
//! # Tree shape
//!
//! Leaves are hashed pairwise with [`MERKLE_DOMAIN`]: `node = BLAKE3(domain || 0
//! || left || right)`. A level with an odd number of nodes duplicates its last
//! node (Bitcoin convention), so every level pairs up fully. A single leaf is
//! its own root; an empty day has no root (`null`) and `count = 0`.

use crate::artifacts::ArtifactBlobs;
use crate::backend::PgBackend;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use chrono::{NaiveDate, TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::{StoreError, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Domain tag of every inner node of the tree.
pub const MERKLE_DOMAIN: &str = "crawlx/audit-merkle/v1";
/// How the leaves were obtained: each leaf is the row's `entry_hash`
/// (`BLAKE3("crawlx/audit-chain/v1" || prev_hash || canonical_json(row))`).
pub const LEAVES_HASH_ALGO: &str = "blake3-audit-chain-entry-hash";
/// Object-key prefix of every export; the orphan collector never deletes under it.
pub const EXPORT_PREFIX: &str = "audit/";

/// Object key of a tenant's export for `day`.
#[must_use]
pub fn export_key(tenant: TenantId, day: NaiveDate) -> String {
    format!("{EXPORT_PREFIX}{tenant}/{}.json", day.format("%Y-%m-%d"))
}

/// BLAKE3 Merkle root of `leaves` (see the module docs for the tree shape);
/// `None` when there are no leaves.
#[must_use]
pub fn merkle_root(leaves: &[Digest]) -> Option<Digest> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<Digest> = leaves.to_vec();
    let mut buf = [0u8; 64];
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            // odd level: the last node pairs with itself
            let last = level[level.len() - 1];
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.as_chunks::<2>().0 {
            buf[..32].copy_from_slice(&pair[0].0);
            buf[32..].copy_from_slice(&pair[1].0);
            next.push(Digest::of(MERKLE_DOMAIN, &buf));
        }
        level = next;
    }
    level.first().copied()
}

/// The record written to `audit/{tenant}/{day}.json`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct AuditDayExport {
    /// Tenant whose chain was folded.
    pub tenant: TenantId,
    /// UTC day covered (`occurred_at` in `[day 00:00Z, day+1 00:00Z)`).
    pub day: NaiveDate,
    /// Number of rows (leaves).
    pub count: u64,
    /// Merkle root, `None` for a day without rows.
    pub root: Option<Digest>,
    /// How leaves were derived ([`LEAVES_HASH_ALGO`]).
    pub leaves_hash_algo: String,
    /// `audit_id` of the first row in order, if any.
    pub first_id: Option<i64>,
    /// `audit_id` of the last row in order, if any.
    pub last_id: Option<i64>,
}

impl AuditDayExport {
    /// Fold ordered `(audit_id, entry_hash)` leaves of `tenant` on `day`.
    #[must_use]
    pub fn from_leaves(tenant: TenantId, day: NaiveDate, leaves: &[(i64, Digest)]) -> Self {
        let digests: Vec<Digest> = leaves.iter().map(|(_, d)| *d).collect();
        Self {
            tenant,
            day,
            count: u64::try_from(leaves.len()).unwrap_or(u64::MAX),
            root: merkle_root(&digests),
            leaves_hash_algo: LEAVES_HASH_ALGO.to_owned(),
            first_id: leaves.first().map(|(id, _)| *id),
            last_id: leaves.last().map(|(id, _)| *id),
        }
    }
}

/// Reads `audit_events` and writes one export per tenant and day.
pub struct MerkleExport<B: Sql = PgBackend> {
    store: Store<B>,
    blobs: Arc<dyn ArtifactBlobs>,
}

impl<B: Sql> std::fmt::Debug for MerkleExport<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleExport")
            .field("bucket", &self.blobs.bucket())
            .finish_non_exhaustive()
    }
}

/// `[day 00:00Z, day+1 00:00Z)`.
fn day_bounds(day: NaiveDate) -> Result<(Timestamp, Timestamp), StoreError> {
    let start = day
        .and_hms_opt(0, 0, 0)
        .map(|t| Utc.from_utc_datetime(&t))
        .ok_or_else(|| StoreError::Backend(format!("day {day} has no midnight")))?;
    let end = day
        .succ_opt()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| Utc.from_utc_datetime(&t))
        .ok_or_else(|| StoreError::Backend(format!("day after {day} is out of range")))?;
    Ok((start, end))
}

fn digest_from_column(bytes: &[u8]) -> Result<Digest, StoreError> {
    <[u8; 32]>::try_from(bytes)
        .map(Digest)
        .map_err(|_| StoreError::Serialization(format!("entry_hash has {} bytes, expected 32", bytes.len())))
}

impl<B: Sql> MerkleExport<B> {
    /// Export over the `audit_events` of `store` into `blobs` (the audit bucket).
    #[must_use]
    pub fn new(store: Store<B>, blobs: Arc<dyn ArtifactBlobs>) -> Self {
        Self { store, blobs }
    }

    /// Ordered `(audit_id, entry_hash)` leaves of `tenant` on `day`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] if `day` is at the edge of the representable range,
    /// [`StoreError::Serialization`] if an `entry_hash` is not 32 bytes, or the database error.
    pub async fn leaves(&self, tenant: TenantId, day: NaiveDate) -> Result<Vec<(i64, Digest)>, StoreError> {
        let (start, end) = day_bounds(day)?;
        let rows = stmt!(
            B,
            "SELECT audit_id, entry_hash FROM audit_events \
             WHERE tenant_id = $1 AND occurred_at >= $2 AND occurred_at < $3 \
             ORDER BY occurred_at, audit_id"
        )
        .uuid(tenant.0)
        .ts(start)
        .ts(end)
        .fetch_all_pool(&self.store.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let id = row.i64("audit_id")?;
                digest_from_column(&row.bytes("entry_hash")?).map(|digest| (id, digest))
            })
            .collect()
    }

    /// Tenants with at least one `audit_events` row on `day`, sorted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Backend`] for a day at the edge of the representable range or
    /// the database error.
    pub async fn tenants_with_events(&self, day: NaiveDate) -> Result<Vec<TenantId>, StoreError> {
        let (start, end) = day_bounds(day)?;
        let rows = stmt!(
            B,
            "SELECT DISTINCT tenant_id FROM audit_events \
             WHERE tenant_id IS NOT NULL AND occurred_at >= $1 AND occurred_at < $2 ORDER BY tenant_id"
        )
        .ts(start)
        .ts(end)
        .fetch_all_pool(&self.store.pool)
        .await?;
        rows.iter()
            .map(|row| row.uuid("tenant_id").map(TenantId))
            .collect()
    }

    /// Compute and write `tenant`'s export for `day`, replacing any existing object with
    /// the same key (an object-lock bucket refuses the replacement; the first write wins).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::leaves`], [`StoreError::Serialization`] if the record
    /// cannot be encoded, or the backend error of the write.
    pub async fn export_day(&self, tenant: TenantId, day: NaiveDate) -> Result<AuditDayExport, StoreError> {
        let leaves = self.leaves(tenant, day).await?;
        let export = AuditDayExport::from_leaves(tenant, day, &leaves);
        let bytes = serde_json::to_vec(&export)?;
        self.blobs.put(&export_key(tenant, day), &bytes).await?;
        Ok(export)
    }

    /// [`Self::export_day`] for every tenant that has rows on `day`.
    ///
    /// # Errors
    ///
    /// Returns the first error of [`Self::tenants_with_events`] or [`Self::export_day`].
    pub async fn export_all(&self, day: NaiveDate) -> Result<Vec<AuditDayExport>, StoreError> {
        let tenants = self.tenants_with_events(day).await?;
        let mut out = Vec::with_capacity(tenants.len());
        for tenant in tenants {
            out.push(self.export_day(tenant, day).await?);
        }
        Ok(out)
    }

    /// The stored export, if one was written.
    ///
    /// # Errors
    ///
    /// Returns the backend error of the read or [`StoreError::Serialization`] if the object
    /// is not a valid record.
    pub async fn stored(
        &self,
        tenant: TenantId,
        day: NaiveDate,
    ) -> Result<Option<AuditDayExport>, StoreError> {
        match self.blobs.get(&export_key(tenant, day)).await? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn leaf(b: u8) -> Digest {
        Digest([b; 32])
    }

    fn node(l: &Digest, r: &Digest) -> Digest {
        Digest::of(MERKLE_DOMAIN, &[l.0.as_slice(), r.0.as_slice()].concat())
    }

    #[test]
    fn empty_has_no_root() {
        assert_eq!(merkle_root(&[]), None);
    }

    #[test]
    fn one_leaf_is_its_own_root() {
        assert_eq!(merkle_root(&[leaf(1)]), Some(leaf(1)));
    }

    #[test]
    fn two_leaves_hash_pairwise() {
        let (a, b) = (leaf(1), leaf(2));
        assert_eq!(merkle_root(&[a, b]), Some(node(&a, &b)));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]), "order matters");
    }

    #[test]
    fn three_leaves_duplicate_the_last() {
        let (a, b, c) = (leaf(1), leaf(2), leaf(3));
        let want = node(&node(&a, &b), &node(&c, &c));
        assert_eq!(merkle_root(&[a, b, c]), Some(want));
        // four leaves with the last repeated give the same root: the duplication is explicit
        assert_eq!(merkle_root(&[a, b, c, c]), Some(want));
    }

    #[test]
    fn five_leaves_duplicate_on_two_levels() {
        let l: Vec<Digest> = (1..=5).map(leaf).collect();
        let ab = node(&l[0], &l[1]);
        let cd = node(&l[2], &l[3]);
        let ee = node(&l[4], &l[4]);
        let abcd = node(&ab, &cd);
        let eeee = node(&ee, &ee);
        assert_eq!(merkle_root(&l), Some(node(&abcd, &eeee)));
    }

    #[test]
    fn export_record_shape() {
        let tenant = TenantId::new();
        let day = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let e = AuditDayExport::from_leaves(tenant, day, &[(7, leaf(1)), (9, leaf(2))]);
        assert_eq!(e.count, 2);
        assert_eq!((e.first_id, e.last_id), (Some(7), Some(9)));
        assert_eq!(e.root, merkle_root(&[leaf(1), leaf(2)]));
        let json: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(json["day"], "2026-01-15");
        assert_eq!(json["leaves_hash_algo"], LEAVES_HASH_ALGO);
        assert_eq!(
            json["root"].as_str().map(str::len),
            Some(64),
            "root is lowercase hex"
        );
        let back: AuditDayExport = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
        assert_eq!(export_key(tenant, day), format!("audit/{tenant}/2026-01-15.json"));
        let empty = AuditDayExport::from_leaves(tenant, day, &[]);
        assert_eq!((empty.count, empty.root, empty.first_id), (0, None, None));
    }

    #[test]
    fn day_bounds_are_half_open_utc() {
        let day = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let (start, end) = day_bounds(day).unwrap();
        assert_eq!(start.to_rfc3339(), "2026-01-15T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-01-16T00:00:00+00:00");
        assert!(day_bounds(NaiveDate::MAX).is_err());
    }
}
