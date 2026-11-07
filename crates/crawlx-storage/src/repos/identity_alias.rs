//! `IdentityAliasRepo` over `identity_aliases` (migration 0009).

use crate::codec::{conv, digest, get};
use crate::error::db;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::{IdentityAlias, IdentityAliasRepo};
use crawlx_core::{CrawlRunId, StoreError};

#[async_trait]
impl IdentityAliasRepo for Pg {
    async fn record_alias(&self, run: CrawlRunId, alias: &IdentityAlias) -> Result<(), StoreError> {
        let _timer = self.query_timer("identity.record_alias");
        let mut tx = self.pool.begin().await.map_err(db)?;
        for (hash, version) in [
            (alias.alias, alias.from_version),
            (alias.canonical, alias.to_version),
        ] {
            sqlx::query(
                "INSERT INTO elements (run_id, identity_hash, identity_version) VALUES ($1, $2, $3) \
                 ON CONFLICT (run_id, identity_hash, identity_version) DO NOTHING",
            )
            .bind(run.0)
            .bind(hash.0 .0.as_slice())
            .bind(conv::<u16, i16>(version, "identity_version")?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        sqlx::query(
            "INSERT INTO identity_aliases (run_id, alias_hash, canonical_hash, from_version, to_version, score) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (run_id, alias_hash, canonical_hash, from_version, to_version) DO NOTHING",
        )
        .bind(run.0)
        .bind(alias.alias.0 .0.as_slice())
        .bind(alias.canonical.0 .0.as_slice())
        .bind(conv::<u16, i16>(alias.from_version, "from_version")?)
        .bind(conv::<u16, i16>(alias.to_version, "to_version")?)
        .bind(alias.score)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn aliases_of(
        &self,
        run: CrawlRunId,
        canonical: ElementIdentityHash,
    ) -> Result<Vec<IdentityAlias>, StoreError> {
        let _timer = self.query_timer("identity.aliases_of");
        let rows = sqlx::query(
            "SELECT alias_hash, canonical_hash, from_version, to_version, score FROM identity_aliases \
             WHERE run_id = $1 AND canonical_hash = $2 ORDER BY alias_hash, from_version, to_version",
        )
        .bind(run.0)
        .bind(canonical.0 .0.as_slice())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(IdentityAlias {
                    alias: ElementIdentityHash(digest(&get::<Vec<u8>>(r, "alias_hash")?)?),
                    canonical: ElementIdentityHash(digest(&get::<Vec<u8>>(r, "canonical_hash")?)?),
                    from_version: conv::<i16, u16>(get::<i16>(r, "from_version")?, "from_version")?,
                    to_version: conv::<i16, u16>(get::<i16>(r, "to_version")?, "to_version")?,
                    score: get(r, "score")?,
                })
            })
            .collect()
    }
}
