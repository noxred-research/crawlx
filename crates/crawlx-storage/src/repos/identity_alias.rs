//! `IdentityAliasRepo` over `identity_aliases`.

use crate::backend::Dialect;
use crate::codec::{conv, digest};
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::{IdentityAlias, IdentityAliasRepo};
use crawlx_core::{CrawlRunId, StoreError};

#[async_trait]
impl<B: Sql> IdentityAliasRepo for Store<B> {
    async fn record_alias(&self, run: CrawlRunId, alias: &IdentityAlias) -> Result<(), StoreError> {
        let _timer = self.query_timer("identity.record_alias");
        let element_conflict =
            <B::Dialect as Dialect>::upsert_do_nothing(&["run_id", "identity_hash", "identity_version"]);
        let alias_conflict = <B::Dialect as Dialect>::upsert_do_nothing(&[
            "run_id",
            "alias_hash",
            "canonical_hash",
            "from_version",
            "to_version",
        ]);
        let mut tx = self.begin_write().await?;
        for (hash, version) in [
            (alias.alias, alias.from_version),
            (alias.canonical, alias.to_version),
        ] {
            stmt!(
                B,
                format!("INSERT INTO elements (run_id, identity_hash, identity_version) VALUES ($1, $2, $3) {element_conflict}")
            )
            .uuid(run.0)
            .bytes(&hash.0 .0)
            .i16(conv::<u16, i16>(version, "identity_version")?)
            .execute(tx.conn())
            .await?;
        }
        stmt!(
            B,
            format!(
                "INSERT INTO identity_aliases (run_id, alias_hash, canonical_hash, from_version, to_version, score) \
                 VALUES ($1, $2, $3, $4, $5, $6) {alias_conflict}"
            )
        )
        .uuid(run.0)
        .bytes(&alias.alias.0 .0)
        .bytes(&alias.canonical.0 .0)
        .i16(conv::<u16, i16>(alias.from_version, "from_version")?)
        .i16(conv::<u16, i16>(alias.to_version, "to_version")?)
        .f32(alias.score)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn aliases_of(
        &self,
        run: CrawlRunId,
        canonical: ElementIdentityHash,
    ) -> Result<Vec<IdentityAlias>, StoreError> {
        let _timer = self.query_timer("identity.aliases_of");
        let rows = stmt!(
            B,
            "SELECT alias_hash, canonical_hash, from_version, to_version, score FROM identity_aliases \
             WHERE run_id = $1 AND canonical_hash = $2 ORDER BY alias_hash, from_version, to_version"
        )
        .uuid(run.0)
        .bytes(&canonical.0 .0)
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(IdentityAlias {
                    alias: ElementIdentityHash(digest(&r.bytes("alias_hash")?)?),
                    canonical: ElementIdentityHash(digest(&r.bytes("canonical_hash")?)?),
                    from_version: conv::<i16, u16>(r.i16("from_version")?, "from_version")?,
                    to_version: conv::<i16, u16>(r.i16("to_version")?, "to_version")?,
                    score: r.f32("score")?,
                })
            })
            .collect()
    }
}
