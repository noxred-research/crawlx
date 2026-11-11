//! `PageRepo` over `pages`.

use crate::codec::{canonical_to_json, conv, digest, from_json, get, label, opt_digest, parse_label};
use crate::error::db;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::{KnownPage, PageBilling, PageRecord, PageRepo, NOT_CACHEABLE_PATH};
use crawlx_core::traffic::TrustLane;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use sqlx::postgres::PgRow;

fn artifact_ref(id: Option<uuid::Uuid>, digest: Option<Vec<u8>>) -> Result<Option<ArtifactRef>, StoreError> {
    match (id, opt_digest(digest)?) {
        (Some(id), Some(digest)) => Ok(Some(ArtifactRef {
            id: ArtifactId(id),
            digest,
        })),
        (None, _) => Ok(None),
        (Some(_), None) => Err(StoreError::Serialization("artifact id without digest".to_owned())),
    }
}

fn page_url(r: &PgRow) -> Result<CanonicalUrl, StoreError> {
    from_json::<CanonicalUrl>(
        get::<Option<serde_json::Value>>(r, "url_meta")?
            .ok_or_else(|| StoreError::Serialization("page without url_meta".to_owned()))?,
    )
}

fn page_links(r: &PgRow) -> Result<Vec<String>, StoreError> {
    let links: Option<serde_json::Value> = get(r, "links")?;
    Ok(links.map(from_json).transpose()?.unwrap_or_default())
}

fn page_from_row(r: &PgRow) -> Result<PageRecord, StoreError> {
    Ok(PageRecord {
        run: CrawlRunId(get(r, "run_id")?),
        frontier_id: get::<Option<i64>>(r, "frontier_id")?.unwrap_or_default(),
        url: page_url(r)?,
        status: conv(
            get::<Option<i32>>(r, "http_status")?.unwrap_or_default(),
            "http_status",
        )?,
        content_type: get(r, "content_type")?,
        content_digest: digest(&get::<Option<Vec<u8>>>(r, "content_digest")?.unwrap_or_default())?,
        title: get(r, "title")?,
        markdown: artifact_ref(get(r, "markdown_artifact_id")?, get(r, "markdown_digest")?)?,
        html: artifact_ref(get(r, "html_artifact_id")?, get(r, "html_digest")?)?,
        metadata: get(r, "metadata")?,
        links: page_links(r)?,
        fetched_at: get(r, "fetched_at")?,
        lane: parse_label::<TrustLane>(&get::<String>(r, "lane")?)?,
    })
}

/// The `pages.host_key` of `domain` (its lower-case reversed host) and, with `subdomains`, the
/// `LIKE` pattern of the keys of its subdomains (`key`, a dot, anything; `LIKE` metacharacters
/// escaped). A subdomain's reversed host starts with the domain's, so a prefix pattern finds it.
fn host_keys(domain: &str, subdomains: bool) -> (String, Option<String>) {
    let key: String = domain
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .chars()
        .rev()
        .collect();
    let below = subdomains.then(|| {
        let mut pattern = String::with_capacity(key.len() + 3);
        for c in key.chars() {
            if matches!(c, '%' | '_' | '\\') {
                pattern.push('\\');
            }
            pattern.push(c);
        }
        pattern.push_str(".%");
        pattern
    });
    (key, below)
}

impl Pg {
    /// Write the latest-page projection using the caller's result transaction.
    pub(super) async fn put_page_tx(
        &self,
        page: &PageRecord,
        connection: &mut sqlx::PgConnection,
    ) -> Result<(), StoreError> {
        self.put_page_projection_tx(page, connection, "anonymous", false)
            .await
    }

    /// Preserve the first observed projection while retaining later captures separately.
    pub(super) async fn put_page_projection_tx(
        &self,
        page: &PageRecord,
        connection: &mut sqlx::PgConnection,
        role: &str,
        first_canonical: bool,
    ) -> Result<(), StoreError> {
        let (tenant, zdr) = Self::privacy_scope_tx(connection, page.run).await?;
        if zdr {
            self.ephemeral_put(tenant, page.run, page.frontier_id, "page_record", page)
                .await?;
        }
        let canonical = (!zdr).then_some(page.url.url.as_str());
        let content_type = if zdr { None } else { page.content_type.as_ref() };
        let title = if zdr { None } else { page.title.as_ref() };
        let billing_metadata = if zdr {
            let config: crawlx_core::CreateCrawl = self
                .ephemeral_get(tenant, page.run, i64::MIN, "run_config")
                .await?;
            let document = crawlx_core::scrape::ScrapeDocument::from_page_metadata(&page.metadata);
            let credits = match (config.scrape.as_ref(), document.as_ref()) {
                (Some(job), Some(document)) => {
                    crawlx_core::scrape::page_credits(&job.options, document, true)
                }
                _ => 1,
            };
            Some(serde_json::json!({ "billing": {
                "credits": credits,
                "llm_tokens": document.as_ref().map_or(0, |document| document.llm_tokens),
                "pages": 1,
            }}))
        } else {
            None
        };
        let metadata = billing_metadata.as_ref().unwrap_or(&page.metadata);
        let links = if zdr {
            None
        } else {
            Some(
                serde_json::to_value(&page.links)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?,
            )
        };
        let url_meta = if zdr {
            None
        } else {
            Some(canonical_to_json(&page.url)?)
        };
        let plane = if page.lane == TrustLane::TrustedUi {
            "browser"
        } else {
            "http"
        };
        sqlx::query(
            "INSERT INTO pages (page_id, run_id, frontier_id, plane, url_hash, canonical_url, http_status, content_type, content_digest, \
               markdown_artifact_id, html_artifact_id, metadata, links, fetched_at, expires_at, lane, title, url_meta, markdown_digest, html_digest, role) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
               (SELECT expires_at FROM crawl_runs WHERE run_id = $2), $15, $16, $17, $18, $19, $20) \
             ON CONFLICT (run_id, role, url_hash) DO UPDATE SET frontier_id = EXCLUDED.frontier_id, plane = EXCLUDED.plane, \
               canonical_url = EXCLUDED.canonical_url, \
               http_status = EXCLUDED.http_status, content_type = EXCLUDED.content_type, content_digest = EXCLUDED.content_digest, \
               markdown_artifact_id = EXCLUDED.markdown_artifact_id, html_artifact_id = EXCLUDED.html_artifact_id, metadata = EXCLUDED.metadata, \
               links = EXCLUDED.links, fetched_at = EXCLUDED.fetched_at, lane = EXCLUDED.lane, title = EXCLUDED.title, \
               url_meta = EXCLUDED.url_meta, markdown_digest = EXCLUDED.markdown_digest, html_digest = EXCLUDED.html_digest WHERE NOT $21",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(page.run.0)
        .bind(page.frontier_id)
        .bind(plane)
        .bind(page.url.key.0.to_vec())
        .bind(canonical)
        .bind(i32::from(page.status))
        .bind(content_type)
        .bind(page.content_digest.0.to_vec())
        .bind(page.markdown.as_ref().filter(|_| !zdr).map(|a| a.id.0))
        .bind(page.html.as_ref().filter(|_| !zdr).map(|a| a.id.0))
        .bind(metadata)
        .bind(links)
        .bind(page.fetched_at)
        .bind(label(&page.lane)?)
        .bind(title)
        .bind(url_meta)
        .bind(page.markdown.as_ref().filter(|_| !zdr).map(|a| a.digest.0.to_vec()))
        .bind(page.html.as_ref().filter(|_| !zdr).map(|a| a.digest.0.to_vec()))
        .bind(role)
        .bind(first_canonical)
        .execute(connection)
        .await
        .map_err(db)?;
        Ok(())
    }
}

#[async_trait]
impl PageRepo for Pg {
    async fn put(&self, page: &PageRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("page.put");
        let mut tx = self.pool.begin().await.map_err(db)?;
        self.put_page_tx(page, &mut tx).await?;
        tx.commit().await.map_err(db)
    }
    async fn committed_page_keyset(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        if !(1..=64).contains(&limit) {
            return Err(StoreError::Conflict("page keyset limit must be 1..64".into()));
        }
        let (tenant, zdr) = self.privacy_scope(run).await?;
        if crate::tenant::current().is_some_and(|scope| scope != tenant) {
            return Err(StoreError::AccessDenied("page capture tenant mismatch".into()));
        }
        if zdr {
            return Err(StoreError::RetentionDenied(
                "durable archive cannot read zdr pages".into(),
            ));
        }
        let expired: bool = sqlx::query_scalar(
            "SELECT expires_at IS NOT NULL AND expires_at<=clock_timestamp() FROM crawl_runs WHERE run_id=$1",
        )
        .bind(run.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        if expired {
            return Err(StoreError::RetentionDenied(
                "committed page source expired".into(),
            ));
        }
        let rows = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT c.payload FROM page_captures c JOIN crawl_runs r ON r.run_id=c.run_id AND r.tenant_id=c.tenant_id \
             JOIN url_frontier f ON f.run_id=c.run_id AND f.frontier_id=c.frontier_id \
             WHERE c.run_id=$1 AND c.frontier_id>$2 AND f.status='succeeded' \
             AND f.fencing_token=c.fence AND f.state_version=c.state_version+1 \
             AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) \
             AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp()) AND r.retention_mode<>'zdr' \
             ORDER BY c.frontier_id LIMIT $3",
        )
        .bind(run.0)
        .bind(after)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.into_iter().map(from_json).collect()
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<PageRecord>, StoreError> {
        let _timer = self.query_timer("page.list");
        let (tenant, zdr) = self.privacy_scope(run).await?;
        if crate::tenant::current().is_some_and(|scope| scope != tenant) {
            return Err(StoreError::AccessDenied("page capture tenant mismatch".into()));
        }
        let dynamic: bool = sqlx::query_scalar("SELECT mode='dynamic' FROM crawl_runs WHERE run_id=$1")
            .bind(run.0)
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        let observed: std::collections::BTreeSet<i64> = sqlx::query_scalar(
            "SELECT frontier_id FROM url_frontier WHERE run_id=$1 AND via='interaction' ORDER BY frontier_id",
        )
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .into_iter()
        .collect();
        // Ordinary URL pages retain their canonical projection. Observations expose their
        // immutable renditions instead, including in runs that also perform URL work.
        let rows = sqlx::query(
            "SELECT p.run_id,p.frontier_id,p.url_meta,p.http_status,p.content_type,p.content_digest,p.title, \
               p.markdown_artifact_id,p.markdown_digest,p.html_artifact_id,p.html_digest,p.metadata,p.links,p.fetched_at,p.lane \
             FROM pages p WHERE p.run_id=$1 AND NOT $2 \
               AND NOT EXISTS(SELECT 1 FROM url_frontier f WHERE f.frontier_id=p.frontier_id AND f.run_id=$1 AND f.via='interaction') \
             ORDER BY p.fetched_at,p.page_id",
        )
        .bind(run.0)
        .bind(dynamic)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut pages = Vec::new();
        if !zdr {
            for row in &rows {
                pages.push(page_from_row(row)?);
            }
            if dynamic || !observed.is_empty() {
                let mut after = 0;
                loop {
                    let batch = self.committed_page_keyset(run, after, 64).await?;
                    let Some(last) = batch.last() else {
                        break;
                    };
                    after = last.frontier_id;
                    for mut page in batch {
                        if dynamic || observed.contains(&page.frontier_id) {
                            page.mark_late_xhr_unattributed();
                            pages.push(page);
                        }
                    }
                }
            }
        } else {
            let mut ids = std::collections::BTreeSet::new();
            for row in &rows {
                ids.insert(
                    get::<Option<i64>>(row, "frontier_id")?.ok_or_else(|| {
                        StoreError::Serialization("zdr page without frontier id".to_owned())
                    })?,
                );
            }
            let observed_ids: Vec<i64> = sqlx::query_scalar(
                "SELECT frontier_id FROM url_frontier WHERE run_id=$1 AND status='succeeded' AND ($2 OR via='interaction') ORDER BY frontier_id",
            )
            .bind(run.0)
            .bind(dynamic)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            ids.extend(observed_ids);
            let buffer = self.delivery.as_ref().ok_or_else(|| {
                StoreError::RetentionDenied("required ephemeral zdr buffer is unavailable".to_owned())
            })?;
            for id in ids {
                // Never reconstruct acknowledged, expired or evicted content from durable rows.
                if let Some(entry) = buffer.get(tenant, run, id).await? {
                    if let Some(blob) = entry.blobs.get("page_record") {
                        let mut page: PageRecord = serde_json::from_slice(&blob.bytes)?;
                        if page.run != run || page.frontier_id != id {
                            return Err(StoreError::Serialization("zdr page scope mismatch".into()));
                        }
                        if dynamic || observed.contains(&id) {
                            page.mark_late_xhr_unattributed();
                        }
                        pages.push(page);
                    }
                }
            }
        }
        pages.sort_by_key(|page| (page.fetched_at, page.frontier_id));
        Ok(pages)
    }

    async fn billing(&self, run: CrawlRunId) -> Result<Option<PageBilling>, StoreError> {
        if !self.privacy_scope(run).await?.1 {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT COALESCE(sum((metadata #>> '{billing,credits}')::numeric), 0)::text AS credits, \
             COALESCE(sum((metadata #>> '{billing,llm_tokens}')::numeric), 0)::text AS llm_tokens, \
             count(*) AS pages FROM pages WHERE run_id = $1",
        )
        .bind(run.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        let number = |field: &str| -> Result<u64, StoreError> {
            get::<String>(&row, field)?
                .parse()
                .map_err(|_| StoreError::Serialization("page billing total exceeds u64".to_owned()))
        };
        Ok(Some(PageBilling::new(
            number("credits")?,
            number("llm_tokens")?,
            conv(get::<i64>(&row, "pages")?, "pages")?,
        )))
    }

    async fn recent_for_url(
        &self,
        tenant: crawlx_core::TenantId,
        url: &CanonicalUrl,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        let _timer = self.query_timer("page.recent_for_url");
        let rows = sqlx::query(
            "SELECT p.run_id, p.frontier_id, p.url_meta, p.http_status, p.content_type, p.content_digest, p.title, p.markdown_artifact_id, \
               p.markdown_digest, p.html_artifact_id, p.html_digest, p.metadata, p.links, p.fetched_at, p.lane \
             FROM pages p JOIN crawl_runs r ON r.run_id = p.run_id \
             WHERE r.tenant_id = $1 AND p.url_hash = $2 AND r.retention_mode <> 'zdr' \
             ORDER BY p.fetched_at DESC, p.page_id DESC LIMIT $3",
        )
        .bind(tenant.0)
        .bind(url.key.0.to_vec())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(page_from_row).collect()
    }

    async fn known_pages(
        &self,
        tenant: TenantId,
        domain: &str,
        subdomains: bool,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<KnownPage>, StoreError> {
        let _timer = self.query_timer("page.known_pages");
        let (key, below) = host_keys(domain, subdomains);
        // an unnamed statement is planned for these very values, so the prefix `LIKE` can use
        // the `pages_host_key` index (a cached generic plan could not)
        let rows = sqlx::query(
            "SELECT p.url_meta, p.title, \
               CASE WHEN jsonb_typeof(p.metadata -> 'description') = 'string' THEN p.metadata ->> 'description' END AS description, p.links \
             FROM pages p JOIN crawl_runs r ON r.run_id = p.run_id \
             WHERE r.tenant_id = $1 AND (p.host_key = $2 OR p.host_key LIKE $3) \
               AND r.retention_mode <> 'zdr' AND (r.expires_at IS NULL OR r.expires_at > $4) \
               AND COALESCE(p.http_status, 0) < 400 AND COALESCE(p.metadata #>> $5::text[], '') <> 'true' \
             ORDER BY p.fetched_at DESC, p.page_id DESC LIMIT $6",
        )
        .bind(tenant.0)
        .bind(key)
        .bind(below)
        .bind(now)
        .bind(NOT_CACHEABLE_PATH.map(str::to_owned).to_vec())
        .bind(i64::from(limit))
        .persistent(false)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(KnownPage {
                    url: page_url(r)?,
                    title: get(r, "title")?,
                    description: get(r, "description")?,
                    links: page_links(r)?,
                })
            })
            .collect()
    }
}
