//! `PageRepo` over `pages`.

use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect};
use crate::codec::{canonical_to_json, conv, digest, from_json, label, opt_digest, parse_label};
use crate::sql::{stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::repo::{KnownPage, PageBilling, PageRecord, PageRepo, NOT_CACHEABLE_PATH};
use crawlx_core::traffic::TrustLane;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};

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

fn page_url<R: SqlRow>(r: &R) -> Result<CanonicalUrl, StoreError> {
    from_json::<CanonicalUrl>(
        r.opt_json("url_meta")?
            .ok_or_else(|| StoreError::Serialization("page without url_meta".to_owned()))?,
    )
}

fn page_links<R: SqlRow>(r: &R) -> Result<Vec<String>, StoreError> {
    let links = r.opt_json("links")?;
    Ok(links.map(from_json).transpose()?.unwrap_or_default())
}

fn page_from_row<R: SqlRow>(r: &R) -> Result<PageRecord, StoreError> {
    Ok(PageRecord {
        run: CrawlRunId(r.uuid("run_id")?),
        frontier_id: r.opt_i64("frontier_id")?.unwrap_or_default(),
        url: page_url(r)?,
        status: conv(r.opt_i32("http_status")?.unwrap_or_default(), "http_status")?,
        content_type: r.opt_text("content_type")?,
        content_digest: digest(&r.opt_bytes("content_digest")?.unwrap_or_default())?,
        title: r.opt_text("title")?,
        markdown: artifact_ref(
            r.opt_uuid("markdown_artifact_id")?,
            r.opt_bytes("markdown_digest")?,
        )?,
        html: artifact_ref(r.opt_uuid("html_artifact_id")?, r.opt_bytes("html_digest")?)?,
        metadata: r.json("metadata")?,
        links: page_links(r)?,
        fetched_at: r.ts("fetched_at")?,
        lane: parse_label::<TrustLane>(&r.text("lane")?)?,
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

/// The `pages.host_key` PostgreSQL generates from a canonical URL: the host (bracketed IPv6
/// literal included), lower-cased and reversed; `None` when the URL has no `scheme://`
/// prefix. SQLite stores it in a plain column, written from here; MariaDB generates it.
#[must_use]
pub(crate) fn host_key_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let mut scheme_chars = scheme.chars();
    let first = scheme_chars.next()?;
    if !first.is_ascii_alphabetic()
        || !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    {
        return None;
    }
    // optional `userinfo@`: the first of `/ ? # @` decides
    let after_user = match rest.find(['/', '?', '#', '@']) {
        Some(at) if rest.as_bytes()[at] == b'@' => &rest[at + 1..],
        _ => rest,
    };
    let host = match after_user.strip_prefix('[') {
        Some(inside) => match inside.find([']', '/', '?', '#']) {
            Some(at) if inside.as_bytes()[at] == b']' => Some(&after_user[..at + 2]),
            _ => None,
        },
        None => None,
    };
    let host = host.unwrap_or_else(|| {
        let end = after_user
            .find(['/', '?', '#', ':', '@'])
            .unwrap_or(after_user.len());
        &after_user[..end]
    });
    Some(host.to_ascii_lowercase().chars().rev().collect())
}

impl<B: Sql> Store<B> {
    /// Write the latest-page projection using the caller's result transaction.
    pub(super) async fn put_page_tx(
        &self,
        page: &PageRecord,
        connection: &mut Conn<B>,
    ) -> Result<(), StoreError> {
        self.put_page_projection_tx(page, connection, "anonymous", false)
            .await
    }

    /// Preserve the first observed projection while retaining later captures separately.
    pub(super) async fn put_page_projection_tx(
        &self,
        page: &PageRecord,
        connection: &mut Conn<B>,
        role: &str,
        first_canonical: bool,
    ) -> Result<(), StoreError> {
        let (tenant, zdr) = Self::privacy_scope_tx(connection, page.run).await?;
        if zdr {
            self.ephemeral_put(tenant, page.run, page.frontier_id, "page_record", page)
                .await?;
        }
        let canonical = (!zdr).then_some(page.url.url.as_str());
        let content_type = if zdr { None } else { page.content_type.as_deref() };
        let title = if zdr { None } else { page.title.as_deref() };
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
        let lane = label(&page.lane)?;
        // SQLite keeps the host key in a plain column; PostgreSQL and MariaDB generate it
        let host_key = canonical.and_then(host_key_of);
        let sqlite = B::KIND == BackendKind::Sqlite;
        let mut set = vec![
            "frontier_id",
            "plane",
            "canonical_url",
            "http_status",
            "content_type",
            "content_digest",
            "markdown_artifact_id",
            "html_artifact_id",
            "metadata",
            "links",
            "fetched_at",
            "lane",
            "title",
            "url_meta",
            "markdown_digest",
            "html_digest",
        ];
        if sqlite {
            set.push("host_key");
        }
        let conflict =
            <B::Dialect as Dialect>::upsert_update(&["run_id", "role", "url_hash"], &set, Some("NOT $21"));
        let (host_column, host_value) = if sqlite { (", host_key", ", $22") } else { ("", "") };
        let mut insert = stmt!(
            B,
            format!(
                "INSERT INTO pages (page_id, run_id, frontier_id, plane, url_hash, canonical_url, http_status, content_type, content_digest, \
                   markdown_artifact_id, html_artifact_id, metadata, links, fetched_at, expires_at, lane, title, url_meta, markdown_digest, html_digest, role{host_column}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                   (SELECT expires_at FROM crawl_runs WHERE run_id = $2), $15, $16, $17, $18, $19, $20{host_value}) \
                 {conflict}"
            )
        )
        .uuid(uuid::Uuid::now_v7())
        .uuid(page.run.0)
        .i64(page.frontier_id)
        .text(plane)
        .bytes(&page.url.key.0)
        .opt_text(canonical)
        .i32(i32::from(page.status))
        .opt_text(content_type)
        .bytes(&page.content_digest.0)
        .opt_uuid(page.markdown.as_ref().filter(|_| !zdr).map(|a| a.id.0))
        .opt_uuid(page.html.as_ref().filter(|_| !zdr).map(|a| a.id.0))
        .json(metadata)
        .opt_json(links.as_ref())
        .ts(page.fetched_at)
        .text(&lane)
        .opt_text(title)
        .opt_json(url_meta.as_ref())
        .opt_bytes(page.markdown.as_ref().filter(|_| !zdr).map(|a| a.digest.0.as_slice()))
        .opt_bytes(page.html.as_ref().filter(|_| !zdr).map(|a| a.digest.0.as_slice()))
        .text(role)
        .bool(first_canonical);
        if sqlite {
            insert = insert.opt_text(host_key.as_deref());
        }
        insert.execute(connection).await?;
        Ok(())
    }
}

#[async_trait]
impl<B: Sql> PageRepo for Store<B> {
    async fn put(&self, page: &PageRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("page.put");
        let mut tx = self.begin_write().await?;
        self.put_page_tx(page, tx.conn()).await?;
        tx.commit().await
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
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let expired = stmt!(
            B,
            format!(
                "SELECT expires_at IS NOT NULL AND expires_at<={clock} AS expired FROM crawl_runs WHERE run_id=$1"
            )
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?
        .flag("expired")?;
        if expired {
            return Err(StoreError::RetentionDenied(
                "committed page source expired".into(),
            ));
        }
        let rows = stmt!(
            B,
            format!(
                "SELECT c.payload FROM page_captures c JOIN crawl_runs r ON r.run_id=c.run_id AND r.tenant_id=c.tenant_id \
                 JOIN url_frontier f ON f.run_id=c.run_id AND f.frontier_id=c.frontier_id \
                 WHERE c.run_id=$1 AND c.frontier_id>$2 AND f.status='succeeded' \
                 AND f.fencing_token=c.fence AND f.state_version=c.state_version+1 \
                 AND (c.expires_at IS NULL OR c.expires_at>{clock}) \
                 AND (r.expires_at IS NULL OR r.expires_at>{clock}) AND r.retention_mode<>'zdr' \
                 ORDER BY c.frontier_id LIMIT $3"
            )
        )
        .uuid(run.0)
        .i64(after)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter().map(|row| from_json(row.json("payload")?)).collect()
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<PageRecord>, StoreError> {
        let _timer = self.query_timer("page.list");
        let (tenant, zdr) = self.privacy_scope(run).await?;
        if crate::tenant::current().is_some_and(|scope| scope != tenant) {
            return Err(StoreError::AccessDenied("page capture tenant mismatch".into()));
        }
        let dynamic = stmt!(B, "SELECT mode::text AS mode FROM crawl_runs WHERE run_id=$1")
            .uuid(run.0)
            .fetch_one_pool(&self.pool)
            .await?
            .text("mode")?
            == "dynamic";
        let observed: std::collections::BTreeSet<i64> = stmt!(
            B,
            "SELECT frontier_id FROM url_frontier WHERE run_id=$1 AND via='interaction' ORDER BY frontier_id"
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?
        .iter()
        .map(|row| row.i64("frontier_id"))
        .collect::<Result<_, _>>()?;
        // Ordinary URL pages retain their canonical projection. Observations expose their
        // immutable renditions instead, including in runs that also perform URL work.
        let rows = stmt!(
            B,
            "SELECT p.run_id,p.frontier_id,p.url_meta,p.http_status,p.content_type,p.content_digest,p.title, \
               p.markdown_artifact_id,p.markdown_digest,p.html_artifact_id,p.html_digest,p.metadata,p.links,p.fetched_at,p.lane \
             FROM pages p WHERE p.run_id=$1 AND NOT $2 \
               AND NOT EXISTS(SELECT 1 FROM url_frontier f WHERE f.frontier_id=p.frontier_id AND f.run_id=$1 AND f.via='interaction') \
             ORDER BY p.fetched_at,p.page_id"
        )
        .uuid(run.0)
        .bool(dynamic)
        .fetch_all_pool(&self.pool)
        .await?;
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
                    row.opt_i64("frontier_id")?.ok_or_else(|| {
                        StoreError::Serialization("zdr page without frontier id".to_owned())
                    })?,
                );
            }
            let observed_ids: Vec<i64> = stmt!(
                B,
                "SELECT frontier_id FROM url_frontier WHERE run_id=$1 AND status='succeeded' AND ($2 OR via='interaction') ORDER BY frontier_id"
            )
            .uuid(run.0)
            .bool(dynamic)
            .fetch_all_pool(&self.pool)
            .await?
            .iter()
            .map(|row| row.i64("frontier_id"))
            .collect::<Result<_, _>>()?;
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
        if B::KIND != BackendKind::Postgres {
            return self.billing_from_rows(run).await.map(Some);
        }
        let row = stmt!(
            B,
            "SELECT COALESCE(sum((metadata #>> '{billing,credits}')::numeric), 0)::text AS credits, \
             COALESCE(sum((metadata #>> '{billing,llm_tokens}')::numeric), 0)::text AS llm_tokens, \
             count(*) AS pages FROM pages WHERE run_id = $1"
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        let number = |field: &str| -> Result<u64, StoreError> {
            row.text(field)?
                .parse()
                .map_err(|_| StoreError::Serialization("page billing total exceeds u64".to_owned()))
        };
        Ok(Some(PageBilling::new(
            number("credits")?,
            number("llm_tokens")?,
            conv(row.i64("pages")?, "pages")?,
        )))
    }

    async fn recent_for_url(
        &self,
        tenant: crawlx_core::TenantId,
        url: &CanonicalUrl,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        let _timer = self.query_timer("page.recent_for_url");
        let rows = stmt!(
            B,
            "SELECT p.run_id, p.frontier_id, p.url_meta, p.http_status, p.content_type, p.content_digest, p.title, p.markdown_artifact_id, \
               p.markdown_digest, p.html_artifact_id, p.html_digest, p.metadata, p.links, p.fetched_at, p.lane \
             FROM pages p JOIN crawl_runs r ON r.run_id = p.run_id \
             WHERE r.tenant_id = $1 AND p.url_hash = $2 AND r.retention_mode <> 'zdr' \
             ORDER BY p.fetched_at DESC, p.page_id DESC LIMIT $3"
        )
        .uuid(tenant.0)
        .bytes(&url.key.0)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
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
        let postgres = B::KIND == BackendKind::Postgres;
        // PostgreSQL scans the `host_key` index by `LIKE`; the other engines compare a key
        // range, because `LIKE` has no escape character by default on SQLite
        let (host_filter, description, not_cacheable) = if postgres {
            (
                "(p.host_key = $2 OR p.host_key LIKE $3)".to_owned(),
                "CASE WHEN jsonb_typeof(p.metadata -> 'description') = 'string' THEN p.metadata ->> 'description' END AS description"
                    .to_owned(),
                "COALESCE(p.metadata #>> $5::text[], '') <> 'true'".to_owned(),
            )
        } else {
            let path = format!("$.{}", NOT_CACHEABLE_PATH.join("."));
            // MariaDB's JSON_VALUE renders a JSON `true` as `1`, not `true`: compare as JSON
            let flag = if B::KIND == BackendKind::Sqlite {
                format!("COALESCE(json_type(p.metadata, '{path}'), '') <> 'true'")
            } else {
                format!("COALESCE(JSON_CONTAINS(p.metadata, 'true', '{path}'), 0) = 0")
            };
            (
                "(p.host_key = $2 OR (p.host_key >= $3 AND p.host_key < $4))".to_owned(),
                "p.metadata AS metadata".to_owned(),
                flag,
            )
        };
        let (limit_at, expiry_at) = if postgres { ("$6", "$4") } else { ("$6", "$5") };
        // an unnamed statement is planned for these very values, so the prefix `LIKE` can use
        // the `pages_host_key` index (a cached generic plan could not)
        let mut query = Stmt::<B>::dynamic(&format!(
            "SELECT p.url_meta, p.title, {description}, p.links \
             FROM pages p JOIN crawl_runs r ON r.run_id = p.run_id \
             WHERE r.tenant_id = $1 AND {host_filter} \
               AND r.retention_mode <> 'zdr' AND (r.expires_at IS NULL OR r.expires_at > {expiry_at}) \
               AND COALESCE(p.http_status, 0) < 400 AND {not_cacheable} \
             ORDER BY p.fetched_at DESC, p.page_id DESC LIMIT {limit_at}"
        ))
        .unnamed()
        .uuid(tenant.0)
        .text(&key);
        let upper = below.as_ref().map(|_| format!("{key}/"));
        let lower = below.as_ref().map(|_| format!("{key}."));
        let path: Vec<String> = NOT_CACHEABLE_PATH.iter().map(|part| (*part).to_owned()).collect();
        if postgres {
            query = query
                .opt_text(below.as_deref())
                .ts(now)
                .text_list(&path)
                .i64(i64::from(limit));
        } else {
            query = query
                .opt_text(lower.as_deref())
                .opt_text(upper.as_deref())
                .ts(now)
                .i64(i64::from(limit));
        }
        let rows = query.fetch_all_pool(&self.pool).await?;
        rows.iter()
            .map(|r| {
                let description = if postgres {
                    r.opt_text("description")?
                } else {
                    r.json("metadata")?
                        .get("description")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                };
                Ok(KnownPage {
                    url: page_url(r)?,
                    title: r.opt_text("title")?,
                    description,
                    links: page_links(r)?,
                })
            })
            .collect()
    }
}

impl<B: Sql> Store<B> {
    /// Billing of a zero-data-retention run on engines whose SQL cannot sum JSON members:
    /// the totals of `metadata.billing`, summed in Rust.
    async fn billing_from_rows(&self, run: CrawlRunId) -> Result<PageBilling, StoreError> {
        let rows = stmt!(B, "SELECT metadata FROM pages WHERE run_id = $1")
            .uuid(run.0)
            .fetch_all_pool(&self.pool)
            .await?;
        let (mut credits, mut tokens) = (0_u64, 0_u64);
        for row in &rows {
            let metadata = row.json("metadata")?;
            let billing = metadata.get("billing");
            let field = |name: &str| {
                billing
                    .and_then(|b| b.get(name))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            };
            credits = credits
                .checked_add(field("credits"))
                .ok_or_else(|| StoreError::Serialization("page billing total exceeds u64".to_owned()))?;
            tokens = tokens
                .checked_add(field("llm_tokens"))
                .ok_or_else(|| StoreError::Serialization("page billing total exceeds u64".to_owned()))?;
        }
        Ok(PageBilling::new(credits, tokens, conv(rows.len(), "pages")?))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn host_keys_follow_the_generated_column() {
        for (url, key) in [
            ("https://Example.COM/path?q=1", Some("moc.elpmaxe")),
            ("http://user:pw@sub.example.com:8080/x", Some("moc.elpmaxe.bus")),
            ("http://[2001:DB8::1]:80/", Some("]1::8bd:1002[")),
            ("https://a@b@c.test/", Some("b")),
            ("https://example.com", Some("moc.elpmaxe")),
            ("ftp://host#frag", Some("tsoh")),
            ("mailto:someone@example.com", None),
            ("//example.com/x", None),
            ("1http://example.com", None),
            ("ht tp://example.com", None),
        ] {
            assert_eq!(host_key_of(url).as_deref(), key, "{url}");
        }
    }

    #[test]
    fn domain_lookups_reverse_the_host() {
        assert_eq!(host_keys("Example.com.", false), ("moc.elpmaxe".to_owned(), None));
        assert_eq!(host_keys("a_b.test", true).1.as_deref(), Some("tset.b\\_a.%"));
    }
}
