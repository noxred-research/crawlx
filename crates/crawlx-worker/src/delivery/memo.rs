//! Source memo hooks live below URL-plane discovery, preserving current admission authority.
use super::*;
use crawlx_core::dataset::memo::{CategoryCacheEntryV1, MemoScopeV1, MAX_CATEGORY_CACHE_BYTES};
use crawlx_core::dataset::DatasetContentV1;

fn memo_digest<T: serde::Serialize>(domain: &str, value: &T) -> Result<Digest, WorkerError> {
    Digest::of_value(domain, value)
        .map_err(|_| WorkerError::Other("source memo scope serialization failed".into()))
}

impl UrlPlaneRunner {
    pub(super) async fn discovery_memo_scope(
        &self,
        parent: &FrontierEntry,
        label: &str,
    ) -> Result<MemoScopeV1, WorkerError> {
        let run = self.deps.runs.get_metadata(self.run).await?;
        let queued = self.deps.frontier.get_request(self.run, parent.id).await?;
        let controls = &self.fetcher.config().controls;
        let credentials = self
            .request_identity_key
            .as_ref()
            .map(|root| crawlx_core::cache::credential_digest(root.expose(), run.tenant, controls))
            .transpose()?;
        let memo_enabled = self
            .crawl
            .scope
            .discovery
            .as_ref()
            .is_some_and(|policy| policy.article_memo.enabled || policy.category_cache.enabled);
        if memo_enabled
            && credentials.is_none()
            && (!controls.headers().is_empty() || !controls.cookies().is_empty())
        {
            return Err(DiscoveryErrorV1::CapabilityUnavailable(
                "protected source credential correlation key",
            )
            .into());
        }
        let source = memo_digest("crawlx/source-memo-source/v1", &(parent.url.key, label))?;
        let role = memo_digest(
            "crawlx/source-memo-role/v1",
            &(
                &queued.principal,
                queued.envelope.session_generation,
                &queued.envelope.header_control,
                credentials,
                &self.crawl.fetch,
            ),
        )?;
        let policy = memo_digest(
            "crawlx/source-memo-policy/v1",
            &(&self.crawl.scope, &self.crawl.extract),
        )?;
        Ok(MemoScopeV1::new(run.tenant, self.run, source, role, policy))
    }

    pub(super) async fn discovery_memo_seen(
        &self,
        scope: &MemoScopeV1,
        article: Digest,
    ) -> Result<bool, WorkerError> {
        if !self
            .crawl
            .scope
            .discovery
            .as_ref()
            .is_some_and(|policy| policy.article_memo.enabled)
        {
            return Ok(false);
        }
        Ok(self
            .deps
            .source_memo
            .seen(scope, article, self.deps.clock.now())
            .await?)
    }

    pub(super) async fn discovery_memo_record(
        &self,
        scope: &MemoScopeV1,
        articles: &[Digest],
    ) -> Result<(), WorkerError> {
        let Some(policy) = self
            .crawl
            .scope
            .discovery
            .as_ref()
            .filter(|policy| policy.article_memo.enabled)
        else {
            return Ok(());
        };
        self.deps
            .source_memo
            .record_seen(
                scope,
                articles,
                policy.article_memo.max_entries,
                self.deps.clock.now(),
            )
            .await?;
        Ok(())
    }

    pub(super) async fn discovery_categories(
        &self,
        parent: &FrontierEntry,
        response: &FetchResponse,
        doc: &Document,
    ) -> Result<Vec<Url>, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(Vec::new());
        };
        let candidates = || {
            doc.links
                .iter()
                .filter(|link| !link.nofollow && category_signal(&link.url))
                .map(|link| link.url.clone())
                .take(policy.max_category_links)
                .collect::<Vec<_>>()
        };
        if !policy.category_cache.enabled {
            return Ok(candidates());
        }
        let scope = self.discovery_memo_scope(parent, "categories").await?;
        let representation = Digest::of_value(
            "crawlx/category-representation/v1",
            &(
                Digest::of("crawlx/category-source-bytes/v1", &response.body),
                &response.final_url,
                doc.raw_html_digest,
                policy.max_category_links,
            ),
        )
        .map_err(|_| WorkerError::Other("category representation serialization failed".into()))?;
        let now = self.deps.clock.now();
        if let Some(entry) = self
            .deps
            .source_memo
            .category(&scope, representation, now)
            .await?
        {
            let bytes = match &entry.content {
                DatasetContentV1::Durable { artifact } => {
                    self.deps
                        .artifacts
                        .read_archive_content(scope.tenant, scope.run, artifact, MAX_CATEGORY_CACHE_BYTES)
                        .await?
                }
                DatasetContentV1::Volatile { page, artifact, .. } => {
                    self.deps
                        .artifacts
                        .dataset_content(scope.run, *page, artifact, entry.size_bytes)
                        .await?;
                    self.deps.artifacts.get(artifact).await?
                }
                _ => {
                    return Err(
                        StoreError::RetentionDenied("unsupported category content handle".into()).into(),
                    )
                }
            };
            if u64::try_from(bytes.len()).ok() != Some(entry.size_bytes)
                || entry.size_bytes > MAX_CATEGORY_CACHE_BYTES
            {
                return Err(StoreError::RetentionDenied("category cache length mismatch".into()).into());
            }
            crawlx_core::secret::Redactor::new().check_canonical(&bytes)?;
            let urls: Vec<Url> = serde_json::from_slice(&bytes)
                .map_err(|_| StoreError::Serialization("invalid category cache payload".into()))?;
            if urls.len() > policy.max_category_links || urls.iter().any(|url| url.as_str().len() > 4096) {
                return Err(StoreError::RetentionDenied("category cache bounds mismatch".into()).into());
            }
            return Ok(urls);
        }
        let urls = candidates();
        let bytes = serde_json::to_vec(&urls)
            .map_err(|_| StoreError::Serialization("category cache serialization failed".into()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CATEGORY_CACHE_BYTES {
            return Ok(urls);
        }
        let Some(registry) = self.captcha_secrets.as_ref() else {
            return Ok(urls);
        };
        if crate::capture::check_run_secrets(&bytes, &self.fetcher.config().controls, Some(registry)).is_err()
        {
            return Ok(urls);
        }
        // Approval must not transform URL identity. Uncacheable candidates still use normal admission.
        let Ok(approved) = crawlx_core::secret::Redactor::new().verify_canonical(&bytes) else {
            return Ok(urls);
        };
        let run = self.deps.runs.get(self.run).await?;
        let retention = if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr {
            chrono::Duration::hours(1)
        } else {
            chrono::Duration::days(i64::from(run.config.retention.days))
        };
        let horizon = run
            .created_at
            .checked_add_signed(retention)
            .ok_or_else(|| StoreError::RetentionDenied("category retention overflow".into()))?;
        let deadline = now
            .checked_add_signed(chrono::Duration::seconds(i64::from(
                policy.category_cache.ttl_seconds,
            )))
            .ok_or_else(|| StoreError::RetentionDenied("category expiry overflow".into()))?
            .min(horizon);
        if deadline <= now {
            return Ok(urls);
        }
        let artifact = ArtifactSink::over(self.deps.artifacts.as_ref())
            .put_dataset_until(
                self.run,
                parent.id,
                "discovery_categories",
                "application/json",
                &approved,
                deadline,
            )
            .await?;
        let size = u64::try_from(bytes.len())
            .map_err(|_| StoreError::Conflict("category cache length overflow".into()))?;
        let content = self
            .deps
            .artifacts
            .dataset_content(self.run, parent.id, &artifact, size)
            .await?;
        // Use the committed artifact deadline, not the pre-write timestamp. Durable
        // timestamp precision and custody policy can shorten that original deadline.
        let source_expiry = match &content {
            DatasetContentV1::Durable { artifact } => {
                let custody = self
                    .deps
                    .artifacts
                    .archive_custody(scope.tenant, self.run, artifact, size)
                    .await?;
                if custody.sensitivity != Sensitivity::Content {
                    return Err(StoreError::RetentionDenied(
                        "category artifact classification mismatch".into(),
                    )
                    .into());
                }
                custody.expires_at
            }
            _ => content.expires_at(),
        };
        let deadline = source_expiry.map_or(deadline, |expiry| expiry.min(deadline));
        self.deps
            .source_memo
            .cache_category(
                &scope,
                representation,
                CategoryCacheEntryV1::new(content, size, deadline),
                now,
            )
            .await?;
        Ok(urls)
    }
}
