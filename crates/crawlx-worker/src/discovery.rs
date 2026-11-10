//! URL-plane source discovery. All network work stays behind normal scope/robots/egress.
//!
//! Loader cursors and child requests commit in one fenced frontier transaction. Cursor
//! identity pins source bytes and policy, so changed representations cannot silently resume.

use super::*;
use crate::acquisition::AcquisitionBudgetV1;
use crawlx_core::discovery::{DiscoveryErrorV1, DiscoveryProviderV1, DiscoverySourceV1};
use crawlx_core::extraction::{DiscoveryPurposeV1, QualityStatusV1};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{LoaderCursorV1, RequestBatchV1};
use crawlx_core::request::RequestEnvelopeV1;
use std::borrow::Cow;
use std::io::Read;

/// Independent gzip expansion ceiling, including every concatenated member.
const MAX_SITEMAP_GZIP_RATIO: usize = 100;

#[derive(Debug, thiserror::Error)]
pub(super) enum SitemapDecodeError {
    #[error("sitemap gzip expansion limit exceeded")]
    Limit,
    #[error("invalid sitemap gzip stream")]
    Invalid(#[source] std::io::Error),
}

/// Decode the complete gzip stream before exposing XML to a parser. Concatenated members
/// are accepted and checked together; bad checksums, truncation and trailing junk reject
/// the whole document. Both expanded bytes and the 100:1 expansion ratio are hard limits.
///
/// # Errors
/// Rejects invalid or incomplete gzip members, trailing junk, and either expansion limit.
pub(super) fn decode_sitemap(bytes: &[u8], max_bytes: usize) -> Result<Cow<'_, [u8]>, SitemapDecodeError> {
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(Cow::Borrowed(bytes));
    }
    let limit = max_bytes.min(bytes.len().saturating_mul(MAX_SITEMAP_GZIP_RATIO));
    let mut decoder = flate2::read::MultiGzDecoder::new(bytes);
    let mut decoded = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // Read one byte beyond the remaining allowance to reject overflow without
        // allocating it. At the exact limit, still read EOF to validate the trailer.
        let room = limit.saturating_sub(decoded.len());
        let read_size = chunk.len().min(room.saturating_add(1));
        let count = decoder
            .read(&mut chunk[..read_size])
            .map_err(SitemapDecodeError::Invalid)?;
        if count == 0 {
            return Ok(Cow::Owned(decoded));
        }
        if count > room {
            return Err(SitemapDecodeError::Limit);
        }
        decoded.extend_from_slice(&chunk[..count]);
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SitemapIngestError {
    #[error(transparent)]
    Decode(#[from] SitemapDecodeError),
    #[error(transparent)]
    Parse(#[from] crawlx_url::UrlError),
}

#[derive(Debug, thiserror::Error)]
enum SourceParseError {
    #[error(transparent)]
    Feed(#[from] crawlx_url::feed::FeedError),
    #[error(transparent)]
    Decode(#[from] SitemapDecodeError),
}

impl UrlPlaneRunner {
    pub(super) fn source_enabled(&self, source: DiscoverySourceV1) -> bool {
        if self.crawl.scope.sources.is_empty() {
            return matches!(source, DiscoverySourceV1::Html | DiscoverySourceV1::Sitemap);
        }
        self.crawl.scope.sources.contains(&source)
    }

    pub(super) fn validate_discovery_providers(&self) -> Result<(), WorkerError> {
        if self.crawl.scope.discovery.is_some()
            && self.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr
            && self.request_identity_key.is_none()
        {
            return Err(DiscoveryErrorV1::CapabilityUnavailable("protected source correlation key").into());
        }
        for (source, provider) in [
            (DiscoverySourceV1::NewsSearch, DiscoveryProviderV1::NewsSearch),
            (DiscoverySourceV1::TrendsSearch, DiscoveryProviderV1::TrendsSearch),
            (DiscoverySourceV1::Archive, DiscoveryProviderV1::WebArchiveIndex),
        ] {
            if self.source_enabled(source) && self.crawl.cache_only() {
                return Err(DiscoveryErrorV1::ProviderForbiddenInReplay(provider).into());
            }
            if self.source_enabled(source)
                && self.crawl.scope.discovery.as_ref().is_none_or(|policy| {
                    !policy
                        .connectors
                        .iter()
                        .any(|connector| connector.provider == provider)
                })
            {
                return Err(DiscoveryErrorV1::ProviderUnavailable(provider).into());
            }
        }
        Ok(())
    }

    fn configured_discovery_sources(&self, seed: &CanonicalUrl) -> Vec<Url> {
        if self.crawl.cache_only() {
            return Vec::new();
        }
        let Some(policy) = &self.crawl.scope.discovery else {
            return Vec::new();
        };
        let mut candidates = Vec::new();
        if self.source_enabled(DiscoverySourceV1::Conventional) {
            candidates.extend(
                policy
                    .conventional_paths
                    .iter()
                    .filter_map(|path| seed.url.join(path).ok()),
            );
        }
        candidates.extend(
            policy
                .connectors
                .iter()
                .filter(|connector| {
                    self.source_enabled(match connector.provider {
                        DiscoveryProviderV1::NewsSearch => DiscoverySourceV1::NewsSearch,
                        DiscoveryProviderV1::TrendsSearch => DiscoverySourceV1::TrendsSearch,
                        DiscoveryProviderV1::WebArchiveIndex => DiscoverySourceV1::Archive,
                        _ => return false,
                    })
                })
                .map(|connector| connector.endpoint.clone()),
        );
        candidates.truncate(policy.max_source_documents);
        candidates
    }

    /// Admit a parsed source as bounded atomic chunks, including rejected input positions.
    async fn append_source_urls(
        &self,
        urls: &[Url],
        parent: &FrontierEntry,
        label: &str,
        source_bytes: &[u8],
    ) -> Result<usize, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(0);
        };
        if parent.depth >= policy.max_source_depth {
            return Ok(0);
        }
        let tenant = self.deps.runs.get(self.run).await?.tenant;
        let private_key = if self.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr {
            let root = self
                .request_identity_key
                .as_ref()
                .ok_or(DiscoveryErrorV1::CapabilityUnavailable(
                    "protected source correlation key",
                ))?;
            Some(Digest::keyed(
                root.expose(),
                "crawlx/tenant-request-key/v1",
                tenant.0.as_bytes(),
            ))
        } else {
            None
        };
        let source = format!(
            "discovery:{}",
            Digest::of_value("crawlx/discovery-source/v1", &(parent.url.key, label))
                .map_err(|error| WorkerError::Other(error.to_string()))?
                .to_hex()
        );
        let digest = Digest::of_value(
            if label == "html_sources" {
                "crawlx/discovery-representation/v2"
            } else {
                "crawlx/discovery-representation/v1"
            },
            &(
                Digest::of("crawlx/discovery-bytes/v1", source_bytes),
                policy,
                &self.crawl.scope.sources,
            ),
        )
        .map_err(|error| WorkerError::Other(error.to_string()))?;
        let digest = private_key.as_ref().map_or(digest, |key| {
            Digest::keyed(&key.0, "crawlx/discovery-private-source/v1", &digest.0)
        });
        let mut cursor = self.deps.frontier.loader_cursor(self.run, &source).await?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.source_digest != digest)
        {
            return Err(StoreError::Conflict("discovery source changed during resume".into()).into());
        }
        let start = cursor
            .as_ref()
            .map_or(0, |cursor| usize::try_from(cursor.position).unwrap_or(usize::MAX));
        if start > urls.len() {
            return Err(StoreError::Conflict("discovery cursor exceeds source".into()).into());
        }
        let fence = self
            .held
            .lock()
            .get(&parent.id)
            .copied()
            .ok_or_else(|| StoreError::Conflict("source parent lease lost".into()))?;
        // Bound serialized envelopes even when every URL is at the 4 KiB URL ceiling.
        let chunk_size = self
            .crawl
            .orchestration
            .as_ref()
            .map_or(128, |config| {
                usize::try_from(config.queue.batch_size).unwrap_or(128)
            })
            .clamp(1, 128);
        let mut inserted = 0usize;
        // Even an empty selected set pins its representation and policy across restart.
        let empty_source = (urls.is_empty() && cursor.is_none()).then_some(urls);
        for (chunk_index, chunk) in urls[start..].chunks(chunk_size).chain(empty_source).enumerate() {
            if self.authorization_lost().await {
                return Err(DiscoveryErrorV1::Protocol("authorization revoked".into()).into());
            }
            let mut requests = Vec::new();
            let mut denied = Vec::new();
            let depth = parent.depth.saturating_add(1);
            for url in chunk {
                let Some((canonical, bearing)) = self.canonicalize(url) else {
                    continue;
                };
                if self.ledger.lock().carried.contains(canonical.url.as_str()) {
                    continue;
                }
                let (denial, counted_as, reason) = self
                    .discovery_admission(&canonical, depth, Some(parent.id), bearing)
                    .await;
                if let Some((status, _)) = denial {
                    denied.push((
                        counted_as.unwrap_or(if status == FrontierStatus::RobotsBlocked {
                            DiscoveryOutcome::RobotsBlocked
                        } else {
                            DiscoveryOutcome::PolicyBlocked
                        }),
                        reason,
                    ));
                    continue;
                }
                let pending = {
                    let ledger = self.ledger.lock();
                    ledger.pending.len().saturating_add(ledger.visited.len())
                };
                if pending.saturating_add(requests.len())
                    >= usize::try_from(self.crawl.scope.max_known_urls).unwrap_or(usize::MAX)
                {
                    denied.push((DiscoveryOutcome::PolicyBlocked, "known_url_limit"));
                    continue;
                }
                requests.push(RequestEnvelopeV1::get(canonical, depth, Some(parent.id)));
            }
            let position = start
                .saturating_add(chunk_index.saturating_mul(chunk_size))
                .saturating_add(chunk.len());
            let next = LoaderCursorV1::new(
                source.clone(),
                digest,
                u64::try_from(position).unwrap_or(u64::MAX),
            );
            let batch_id = Digest::of_value(
                "crawlx/discovery-batch/v1",
                &(self.run, &source, digest, &cursor, &next),
            )
            .map_err(|error| WorkerError::Other(error.to_string()))?;
            let batch_id = private_key.as_ref().map_or(batch_id, |key| {
                Digest::keyed(&key.0, "crawlx/discovery-private-batch/v1", &batch_id.0)
            });
            let mut batch = RequestBatchV1::new(tenant, self.run, "anonymous".into(), batch_id, requests);
            batch.expected_cursor = cursor.clone();
            batch.next_cursor = Some(next.clone());
            batch.parent_fence = Some((parent.id, fence));
            let receipt = self.deps.frontier.append_batch(batch).await?;
            inserted = inserted.saturating_add(receipt.inserted.len());
            for id in receipt.inserted {
                let request = self.deps.frontier.get_request(self.run, id).await?;
                self.ledger
                    .lock()
                    .pending
                    .insert(id, ResumeEntry::new(request.envelope.url.url.to_string(), depth));
                self.counters.discovery(Plane::Urls, DiscoveryOutcome::Admitted);
            }
            for _ in 0..receipt.duplicates {
                self.counters.discovery(Plane::Urls, DiscoveryOutcome::Duplicate);
            }
            for (outcome, reason) in denied {
                self.counters.discovery_with_reason(Plane::Urls, outcome, reason);
            }
            cursor = Some(next);
        }
        Ok(inserted)
    }

    /// Consume actual feed/provider responses before generic endpoint mining can treat feed
    /// self links as articles. Content-bearing hints/provenance go through ArtifactSink.
    pub(super) async fn discover_source_response(
        &self,
        entry: &FrontierEntry,
        response: &FetchResponse,
        record: &mut PageRecord,
        expand: bool,
        budget: Option<&AcquisitionBudgetV1>,
    ) -> Result<bool, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(false);
        };
        let connector = policy.connectors.iter().find(|connector| {
            self.source_enabled(match connector.provider {
                DiscoveryProviderV1::NewsSearch => DiscoverySourceV1::NewsSearch,
                DiscoveryProviderV1::TrendsSearch => DiscoverySourceV1::TrendsSearch,
                DiscoveryProviderV1::WebArchiveIndex => DiscoverySourceV1::Archive,
                _ => return false,
            }) && self
                .canonicalize(&connector.endpoint)
                .is_some_and(|(canonical, _)| canonical.key == entry.url.key)
        });
        let feed = self.source_enabled(DiscoverySourceV1::Feeds)
            && crawlx_url::feed::is_feed(response.content_type.as_deref(), &response.body);
        let gzip = response.body.starts_with(&[0x1f, 0x8b]);
        let prefix = if gzip {
            Cow::Borrowed("")
        } else {
            String::from_utf8_lossy(&response.body[..response.body.len().min(1024)])
        };
        let sitemap = self.source_enabled(DiscoverySourceV1::Sitemap)
            && (gzip
                || (response
                    .content_type
                    .as_deref()
                    .is_none_or(|kind| !kind.contains("html"))
                    && (prefix.contains("<urlset")
                        || prefix.contains(":urlset")
                        || prefix.contains("<sitemapindex")
                        || prefix.contains(":sitemapindex")
                        || (entry.depth == 0
                            && self.crawl.scope.sources == [DiscoverySourceV1::Sitemap]
                            && response
                                .content_type
                                .as_deref()
                                .is_some_and(|kind| kind.starts_with("text/plain"))))));
        if connector.is_none() && !feed && !sitemap {
            return Ok(false);
        }
        // A recognized source has completed its acquisition and cannot spend more of
        // this parent allowance. Admission retains its separate scope/robots checks.
        // Settle observed usage before a cursor can commit, so a crash afterward does
        // not forfeit unused escrow needed to reacquire and check the pinned source.
        self.settle_native_allowance(entry, budget).await?;
        if response.truncated || response.body.len() > policy.max_feed_bytes {
            record.metadata["source_discovery"] =
                serde_json::json!({"status":"resource_limit","reason":"source_bytes"});
            return Ok(true);
        }
        let body = response.body.clone();
        let base = response.final_url.clone();
        let parser_policy = policy.clone();
        let configured = connector.cloned();
        let parsed = self.cpu_pool.run(move || -> Result<_, SourceParseError> {
            let parsed = if let Some(connector) = configured {
                crawlx_url::feed::parse_connector(connector.provider, Some(&connector), &body, &parser_policy).map(|document| {
                    let evidence = serde_json::json!({"provider":connector.provider,"endpoint":connector.endpoint,
                        "terms":document.terms,"captures":document.captures.iter().map(|capture| serde_json::json!({
                            "originalUrl":capture.original_url,"archiveUrl":capture.archive_url,
                            "captureTime":capture.capture_time,"recordedTargetStatus":capture.target_status})).collect::<Vec<_>>()});
                    let candidates = if connector.provider == DiscoveryProviderV1::WebArchiveIndex {
                        document.captures.into_iter().map(|capture| capture.archive_url).collect()
                    } else { document.articles };
                    (candidates, evidence, document.truncated, "connector")
                })
            } else if sitemap {
                let decoded = decode_sitemap(&body, parser_policy.max_feed_bytes)?;
                crawlx_url::SitemapParser::parse_limited(&decoded, parser_policy.max_entries)
                    .map_err(crawlx_url::feed::FeedError::from).and_then(|document| {
                        if document.malformed {
                            return Err(DiscoveryErrorV1::Protocol("malformed sitemap source".into()).into());
                        }
                        let mut truncated = document.truncated
                            || document.nested.len() > parser_policy.max_source_documents;
                        let mut urls = Vec::new();
                        let mut evidence = Vec::new();
                        for entry in document.urls {
                            if parser_policy.sitemap_lastmod.as_ref()
                                .is_some_and(|policy| !policy.includes(entry.lastmod.as_ref())) {
                                continue;
                            }
                            for (location, language) in std::iter::once((entry.loc, None))
                                .chain(entry.hreflang.into_iter().map(|variant| (variant.loc, Some(variant.language)))) {
                                if urls.len() >= parser_policy.max_entries { truncated = true; break; }
                                if let Ok(url) = Url::parse(&location) {
                                    evidence.push(serde_json::json!({"url":url,"languageHint":language,
                                        "lastmodHint":entry.lastmod}));
                                    urls.push(url);
                                }
                            }
                        }
                        urls.extend(document.nested.into_iter().take(parser_policy.max_source_documents)
                            .filter_map(|nested| Url::parse(&nested.loc).ok()));
                        Ok((urls, serde_json::json!({"variants":evidence}), truncated, "sitemap"))
                    })
            } else {
                crawlx_url::feed::parse_feed(&body, &base, &parser_policy).map(|document| {
                    let mut urls: Vec<_> = document.entries.iter().map(|entry| entry.url.clone()).collect();
                    urls.extend(document.next.into_iter().take(parser_policy.max_source_documents));
                    let evidence = serde_json::json!({"entries":document.entries.iter().map(|entry| serde_json::json!({
                        "url":entry.url,"titleHint":entry.title,"dateHint":entry.date,"publisherHint":entry.publisher,
                        "mediaIntents":entry.media,"readMoreIntents":entry.read_more})).collect::<Vec<_>>()});
                    (urls, evidence, document.truncated, "feed")
                })
            };
            Ok(parsed?)
        }).await.map_err(|error| WorkerError::Other(error.to_string()))?;
        match parsed {
            Ok((mut urls, evidence, truncated, kind)) => {
                if entry.depth == 0 {
                    urls.extend(self.configured_discovery_sources(&entry.url));
                }
                let admitted = if expand && !self.crawl.cache_only() {
                    self.append_source_urls(&urls, entry, kind, &response.body)
                        .await?
                } else {
                    0
                };
                let content =
                    serde_json::to_vec(&evidence).map_err(|error| WorkerError::Other(error.to_string()))?;
                let artifact = self
                    .store(
                        entry.id,
                        Sensitivity::Content,
                        "application/vnd.crawlx.discovery+json",
                        &content,
                    )
                    .await;
                record.metadata["source_discovery"] = serde_json::json!({"status":"parsed","kind":kind,
                    "candidates":urls.len(),"admitted":admitted,"truncated":truncated,"content":artifact});
            }
            Err(error) => {
                let (status, reason) = match error {
                    SourceParseError::Decode(SitemapDecodeError::Limit) => {
                        ("resource_limit", "sitemap_gzip_expansion")
                    }
                    SourceParseError::Decode(SitemapDecodeError::Invalid(_)) => {
                        ("rejected", "sitemap_gzip_invalid")
                    }
                    SourceParseError::Feed(_) => ("rejected", "source_protocol"),
                };
                record.metadata["source_discovery"] = serde_json::json!({"status":status,"reason":reason});
            }
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn discover_article_sources(
        &self,
        entry: &FrontierEntry,
        response: &FetchResponse,
        doc: &Document,
        record: &mut PageRecord,
        expand: bool,
        mut budget: Option<&mut AcquisitionBudgetV1>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(());
        };
        let sufficient = doc.article.as_ref().is_some_and(|article| {
            article.quality.status == QualityStatusV1::Accepted
                && article.quality.main_chars >= policy.sufficient_main_chars
        });
        record.metadata["discovery_probe"] = serde_json::json!({"mode":policy.mode,"sufficient":sufficient,
            "reason":if doc.article.is_none() { "extraction_unavailable" } else if sufficient { "selected_article_sufficient" } else { "selected_article_insufficient" },
            "mainChars":doc.article.as_ref().map(|article| article.quality.main_chars)});
        if !expand || self.crawl.cache_only() || entry.depth >= policy.max_source_depth {
            return Ok(());
        }
        let sitemap_candidates = if entry.depth == 0
            && self.source_enabled(DiscoverySourceV1::Sitemap)
            && self.crawl.scope.sitemap != SitemapMode::Skip
        {
            if let Some(budget) = budget.as_deref_mut() {
                self.discover_parent_sitemaps(entry, record, budget, cancel)
                    .await?
            } else {
                0
            }
        } else {
            0
        };
        record.metadata["discovery_probe"]["sitemapCandidates"] = serde_json::json!(sitemap_candidates);
        let mut sources = Vec::new();
        if self.source_enabled(DiscoverySourceV1::Feeds)
            && !response.truncated
            && response.body.len() <= policy.max_feed_bytes
        {
            let body = response.body.clone();
            let base = response.final_url.clone();
            let links = self
                .cpu_pool
                .run(move || crawlx_url::extract_links(&String::from_utf8_lossy(&body), &base))
                .await
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            sources.extend(
                links
                    .into_iter()
                    .filter(advertised_feed)
                    .map(|link| link.url)
                    .take(policy.max_source_documents),
            );
        }
        if entry.depth == 0 {
            sources.extend(self.configured_discovery_sources(&entry.url));
        }
        // One governed homepage proposal, not a parser-owned request or a fresh budget.
        // Descendant articles never restart this fallback, even when a feed points back.
        if entry.depth == 0
            && sources.is_empty()
            && self.source_enabled(DiscoverySourceV1::Feeds)
            && !response.truncated
            && response.body.len() <= policy.max_feed_bytes
            && response.final_url.path() != "/"
        {
            let mut homepage = response.final_url.clone();
            homepage.set_path("/");
            homepage.set_query(None);
            homepage.set_fragment(None);
            sources.push(homepage);
            record.metadata["discovery_probe"]["homepageFallback"] = serde_json::json!(true);
        }
        if self.source_enabled(DiscoverySourceV1::Categories) {
            sources.extend(
                doc.links
                    .iter()
                    .filter(|link| !link.nofollow && category_signal(&link.url))
                    .map(|link| link.url.clone())
                    .take(policy.max_category_links),
            );
        }
        // No domain/category heuristic can authorize a URL; every proposal below goes through
        // the same admission gate as ordinary links. Sitemap enumeration precedes this stage.
        if !sufficient
            && sitemap_candidates < policy.min_sitemap_articles
            && self.source_enabled(DiscoverySourceV1::Html)
        {
            sources.extend(
                doc.links
                    .iter()
                    .filter(|link| {
                        !link.nofollow
                            && !category_signal(&link.url)
                            && doc.article.as_ref().is_none_or(|article| {
                                !article.discovery.iter().any(|intent| {
                                    intent.url == link.url
                                        && intent.purpose == DiscoveryPurposeV1::ReadMoreReference
                                })
                            })
                    })
                    .map(|link| link.url.clone())
                    .take(policy.max_focused_links),
            );
        }
        let admitted = self
            .append_source_urls(&sources, entry, "html_sources", &response.body)
            .await?;
        record.metadata["discovery_probe"]["admitted"] = serde_json::json!(admitted);
        if let Some(budget) = budget {
            let mut metadata = serde_json::from_value::<crawlx_core::acquisition::AcquisitionResultV1>(
                record.metadata["acquisition"].clone(),
            )
            .map_err(|error| WorkerError::Other(format!("discovery acquisition metadata: {error}")))?;
            budget.stamp(&mut metadata);
            record.metadata["acquisition"] =
                serde_json::to_value(metadata).map_err(|error| WorkerError::Other(error.to_string()))?;
        }
        Ok(())
    }

    /// One live-parent logical source: acquire bounded sitemaps before focused fallback,
    /// then commit the article set and the pinned representation cursor together.
    async fn discover_parent_sitemaps(
        &self,
        parent: &FrontierEntry,
        record: &mut PageRecord,
        budget: &mut AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<usize, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(0);
        };
        let mut roots = self.robots.sitemaps(&parent.url.origin);
        if roots.is_empty() {
            if let Ok(url) = parent.url.url.join("/sitemap.xml") {
                roots.push(url.to_string());
            }
        }
        let mut incomplete = roots.len() > policy.max_source_documents;
        let mut queue: std::collections::VecDeque<_> = roots
            .into_iter()
            .take(policy.max_source_documents)
            .map(|url| (url, 0usize))
            .collect();
        let mut seen = BTreeSet::new();
        let mut traversal = SitemapTraversal::new();
        let mut representations = Vec::new();
        let mut attempted = 0usize;
        let mut failed = 0usize;
        while let Some((location, depth)) = queue.pop_front() {
            if attempted >= policy.max_source_documents
                || depth > usize::from(policy.max_source_depth)
                || !traversal.has_room()
                || !budget.can_retry()
            {
                incomplete = true;
                break;
            }
            if !seen.insert(location.clone()) {
                continue;
            }
            attempted = attempted.saturating_add(1);
            let Ok(url) = Url::parse(&location) else {
                continue;
            };
            let response = match self
                .fetch_discovery_auxiliary(&url, parent.depth, policy.max_feed_bytes, budget, cancel)
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    failed = failed.saturating_add(1);
                    continue;
                }
            };
            representations.push((
                url,
                Digest::of("crawlx/sitemap-representation/v1", &response.body),
                response.status.as_u16(),
                response.truncated,
            ));
            if !response.status.is_success() || response.truncated {
                failed = failed.saturating_add(1);
                continue;
            }
            let body = response.body.clone();
            let entry_limit = policy.max_entries;
            let byte_limit = policy.max_feed_bytes;
            let (next_traversal, nested) = self
                .cpu_pool
                .run(move || {
                    let nested = decode_sitemap(&body, byte_limit)
                        .map_err(SitemapIngestError::from)
                        .and_then(|decoded| {
                            traversal
                                .ingest_limited(&decoded, depth, entry_limit)
                                .map_err(SitemapIngestError::from)
                        });
                    (traversal, nested)
                })
                .await
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            traversal = next_traversal;
            if let Ok(nested) = nested {
                let room = policy
                    .max_source_documents
                    .saturating_sub(attempted)
                    .saturating_sub(queue.len());
                incomplete |= nested.len() > room;
                queue.extend(
                    nested
                        .into_iter()
                        .take(room)
                        .map(|nested| (nested.loc, nested.depth)),
                );
            } else {
                failed = failed.saturating_add(1);
            }
        }
        incomplete |= traversal.truncated();
        let mut candidates = Vec::new();
        let mut unique = BTreeSet::new();
        let mut provenance = Vec::new();
        for entry in traversal.into_urls() {
            if policy
                .sitemap_lastmod
                .as_ref()
                .is_some_and(|policy| !policy.includes(entry.lastmod.as_ref()))
            {
                continue;
            }
            for (location, language) in std::iter::once((entry.loc, None)).chain(
                entry
                    .hreflang
                    .into_iter()
                    .map(|variant| (variant.loc, Some(variant.language))),
            ) {
                let Ok(url) = Url::parse(&location) else {
                    continue;
                };
                let Some((canonical, bearing)) = self.canonicalize(&url) else {
                    continue;
                };
                if !bearing
                    && matches!(
                        self.scope.decide(&canonical, parent.depth.saturating_add(1)),
                        ScopeVerdict::Admitted { leaf_only: false }
                    )
                    && unique.insert(canonical.key)
                {
                    provenance.push(serde_json::json!({"url":url,"languageHint":language,
                        "lastmodHint":entry.lastmod,
                        "source":if language.is_some() { "sitemap_hreflang" } else { "sitemap_loc" }}));
                    candidates.push(url);
                }
                if candidates.len() >= policy.max_entries {
                    break;
                }
            }
            if candidates.len() >= policy.max_entries {
                break;
            }
        }
        let source_bytes =
            serde_json::to_vec(&representations).map_err(|error| WorkerError::Other(error.to_string()))?;
        let count = candidates.len();
        self.append_source_urls(&candidates, parent, "sitemap", &source_bytes)
            .await?;
        let evidence = serde_json::to_vec(&serde_json::json!({
            "representations":representations,"variants":provenance,
        }))
        .map_err(|error| WorkerError::Other(error.to_string()))?;
        let content = self
            .store(
                parent.id,
                Sensitivity::Content,
                "application/vnd.crawlx.discovery+json",
                &evidence,
            )
            .await;
        record.metadata["sitemap_discovery"] = serde_json::json!({
            "candidates":count,"documentsAttempted":attempted,"failedDocuments":failed,
            "partial":incomplete || failed > 0,"content":content,
        });
        Ok(count)
    }

    /// Shared scope and authority admission, without recursively loading robots.
    pub(super) async fn admit_native_scope(&self, url: &Url, depth: u16) -> Result<CanonicalUrl, FetchError> {
        if self.crawl.cache_only() || self.authorization_lost().await {
            return Err(FetchError::AcquisitionUnavailable);
        }
        let (canonical, bearing) = self.canonicalize(url).ok_or(FetchError::AcquisitionUnavailable)?;
        if bearing
            || !matches!(
                self.scope.decide(&canonical, depth),
                ScopeVerdict::Admitted { leaf_only: false }
            )
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(canonical)
    }

    /// Legacy auxiliary admission retains its existing separate robots policy.
    pub(super) async fn admit_native_destination(&self, url: &Url, depth: u16) -> Result<(), FetchError> {
        let canonical = self.admit_native_scope(url, depth).await?;
        if !matches!(self.robots_decision(&canonical).await, RobotsDecision::Allowed) {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    /// Fetch one auxiliary resource with scope/robots checked before every manual redirect.
    /// Same fetcher means checked DNS/peer/cert/proxy and shared OriginGovernor, never a raw client.
    pub(super) async fn fetch_discovery_auxiliary(
        &self,
        original: &Url,
        depth: u16,
        cap: usize,
        budget: &mut AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<FetchResponse, FetchError> {
        if self.crawl.cache_only() {
            return Err(FetchError::AcquisitionUnavailable);
        }
        let mut current = original.clone();
        let mut seen = BTreeSet::new();
        let mut redirects = Vec::new();
        for _ in 0..=self.fetcher.config().max_redirects.min(20) {
            if !seen.insert(current.as_str().to_owned()) {
                return Err(FetchError::AcquisitionAllowance);
            }
            self.admit_native_destination(&current, depth).await?;
            let remaining = budget.reserve(cancel)?;
            let mut options = budget.options(&FetchOptions::default(), cap);
            options.follow_redirects = false;
            let fetched = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
                result = tokio::time::timeout(remaining, self.fetcher.fetch_once(&current, &options)) =>
                    result.unwrap_or(Err(FetchError::AcquisitionDeadline)),
            };
            self.record_exchange(&current, &fetched);
            let mut response = match fetched {
                Ok(response) => response,
                Err(error) => {
                    budget.on_fetch_failure(&error, options.max_body_bytes.unwrap_or(cap));
                    return Err(error);
                }
            };
            budget.charge_bytes(response.body.len());
            budget.record(
                "discovery_auxiliary",
                Some(response.status.as_u16()),
                crawlx_core::acquisition::ValidationCategoryV1::Indeterminate,
            );
            if !response.status.is_redirection() || !self.fetcher.config().follow_redirects {
                response.redirects = redirects;
                return Ok(response);
            }
            let location = response
                .headers
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(FetchError::AcquisitionUnavailable)?;
            redirects.push(current.to_string());
            current = current
                .join(location)
                .map_err(|_| FetchError::AcquisitionUnavailable)?;
        }
        Err(FetchError::AcquisitionAllowance)
    }

    pub(super) async fn follow_article_intents(
        &self,
        entry: &FrontierEntry,
        doc: &Document,
        record: &mut PageRecord,
        budget: Option<&mut AcquisitionBudgetV1>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(());
        };
        if self.crawl.cache_only() {
            record.metadata["discovery_auxiliary"] =
                serde_json::json!({"status":"unavailable","reason":"cache_only","followed":0});
            return Ok(());
        }
        let Some(article) = &doc.article else {
            return Ok(());
        };
        let Some(budget) = budget else {
            return Ok(());
        };
        let captcha = self.captcha_secrets.clone().ok_or_else(|| {
            StoreError::RetentionDenied("discovery dynamic-secret registry unavailable".into())
        })?;
        let mut reports = Vec::new();
        let mut media_count = 0usize;
        let mut seen = BTreeSet::from([entry.url.url.as_str().to_owned()]);
        for intent in &article.discovery {
            if intent.purpose != DiscoveryPurposeV1::ImageReference || media_count >= policy.media_probes {
                continue;
            }
            if !seen.insert(intent.url.as_str().to_owned()) {
                continue;
            }
            media_count = media_count.saturating_add(1);
            let outcome = match self
                .fetch_discovery_auxiliary(
                    &intent.url,
                    entry.depth,
                    policy.media_header_bytes,
                    budget,
                    cancel,
                )
                .await
            {
                Ok(response) => {
                    let dimensions = if response.status.is_success() {
                        crate::media_probe::inspect_header(&response.body, policy.max_media_pixels)
                    } else {
                        Err(crate::media_probe::MediaProbeError::Header)
                    };
                    let outcome = match &dimensions {
                        Ok(_) => "header_dimensions",
                        Err(crate::media_probe::MediaProbeError::Pixels) => "pixel_limit",
                        Err(crate::media_probe::MediaProbeError::Bytes) => "header_byte_limit",
                        Err(_) => "header_unavailable",
                    };
                    serde_json::json!({"purpose":"media","originalUrl":intent.url,"finalUrl":response.final_url,
                        "status":response.status.as_u16(),"dimensions":dimensions.ok(),"outcome":outcome,
                        "boundedBytes":response.body.len(),"truncated":response.truncated})
                }
                Err(error) => {
                    serde_json::json!({"purpose":"media","originalUrl":intent.url,"outcome":error.code()})
                }
            };
            reports.push(outcome);
        }
        let mut next = article
            .discovery
            .iter()
            .find(|intent| intent.purpose == DiscoveryPurposeV1::ReadMoreReference)
            .map(|intent| intent.url.clone());
        for hop in 0..policy.read_more_hops {
            let Some(url) = next.take() else {
                break;
            };
            if !seen.insert(url.as_str().to_owned()) {
                break;
            }
            match self
                .fetch_discovery_auxiliary(
                    &url,
                    entry.depth.saturating_add(u16::from(hop)).saturating_add(1),
                    policy.max_feed_bytes,
                    budget,
                    cancel,
                )
                .await
            {
                Ok(response) => {
                    let mut opts = self.extract.clone();
                    opts.depth = u32::from(entry.depth)
                        .saturating_add(u32::from(hop))
                        .saturating_add(1);
                    opts.status = response.status.as_u16();
                    opts.headers = header_pairs(&response.headers);
                    opts.content_type.clone_from(&response.content_type);
                    opts.acquisition_validation = Some(crate::acquisition::context(
                        &self.crawl.acquisition.clone().unwrap_or_default(),
                        Some(opts.status),
                        response.truncated,
                    ));
                    let body = response.body.clone();
                    let base = response.final_url.clone();
                    let controls = self.fetcher.config().controls.clone();
                    let captcha = captcha.clone();
                    let extracted = if response.status.is_success() && !response.truncated {
                        Some(
                            self.cpu_pool
                                .run(move || {
                                    crate::acquisition::extract_document_with_secrets(
                                        &body, &base, &opts, &controls, &captcha,
                                    )
                                })
                                .await
                                .map_err(|error| WorkerError::Other(error.to_string()))?,
                        )
                    } else {
                        None
                    };
                    let mut article_content = None;
                    if let Some(Ok(document)) = extracted {
                        next = document.article.as_ref().and_then(|article| {
                            article
                                .discovery
                                .iter()
                                .find(|intent| intent.purpose == DiscoveryPurposeV1::ReadMoreReference)
                                .map(|intent| intent.url.clone())
                        });
                        let mut bytes = Vec::new();
                        if document.article.is_some()
                            && crawlx_extract::serialize::write_article(
                                &mut bytes,
                                &document,
                                crawlx_extract::serialize::ArticleFormat::Json,
                            )
                            .is_ok()
                        {
                            article_content = self
                                .store(
                                    entry.id,
                                    Sensitivity::Content,
                                    "application/vnd.crawlx.article+json",
                                    &bytes,
                                )
                                .await;
                        }
                    }
                    reports.push(serde_json::json!({"purpose":"read_more","originalUrl":url,"finalUrl":response.final_url,
                        "status":response.status.as_u16(),"article":article_content,
                        "bodyBytes":response.body.len(),"truncated":response.truncated,"hop":hop.saturating_add(1)}));
                }
                Err(error) => {
                    reports.push(
                        serde_json::json!({"purpose":"read_more","originalUrl":url,"outcome":error.code()}),
                    );
                    break;
                }
            }
        }
        if !reports.is_empty() {
            let bytes =
                serde_json::to_vec(&reports).map_err(|error| WorkerError::Other(error.to_string()))?;
            let artifact = self
                .store(
                    entry.id,
                    Sensitivity::Content,
                    "application/vnd.crawlx.discovery+json",
                    &bytes,
                )
                .await;
            record.metadata["discovery_auxiliary"] =
                serde_json::json!({"count":reports.len(),"content":artifact});
            let mut metadata = serde_json::from_value::<crawlx_core::acquisition::AcquisitionResultV1>(
                record.metadata["acquisition"].clone(),
            )
            .map_err(|error| WorkerError::Other(format!("auxiliary acquisition metadata: {error}")))?;
            budget.stamp(&mut metadata);
            record.metadata["acquisition"] =
                serde_json::to_value(metadata).map_err(|error| WorkerError::Other(error.to_string()))?;
        }
        Ok(())
    }
    /// Refund only observed unused allowance while the parent fence remains live.
    pub(super) async fn settle_native_allowance(
        &self,
        entry: &FrontierEntry,
        budget: Option<&AcquisitionBudgetV1>,
    ) -> Result<(), WorkerError> {
        if self.crawl.acquisition.is_none() || self.crawl.cache_only() {
            return Ok(());
        }
        if let Some(budget) = budget {
            let fence = *self.held.lock().get(&entry.id).ok_or(StoreError::LeaseLost)?;
            self.deps
                .frontier
                .settle_acquisition_fenced(self.run, entry.id, fence, &budget.usage())
                .await?;
        }
        Ok(())
    }
}

fn advertised_feed(link: &crawlx_url::RawLink) -> bool {
    if link.nofollow
        || !matches!(
            link.kind,
            crawlx_url::LinkKind::Anchor | crawlx_url::LinkKind::Alternate
        )
    {
        return false;
    }
    if link
        .media_type
        .as_deref()
        .is_some_and(|kind| crawlx_url::feed::is_feed(Some(kind), &[]))
    {
        return true;
    }
    let feed_word = |word: &str| {
        ["rss", "atom", "feed", "feeds"]
            .iter()
            .any(|hint| word.eq_ignore_ascii_case(hint))
    };
    link.text
        .as_deref()
        .is_some_and(|text| text.split(|c: char| !c.is_alphanumeric()).any(feed_word))
        || link.url.path_segments().is_some_and(|mut segments| {
            segments.any(|segment| {
                feed_word(segment)
                    || segment.rsplit_once('.').is_some_and(|(stem, extension)| {
                        extension.eq_ignore_ascii_case("rss")
                            || extension.eq_ignore_ascii_case("atom")
                            || (extension.eq_ignore_ascii_case("xml") && feed_word(stem))
                    })
            })
        })
}

fn category_signal(url: &Url) -> bool {
    url.path_segments().is_some_and(|segments| {
        segments.into_iter().any(|segment| {
            matches!(
                segment,
                "category" | "categories" | "section" | "sections" | "topic" | "topics" | "tag" | "tags"
            )
        })
    })
}
