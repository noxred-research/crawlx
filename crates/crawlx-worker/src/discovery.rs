//! URL-plane source discovery. All network work stays behind normal scope/robots/egress.
//!
//! Loader cursors and child requests commit in one fenced frontier transaction. Cursor
//! identity pins source bytes and policy, so changed representations cannot silently resume.

use super::*;
use crate::acquisition::AcquisitionBudgetV1;
use crate::extension_recipes::{
    CompiledExtensionRecipe, RecipeCandidateKindV1, RecipeCandidateV1, RecipeExecutionError,
};
use crate::source_dispatch::{
    SourceDispatchError, SourceDispatchInput, SourceDispatchOutcome, SourceDispatcher, SourceReferenceV1,
};
use crawlx_core::discovery::{DiscoveryErrorV1, DiscoveryProviderV1, DiscoverySourceV1};
use crawlx_core::extension_recipes::ExtensionRecipeV1;
use crawlx_core::extraction::{DiscoveryIntentV1, DiscoveryPurposeV1, QualityStatusV1};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{LoaderCursorV1, RequestBatchV1};
use crawlx_core::request::RequestEnvelopeV1;
use std::borrow::Cow;
use std::future::Future;
use std::io::Read;

#[path = "delivery/memo.rs"]
mod memo;

/// Live run authority used by budgeted robots acquisition for discovery resources.
struct DiscoveryHopAdmission<'a>(&'a UrlPlaneRunner);

#[async_trait::async_trait]
impl crate::acquisition::HopAdmission for DiscoveryHopAdmission<'_> {
    async fn admit(
        &self,
        url: &Url,
        _options: &FetchOptions,
        _budget: &mut AcquisitionBudgetV1,
        _cancel: &CancellationToken,
    ) -> Result<(), FetchError> {
        let canonical = self.0.admit_native_scope(url, 0, false).await?;
        if canonical.url != *url {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    async fn check_scope(&self, url: &Url) -> Result<(), FetchError> {
        self.check_authority().await?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || self.0.prefetch.check(url).is_some()
            || !self.0.scope.decide_protocol_resource(url).is_admitted()
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    async fn check_authority(&self) -> Result<(), FetchError> {
        if self.0.authorization_lost().await
            || self
                .0
                .deps
                .runs
                .get(self.0.run)
                .await
                .map_err(FetchError::OriginAdmission)?
                .status
                == RunStatus::Cancelled
        {
            return Err(FetchError::AcquisitionCancelled);
        }
        Ok(())
    }
}

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
    #[error(transparent)]
    Recipe(#[from] RecipeExecutionError),
}

/// Shared checkpoint authority for list and row-stream source loaders.
struct DiscoveryLoader {
    tenant: crawlx_core::TenantId,
    private_key: Option<Digest>,
    source: String,
    digest: Digest,
    cursor: Option<LoaderCursorV1>,
    fence: i64,
    chunk_size: usize,
    label: String,
}

/// Borrow legacy URLs, recipe proposals or typed child references without copying URLs.
#[derive(Clone, Copy)]
enum SourceBatch<'a> {
    Urls(&'a [Url]),
    Intents(&'a [DiscoveryIntentV1]),
    Recipe(&'a [RecipeCandidateV1]),
    Dispatch(&'a [SourceReferenceV1]),
}

/// Handler and provenance hints carried by one proposal; none is an admission input.
#[derive(Clone, Copy)]
enum Proposal<'a> {
    Recipe(&'a RecipeCandidateV1),
    Reference(&'a SourceReferenceV1),
}

impl<'a> SourceBatch<'a> {
    fn len(self) -> usize {
        match self {
            Self::Urls(urls) => urls.len(),
            Self::Intents(intents) => intents.len(),
            Self::Recipe(candidates) => candidates.len(),
            Self::Dispatch(references) => references.len(),
        }
    }

    fn slice(self, start: usize, end: usize) -> Self {
        match self {
            Self::Urls(urls) => Self::Urls(&urls[start..end]),
            Self::Intents(intents) => Self::Intents(&intents[start..end]),
            Self::Recipe(candidates) => Self::Recipe(&candidates[start..end]),
            Self::Dispatch(references) => Self::Dispatch(&references[start..end]),
        }
    }

    fn iter(self) -> impl Iterator<Item = (&'a Url, Option<Proposal<'a>>)> {
        (0..self.len()).map(move |index| match self {
            Self::Urls(urls) => (&urls[index], None),
            Self::Intents(intents) => (&intents[index].url, None),
            Self::Recipe(candidates) => (&candidates[index].url, Some(Proposal::Recipe(&candidates[index]))),
            Self::Dispatch(references) => (
                &references[index].url,
                Some(Proposal::Reference(&references[index])),
            ),
        })
    }
}

/// Shared immutable selector snapshot used by both native sitemap source paths.
#[derive(Clone)]
struct SourceRecipe {
    compiled: Arc<CompiledExtensionRecipe>,
    max_input_bytes: usize,
    max_sitemap_depth: u16,
}

impl SourceRecipe {
    fn new(spec: &ExtensionRecipeV1, compiled: Arc<CompiledExtensionRecipe>) -> Self {
        Self {
            compiled,
            max_input_bytes: spec.max_input_bytes,
            max_sitemap_depth: spec.max_sitemap_depth,
        }
    }

    fn select(
        &self,
        bytes: &[u8],
        source: &Url,
        depth: u16,
        policy: &crawlx_core::discovery::SourceDiscoveryPolicyV1,
        cancel: &CancellationToken,
    ) -> Result<Vec<RecipeCandidateV1>, SourceParseError> {
        let decoded = decode_sitemap(bytes, policy.max_feed_bytes.min(self.max_input_bytes))?;
        if decoded.len() > self.max_input_bytes {
            return Err(RecipeExecutionError::from(
                crawlx_core::extension_recipes::ExtensionRecipeError::Limit,
            )
            .into());
        }
        let mut document = crawlx_url::SitemapParser::parse_limited(&decoded, policy.max_entries)
            .map_err(crawlx_url::feed::FeedError::from)?;
        if let Some(lastmod) = &policy.sitemap_lastmod {
            document
                .urls
                .retain(|entry| lastmod.includes(entry.lastmod.as_ref()));
        }
        Ok(self.compiled.sitemap_document(document, source, depth, cancel)?)
    }
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

    /// Open one immutable representation; row and list positions share the same cursor CAS.
    async fn source_loader(
        &self,
        parent: &FrontierEntry,
        label: &str,
        source_bytes: &[u8],
    ) -> Result<Option<DiscoveryLoader>, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(None);
        };
        if parent.depth >= policy.max_source_depth {
            return Ok(None);
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
        let wire_digest = Digest::of("crawlx/discovery-bytes/v1", source_bytes);
        let digest = if let Some(recipe) = self.extension_recipe() {
            let pin = recipe.pin();
            Digest::of_value(
                "crawlx/discovery-recipe-representation/v1",
                &(wire_digest, policy, &self.crawl.scope.sources, pin),
            )
        } else {
            Digest::of_value(
                if matches!(label, "html_sources" | "feed") {
                    "crawlx/discovery-representation/v2"
                } else {
                    "crawlx/discovery-representation/v1"
                },
                &(wire_digest, policy, &self.crawl.scope.sources),
            )
        }
        .map_err(|error| WorkerError::Other(error.to_string()))?;
        let digest = private_key.as_ref().map_or(digest, |key| {
            Digest::keyed(&key.0, "crawlx/discovery-private-source/v1", &digest.0)
        });
        let cursor = self.deps.frontier.loader_cursor(self.run, &source).await?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.source_digest != digest)
        {
            return Err(StoreError::Conflict("discovery source changed during resume".into()).into());
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
        Ok(Some(DiscoveryLoader {
            tenant,
            private_key,
            source,
            digest,
            cursor,
            fence,
            chunk_size,
            label: label.to_owned(),
        }))
    }

    /// Commit bounded proposals and their physical source position under the parent fence.
    async fn append_source_chunk(
        &self,
        candidates: SourceBatch<'_>,
        position: u64,
        parent: &FrontierEntry,
        loader: &mut DiscoveryLoader,
    ) -> Result<usize, WorkerError> {
        if self.authorization_lost().await {
            return Err(DiscoveryErrorV1::Protocol("authorization revoked".into()).into());
        }
        let mut requests = Vec::new();
        let mut denied = Vec::new();
        let memo_scope = self.discovery_memo_scope(parent, &loader.label).await?;
        let mut memo_keys = Vec::new();
        let depth = parent.depth.saturating_add(1);
        for (url, recipe) in candidates.iter() {
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
            if self.discovery_memo_seen(&memo_scope, canonical.key).await? {
                continue;
            }
            memo_keys.push(canonical.key);
            let mut request = RequestEnvelopeV1::get(canonical, depth, Some(parent.id));
            match recipe {
                Some(Proposal::Recipe(candidate)) => {
                    request.route.clone_from(&candidate.route);
                    if candidate.kind == RecipeCandidateKindV1::Sitemap {
                        request.metadata.insert(
                            "recipe_sitemap_depth".into(),
                            serde_json::json!(candidate.sitemap_depth),
                        );
                    }
                    if let Some(language) = &candidate.language_hint {
                        request
                            .metadata
                            .insert("recipe_language_hint".into(), serde_json::json!(language));
                    }
                }
                Some(Proposal::Reference(reference)) => {
                    // A source-authored label names a reviewed handler only; otherwise default.
                    if self.crawl.extensions.route(&reference.route).is_ok() {
                        request.route.clone_from(&reference.route);
                    }
                    request.metadata.insert(
                        "source_child".into(),
                        serde_json::json!(reference.source_child.to_hex()),
                    );
                    request
                        .metadata
                        .insert("source_ordinal".into(), serde_json::json!(reference.ordinal));
                }
                None => {}
            }
            requests.push(request);
        }
        let next = LoaderCursorV1::new(loader.source.clone(), loader.digest, position);
        let batch_id = Digest::of_value(
            "crawlx/discovery-batch/v1",
            &(self.run, &loader.source, loader.digest, &loader.cursor, &next),
        )
        .map_err(|error| WorkerError::Other(error.to_string()))?;
        let batch_id = loader.private_key.as_ref().map_or(batch_id, |key| {
            Digest::keyed(&key.0, "crawlx/discovery-private-batch/v1", &batch_id.0)
        });
        let mut batch = RequestBatchV1::new(loader.tenant, self.run, "anonymous".into(), batch_id, requests);
        batch.expected_cursor = loader.cursor.clone();
        batch.next_cursor = Some(next.clone());
        batch.parent_fence = Some((parent.id, loader.fence));
        let receipt = self.deps.frontier.append_batch(batch).await?;
        self.discovery_memo_record(&memo_scope, &memo_keys).await?;
        let inserted = receipt.inserted.len();
        for id in receipt.inserted {
            let request = self.deps.frontier.get_request(self.run, id).await?;
            self.ledger.lock().pending.insert(
                id,
                PendingUrl {
                    resume: ResumeEntry::new(request.envelope.url.url.to_string(), depth),
                    is_get: request.envelope.method == "GET",
                },
            );
            self.counters.discovery(Plane::Urls, DiscoveryOutcome::Admitted);
        }
        for _ in 0..receipt.duplicates {
            self.counters.discovery(Plane::Urls, DiscoveryOutcome::Duplicate);
        }
        for (outcome, reason) in denied {
            self.counters.discovery_with_reason(Plane::Urls, outcome, reason);
        }
        loader.cursor = Some(next);
        Ok(inserted)
    }

    /// Resolve inline candidates once at the seed, using the normal fenced source admission.
    async fn discover_url_list(
        &self,
        parent: &FrontierEntry,
        record: &mut PageRecord,
        expand: bool,
    ) -> Result<(), WorkerError> {
        if !expand
            || parent.depth != 0
            || self.crawl.cache_only()
            || !self.source_enabled(DiscoverySourceV1::UrlList)
        {
            return Ok(());
        }
        let Some(list) = self
            .crawl
            .scope
            .discovery
            .as_ref()
            .and_then(|policy| policy.url_list.as_ref())
        else {
            return Ok(());
        };
        let resolved = list.resolve(self.crawl.scope.max_known_urls)?;
        let intents = resolved.intents();
        let source_bytes = serde_json::to_vec(list).map_err(crawlx_core::CoreError::from)?;
        let admitted = self
            .append_source_candidates(SourceBatch::Intents(&intents), parent, "url_list", &source_bytes)
            .await?;
        record.metadata["url_list"] = serde_json::json!({
            "candidates":intents.len(),"duplicates":resolved.duplicates,"admitted":admitted,
        });
        Ok(())
    }

    /// Admit a parsed source as bounded atomic chunks, including rejected input positions.
    async fn append_source_urls(
        &self,
        urls: &[Url],
        parent: &FrontierEntry,
        label: &str,
        source_bytes: &[u8],
    ) -> Result<usize, WorkerError> {
        self.append_source_candidates(SourceBatch::Urls(urls), parent, label, source_bytes)
            .await
    }

    /// Preserve exact recipe handlers while sharing native admission and fenced cursors.
    async fn append_source_candidates(
        &self,
        candidates: SourceBatch<'_>,
        parent: &FrontierEntry,
        label: &str,
        source_bytes: &[u8],
    ) -> Result<usize, WorkerError> {
        let Some(mut loader) = self.source_loader(parent, label, source_bytes).await? else {
            return Ok(0);
        };
        let mut start = loader
            .cursor
            .as_ref()
            .map_or(0, |cursor| usize::try_from(cursor.position).unwrap_or(usize::MAX));
        if start > candidates.len() {
            return Err(StoreError::Conflict("discovery cursor exceeds source".into()).into());
        }
        let mut inserted = 0_usize;
        // Empty selections still pin representation and recipe identity on the first commit.
        while start < candidates.len() || (candidates.len() == 0 && loader.cursor.is_none()) {
            let end = start.saturating_add(loader.chunk_size).min(candidates.len());
            inserted = inserted.saturating_add(
                self.append_source_chunk(
                    candidates.slice(start, end),
                    u64::try_from(end).unwrap_or(u64::MAX),
                    parent,
                    &mut loader,
                )
                .await?,
            );
            start = end;
        }
        Ok(inserted)
    }

    /// Redact source-authored fields before attaching the generated artifact-chain link.
    async fn store_feed_batch(
        &self,
        page: i64,
        evidence: &[u8],
        previous: Option<&crawlx_core::ArtifactRef>,
    ) -> Option<crawlx_core::ArtifactRef> {
        let registry = self.captcha_secrets.as_ref()?;
        let controls = &self.fetcher.config().controls;
        let redactor = crawlx_core::secret::Redactor::new();
        let evidence = redactor.scrub_bytes(evidence, controls.secret_values());
        let mut entries: serde_json::Value = serde_json::from_slice(evidence.as_ref()).ok()?;
        registry.redact_json(&mut entries).ok()?;
        let entries = redactor
            .redact_artifact(&serde_json::to_vec(&entries).ok()?)
            .ok()?;
        let entries: serde_json::Value = serde_json::from_slice(entries.as_ref()).ok()?;
        // Only this locally generated reference avoids the bare-hex heuristic. Source fields
        // already passed generic redaction; canonical approval and scoped checks still inspect
        // the complete envelope, including the reference, before it reaches ArtifactSink.
        let bytes = serde_json::to_vec(&serde_json::json!({
            "previous":previous,"entries":entries,
        }))
        .ok()?;
        let bytes = redactor.verify_canonical_owned(bytes).ok()?;
        crate::capture::check_run_secrets(bytes.as_ref(), controls, Some(registry)).ok()?;
        match ArtifactSink::over(self.deps.artifacts.as_ref())
            .put_page(
                self.run,
                page,
                Sensitivity::Content,
                "application/vnd.crawlx.discovery+json",
                &bytes,
            )
            .await
        {
            Ok(reference) => Some(reference),
            Err(error) => {
                tracing::debug!(error = %error, "feed evidence artifact not stored");
                None
            }
        }
    }

    /// Stream XML rows on the bounded CPU pool, committing physical positions, not selected URLs.
    async fn discover_xml_feed(
        &self,
        entry: &FrontierEntry,
        response: &FetchResponse,
        record: &mut PageRecord,
        expand: bool,
    ) -> Result<(), WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(());
        };
        let mut loader = if expand && !self.crawl.cache_only() {
            self.source_loader(entry, "feed", &response.body).await?
        } else {
            None
        };
        let start = loader
            .as_ref()
            .and_then(|loader| loader.cursor.as_ref())
            .map_or(0, |cursor| cursor.position);
        let row_chunk_size = loader
            .as_ref()
            .map_or(4, |loader| (loader.chunk_size / 16).clamp(1, 4));
        let body = response.body.clone();
        let base = response.final_url.clone();
        let parser_policy = policy.clone();
        let opened = self
            .cpu_pool
            .run(move || crawlx_url::feed::XmlFeedStream::new(body, base, parser_policy))
            .await
            .map_err(|error| WorkerError::Other(error.to_string()))?;
        let mut stream = match opened {
            Ok(stream) => stream,
            Err(_) => {
                record.metadata["source_discovery"] = serde_json::json!({
                    "status":"rejected","reason":"source_protocol","kind":"feed","streamed":true,
                });
                return Ok(());
            }
        };
        let mut position = 0u64;
        let mut candidates = 0usize;
        let mut admitted = 0usize;
        let mut malformed = 0usize;
        let mut content = None;
        let mut truncated = false;
        let mut rejected = false;
        let max_entries = u64::try_from(policy.max_entries).unwrap_or(u64::MAX);
        loop {
            if self.authorization_lost().await {
                return Err(DiscoveryErrorV1::Protocol("authorization revoked".into()).into());
            }
            let (returned, parsed) = self
                .cpu_pool
                .run(move || {
                    let mut urls = Vec::new();
                    let mut evidence = Vec::new();
                    let mut next_position = position;
                    let mut bad = 0usize;
                    let mut count = 0usize;
                    let mut done = false;
                    let mut truncated = false;
                    let result = (|| -> Result<_, crawlx_url::feed::FeedError> {
                        for _ in 0..row_chunk_size {
                            if next_position >= max_entries {
                                truncated = stream.next().transpose()?.is_some();
                                done = true;
                                break;
                            }
                            let Some(row) = stream.next().transpose()? else {
                                done = true;
                                break;
                            };
                            next_position = row.cursor.row_index;
                            match row.document {
                                Ok(document) => {
                                    count = count.saturating_add(document.entries.len());
                                    for item in document.entries {
                                        evidence.push(serde_json::json!({
                                            "row":row.cursor.row_index.saturating_sub(1),"url":item.url,
                                            "titleHint":item.title,"dateHint":item.date,
                                            "publisherHint":item.publisher,"mediaIntents":item.media,
                                            "readMoreIntents":item.read_more,
                                        }));
                                        if next_position > start {
                                            urls.push(item.url);
                                        }
                                    }
                                }
                                Err(_) => {
                                    bad = bad.saturating_add(1);
                                    evidence.push(serde_json::json!({
                                        "row":row.cursor.row_index.saturating_sub(1),"outcome":"malformed",
                                    }));
                                }
                            }
                        }
                        let bytes =
                            serde_json::to_vec(&evidence).map_err(crawlx_url::feed::FeedError::from)?;
                        Ok((urls, bytes, next_position, bad, count, done, truncated))
                    })();
                    (stream, result)
                })
                .await
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            stream = returned;
            let (urls, evidence, next_position, bad, count, done, limited) = match parsed {
                Ok(chunk) => chunk,
                Err(_) => {
                    rejected = true;
                    break;
                }
            };
            malformed = malformed.saturating_add(bad);
            candidates = candidates.saturating_add(count);
            truncated |= limited;
            if next_position > position {
                content = self.store_feed_batch(entry.id, &evidence, content.as_ref()).await;
            }
            position = next_position;
            if let Some(loader) = &mut loader {
                let committed = loader.cursor.as_ref().map_or(0, |cursor| cursor.position);
                if position > committed || (done && loader.cursor.is_none()) {
                    if urls.len() > loader.chunk_size {
                        return Err(DiscoveryErrorV1::Limit("feed_row_requests").into());
                    }
                    admitted = admitted.saturating_add(
                        self.append_source_chunk(SourceBatch::Urls(&urls), position, entry, loader)
                            .await?,
                    );
                }
            }
            if done {
                break;
            }
        }
        if start > position && !rejected {
            return Err(StoreError::Conflict("discovery cursor exceeds source".into()).into());
        }
        if !rejected && expand && !self.crawl.cache_only() {
            let mut links: Vec<_> = stream
                .next_links()
                .iter()
                .take(policy.max_source_documents)
                .cloned()
                .collect();
            if entry.depth == 0 {
                links.extend(self.configured_discovery_sources(&entry.url));
            }
            admitted = admitted.saturating_add(
                self.append_source_urls(&links, entry, "feed_links", &response.body)
                    .await?,
            );
        }
        record.metadata["source_discovery"] = serde_json::json!({
            "status":if rejected { "partial" } else { "parsed" },"kind":"feed","streamed":true,
            "reason":if rejected { Some("source_protocol") } else { None },
            "rows":position,"candidates":candidates,"admitted":admitted,"malformed":malformed,
            "truncated":truncated,"content":content,"contentLayout":"reverse_batch_chain_v1",
        });
        Ok(())
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
        cancel: &CancellationToken,
    ) -> Result<bool, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(false);
        };
        self.discover_url_list(entry, record, expand).await?;
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
        let source_dispatcher =
            if connector.is_none() && !sitemap && self.source_enabled(DiscoverySourceV1::Feeds) {
                self.source_dispatcher()
            } else {
                None
            };
        let dispatch_recognized = source_dispatcher.is_some()
            && SourceDispatcher::recognizes(&response.body, response.content_type.as_deref());
        // Supported archive bytes without an operator capability are reported, never parsed.
        let dispatch_unavailable = connector.is_none()
            && !sitemap
            && source_dispatcher.is_none()
            && self.source_enabled(DiscoverySourceV1::Feeds)
            && response.body.starts_with(b"PK\x03\x04");
        if connector.is_none() && !feed && !sitemap && !dispatch_recognized && !dispatch_unavailable {
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
        if dispatch_unavailable {
            record.metadata["source_dispatch"] = serde_json::json!({
                "status":"unavailable","reason":"operator_policy_missing",
            });
            return Ok(true);
        }
        if let Some(dispatcher) = source_dispatcher.filter(|_| dispatch_recognized) {
            self.discover_dispatched_source(Arc::clone(dispatcher), entry, response, record, expand, cancel)
                .await?;
            // Feeds still run the richer native URL parser below; archive and unhandled
            // bytes end here without a second, independent interpretation.
            if !feed {
                return Ok(true);
            }
        }
        if sitemap && connector.is_none() && self.crawl.extension_recipe.is_some() {
            self.discover_recipe_source_response(entry, response, record, expand, cancel)
                .await?;
            return Ok(true);
        }
        if connector.is_none()
            && feed
            && !sitemap
            && response
                .body
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&response.body)
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| *byte == b'<')
        {
            self.discover_xml_feed(entry, response, record, expand).await?;
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
                    SourceParseError::Recipe(_) => ("rejected", "recipe_source"),
                };
                record.metadata["source_discovery"] = serde_json::json!({"status":status,"reason":reason});
            }
        }
        Ok(true)
    }

    /// Run the operator-approved bounded dispatcher on the CPU pool and admit its typed child
    /// references through the same fenced scope/robots/budget path as every other source.
    async fn discover_dispatched_source(
        &self,
        dispatcher: Arc<SourceDispatcher>,
        entry: &FrontierEntry,
        response: &FetchResponse,
        record: &mut PageRecord,
        expand: bool,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        // Body and its transport admission enter the blocking closure together.
        let body = super::memory_plane::owned_bytes(response);
        let content_type = response.content_type.clone();
        let final_url = response.final_url.clone();
        let tenant = self.deps.runs.get(self.run).await?.tenant;
        // Stable and tenant-scoped; never derived from source content.
        let root_id = Digest::of_value(
            "crawlx/source-dispatch-root/v1",
            &(tenant, self.run, entry.id, entry.url.key),
        )
        .map_err(|error| WorkerError::Other(error.to_string()))?;
        let retention = self.crawl.retention.mode;
        let controls = self.fetcher.config().controls.clone();
        let captcha = self.captcha_secrets.clone();
        let token = cancel.clone();
        let outcome = self
            .cpu_pool
            .run(move || {
                let privacy = |text: &str| -> Result<String, StoreError> {
                    let scrubbed = crawlx_core::secret::Redactor::new()
                        .scrub_bytes(text.as_bytes(), controls.secret_values());
                    let text = String::from_utf8(scrubbed.into_owned())
                        .map_err(|_| StoreError::RetentionDenied("source projection unavailable".into()))?;
                    match &captcha {
                        Some(registry) => registry
                            .redact(&text)
                            .map_err(|_| StoreError::RetentionDenied("source projection unavailable".into())),
                        None => Ok(text),
                    }
                };
                let cancelled = || token.is_cancelled();
                dispatcher.dispatch(SourceDispatchInput {
                    body: body.as_ref(),
                    content_type: content_type.as_deref(),
                    response_url: &final_url,
                    root_id,
                    retention,
                    truncated: false,
                    baseline_modified_ms: None,
                    privacy: &privacy,
                    cancelled: &cancelled,
                })
            })
            .await
            .map_err(|error| WorkerError::Other(error.to_string()))?;
        if cancel.is_cancelled() {
            return Err(FetchError::AcquisitionCancelled.into());
        }
        match outcome {
            Ok(SourceDispatchOutcome::NotHandled) => {}
            Ok(SourceDispatchOutcome::Handled(carrier)) => {
                // The carrier owns the expansion reservation until references are admitted
                // and the evidence is stored.
                let batch = carrier.value();
                let admitted = if expand && !self.crawl.cache_only() {
                    self.append_source_candidates(
                        SourceBatch::Dispatch(&batch.references),
                        entry,
                        "source_dispatch",
                        &response.body,
                    )
                    .await?
                } else {
                    0
                };
                let evidence =
                    serde_json::to_vec(batch).map_err(|error| WorkerError::Other(error.to_string()))?;
                let artifact = self
                    .store(
                        entry.id,
                        Sensitivity::Content,
                        "application/vnd.crawlx.discovery+json",
                        &evidence,
                    )
                    .await;
                record.metadata["source_dispatch"] = serde_json::json!({
                    "status":"parsed","children":batch.children.len(),
                    "references":batch.references.len(),"admitted":admitted,
                    "truncated":batch.truncated,"omittedChildren":batch.omitted_children,
                    "freshness":batch.freshness,"policyDigest":batch.policy_digest,
                    "content":artifact,
                });
            }
            Err(SourceDispatchError::Cancelled) => return Err(FetchError::AcquisitionCancelled.into()),
            Err(SourceDispatchError::Unavailable(reason)) => {
                record.metadata["source_dispatch"] =
                    serde_json::json!({"status":"unavailable","reason":reason.as_str()});
            }
            Err(SourceDispatchError::SourceTruncated | SourceDispatchError::Limit) => {
                record.metadata["source_dispatch"] =
                    serde_json::json!({"status":"resource_limit","reason":"source_dispatch_limit"});
            }
            Err(_) => {
                record.metadata["source_dispatch"] =
                    serde_json::json!({"status":"rejected","reason":"source_dispatch_refused"});
            }
        }
        Ok(())
    }

    /// Evaluate source recipes before the generic source response can return early.
    async fn discover_recipe_source_response(
        &self,
        entry: &FrontierEntry,
        response: &FetchResponse,
        record: &mut PageRecord,
        expand: bool,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let Some(spec) = &self.crawl.extension_recipe else {
            return Ok(());
        };
        let compiled = self
            .extension_recipe()
            .ok_or_else(|| WorkerError::Config("extension recipe snapshot unavailable".into()))?;
        let recipe = SourceRecipe::new(spec, Arc::clone(compiled));
        let pin = compiled.pin().clone();
        let request = self.deps.frontier.get_request(self.run, entry.id).await?;
        let depth = match request.envelope.metadata.get("recipe_sitemap_depth") {
            Some(value) => value
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| WorkerError::Config("invalid recipe sitemap depth".into()))?,
            None => 0,
        };
        let body = response.body.clone();
        let source = response.final_url.clone();
        let policy = self
            .crawl
            .scope
            .discovery
            .clone()
            .ok_or_else(|| WorkerError::Config("source policy unavailable".into()))?;
        let cancellation = cancel.clone();
        let selected = self
            .cpu_pool
            .run(move || recipe.select(&body, &source, depth, &policy, &cancellation))
            .await
            .map_err(|error| WorkerError::Other(error.to_string()))?;
        if cancel.is_cancelled() {
            return Err(FetchError::AcquisitionCancelled.into());
        }
        match selected {
            Ok(candidates) => {
                let mut admitted = if expand && !self.crawl.cache_only() {
                    self.append_source_candidates(
                        SourceBatch::Recipe(&candidates),
                        entry,
                        "sitemap",
                        &response.body,
                    )
                    .await?
                } else {
                    0
                };
                if expand && !self.crawl.cache_only() && entry.depth == 0 {
                    let configured = self.configured_discovery_sources(&entry.url);
                    if !configured.is_empty() {
                        admitted = admitted.saturating_add(
                            self.append_source_urls(&configured, entry, "configured_sources", &response.body)
                                .await?,
                        );
                    }
                }
                let content = serde_json::to_vec(&serde_json::json!({
                    "recipe":pin, "variants":candidates,
                }))
                .map_err(|error| WorkerError::Other(error.to_string()))?;
                let artifact = self
                    .store(
                        entry.id,
                        Sensitivity::Content,
                        "application/vnd.crawlx.discovery+json",
                        &content,
                    )
                    .await;
                record.metadata["source_discovery"] = serde_json::json!({
                    "status":"parsed", "kind":"sitemap", "recipe":pin,
                    "candidates":candidates.len(), "admitted":admitted,
                    "truncated":false, "content":artifact,
                });
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
                    SourceParseError::Recipe(_) => ("rejected", "recipe_source"),
                };
                record.metadata["source_discovery"] = serde_json::json!({
                    "status":status, "reason":reason, "recipe":pin,
                });
            }
        }
        Ok(())
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
            sources.extend(self.discovery_categories(entry, response, doc).await?);
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
        if self.crawl.extension_recipe.is_some() {
            return self
                .discover_recipe_parent_sitemaps(parent, record, budget, cancel)
                .await;
        }
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
                .fetch_discovery_auxiliary(
                    &url,
                    parent.depth,
                    policy.max_feed_bytes,
                    budget,
                    cancel,
                    crawlx_policy::robots::HopKind::Feed,
                )
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

    /// Keep native auxiliary budgets while applying the same recipe to every sitemap.
    async fn discover_recipe_parent_sitemaps(
        &self,
        parent: &FrontierEntry,
        record: &mut PageRecord,
        budget: &mut AcquisitionBudgetV1,
        cancel: &CancellationToken,
    ) -> Result<usize, WorkerError> {
        let Some(policy) = &self.crawl.scope.discovery else {
            return Ok(0);
        };
        let Some(spec) = &self.crawl.extension_recipe else {
            return Ok(0);
        };
        let compiled = self
            .extension_recipe()
            .ok_or_else(|| WorkerError::Config("extension recipe snapshot unavailable".into()))?;
        let recipe = SourceRecipe::new(spec, Arc::clone(compiled));
        let mut roots = self.robots.sitemaps(&parent.url.origin);
        if roots.is_empty() {
            if let Ok(url) = parent.url.url.join("/sitemap.xml") {
                roots.push(url.to_string());
            }
        }
        let mut partial = roots.len() > policy.max_source_documents;
        let mut queue: std::collections::VecDeque<_> = roots
            .into_iter()
            .take(policy.max_source_documents)
            .map(|url| (url, 0_u16))
            .collect();
        let mut seen = BTreeSet::new();
        let mut unique = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut output_bytes = 2_usize;
        let mut representations = Vec::new();
        let mut attempted = 0_usize;
        let mut failed = 0_usize;
        while let Some((location, depth)) = queue.pop_front() {
            if cancel.is_cancelled() {
                return Err(FetchError::AcquisitionCancelled.into());
            }
            if attempted >= policy.max_source_documents
                || depth > policy.max_source_depth.min(recipe.max_sitemap_depth)
                || candidates.len() >= policy.max_entries.min(spec.max_candidates)
                || !budget.can_retry()
            {
                partial = true;
                break;
            }
            if !seen.insert(location.clone()) {
                continue;
            }
            attempted = attempted.saturating_add(1);
            let Ok(url) = Url::parse(&location) else {
                failed = failed.saturating_add(1);
                continue;
            };
            let response = match self
                .fetch_discovery_auxiliary(
                    &url,
                    parent.depth,
                    policy.max_feed_bytes.min(recipe.max_input_bytes),
                    budget,
                    cancel,
                    crawlx_policy::robots::HopKind::Feed,
                )
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
            let source = response.final_url.clone();
            let parser = recipe.clone();
            let parser_policy = policy.clone();
            let cancellation = cancel.clone();
            let selected = self
                .cpu_pool
                .run(move || parser.select(&body, &source, depth, &parser_policy, &cancellation))
                .await
                .map_err(|error| WorkerError::Other(error.to_string()))?;
            match selected {
                Ok(selected) => {
                    for candidate in selected {
                        if candidate.kind == RecipeCandidateKindV1::Sitemap {
                            let room = policy
                                .max_source_documents
                                .saturating_sub(attempted)
                                .saturating_sub(queue.len());
                            if room == 0 {
                                partial = true;
                            } else {
                                queue.push_back((candidate.url.into(), candidate.sitemap_depth));
                            }
                        } else if unique.insert(candidate.url.clone()) {
                            let bytes = crawlx_core::extensions::json_size(&candidate)
                                .map_err(|error| WorkerError::Config(error.to_string()))?;
                            let next_bytes = output_bytes
                                .saturating_add(bytes)
                                .saturating_add(usize::from(!candidates.is_empty()));
                            if candidates.len() >= policy.max_entries.min(spec.max_candidates)
                                || next_bytes > spec.max_output_bytes
                            {
                                partial = true;
                                break;
                            }
                            output_bytes = next_bytes;
                            candidates.push(candidate);
                        }
                    }
                }
                Err(_) => failed = failed.saturating_add(1),
            }
        }
        if cancel.is_cancelled() {
            return Err(FetchError::AcquisitionCancelled.into());
        }
        let source_bytes =
            serde_json::to_vec(&representations).map_err(|error| WorkerError::Other(error.to_string()))?;
        let admitted = self
            .append_source_candidates(SourceBatch::Recipe(&candidates), parent, "sitemap", &source_bytes)
            .await?;
        let evidence = serde_json::to_vec(&serde_json::json!({
            "recipe":compiled.pin(), "representations":representations, "variants":candidates,
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
            "recipe":compiled.pin(), "candidates":candidates.len(), "admitted":admitted,
            "documentsAttempted":attempted, "failedDocuments":failed,
            "partial":partial || failed > 0, "content":content,
        });
        Ok(admitted)
    }

    /// Shared scope and authority admission, without recursively loading robots.
    pub(super) async fn admit_native_scope(
        &self,
        url: &Url,
        depth: u16,
        allow_leaf: bool,
    ) -> Result<CanonicalUrl, FetchError> {
        if self.crawl.cache_only() || self.authorization_lost().await {
            return Err(FetchError::AcquisitionUnavailable);
        }
        if self.prefetch.check(url).is_some() {
            return Err(FetchError::AcquisitionUnavailable);
        }
        let (canonical, bearing) = self.canonicalize(url).ok_or(FetchError::AcquisitionUnavailable)?;
        if bearing
            || !match self.scope.decide(&canonical, depth) {
                ScopeVerdict::Admitted { leaf_only } => {
                    !leaf_only || (allow_leaf && self.scope.fetch_leaves())
                }
                ScopeVerdict::Denied(_) => false,
            }
        {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(canonical)
    }

    /// Fetch one auxiliary resource with scope/robots checked before every manual redirect.
    /// Same fetcher means checked DNS/peer/cert/proxy and shared OriginGovernor, never a raw client.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn fetch_discovery_auxiliary<'a>(
        &'a self,
        original: &'a Url,
        depth: u16,
        cap: usize,
        budget: &'a mut AcquisitionBudgetV1,
        cancel: &'a CancellationToken,
        kind: crawlx_policy::robots::HopKind,
    ) -> impl Future<Output = Result<FetchResponse, FetchError>> + 'a {
        Box::pin(self.fetch_discovery_auxiliary_inner(original, depth, cap, budget, cancel, kind, None))
    }

    /// Bind parser-produced auxiliary work to the exact live parent URL lease.
    #[allow(clippy::too_many_arguments)]
    fn fetch_discovery_auxiliary_owned<'a>(
        &'a self,
        parent: &'a FrontierEntry,
        original: &'a Url,
        depth: u16,
        cap: usize,
        budget: &'a mut AcquisitionBudgetV1,
        cancel: &'a CancellationToken,
        kind: crawlx_policy::robots::HopKind,
    ) -> impl Future<Output = Result<FetchResponse, FetchError>> + 'a {
        Box::pin(self.fetch_discovery_auxiliary_inner(
            original,
            depth,
            cap,
            budget,
            cancel,
            kind,
            Some(parent),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_discovery_auxiliary_inner(
        &self,
        original: &Url,
        depth: u16,
        cap: usize,
        budget: &mut AcquisitionBudgetV1,
        cancel: &CancellationToken,
        kind: crawlx_policy::robots::HopKind,
        parent: Option<&FrontierEntry>,
    ) -> Result<FetchResponse, FetchError> {
        if self.crawl.cache_only() {
            return Err(FetchError::AcquisitionUnavailable);
        }
        let parent_authority = parent
            .map(|entry| NativeHopAdmission::new(self, entry))
            .transpose()?;
        let discovery_authority = DiscoveryHopAdmission(self);
        let authority: &dyn crate::acquisition::HopAdmission = match &parent_authority {
            Some(parent) => parent,
            None => &discovery_authority,
        };
        let mut current = original.clone();
        let mut seen = BTreeSet::new();
        let mut redirects = Vec::new();
        let mut original_options = crate::acquisition::fetch_options(&self.crawl.fetch);
        original_options.max_body_bytes = Some(cap);
        original_options.follow_redirects = false;
        for hop in 0..=self.fetcher.config().max_redirects.min(20) {
            if !seen.insert(current.as_str().to_owned()) {
                return Err(FetchError::AcquisitionAllowance);
            }
            authority.check_authority().await?;
            let canonical = self.admit_native_scope(&current, depth, false).await?;
            if canonical.url != current {
                return Err(FetchError::AcquisitionUnavailable);
            }
            if kind == crawlx_policy::robots::HopKind::Page {
                crawlx_core::extraction::check_preview_target(&current)
                    .map_err(|_| FetchError::AcquisitionUnavailable)?;
            }
            let hop_kind = if hop == 0 {
                kind
            } else {
                crawlx_policy::robots::HopKind::Redirect
            };
            if self
                .robots
                .decide_hop_with_budget(hop_kind, &current, &original_options, budget, cancel, authority)
                .await?
                != RobotsDecision::Allowed
            {
                return Err(FetchError::AcquisitionUnavailable);
            }
            let fetched = Box::pin(crate::acquisition::fetch_budgeted_once(
                &self.fetcher,
                &current,
                &original_options,
                budget,
                cancel,
                authority,
            ))
            .await;
            self.record_exchange(&current, &fetched);
            let mut response = fetched?;
            if !response.status.is_redirection() || !self.fetcher.config().follow_redirects {
                response.redirects = redirects;
                return Ok(response);
            }
            let location = response
                .headers
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(FetchError::AcquisitionUnavailable)?;
            let next = current
                .join(location)
                .map_err(|_| FetchError::AcquisitionUnavailable)?;
            if current.origin() != next.origin() {
                original_options.suppress_credentials = true;
                crawlx_fetch::redirect::strip_credentials(&mut original_options.headers);
            }
            original_options.validators = None;
            original_options.suppress_validators = true;
            redirects.push(current.to_string());
            current = next;
        }
        Err(FetchError::AcquisitionAllowance)
    }

    pub(super) async fn follow_article_intents(
        &self,
        entry: &FrontierEntry,
        doc: &Document,
        primary_body: &[u8],
        record: &mut PageRecord,
        budget: Option<&mut AcquisitionBudgetV1>,
        cancel: &CancellationToken,
    ) -> Result<(), WorkerError> {
        let defaults = crawlx_core::discovery::SourceDiscoveryPolicyV1::default();
        let policy = self.crawl.scope.discovery.as_ref().unwrap_or(&defaults);
        if self.crawl.cache_only() {
            record.metadata["discovery_auxiliary"] =
                serde_json::json!({"status":"unavailable","reason":"cache_only","followed":0});
            return Ok(());
        }
        let discovery = doc
            .article
            .as_ref()
            .map(|article| article.discovery.as_slice())
            .unwrap_or(&[]);
        let Some(budget) = budget else {
            return Ok(());
        };
        let captcha = self.captcha_secrets.clone().ok_or_else(|| {
            StoreError::RetentionDenied("discovery dynamic-secret registry unavailable".into())
        })?;
        let mut reports = Vec::new();
        if let Some(link_media) = doc
            .outputs
            .as_ref()
            .and_then(|outputs| outputs.link_media.as_ref())
        {
            for intent in &link_media.previews {
                let primary_target = intent.url == entry.url.url
                    || record.metadata["final_url"].as_str() == Some(intent.url.as_str());
                let obtained = if primary_target {
                    let cap = usize::try_from(intent.max_head_bytes).unwrap_or(usize::MAX);
                    Ok((
                        bytes::Bytes::copy_from_slice(&primary_body[..primary_body.len().min(cap)]),
                        primary_body.len() > cap,
                    ))
                } else {
                    match self
                        .fetch_discovery_auxiliary_owned(
                            entry,
                            &intent.url,
                            entry.depth,
                            usize::try_from(intent.max_head_bytes).unwrap_or(usize::MAX),
                            budget,
                            cancel,
                            crawlx_policy::robots::HopKind::Page,
                        )
                        .await
                    {
                        Ok(response) if response.status.is_success() => {
                            Ok((response.body, response.truncated))
                        }
                        Ok(_) => Err("target_status".to_owned()),
                        Err(error) => Err(error.code().to_owned()),
                    }
                };
                let report = match obtained {
                    Ok((body, truncated)) => {
                        let intent = intent.clone();
                        let controls = self.fetcher.config().controls.clone();
                        let registry = captcha.clone();
                        let head = self
                            .cpu_pool
                            .run(move || {
                                let redactor = crawlx_core::secret::Redactor::new();
                                let body = redactor.scrub_bytes(&body, controls.secret_values());
                                let decoded = String::from_utf8_lossy(body.as_ref());
                                let projected = registry.redact_if_present(&decoded).map_err(|_| {
                                    StoreError::RetentionDenied(
                                        "preview secret projection unavailable".into(),
                                    )
                                })?;
                                let mut head =
                                    crawlx_extract::link_media::project_head(&intent, projected.as_bytes())
                                        .map_err(WorkerError::Extraction)?;
                                head.truncated |= truncated;
                                Ok::<_, WorkerError>(head)
                            })
                            .await
                            .map_err(|error| WorkerError::Other(error.to_string()))??;
                        serde_json::json!({"purpose":"preview","status":"fulfilled","head":head})
                    }
                    Err(reason) => {
                        serde_json::json!({"purpose":"preview","status":"unavailable","reason":reason})
                    }
                };
                reports.push(report);
            }
        }
        let mut media_count = 0usize;
        let article_hops_enabled = self.crawl.scope.discovery.is_some();
        let mut seen = BTreeSet::from([entry.url.url.as_str().to_owned()]);
        for intent in discovery {
            if !article_hops_enabled
                || intent.purpose != DiscoveryPurposeV1::ImageReference
                || media_count >= policy.media_probes
            {
                continue;
            }
            if !seen.insert(intent.url.as_str().to_owned()) {
                continue;
            }
            media_count = media_count.saturating_add(1);
            let outcome = match self
                .fetch_discovery_auxiliary_owned(
                    entry,
                    &intent.url,
                    entry.depth,
                    policy.media_header_bytes,
                    budget,
                    cancel,
                    crawlx_policy::robots::HopKind::Media,
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
        let mut next = discovery
            .iter()
            .find(|intent| intent.purpose == DiscoveryPurposeV1::ReadMoreReference)
            .map(|intent| intent.url.clone());
        for hop in 0..if article_hops_enabled {
            policy.read_more_hops
        } else {
            0
        } {
            let Some(url) = next.take() else {
                break;
            };
            if !seen.insert(url.as_str().to_owned()) {
                break;
            }
            match self
                .fetch_discovery_auxiliary_owned(
                    entry,
                    &url,
                    entry.depth.saturating_add(u16::from(hop)).saturating_add(1),
                    policy.max_feed_bytes,
                    budget,
                    cancel,
                    crawlx_policy::robots::HopKind::ReadMore,
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
                    let base = response.final_url.clone();
                    let extracted = if response.status.is_success() && !response.truncated {
                        let hold =
                            memory_plane::reserve_derived(memory_plane::derived_bytes(response.body.len()))
                                .map_err(|error| {
                                WorkerError::Other(format!("discovery document memory admission: {error}"))
                            })?;
                        match memory_plane::extract_isolated(
                            &self.cpu_pool,
                            crawlx_core::parser_memory::Budgeted::new(
                                memory_plane::owned_bytes(&response),
                                hold,
                            ),
                            base,
                            opts,
                            &self.fetcher.config().controls,
                            Some(&captcha),
                            cancel,
                        )
                        .await
                        {
                            memory_plane::IsolatedOutcome::Parsed(document, hold) => Some((document, hold)),
                            memory_plane::IsolatedOutcome::Failed(_) => None,
                            memory_plane::IsolatedOutcome::Cancelled => {
                                return Err(FetchError::AcquisitionCancelled.into())
                            }
                        }
                    } else {
                        None
                    };
                    let mut article_content = None;
                    if let Some((document, _document_hold)) = extracted {
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

/// What a live check of one seed candidate found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveCheck {
    /// The server answered with a status from 200 to 399.
    Alive,
    /// It answered with another status.
    Dead,
    /// Scope, robots, authorization or egress refused the request; nothing was sent.
    Refused,
    /// The request was admitted but did not complete.
    Failed,
}

/// Tally of one seeding pass, recorded as the `seed.sources` event.
#[derive(Default)]
struct SeedTally {
    queued: u64,
    duplicate: u64,
    policy_blocked: u64,
    robots_blocked: u64,
    live_dead: u64,
    live_refused: u64,
    live_failed: u64,
}

impl UrlPlaneRunner {
    /// Queue the candidates of `scope.seeding`'s recorded sources next to the seed.
    ///
    /// Parsing the fixtures touches no network. Each candidate then enters the frontier through
    /// the ordinary discovery gate (scope, robots, authorization, the budget, dedupe), so a source
    /// can only propose: a URL outside the crawl's scope or disallowed by robots is refused
    /// exactly like a link to it would be. With `liveCheck: head` the candidate first gets one
    /// `HEAD` request, made through the run's checked fetcher and its shared origin governor, and
    /// only candidates that answer 200 to 399 are queued.
    ///
    /// # Errors
    /// A fixture that is not what its kind says, a stop signal of the run, or a storage failure.
    pub(super) async fn seed_from_sources(&self) -> Result<(), WorkerError> {
        let Some(seeding) = &self.crawl.scope.seeding else {
            return Ok(());
        };
        let max = usize::try_from(seeding.max_urls).unwrap_or(usize::MAX);
        let set = crawlx_url::seed_sources::collect(&seeding.fixtures, &self.crawl.seed_url, max)
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        let cancel = self.hard_cancel.clone().unwrap_or_default();
        let mut tally = SeedTally::default();
        for candidate in &set.candidates {
            let Some((canonical, bearing)) = self.canonicalize(&candidate.url) else {
                tally.policy_blocked += 1;
                continue;
            };
            if seeding.live_check == crawlx_core::discovery::SeedLiveCheckV1::Head {
                match self.live_check_head(&canonical.url, &cancel).await {
                    LiveCheck::Alive => {}
                    LiveCheck::Dead => {
                        tally.live_dead += 1;
                        continue;
                    }
                    LiveCheck::Refused => {
                        tally.live_refused += 1;
                        continue;
                    }
                    LiveCheck::Failed => {
                        tally.live_failed += 1;
                        continue;
                    }
                }
            }
            let source = RequestSource {
                tag: "seed-source",
                attribute: candidate.source.as_str(),
                source: self.crawl.seed_url.to_string(),
            };
            match self.discover_listed(canonical, bearing, source).await? {
                DiscoveryOutcome::Admitted => tally.queued += 1,
                DiscoveryOutcome::Duplicate => tally.duplicate += 1,
                DiscoveryOutcome::RobotsBlocked => tally.robots_blocked += 1,
                _ => tally.policy_blocked += 1,
            }
        }
        self.event(
            "seed.sources",
            serde_json::json!({
                "fixtures": seeding.fixtures.len(),
                "candidates": set.candidates.len(),
                "duplicateSightings": set.duplicates,
                "rejectedEntries": set.rejected,
                "truncated": set.truncated,
                "liveCheck": seeding.live_check,
                "queued": tally.queued,
                "alreadyKnown": tally.duplicate,
                "policyBlocked": tally.policy_blocked,
                "robotsBlocked": tally.robots_blocked,
                "liveDead": tally.live_dead,
                "liveRefused": tally.live_refused,
                "liveFailed": tally.live_failed,
            }),
        )
        .await;
        Ok(())
    }

    /// One `HEAD` request to `url`, only after scope, robots and authorization admit it. It is
    /// charged to its own bounded budget, goes through the run's fetcher (egress checks, the
    /// shared origin governor) and follows no redirect: a redirect status is an answer, not a hop.
    async fn live_check_head(&self, url: &Url, cancel: &CancellationToken) -> LiveCheck {
        let authority = DiscoveryHopAdmission(self);
        let Ok(mut budget) =
            AcquisitionBudgetV1::new(&crawlx_core::acquisition::AcquisitionPolicyV1::default())
        else {
            return LiveCheck::Failed;
        };
        if crate::acquisition::HopAdmission::check_authority(&authority)
            .await
            .is_err()
        {
            return LiveCheck::Refused;
        }
        match self.admit_native_scope(url, 1, false).await {
            Ok(canonical) if canonical.url == *url => {}
            _ => return LiveCheck::Refused,
        }
        let mut options = crate::acquisition::fetch_options(&self.crawl.fetch);
        options.method = http::Method::HEAD;
        options.follow_redirects = false;
        options.max_body_bytes = Some(1024);
        match self
            .robots
            .decide_hop_with_budget(
                crawlx_policy::robots::HopKind::Page,
                url,
                &options,
                &mut budget,
                cancel,
                &authority,
            )
            .await
        {
            Ok(RobotsDecision::Allowed) => {}
            Ok(_) => return LiveCheck::Refused,
            Err(_) => return LiveCheck::Failed,
        }
        let fetched = Box::pin(crate::acquisition::fetch_budgeted_once(
            &self.fetcher,
            url,
            &options,
            &mut budget,
            cancel,
            &authority,
        ))
        .await;
        self.record_exchange_method("HEAD", url, &fetched);
        match fetched {
            Ok(response) if (200..400).contains(&response.status.as_u16()) => LiveCheck::Alive,
            Ok(_) => LiveCheck::Dead,
            Err(_) => LiveCheck::Failed,
        }
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
