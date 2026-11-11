//! The page loop of compatibility-API scrape runs: the URL plane's queue, scope, robots and counters
//! drive the [`ScrapeEngine`], which produces the stored result of every leased frontier row.
//!
//! Compared with the plain static plane a scrape run
//!
//! * also seeds `ScrapeJob::urls` at depth 0 (batch scrape, tag `batch`);
//! * stores a page for every HTTP status; only the engine's failure reasons fail a row;
//! * never dedupes or filters pages by content: every requested URL gets its document;
//! * follows links only for the `crawl` kind (the `scrape` and `batch` kinds fetch exactly
//!   their URLs);
//! * scrapes a crawl's seed that only `includePaths` / `urlInclude` refuse, for its links alone:
//!   the row ends `policy_blocked` and no document is stored;
//! * runs under the configuration [`adapt`] derives: no default extension filter, no
//!   URL-shape similarity filter for `scrape` and `batch` jobs (a caller who names a `.pdf` or
//!   a third page of the same shape wants it; a crawl keeps the filter its request asked for
//!   with `deduplicateSimilarURLs`), no `robots.txt` gate for `scrape` and `batch` jobs
//!   (the compatibility API scrapes the URLs it is given) and no seed-path restriction for `batch` jobs.

use super::{Future, NativeHopAdmission, RequestPublication, RequestSource, UrlPlaneRunner};
use crate::counters::{Attempt, Plane};
use crate::error::WorkerError;
use crate::run::RunContext;
use crate::scrape::{BrowserRenderer, FailReason, Outcome, ScrapeEngine, Scraped};
use crate::WorkerConfig;
use crawlx_core::config::SitemapMode;
use crawlx_core::repo::{FrontierEntry, FrontierStatus};
use crawlx_core::scrape::JobKind;
use crawlx_core::CreateCrawl;
use crawlx_policy::{DenialReason, ScopeVerdict};
use std::sync::Arc;

/// The configuration the URL plane of a run executes with: `crawl` unchanged for plain and
/// `map` runs; for the engine's kinds the filters that would silently drop a requested URL are
/// off (see the [module documentation](self)); a batch's URLs are not held to the seed's path.
pub(super) fn adapt(mut crawl: CreateCrawl) -> CreateCrawl {
    let Some(kind) = crawl
        .scrape
        .as_ref()
        .map(|job| job.kind)
        .filter(|kind| *kind != JobKind::Map)
    else {
        return crawl;
    };
    crawl.scope.no_default_extension_filter = true;
    if kind != JobKind::Crawl {
        // `scrape` and `batch` fetch exactly the URLs they were given; only a crawl follows
        // links, so only a crawl honours `deduplicateSimilarURLs` (`scope.filterSimilar`)
        crawl.scope.filter_similar = false;
    }
    if kind != JobKind::Crawl {
        crawl.safety.respect_robots_txt = false;
    }
    if kind == JobKind::Batch {
        crawl.scope.crawl_entire_domain = true;
    }
    crawl
}

impl UrlPlaneRunner {
    /// Give the scrape engine of the run its services: the worker's LLM (`WorkerConfig::llm`)
    /// and the page renderer for options that need a browser (`WorkerConfig::renderer`, or the
    /// production [`BrowserRenderer`] over `rc`). A run without a scrape job is unchanged.
    #[must_use]
    pub fn with_scrape_services(mut self, rc: &Arc<RunContext>, cfg: &WorkerConfig) -> Self {
        self.extract
            .language_detector
            .clone_from(&cfg.article_language_detector);
        if let Some(mut engine) = self.scrape.take() {
            engine = engine.with_article_language(cfg.article_language_detector.clone());
            if let Some(llm) = &cfg.llm {
                engine = engine.with_llm(Arc::clone(llm));
            }
            if let Some(router) = &cfg.extraction_llm {
                engine = engine.with_extraction_router(Arc::clone(router));
            }
            if let Some(llm) = &cfg.branding_llm {
                engine = engine.with_branding_llm(Arc::clone(llm));
            }
            if let Some(ocr) = &cfg.ocr {
                engine = engine.with_ocr(Arc::clone(ocr));
            }
            engine = engine.with_media_limit(cfg.media_max_bytes);
            engine = engine.with_protocol_services(rc);
            if let Some(renderer) = &cfg.renderer {
                engine = engine.with_renderer(Arc::clone(renderer));
            } else if engine.needs_browser() {
                engine = engine.with_renderer(Arc::new(BrowserRenderer::new(Arc::clone(rc))));
            }
            self.scrape = Some(engine);
        }
        if let Some(engine) = self.protocol_browser.take() {
            let mut engine = engine.with_protocol_services(rc);
            engine = engine.with_article_language(cfg.article_language_detector.clone());
            engine = engine.with_renderer(cfg.renderer.as_ref().map_or_else(
                || Arc::new(BrowserRenderer::new(Arc::clone(rc))) as Arc<dyn crate::scrape::PageRenderer>,
                Arc::clone,
            ));
            self.protocol_browser = Some(engine);
        }
        self
    }

    /// Discover `ScrapeJob::urls` at depth 0 next to the seed.
    pub(super) async fn seed_batch_urls(&self) -> Result<(), WorkerError> {
        let Some(job) = &self.crawl.scrape else {
            return Ok(());
        };
        for url in &job.urls {
            let Some((canon, bearing)) = self.canonicalize(url) else {
                continue;
            };
            let source = RequestSource {
                tag: "batch",
                attribute: "urls",
                source: self.crawl.seed_url.to_string(),
            };
            self.discover(canon, 0, None, bearing, Some(source)).await?;
        }
        Ok(())
    }

    /// Produce, store and complete one frontier row through `engine`. `discovery` is the include
    /// denial of the crawl's entry URL when it is fetched to start discovery only: its row ends
    /// `policy_blocked`, no page is stored, and its links are followed.
    pub(super) fn process_scrape_entry<'a>(
        &'a self,
        engine: &'a ScrapeEngine,
        entry: &'a FrontierEntry,
        discovery: Option<&'a DenialReason>,
        cancel: &'a tokio_util::sync::CancellationToken,
        legacy_reserved_effects: Option<u32>,
    ) -> impl Future<Output = Result<(), WorkerError>> + Send + 'a {
        Box::pin(self.process_scrape_entry_inner(engine, entry, discovery, cancel, legacy_reserved_effects))
    }

    async fn process_scrape_entry_inner(
        &self,
        engine: &ScrapeEngine,
        entry: &FrontierEntry,
        discovery: Option<&DenialReason>,
        cancel: &tokio_util::sync::CancellationToken,
        legacy_reserved_effects: Option<u32>,
    ) -> Result<(), WorkerError> {
        let observe =
            |url: &url::Url, fetched: &Result<crawlx_fetch::FetchResponse, crawlx_fetch::FetchError>| {
                self.record_exchange(url, fetched);
            };
        let fence = *self
            .held
            .lock()
            .get(&entry.id)
            .ok_or(crawlx_core::StoreError::LeaseLost)?;
        let native_escrow = self.crawl.acquisition.is_some();
        let budget = if native_escrow {
            let allowance = match self
                .deps
                .frontier
                .reserve_acquisition_fenced(self.run, entry.id, fence)
                .await
            {
                Ok(allowance) => allowance,
                Err(crawlx_core::StoreError::Conflict(_)) => {
                    return self
                        .fail(
                            entry,
                            "acquisition_allowance",
                            "acquisition_allowance",
                            Attempt::Failed,
                            serde_json::json!({"reason":"durable acquisition allowance exhausted"}),
                        )
                        .await
                }
                Err(error) => return Err(error.into()),
            };
            match engine.budget_from_allowance(&allowance) {
                Ok(budget) => Some(budget),
                Err(failure) => {
                    return self
                        .fail(
                            entry,
                            failure.reason.code(),
                            failure.reason.code(),
                            Attempt::Failed,
                            serde_json::json!({"reason":failure.message}),
                        )
                        .await
                }
            }
        } else {
            None
        };
        let outcome = engine
            .scrape_with_budget(
                entry,
                &self.cpu_pool,
                &observe,
                cancel,
                budget,
                Some(&NativeHopAdmission::new(self, entry)?),
            )
            .await?;
        if native_escrow {
            let usage = match &outcome {
                Outcome::Failed(failure) => failure
                    .acquisition
                    .as_deref()
                    .map(|metadata| Ok(metadata.allowance_usage.clone())),
                Outcome::Page(page) => Some(
                    serde_json::from_value::<crawlx_core::acquisition::AcquisitionUsageV1>(
                        page.record.metadata["acquisition"]["allowanceUsage"].clone(),
                    )
                    .map_err(|error| WorkerError::Config(format!("acquisition usage metadata: {error}"))),
                ),
            }
            .transpose()?;
            if let Some(usage) = usage {
                self.deps
                    .frontier
                    .settle_acquisition_fenced(self.run, entry.id, fence, &usage)
                    .await?;
            }
        }
        match outcome {
            Outcome::Failed(failure)
                if failure.reason == FailReason::RateLimited
                    && self.fetcher.governor().defers_source_throttle() =>
            {
                if let (Some(reserved), Some(metadata)) =
                    (legacy_reserved_effects, failure.acquisition.as_deref())
                {
                    // A completed HTTP fetch reports every send. Browser redirects
                    // and a legacy multi-backend result are not subrequest counters.
                    let single_http = !engine.needs_browser()
                        && metadata.backend.backend_id == "native_http"
                        && self
                            .crawl
                            .scrape
                            .as_ref()
                            .is_none_or(|job| job.options.proxy != crawlx_core::scrape::ProxyMode::Auto);
                    if single_http && metadata.network_requests > 0 {
                        self.deps
                            .frontier
                            .settle_effects_fenced(
                                self.run,
                                entry.id,
                                fence,
                                reserved,
                                metadata.network_requests,
                            )
                            .await?;
                    }
                }
                let final_url = failure
                    .acquisition
                    .as_deref()
                    .and_then(|metadata| metadata.final_url.as_ref())
                    .unwrap_or(&entry.url.url);
                self.defer_rate_limited(entry, final_url).await
            }
            Outcome::Failed(failure) if failure.reason == FailReason::AuthorizationScope => {
                // a redirect hop left the authorization record's target: blocked, never fetched
                self.block_by_authorization_scope(entry).await
            }
            Outcome::Failed(failure) if failure.reason.is_cancelled() => {
                self.finish(
                    entry,
                    FrontierStatus::Abandoned,
                    Some(failure.reason.code().to_owned()),
                )
                .await?;
                self.counters
                    .attempt_with_reason(Plane::Urls, Attempt::Abandoned, failure.reason.code());
                Ok(())
            }
            Outcome::Failed(failure) => {
                let code = failure.reason.code();
                let attempt = if failure.reason.is_unreachable() {
                    Attempt::Unreachable
                } else {
                    Attempt::Failed
                };
                let mut payload = serde_json::json!({
                    "url": entry.url.url.as_str(), "reason": code, "message": failure.message,
                });
                if let Some(evidence) = failure
                    .acquisition
                    .as_deref()
                    .and_then(|metadata| metadata.meta_refresh.as_ref())
                {
                    payload["metaRefresh"] = serde_json::to_value(evidence)
                        .map_err(|error| WorkerError::Other(error.to_string()))?;
                }
                self.fail(entry, code, code, attempt, payload).await
            }
            Outcome::Page(page) => {
                let Scraped {
                    mut record,
                    links,
                    final_url,
                    mut accepted,
                    mut outbox,
                    content_dedupe,
                    local_dedupe,
                } = *page;
                if let Some(reason) = discovery {
                    if engine.kind() == JobKind::Crawl && self.crawl.scope.sitemap != SitemapMode::Only {
                        self.expand_endpoints(entry, &final_url, &links, Vec::new())
                            .await?;
                    }
                    self.finish_discovery_only(entry, reason).await?;
                    return Ok(());
                }
                if let Some(src) = self.sources.lock().remove(&entry.id) {
                    record.metadata["request"] = serde_json::json!({
                        "tag": src.tag, "attribute": src.attribute, "source": src.source,
                    });
                }
                let (extension_accepted, extension_outbox) = if self.crawl.extensions.configured()
                    && record
                        .metadata
                        .get("acquisition")
                        .and_then(|value| value.get("validation"))
                        .and_then(|value| value.get("contentAccepted"))
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                {
                    let item = record
                        .metadata
                        .get(crawlx_core::scrape::ScrapeDocument::METADATA_KEY)
                        .and_then(|v| v.get("meta"))
                        .and_then(|v| v.get("extensionItem"));
                    if let Some(item) = item {
                        let run = self.deps.runs.get(self.run).await?;
                        let (content, accepted, outbox) = crate::extensions::store_candidate(
                            self.deps.artifacts.as_ref(),
                            &self.cpu_pool,
                            &run,
                            entry.id,
                            item,
                            "native_article_v1.unicode_rules_v1",
                            &self.fetcher.config().controls,
                            self.captcha_secrets.as_ref().ok_or_else(|| {
                                crawlx_core::StoreError::RetentionDenied(
                                    "item dynamic-secret registry unavailable".into(),
                                )
                            })?,
                        )
                        .await?;
                        record.metadata["itemPipeline"] = serde_json::json!({"accepted":1,"rejected":0});
                        record.metadata["extensions"] = serde_json::json!({"version":1,"content":content,
                            "pipeline":self.crawl.extensions.publication().map_err(|e| WorkerError::Config(e.to_string()))?});
                        (accepted.into_iter().collect(), outbox)
                    } else if self.crawl.extensions.requires_document()
                        && record
                            .metadata
                            .get(crawlx_core::scrape::ScrapeDocument::METADATA_KEY)
                            .and_then(|v| v.get("meta"))
                            .and_then(|v| v.get("extensionOutcome"))
                            .and_then(serde_json::Value::as_str)
                            != Some("rejected")
                    {
                        return self
                            .fail(
                                entry,
                                "extension_item_unavailable",
                                "extension_item_unavailable",
                                Attempt::Failed,
                                serde_json::json!({"reason":"extension_item_unavailable"}),
                            )
                            .await;
                    } else {
                        if record
                            .metadata
                            .get(crawlx_core::scrape::ScrapeDocument::METADATA_KEY)
                            .and_then(|value| value.get("meta"))
                            .and_then(|value| value.get("extensionOutcome"))
                            .and_then(serde_json::Value::as_str)
                            == Some("rejected")
                        {
                            record.metadata["itemPipeline"] = serde_json::json!({
                                "accepted":0,"rejected":1,"reason":"extension_item_rejected"
                            });
                        }
                        (Vec::new(), Vec::new())
                    }
                } else {
                    (Vec::new(), Vec::new())
                };
                accepted.extend(extension_accepted);
                outbox.extend(extension_outbox);
                let leaf_only = matches!(
                    self.scope.decide(&entry.url, entry.depth),
                    ScopeVerdict::Admitted { leaf_only: true }
                );
                if engine.kind() == JobKind::Crawl
                    && !leaf_only
                    && self.crawl.scope.sitemap != SitemapMode::Only
                {
                    self.expand_endpoints(entry, &final_url, &links, Vec::new())
                        .await?;
                }
                let event = serde_json::json!({
                    "pageId": entry.id,
                    "url": entry.url.url.as_str(),
                    "status": record.status,
                    "title": record.title,
                });
                self.finish_with_results(
                    entry,
                    FrontierStatus::Succeeded,
                    None,
                    accepted,
                    Vec::new(),
                    RequestPublication {
                        outbox,
                        page: Some(record),
                        content_dedupe,
                        local_dedupe,
                        ..RequestPublication::default()
                    },
                )
                .await?;
                *self.pages_written.lock() += 1;
                self.counters.attempt(Plane::Urls, Attempt::Succeeded);
                self.event("page", event).await;
                Ok(())
            }
        }
    }
}
