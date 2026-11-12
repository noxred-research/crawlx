//! When the well-known files of the seed's origin (its sitemaps and the `robots.txt` paths) are
//! enqueued relative to the seed page's own links.
//!
//! Order of discovery: the seed, the links of the seed page, then the sitemap entries, then the
//! `robots.txt` paths. The links come first because the seed page is the crawl's own entry point
//! while a sitemap is a second, unordered source; under a `limits.urls` smaller than the site the
//! pages kept are therefore the seed's neighbours, the same ones on every run. Queue order is
//! `(priority, depth, row id)`, so enqueueing the files after the links is what orders them.
//!
//! The seed is processed through the normal lease loop. [`UrlPlaneRunner::seed`] only records that
//! the files are still to be discovered; [`UrlPlaneRunner::run`] discovers them as soon as the
//! seed row is settled (its links are admitted before it is finished), and writes the
//! `seed.known_files` event. A worker that finds a frontier without that event, because the
//! previous holder stopped in between, discovers them again; admission dedupes the rest.

use super::*;

/// Event recorded once the well-known files of the seed's origin were discovered.
const KNOWN_FILES_EVENT: &str = "seed.known_files";

/// The seed whose well-known files are still to be discovered, and its frontier row once found.
pub(super) struct DeferredKnownFiles {
    seed: CanonicalUrl,
    row: Option<i64>,
}

impl DeferredKnownFiles {
    pub(super) const fn new(seed: CanonicalUrl) -> Self {
        Self { seed, row: None }
    }
}

impl UrlPlaneRunner {
    /// Does this run discover sitemaps or `robots.txt` paths for its seed at all?
    pub(super) fn known_files_wanted(&self) -> bool {
        let known = &self.crawl.scope.known_files;
        !self.crawl.cache_only()
            && ((self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Sitemap)
                && self.crawl.scope.discovery.is_none()
                && self.crawl.scope.sitemap != SitemapMode::Skip
                && known.contains(&KnownFile::Sitemap))
                || known.contains(&KnownFile::RobotsPaths))
    }

    /// Remember that the files of `seed`'s origin are discovered once the seed row is settled.
    pub(super) fn defer_known_files(&self, seed: CanonicalUrl) {
        *self.deferred_known_files.lock() = Some(DeferredKnownFiles::new(seed));
    }

    /// Are the seed's well-known files still to be discovered?
    pub(super) fn known_files_deferred(&self) -> bool {
        self.deferred_known_files.lock().is_some()
    }

    /// Does the run's input end with its seeds (the finite producer mode)?
    pub(super) fn finite_input(&self) -> bool {
        self.crawl.orchestration.as_ref().is_none_or(|config| {
            config.queue.producer_mode == crawlx_core::orchestration::ProducerModeV1::Finite
        })
    }

    /// Discover the sitemap entries (depth 1) and then the `robots.txt` paths of `seed`'s
    /// origin, as the seed's own discovery always did.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub(super) async fn discover_known_files(&self, seed: &CanonicalUrl) -> Result<(), WorkerError> {
        let known = &self.crawl.scope.known_files;
        if self.source_enabled(crawlx_core::discovery::DiscoverySourceV1::Sitemap)
            && self.crawl.scope.discovery.is_none()
            && self.crawl.scope.sitemap != SitemapMode::Skip
            && known.contains(&KnownFile::Sitemap)
        {
            self.discover_sitemaps(seed).await?;
        }
        if known.contains(&KnownFile::RobotsPaths) {
            self.discover_robots_paths(seed).await?;
        }
        Ok(())
    }

    /// Discover the deferred files when the seed row is settled (finished or never leasable),
    /// so every link of the seed page already precedes them. Returns whether it did.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails, including the
    /// run deadline passing while the files are enqueued.
    pub(super) async fn discover_known_files_when_due(&self) -> Result<bool, WorkerError> {
        let Some((seed, known_row)) = self
            .deferred_known_files
            .lock()
            .as_ref()
            .map(|deferred| (deferred.seed.clone(), deferred.row))
        else {
            return Ok(false);
        };
        let row = match known_row {
            Some(id) => self
                .deps
                .frontier
                .page(self.run, id.saturating_sub(1), 1)
                .await?
                .into_iter()
                .next()
                .filter(|row| row.id == id),
            None => self.find_seed_row(&seed).await?,
        };
        if let Some(row) = &row {
            if let Some(deferred) = self.deferred_known_files.lock().as_mut() {
                deferred.row = Some(row.id);
            }
            if matches!(row.status, FrontierStatus::Pending | FrontierStatus::Leased) {
                return Ok(false);
            }
        }
        self.deferred_known_files.lock().take();
        self.discover_known_files(&seed).await?;
        self.event(KNOWN_FILES_EVENT, serde_json::json!({})).await;
        if self.finite_input() {
            // the producers were kept open for these entries (`seed_if_empty`)
            self.deps.frontier.seal(self.run, 1).await?;
        }
        self.persist_counters().await?;
        Ok(true)
    }

    /// The frontier row of the seed itself: depth 0, found on no page, the seed's canonical URL.
    async fn find_seed_row(&self, seed: &CanonicalUrl) -> Result<Option<FrontierEntry>, StoreError> {
        let mut after = 0;
        loop {
            let rows = self.deps.frontier.page(self.run, after, 1000).await?;
            let Some(last) = rows.last().map(|row| row.id) else {
                return Ok(None);
            };
            after = last;
            if let Some(row) = rows
                .into_iter()
                .find(|row| row.depth == 0 && row.discovered_from.is_none() && row.url.key == seed.key)
            {
                return Ok(Some(row));
            }
        }
    }

    /// A worker taking over a frontier whose previous holder stopped after the seed and before the
    /// files were discovered: defer them again. Nothing is deferred once the event exists.
    ///
    /// # Errors
    /// Fails when the run's events cannot be read.
    pub(super) async fn restore_known_files(&self, seed: &CanonicalUrl) -> Result<(), WorkerError> {
        if !self.known_files_wanted()
            || self.initial_request_method != http::Method::GET
            || self.prefetch.check(&seed.url).is_some()
            || self.deferred_known_files.lock().is_some()
        {
            return Ok(());
        }
        let mut after = 0;
        loop {
            let events = self
                .deps
                .events
                .list_metadata_after(self.run, after, 1000)
                .await?;
            let Some(last) = events.last().map(|event| event.seq) else {
                break;
            };
            if events.iter().any(|event| event.kind == KNOWN_FILES_EVENT) {
                return Ok(());
            }
            after = last;
        }
        self.defer_known_files(seed.clone());
        Ok(())
    }
}
