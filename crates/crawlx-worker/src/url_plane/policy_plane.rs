//! Outbound request policy of the URL plane: the `Referer` of a request found on a page
//! (`fetch.referrerPolicy`) and the stable refusal of an over-long link (`scope.maxUrlLength`).

use super::*;
use crawlx_core::config::ReferrerPolicy;
use crawlx_fetch::redirect::Referrer;

/// The `reason` of a link refused for its length: the denial code of `scope.maxUrlLength`.
const URL_TOO_LONG: &str = "url_too_long";

impl UrlPlaneRunner {
    /// [`Self::canonicalize`] for a URL the crawl just discovered. A URL longer than
    /// `scope.maxUrlLength` is counted as a discovery refused by policy with the reason
    /// `url_too_long` and never reaches the frontier; any other canonicalization failure drops the
    /// URL as before. The URL itself is not logged, only its length.
    pub(super) fn canonicalize_discovered(&self, url: &Url) -> Option<(CanonicalUrl, bool)> {
        match Canonicalizer::canonicalize_detailed(url.as_str(), url, &self.canon) {
            Ok(canonical) => Some((canonical.url, canonical.action_bearing)),
            Err(crawlx_url::UrlError::TooLong { len, max }) => {
                self.counters.discovery_with_reason(
                    Plane::Urls,
                    DiscoveryOutcome::PolicyBlocked,
                    URL_TOO_LONG,
                );
                tracing::debug!(run = %self.run, len, max, "discovered url refused: too long");
                None
            }
            Err(_) => None,
        }
    }

    /// The `Referer` policy of the request for `entry`: the page it was found on, redacted, under
    /// `fetch.referrerPolicy`. `None` without a policy, for a URL no page links to (the seed,
    /// sitemap and robots entries) and when the parent page is not known.
    ///
    /// The page is the URL the link was read from (after redirects) while this plane still
    /// remembers it, else the parent frontier row's URL.
    ///
    /// # Errors
    /// Fails when the frontier cannot be read.
    pub(super) async fn referrer_for(&self, entry: &FrontierEntry) -> Result<Option<Referrer>, WorkerError> {
        let policy = self.crawl.fetch.referrer_policy;
        let Some(parent) = entry
            .discovered_from
            .filter(|_| policy != ReferrerPolicy::NoReferrer)
        else {
            return Ok(None);
        };
        let remembered = self
            .sources
            .lock()
            .get(&entry.id)
            .and_then(|source| Url::parse(&source.source).ok());
        let page = match remembered {
            Some(page) => page,
            None => {
                let rows = self
                    .deps
                    .frontier
                    .page(self.run, parent.saturating_sub(1), 1)
                    .await?;
                match rows.into_iter().next().filter(|row| row.id == parent) {
                    Some(row) => row.url.url,
                    None => return Ok(None),
                }
            }
        };
        let controls = &self.fetcher.config().controls;
        Ok(Referrer::new(&page, policy, &|value| {
            controls.echoes_secret(value)
        }))
    }
}
