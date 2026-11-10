//! `robots.txt` obedience shared by the planes of one run.
//!
//! The URL plane asks [`RobotsGate::decide`] before it fetches a frontier URL; the browser
//! plane asks it, through [`NavigationGuard`], before a context loads a document. Both go
//! through the same two-round logic (unknown origin, fetch `/robots.txt`, evaluate again), the
//! same user-agent and alias configuration and the same `robots_unavailable` handling, and a
//! run's planes share one cache, so a hybrid run fetches each origin's `robots.txt` once.
//!
//! `respectRobotsTxt: false` makes the gate allow everything. That setting is admitted only
//! with an authorization record whose `robotsOverrideAcknowledged` is set; the gate backs the
//! admission up with [`RobotsGate::check_override`], which refuses to run a browser plane that
//! ignores `robots.txt` without a referenced record.

use crate::error::WorkerError;
use async_trait::async_trait;
use crawlx_core::browser::{NavigationGuard, NavigationVerdict};
use crawlx_core::{Clock, CreateCrawl};
use crawlx_fetch::{FetchError, FetchOptions, Fetcher};
use crawlx_policy::robots::{DisallowedBy, FetchStatus, RobotsCache, RobotsConfig, RobotsVerdict};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// The robots.txt product token Firecrawl's crawler answers to (lowercase).
const FIRECRAWL_ROBOTS_TOKEN: &str = "firecrawlagent";
/// The product token of crawlx itself (lowercase).
const OWN_ROBOTS_TOKEN: &str = "crawlx";

/// Whether to fetch a URL, or the robots/egress policy that refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RobotsDecision {
    Allowed,
    Blocked(&'static str),
    EgressDenied,
}

/// State the planes of a run share.
struct Shared {
    cache: Mutex<RobotsCache>,
    /// Raw `robots.txt` bodies by origin, for known-files seeding.
    bodies: Mutex<BTreeMap<String, Vec<u8>>>,
    /// One fetch of an origin's `robots.txt` at a time: concurrent decisions for an origin the
    /// cache does not know yet wait for the first one's answer instead of fetching again.
    fetching: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// The run honours `robots.txt`.
    obey: bool,
}

/// `robots.txt` evaluation for one run: a cache shared by every plane and the fetcher that
/// reads the files. Cloning is cheap; the clones share the cache.
#[derive(Clone)]
pub struct RobotsGate {
    shared: Arc<Shared>,
    fetcher: Arc<Fetcher>,
}

impl fmt::Debug for RobotsGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RobotsGate")
            .field("obey", &self.shared.obey)
            .finish_non_exhaustive()
    }
}

impl RobotsGate {
    /// The gate of the run `crawl` describes, reading `robots.txt` through `fetcher`.
    ///
    /// `crawl` is the configuration the URL plane executes with
    /// ([`crate::url_plane::effective_crawl`]): its `safety.respectRobotsTxt` already says
    /// whether the run honours the file. Firecrawl's crawler answers to `FirecrawlAgent`: a
    /// facade run (one with a scrape job) that does not name its own robots user agent honours
    /// the groups of both tokens; one that names `FirecrawlAgent` itself keeps honouring
    /// `crawlx` groups too.
    #[must_use]
    pub(crate) fn for_crawl(crawl: &CreateCrawl, fetcher: Arc<Fetcher>, clock: Arc<dyn Clock>) -> Self {
        let aliases = if crawl.scrape.is_some() {
            match (&crawl.fetch.robots_user_agent, &crawl.fetch.user_agent) {
                (None, None) => vec![FIRECRAWL_ROBOTS_TOKEN.to_owned()],
                (Some(ua), _) if crawlx_policy::robots::product_token(ua) == FIRECRAWL_ROBOTS_TOKEN => {
                    vec![OWN_ROBOTS_TOKEN.to_owned()]
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let cache = RobotsCache::with_config(
            clock,
            RobotsConfig {
                user_agent: fetcher.config().robots_user_agent(),
                aliases,
                ..RobotsConfig::default()
            },
        );
        Self {
            shared: Arc::new(Shared {
                cache: Mutex::new(cache),
                bodies: Mutex::new(BTreeMap::new()),
                fetching: Mutex::new(BTreeMap::new()),
                obey: crawl.safety.respect_robots_txt,
            }),
            fetcher,
        }
    }

    /// The same gate reading `robots.txt` through `fetcher`: the cache, and so every answer
    /// already fetched, stays shared. The URL plane keeps its own fetcher (its governor and
    /// its traffic capture) while the browser plane reads through another.
    #[must_use]
    pub(crate) fn with_fetcher(&self, fetcher: Arc<Fetcher>) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            fetcher,
        }
    }

    /// Whether the run honours `robots.txt`; a gate that does not allows everything.
    #[must_use]
    pub fn obeys(&self) -> bool {
        self.shared.obey
    }

    /// A run that ignores `robots.txt` in a browser needs the authorization record that
    /// admission demands for `respectRobotsTxt: false` (`robotsOverrideAcknowledged`).
    /// Admission has already checked the record's content; this refuses a run that reaches
    /// the browser plane with the override and no record at all, whatever path built it.
    ///
    /// # Errors
    /// [`WorkerError::Config`] when `crawl` ignores `robots.txt` without
    /// `safety.authorizationRecordRef`.
    pub fn check_override(crawl: &CreateCrawl) -> Result<(), WorkerError> {
        if !crawl.safety.respect_robots_txt && crawl.safety.authorization_record_ref.is_none() {
            return Err(WorkerError::Config(
                "safety.respectRobotsTxt = false needs safety.authorizationRecordRef \
                 (an authorization record with robotsOverrideAcknowledged)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Load uncached continuation robots using the exact parent acquisition allowance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn decide_with_budget(
        &self,
        origin: &str,
        url: &Url,
        options: &FetchOptions,
        budget: &mut crate::acquisition::AcquisitionBudgetV1,
        cancel: &tokio_util::sync::CancellationToken,
        admission: &dyn crate::acquisition::HopAdmission,
    ) -> Result<RobotsDecision, FetchError> {
        if !self.shared.obey {
            return Ok(RobotsDecision::Allowed);
        }
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        for round in 0..2 {
            let verdict = self.evaluate_and_pace(origin, url, &path);
            match verdict {
                RobotsVerdict::Allowed => return Ok(RobotsDecision::Allowed),
                RobotsVerdict::Disallowed(DisallowedBy::Rule(_)) => {
                    return Ok(RobotsDecision::Blocked("robots_disallow"))
                }
                RobotsVerdict::Disallowed(DisallowedBy::Unreachable { .. }) => {
                    return Ok(RobotsDecision::Blocked("robots_unavailable"))
                }
                RobotsVerdict::Unknown if round == 0 => {
                    let turn = {
                        let mut fetching = self.shared.fetching.lock();
                        Arc::clone(fetching.entry(origin.to_owned()).or_default())
                    };
                    let remaining = budget.preflight(cancel)?;
                    let _turn = tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Err(FetchError::AcquisitionCancelled),
                        result = tokio::time::timeout(remaining, turn.lock()) =>
                            result.map_err(|_| FetchError::AcquisitionDeadline)?,
                    };
                    if !matches!(
                        self.shared.cache.lock().evaluate(origin, "/"),
                        RobotsVerdict::Unknown
                    ) {
                        continue;
                    }
                    let response = match self
                        .fetch_with_budget(url, options, budget, cancel, admission)
                        .await
                    {
                        Ok(response) => response,
                        Err(FetchError::EgressDenied(_)) => return Ok(RobotsDecision::EgressDenied),
                        // Budget, cancellation and transport failures are not robots-site outage facts.
                        Err(error) => return Err(error),
                    };
                    let status = if response.status.is_success() {
                        self.shared
                            .bodies
                            .lock()
                            .insert(origin.to_owned(), response.body.to_vec());
                        FetchStatus::Ok(response.body.to_vec())
                    } else if response.status.is_client_error() {
                        FetchStatus::Status4xx
                    } else {
                        FetchStatus::Status5xx
                    };
                    self.record_and_pace(origin, status, url);
                }
                RobotsVerdict::Unknown => return Ok(RobotsDecision::Blocked("robots_unavailable")),
            }
        }
        Ok(RobotsDecision::Blocked("robots_unavailable"))
    }

    async fn fetch_with_budget(
        &self,
        destination: &Url,
        original_options: &FetchOptions,
        budget: &mut crate::acquisition::AcquisitionBudgetV1,
        cancel: &tokio_util::sync::CancellationToken,
        admission: &dyn crate::acquisition::HopAdmission,
    ) -> Result<crawlx_fetch::FetchResponse, FetchError> {
        let mut current = destination
            .join("/robots.txt")
            .map_err(|_| FetchError::AcquisitionUnavailable)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut options = original_options.clone();
        options.follow_redirects = false;
        options.validators = None;
        options.suppress_validators = true;
        let max_hops = self.fetcher.config().max_redirects.min(20);
        for _ in 0..=max_hops {
            if !seen.insert(current.as_str().to_owned()) {
                return Err(FetchError::TooManyRedirects { limit: max_hops });
            }
            let response = crate::acquisition::fetch_budgeted_once(
                &self.fetcher,
                &current,
                &options,
                budget,
                cancel,
                admission,
            )
            .await?;
            if response.truncated {
                return Err(FetchError::AcquisitionAllowance);
            }
            if !crawlx_fetch::redirect::is_redirect(response.status.as_u16())
                || !self.fetcher.config().follow_redirects
            {
                return Ok(response);
            }
            let mut next = crawlx_fetch::redirect::location(&response.final_url, &response.headers)?;
            next.set_fragment(None);
            if current.origin() != next.origin() {
                options.suppress_credentials = true;
                crawlx_fetch::redirect::strip_credentials(&mut options.headers);
            }
            current = next;
        }
        Err(FetchError::TooManyRedirects { limit: max_hops })
    }

    /// May `url`, on `origin`, be fetched? An origin the cache does not know yet has its
    /// `robots.txt` fetched first and the verdict re-evaluated; a second unknown answer, an
    /// unreachable file and a 5xx all block the URL as `robots_unavailable`. An egress refusal
    /// stays distinct: it is not evidence that the site's robots service is unavailable.
    /// An allowed URL's origin is paced by its capped `Crawl-delay` from then on.
    pub(crate) async fn decide(&self, origin: &str, url: &Url) -> RobotsDecision {
        if !self.shared.obey {
            return RobotsDecision::Allowed;
        }
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_owned(),
        };
        for round in 0..2 {
            let verdict = self.evaluate_and_pace(origin, url, &path);
            match verdict {
                RobotsVerdict::Allowed => return RobotsDecision::Allowed,
                RobotsVerdict::Disallowed(DisallowedBy::Rule(_)) => {
                    return RobotsDecision::Blocked("robots_disallow")
                }
                RobotsVerdict::Disallowed(DisallowedBy::Unreachable { .. }) => {
                    return RobotsDecision::Blocked("robots_unavailable")
                }
                RobotsVerdict::Unknown if round == 0 => {
                    if self.fetch_once(origin, url).await {
                        return RobotsDecision::EgressDenied;
                    }
                }
                RobotsVerdict::Unknown => return RobotsDecision::Blocked("robots_unavailable"),
            }
        }
        RobotsDecision::Blocked("robots_unavailable")
    }

    /// The cached verdict for `path` on `origin`; an allowed verdict paces the governor origin
    /// of `url` by the capped `Crawl-delay` of the same cache entry. Verdict and delay are
    /// read under one cache guard, so a refetch in between cannot pair a verdict with another
    /// entry's delay. The guard is never held across an `.await`.
    fn evaluate_and_pace(&self, origin: &str, url: &Url, path: &str) -> RobotsVerdict {
        let cache = self.shared.cache.lock();
        let verdict = cache.evaluate(origin, path);
        if matches!(verdict, RobotsVerdict::Allowed) {
            if let Some(delay) = cache.crawl_delay(origin) {
                self.pace(url, delay);
            }
        }
        verdict
    }

    /// Make the fetcher's governor space `url`'s origin by `delay`, a capped `Crawl-delay`.
    /// The governor itself ignores a value it already holds, so every gate over it, the
    /// browser guard and the URL plane's included, can call this on each allowed URL.
    /// A missing hint is never passed here: it does not lower a floor an earlier hint set.
    /// The run governor is shared by the HTTP and browser planes, so both honour it. Only the
    /// origin of `url` is paced, so a gate-bypassing fetch (sitemap, known-file discovery) is
    /// paced only when it targets the origin whose `robots.txt` was recorded. Callers hold the
    /// cache guard (lock order cache, governor; the governor never calls back into the
    /// robots cache) and never across an `.await`.
    fn pace(&self, url: &Url, delay: Duration) {
        self.fetcher
            .governor()
            .set_crawl_delay(&crawlx_fetch::Origin::from_url(url), delay);
    }

    /// Record the `robots.txt` answer `status` for `origin` and, when the run obeys the file
    /// and the cached entry carries a `Crawl-delay`, pace the governor origin of `url` by it,
    /// so fetches that bypass the gate are spaced too. `url` is the URL whose origin the cache
    /// entry is keyed by, never a redirect target; gate-bypassing fetches of any other origin
    /// are not paced by this answer. An answer without a hint (4xx, 5xx, unreachable, a file
    /// without `Crawl-delay`) leaves the floor as it was.
    fn record_and_pace(&self, origin: &str, status: FetchStatus, url: &Url) {
        let mut cache = self.shared.cache.lock();
        cache.record_fetch(origin, status);
        if self.shared.obey {
            if let Some(delay) = cache.crawl_delay(origin) {
                self.pace(url, delay);
            }
        }
    }

    /// Fetch the `robots.txt` of `origin` unless another task did while this one waited.
    /// Return whether the egress policy denied the lookup.
    async fn fetch_once(&self, origin: &str, any_url: &Url) -> bool {
        let turn = {
            let mut fetching = self.shared.fetching.lock();
            Arc::clone(fetching.entry(origin.to_owned()).or_default())
        };
        let _turn = turn.lock().await;
        let known = !matches!(
            self.shared.cache.lock().evaluate(origin, "/"),
            RobotsVerdict::Unknown
        );
        if known {
            return false;
        }
        self.fetch(origin, any_url).await
    }

    /// Fetch `/robots.txt` of `origin` (`any_url` names a URL on it) and record the answer.
    /// Return whether egress denied the lookup; do not cache policy denials as site outages.
    pub(crate) async fn fetch(&self, origin: &str, any_url: &Url) -> bool {
        let Ok(robots_url) = any_url.join("/robots.txt") else {
            self.shared
                .cache
                .lock()
                .record_fetch(origin, FetchStatus::Unreachable);
            return false;
        };
        let status = match self.fetcher.fetch(&robots_url, &FetchOptions::default()).await {
            Ok(resp) if resp.status.is_success() => FetchStatus::Ok(resp.body.to_vec()),
            Ok(resp) if resp.status.is_client_error() => FetchStatus::Status4xx,
            Ok(_) => FetchStatus::Status5xx,
            Err(FetchError::TooManyRedirects { .. }) => FetchStatus::TooManyRedirects,
            Err(FetchError::EgressDenied(_)) => return true,
            Err(_) => FetchStatus::Unreachable,
        };
        if let FetchStatus::Ok(body) = &status {
            self.shared.bodies.lock().insert(origin.to_owned(), body.clone());
        }
        self.record_and_pace(origin, status, any_url);
        false
    }

    /// The raw `robots.txt` fetched from `origin`, if the fetch succeeded.
    pub(crate) fn body(&self, origin: &str) -> Option<Vec<u8>> {
        self.shared.bodies.lock().get(origin).cloned()
    }

    /// The `Sitemap:` lines of `origin`'s cached `robots.txt`.
    pub(crate) fn sitemaps(&self, origin: &str) -> Vec<String> {
        self.shared.cache.lock().sitemaps(origin).to_vec()
    }
}

#[async_trait]
impl NavigationGuard for RobotsGate {
    async fn check(&self, url: &Url) -> NavigationVerdict {
        match self.decide(&crawlx_url::origin_of(url), url).await {
            RobotsDecision::Allowed => NavigationVerdict::Allow,
            RobotsDecision::Blocked(reason) => NavigationVerdict::RobotsBlocked { reason },
            RobotsDecision::EgressDenied => NavigationVerdict::EgressDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::{EgressConfig, WorkerConfig};
    use crawlx_core::request_controls::RequestControls;
    use crawlx_core::SystemClock;
    use crawlx_fetch::StaticResolver;

    /// A gate with one denied loopback host and no DNS answer for the robots.invalid origin.
    fn gate(mutate: impl FnOnce(&mut CreateCrawl)) -> RobotsGate {
        let mut crawl = CreateCrawl::new(Url::parse("http://robots.invalid/").unwrap());
        mutate(&mut crawl);
        let cfg = WorkerConfig {
            egress: EgressConfig {
                resolver: Some(Arc::new(
                    StaticResolver::new().with("denied.invalid", [std::net::IpAddr::from([127, 0, 0, 1])]),
                )),
                ..EgressConfig::default()
            },
            ..WorkerConfig::default()
        };
        let (fetcher, _) = crate::run::build_fetcher(
            &crawl,
            crawlx_core::CrawlRunId(uuid::Uuid::nil()),
            crawl.effective_seed(),
            &cfg,
            RequestControls::default(),
            None,
            Arc::new(crawlx_fetch::OriginGovernor::with_global_cap(
                crawlx_fetch::GovernorConfig::from_politeness(&crawl.politeness, crawl.effective_seed()),
                Arc::clone(&cfg.origin_cap),
            )),
        )
        .unwrap();
        RobotsGate::for_crawl(&crawl, fetcher, Arc::new(SystemClock))
    }

    fn url(path: &str) -> Url {
        Url::parse(&format!("http://robots.invalid{path}")).unwrap()
    }

    #[tokio::test]
    async fn a_gate_for_a_run_that_ignores_robots_allows_everything_and_reads_nothing() {
        let gate = gate(|c| c.safety.respect_robots_txt = false);
        assert!(!gate.obeys());
        assert_eq!(gate.check(&url("/private/x")).await, NavigationVerdict::Allow);
        assert_eq!(gate.body("http://robots.invalid"), None, "nothing was fetched");
    }

    #[tokio::test]
    async fn an_unreadable_robots_txt_blocks_every_url_as_unavailable_like_the_url_plane() {
        let gate = gate(|_| {});
        assert!(gate.obeys());
        let blocked = NavigationVerdict::RobotsBlocked {
            reason: "robots_unavailable",
        };
        assert_eq!(gate.check(&url("/a")).await, blocked);
        // the cached outage answers the next URL without another fetch
        assert_eq!(gate.check(&url("/b")).await, blocked);
        // the URL plane asks the same gate and gets the same code
        assert_eq!(
            gate.decide("http://robots.invalid", &url("/c")).await,
            RobotsDecision::Blocked("robots_unavailable")
        );
    }

    #[tokio::test]
    async fn egress_denial_stays_typed_and_never_dispatches_a_robots_request() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = Url::parse(&format!(
            "http://denied.invalid:{}/private?token=secret",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let gate = gate(|_| {});
        for _ in 0..2 {
            let verdict = gate.check(&target).await;
            assert_eq!(verdict, NavigationVerdict::EgressDenied);
            let error =
                crawlx_core::BlockedNavigation::new(target.as_str(), verdict.refusal().unwrap()).into_error();
            assert!(matches!(error, crawlx_core::BrowserError::EgressDenied(_)));
            assert!(!error.to_string().contains("secret"));
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        }
        assert_eq!(gate.body(&crawlx_url::origin_of(&target)), None);
        assert!(matches!(
            gate.shared
                .cache
                .lock()
                .evaluate(&crawlx_url::origin_of(&target), "/"),
            RobotsVerdict::Unknown
        ));
    }

    #[tokio::test]
    async fn clones_share_the_cache_and_a_new_fetcher_keeps_it() {
        let first = gate(|_| {});
        let second = first.clone();
        assert_eq!(
            first.decide("http://robots.invalid", &url("/a")).await,
            RobotsDecision::Blocked("robots_unavailable")
        );
        // learned by `first`, visible to `second` without a lookup of its own
        assert!(matches!(
            second.shared.cache.lock().evaluate("http://robots.invalid", "/a"),
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { .. })
        ));
        assert!(Arc::ptr_eq(
            &first.shared,
            &second.with_fetcher(Arc::clone(&first.fetcher)).shared
        ));
    }

    /// `gate` with `robots` already cached for `http://robots.invalid`.
    fn gate_with_robots(mutate: impl FnOnce(&mut CreateCrawl), robots: &str) -> RobotsGate {
        let gate = gate(mutate);
        gate.shared.cache.lock().record_fetch(
            "http://robots.invalid",
            FetchStatus::Ok(robots.as_bytes().to_vec()),
        );
        gate
    }

    fn paced(gate: &RobotsGate) -> Duration {
        paced_at(gate, &url("/"))
    }

    /// The spacing `gate`'s governor holds for the origin of `at`.
    fn paced_at(gate: &RobotsGate, at: &Url) -> Duration {
        gate.fetcher
            .governor()
            .current_delay(&crawlx_fetch::Origin::from_url(at))
    }

    /// Admission of a continuation that owns no extra hop: a `robots.txt` answered in one hop
    /// only ever asks it for authority.
    struct NoHop;

    #[async_trait::async_trait]
    impl crate::acquisition::HopAdmission for NoHop {
        async fn admit(
            &self,
            _: &Url,
            _: &FetchOptions,
            _: &mut crate::acquisition::AcquisitionBudgetV1,
            _: &tokio_util::sync::CancellationToken,
        ) -> Result<(), FetchError> {
            Err(FetchError::AcquisitionUnavailable)
        }
        async fn check_authority(&self) -> Result<(), FetchError> {
            Ok(())
        }
    }

    /// A gate reading `/robots.txt` from a loopback server that answers `status` with `body`,
    /// the server's task (abort it when done) and a URL on the server.
    async fn served_gate(status: u16, body: &'static str) -> (RobotsGate, Url, tokio::task::JoinHandle<()>) {
        let status = axum::http::StatusCode::from_u16(status).unwrap();
        let app = axum::Router::new().route(
            "/robots.txt",
            axum::routing::get(move || async move { (status, body) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Url::parse(&format!("http://{}/selected", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut config = crawlx_fetch::FetchConfig::default();
        config.governor.base_delay = Duration::ZERO;
        let fetcher = Arc::new(
            Fetcher::new(
                config,
                Arc::new(crawlx_policy::egress::EgressPolicy::new(true).with_seed_port(&target)),
                Arc::new(StaticResolver::new()),
            )
            .unwrap(),
        );
        let gate = RobotsGate::for_crawl(&CreateCrawl::new(target.clone()), fetcher, Arc::new(SystemClock));
        (gate, target, server)
    }

    #[tokio::test]
    async fn an_allowed_url_paces_its_origin_by_the_capped_crawl_delay() {
        let gate = gate_with_robots(|_| {}, "User-agent: *\nDisallow: /private\nCrawl-delay: 3\n");
        let base = paced(&gate);
        assert!(base < Duration::from_secs(3), "{base:?}");
        // a refused URL is not fetched, so it changes no pacing
        assert_eq!(
            gate.decide("http://robots.invalid", &url("/private/x")).await,
            RobotsDecision::Blocked("robots_disallow")
        );
        assert_eq!(paced(&gate), base);
        assert_eq!(
            gate.decide("http://robots.invalid", &url("/a")).await,
            RobotsDecision::Allowed
        );
        assert_eq!(paced(&gate), Duration::from_secs(3));
        // the browser plane's navigations go through the same gate
        let browser = gate_with_robots(|_| {}, "User-agent: *\nCrawl-delay: 99\n");
        assert_eq!(browser.check(&url("/b")).await, NavigationVerdict::Allow);
        assert_eq!(paced(&browser), crawlx_policy::robots::MAX_CRAWL_DELAY);
    }

    #[tokio::test]
    async fn a_robots_answer_without_a_hint_never_lowers_the_crawl_delay_floor() {
        let origin = "http://robots.invalid";
        let gate = gate_with_robots(|_| {}, "User-agent: *\nCrawl-delay: 3\n");
        assert_eq!(gate.decide(origin, &url("/a")).await, RobotsDecision::Allowed);
        assert_eq!(paced(&gate), Duration::from_secs(3));
        // a refetch answered 429 or 403 is recorded as 4xx: allow-all, and no hint
        gate.record_and_pace(origin, FetchStatus::Status4xx, &url("/"));
        assert_eq!(gate.decide(origin, &url("/a")).await, RobotsDecision::Allowed);
        // success decay must not speed the origin up past the last hint
        let governor_origin = crawlx_fetch::Origin::from_url(&url("/"));
        for _ in 0..20 {
            gate.fetcher
                .governor()
                .on_response_with_latency(&governor_origin, 200, None, None, false)
                .await
                .unwrap();
        }
        assert_eq!(paced(&gate), Duration::from_secs(3));
        // a parsed file with another value still updates the floor
        gate.record_and_pace(
            origin,
            FetchStatus::Ok(b"User-agent: *\nCrawl-delay: 5\n".to_vec()),
            &url("/"),
        );
        assert_eq!(paced(&gate), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_run_that_ignores_robots_ignores_its_crawl_delay_too() {
        let gate = gate_with_robots(
            |c| c.safety.respect_robots_txt = false,
            "User-agent: *\nCrawl-delay: 3\n",
        );
        let base = paced(&gate);
        assert_eq!(gate.check(&url("/a")).await, NavigationVerdict::Allow);
        assert_eq!(paced(&gate), base);
    }

    #[tokio::test]
    async fn a_recorded_robots_answer_paces_its_origin_without_an_allowed_decision() {
        // sitemap and known-file discovery fetch around the gate, after a seed it refused
        let obeying = gate(|_| {});
        let base = paced(&obeying);
        assert!(base < Duration::from_secs(3), "{base:?}");
        obeying.record_and_pace(
            "http://robots.invalid",
            FetchStatus::Ok(b"User-agent: *\nDisallow: /\nCrawl-delay: 3\n".to_vec()),
            &url("/"),
        );
        assert_eq!(
            obeying.decide("http://robots.invalid", &url("/a")).await,
            RobotsDecision::Blocked("robots_disallow")
        );
        assert_eq!(paced(&obeying), Duration::from_secs(3));
        // a run that ignores robots.txt is never paced by it
        let ignoring = gate(|c| c.safety.respect_robots_txt = false);
        let base = paced(&ignoring);
        ignoring.record_and_pace(
            "http://robots.invalid",
            FetchStatus::Ok(b"User-agent: *\nCrawl-delay: 3\n".to_vec()),
            &url("/"),
        );
        assert_eq!(paced(&ignoring), base);
    }

    #[test]
    fn ignoring_robots_needs_a_record_reference() {
        let mut crawl = CreateCrawl::new(Url::parse("http://robots.invalid/").unwrap());
        assert!(
            RobotsGate::check_override(&crawl).is_ok(),
            "obeying robots needs nothing"
        );
        crawl.safety.respect_robots_txt = false;
        let err = RobotsGate::check_override(&crawl).unwrap_err();
        assert!(matches!(err, WorkerError::Config(_)), "{err:?}");
        assert!(err.to_string().contains("authorizationRecordRef"), "{err}");
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        assert!(RobotsGate::check_override(&crawl).is_ok());
    }
    #[tokio::test]
    async fn continuation_robots_allowance_failure_does_not_poison_cache_and_cached_rules_cost_zero() {
        use crate::acquisition::{AcquisitionBudgetV1, HopAdmission};
        use crawlx_core::acquisition::AcquisitionPolicyV1;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio_util::sync::CancellationToken;
        struct OwnedAuthority;
        #[async_trait::async_trait]
        impl HopAdmission for OwnedAuthority {
            async fn admit(
                &self,
                _: &Url,
                _: &FetchOptions,
                _: &mut AcquisitionBudgetV1,
                _: &CancellationToken,
            ) -> Result<(), FetchError> {
                Err(FetchError::AcquisitionUnavailable)
            }
            async fn check_authority(&self) -> Result<(), FetchError> {
                Ok(())
            }
        }
        const BODY: &str = "User-agent: *\nAllow: /\n";
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/robots.txt",
            axum::routing::get(move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::AcqRel);
                    BODY
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Url::parse(&format!("http://{}/selected", listener.local_addr().unwrap())).unwrap();
        let origin = target.origin().ascii_serialization();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let crawl = CreateCrawl::new(target.clone());
        let mut config = crawlx_fetch::FetchConfig::default();
        config.governor.base_delay = Duration::ZERO;
        let fetcher = Arc::new(
            Fetcher::new(
                config,
                Arc::new(crawlx_policy::egress::EgressPolicy::new(true).with_seed_port(&target)),
                Arc::new(StaticResolver::new()),
            )
            .unwrap(),
        );
        let gate = RobotsGate::for_crawl(&crawl, fetcher, Arc::new(SystemClock));
        let mut policy = AcquisitionPolicyV1::default();
        policy.max_decoded_bytes = 5;
        let mut short = AcquisitionBudgetV1::new(&policy).unwrap();
        let cancel = CancellationToken::new();
        let options = FetchOptions::default();
        assert!(matches!(
            gate.decide_with_budget(&origin, &target, &options, &mut short, &cancel, &OwnedAuthority)
                .await,
            Err(FetchError::AcquisitionAllowance)
        ));
        assert_eq!(hits.load(Ordering::Acquire), 1);
        policy.max_decoded_bytes = 1024;
        let mut complete = AcquisitionBudgetV1::new(&policy).unwrap();
        assert_eq!(
            gate.decide_with_budget(
                &origin,
                &target,
                &options,
                &mut complete,
                &cancel,
                &OwnedAuthority
            )
            .await
            .unwrap(),
            RobotsDecision::Allowed
        );
        assert_eq!(
            hits.load(Ordering::Acquire),
            2,
            "failed quota must not cache a site outage"
        );
        assert_eq!(complete.usage().network_requests_reserved, 1);
        assert_eq!(
            complete.usage().decoded_bytes_observed,
            u64::try_from(BODY.len()).unwrap()
        );
        policy.max_attempts = 1;
        let mut cached = AcquisitionBudgetV1::new(&policy).unwrap();
        cached.reserve(&cancel).unwrap();
        let before = cached.usage();
        assert_eq!(
            gate.decide_with_budget(&origin, &target, &options, &mut cached, &cancel, &OwnedAuthority)
                .await
                .unwrap(),
            RobotsDecision::Allowed
        );
        assert_eq!(cached.usage(), before);
        assert_eq!(hits.load(Ordering::Acquire), 2);
        server.abort();
    }

    #[tokio::test]
    async fn a_cached_allowed_continuation_paces_its_origin_by_the_crawl_delay() {
        use crate::acquisition::AcquisitionBudgetV1;
        use crawlx_core::acquisition::AcquisitionPolicyV1;
        use tokio_util::sync::CancellationToken;
        let gate = gate_with_robots(|_| {}, "User-agent: *\nDisallow: /private\nCrawl-delay: 3\n");
        let base = paced(&gate);
        assert!(base < Duration::from_secs(3), "{base:?}");
        let mut budget = AcquisitionBudgetV1::new(&AcquisitionPolicyV1::default()).unwrap();
        let cancel = CancellationToken::new();
        let options = FetchOptions::default();
        // a refused URL is not fetched, so it changes no pacing
        assert_eq!(
            gate.decide_with_budget(
                "http://robots.invalid",
                &url("/private/x"),
                &options,
                &mut budget,
                &cancel,
                &NoHop
            )
            .await
            .unwrap(),
            RobotsDecision::Blocked("robots_disallow")
        );
        assert_eq!(paced(&gate), base);
        assert_eq!(
            gate.decide_with_budget(
                "http://robots.invalid",
                &url("/a"),
                &options,
                &mut budget,
                &cancel,
                &NoHop
            )
            .await
            .unwrap(),
            RobotsDecision::Allowed
        );
        assert_eq!(paced(&gate), Duration::from_secs(3));
    }

    const ROBOTS: &str = "User-agent: *\nDisallow: /private\nCrawl-delay: 3\n";

    #[tokio::test]
    async fn a_fetched_robots_txt_paces_its_origin_without_a_decision() {
        let (gate, target, server) = served_gate(200, ROBOTS).await;
        let origin = target.origin().ascii_serialization();
        assert!(paced_at(&gate, &target) < Duration::from_secs(3));
        // the sitemap and known-file discovery path: fetch only, no `decide`
        assert!(!gate.fetch(&origin, &target).await);
        assert_eq!(paced_at(&gate, &target), Duration::from_secs(3));
        server.abort();
    }

    #[tokio::test]
    async fn a_budgeted_robots_fetch_paces_its_origin_even_when_it_refuses_the_url() {
        use crate::acquisition::AcquisitionBudgetV1;
        use crawlx_core::acquisition::AcquisitionPolicyV1;
        use tokio_util::sync::CancellationToken;
        let (gate, target, server) = served_gate(200, ROBOTS).await;
        let origin = target.origin().ascii_serialization();
        let refused = target.join("/private/x").unwrap();
        let mut budget = AcquisitionBudgetV1::new(&AcquisitionPolicyV1::default()).unwrap();
        // the refused URL is never allowed, so only the record path can pace the origin
        assert_eq!(
            gate.decide_with_budget(
                &origin,
                &refused,
                &FetchOptions::default(),
                &mut budget,
                &CancellationToken::new(),
                &NoHop
            )
            .await
            .unwrap(),
            RobotsDecision::Blocked("robots_disallow")
        );
        assert_eq!(paced_at(&gate, &target), Duration::from_secs(3));
        server.abort();
    }

    #[tokio::test]
    async fn gates_over_one_governor_never_leave_a_stale_floor() {
        // the browser guard and the URL plane's gate share the run's governor and its cache
        let origin = "http://robots.invalid";
        let a = gate(|_| {});
        let b = a.with_fetcher(Arc::clone(&a.fetcher));
        let robots =
            |delay: u8| FetchStatus::Ok(format!("User-agent: *\nCrawl-delay: {delay}\n").into_bytes());
        a.record_and_pace(origin, robots(3), &url("/"));
        assert_eq!(paced(&a), Duration::from_secs(3));
        // `b` reads the file again after its TTL and finds an explicit `Crawl-delay: 0`: the
        // floor drops (a missing directive would keep it)
        b.record_and_pace(origin, robots(0), &url("/"));
        let governor_origin = crawlx_fetch::Origin::from_url(&url("/"));
        for _ in 0..20 {
            a.fetcher
                .governor()
                .on_response_with_latency(&governor_origin, 200, None, None, false)
                .await
                .unwrap();
        }
        assert!(paced(&a) < Duration::from_secs(3), "{:?}", paced(&a));
        // `a` sees the hint again: a per-gate memo of the last value would skip this
        a.record_and_pace(origin, robots(3), &url("/"));
        assert_eq!(paced(&a), Duration::from_secs(3));
    }
}
