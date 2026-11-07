//! A small URL-plane crawl of the static fixture `s1` (ablation A0).
//!
//! The loop composes the production pieces: [`crawlx_fetch::Fetcher`] over the loopback
//! egress exemption, [`crawlx_url`] canonicalization/links/sitemaps/frontier,
//! [`crawlx_policy`] scope and robots. Its counters are what `fixtures/s1/manifest.json`
//! records; the same numbers must come out of `crawlx crawl --mode static`.

use crate::error::BenchError;
use crate::gym::manifest::{FixtureManifest, TrailingSlashHint};
use crawlx_core::config::CreateCrawl;
use crawlx_core::counters::Counters;
use crawlx_core::seed::CrawlSeed;
use crawlx_fetch::{FetchConfig, FetchOptions, Fetcher, GovernorConfig, RetryPolicy, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use crawlx_policy::robots::Match;
use crawlx_policy::scope::ScopePolicy;
use crawlx_policy::RobotsTxt;
use crawlx_url::{
    extract_links, BlockKind, CanonicalizeOptions, Canonicalizer, Frontier, LinkSource, PushOutcome,
    SitemapParser, TrailingSlash,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Result of a URL-plane crawl.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct StaticCrawl {
    /// URL-plane counters of the crawl; for a static fixture they must equal the manifest's `url_counters`.
    pub counters: Counters,
    /// Canonical URLs fetched (attempted), in fetch order.
    pub fetched: Vec<String>,
    /// HTTP status per fetched canonical URL.
    pub statuses: BTreeMap<String, u16>,
}

/// Map the manifest's trailing-slash hint to the canonicalizer's policy.
#[must_use]
pub const fn trailing_slash(h: TrailingSlashHint) -> TrailingSlash {
    match h {
        TrailingSlashHint::Keep => TrailingSlash::Keep,
        TrailingSlashHint::Strip => TrailingSlash::Strip,
        TrailingSlashHint::Add => TrailingSlash::Add,
    }
}

/// Crawl fixture `manifest` (a static fixture served by a gym at `base_url`) over the URL plane.
///
/// `max_pages` bounds the number of fetches. Robots and sitemap discovery follow the plan:
/// `/robots.txt` rules apply to every admitted URL and its `Sitemap:` lines seed the frontier.
///
/// # Errors
/// Fetch or parse failures of the seed, robots or sitemap documents.
pub async fn crawl(
    base_url: &str,
    manifest: &FixtureManifest,
    max_pages: usize,
) -> Result<StaticCrawl, BenchError> {
    let base = Url::parse(base_url)?;
    let seed_url = Url::parse(&manifest.entry_url(base_url))?;
    let port = seed_url
        .port_or_known_default()
        .ok_or_else(|| BenchError::manifest(manifest.id.clone(), "entry url has no port"))?;

    // Loopback is exempt (authorized fixture network); every other private range stays denied.
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse()?);
    policy.extra_ports.push(port);
    let fetcher = Fetcher::new(
        FetchConfig {
            governor: GovernorConfig {
                base_delay: Duration::from_millis(2),
                ..GovernorConfig::default()
            },
            retry: RetryPolicy {
                max_retries: 0,
                ..RetryPolicy::default()
            },
            request_timeout: Duration::from_secs(10),
            seed: CrawlSeed(0),
            ..FetchConfig::default()
        },
        Arc::new(policy),
        Arc::new(StaticResolver::new()),
    )?;
    let ua = fetcher.config().user_agent();
    let opts = FetchOptions::default();

    let crawl_cfg = CreateCrawl::new(seed_url.clone());
    let scope = ScopePolicy::new(&crawl_cfg)?;
    let canon = CanonicalizeOptions {
        trailing_slash: trailing_slash(manifest.expected.trailing_slash),
        ..CanonicalizeOptions::default()
    };

    let robots_url = base.join("/robots.txt")?;
    let robots = match fetcher.fetch(&robots_url, &opts).await {
        Ok(r) if r.status.is_success() => RobotsTxt::parse(&r.body),
        _ => RobotsTxt::allow_all(),
    };

    let mut frontier = Frontier::new();
    let seed = Canonicalizer::canonicalize_url(&seed_url, &canon)?;
    frontier.push(seed, 0, LinkSource::Seed, None);

    let discover =
        |frontier: &mut Frontier, raw: &Url, depth: u32, source: LinkSource, priority: Option<f32>| {
            let Ok(c) = Canonicalizer::canonicalize_url(raw, &canon) else {
                return;
            };
            let depth16 = u16::try_from(depth).unwrap_or(u16::MAX);
            if !scope.decide(&c, depth16).is_admitted() {
                frontier.note_blocked(BlockKind::Policy);
                return;
            }
            let pq = match c.url.query() {
                Some(q) => format!("{}?{q}", c.url.path()),
                None => c.url.path().to_owned(),
            };
            if matches!(robots.evaluate(&ua, &pq), Match::Disallowed(_)) {
                frontier.note_blocked(BlockKind::Robots);
                return;
            }
            let outcome = frontier.push(c, depth, source, priority);
            debug_assert!(matches!(
                outcome,
                PushOutcome::Admitted | PushOutcome::Duplicate | PushOutcome::DepthExceeded
            ));
        };

    for sm in robots.sitemaps() {
        let Ok(sm_url) = Url::parse(sm) else { continue };
        let Ok(resp) = fetcher.fetch(&sm_url, &opts).await else {
            continue;
        };
        if !resp.status.is_success() {
            continue;
        }
        let doc = SitemapParser::parse(&resp.body)?;
        for u in doc.urls {
            if let Ok(loc) = Url::parse(&u.loc) {
                discover(&mut frontier, &loc, 1, LinkSource::Sitemap, u.priority);
            }
        }
    }

    let mut fetched = Vec::new();
    let mut statuses = BTreeMap::new();
    let (mut attempted, mut succeeded, mut failed, mut unreachable) = (0u64, 0u64, 0u64, 0u64);
    while fetched.len() < max_pages {
        let Some(entry) = frontier.pop() else { break };
        attempted += 1;
        let key = entry.url.url.to_string();
        fetched.push(key.clone());
        match fetcher.fetch(&entry.url.url, &opts).await {
            Ok(resp) if resp.status.is_success() => {
                succeeded += 1;
                statuses.insert(key, resp.status.as_u16());
                let html = String::from_utf8_lossy(&resp.body);
                for link in extract_links(&html, &resp.final_url) {
                    discover(&mut frontier, &link.url, entry.depth + 1, LinkSource::Body, None);
                }
            }
            Ok(resp) => {
                failed += 1;
                statuses.insert(key, resp.status.as_u16());
            }
            Err(_) => unreachable += 1,
        }
    }

    let mut counters = frontier.counters();
    counters.attempted = attempted;
    counters.succeeded = succeeded;
    counters.failed = failed;
    counters.unreachable = unreachable;
    Ok(StaticCrawl {
        counters,
        fetched,
        statuses,
    })
}
