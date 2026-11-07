//! The crawlx side as data: a [`CrawlxRun`] built from an in-process worker run, from the
//! directory `crawlx crawl --out DIR` writes, or from its own JSON serialization.

use super::access::AccessLog;
use crate::error::BenchError;
use crate::gym::manifest::FixtureManifest;
use crate::gym::GymHandle;
use crate::worker_exec::{authorize_fixture, crawl_request, worker_config, worker_config_with};
use crawlx_core::config::{CrawlMode, QueryPolicy, SafetyProfile, SitemapMode};
use crawlx_core::counters::Counters;
use crawlx_core::repo::{FrontierEntry, FrontierStatus};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_url::TrailingSlash;
use crawlx_worker::{run_local_with, LocalRun, RunReport, Stores};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// A crawlx run reduced to what the comparator reads.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct CrawlxRun {
    /// Native run status (`completed`, `failed`, `cancelled`, ...).
    pub status: String,
    /// Terminal reason, when terminal.
    #[serde(default)]
    pub terminal_reason: Option<String>,
    /// URL-plane counters.
    #[serde(default)]
    pub counters: Counters,
    /// Succeeded pages.
    #[serde(default)]
    pub pages: Vec<CrawlxPage>,
    /// Frontier rows (every discovered URL with its outcome). Empty when the run was loaded
    /// from a CLI output directory, which does not export the frontier.
    #[serde(default)]
    pub frontier: Vec<CrawlxFrontierRow>,
    /// The gym's access log of the run (the page requests the fixture server saw), when the run
    /// was made against a gym.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<AccessLog>,
}

/// One succeeded page.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct CrawlxPage {
    /// Canonical URL.
    pub url: String,
    /// HTTP status.
    pub status: u16,
    /// Title.
    #[serde(default)]
    pub title: Option<String>,
    /// Description.
    #[serde(default)]
    pub description: Option<String>,
    /// Language.
    #[serde(default)]
    pub language: Option<String>,
    /// Content type.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Markdown, when produced and retained.
    #[serde(default)]
    pub markdown: Option<String>,
    /// Outgoing links.
    #[serde(default)]
    pub links: Vec<String>,
}

/// One frontier row.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct CrawlxFrontierRow {
    /// Canonical URL.
    pub url: String,
    /// Final status (`succeeded`, `failed`, `policy_blocked`, `robots_blocked`, ...).
    pub status: String,
    /// Denial reason or error code.
    #[serde(default)]
    pub reason: Option<String>,
    /// Link depth of the row (`0` is the seed); `None` in a run file saved before the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u16>,
}

impl CrawlxFrontierRow {
    /// The crawl's entry URL that `includePaths` refused as a page but that was fetched once for
    /// its links (`policy_blocked` `not_included` / `url_not_included` at depth 0). Firecrawl
    /// reports the same URL in `errors[]` as `CRAWL_DENIAL` (the compat `/errors` of crawlx does
    /// too), so it belongs to the attempted set of C1.
    pub(crate) fn is_fetched_entry_denial(&self) -> bool {
        self.status == FrontierStatus::PolicyBlocked.as_str()
            && self.depth == Some(0)
            && matches!(self.reason.as_deref(), Some("not_included" | "url_not_included"))
    }
}

/// How the in-process fixture run is configured.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FixtureRun {
    /// Fixture id (`s1`).
    pub fixture: String,
    /// Crawl seed.
    pub seed: u64,
    /// Query handling; the comparison uses `keep_all` (Firecrawl's default).
    pub query_policy: QueryPolicy,
    /// The Firecrawl crawl request the other side received (`POST /v2/crawl` body without
    /// `url`); `Null` means the defaults. See [`apply_firecrawl_request`].
    pub request: serde_json::Value,
    /// Trailing-slash policy of the worker's canonicalizer; `None` takes the fixture manifest's
    /// (`s1`: strip). The compat facade's workers run with the crawlx default, `Keep`.
    pub trailing_slash: Option<TrailingSlash>,
    /// Host name the crawl addresses the gym by (`gym.test`, a name of `fixtures::d2::HOSTS`);
    /// `None` crawls the gym's loopback address.
    pub host: Option<String>,
    /// Further host names a fixture's pages link to (`app.gym.test`, ...): the worker's
    /// resolver maps them, and `host`, to the loopback gym.
    pub aliases: Vec<String>,
    /// Make the fixture own the origin-level files (`robots.txt`, the gym's `claim_origin`).
    pub claim_origin: bool,
    /// Seed path below the origin (`/d2/scope/`) instead of the manifest's `url_path`.
    pub seed_path: Option<String>,
}

impl FixtureRun {
    /// Plan defaults for `fixture`.
    #[must_use]
    pub fn new(fixture: &str) -> Self {
        Self {
            fixture: fixture.to_owned(),
            seed: 20_261_019,
            query_policy: QueryPolicy::KeepAll,
            request: serde_json::Value::Null,
            trailing_slash: None,
            host: None,
            aliases: Vec::new(),
            claim_origin: false,
            seed_path: None,
        }
    }

    /// The origin the crawl addresses on `gym`: `http://{host}:{port}` when a host name is
    /// set, the gym's own base URL otherwise.
    #[must_use]
    pub fn crawl_origin(&self, gym: &GymHandle) -> String {
        match &self.host {
            Some(h) => format!("http://{h}:{}", gym.port),
            None => gym.base_url.clone(),
        }
    }
}

/// Apply the options of a Firecrawl crawl request to the crawlx request, the way the compat
/// facade translates them (`crawlx-api` `compat_crawl`): `limit` to
/// `limits.urls`; `includePaths`/`excludePaths` to `scope.includePaths`/`excludePaths` (or the
/// URL-wide `urlInclude`/`urlExclude` with `regexOnFullURL`); `maxDiscoveryDepth`; `sitemap`;
/// `crawlEntireDomain`, `allowExternalLinks`, `allowSubdomains`; `ignoreQueryParameters`
/// (`true` maps to `strip_all`, otherwise `query_policy` stays as given). Keys the in-process
/// run has no counterpart for (`scrapeOptions`, `maxConcurrency`, `delay`, `webhook`,
/// `deduplicateSimilarURLs`, ...) are ignored: they do not change admission. In particular
/// `deduplicateSimilarURLs` is URL normalization in Firecrawl (a real run, 2026-10-28: `true`
/// fetches `/s1/blog/` once, `false` also `/s1/blog`), which canonicalization always does, so it
/// must not turn on the native shape filter `scope.filterSimilar`.
///
/// # Errors
/// [`BenchError::Request`] when a mapped key has the wrong JSON type or an unknown enum value.
pub fn apply_firecrawl_request(
    crawl: &mut crawlx_core::config::CreateCrawl,
    request: &serde_json::Value,
) -> Result<(), BenchError> {
    let Some(map) = request.as_object() else {
        return match request {
            serde_json::Value::Null => Ok(()),
            _ => Err(BenchError::Request("the request must be a JSON object".into())),
        };
    };
    let uint = |key: &str| -> Result<Option<u64>, BenchError> {
        map.get(key).map_or(Ok(None), |v| {
            v.as_u64()
                .map(Some)
                .ok_or_else(|| BenchError::Request(format!("`{key}` must be a non-negative integer")))
        })
    };
    let flag = |key: &str| -> Result<Option<bool>, BenchError> {
        map.get(key).map_or(Ok(None), |v| {
            v.as_bool()
                .map(Some)
                .ok_or_else(|| BenchError::Request(format!("`{key}` must be a boolean")))
        })
    };
    let patterns = |key: &str| -> Result<Option<Vec<String>>, BenchError> {
        map.get(key).map_or(Ok(None), |v| {
            v.as_array()
                .and_then(|a| {
                    a.iter()
                        .map(|s| s.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                })
                .map(Some)
                .ok_or_else(|| BenchError::Request(format!("`{key}` must be an array of strings")))
        })
    };
    if let Some(n) = uint("limit")? {
        crawl.limits.urls = u32::try_from(n).unwrap_or(u32::MAX);
    }
    let on_full_url = flag("regexOnFullURL")?.unwrap_or(false);
    let scope = &mut crawl.scope;
    let (paths_in, paths_out) = if on_full_url {
        (&mut scope.url_include, &mut scope.url_exclude)
    } else {
        (&mut scope.include_paths, &mut scope.exclude_paths)
    };
    if let Some(l) = patterns("includePaths")? {
        *paths_in = l;
    }
    if let Some(l) = patterns("excludePaths")? {
        *paths_out = l;
    }
    if let Some(n) = uint("maxDiscoveryDepth")? {
        scope.max_discovery_depth = u16::try_from(n).unwrap_or(u16::MAX);
    }
    if let Some(v) = map.get("sitemap") {
        scope.sitemap = match v.as_str() {
            Some("skip") => SitemapMode::Skip,
            Some("include") => SitemapMode::Include,
            Some("only") => SitemapMode::Only,
            _ => {
                return Err(BenchError::Request(
                    "`sitemap` must be skip, include or only".into(),
                ))
            }
        };
    }
    if flag("ignoreQueryParameters")?.unwrap_or(false) {
        scope.query_policy = QueryPolicy::StripAll;
    }
    if let Some(b) = flag("crawlEntireDomain")? {
        scope.crawl_entire_domain = b;
    }
    if let Some(b) = flag("allowExternalLinks")? {
        scope.allow_external_links = b;
    }
    if let Some(b) = flag("allowSubdomains")? {
        scope.allow_subdomains = b;
    }
    Ok(())
}

fn meta_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(serde_json::Value::as_str).map(str::to_owned)
}

impl CrawlxRun {
    /// Reduce a worker report plus the run's frontier rows.
    #[must_use]
    pub fn from_report(report: &RunReport, frontier: &[FrontierEntry]) -> Self {
        let pages = report
            .pages
            .iter()
            .enumerate()
            .map(|(i, p)| CrawlxPage {
                url: p.url.url.to_string(),
                status: p.status,
                title: p.title.clone(),
                description: meta_str(&p.metadata, "description"),
                language: meta_str(&p.metadata, "language"),
                content_type: p.content_type.clone(),
                markdown: report.page_contents.get(i).and_then(|c| c.markdown.clone()),
                links: p.links.clone(),
            })
            .collect();
        Self {
            status: report.status.as_str().to_owned(),
            terminal_reason: report.terminal_reason.map(|r| r.as_str().to_owned()),
            counters: report.counters.urls,
            pages,
            frontier: frontier
                .iter()
                .map(|f| CrawlxFrontierRow {
                    url: f.url.url.to_string(),
                    status: f.status.as_str().to_owned(),
                    reason: f.denial_reason.clone(),
                    depth: Some(f.depth),
                })
                .collect(),
            access_log: None,
        }
    }

    /// Load the directory `crawlx crawl --out DIR` writes (`metadata.json`, `pages/*.md`,
    /// `report.json`). The frontier is not part of that output, so admission is judged on
    /// succeeded pages only; prefer [`CrawlxRun::load`] on a file written by [`CrawlxRun::save`].
    ///
    /// # Errors
    /// [`BenchError::Io`] when a file cannot be read, [`BenchError::Json`] when
    /// `metadata.json` or `report.json` do not parse.
    pub fn from_cli_dir(dir: &Path) -> Result<Self, BenchError> {
        let read = |name: &str| -> Result<Vec<u8>, BenchError> {
            let p = dir.join(name);
            std::fs::read(&p).map_err(|e| BenchError::io(p, e))
        };
        let metadata: Vec<serde_json::Value> = serde_json::from_slice(&read("metadata.json")?)?;
        let report: serde_json::Value = serde_json::from_slice(&read("report.json")?)?;
        let links: serde_json::Map<String, serde_json::Value> = match dir.join("links.json").exists() {
            true => serde_json::from_slice(&read("links.json")?)?,
            false => serde_json::Map::new(),
        };
        let mut pages = Vec::with_capacity(metadata.len());
        for m in &metadata {
            let url = meta_str(m, "url").unwrap_or_default();
            let markdown = match meta_str(m, "file") {
                Some(rel) => Some(String::from_utf8_lossy(&read(&rel)?).into_owned()),
                None => None,
            };
            let inner = m.get("metadata").cloned().unwrap_or_default();
            pages.push(CrawlxPage {
                status: u16::try_from(m.get("status").and_then(serde_json::Value::as_u64).unwrap_or(0))
                    .unwrap_or(u16::MAX),
                title: meta_str(m, "title"),
                description: meta_str(&inner, "description"),
                language: meta_str(&inner, "language"),
                content_type: meta_str(m, "contentType"),
                markdown,
                links: links
                    .get(&url)
                    .and_then(serde_json::Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                url,
            });
        }
        Ok(Self {
            status: meta_str(&report, "status").unwrap_or_default(),
            terminal_reason: meta_str(&report, "terminal_reason"),
            counters: report
                .get("counters")
                .and_then(|c| c.get("urls"))
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default(),
            pages,
            frontier: Vec::new(),
            access_log: None,
        })
    }

    /// Load a file written by [`CrawlxRun::save`].
    ///
    /// # Errors
    /// [`BenchError::Io`] when the file cannot be read, [`BenchError::Json`] when it does not
    /// parse.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let bytes = std::fs::read(path).map_err(|e| BenchError::io(path, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Write the run as pretty JSON.
    ///
    /// # Errors
    /// [`BenchError::Json`] when serialization fails, [`BenchError::Io`] when the write fails.
    pub fn save(&self, path: &Path) -> Result<(), BenchError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes).map_err(|e| BenchError::io(path, e))
    }

    /// Run a gym fixture through `crawlx_worker::run_local_with` (static plane, in-memory
    /// stores, artifacts under `artifacts`) and reduce the result. The frontier is read back
    /// from the shared store so failed and blocked URLs are part of the run, and the gym's
    /// access log rows of the run are kept as the requested set.
    ///
    /// # Errors
    /// [`BenchError::UnknownFixture`] for an unknown id; [`BenchError::Worker`] when the run
    /// fails; [`BenchError::Store`] when the frontier cannot be listed;
    /// [`BenchError::Network`] when an alias does not parse.
    pub async fn crawl_fixture(
        opts: &FixtureRun,
        gym: &GymHandle,
        artifacts: &Path,
    ) -> Result<Self, BenchError> {
        let manifest = FixtureManifest::embedded(&opts.fixture)?;
        let mut req = crawl_request(
            &manifest,
            &opts.crawl_origin(gym),
            opts.seed,
            SafetyProfile::ReadOnly,
        )?;
        req.mode = CrawlMode::Static;
        req.dynamic.enabled = false;
        if let Some(path) = &opts.seed_path {
            req.seed_url = url::Url::parse(&opts.crawl_origin(gym))?.join(path)?;
        }
        req.scope.query_policy = opts.query_policy;
        apply_firecrawl_request(&mut req, &opts.request)?;
        let mut cfg = match opts.trailing_slash {
            Some(policy) => worker_config_with(policy, artifacts)?,
            None => worker_config(&manifest, artifacts)?,
        };
        if opts.host.is_some() || !opts.aliases.is_empty() {
            let mut resolver = StaticResolver::new();
            for name in opts.host.iter().chain(&opts.aliases) {
                resolver = resolver.with(name, [std::net::IpAddr::from([127, 0, 0, 1])]);
            }
            cfg.egress.resolver = Some(Arc::new(resolver));
            cfg.egress.extra_ports = vec![gym.port];
        }
        if opts.claim_origin {
            gym.claim_origin(&opts.fixture);
        }
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), artifacts).await?;
        let ledger = gym.ledger();
        let seen = ledger.len();
        let mut local = authorize_fixture(LocalRun::new(req, cfg).with_stores(stores.clone()));
        if let Some(record) = local.authorization.as_mut() {
            for alias in &opts.aliases {
                let origin = url::Url::parse(&format!("http://{alias}:{}", gym.port))?
                    .origin()
                    .ascii_serialization();
                if !record.origins.contains(&origin) {
                    record.origins.push(origin);
                }
            }
        }
        let report = run_local_with(local).await?;
        let frontier = stores.frontier.list(report.run_id).await?;
        let mut run = Self::from_report(&report, &frontier);
        run.access_log = Some(AccessLog::from_ledger(
            ledger.entries().get(seen..).unwrap_or_default(),
        ));
        Ok(run)
    }

    /// Frontier rows in `status`.
    pub(crate) fn frontier_with(&self, status: FrontierStatus) -> impl Iterator<Item = &CrawlxFrontierRow> {
        let s = status.as_str();
        self.frontier.iter().filter(move |r| r.status == s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::CreateCrawl;
    use serde_json::json;

    fn crawl() -> CreateCrawl {
        CreateCrawl::new(url::Url::parse("http://gym.test/s1/").unwrap())
    }

    #[test]
    fn firecrawl_request_options_map_to_the_scope_and_limits() {
        let mut c = crawl();
        apply_firecrawl_request(
            &mut c,
            &json!({"limit": 10, "includePaths": ["^/s1/docs"], "excludePaths": ["^/s1/blog"],
                    "maxDiscoveryDepth": 2, "sitemap": "only", "crawlEntireDomain": true,
                    "allowSubdomains": true, "ignoreQueryParameters": true,
                    "scrapeOptions": {"formats": ["markdown"]}, "maxConcurrency": 1}),
        )
        .unwrap();
        assert_eq!(c.limits.urls, 10);
        assert_eq!(c.scope.include_paths, vec!["^/s1/docs"]);
        assert_eq!(c.scope.exclude_paths, vec!["^/s1/blog"]);
        assert_eq!(c.scope.max_discovery_depth, 2);
        assert_eq!(c.scope.sitemap, SitemapMode::Only);
        assert!(c.scope.crawl_entire_domain && c.scope.allow_subdomains);
        assert_eq!(c.scope.query_policy, QueryPolicy::StripAll);
    }

    #[test]
    fn deduplicate_similar_urls_never_turns_on_the_shape_filter() {
        // a real run showed it is URL normalization in Firecrawl, not a shape filter
        let mut c = crawl();
        apply_firecrawl_request(&mut c, &json!({"deduplicateSimilarURLs": true})).unwrap();
        assert!(!c.scope.filter_similar);
    }

    #[test]
    fn null_request_is_the_defaults_and_bad_types_are_errors() {
        let mut c = crawl();
        apply_firecrawl_request(&mut c, &serde_json::Value::Null).unwrap();
        assert_eq!(c.limits.urls, crawl().limits.urls);
        assert!(apply_firecrawl_request(&mut c, &json!({"limit": "ten"})).is_err());
        assert!(apply_firecrawl_request(&mut c, &json!({"sitemap": "maybe"})).is_err());
        assert!(apply_firecrawl_request(&mut c, &json!([1])).is_err());
    }
}
