//! `--katana-defaults`: the request values katana's flag defaults would produce.
//!
//! The preset is the lowest layer of a crawl request: `--request`, `--config` and explicit
//! flags all override it. crawlx's own defaults differ from katana's on purpose; this preset exists for users who
//! want katana's behaviour without spelling out every flag.

use crawlx_core::config::{CrawlStrategy, HostScope};
use crawlx_core::CreateCrawl;

/// katana `-rate-limit` default: requests per second across all hosts.
pub(crate) const RATE_LIMIT: u32 = 150;
/// katana `-depth` default.
pub(crate) const MAX_DEPTH: u16 = 3;
/// katana `-max-response-size` default: 4 MiB.
pub(crate) const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
/// katana `-delay` default is 0; crawlx never paces an origin faster than its politeness
/// floor (`politeness.delayMs >= 50`, `crawlx-core`), so the preset sits on the floor.
pub(crate) const DELAY_MS: u32 = 50;

/// Apply the preset to a request.
///
/// | field | value | katana flag |
/// |---|---|---|
/// | `scope.hostScope` | `rdn` | `-field-scope rdn` |
/// | `scope.maxDiscoveryDepth` | 3 | `-depth 3` |
/// | `scope.strategy` | `depth_first` | `-strategy depth-first` |
/// | `scope.jsEndpoints` | `false` | no `-js-crawl` |
/// | `scope.knownFiles` | none | no `-known-files` |
/// | `extract.forms` | `false` | no `-form-extraction` |
/// | `politeness.globalRps` | 150 | `-rate-limit 150` |
/// | `politeness.delayMs` | 50 (floor) | `-delay 0` |
/// | `fetch.maxResponseBytes` | 4 MiB | `-max-response-size` |
///
/// Katana's technology detection is off unless `-tech-detect`: the CLI mirrors that by leaving
/// `technologies` out of JSONL records under the preset (see `output_args`).
pub(crate) fn apply(crawl: &mut CreateCrawl) {
    crawl.scope.host_scope = HostScope::Rdn;
    crawl.scope.max_discovery_depth = MAX_DEPTH;
    crawl.scope.strategy = CrawlStrategy::DepthFirst;
    crawl.scope.js_endpoints = false;
    crawl.scope.known_files.clear();
    crawl.extract.forms = false;
    crawl.politeness.global_rps = Some(RATE_LIMIT);
    crawl.politeness.delay_ms = DELAY_MS;
    crawl.fetch.max_response_bytes = MAX_RESPONSE_BYTES;
}
