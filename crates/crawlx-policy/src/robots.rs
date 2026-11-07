//! Robots Exclusion Protocol, RFC 9309.
//!
//! * [`RobotsTxt::parse`]: tolerant line parser; the first 500 KiB are parsed
//!   and a trailing partial line is dropped; groups are keyed by user-agent
//!   product tokens (consecutive `User-agent` lines share one group);
//!   `Sitemap:` lines are global; `Crawl-delay` is a non-standard politeness
//!   hint attached to its group.
//! * [`RobotsTxt::evaluate`]: product-token group selection (case-insensitive,
//!   duplicate groups merged, `*` fallback, no group means allow), longest
//!   matching pattern wins, `Allow` wins ties, `*` and `$` wildcards, both
//!   sides percent-normalized.
//! * [`RobotsCache`]: per-origin cache driven by fetch status semantics
//!   (2xx parse, 4xx allow all, 5xx/unreachable temporary disallow with
//!   backoff and a 24 h give-up horizon) on an injected [`Clock`].
//!
//! Robots is not authorization; this module only answers
//! "may this crawler fetch this path".

use chrono::Duration as ChronoDuration;
use crawlx_core::time::{Clock, Timestamp};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Bytes of `robots.txt` that are parsed (RFC 9309 §2.5: at least 500 KiB).
pub const MAX_ROBOTS_BYTES: usize = 500 * 1024;

/// Upper bound applied to `Crawl-delay` hints (planning default).
pub const MAX_CRAWL_DELAY: Duration = Duration::from_secs(10);

/// One `Allow`/`Disallow` rule with its normalized pattern.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RobotsRule {
    /// `true` for `Allow`, `false` for `Disallow`.
    pub allow: bool,
    /// Percent-normalized pattern as matched (`*` and `$` kept literal).
    pub pattern: String,
}

impl RobotsRule {
    fn matches(&self, path: &str) -> bool {
        pattern_matches(self.pattern.as_bytes(), path.as_bytes())
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
struct Group {
    /// Lowercased user-agent product tokens.
    agents: Vec<String>,
    rules: Vec<RobotsRule>,
    crawl_delay: Option<f64>,
}

/// A parsed `robots.txt`.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct RobotsTxt {
    groups: Vec<Group>,
    sitemaps: Vec<String>,
    truncated: bool,
}

/// Result of matching a path against a `robots.txt`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Match {
    /// No rule denies the path.
    Allowed,
    /// Denied by this rule.
    Disallowed(RobotsRule),
}

impl RobotsTxt {
    /// A file that allows everything (empty or unavailable file).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Parse `body`, honoring the 500 KiB limit.
    #[must_use]
    pub fn parse(body: &[u8]) -> Self {
        let mut out = Self::default();
        let mut bytes = body;
        if bytes.len() > MAX_ROBOTS_BYTES {
            bytes = &bytes[..MAX_ROBOTS_BYTES];
            out.truncated = true;
            // drop a trailing partial line: a cut rule could widen or narrow scope
            if let Some(pos) = bytes.iter().rposition(|&b| b == b'\n' || b == b'\r') {
                bytes = &bytes[..=pos];
            } else {
                bytes = &[];
            }
        }
        let text = String::from_utf8_lossy(bytes);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        // `last_was_agent`: the previous directive was a user-agent line, so another
        // user-agent line extends the same group instead of opening a new one.
        let mut last_was_agent = false;
        let mut current: Option<usize> = None;
        for raw in text.split(['\n', '\r']) {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match key.as_str() {
                "user-agent" | "useragent" => {
                    let token = value.to_ascii_lowercase();
                    if token.is_empty() {
                        continue;
                    }
                    if last_was_agent {
                        if let Some(g) = current.and_then(|i| out.groups.get_mut(i)) {
                            g.agents.push(token);
                        }
                    } else {
                        out.groups.push(Group {
                            agents: vec![token],
                            ..Group::default()
                        });
                        current = Some(out.groups.len() - 1);
                    }
                    last_was_agent = true;
                }
                "allow" | "disallow" => {
                    last_was_agent = false;
                    let Some(g) = current.and_then(|i| out.groups.get_mut(i)) else {
                        continue;
                    };
                    if value.is_empty() {
                        // empty Disallow allows everything; empty Allow is a no-op
                        continue;
                    }
                    g.rules.push(RobotsRule {
                        allow: key == "allow",
                        pattern: normalize(value),
                    });
                }
                "crawl-delay" => {
                    last_was_agent = false;
                    if let (Some(g), Ok(d)) =
                        (current.and_then(|i| out.groups.get_mut(i)), value.parse::<f64>())
                    {
                        if d.is_finite() && d >= 0.0 {
                            g.crawl_delay = Some(d);
                        }
                    }
                }
                // global; does not terminate the current group
                "sitemap" if !value.is_empty() && !out.sitemaps.iter().any(|s| s == value) => {
                    out.sitemaps.push(value.to_owned());
                }
                _ => {}
            }
        }
        out
    }

    /// `Sitemap:` URLs in file order, deduplicated.
    #[must_use]
    pub fn sitemaps(&self) -> &[String] {
        &self.sitemaps
    }

    /// True when the file exceeded [`MAX_ROBOTS_BYTES`] and was cut.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Every `Allow`/`Disallow` rule of every group, in file order (known-files
    /// seeding; the user-agent does not matter for discovery).
    pub fn rules(&self) -> impl Iterator<Item = &RobotsRule> {
        self.groups.iter().flat_map(|g| g.rules.iter())
    }

    /// Groups that apply to `user_agent`: all groups naming its product token or one of the
    /// `aliases` (lowercase product tokens), else all `*` groups.
    fn applicable(&self, user_agent: &str, aliases: &[String]) -> Vec<&Group> {
        let token = product_token(user_agent);
        let specific: Vec<&Group> = self
            .groups
            .iter()
            .filter(|g| g.agents.contains(&token) || g.agents.iter().any(|a| aliases.contains(a)))
            .collect();
        if !specific.is_empty() {
            return specific;
        }
        self.groups
            .iter()
            .filter(|g| g.agents.iter().any(|a| a == "*"))
            .collect()
    }

    /// Match `path_and_query` (path plus query) for `user_agent`.
    #[must_use]
    pub fn evaluate(&self, user_agent: &str, path_and_query: &str) -> Match {
        self.evaluate_as(user_agent, &[], path_and_query)
    }

    /// As [`Self::evaluate`] for a crawler that also answers to the product tokens `aliases`
    /// (lowercase): a group naming any of them applies next to the groups naming `user_agent`'s
    /// own token (Firecrawl's `FirecrawlAgent`).
    #[must_use]
    pub fn evaluate_as(&self, user_agent: &str, aliases: &[String], path_and_query: &str) -> Match {
        let groups = self.applicable(user_agent, aliases);
        let path = if path_and_query.is_empty() {
            "/".to_owned()
        } else {
            normalize(path_and_query)
        };
        // Longest pattern wins; Allow wins a tie.
        let mut best: Option<&RobotsRule> = None;
        for rule in groups.iter().flat_map(|g| g.rules.iter()) {
            if !rule.matches(&path) {
                continue;
            }
            best = match best {
                None => Some(rule),
                Some(b) if rule.pattern.len() > b.pattern.len() => Some(rule),
                Some(b) if rule.pattern.len() == b.pattern.len() && rule.allow && !b.allow => Some(rule),
                keep => keep,
            };
        }
        match best {
            Some(r) if !r.allow => Match::Disallowed(r.clone()),
            _ => Match::Allowed,
        }
    }

    /// `Crawl-delay` hint for `user_agent` (largest among applicable groups),
    /// capped at [`MAX_CRAWL_DELAY`]. Not part of RFC 9309.
    #[must_use]
    pub fn crawl_delay(&self, user_agent: &str) -> Option<Duration> {
        self.crawl_delay_as(user_agent, &[])
    }

    /// As [`Self::crawl_delay`] with the product-token `aliases` of [`Self::evaluate_as`].
    #[must_use]
    pub fn crawl_delay_as(&self, user_agent: &str, aliases: &[String]) -> Option<Duration> {
        let secs = self
            .applicable(user_agent, aliases)
            .iter()
            .filter_map(|g| g.crawl_delay)
            .fold(None, |acc: Option<f64>, d| Some(acc.map_or(d, |a| a.max(d))))?;
        Some(Duration::from_secs_f64(secs).min(MAX_CRAWL_DELAY))
    }
}

/// Product token of a user-agent string: `crawlx/1.0 (+https://x)` gives `crawlx`.
#[must_use]
pub fn product_token(user_agent: &str) -> String {
    user_agent
        .trim()
        .split(|c: char| c == '/' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Percent-normalization for comparison (RFC 9309 §2.2.2): hex digits are
/// uppercased, escapes of unreserved characters are decoded, and octets
/// outside printable ASCII are encoded. Reserved characters (including `*`
/// and `$`) are untouched.
fn normalize(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' && i + 2 < b.len() && is_hex(b[i + 1]) && is_hex(b[i + 2]) {
            let v = (hex_val(b[i + 1]) << 4) | hex_val(b[i + 2]);
            if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(v));
            } else {
                push_pct(&mut out, v);
            }
            i += 3;
        } else if c <= 0x20 || c >= 0x7f {
            push_pct(&mut out, c);
            i += 1;
        } else {
            out.push(char::from(c));
            i += 1;
        }
    }
    out
}

const fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

const fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

fn push_pct(out: &mut String, v: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(char::from(HEX[usize::from(v >> 4)]));
    out.push(char::from(HEX[usize::from(v & 0x0f)]));
}

/// Match `pattern` (with `*` wildcards and an optional trailing `$`) as a
/// prefix of `path`, or as the whole path when it ends in `$`.
fn pattern_matches(pattern: &[u8], path: &[u8]) -> bool {
    let (pat, anchored) = match pattern.split_last() {
        Some((b'$', rest)) => (rest, true),
        _ => (pattern, false),
    };
    let mut segs = pat.split(|&b| b == b'*');
    let Some(first) = segs.next() else {
        return !anchored || path.is_empty();
    };
    if !path.starts_with(first) {
        return false;
    }
    let mut pos = first.len();
    let rest: Vec<&[u8]> = segs.collect();
    if rest.is_empty() {
        return !anchored || pos == path.len();
    }
    let last_idx = rest.len() - 1;
    for (i, seg) in rest.iter().enumerate() {
        if i == last_idx && anchored {
            // last segment must be a suffix that does not overlap what was consumed
            return path.len() >= pos + seg.len() && path.ends_with(seg);
        }
        match find(&path[pos..], seg) {
            Some(off) => pos += off + seg.len(),
            None => return false,
        }
    }
    true
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Outcome of fetching `/robots.txt`, as reported by the fetch plane.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FetchStatus {
    /// 2xx with the (possibly large) body.
    Ok(Vec<u8>),
    /// 4xx including 401/403: unavailable, allow all.
    Status4xx,
    /// 5xx: unreachable, temporarily disallow.
    Status5xx,
    /// Network error, timeout or refused by egress policy: unreachable.
    Unreachable,
    /// More than 5 consecutive redirects: unavailable, allow all.
    TooManyRedirects,
}

/// Why a path is disallowed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DisallowedBy {
    /// A `Disallow` rule from the file.
    Rule(RobotsRule),
    /// `robots.txt` is unreachable; retry the fetch at `retry_at`. With
    /// `give_up` set the outage exceeded the horizon: mark URLs `unreachable`
    /// with reason `robots_unavailable` instead of waiting.
    Unreachable {
        /// Earliest instant at which `/robots.txt` should be fetched again.
        retry_at: Timestamp,
        /// The outage exceeded the horizon; stop waiting.
        give_up: bool,
    },
}

/// Verdict of [`RobotsCache::evaluate`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RobotsVerdict {
    /// The path may be fetched.
    Allowed,
    /// The path or the whole origin must not be fetched now.
    Disallowed(DisallowedBy),
    /// No fresh entry for the origin: fetch `/robots.txt` and `record_fetch`.
    Unknown,
}

/// Cache tuning.
#[derive(Clone, Debug)]
pub struct RobotsConfig {
    /// User-agent string; its product token selects the group.
    pub user_agent: String,
    /// Extra lowercase product tokens whose groups also apply (Firecrawl's `FirecrawlAgent` for
    /// the facade's runs); empty by default.
    pub aliases: Vec<String>,
    /// Default and maximum cache lifetime.
    pub ttl: Duration,
    /// Floor applied to a server-supplied `max-age`.
    pub min_ttl: Duration,
    /// Continuous unreachability after which URLs are given up (`robots_unreachable_max`).
    pub unreachable_max: Duration,
    /// First retry delay after an unreachable fetch; doubles per failure.
    pub backoff_base: Duration,
    /// Retry delay ceiling.
    pub backoff_cap: Duration,
}

impl Default for RobotsConfig {
    fn default() -> Self {
        Self {
            user_agent: "crawlx".to_owned(),
            aliases: Vec::new(),
            ttl: Duration::from_secs(24 * 3600),
            min_ttl: Duration::from_secs(60),
            unreachable_max: Duration::from_secs(24 * 3600),
            backoff_base: Duration::from_secs(60),
            backoff_cap: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone, Debug)]
enum Entry {
    Parsed {
        txt: RobotsTxt,
        expires_at: Timestamp,
    },
    AllowAll {
        expires_at: Timestamp,
    },
    Unreachable {
        first_failure: Timestamp,
        failures: u32,
        retry_at: Timestamp,
    },
}

/// Per-origin robots cache. Not internally synchronized; wrap it in a mutex
/// when shared (it never awaits).
pub struct RobotsCache {
    clock: Arc<dyn Clock>,
    config: RobotsConfig,
    entries: HashMap<String, Entry>,
}

fn chrono_of(d: Duration) -> ChronoDuration {
    ChronoDuration::from_std(d).unwrap_or(ChronoDuration::MAX)
}

impl RobotsCache {
    /// Cache with default configuration.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self::with_config(clock, RobotsConfig::default())
    }

    /// Cache with explicit configuration.
    #[must_use]
    pub fn with_config(clock: Arc<dyn Clock>, config: RobotsConfig) -> Self {
        Self {
            clock,
            config,
            entries: HashMap::new(),
        }
    }

    /// The configured user agent.
    #[must_use]
    pub fn user_agent(&self) -> &str {
        &self.config.user_agent
    }

    fn key(origin: &str) -> String {
        origin.trim_end_matches('/').to_ascii_lowercase()
    }

    fn add(at: Timestamp, d: Duration) -> Timestamp {
        at.checked_add_signed(chrono_of(d)).unwrap_or(at)
    }

    /// Decide whether `path_and_query` on `origin` may be fetched.
    #[must_use]
    pub fn evaluate(&self, origin: &str, path_and_query: &str) -> RobotsVerdict {
        let now = self.clock.now();
        match self.entries.get(&Self::key(origin)) {
            None => RobotsVerdict::Unknown,
            Some(Entry::AllowAll { expires_at }) => {
                if now >= *expires_at {
                    RobotsVerdict::Unknown
                } else {
                    RobotsVerdict::Allowed
                }
            }
            Some(Entry::Parsed { txt, expires_at }) => {
                if now >= *expires_at {
                    return RobotsVerdict::Unknown;
                }
                match txt.evaluate_as(&self.config.user_agent, &self.config.aliases, path_and_query) {
                    Match::Allowed => RobotsVerdict::Allowed,
                    Match::Disallowed(r) => RobotsVerdict::Disallowed(DisallowedBy::Rule(r)),
                }
            }
            Some(Entry::Unreachable {
                first_failure,
                retry_at,
                ..
            }) => {
                let give_up =
                    now.signed_duration_since(*first_failure) >= chrono_of(self.config.unreachable_max);
                RobotsVerdict::Disallowed(DisallowedBy::Unreachable {
                    retry_at: *retry_at,
                    give_up,
                })
            }
        }
    }

    /// Record a fetch outcome with the default TTL.
    pub fn record_fetch(&mut self, origin: &str, status: FetchStatus) {
        self.record_fetch_with(origin, status, None);
    }

    /// Record a fetch outcome. `max_age` is the response's `Cache-Control`
    /// lifetime; it is clamped to `[min_ttl, ttl]`.
    pub fn record_fetch_with(&mut self, origin: &str, status: FetchStatus, max_age: Option<Duration>) {
        let now = self.clock.now();
        let ttl = max_age.map_or(self.config.ttl, |m| m.clamp(self.config.min_ttl, self.config.ttl));
        let key = Self::key(origin);
        let entry = match status {
            FetchStatus::Ok(body) => Entry::Parsed {
                txt: RobotsTxt::parse(&body),
                expires_at: Self::add(now, ttl),
            },
            FetchStatus::Status4xx | FetchStatus::TooManyRedirects => Entry::AllowAll {
                expires_at: Self::add(now, ttl),
            },
            FetchStatus::Status5xx | FetchStatus::Unreachable => {
                let (first_failure, failures) = match self.entries.get(&key) {
                    Some(Entry::Unreachable {
                        first_failure,
                        failures,
                        ..
                    }) => (*first_failure, failures.saturating_add(1)),
                    _ => (now, 1),
                };
                let shift = failures.saturating_sub(1).min(20);
                let delay = self
                    .config
                    .backoff_base
                    .saturating_mul(1u32 << shift)
                    .min(self.config.backoff_cap);
                Entry::Unreachable {
                    first_failure,
                    failures,
                    retry_at: Self::add(now, delay),
                }
            }
        };
        self.entries.insert(key, entry);
    }

    /// Whether the fetch plane should (re)fetch `/robots.txt` for `origin` at `now`:
    /// no entry, an expired entry, or an unreachable entry whose retry time has come.
    #[must_use]
    pub fn needs_refetch(&self, origin: &str, now: Timestamp) -> bool {
        match self.entries.get(&Self::key(origin)) {
            None => true,
            Some(Entry::Parsed { expires_at, .. } | Entry::AllowAll { expires_at }) => now >= *expires_at,
            Some(Entry::Unreachable { retry_at, .. }) => now >= *retry_at,
        }
    }

    /// `Sitemap:` URLs from the cached file for `origin`.
    #[must_use]
    pub fn sitemaps(&self, origin: &str) -> &[String] {
        match self.entries.get(&Self::key(origin)) {
            Some(Entry::Parsed { txt, .. }) => txt.sitemaps(),
            _ => &[],
        }
    }

    /// Capped `Crawl-delay` hint for `origin` and the configured user agent.
    #[must_use]
    pub fn crawl_delay(&self, origin: &str) -> Option<Duration> {
        match self.entries.get(&Self::key(origin)) {
            Some(Entry::Parsed { txt, .. }) => {
                txt.crawl_delay_as(&self.config.user_agent, &self.config.aliases)
            }
            _ => None,
        }
    }

    /// Drop the entry for `origin`.
    pub fn invalidate(&mut self, origin: &str) {
        self.entries.remove(&Self::key(origin));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::TimeZone;
    use crawlx_core::time::ManualClock;

    const UA: &str = "crawlx/1.0 (+https://example.test/bot)";

    fn allowed(body: &str, path: &str) -> bool {
        RobotsTxt::parse(body.as_bytes()).evaluate(UA, path) == Match::Allowed
    }

    fn denied_by(body: &str, path: &str) -> Option<String> {
        match RobotsTxt::parse(body.as_bytes()).evaluate(UA, path) {
            Match::Allowed => None,
            Match::Disallowed(r) => Some(r.pattern),
        }
    }

    #[test]
    fn v01_disallow_all() {
        let body = "User-agent: *\nDisallow: /\n";
        assert!(!allowed(body, "/"));
        assert!(!allowed(body, "/a/b?x=1"));
    }

    #[test]
    fn v02_empty_disallow_allows_everything() {
        let body = "User-agent: *\nDisallow:\n";
        assert!(allowed(body, "/"));
        assert!(allowed(body, "/private"));
    }

    #[test]
    fn v03_missing_group_allows() {
        assert!(allowed("", "/x"));
        assert!(allowed("# only a comment\n", "/x"));
        // rules for another agent only
        assert!(allowed("User-agent: otherbot\nDisallow: /\n", "/x"));
    }

    #[test]
    fn v04_prefix_match() {
        let body = "User-agent: *\nDisallow: /private\n";
        assert!(!allowed(body, "/private"));
        assert!(!allowed(body, "/private/a"));
        assert!(!allowed(body, "/private-things"));
        assert!(allowed(body, "/public"));
        assert!(allowed(body, "/priv"));
    }

    #[test]
    fn v05_longest_match_allow_beats_shorter_disallow() {
        let body = "User-agent: *\nDisallow: /folder/\nAllow: /folder/page\n";
        assert!(allowed(body, "/folder/page"));
        assert!(allowed(body, "/folder/page2"));
        assert!(!allowed(body, "/folder/other"));
    }

    #[test]
    fn v06_longest_match_disallow_beats_shorter_allow() {
        let body = "User-agent: *\nAllow: /folder\nDisallow: /folder/secret\n";
        assert!(allowed(body, "/folder/open"));
        assert_eq!(
            denied_by(body, "/folder/secret/x").as_deref(),
            Some("/folder/secret")
        );
    }

    #[test]
    fn v07_allow_wins_a_tie_regardless_of_order() {
        assert!(allowed("User-agent: *\nAllow: /p\nDisallow: /p\n", "/p"));
        assert!(allowed("User-agent: *\nDisallow: /p\nAllow: /p\n", "/p"));
    }

    #[test]
    fn v08_star_wildcard() {
        let body = "User-agent: *\nDisallow: /*.json\nDisallow: /a/*/c\n";
        assert!(!allowed(body, "/data.json"));
        assert!(!allowed(body, "/x/y/data.json?z=1"));
        assert!(!allowed(body, "/a/b/c"));
        assert!(!allowed(body, "/a/b/b/c/d"));
        assert!(allowed(body, "/a/c"));
        assert!(allowed(body, "/data.txt"));
    }

    #[test]
    fn v09_dollar_end_anchor() {
        let body = "User-agent: *\nDisallow: /*.php$\n";
        assert!(!allowed(body, "/index.php"));
        assert!(allowed(body, "/index.php?x=1"));
        assert!(allowed(body, "/index.php5"));
        let exact = "User-agent: *\nDisallow: /fish$\n";
        assert!(!allowed(exact, "/fish"));
        assert!(allowed(exact, "/fish/salmon"));
        assert!(allowed(exact, "/fishing"));
    }

    #[test]
    fn v10_rfc_longest_match_example() {
        // RFC 9309 §5.2 style: "/example/page/" is longer than "/example/page/disallowed"? no:
        // Allow /example/page/disallowed.gif vs Disallow /example/page/ — the longer Allow wins.
        let body = "User-agent: *\nAllow: /example/page/disallowed.gif\nDisallow: /example/page/\n";
        assert!(allowed(body, "/example/page/disallowed.gif"));
        assert!(!allowed(body, "/example/page/other.gif"));
    }

    #[test]
    fn v11_specific_group_beats_star_group_and_does_not_fall_back() {
        let body = "User-agent: *\nDisallow: /\n\nUser-agent: crawlx\nDisallow: /admin\n";
        assert!(allowed(body, "/page"));
        assert!(!allowed(body, "/admin/x"));
    }

    #[test]
    fn v12_product_token_is_case_insensitive() {
        let body = "User-Agent: CrawlX\nDisallow: /nope\n";
        assert!(!allowed(body, "/nope"));
        let t = RobotsTxt::parse(body.as_bytes());
        assert!(matches!(t.evaluate("CRAWLX/2", "/nope"), Match::Disallowed(_)));
        assert_eq!(product_token("Crawlx/1.0 (+x)"), "crawlx");
        assert_eq!(product_token("crawlx bot"), "crawlx");
        // a longer token is a different product
        assert!(allowed("User-agent: crawlxbot\nDisallow: /\n", "/x"));
    }

    #[test]
    fn v13_consecutive_user_agents_share_one_group() {
        let body = "User-agent: a\nUser-agent: crawlx\nUser-agent: b\nDisallow: /shared\n";
        assert!(!allowed(body, "/shared"));
    }

    #[test]
    fn v14_duplicate_groups_for_the_same_agent_merge() {
        let body = "User-agent: crawlx\nDisallow: /one\n\nUser-agent: other\nDisallow: /x\n\nUser-agent: crawlx\nDisallow: /two\n";
        assert!(!allowed(body, "/one"));
        assert!(!allowed(body, "/two"));
        assert!(allowed(body, "/three"));
    }

    #[test]
    fn v15_comments_whitespace_crlf_bom_and_case() {
        let body = "\u{feff}USER-AGENT :  *  # everyone\r\nDISALLOW:\t/c # trailing\r\n\r\n# standalone\r\nallow: /c/ok\r\n";
        assert!(!allowed(body, "/c"));
        assert!(allowed(body, "/c/ok"));
        assert!(allowed("User-agent: *\rDisallow: /x\r", "/y"));
        assert!(!allowed("User-agent: *\rDisallow: /x\r", "/x"));
    }

    #[test]
    fn v16_rules_before_any_user_agent_are_ignored() {
        assert!(allowed("Disallow: /\nUser-agent: *\nDisallow: /z\n", "/a"));
    }

    #[test]
    fn v17_query_string_is_part_of_the_match() {
        let body = "User-agent: *\nDisallow: /*?session=\nDisallow: /search?\n";
        assert!(!allowed(body, "/page?session=abc"));
        assert!(!allowed(body, "/search?q=1"));
        assert!(allowed(body, "/search"));
        assert!(allowed(body, "/page?other=1"));
    }

    #[test]
    fn v18_percent_normalization() {
        // unreserved escapes decode, hex case folds, non-ASCII is encoded
        assert!(!allowed("User-agent: *\nDisallow: /a%7eb\n", "/a~b"));
        assert!(!allowed("User-agent: *\nDisallow: /a~b\n", "/a%7Eb"));
        assert!(!allowed("User-agent: *\nDisallow: /caf%c3%a9\n", "/caf%C3%A9"));
        assert!(!allowed("User-agent: *\nDisallow: /café\n", "/caf%C3%A9"));
        // reserved escapes are not decoded: %2F is not a slash
        assert!(allowed("User-agent: *\nDisallow: /a/b\n", "/a%2Fb"));
    }

    #[test]
    fn v19_wildcard_only_and_empty_path() {
        assert!(!allowed("User-agent: *\nDisallow: *\n", "/anything"));
        let t = RobotsTxt::parse(b"User-agent: *\nDisallow: /\n");
        assert!(matches!(t.evaluate(UA, ""), Match::Disallowed(_)));
        assert!(allowed("User-agent: *\nAllow:\n", "/x"));
    }

    #[test]
    fn v20_sitemaps_are_global_and_do_not_break_groups() {
        let body = "Sitemap: https://e.test/a.xml\nUser-agent: crawlx\nSitemap: https://e.test/b.xml\nDisallow: /x\nSitemap: https://e.test/a.xml\n";
        let t = RobotsTxt::parse(body.as_bytes());
        assert_eq!(t.sitemaps(), ["https://e.test/a.xml", "https://e.test/b.xml"]);
        assert!(matches!(t.evaluate(UA, "/x"), Match::Disallowed(_)));
    }

    #[test]
    fn v21_crawl_delay_is_a_capped_hint() {
        let t = RobotsTxt::parse(b"User-agent: crawlx\nCrawl-delay: 2.5\n\nUser-agent: *\nCrawl-delay: 99\n");
        assert_eq!(t.crawl_delay(UA), Some(Duration::from_millis(2500)));
        assert_eq!(t.crawl_delay("otherbot"), Some(MAX_CRAWL_DELAY));
        assert_eq!(
            RobotsTxt::parse(b"User-agent: *\nCrawl-delay: abc\n").crawl_delay(UA),
            None
        );
        assert_eq!(
            RobotsTxt::parse(b"User-agent: *\nCrawl-delay: -3\n").crawl_delay(UA),
            None
        );
        assert_eq!(RobotsTxt::parse(b"").crawl_delay(UA), None);
    }

    #[test]
    fn v22_size_limit_truncates_and_drops_partial_line() {
        let mut body = String::from("User-agent: *\nDisallow: /early\n");
        let filler = "# filler line\n";
        while body.len() < MAX_ROBOTS_BYTES - 20 {
            body.push_str(filler);
        }
        // straddles the limit: a rule cut in half must not apply as its prefix
        body.push_str("Disallow: /straddling-the-limit-rule\n");
        body.push_str("Disallow: /late\n");
        let t = RobotsTxt::parse(body.as_bytes());
        assert!(t.truncated());
        assert!(matches!(t.evaluate(UA, "/early"), Match::Disallowed(_)));
        assert_eq!(t.evaluate(UA, "/late"), Match::Allowed);
        assert_eq!(t.evaluate(UA, "/straddling"), Match::Allowed);
        // exactly at the limit is not truncated
        let exact = format!(
            "User-agent: *\nDisallow: /x\n{}",
            "#".repeat(MAX_ROBOTS_BYTES - 27)
        );
        assert_eq!(exact.len(), MAX_ROBOTS_BYTES);
        assert!(!RobotsTxt::parse(exact.as_bytes()).truncated());
    }

    #[test]
    fn v23_invalid_utf8_is_tolerated() {
        let mut body = b"User-agent: *\nDisallow: /bad".to_vec();
        body.extend_from_slice(&[0xff, 0xfe]);
        body.extend_from_slice(b"\nDisallow: /ok\n");
        let t = RobotsTxt::parse(&body);
        assert!(matches!(t.evaluate(UA, "/ok"), Match::Disallowed(_)));
    }

    #[test]
    fn matcher_unit_cases() {
        for (pat, path, want) in [
            ("/", "/a", true),
            ("/a", "/a", true),
            ("/a", "/", false),
            ("/a$", "/a", true),
            ("/a$", "/ab", false),
            ("/*", "/", true),
            ("/a*b", "/axxb", true),
            ("/a*b", "/axx", false),
            ("/a*b$", "/axxbc", false),
            ("/a*b$", "/axxb", true),
            ("/a*b*c$", "/abc", true),
            ("/a*b*c$", "/abcx", false),
            ("/ab*b$", "/ab", false),
            ("*.gif", "/x.gif", true),
            ("$", "/", false),
        ] {
            assert_eq!(
                pattern_matches(pat.as_bytes(), path.as_bytes()),
                want,
                "{pat} vs {path}"
            );
        }
    }

    fn cache() -> (RobotsCache, ManualClock) {
        let clock = ManualClock::new(chrono::Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap());
        (RobotsCache::new(Arc::new(clock.clone())), clock)
    }

    const ORIGIN: &str = "https://example.test";

    #[test]
    fn cache_unknown_until_fetched() {
        let (c, clock) = cache();
        assert_eq!(c.evaluate(ORIGIN, "/"), RobotsVerdict::Unknown);
        assert!(c.needs_refetch(ORIGIN, clock.now()));
    }

    #[test]
    fn cache_2xx_parses_and_evaluates() {
        let (mut c, clock) = cache();
        c.record_fetch(
            ORIGIN,
            FetchStatus::Ok(
                b"User-agent: *\nDisallow: /private\nSitemap: https://example.test/s.xml\nCrawl-delay: 3\n"
                    .to_vec(),
            ),
        );
        assert_eq!(c.evaluate(ORIGIN, "/public"), RobotsVerdict::Allowed);
        match c.evaluate(ORIGIN, "/private/x") {
            RobotsVerdict::Disallowed(DisallowedBy::Rule(r)) => assert_eq!(r.pattern, "/private"),
            other => panic!("{other:?}"),
        }
        assert_eq!(c.sitemaps(ORIGIN), ["https://example.test/s.xml"]);
        assert_eq!(c.crawl_delay(ORIGIN), Some(Duration::from_secs(3)));
        assert!(!c.needs_refetch(ORIGIN, clock.now()));
        // origin keys are case- and trailing-slash-insensitive
        assert_eq!(
            c.evaluate("HTTPS://Example.test/", "/public"),
            RobotsVerdict::Allowed
        );
    }

    #[test]
    fn cache_4xx_allows_all() {
        let (mut c, _) = cache();
        c.record_fetch(ORIGIN, FetchStatus::Status4xx);
        assert_eq!(c.evaluate(ORIGIN, "/anything"), RobotsVerdict::Allowed);
        c.record_fetch("https://redir.test", FetchStatus::TooManyRedirects);
        assert_eq!(c.evaluate("https://redir.test", "/x"), RobotsVerdict::Allowed);
    }

    #[test]
    fn cache_5xx_temporarily_disallows_with_backoff() {
        let (mut c, clock) = cache();
        let start = clock.now();
        c.record_fetch(ORIGIN, FetchStatus::Status5xx);
        let first = match c.evaluate(ORIGIN, "/x") {
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { retry_at, give_up }) => {
                assert!(!give_up);
                retry_at
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(first, start + ChronoDuration::seconds(60));
        assert!(!c.needs_refetch(ORIGIN, start + ChronoDuration::seconds(59)));
        assert!(c.needs_refetch(ORIGIN, first));
        // second consecutive failure doubles the delay from the new attempt time
        clock.advance_ms(60_000);
        c.record_fetch(ORIGIN, FetchStatus::Unreachable);
        match c.evaluate(ORIGIN, "/x") {
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { retry_at, .. }) => {
                assert_eq!(retry_at, clock.now() + ChronoDuration::seconds(120));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cache_backoff_is_capped_and_gives_up_after_24h() {
        let (mut c, clock) = cache();
        for _ in 0..30 {
            c.record_fetch(ORIGIN, FetchStatus::Status5xx);
            clock.advance_ms(1000);
        }
        match c.evaluate(ORIGIN, "/x") {
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { retry_at, give_up }) => {
                assert!(!give_up);
                assert!(retry_at - clock.now() <= ChronoDuration::seconds(3600));
            }
            other => panic!("{other:?}"),
        }
        clock.advance_ms(24 * 3600 * 1000);
        match c.evaluate(ORIGIN, "/x") {
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { give_up, .. }) => assert!(give_up),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cache_recovery_replaces_unreachable_entry() {
        let (mut c, _) = cache();
        c.record_fetch(ORIGIN, FetchStatus::Status5xx);
        c.record_fetch(ORIGIN, FetchStatus::Ok(b"User-agent: *\nDisallow: /a\n".to_vec()));
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Allowed);
        // a later outage starts a fresh give-up clock
        c.record_fetch(ORIGIN, FetchStatus::Status5xx);
        assert!(matches!(
            c.evaluate(ORIGIN, "/b"),
            RobotsVerdict::Disallowed(DisallowedBy::Unreachable { give_up: false, .. })
        ));
    }

    #[test]
    fn cache_ttl_expiry_and_max_age() {
        let (mut c, clock) = cache();
        c.record_fetch(ORIGIN, FetchStatus::Ok(b"User-agent: *\nDisallow: /a\n".to_vec()));
        clock.advance_ms(24 * 3600 * 1000 - 1);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Allowed);
        assert!(!c.needs_refetch(ORIGIN, clock.now()));
        clock.advance_ms(1);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Unknown);
        assert!(c.needs_refetch(ORIGIN, clock.now()));

        // Cache-Control max-age shortens the TTL but never exceeds 24 h or drops under the floor
        c.record_fetch_with(ORIGIN, FetchStatus::Status4xx, Some(Duration::from_secs(600)));
        clock.advance_ms(599_000);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Allowed);
        clock.advance_ms(1_000);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Unknown);
        c.record_fetch_with(
            ORIGIN,
            FetchStatus::Status4xx,
            Some(Duration::from_secs(10 * 24 * 3600)),
        );
        clock.advance_ms(24 * 3600 * 1000);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Unknown);
        c.record_fetch_with(ORIGIN, FetchStatus::Status4xx, Some(Duration::ZERO));
        clock.advance_ms(30_000);
        assert_eq!(c.evaluate(ORIGIN, "/b"), RobotsVerdict::Allowed);
    }

    #[test]
    fn cache_uses_configured_user_agent() {
        let clock = ManualClock::new(chrono::Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap());
        let cfg = RobotsConfig {
            user_agent: "mybot/2.0".to_owned(),
            ..RobotsConfig::default()
        };
        let mut c = RobotsCache::with_config(Arc::new(clock), cfg);
        c.record_fetch(
            ORIGIN,
            FetchStatus::Ok(b"User-agent: mybot\nDisallow: /m\n\nUser-agent: *\nDisallow: /star\n".to_vec()),
        );
        assert!(matches!(c.evaluate(ORIGIN, "/m"), RobotsVerdict::Disallowed(_)));
        assert_eq!(c.evaluate(ORIGIN, "/star"), RobotsVerdict::Allowed);
        assert_eq!(c.user_agent(), "mybot/2.0");
        c.invalidate(ORIGIN);
        assert_eq!(c.evaluate(ORIGIN, "/m"), RobotsVerdict::Unknown);
    }

    #[test]
    fn an_alias_token_selects_its_group_next_to_the_own_token() {
        let body = "User-agent: FirecrawlAgent\nDisallow: /fc\n\nUser-agent: crawlx\nDisallow: /own\n\nUser-agent: *\nDisallow: /star\n";
        let t = RobotsTxt::parse(body.as_bytes());
        let alias = ["firecrawlagent".to_owned()];
        // without the alias the `*` group applies only when no group names the token
        assert!(matches!(t.evaluate("crawlx", "/fc"), Match::Allowed));
        // with it both named groups apply and `*` does not
        assert!(matches!(
            t.evaluate_as("crawlx", &alias, "/fc"),
            Match::Disallowed(_)
        ));
        assert!(matches!(
            t.evaluate_as("crawlx", &alias, "/own"),
            Match::Disallowed(_)
        ));
        assert!(matches!(t.evaluate_as("crawlx", &alias, "/star"), Match::Allowed));
        // an alias alone is enough when the robots.txt only names it
        let only = RobotsTxt::parse(b"User-agent: FirecrawlAgent\nDisallow: /fc\nCrawl-delay: 3\n");
        assert!(matches!(
            only.evaluate_as("crawlx", &alias, "/fc"),
            Match::Disallowed(_)
        ));
        assert_eq!(
            only.crawl_delay_as("crawlx", &alias),
            Some(Duration::from_secs(3))
        );
        assert_eq!(only.crawl_delay("crawlx"), None);
    }

    #[test]
    fn the_cache_applies_configured_aliases() {
        let clock = ManualClock::new(chrono::Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap());
        let cfg = RobotsConfig {
            aliases: vec!["firecrawlagent".to_owned()],
            ..RobotsConfig::default()
        };
        let mut c = RobotsCache::with_config(Arc::new(clock), cfg);
        c.record_fetch(
            ORIGIN,
            FetchStatus::Ok(b"User-agent: FirecrawlAgent\nDisallow: /fc\n".to_vec()),
        );
        assert!(matches!(c.evaluate(ORIGIN, "/fc"), RobotsVerdict::Disallowed(_)));
        assert_eq!(c.evaluate(ORIGIN, "/ok"), RobotsVerdict::Allowed);
    }
}
