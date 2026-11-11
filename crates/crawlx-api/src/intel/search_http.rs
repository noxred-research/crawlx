//! HTTP plumbing of the search providers: one GET with a deadline and a response-size cap,
//! the result post-filters (domains, categories) and the `tbs` time-range parser.

use crate::intel::search::{SearchCategory, SearchError};
use serde_json::Value;
use std::time::Duration;

/// Largest provider reply read, bytes.
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// Send `request` and parse a JSON reply, at most `max_bytes` long, within `timeout`.
///
/// # Errors
/// [`SearchError::Timeout`], [`SearchError::Transport`] (connect/TLS/body failures),
/// [`SearchError::Status`] for a non-2xx status and [`SearchError::InvalidReply`] for a reply that
/// is oversize or not JSON.
#[allow(
    clippy::disallowed_types,
    reason = "bounded search reply reader takes the raw reqwest request builder"
)]
pub async fn get_json(
    request: reqwest::RequestBuilder,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Value, SearchError> {
    let after_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let fetch = async {
        let mut resp = request.send().await.map_err(|e| map_reqwest(e, after_ms))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(SearchError::Status {
                status: status.as_u16(),
            });
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| map_reqwest(e, after_ms))? {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(SearchError::InvalidReply(format!(
                    "reply exceeds {max_bytes} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<Value>(&body).map_err(|e| SearchError::InvalidReply(e.to_string()))
    };
    match tokio::time::timeout(timeout, fetch).await {
        Ok(r) => r,
        Err(_) => Err(SearchError::Timeout { after_ms }),
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "search transport error translation consumes the raw reqwest error"
)]
fn map_reqwest(e: reqwest::Error, after_ms: u64) -> SearchError {
    if e.is_timeout() {
        SearchError::Timeout { after_ms }
    } else {
        // `without_url` keeps credentials in query strings out of the message.
        SearchError::Transport(e.without_url().to_string())
    }
}

/// Coarse time range of a compat `tbs` value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeRange {
    /// `qdr:h`.
    Hour,
    /// `qdr:d`.
    Day,
    /// `qdr:w`.
    Week,
    /// `qdr:m`.
    Month,
    /// `qdr:y`.
    Year,
}

/// Parse `tbs`: `Ok(Some(range))` for `qdr:h|d|w|m|y`, `Ok(None)` when empty.
///
/// # Errors
/// The unsupported form (`cdr:` custom ranges, `sbd:` sorting, anything else) as text for a warning.
pub fn parse_tbs(tbs: Option<&str>) -> Result<Option<TimeRange>, String> {
    let Some(t) = tbs.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    match t.split(',').next().unwrap_or(t) {
        "qdr:h" => Ok(Some(TimeRange::Hour)),
        "qdr:d" => Ok(Some(TimeRange::Day)),
        "qdr:w" => Ok(Some(TimeRange::Week)),
        "qdr:m" => Ok(Some(TimeRange::Month)),
        "qdr:y" => Ok(Some(TimeRange::Year)),
        other => Err(format!(
            "tbs value {other:?} is not supported by this search backend; ignored"
        )),
    }
}

/// Host of `url` lowercased, `None` when `url` is not an absolute http(s) URL.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.host_str().map(str::to_ascii_lowercase)
}

/// Whether `host` equals `domain` or is a subdomain of it (`domain` may carry a leading dot).
#[must_use]
pub fn host_matches(host: &str, domain: &str) -> bool {
    let d = domain.trim().trim_start_matches('.').to_ascii_lowercase();
    !d.is_empty() && (host == d || host.ends_with(&format!(".{d}")))
}

/// Suffixes of government hosts the `gov` category keeps.
pub const GOV_SUFFIXES: [&str; 9] = [
    "gov",
    "mil",
    "gov.uk",
    "gc.ca",
    "gov.au",
    "europa.eu",
    "gouv.fr",
    "bund.de",
    "go.jp",
];

/// Whether a result with `url` passes the domain filters and categories of a query.
#[must_use]
pub fn url_allowed(url: &str, include: &[String], exclude: &[String], categories: &[SearchCategory]) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if !include.is_empty() && !include.iter().any(|d| host_matches(&host, d)) {
        return false;
    }
    if exclude.iter().any(|d| host_matches(&host, d)) {
        return false;
    }
    if categories.contains(&SearchCategory::Gov) && !GOV_SUFFIXES.iter().any(|s| host_matches(&host, s)) {
        return false;
    }
    if categories.contains(&SearchCategory::Pdf) {
        let path = url::Url::parse(url)
            .map(|u| u.path().to_ascii_lowercase())
            .unwrap_or_default();
        if !std::path::Path::new(&path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
        {
            return false;
        }
    }
    true
}

/// `query` with the `site:` operators of the domain filters and categories appended, so the
/// backend narrows at the source (results are still post-filtered with [`url_allowed`]).
#[must_use]
pub fn decorate_query(
    query: &str,
    include: &[String],
    exclude: &[String],
    categories: &[SearchCategory],
) -> String {
    let mut q = query.trim().to_owned();
    if !include.is_empty() {
        let sites: Vec<String> = include.iter().map(|d| format!("site:{d}")).collect();
        q.push_str(&format!(" ({})", sites.join(" OR ")));
    }
    for d in exclude {
        q.push_str(&format!(" -site:{d}"));
    }
    if categories.contains(&SearchCategory::Gov) && include.is_empty() {
        q.push_str(" (site:gov OR site:mil)");
    }
    if categories.contains(&SearchCategory::Pdf) {
        q.push_str(" filetype:pdf");
    }
    q
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn tbs_parses_known_ranges_and_rejects_custom() {
        assert_eq!(parse_tbs(Some("qdr:w")).unwrap(), Some(TimeRange::Week));
        assert_eq!(parse_tbs(Some("qdr:h,sbd:1")).unwrap(), Some(TimeRange::Hour));
        assert_eq!(parse_tbs(None).unwrap(), None);
        assert_eq!(parse_tbs(Some(" ")).unwrap(), None);
        assert!(parse_tbs(Some("cdr:1,cd_min:1/1/2020,cd_max:2/1/2020")).is_err());
    }

    #[test]
    fn domain_filters_match_subdomains_only_on_label_boundary() {
        assert!(host_matches("docs.rust-lang.org", "rust-lang.org"));
        assert!(host_matches("rust-lang.org", ".rust-lang.org"));
        assert!(!host_matches("evilrust-lang.org", "rust-lang.org"));
        let inc = vec!["rust-lang.org".to_owned()];
        let exc = vec!["users.rust-lang.org".to_owned()];
        assert!(url_allowed("https://doc.rust-lang.org/x", &inc, &exc, &[]));
        assert!(!url_allowed("https://users.rust-lang.org/x", &inc, &exc, &[]));
        assert!(!url_allowed("https://example.com/x", &inc, &exc, &[]));
        assert!(!url_allowed("javascript:alert(1)", &[], &[], &[]));
    }

    #[test]
    fn categories_filter_results() {
        assert!(url_allowed(
            "https://www.irs.gov/a",
            &[],
            &[],
            &[SearchCategory::Gov]
        ));
        assert!(!url_allowed(
            "https://example.com/a",
            &[],
            &[],
            &[SearchCategory::Gov]
        ));
        assert!(url_allowed(
            "https://a.org/x.PDF",
            &[],
            &[],
            &[SearchCategory::Pdf]
        ));
        assert!(!url_allowed(
            "https://a.org/x.html",
            &[],
            &[],
            &[SearchCategory::Pdf]
        ));
    }

    #[test]
    fn query_gets_site_operators() {
        let q = decorate_query("rust", &["a.com".into(), "b.com".into()], &["c.com".into()], &[]);
        assert_eq!(q, "rust (site:a.com OR site:b.com) -site:c.com");
        assert!(decorate_query("x", &[], &[], &[SearchCategory::Pdf]).ends_with("filetype:pdf"));
    }
}
