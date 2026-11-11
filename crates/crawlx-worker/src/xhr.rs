//! Browser-plane XHR and `fetch()` requests attached to page records (`extract.xhr`, the
//! `-xhr-extraction` compatibility flag, `xhr_requests` of the JSONL record).
//!
//! The exploration driver drains the requests every page of its session issued
//! ([`crawlx_core::BrowserContext::drain_xhr`]) into the run's [`XhrSink`], keyed by the
//! canonical URL of the issuing page. The page records themselves are written by the URL plane,
//! possibly after the browser saw the page, so the sink does not write them when it receives
//! the requests: [`XhrSink::apply`] runs once the planes are done and merges the collected
//! requests into the matching records' `metadata.xhr_requests`.
//!
//! `metadata.xhr_requests` is an array of `{method, url, resource_type, status?,
//! endpoint_class}` objects sorted by `(method, url)` (a request seen twice keeps its last
//! status): `resource_type` is `xhr` or `fetch`, `status` is the response status when one arrived
//! and `endpoint_class` is the traffic classifier's family (`rest`, `graphql`, `soap`, `xhr`,
//! `static`). Request URLs are redacted like every captured URL. Dynamic-only runs publish
//! settled browser DOM pages through the URL-plane output lane, so the same merge attaches
//! their requests without another HTTP acquisition.

use crawlx_core::dom_ops::XhrRecord;
use crawlx_core::hash::Digest;
use crawlx_core::repo::PageRepo;
use crawlx_core::{CrawlRunId, StoreError};
use crawlx_observe::network::classify_endpoint;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What the browser saw of one request.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Seen {
    status: Option<u16>,
    resource_type: String,
    content_type: Option<String>,
}

/// Requests of one page by `(method, url)`.
type PageRequests = BTreeMap<(String, String), Seen>;

/// Collects the XHR/fetch requests of the run's browser sessions; cheap to clone (shared).
#[derive(Clone, Default)]
pub struct XhrSink {
    pages: Arc<Mutex<BTreeMap<Digest, PageRequests>>>,
}

impl std::fmt::Debug for XhrSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhrSink")
            .field("pages", &self.pages.lock().len())
            .finish()
    }
}

impl XhrSink {
    /// Add `records`, each filed under the canonical form (per `canon`) of the page that issued
    /// it. A record whose page URL does not parse is dropped.
    pub fn record(&self, records: Vec<XhrRecord>, canon: &CanonicalizeOptions) {
        if records.is_empty() {
            return;
        }
        let mut pages = self.pages.lock();
        for r in records {
            let Some(key) = url::Url::parse(&r.page_url)
                .ok()
                .and_then(|u| Canonicalizer::canonicalize_url(&u, canon).ok())
                .map(|c| c.key)
            else {
                continue;
            };
            pages.entry(key).or_default().insert(
                (r.method, r.url),
                Seen {
                    status: r.status,
                    resource_type: r.resource_type,
                    content_type: r.content_type,
                },
            );
        }
    }

    /// The `xhr_requests` array of the page with canonical key `page`; empty when the browser
    /// saw no request of it.
    #[must_use]
    pub fn requests_for(&self, page: &Digest) -> Vec<Value> {
        self.pages
            .lock()
            .get(page)
            .map(|requests| {
                requests
                    .iter()
                    .map(|((method, url), seen)| entry(method, url, seen))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge the collected requests into `metadata.xhr_requests` of every stored page of `run`
    /// that the browser issued requests from, and return how many records changed. Idempotent:
    /// a record that already holds exactly these requests is not written again.
    /// Immutable browser renditions with an explicit late-attribution-unavailable marker retain
    /// their committed snapshot; a URL-wide aggregate must not replace their canonical projection.
    ///
    /// # Errors
    /// [`StoreError`] when pages cannot be listed or a record cannot be stored.
    pub async fn apply(&self, pages: &dyn PageRepo, run: CrawlRunId) -> Result<usize, StoreError> {
        if self.pages.lock().is_empty() {
            return Ok(0);
        }
        let mut changed = 0;
        for mut page in pages.list(run).await? {
            if page.metadata.get("late_xhr_attribution").and_then(Value::as_str)
                == Some("late_xhr_not_epoch_attributed")
            {
                continue;
            }
            let requests = self.requests_for(&page.url.key);
            if requests.is_empty() {
                continue;
            }
            let value = Value::Array(requests);
            if !page.metadata.is_object() {
                page.metadata = json!({});
            }
            if page.metadata.get("xhr_requests") == Some(&value) {
                continue;
            }
            page.metadata["xhr_requests"] = value;
            pages.put(&page).await?;
            changed += 1;
        }
        Ok(changed)
    }
}

/// One `xhr_requests` element.
fn entry(method: &str, url: &str, seen: &Seen) -> Value {
    let class = classify_endpoint(method, url, seen.content_type.as_deref(), &[]);
    let mut v = json!({
        "method": method,
        "url": url,
        "resource_type": seen.resource_type,
        "endpoint_class": class.as_str(),
    });
    if let Some(status) = seen.status {
        v["status"] = json!(status);
    }
    v
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn record(page: &str, method: &str, url: &str, status: Option<u16>) -> XhrRecord {
        XhrRecord {
            page_url: page.to_owned(),
            method: method.to_owned(),
            url: url.to_owned(),
            status,
            resource_type: "xhr".to_owned(),
            content_type: Some("application/json".to_owned()),
        }
    }

    fn key(url: &str) -> Digest {
        Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default())
            .unwrap()
            .key
    }

    #[test]
    fn requests_are_filed_per_canonical_page_sorted_and_deduplicated() {
        let sink = XhrSink::default();
        let canon = CanonicalizeOptions::default();
        sink.record(
            vec![
                record(
                    "http://a.test/page#frag",
                    "POST",
                    "http://a.test/api/save",
                    Some(500),
                ),
                record("http://a.test/page", "GET", "http://a.test/api/list", Some(200)),
                record("http://a.test/page", "POST", "http://a.test/api/save", Some(201)),
                record("http://a.test/other", "GET", "http://a.test/api/other", None),
                record("not a url", "GET", "http://a.test/api/x", Some(200)),
            ],
            &canon,
        );
        let page = sink.requests_for(&key("http://a.test/page"));
        assert_eq!(
            page,
            [
                json!({"method":"GET","url":"http://a.test/api/list","resource_type":"xhr","endpoint_class":"rest","status":200}),
                json!({"method":"POST","url":"http://a.test/api/save","resource_type":"xhr","endpoint_class":"rest","status":201}),
            ],
            "sorted by (method, url); the later status of a repeated request wins"
        );
        let other = sink.requests_for(&key("http://a.test/other"));
        assert_eq!(other.len(), 1);
        assert!(other[0].get("status").is_none(), "no response, no status");
        assert!(sink.requests_for(&key("http://a.test/none")).is_empty());
    }
}
