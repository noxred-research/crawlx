//! The gym access log as the "requested set" observable: what the fixture
//! server saw each system ask for, as opposed to what each system reports having attempted.
//!
//! The gym ledger (`/__gym/ledger`, [`crate::gym::ledger::Ledger`]) records every request that
//! reaches a fixture with method, path, query and the `Host` header. A fresh gym serves one
//! system, so the rows of one run are the requests of one system. `robots.txt`, sitemaps, the
//! gym beacons and favicons are not page requests and are left out of the requested set, as
//! the requested-set comparison requires.

use super::normalize::url_key;
use crate::gym::ledger::{LedgerEntry, LedgerEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

/// One request the gym saw.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccessEntry {
    /// Upper-case HTTP method.
    pub method: String,
    /// Request path without query.
    pub path: String,
    /// Raw query string without `?`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// `Host` header (`app.gym.test:4101`); `None` when the request carried none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// The requests one gym run served, in arrival order.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct AccessLog {
    /// Rows.
    #[serde(default)]
    pub entries: Vec<AccessEntry>,
}

/// Is this path a page request? `robots.txt`, sitemaps, gym beacons and favicons are not.
fn is_page_request(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or_default().to_ascii_lowercase();
    !(path == "/robots.txt"
        || path.starts_with("/__gym/")
        || last == "favicon.ico"
        || (last.contains("sitemap") && (last.ends_with(".xml") || last.ends_with(".xml.gz"))))
}

impl AccessLog {
    /// Rows from the ledger of an in-process gym (`GymHandle::ledger().entries()`): the `op`
    /// rows only.
    #[must_use]
    pub fn from_ledger(entries: &[LedgerEntry]) -> Self {
        Self {
            entries: entries
                .iter()
                .filter_map(|e| match &e.event {
                    LedgerEvent::Op {
                        method,
                        path,
                        query,
                        host,
                    } => Some(AccessEntry {
                        method: method.clone(),
                        path: path.clone(),
                        query: query.clone(),
                        host: host.clone(),
                    }),
                    _ => None,
                })
                .collect(),
        }
    }

    /// Rows from a `/__gym/ledger` response body (`{"count": N, "entries": [...]}`): the rows
    /// of kind `op`; other rows and unknown fields are ignored.
    #[must_use]
    pub fn from_gym_json(body: &serde_json::Value) -> Self {
        let entries = body
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter(|r| r.get("kind").and_then(serde_json::Value::as_str) == Some("op"))
                    .filter_map(|r| {
                        Some(AccessEntry {
                            method: r.get("method")?.as_str()?.to_owned(),
                            path: r.get("path")?.as_str()?.to_owned(),
                            query: r
                                .get("query")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_owned),
                            host: r
                                .get("host")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_owned),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { entries }
    }

    /// The page requests as `URL key -> number of requests` (every method), keys as
    /// [`url_key`] builds them against `origin`, the origin the run crawled. A row without a
    /// `Host` header counts for `origin`.
    #[must_use]
    pub fn requested(&self, origin: &Url, keep_query: bool) -> BTreeMap<String, u32> {
        let mut out: BTreeMap<String, u32> = BTreeMap::new();
        let authority = match origin.port() {
            Some(p) => format!("{}:{p}", origin.host_str().unwrap_or_default()),
            None => origin.host_str().unwrap_or_default().to_owned(),
        };
        for e in self.entries.iter().filter(|e| is_page_request(&e.path)) {
            let host = e.host.as_deref().unwrap_or(&authority);
            let mut raw = format!("{}://{host}{}", origin.scheme(), e.path);
            if let Some(q) = e.query.as_deref().filter(|q| !q.is_empty()) {
                raw.push('?');
                raw.push_str(q);
            }
            let slot = out.entry(url_key(&raw, origin, keep_query)).or_default();
            *slot = slot.saturating_add(1);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn entry(method: &str, path: &str, query: Option<&str>, host: Option<&str>) -> AccessEntry {
        AccessEntry {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.map(str::to_owned),
            host: host.map(str::to_owned),
        }
    }

    #[test]
    fn page_requests_are_keyed_against_the_crawl_origin_and_counted() {
        let log = AccessLog {
            entries: vec![
                entry("GET", "/robots.txt", None, Some("gym.test:4101")),
                entry("GET", "/s1/sitemap.xml", None, Some("gym.test:4101")),
                entry("GET", "/s1/", None, Some("gym.test:4101")),
                entry("GET", "/s1/about/", None, Some("gym.test:4101")),
                entry("GET", "/s1/about", None, Some("gym.test:4101")),
                entry("GET", "/d2/scope/sub", Some("b=2&a=1"), Some("app.gym.test:4101")),
                entry("POST", "/__gym/click", None, Some("gym.test:4101")),
                entry("GET", "/s1/x", None, None),
            ],
        };
        let origin = Url::parse("http://gym.test:4101").unwrap();
        let keys = log.requested(&origin, true);
        assert_eq!(keys.get("{origin}/s1"), Some(&1));
        assert_eq!(
            keys.get("{origin}/s1/about"),
            Some(&2),
            "slash variants share a key"
        );
        assert_eq!(
            keys.get("http://app.gym.test:{port}/d2/scope/sub?a=1&b=2"),
            Some(&1),
            "{keys:?}"
        );
        assert_eq!(
            keys.get("{origin}/s1/x"),
            Some(&1),
            "no Host header counts for the origin"
        );
        assert!(keys
            .keys()
            .all(|k| !k.contains("robots") && !k.contains("sitemap") && !k.contains("__gym")));
        // the same run seen on another port keys identically
        let other = Url::parse("http://gym.test:41233").unwrap();
        let moved = AccessLog {
            entries: log
                .entries
                .iter()
                .map(|e| AccessEntry {
                    host: e.host.as_ref().map(|h| h.replace(":4101", ":41233")),
                    ..e.clone()
                })
                .collect(),
        };
        assert_eq!(moved.requested(&other, true), keys);
    }

    #[test]
    fn gym_ledger_json_yields_op_rows_only() {
        let body = serde_json::json!({"count": 3, "entries": [
            {"seq": 1, "at": "x", "fixture": "s1", "kind": "op", "method": "GET", "path": "/s1/", "host": "gym.test:1"},
            {"seq": 2, "at": "x", "fixture": "g01", "kind": "click", "control": "c", "trusted": true},
            {"seq": 3, "at": "x", "fixture": "s1", "kind": "op", "method": "GET", "path": "/s1/a", "query": "q=1"},
        ]});
        let log = AccessLog::from_gym_json(&body);
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].host.as_deref(), Some("gym.test:1"));
        assert_eq!(log.entries[1].query.as_deref(), Some("q=1"));
    }
}
