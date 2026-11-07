//! Traffic redaction and third-party marking.
//!
//! Redaction runs here, before an event leaves the observer: credential
//! headers keep their names and lose their values, `Session`-class query
//! parameters are dropped from the stored URL, and a keyed BLAKE3 hash of every
//! removed value is retained so two events carrying the same secret can still
//! be correlated within a run (a per-run key defeats dictionary matching).

use crawlx_core::hash::Digest;
use crawlx_core::traffic::{TrafficEvent, REDACTED_PLACEHOLDER};
use crawlx_core::url::{ParamClass, RouteTemplate};
use crawlx_url::{ParamClassifier, ParamObservation, RouteTemplater};
use std::net::IpAddr;
use std::sync::Arc;

/// Domain tag of the correlation hash.
pub const REDACTION_DOMAIN: &str = "crawlx/redacted-value/v1";

/// Header names whose values are always redacted (lower-case).
pub const DENIED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
];

/// Where a removed value was found.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum SecretLocation {
    /// A request header whose name is listed in [`DENIED_HEADERS`].
    RequestHeader,
    /// A response header whose name is listed in [`DENIED_HEADERS`].
    ResponseHeader,
    /// A `Session`-class or JWT-shaped query parameter (or the whole query of an unparsable URL).
    QueryParam,
    /// The `user:password@` part of the URL authority.
    UrlUserinfo,
}

/// A value removed from an event, with its keyed correlation hash.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RemovedSecret {
    /// Where in the event the value was found.
    pub location: SecretLocation,
    /// Header or parameter name (empty for userinfo).
    pub name: String,
    /// Keyed BLAKE3 hash of the removed value under [`REDACTION_DOMAIN`]; equal secrets hash equally within one run.
    pub hash: Digest,
}

/// Redacts [`TrafficEvent`]s.
#[derive(Clone, Debug)]
pub struct Redactor {
    key: [u8; 32],
    classifier: Arc<ParamClassifier>,
    templater: RouteTemplater,
    page_origin: Option<String>,
}

impl Redactor {
    /// `key` is the per-run correlation key.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            classifier: Arc::new(ParamClassifier::default()),
            templater: RouteTemplater::new(),
            page_origin: None,
        }
    }

    /// Use the crawl's classifier (per-crawl overrides, learned session parameters).
    #[must_use]
    pub fn with_classifier(mut self, classifier: Arc<ParamClassifier>) -> Self {
        self.classifier = classifier;
        self
    }

    /// Use the crawl's route templater when classifying parameters per route.
    #[must_use]
    pub fn with_templater(mut self, templater: RouteTemplater) -> Self {
        self.templater = templater;
        self
    }

    /// Origin of the page the traffic belongs to; enables `third_party` marking.
    #[must_use]
    pub fn with_page_origin(mut self, origin: impl Into<String>) -> Self {
        self.page_origin = Some(origin.into());
        self
    }

    /// Update the page origin (after a main-frame navigation).
    pub fn set_page_origin(&mut self, origin: impl Into<String>) {
        self.page_origin = Some(origin.into());
    }

    fn hash(&self, value: &str) -> Digest {
        Digest::keyed(&self.key, REDACTION_DOMAIN, value.as_bytes())
    }

    /// Redact `ev` using the configured page origin.
    #[must_use]
    pub fn redact(&self, ev: TrafficEvent) -> TrafficEvent {
        self.redact_with_report(ev).0
    }

    /// Redact `ev` and report every removed value with its correlation hash.
    #[must_use]
    pub fn redact_with_report(&self, ev: TrafficEvent) -> (TrafficEvent, Vec<RemovedSecret>) {
        self.redact_inner(ev, self.page_origin.as_deref())
    }

    /// Redact `ev` against an explicit page origin.
    #[must_use]
    pub fn redact_with_origin(
        &self,
        ev: TrafficEvent,
        page_origin: &str,
    ) -> (TrafficEvent, Vec<RemovedSecret>) {
        self.redact_inner(ev, Some(page_origin))
    }

    fn redact_inner(
        &self,
        mut ev: TrafficEvent,
        page_origin: Option<&str>,
    ) -> (TrafficEvent, Vec<RemovedSecret>) {
        let mut removed = Vec::new();
        if let Some(origin) = page_origin {
            ev.third_party = is_third_party(origin, &ev.url);
        }
        ev.url = self.redact_url(&ev.url, &mut removed);
        self.redact_headers(
            &mut ev.request_headers,
            SecretLocation::RequestHeader,
            &mut removed,
        );
        self.redact_headers(
            &mut ev.response_headers,
            SecretLocation::ResponseHeader,
            &mut removed,
        );
        removed.sort();
        removed.dedup();
        (ev, removed)
    }

    fn redact_headers(
        &self,
        headers: &mut [(String, String)],
        location: SecretLocation,
        removed: &mut Vec<RemovedSecret>,
    ) {
        for (name, value) in headers.iter_mut() {
            let lower = name.to_ascii_lowercase();
            if !DENIED_HEADERS.contains(&lower.as_str()) || value == REDACTED_PLACEHOLDER {
                // a value a capture task already replaced carries nothing to hash
                continue;
            }
            let hash = self.hash(value);
            *value = format!("[redacted:{}]", &hash.to_hex()[..16]);
            removed.push(RemovedSecret {
                location,
                name: lower,
                hash,
            });
        }
    }

    fn redact_url(&self, raw: &str, removed: &mut Vec<RemovedSecret>) -> String {
        let Ok(mut url) = url::Url::parse(raw) else {
            // Unparseable: keep nothing that could be a secret.
            return match raw.split_once('?') {
                Some((head, query)) => {
                    removed.push(RemovedSecret {
                        location: SecretLocation::QueryParam,
                        name: String::new(),
                        hash: self.hash(query),
                    });
                    head.to_owned()
                }
                None => raw.to_owned(),
            };
        };
        if !url.username().is_empty() || url.password().is_some() {
            let userinfo = format!("{}:{}", url.username(), url.password().unwrap_or(""));
            removed.push(RemovedSecret {
                location: SecretLocation::UrlUserinfo,
                name: String::new(),
                hash: self.hash(&userinfo),
            });
            let _ = url.set_username("");
            let _ = url.set_password(None);
        }
        if url.query().is_some() {
            let route: RouteTemplate = self.templater.template(url.path());
            let mut kept: Vec<(String, String)> = Vec::new();
            let mut dropped_any = false;
            for (name, value) in url.query_pairs() {
                let class = self.classifier.classify(&ParamObservation {
                    route: &route,
                    name: &name,
                    value: &value,
                });
                if class == ParamClass::Session || looks_like_jwt(&value) {
                    dropped_any = true;
                    removed.push(RemovedSecret {
                        location: SecretLocation::QueryParam,
                        name: name.to_ascii_lowercase(),
                        hash: self.hash(&value),
                    });
                } else {
                    kept.push((name.into_owned(), value.into_owned()));
                }
            }
            if dropped_any {
                if kept.is_empty() {
                    url.set_query(None);
                } else {
                    url.query_pairs_mut().clear().extend_pairs(kept.iter());
                }
            }
        }
        url.to_string()
    }
}

fn looks_like_jwt(v: &str) -> bool {
    let mut parts = v.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    h.starts_with("eyJ")
        && [h, p, s].iter().all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
        })
}

/// Registrable domain without a public-suffix list: the last two labels, or
/// three when the second-level label is a common generic one under a
/// two-letter country code (`example.co.uk`). IP addresses and single-label
/// hosts are returned whole.
#[must_use]
fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host;
    }
    let tld = labels[n - 1];
    let sld = labels[n - 2];
    let take = if tld.len() == 2
        && matches!(
            sld,
            "co" | "com" | "org" | "net" | "gov" | "ac" | "edu" | "ne" | "or" | "go"
        ) {
        3
    } else {
        2
    };
    labels[n - take..].join(".")
}

/// Is `request_url` served from a different registrable domain than `page_origin`?
/// Unparseable inputs count as third-party.
#[must_use]
pub fn is_third_party(page_origin: &str, request_url: &str) -> bool {
    let page_host = url::Url::parse(page_origin)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    let req_host = url::Url::parse(request_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    match (page_host, req_host) {
        (Some(p), Some(r)) => registrable_domain(&p) != registrable_domain(&r),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::traffic::TrafficOrigin;

    fn event(url: &str) -> TrafficEvent {
        TrafficEvent {
            seq: 1,
            epoch_id: None,
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: url.to_owned(),
            status: Some(200),
            request_headers: vec![
                ("Authorization".to_owned(), "Bearer s3cr3t-token".to_owned()),
                ("Cookie".to_owned(), "sid=abc123".to_owned()),
                ("Accept".to_owned(), "application/json".to_owned()),
                ("X-Api-Key".to_owned(), "key-123".to_owned()),
                ("Proxy-Authorization".to_owned(), "Basic Zm9v".to_owned()),
            ],
            response_headers: vec![
                ("Set-Cookie".to_owned(), "sid=zzz; HttpOnly".to_owned()),
                ("Set-Cookie".to_owned(), "other=1".to_owned()),
                ("Content-Type".to_owned(), "text/html".to_owned()),
            ],
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: chrono::DateTime::default(),
            finished_at: None,
        }
    }

    #[test]
    fn header_names_are_kept_and_values_hashed() {
        let r = Redactor::new([7; 32]);
        let (out, removed) = r.redact_with_report(event("https://example.com/a"));
        let names: Vec<_> = out.request_headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "Authorization",
                "Cookie",
                "Accept",
                "X-Api-Key",
                "Proxy-Authorization"
            ]
        );
        for (n, v) in &out.request_headers {
            if n == "Accept" {
                assert_eq!(v, "application/json");
            } else {
                assert!(v.starts_with("[redacted:") && v.ends_with(']'), "{n}: {v}");
                assert!(!v.contains("s3cr3t") && !v.contains("abc123"));
            }
        }
        assert!(out
            .response_headers
            .iter()
            .all(|(n, v)| n != "Set-Cookie" || v.starts_with("[redacted:")));
        assert_eq!(out.response_headers[2].1, "text/html");
        assert_eq!(removed.len(), 4 + 2);

        // the hash is the keyed correlation hash of the original value
        let expected = Digest::keyed(&[7; 32], REDACTION_DOMAIN, b"Bearer s3cr3t-token");
        assert!(removed
            .iter()
            .any(|s| s.name == "authorization" && s.hash == expected));
        assert_eq!(
            out.request_headers[0].1,
            format!("[redacted:{}]", &expected.to_hex()[..16])
        );
    }

    #[test]
    fn correlation_hash_depends_on_key_and_value() {
        let a = Redactor::new([1; 32]).redact(event("https://example.com/"));
        let b = Redactor::new([2; 32]).redact(event("https://example.com/"));
        let a2 = Redactor::new([1; 32]).redact(event("https://example.com/"));
        assert_ne!(a.request_headers[0].1, b.request_headers[0].1);
        assert_eq!(a.request_headers[0].1, a2.request_headers[0].1);
    }

    #[test]
    fn session_params_are_dropped_and_others_kept() {
        let r = Redactor::new([7; 32]);
        let (out, removed) = r.redact_with_report(event(
            "https://example.com/search?q=shoes&token=abc.def&sessionid=xyz&page=2&utm_source=a",
        ));
        assert_eq!(out.url, "https://example.com/search?q=shoes&page=2&utm_source=a");
        let names: Vec<_> = removed
            .iter()
            .filter(|s| s.location == SecretLocation::QueryParam)
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["sessionid", "token"]);
        assert!(!out.url.contains("xyz"));

        let only = r.redact(event("https://example.com/cb?access_token=zzz"));
        assert_eq!(only.url, "https://example.com/cb");
        // untouched URLs are not re-encoded
        let plain = r.redact(event("https://example.com/a?q=a%20b"));
        assert_eq!(plain.url, "https://example.com/a?q=a%20b");
    }

    #[test]
    fn userinfo_and_jwt_shaped_values_are_removed() {
        let r = Redactor::new([7; 32]);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln";
        let (out, removed) =
            r.redact_with_report(event(&format!("https://u:p@example.com/x?data={jwt}&k=1")));
        assert_eq!(out.url, "https://example.com/x?k=1");
        assert!(removed.iter().any(|s| s.location == SecretLocation::UrlUserinfo));
        assert!(!out.url.contains("eyJ"));
        let bad = r.redact(event("not a url?token=secret"));
        assert_eq!(bad.url, "not a url");
    }

    #[test]
    fn third_party_is_marked_against_the_page_origin() {
        let r = Redactor::new([7; 32]).with_page_origin("https://www.example.com");
        assert!(!r.redact(event("https://api.example.com/x")).third_party);
        assert!(!r.redact(event("https://example.com/x")).third_party);
        assert!(r.redact(event("https://cdn.tracker.net/p.js")).third_party);
        assert!(r.redact(event("https://example.org/x")).third_party);
        let uk = Redactor::new([7; 32]).with_page_origin("https://shop.example.co.uk");
        assert!(!uk.redact(event("https://img.example.co.uk/a.png")).third_party);
        assert!(uk.redact(event("https://other.co.uk/a.png")).third_party);
        // without a configured origin the captured flag is left alone
        let none = Redactor::new([7; 32]);
        assert!(!none.redact(event("https://cdn.tracker.net/p.js")).third_party);
        let (ev, _) = none.redact_with_origin(event("https://cdn.tracker.net/p.js"), "https://example.com");
        assert!(ev.third_party);
    }
}
