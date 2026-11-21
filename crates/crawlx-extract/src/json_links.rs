//! Same-origin URLs named by the string values of a JSON document (`scope.jsonEndpoints`).
//!
//! A single-page application often keeps its route table in a JSON endpoint that a script
//! fetches: `{"href":"/app/item/01"}`. The static plane already fetches such an endpoint once the
//! endpoint miner finds it; this module turns the document's string values into crawl
//! candidates without a browser.
//!
//! A string value is a candidate when it is a root-relative path (`/app/item/01`, not the
//! scheme-relative `//host/x`) or an absolute `http(s)` URL on the origin of the document. Keys,
//! numbers, bare relative references (`item/01`), other origins and strings that cannot be a
//! path (whitespace, control characters, template or markup characters, the lone `/`) are
//! ignored. The values are never stored: only the admitted URLs leave this module, and the
//! caller still applies scope, robots and the egress policy to each one.
//!
//! The walk is a streaming `serde` visitor that builds no value tree, so memory does not grow
//! with the document. Every dimension is bounded by [`JsonLinkLimits`]: input bytes (a longer
//! body is read as a prefix and ends at the first incomplete token), nesting depth (deeper
//! values are skipped) and the number of URLs (the walk stops at the cap). The nesting that
//! `serde_json` itself accepts is bounded too, so hostile input cannot overflow the stack.

use std::collections::BTreeSet;
use std::fmt;

use http::Method;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::endpoints::body::JSON_ENDPOINT;
use crate::endpoints::{Confidence, DiscoveredEndpoint, DiscoveryInput};
use url::Url;

/// Default cap on the URLs one document yields.
pub const DEFAULT_MAX_URLS: usize = 500;
/// Default cap on the nesting depth that is walked (the document itself is depth 0).
pub const DEFAULT_MAX_DEPTH: usize = 16;
/// Default cap on the bytes read from one document: 1 MiB.
pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
/// Longest string value considered a URL candidate.
pub const MAX_VALUE_BYTES: usize = 2048;

/// Bounds of [`same_origin_links`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLinkLimits {
    /// Stop after this many distinct URLs.
    pub max_urls: usize,
    /// Values nested deeper than this are skipped.
    pub max_depth: usize,
    /// Only this many leading bytes of the body are read.
    pub max_bytes: usize,
}

impl Default for JsonLinkLimits {
    fn default() -> Self {
        Self {
            max_urls: DEFAULT_MAX_URLS,
            max_depth: DEFAULT_MAX_DEPTH,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// The URLs found in one JSON document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsonLinks {
    /// Distinct absolute URLs, fragment removed, in document order.
    pub urls: Vec<Url>,
    /// The walk ended at a bound ([`JsonLinkLimits::max_urls`] or [`JsonLinkLimits::max_bytes`])
    /// before the document did.
    pub truncated: bool,
}

/// Is `content_type` exactly `application/json` (parameters such as `charset` ignored)?
#[must_use]
pub fn is_json_media_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// The same-origin URLs named by the string values of the JSON `body`, resolved against `base`
/// (the URL the document was fetched from). Invalid or incomplete JSON yields the URLs found
/// before the first error.
#[must_use]
pub fn same_origin_links(body: &[u8], base: &Url, limits: &JsonLinkLimits) -> JsonLinks {
    let read = &body[..body.len().min(limits.max_bytes)];
    let mut walk = Walk {
        base,
        limits: *limits,
        seen: BTreeSet::new(),
        urls: Vec::new(),
        full: false,
    };
    let mut de = serde_json::Deserializer::from_slice(read);
    // an error (the cap, a truncated or malformed document) keeps what was found so far
    let _ = Node {
        walk: &mut walk,
        depth: 0,
    }
    .deserialize(&mut de);
    JsonLinks {
        truncated: walk.full || read.len() < body.len(),
        urls: walk.urls,
    }
}

/// The `application/json` response `input` as `json_endpoint` GET endpoints, one per URL
/// [`same_origin_links`] finds in it; empty for any other response (other media type, a status
/// outside 2xx).
#[must_use]
pub fn discover(input: &DiscoveryInput<'_>, limits: &JsonLinkLimits) -> Vec<DiscoveredEndpoint> {
    if !(200..300).contains(&input.status) || !is_json_media_type(input.content_type) {
        return Vec::new();
    }
    same_origin_links(input.body, input.url, limits)
        .urls
        .into_iter()
        .map(|url| DiscoveredEndpoint {
            url,
            method: Method::GET,
            source: JSON_ENDPOINT,
            body: None,
            content_type: None,
            confidence: Confidence::Structural,
            depth: input.depth.saturating_add(1),
            headers: Vec::new(),
        })
        .collect()
}

/// Walk state shared by every node of one document.
struct Walk<'a> {
    base: &'a Url,
    limits: JsonLinkLimits,
    seen: BTreeSet<String>,
    urls: Vec<Url>,
    full: bool,
}

impl Walk<'_> {
    /// Admit `value` when it names a same-origin URL; `true` once the URL cap is reached.
    fn offer(&mut self, value: &str) -> bool {
        if let Some(url) = self.candidate(value) {
            if self.seen.insert(url.to_string()) {
                self.urls.push(url);
            }
        }
        self.full = self.urls.len() >= self.limits.max_urls;
        self.full
    }

    fn candidate(&self, value: &str) -> Option<Url> {
        if value.len() < 2 || value.len() > MAX_VALUE_BYTES {
            return None;
        }
        // not a path: whitespace, control, template, markup, quoting or escape characters
        if value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "{}<>\\\"'`|^".contains(c))
        {
            return None;
        }
        let mut url = if value.starts_with('/') {
            // `//host/x` is scheme-relative: another origin, never a path
            if value.starts_with("//") {
                return None;
            }
            self.base.join(value).ok()?
        } else if is_http_url(value) {
            Url::parse(value).ok()?
        } else {
            return None;
        };
        if url.origin() != self.base.origin() {
            return None;
        }
        url.set_fragment(None);
        (url != *self.base).then_some(url)
    }
}

/// Does `value` start with an `http://` or `https://` scheme (case-insensitive)?
fn is_http_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 8
        && (bytes[..8].eq_ignore_ascii_case(b"https://") || bytes[..7].eq_ignore_ascii_case(b"http://"))
}

/// One JSON value at `depth`.
struct Node<'w, 'a> {
    walk: &'w mut Walk<'a>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Node<'_, '_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if self.depth <= self.walk.limits.max_depth && self.walk.offer(value) {
            return Err(E::custom("url cap reached"));
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        if self.depth >= self.walk.limits.max_depth {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(());
        }
        let depth = self.depth + 1;
        while seq
            .next_element_seed(Node {
                walk: &mut *self.walk,
                depth,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        if self.depth >= self.walk.limits.max_depth {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(());
        }
        let depth = self.depth + 1;
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(Node {
                walk: &mut *self.walk,
                depth,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn base() -> Url {
        Url::parse("https://app.example.test/api/app-index.json").unwrap()
    }

    fn paths(json: &str) -> Vec<String> {
        same_origin_links(json.as_bytes(), &base(), &JsonLinkLimits::default())
            .urls
            .iter()
            .map(Url::to_string)
            .collect()
    }

    #[test]
    fn root_relative_and_same_origin_absolute_values_are_candidates() {
        let got = paths(
            r#"{"items":[{"href":"/app/item/01"},{"href":"https://app.example.test/app/item/02#top"},
               {"nested":{"deep":["/app/item/03?x=1"]}}]}"#,
        );
        assert_eq!(
            got,
            [
                "https://app.example.test/app/item/01",
                "https://app.example.test/app/item/02",
                "https://app.example.test/app/item/03?x=1",
            ]
        );
    }

    #[test]
    fn other_values_are_ignored() {
        let got = paths(
            r#"["//cdn.example.test/x", "https://other.example.test/p", "http://app.example.test/p",
                "item/01", "/", " /a", "/a b", "/{id}", "/<b>", "/a\\b", "mailto:x@y", "javascript:alert(1)",
                "application/json", 42, true, null, {"/api/key-not-value": 1}]"#,
        );
        // only the scheme and port differ for `http://app.example.test/p`: another origin
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn the_document_itself_and_repeats_are_not_listed() {
        let got = paths(r#"["/api/app-index.json", "/a", "/a", "https://app.example.test/a#x"]"#);
        assert_eq!(got, ["https://app.example.test/a"]);
    }

    #[test]
    fn url_cap_stops_the_walk_and_marks_truncation() {
        let json = format!(
            "[{}]",
            (0..100)
                .map(|i| format!("\"/p/{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let limits = JsonLinkLimits {
            max_urls: 7,
            ..JsonLinkLimits::default()
        };
        let links = same_origin_links(json.as_bytes(), &base(), &limits);
        assert_eq!(links.urls.len(), 7);
        assert!(links.truncated);
        assert_eq!(links.urls[0].path(), "/p/0");
    }

    #[test]
    fn depth_cap_skips_deeper_values() {
        let limits = JsonLinkLimits {
            max_depth: 2,
            ..JsonLinkLimits::default()
        };
        let links = same_origin_links(
            br#"{"a":"/d1","b":{"c":"/d2","d":{"e":"/d3"}},"f":[["/d3b"]]}"#,
            &base(),
            &limits,
        );
        let got: Vec<&str> = links.urls.iter().map(Url::path).collect();
        assert_eq!(got, ["/d1", "/d2"]);
    }

    #[test]
    fn nesting_far_beyond_the_parser_limit_neither_overflows_nor_yields_links() {
        let deep = format!("{}\"/x\"{}", "[".repeat(100_000), "]".repeat(100_000));
        let links = same_origin_links(deep.as_bytes(), &base(), &JsonLinkLimits::default());
        assert!(links.urls.is_empty());
        let deep_map = format!("{}\"/x\"{}", "{\"k\":".repeat(100_000), "}".repeat(100_000));
        assert!(
            same_origin_links(deep_map.as_bytes(), &base(), &JsonLinkLimits::default())
                .urls
                .is_empty()
        );
    }

    #[test]
    fn a_huge_document_is_read_only_up_to_the_byte_cap() {
        let limits = JsonLinkLimits {
            max_urls: usize::MAX,
            max_bytes: 4096,
            ..JsonLinkLimits::default()
        };
        let json = format!(
            "[{}]",
            (0..200_000)
                .map(|i| format!("\"/p/{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let links = same_origin_links(json.as_bytes(), &base(), &limits);
        assert!(links.truncated);
        // a prefix of the array: complete strings only, none past the cap
        assert!(
            !links.urls.is_empty() && links.urls.len() < 4096 / 6,
            "{}",
            links.urls.len()
        );
        assert!(links.urls.iter().all(|url| url.path().starts_with("/p/")));
    }

    #[test]
    fn malformed_json_keeps_what_came_before_the_error() {
        let got = paths(r#"["/a", "/b", oops, "/c"]"#);
        assert_eq!(got, ["https://app.example.test/a", "https://app.example.test/b"]);
        assert!(paths("not json").is_empty());
    }

    #[test]
    fn only_application_json_counts() {
        assert!(is_json_media_type(Some("application/json")));
        assert!(is_json_media_type(Some("Application/JSON; charset=utf-8")));
        assert!(!is_json_media_type(Some("application/ld+json")));
        assert!(!is_json_media_type(Some("text/html")));
        assert!(!is_json_media_type(None));
    }
}
