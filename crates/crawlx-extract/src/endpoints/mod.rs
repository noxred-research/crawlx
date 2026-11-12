//! Endpoint discovery extractor: headers,
//! ~30 HTML constructs, forms with synthesized bodies, htmx attributes,
//! the JavaScript AST pass ([`ast`], feature `js-ast`) and regex mining of
//! script text and textual bodies.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md, with two
//! deliberate differences: relative
//! references honour `<base href>` (the reference resolves against the request URL
//! only), and form bodies use fixed deterministic placeholder values (the reference's
//! random `rand_*` fillers are not adopted).
//!
//! Every result is a typed [`DiscoveredEndpoint`]. Non-GET and body-bearing
//! endpoints are recorded, never fetched. Results are deduplicated
//! by `(method, url, body)` and capped by [`DiscoveryOptions::max_results`];
//! bodies are scanned up to [`DiscoveryOptions::max_body_bytes`].

#[cfg(feature = "js-ast")]
pub mod ast;
pub mod body;
mod embedded;
pub mod headers;
pub mod script;
#[cfg(feature = "js-ast")]
mod shape;
pub mod textual;
pub mod unresolved;

use std::collections::BTreeSet;

use crawlx_core::config::JavascriptMode;
use http::Method;
use scraper::Html;
use serde::{Deserialize, Serialize};
use url::Url;

pub use unresolved::{DiscoveryReport, ScriptOrigin, SourceSpan, UnresolvedEndpoint, UnresolvedKind};
use unresolved::{UnresolvedLog, DEFAULT_MAX_UNRESOLVED};

use crate::metadata::effective_base;

/// Default cap on discovered endpoints per response.
pub const DEFAULT_MAX_RESULTS: usize = 10_000;
/// Default cap on the body prefix that is parsed and mined: 8 MiB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// One response to mine.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryInput<'a> {
    /// Final URL of the response (after redirects).
    pub url: &'a Url,
    /// HTTP status.
    pub status: u16,
    /// Response headers as `(name, value)`; names are matched case-insensitively.
    pub headers: &'a [(String, String)],
    /// `Content-Type` header value, when known.
    pub content_type: Option<&'a str>,
    /// Raw body bytes.
    pub body: &'a [u8],
    /// Crawl depth of the response; discovered endpoints are one deeper.
    pub depth: u32,
}

/// Bounds and switches of [`discover_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryOptions {
    /// Stop after this many distinct endpoints.
    pub max_results: usize,
    /// Only the first `max_body_bytes` of the body are parsed and mined.
    pub max_body_bytes: usize,
    /// Selected JavaScript miners. AST-only never falls back to regex on malformed
    /// or oversized scripts. Both always runs regex, even when AST parsing fails.
    pub javascript_mode: JavascriptMode,
    /// Cap on the unresolved-expression outcomes listed by [`discover_report`];
    /// further outcomes are only counted. Ignored by the endpoint-only entry points.
    pub max_unresolved: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            max_results: DEFAULT_MAX_RESULTS,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_unresolved: DEFAULT_MAX_UNRESOLVED,
            javascript_mode: if cfg!(feature = "js-ast") {
                JavascriptMode::Both
            } else {
                JavascriptMode::Regex
            },
        }
    }
}

/// Endpoint discovery cannot honor the selected JavaScript policy or parse memory is exhausted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// AST mining was requested but the binary lacks the parser.
    #[error("javascript AST mining unavailable: build with the js-ast feature")]
    AstUnavailable,
    /// The process-wide parse-memory budget could not take the HTML parse's charge.
    #[error(transparent)]
    ParseMemory(#[from] crate::parse_budget::ParseBudgetExhausted),
}

impl DiscoveryOptions {
    /// Check that the selected miners exist in this build.
    ///
    /// # Errors
    /// Returns [`DiscoveryError::AstUnavailable`] for `ast` or `both` without `js-ast`.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.javascript_mode.ast() && !cfg!(feature = "js-ast") {
            return Err(DiscoveryError::AstUnavailable);
        }
        Ok(())
    }
}

/// Where an endpoint was found: the reference `tag` / `attribute` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EndpointSource {
    /// Element or pseudo-tag (`a`, `header`, `htmx`, `js`, `html`).
    pub tag: &'static str,
    /// Attribute or pseudo-attribute (`href`, `srcset`, `regex`, `text`).
    pub attribute: &'static str,
}

impl<'de> Deserialize<'de> for EndpointSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            tag: String,
            attribute: String,
        }
        let raw = Raw::deserialize(d)?;
        ALL_SOURCES
            .iter()
            .copied()
            .find(|s| s.tag == raw.tag && s.attribute == raw.attribute)
            .ok_or_else(|| {
                serde::de::Error::custom(format!("unknown endpoint source {}/{}", raw.tag, raw.attribute))
            })
    }
}

/// Every source this extractor can emit (deserialization resolves to these).
pub const ALL_SOURCES: &[EndpointSource] = &[
    headers::CONTENT_LOCATION,
    headers::LINK,
    headers::LOCATION,
    headers::REFRESH,
    body::A_HREF,
    body::A_PING,
    body::LINK_HREF,
    body::EMBED_SRC,
    body::FRAME_SRC,
    body::IFRAME_SRC,
    body::IFRAME_SRCDOC,
    body::INPUT_IMAGE_SRC,
    body::ISINDEX_ACTION,
    body::SCRIPT_SRC,
    body::SCRIPT_TEXT,
    body::BODY_BACKGROUND,
    body::AUDIO_SRC,
    body::AUDIO_SOURCE,
    body::AUDIO_SOURCE_SRCSET,
    body::APPLET_ARCHIVE,
    body::APPLET_CODEBASE,
    body::IMG_DYNSRC,
    body::IMG_LONGDESC,
    body::IMG_LOWSRC,
    body::IMG_SRC,
    body::IMG_SRCSET,
    body::OBJECT_DATA,
    body::OBJECT_CODEBASE,
    body::OBJECT_PARAM_VALUE,
    body::SVG_IMAGE_HREF,
    body::SVG_SCRIPT_HREF,
    body::TABLE_BACKGROUND,
    body::TABLE_TD_BACKGROUND,
    body::VIDEO_SRC,
    body::VIDEO_POSTER,
    body::VIDEO_TRACK_SRC,
    body::SOURCE_SRC,
    body::SOURCE_SRCSET,
    body::TRACK_SRC,
    body::BLOCKQUOTE_CITE,
    body::Q_CITE,
    body::DEL_CITE,
    body::INS_CITE,
    body::AREA_HREF,
    body::AREA_PING,
    body::BASE_HREF,
    body::IMPORT_IMPLEMENTATION,
    body::BUTTON_FORMACTION,
    body::HTML_MANIFEST,
    body::HTML_DOCTYPE,
    body::FORM_ACTION,
    body::META_REFRESH,
    body::HTMX_GET,
    body::HTMX_POST,
    body::HTMX_PUT,
    body::HTMX_PATCH,
    body::JS_REGEX,
    body::HTML_REGEX,
    body::META_CONTENT,
    body::HEAD_PROFILE,
    body::CONDITIONAL_COMMENT,
    body::IMG_DATA,
    body::JS_FETCH,
    body::JS_AXIOS,
    body::JS_HTTP,
    body::JS_XHR,
    body::JS_AJAX,
    body::JS_BEACON,
    body::JS_URL,
    body::JS_LOCATION,
    body::JS_OPEN,
    body::JS_HISTORY,
    body::JS_WEBSOCKET,
    body::JS_EVENTSOURCE,
    body::JS_STRING,
];

/// How the endpoint was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Confidence {
    /// Read from a URL-bearing attribute or header, or from a request site
    /// in the JavaScript AST.
    Structural,
    /// Mined by regex from text.
    Regex,
}

/// A discovered navigation target. Recorded as metadata; only GET endpoints
/// without a body are candidates for fetching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    /// Absolute `http(s)` URL, fragment removed.
    pub url: Url,
    /// HTTP method (`GET` unless a form or htmx attribute says otherwise).
    #[serde(with = "method_serde")]
    pub method: Method,
    /// Construct that yielded the endpoint.
    pub source: EndpointSource,
    /// Synthesized request body (forms with `POST`).
    pub body: Option<String>,
    /// `Content-Type` of `body`.
    pub content_type: Option<String>,
    /// Structural or regex-derived.
    pub confidence: Confidence,
    /// Crawl depth of the endpoint (input depth + 1).
    pub depth: u32,
    /// Request header names the script sets (AST pass), lower-cased and
    /// sorted; empty elsewhere.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
}

impl DiscoveredEndpoint {
    /// Resolve `raw` against `base` into a GET endpoint; `None` for empty,
    /// fragment-only, `data:`/`mailto:`/`javascript:`/`vbscript:` or non-http
    /// targets.
    #[must_use]
    pub fn get(
        base: &Url,
        raw: &str,
        source: EndpointSource,
        confidence: Confidence,
        depth: u32,
    ) -> Option<Self> {
        let url = resolve(base, raw)?;
        Some(Self {
            url,
            method: Method::GET,
            source,
            body: None,
            content_type: None,
            confidence,
            depth: depth.saturating_add(1),
            headers: Vec::new(),
        })
    }
}

mod method_serde {
    use http::Method;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(m: &Method, s: S) -> Result<S::Ok, S::Error> {
        m.as_str().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Method, D::Error> {
        let s = String::deserialize(d)?;
        Method::from_bytes(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Resolve a raw reference the reference way: skip `#…`, strip the fragment,
/// refuse non-navigational schemes.
#[must_use]
pub fn resolve(base: &Url, raw: &str) -> Option<Url> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    let lc = raw.to_ascii_lowercase();
    if ["data:", "mailto:", "javascript:", "vbscript:"]
        .iter()
        .any(|p| lc.starts_with(p))
    {
        return None;
    }
    let mut url = base.join(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

/// Discover endpoints with [`DiscoveryOptions::default`].
///
/// # Errors
/// Returns [`DiscoveryError`] when a selected miner is unavailable.
pub fn discover(input: &DiscoveryInput<'_>) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    discover_with(input, &DiscoveryOptions::default())
}

fn is_script_like(media: &str, path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".js")
        || p.ends_with(".css")
        || p.ends_with(".mjs")
        || media.contains("javascript")
        || media.contains("ecmascript")
        || media == "text/css"
        || media == "application/json"
        || media.ends_with("+json")
}

/// JavaScript proper (not CSS/JSON): the AST pass applies.
#[cfg(feature = "js-ast")]
fn is_javascript(media: &str, path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".js") || p.ends_with(".mjs") || media.contains("javascript") || media.contains("ecmascript")
}

/// Discover endpoints in one response.
///
/// Header parsers always run for a supported policy. HTML structural parsers
/// remain enabled in every mode. Selected JavaScript miners handle scripts;
/// selected regex mining also covers stylesheets/JSON and textual page bodies.
/// Binary bodies (declared or sniffed) are never mined.
///
/// # Errors
/// Returns [`DiscoveryError::AstUnavailable`] before mining when AST was selected
/// but this build lacks `js-ast`; no regex fallback is substituted.
/// Returns [`DiscoveryError::ParseMemory`] when an HTML body cannot be charged to the
/// process-wide parse-memory budget; endpoints found so far are not returned as a success.
pub fn discover_with(
    input: &DiscoveryInput<'_>,
    opts: &DiscoveryOptions,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    discover_report(input, opts).map(|r| r.endpoints)
}

/// [`discover_with`] plus the typed unresolved outcomes of the AST pass: URL
/// expressions of request sites that could not be resolved statically
/// (see [`UnresolvedEndpoint`]), bounded by [`DiscoveryOptions::max_unresolved`].
/// The endpoints are exactly those of [`discover_with`].
///
/// # Errors
/// The errors of [`discover_with`].
pub fn discover_report(
    input: &DiscoveryInput<'_>,
    opts: &DiscoveryOptions,
) -> Result<DiscoveryReport, DiscoveryError> {
    opts.validate()?;
    let mut out: Vec<DiscoveredEndpoint> = Vec::new();
    let mut log = UnresolvedLog::new(opts.max_unresolved);
    headers::parse(input.headers, input.url, input.depth, &mut out);

    let body_bytes = &input.body[..input.body.len().min(opts.max_body_bytes)];
    if textual::is_textual(input.content_type, body_bytes) {
        let media = input
            .content_type
            .and_then(textual::media_type_of)
            .filter(|m| m != "application/octet-stream")
            .unwrap_or_else(|| textual::sniff(body_bytes).to_owned());
        let text = String::from_utf8_lossy(body_bytes);
        let mined = if opts.javascript_mode.regex() {
            script::decode_slash_escapes(&text)
        } else {
            std::borrow::Cow::Borrowed("")
        };
        // relative references in an HTML page resolve against its `<base>`
        let mut html_base: Option<Url> = None;
        if is_script_like(&media, input.url.path()) {
            #[cfg(feature = "js-ast")]
            if opts.javascript_mode.ast() && is_javascript(&media, input.url.path()) {
                ast::discover_into(
                    &text,
                    input.url,
                    input.depth,
                    ScriptOrigin::ScriptFile,
                    &mut out,
                    &mut log,
                );
            }
            if opts.javascript_mode.regex() {
                regex_pass(
                    input,
                    input.url,
                    script::extract_relative_endpoints(&mined),
                    body::JS_REGEX,
                    &mut out,
                );
            }
        } else {
            // declared before `doc`: released after the parsed tree is dropped
            let mut charge = crate::parse_budget::charge(text.len())?;
            let doc = crate::dom::parse_document(&mut charge, &text)?;
            let base = effective_base(&doc, input.url);
            body::parse(
                &doc,
                input.url,
                &base,
                input.depth,
                opts.javascript_mode,
                &mut out,
                &mut log,
            );
            html_base = Some(base);
        }
        if opts.javascript_mode.regex() {
            regex_pass(
                input,
                html_base.as_ref().unwrap_or(input.url),
                script::extract_body_endpoints(&mined),
                body::HTML_REGEX,
                &mut out,
            );
        }
    }

    Ok(log.finish(dedupe(out, opts.max_results)))
}

/// Discover endpoints in an HTML response that is already parsed (`doc`,
/// with `base` its effective base URL). `input.body` is still consulted for
/// the textual guard and the page-body regex; header parsers run as in
/// [`discover_with`].
///
/// # Errors
/// Returns [`DiscoveryError::AstUnavailable`] when AST was selected but not built.
pub fn discover_html(
    doc: &Html,
    base: &Url,
    input: &DiscoveryInput<'_>,
    opts: &DiscoveryOptions,
) -> Result<Vec<DiscoveredEndpoint>, DiscoveryError> {
    discover_html_report(doc, base, input, opts).map(|r| r.endpoints)
}

/// [`discover_html`] plus the unresolved outcomes, like [`discover_report`].
///
/// # Errors
/// The errors of [`discover_html`].
pub fn discover_html_report(
    doc: &Html,
    base: &Url,
    input: &DiscoveryInput<'_>,
    opts: &DiscoveryOptions,
) -> Result<DiscoveryReport, DiscoveryError> {
    opts.validate()?;
    let mut out: Vec<DiscoveredEndpoint> = Vec::new();
    let mut log = UnresolvedLog::new(opts.max_unresolved);
    headers::parse(input.headers, input.url, input.depth, &mut out);
    body::parse(
        doc,
        input.url,
        base,
        input.depth,
        opts.javascript_mode,
        &mut out,
        &mut log,
    );
    let body_bytes = &input.body[..input.body.len().min(opts.max_body_bytes)];
    if opts.javascript_mode.regex() && textual::is_textual(input.content_type, body_bytes) {
        let text = String::from_utf8_lossy(body_bytes);
        regex_pass(
            input,
            base,
            script::extract_body_endpoints(&script::decode_slash_escapes(&text)),
            body::HTML_REGEX,
            &mut out,
        );
    }
    Ok(log.finish(dedupe(out, opts.max_results)))
}

/// Resolve regex-mined strings against `base` as GET endpoints; a match that
/// still holds a backslash after the escape decoding is not a URL.
fn regex_pass(
    input: &DiscoveryInput<'_>,
    base: &Url,
    raws: Vec<&str>,
    source: EndpointSource,
    out: &mut Vec<DiscoveredEndpoint>,
) {
    for raw in raws.into_iter().filter_map(script::mined_target) {
        out.extend(DiscoveredEndpoint::get(
            base,
            raw,
            source,
            Confidence::Regex,
            input.depth,
        ));
    }
}

fn dedupe(found: Vec<DiscoveredEndpoint>, cap: usize) -> Vec<DiscoveredEndpoint> {
    let mut seen: BTreeSet<(String, String, Option<String>)> = BTreeSet::new();
    let mut out = Vec::with_capacity(found.len().min(cap));
    for ep in found {
        if out.len() >= cap {
            break;
        }
        let key = (ep.method.as_str().to_owned(), ep.url.to_string(), ep.body.clone());
        if seen.insert(key) {
            out.push(ep);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn page() -> Url {
        Url::parse("https://example.com/dir/page.html").unwrap()
    }

    #[test]
    fn resolve_filters_schemes_and_fragments() {
        let b = page();
        assert_eq!(
            resolve(&b, "x#frag").unwrap().as_str(),
            "https://example.com/dir/x"
        );
        assert!(resolve(&b, "#top").is_none());
        assert!(resolve(&b, "javascript:void(0)").is_none());
        assert!(resolve(&b, "MAILTO:a@b").is_none());
        assert!(resolve(&b, "data:text/plain,hi").is_none());
        assert!(resolve(&b, "ftp://x/y").is_none());
        assert!(resolve(&b, "  ").is_none());
    }

    #[test]
    fn dedupe_and_cap() {
        let b = page();
        let mk =
            |raw: &str| DiscoveredEndpoint::get(&b, raw, body::A_HREF, Confidence::Structural, 0).unwrap();
        let got = dedupe(vec![mk("/a"), mk("/a"), mk("/b"), mk("/c")], 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].url.path(), "/b");
        assert_eq!(got[0].depth, 1);
    }

    #[test]
    fn source_roundtrip() {
        let ep = DiscoveredEndpoint::get(&page(), "/x", body::IMG_SRCSET, Confidence::Structural, 2).unwrap();
        let json = serde_json::to_string(&ep).unwrap();
        let back: DiscoveredEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ep);
        assert!(serde_json::from_str::<EndpointSource>(r#"{"tag":"zz","attribute":"q"}"#).is_err());
    }
}
