//! URL canonicalization.
//!
//! Pipeline: resolve against `base` → scheme guard (`http`/`https`) → strip
//! userinfo → host lowercase/IDNA/trailing-dot/default-port normalization →
//! path percent-encoding normalization and trailing-slash policy → query
//! parsing, classification ([`crate::params`]) and canonical ordering →
//! fragment removal → route template ([`crate::route_template`]) → key
//! `Digest::of("crawlx/canonical-url/v1", canonical string)`.
//!
//! The result is idempotent: canonicalizing `canonical.url` yields the same
//! `url`, `key` and route template. `params` of the second pass lists only the
//! kept parameters because dropped ones are already absent.

use std::borrow::Cow;
use std::sync::Arc;

use parking_lot::RwLock;

use crawlx_core::config::{QueryPolicy, Scope};
use crawlx_core::hash::Digest;
use crawlx_core::url::{CanonicalUrl, ClassifiedParam, ParamClass, RouteTemplate};
use url::Url;

use crate::error::UrlError;
use crate::params::{bucket_value, ParamClassifier, ParamObservation};
use crate::route_template::RouteTemplater;

/// Domain tag of the canonical URL key.
pub const KEY_DOMAIN: &str = "crawlx/canonical-url/v1";
/// Domain tag of keyed resource-id value hashes.
pub const RESOURCE_ID_DOMAIN: &str = "crawlx/resource-id/v1";

/// Trailing-slash policy. Default keeps the slash because `/a` and `/a/`
/// can address distinct resources.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum TrailingSlash {
    /// Leave the path as written.
    #[default]
    Keep,
    /// Remove trailing slashes except for the root path.
    Strip,
    /// Add a trailing slash unless the last segment looks like a file (`.` in it).
    Add,
}

/// Canonicalization options (per crawl).
#[derive(Clone, Debug)]
pub struct CanonicalizeOptions {
    /// How query parameters are treated (kept, dropped or classified per parameter).
    pub query_policy: QueryPolicy,
    /// Holds per-crawl overrides and observed-value statistics.
    pub classifier: Arc<ParamClassifier>,
    /// Static and learned route-template rules. Shared behind a lock so the crawl can learn
    /// sibling slots while it runs (`RouteTemplater::learn`): every holder of a clone of
    /// these options sees the same rules, and a replaced templater re-keys later URLs only.
    pub templater: Arc<RwLock<RouteTemplater>>,
    /// Per-run 32-byte key for resource-id value hashes.
    pub resource_key: [u8; 32],
    /// Whether trailing slashes are kept, stripped or added.
    pub trailing_slash: TrailingSlash,
    /// Inputs longer than this many bytes are rejected.
    pub max_url_len: usize,
    /// Keep `#/route` and `#!/route` fragments (set once the browser plane
    /// observed fragment-driven route changes on the origin).
    pub keep_hash_route: bool,
}

impl Default for CanonicalizeOptions {
    fn default() -> Self {
        Self {
            query_policy: QueryPolicy::Classify,
            classifier: Arc::new(ParamClassifier::default()),
            templater: Arc::new(RwLock::new(RouteTemplater::new())),
            resource_key: [0; 32],
            trailing_slash: TrailingSlash::Keep,
            max_url_len: 8192,
            keep_hash_route: false,
        }
    }
}

impl CanonicalizeOptions {
    /// Options from a crawl's `Scope` (query policy and overrides).
    #[must_use]
    pub fn from_scope(scope: &Scope, resource_key: [u8; 32]) -> Self {
        Self {
            query_policy: scope.query_policy,
            classifier: Arc::new(ParamClassifier::new(&scope.query_overrides)),
            resource_key,
            ..Self::default()
        }
    }
}

/// Canonical URL plus audit facts that do not fit `CanonicalUrl`.
#[derive(Clone, Debug)]
pub struct Canonicalized {
    /// The canonical URL (key, origin and canonical string).
    pub url: CanonicalUrl,
    /// The input carried `user:pass@`; it was removed and must never be forwarded.
    pub had_userinfo: bool,
    /// At least one `ActionBearing` parameter: route to the safety kernel.
    pub action_bearing: bool,
    /// A fragment was removed.
    pub fragment_dropped: bool,
}

/// Stateless entry points; state lives in [`CanonicalizeOptions`].
pub struct Canonicalizer;

impl Canonicalizer {
    /// Canonicalize `raw` resolved against `base`.
    ///
    /// # Errors
    /// Returns [`UrlError::Empty`] for blank input, [`UrlError::TooLong`] past
    /// `opts.max_url_len`, [`UrlError::Parse`] when the WHATWG parser rejects it,
    /// and [`UrlError::Scheme`] / [`UrlError::NoHost`] for non-HTTP(S) or host-less results.
    pub fn canonicalize(raw: &str, base: &Url, opts: &CanonicalizeOptions) -> Result<CanonicalUrl, UrlError> {
        Self::canonicalize_detailed(raw, base, opts).map(|c| c.url)
    }

    /// Like [`Self::canonicalize`], with audit facts.
    ///
    /// # Errors
    /// Same as [`Self::canonicalize`].
    pub fn canonicalize_detailed(
        raw: &str,
        base: &Url,
        opts: &CanonicalizeOptions,
    ) -> Result<Canonicalized, UrlError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(UrlError::Empty);
        }
        if raw.len() > opts.max_url_len {
            return Err(UrlError::TooLong {
                len: raw.len(),
                max: opts.max_url_len,
            });
        }
        let url = Url::options()
            .base_url(Some(base))
            .parse(raw)
            .map_err(|e| UrlError::Parse(e.to_string()))?;
        Self::canonicalize_parsed(url, opts)
    }

    /// Canonicalize an absolute, already parsed URL (e.g. a redirect target).
    ///
    /// # Errors
    /// Returns [`UrlError::Scheme`] for non-HTTP(S) schemes and [`UrlError::NoHost`]
    /// for host-less URLs.
    pub fn canonicalize_url(url: &Url, opts: &CanonicalizeOptions) -> Result<CanonicalUrl, UrlError> {
        Self::canonicalize_parsed(url.clone(), opts).map(|c| c.url)
    }

    fn canonicalize_parsed(mut u: Url, opts: &CanonicalizeOptions) -> Result<Canonicalized, UrlError> {
        if !matches!(u.scheme(), "http" | "https") {
            return Err(UrlError::Scheme(u.scheme().to_owned()));
        }
        // Host: the parser lowercases, applies IDNA and drops default ports.
        let host = u.host_str().filter(|h| !h.is_empty()).ok_or(UrlError::NoHost)?;
        if host.ends_with('.') {
            let trimmed = host.trim_end_matches('.').to_owned();
            if trimmed.is_empty() {
                return Err(UrlError::NoHost);
            }
            u.set_host(Some(&trimmed))
                .map_err(|e| UrlError::Parse(e.to_string()))?;
        }
        // Userinfo is never forwarded.
        let had_userinfo = !u.username().is_empty() || u.password().is_some();
        if had_userinfo {
            let _ = u.set_username("");
            let _ = u.set_password(None);
        }

        normalize_path(&mut u, opts.trailing_slash);
        let route_template = opts.templater.read().template(u.path());

        let (params, kept_query) = process_query(&u, &route_template, opts);
        u.set_query(kept_query.as_deref());
        let action_bearing = params.iter().any(|p| p.class == ParamClass::ActionBearing);

        let fragment_dropped = u.fragment().is_some();
        if fragment_dropped {
            let keep = opts.keep_hash_route
                && u.fragment()
                    .is_some_and(|f| f.starts_with('/') || f.starts_with("!/"));
            if !keep {
                u.set_fragment(None);
            }
        }

        let key = Digest::of(KEY_DOMAIN, u.as_str().as_bytes());
        let origin = origin_of(&u);
        Ok(Canonicalized {
            url: CanonicalUrl {
                url: u,
                key,
                origin,
                route_template,
                params,
            },
            had_userinfo,
            action_bearing,
            fragment_dropped,
        })
    }
}

/// `scheme://host[:port]`, lowercase, default port dropped.
#[must_use]
pub fn origin_of(u: &Url) -> String {
    let host = u.host_str().unwrap_or("");
    match u.port() {
        Some(p) => format!("{}://{host}:{p}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    }
}

fn normalize_path(u: &mut Url, policy: TrailingSlash) {
    let mut path: Cow<'_, str> = normalize_pct(u.path());
    match policy {
        TrailingSlash::Keep => {}
        TrailingSlash::Strip => {
            if path.len() > 1 && path.ends_with('/') {
                let t = path.trim_end_matches('/');
                path = Cow::Owned(if t.is_empty() {
                    "/".to_owned()
                } else {
                    t.to_owned()
                });
            }
        }
        TrailingSlash::Add => {
            let last = path.rsplit('/').next().unwrap_or("");
            if !path.ends_with('/') && !last.contains('.') {
                path = Cow::Owned(format!("{path}/"));
            }
        }
    }
    if path != u.path() {
        let new = path.into_owned();
        u.set_path(&new);
    }
}

struct RawParam {
    name: String,
    value: String,
    has_eq: bool,
    dec_name: String,
    dec_value: String,
    class: ParamClass,
}

/// Classify and order the query. Returns the classified params (canonical
/// order, dropped ones included with `value: None`) and the kept query string.
fn process_query(
    u: &Url,
    route: &RouteTemplate,
    opts: &CanonicalizeOptions,
) -> (Vec<ClassifiedParam>, Option<String>) {
    let Some(q) = u.query() else {
        return (Vec::new(), None);
    };
    if q.is_empty() || opts.query_policy == QueryPolicy::StripAll {
        return (Vec::new(), None);
    }
    let mut raws: Vec<RawParam> = Vec::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (n, v, has_eq) = match pair.split_once('=') {
            Some((n, v)) => (n, v, true),
            None => (pair, "", false),
        };
        let dec_name = pct_decode(n);
        let dec_value = pct_decode(v);
        let mut class = opts.classifier.classify(&ParamObservation {
            route,
            name: &dec_name,
            value: &dec_value,
        });
        if opts.query_policy == QueryPolicy::KeepAll && !class.kept() {
            class = ParamClass::Filter;
        }
        raws.push(RawParam {
            name: normalize_pct(n).into_owned(),
            value: normalize_pct(v).into_owned(),
            has_eq,
            dec_name,
            dec_value,
            class,
        });
    }
    // Stable: repeated keys keep their relative order.
    raws.sort_by(|a, b| a.name.cmp(&b.name));

    let mut kept = String::with_capacity(q.len());
    let mut params = Vec::with_capacity(raws.len());
    for r in raws {
        let value = match r.class {
            ParamClass::Tracking | ParamClass::Session => None,
            ParamClass::Navigation | ParamClass::ActionBearing => Some(r.dec_value.clone()),
            ParamClass::Filter => Some(bucket_value(&r.dec_value)),
            ParamClass::ResourceId => Some(hash_id(&opts.resource_key, &r.dec_value)),
        };
        if r.class.kept() {
            if !kept.is_empty() {
                kept.push('&');
            }
            kept.push_str(&r.name);
            if r.has_eq {
                kept.push('=');
                kept.push_str(&r.value);
            }
        }
        params.push(ClassifiedParam {
            name: r.dec_name,
            class: r.class,
            value,
        });
    }
    let kept = if kept.is_empty() { None } else { Some(kept) };
    (params, kept)
}

fn hash_id(key: &[u8; 32], value: &str) -> String {
    let d = Digest::keyed(key, RESOURCE_ID_DOMAIN, value.as_bytes());
    let mut s = String::with_capacity(32);
    for b in d.truncate16() {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Uppercase percent-escapes and decode escaped unreserved characters. A `%` that does not
/// start a valid escape is a literal and is encoded as `%25`: decoding an unreserved escape
/// next to it (`%6%66` → `%6f`) must not manufacture a new escape, or normalization would
/// not be idempotent (found by the `url_canonicalize` fuzz target).
fn normalize_pct(s: &str) -> Cow<'_, str> {
    if !s.contains('%') {
        return Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (
                b.get(i + 1).copied().and_then(hex_val),
                b.get(i + 2).copied().and_then(hex_val),
            ) {
                let v = (h << 4) | l;
                if is_unreserved(v) {
                    out.push(v);
                } else {
                    out.push(b'%');
                    out.push(b"0123456789ABCDEF"[usize::from(h)]);
                    out.push(b"0123456789ABCDEF"[usize::from(l)]);
                }
                i += 3;
                continue;
            }
            out.extend_from_slice(b"%25");
            i += 1;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(_) => Cow::Borrowed(s),
    }
}

/// Form-style decode (`+` → space, `%XX` → byte, lossy UTF-8) for classification.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if let (Some(h), Some(l)) = (
                    b.get(i + 1).copied().and_then(hex_val),
                    b.get(i + 2).copied().and_then(hex_val),
                ) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
