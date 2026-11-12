//! Manual redirect handling: `Policy::none()` in the client,
//! `Location` resolution and credential stripping here, re-resolution and
//! re-check of every hop in `client`.

use crate::error::FetchError;
use crawlx_core::config::ReferrerPolicy;
use crawlx_core::url::ParamClass;
use http::{header, HeaderMap, HeaderValue};
use url::Url;

/// Default hop limit.
pub const DEFAULT_MAX_REDIRECTS: usize = 10;

/// Statuses the fetcher follows.
#[must_use]
pub const fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve the `Location` header against `base`. Only `GET`/`HEAD` are issued
/// by this plane, so the method never changes across hops.
///
/// # Errors
/// [`FetchError::InvalidRedirect`] when `Location` is missing, empty, not visible ASCII
/// or not a valid URL reference.
pub fn location(base: &Url, headers: &HeaderMap) -> Result<Url, FetchError> {
    let invalid = |reason: &str| FetchError::InvalidRedirect {
        from: base.to_string(),
        reason: reason.to_owned(),
    };
    let raw = headers
        .get(header::LOCATION)
        .ok_or_else(|| invalid("missing Location header"))?
        .to_str()
        .map_err(|_| invalid("Location is not visible ASCII"))?
        .trim();
    if raw.is_empty() {
        return Err(invalid("empty Location header"));
    }
    let mut next = base
        .join(raw)
        .map_err(|e| invalid(&format!("unparseable Location: {e}")))?;
    next.set_fragment(base.fragment().filter(|_| next.fragment().is_none()));
    Ok(next)
}

/// Drop credentials that must not follow a redirect to another origin.
pub fn strip_credentials(headers: &mut HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
    headers.remove(header::PROXY_AUTHORIZATION);
}

/// Longest `Referer` value sent whole; a longer full URL is reduced to its origin.
const MAX_REFERRER_BYTES: usize = 4096;

/// Query-parameter name fragments that mark a secret whatever the built-in classes say.
const SECRET_NAME_PARTS: [&str; 10] = [
    "token",
    "secret",
    "passw",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "signature",
    "session",
    "auth",
];

/// Shortest query value that can be an opaque secret by its shape alone.
const SECRET_VALUE_MIN_LEN: usize = 24;

/// Entropy in bits per character from which a long opaque query value counts as a secret.
const SECRET_VALUE_MIN_ENTROPY: f64 = 3.5;

/// The page a request was found on and the policy that decides which part of its URL the
/// request carries as `Referer`.
///
/// The stored source never holds credentials, a fragment or a secret query parameter, so no
/// header value computed from it can leak one.
#[derive(Clone, Debug)]
pub struct Referrer {
    source: Url,
    policy: ReferrerPolicy,
}

impl Referrer {
    /// The referrer of a request found on `source`. `echoes_secret` tells whether a query value
    /// holds a configured secret. `None` when the policy sends nothing or `source` is not an
    /// `http(s)` URL.
    #[must_use]
    pub fn new(source: &Url, policy: ReferrerPolicy, echoes_secret: &dyn Fn(&str) -> bool) -> Option<Self> {
        if policy == ReferrerPolicy::NoReferrer || !matches!(source.scheme(), "http" | "https") {
            return None;
        }
        Some(Self {
            source: redact_source(source, echoes_secret),
            policy,
        })
    }

    /// The sanitized page URL.
    #[must_use]
    pub const fn source(&self) -> &Url {
        &self.source
    }

    /// The `Referer` value for a request to `target`, or `None` when the policy sends none to it.
    /// A redirect hop is judged against its own target: the referrer stays the page the request
    /// was found on.
    #[must_use]
    pub fn header_for(&self, target: &Url) -> Option<HeaderValue> {
        let downgrade = self.source.scheme() == "https" && target.scheme() == "http";
        let same_origin = self.source.origin() == target.origin();
        let value = match self.policy {
            ReferrerPolicy::NoReferrer => return None,
            ReferrerPolicy::NoReferrerWhenDowngrade if downgrade => return None,
            ReferrerPolicy::SameOrigin if !same_origin => return None,
            ReferrerPolicy::StrictOrigin | ReferrerPolicy::StrictOriginWhenCrossOrigin if downgrade => {
                return None
            }
            ReferrerPolicy::Origin | ReferrerPolicy::StrictOrigin => self.origin_only(),
            ReferrerPolicy::OriginWhenCrossOrigin | ReferrerPolicy::StrictOriginWhenCrossOrigin
                if !same_origin =>
            {
                self.origin_only()
            }
            _ => self.full(),
        };
        HeaderValue::from_str(&value).ok()
    }

    fn origin_only(&self) -> String {
        let mut origin = self.source.clone();
        origin.set_path("");
        origin.set_query(None);
        origin.into()
    }

    fn full(&self) -> String {
        if self.source.as_str().len() > MAX_REFERRER_BYTES {
            self.origin_only()
        } else {
            self.source.as_str().to_owned()
        }
    }
}

/// `source` without credentials, fragment and secret query parameters.
fn redact_source(source: &Url, echoes_secret: &dyn Fn(&str) -> bool) -> Url {
    let mut out = source.clone();
    let _ = out.set_username("");
    let _ = out.set_password(None);
    out.set_fragment(None);
    if let Some(query) = source.query() {
        let kept: Vec<&str> = query
            .split('&')
            .filter(|segment| !segment.is_empty() && !is_secret_segment(segment, echoes_secret))
            .collect();
        let kept = kept.join("&");
        out.set_query((!kept.is_empty()).then_some(kept.as_str()));
    }
    out
}

/// Does the raw query segment `name=value` carry a secret: a session or credential parameter by
/// name, an opaque high-entropy value, or a configured secret echoed back?
fn is_secret_segment(segment: &str, echoes_secret: &dyn Fn(&str) -> bool) -> bool {
    let (name, value) = url::form_urlencoded::parse(segment.as_bytes())
        .next()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    crawlx_url::params::builtin_class(&lower, &name, &value) == Some(ParamClass::Session)
        || SECRET_NAME_PARTS.iter().any(|part| lower.contains(part))
        || (value.len() >= SECRET_VALUE_MIN_LEN
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'='))
            && crawlx_url::shannon_entropy(&value) >= SECRET_VALUE_MIN_ENTROPY)
        || echoes_secret(&value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn referrer(source: &str, policy: ReferrerPolicy) -> Referrer {
        Referrer::new(&Url::parse(source).unwrap(), policy, &|_| false).unwrap()
    }

    fn sent(referrer: &Referrer, target: &str) -> Option<String> {
        referrer
            .header_for(&Url::parse(target).unwrap())
            .map(|value| value.to_str().unwrap().to_owned())
    }

    #[test]
    fn every_policy_follows_the_standard_table() {
        let page = "https://a.test/dir/page?x=1";
        let full = Some(page.to_owned());
        let origin = Some("https://a.test/".to_owned());
        let cases: [(ReferrerPolicy, [Option<String>; 4]); 7] = [
            // same origin, cross origin, https to http downgrade, http to https
            (
                ReferrerPolicy::NoReferrerWhenDowngrade,
                [full.clone(), full.clone(), None, full.clone()],
            ),
            (ReferrerPolicy::SameOrigin, [full.clone(), None, None, None]),
            (
                ReferrerPolicy::Origin,
                [origin.clone(), origin.clone(), origin.clone(), origin.clone()],
            ),
            (
                ReferrerPolicy::StrictOrigin,
                [origin.clone(), origin.clone(), None, origin.clone()],
            ),
            (
                ReferrerPolicy::OriginWhenCrossOrigin,
                [full.clone(), origin.clone(), origin.clone(), origin.clone()],
            ),
            (
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                [full.clone(), origin.clone(), None, origin.clone()],
            ),
            (
                ReferrerPolicy::UnsafeUrl,
                [full.clone(), full.clone(), full.clone(), full.clone()],
            ),
        ];
        let targets = [
            "https://a.test/other",
            "https://b.test/x",
            "http://b.test/x",
            "https://a.test/other",
        ];
        for (policy, expected) in cases {
            for (index, (target, want)) in targets.iter().zip(expected).enumerate() {
                // the fourth case judges an http source against an https target
                let source = if index == 3 {
                    "http://a.test/dir/page?x=1"
                } else {
                    page
                };
                let r = referrer(source, policy);
                let want = match (&want, index) {
                    (Some(url), 3) if url.starts_with("https://") => {
                        Some(url.replacen("https://", "http://", 1))
                    }
                    _ => want.clone(),
                };
                assert_eq!(sent(&r, target), want, "{policy:?} -> {target}");
            }
        }
        assert!(Referrer::new(&Url::parse(page).unwrap(), ReferrerPolicy::NoReferrer, &|_| false).is_none());
        assert!(Referrer::new(
            &Url::parse("ftp://a.test/").unwrap(),
            ReferrerPolicy::UnsafeUrl,
            &|_| false
        )
        .is_none());
    }

    #[test]
    fn the_source_never_carries_credentials_fragment_or_secret_parameters() {
        let source = Url::parse(
            "https://user:pw@a.test/p?keep=1&token=abc&Session_Id=7&api_key=k&q=a%20b&\
             blob=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg&echo=configured-secret&sig=zz#frag",
        )
        .unwrap();
        let r = Referrer::new(&source, ReferrerPolicy::UnsafeUrl, &|v| {
            v.contains("configured-secret")
        })
        .unwrap();
        assert_eq!(r.source().as_str(), "https://a.test/p?keep=1&q=a%20b");
        assert_eq!(
            sent(&r, "https://a.test/x").as_deref(),
            Some("https://a.test/p?keep=1&q=a%20b")
        );
        // only secrets: the query disappears completely
        let r = referrer("https://a.test/p?token=abc", ReferrerPolicy::UnsafeUrl);
        assert_eq!(r.source().as_str(), "https://a.test/p");
    }

    #[test]
    fn an_over_long_full_referrer_falls_back_to_the_origin() {
        let long = format!("https://a.test/{}", "p".repeat(5000));
        let r = referrer(&long, ReferrerPolicy::UnsafeUrl);
        assert_eq!(sent(&r, "https://b.test/").as_deref(), Some("https://a.test/"));
    }

    fn h(loc: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(header::LOCATION, HeaderValue::from_str(loc).unwrap());
        m
    }

    #[test]
    fn resolves_relative_and_absolute() {
        let base = Url::parse("https://a.test/dir/page?x=1").unwrap();
        assert_eq!(
            location(&base, &h("/other")).unwrap().as_str(),
            "https://a.test/other"
        );
        assert_eq!(
            location(&base, &h("sib")).unwrap().as_str(),
            "https://a.test/dir/sib"
        );
        assert_eq!(
            location(&base, &h("//b.test/z")).unwrap().as_str(),
            "https://b.test/z"
        );
        assert_eq!(
            location(&base, &h("http://c.test:81/")).unwrap().as_str(),
            "http://c.test:81/"
        );
    }

    #[test]
    fn missing_or_empty_location_is_invalid() {
        let base = Url::parse("https://a.test/").unwrap();
        assert!(matches!(
            location(&base, &HeaderMap::new()),
            Err(FetchError::InvalidRedirect { .. })
        ));
        assert!(matches!(
            location(&base, &h(" ")),
            Err(FetchError::InvalidRedirect { .. })
        ));
    }

    #[test]
    fn classifies_statuses() {
        for s in [301, 302, 303, 307, 308] {
            assert!(is_redirect(s));
        }
        for s in [200, 300, 304, 305, 404] {
            assert!(!is_redirect(s));
        }
    }

    #[test]
    fn strips_credentials() {
        let mut m = HeaderMap::new();
        m.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        m.insert(header::COOKIE, HeaderValue::from_static("a=b"));
        m.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_credentials(&mut m);
        assert_eq!(m.len(), 1);
    }
}
