//! Manual redirect handling: `Policy::none()` in the client,
//! `Location` resolution and credential stripping here, re-resolution and
//! re-check of every hop in `client`.

use crate::error::FetchError;
use http::{header, HeaderMap};
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use http::HeaderValue;

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
