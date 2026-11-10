//! Egress routing and traffic redaction.
//!
//! Page-initiated requests bypass the HTTP fetcher, so Chromium is pointed at the
//! loopback egress proxy. This module owns the proxy/resolver/WebRTC flags (the launch
//! profile cannot touch them), recognizes the proxy's denial responses, and redacts
//! captured traffic before it leaves the browser layer.

/// Response header the egress proxy sets on denied requests (`crawlx-fetch::egress`).
pub const DENIED_HEADER: &str = "x-crawlx-egress-denied";

/// Placeholder written in place of a secret value; names are kept.
pub const REDACTED: &str = "[redacted]";

/// Host suffixes of the browser vendor's services the stock pinned Chrome-for-Testing `155.0.8059.84`
/// contacts on its own, unrelated to any crawled page (see `docs/design/data-and-secrets.md`).
///
/// The egress proxy denies every such request before any foreign connection and logs it; the
/// stock browser cannot be made to attempt none (a source-patched, self-hosted Chromium is
/// post-release work). Tests use this list to tell this browser-owned background traffic
/// from a page-initiated out-of-scope attempt, which must still fail them. A host matches
/// when it equals a suffix or is a subdomain of it; see [`is_browser_background_host`].
///
/// Observed families: the account-service host, the component-updater hosts, the
/// autofill-crowdsourcing host and the push-checkin host.
pub const BROWSER_BACKGROUND_HOST_SUFFIXES: [&str; 3] = [
    "google.com",     // wire-compat: browser-owned background host suffix
    "googleapis.com", // wire-compat: browser-owned background host suffix
    "gvt1.com",       // wire-compat: browser-owned background host suffix
];

/// Is `host` a known browser-owned background service host
/// ([`BROWSER_BACKGROUND_HOST_SUFFIXES`])? Exact suffix match on a label boundary, ASCII
/// case-insensitive: a host that merely ends in the same letters as a suffix does not match.
#[must_use]
pub fn is_browser_background_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    BROWSER_BACKGROUND_HOST_SUFFIXES.iter().any(|suffix| {
        host.len().checked_sub(suffix.len()).is_some_and(|at| {
            host.get(at..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
                && (at == 0 || host.get(..at).is_some_and(|head| head.ends_with('.')))
        })
    })
}

/// Chromium flags that route everything through the loopback egress proxy.
///
/// With no proxy port (tests only) the page can reach loopback directly, and the WebRTC
/// policy is still applied.
#[must_use]
pub fn egress_flags(port: Option<u16>) -> Vec<String> {
    let mut flags = Vec::new();
    if let Some(port) = port {
        flags.push(format!("--proxy-server=http://127.0.0.1:{port}"));
        flags.push("--proxy-bypass-list=<-loopback>".to_owned());
        flags.push("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_owned());
    }
    flags.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned());
    flags
}

/// Is this a response the egress proxy produced to deny the request?
#[must_use]
pub fn is_egress_denied(status: u16, headers: &[(String, String)]) -> bool {
    status == 403 && headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(DENIED_HEADER))
}

/// Header names whose values never leave the browser layer.
const SECRET_HEADERS: [&str; 4] = ["authorization", "cookie", "set-cookie", "proxy-authorization"];

/// Query parameter names whose values are always redacted.
const SECRET_PARAM_HINTS: [&str; 14] = [
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "session",
    "sig",
    "signature",
    "jwt",
    "bearer",
    "apikey",
    "api_key",
    "key",
];

/// Drop the values of secret-bearing headers; names are kept.
#[must_use]
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            if SECRET_HEADERS.iter().any(|h| k.eq_ignore_ascii_case(h)) {
                (k.clone(), REDACTED.to_owned())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// A value that looks like a credential: long, URL-safe, mixed letters and digits, or a JWT.
#[must_use]
pub fn looks_like_token(value: &str) -> bool {
    let v = value.trim();
    if v.len() < 20 {
        return false;
    }
    let url_safe = v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '/' | '='));
    if !url_safe {
        return false;
    }
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
    let jwt = v.split('.').count() == 3 && v.split('.').all(|p| !p.is_empty());
    jwt || (has_digit && has_alpha)
}

fn param_name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SECRET_PARAM_HINTS.iter().any(|h| lower.contains(h))
}

/// Redact a URL for capture: userinfo and fragment are removed, token-shaped query
/// values (or values of secret-named parameters) are replaced, parameter names stay.
#[must_use]
pub fn redact_url(raw: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(raw) else {
        return raw.split(['?', '#']).next().unwrap_or_default().to_owned();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_fragment(None);
    if let Some(query) = parsed.query() {
        let redacted: Vec<String> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((name, value)) if param_name_is_secret(name) || looks_like_token(value) => {
                    format!("{name}={REDACTED}")
                }
                _ => pair.to_owned(),
            })
            .collect();
        if redacted.is_empty() {
            parsed.set_query(None);
        } else {
            parsed.set_query(Some(&redacted.join("&")));
        }
    }
    parsed.to_string()
}

/// Origin (`scheme://host[:port]`) of a URL string, `None` when it has none.
#[must_use]
pub fn origin_of_str(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    let origin = parsed.origin();
    if origin.is_tuple() {
        Some(origin.ascii_serialization())
    } else {
        None
    }
}

/// Is `request_url` on a different origin than `page_url`?
#[must_use]
pub fn is_third_party(page_url: &str, request_url: &str) -> bool {
    match (origin_of_str(page_url), origin_of_str(request_url)) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn background_hosts_match_on_label_boundaries_only() {
        // wire-compat: hostnames the stock browser contacts on its own
        for host in [
            "accounts.google.com",             // wire-compat: browser-owned background host
            "android.clients.google.com",      // wire-compat: browser-owned background host
            "content-autofill.googleapis.com", // wire-compat: browser-owned background host
            "redirector.gvt1.com",             // wire-compat: browser-owned background host
            "REDIRECTOR.GVT1.COM",             // wire-compat: browser-owned background host
            "google.com.",                     // wire-compat: browser-owned background host
        ] {
            assert!(is_browser_background_host(host), "{host}");
        }
        for host in [
            "evilgoogle.com",       // wire-compat: near-miss host
            "google.com.evil.test", // wire-compat: near-miss host
            "127.0.0.1",
            "gvt1.com.cn",
            "",
        ] {
            assert!(!is_browser_background_host(host), "{host}");
        }
    }

    #[test]
    fn proxy_flags_are_exact() {
        assert_eq!(
            egress_flags(Some(3128)),
            vec![
                "--proxy-server=http://127.0.0.1:3128",
                "--proxy-bypass-list=<-loopback>",
                "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ]
        );
        assert_eq!(
            egress_flags(None),
            vec!["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
        );
    }

    #[test]
    fn denial_requires_403_and_header() {
        let h = vec![("X-Crawlx-Egress-Denied".to_owned(), "private-range".to_owned())];
        assert!(is_egress_denied(403, &h));
        assert!(!is_egress_denied(200, &h));
        assert!(!is_egress_denied(403, &[]));
    }

    #[test]
    fn secret_headers_lose_values_but_keep_names() {
        let h = vec![
            ("Authorization".to_owned(), "Bearer abc".to_owned()),
            ("cookie".to_owned(), "sid=1".to_owned()),
            ("Set-Cookie".to_owned(), "sid=1; HttpOnly".to_owned()),
            ("Accept".to_owned(), "text/html".to_owned()),
        ];
        let r = redact_headers(&h);
        assert_eq!(r[0], ("Authorization".to_owned(), REDACTED.to_owned()));
        assert_eq!(r[1], ("cookie".to_owned(), REDACTED.to_owned()));
        assert_eq!(r[2], ("Set-Cookie".to_owned(), REDACTED.to_owned()));
        assert_eq!(r[3], ("Accept".to_owned(), "text/html".to_owned()));
    }

    #[test]
    fn token_shaped_query_values_are_redacted() {
        let u = redact_url(
            "https://user:pw@example.com/p?page=2&token=abc&x=0123456789abcdef0123456789&q=hello#frag",
        );
        assert_eq!(
            u,
            "https://example.com/p?page=2&token=[redacted]&x=[redacted]&q=hello"
        );
        assert_eq!(redact_url("https://example.com/a"), "https://example.com/a");
    }

    #[test]
    fn token_heuristic() {
        assert!(looks_like_token("eyJhbGciOi.eyJzdWIiOiIx.c2ln"));
        assert!(looks_like_token("a1b2c3d4e5f6a1b2c3d4e5"));
        assert!(!looks_like_token("short1"));
        assert!(!looks_like_token("just-letters-no-digits-here"));
        assert!(!looks_like_token("has spaces and 1234567890 digits"));
    }

    #[test]
    fn third_party_by_origin() {
        assert!(is_third_party("https://a.example/x", "https://cdn.example/y"));
        assert!(!is_third_party("https://a.example/x", "https://a.example/y?z=1"));
        assert!(is_third_party("https://a.example/", "http://a.example/"));
        assert!(!is_third_party("about:blank", "https://a.example/"));
    }
}
