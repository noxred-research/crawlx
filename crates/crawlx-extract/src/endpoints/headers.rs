//! Header parsers: `Content-Location`, `Link`, `Location`, `Refresh`.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md
//! (`header*Parser`, `ParseLinkTag`,
//! `ParseRefreshTag`).

use url::Url;

use super::{Confidence, DiscoveredEndpoint, EndpointSource};

/// `Content-Location` header.
pub const CONTENT_LOCATION: EndpointSource = EndpointSource {
    tag: "header",
    attribute: "content-location",
};
/// `Link` header `<url>` parts.
pub const LINK: EndpointSource = EndpointSource {
    tag: "header",
    attribute: "link",
};
/// `Location` header.
pub const LOCATION: EndpointSource = EndpointSource {
    tag: "header",
    attribute: "location",
};
/// `Refresh` header `url=` part.
pub const REFRESH: EndpointSource = EndpointSource {
    tag: "header",
    attribute: "refresh",
};

/// URL parts of an RFC 8288 `Link` header value: every `<…>` target of every
/// member, parameters ignored. A target may contain commas and semicolons, and
/// a quoted parameter may contain `<…>` text; neither splits a member.
#[must_use]
pub fn parse_link_header(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut urls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => {
                let start = i + 1;
                let Some(len) = value[start..].find('>') else {
                    break;
                };
                urls.push(value[start..start + len].trim());
                i = start + len + 1;
            }
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            _ => i += 1,
        }
    }
    urls
}

/// URL of a `Refresh` header / `meta http-equiv=refresh` value: a delay, a
/// separator, then `url=<target>` or the bare target (`5; url=/next`,
/// `0;/next`). `None` when no target follows the delay.
#[must_use]
pub fn parse_refresh(value: &str) -> Option<&str> {
    let rest = value
        .trim_start()
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.')
        .trim_start_matches(|c: char| c.is_ascii_whitespace() || c == ';' || c == ',');
    let rest = match rest.get(..3) {
        Some(head) if head.eq_ignore_ascii_case("url") => rest[3..]
            .trim_start()
            .strip_prefix('=')
            .map_or(rest, str::trim_start),
        _ => rest,
    };
    let rest = rest.trim_end_matches(';').trim();
    let rest = rest.trim_matches(|c| c == '"' || c == '\'');
    (!rest.is_empty()).then_some(rest)
}

/// Run the four header parsers over `headers` (name, value), resolving
/// against `page`.
pub(super) fn parse(headers: &[(String, String)], page: &Url, depth: u32, out: &mut Vec<DiscoveredEndpoint>) {
    for (name, value) in headers {
        let source = match name.to_ascii_lowercase().as_str() {
            "content-location" => CONTENT_LOCATION,
            "link" => LINK,
            "location" => LOCATION,
            "refresh" => REFRESH,
            _ => continue,
        };
        match source.attribute {
            "link" => {
                for raw in parse_link_header(value) {
                    out.extend(DiscoveredEndpoint::get(
                        page,
                        raw,
                        source,
                        Confidence::Structural,
                        depth,
                    ));
                }
            }
            "refresh" => {
                if let Some(raw) = parse_refresh(value) {
                    out.extend(DiscoveredEndpoint::get(
                        page,
                        raw,
                        source,
                        Confidence::Structural,
                        depth,
                    ));
                }
            }
            _ => out.extend(DiscoveredEndpoint::get(
                page,
                value,
                source,
                Confidence::Structural,
                depth,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn link_header_parts() {
        let v = r#"</a.css>; rel=preload; as=style, <https://x.example/b>; rel="next""#;
        assert_eq!(parse_link_header(v), vec!["/a.css", "https://x.example/b"]);
        assert!(parse_link_header("rel=next").is_empty());
    }

    #[test]
    fn refresh_values() {
        assert_eq!(parse_refresh("5; url=/next"), Some("/next"));
        assert_eq!(parse_refresh("0;URL='/q';"), Some("/q"));
        assert_eq!(parse_refresh("5"), None);
        assert_eq!(parse_refresh("5; url="), None);
    }

    #[test]
    fn link_targets_may_contain_commas_and_quoted_params_may_contain_brackets() {
        let v = r#"</s?ids=1,2;3>; rel="next", <https://x.example/p>; title="a <b> c, d"; rel=prev, <unterminated"#;
        assert_eq!(parse_link_header(v), vec!["/s?ids=1,2;3", "https://x.example/p"]);
        assert_eq!(parse_link_header(r#"<a>; title="esc \" <q>""#), vec!["a"]);
        assert!(parse_link_header("").is_empty());
    }

    #[test]
    fn refresh_accepts_a_bare_target_and_spaced_url_keyword() {
        assert_eq!(parse_refresh("0;/bare"), Some("/bare"));
        assert_eq!(parse_refresh("0, /comma"), Some("/comma"));
        assert_eq!(parse_refresh("2.5 ; URL = /spaced"), Some("/spaced"));
        assert_eq!(parse_refresh("url=/no-delay"), Some("/no-delay"));
        assert_eq!(parse_refresh(""), None);
        assert_eq!(parse_refresh(";"), None);
    }
}
