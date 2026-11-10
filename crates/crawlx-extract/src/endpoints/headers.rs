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

/// URL parts of an RFC 8288 `Link` header value: every `<…>` piece of every
/// comma-separated member, parameters ignored.
#[must_use]
pub fn parse_link_header(value: &str) -> Vec<&str> {
    let mut urls = Vec::new();
    for chunk in value.split(',') {
        for piece in chunk.split(';') {
            let piece = piece.trim_matches(' ');
            if piece.len() >= 2 && piece.starts_with('<') && piece.ends_with('>') {
                urls.push(piece.trim_matches(|c| c == '<' || c == '>'));
            }
        }
    }
    urls
}

/// URL of a `Refresh` header / `meta http-equiv=refresh` value
/// (`5; url=/next`), `None` when there is no `url=` part.
#[must_use]
pub fn parse_refresh(value: &str) -> Option<&str> {
    let lower = value.to_ascii_lowercase();
    let idx = lower.find("url=")?;
    let rest = value[idx + 4..].trim_end_matches(';').trim();
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
}
