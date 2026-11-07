//! Form submission encodings (HTML living standard "form submission"):
//! `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
//! and a JSON object for `application/json`.

use std::collections::BTreeSet;

use crawlx_core::seed::CrawlSeed;
use url::form_urlencoded;

use super::values::pick;

/// A negotiated body encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Encoding {
    UrlEncoded,
    Multipart,
    TextPlain,
    Json,
}

impl Encoding {
    /// Encoding named by an `enctype` attribute; anything unknown falls back
    /// to URL encoding, as browsers do.
    pub(super) fn from_enctype(enctype: Option<&str>) -> Self {
        let media = enctype
            .and_then(|e| e.split(';').next())
            .map(|e| e.trim().to_ascii_lowercase())
            .unwrap_or_default();
        match media.as_str() {
            "multipart/form-data" => Self::Multipart,
            "text/plain" => Self::TextPlain,
            "application/json" => Self::Json,
            _ => Self::UrlEncoded,
        }
    }
}

/// `name=value&...` with form-urlencoded escaping.
pub(super) fn urlencoded(pairs: &[(String, String)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .finish()
}

/// One `name=value` line per pair, CRLF-terminated.
fn text_plain(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(k, v)| format!("{k}={v}\r\n")).collect()
}

/// A JSON object; a repeated name keeps its last value.
fn json(pairs: &[(String, String)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::Value::Object(map).to_string()
}

fn escape_disposition(s: &str) -> String {
    s.replace('\r', "%0D").replace('\n', "%0A").replace('"', "%22")
}

/// A `multipart/form-data` body. Names in `files` are file controls with no
/// file chosen: an empty `filename`, as browsers send. The boundary derives
/// from the seed, the action and the data, and is re-drawn until it occurs in
/// none of them.
fn multipart(
    pairs: &[(String, String)],
    files: &BTreeSet<String>,
    seed: &CrawlSeed,
    action: &str,
) -> (String, String) {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = seed.rng("extract/form_fill/boundary/v1", &[action.as_bytes()]);
    let boundary = loop {
        let token: String = (0..24)
            .map(|_| char::from(HEX[pick(&mut rng, HEX.len())]))
            .collect();
        let candidate = format!("----crawlxFormBoundary{token}");
        if !pairs
            .iter()
            .any(|(k, v)| k.contains(&candidate) || v.contains(&candidate))
        {
            break candidate;
        }
    };
    let mut body = String::new();
    for (name, value) in pairs {
        body.push_str("--");
        body.push_str(&boundary);
        body.push_str("\r\nContent-Disposition: form-data; name=\"");
        body.push_str(&escape_disposition(name));
        if files.contains(name) {
            body.push_str("\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n");
        } else {
            body.push_str("\"\r\n\r\n");
            body.push_str(value);
            body.push_str("\r\n");
        }
    }
    body.push_str("--");
    body.push_str(&boundary);
    body.push_str("--\r\n");
    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// Encode `pairs` (document order) as a request body: `(content_type, body)`.
pub(super) fn encode(
    encoding: Encoding,
    pairs: &[(String, String)],
    files: &BTreeSet<String>,
    seed: &CrawlSeed,
    action: &str,
) -> (String, String) {
    match encoding {
        Encoding::UrlEncoded => ("application/x-www-form-urlencoded".to_owned(), urlencoded(pairs)),
        Encoding::Multipart => multipart(pairs, files, seed, action),
        Encoding::TextPlain => ("text/plain".to_owned(), text_plain(pairs)),
        Encoding::Json => ("application/json".to_owned(), json(pairs)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn enctype_negotiation() {
        assert_eq!(Encoding::from_enctype(None), Encoding::UrlEncoded);
        assert_eq!(
            Encoding::from_enctype(Some("Multipart/Form-Data; x=y")),
            Encoding::Multipart
        );
        assert_eq!(Encoding::from_enctype(Some("text/plain")), Encoding::TextPlain);
        assert_eq!(Encoding::from_enctype(Some("application/json")), Encoding::Json);
        assert_eq!(Encoding::from_enctype(Some("bogus/type")), Encoding::UrlEncoded);
    }

    #[test]
    fn urlencoding_escapes_reserved_characters() {
        assert_eq!(
            urlencoded(&pairs(&[("a b", "c&d=e"), ("q", "é")])),
            "a+b=c%26d%3De&q=%C3%A9"
        );
    }

    #[test]
    fn multipart_is_well_formed_and_deterministic() {
        let data = pairs(&[("a", "1"), ("up", ""), ("na\"me", "x\r\ny")]);
        let files: BTreeSet<String> = ["up".to_owned()].into();
        let (ct, body) = multipart(&data, &files, &CrawlSeed(3), "https://e.test/u");
        let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
        assert_eq!(body.matches(&format!("--{boundary}\r\n")).count(), 3);
        assert!(body.ends_with(&format!("--{boundary}--\r\n")));
        assert!(body.contains("name=\"a\"\r\n\r\n1\r\n"));
        assert!(
            body.contains("name=\"up\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n")
        );
        assert!(body.contains("name=\"na%22me\""));
        assert_eq!(
            multipart(&data, &files, &CrawlSeed(3), "https://e.test/u").1,
            body
        );
        assert_ne!(multipart(&data, &files, &CrawlSeed(4), "https://e.test/u").0, ct);
    }

    #[test]
    fn text_plain_and_json() {
        let data = pairs(&[("a", "1"), ("b", "2"), ("a", "3")]);
        assert_eq!(text_plain(&data), "a=1\r\nb=2\r\na=3\r\n");
        assert_eq!(json(&data), r#"{"a":"3","b":"2"}"#);
    }
}
