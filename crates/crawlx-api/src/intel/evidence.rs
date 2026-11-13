//! Retained evidence: loading page renditions as bounded sources, chunking them, and the
//! deterministic checks that decide whether a model's claim is grounded.
//!
//! Nothing here fetches anything. Sources come from the artifacts a run already retained; a
//! missing or expired artifact makes a field *unknown*, never a guessed value. A claim becomes
//! `observed` only when its quote occurs in the cited source text at a byte span this module
//! computed itself and the claimed value literally occurs in that quote.

use crate::errors::{ApiResult, HttpError};
use crate::routes::pages::{read_content, sorted_pages};
use crate::state::AppState;
use crawlx_core::hash::Digest;
use crawlx_core::repo::CrawlRun;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ops::Range;

/// Largest rendition read into a source (bytes); a larger rendition is reported, not cut.
pub const MAX_SOURCE_BYTES: usize = 512 * 1024;
/// Longest quote a claim may carry (characters).
pub const MAX_QUOTE_CHARS: usize = 2000;
/// Most retained renditions one request may cite.
pub const MAX_SOURCES_PER_REQUEST: usize = 8;
/// Chunk size sent to a model (bytes, on a character boundary).
pub const CHUNK_BYTES: usize = 8 * 1024;
/// Bytes two neighbouring chunks of one source share.
pub const CHUNK_OVERLAP: usize = 256;

/// One retained rendition offered as evidence.
#[derive(Clone, Debug)]
pub struct Source {
    /// The artifact id of the rendition; every citation uses it.
    pub id: String,
    /// Canonical URL of the page the rendition belongs to.
    pub url: String,
    /// `markdown` or `html`.
    pub kind: &'static str,
    /// The text after privacy projection; spans are byte offsets into this text.
    pub text: String,
    /// Digest of the retained bytes as read.
    pub digest: String,
    /// Whether projection changed the text.
    pub redacted: bool,
    /// HTTP status the page was fetched with.
    pub status: u16,
}

/// Which renditions a caller asks for.
#[derive(Clone, Debug, Default)]
pub struct Wanted {
    /// Artifact ids.
    pub artifacts: BTreeSet<String>,
    /// Canonical page URLs.
    pub urls: BTreeSet<String>,
}

/// Why a requested rendition is not a source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    /// What was requested.
    pub requested: String,
    /// `not_retained`, `unavailable` or `too_large`.
    pub reason: &'static str,
}

impl Missing {
    /// As JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({"requested": self.requested, "reason": self.reason})
    }
}

/// Source digest of retained bytes.
#[must_use]
pub fn source_digest(bytes: &[u8]) -> String {
    Digest::of("crawlx.evidence.source.v1", bytes).to_hex()
}

/// Load the wanted renditions of `run` (retained-only, run-scoped).
///
/// # Errors
/// Storage failures only; absent renditions are returned in the second element.
pub async fn load_sources(
    state: &AppState,
    run: &CrawlRun,
    wanted: &Wanted,
    max_sources: usize,
) -> ApiResult<(Vec<Source>, Vec<Missing>)> {
    let pages = sorted_pages(state, run, None).await?;
    let mut sources: Vec<Source> = Vec::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut missing = Vec::new();
    for page in &pages {
        let url = page.url.to_string();
        let mut url_served = false;
        for (kind, artifact) in [("markdown", &page.markdown), ("html", &page.html)] {
            let Some(artifact) = artifact else { continue };
            let id = artifact.id.to_string();
            let by_artifact = wanted.artifacts.contains(&id);
            // a URL request yields one rendition per page (markdown wins over html); an
            // artifact id always yields exactly that rendition
            let by_url = wanted.urls.contains(&url) && !url_served;
            if !(by_artifact || by_url) {
                continue;
            }
            found.insert(id.clone());
            if wanted.urls.contains(&url) {
                found.insert(url.clone());
            }
            if by_url {
                url_served = true;
            }
            if sources.len() >= max_sources {
                missing.push(Missing {
                    requested: id,
                    reason: "source_limit",
                });
                continue;
            }
            match read_content(state, run, artifact).await {
                None => missing.push(Missing {
                    requested: id,
                    reason: "unavailable",
                }),
                Some(bytes) if bytes.len() > MAX_SOURCE_BYTES => missing.push(Missing {
                    requested: id,
                    reason: "too_large",
                }),
                Some(bytes) => {
                    let original = String::from_utf8_lossy(&bytes).into_owned();
                    let text = match &state.ai.governor {
                        Some(g) => g.project_text(&original),
                        None => crawlx_core::secret::Redactor::new()
                            .redact_text(&original)
                            .into_inner(),
                    };
                    sources.push(Source {
                        id,
                        url: url.clone(),
                        kind,
                        redacted: text != original,
                        digest: source_digest(&bytes),
                        text,
                        status: page.status,
                    });
                }
            }
        }
    }
    for item in wanted.artifacts.iter().chain(&wanted.urls) {
        if !found.contains(item) {
            missing.push(Missing {
                requested: item.clone(),
                reason: "not_retained",
            });
        }
    }
    Ok((sources, missing))
}

/// Refuse a request whose expected digests do not match what is retained now.
///
/// # Errors
/// `409 stale_source` naming the artifact whose digest changed or that is no longer retained
/// or readable.
pub fn check_expected(
    sources: &[Source],
    expected: &std::collections::BTreeMap<String, String>,
) -> ApiResult<()> {
    for (artifact, digest) in expected {
        let stale = |why: &str| {
            HttpError::compat(
                axum::http::StatusCode::CONFLICT,
                "stale_source",
                format!("artifact {artifact} {why}"),
            )
        };
        match sources.iter().find(|s| &s.id == artifact) {
            None => return Err(stale("is not available as a source of this request")),
            Some(source) if &source.digest != digest => {
                return Err(stale("no longer has the expected digest"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// A model-visible slice of one source.
#[derive(Clone, Debug)]
pub struct Chunk {
    /// Record id the model cites: `<artifact id>.<index>`.
    pub record_id: String,
    /// Index into the source list.
    pub source: usize,
    /// Byte range within the source text.
    pub range: Range<usize>,
}

/// Split every source into overlapping chunks of at most [`CHUNK_BYTES`] bytes on character
/// boundaries. Returns the chunks that fit in `max_chunks` and whether any were left out.
#[must_use]
pub fn build_chunks(sources: &[Source], max_chunks: usize) -> (Vec<Chunk>, bool) {
    let mut chunks = Vec::new();
    let mut partial = false;
    for (index, source) in sources.iter().enumerate() {
        let text = &source.text;
        let mut start = 0usize;
        let mut n = 0usize;
        while start < text.len() {
            let mut end = (start + CHUNK_BYTES).min(text.len());
            while end < text.len() && !text.is_char_boundary(end) {
                end -= 1;
            }
            if chunks.len() >= max_chunks {
                partial = true;
                break;
            }
            chunks.push(Chunk {
                record_id: format!("{}.{n}", source.id),
                source: index,
                range: start..end,
            });
            n += 1;
            if end >= text.len() {
                break;
            }
            let mut next = end.saturating_sub(CHUNK_OVERLAP).max(start + 1);
            while next < text.len() && !text.is_char_boundary(next) {
                next += 1;
            }
            start = next;
        }
    }
    (chunks, partial)
}

/// `text` with whitespace runs collapsed to one space, and for each byte of the result the
/// byte range of the original character it came from.
fn collapse(text: &str) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(text.len());
    let mut map: Vec<(usize, usize)> = Vec::with_capacity(text.len());
    let mut in_space = false;
    for (i, c) in text.char_indices() {
        let end = i + c.len_utf8();
        if c.is_whitespace() {
            if !in_space && !out.is_empty() {
                out.push(' ');
                map.push((i, end));
            }
            in_space = true;
        } else {
            in_space = false;
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            out.push_str(s);
            map.extend(std::iter::repeat_n((i, end), s.len()));
        }
    }
    (out, map)
}

/// The byte span of `quote` inside `text`: an exact match first, then a whitespace-insensitive
/// match mapped back to original offsets. `None` when the quote does not occur.
#[must_use]
pub fn locate(text: &str, quote: &str) -> Option<Range<usize>> {
    if quote.trim().is_empty() {
        return None;
    }
    if let Some(start) = text.find(quote) {
        return Some(start..start + quote.len());
    }
    let (norm_text, map) = collapse(text);
    let (norm_quote, _) = collapse(quote);
    let norm_quote = norm_quote.trim_end().to_owned();
    if norm_quote.is_empty() {
        return None;
    }
    let at = norm_text.find(&norm_quote)?;
    let first = map.get(at)?.0;
    let last = map.get(at + norm_quote.len() - 1)?.1;
    Some(first..last)
}

fn norm_lower(text: &str) -> String {
    collapse(text).0.trim().to_lowercase()
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `needle` occurs in `hay` as a whole token (neighbours are not word characters).
fn token_in(hay: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        if !before.is_some_and(is_word) && !after.is_some_and(is_word) {
            return true;
        }
        from = start + hay[start..].chars().next().map_or(1, char::len_utf8);
        if from >= hay.len() {
            break;
        }
    }
    false
}

/// How a claimed value relates to its quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grounding {
    /// The value occurs literally in the quote.
    Literal,
    /// The quote is real but the value does not occur in it as such.
    Derived,
    /// The claim is not a scalar.
    NotScalar,
}

/// Decide whether `value` is literally present in `quote`.
#[must_use]
pub fn ground(value: &Value, quote: &str) -> Grounding {
    match value {
        Value::String(text) => {
            let needle = norm_lower(text);
            let hay = norm_lower(quote);
            if needle.is_empty() {
                return Grounding::Derived;
            }
            let ok = if needle.chars().count() < 3 {
                token_in(&hay, &needle)
            } else {
                hay.contains(&needle)
            };
            if ok {
                Grounding::Literal
            } else {
                Grounding::Derived
            }
        }
        Value::Number(number) => {
            let Some(want) = number.as_f64() else {
                return Grounding::Derived;
            };
            let mut token = String::new();
            let mut tokens = Vec::new();
            for c in quote.chars().chain(std::iter::once(' ')) {
                if c.is_ascii_digit() || (!token.is_empty() && matches!(c, '.' | ',')) {
                    token.push(c);
                } else {
                    if !token.is_empty() {
                        tokens.push(std::mem::take(&mut token));
                    }
                }
            }
            let found = tokens.iter().any(|t| {
                let trimmed = t.trim_end_matches(['.', ',']);
                let plain: String = trimmed.chars().filter(|c| *c != ',').collect();
                plain
                    .parse::<f64>()
                    .is_ok_and(|got| (got.abs() - want.abs()).abs() < 1e-9)
            });
            if found {
                Grounding::Literal
            } else {
                Grounding::Derived
            }
        }
        Value::Bool(_) | Value::Null => Grounding::Derived,
        Value::Array(_) | Value::Object(_) => Grounding::NotScalar,
    }
}

/// Whether `pointer` is an acceptable JSON pointer for a claim: at most eight tokens of
/// `[A-Za-z0-9_-]`, array indexes below 64.
#[must_use]
pub fn pointer_tokens(pointer: &str) -> Option<Vec<String>> {
    let rest = pointer.strip_prefix('/')?;
    let tokens: Vec<String> = rest.split('/').map(str::to_owned).collect();
    let ok = !tokens.is_empty()
        && tokens.len() <= 8
        && tokens.iter().all(|t| {
            !t.is_empty()
                && t.len() <= 64
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && t.parse::<usize>().map_or(true, |n| n < 64)
        });
    ok.then_some(tokens)
}

/// Set `value` at `tokens` inside `doc`, creating objects and appending to arrays only at
/// their end. `false` when the pointer conflicts with what is already there.
pub fn set_pointer(doc: &mut Value, tokens: &[String], value: Value) -> bool {
    let Some((head, rest)) = tokens.split_first() else {
        *doc = value;
        return true;
    };
    let index = head.parse::<usize>().ok();
    if doc.is_null() {
        *doc = if index.is_some() { json!([]) } else { json!({}) };
    }
    match (doc, index) {
        (Value::Object(map), _) => {
            let slot = map.entry(head.clone()).or_insert(Value::Null);
            set_pointer(slot, rest, value)
        }
        (Value::Array(items), Some(n)) => {
            if n > items.len() {
                return false;
            }
            if n == items.len() {
                items.push(Value::Null);
            }
            items
                .get_mut(n)
                .is_some_and(|slot| set_pointer(slot, rest, value))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn exact_and_whitespace_insensitive_quotes_have_exact_spans() {
        let text = "Price:   \n  EUR 1,299.00   per\tmonth";
        let exact = locate(text, "EUR 1,299.00").unwrap();
        assert_eq!(&text[exact], "EUR 1,299.00");
        let loose = locate(text, "Price: EUR 1,299.00 per month").unwrap();
        assert_eq!(
            &text[loose.clone()],
            text,
            "the span covers the original, whitespace included"
        );
        assert!(locate(text, "EUR 9,999").is_none());
        assert!(locate(text, "  ").is_none());
    }

    #[test]
    fn spans_are_valid_for_multibyte_text() {
        let text = "Größe: 42 — ½ Liter";
        let span = locate(text, "42 — ½").unwrap();
        assert_eq!(&text[span], "42 — ½");
    }

    #[test]
    fn grounding_is_literal_or_derived() {
        assert_eq!(
            ground(&json!("Acme Corp"), "Vendor: ACME   corp, Berlin"),
            Grounding::Literal
        );
        assert_eq!(ground(&json!("Globex"), "Vendor: Acme"), Grounding::Derived);
        assert_eq!(ground(&json!(1299), "EUR 1,299.00 per month"), Grounding::Literal);
        assert_eq!(ground(&json!(1300), "EUR 1,299.00 per month"), Grounding::Derived);
        assert_eq!(ground(&json!(true), "enabled"), Grounding::Derived);
        assert_eq!(ground(&json!({"a": 1}), "x"), Grounding::NotScalar);
    }

    #[test]
    fn short_scalars_need_whole_tokens() {
        assert_eq!(
            ground(&json!("ok"), "booking confirmed"),
            Grounding::Derived,
            "`ok` inside `booking`"
        );
        assert_eq!(ground(&json!("ok"), "status: ok."), Grounding::Literal);
        assert_eq!(ground(&json!(7), "page 17 of 70"), Grounding::Derived);
        assert_eq!(ground(&json!(7), "page 7 of 70"), Grounding::Literal);
    }

    #[test]
    fn pointers_are_bounded_and_assembled_safely() {
        assert!(pointer_tokens("/a/b/0").is_some());
        assert!(pointer_tokens("a/b").is_none());
        assert!(pointer_tokens("/a//b").is_none());
        assert!(pointer_tokens("/a/../b").is_none());
        assert!(pointer_tokens("/a/1000").is_none());
        assert!(pointer_tokens(&"/x".repeat(9)).is_none());
        let mut doc = Value::Null;
        assert!(set_pointer(
            &mut doc,
            &pointer_tokens("/items/0/url").unwrap(),
            json!("a")
        ));
        assert!(set_pointer(
            &mut doc,
            &pointer_tokens("/items/1/url").unwrap(),
            json!("b")
        ));
        assert!(
            !set_pointer(&mut doc, &pointer_tokens("/items/5/url").unwrap(), json!("c")),
            "no gaps"
        );
        assert!(
            !set_pointer(&mut doc, &pointer_tokens("/items/url").unwrap(), json!("d")),
            "array vs object"
        );
        assert_eq!(doc, json!({"items": [{"url": "a"}, {"url": "b"}]}));
    }

    #[test]
    fn chunks_overlap_and_cover_the_text() {
        let text = "é".repeat(10_000);
        let source = Source {
            id: "a1".to_owned(),
            url: "https://x.test/".to_owned(),
            kind: "markdown",
            text: text.clone(),
            digest: String::new(),
            redacted: false,
            status: 200,
        };
        let (chunks, partial) = build_chunks(&[source], 100);
        assert!(!partial);
        assert!(chunks.len() > 2);
        assert_eq!(chunks[0].range.start, 0);
        assert_eq!(chunks.last().unwrap().range.end, text.len());
        for pair in chunks.windows(2) {
            assert!(pair[1].range.start < pair[0].range.end, "neighbours overlap");
        }
        for chunk in &chunks {
            assert!(text.is_char_boundary(chunk.range.start) && text.is_char_boundary(chunk.range.end));
        }
        let source = Source {
            id: "a1".to_owned(),
            url: String::new(),
            kind: "markdown",
            text,
            digest: String::new(),
            redacted: false,
            status: 200,
        };
        let (limited, partial) = build_chunks(&[source], 2);
        assert_eq!(limited.len(), 2);
        assert!(partial);
    }
}
