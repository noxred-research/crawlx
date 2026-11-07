//! Pure bounded RSS 2.0, RSS 1.0/RDF, Atom and JSON Feed parsers.
//!
//! No I/O is performed. Resolved references are proposals, never network authority.
//! DTDs and entity declarations are rejected. Namespace aliases are resolved by URI.

use crawlx_core::discovery::{DiscoveryErrorV1, SourceDiscoveryPolicyV1};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::BTreeSet;
use url::Url;

const ATOM: &[u8] = b"http://www.w3.org/2005/Atom";
const RSS1: &[u8] = b"http://purl.org/rss/1.0/";
const RDF: &[u8] = b"http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const MEDIA: &[u8] = b"http://search.yahoo.com/mrss/";
const TRENDS: &[u8] = b"https://trends.google.com/trending/rss";
const MAX_URL_BYTES: usize = 4096;
const MAX_HINT_BYTES: usize = 2048;

/// Detected declared feed format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeedKind {
    /// RSS 2.0 channel.
    Rss,
    /// RDF/RSS 1.0.
    Rdf,
    /// Atom 1.0.
    Atom,
    /// JSON Feed 1.0 or 1.1.
    Json,
}
/// Article candidate with untrusted publisher metadata hints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FeedEntry {
    /// Resolved HTML alternate or article URL, not a self feed URL.
    pub url: Url,
    /// Untrusted title hint.
    pub title: Option<String>,
    /// Untrusted publication date, not a verified timestamp.
    pub date: Option<String>,
    /// Untrusted publisher hint.
    pub publisher: Option<String>,
    /// Media references; only the worker may probe them.
    pub media: Vec<Url>,
    /// Explicit entry-level next/read-more references.
    pub read_more: Vec<Url>,
}
/// One parsed source document.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FeedDocument {
    /// Source representation.
    pub kind: FeedKind,
    /// Article candidates in source order, deduplicated by resolved URL.
    pub entries: Vec<FeedEntry>,
    /// Feed pagination references, not article records.
    pub next: Vec<Url>,
    /// Entries exceeded caller's configured cap.
    pub truncated: bool,
}
/// Feed parsing failure, retaining malformed input's source error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeedError {
    /// Strict policy or resource limit failure.
    #[error(transparent)]
    Policy(#[from] DiscoveryErrorV1),
    /// Malformed XML.
    #[error("invalid feed xml")]
    Xml(#[from] quick_xml::Error),
    /// Malformed JSON.
    #[error("invalid json feed")]
    Json(#[from] serde_json::Error),
    /// Malformed or forbidden sitemap representation.
    #[error("invalid sitemap source")]
    Sitemap(#[from] crate::error::UrlError),
}
/// Parse an already acquired decoded body. Never resolves DNS or opens sockets.
///
/// # Errors
/// Rejects unknown formats, DTD/entity declarations, invalid namespaces or URLs, malformed
/// documents and byte/nesting limits. Entry overflow produces explicit `truncated` output.
pub fn parse_feed(
    bytes: &[u8],
    base: &Url,
    policy: &SourceDiscoveryPolicyV1,
) -> Result<FeedDocument, FeedError> {
    policy
        .validate()
        .map_err(|error| DiscoveryErrorV1::Protocol(error.to_string()))?;
    if bytes.len() > policy.max_feed_bytes {
        return Err(DiscoveryErrorV1::Limit("feed_bytes").into());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    match bytes.iter().find(|b| !b.is_ascii_whitespace()) {
        Some(b'{') => parse_json(bytes, base, policy),
        Some(b'<') => parse_xml(bytes, base, policy),
        _ => Err(DiscoveryErrorV1::Protocol("unknown feed format".into()).into()),
    }
}
fn protocol(reason: &str) -> FeedError {
    DiscoveryErrorV1::Protocol(reason.into()).into()
}
fn reference(base: &Url, value: &str) -> Option<Url> {
    if value.len() > MAX_URL_BYTES {
        return None;
    }
    let mut url = base.join(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    url.set_fragment(None);
    if url.as_str().len() > MAX_URL_BYTES {
        return None;
    }
    Some(url)
}
fn hint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .take_while(|i| *i <= MAX_HINT_BYTES)
        .last()
        .unwrap_or(0);
    Some(trimmed[..end].to_owned())
}
fn unique_push(urls: &mut Vec<Url>, url: Url, cap: usize) {
    if urls.len() < cap && !urls.contains(&url) {
        urls.push(url);
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    None,
    Atom,
    Rss1,
    Rdf,
    Media,
    Trends,
    Other,
}
fn namespace(resolved: ResolveResult<'_>) -> Result<Namespace, FeedError> {
    match resolved {
        ResolveResult::Unbound => Ok(Namespace::None),
        ResolveResult::Unknown(_) => Err(protocol("unbound namespace prefix")),
        ResolveResult::Bound(ns) => Ok(match ns.as_ref() {
            ATOM => Namespace::Atom,
            RSS1 => Namespace::Rss1,
            RDF => Namespace::Rdf,
            MEDIA => Namespace::Media,
            TRENDS => Namespace::Trends,
            _ => Namespace::Other,
        }),
    }
}
#[derive(Default)]
struct PendingEntry {
    url: Option<Url>,
    title: Option<String>,
    date: Option<String>,
    publisher: Option<String>,
    media: Vec<Url>,
    read_more: Vec<Url>,
    related: Vec<Url>,
}
// Keep literal whitespace unchanged while resolving only XML's built-in references.
fn attribute_text<'a>(
    attribute: &'a quick_xml::events::attributes::Attribute<'_>,
) -> Result<std::borrow::Cow<'a, str>, quick_xml::Error> {
    let raw = std::str::from_utf8(&attribute.value).map_err(quick_xml::encoding::EncodingError::from)?;
    Ok(quick_xml::escape::unescape_with(
        raw,
        quick_xml::escape::resolve_xml_entity,
    )?)
}
fn attr(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, FeedError> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        if attribute.key.as_ref() == name {
            return Ok(Some(attribute_text(&attribute)?.into_owned()));
        }
    }
    Ok(None)
}
fn parse_xml(bytes: &[u8], base: &Url, policy: &SourceDiscoveryPolicyV1) -> Result<FeedDocument, FeedError> {
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<(Namespace, Vec<u8>)> = Vec::new();
    let mut bases: Vec<Option<Url>> = Vec::new();
    let mut document: Option<FeedDocument> = None;
    let mut pending: Option<PendingEntry> = None;
    let mut entry_depth = 0;
    let mut entry_count = 0usize;
    let mut seen = BTreeSet::new();
    // References arrive as separate events; trim only after joining a text run.
    let mut text = String::new();
    loop {
        let (resolved, event) = reader.read_resolved_event()?;
        let ns = namespace(resolved)?;
        if !matches!(&event, Event::Text(_) | Event::GeneralRef(_) | Event::CData(_)) {
            if !text.trim().is_empty() {
                assign(
                    &stack,
                    pending.as_mut(),
                    text.trim(),
                    bases.iter().rev().find_map(Option::as_ref).unwrap_or(base),
                );
            }
            text.clear();
        }
        match event {
            Event::DocType(_) => return Err(protocol("DTD and entity declarations are forbidden")),
            Event::Start(element) => {
                for attribute in element.attributes() {
                    attribute_text(&attribute.map_err(quick_xml::Error::from)?)?;
                }
                if stack.len() >= policy.max_nesting {
                    return Err(DiscoveryErrorV1::Limit("feed_nesting").into());
                }
                let inherited = bases.iter().rev().find_map(Option::as_ref).unwrap_or(base);
                let local_base = match attr(&element, b"xml:base")? {
                    Some(value) => {
                        Some(reference(inherited, &value).ok_or_else(|| protocol("invalid XML base URL"))?)
                    }
                    None => None,
                };
                bases.push(local_base);
                let active_base = bases.iter().rev().find_map(Option::as_ref).unwrap_or(base);
                let local = element.local_name();
                let name = local.as_ref();
                if document.is_none() {
                    let kind = match (ns, name) {
                        (Namespace::None, b"rss") => FeedKind::Rss,
                        (Namespace::Rdf, b"RDF") => FeedKind::Rdf,
                        (Namespace::Atom, b"feed") => FeedKind::Atom,
                        _ => return Err(protocol("unsupported feed root namespace")),
                    };
                    document = Some(FeedDocument {
                        kind,
                        entries: Vec::new(),
                        next: Vec::new(),
                        truncated: false,
                    });
                }
                let article = matches!(
                    (ns, name),
                    (Namespace::None | Namespace::Rss1, b"item") | (Namespace::Atom, b"entry")
                );
                if article {
                    if pending.is_some() {
                        return Err(protocol("nested feed entry"));
                    }
                    if entry_count >= policy.max_entries {
                        if let Some(doc) = document.as_mut() {
                            doc.truncated = true;
                        }
                        break;
                    }
                    entry_count = entry_count.saturating_add(1);
                    pending = Some(PendingEntry::default());
                    entry_depth = stack.len();
                }
                if ns == Namespace::Atom && name == b"link" {
                    let rel = attr(&element, b"rel")?.unwrap_or_else(|| "alternate".into());
                    let kind = attr(&element, b"type")?;
                    if let Some(url) =
                        attr(&element, b"href")?.and_then(|value| reference(active_base, &value))
                    {
                        if let Some(entry) = pending.as_mut() {
                            if rel == "alternate"
                                && kind
                                    .as_deref()
                                    .is_none_or(|kind| matches!(kind, "text/html" | "application/xhtml+xml"))
                                && entry.url.is_none()
                            {
                                entry.url = Some(url);
                            } else if rel == "next" {
                                unique_push(&mut entry.read_more, url, 4);
                            } else if rel == "enclosure"
                                && kind.as_deref().is_some_and(|kind| {
                                    kind.starts_with("image/") || kind.starts_with("video/")
                                })
                            {
                                unique_push(&mut entry.media, url, 16);
                            }
                        } else if rel == "next" {
                            if let Some(doc) = document.as_mut() {
                                unique_push(&mut doc.next, url, 4);
                            }
                        }
                    }
                }
                if let Some(entry) = pending.as_mut() {
                    if (ns == Namespace::Media && matches!(name, b"content" | b"thumbnail"))
                        || (matches!(ns, Namespace::None | Namespace::Rss1) && name == b"enclosure")
                    {
                        if let Some(url) =
                            attr(&element, b"url")?.and_then(|value| reference(active_base, &value))
                        {
                            unique_push(&mut entry.media, url, 16);
                        }
                    }
                }
                stack.push((ns, name.to_vec()));
            }
            Event::Text(part) => {
                text.push_str(&part.decode().map_err(quick_xml::Error::from)?);
            }
            Event::GeneralRef(reference) => {
                if let Some(ch) = reference.resolve_char_ref()? {
                    text.push(ch);
                } else {
                    let name = reference.decode().map_err(quick_xml::Error::from)?;
                    text.push_str(
                        quick_xml::escape::resolve_xml_entity(&name)
                            .ok_or_else(|| protocol("custom XML entities are forbidden"))?,
                    );
                }
            }
            Event::CData(part) => {
                text.push_str(&String::from_utf8_lossy(part.as_ref()));
            }
            Event::End(_) => {
                let Some((ns, name)) = stack.pop() else {
                    return Err(protocol("unbalanced feed"));
                };
                bases.pop();
                if stack.len() == entry_depth
                    && matches!(
                        (ns, name.as_slice()),
                        (Namespace::None | Namespace::Rss1, b"item") | (Namespace::Atom, b"entry")
                    )
                {
                    if let Some(entry) = pending.take() {
                        if entry.related.is_empty() {
                            if let Some(url) = entry.url.filter(|url| seen.insert(url.as_str().to_owned())) {
                                if let Some(doc) = document.as_mut() {
                                    doc.entries.push(FeedEntry {
                                        url,
                                        title: entry.title,
                                        date: entry.date,
                                        publisher: entry.publisher,
                                        media: entry.media,
                                        read_more: entry.read_more,
                                    });
                                }
                            }
                        } else if let Some(doc) = document.as_mut() {
                            for url in entry.related {
                                if doc.entries.len() >= policy.max_entries {
                                    doc.truncated = true;
                                    break;
                                }
                                if seen.insert(url.as_str().to_owned()) {
                                    doc.entries.push(FeedEntry {
                                        url,
                                        title: entry.title.clone(),
                                        date: entry.date.clone(),
                                        publisher: entry.publisher.clone(),
                                        media: Vec::new(),
                                        read_more: Vec::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(protocol("incomplete feed document"));
                }
                break;
            }
            _ => {}
        }
    }
    document.ok_or_else(|| protocol("empty feed document"))
}
fn assign(stack: &[(Namespace, Vec<u8>)], pending: Option<&mut PendingEntry>, text: &str, base: &Url) {
    let Some(entry) = pending else {
        return;
    };
    let Some((ns, name)) = stack.last() else {
        return;
    };
    match (*ns, name.as_slice()) {
        (Namespace::None | Namespace::Rss1, b"link") if entry.url.is_none() => {
            entry.url = reference(base, text)
        }
        (Namespace::None | Namespace::Rss1 | Namespace::Atom, b"title") if entry.title.is_none() => {
            entry.title = hint(text)
        }
        (Namespace::None, b"pubDate") | (Namespace::Atom, b"published" | b"updated")
            if entry.date.is_none() =>
        {
            entry.date = hint(text)
        }
        (Namespace::None | Namespace::Rss1, b"source") | (Namespace::Atom, b"name")
            if entry.publisher.is_none() =>
        {
            entry.publisher = hint(text)
        }
        (Namespace::Trends, b"news_item_url") => {
            if let Some(url) = reference(base, text) {
                unique_push(&mut entry.related, url, 16);
            }
        }
        _ => {}
    }
}
fn json_depth(bytes: &[u8], max: usize) -> Result<(), FeedError> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth = depth.saturating_add(1);
                    if depth > max {
                        return Err(DiscoveryErrorV1::Limit("feed_nesting").into());
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}
fn parse_json(bytes: &[u8], base: &Url, policy: &SourceDiscoveryPolicyV1) -> Result<FeedDocument, FeedError> {
    json_depth(bytes, policy.max_nesting)?;
    let root: serde_json::Value = serde_json::from_slice(bytes)?;
    if !matches!(
        root.get("version").and_then(serde_json::Value::as_str),
        Some("https://jsonfeed.org/version/1" | "https://jsonfeed.org/version/1.1")
    ) {
        return Err(protocol("unsupported JSON Feed version"));
    }
    let items = root
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| protocol("JSON Feed items absent"))?;
    let mut document = FeedDocument {
        kind: FeedKind::Json,
        entries: Vec::new(),
        next: Vec::new(),
        truncated: items.len() > policy.max_entries,
    };
    let mut seen = BTreeSet::new();
    for item in items.iter().take(policy.max_entries) {
        let Some(url) = item
            .get("url")
            .or_else(|| item.get("external_url"))
            .and_then(serde_json::Value::as_str)
            .and_then(|value| reference(base, value))
        else {
            continue;
        };
        if !seen.insert(url.as_str().to_owned()) {
            continue;
        }
        let mut media = Vec::new();
        for key in ["image", "banner_image"] {
            if let Some(url) = item
                .get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(|value| reference(base, value))
            {
                unique_push(&mut media, url, 16);
            }
        }
        if let Some(attachments) = item.get("attachments").and_then(serde_json::Value::as_array) {
            for attachment in attachments.iter().take(16) {
                if let Some(url) = attachment
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| reference(base, value))
                {
                    unique_push(&mut media, url, 16);
                }
            }
        }
        document.entries.push(FeedEntry {
            url,
            title: item
                .get("title")
                .and_then(serde_json::Value::as_str)
                .and_then(hint),
            date: item
                .get("date_published")
                .and_then(serde_json::Value::as_str)
                .and_then(hint),
            publisher: root
                .get("title")
                .and_then(serde_json::Value::as_str)
                .and_then(hint),
            media,
            read_more: Vec::new(),
        });
    }
    if let Some(next) = root
        .get("next_url")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| reference(base, value))
    {
        document.next.push(next);
    }
    Ok(document)
}

/// Whether declared response headers or a bounded prefix identify a feed source.
#[must_use]
pub fn is_feed(content_type: Option<&str>, bytes: &[u8]) -> bool {
    if content_type.is_some_and(|kind| {
        [
            "application/rss+xml",
            "application/atom+xml",
            "application/feed+json",
            "application/rdf+xml",
        ]
        .iter()
        .any(|feed| {
            kind.split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(feed))
        })
    }) {
        return true;
    }
    if content_type.is_some_and(|kind| kind.contains("text/html") || kind.contains("application/xhtml+xml")) {
        return false;
    }
    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]);
    prefix.contains("<rss")
        || prefix.contains("<feed")
        || prefix.contains("http://www.w3.org/2005/Atom")
        || prefix.contains("http://purl.org/rss/1.0/")
        || prefix.contains("https://jsonfeed.org/version/")
}

/// One CDX capture; original identity and recorded target status remain distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArchiveCapture {
    /// Original resource, never replaced by archive endpoint identity.
    pub original_url: Url,
    /// Explicitly configured archive replay URL.
    pub archive_url: Url,
    /// CDX timestamp exactly as recorded, fourteen decimal digits.
    pub capture_time: String,
    /// Recorded original response status; absent is unknown, not HTTP 200.
    pub target_status: Option<u16>,
}
/// Explicit provider result; no implicit network or endpoint discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectorDocument {
    /// Article URLs proposed by news/trends or original URLs from CDX.
    pub articles: Vec<Url>,
    /// Trends query labels, not fabricated article URLs.
    pub terms: Vec<String>,
    /// Archive provenance for each selected capture.
    pub captures: Vec<ArchiveCapture>,
    /// Provider result exceeded configured entry limit.
    pub truncated: bool,
}
/// Parse the response of an explicitly selected connector.
///
/// # Errors
/// Returns typed unavailable when configuration is absent, or protocol/resource errors.
/// Google News accepts RSS/Atom or the recorded `garturlres` batchexecute response.
/// Trends accepts daily-trends JSON (including its anti-XSSI prefix) or trends RSS.
/// Internet Archive accepts the CDX JSON table; no implicit archive replay is requested.
pub fn parse_connector(
    provider: crawlx_core::discovery::DiscoveryProviderV1,
    configured: Option<&crawlx_core::discovery::DiscoveryConnectorV1>,
    bytes: &[u8],
    policy: &SourceDiscoveryPolicyV1,
) -> Result<ConnectorDocument, FeedError> {
    use crawlx_core::discovery::DiscoveryProviderV1;
    let connector = configured.ok_or(DiscoveryErrorV1::ProviderUnavailable(provider))?;
    if connector.provider != provider {
        return Err(protocol("connector provider mismatch"));
    }
    policy
        .validate()
        .map_err(|error| DiscoveryErrorV1::Protocol(error.to_string()))?;
    if bytes.len() > policy.max_feed_bytes {
        return Err(DiscoveryErrorV1::Limit("connector_bytes").into());
    }
    if is_feed(None, bytes) && provider != DiscoveryProviderV1::InternetArchive {
        let document = parse_feed(bytes, &connector.endpoint, policy)?;
        return Ok(ConnectorDocument {
            articles: document.entries.into_iter().map(|entry| entry.url).collect(),
            terms: Vec::new(),
            captures: Vec::new(),
            truncated: document.truncated,
        });
    }
    let bytes = bytes.strip_prefix(b")]}'").map_or(bytes, |rest| {
        rest.iter()
            .position(|byte| matches!(byte, b'[' | b'{'))
            .map_or(rest, |position| &rest[position..])
    });
    json_depth(bytes, policy.max_nesting)?;
    let root: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut result = ConnectorDocument {
        articles: Vec::new(),
        terms: Vec::new(),
        captures: Vec::new(),
        truncated: false,
    };
    match provider {
        DiscoveryProviderV1::GoogleNews => {
            let rows = root
                .as_array()
                .ok_or_else(|| protocol("Google News batchexecute array absent"))?;
            for call in rows.iter().take(policy.max_entries) {
                let Some(call) = call.as_array() else {
                    continue;
                };
                if call.first().and_then(serde_json::Value::as_str) != Some("wrb.fr") {
                    continue;
                }
                let Some(encoded) = call.get(2).and_then(serde_json::Value::as_str) else {
                    continue;
                };
                json_depth(encoded.as_bytes(), policy.max_nesting)?;
                let response: serde_json::Value = serde_json::from_str(encoded)?;
                if response.get(0).and_then(serde_json::Value::as_str) != Some("garturlres") {
                    continue;
                }
                if let Some(url) = response
                    .get(1)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| reference(&connector.endpoint, value))
                {
                    unique_push(&mut result.articles, url, policy.max_entries);
                }
            }
            if result.articles.is_empty() {
                return Err(protocol("Google News decoded article response absent"));
            }
            result.truncated = rows.len() > policy.max_entries;
        }
        DiscoveryProviderV1::GoogleTrends => {
            let days = root
                .pointer("/default/trendingSearchesDays")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| protocol("Google Trends daily-trends records absent"))?;
            let mut count = 0usize;
            for day in days.iter().take(policy.max_entries) {
                let Some(searches) = day.get("trendingSearches").and_then(serde_json::Value::as_array) else {
                    continue;
                };
                for search in searches {
                    if count >= policy.max_entries {
                        result.truncated = true;
                        break;
                    }
                    count = count.saturating_add(1);
                    if let Some(term) = search
                        .pointer("/title/query")
                        .and_then(serde_json::Value::as_str)
                        .and_then(hint)
                    {
                        if !result.terms.contains(&term) {
                            result.terms.push(term);
                        }
                    }
                    if let Some(articles) = search.get("articles").and_then(serde_json::Value::as_array) {
                        for article in articles.iter().take(policy.max_entries) {
                            if let Some(url) = article
                                .get("url")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|value| reference(&connector.endpoint, value))
                            {
                                if result.articles.len() >= policy.max_entries {
                                    result.truncated = true;
                                    break;
                                }
                                unique_push(&mut result.articles, url, policy.max_entries);
                            }
                        }
                    }
                }
            }
        }
        DiscoveryProviderV1::InternetArchive => {
            let rows = root.as_array().ok_or_else(|| protocol("CDX table absent"))?;
            let header = rows
                .first()
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| protocol("CDX header absent"))?;
            let column = |name| header.iter().position(|value| value.as_str() == Some(name));
            let original = column("original").ok_or_else(|| protocol("CDX original column absent"))?;
            let timestamp = column("timestamp").ok_or_else(|| protocol("CDX timestamp column absent"))?;
            let status = column("statuscode");
            let archive_base = connector
                .archive_base
                .as_ref()
                .ok_or_else(|| protocol("CDX replay base absent"))?;
            for row in rows.iter().skip(1).take(policy.max_entries) {
                let Some(row) = row.as_array() else {
                    return Err(protocol("invalid CDX row"));
                };
                let original = row
                    .get(original)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| protocol("CDX original absent"))?;
                let time = row
                    .get(timestamp)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| protocol("CDX timestamp absent"))?;
                if time.len() != 14
                    || !time.bytes().all(|byte| byte.is_ascii_digit())
                    || chrono::NaiveDateTime::parse_from_str(time, "%Y%m%d%H%M%S").is_err()
                {
                    return Err(protocol("invalid CDX capture timestamp"));
                }
                let original_url = Url::parse(original)
                    .ok()
                    .and_then(|url| reference(&url, ""))
                    .ok_or_else(|| protocol("invalid CDX original URL"))?;
                let archive_url = archive_base
                    .join(&format!("{time}id_/{original_url}"))
                    .map_err(|_| protocol("invalid CDX replay URL"))?;
                let target_status = match status
                    .and_then(|column| row.get(column))
                    .and_then(serde_json::Value::as_str)
                {
                    None | Some("-") => None,
                    Some(value) => Some(
                        value
                            .parse::<u16>()
                            .ok()
                            .filter(|status| (100..=599).contains(status))
                            .ok_or_else(|| protocol("invalid CDX recorded status"))?,
                    ),
                };
                unique_push(&mut result.articles, original_url.clone(), policy.max_entries);
                result.captures.push(ArchiveCapture {
                    original_url,
                    archive_url,
                    capture_time: time.to_owned(),
                    target_status,
                });
            }
            result.truncated = rows.len().saturating_sub(1) > policy.max_entries;
        }
        _ => return Err(protocol("unsupported connector provider")),
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn parse(bytes: &[u8]) -> FeedDocument {
        parse_feed(
            bytes,
            &Url::parse("https://example.test/feed").unwrap(),
            &SourceDiscoveryPolicyV1::default(),
        )
        .unwrap()
    }
    #[test]
    fn atom_namespace_alias_ignores_self_and_uses_html_alternate() {
        let document = parse(br#"<a:feed xmlns:a="http://www.w3.org/2005/Atom"><a:link rel="next" href="/feed?page=2"/><a:entry><a:link rel="self" href="/feed/1"/><a:link type="text/html" href="/article"/><a:title>News &amp; facts</a:title></a:entry></a:feed>"#);
        assert_eq!(document.entries[0].url.as_str(), "https://example.test/article");
        assert_eq!(document.entries[0].title.as_deref(), Some("News & facts"));
        assert_eq!(document.next.len(), 1);
    }
    #[test]
    fn references_preserve_complete_feed_urls_and_metadata() {
        let document = parse(br#"<rss><channel><item><link>/story?a=1&amp;b=&#50;</link><title> A &amp; B &#x1F642; &lt;ok&gt; </title><source>One &apos;two&apos;</source><pubDate>2026-11-0&#54;</pubDate></item></channel></rss>"#);
        let entry = &document.entries[0];
        assert_eq!(entry.url.as_str(), "https://example.test/story?a=1&b=2");
        assert_eq!(entry.title.as_deref(), Some("A & B 🙂 <ok>"));
        assert_eq!(entry.publisher.as_deref(), Some("One 'two'"));
        assert_eq!(entry.date.as_deref(), Some("2026-11-06"));
        assert!(
            parse(br#"<rss><channel><item><link> </link></item></channel></rss>"#)
                .entries
                .is_empty()
        );
    }
    #[test]
    fn rss_rdf_json_are_pure_and_keep_private_references_as_unapproved_proposals() {
        let rss = parse(br#"<rss><channel><item><link>http://127.0.0.1/private</link><enclosure url="/image"/></item><item><link>http://127.0.0.1/private</link></item></channel></rss>"#);
        assert_eq!(rss.entries.len(), 1);
        assert_eq!(rss.entries[0].media.len(), 1);
        let rdf = parse(br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"><item><link>/story</link></item></r:RDF>"#);
        assert_eq!(rdf.kind, FeedKind::Rdf);
        let json = parse(br#"{"version":"https://jsonfeed.org/version/1.1","items":[{"id":"1","url":"/story","image":"/image"}],"next_url":"/feed"}"#);
        assert_eq!(json.entries[0].url, rdf.entries[0].url);
    }
    #[test]
    fn rejects_dtd_unknown_entities_and_depth_bombs() {
        let base = Url::parse("https://example.test/").unwrap();
        let policy = SourceDiscoveryPolicyV1::default();
        for bytes in [
            br#"<!DOCTYPE rss [<!ENTITY x SYSTEM "http://127.0.0.1/secret">]><rss/>"#.as_slice(),
            br#"<rss><channel><item><link>&unbound;</link></item></channel></rss>"#.as_slice(),
            br#"<rss><channel><item><link>&#x110000;</link></item></channel></rss>"#.as_slice(),
            br#"<rss duplicate="1" duplicate="2"/>"#.as_slice(),
        ] {
            assert!(parse_feed(bytes, &base, &policy).is_err());
        }
        let bomb = format!("<rss>{}{}</rss>", "<x>".repeat(33), "</x>".repeat(33));
        assert!(parse_feed(bomb.as_bytes(), &base, &policy).is_err());
    }
    #[test]
    fn caps_entries_and_never_promotes_unknown_namespace_links() {
        let base = Url::parse("https://example.test/").unwrap();
        let mut policy = SourceDiscoveryPolicyV1::default();
        policy.max_entries = 1;
        let doc = parse_feed(br#"<rss xmlns:e="urn:evil"><channel><item><e:link>/evil</e:link><link>/good</link></item><item><link>/other</link></item></channel></rss>"#, &base, &policy).unwrap();
        assert!(doc.truncated);
        assert_eq!(doc.entries[0].url.path(), "/good");
    }
    #[test]
    fn recorded_news_trends_and_cdx_protocols_keep_provenance_and_unknown_status() {
        use crawlx_core::discovery::{DiscoveryConnectorV1, DiscoveryProviderV1};
        let policy = SourceDiscoveryPolicyV1::default();
        let connector = |provider, archive_base: Option<&str>| -> DiscoveryConnectorV1 {
            serde_json::from_value(serde_json::json!({"provider":provider,"endpoint":"https://provider.test/query","archiveBase":archive_base})).unwrap()
        };
        let news = connector("google_news", None);
        let decoded = parse_connector(
            DiscoveryProviderV1::GoogleNews,
            Some(&news),
            br#")]}'
[["wrb.fr","Fbv4je","[\"garturlres\",\"https://publisher.test/story\"]",null]]"#,
            &policy,
        )
        .unwrap();
        assert_eq!(decoded.articles[0].as_str(), "https://publisher.test/story");
        let trends = connector("google_trends", None);
        let parsed = parse_connector(DiscoveryProviderV1::GoogleTrends, Some(&trends),
            br#"{"default":{"trendingSearchesDays":[{"trendingSearches":[{"title":{"query":"space mission"},"articles":[{"url":"https://publisher.test/mission"}]}]}]}}"#, &policy).unwrap();
        assert_eq!(parsed.terms, vec!["space mission"]);
        assert_eq!(parsed.articles.len(), 1);
        let archive = connector("internet_archive", Some("https://archive.test/web/"));
        let captures = parse_connector(DiscoveryProviderV1::InternetArchive, Some(&archive),
            br#"[["timestamp","original","statuscode"],["20260101120000","https://publisher.test/story","404"],["20260102120000","https://publisher.test/other","-"]]"#, &policy).unwrap();
        assert_eq!(captures.captures[0].target_status, Some(404));
        assert_eq!(captures.captures[1].target_status, None);
        assert_ne!(
            captures.captures[0].original_url,
            captures.captures[0].archive_url
        );
        assert_eq!(captures.captures[0].capture_time, "20260101120000");
        assert!(matches!(
            parse_connector(DiscoveryProviderV1::GoogleNews, None, b"", &policy),
            Err(FeedError::Policy(DiscoveryErrorV1::ProviderUnavailable(
                DiscoveryProviderV1::GoogleNews
            )))
        ));
    }
    #[test]
    fn trends_rss_returns_publisher_articles_not_search_urls() {
        let document = parse(br#"<rss xmlns:ht="https://trends.google.com/trending/rss"><channel><item><title>Space</title><link>https://trends.google.com/search?q=space</link><ht:news_item><ht:news_item_url>https://publisher.test/one</ht:news_item_url></ht:news_item><ht:news_item><ht:news_item_url>https://publisher.test/two</ht:news_item_url></ht:news_item></item></channel></rss>"#);
        assert_eq!(document.entries.len(), 2);
        assert!(document
            .entries
            .iter()
            .all(|entry| entry.url.host_str() == Some("publisher.test")));
    }
    #[test]
    fn atom_xml_base_changes_resolution_without_network_or_authority() {
        let document = parse(br#"<feed xmlns="http://www.w3.org/2005/Atom" xml:base="https://publisher.test/news/"><entry xml:base="2026/"><link href="story"/></entry></feed>"#);
        assert_eq!(
            document.entries[0].url.as_str(),
            "https://publisher.test/news/2026/story"
        );
    }
}
