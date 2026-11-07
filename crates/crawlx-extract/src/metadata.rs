//! Page metadata extraction.
//!
//! One pass over the parsed document collects `<title>`, `<html lang>`,
//! `<meta>` (Open Graph, Twitter cards, named and `http-equiv` entries),
//! `<link rel=canonical|alternate>`, microdata dates/authors, JSON-LD blocks
//! and the first `<h1>`. `<base href>` is honoured for every relative URL.
//!
//! Title fallback order: `og:title`, `<title>`, first `<h1>`.

use std::collections::BTreeMap;

use scraper::Html;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::dom::{collapse_ws, resolve, walk};

/// Largest JSON-LD block that is parsed.
const MAX_JSON_LD_BYTES: usize = 256 * 1024;
/// Largest number of JSON-LD blocks kept.
const MAX_JSON_LD_BLOCKS: usize = 16;
/// Largest number of distinct `<meta>` names kept in [`Metadata::all_meta`].
const MAX_META_NAMES: usize = 512;
/// Largest number of values kept per name in [`Metadata::all_meta`].
const MAX_META_VALUES: usize = 32;

/// Parse only the first matching refresh tag in complete bounded UTF-8 HTML.
///
/// Delay is syntax only; acquisition pacing remains the origin governor's job.
/// Relative URLs use the observed response URL, never the document's `<base>`.
///
/// This parses without charging the process-wide parse-memory budget; production callers use
/// [`try_meta_refresh_target`] so a refusal is not mistaken for "no refresh".
#[must_use]
pub fn meta_refresh_target(bytes: &[u8], observed: &Url, max_bytes: u32) -> Option<Url> {
    if bytes.len() > usize::try_from(max_bytes).unwrap_or(usize::MAX) {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let html = Html::parse_document(text);
    let mut target = None;
    let mut matched = false;
    walk(html.tree.root(), |el| {
        if matched {
            return false;
        }
        if el.value().name() == "meta"
            && el
                .value()
                .attr("http-equiv")
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("refresh"))
        {
            matched = true;
            target = el.value().attr("content").and_then(|content| {
                let (delay, destination) = content.split_once(';')?;
                let delay = delay.trim();
                if delay.is_empty()
                    || !delay.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
                    || delay
                        .parse::<f64>()
                        .ok()
                        .is_none_or(|value| !value.is_finite() || value < 0.0)
                {
                    return None;
                }
                let (name, value) = destination.trim().split_once('=')?;
                if !name.trim().eq_ignore_ascii_case("url") {
                    return None;
                }
                let value = value.trim();
                let value = if value.starts_with(['\'', '"']) {
                    let quote = value.as_bytes()[0];
                    if value.len() < 2 || value.as_bytes().last() != Some(&quote) {
                        return None;
                    }
                    &value[1..value.len() - 1]
                } else {
                    value
                };
                if value.trim().is_empty() || value.len() > 4096 {
                    return None;
                }
                observed.join(value.trim()).ok()
            });
        }
        !matches!(el.value().name(), "script" | "style" | "template")
    });
    target
}

/// [`meta_refresh_target`] after charging the process-wide parse-memory budget for the parse.
///
/// # Errors
/// [`crate::parse_budget::ParseBudgetExhausted`] when the budget cannot take the charge right
/// now; the caller must not treat this as "the page has no refresh".
pub fn try_meta_refresh_target(
    bytes: &[u8],
    observed: &Url,
    max_bytes: u32,
) -> Result<Option<Url>, crate::parse_budget::ParseBudgetExhausted> {
    if bytes.len() > usize::try_from(max_bytes).unwrap_or(usize::MAX) {
        return Ok(None);
    }
    // held until the DOM inside `meta_refresh_target` has been dropped
    let _charge = crate::parse_budget::charge(bytes.len())?;
    Ok(meta_refresh_target(bytes, observed, max_bytes))
}

/// `<meta name=robots>` directives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RobotsMeta {
    /// `noindex` or `none`.
    pub noindex: bool,
    /// `nofollow` or `none`.
    pub nofollow: bool,
    /// `noarchive`.
    pub noarchive: bool,
}

/// `<link rel=alternate hreflang=...>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alternate {
    /// Language tag as written (`x-default` allowed).
    pub hreflang: String,
    /// Absolute URL.
    pub url: Url,
}

/// Structured page metadata.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    /// `og:*` properties keyed by full property name; first occurrence wins.
    pub open_graph: BTreeMap<String, String>,
    /// `twitter:*` entries keyed by full name; first occurrence wins.
    pub twitter: BTreeMap<String, String>,
    /// Other `<meta name|property|http-equiv>` entries (names lower-cased,
    /// `http-equiv` entries prefixed `http-equiv:`); first occurrence wins.
    pub meta: BTreeMap<String, String>,
    /// Publication time as written in the page.
    pub published_time: Option<String>,
    /// Modification time as written in the page.
    pub modified_time: Option<String>,
    /// Author name.
    pub author: Option<String>,
    /// Robots meta directives.
    pub robots: RobotsMeta,
    /// hreflang alternates, deduplicated, in document order.
    pub alternates: Vec<Alternate>,
    /// Parsed JSON-LD blocks.
    pub json_ld: Vec<Value>,
    /// Text of the first non-empty `<title>` (unlike `Document::title`, no `og:title` or `<h1>`
    /// fallback; Firecrawl `metadata.title`).
    #[serde(default)]
    pub title_tag: Option<String>,
    /// Every non-empty `<meta name|property>` content in document order, keyed by lower-cased
    /// name; repeated names keep every value (at most 512 names and 32 values per name).
    #[serde(default)]
    pub all_meta: BTreeMap<String, Vec<String>>,
}

/// Head-level information needed by [`crate::Document`].
#[derive(Debug, Clone)]
pub struct HeadInfo {
    /// Resolved title.
    pub title: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Language tag.
    pub language: Option<String>,
    /// Canonical URL.
    pub canonical_url: Option<Url>,
    /// All metadata.
    pub metadata: Metadata,
}

/// The base URL for relative references: the first `<base href>` resolved
/// against `page`, or `page` itself.
#[must_use]
pub fn effective_base(html: &Html, page: &Url) -> Url {
    let mut found: Option<Url> = None;
    walk(html.tree.root(), |el| {
        if found.is_some() {
            return false;
        }
        if el.value().name() == "base" {
            if let Some(u) = el.value().attr("href").and_then(|h| resolve(page, h)) {
                if matches!(u.scheme(), "http" | "https") {
                    found = Some(u);
                }
            }
            return false;
        }
        !matches!(el.value().name(), "script" | "style" | "template")
    });
    found.unwrap_or_else(|| page.clone())
}

fn find_key<'a>(v: &'a Value, key: &str, depth: usize) -> Option<&'a Value> {
    if depth > 8 {
        return None;
    }
    match v {
        Value::Object(m) => {
            if let Some(x) = m.get(key) {
                return Some(x);
            }
            m.values().find_map(|c| find_key(c, key, depth + 1))
        }
        Value::Array(a) => a.iter().find_map(|c| find_key(c, key, depth + 1)),
        _ => None,
    }
}

fn value_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(collapse_ws(s)).filter(|s| !s.is_empty()),
        Value::Object(m) => m.get("name").and_then(value_string),
        Value::Array(a) => a.iter().find_map(value_string),
        _ => None,
    }
}

fn json_ld_string(blocks: &[Value], key: &str) -> Option<String> {
    blocks
        .iter()
        .find_map(|b| find_key(b, key, 0).and_then(value_string))
}

fn first_of(maps: &[&BTreeMap<String, String>], keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| maps.iter().find_map(|m| m.get(*k).cloned()))
}

fn set_first(slot: &mut Option<String>, value: String) {
    if slot.is_none() && !value.is_empty() {
        *slot = Some(value);
    }
}

#[derive(Default)]
struct Micro {
    published: Option<String>,
    modified: Option<String>,
    author: Option<String>,
}

/// Extract head-level metadata from `html`; relative URLs resolve against `base`.
#[must_use]
pub fn extract(html: &Html, base: &Url) -> HeadInfo {
    let mut md = Metadata::default();
    let mut title_tag: Option<String> = None;
    let mut h1: Option<String> = None;
    let mut html_lang: Option<String> = None;
    let mut canonical: Option<Url> = None;
    let mut micro = Micro::default();

    walk(html.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "html" => {
                if let Some(l) = v.attr("lang").or_else(|| v.attr("xml:lang")) {
                    set_first(&mut html_lang, l.trim().to_owned());
                }
            }
            "title" => {
                if title_tag.is_none() {
                    let t = collapse_ws(&el.text().collect::<String>());
                    if !t.is_empty() {
                        title_tag = Some(t);
                    }
                }
                return false;
            }
            "h1" => {
                if h1.is_none() {
                    let t = collapse_ws(&el.text().collect::<String>());
                    if !t.is_empty() {
                        h1 = Some(t);
                    }
                }
            }
            "meta" => {
                let content = collapse_ws(v.attr("content").unwrap_or(""));
                if let Some(prop) = v.attr("itemprop") {
                    micro_value(&mut micro, prop, content.clone());
                }
                if content.is_empty() {
                    return false;
                }
                if let Some(he) = v.attr("http-equiv") {
                    md.meta
                        .entry(format!("http-equiv:{}", he.trim().to_ascii_lowercase()))
                        .or_insert(content.clone());
                }
                let key = v
                    .attr("property")
                    .or_else(|| v.attr("name"))
                    .map(|k| k.trim().to_ascii_lowercase());
                if let Some(key) = key.filter(|k| !k.is_empty()) {
                    if md.all_meta.len() < MAX_META_NAMES || md.all_meta.contains_key(&key) {
                        let values = md.all_meta.entry(key.clone()).or_default();
                        if values.len() < MAX_META_VALUES {
                            values.push(content.clone());
                        }
                    }
                    if key.starts_with("og:") {
                        md.open_graph.entry(key).or_insert(content);
                    } else if key.starts_with("twitter:") {
                        md.twitter.entry(key).or_insert(content);
                    } else {
                        md.meta.entry(key).or_insert(content);
                    }
                }
                return false;
            }
            "link" => {
                let rel: Vec<String> = v
                    .attr("rel")
                    .unwrap_or("")
                    .split_whitespace()
                    .map(str::to_ascii_lowercase)
                    .collect();
                if let Some(u) = v.attr("href").and_then(|h| resolve(base, h)) {
                    if matches!(u.scheme(), "http" | "https") {
                        if rel.iter().any(|r| r == "canonical") && canonical.is_none() {
                            canonical = Some(u.clone());
                        }
                        if rel.iter().any(|r| r == "alternate") {
                            if let Some(lang) = v.attr("hreflang").map(str::trim).filter(|l| !l.is_empty()) {
                                let alt = Alternate {
                                    hreflang: lang.to_owned(),
                                    url: u,
                                };
                                if !md.alternates.contains(&alt) {
                                    md.alternates.push(alt);
                                }
                            }
                        }
                    }
                }
                return false;
            }
            "script" => {
                let is_ld = v
                    .attr("type")
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/ld+json"));
                if is_ld && md.json_ld.len() < MAX_JSON_LD_BLOCKS {
                    let text: String = el.text().collect();
                    if text.len() <= MAX_JSON_LD_BYTES {
                        if let Ok(val) = serde_json::from_str::<Value>(text.trim()) {
                            md.json_ld.push(val);
                        }
                    }
                }
                return false;
            }
            "style" | "template" => return false,
            _ => {}
        }
        if let Some(prop) = v.attr("itemprop") {
            let value = if let Some(c) = v.attr("content") {
                collapse_ws(c)
            } else if v.name() == "time" {
                v.attr("datetime")
                    .map(collapse_ws)
                    .unwrap_or_else(|| collapse_ws(&el.text().collect::<String>()))
            } else if el.child_elements().next().is_none() {
                let t = collapse_ws(&el.text().collect::<String>());
                if t.chars().count() > 200 {
                    String::new()
                } else {
                    t
                }
            } else {
                String::new()
            };
            micro_value(&mut micro, prop, value);
        }
        true
    });

    let robots_tokens = |name: &str| -> Vec<String> {
        md.meta
            .get(name)
            .map(|c| {
                c.split(|ch: char| ch == ',' || ch.is_whitespace())
                    .filter(|t| !t.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut tokens = robots_tokens("robots");
    tokens.extend(robots_tokens("crawlx"));
    let has = |t: &str| tokens.iter().any(|x| x == t);
    md.robots = RobotsMeta {
        noindex: has("noindex") || has("none"),
        nofollow: has("nofollow") || has("none"),
        noarchive: has("noarchive"),
    };

    let (og, tw, meta) = (&md.open_graph, &md.twitter, &md.meta);
    let published = first_of(
        &[meta, og],
        &[
            "article:published_time",
            "og:article:published_time",
            "datepublished",
            "date",
            "dc.date",
            "dc.date.issued",
            "dcterms.created",
            "dcterms.date",
            "pubdate",
            "publishdate",
            "publish-date",
            "parsely-pub-date",
            "sailthru.date",
        ],
    )
    .or(micro.published)
    .or_else(|| json_ld_string(&md.json_ld, "datePublished"));
    let modified = first_of(
        &[meta, og],
        &[
            "article:modified_time",
            "og:updated_time",
            "datemodified",
            "last-modified",
            "dcterms.modified",
        ],
    )
    .or(micro.modified)
    .or_else(|| json_ld_string(&md.json_ld, "dateModified"));
    let author = first_of(&[meta], &["author", "byl", "parsely-author", "dc.creator"])
        .or(micro.author)
        .or_else(|| json_ld_string(&md.json_ld, "author"))
        .or_else(|| first_of(&[tw], &["twitter:creator"]))
        .or_else(|| first_of(&[meta, og], &["article:author", "og:article:author"]));

    let title = og.get("og:title").cloned().or_else(|| title_tag.clone()).or(h1);
    let description = first_of(&[meta], &["description"])
        .or_else(|| first_of(&[og], &["og:description"]))
        .or_else(|| first_of(&[tw], &["twitter:description"]));
    let language = html_lang
        .or_else(|| {
            meta.get("http-equiv:content-language")
                .map(|l| l.trim().to_owned())
                .filter(|l| !l.is_empty())
        })
        .or_else(|| og.get("og:locale").map(|l| l.replace('_', "-")));
    let canonical_url = canonical.or_else(|| {
        og.get("og:url")
            .and_then(|u| resolve(base, u))
            .filter(|u| matches!(u.scheme(), "http" | "https"))
    });

    md.title_tag = title_tag;
    md.published_time = published;
    md.modified_time = modified;
    md.author = author;
    HeadInfo {
        title,
        description,
        language,
        canonical_url,
        metadata: md,
    }
}

fn micro_value(m: &mut Micro, prop: &str, value: String) {
    if value.is_empty() {
        return;
    }
    let slot = match prop.trim().to_ascii_lowercase().as_str() {
        "datepublished" => &mut m.published,
        "datemodified" => &mut m.modified,
        "author" => &mut m.author,
        _ => return,
    };
    set_first(slot, value);
}
