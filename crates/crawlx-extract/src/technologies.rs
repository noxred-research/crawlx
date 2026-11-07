//! Technology detection from a curated catalog (katana `-td`).
//!
//! The catalog is `data/technologies.json`, authored for this repository (no
//! third-party fingerprint data). It
//! is embedded at build time and compiled once. Every entry has a `category`
//! and any of these pattern kinds:
//!
//! | kind | matched against | shape |
//! |---|---|---|
//! | `headers` | response header value, by lower-case name | `{name: regex}`; `""` = presence |
//! | `cookies` | `Set-Cookie` cookie value, by cookie name | `{name: regex}`; `""` = presence |
//! | `meta` | `<meta name=… content=…>`, by lower-case name | `{name: regex}` |
//! | `script_src` | every `<script src>` URL | `[regex]` |
//! | `html` | the raw markup (first [`MAX_HTML_SCAN`] bytes) | `[regex]` |
//! | `js_globals` | `window` property names reported by the browser plane | `[name]` |
//! | `url` | the page URL | `[regex]` |
//!
//! Regexes are case-insensitive; capture group 1, when it matches, is the
//! version. `implies` adds other catalog entries (transitively) with evidence
//! `implied:<name>`. Output is one [`Technology`] per detected entry, sorted
//! by name, with the first evidence in kind order (headers, cookies, meta,
//! script_src, js_globals, html, url, implied) and the first version seen:
//! the same input always yields the same output.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use scraper::Html;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::dom::walk;

/// Cap on technologies reported per page.
pub const MAX_TECHNOLOGIES: usize = 64;
/// Only this many leading bytes of the markup are scanned by `html` patterns.
pub const MAX_HTML_SCAN: usize = 1024 * 1024;
/// Compiled-program size limit per catalog regex.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// The embedded catalog.
pub const CATALOG_JSON: &str = include_str!("../data/technologies.json");

/// A detected technology.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Technology {
    /// Canonical name (`WordPress`, `React`, `nginx`).
    pub name: String,
    /// What matched first: `header:<name>`, `cookie:<name>`, `meta:<name>`,
    /// `script_src`, `js_global:<name>`, `html`, `url` or `implied:<name>`.
    pub evidence: String,
    /// Catalog category (`web-server`, `cms`, …); empty for records written
    /// before the catalog existed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
    /// Version captured by the matching pattern, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Catalog categories (closed set; the schema test enforces it).
pub const CATEGORIES: &[&str] = &[
    "web-server",
    "cdn",
    "framework",
    "language",
    "cms",
    "e-commerce",
    "analytics",
    "tag-manager",
    "js-library",
    "ui-framework",
    "bundler",
    "hosting",
    "security",
    "auth",
    "payment",
    "marketing",
    "monitoring",
    "search",
    "media",
    "cache",
];

/// One catalog entry as authored in `data/technologies.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// One of [`CATEGORIES`].
    pub category: String,
    /// Project website (documentation only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Header name (lower-case) → value regex (`""` = presence).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Cookie name → value regex (`""` = presence).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cookies: BTreeMap<String, String>,
    /// `meta name` (lower-case) → content regex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    /// Regexes over `<script src>` URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_src: Vec<String>,
    /// Regexes over the raw markup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub html: Vec<String>,
    /// `window` property names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub js_globals: Vec<String>,
    /// Regexes over the page URL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url: Vec<String>,
    /// Other catalog entries this one implies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implies: Vec<String>,
}

/// The catalog file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    /// Schema version (1).
    pub version: u32,
    /// Entries by canonical name.
    pub technologies: BTreeMap<String, Entry>,
}

/// Catalog load/compile failure.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// The JSON does not match [`CatalogFile`].
    #[error("technology catalog is not valid json")]
    Json(#[source] serde_json::Error),
    /// A regex of `entry` under `kind` failed to compile.
    #[error("technology catalog: {entry}/{kind}: pattern does not compile")]
    Pattern {
        /// Entry name.
        entry: String,
        /// Pattern kind.
        kind: &'static str,
        /// Compile error.
        #[source]
        source: Box<regex::Error>,
    },
    /// `entry` implies a name that is not in the catalog.
    #[error("technology catalog: {entry} implies unknown entry {implied}")]
    UnknownImplied {
        /// Entry name.
        entry: String,
        /// The missing name.
        implied: String,
    },
    /// `entry` has a category outside [`CATEGORIES`].
    #[error("technology catalog: {entry} has unknown category {category}")]
    UnknownCategory {
        /// Entry name.
        entry: String,
        /// The category.
        category: String,
    },
    /// Unsupported schema version.
    #[error("technology catalog: unsupported schema version {0}")]
    Version(u32),
}

/// A compiled value pattern.
#[derive(Debug)]
struct Pat {
    /// `None` = presence only.
    re: Option<Regex>,
}

impl Pat {
    fn compile(entry: &str, kind: &'static str, pattern: &str) -> Result<Self, CatalogError> {
        if pattern.is_empty() {
            return Ok(Self { re: None });
        }
        let re = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| CatalogError::Pattern {
                entry: entry.to_owned(),
                kind,
                source: Box::new(e),
            })?;
        Ok(Self { re: Some(re) })
    }

    /// `Some(version)` on match (`Some(None)` when no version is captured).
    fn matches(&self, value: &str) -> Option<Option<String>> {
        match &self.re {
            None => Some(None),
            Some(re) => {
                let caps = re.captures(value)?;
                Some(
                    caps.get(1)
                        .map(|m| m.as_str().trim())
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned),
                )
            }
        }
    }
}

/// A compiled catalog entry.
#[derive(Debug)]
struct Compiled {
    category: String,
    headers: Vec<(String, Pat)>,
    cookies: Vec<(String, Pat)>,
    meta: Vec<(String, Pat)>,
    script_src: Vec<Pat>,
    html: Vec<Pat>,
    js_globals: Vec<String>,
    url: Vec<Pat>,
    implies: Vec<String>,
}

/// The compiled catalog.
#[derive(Debug)]
pub struct Catalog {
    entries: BTreeMap<String, Compiled>,
}

impl Catalog {
    /// Parse and compile a catalog file.
    ///
    /// # Errors
    /// [`CatalogError`] for invalid JSON, a pattern that does not compile, an
    /// unknown category, an unknown implied entry or an unsupported version.
    pub fn parse(json: &str) -> Result<Self, CatalogError> {
        let file: CatalogFile = serde_json::from_str(json).map_err(CatalogError::Json)?;
        if file.version != 1 {
            return Err(CatalogError::Version(file.version));
        }
        let names: BTreeSet<&str> = file.technologies.keys().map(String::as_str).collect();
        let mut entries = BTreeMap::new();
        for (name, e) in &file.technologies {
            if !CATEGORIES.contains(&e.category.as_str()) {
                return Err(CatalogError::UnknownCategory {
                    entry: name.clone(),
                    category: e.category.clone(),
                });
            }
            for implied in &e.implies {
                if !names.contains(implied.as_str()) {
                    return Err(CatalogError::UnknownImplied {
                        entry: name.clone(),
                        implied: implied.clone(),
                    });
                }
            }
            let keyed = |kind: &'static str, m: &BTreeMap<String, String>| {
                m.iter()
                    .map(|(k, p)| {
                        // header and meta names are lower-cased; cookie names keep their case
                        let key = if kind == "cookies" {
                            k.clone()
                        } else {
                            k.to_ascii_lowercase()
                        };
                        Ok((key, Pat::compile(name, kind, p)?))
                    })
                    .collect::<Result<Vec<_>, CatalogError>>()
            };
            let listed = |kind: &'static str, l: &[String]| {
                l.iter()
                    .map(|p| Pat::compile(name, kind, p))
                    .collect::<Result<Vec<_>, CatalogError>>()
            };
            entries.insert(
                name.clone(),
                Compiled {
                    category: e.category.clone(),
                    headers: keyed("headers", &e.headers)?,
                    cookies: keyed("cookies", &e.cookies)?,
                    meta: keyed("meta", &e.meta)?,
                    script_src: listed("script_src", &e.script_src)?,
                    html: listed("html", &e.html)?,
                    js_globals: e.js_globals.clone(),
                    url: listed("url", &e.url)?,
                    implies: e.implies.clone(),
                },
            );
        }
        Ok(Self { entries })
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entry names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Category of `name`.
    #[must_use]
    pub fn category(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|e| e.category.as_str())
    }
}

/// The embedded catalog, compiled once. The schema test guarantees it
/// compiles; a broken catalog would make every detection empty.
pub static CATALOG: LazyLock<Option<Catalog>> = LazyLock::new(|| Catalog::parse(CATALOG_JSON).ok());

/// What the matcher looks at.
#[derive(Debug, Clone, Copy)]
pub struct TechInput<'a> {
    /// Final page URL.
    pub url: Option<&'a Url>,
    /// Response headers `(name, value)`; names matched case-insensitively.
    pub headers: &'a [(String, String)],
    /// Raw markup (for `html` patterns); `""` when only the parsed document is at hand.
    pub html: &'a str,
    /// `window` property names reported by the browser plane; empty on the static plane.
    pub js_globals: &'a [String],
}

/// Page-level facts extracted once for every entry.
struct Facts<'a> {
    headers: Vec<(String, &'a str)>,
    cookies: Vec<(String, String)>,
    meta: Vec<(String, String)>,
    script_src: Vec<String>,
    html: &'a str,
    js_globals: BTreeSet<&'a str>,
    url: Option<String>,
}

fn cookie_name_value(set_cookie: &str) -> Option<(String, String)> {
    let first = set_cookie.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    (!name.is_empty()).then(|| (name.to_owned(), value.trim().to_owned()))
}

fn facts<'a>(input: &TechInput<'a>, doc: &Html) -> Facts<'a> {
    let headers: Vec<(String, &str)> = input
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    let cookies = headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .filter_map(|(_, v)| cookie_name_value(v))
        .collect();
    let mut meta = Vec::new();
    let mut script_src = Vec::new();
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "meta" => {
                if let (Some(n), Some(c)) = (v.attr("name"), v.attr("content")) {
                    meta.push((n.trim().to_ascii_lowercase(), c.to_owned()));
                }
                false
            }
            "script" => {
                if let Some(s) = v.attr("src").filter(|s| !s.trim().is_empty()) {
                    script_src.push(s.trim().to_owned());
                }
                false
            }
            _ => true,
        }
    });
    Facts {
        headers,
        cookies,
        meta,
        script_src,
        // a multi-byte character (a lossy U+FFFD, say) may straddle the scan limit
        html: &input.html[..input.html.floor_char_boundary(MAX_HTML_SCAN)],
        js_globals: input.js_globals.iter().map(String::as_str).collect(),
        url: input.url.map(ToString::to_string),
    }
}

/// First match of `entry` against the facts: `(evidence, version)`.
fn first_match(entry: &Compiled, f: &Facts<'_>) -> Option<(String, Option<String>)> {
    for (name, pat) in &entry.headers {
        for (h, v) in &f.headers {
            if h == name {
                if let Some(ver) = pat.matches(v) {
                    return Some((format!("header:{name}"), ver));
                }
            }
        }
    }
    for (name, pat) in &entry.cookies {
        for (c, v) in &f.cookies {
            if c.eq_ignore_ascii_case(name) {
                if let Some(ver) = pat.matches(v) {
                    return Some((format!("cookie:{name}"), ver));
                }
            }
        }
    }
    for (name, pat) in &entry.meta {
        for (m, v) in &f.meta {
            if m == name {
                if let Some(ver) = pat.matches(v) {
                    return Some((format!("meta:{name}"), ver));
                }
            }
        }
    }
    for pat in &entry.script_src {
        for s in &f.script_src {
            if let Some(ver) = pat.matches(s) {
                return Some(("script_src".to_owned(), ver));
            }
        }
    }
    for g in &entry.js_globals {
        if f.js_globals.contains(g.as_str()) {
            return Some((format!("js_global:{g}"), None));
        }
    }
    if !f.html.is_empty() {
        for pat in &entry.html {
            if let Some(ver) = pat.matches(f.html) {
                return Some(("html".to_owned(), ver));
            }
        }
    }
    if let Some(u) = &f.url {
        for pat in &entry.url {
            if let Some(ver) = pat.matches(u) {
                return Some(("url".to_owned(), ver));
            }
        }
    }
    None
}

/// Detect technologies with the embedded catalog. Empty when the catalog
/// failed to compile (the schema test prevents that).
#[must_use]
pub fn detect(input: &TechInput<'_>, doc: &Html) -> Vec<Technology> {
    CATALOG
        .as_ref()
        .map_or_else(Vec::new, |c| detect_with(c, input, doc))
}

/// Detect technologies with `catalog`.
#[must_use]
pub fn detect_with(catalog: &Catalog, input: &TechInput<'_>, doc: &Html) -> Vec<Technology> {
    let f = facts(input, doc);
    let mut found: BTreeMap<&str, Technology> = BTreeMap::new();
    for (name, entry) in &catalog.entries {
        if let Some((evidence, version)) = first_match(entry, &f) {
            found.insert(
                name,
                Technology {
                    name: name.clone(),
                    evidence,
                    category: entry.category.clone(),
                    version,
                },
            );
        }
    }
    // implications, transitively (catalog order keeps this deterministic)
    let mut queue: Vec<(&str, &str)> = found
        .keys()
        .filter_map(|n| catalog.entries.get(*n).map(|e| (*n, e)))
        .flat_map(|(n, e)| e.implies.iter().map(move |i| (i.as_str(), n)))
        .collect();
    while let Some((implied, by)) = queue.pop() {
        if found.contains_key(implied) {
            continue;
        }
        let Some(entry) = catalog.entries.get(implied) else {
            continue;
        };
        found.insert(
            implied,
            Technology {
                name: implied.to_owned(),
                evidence: format!("implied:{by}"),
                category: entry.category.clone(),
                version: None,
            },
        );
        queue.extend(entry.implies.iter().map(|i| (i.as_str(), implied)));
    }
    found.into_values().take(MAX_TECHNOLOGIES).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn cookie_parsing() {
        assert_eq!(
            cookie_name_value("PHPSESSID=abc; Path=/; HttpOnly"),
            Some(("PHPSESSID".to_owned(), "abc".to_owned()))
        );
        assert_eq!(cookie_name_value("=x"), None);
        assert_eq!(cookie_name_value("novalue"), None);
    }

    #[test]
    fn catalog_errors_are_typed() {
        let bad = r#"{"version": 1, "technologies": {"A": {"category": "cms", "implies": ["B"]}}}"#;
        assert!(matches!(
            Catalog::parse(bad),
            Err(CatalogError::UnknownImplied { .. })
        ));
        let bad = r#"{"version": 1, "technologies": {"A": {"category": "nope"}}}"#;
        assert!(matches!(
            Catalog::parse(bad),
            Err(CatalogError::UnknownCategory { .. })
        ));
        let bad = r#"{"version": 1, "technologies": {"A": {"category": "cms", "html": ["("]}}}"#;
        assert!(matches!(Catalog::parse(bad), Err(CatalogError::Pattern { .. })));
        assert!(matches!(
            Catalog::parse(r#"{"version": 2, "technologies": {}}"#),
            Err(CatalogError::Version(2))
        ));
        assert!(matches!(Catalog::parse("{"), Err(CatalogError::Json(_))));
    }

    #[test]
    fn html_scan_limit_never_splits_a_character() {
        // the three bytes of `€` straddle byte MAX_HTML_SCAN
        let html = format!("<p>{}€€</p>", "a".repeat(MAX_HTML_SCAN - 4));
        let base = url::Url::parse("https://example.test/").unwrap();
        crate::Extractor::extract(&html, &base, &crate::ExtractOptions::default()).unwrap();
    }
}
