//! The compatibility API's `metadata` object for a scraped document.
//!
//! [`compat_meta`] maps a [`Document`] to the camelCase keys the compatibility API documents
//! (`title`, `description`, `language`, `keywords`, `robots`, `ogTitle`, `ogDescription`,
//! `ogUrl`, `ogImage`, `ogAudio`, `ogDeterminer`, `ogLocale`, `ogLocaleAlternate`,
//! `ogSiteName`, `ogVideo`, the `dc*` Dublin Core keys, `publishedTime`, `modifiedTime`,
//! `articleTag`, `articleSection`) and additionally carries every `<meta name|property>` entry
//! of the page under its own name (`og:type`, `twitter:card`, `article:author`, `dc.title`,
//! `viewport`, ...). A name that occurs once yields a string, a repeated name an array of
//! strings in document order. Absent values are omitted, never `null`. Meta names are
//! lower-cased by the extractor, so `DC.title` appears as `dc.title`.
//!
//! The transport keys (`sourceURL`, `url`, `statusCode`, `contentType`, ...) belong to the page
//! fetch, not to the document, and are added by the caller.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::document::Document;

/// `(compatibility key, meta name)` pairs of single-valued keys.
const SINGLE: &[(&str, &str)] = &[
    ("keywords", "keywords"),
    ("robots", "robots"),
    ("ogTitle", "og:title"),
    ("ogDescription", "og:description"),
    ("ogUrl", "og:url"),
    ("ogImage", "og:image"),
    ("ogAudio", "og:audio"),
    ("ogDeterminer", "og:determiner"),
    ("ogLocale", "og:locale"),
    ("ogSiteName", "og:site_name"),
    ("ogVideo", "og:video"),
    ("dctermsCreated", "dcterms.created"),
    ("dcDateCreated", "dc.date.created"),
    ("dcDate", "dc.date"),
    ("dctermsType", "dcterms.type"),
    ("dcType", "dc.type"),
    ("dctermsAudience", "dcterms.audience"),
    ("dctermsSubject", "dcterms.subject"),
    ("dcSubject", "dc.subject"),
    ("dcDescription", "dc.description"),
    ("dctermsKeywords", "dcterms.keywords"),
    ("modifiedTime", "article:modified_time"),
    ("publishedTime", "article:published_time"),
    ("articleTag", "article:tag"),
    ("articleSection", "article:section"),
];

/// Meta name of the alternate locales (`ogLocaleAlternate`, always an array).
const OG_LOCALE_ALTERNATE: &str = "og:locale:alternate";

fn value_of(values: &[String]) -> Option<Value> {
    match values {
        [] => None,
        [one] => Some(Value::String(one.clone())),
        many => Some(Value::Array(many.iter().cloned().map(Value::String).collect())),
    }
}

/// The compatibility API `metadata` entries of `doc`, keyed in its spelling.
#[must_use]
pub fn compat_meta(doc: &Document) -> BTreeMap<String, Value> {
    let md = &doc.metadata;
    let mut out: BTreeMap<String, Value> = BTreeMap::new();

    // Every meta entry verbatim first; the documented keys below overwrite on collision.
    for (name, values) in &md.all_meta {
        if let Some(v) = value_of(values) {
            out.insert(name.clone(), v);
        }
    }

    let title = md.title_tag.as_ref().or(doc.title.as_ref());
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        out.insert("title".to_owned(), Value::String(t.clone()));
    }
    if let Some(d) = doc.description.as_ref().filter(|d| !d.is_empty()) {
        out.insert("description".to_owned(), Value::String(d.clone()));
    }
    if let Some(l) = doc.language.as_ref().filter(|l| !l.is_empty()) {
        out.insert("language".to_owned(), Value::String(l.clone()));
    }
    for (key, name) in SINGLE {
        if let Some(values) = md.all_meta.get(*name) {
            // A single-valued compatibility key takes the first occurrence.
            if let Some(first) = values.first() {
                out.insert((*key).to_owned(), Value::String(first.clone()));
            }
        }
    }
    if let Some(values) = md.all_meta.get(OG_LOCALE_ALTERNATE) {
        out.insert(
            "ogLocaleAlternate".to_owned(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::json;
    use url::Url;

    use super::*;
    use crate::{ExtractOptions, Extractor};

    const PAGE: &str = r#"<!doctype html><html lang="en-GB"><head>
        <title>Widget Guide | Acme</title>
        <meta name="description" content="How to use the widget.">
        <meta name="keywords" content="widget, guide">
        <meta name="robots" content="index, follow">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta property="og:title" content="Widget Guide">
        <meta property="og:description" content="OG description">
        <meta property="og:url" content="https://acme.example/guide">
        <meta property="og:image" content="https://acme.example/card.png">
        <meta property="og:site_name" content="Acme">
        <meta property="og:type" content="article">
        <meta property="og:locale" content="en_GB">
        <meta property="og:locale:alternate" content="fr_FR">
        <meta property="og:locale:alternate" content="de_DE">
        <meta property="article:published_time" content="2025-01-02T03:04:05Z">
        <meta property="article:tag" content="widgets">
        <meta property="article:tag" content="howto">
        <meta property="article:section" content="Docs">
        <meta name="DC.title" content="Dublin Title">
        <meta name="dcterms.created" content="2024-12-31">
        <meta name="twitter:card" content="summary_large_image">
        <meta name="twitter:site" content="@acme">
        <meta name="generator" content="">
      </head><body><h1>Heading</h1><p>text</p></body></html>"#;

    fn doc(html: &str) -> Document {
        Extractor::extract(
            html,
            &Url::parse("https://acme.example/guide").unwrap(),
            &ExtractOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn documented_compat_keys_use_the_title_tag_and_og_values() {
        let m = compat_meta(&doc(PAGE));
        assert_eq!(m["title"], json!("Widget Guide | Acme"));
        assert_eq!(m["description"], json!("How to use the widget."));
        assert_eq!(m["language"], json!("en-GB"));
        assert_eq!(m["keywords"], json!("widget, guide"));
        assert_eq!(m["robots"], json!("index, follow"));
        assert_eq!(m["ogTitle"], json!("Widget Guide"));
        assert_eq!(m["ogDescription"], json!("OG description"));
        assert_eq!(m["ogUrl"], json!("https://acme.example/guide"));
        assert_eq!(m["ogImage"], json!("https://acme.example/card.png"));
        assert_eq!(m["ogSiteName"], json!("Acme"));
        assert_eq!(m["ogLocale"], json!("en_GB"));
        assert_eq!(m["publishedTime"], json!("2025-01-02T03:04:05Z"));
        assert_eq!(m["articleSection"], json!("Docs"));
        assert_eq!(m["dctermsCreated"], json!("2024-12-31"));
    }

    #[test]
    fn og_locale_alternate_is_always_an_array_of_every_occurrence() {
        let m = compat_meta(&doc(PAGE));
        assert_eq!(m["ogLocaleAlternate"], json!(["fr_FR", "de_DE"]));
        let single = compat_meta(&doc(
            r#"<head><meta property="og:locale:alternate" content="es_ES"></head>"#,
        ));
        assert_eq!(single["ogLocaleAlternate"], json!(["es_ES"]));
    }

    #[test]
    fn other_meta_entries_are_carried_verbatim_and_repeated_names_become_arrays() {
        let m = compat_meta(&doc(PAGE));
        assert_eq!(m["viewport"], json!("width=device-width, initial-scale=1"));
        assert_eq!(m["og:type"], json!("article"));
        assert_eq!(m["twitter:card"], json!("summary_large_image"));
        assert_eq!(m["twitter:site"], json!("@acme"));
        assert_eq!(m["dc.title"], json!("Dublin Title"));
        assert_eq!(m["article:tag"], json!(["widgets", "howto"]));
        assert_eq!(m["articleTag"], json!("widgets"));
    }

    #[test]
    fn missing_and_empty_values_are_omitted_not_null() {
        let m = compat_meta(&doc("<html><body><p>bare</p></body></html>"));
        assert!(m.values().all(|v| !v.is_null()));
        for key in [
            "title",
            "description",
            "language",
            "keywords",
            "robots",
            "ogTitle",
            "ogLocaleAlternate",
        ] {
            assert!(!m.contains_key(key), "{key} must be absent");
        }
        assert!(
            !compat_meta(&doc(PAGE)).contains_key("generator"),
            "empty content is skipped"
        );
    }

    #[test]
    fn title_falls_back_to_og_title_then_heading_when_there_is_no_title_tag() {
        let m = compat_meta(&doc(
            r#"<head><meta property="og:title" content="Only OG"></head><body><h1>H</h1></body>"#,
        ));
        assert_eq!(m["title"], json!("Only OG"));
        let h = compat_meta(&doc("<body><h1>Just H</h1><p>x</p></body>"));
        assert_eq!(h["title"], json!("Just H"));
    }
}
