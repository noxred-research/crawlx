//! Bounded article metadata and source-only Unicode rule NLP.
//!
//! Independently authored rules; no downloaded models, remote fallback or clock.
//! Dates preserve uncertainty. Language comes only from valid declared evidence.

use crate::{
    article::english_stopword,
    dom::{collapse_ws, walk},
    metadata::HeadInfo,
    StringProjection,
};
use crawlx_core::extraction::{
    ArticleDateV1, ArticleMetadataV1, ExtractionPolicyV1, KeywordV1, MetadataEvidenceV1, MetadataValueV1,
    NlpCapabilityV1, SourceRangeV1,
};
use scraper::Html;
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

const MAX_EVIDENCE: usize = 32;
fn string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(collapse_ws(s).chars().take(4096).collect()),
        Value::Object(m) => m.get("name").and_then(string),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}
fn articles<'a>(value: &'a Value, depth: usize, output: &mut Vec<&'a Value>) {
    if depth > 8 || output.len() >= 32 {
        return;
    }
    match value {
        Value::Array(items) => {
            for item in items.iter().take(128) {
                articles(item, depth + 1, output);
            }
        }
        Value::Object(m) => {
            let is_article = m.get("@type").is_some_and(|t| match t {
                Value::String(t) => matches!(
                    t.as_str(),
                    "Article" | "NewsArticle" | "BlogPosting" | "DiscussionForumPosting"
                ),
                Value::Array(a) => a.iter().any(|t| {
                    t.as_str().is_some_and(|s| {
                        matches!(
                            s,
                            "Article" | "NewsArticle" | "BlogPosting" | "DiscussionForumPosting"
                        )
                    })
                }),
                _ => false,
            });
            if is_article {
                output.push(value);
            }
            if let Some(graph) = m.get("@graph") {
                articles(graph, depth + 1, output);
            }
            if let Some(entity) = m.get("mainEntity") {
                articles(entity, depth + 1, output);
            }
        }
        _ => {}
    }
}
/// Structured forum posts are main content, not blog comments.
pub(crate) fn is_forum(head: &HeadInfo) -> bool {
    let mut selected = Vec::new();
    for value in &head.metadata.json_ld {
        articles(value, 0, &mut selected);
    }
    selected.iter().any(|value| {
        value.get("@type").is_some_and(|t| {
            t.as_str() == Some("DiscussionForumPosting")
                || t.as_array()
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("DiscussionForumPosting")))
        })
    })
}
fn push(evidence: &mut Vec<MetadataEvidenceV1>, source: &str, raw: &str, truncated: &mut bool) {
    if raw.is_empty() {
        return;
    }
    if evidence.len() == MAX_EVIDENCE {
        *truncated = true;
        return;
    }
    *truncated |= raw.chars().count() > 4096;
    evidence.push(MetadataEvidenceV1::new(source, raw, evidence.len()));
}
fn field(
    articles: &[&Value],
    head: &HeadInfo,
    keys: &[&str],
    meta: &[&str],
    fallback: Option<&str>,
) -> MetadataValueV1<String> {
    let mut evidence = Vec::new();
    let mut truncated = false;
    for article in articles {
        for key in keys {
            if let Some(value) = article.get(*key).and_then(string) {
                push(&mut evidence, key, &value, &mut truncated);
            }
        }
    }
    for key in meta {
        if let Some(values) = head.metadata.all_meta.get(*key) {
            for value in values {
                push(&mut evidence, key, value, &mut truncated);
            }
        }
    }
    if let Some(value) = fallback {
        push(&mut evidence, "document_fallback", value, &mut truncated);
    }
    let value = evidence.first().map(|e| e.raw.clone());
    let uncertain = evidence.iter().any(|e| Some(&e.raw) != value.as_ref());
    MetadataValueV1::new(value, evidence, uncertain, truncated)
}
fn authors(articles: &[&Value], head: &HeadInfo, doc: &Html) -> MetadataValueV1<Vec<String>> {
    let mut evidence = Vec::new();
    let mut chosen = Vec::new();
    let mut truncated = false;
    for article in articles {
        if let Some(author) = article.get("author") {
            let values: Vec<&Value> = match author {
                Value::Array(a) => a.iter().take(32).collect(),
                value => vec![value],
            };
            let mut group = Vec::new();
            for value in values {
                if let Some(name) = string(value) {
                    push(&mut evidence, "article.author", &name, &mut truncated);
                    if !group.contains(&name) {
                        group.push(name);
                    }
                }
            }
            if chosen.is_empty() {
                chosen = group;
            }
        }
    }
    for key in ["author", "article:author", "parsely-author"] {
        if let Some(values) = head.metadata.all_meta.get(key) {
            let mut group = Vec::new();
            for value in values {
                push(&mut evidence, key, value, &mut truncated);
                let name: String = value.chars().take(4096).collect();
                if !group.contains(&name) {
                    group.push(name);
                }
            }
            if chosen.is_empty() {
                chosen = group;
            }
        }
    }
    let mut byline = Vec::new();
    walk(doc.tree.root(), |el| {
        if matches!(el.value().name(), "script" | "style" | "template") {
            return false;
        }
        if el
            .value()
            .attr("rel")
            .is_some_and(|v| v.split_whitespace().any(|s| s == "author"))
            || el.value().attr("itemprop") == Some("author")
        {
            let value = collapse_ws(&el.text().collect::<String>());
            if !value.is_empty() && byline.len() < 32 {
                byline.push(value);
            }
            return false;
        }
        true
    });
    for value in &byline {
        push(&mut evidence, "visible_author", value, &mut truncated);
    }
    if chosen.is_empty() {
        chosen = byline
            .into_iter()
            .take(32)
            .map(|s| s.chars().take(4096).collect())
            .collect();
    }
    let uncertain = evidence.iter().any(|e| !chosen.contains(&e.raw));
    MetadataValueV1::new(
        (!chosen.is_empty()).then_some(chosen),
        evidence,
        uncertain,
        truncated,
    )
}
fn normalize_language(raw: &str) -> Option<String> {
    let normalized = raw.trim().replace('_', "-");
    let mut parts = normalized.split('-');
    let first = parts.next()?;
    if !(2..=3).contains(&first.len())
        || !first.bytes().all(|c| c.is_ascii_alphabetic())
        || !parts.all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|c| c.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(normalized.to_ascii_lowercase())
}
fn parse_date(raw: &str, policy: &ExtractionPolicyV1) -> Option<ArticleDateV1> {
    crate::article_dates::parse(raw, policy).map(|(date, _)| date)
}
fn dates(
    mut raw: MetadataValueV1<String>,
    visible: &[String],
    url: &Url,
    policy: &ExtractionPolicyV1,
    published: bool,
) -> MetadataValueV1<ArticleDateV1> {
    for value in visible {
        push(&mut raw.evidence, "visible_time", value, &mut raw.truncated);
    }
    if published {
        let parts: Vec<_> = url
            .path()
            .split('/')
            .filter(|p| !p.is_empty())
            .take(128)
            .collect();
        for chunk in parts.windows(3) {
            if chunk[0].len() == 4 && chunk[1].len() <= 2 && chunk[2].len() <= 2 {
                let candidate = format!("{}/{}/{}", chunk[0], chunk[1], chunk[2]);
                if parse_date(&candidate, policy).is_some() {
                    push(
                        &mut raw.evidence,
                        "url_calendar_hint",
                        &candidate,
                        &mut raw.truncated,
                    );
                    break;
                }
            }
        }
    }
    let value = raw.evidence.iter().find_map(|e| parse_date(&e.raw, policy));
    let uncertain = (!raw.evidence.is_empty() && value.is_none())
        || raw.evidence.iter().any(|e| {
            crate::article_dates::parse(&e.raw, policy)
                .is_none_or(|(date, inferred)| inferred || Some(date).as_ref() != value.as_ref())
        });
    MetadataValueV1::new(value, raw.evidence, uncertain, raw.truncated)
}
fn tokens(source: &str) -> (Vec<(String, SourceRangeV1)>, bool) {
    let mut result = Vec::new();
    let mut truncated = false;
    crate::article_tokens::rules_words(source, |start, end| {
        if result.len() == 100_000 {
            truncated = true;
            return false;
        }
        result.push((source[start..end].to_lowercase(), SourceRangeV1::new(start, end)));
        true
    });
    (result, truncated)
}
fn policy_tokens(source: &str, policy: &ExtractionPolicyV1) -> (Vec<(String, SourceRangeV1)>, bool) {
    match policy.tokenizer {
        crawlx_core::extraction::ArticleTokenizerV1::IcuDictionaryUax29V17V1 => {
            crate::article_tokens::dictionary(source)
        }
        _ => tokens(source),
    }
}

/// Count version-one Unicode lexical units, including individual CJK scalars.
pub(crate) fn word_count(source: &str) -> usize {
    let mut count = 0usize;
    crate::article_tokens::rules_words(source, |_, _| {
        count = count.saturating_add(1);
        true
    });
    count
}
fn sentences(source: &str) -> Vec<SourceRangeV1> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut iter = source.char_indices().peekable();
    while let Some((offset, ch)) = iter.next() {
        if !matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '؟' | '।' | '॥' | '\n') {
            continue;
        }
        let mut end = offset + ch.len_utf8();
        if ch == '.' {
            let prefix = &source[start..offset];
            let last = prefix.split_whitespace().next_back().unwrap_or("");
            if matches!(last, "Dr" | "Mr" | "Mrs" | "Ms" | "Prof" | "e.g" | "i.e")
                || (last.chars().next_back().is_some_and(|c| c.is_ascii_digit())
                    && iter.peek().is_some_and(|(_, c)| c.is_ascii_digit()))
            {
                continue;
            }
        }
        while iter.peek().is_some_and(|(_, c)| {
            matches!(
                c,
                '"' | '\'' | '”' | '’' | '」' | '』' | ')' | ']' | '.' | '!' | '?'
            )
        }) {
            if let Some((i, c)) = iter.next() {
                end = i + c.len_utf8();
            }
        }
        let slice = &source[start..end];
        let left = slice.len() - slice.trim_start().len();
        let right = slice.trim_end().len();
        if right > left && result.len() < 20_001 {
            result.push(SourceRangeV1::new(start + left, start + right));
        }
        start = end;
    }
    if start < source.len() && result.len() < 20_001 {
        let tail = &source[start..];
        let left = tail.len() - tail.trim_start().len();
        let right = tail.trim_end().len();
        if right > left {
            result.push(SourceRangeV1::new(start + left, start + right));
        }
    }
    result
}
fn nlp(metadata: &mut ArticleMetadataV1, main: &str, policy: &ExtractionPolicyV1) {
    if policy.nlp != NlpCapabilityV1::UnicodeRulesV1 {
        return;
    }
    metadata.tokenizer_version = Some(
        match policy.tokenizer {
            crawlx_core::extraction::ArticleTokenizerV1::IcuDictionaryUax29V17V1 => {
                "icu_dictionary_uax29_v17_v1"
            }
            _ => "unicode_rules_v1",
        }
        .to_owned(),
    );
    let (main_tokens, truncated) = policy_tokens(main, policy);
    metadata.nlp_truncated = truncated;
    let english = metadata
        .language
        .value
        .as_deref()
        .is_some_and(|s| s == "en" || s.starts_with("en-"));
    let mut counts: BTreeMap<String, (usize, SourceRangeV1)> = BTreeMap::new();
    for (token, span) in main_tokens {
        if (english && english_stopword(&token)) || token.chars().all(char::is_numeric) {
            continue;
        }
        if counts.len() >= 20_000 && !counts.contains_key(&token) {
            metadata.nlp_truncated = true;
            continue;
        }
        let entry = counts.entry(token).or_insert((0, span));
        entry.0 = entry.0.saturating_add(1);
    }
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|(ta, (ca, sa)), (tb, (cb, sb))| {
        cb.cmp(ca)
            .then_with(|| sa.start.cmp(&sb.start))
            .then_with(|| ta.cmp(tb))
    });
    metadata.keywords = ranked
        .into_iter()
        .take(policy.keywords)
        .map(|(t, (c, s))| KeywordV1::new(t, c, s))
        .collect();
    let title_tokens: std::collections::BTreeSet<_> = metadata
        .title
        .value
        .as_deref()
        .map(|title| policy_tokens(title, policy).0)
        .unwrap_or_default()
        .into_iter()
        .map(|(word, _)| word)
        .collect();
    let keyword_scores: BTreeMap<_, _> = metadata
        .keywords
        .iter()
        .map(|k| (k.token.as_str(), k.score))
        .collect();
    let mut sentence_ranges = sentences(main);
    metadata.nlp_truncated |= sentence_ranges.len() > 20_000;
    sentence_ranges.truncate(20_000);
    let mut summary: Vec<_> = sentence_ranges
        .into_iter()
        .enumerate()
        .map(|(i, span)| {
            let (words, truncated) = policy_tokens(&main[span.start..span.end], policy);
            metadata.nlp_truncated |= truncated;
            let score = words
                .iter()
                .fold(0usize, |score, (word, _)| {
                    score
                        .saturating_add(if title_tokens.contains(word) { 32 } else { 0 })
                        .saturating_add(
                            keyword_scores
                                .get(word.as_str())
                                .map_or(0, |score| score.saturating_mul(8)),
                        )
                })
                .saturating_add(64usize.saturating_sub(i))
                .saturating_add(words.len().min(40));
            (score, span)
        })
        .collect();
    summary.sort_by(|(a, sa), (b, sb)| b.cmp(a).then_with(|| sa.start.cmp(&sb.start)));
    let mut chars = 0usize;
    metadata.summary = summary
        .into_iter()
        .filter_map(|(_, span)| {
            let count = main[span.start..span.end]
                .chars()
                .count()
                .saturating_add(usize::from(chars > 0));
            if chars.saturating_add(count) > policy.summary_max_chars {
                None
            } else {
                chars += count;
                Some(span)
            }
        })
        .take(policy.summary_sentences)
        .collect();
    metadata.summary.sort_by_key(|span| span.start);
}
/// Apply a trusted compiled worker projection without copying unchanged strings.
pub(crate) fn project_string(value: &mut String, project: &StringProjection<'_>) -> bool {
    if let Some(projected) = project(value) {
        if projected != *value {
            *value = projected;
            return true;
        }
    }
    false
}
fn project_metadata(metadata: &mut ArticleMetadataV1, project: &StringProjection<'_>) {
    for evidence in [
        &mut metadata.title.evidence,
        &mut metadata.authors.evidence,
        &mut metadata.language.evidence,
        &mut metadata.publisher.evidence,
        &mut metadata.published.evidence,
        &mut metadata.modified.evidence,
    ] {
        for item in evidence {
            project_string(&mut item.raw, project);
        }
    }
    for value in [
        &mut metadata.title.value,
        &mut metadata.language.value,
        &mut metadata.publisher.value,
    ]
    .into_iter()
    .flatten()
    {
        project_string(value, project);
    }
    if let Some(authors) = &mut metadata.authors.value {
        for author in authors {
            project_string(author, project);
        }
    }
    for keyword in &mut metadata.declared_keywords {
        project_string(keyword, project);
    }
    metadata.language.value = metadata.language.value.as_deref().and_then(normalize_language);
    metadata.language.uncertain |=
        !metadata.language.evidence.is_empty() && metadata.language.value.is_none();
    for field in [&mut metadata.published, &mut metadata.modified] {
        if field.value.as_ref().is_some_and(|date| {
            project(&date.date.to_string()).is_some()
                || date
                    .timestamp
                    .as_deref()
                    .is_some_and(|stamp| project(stamp).is_some())
        }) {
            field.value = None;
            field.uncertain = true;
        }
    }
}

/// Build evidence from the already parsed document and metadata pass.
pub(crate) fn extract(
    doc: &Html,
    head: &HeadInfo,
    url: &Url,
    main: &str,
    policy: &ExtractionPolicyV1,
    project: Option<&StringProjection<'_>>,
    detector: Option<&dyn crawlx_core::article_language::ArticleLanguageDetector>,
) -> (ArticleMetadataV1, bool) {
    let mut selected = Vec::new();
    for value in &head.metadata.json_ld {
        articles(value, 0, &mut selected);
    }
    let mut metadata = ArticleMetadataV1::default();
    metadata.title = field(
        &selected,
        head,
        &["headline", "name"],
        &["og:title", "twitter:title"],
        head.title.as_deref(),
    );
    metadata.authors = authors(&selected, head, doc);
    metadata.publisher = field(&selected, head, &["publisher"], &["og:site_name"], None);
    metadata.language = field(
        &selected,
        head,
        &["inLanguage"],
        &["language", "og:locale"],
        head.language.as_deref(),
    );
    metadata.language.value = metadata.language.value.as_deref().and_then(normalize_language);
    metadata.language.uncertain |=
        !metadata.language.evidence.is_empty() && metadata.language.value.is_none();
    let mut published = Vec::new();
    let mut modified = Vec::new();
    walk(doc.tree.root(), |el| {
        if matches!(el.value().name(), "script" | "style" | "template") {
            return false;
        }
        let prop = el.value().attr("itemprop");
        if el.value().name() == "time" || matches!(prop, Some("datePublished" | "dateModified")) {
            let near_main = el
                .ancestors()
                .filter_map(scraper::ElementRef::wrap)
                .any(|p| matches!(p.value().name(), "main" | "article"));
            if near_main || prop.is_some() {
                let raw = el
                    .value()
                    .attr("datetime")
                    .or_else(|| el.value().attr("content"))
                    .map(str::to_owned)
                    .unwrap_or_else(|| collapse_ws(&el.text().collect::<String>()));
                let group = if prop == Some("dateModified") {
                    &mut modified
                } else {
                    &mut published
                };
                if group.len() < 32 {
                    group.push(raw.chars().take(4096).collect());
                }
            }
        }
        true
    });
    metadata.published = dates(
        field(
            &selected,
            head,
            &["datePublished"],
            &["article:published_time", "date", "pubdate"],
            None,
        ),
        &published,
        url,
        policy,
        true,
    );
    metadata.modified = dates(
        field(
            &selected,
            head,
            &["dateModified"],
            &["article:modified_time", "last-modified"],
            None,
        ),
        &modified,
        url,
        policy,
        false,
    );
    if let Some(values) = head.metadata.all_meta.get("keywords") {
        for value in values {
            for token in value.split(',') {
                let token: String = token.trim().chars().take(128).collect();
                if !token.is_empty()
                    && metadata.declared_keywords.len() < 128
                    && !metadata.declared_keywords.contains(&token)
                {
                    metadata.declared_keywords.push(token);
                }
            }
        }
    }
    let author_excluded = crate::article_quality::author_excluded(policy, &metadata);
    if let Some(project) = project {
        project_metadata(&mut metadata, project);
    }
    crate::article_language::select(&mut metadata, policy, detector, main);
    nlp(&mut metadata, main, policy);
    if let Some(project) = project {
        metadata
            .keywords
            .retain(|keyword| project(&keyword.token).is_none_or(|value| value == keyword.token));
    }
    (metadata, author_excluded)
}

/// Return references only. No parser path owns an HTTP client or worker authority.
pub(crate) fn discovery(
    doc: &Html,
    base: &Url,
    policy: &ExtractionPolicyV1,
) -> Vec<crawlx_core::extraction::DiscoveryIntentV1> {
    use crawlx_core::extraction::{DiscoveryIntentV1, DiscoveryPurposeV1};
    let mut intents = Vec::new();
    walk(doc.tree.root(), |el| {
        if intents.len() >= 32 {
            return false;
        }
        let value = el.value();
        if matches!(value.name(), "script" | "style" | "template") {
            return false;
        }
        let reference = if policy.images && value.name() == "img" {
            value
                .attr("src")
                .map(|src| (src, DiscoveryPurposeV1::ImageReference))
        } else if policy.images
            && value.name() == "meta"
            && matches!(
                value.attr("property").or_else(|| value.attr("name")),
                Some("og:image" | "twitter:image")
            )
        {
            value
                .attr("content")
                .map(|src| (src, DiscoveryPurposeV1::ImageReference))
        } else if value.name() == "a"
            && value
                .attr("rel")
                .is_some_and(|rel| rel.split_whitespace().any(|r| r == "next"))
        {
            value
                .attr("href")
                .map(|src| (src, DiscoveryPurposeV1::ReadMoreReference))
        } else {
            None
        };
        if let Some((raw, purpose)) = reference {
            if let Some(url) =
                crate::dom::resolve(base, raw).filter(|u| matches!(u.scheme(), "http" | "https"))
            {
                if !intents
                    .iter()
                    .any(|intent: &DiscoveryIntentV1| intent.url == url && intent.purpose == purpose)
                {
                    intents.push(DiscoveryIntentV1::new(url, purpose));
                }
            }
        }
        true
    });
    intents
}
