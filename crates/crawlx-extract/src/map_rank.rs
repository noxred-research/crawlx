//! Relevance ordering of `/map` results for the `search` parameter.
//!
//! The compatibility API orders the links of a map by relevance to a search string; it never drops any.
//! [`rank`] scores every item by how many distinct query words it contains and where: a word
//! that is a whole token of the URL (host, path, query) counts most, then a title token, then
//! a description token; a word that only occurs inside a longer token counts a little. The
//! whole query appearing as a phrase in the title or the URL path adds a bonus. Items with the
//! same score keep their input order, so the result is deterministic.

use std::collections::BTreeSet;

/// One link of a map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapItem {
    /// Absolute URL.
    pub url: String,
    /// Page title, when known.
    pub title: Option<String>,
    /// Page description, when known.
    pub description: Option<String>,
}

/// Most query words considered.
const MAX_QUERY_WORDS: usize = 32;

/// Weight of a distinct query word found in any field (outweighs any single field bonus).
const COVERAGE: u32 = 10;
const URL_TOKEN: u32 = 4;
const URL_SUBSTRING: u32 = 2;
const TITLE_TOKEN: u32 = 3;
const TITLE_SUBSTRING: u32 = 1;
const DESCRIPTION_TOKEN: u32 = 2;
const PHRASE: u32 = 3;

/// Lower-cased alphanumeric words of `s`.
fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// A field prepared for matching: its words and its words joined by single spaces.
struct Field {
    tokens: BTreeSet<String>,
    flat: String,
}

impl Field {
    fn new(text: &str) -> Self {
        let list = words(text);
        Self {
            flat: list.join(" "),
            tokens: list.into_iter().collect(),
        }
    }

    fn has_token(&self, w: &str) -> bool {
        self.tokens.contains(w)
    }

    fn has_substring(&self, w: &str) -> bool {
        self.flat.contains(w)
    }
}

/// URL without scheme and fragment, so that `https` and `www` do not match every query.
fn url_text(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split('#').next().unwrap_or(rest)
}

fn score(query: &[String], phrase: &str, item: &MapItem) -> u32 {
    let url = Field::new(url_text(&item.url));
    let title = Field::new(item.title.as_deref().unwrap_or(""));
    let desc = Field::new(item.description.as_deref().unwrap_or(""));
    let mut total = 0u32;
    for w in query {
        let mut hit = 0u32;
        hit += if url.has_token(w) {
            URL_TOKEN
        } else if url.has_substring(w) {
            URL_SUBSTRING
        } else {
            0
        };
        hit += if title.has_token(w) {
            TITLE_TOKEN
        } else if title.has_substring(w) {
            TITLE_SUBSTRING
        } else {
            0
        };
        if desc.has_token(w) {
            hit += DESCRIPTION_TOKEN;
        }
        if hit > 0 {
            total += COVERAGE + hit;
        }
    }
    if query.len() > 1 && (title.flat.contains(phrase) || url.flat.contains(phrase)) {
        total += PHRASE;
    }
    total
}

/// `items` ordered by relevance to `search` (best first, ties in input order). An empty or
/// wordless `search` returns the items unchanged; no item is ever dropped.
#[must_use]
pub fn rank(search: &str, items: Vec<MapItem>) -> Vec<MapItem> {
    let mut query: Vec<String> = Vec::new();
    for w in words(search) {
        if !query.contains(&w) && query.len() < MAX_QUERY_WORDS {
            query.push(w);
        }
    }
    if query.is_empty() {
        return items;
    }
    let phrase = query.join(" ");
    let mut scored: Vec<(u32, MapItem)> = items
        .into_iter()
        .map(|i| (score(&query, &phrase, &i), i))
        .collect();
    // `sort_by_key` is stable: equal scores keep their input order.
    scored.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
    scored.into_iter().map(|(_, i)| i).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn item(url: &str, title: Option<&str>, description: Option<&str>) -> MapItem {
        MapItem {
            url: url.to_owned(),
            title: title.map(str::to_owned),
            description: description.map(str::to_owned),
        }
    }

    fn urls(items: &[MapItem]) -> Vec<&str> {
        items.iter().map(|i| i.url.as_str()).collect()
    }

    #[test]
    fn url_token_beats_title_beats_description_and_all_items_are_kept() {
        let items = vec![
            item(
                "https://example.com/about",
                Some("About us"),
                Some("We write a blog too"),
            ),
            item("https://example.com/news", Some("The blog of Example"), None),
            item("https://example.com/blog/hello", None, None),
            item("https://example.com/contact", Some("Contact"), None),
        ];
        let ranked = rank("blog", items);
        assert_eq!(
            urls(&ranked),
            [
                "https://example.com/blog/hello",
                "https://example.com/news",
                "https://example.com/about",
                "https://example.com/contact",
            ]
        );
    }

    #[test]
    fn matching_more_query_words_wins_over_matching_one_word_strongly() {
        let items = vec![
            item("https://example.com/pricing", None, None),
            item(
                "https://example.com/docs/api/pricing-plans",
                Some("API pricing"),
                None,
            ),
            item("https://example.com/api", None, None),
        ];
        let ranked = rank("api pricing", items);
        assert_eq!(ranked[0].url, "https://example.com/docs/api/pricing-plans");
    }

    #[test]
    fn equal_scores_keep_input_order() {
        let items = vec![
            item("https://example.com/z", None, None),
            item("https://example.com/a", None, None),
            item("https://example.com/m", None, None),
        ];
        let ranked = rank("nothing matches", items.clone());
        assert_eq!(ranked, items);
        let tie = vec![
            item("https://example.com/b/shop", None, None),
            item("https://example.com/a/shop", None, None),
        ];
        assert_eq!(urls(&rank("shop", tie.clone())), urls(&tie));
    }

    #[test]
    fn empty_and_wordless_queries_return_the_input_unchanged() {
        let items = vec![
            item("https://b.example/", None, None),
            item("https://a.example/", None, None),
        ];
        assert_eq!(rank("", items.clone()), items);
        assert_eq!(rank("  --  ", items.clone()), items);
    }

    #[test]
    fn matching_is_case_insensitive_and_substring_matches_count_less_than_token_matches() {
        let items = vec![
            item("https://example.com/blogging-tips", None, None),
            item("https://example.com/BLOG/Post", None, None),
        ];
        let ranked = rank("Blog", items);
        assert_eq!(ranked[0].url, "https://example.com/BLOG/Post");
        assert_eq!(ranked[1].url, "https://example.com/blogging-tips");
    }

    #[test]
    fn scheme_and_www_do_not_count_and_unicode_words_match() {
        let items = vec![
            item("https://example.com/other", None, None),
            item("https://example.com/straße-guide", Some("Straße"), None),
        ];
        assert_eq!(rank("https", items.clone()), items);
        let ranked = rank("STRASSE straße", items);
        assert_eq!(ranked[0].url, "https://example.com/straße-guide");
    }

    #[test]
    fn repeated_query_words_are_counted_once() {
        let a = rank(
            "blog blog blog",
            vec![
                item("https://e.com/x", None, None),
                item("https://e.com/blog", None, None),
            ],
        );
        assert_eq!(a[0].url, "https://e.com/blog");
    }
}
