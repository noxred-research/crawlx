//! Locale-specific V2 name normalization and page language selection.

use std::sync::LazyLock;

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

use crate::normalize::normalize_accessible_name;

const FRENCH: &str = r"\b(?:(?:il y a|dans)\s+(?:\d+|une?)\s+(?:secondes?|minutes?|heures?|jours?|semaines?|mois|ans?|années?)|hier|aujourd'hui|à l'instant)\b|\b\d{1,2}(?:er)?\s+(?:janvier|février|mars|avril|mai|juin|juillet|août|septembre|octobre|novembre|décembre)(?:\s+\d{4})?\b";
const GERMAN: &str = r"\b(?:(?:vor|in)\s+(?:\d+|eine?[mnrs]?)\s+(?:sekunden?|minuten?|stunden?|tag(?:en?|s)?|wochen?|monat(?:en?|s)?|jahr(?:en?|s)?)|gestern|heute|gerade eben)\b|\b\d{1,2}\.\s*(?:januar|februar|märz|april|mai|juni|juli|august|september|oktober|november|dezember)(?:\s+\d{4})?\b";
const SPANISH: &str = r"\b(?:(?:hace|en)\s+(?:\d+|un[ao]?)\s+(?:segundos?|minutos?|horas?|días?|semanas?|mes(?:es)?|años?)|ayer|hoy|ahora mismo)\b|\b\d{1,2}\s+(?:de\s+)?(?:enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)(?:\s+(?:de\s+)?\d{4})?\b";
const NUMBERS: &str = r"\b\d+(?:[., '/’\-]\d+)+\b";

static PATTERNS: LazyLock<[Option<Regex>; 4]> =
    LazyLock::new(|| [FRENCH, GERMAN, SPANISH, NUMBERS].map(|source| Regex::new(source).ok()));
static HTML_LANG: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?is)<html\b[^>]*?\s+lang\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).ok());

/// Main document's `lang` attribute, or an empty language for untagged pages.
/// Browser observations already capture the main document HTML.
#[must_use]
pub fn page_language(html: Option<&str>) -> &str {
    let Some(captures) = HTML_LANG.as_ref().and_then(|re| re.captures(html?)) else {
        return "";
    };
    (1..=3)
        .find_map(|i| captures.get(i).map(|m| m.as_str()))
        .unwrap_or("")
}

pub(crate) fn normalize_name(raw: &str, lang: &str) -> String {
    let mut name = raw.nfkc().collect::<String>().to_lowercase();
    let language = lang.trim().split(['-', '_']).next().unwrap_or("");
    let index = if language.eq_ignore_ascii_case("fr") {
        Some(0)
    } else if language.eq_ignore_ascii_case("de") {
        Some(1)
    } else if language.eq_ignore_ascii_case("es") {
        Some(2)
    } else {
        None
    };
    if let Some(pattern) = index.and_then(|i| PATTERNS[i].as_ref()) {
        name = pattern.replace_all(&name, " ").into_owned();
    }
    // Strip complete ISO datetimes before grouped numbers can consume their date prefix.
    name = crate::normalize::strip_standard_patterns(&name);
    if let Some(pattern) = &PATTERNS[3] {
        name = pattern.replace_all(&name, " ").into_owned();
    }
    normalize_accessible_name(&name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_pattern_compiles_and_page_language_uses_only_html() {
        assert!(PATTERNS.iter().all(Option::is_some));
        assert!(HTML_LANG.is_some());
        assert_eq!(
            page_language(Some("<html LANG='fr-FR'><body lang='de'>")),
            "fr-FR"
        );
        assert_eq!(page_language(Some("<html lang=es-ES>")), "es-ES");
        assert_eq!(page_language(Some("<body lang='de'>")), "");
        assert_eq!(page_language(None), "");
    }

    #[test]
    fn locale_selection_and_common_numeric_dates_are_explicit() {
        assert_eq!(normalize_name("Messages il y a 3 minutes", "FR-ca"), "messages");
        assert_ne!(normalize_name("Messages il y a 3 minutes", "de"), "messages");
        for language in ["fr", "de", "es"] {
            for name in [
                "Inbox 20/10/2026",
                "Inbox 21.11.2027",
                "Inbox ２０-１０-２０２６",
                "Inbox 1’234",
            ] {
                assert_eq!(normalize_name(name, language), "inbox");
            }
        }
        assert_eq!(normalize_name("Post vor einem Tag", "de"), "post");
        assert_eq!(normalize_name("Post vor einem Jahr", "de"), "post");
        assert_eq!(normalize_name("Inbox 2026-10-20T10:45:12Z", "fr"), "inbox");
    }
}
