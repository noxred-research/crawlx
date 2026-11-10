//! Browser emulation of a scrape request: the compatibility API's `mobile` and `location{country,
//! languages}` options as one [`Emulation`].
//!
//! `location` sets the `Accept-Language` header, the `navigator.language` locale and the time
//! zone of the page. The country table below is written for this crate: each entry names the
//! country's main language tag and the IANA zone of its capital or largest city. A country
//! without an entry contributes nothing: only the caller's `languages` apply.

use crawlx_core::page_op::Emulation;
use crawlx_core::scrape::{Location, ScrapeOptions, MOBILE_USER_AGENT, MOBILE_VIEWPORT};

/// What a country implies for a browser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CountryProfile {
    /// ISO 3166-1 alpha-2 code, upper case.
    pub country: &'static str,
    /// BCP 47 tag of the country's main language.
    pub language: &'static str,
    /// IANA time zone of the capital or largest city.
    pub timezone: &'static str,
}

const fn c(country: &'static str, language: &'static str, timezone: &'static str) -> CountryProfile {
    CountryProfile {
        country,
        language,
        timezone,
    }
}

/// The countries `location.country` knows, sorted by code.
pub const COUNTRIES: &[CountryProfile] = &[
    c("AE", "ar-AE", "Asia/Dubai"),
    c("AR", "es-AR", "America/Argentina/Buenos_Aires"),
    c("AT", "de-AT", "Europe/Vienna"),
    c("AU", "en-AU", "Australia/Sydney"),
    c("BD", "bn-BD", "Asia/Dhaka"),
    c("BE", "nl-BE", "Europe/Brussels"),
    c("BG", "bg-BG", "Europe/Sofia"),
    c("BR", "pt-BR", "America/Sao_Paulo"),
    c("CA", "en-CA", "America/Toronto"),
    c("CH", "de-CH", "Europe/Zurich"),
    c("CL", "es-CL", "America/Santiago"),
    c("CN", "zh-CN", "Asia/Shanghai"),
    c("CO", "es-CO", "America/Bogota"),
    c("CZ", "cs-CZ", "Europe/Prague"),
    c("DE", "de-DE", "Europe/Berlin"),
    c("DK", "da-DK", "Europe/Copenhagen"),
    c("EG", "ar-EG", "Africa/Cairo"),
    c("ES", "es-ES", "Europe/Madrid"),
    c("FI", "fi-FI", "Europe/Helsinki"),
    c("FR", "fr-FR", "Europe/Paris"),
    c("GB", "en-GB", "Europe/London"),
    c("GR", "el-GR", "Europe/Athens"),
    c("HK", "zh-HK", "Asia/Hong_Kong"),
    c("HU", "hu-HU", "Europe/Budapest"),
    c("ID", "id-ID", "Asia/Jakarta"),
    c("IE", "en-IE", "Europe/Dublin"),
    c("IL", "he-IL", "Asia/Jerusalem"),
    c("IN", "en-IN", "Asia/Kolkata"),
    c("IS", "is-IS", "Atlantic/Reykjavik"),
    c("IT", "it-IT", "Europe/Rome"),
    c("JP", "ja-JP", "Asia/Tokyo"),
    c("KE", "en-KE", "Africa/Nairobi"),
    c("KR", "ko-KR", "Asia/Seoul"),
    c("LU", "fr-LU", "Europe/Luxembourg"),
    c("MX", "es-MX", "America/Mexico_City"),
    c("MY", "ms-MY", "Asia/Kuala_Lumpur"),
    c("NG", "en-NG", "Africa/Lagos"),
    c("NL", "nl-NL", "Europe/Amsterdam"),
    c("NO", "nb-NO", "Europe/Oslo"),
    c("NZ", "en-NZ", "Pacific/Auckland"),
    c("PE", "es-PE", "America/Lima"),
    c("PH", "en-PH", "Asia/Manila"),
    c("PK", "ur-PK", "Asia/Karachi"),
    c("PL", "pl-PL", "Europe/Warsaw"),
    c("PT", "pt-PT", "Europe/Lisbon"),
    c("RO", "ro-RO", "Europe/Bucharest"),
    c("RU", "ru-RU", "Europe/Moscow"),
    c("SA", "ar-SA", "Asia/Riyadh"),
    c("SE", "sv-SE", "Europe/Stockholm"),
    c("SG", "en-SG", "Asia/Singapore"),
    c("SK", "sk-SK", "Europe/Bratislava"),
    c("TH", "th-TH", "Asia/Bangkok"),
    c("TR", "tr-TR", "Europe/Istanbul"),
    c("TW", "zh-TW", "Asia/Taipei"),
    c("UA", "uk-UA", "Europe/Kiev"),
    c("US", "en-US", "America/New_York"),
    c("VN", "vi-VN", "Asia/Ho_Chi_Minh"),
    c("ZA", "en-ZA", "Africa/Johannesburg"),
];

/// The profile of `code` (ISO 3166-1 alpha-2, any case), or `None` for a country the table
/// does not list.
#[must_use]
pub fn country_profile(code: &str) -> Option<&'static CountryProfile> {
    let upper = code.trim().to_ascii_uppercase();
    COUNTRIES
        .binary_search_by(|p| p.country.cmp(upper.as_str()))
        .ok()
        .and_then(|i| COUNTRIES.get(i))
}

/// Is `tag` a syntactically valid BCP 47 language tag (`en`, `de-DE`, `zh-Hant-TW`)? Tags
/// travel into the `Accept-Language` header and the browser's locale override, so anything
/// else is dropped.
fn is_language_tag(tag: &str) -> bool {
    let mut parts = tag.split('-');
    let primary_ok = parts
        .next()
        .is_some_and(|p| (2..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphabetic()));
    primary_ok && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The caller's valid language tags in order; the country's main language when the caller named
/// none.
fn languages(location: &Location, profile: Option<&CountryProfile>) -> Vec<String> {
    let given: Vec<String> = location
        .languages
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|l| is_language_tag(l))
        .map(str::to_owned)
        .collect();
    if given.is_empty() {
        profile.map(|p| p.language.to_owned()).into_iter().collect()
    } else {
        given
    }
}

/// The `Accept-Language` list of the override: `languages` joined by commas. Chromium weights
/// the entries itself, so the header on the wire reads `de-DE,en;q=0.9,fr;q=0.8` for
/// `["de-DE", "en", "fr"]`; weights written here would be weighted a second time
/// (`en;q=0.9;q=0.9`). `None` for no language.
#[must_use]
pub fn accept_language(languages: &[String]) -> Option<String> {
    (!languages.is_empty()).then(|| languages.join(","))
}

/// The `Accept-Language` header the HTTP plane sends for `location`: the caller's valid
/// `languages` (else the country's main language) with descending quality weights
/// (`de-DE,en;q=0.9,fr;q=0.8`), at most 10 entries. Unlike the browser override, nothing
/// weights the entries afterwards, so the weights are written here. `None` when `location`
/// names no usable language and no known country.
#[must_use]
pub fn http_accept_language(location: &Location) -> Option<String> {
    let profile = location.country.as_deref().and_then(country_profile);
    let langs = languages(location, profile);
    let mut parts = Vec::with_capacity(langs.len().min(10));
    for (i, lang) in langs.iter().take(10).enumerate() {
        if i == 0 {
            parts.push(lang.clone());
        } else {
            let tenths = 10usize.saturating_sub(i).max(1);
            parts.push(format!("{lang};q=0.{tenths}"));
        }
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

/// The emulation `location` asks for, or `None` when it names nothing the browser can apply
/// (an unknown country and no valid language).
#[must_use]
pub fn location_emulation(location: &Location) -> Option<Emulation> {
    let profile = location.country.as_deref().and_then(country_profile);
    let langs = languages(location, profile);
    let em = Emulation {
        accept_language: accept_language(&langs),
        locale: langs.first().cloned(),
        timezone: profile.map(|p| p.timezone.to_owned()),
        ..Emulation::default()
    };
    (em != Emulation::default()).then_some(em)
}

/// The emulation a scrape applies before it navigates: the phone viewport and `User-Agent` of
/// `mobile`, merged with the `location` emulation. `None` when the options ask for neither.
#[must_use]
pub fn emulation_for(options: &ScrapeOptions) -> Option<Emulation> {
    let mut em = options
        .location
        .as_ref()
        .and_then(location_emulation)
        .unwrap_or_default();
    if options.mobile {
        em.viewport = Some((MOBILE_VIEWPORT.width, MOBILE_VIEWPORT.height));
        em.mobile = true;
        em.user_agent = Some(MOBILE_USER_AGENT.to_owned());
    }
    (em != Emulation::default()).then_some(em)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn loc(country: Option<&str>, languages: &[&str]) -> Location {
        Location {
            country: country.map(str::to_owned),
            languages: languages.iter().map(|l| (*l).to_owned()).collect(),
        }
    }

    #[test]
    fn the_table_is_sorted_unique_and_covers_at_least_forty_countries() {
        assert!(COUNTRIES.len() >= 40);
        assert!(COUNTRIES.windows(2).all(|w| w[0].country < w[1].country));
        for p in COUNTRIES {
            assert_eq!(p.country.len(), 2, "{p:?}");
            assert!(p.country.bytes().all(|b| b.is_ascii_uppercase()), "{p:?}");
            assert!(is_language_tag(p.language), "{p:?}");
            assert!(p.language.ends_with(p.country), "{p:?}");
            assert!(p.timezone.contains('/') && !p.timezone.contains(' '), "{p:?}");
        }
    }

    #[test]
    fn country_lookup_ignores_case_and_whitespace_and_unknown_codes_miss() {
        assert_eq!(country_profile("de").unwrap().timezone, "Europe/Berlin");
        assert_eq!(country_profile(" JP ").unwrap().language, "ja-JP");
        assert!(country_profile("XX").is_none());
        assert!(country_profile("").is_none());
    }

    #[test]
    fn accept_language_is_the_plain_comma_list_the_browser_weights() {
        assert_eq!(accept_language(&[]), None);
        assert_eq!(accept_language(&["de-DE".to_owned()]).unwrap(), "de-DE");
        let many: Vec<String> = ["fr", "en", "de"].iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(accept_language(&many).unwrap(), "fr,en,de");
    }

    #[test]
    fn the_http_header_carries_descending_quality_weights() {
        assert_eq!(
            http_accept_language(&loc(Some("JP"), &["en-US", "fr", "de"])).unwrap(),
            "en-US,fr;q=0.9,de;q=0.8"
        );
        assert_eq!(http_accept_language(&loc(Some("DE"), &[])).unwrap(), "de-DE");
        assert_eq!(http_accept_language(&loc(Some("ZZ"), &["bad tag"])), None);
        let many: Vec<String> = (0..14u8).map(|i| format!("a{}", char::from(b'a' + i))).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let header = http_accept_language(&loc(None, &refs)).unwrap();
        assert_eq!(header.split(',').count(), 10);
        assert!(header.ends_with("q=0.1"), "{header}");
    }

    #[test]
    fn a_known_country_sets_locale_zone_and_its_language_when_none_is_given() {
        let em = location_emulation(&loc(Some("DE"), &[])).unwrap();
        assert_eq!(em.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(em.locale.as_deref(), Some("de-DE"));
        assert_eq!(em.accept_language.as_deref(), Some("de-DE"));
        assert!(!em.mobile && em.viewport.is_none() && em.user_agent.is_none());
    }

    #[test]
    fn caller_languages_win_over_the_country_language_and_invalid_tags_drop() {
        let em = location_emulation(&loc(Some("JP"), &["en-US", "x", "ja\r\nX: y", "fr"])).unwrap();
        assert_eq!(em.locale.as_deref(), Some("en-US"));
        assert_eq!(em.accept_language.as_deref(), Some("en-US,fr"));
        assert_eq!(em.timezone.as_deref(), Some("Asia/Tokyo"));
    }

    #[test]
    fn an_unknown_country_leaves_only_the_languages() {
        let em = location_emulation(&loc(Some("ZZ"), &["pt-BR"])).unwrap();
        assert_eq!(em.timezone, None);
        assert_eq!(em.locale.as_deref(), Some("pt-BR"));
        assert_eq!(em.accept_language.as_deref(), Some("pt-BR"));
        assert_eq!(location_emulation(&loc(Some("ZZ"), &[])), None);
        assert_eq!(location_emulation(&loc(None, &[])), None);
    }

    #[test]
    fn mobile_and_location_merge_into_one_emulation() {
        let options: ScrapeOptions = serde_json::from_value(serde_json::json!({
            "mobile": true,
            "location": {"country": "FR", "languages": ["fr-FR", "en"]}
        }))
        .unwrap();
        let em = emulation_for(&options).unwrap();
        assert!(em.mobile);
        assert_eq!(em.viewport, Some((390, 844)));
        assert_eq!(em.user_agent.as_deref(), Some(MOBILE_USER_AGENT));
        assert_eq!(em.accept_language.as_deref(), Some("fr-FR,en"));
        assert_eq!(em.timezone.as_deref(), Some("Europe/Paris"));
        let plain: ScrapeOptions = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(emulation_for(&plain), None);
    }
}
