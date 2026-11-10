//! The `options` part of `POST /parse` (`ParseOptions` of the compat v2 OpenAPI) as a typed
//! request: every violation is collected with its JSON pointer so one `400` lists them all, and
//! options that are valid but meaningless for an upload are recorded so the route can answer a
//! `warnings[]` entry instead of ignoring them silently.

use crate::errors::{Detail, HttpError};
use crate::resources::Warning;
use crawlx_extract::parse::redact::{RedactEntity, RedactMode, RedactOptions, ReplaceStyle};
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::time::Duration;

/// Longest `question` / `highlights.query` / `json.prompt` text (the compat API limit).
const MAX_PROMPT_CHARS: usize = 10_000;
/// Default `timeout`, milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// Largest `timeout`, milliseconds.
const MAX_TIMEOUT_MS: u64 = 300_000;
/// Most entries of `formats`, `parsers`, `includeTags` and `excludeTags`.
const MAX_ITEMS: usize = 64;
/// Largest CSS selector.
const MAX_SELECTOR_CHARS: usize = 512;
/// Most `parsers[].maxPages`.
const MAX_PDF_PAGES: u64 = 10_000;

/// Every key of `ParseOptions`.
const KNOWN_KEYS: &[&str] = &[
    "formats",
    "onlyMainContent",
    "includeTags",
    "excludeTags",
    "headers",
    "timeout",
    "parsers",
    "skipTlsVerification",
    "removeBase64Images",
    "blockAds",
    "checkPromptInjection",
    "redactPII",
    "proxy",
    "origin",
    "integration",
    "auditMetadata",
    "zeroDataRetention",
];

/// Formats `/parse` does not produce although the compat API knows them.
const UNSUPPORTED_FORMATS: &[&str] = &[
    "rawBase64",
    "screenshot",
    "attributes",
    "changeTracking",
    "branding",
    "product",
    "menu",
    "audio",
    "video",
    "query",
];

/// `parsers[].mode` of the PDF parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(super) enum PdfMode {
    /// Text layer, OCR where a page needs it (no OCR engine here: reported).
    #[default]
    Auto,
    /// Text layer only; fails when no page has one.
    Fast,
    /// OCR on every page (no OCR engine here: reported, the text layer is used).
    Ocr,
}

/// `parsers[]` entry of `type: pdf`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub(super) struct PdfSpec {
    pub mode: PdfMode,
    pub max_pages: Option<u32>,
    pub pages: bool,
    pub blocks: bool,
    pub page_markers: bool,
}

/// `{type: json}` format.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct JsonSpec {
    pub schema: Option<Value>,
    pub prompt: Option<String>,
}

/// The requested output formats.
#[derive(Clone, PartialEq, Debug, Default)]
pub(super) struct Formats {
    pub markdown: bool,
    pub html: bool,
    pub raw_html: bool,
    pub text: bool,
    pub links: bool,
    pub images: bool,
    pub summary: bool,
    pub json: Option<JsonSpec>,
    pub question: Option<String>,
    pub highlights: Option<String>,
}

impl Formats {
    /// Whether any format needs the LLM.
    pub(super) fn needs_llm(&self) -> bool {
        self.summary || self.json.is_some() || self.question.is_some() || self.highlights.is_some()
    }

    /// Number of formats that bill the LLM surcharge (`json`, `question`, `highlights`).
    pub(super) fn surcharged(&self) -> u64 {
        u64::from(self.json.is_some())
            + u64::from(self.question.is_some())
            + u64::from(self.highlights.is_some())
    }
}

/// A parsed `options` object.
#[derive(Clone, Debug)]
pub(super) struct ParseRequest {
    pub formats: Formats,
    pub only_main_content: bool,
    pub include_tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub timeout: Duration,
    pub pdf: PdfSpec,
    /// `parsers: []`: skip parsing and return the PDF as base64.
    pub parsers_disabled: bool,
    pub remove_base64_images: bool,
    pub check_prompt_injection: bool,
    pub redact: Option<RedactOptions>,
    pub zero_data_retention: bool,
    /// Warnings that follow from the options alone (not applicable to uploads, unknown keys).
    pub warnings: Vec<Warning>,
    /// The options that were present, for the format-dependent warnings.
    present: BTreeSet<&'static str>,
}

impl ParseRequest {
    /// Whether the request set `key` explicitly.
    pub(super) fn has(&self, key: &str) -> bool {
        self.present.contains(key)
    }
}

struct Cx {
    details: Vec<Detail>,
}

impl Cx {
    fn bad(&mut self, path: impl Into<String>, code: &str, message: impl Into<String>) {
        self.details.push(Detail::new(path, code, message));
    }
}

fn bool_of(cx: &mut Cx, obj: &Map<String, Value>, key: &str) -> Option<bool> {
    let v = obj.get(key).filter(|v| !v.is_null())?;
    v.as_bool().or_else(|| {
        cx.bad(format!("/{key}"), "invalid_type", "expected a boolean");
        None
    })
}

fn string_list(cx: &mut Cx, obj: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    let v = obj.get(key).filter(|v| !v.is_null())?;
    let Some(items) = v.as_array() else {
        cx.bad(format!("/{key}"), "invalid_type", "expected an array of strings");
        return None;
    };
    if items.len() > MAX_ITEMS {
        cx.bad(
            format!("/{key}"),
            "too_big",
            format!("at most {MAX_ITEMS} entries"),
        );
        return None;
    }
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        match item.as_str() {
            Some(s) if !s.trim().is_empty() && s.chars().count() <= MAX_SELECTOR_CHARS => {
                out.push(s.to_owned())
            }
            _ => {
                cx.bad(
                    format!("/{key}/{i}"),
                    "invalid_type",
                    format!("expected a non-empty string of at most {MAX_SELECTOR_CHARS} characters"),
                );
                return None;
            }
        }
    }
    Some(out)
}

fn text_field(cx: &mut Cx, at: &str, m: &Map<String, Value>, key: &str) -> Option<String> {
    let v = m.get(key).filter(|v| !v.is_null())?;
    match v.as_str() {
        Some(s) if s.trim().is_empty() => {
            cx.bad(
                format!("{at}/{key}"),
                "required",
                format!("{key} must not be empty"),
            );
            None
        }
        Some(s) if s.chars().count() > MAX_PROMPT_CHARS => {
            cx.bad(
                format!("{at}/{key}"),
                "too_big",
                format!("{key} is at most {MAX_PROMPT_CHARS} characters"),
            );
            None
        }
        Some(s) => Some(s.to_owned()),
        None => {
            cx.bad(format!("{at}/{key}"), "invalid_type", "expected a string");
            None
        }
    }
}

fn parse_formats(cx: &mut Cx, v: &Value, check_injection: &mut bool) -> Formats {
    let mut f = Formats::default();
    let Some(items) = v.as_array() else {
        cx.bad("/formats", "invalid_type", "expected an array of formats");
        return f;
    };
    if items.len() > MAX_ITEMS {
        cx.bad("/formats", "too_big", format!("at most {MAX_ITEMS} formats"));
        return f;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        let at = format!("/formats/{i}");
        let (kind, obj): (&str, Option<&Map<String, Value>>) = match item {
            Value::String(s) => (s.as_str(), None),
            Value::Object(m) => match m.get("type").and_then(Value::as_str) {
                Some(t) => (t, Some(m)),
                None => {
                    cx.bad(format!("{at}/type"), "required", "a format object needs a `type`");
                    continue;
                }
            },
            _ => {
                cx.bad(&at, "invalid_type", "expected a format name or a format object");
                continue;
            }
        };
        if !seen.insert(kind.to_owned()) {
            cx.bad(
                &at,
                "duplicate_format",
                format!("the `{kind}` format is listed twice"),
            );
            continue;
        }
        let empty = Map::new();
        let m = obj.unwrap_or(&empty);
        match kind {
            "markdown" => f.markdown = true,
            "html" => f.html = true,
            "rawHtml" => f.raw_html = true,
            "text" => f.text = true,
            "links" => f.links = true,
            "images" => f.images = true,
            "summary" => f.summary = true,
            "json" => {
                let schema = match m.get("schema").filter(|v| !v.is_null()) {
                    Some(s) if s.is_object() => Some(s.clone()),
                    Some(_) => {
                        cx.bad(format!("{at}/schema"), "invalid_type", "expected a JSON Schema object");
                        None
                    }
                    None => None,
                };
                let prompt = text_field(cx, &at, m, "prompt");
                if schema.is_none() && prompt.is_none() && !cx.details.iter().any(|d| d.path.starts_with(&at)) {
                    cx.bad(
                        &at,
                        "required",
                        "the `json` format needs a `schema` or a `prompt`",
                    );
                }
                if let Some(c) = m.get("checkPromptInjection").filter(|v| !v.is_null()) {
                    match c.as_bool() {
                        Some(true) => *check_injection = true,
                        Some(false) => {}
                        None => cx.bad(format!("{at}/checkPromptInjection"), "invalid_type", "expected a boolean"),
                    }
                }
                f.json = Some(JsonSpec { schema, prompt });
            }
            "question" => match text_field(cx, &at, m, "question") {
                Some(q) => f.question = Some(q),
                None => {
                    if !m.contains_key("question") {
                        cx.bad(
                            format!("{at}/question"),
                            "required",
                            "the `question` format needs a `question`",
                        );
                    }
                }
            },
            "highlights" => match text_field(cx, &at, m, "query") {
                Some(q) => f.highlights = Some(q),
                None => {
                    if !m.contains_key("query") {
                        cx.bad(
                            format!("{at}/query"),
                            "required",
                            "the `highlights` format needs a `query`",
                        );
                    }
                }
            },
            other if UNSUPPORTED_FORMATS.contains(&other) => cx.bad(
                &at,
                "unsupported_format",
                format!("the `{other}` format is not available on /parse uploads"),
            ),
            other => cx.bad(
                format!("{at}/type"),
                "unknown_enum",
                format!(
                    "unknown format `{other}`; use markdown, html, rawHtml, links, images, text, summary, json, question or highlights"
                ),
            ),
        }
    }
    f
}

fn parse_parsers(cx: &mut Cx, v: &Value) -> (PdfSpec, bool) {
    let mut pdf = PdfSpec::default();
    let Some(items) = v.as_array() else {
        cx.bad("/parsers", "invalid_type", "expected an array of parsers");
        return (pdf, false);
    };
    if items.is_empty() {
        return (pdf, true);
    }
    if items.len() > MAX_ITEMS {
        cx.bad("/parsers", "too_big", format!("at most {MAX_ITEMS} parsers"));
        return (pdf, false);
    }
    for (i, item) in items.iter().enumerate() {
        let at = format!("/parsers/{i}");
        let Some(m) = item.as_object() else {
            cx.bad(&at, "invalid_type", "expected a parser object");
            continue;
        };
        for k in m.keys() {
            if !matches!(
                k.as_str(),
                "type" | "mode" | "maxPages" | "pages" | "blocks" | "pageMarkers"
            ) {
                cx.bad(format!("{at}/{k}"), "unrecognized_key", "unknown parser option");
            }
        }
        match m.get("type").and_then(Value::as_str) {
            Some("pdf") => {}
            Some(other) => {
                cx.bad(
                    format!("{at}/type"),
                    "unknown_enum",
                    format!("unknown parser `{other}`; the only parser is `pdf`"),
                );
                continue;
            }
            None => {
                cx.bad(format!("{at}/type"), "required", "a parser needs a `type`");
                continue;
            }
        }
        match m.get("mode").filter(|v| !v.is_null()) {
            None => {}
            Some(Value::String(s)) => match s.as_str() {
                "auto" => pdf.mode = PdfMode::Auto,
                "fast" => pdf.mode = PdfMode::Fast,
                "ocr" => pdf.mode = PdfMode::Ocr,
                _ => cx.bad(format!("{at}/mode"), "unknown_enum", "expected fast, auto or ocr"),
            },
            Some(_) => cx.bad(format!("{at}/mode"), "invalid_type", "expected a string"),
        }
        if let Some(n) = m.get("maxPages").filter(|v| !v.is_null()) {
            match n.as_u64() {
                Some(n) if (1..=MAX_PDF_PAGES).contains(&n) => pdf.max_pages = u32::try_from(n).ok(),
                Some(_) => cx.bad(
                    format!("{at}/maxPages"),
                    "out_of_range",
                    format!("expected 1 to {MAX_PDF_PAGES}"),
                ),
                None => cx.bad(format!("{at}/maxPages"), "invalid_type", "expected an integer"),
            }
        }
        for (key, slot) in [
            ("pages", &mut pdf.pages),
            ("blocks", &mut pdf.blocks),
            ("pageMarkers", &mut pdf.page_markers),
        ] {
            if let Some(b) = m.get(key).filter(|v| !v.is_null()) {
                match b.as_bool() {
                    Some(b) => *slot = b,
                    None => cx.bad(format!("{at}/{key}"), "invalid_type", "expected a boolean"),
                }
            }
        }
    }
    (pdf, false)
}

fn parse_redact(cx: &mut Cx, v: &Value) -> Option<RedactOptions> {
    match v {
        Value::Null | Value::Bool(false) => None,
        Value::Bool(true) => Some(RedactOptions::default()),
        Value::Object(m) => {
            let mut o = RedactOptions::default();
            for k in m.keys() {
                if !matches!(k.as_str(), "mode" | "entities" | "replaceStyle") {
                    cx.bad(
                        format!("/redactPII/{k}"),
                        "unrecognized_key",
                        "unknown redactPII option",
                    );
                }
            }
            if let Some(mode) = m.get("mode").filter(|v| !v.is_null()) {
                match mode.as_str() {
                    Some("accurate") => o.mode = RedactMode::Accurate,
                    Some("aggressive") => o.mode = RedactMode::Aggressive,
                    Some("fast") => o.mode = RedactMode::Fast,
                    _ => cx.bad(
                        "/redactPII/mode",
                        "unknown_enum",
                        "expected accurate, aggressive or fast",
                    ),
                }
            }
            if let Some(style) = m.get("replaceStyle").filter(|v| !v.is_null()) {
                match style.as_str() {
                    Some("tag") => o.replace_style = ReplaceStyle::Tag,
                    Some("mask") => o.replace_style = ReplaceStyle::Mask,
                    Some("remove") => o.replace_style = ReplaceStyle::Remove,
                    _ => cx.bad(
                        "/redactPII/replaceStyle",
                        "unknown_enum",
                        "expected tag, mask or remove",
                    ),
                }
            }
            if let Some(entities) = m.get("entities").filter(|v| !v.is_null()) {
                match entities.as_array() {
                    Some(list) => {
                        for (i, e) in list.iter().enumerate() {
                            match e.as_str().and_then(RedactEntity::from_name) {
                                Some(e) => {
                                    o.entities.insert(e);
                                }
                                None => cx.bad(
                                    format!("/redactPII/entities/{i}"),
                                    "unknown_enum",
                                    "expected PERSON, EMAIL, PHONE, LOCATION, FINANCIAL or SECRET",
                                ),
                            }
                        }
                    }
                    None => cx.bad("/redactPII/entities", "invalid_type", "expected an array"),
                }
            }
            Some(o)
        }
        _ => {
            cx.bad(
                "/redactPII",
                "invalid_type",
                "expected a boolean or an options object",
            );
            None
        }
    }
}

/// Read the `options` JSON of an upload; `None` reads as `{}`.
///
/// # Errors
/// `400 BAD_REQUEST` listing every violation.
pub(super) fn parse_options(raw: Option<&Value>) -> Result<ParseRequest, HttpError> {
    let empty = Map::new();
    let obj = match raw {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => {
            return Err(HttpError::bad_request(vec![Detail::new(
                "/options",
                "invalid_type",
                "options must be a JSON object",
            )]));
        }
    };
    let mut cx = Cx { details: Vec::new() };
    let mut present: BTreeSet<&'static str> = BTreeSet::new();
    for k in KNOWN_KEYS {
        if obj.get(*k).is_some_and(|v| !v.is_null()) {
            present.insert(k);
        }
    }
    let mut warnings = Vec::new();
    let mut unknown: Vec<&String> = obj.keys().filter(|k| !KNOWN_KEYS.contains(&k.as_str())).collect();
    unknown.sort();
    for k in unknown {
        warnings.push(Warning::new(
            "unsupported_option",
            &format!("/{k}"),
            "this option is not part of /parse and was ignored",
        ));
    }

    let mut check_injection = bool_of(&mut cx, obj, "checkPromptInjection").unwrap_or(false);
    let formats = match obj.get("formats").filter(|v| !v.is_null()) {
        Some(v) => parse_formats(&mut cx, v, &mut check_injection),
        None => Formats {
            markdown: true,
            ..Formats::default()
        },
    };
    let only_main_content = bool_of(&mut cx, obj, "onlyMainContent").unwrap_or(true);
    let include_tags = string_list(&mut cx, obj, "includeTags").unwrap_or_default();
    let exclude_tags = string_list(&mut cx, obj, "excludeTags").unwrap_or_default();
    let timeout_ms = match obj.get("timeout").filter(|v| !v.is_null()) {
        None => DEFAULT_TIMEOUT_MS,
        Some(v) => match v.as_u64() {
            Some(n) if (1..=MAX_TIMEOUT_MS).contains(&n) => n,
            Some(_) => {
                cx.bad(
                    "/timeout",
                    "out_of_range",
                    format!("expected 1 to {MAX_TIMEOUT_MS} milliseconds"),
                );
                DEFAULT_TIMEOUT_MS
            }
            None => {
                cx.bad(
                    "/timeout",
                    "invalid_type",
                    "expected an integer number of milliseconds",
                );
                DEFAULT_TIMEOUT_MS
            }
        },
    };
    let (pdf, parsers_disabled) = match obj.get("parsers").filter(|v| !v.is_null()) {
        Some(v) => parse_parsers(&mut cx, v),
        None => (PdfSpec::default(), false),
    };
    let remove_base64_images = bool_of(&mut cx, obj, "removeBase64Images").unwrap_or(true);
    let redact = match obj.get("redactPII") {
        Some(v) => parse_redact(&mut cx, v),
        None => None,
    };
    let zero_data_retention = bool_of(&mut cx, obj, "zeroDataRetention").unwrap_or(false);
    for key in ["skipTlsVerification", "blockAds"] {
        bool_of(&mut cx, obj, key);
    }
    if let Some(h) = obj.get("headers").filter(|v| !v.is_null()) {
        if !h.is_object() {
            cx.bad("/headers", "invalid_type", "expected an object");
        }
    }
    if let Some(p) = obj.get("proxy").filter(|v| !v.is_null()) {
        if !matches!(p.as_str(), Some("basic" | "auto")) {
            cx.bad(
                "/proxy",
                "unknown_enum",
                "/parse supports only `basic` and `auto`",
            );
        }
    }
    for key in ["origin", "integration"] {
        if let Some(v) = obj.get(key).filter(|v| !v.is_null()) {
            if !v.is_string() {
                cx.bad(format!("/{key}"), "invalid_type", "expected a string");
            }
        }
    }
    if let Some(a) = obj.get("auditMetadata").filter(|v| !v.is_null()) {
        match a.as_object() {
            Some(m) => {
                if !m.get("username").is_some_and(Value::is_string) {
                    cx.bad(
                        "/auditMetadata/username",
                        "required",
                        "auditMetadata needs a `username` string",
                    );
                }
            }
            None => cx.bad("/auditMetadata", "invalid_type", "expected an object"),
        }
    }
    if !cx.details.is_empty() {
        return Err(HttpError::bad_request(cx.details));
    }

    // valid for the compat API's `/parse`, but nothing here can act on them
    for (key, why) in [
        ("headers", "an upload makes no network requests"),
        ("skipTlsVerification", "an upload makes no network requests"),
        ("blockAds", "an upload is not rendered in a browser"),
        ("proxy", "an upload makes no network requests"),
    ] {
        if present.contains(key) {
            warnings.push(Warning::new(
                "option_not_applicable",
                &format!("/{key}"),
                format!("ignored: {why}"),
            ));
        }
    }
    Ok(ParseRequest {
        formats,
        only_main_content,
        include_tags,
        exclude_tags,
        timeout: Duration::from_millis(timeout_ms),
        pdf,
        parsers_disabled,
        remove_base64_images,
        check_prompt_injection: check_injection,
        redact,
        zero_data_retention,
        warnings,
        present,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_and_string_formats() {
        let r = parse_options(None).unwrap();
        assert!(r.formats.markdown && !r.formats.html);
        assert!(r.only_main_content && r.remove_base64_images);
        assert_eq!(r.timeout, Duration::from_millis(30_000));
        let r = parse_options(Some(&json!({"formats": ["markdown", {"type": "links"}, "html"]}))).unwrap();
        assert!(r.formats.markdown && r.formats.links && r.formats.html);
    }

    #[test]
    fn every_violation_is_listed_with_its_pointer() {
        let e = parse_options(Some(&json!({
            "formats": ["markdown", "markdown", "screenshot", {"type": "json"}, {"type": "question"}, "nope"],
            "timeout": 0,
            "parsers": [{"type": "pdf", "mode": "turbo", "maxPages": 0}, {"type": "docx"}],
            "redactPII": {"entities": ["EMAIL", "SSN"]},
            "proxy": "stealth",
        })))
        .unwrap_err();
        let paths: Vec<&str> = e.details.iter().map(|d| d.path.as_str()).collect();
        for want in [
            "/formats/1",
            "/formats/2",
            "/formats/3",
            "/formats/4/question",
            "/formats/5/type",
            "/timeout",
            "/parsers/0/mode",
            "/parsers/0/maxPages",
            "/parsers/1/type",
            "/redactPII/entities/1",
            "/proxy",
        ] {
            assert!(paths.contains(&want), "{want} missing in {paths:?}");
        }
    }

    #[test]
    fn not_applicable_and_unknown_options_warn() {
        let r = parse_options(Some(&json!({
            "headers": {"x": "y"}, "skipTlsVerification": false, "blockAds": true, "proxy": "basic", "mystery": 1,
            "origin": "api",
        })))
        .unwrap();
        let w: Vec<(&str, &str)> = r
            .warnings
            .iter()
            .map(|w| (w.code.as_str(), w.path.as_str()))
            .collect();
        assert_eq!(
            w,
            vec![
                ("unsupported_option", "/mystery"),
                ("option_not_applicable", "/headers"),
                ("option_not_applicable", "/skipTlsVerification"),
                ("option_not_applicable", "/blockAds"),
                ("option_not_applicable", "/proxy"),
            ]
        );
    }

    #[test]
    fn json_format_inline_injection_flag_and_parsers() {
        let r = parse_options(Some(&json!({
            "formats": [{"type": "json", "prompt": "p", "checkPromptInjection": true}],
            "parsers": [{"type": "pdf", "mode": "fast", "maxPages": 3, "pages": true, "blocks": true, "pageMarkers": true}],
            "redactPII": {"mode": "aggressive", "entities": ["EMAIL"], "replaceStyle": "mask"},
        })))
        .unwrap();
        assert!(r.check_prompt_injection && r.formats.json.is_some());
        assert_eq!(
            r.pdf,
            PdfSpec {
                mode: PdfMode::Fast,
                max_pages: Some(3),
                pages: true,
                blocks: true,
                page_markers: true
            }
        );
        let red = r.redact.unwrap();
        assert_eq!(red.mode, RedactMode::Aggressive);
        assert_eq!(red.replace_style, ReplaceStyle::Mask);
        assert!(
            parse_options(Some(&json!({"parsers": []})))
                .unwrap()
                .parsers_disabled
        );
    }
}
