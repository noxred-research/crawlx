//! The compat API scrape options (camelCase JSON) -> [`ScrapeOptions`] plus the run fields they drive.
//!
//! Every violation is collected (never just the first) as a [`Detail`] with a JSON Pointer
//! `path`; callers answer them with `400 BAD_REQUEST` ([`crate::errors::HttpError::bad_request`]).
//! Options crawlx does not implement but the compat API documents are accepted and reported in the
//! additive `warnings[]` instead of failing the request.

use crate::errors::Detail;
use crate::resources::Warning;
use crawlx_core::config::{BrowserProfile, CreateCrawl, OutputFormat, RetentionMode, SafetyProfile};
use crawlx_core::page_op::SelectorState;
use crawlx_core::scrape::{
    AttributeSelector, ChangeMode, FormatSpec, JobKind, Location, ParserSpec, PdfMode, PiiEntity, PiiMode,
    PiiReplaceStyle, QueryMode, RedactPii, ScrapeAction, ScrapeJob, ScrapeOptions, ScreenshotViewport,
    ScrollDirection,
};
use serde::Deserialize;
use serde_json::{Map, Value};

/// `lockdown` extends the default `maxAge` to two years so existing stored pages stay eligible.
const LOCKDOWN_MAX_AGE_MS: u64 = 63_072_000_000;

/// Longest `question` / `highlights.query` text (the compat API limit).
const MAX_PROMPT_CHARS: usize = 10_000;

/// Scrape option keys (compat v2 plus the v1 `extract` / `jsonOptions` aliases and the
/// request-level `zeroDataRetention`).
const SCRAPE_KEYS: [&str; 28] = [
    "formats",
    "onlyMainContent",
    "contentPolicy",
    "cache",
    "includeTags",
    "excludeTags",
    "maxAge",
    "minAge",
    "headers",
    "waitFor",
    "mobile",
    "skipTlsVerification",
    "timeout",
    "parsers",
    "actions",
    "location",
    "removeBase64Images",
    "blockAds",
    "proxy",
    "storeInCache",
    "lockdown",
    "zeroDataRetention",
    "extract",
    "jsonOptions",
    "onlyCleanContent",
    "checkPromptInjection",
    "redactPII",
    "profile",
];

/// Formats the compat API documents that crawlx does not produce.
const UNSUPPORTED_FORMATS: [&str; 2] = ["product", "menu"];

/// A parsed compat API scrape request: the typed options plus everything that is not part of
/// [`ScrapeOptions`] itself.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct ParsedScrape {
    /// The typed options the worker's scrape engine executes.
    pub options: ScrapeOptions,
    /// Request headers (`headers`); applied to the run with [`Fetch::set_header`] so both planes
    /// send them and the stored config redacts them. Never stored in `options`.
    ///
    /// [`Fetch::set_header`]: crawlx_core::config::Fetch::set_header
    pub headers: Vec<(String, String)>,
    /// `zeroDataRetention` (also implied by `lockdown`).
    pub zero_data_retention: bool,
    /// Additive `warnings[]` for options crawlx accepted but does not implement.
    pub warnings: Vec<Warning>,
}

impl ParsedScrape {
    /// Does any requested format need the document LLM?
    #[must_use]
    pub fn needs_llm(&self) -> bool {
        self.options.formats.iter().any(FormatSpec::needs_llm)
    }

    /// Fill `crawl` from the options: `scrape` (a job of `kind`; the urls and webhook values of an
    /// existing job are kept), `output.{formats,onlyMainContent,includeTags,excludeTags,waitForMs}`,
    /// `fetch.{timeoutMs,skipTlsVerification}` plus one `fetch.set_header` per header,
    /// `retention.mode = zdr` for `zeroDataRetention`, and `safety.profile = test_environment`
    /// when `actions` holds a `click`, `write` or `press`.
    ///
    /// # Safety profile of actions
    /// The caller wrote the actions, but under the default `read_only` profile the safety kernel
    /// refuses plain button clicks, typing and key presses (`Unclassified` actions). A scrape run
    /// therefore raises the profile to `test_environment`, which admission accepts without an
    /// authorization record. `safety.destructiveActions` and `safety.externalCommunication` stay
    /// `deny`, so a click on a delete-like control, a purchase or a message is still refused (the
    /// page fails with `SCRAPE_ACTION_ERROR`, reason `action_failed`, `denied`). `scroll`, `wait`,
    /// `screenshot`, `scrape`, `executeJavascript` and `pdf` never need the raise. Every request
    /// that raises the profile carries the `actions_profile_raised` warning
    /// ([`parse_scrape_options`]).
    ///
    /// # Errors
    /// One `400` detail per header the fetch controls reject (a `Cookie` value without `name=value`).
    pub fn apply(&self, crawl: &mut CreateCrawl, kind: JobKind) -> Result<(), Vec<Detail>> {
        let o = &self.options;
        let mut job = crawl
            .scrape
            .take()
            .unwrap_or_else(|| ScrapeJob::new(kind, o.clone()));
        job.kind = kind;
        job.options = o.clone();
        crawl.scrape = Some(job);
        crawl.cache.clone_from(&o.cache);

        crawl.output.formats = output_formats(o);
        crawl.output.only_main_content = o.only_main_content;
        crawl.extract.content.clone_from(&o.content_policy);
        crawl.output.include_tags = o.include_tags.clone();
        crawl.output.exclude_tags = o.exclude_tags.clone();
        crawl.output.wait_for_ms = o.wait_for_ms;

        crawl.fetch.timeout_ms = o.timeout_ms;
        crawl.dynamic.browser_profile.clone_from(&o.profile);
        crawl.fetch.skip_tls_verification = o.skip_tls_verification;
        let mut details = Vec::new();
        for (name, value) in &self.headers {
            if let Err(e) = crawl.fetch.set_header(name, value) {
                details.push(Detail::new(
                    format!("/headers/{}", pointer_escape(name)),
                    "invalid_header",
                    e.to_string(),
                ));
            }
        }
        if self.zero_data_retention {
            crawl.retention.mode = RetentionMode::Zdr;
        }
        if interactive(o) && crawl.safety.profile == SafetyProfile::ReadOnly {
            crawl.safety.profile = SafetyProfile::TestEnvironment;
        }
        if details.is_empty() {
            Ok(())
        } else {
            Err(details)
        }
    }
}

/// Do the actions include one the safety kernel only admits above `read_only`?
fn interactive(o: &ScrapeOptions) -> bool {
    o.actions.iter().any(|a| {
        matches!(
            a,
            ScrapeAction::Click { .. } | ScrapeAction::Write { .. } | ScrapeAction::Press { .. }
        )
    })
}
fn output_formats(o: &ScrapeOptions) -> Vec<OutputFormat> {
    let mut out = vec![OutputFormat::Metadata];
    for f in &o.formats {
        let mapped = match f {
            FormatSpec::Markdown => OutputFormat::Markdown,
            FormatSpec::Html => OutputFormat::Html,
            FormatSpec::RawHtml => OutputFormat::RawHtml,
            FormatSpec::Links => OutputFormat::Links,
            FormatSpec::Screenshot { .. } => OutputFormat::Screenshot,
            _ => continue,
        };
        if !out.contains(&mapped) {
            out.push(mapped);
        }
    }
    out
}

/// RFC 6901 escape of one reference token.
fn pointer_escape(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// Violations and warnings collected while parsing one object.
struct Cx {
    path: String,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
    /// A `json` format object carried the deprecated `checkPromptInjection` (lifted to the
    /// top-level option, as the compat API does).
    lifted_injection_check: bool,
}

impl Cx {
    fn at(&self, sub: &str) -> String {
        format!("{}/{}", self.path, sub)
    }

    fn bad(&mut self, at: String, code: &str, message: impl Into<String>) {
        self.details.push(Detail::new(at, code, message));
    }

    fn unsupported(&mut self, at: &str, what: &str, why: &str) {
        self.warnings.push(Warning::new(
            "unsupported_option",
            at,
            format!("{what} is not supported by crawlx and was ignored: {why}"),
        ));
    }

    /// crawlx has no OCR engine: the request is served from the text layer and says so.
    fn ocr_unavailable(&mut self, at: &str, what: &str) {
        self.warnings.push(Warning::new(
            "ocr_unavailable",
            at,
            format!("{what} needs OCR, which crawlx does not have: text layers are extracted and images yield no text"),
        ));
    }

    fn boolean(&mut self, obj: &Map<String, Value>, key: &str) -> Option<bool> {
        match obj.get(key)? {
            Value::Bool(b) => Some(*b),
            Value::Null => None,
            _ => {
                let at = self.at(key);
                self.bad(at, "invalid_type", "expected a boolean");
                None
            }
        }
    }

    fn uint(&mut self, obj: &Map<String, Value>, key: &str, min: u64, max: u64) -> Option<u64> {
        match obj.get(key)? {
            Value::Null => None,
            v => match v.as_u64() {
                Some(n) if (min..=max).contains(&n) => Some(n),
                Some(_) => {
                    let at = self.at(key);
                    self.bad(at, "out_of_range", format!("must be between {min} and {max}"));
                    None
                }
                None => {
                    let at = self.at(key);
                    self.bad(at, "invalid_type", "expected a non-negative integer");
                    None
                }
            },
        }
    }

    fn strings(&mut self, obj: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
        match obj.get(key)? {
            Value::Null => None,
            Value::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for (i, x) in a.iter().enumerate() {
                    match x.as_str() {
                        Some(s) => out.push(s.to_owned()),
                        None => {
                            let at = format!("{}/{key}/{i}", self.path);
                            self.bad(at, "invalid_type", "expected a string");
                        }
                    }
                }
                Some(out)
            }
            _ => {
                let at = self.at(key);
                self.bad(at, "invalid_type", "expected an array of strings");
                None
            }
        }
    }
}

/// Parse the scrape options of `obj` (every key of a scrape request, or a crawl's
/// `scrapeOptions`); `path` is the JSON Pointer of `obj` for the details (`""` for a request
/// body, `/scrapeOptions` for a crawl). Keys that are not scrape options produce an
/// `unsupported_option` warning.
///
/// # Errors
/// Every violation as a [`Detail`].
pub fn parse_scrape_options(obj: &Map<String, Value>, path: &str) -> Result<ParsedScrape, Vec<Detail>> {
    parse_scrape_options_in(obj, path, &[])
}

/// As [`parse_scrape_options`] for a request object that carries more than scrape options:
/// `envelope_keys` (`url`, `urls`, `webhook`, `limit`, ...) are skipped without a warning.
///
/// # Errors
/// Every violation as a [`Detail`].
pub fn parse_scrape_options_in(
    obj: &Map<String, Value>,
    path: &str,
    envelope_keys: &[&str],
) -> Result<ParsedScrape, Vec<Detail>> {
    let mut cx = Cx {
        path: path.to_owned(),
        details: Vec::new(),
        warnings: Vec::new(),
        lifted_injection_check: false,
    };
    for k in obj.keys() {
        if !SCRAPE_KEYS.contains(&k.as_str()) && !envelope_keys.contains(&k.as_str()) {
            let at = cx.at(k);
            cx.unsupported(&at, &format!("option `{k}`"), "unknown to this facade");
        }
    }
    let mut o = ScrapeOptions::default();
    let mut zdr = false;

    if let Some(v) = obj.get("formats") {
        parse_formats(&mut cx, v, &mut o);
    }
    apply_legacy_json(&mut cx, obj, &mut o);
    if let Some(b) = cx.boolean(obj, "onlyMainContent") {
        o.only_main_content = b;
    }
    if let Some(value) = obj.get("contentPolicy").filter(|value| !value.is_null()) {
        match serde_json::from_value::<crawlx_core::extraction::ExtractionPolicyV1>(value.clone()) {
            Ok(policy) => match crawlx_extract::validate_content_policy(&policy) {
                Ok(()) => o.content_policy = Some(policy),
                Err(error) => {
                    let at = cx.at("contentPolicy");
                    cx.bad(at, "invalid_content_policy", error.to_string());
                }
            },
            Err(_) => {
                let at = cx.at("contentPolicy");
                cx.bad(
                    at,
                    "invalid_content_policy",
                    "invalid native content policy or unknown field",
                );
            }
        }
    }
    if let Some(value) = obj.get("cache").filter(|value| !value.is_null()) {
        match serde_json::from_value::<crawlx_core::cache::CachePolicyV1>(value.clone()) {
            Ok(policy) => match policy.validate() {
                Ok(()) => o.cache = Some(policy),
                Err(error) => {
                    let at = cx.at("cache");
                    cx.bad(at, "invalid_cache_policy", error.to_string());
                }
            },
            Err(_) => {
                let at = cx.at("cache");
                cx.bad(
                    at,
                    "invalid_cache_policy",
                    "invalid native cache policy or unknown field",
                );
            }
        }
    }
    if let Some(l) = cx.strings(obj, "includeTags") {
        o.include_tags = l;
    }
    if let Some(l) = cx.strings(obj, "excludeTags") {
        o.exclude_tags = l;
    }
    let max_age = cx.uint(obj, "maxAge", 0, u64::MAX);
    if let Some(n) = max_age {
        o.max_age_ms = n;
    }
    if let Some(n) = cx.uint(obj, "minAge", 0, u64::MAX) {
        o.min_age_ms = Some(n);
    }
    let headers = parse_headers(&mut cx, obj);
    if let Some(n) = cx.uint(obj, "waitFor", 0, 60_000) {
        o.wait_for_ms = u32::try_from(n).unwrap_or(u32::MAX);
    }
    if let Some(b) = cx.boolean(obj, "mobile") {
        o.mobile = b;
    }
    // The compat API's default is true; the core model's default (verify) applies to native runs
    o.skip_tls_verification = cx.boolean(obj, "skipTlsVerification").unwrap_or(true);
    if let Some(n) = cx.uint(obj, "timeout", 1_000, 300_000) {
        o.timeout_ms = u32::try_from(n).unwrap_or(u32::MAX);
    }
    if let Some(v) = obj.get("parsers") {
        parse_parsers(&mut cx, v, &mut o);
    }
    if let Some(v) = obj.get("actions") {
        parse_actions(&mut cx, v, &mut o);
    }
    if let Some(v) = obj.get("location") {
        o.location = parse_location(&mut cx, v);
    }
    if let Some(b) = cx.boolean(obj, "removeBase64Images") {
        o.remove_base64_images = b;
    }
    if let Some(b) = cx.boolean(obj, "blockAds") {
        o.block_ads = b;
    }
    parse_proxy(&mut cx, obj, &mut o);
    parse_profile(&mut cx, obj, &mut o);
    if let Some(b) = cx.boolean(obj, "storeInCache") {
        o.store_in_cache = b;
    }
    if let Some(b) = cx.boolean(obj, "lockdown") {
        o.lockdown = b;
        if b {
            // The compat API: lockdown requests are zero-data-retention and look 2 years back
            zdr = true;
            if max_age.is_none() {
                o.max_age_ms = LOCKDOWN_MAX_AGE_MS;
            }
        }
    }
    if let Some(b) = cx.boolean(obj, "zeroDataRetention") {
        zdr |= b;
    }
    if let Some(b) = cx.boolean(obj, "onlyCleanContent") {
        o.only_clean_content = b;
    }
    o.check_prompt_injection =
        cx.boolean(obj, "checkPromptInjection").unwrap_or(false) || cx.lifted_injection_check;
    if let Some(v) = obj.get("redactPII") {
        o.redact_pii = parse_redact_pii(&mut cx, v);
    }
    if o.only_clean_content && zdr {
        let at = cx.at("onlyCleanContent");
        cx.bad(
            at,
            "unsupported_with_zdr",
            "onlyCleanContent is not supported on zero-data-retention requests",
        );
    }
    if !headers.is_empty() || !o.actions.is_empty() {
        // The compat API: sensitive parameters (headers, actions) force storeInCache to false
        o.store_in_cache = false;
    }
    if interactive(&o) {
        let at = cx.at("actions");
        cx.warnings.push(Warning::new(
            "actions_profile_raised",
            &at,
            "click, write and press actions need the safety profile test_environment; the run uses it \
             (destructive actions and external communication stay denied)",
        ));
    }
    if let Err(msg) = o.validate() {
        let at = validation_path(&cx.path, &o, &msg);
        cx.bad(at, "out_of_range", msg);
    }
    if cx.details.is_empty() {
        Ok(ParsedScrape {
            options: o,
            headers,
            zero_data_retention: zdr,
            warnings: cx.warnings,
        })
    } else {
        Err(cx.details)
    }
}

/// The JSON Pointer a [`ScrapeOptions::validate`] message is about.
fn validation_path(base: &str, o: &ScrapeOptions, msg: &str) -> String {
    let field = if msg.starts_with("waitFor and wait actions") {
        // the sum is too long: blame `waitFor` when it alone is, else the `wait` actions
        if o.wait_for_ms > crawlx_core::scrape::MAX_WAIT_MS {
            "waitFor"
        } else {
            "actions"
        }
    } else {
        [
            "actions",
            "formats",
            "timeout",
            "waitFor",
            "checkPromptInjection",
            "redactPII",
        ]
        .into_iter()
        .find(|f| msg.starts_with(f))
        .unwrap_or("")
    };
    if field.is_empty() {
        format!("{base}/")
    } else {
        format!("{base}/{field}")
    }
}

fn parse_headers(cx: &mut Cx, obj: &Map<String, Value>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match obj.get("headers") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                match v.as_str() {
                    Some(s) => out.push((k.clone(), s.to_owned())),
                    None => {
                        let at = format!("{}/headers/{}", cx.path, pointer_escape(k));
                        cx.bad(at, "invalid_type", "header values must be strings");
                    }
                }
            }
        }
        Some(_) => {
            let at = cx.at("headers");
            cx.bad(at, "invalid_type", "expected an object of header names to values");
        }
    }
    out
}

fn parse_proxy(cx: &mut Cx, obj: &Map<String, Value>, o: &mut ScrapeOptions) {
    use crawlx_core::scrape::ProxyMode;
    match obj.get("proxy") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => match s.as_str() {
            "basic" => o.proxy = ProxyMode::Basic,
            "enhanced" | "stealth" => o.proxy = ProxyMode::Enhanced,
            "auto" => o.proxy = ProxyMode::Auto,
            _ => {
                let at = cx.at("proxy");
                cx.bad(at, "unknown_enum", "proxy must be basic, enhanced or auto");
            }
        },
        Some(_) => {
            let at = cx.at("proxy");
            cx.bad(at, "invalid_type", "expected a string");
        }
    }
}

/// The compat API `profile{name,saveChanges}`: a named persistent browser profile. `saveChanges`
/// defaults to `true`; the name is 1 to 128 of `A-Z a-z 0-9 _ -`.
fn parse_profile(cx: &mut Cx, obj: &Map<String, Value>, o: &mut ScrapeOptions) {
    let Some(v) = obj.get("profile") else { return };
    let at = cx.at("profile");
    let Some(m) = v.as_object() else {
        cx.bad(at, "invalid_type", "expected an object");
        return;
    };
    let name = m.get("name").and_then(Value::as_str).unwrap_or_default();
    if !BrowserProfile::name_is_valid(name) {
        cx.bad(
            format!("{at}/name"),
            "invalid_value",
            "expected a name of 1 to 128 of A-Z a-z 0-9 _ -",
        );
        return;
    }
    let save_changes = match m.get("saveChanges") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            cx.bad(format!("{at}/saveChanges"), "invalid_type", "expected a boolean");
            return;
        }
    };
    o.profile = Some(BrowserProfile {
        name: name.to_owned(),
        save_changes,
    });
}

/// `redactPII`: `true` (every default), `false` (off) or `{mode, entities, replaceStyle}`.
fn parse_redact_pii(cx: &mut Cx, v: &Value) -> Option<RedactPii> {
    let at = cx.at("redactPII");
    match v {
        Value::Null | Value::Bool(false) => None,
        Value::Bool(true) => Some(RedactPii::default()),
        Value::Object(m) => {
            let mut out = RedactPii::default();
            for (k, x) in m {
                let key_at = format!("{at}/{k}");
                match k.as_str() {
                    "mode" => match x.as_str() {
                        Some("accurate") => out.mode = PiiMode::Accurate,
                        Some("aggressive") => out.mode = PiiMode::Aggressive,
                        Some("fast") => out.mode = PiiMode::Fast,
                        _ => cx.bad(
                            key_at,
                            "unknown_enum",
                            "mode must be accurate, aggressive or fast",
                        ),
                    },
                    "replaceStyle" => match x.as_str() {
                        Some("tag") => out.replace_style = PiiReplaceStyle::Tag,
                        Some("mask") => out.replace_style = PiiReplaceStyle::Mask,
                        Some("remove") => out.replace_style = PiiReplaceStyle::Remove,
                        _ => cx.bad(key_at, "unknown_enum", "replaceStyle must be tag, mask or remove"),
                    },
                    "entities" => match x.as_array() {
                        Some(list) => {
                            for (i, e) in list.iter().enumerate() {
                                let entity = match e.as_str() {
                                    Some("PERSON") => Some(PiiEntity::Person),
                                    Some("EMAIL") => Some(PiiEntity::Email),
                                    Some("PHONE") => Some(PiiEntity::Phone),
                                    Some("LOCATION") => Some(PiiEntity::Location),
                                    Some("FINANCIAL") => Some(PiiEntity::Financial),
                                    Some("SECRET") => Some(PiiEntity::Secret),
                                    _ => None,
                                };
                                match entity {
                                    Some(e) if !out.entities.contains(&e) => out.entities.push(e),
                                    Some(_) => {}
                                    None => cx.bad(
                                        format!("{key_at}/{i}"),
                                        "unknown_enum",
                                        "an entity is PERSON, EMAIL, PHONE, LOCATION, FINANCIAL or SECRET",
                                    ),
                                }
                            }
                        }
                        None => cx.bad(key_at, "invalid_type", "expected an array of entity names"),
                    },
                    other => cx.bad(
                        key_at,
                        "unknown_field",
                        format!("unknown redactPII option `{other}`"),
                    ),
                }
            }
            Some(out)
        }
        _ => {
            cx.bad(at, "invalid_type", "expected a boolean or an options object");
            None
        }
    }
}

fn parse_location(cx: &mut Cx, v: &Value) -> Option<Location> {
    let Some(m) = v.as_object() else {
        let at = cx.at("location");
        cx.bad(at, "invalid_type", "expected an object");
        return None;
    };
    let mut loc = Location::default();
    if let Some(c) = m.get("country") {
        match c.as_str() {
            Some(s) if s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()) => {
                loc.country = Some(s.to_owned());
            }
            _ => {
                let at = cx.at("location/country");
                cx.bad(
                    at,
                    "invalid_string",
                    "country must be an ISO 3166-1 alpha-2 code such as `US`",
                );
            }
        }
    }
    if let Some(l) = m.get("languages") {
        match l.as_array() {
            Some(a) => {
                for (i, x) in a.iter().enumerate() {
                    match x.as_str() {
                        Some(s) if !s.is_empty() => loc.languages.push(s.to_owned()),
                        _ => {
                            let at = format!("{}/location/languages/{i}", cx.path);
                            cx.bad(at, "invalid_type", "expected a language tag");
                        }
                    }
                }
            }
            None => {
                let at = cx.at("location/languages");
                cx.bad(at, "invalid_type", "expected an array of language tags");
            }
        }
    }
    Some(loc)
}

/// `parsers`: an absent key keeps the default `[pdf, image]`; a list replaces it (an empty list
/// turns every parser off: a PDF comes back as base64 text for a flat credit). `"pdf"` / `"image"`
/// are shorthands for `{type}`. crawlx has no OCR engine: the `image` parser and PDF `mode: ocr`
/// are accepted and reported with the `ocr_unavailable` warning.
fn parse_parsers(cx: &mut Cx, v: &Value, o: &mut ScrapeOptions) {
    let Some(items) = v.as_array() else {
        let at = cx.at("parsers");
        cx.bad(at, "invalid_type", "expected an array");
        return;
    };
    let mut parsers = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = format!("{}/parsers/{i}", cx.path);
        let ty = match item {
            Value::String(s) => s.as_str(),
            Value::Object(m) => m.get("type").and_then(Value::as_str).unwrap_or(""),
            _ => "",
        };
        let spec = match (ty, item) {
            ("pdf", Value::Object(m)) => Some(parse_pdf_parser(cx, m, &at)),
            ("pdf", _) => Some(ParserSpec::pdf()),
            ("image", Value::Object(m)) => {
                for k in m.keys().filter(|k| k.as_str() != "type") {
                    cx.bad(
                        format!("{at}/{k}"),
                        "unknown_field",
                        format!("the image parser has no option `{k}`"),
                    );
                }
                Some(ParserSpec::Image)
            }
            ("image", _) => Some(ParserSpec::Image),
            _ => {
                cx.bad(
                    at.clone(),
                    "unknown_enum",
                    "a parser is `pdf`, `image` or an object with that `type`",
                );
                None
            }
        };
        if let Some(spec) = spec {
            if spec == ParserSpec::Image {
                cx.ocr_unavailable(&at, "the `image` parser");
            }
            parsers.push(spec);
        }
    }
    o.parsers = parsers;
}

fn parse_pdf_parser(cx: &mut Cx, m: &Map<String, Value>, at: &str) -> ParserSpec {
    let mut mode = PdfMode::Auto;
    let mut max_pages = None;
    let mut pages = false;
    let mut blocks = false;
    let mut page_markers = false;
    let flag = |cx: &mut Cx, v: &Value, key_at: String| match v.as_bool() {
        Some(b) => b,
        None => {
            cx.bad(key_at, "invalid_type", "expected a boolean");
            false
        }
    };
    for (k, v) in m {
        let key_at = format!("{at}/{k}");
        match k.as_str() {
            "type" => {}
            "maxPages" => match v.as_u64() {
                Some(n) if (1..=10_000).contains(&n) => max_pages = u32::try_from(n).ok(),
                _ => cx.bad(
                    key_at,
                    "out_of_range",
                    "maxPages must be an integer between 1 and 10000",
                ),
            },
            "pages" => pages = flag(cx, v, key_at),
            "blocks" => blocks = flag(cx, v, key_at),
            "pageMarkers" => page_markers = flag(cx, v, key_at),
            "mode" => match v.as_str() {
                Some("fast") => mode = PdfMode::Fast,
                Some("auto") => mode = PdfMode::Auto,
                Some("ocr") => {
                    mode = PdfMode::Ocr;
                    cx.ocr_unavailable(&key_at, "PDF `ocr` mode");
                }
                _ => cx.bad(key_at, "unknown_enum", "mode must be fast, auto or ocr"),
            },
            other => cx.bad(
                key_at,
                "unknown_field",
                format!("unknown PDF parser option `{other}`"),
            ),
        }
    }
    ParserSpec::Pdf {
        mode,
        max_pages,
        pages,
        blocks,
        page_markers,
    }
}

fn parse_viewport(cx: &mut Cx, v: &Value, at: &str) -> Option<ScreenshotViewport> {
    let m = v.as_object();
    let dim = |key: &str| {
        m.and_then(|m| m.get(key))
            .and_then(Value::as_u64)
            .filter(|n| (1..=10_000).contains(n))
            .and_then(|n| u32::try_from(n).ok())
    };
    match (dim("width"), dim("height")) {
        (Some(width), Some(height)) => Some(ScreenshotViewport { width, height }),
        _ => {
            cx.bad(
                at.to_owned(),
                "out_of_range",
                "viewport needs integer `width` and `height` between 1 and 10000",
            );
            None
        }
    }
}

fn parse_quality(cx: &mut Cx, m: &Map<String, Value>, at: &str) -> Option<u8> {
    let v = m.get("quality")?;
    match v
        .as_u64()
        .filter(|n| (1..=100).contains(n))
        .and_then(|n| u8::try_from(n).ok())
    {
        Some(q) => Some(q),
        None => {
            cx.bad(
                format!("{at}/quality"),
                "out_of_range",
                "quality must be an integer between 1 and 100",
            );
            None
        }
    }
}

fn parse_actions(cx: &mut Cx, v: &Value, o: &mut ScrapeOptions) {
    let Some(items) = v.as_array() else {
        let at = cx.at("actions");
        cx.bad(at, "invalid_type", "expected an array");
        return;
    };
    for (i, item) in items.iter().enumerate() {
        let at = format!("{}/actions/{i}", cx.path);
        let Some(m) = item.as_object() else {
            cx.bad(at, "invalid_type", "expected an object with a `type`");
            continue;
        };
        if let Some(a) = parse_action(cx, m, &at) {
            o.actions.push(a);
        }
    }
}

fn parse_action(cx: &mut Cx, m: &Map<String, Value>, at: &str) -> Option<ScrapeAction> {
    let text = |cx: &mut Cx, key: &str| -> Option<String> {
        match m.get(key).and_then(Value::as_str) {
            Some(s) => Some(s.to_owned()),
            None => {
                cx.bad(
                    format!("{at}/{key}"),
                    "required",
                    format!("`{key}` is required and must be a string"),
                );
                None
            }
        }
    };
    let opt_text = |cx: &mut Cx, key: &str| -> Option<String> {
        match m.get(key) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                cx.bad(format!("{at}/{key}"), "invalid_type", "expected a string");
                None
            }
        }
    };
    let flag = |cx: &mut Cx, key: &str| -> bool {
        match m.get(key) {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                cx.bad(format!("{at}/{key}"), "invalid_type", "expected a boolean");
                false
            }
        }
    };
    let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
    match ty {
        "wait" => {
            let ms = match m.get("milliseconds") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_u64().filter(|n| *n >= 1).and_then(|n| u32::try_from(n).ok()) {
                    Some(n) => Some(n),
                    None => {
                        cx.bad(
                            format!("{at}/milliseconds"),
                            "out_of_range",
                            "milliseconds must be a positive integer",
                        );
                        return None;
                    }
                },
            };
            let selector = opt_text(cx, "selector");
            let state = match m.get("state") {
                None => SelectorState::Attached,
                Some(value) => match SelectorState::deserialize(value) {
                    Ok(state) => state,
                    Err(_) => {
                        cx.bad(
                            format!("{at}/state"),
                            "invalid_enum_value",
                            "expected attached, visible, hidden or detached",
                        );
                        return None;
                    }
                },
            };
            if selector.is_none() && state != SelectorState::Attached {
                cx.bad(
                    format!("{at}/state"),
                    "invalid_union",
                    "nondefault state requires selector",
                );
                return None;
            }
            match (ms, selector) {
                (Some(ms), None) => Some(ScrapeAction::Wait {
                    milliseconds: Some(ms),
                    selector: None,
                    state,
                }),
                (None, Some(s)) => Some(ScrapeAction::Wait {
                    milliseconds: None,
                    selector: Some(s),
                    state,
                }),
                _ => {
                    cx.bad(
                        at.to_owned(),
                        "invalid_union",
                        "`wait` needs exactly one of `milliseconds` and `selector`",
                    );
                    None
                }
            }
        }
        "screenshot" => {
            let full_page = flag(cx, "fullPage");
            let quality = parse_quality(cx, m, at);
            let viewport = m
                .get("viewport")
                .and_then(|v| parse_viewport(cx, v, &format!("{at}/viewport")));
            Some(ScrapeAction::Screenshot {
                full_page,
                quality,
                viewport,
            })
        }
        "click" => {
            let selector = text(cx, "selector")?;
            Some(ScrapeAction::Click {
                selector,
                all: flag(cx, "all"),
            })
        }
        "write" => Some(ScrapeAction::Write {
            text: text(cx, "text")?,
        }),
        "press" => Some(ScrapeAction::Press {
            key: text(cx, "key")?,
        }),
        "scroll" => {
            let direction = match m.get("direction").and_then(Value::as_str) {
                None | Some("down") => ScrollDirection::Down,
                Some("up") => ScrollDirection::Up,
                Some(_) => {
                    cx.bad(
                        format!("{at}/direction"),
                        "unknown_enum",
                        "direction must be up or down",
                    );
                    return None;
                }
            };
            Some(ScrapeAction::Scroll {
                direction,
                selector: opt_text(cx, "selector"),
            })
        }
        "scrape" => Some(ScrapeAction::Scrape),
        "executeJavascript" => Some(ScrapeAction::ExecuteJavascript {
            script: text(cx, "script")?,
        }),
        "pdf" => {
            let format = opt_text(cx, "format");
            if let Some(f) = &format {
                const PAPER: [&str; 11] = [
                    "A0", "A1", "A2", "A3", "A4", "A5", "A6", "Letter", "Legal", "Tabloid", "Ledger",
                ];
                if !PAPER.contains(&f.as_str()) {
                    cx.bad(
                        format!("{at}/format"),
                        "unknown_enum",
                        "format must be A0..A6, Letter, Legal, Tabloid or Ledger",
                    );
                    return None;
                }
            }
            let scale = match m.get("scale") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_f64() {
                    #[allow(clippy::cast_possible_truncation)]
                    Some(s) if s.is_finite() => Some(s as f32),
                    _ => {
                        cx.bad(format!("{at}/scale"), "invalid_type", "scale must be a number");
                        return None;
                    }
                },
            };
            Some(ScrapeAction::Pdf {
                format,
                landscape: flag(cx, "landscape"),
                scale,
            })
        }
        _ => {
            cx.bad(
                format!("{at}/type"),
                "unknown_enum",
                "type must be wait, screenshot, click, write, press, scroll, scrape, executeJavascript or pdf",
            );
            None
        }
    }
}

fn parse_formats(cx: &mut Cx, v: &Value, o: &mut ScrapeOptions) {
    let Some(items) = v.as_array() else {
        let at = cx.at("formats");
        cx.bad(at, "invalid_type", "expected an array");
        return;
    };
    let mut out: Vec<FormatSpec> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let at = format!("{}/formats/{i}", cx.path);
        if let Some(f) = parse_format(cx, item, &at) {
            if !out.iter().any(|g| g.name() == f.name()) {
                out.push(f);
            }
        }
    }
    // an empty list, or only formats crawlx does not produce, keeps the default (markdown)
    if !out.is_empty() {
        o.formats = out;
    }
}

fn parse_format(cx: &mut Cx, item: &Value, at: &str) -> Option<FormatSpec> {
    let (name, obj): (&str, Option<&Map<String, Value>>) = match item {
        Value::String(s) => (s.as_str(), None),
        Value::Object(m) => (m.get("type").and_then(Value::as_str).unwrap_or(""), Some(m)),
        _ => {
            cx.bad(
                at.to_owned(),
                "invalid_type",
                "a format is a name or an object with a `type`",
            );
            return None;
        }
    };
    let empty = Map::new();
    let m = obj.unwrap_or(&empty);
    let need_object = |cx: &mut Cx, what: &str| {
        cx.bad(
            at.to_owned(),
            "invalid_type",
            format!("the `{what}` format needs an object: {{\"type\":\"{what}\", ...}}"),
        );
    };
    match name {
        "markdown" => Some(FormatSpec::Markdown),
        "html" => Some(FormatSpec::Html),
        "rawHtml" => Some(FormatSpec::RawHtml),
        "links" => Some(FormatSpec::Links),
        "images" => Some(FormatSpec::Images),
        "rawBase64" => Some(FormatSpec::RawBase64),
        "branding" => Some(FormatSpec::Branding),
        "summary" => Some(FormatSpec::Summary),
        "screenshot@fullPage" if obj.is_none() => Some(FormatSpec::Screenshot {
            full_page: true,
            quality: None,
            viewport: None,
        }),
        "screenshot" => {
            let full_page = match m.get("fullPage") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    cx.bad(format!("{at}/fullPage"), "invalid_type", "expected a boolean");
                    false
                }
            };
            let quality = parse_quality(cx, m, at);
            let viewport = m
                .get("viewport")
                .and_then(|v| parse_viewport(cx, v, &format!("{at}/viewport")));
            Some(FormatSpec::Screenshot {
                full_page,
                quality,
                viewport,
            })
        }
        "attributes" => {
            let Some(sel) = m.get("selectors").and_then(Value::as_array) else {
                cx.bad(
                    format!("{at}/selectors"),
                    "required",
                    "the `attributes` format needs `selectors`: [{\"selector\":..., \"attribute\":...}]",
                );
                return None;
            };
            let mut selectors = Vec::new();
            for (i, s) in sel.iter().enumerate() {
                let get = |k: &str| s.get(k).and_then(Value::as_str).filter(|v| !v.is_empty());
                match (get("selector"), get("attribute")) {
                    (Some(selector), Some(attribute)) => selectors.push(AttributeSelector {
                        selector: selector.to_owned(),
                        attribute: attribute.to_owned(),
                    }),
                    _ => cx.bad(
                        format!("{at}/selectors/{i}"),
                        "required",
                        "each selector needs a non-empty `selector` and `attribute`",
                    ),
                }
            }
            Some(FormatSpec::Attributes { selectors })
        }
        "json" | "extract" => {
            let schema = match m.get("schema") {
                None | Some(Value::Null) => None,
                Some(s @ Value::Object(_)) => Some(s.clone()),
                Some(_) => {
                    cx.bad(
                        format!("{at}/schema"),
                        "invalid_type",
                        "schema must be a JSON Schema object",
                    );
                    None
                }
            };
            let prompt = match m.get("prompt") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => {
                    cx.bad(format!("{at}/prompt"), "invalid_type", "prompt must be a string");
                    None
                }
            };
            if let Some(c) = m.get("checkPromptInjection").filter(|c| !c.is_null()) {
                match c.as_bool() {
                    Some(true) => cx.lifted_injection_check = true,
                    Some(false) => {}
                    None => cx.bad(
                        format!("{at}/checkPromptInjection"),
                        "invalid_type",
                        "expected a boolean",
                    ),
                }
            }
            Some(FormatSpec::Json { schema, prompt })
        }
        "question" => match m.get("question").and_then(Value::as_str) {
            Some(q) if q.chars().count() <= MAX_PROMPT_CHARS => Some(FormatSpec::Question {
                question: q.to_owned(),
            }),
            Some(_) => {
                cx.bad(
                    format!("{at}/question"),
                    "too_big",
                    "question is at most 10000 characters",
                );
                None
            }
            None => {
                if obj.is_none() {
                    need_object(cx, "question");
                } else {
                    cx.bad(
                        format!("{at}/question"),
                        "required",
                        "the `question` format needs a `question`",
                    );
                }
                None
            }
        },
        "highlights" => match m.get("query").and_then(Value::as_str) {
            Some(q) if q.chars().count() <= MAX_PROMPT_CHARS => {
                Some(FormatSpec::Highlights { query: q.to_owned() })
            }
            Some(_) => {
                cx.bad(
                    format!("{at}/query"),
                    "too_big",
                    "query is at most 10000 characters",
                );
                None
            }
            None => {
                if obj.is_none() {
                    need_object(cx, "highlights");
                } else {
                    cx.bad(
                        format!("{at}/query"),
                        "required",
                        "the `highlights` format needs a `query`",
                    );
                }
                None
            }
        },
        "query" => match m.get("prompt").and_then(Value::as_str) {
            Some(p) => {
                let mode = match m.get("mode") {
                    None | Some(Value::Null) => QueryMode::Freeform,
                    Some(Value::String(s)) if s == "freeform" => QueryMode::Freeform,
                    Some(Value::String(s)) if s == "directQuote" => QueryMode::DirectQuote,
                    Some(_) => {
                        cx.bad(
                            format!("{at}/mode"),
                            "unknown_enum",
                            "mode must be freeform or directQuote",
                        );
                        QueryMode::Freeform
                    }
                };
                Some(FormatSpec::Query {
                    prompt: p.to_owned(),
                    mode,
                })
            }
            None => {
                if obj.is_none() {
                    need_object(cx, "query");
                } else {
                    cx.bad(
                        format!("{at}/prompt"),
                        "required",
                        "the `query` format needs a `prompt`",
                    );
                }
                None
            }
        },
        "audio" => Some(FormatSpec::Audio),
        "video" => Some(FormatSpec::Video),
        "changeTracking" => Some(parse_change_tracking(cx, m, at)),
        other if UNSUPPORTED_FORMATS.contains(&other) => {
            cx.unsupported(at, &format!("the `{other}` format"), "it is not produced");
            None
        }
        _ => {
            cx.bad(
                format!("{at}/type"),
                "unknown_enum",
                "unknown format; use markdown, html, rawHtml, rawBase64, links, images, screenshot, summary, json, attributes, branding, question, highlights, query or changeTracking",
            );
            None
        }
    }
}

fn parse_change_tracking(cx: &mut Cx, m: &Map<String, Value>, at: &str) -> FormatSpec {
    let mut modes = Vec::new();
    match m.get("modes") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for (i, x) in a.iter().enumerate() {
                match x.as_str() {
                    Some("git-diff") => modes.push(ChangeMode::GitDiff),
                    Some("json") => modes.push(ChangeMode::Json),
                    _ => cx.bad(
                        format!("{at}/modes/{i}"),
                        "unknown_enum",
                        "a change tracking mode is git-diff or json",
                    ),
                }
            }
        }
        Some(_) => cx.bad(format!("{at}/modes"), "invalid_type", "expected an array"),
    }
    let schema = match m.get("schema") {
        None | Some(Value::Null) => None,
        Some(s @ Value::Object(_)) => Some(s.clone()),
        Some(_) => {
            cx.bad(
                format!("{at}/schema"),
                "invalid_type",
                "schema must be a JSON Schema object",
            );
            None
        }
    };
    let text = |cx: &mut Cx, key: &str| match m.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            cx.bad(format!("{at}/{key}"), "invalid_type", "expected a string");
            None
        }
    };
    let prompt = text(cx, "prompt");
    let tag = text(cx, "tag");
    FormatSpec::ChangeTracking {
        modes,
        schema,
        prompt,
        tag,
    }
}

/// v1 aliases: the top-level `extract` object adds a `json` format, `jsonOptions` fills a bare
/// `json` format.
fn apply_legacy_json(cx: &mut Cx, obj: &Map<String, Value>, o: &mut ScrapeOptions) {
    for key in ["jsonOptions", "extract"] {
        let Some(v) = obj.get(key) else { continue };
        let Some(m) = v.as_object() else {
            let at = cx.at(key);
            cx.bad(
                at,
                "invalid_type",
                "expected an object with `schema` and/or `prompt`",
            );
            continue;
        };
        let schema = m.get("schema").filter(|s| s.is_object()).cloned();
        let prompt = m.get("prompt").and_then(Value::as_str).map(str::to_owned);
        if m.contains_key("systemPrompt") {
            let at = format!("{}/{key}/systemPrompt", cx.path);
            cx.unsupported(&at, "`systemPrompt`", "pass the instruction as `prompt`");
        }
        match o.formats.iter_mut().find(|f| f.name() == "json") {
            Some(FormatSpec::Json { schema: s, prompt: p }) => {
                if s.is_none() {
                    *s = schema;
                }
                if p.is_none() {
                    *p = prompt;
                }
            }
            _ if key == "extract" => {
                if o.formats == ScrapeOptions::default().formats && !obj.contains_key("formats") {
                    o.formats.clear();
                }
                o.formats.push(FormatSpec::Json { schema, prompt });
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn parse(v: &Value) -> Result<ParsedScrape, Vec<Detail>> {
        parse_scrape_options(v.as_object().unwrap(), "")
    }

    #[test]
    fn defaults_follow_compat() {
        let p = parse(&json!({})).unwrap();
        assert_eq!(p.options.formats, vec![FormatSpec::Markdown]);
        assert!(
            p.options.skip_tls_verification,
            "the compat API defaults skipTlsVerification to true"
        );
        assert!(p.options.only_main_content);
        assert_eq!(p.options.timeout_ms, 60_000);
        assert!(!p.zero_data_retention);
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn every_format_form_parses() {
        let p = parse(&json!({ "formats": [
            "markdown", "html", "rawHtml", "links", "images", "branding", "summary", "screenshot@fullPage",
            { "type": "screenshot", "fullPage": true, "quality": 80, "viewport": { "width": 800, "height": 600 } },
            { "type": "attributes", "selectors": [{ "selector": "a", "attribute": "href" }] },
            { "type": "json", "schema": { "type": "object" }, "prompt": "p" },
            { "type": "question", "question": "q?" },
            { "type": "highlights", "query": "x" },
            { "type": "query", "prompt": "y" },
            { "type": "changeTracking", "modes": ["git-diff", "json"], "tag": "t" },
        ] }))
        .unwrap();
        let names: Vec<&str> = p.options.formats.iter().map(FormatSpec::name).collect();
        assert_eq!(
            names,
            [
                "markdown",
                "html",
                "rawHtml",
                "links",
                "images",
                "branding",
                "summary",
                "screenshot",
                "attributes",
                "json",
                "question",
                "highlights",
                "query",
                "changeTracking"
            ],
            "the second screenshot is a duplicate name and is dropped"
        );
        assert!(matches!(
            p.options.format("screenshot"),
            Some(FormatSpec::Screenshot {
                full_page: true,
                quality: None,
                ..
            })
        ));
        assert!(matches!(
            p.options.format("changeTracking"),
            Some(FormatSpec::ChangeTracking { modes, tag: Some(t), .. }) if modes.len() == 2 && t == "t"
        ));
    }

    #[test]
    fn rawbase64_must_be_alone() {
        let e = parse(&json!({ "formats": ["rawBase64", "markdown"] })).unwrap_err();
        assert_eq!(e[0].path, "/formats");
    }

    #[test]
    fn violations_are_all_reported_with_pointers() {
        let e = parse(&json!({
            "formats": ["nope", { "type": "question" }, "attributes"],
            "timeout": 10,
            "waitFor": "x",
            "headers": { "a": 1 },
            "location": { "country": "us" },
            "proxy": "turbo",
            "actions": [{ "type": "click" }, { "type": "wait" }]
        }))
        .unwrap_err();
        let paths: Vec<&str> = e.iter().map(|d| d.path.as_str()).collect();
        for want in [
            "/formats/0/type",
            "/formats/1/question",
            "/formats/2/selectors",
            "/timeout",
            "/waitFor",
            "/headers/a",
            "/location/country",
            "/proxy",
            "/actions/0/selector",
            "/actions/1",
        ] {
            assert!(paths.contains(&want), "{want} missing in {paths:?}");
        }
    }

    #[test]
    fn nested_path_prefix_is_used() {
        let v = json!({ "timeout": 5 });
        let e = parse_scrape_options(v.as_object().unwrap(), "/scrapeOptions").unwrap_err();
        assert_eq!(e[0].path, "/scrapeOptions/timeout");
    }

    #[test]
    fn unknown_keys_warn_but_envelope_keys_do_not() {
        let v = json!({ "url": "https://a.test/", "origin": "x", "bogus": 1, "threatProtection": {} });
        let p = parse_scrape_options_in(v.as_object().unwrap(), "", &["url", "origin"]).unwrap();
        let paths: Vec<&str> = p.warnings.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(paths, ["/bogus", "/threatProtection"]);
        assert!(p.warnings.iter().all(|w| w.code == "unsupported_option"));
    }

    #[test]
    fn proxy_tiers_are_retained_and_legacy_stealth_means_enhanced() {
        use crawlx_core::scrape::ProxyMode;
        for (wire, mode) in [
            ("basic", ProxyMode::Basic),
            ("enhanced", ProxyMode::Enhanced),
            ("stealth", ProxyMode::Enhanced),
            ("auto", ProxyMode::Auto),
        ] {
            let p = parse(&json!({ "proxy": wire })).unwrap();
            assert_eq!(p.options.proxy, mode);
            assert!(p.warnings.is_empty());
            for kind in [JobKind::Scrape, JobKind::Batch, JobKind::Crawl] {
                let mut crawl = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
                p.apply(&mut crawl, kind).unwrap();
                assert_eq!(crawl.scrape.as_ref().unwrap().options.proxy, mode);
                let encoded = serde_json::to_vec(&crawl).unwrap();
                let restored: CreateCrawl = serde_json::from_slice(&encoded).unwrap();
                assert_eq!(restored.scrape.unwrap().options.proxy, mode);
            }
        }
        assert!(parse(&json!({ "proxy": "unknown" })).is_err());
    }

    #[test]
    fn parsers_follow_the_openapi_shapes() {
        // absent: the compat API's default [pdf, image], and no warning for it
        let absent = parse(&json!({})).unwrap();
        assert_eq!(absent.options.parsers, vec![ParserSpec::pdf(), ParserSpec::Image]);
        assert!(absent.warnings.is_empty());
        // shorthand strings
        let p = parse(&json!({ "parsers": ["pdf"] })).unwrap();
        assert_eq!(
            p.options.parsers,
            vec![ParserSpec::pdf()],
            "a list without image turns OCR off"
        );
        assert!(p.warnings.is_empty());
        let p = parse(&json!({ "parsers": ["pdf", "image"] })).unwrap();
        assert_eq!(p.options.parsers, vec![ParserSpec::pdf(), ParserSpec::Image]);
        assert_eq!(
            p.warnings
                .iter()
                .map(|w| (w.code.as_str(), w.path.as_str()))
                .collect::<Vec<_>>(),
            [("ocr_unavailable", "/parsers/1")]
        );
        // an explicit empty list is kept: PDFs come back unparsed for a flat credit
        let p = parse(&json!({ "parsers": [] })).unwrap();
        assert!(p.options.parsers.is_empty());
        assert!(p.warnings.is_empty());
        // the object form with every option
        let p = parse(&json!({ "parsers": [
            { "type": "pdf", "mode": "fast", "maxPages": 3, "pages": true, "blocks": true, "pageMarkers": true },
            { "type": "image" },
        ] }))
        .unwrap();
        assert_eq!(
            p.options.parsers[0],
            ParserSpec::Pdf {
                mode: PdfMode::Fast,
                max_pages: Some(3),
                pages: true,
                blocks: true,
                page_markers: true
            }
        );
        assert_eq!(p.options.parsers[1], ParserSpec::Image);
        // ocr mode: text layer only, with the warning at the option
        let p = parse(&json!({ "parsers": [{ "type": "pdf", "mode": "ocr" }] })).unwrap();
        assert!(matches!(
            p.options.parsers[0],
            ParserSpec::Pdf {
                mode: PdfMode::Ocr,
                ..
            }
        ));
        assert_eq!(p.warnings[0].code, "ocr_unavailable");
        assert_eq!(p.warnings[0].path, "/parsers/0/mode");
        // violations
        let e = parse(&json!({ "parsers": [
            "docx",
            { "type": "pdf", "maxPages": 0, "pages": "yes", "mode": "slow", "extra": 1 },
            { "type": "image", "mode": "fast" },
            7,
        ] }))
        .unwrap_err();
        let paths: Vec<&str> = e.iter().map(|d| d.path.as_str()).collect();
        for want in [
            "/parsers/0",
            "/parsers/1/maxPages",
            "/parsers/1/pages",
            "/parsers/1/mode",
            "/parsers/1/extra",
            "/parsers/2/mode",
            "/parsers/3",
        ] {
            assert!(paths.contains(&want), "{want} in {paths:?}");
        }
        let e = parse(&json!({ "parsers": [{ "type": "pdf", "maxPages": 10001 }] })).unwrap_err();
        assert_eq!(e[0].path, "/parsers/0/maxPages");
        let e = parse(&json!({ "parsers": "pdf" })).unwrap_err();
        assert_eq!(e[0].path, "/parsers");
    }

    #[test]
    fn legacy_json_aliases_map_to_the_json_format() {
        let p = parse(
            &json!({ "formats": ["json"], "jsonOptions": { "schema": { "type": "object" }, "prompt": "p" } }),
        )
        .unwrap();
        assert_eq!(
            p.options.formats,
            vec![FormatSpec::Json {
                schema: Some(json!({ "type": "object" })),
                prompt: Some("p".into())
            }]
        );
        let p = parse(&json!({ "extract": { "prompt": "p" } })).unwrap();
        assert_eq!(
            p.options.formats,
            vec![FormatSpec::Json {
                schema: None,
                prompt: Some("p".into())
            }]
        );
        let p = parse(&json!({ "formats": [{ "type": "extract", "prompt": "z" }] })).unwrap();
        assert_eq!(
            p.options.formats,
            vec![FormatSpec::Json {
                schema: None,
                prompt: Some("z".into())
            }]
        );
    }

    #[test]
    fn headers_lockdown_and_retention_side_effects() {
        let p =
            parse(&json!({ "headers": { "X-A": "1", "Cookie": "a=b" }, "actions": [{ "type": "scrape" }] }))
                .unwrap();
        assert_eq!(p.headers.len(), 2);
        assert!(
            p.options.headers.is_empty(),
            "header values stay out of the stored options"
        );
        assert!(
            !p.options.store_in_cache,
            "headers/actions force storeInCache=false"
        );
        let p = parse(&json!({ "lockdown": true })).unwrap();
        assert!(p.zero_data_retention && p.options.lockdown);
        assert_eq!(p.options.max_age_ms, LOCKDOWN_MAX_AGE_MS);
        let p = parse(&json!({ "lockdown": true, "maxAge": 5 })).unwrap();
        assert_eq!(p.options.max_age_ms, 5);
        let p = parse(
            &json!({ "maxAge": 0, "minAge": 7, "skipTlsVerification": false, "mobile": true, "waitFor": 20 }),
        )
        .unwrap();
        assert_eq!(p.options.max_age_ms, 0);
        assert_eq!(p.options.min_age_ms, Some(7));
        assert!(!p.options.skip_tls_verification && p.options.mobile && p.options.wait_for_ms == 20);
    }

    #[test]
    fn apply_fills_the_run() {
        let p = parse(&json!({
            "formats": ["markdown", "links", { "type": "screenshot" }],
            "headers": { "X-Token": "s3", "User-Agent": "bot/1", "Cookie": "sid=9" },
            "onlyMainContent": false, "includeTags": ["main"], "excludeTags": ["nav"],
            "timeout": 5000, "waitFor": 100, "zeroDataRetention": true,
        }))
        .unwrap();
        let mut c = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        p.apply(&mut c, JobKind::Scrape).unwrap();
        let job = c.scrape.as_ref().unwrap();
        assert_eq!(job.kind, JobKind::Scrape);
        assert_eq!(job.options, p.options);
        assert!(
            c.output.formats.contains(&OutputFormat::Screenshot)
                && c.output.formats.contains(&OutputFormat::Links)
        );
        assert!(!c.output.only_main_content);
        assert_eq!(
            (c.output.include_tags.clone(), c.output.exclude_tags.clone()),
            (vec!["main".to_owned()], vec!["nav".to_owned()])
        );
        assert_eq!(c.output.wait_for_ms, 100);
        assert_eq!(c.fetch.timeout_ms, 5000);
        assert!(c.fetch.skip_tls_verification);
        assert_eq!(c.fetch.extra_headers.get("x-token"), Some("s3"));
        assert_eq!(c.fetch.user_agent.as_deref(), Some("bot/1"));
        assert_eq!(c.fetch.cookies.len(), 1);
        assert_eq!(c.retention.mode, RetentionMode::Zdr);
        let bad = parse(&json!({ "headers": { "Cookie": "nameless" } })).unwrap();
        let e = bad.apply(&mut c, JobKind::Scrape).unwrap_err();
        assert_eq!(e[0].path, "/headers/Cookie");
    }

    #[test]
    fn apply_keeps_batch_urls_and_webhook() {
        let p = parse(&json!({})).unwrap();
        let mut c = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        let mut job = ScrapeJob::new(JobKind::Batch, ScrapeOptions::default());
        job.urls.push(url::Url::parse("https://b.test/").unwrap());
        job.webhook_metadata = json!({ "k": 1 });
        c.scrape = Some(job);
        p.apply(&mut c, JobKind::Batch).unwrap();
        let job = c.scrape.unwrap();
        assert_eq!(job.urls.len(), 1);
        assert_eq!(job.webhook_metadata, json!({ "k": 1 }));
    }

    #[test]
    fn actions_parse_and_validate() {
        let p = parse(&json!({ "actions": [
            { "type": "wait", "milliseconds": 100 },
            { "type": "wait", "selector": "#a" },
            { "type": "click", "selector": "#b", "all": true },
            { "type": "write", "text": "t" },
            { "type": "press", "key": "Enter" },
            { "type": "scroll" },
            { "type": "scroll", "direction": "up", "selector": "#c" },
            { "type": "screenshot", "fullPage": true, "quality": 50 },
            { "type": "scrape" },
            { "type": "executeJavascript", "script": "1+1" },
            { "type": "pdf", "format": "A4", "landscape": true, "scale": 1.5 },
        ] }))
        .unwrap();
        assert_eq!(p.options.actions.len(), 11);
        assert!(matches!(
            p.options.actions[5],
            ScrapeAction::Scroll {
                direction: ScrollDirection::Down,
                selector: None
            }
        ));
        let e = parse(&json!({ "actions": [{ "type": "wait", "milliseconds": 61000 }] })).unwrap_err();
        assert_eq!(e[0].path, "/actions", "{e:?}");
        let e = parse(&json!({ "actions": [{ "type": "pdf", "format": "B7" }] })).unwrap_err();
        assert_eq!(e[0].path, "/actions/0/format");
    }

    #[test]
    fn selector_wait_states_parse_and_reject_invalid_values() {
        for (wire, expected) in [
            ("attached", SelectorState::Attached),
            ("visible", SelectorState::Visible),
            ("hidden", SelectorState::Hidden),
            ("detached", SelectorState::Detached),
        ] {
            let parsed = parse(&json!({
                "actions": [{"type": "wait", "selector": "#ready", "state": wire}]
            }))
            .unwrap();
            assert!(matches!(
                parsed.options.actions[0],
                ScrapeAction::Wait { state, .. } if state == expected
            ));
        }
        let parsed = parse(&json!({
            "actions": [{"type": "wait", "selector": "#ready"}]
        }))
        .unwrap();
        assert!(matches!(
            parsed.options.actions[0],
            ScrapeAction::Wait {
                state: SelectorState::Attached,
                ..
            }
        ));
        for state in [json!("unknown"), json!(null), json!(1)] {
            let errors = parse(&json!({
                "actions": [{"type": "wait", "selector": "#ready", "state": state}]
            }))
            .unwrap_err();
            assert_eq!(errors[0].path, "/actions/0/state");
        }
        let errors = parse(&json!({
            "actions": [{"type": "wait", "milliseconds": 1, "state": "visible"}]
        }))
        .unwrap_err();
        assert_eq!(errors[0].path, "/actions/0/state");
    }

    #[test]
    fn interactive_actions_raise_the_profile_and_warn_once() {
        for action in [
            json!({ "type": "click", "selector": "a" }),
            json!({ "type": "write", "text": "t" }),
            json!({ "type": "press", "key": "Enter" }),
        ] {
            let p = parse(&json!({ "actions": [action, { "type": "wait", "milliseconds": 5 }] })).unwrap();
            let warned: Vec<&str> = p.warnings.iter().map(|w| w.code.as_str()).collect();
            assert_eq!(warned, ["actions_profile_raised"]);
            assert_eq!(p.warnings[0].path, "/actions");
            let mut c = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
            p.apply(&mut c, JobKind::Scrape).unwrap();
            assert_eq!(c.safety.profile, SafetyProfile::TestEnvironment);
            assert_eq!(
                c.safety.destructive_actions,
                crawlx_core::config::DestructiveActions::Deny
            );
        }
        let quiet = parse(&json!({ "actions": [
            { "type": "wait", "milliseconds": 5 }, { "type": "scroll" }, { "type": "screenshot" },
            { "type": "scrape" }, { "type": "executeJavascript", "script": "1" }, { "type": "pdf" }
        ] }))
        .unwrap();
        assert!(quiet.warnings.is_empty());
        let mut c = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        quiet.apply(&mut c, JobKind::Scrape).unwrap();
        assert_eq!(c.safety.profile, SafetyProfile::ReadOnly);
        let nested = parse_scrape_options(
            json!({ "actions": [{ "type": "click", "selector": "a" }] })
                .as_object()
                .unwrap(),
            "/scrapeOptions",
        )
        .unwrap();
        assert_eq!(nested.warnings[0].path, "/scrapeOptions/actions");
    }
    #[test]
    fn native_content_policy_is_validated_and_reaches_the_actual_extractor() {
        use crawlx_core::extraction::QualityStatusV1;
        let parsed = parse(&json!({ "contentPolicy": {
            "version": 1, "minMainChars": 1000, "comments": "separate",
            "referenceDate": "2026-11-04"
        }}))
        .unwrap();
        let mut request = CreateCrawl::new(url::Url::parse("https://fixture.test/article").unwrap());
        parsed.apply(&mut request, JobKind::Scrape).unwrap();
        let document = crawlx_extract::Extractor::extract(
            "<article><p>The town has opened a new library, and residents can borrow books from this morning.</p></article>",
            &request.seed_url,
            &crawlx_extract::ExtractOptions { content: request.extract.content.clone(),
                ..crawlx_extract::ExtractOptions::default() },
        ).unwrap();
        assert_eq!(
            document.article.unwrap().quality.status,
            QualityStatusV1::Rejected
        );
        assert!(parsed.warnings.is_empty());
        for policy in [
            json!({"version": 2}),
            json!({"minMainChars": 9, "maxOutputChars": 8}),
            json!({"keywords": 36}),
            json!({"hiddenRemoteFallback": true}),
            json!({"dateTimezone": "Not/A_Timezone"}),
            json!({"selectors": {"include": [{"kind": "css", "expression": "["}]}}),
            json!({"selectors": {"readMore": [{"kind": "xpath", "expression": "//missing:article"}]}}),
        ] {
            assert!(parse(&json!({"contentPolicy": policy})).is_err());
        }
        assert!(parse(&json!({})).unwrap().options.content_policy.is_none());
    }
}
