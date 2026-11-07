//! The Firecrawl `branding` format: a `BrandingProfile` read from a page's markup and styles.
//!
//! [`branding`] is a pure, deterministic heuristic; it never renders the page. Inputs are the
//! page HTML (its `<style>` blocks, `style=""` attributes, `<meta>` and `<link>` tags, logo-like
//! `<img>` elements) and the text of external stylesheets the caller fetched
//! ([`stylesheet_urls`] lists the ones worth fetching). The result is a JSON object with the
//! documented `BrandingProfile` fields; a field is absent when nothing in the page supports it:
//!
//! * `colorScheme` (`light`/`dark`): from the background colour's brightness, else a dark hint
//!   (`color-scheme`, `<meta name=color-scheme>`, `data-theme`/`class` on `<html>`), else `light`
//!   (the user-agent default canvas);
//! * `colors`: `primary`, `secondary`, `accent`, `background`, `textPrimary`, `textSecondary`,
//!   `link`, `success`, `warning`, `error`: from custom properties (`--primary`, `--brand`,
//!   `--bg`, `--text`, ...), `<meta name=theme-color>`, the rules of `body`/`a`/buttons and the
//!   frequency of saturated colours; every colour is upper-case `#RRGGBB`;
//! * `fonts` and `typography` (`fontFamilies`, `fontSizes`, `fontWeights`, `lineHeights`): from
//!   `font-family`/`font-size`/`font-weight`/`line-height` declarations (and Google Fonts
//!   links), ranked by use; `rem`/`em` sizes are converted to `px`;
//! * `spacing` (`baseUnit`, `borderRadius`), `components` (`buttonPrimary`, `buttonSecondary`,
//!   `input`), `animations`, `layout`, `icons`, `personality`;
//! * `logo` and `images` (`logo`, `favicon`, `ogImage`): absolute URLs. The logo is the best
//!   logo-like `<img>` (header and home-link images first, logo walls last), then the
//!   largest `apple-touch-icon`, then the favicon, then `og:image`.
//!
//! A page rendered in a browser can also hand over what `getComputedStyle` reported
//! ([`ComputedStyles`], collected by [`COLLECT_SCRIPT`]); [`branding_computed`] reads it as the
//! ground truth of what the page paints (canvas and text colours, link colour, fonts, sizes,
//! button and input looks, border radius, icon links) over what the stylesheets declare, and
//! falls back to the markup and stylesheet heuristics above for everything it does not report.
//!
//! Resource bounds: stylesheets are read up to 2 MiB each, at most 16 external stylesheets, 64
//! `<style>` blocks and 2000 inline styles are used, and rule and tally counts are capped.

mod color;
mod computed;
mod css;
mod style;

use scraper::{ElementRef, Html};
use serde_json::{json, Map, Value};
use url::Url;

use self::color::{parse_paint, Paint, Rgb};
use self::css::{Rule, Sheet};
use self::style::Facts;
use crate::dom::{resolve, srcset_urls, walk};
use crate::metadata::effective_base;
use crate::ExtractOptions;

pub use self::computed::{ComputedStyles, ElementStyle, LinkedIcon, COLLECT_SCRIPT};

/// Most external stylesheets read.
pub const MAX_STYLESHEETS: usize = 16;
/// Most stylesheet URLs [`stylesheet_urls`] returns.
pub const MAX_STYLESHEET_URLS: usize = 64;
/// Most `<style>` blocks read.
const MAX_STYLE_TAGS: usize = 64;
/// Most `style=""` attributes read.
const MAX_INLINE_STYLES: usize = 2000;
/// Most font families listed.
const MAX_FONTS: usize = 8;
/// Most `theme-color` metas, icon links and font-host families kept by the page scan.
const MAX_PAGE_ITEMS: usize = 64;

/// Input of [`branding`].
#[derive(Debug, Clone, Copy)]
pub struct BrandingInput<'a> {
    /// Page HTML.
    pub html: &'a str,
    /// Page URL; `<base href>` in the document refines it.
    pub base: &'a Url,
    /// Text of external stylesheets, in document order (see [`stylesheet_urls`]); at most
    /// [`MAX_STYLESHEETS`] are read.
    pub stylesheets: &'a [String],
}

/// `rel=stylesheet` (and `rel=preload as=style`) URLs of `html`: absolute, `http`/`https` only,
/// de-duplicated, in document order, at most [`MAX_STYLESHEET_URLS`]; `media=print` sheets and
/// disabled links are skipped. `<base href>` is honoured. Input beyond the default extraction
/// limits yields an empty list. The parse is not charged to [`crate::parse_budget`]: callers hold
/// a [`crate::parse_budget::charge`] around this call.
#[must_use]
pub fn stylesheet_urls(html: &str, base: &Url) -> Vec<Url> {
    if crate::precheck(html, &ExtractOptions::default()).is_err() {
        return Vec::new();
    }
    let doc = Html::parse_document(html);
    let base = effective_base(&doc, base);
    let mut out: Vec<Url> = Vec::new();
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "link" => {
                let rel = v.attr("rel").unwrap_or("").to_ascii_lowercase();
                let rels: Vec<&str> = rel.split_whitespace().collect();
                let sheet = rels.contains(&"stylesheet")
                    || (rels.contains(&"preload")
                        && v.attr("as").is_some_and(|a| a.eq_ignore_ascii_case("style")));
                let print = v
                    .attr("media")
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("print"));
                if sheet && !print && v.attr("disabled").is_none() && out.len() < MAX_STYLESHEET_URLS {
                    if let Some(mut u) = v.attr("href").and_then(|h| resolve(&base, h)) {
                        if matches!(u.scheme(), "http" | "https") {
                            u.set_fragment(None);
                            if !out.contains(&u) {
                                out.push(u);
                            }
                        }
                    }
                }
                false
            }
            "script" | "style" | "template" => false,
            _ => true,
        }
    });
    out
}

/// A `<link rel=icon|apple-touch-icon>` candidate.
struct IconLink {
    url: String,
    area: u32,
}

/// An icon library seen in class names: (library, style, elements).
type IconHit = (&'static str, Option<&'static str>, u32);

#[derive(Default)]
struct Scan {
    sheet: Sheet,
    style_tags: usize,
    inline_styles: usize,
    theme: Vec<(Option<String>, Paint)>,
    meta_color_scheme: Option<String>,
    dark_hint: bool,
    body_bgcolor: Option<Rgb>,
    body_text: Option<Rgb>,
    google_fonts: Vec<String>,
    logo: Option<(i32, String)>,
    icons: Vec<IconLink>,
    apple: Vec<IconLink>,
    og_image: Option<String>,
    icon_hits: Vec<IconHit>,
}

const IMG_SRC_ATTRS: [&str; 4] = ["src", "data-src", "data-original", "data-lazy-src"];
const LOGO_WALL_WORDS: [&str; 19] = [
    "partner",
    "client",
    "customer",
    "sponsor",
    "trusted",
    "testimonial",
    "press",
    "featured",
    "brands",
    "logos",
    "logo-wall",
    "logo-cloud",
    "logo-grid",
    "logo-strip",
    "logo-list",
    "logo-slider",
    "logo-carousel",
    "integration",
    "as-seen",
];

fn http_url(base: &Url, raw: &str) -> Option<String> {
    let mut u = resolve(base, raw)?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.set_fragment(None);
    Some(u.into())
}

fn img_url(el: &scraper::node::Element, base: &Url) -> Option<String> {
    IMG_SRC_ATTRS
        .iter()
        .filter_map(|a| el.attr(a))
        .find_map(|s| http_url(base, s))
        .or_else(|| {
            ["srcset", "data-srcset"]
                .iter()
                .filter_map(|a| el.attr(a))
                .find_map(|s| srcset_urls(s).into_iter().find_map(|u| http_url(base, u)))
        })
}

fn lower_attr(el: &scraper::node::Element, name: &str) -> String {
    el.attr(name).unwrap_or("").to_ascii_lowercase()
}

/// How logo-like an `<img>` is; `None` when it is not a logo candidate at all.
fn logo_score(el: ElementRef<'_>, base: &Url) -> Option<i32> {
    let v = el.value();
    let (class, id, alt) = (lower_attr(v, "class"), lower_attr(v, "id"), lower_attr(v, "alt"));
    let src = IMG_SRC_ATTRS
        .iter()
        .find_map(|a| v.attr(a))
        .unwrap_or("")
        .to_ascii_lowercase();
    let file = src.split(['?', '#']).next().unwrap_or("");
    let file = file.rsplit('/').next().unwrap_or(file);
    let named = class.contains("logo") || id.contains("logo") || alt.contains("logo");
    if !named && !file.contains("logo") {
        return None;
    }
    let mut score = if named { 10 } else { 6 };
    let wall = |s: &str| LOGO_WALL_WORDS.iter().any(|w| s.contains(w));
    if wall(&class) || wall(&id) || wall(&alt) {
        score -= 20;
    }
    let (mut in_header, mut in_footer, mut home_link) = (false, false, false);
    for a in el.ancestors().filter_map(ElementRef::wrap).take(24) {
        let av = a.value();
        let (aclass, aid) = (lower_attr(av, "class"), lower_attr(av, "id"));
        match av.name() {
            "header" | "nav" => in_header = true,
            "footer" => in_footer = true,
            "a" => {
                let href = av.attr("href").unwrap_or("").trim();
                let to_home = href == "/"
                    || resolve(base, href).is_some_and(|u| {
                        u.path() == "/" && u.query().is_none() && u.host_str() == base.host_str()
                    });
                home_link |= to_home || aclass.contains("logo") || aclass.contains("brand");
            }
            _ => {}
        }
        if lower_attr(av, "role") == "banner" {
            in_header = true;
        }
        if wall(&aclass) || wall(&aid) {
            score -= 20;
        }
    }
    score += 5 * i32::from(in_header) + 3 * i32::from(home_link) - 8 * i32::from(in_footer);
    Some(score)
}

fn icon_sizes(sizes: Option<&str>, mime: Option<&str>) -> u32 {
    let svg = mime.is_some_and(|m| m.contains("svg"));
    match sizes.map(|s| s.trim().to_ascii_lowercase()) {
        Some(s) if s == "any" => 1_000_000,
        Some(s) => s
            .split_whitespace()
            .filter_map(|p| {
                let (w, h) = p.split_once('x')?;
                w.parse::<u32>().ok()?.checked_mul(h.parse::<u32>().ok()?)
            })
            .max()
            .unwrap_or(0),
        None if svg => 1_000_000,
        None => 0,
    }
}

fn best_icon(icons: &[IconLink]) -> Option<&str> {
    let mut best: Option<&IconLink> = None;
    for i in icons {
        if best.is_none_or(|b| i.area > b.area) {
            best = Some(i);
        }
    }
    best.map(|i| i.url.as_str())
}

fn is_font_host(u: &Url) -> bool {
    matches!(
        u.host_str(),
        Some("fonts.googleapis.com" | "fonts.bunny.net" | "fonts.googleapis.cn")
    )
}

/// Families named by a Google Fonts (CSS API v1 or v2) URL.
fn google_families(u: &Url) -> Vec<String> {
    u.query_pairs()
        .filter(|(k, _)| k == "family")
        .flat_map(|(_, v)| v.split('|').map(str::to_owned).collect::<Vec<_>>())
        .filter_map(|f| {
            let name = f.split(':').next().unwrap_or("").trim().to_owned();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

fn note_icon_class(hits: &mut Vec<IconHit>, class: &str) {
    for tok in class.split_whitespace() {
        let hit: Option<(&'static str, Option<&'static str>)> = match tok {
            "fa-solid" | "fas" => Some(("font-awesome", Some("solid"))),
            "fa-regular" | "far" => Some(("font-awesome", Some("regular"))),
            "fa-brands" | "fab" => Some(("font-awesome", Some("brands"))),
            "material-icons" => Some(("material-icons", Some("filled"))),
            "material-icons-outlined" | "material-symbols-outlined" => {
                Some(("material-icons", Some("outlined")))
            }
            "material-icons-round" | "material-symbols-rounded" => Some(("material-icons", Some("rounded"))),
            "feather" => Some(("feather", Some("outline"))),
            "lucide" => Some(("lucide", Some("outline"))),
            t if t.starts_with("bi-") => Some(("bootstrap-icons", None)),
            t if t.starts_with("ri-") => Some(("remixicon", None)),
            t if t.starts_with("ti-") => Some(("tabler-icons", Some("outline"))),
            t if t.starts_with("ion-") => Some(("ionicons", None)),
            _ => None,
        };
        if let Some((lib, st)) = hit {
            match hits.iter_mut().find(|h| h.0 == lib && h.1 == st) {
                Some(h) => h.2 += 1,
                None => hits.push((lib, st, 1)),
            }
        }
    }
}

fn dark_word(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w == "dark")
}

fn scan_page(doc: &Html, base: &Url, scan: &mut Scan) {
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "html" => {
                let hint = [
                    "class",
                    "data-theme",
                    "data-bs-theme",
                    "data-color-mode",
                    "data-mode",
                ]
                .iter()
                .any(|a| dark_word(&lower_attr(v, a)));
                scan.dark_hint |= hint;
            }
            "body" => {
                let paint = |a: &str| match v.attr(a).and_then(parse_paint) {
                    Some(Paint::Color(c)) => Some(c),
                    _ => None,
                };
                scan.body_bgcolor = paint("bgcolor");
                scan.body_text = paint("text");
                scan.dark_hint |= dark_word(&lower_attr(v, "class"));
            }
            "meta" => {
                let name = v
                    .attr("name")
                    .or_else(|| v.attr("property"))
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                let content = v.attr("content").unwrap_or("").trim();
                match name.as_str() {
                    "theme-color" | "msapplication-tilecolor" | "msapplication-navbutton-color" => {
                        if let Some(p) = parse_paint(content).filter(|_| scan.theme.len() < MAX_PAGE_ITEMS) {
                            scan.theme.push((v.attr("media").map(str::to_ascii_lowercase), p));
                        }
                    }
                    "color-scheme" | "supported-color-schemes" => {
                        scan.meta_color_scheme
                            .get_or_insert_with(|| content.to_ascii_lowercase());
                    }
                    "og:image" | "og:image:url" | "og:image:secure_url" if scan.og_image.is_none() => {
                        scan.og_image = http_url(base, content);
                    }
                    _ => {}
                }
                return false;
            }
            "link" => {
                let rel = lower_attr(v, "rel");
                let rels: Vec<&str> = rel.split_whitespace().collect();
                if let Some(href) = v.attr("href") {
                    if let Some(u) = resolve(base, href) {
                        if is_font_host(&u) && scan.google_fonts.len() < MAX_PAGE_ITEMS {
                            scan.google_fonts.extend(google_families(&u));
                        }
                    }
                    if let Some(url) = http_url(base, href) {
                        let area = icon_sizes(v.attr("sizes"), v.attr("type"));
                        if rels.iter().any(|r| r.starts_with("apple-touch-icon")) {
                            if scan.apple.len() < MAX_PAGE_ITEMS {
                                scan.apple.push(IconLink { url, area });
                            }
                        } else if rels.contains(&"icon") && scan.icons.len() < MAX_PAGE_ITEMS {
                            scan.icons.push(IconLink { url, area });
                        }
                    }
                }
                return false;
            }
            "style" => {
                if scan.style_tags < MAX_STYLE_TAGS {
                    scan.style_tags += 1;
                    let text: String = el.text().collect();
                    css::parse(&text, &mut scan.sheet);
                }
                return false;
            }
            "script" | "template" | "noscript" => return false,
            "img" => {
                if let Some(score) = logo_score(el, base) {
                    if scan.logo.as_ref().is_none_or(|(best, _)| score > *best) {
                        if let Some(url) = img_url(v, base) {
                            scan.logo = Some((score, url));
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some(class) = v.attr("class") {
            note_icon_class(&mut scan.icon_hits, &class.to_ascii_lowercase());
        }
        if v.attr("data-feather").is_some() {
            note_icon_class(&mut scan.icon_hits, "feather");
        }
        if v.attr("data-lucide").is_some() {
            note_icon_class(&mut scan.icon_hits, "lucide");
        }
        if let Some(inline) = v.attr("style") {
            if scan.inline_styles < MAX_INLINE_STYLES && scan.sheet.rules.len() < css::MAX_RULES {
                scan.inline_styles += 1;
                let decls = css::parse_declarations(inline);
                if !decls.is_empty() {
                    let mut selector = v.name().to_owned();
                    for c in v.classes().take(4) {
                        selector.push('.');
                        selector.push_str(&c.to_ascii_lowercase());
                    }
                    scan.sheet.rules.push(Rule {
                        selectors: vec![selector],
                        decls,
                        dark: false,
                    });
                }
            }
        }
        true
    });
}

fn paint_rgb(s: Option<&str>) -> Option<Rgb> {
    match s.and_then(parse_paint)? {
        Paint::Color(c) => Some(c),
        Paint::Transparent => None,
    }
}

/// Colours of the profile.
struct Palette {
    primary: Option<Rgb>,
    secondary: Option<Rgb>,
    accent: Option<Rgb>,
    background: Option<Rgb>,
    text_primary: Option<Rgb>,
    text_secondary: Option<Rgb>,
    link: Option<Rgb>,
    success: Option<Rgb>,
    warning: Option<Rgb>,
    error: Option<Rgb>,
}

fn theme_color(scan: &Scan) -> Option<Rgb> {
    let light = |m: &Option<String>| m.as_deref().is_none_or(|m| !m.contains("dark"));
    scan.theme
        .iter()
        .filter(|(m, _)| light(m))
        .chain(scan.theme.iter())
        .find_map(|(_, p)| match p {
            Paint::Color(c) => Some(*c),
            Paint::Transparent => None,
        })
}

fn palette(scan: &Scan, f: &Facts) -> Palette {
    let r = &f.roles;
    let background = r.background.or(f.body_bg).or(scan.body_bgcolor);
    let differs = |c: Rgb, o: Option<Rgb>| o.is_none_or(|o| c.differs_from(o));
    let text_primary = r
        .text_primary
        .or(f.body_color)
        .or(scan.body_text)
        .or_else(|| f.text_ranked.iter().copied().find(|c| differs(*c, background)));
    let text_secondary = r.text_secondary.or_else(|| {
        f.text_ranked
            .iter()
            .copied()
            .find(|c| c.is_neutral() && differs(*c, background) && differs(*c, text_primary))
    });
    let link = r.link.or(f.link_color);
    let success = r.success.or(f.success);
    let warning = r.warning.or(f.warning);
    let error = r.error.or(f.error);
    let semantic = [success, warning, error];
    let candidates = |taken: &[Option<Rgb>]| {
        f.pool
            .iter()
            .copied()
            .filter(|c| differs(*c, background))
            .filter(|c| semantic.iter().all(|s| differs(*c, *s)))
            .find(|c| taken.iter().all(|t| differs(*c, *t)))
    };
    let primary = r
        .primary
        .or_else(|| theme_color(scan).filter(|c| !c.is_neutral() && differs(*c, background)))
        .or_else(|| paint_rgb(f.button_primary.background.as_deref()).filter(|c| differs(*c, background)))
        .or_else(|| candidates(&[]))
        .or_else(|| link.filter(|c| !c.is_neutral()));
    let secondary = r.secondary.or_else(|| candidates(&[primary]));
    let accent = r.accent.or_else(|| candidates(&[primary, secondary]));
    Palette {
        primary,
        secondary,
        accent,
        background,
        text_primary,
        text_secondary,
        link,
        success,
        warning,
        error,
    }
}

fn colors_json(p: &Palette) -> Value {
    let mut m = Map::new();
    for (key, c) in [
        ("primary", p.primary),
        ("secondary", p.secondary),
        ("accent", p.accent),
        ("background", p.background),
        ("textPrimary", p.text_primary),
        ("textSecondary", p.text_secondary),
        ("link", p.link),
        ("success", p.success),
        ("warning", p.warning),
        ("error", p.error),
    ] {
        if let Some(c) = c {
            m.insert(key.to_owned(), json!(c.hex()));
        }
    }
    Value::Object(m)
}

fn color_scheme(scan: &Scan, f: &Facts, background: Option<Rgb>) -> &'static str {
    if let Some(bg) = background {
        return if bg.brightness() < 128 { "dark" } else { "light" };
    }
    let meta_dark = scan.meta_color_scheme.as_deref().is_some_and(|s| {
        let words: Vec<&str> = s.split_whitespace().collect();
        words.contains(&"dark") && !words.contains(&"light") && !words.contains(&"normal")
    });
    if f.dark_scheme || scan.dark_hint || meta_dark {
        "dark"
    } else {
        "light"
    }
}

const SERIF_HINTS: [&str; 16] = [
    "georgia",
    "times",
    "playfair",
    "merriweather",
    "lora",
    "garamond",
    "baskerville",
    "cambria",
    "palatino",
    "serif display",
    "source serif",
    "pt serif",
    "crimson",
    "cormorant",
    "noto serif",
    "spectral",
];
const MONO_HINTS: [&str; 8] = [
    "mono",
    "courier",
    "consolas",
    "menlo",
    "fira code",
    "jetbrains",
    "source code",
    "code",
];
const SANS_HINTS: [&str; 22] = [
    "inter",
    "roboto",
    "helvetica",
    "arial",
    "open sans",
    "lato",
    "montserrat",
    "poppins",
    "segoe ui",
    "sf pro",
    "nunito",
    "work sans",
    "dm sans",
    "plex sans",
    "source sans",
    "noto sans",
    "raleway",
    "ubuntu",
    "manrope",
    "figtree",
    "geist",
    "outfit",
];

/// Voice of the typography: `traditional` (serif), `technical` (monospace) or `modern` (sans).
fn tone(font: &str) -> Option<&'static str> {
    let f = font.to_ascii_lowercase();
    if MONO_HINTS.iter().any(|h| f.contains(h)) {
        Some("technical")
    } else if SERIF_HINTS.iter().any(|h| f.contains(h)) {
        Some("traditional")
    } else if SANS_HINTS.iter().any(|h| f.contains(h)) {
        Some("modern")
    } else {
        None
    }
}

/// Energy of the palette: saturation and lightness of the primary colour.
fn energy(primary: Rgb) -> &'static str {
    let (s, l) = (primary.saturation(), primary.lightness());
    if s >= 0.7 && (0.3..=0.75).contains(&l) {
        "high"
    } else if s >= 0.35 {
        "medium"
    } else {
        "low"
    }
}

fn put<V: Into<Value>>(m: &mut Map<String, Value>, key: &str, v: Option<V>) {
    if let Some(v) = v {
        m.insert(key.to_owned(), v.into());
    }
}

fn non_empty(m: Map<String, Value>) -> Option<Value> {
    (!m.is_empty()).then_some(Value::Object(m))
}

fn typography(f: &Facts, fonts: &[String]) -> Option<Value> {
    let mut t = Map::new();
    let primary = f
        .body_font
        .clone()
        .or_else(|| fonts.iter().find(|x| Some(*x) != f.code_font.as_ref()).cloned());
    let mut fam = Map::new();
    put(&mut fam, "primary", primary.clone());
    put(&mut fam, "heading", f.heading_font.clone().or(primary));
    put(&mut fam, "code", f.code_font.clone());
    if let Some(v) = non_empty(fam) {
        t.insert("fontFamilies".to_owned(), v);
    }
    let sizes: Map<String, Value> = f
        .font_sizes
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect();
    if let Some(v) = non_empty(sizes) {
        t.insert("fontSizes".to_owned(), v);
    }
    let weights: Map<String, Value> = f
        .font_weights
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect();
    if let Some(v) = non_empty(weights) {
        t.insert("fontWeights".to_owned(), v);
    }
    let lines: Map<String, Value> = f
        .line_heights
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    if let Some(v) = non_empty(lines) {
        t.insert("lineHeights".to_owned(), v);
    }
    non_empty(t)
}

fn merged_fonts(scan: &Scan, f: &Facts) -> Vec<String> {
    let mut fonts: Vec<String> = Vec::new();
    for name in f.fonts.iter().chain(&scan.google_fonts) {
        if fonts.len() >= MAX_FONTS {
            break;
        }
        if !fonts.iter().any(|x| x.eq_ignore_ascii_case(name)) {
            fonts.push(name.clone());
        }
    }
    fonts.truncate(MAX_FONTS);
    fonts
}

fn motion_and_layout(f: &Facts, out: &mut Map<String, Value>) {
    let mut anim = Map::new();
    put(&mut anim, "transitionDuration", f.transition_duration.clone());
    put(&mut anim, "easing", f.easing.clone());
    if !f.keyframes.is_empty() {
        anim.insert("keyframes".to_owned(), json!(f.keyframes));
    }
    if let Some(v) = non_empty(anim) {
        out.insert("animations".to_owned(), v);
    }
    let mut grid = Map::new();
    put(&mut grid, "columns", f.columns);
    put(&mut grid, "maxWidth", f.max_width.clone());
    let mut layout = Map::new();
    if let Some(v) = non_empty(grid) {
        layout.insert("grid".to_owned(), v);
    }
    put(&mut layout, "headerHeight", f.header_height.clone());
    put(&mut layout, "footerHeight", f.footer_height.clone());
    if let Some(v) = non_empty(layout) {
        out.insert("layout".to_owned(), v);
    }
}

/// The brand profile of the page described by `input` (Firecrawl `BrandingProfile` shape).
/// Input beyond the default extraction limits yields an empty object. The parse is not charged
/// to [`crate::parse_budget`]: callers hold a [`crate::parse_budget::charge`] around this call.
#[must_use]
pub fn branding(input: &BrandingInput<'_>) -> Value {
    profile(input, None)
}

/// As [`branding`] for a page rendered in a browser: `computed` (what [`COLLECT_SCRIPT`]
/// reported, see [`ComputedStyles::from_value`]) is read as the ground truth of what the page
/// paints, over what the stylesheets declare. An empty report changes nothing.
#[must_use]
pub fn branding_computed(input: &BrandingInput<'_>, computed: &ComputedStyles) -> Value {
    profile(input, Some(computed))
}

fn profile(input: &BrandingInput<'_>, computed: Option<&ComputedStyles>) -> Value {
    if crate::precheck(input.html, &ExtractOptions::default()).is_err() {
        return json!({});
    }
    let doc = Html::parse_document(input.html);
    let base = effective_base(&doc, input.base);
    let mut scan = Scan::default();
    for sheet in input.stylesheets.iter().take(MAX_STYLESHEETS) {
        css::parse(sheet, &mut scan.sheet);
    }
    scan_page(&doc, &base, &mut scan);
    // the browser's own reading comes after every stylesheet rule
    let observed = computed.map(|c| {
        let read = computed::analyze(c);
        scan.sheet.rules.extend(read.rules);
        computed::merge_assets(c, &base, &mut scan);
        read.observed
    });
    let mut facts = style::analyze(&scan.sheet);
    if let Some(observed) = &observed {
        observed.apply(&mut facts);
    }

    let pal = palette(&scan, &facts);
    let fonts = merged_fonts(&scan, &facts);
    let mut out = Map::new();
    out.insert(
        "colorScheme".to_owned(),
        json!(color_scheme(&scan, &facts, pal.background)),
    );
    if let Some(c) = non_empty(match colors_json(&pal) {
        Value::Object(m) => m,
        _ => Map::new(),
    }) {
        out.insert("colors".to_owned(), c);
    }
    if !fonts.is_empty() {
        out.insert(
            "fonts".to_owned(),
            Value::Array(fonts.iter().map(|f| json!({ "family": f })).collect()),
        );
    }
    if let Some(t) = typography(&facts, &fonts) {
        out.insert("typography".to_owned(), t);
    }
    let mut spacing = Map::new();
    put(&mut spacing, "baseUnit", facts.base_unit);
    put(&mut spacing, "borderRadius", facts.border_radius.clone());
    if let Some(v) = non_empty(spacing) {
        out.insert("spacing".to_owned(), v);
    }
    let mut components = Map::new();
    for (key, c) in [
        ("buttonPrimary", &facts.button_primary),
        ("buttonSecondary", &facts.button_secondary),
        ("input", &facts.input),
    ] {
        if !c.is_empty() {
            components.insert(key.to_owned(), c.to_json());
        }
    }
    if let Some(v) = non_empty(components) {
        out.insert("components".to_owned(), v);
    }
    motion_and_layout(&facts, &mut out);

    // Most used icon library (first seen wins ties).
    let mut best: Option<&IconHit> = None;
    for h in &scan.icon_hits {
        if best.is_none_or(|b| h.2 > b.2) {
            best = Some(h);
        }
    }
    if let Some((lib, st, _)) = best {
        let mut icons = Map::new();
        icons.insert("library".to_owned(), json!(lib));
        put(&mut icons, "style", st.map(str::to_owned));
        out.insert("icons".to_owned(), Value::Object(icons));
    }

    let favicon = best_icon(&scan.icons)
        .or_else(|| best_icon(&scan.apple))
        .map(str::to_owned);
    let logo = scan
        .logo
        .as_ref()
        .map(|(_, u)| u.clone())
        .or_else(|| best_icon(&scan.apple).map(str::to_owned))
        .or_else(|| favicon.clone())
        .or_else(|| scan.og_image.clone());
    put(&mut out, "logo", logo.clone());
    let mut images = Map::new();
    put(&mut images, "logo", logo);
    put(&mut images, "favicon", favicon);
    put(&mut images, "ogImage", scan.og_image.clone());
    if let Some(v) = non_empty(images) {
        out.insert("images".to_owned(), v);
    }

    let mut personality = Map::new();
    let voice = facts
        .heading_font
        .as_deref()
        .or(facts.body_font.as_deref())
        .or(fonts.first().map(String::as_str));
    put(&mut personality, "tone", voice.and_then(tone));
    put(&mut personality, "energy", pal.primary.map(energy));
    if let Some(v) = non_empty(personality) {
        out.insert("personality".to_owned(), v);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const FIXTURE: &str = r##"<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8">
  <title>Acme Rockets</title>
  <meta name="theme-color" content="#FF6B35">
  <meta property="og:image" content="/img/og-card.png">
  <link rel="icon" href="/favicon.ico" sizes="32x32">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
  <link rel="stylesheet" href="/assets/site.css">
  <link rel="stylesheet" href="https://cdn.example.net/lib.css" media="print">
  <link rel="preload" as="style" href="/assets/late.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=Roboto+Mono&display=swap" rel="stylesheet">
  <style>
    :root { --primary: #ff6b35; --secondary: #004e89; --accent: #f77f00; --bg: #1a1a1a; --text: #ffffff; --text-muted: #b0b0b0;
            --radius: 8px; }
    body { font-family: 'Inter', sans-serif; font-size: 16px; line-height: 1.5; background: var(--bg); color: var(--text); }
    h1, h2, h3 { font-family: 'Inter', sans-serif; font-weight: 700; }
    h1 { font-size: 3rem } h2 { font-size: 2.25rem } h3 { font-size: 1.5rem }
    code, pre { font-family: 'Roboto Mono', monospace; }
    a { color: #4aa3ff; }
    .btn { border-radius: 8px; padding: 8px 16px; transition: all .3s ease-in-out; }
    .btn-primary { background: var(--primary); color: #fff; }
    .btn-secondary { background: transparent; color: var(--primary); border: 1px solid var(--primary); }
    .container { max-width: 1200px; margin: 0 auto; padding: 16px 24px }
  </style>
</head><body>
  <header><a href="/"><img class="site-logo" alt="Acme logo" src="/img/acme-logo.svg"></a></header>
  <main><h1>Rockets</h1><i class="fa-solid fa-rocket"></i><i class="fa-solid fa-star"></i></main>
  <section class="partners"><img class="partner-logo" src="/img/partner.png" alt="partner logo"></section>
  <footer><img src="/img/footer-logo.png" alt="Acme logo"></footer>
</body></html>"##;

    fn base() -> Url {
        Url::parse("https://acme.example/").unwrap()
    }

    fn run(html: &str, sheets: &[String]) -> Value {
        branding(&BrandingInput {
            html,
            base: &base(),
            stylesheets: sheets,
        })
    }

    #[test]
    fn fixture_page_yields_the_documented_profile_fields() {
        let b = run(FIXTURE, &[]);
        assert_eq!(b["colorScheme"], "dark");
        assert_eq!(b["colors"]["primary"], "#FF6B35");
        assert_eq!(b["colors"]["secondary"], "#004E89");
        assert_eq!(b["colors"]["accent"], "#F77F00");
        assert_eq!(b["colors"]["background"], "#1A1A1A");
        assert_eq!(b["colors"]["textPrimary"], "#FFFFFF");
        assert_eq!(b["colors"]["textSecondary"], "#B0B0B0");
        assert_eq!(b["colors"]["link"], "#4AA3FF");
        assert_eq!(b["fonts"][0], json!({"family": "Inter"}));
        assert_eq!(b["fonts"][1], json!({"family": "Roboto Mono"}));
        assert_eq!(
            b["typography"]["fontFamilies"],
            json!({"primary": "Inter", "heading": "Inter", "code": "Roboto Mono"})
        );
        assert_eq!(
            b["typography"]["fontSizes"],
            json!({"body": "16px", "h1": "48px", "h2": "36px", "h3": "24px"})
        );
        assert_eq!(b["typography"]["fontWeights"], json!({"bold": 700}));
        assert_eq!(b["typography"]["lineHeights"], json!({"body": 1.5}));
        assert_eq!(b["spacing"], json!({"baseUnit": 8, "borderRadius": "8px"}));
        assert_eq!(
            b["components"]["buttonPrimary"],
            json!({"background": "#FF6B35", "textColor": "#FFFFFF", "borderRadius": "8px"})
        );
        assert_eq!(
            b["components"]["buttonSecondary"],
            json!({"background": "transparent", "textColor": "#FF6B35", "borderColor": "#FF6B35", "borderRadius": "8px"})
        );
        assert_eq!(
            b["animations"],
            json!({"transitionDuration": "0.3s", "easing": "ease-in-out"})
        );
        assert_eq!(b["layout"], json!({"grid": {"maxWidth": "1200px"}}));
        assert_eq!(b["icons"], json!({"library": "font-awesome", "style": "solid"}));
        assert_eq!(b["personality"], json!({"tone": "modern", "energy": "high"}));
    }

    #[test]
    fn logo_prefers_the_header_image_over_partner_walls_and_the_footer() {
        let b = run(FIXTURE, &[]);
        assert_eq!(b["logo"], "https://acme.example/img/acme-logo.svg");
        assert_eq!(
            b["images"],
            json!({
                "logo": "https://acme.example/img/acme-logo.svg",
                "favicon": "https://acme.example/favicon.svg",
                "ogImage": "https://acme.example/img/og-card.png",
            })
        );
    }

    #[test]
    fn logo_falls_back_to_touch_icon_then_favicon_then_og_image() {
        let touch = run(
            r#"<head><link rel="icon" href="/f.ico"><link rel="apple-touch-icon" href="/t.png"></head><body></body>"#,
            &[],
        );
        assert_eq!(touch["logo"], "https://acme.example/t.png");
        let fav = run(r#"<head><link rel="shortcut icon" href="/f.ico"></head>"#, &[]);
        assert_eq!(fav["logo"], "https://acme.example/f.ico");
        let og = run(
            r#"<head><meta property="og:image" content="https://cdn.example.org/o.png"></head>"#,
            &[],
        );
        assert_eq!(og["logo"], "https://cdn.example.org/o.png");
        assert!(run("<p>x</p>", &[]).get("logo").is_none());
    }

    #[test]
    fn theme_color_and_declarations_work_without_custom_properties() {
        let html = r##"<head><meta name="theme-color" content="#0a7cff"><style>
            body{background:#ffffff;color:#222222}
            a{color:#0a7cff}.cta{background:#0a7cff;color:#fff;border-radius:6px}
            .muted{color:#666666} .muted2{color:#666666}
        </style></head><body style="font-family: Georgia, serif"></body>"##;
        let b = run(html, &[]);
        assert_eq!(b["colorScheme"], "light");
        assert_eq!(b["colors"]["primary"], "#0A7CFF");
        assert_eq!(b["colors"]["background"], "#FFFFFF");
        assert_eq!(b["colors"]["textPrimary"], "#222222");
        assert_eq!(b["colors"]["textSecondary"], "#666666");
        assert_eq!(b["colors"]["link"], "#0A7CFF");
        assert_eq!(b["components"]["buttonPrimary"]["background"], "#0A7CFF");
        assert_eq!(b["fonts"][0]["family"], "Georgia");
        assert_eq!(b["personality"]["tone"], "traditional");
    }

    #[test]
    fn external_stylesheets_are_read_and_inline_styles_override_them() {
        let html = r##"<body style="background:#101010"><p>x</p></body>"##;
        let sheets = vec!["body{background:#fafafa;color:#111;font-family:Lato,sans-serif}".to_owned()];
        let b = run(html, &sheets);
        assert_eq!(b["colors"]["background"], "#101010");
        assert_eq!(b["colorScheme"], "dark");
        assert_eq!(b["fonts"][0]["family"], "Lato");
    }

    #[test]
    fn color_scheme_hints_apply_when_no_background_is_known() {
        assert_eq!(
            run(r#"<html class="dark"><body>x</body></html>"#, &[])["colorScheme"],
            "dark"
        );
        assert_eq!(
            run(r#"<head><meta name="color-scheme" content="dark"></head>"#, &[])["colorScheme"],
            "dark"
        );
        assert_eq!(
            run(
                r#"<head><meta name="color-scheme" content="light dark"></head>"#,
                &[]
            )["colorScheme"],
            "light"
        );
        assert_eq!(run("<p>nothing</p>", &[])["colorScheme"], "light");
    }

    #[test]
    fn dark_media_blocks_do_not_change_the_light_palette() {
        let b = run(
            "<style>body{background:#fff;color:#111}@media (prefers-color-scheme: dark){body{background:#000;color:#eee}}</style>",
            &[],
        );
        assert_eq!(b["colorScheme"], "light");
        assert_eq!(b["colors"]["background"], "#FFFFFF");
    }

    #[test]
    fn page_without_any_signal_is_a_minimal_profile_and_is_deterministic() {
        let b = run("<html><body><p>hello</p></body></html>", &[]);
        assert_eq!(b, json!({"colorScheme": "light"}));
        assert_eq!(run(FIXTURE, &[]), run(FIXTURE, &[]));
    }

    #[test]
    fn oversized_input_yields_an_empty_object() {
        let huge = "<i>".repeat(crate::document::DEFAULT_MAX_NODES + 1);
        assert_eq!(run(&huge, &[]), json!({}));
    }

    #[test]
    fn stylesheet_urls_are_absolute_deduplicated_and_ordered() {
        let urls = stylesheet_urls(FIXTURE, &base());
        let got: Vec<&str> = urls.iter().map(Url::as_str).collect();
        assert_eq!(
            got,
            [
                "https://acme.example/assets/site.css",
                "https://acme.example/assets/late.css",
                "https://fonts.googleapis.com/css2?family=Inter:wght@400;700&family=Roboto+Mono&display=swap",
            ]
        );
    }

    #[test]
    fn stylesheet_urls_honour_base_href_and_skip_non_http() {
        let html = r#"<head><base href="https://static.example.net/v1/">
            <link rel="stylesheet" href="a.css"><link rel="stylesheet" href="a.css#x">
            <link rel="stylesheet" href="data:text/css,a{}"><link rel="stylesheet" href="b.css" disabled></head>"#;
        let urls = stylesheet_urls(html, &base());
        assert_eq!(
            urls.iter().map(Url::as_str).collect::<Vec<_>>(),
            ["https://static.example.net/v1/a.css"]
        );
    }
}
