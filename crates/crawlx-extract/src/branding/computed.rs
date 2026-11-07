//! The browser leg's input of the `branding` format: what `getComputedStyle` reported for the
//! rendered page.
//!
//! [`COLLECT_SCRIPT`] runs in the page and answers one JSON object that parses as
//! [`ComputedStyles`] ([`ComputedStyles::from_value`]): the computed colours, font families,
//! sizes, weights and border radius of `<html>`, `<body>`, the first visible heading of each
//! level, visible links, buttons, text inputs and `code`, plus the `<link rel=icon>` /
//! `apple-touch-icon` links, the `og:image` and a logo-like header image as the browser
//! resolved them. [`super::branding_computed`] reads them as the ground truth of what the page
//! paints, over what the stylesheets declare:
//!
//! * the canvas background (`body`, else `html`), the body text colour and the dominant link
//!   colour set `colors.background`, `colors.textPrimary` and `colors.link` (and with them
//!   `colorScheme`) even when custom properties name other colours;
//! * body and heading families lead `fonts`; sizes, weights and line heights of the elements feed
//!   `typography`; the most common radius of buttons and inputs is `spacing.borderRadius`;
//! * the most common button with a coloured background is `components.buttonPrimary`, the most
//!   common other look `components.buttonSecondary`, a text input `components.input`; their
//!   backgrounds feed the primary/secondary/accent colour pool like a stylesheet rule would;
//! * icon links, the `og:image` and the logo image fill `logo` and `images` where the markup
//!   scan found none.
//!
//! The values come from the page, so they are bounded ([`ComputedStyles::from_value`] drops
//! over-long values and surplus entries) and read like any other page-supplied CSS.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::color::{parse_paint, Paint, Rgb};
use super::css::{Decl, Rule};
use super::style::{primary_family, Facts};
use super::{http_url, icon_sizes, IconLink, Scan, MAX_PAGE_ITEMS};

/// JavaScript for the page's main world (an expression): the computed styles of the page as
/// one JSON object, see [`ComputedStyles`].
pub const COLLECT_SCRIPT: &str = r#"(() => {
  const SCAN_LIMIT = 400;
  const style = (el) => getComputedStyle(el);
  const shown = (el) => {
    const s = style(el);
    return s.display !== 'none' && s.visibility !== 'hidden' && Number(s.opacity) > 0 && el.getClientRects().length > 0;
  };
  const read = (el) => {
    const s = style(el);
    return {
      tag: el.tagName.toLowerCase(),
      color: s.color,
      backgroundColor: s.backgroundColor,
      borderColor: s.borderTopColor,
      borderWidth: s.borderTopWidth,
      borderRadius: s.borderTopLeftRadius,
      fontFamily: s.fontFamily,
      fontSize: s.fontSize,
      fontWeight: s.fontWeight,
      lineHeight: s.lineHeight,
    };
  };
  const visible = (selector, limit) => {
    const out = [];
    let seen = 0;
    for (const el of document.querySelectorAll(selector)) {
      if (out.length >= limit || seen++ >= SCAN_LIMIT) break;
      if (shown(el)) out.push(read(el));
    }
    return out;
  };
  const absolute = (value) => {
    try { return new URL(value, document.baseURI).href; } catch (_) { return ''; }
  };
  const headings = [];
  for (const tag of ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']) {
    const first = visible(tag, 1);
    if (first.length) headings.push(first[0]);
  }
  const icons = [];
  const iconSelector = 'link[rel~="icon" i], link[rel~="apple-touch-icon" i], link[rel~="apple-touch-icon-precomposed" i]';
  for (const link of document.querySelectorAll(iconSelector)) {
    if (icons.length >= 32) break;
    if (link.href) {
      icons.push({
        rel: link.getAttribute('rel') || '',
        href: link.href,
        sizes: link.getAttribute('sizes') || '',
        mime: link.getAttribute('type') || '',
      });
    }
  }
  const og = document.querySelector('meta[property="og:image" i], meta[name="og:image" i]');
  let logo = '';
  for (const img of document.querySelectorAll('header img, [role="banner"] img, nav img, a[href="/"] img')) {
    const hint = [img.className, img.id, img.alt, img.currentSrc || img.src].join(' ').toLowerCase();
    if (hint.includes('logo') && shown(img)) { logo = img.currentSrc || img.src || ''; break; }
  }
  return {
    root: read(document.documentElement),
    body: document.body ? read(document.body) : {},
    headings,
    links: visible('a[href]', 64),
    buttons: visible('button, input[type="submit" i], input[type="button" i], [role="button" i], a[class*="btn" i], a[class*="button" i], a[class*="cta" i]', 32),
    inputs: visible('input:not([type]), input[type="text" i], input[type="email" i], input[type="search" i], input[type="password" i], textarea, select', 16),
    code: visible('code', 1)[0] || visible('pre', 1)[0] || {},
    icons,
    ogImage: og ? absolute(og.getAttribute('content') || '') : '',
    logo,
  };
})()"#;

/// Most headings kept (one per level).
const MAX_HEADINGS: usize = 6;
/// Most links kept.
const MAX_LINKS: usize = 64;
/// Most buttons kept.
const MAX_BUTTONS: usize = 32;
/// Most inputs kept.
const MAX_INPUTS: usize = 16;
/// Most icon links kept.
const MAX_ICONS: usize = 32;
/// Longest value kept; a longer one is dropped.
const MAX_VALUE_LEN: usize = 512;
/// A radius from this many pixels up makes a pill or a circle, not the site's corner radius.
const MAX_ROUND_PX: f32 = 999.0;

/// The computed style of one element. A field is empty when the page did not report it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct ElementStyle {
    /// Lower-case tag name (`h1`, `button`, ...).
    pub tag: String,
    /// `color` (`rgb(...)`, `rgba(...)`).
    pub color: String,
    /// `background-color`.
    pub background_color: String,
    /// `border-top-color`.
    pub border_color: String,
    /// `border-top-width` (`1px`).
    pub border_width: String,
    /// `border-top-left-radius` (`8px`).
    pub border_radius: String,
    /// `font-family`, the whole stack.
    pub font_family: String,
    /// `font-size` in pixels (`16px`).
    pub font_size: String,
    /// `font-weight` (`400`, `700`).
    pub font_weight: String,
    /// `line-height` (`24px` or `normal`).
    pub line_height: String,
}

impl ElementStyle {
    fn bound(&mut self) {
        for value in [
            &mut self.tag,
            &mut self.color,
            &mut self.background_color,
            &mut self.border_color,
            &mut self.border_width,
            &mut self.border_radius,
            &mut self.font_family,
            &mut self.font_size,
            &mut self.font_weight,
            &mut self.line_height,
        ] {
            clip(value);
        }
    }
}

/// A `<link rel=icon|apple-touch-icon>` as the browser resolved it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct LinkedIcon {
    /// The `rel` attribute.
    pub rel: String,
    /// Absolute URL (`link.href`).
    pub href: String,
    /// The `sizes` attribute (`32x32`, `any`), empty when absent.
    pub sizes: String,
    /// The `type` attribute (`image/svg+xml`), empty when absent.
    pub mime: String,
}

/// What [`COLLECT_SCRIPT`] reported.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[non_exhaustive]
pub struct ComputedStyles {
    /// `<html>`.
    pub root: ElementStyle,
    /// `<body>`.
    pub body: ElementStyle,
    /// The first visible heading of each level, `h1` first.
    pub headings: Vec<ElementStyle>,
    /// Visible links, in document order.
    pub links: Vec<ElementStyle>,
    /// Visible buttons (`<button>`, submit inputs, `role=button`, `.btn`-like links).
    pub buttons: Vec<ElementStyle>,
    /// Visible text inputs, textareas and selects.
    pub inputs: Vec<ElementStyle>,
    /// The first visible `code` element, else the first visible `pre`.
    pub code: ElementStyle,
    /// Icon links.
    pub icons: Vec<LinkedIcon>,
    /// Absolute URL of the `og:image`, empty when absent.
    pub og_image: String,
    /// Source of the first visible logo-like image of the header, empty when none.
    pub logo: String,
}

fn clip(value: &mut String) {
    if value.len() > MAX_VALUE_LEN {
        value.clear();
    }
}

impl ComputedStyles {
    /// Parse the answer of [`COLLECT_SCRIPT`]. `None` when `value` is not an object of the
    /// documented shape. Over-long values are dropped and surplus entries cut.
    #[must_use]
    pub fn from_value(value: Value) -> Option<Self> {
        if !value.is_object() {
            return None;
        }
        let mut styles: Self = serde_json::from_value(value).ok()?;
        styles.root.bound();
        styles.body.bound();
        styles.code.bound();
        for (list, max) in [
            (&mut styles.headings, MAX_HEADINGS),
            (&mut styles.links, MAX_LINKS),
            (&mut styles.buttons, MAX_BUTTONS),
            (&mut styles.inputs, MAX_INPUTS),
        ] {
            list.truncate(max);
            list.iter_mut().for_each(ElementStyle::bound);
        }
        styles.icons.truncate(MAX_ICONS);
        for icon in &mut styles.icons {
            for value in [&mut icon.rel, &mut icon.href, &mut icon.sizes, &mut icon.mime] {
                clip(value);
            }
        }
        clip(&mut styles.og_image);
        clip(&mut styles.logo);
        Some(styles)
    }
}

/// What the browser observed that overrides what the stylesheets say.
#[derive(Debug, Default)]
pub(super) struct Observed {
    background: Option<Rgb>,
    text: Option<Rgb>,
    link: Option<Rgb>,
    body_font: Option<String>,
    heading_font: Option<String>,
    radius: Option<String>,
}

impl Observed {
    /// Put the observations over `facts`.
    pub fn apply(&self, facts: &mut Facts) {
        if let Some(c) = self.background {
            facts.roles.background = Some(c);
        }
        if let Some(c) = self.text {
            facts.roles.text_primary = Some(c);
        }
        if let Some(c) = self.link {
            facts.roles.link = Some(c);
        }
        if let Some(font) = &self.heading_font {
            facts.heading_font = Some(font.clone());
        }
        if let Some(radius) = &self.radius {
            facts.border_radius = Some(radius.clone());
        }
        let mut lead: Vec<String> = Vec::new();
        for font in [&self.body_font, &self.heading_font].into_iter().flatten() {
            if !lead.iter().any(|known| known.eq_ignore_ascii_case(font)) {
                lead.push(font.clone());
            }
        }
        facts
            .fonts
            .retain(|font| !lead.iter().any(|known| known.eq_ignore_ascii_case(font)));
        lead.append(&mut facts.fonts);
        facts.fonts = lead;
    }
}

/// The computed styles as stylesheet rules (read after every stylesheet rule, so they win ties)
/// and as observations.
pub(super) struct Computed {
    pub rules: Vec<Rule>,
    pub observed: Observed,
}

fn opaque(value: &str) -> Option<Rgb> {
    match parse_paint(value)? {
        Paint::Color(c) => Some(c),
        Paint::Transparent => None,
    }
}

fn decl(prop: &str, value: &str) -> Decl {
    Decl {
        prop: prop.to_owned(),
        value: value.to_owned(),
    }
}

fn rule(selector: &str, decls: Vec<Decl>) -> Option<Rule> {
    (!decls.is_empty()).then(|| Rule {
        selectors: vec![selector.to_owned()],
        decls,
        dark: false,
    })
}

/// `24px` as 24.0.
fn px(value: &str) -> Option<f32> {
    value
        .trim()
        .strip_suffix("px")?
        .trim()
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite())
}

/// A pixel line height as the unitless ratio to the font size (`24px` at `16px` is `1.5`); any
/// other value verbatim; `normal` is no line height.
fn line_height(value: &str, font_size: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "normal" {
        return None;
    }
    match (px(value), px(font_size)) {
        (Some(line), Some(size)) if size > 0.0 => {
            let ratio = format!("{:.3}", line / size);
            Some(ratio.trim_end_matches('0').trim_end_matches('.').to_owned())
        }
        _ => Some(value.to_owned()),
    }
}

/// `color`, `font-family`, `font-size`, `font-weight` and, when asked, `line-height` of `el`.
fn text_decls(el: &ElementStyle, with_line_height: bool) -> Vec<Decl> {
    let mut out = Vec::new();
    for (prop, value) in [
        ("color", &el.color),
        ("font-family", &el.font_family),
        ("font-size", &el.font_size),
        ("font-weight", &el.font_weight),
    ] {
        if !value.is_empty() {
            out.push(decl(prop, value));
        }
    }
    if with_line_height {
        if let Some(lh) = line_height(&el.line_height, &el.font_size) {
            out.push(decl("line-height", &lh));
        }
    }
    out
}

/// The value seen most often; the first seen wins ties.
fn most_common<K: PartialEq>(items: impl IntoIterator<Item = K>) -> Option<K> {
    let mut counts: Vec<(K, usize)> = Vec::new();
    for item in items {
        match counts.iter_mut().find(|(known, _)| *known == item) {
            Some((_, n)) => *n += 1,
            None => counts.push((item, 1)),
        }
    }
    let mut best: Option<(K, usize)> = None;
    for (item, n) in counts {
        if best.as_ref().is_none_or(|(_, top)| n > *top) {
            best = Some((item, n));
        }
    }
    best.map(|(item, _)| item)
}

/// First token of a `border-radius` value; `None` for an empty one.
fn radius_of(value: &str) -> Option<String> {
    value.split_whitespace().next().map(str::to_owned)
}

/// How a button or input looks.
#[derive(Clone, PartialEq, Eq)]
struct Look {
    background: Option<Paint>,
    text: Option<Rgb>,
    border: Option<Rgb>,
    radius: Option<String>,
}

fn look(el: &ElementStyle) -> Look {
    let bordered = px(&el.border_width).is_some_and(|w| w > 0.0);
    Look {
        background: parse_paint(&el.background_color),
        text: opaque(&el.color),
        border: if bordered { opaque(&el.border_color) } else { None },
        radius: radius_of(&el.border_radius),
    }
}

fn look_decls(look: &Look) -> Vec<Decl> {
    let mut out = Vec::new();
    match look.background {
        Some(Paint::Color(c)) => out.push(decl("background-color", &c.hex())),
        Some(Paint::Transparent) => out.push(decl("background-color", "transparent")),
        None => {}
    }
    if let Some(c) = look.text {
        out.push(decl("color", &c.hex()));
    }
    if let Some(c) = look.border {
        out.push(decl("border-color", &c.hex()));
    }
    if let Some(r) = &look.radius {
        out.push(decl("border-radius", r));
    }
    out
}

/// The most common look among those `keep` accepts.
fn top_look(looks: &[Look], keep: impl Fn(&Look) -> bool) -> Option<Look> {
    most_common(looks.iter().filter(|l| keep(l)).cloned())
}

/// Read `c` as rules and observations.
pub(super) fn analyze(c: &ComputedStyles) -> Computed {
    let mut rules = Vec::new();
    let mut observed = Observed::default();

    // body: the canvas background is the body's, else the root's
    let canvas = opaque(&c.body.background_color).or_else(|| opaque(&c.root.background_color));
    let mut body = text_decls(&c.body, true);
    if let Some(bg) = canvas {
        body.push(decl("background-color", &bg.hex()));
    }
    rules.extend(rule("body", body));
    observed.background = canvas;
    observed.text = opaque(&c.body.color);
    observed.body_font = primary_family(&c.body.font_family);

    // headings: the first one carries the heading line height
    let mut first_heading = true;
    for heading in &c.headings {
        let tag = heading.tag.to_ascii_lowercase();
        if !matches!(tag.as_str(), "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
            continue;
        }
        if observed.heading_font.is_none() {
            observed.heading_font = primary_family(&heading.font_family);
        }
        rules.extend(rule(&tag, text_decls(heading, first_heading)));
        first_heading = false;
    }

    // links: the colour most links share
    observed.link = most_common(c.links.iter().filter_map(|l| opaque(&l.color)));
    if let Some(link) = observed.link {
        rules.extend(rule("a", vec![decl("color", &link.hex())]));
    }

    // buttons: the primary look has a coloured background, the secondary is the most common
    // other look
    let buttons: Vec<Look> = c.buttons.iter().map(look).collect();
    let coloured = |l: &Look| matches!(l.background, Some(Paint::Color(fill)) if !fill.is_neutral());
    let filled = |l: &Look| matches!(l.background, Some(Paint::Color(_)));
    let primary = top_look(&buttons, coloured).or_else(|| top_look(&buttons, filled));
    let secondary = top_look(&buttons, |l| primary.as_ref() != Some(l));
    if let Some(l) = &primary {
        rules.extend(rule(".btn-primary", look_decls(l)));
    }
    if let Some(l) = &secondary {
        rules.extend(rule(".btn-secondary", look_decls(l)));
    }

    let inputs: Vec<Look> = c.inputs.iter().map(look).collect();
    if let Some(l) = top_look(&inputs, |_| true) {
        rules.extend(rule("input[type=text]", look_decls(&l)));
    }

    // the radius shoppers see: the most common non-zero one of buttons, then of inputs
    let radii = |looks: &[Look]| {
        most_common(
            looks
                .iter()
                .filter_map(|l| l.radius.clone())
                .filter(|r| px(r).is_some_and(|v| (0.0..MAX_ROUND_PX).contains(&v) && v > 0.0)),
        )
    };
    observed.radius = radii(&buttons).or_else(|| radii(&inputs));

    if let Some(font) = primary_family(&c.code.font_family) {
        rules.extend(rule("code", vec![decl("font-family", &font)]));
    }
    Computed { rules, observed }
}

/// `s` unless it is empty.
fn present(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Icon links, the `og:image` and the logo image of `c` where the markup scan of `scan` found
/// none (the browser resolved them against the document's base URL).
pub(super) fn merge_assets(c: &ComputedStyles, base: &Url, scan: &mut Scan) {
    for icon in &c.icons {
        let Some(url) = http_url(base, &icon.href) else {
            continue;
        };
        let rel = icon.rel.to_ascii_lowercase();
        let touch = rel.split_whitespace().any(|r| r.starts_with("apple-touch-icon"));
        let plain = rel.split_whitespace().any(|r| r == "icon");
        let list = if touch {
            &mut scan.apple
        } else if plain {
            &mut scan.icons
        } else {
            continue;
        };
        if list.len() < MAX_PAGE_ITEMS && !list.iter().any(|known| known.url == url) {
            list.push(IconLink {
                url,
                area: icon_sizes(present(&icon.sizes), present(&icon.mime)),
            });
        }
    }
    if scan.og_image.is_none() && !c.og_image.is_empty() {
        scan.og_image = http_url(base, &c.og_image);
    }
    if scan.logo.is_none() && !c.logo.is_empty() {
        scan.logo = http_url(base, &c.logo).map(|u| (0, u));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::branding::{branding, branding_computed, BrandingInput};
    use serde_json::json;

    fn el(tag: &str, v: Value) -> Value {
        let mut base = json!({"tag": tag});
        base.as_object_mut()
            .unwrap()
            .extend(v.as_object().unwrap().clone());
        base
    }

    fn page() -> Value {
        json!({
            "root": {"tag": "html", "backgroundColor": "rgba(0, 0, 0, 0)"},
            "body": el("body", json!({
                "color": "rgb(238, 238, 238)", "backgroundColor": "rgb(18, 18, 18)",
                "fontFamily": "\"Space Grotesk\", Arial, sans-serif", "fontSize": "16px",
                "fontWeight": "400", "lineHeight": "24px",
            })),
            "headings": [
                el("h1", json!({"color": "rgb(255, 255, 255)", "fontFamily": "Fraunces, serif",
                    "fontSize": "48px", "fontWeight": "700", "lineHeight": "52.8px"})),
                el("h2", json!({"color": "rgb(255, 255, 255)", "fontFamily": "Fraunces, serif",
                    "fontSize": "32px", "fontWeight": "700"})),
            ],
            "links": [
                el("a", json!({"color": "rgb(74, 163, 255)"})),
                el("a", json!({"color": "rgb(74, 163, 255)"})),
                el("a", json!({"color": "rgb(200, 200, 200)"})),
            ],
            "buttons": [
                el("button", json!({"color": "rgb(255, 255, 255)", "backgroundColor": "rgb(255, 107, 53)",
                    "borderColor": "rgb(255, 107, 53)", "borderWidth": "1px", "borderRadius": "12px"})),
                el("button", json!({"color": "rgb(255, 255, 255)", "backgroundColor": "rgb(255, 107, 53)",
                    "borderColor": "rgb(255, 107, 53)", "borderWidth": "1px", "borderRadius": "12px"})),
                el("button", json!({"color": "rgb(255, 107, 53)", "backgroundColor": "rgba(0, 0, 0, 0)",
                    "borderColor": "rgb(255, 107, 53)", "borderWidth": "2px", "borderRadius": "12px"})),
            ],
            "inputs": [
                el("input", json!({"color": "rgb(255, 255, 255)", "backgroundColor": "rgb(30, 30, 30)",
                    "borderColor": "rgb(80, 80, 80)", "borderWidth": "1px", "borderRadius": "6px"})),
            ],
            "code": el("code", json!({"fontFamily": "\"Fira Code\", monospace"})),
            "icons": [
                {"rel": "icon", "href": "https://brand.example/fav-32.png", "sizes": "32x32", "mime": ""},
                {"rel": "apple-touch-icon", "href": "https://brand.example/touch.png", "sizes": "180x180", "mime": ""},
            ],
            "ogImage": "https://brand.example/og.png",
            "logo": "https://brand.example/logo.svg",
        })
    }

    fn base() -> Url {
        Url::parse("https://brand.example/").unwrap()
    }

    fn profile(html: &str, computed: Value) -> Value {
        let styles = ComputedStyles::from_value(computed).unwrap();
        branding_computed(
            &BrandingInput {
                html,
                base: &base(),
                stylesheets: &[],
            },
            &styles,
        )
    }

    #[test]
    fn computed_styles_give_the_profile_without_any_stylesheet() {
        let b = profile("<html><body><p>x</p></body></html>", page());
        assert_eq!(b["colorScheme"], "dark");
        assert_eq!(b["colors"]["background"], "#121212");
        assert_eq!(b["colors"]["textPrimary"], "#EEEEEE");
        assert_eq!(b["colors"]["link"], "#4AA3FF");
        assert_eq!(b["colors"]["primary"], "#FF6B35");
        assert_eq!(b["fonts"][0], json!({"family": "Space Grotesk"}));
        assert_eq!(b["fonts"][1], json!({"family": "Fraunces"}));
        assert_eq!(
            b["typography"]["fontFamilies"],
            json!({"primary": "Space Grotesk", "heading": "Fraunces", "code": "Fira Code"})
        );
        assert_eq!(
            b["typography"]["fontSizes"],
            json!({"body": "16px", "h1": "48px", "h2": "32px"})
        );
        assert_eq!(b["typography"]["lineHeights"]["body"], json!(1.5));
        assert_eq!(b["typography"]["lineHeights"]["heading"], json!(1.1));
        assert_eq!(b["spacing"]["borderRadius"], "12px");
        assert_eq!(
            b["components"]["buttonPrimary"],
            json!({"background": "#FF6B35", "textColor": "#FFFFFF", "borderColor": "#FF6B35", "borderRadius": "12px"})
        );
        assert_eq!(
            b["components"]["buttonSecondary"],
            json!({"background": "transparent", "textColor": "#FF6B35", "borderColor": "#FF6B35", "borderRadius": "12px"})
        );
        assert_eq!(b["components"]["input"]["borderRadius"], "6px");
        assert_eq!(b["components"]["input"]["background"], "#1E1E1E");
    }

    #[test]
    fn icons_og_image_and_logo_fill_what_the_markup_lacks() {
        let b = profile("<html><body></body></html>", page());
        assert_eq!(b["logo"], "https://brand.example/logo.svg");
        assert_eq!(
            b["images"],
            json!({
                "logo": "https://brand.example/logo.svg",
                "favicon": "https://brand.example/fav-32.png",
                "ogImage": "https://brand.example/og.png",
            })
        );
        // the markup's own findings stay
        let html = r#"<head><meta property="og:image" content="/own-og.png"></head>
            <body><header><a href="/"><img class="logo" src="/own-logo.svg"></a></header></body>"#;
        let b = profile(html, page());
        assert_eq!(b["logo"], "https://brand.example/own-logo.svg");
        assert_eq!(b["images"]["ogImage"], "https://brand.example/own-og.png");
    }

    #[test]
    fn computed_values_win_over_what_the_stylesheets_declare() {
        let html = "<style>:root{--bg:#ffffff;--text:#111111;--link:#0000ff;--radius:2px}\
                    body{background:var(--bg);color:var(--text);font-family:Lato,sans-serif}\
                    a{color:#0000ff}.btn-primary{background:#00aa00;color:#000;border-radius:2px}</style>";
        let plain = branding(&BrandingInput {
            html,
            base: &base(),
            stylesheets: &[],
        });
        assert_eq!(plain["colorScheme"], "light");
        assert_eq!(plain["colors"]["background"], "#FFFFFF");
        let b = profile(html, page());
        assert_eq!(b["colorScheme"], "dark");
        assert_eq!(b["colors"]["background"], "#121212");
        assert_eq!(b["colors"]["textPrimary"], "#EEEEEE");
        assert_eq!(b["colors"]["link"], "#4AA3FF");
        assert_eq!(b["spacing"]["borderRadius"], "12px");
        assert_eq!(b["components"]["buttonPrimary"]["background"], "#FF6B35");
        assert_eq!(b["fonts"][0], json!({"family": "Space Grotesk"}));
    }

    #[test]
    fn a_transparent_body_takes_the_root_background_and_none_means_no_override() {
        let mut v = page();
        v["body"]["backgroundColor"] = json!("rgba(0, 0, 0, 0)");
        v["root"]["backgroundColor"] = json!("rgb(250, 250, 250)");
        let b = profile("<p>x</p>", v);
        assert_eq!(b["colors"]["background"], "#FAFAFA");
        assert_eq!(b["colorScheme"], "light");
        let mut v = page();
        v["body"]["backgroundColor"] = json!("rgba(0, 0, 0, 0)");
        let b = profile("<style>body{background:#202020}</style>", v);
        assert_eq!(
            b["colors"]["background"], "#202020",
            "a fully transparent canvas observes nothing"
        );
    }

    #[test]
    fn the_script_answer_is_bounded_and_garbage_is_refused() {
        assert!(ComputedStyles::from_value(json!("text")).is_none());
        assert!(ComputedStyles::from_value(json!([1, 2])).is_none());
        assert!(ComputedStyles::from_value(json!({"body": 3})).is_none());
        let many: Vec<Value> = (0..200).map(|_| json!({"tag": "a", "color": "red"})).collect();
        let long = "x".repeat(MAX_VALUE_LEN + 1);
        let s = ComputedStyles::from_value(json!({
            "links": many,
            "body": {"fontFamily": long},
            "ogImage": "y".repeat(MAX_VALUE_LEN + 1),
        }))
        .unwrap();
        assert_eq!(s.links.len(), MAX_LINKS);
        assert!(s.body.font_family.is_empty() && s.og_image.is_empty());
        assert_eq!(
            ComputedStyles::from_value(json!({})).unwrap(),
            ComputedStyles::default()
        );
    }

    #[test]
    fn an_empty_report_changes_nothing() {
        let html = "<style>body{background:#fff;color:#222;font-family:Lato}</style>";
        let empty = ComputedStyles::from_value(json!({})).unwrap();
        let input = BrandingInput {
            html,
            base: &base(),
            stylesheets: &[],
        };
        assert_eq!(branding_computed(&input, &empty), branding(&input));
    }

    #[test]
    fn line_heights_become_ratios() {
        assert_eq!(line_height("24px", "16px").as_deref(), Some("1.5"));
        assert_eq!(line_height("16px", "16px").as_deref(), Some("1"));
        assert_eq!(line_height("normal", "16px"), None);
        assert_eq!(line_height("1.4", "16px").as_deref(), Some("1.4"));
        assert_eq!(line_height("20px", "").as_deref(), Some("20px"));
    }

    #[test]
    fn the_collect_script_is_one_expression() {
        let s = COLLECT_SCRIPT.trim();
        assert!(s.starts_with("(() => {") && s.ends_with("})()"));
        for key in [
            "getComputedStyle",
            "headings",
            "buttons",
            "inputs",
            "icons",
            "ogImage",
            "logo",
        ] {
            assert!(s.contains(key), "{key}");
        }
    }
}
