//! Style analysis behind the branding profile: what the parsed stylesheets say about colours,
//! typography, spacing, components, motion and layout.
//!
//! The analysis never evaluates selectors against the document. It reads the selector text of
//! every non-dark rule to decide which role a declaration plays (`body`, a link, a heading, a
//! primary button, a container, ...) and tallies values by frequency, with ties broken by first
//! appearance so the result is deterministic.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::color::{first_paint, split_top_level, Paint, Rgb};
use super::css::{Decl, Rule, Sheet};

/// Most distinct keys any tally keeps.
const MAX_TALLY_KEYS: usize = 4096;
/// Longest value kept after resolving `var()`.
const MAX_VALUE_LEN: usize = 4096;
/// Most custom properties read.
const MAX_PROPS: usize = 4096;

// ---------------------------------------------------------------------------------------------
// Tally
// ---------------------------------------------------------------------------------------------

/// Frequency tally with deterministic order: count descending, first appearance ascending.
#[derive(Debug)]
struct Tally<K: Ord> {
    map: BTreeMap<K, (u32, usize)>,
    seq: usize,
}

impl<K: Ord> Default for Tally<K> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
            seq: 0,
        }
    }
}

impl<K: Ord + Clone> Tally<K> {
    fn add(&mut self, key: K, weight: u32) {
        if self.map.len() >= MAX_TALLY_KEYS && !self.map.contains_key(&key) {
            return;
        }
        let seq = self.seq;
        self.seq += 1;
        let slot = self.map.entry(key).or_insert((0, seq));
        slot.0 = slot.0.saturating_add(weight);
    }

    fn ranked(&self) -> Vec<K> {
        let mut v: Vec<(&K, &(u32, usize))> = self.map.iter().collect();
        v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.1 .1.cmp(&b.1 .1)));
        v.into_iter().map(|(k, _)| k.clone()).collect()
    }

    fn top(&self) -> Option<K> {
        self.ranked().into_iter().next()
    }
}

// ---------------------------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------------------------

/// Style of one UI component.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Component {
    pub background: Option<String>,
    pub text_color: Option<String>,
    pub border_color: Option<String>,
    pub border_radius: Option<String>,
}

impl Component {
    pub fn is_empty(&self) -> bool {
        self.background.is_none()
            && self.text_color.is_none()
            && self.border_color.is_none()
            && self.border_radius.is_none()
    }

    /// Fields of `self`, completed with those of `base`.
    fn over(self, base: &Component) -> Component {
        Component {
            background: self.background.or_else(|| base.background.clone()),
            text_color: self.text_color.or_else(|| base.text_color.clone()),
            border_color: self.border_color.or_else(|| base.border_color.clone()),
            border_radius: self.border_radius.or_else(|| base.border_radius.clone()),
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        let mut put = |k: &str, v: &Option<String>| {
            if let Some(v) = v {
                m.insert(k.to_owned(), json!(v));
            }
        };
        put("background", &self.background);
        put("textColor", &self.text_color);
        put("borderColor", &self.border_color);
        put("borderRadius", &self.border_radius);
        Value::Object(m)
    }
}

/// Colours named by custom properties (`--primary`, `--brand`, ...).
#[derive(Debug, Default)]
pub(super) struct Roles {
    pub primary: Option<Rgb>,
    pub secondary: Option<Rgb>,
    pub accent: Option<Rgb>,
    pub background: Option<Rgb>,
    pub text_primary: Option<Rgb>,
    pub text_secondary: Option<Rgb>,
    pub link: Option<Rgb>,
    pub success: Option<Rgb>,
    pub warning: Option<Rgb>,
    pub error: Option<Rgb>,
}

/// Everything the stylesheets say.
#[derive(Debug, Default)]
pub(super) struct Facts {
    /// Colours from custom properties.
    pub roles: Roles,
    /// `background` of `body`/`html`/`:root`.
    pub body_bg: Option<Rgb>,
    /// `color` of `body`/`html`/`:root`.
    pub body_color: Option<Rgb>,
    /// `color` of plain `a`.
    pub link_color: Option<Rgb>,
    /// Text colours, most used first.
    pub text_ranked: Vec<Rgb>,
    /// Saturated colours of buttons, links and borders, most weighted first.
    pub pool: Vec<Rgb>,
    /// Semantic colours from `.success`/`.warning`/`.error` style selectors.
    pub success: Option<Rgb>,
    pub warning: Option<Rgb>,
    pub error: Option<Rgb>,
    /// `color-scheme: dark` on the root.
    pub dark_scheme: bool,
    /// Font families, most used first (non-monospace and monospace together).
    pub fonts: Vec<String>,
    pub body_font: Option<String>,
    pub heading_font: Option<String>,
    pub code_font: Option<String>,
    pub font_sizes: BTreeMap<&'static str, String>,
    pub font_weights: BTreeMap<&'static str, u16>,
    pub line_heights: BTreeMap<&'static str, Value>,
    pub base_unit: Option<u32>,
    pub border_radius: Option<String>,
    pub button_primary: Component,
    pub button_secondary: Component,
    pub input: Component,
    pub transition_duration: Option<String>,
    pub easing: Option<String>,
    pub keyframes: Vec<String>,
    pub max_width: Option<String>,
    pub columns: Option<u32>,
    pub header_height: Option<String>,
    pub footer_height: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// var() resolution
// ---------------------------------------------------------------------------------------------

/// Byte offset of the `)` that closes a `(` already consumed in `s`.
fn matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Index of the first top-level comma of `s`.
fn first_comma(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Replace every `var(--x, fallback)` of `value`; `None` when one cannot be resolved.
fn resolve(value: &str, props: &BTreeMap<String, String>, depth: usize) -> Option<String> {
    if !value.contains("var(") {
        return Some(value.to_owned());
    }
    if depth > 4 {
        return None;
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(pos) = rest.find("var(") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 4..];
        let close = matching_paren(after)?;
        let inner = &after[..close];
        let (name, fallback) = match first_comma(inner) {
            Some(i) => (inner[..i].trim(), Some(inner[i + 1..].trim())),
            None => (inner.trim(), None),
        };
        let resolved = match props.get(name) {
            Some(v) => resolve(v, props, depth + 1),
            None => None,
        }
        .or_else(|| fallback.and_then(|f| resolve(f, props, depth + 1)))?;
        out.push_str(&resolved);
        rest = &after[close + 1..];
        if out.len() > MAX_VALUE_LEN {
            return None;
        }
    }
    out.push_str(rest);
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Custom property roles
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Primary,
    Secondary,
    Accent,
    Background,
    TextPrimary,
    TextSecondary,
    Link,
    Success,
    Warning,
    Error,
}

const NOISE: &[&str] = &[
    "hover",
    "focus",
    "active",
    "disabled",
    "rgb",
    "hsl",
    "hsla",
    "rgba",
    "alpha",
    "opacity",
    "shadow",
    "ring",
    "border",
    "outline",
    "size",
    "width",
    "height",
    "radius",
    "font",
    "family",
    "weight",
    "spacing",
    "gap",
    "padding",
    "margin",
    "line",
    "transition",
    "duration",
    "index",
    "inverse",
    "invert",
    "contrast",
    "on",
    "light",
    "dark",
    "lighter",
    "darker",
    "tint",
    "shade",
    "bold",
    "gradient",
    "start",
    "end",
    "from",
    "to",
    "via",
];
const NEUTRAL_WORDS: &[&str] = &[
    "color", "colors", "colour", "base", "main", "default", "body", "page", "site", "theme", "global", "wp",
    "preset", "bs", "c", "clr", "tw", "app",
];
const TEXT_WORDS: &[&str] = &["text", "foreground", "fg", "ink"];
const MUTED_WORDS: &[&str] = &[
    "secondary",
    "muted",
    "subtle",
    "dim",
    "soft",
    "faded",
    "tertiary",
    "weak",
];

/// Role of a custom property from the words of its name, with the number of words (fewer is
/// more specific).
fn classify(name: &str) -> Option<(Role, usize)> {
    let lower = name.trim_start_matches('-').to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split(['-', '_']).filter(|t| !t.is_empty()).collect();
    if tokens.is_empty() || tokens.iter().any(|t| t.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let has = |w: &str| tokens.contains(&w);
    let any = |ws: &[&str]| tokens.iter().any(|t| ws.contains(t));
    // Words that put a name outside every role (`--primary-hover`, `--bg-rgb`); the muted-text
    // words are not noise.
    if any(NOISE) {
        return None;
    }
    let n = tokens.len();
    let only = |allowed: &[&[&str]]| tokens.iter().all(|t| allowed.iter().any(|set| set.contains(t)));
    // `--primary-foreground` is the text *on* the primary colour, not the page text.
    if has("foreground")
        && any(&[
            "primary",
            "secondary",
            "accent",
            "brand",
            "destructive",
            "card",
            "popover",
            "sidebar",
        ])
    {
        return None;
    }
    if any(TEXT_WORDS) {
        if has("link") {
            return None;
        }
        if any(MUTED_WORDS) {
            return only(&[TEXT_WORDS, MUTED_WORDS, NEUTRAL_WORDS]).then_some((Role::TextSecondary, n));
        }
        return only(&[TEXT_WORDS, &["primary"], NEUTRAL_WORDS]).then_some((Role::TextPrimary, n));
    }
    if has("background") || has("bg") {
        return only(&[&["background", "bg", "primary"], NEUTRAL_WORDS]).then_some((Role::Background, n));
    }
    let role = if has("primary") || has("brand") {
        Role::Primary
    } else if has("secondary") {
        Role::Secondary
    } else if has("accent") {
        Role::Accent
    } else if has("link") {
        Role::Link
    } else if has("success") || has("positive") {
        Role::Success
    } else if has("warning") || has("caution") {
        Role::Warning
    } else if has("error") || has("danger") || has("destructive") || has("negative") {
        Role::Error
    } else {
        return None;
    };
    Some((role, n))
}

fn roles_from_props(props: &BTreeMap<String, String>) -> Roles {
    let mut best: BTreeMap<Role, (usize, Rgb)> = BTreeMap::new();
    for (name, value) in props {
        let Some((role, n)) = classify(name) else { continue };
        let Some(v) = resolve(value, props, 0) else {
            continue;
        };
        let Some(Paint::Color(c)) = first_paint(&v) else {
            continue;
        };
        let better = best.get(&role).is_none_or(|(bn, _)| n < *bn);
        if better {
            best.insert(role, (n, c));
        }
    }
    let get = |r: Role| best.get(&r).map(|(_, c)| *c);
    Roles {
        primary: get(Role::Primary),
        secondary: get(Role::Secondary),
        accent: get(Role::Accent),
        background: get(Role::Background),
        text_primary: get(Role::TextPrimary),
        text_secondary: get(Role::TextSecondary),
        link: get(Role::Link),
        success: get(Role::Success),
        warning: get(Role::Warning),
        error: get(Role::Error),
    }
}

// ---------------------------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------------------------

fn is_root_selector(s: &str) -> bool {
    matches!(
        s,
        ":root" | "html" | "body" | "*" | ":host" | "html body" | "html:root"
    ) || s.contains("light")
}

fn is_body_selector(s: &str) -> bool {
    matches!(s, "body" | "html" | ":root" | "html body" | "html:root")
}

fn last_compound(sel: &str) -> &str {
    sel.rsplit([' ', '>', '+', '~'])
        .find(|p| !p.is_empty())
        .unwrap_or(sel)
}

fn has_state(sel: &str) -> bool {
    [
        ":hover",
        ":focus",
        ":active",
        ":disabled",
        ":checked",
        "::",
        ":before",
        ":after",
        ":selection",
        ":placeholder",
    ]
    .iter()
    .any(|s| sel.contains(s))
}

/// Roles one selector plays.
#[derive(Default)]
struct Sel {
    body: bool,
    link: bool,
    heading: Option<u8>,
    code: bool,
    small: bool,
    button: bool,
    primary: bool,
    secondary: bool,
    base_button: bool,
    input: bool,
    header: bool,
    footer: bool,
    container: bool,
    success: bool,
    warning: bool,
    error: bool,
    /// `html`/`:root`: carries the root font size.
    root: bool,
    /// `body`: carries the body text size.
    body_el: bool,
    /// The heading selector is the bare tag (`h1`), not a descendant form (`.prose h1`).
    bare: bool,
}

fn heading_level(compound: &str) -> Option<u8> {
    let name = compound.strip_prefix('.').unwrap_or(compound);
    let digit = name.strip_prefix('h')?;
    match digit.as_bytes() {
        [d @ b'1'..=b'6'] => Some(d - b'0'),
        _ => None,
    }
}

fn sel_flags(sel: &str) -> Sel {
    let last = last_compound(sel);
    let submit = [
        "input[type=submit",
        "input[type=\"submit",
        "input[type='submit",
        "input[type=button",
        "input[type=\"button",
    ];
    let button = last.contains("btn")
        || last.contains("button")
        || last.contains("cta")
        || submit.iter().any(|p| last.starts_with(p));
    let primary = button && (sel.contains("primary") || sel.contains("cta") || sel.contains("btn-brand"));
    let secondary = button
        && !primary
        && [
            "secondary",
            "outline",
            "ghost",
            "tertiary",
            "btn-default",
            "btn-light",
            "-alt",
        ]
        .iter()
        .any(|w| sel.contains(w));
    let text_inputs = [
        "input[type=text",
        "input[type=\"text",
        "input[type='text",
        "input[type=email",
        "input[type=\"email",
        "input[type=search",
    ];
    Sel {
        body: is_body_selector(sel),
        root: matches!(sel, "html" | ":root" | "html:root"),
        body_el: matches!(sel, "body" | "html body"),
        link: matches!(last, "a" | "a:link" | "a:visited"),
        heading: heading_level(last).filter(|_| last.starts_with('h') || last.starts_with(".h")),
        code: matches!(last, "code" | "pre" | "kbd" | "samp"),
        small: last == "small",
        button,
        primary,
        secondary,
        base_button: button
            && !primary
            && !secondary
            && (matches!(last, "button" | ".btn" | ".button") || submit.iter().any(|p| last.starts_with(p))),
        input: matches!(
            last,
            "input" | "textarea" | "select" | ".form-control" | ".input" | ".form-input" | ".input-field"
        ) || text_inputs.iter().any(|p| last.starts_with(p)),
        header: matches!(
            last,
            "header"
                | ".header"
                | ".site-header"
                | "#header"
                | ".navbar"
                | "nav"
                | ".nav"
                | "#masthead"
                | ".masthead"
                | ".topbar"
        ),
        footer: matches!(last, "footer" | ".footer" | ".site-footer" | "#footer"),
        container: ["container", "wrapper", "content", "layout", "page", "main"]
            .iter()
            .any(|w| last.contains(w))
            || matches!(last, "body"),
        success: last.contains("success"),
        warning: last.contains("warning"),
        error: last.contains("error") || last.contains("danger") || last.contains("invalid"),
        bare: last == sel || sel.rsplit_once(' ').is_none(),
    }
}

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

const GENERIC_FAMILIES: &[&str] = &[
    "serif",
    "sans-serif",
    "monospace",
    "cursive",
    "fantasy",
    "system-ui",
    "ui-serif",
    "ui-sans-serif",
    "ui-monospace",
    "ui-rounded",
    "emoji",
    "math",
    "fangsong",
    "inherit",
    "initial",
    "unset",
    "revert",
    "-apple-system",
    "blinkmacsystemfont",
    "segoe ui emoji",
    "segoe ui symbol",
    "apple color emoji",
    "noto color emoji",
];

/// Families of a `font-family` value, unquoted, in order.
fn families(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = value;
    loop {
        let (item, tail) = match first_comma(rest) {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let name = item.trim().trim_matches(['"', '\'']).trim();
        if !name.is_empty() {
            out.push(name.to_owned());
        }
        match tail {
            Some(t) => rest = t,
            None => return out,
        }
    }
}

fn is_generic(family: &str) -> bool {
    GENERIC_FAMILIES.contains(&family.to_ascii_lowercase().as_str())
}

/// The first named (non-generic) family of a `font-family` value, unquoted.
pub(super) fn primary_family(value: &str) -> Option<String> {
    families(value).into_iter().find(|f| !is_generic(f))
}

fn is_mono_stack(fams: &[String]) -> bool {
    fams.iter()
        .any(|f| matches!(f.to_ascii_lowercase().as_str(), "monospace" | "ui-monospace"))
}

/// Split a `length` into (number, unit).
fn length(token: &str) -> Option<(f32, &str)> {
    let t = token.trim();
    let end = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(t.len());
    let n: f32 = t[..end].parse().ok()?;
    n.is_finite().then_some((n, &t[end..]))
}

/// A `px`, `rem` or `em` length in pixels (`rem`/`em` against `root_px`).
fn to_px(token: &str, root_px: f32) -> Option<f32> {
    let (n, unit) = length(token)?;
    match unit.to_ascii_lowercase().as_str() {
        "px" => Some(n),
        "rem" | "em" => Some(n * root_px),
        _ => None,
    }
}

fn fmt_px(v: f32) -> String {
    let s = format!("{v:.2}");
    format!("{}px", s.trim_end_matches('0').trim_end_matches('.'))
}

/// `3rem` → `48px`; other values verbatim.
fn normalize_len(value: &str, root_px: f32) -> String {
    let v = value.trim();
    to_px(v, root_px).map_or_else(|| v.to_owned(), fmt_px)
}

fn weight_of(value: &str) -> Option<u16> {
    let v = value.trim().to_ascii_lowercase();
    match v.as_str() {
        "normal" => Some(400),
        "bold" | "bolder" => Some(700),
        "lighter" => Some(300),
        _ => {
            let n: f32 = v.parse().ok()?;
            if !(1.0..=1000.0).contains(&n) {
                return None;
            }
            let hundreds = (n / 100.0).round().clamp(1.0, 9.0);
            u16::try_from(format!("{hundreds:.0}00").parse::<u32>().ok()?).ok()
        }
    }
}

fn hex_or_transparent(v: &str) -> Option<String> {
    match first_paint(v)? {
        Paint::Color(c) => Some(c.hex()),
        Paint::Transparent => Some("transparent".to_owned()),
    }
}

/// `font: 16px/1.5 Inter, sans-serif` → size, line-height and family list.
fn expand_font_shorthand(value: &str) -> Vec<(&'static str, String)> {
    let tokens = split_top_level(value);
    let Some(i) = tokens.iter().position(|t| {
        let size = t.split('/').next().unwrap_or(t);
        size.starts_with(|c: char| c.is_ascii_digit() || c == '.')
            && length(size).is_some_and(|(_, u)| !u.is_empty())
    }) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let (size, lh) = match tokens[i].split_once('/') {
        Some((s, l)) => (s, Some(l)),
        None => (tokens[i], None),
    };
    out.push(("font-size", size.to_owned()));
    if let Some(l) = lh.filter(|l| !l.is_empty()) {
        out.push(("line-height", l.to_owned()));
    }
    if i + 1 < tokens.len() {
        out.push(("font-family", tokens[i + 1..].join(" ")));
    }
    if let Some(w) = tokens[..i].iter().find_map(|t| {
        weight_of(t).filter(|_| {
            t.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_digit() || b == b'b' || b == b'n')
        })
    }) {
        out.push(("font-weight", w.to_string()));
    }
    out
}

fn json_number_or_string(v: &str) -> Value {
    match v.trim().parse::<f64>() {
        Ok(n) if n.is_finite() => json!(n),
        _ => json!(v.trim()),
    }
}

fn is_time(token: &str) -> bool {
    length(token).is_some_and(|(_, u)| u == "s" || u == "ms") && !token.contains('(')
}

fn is_easing(token: &str) -> bool {
    matches!(
        token,
        "ease" | "ease-in" | "ease-out" | "ease-in-out" | "linear" | "step-start" | "step-end"
    ) || token.starts_with("cubic-bezier(")
        || token.starts_with("steps(")
}

fn normalize_time(token: &str) -> Option<String> {
    let (n, unit) = length(token)?;
    if n <= 0.0 {
        return None;
    }
    let s = format!("{n:.3}");
    Some(format!("{}{unit}", s.trim_end_matches('0').trim_end_matches('.')))
}

/// Split on top-level commas.
fn comma_list(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(i) = first_comma(rest) {
        out.push(rest[..i].trim());
        rest = &rest[i + 1..];
    }
    out.push(rest.trim());
    out
}

fn repeat_count(value: &str) -> Option<u32> {
    let i = value.find("repeat(")? + "repeat(".len();
    let n: u32 = value[i..].split(',').next()?.trim().parse().ok()?;
    (2..=24).contains(&n).then_some(n)
}

// ---------------------------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Acc {
    text: Tally<Rgb>,
    bg: Tally<Rgb>,
    pool: Tally<Rgb>,
    fonts: Tally<String>,
    mono_fonts: Tally<String>,
    heading_fonts: Tally<String>,
    weights: Tally<u16>,
    spacing: Tally<String>,
    radius: Tally<String>,
    durations: Tally<String>,
    easings: Tally<String>,
    max_widths: Tally<String>,
    columns: Tally<u32>,
    size_raw: BTreeMap<&'static str, (bool, String)>,
    line_raw: BTreeMap<&'static str, String>,
    root_font: Option<String>,
    facts: Facts,
    base: Component,
    primary: Component,
    secondary: Component,
}

const HEADING_KEYS: [&str; 6] = ["h1", "h2", "h3", "h4", "h5", "h6"];

impl Acc {
    fn color_decl(&mut self, flags: &[Sel], c: Rgb) {
        self.text.add(c, 1);
        let weight = flags
            .iter()
            .map(|f| if f.link { 3 } else { u32::from(f.button) * 2 })
            .max()
            .unwrap_or(0)
            .max(1);
        if !c.is_neutral() {
            self.pool.add(c, weight);
        }
        for f in flags {
            if f.body {
                self.facts.body_color = Some(c);
            }
            if f.link {
                self.facts.link_color = Some(c);
            }
            if f.success {
                self.facts.success = Some(c);
            }
            if f.warning {
                self.facts.warning = Some(c);
            }
            if f.error {
                self.facts.error = Some(c);
            }
        }
    }

    fn background_decl(&mut self, flags: &[Sel], c: Rgb) {
        self.bg.add(c, 1);
        let weight = flags
            .iter()
            .map(|f| match (f.button, f.primary) {
                (true, true) => 6,
                (true, false) => 4,
                _ => 1,
            })
            .max()
            .unwrap_or(1);
        if !c.is_neutral() {
            self.pool.add(c, weight);
        }
        for f in flags {
            if f.body {
                self.facts.body_bg = Some(c);
            }
            if f.success {
                self.facts.success = Some(c);
            }
            if f.warning {
                self.facts.warning = Some(c);
            }
            if f.error {
                self.facts.error = Some(c);
            }
        }
    }

    fn font_family_decl(&mut self, flags: &[Sel], value: &str) {
        let fams = families(value);
        let Some(first) = fams.iter().find(|f| !is_generic(f)).cloned() else {
            return;
        };
        if is_mono_stack(&fams) {
            self.mono_fonts.add(first.clone(), 1);
        } else {
            self.fonts.add(first.clone(), 1);
        }
        for f in flags {
            if f.body {
                self.facts.body_font = Some(first.clone());
            }
            if f.heading.is_some() {
                self.heading_fonts.add(first.clone(), 1);
            }
            if f.code {
                self.facts.code_font = Some(first.clone());
            }
        }
    }

    fn component_decl(&mut self, flags: &[Sel], prop: &str, value: &str) {
        let apply = |c: &mut Component| match prop {
            "background" | "background-color" => {
                if let Some(v) = hex_or_transparent(value) {
                    c.background = Some(v);
                }
            }
            "color" => {
                if let Some(Paint::Color(col)) = first_paint(value) {
                    c.text_color = Some(col.hex());
                }
            }
            "border" | "border-color" | "border-top-color" => {
                if let Some(Paint::Color(col)) = first_paint(value) {
                    c.border_color = Some(col.hex());
                }
            }
            "border-radius" => {
                if let Some(r) = value.split_whitespace().next().filter(|r| !r.contains('/')) {
                    c.border_radius = Some(r.to_owned());
                }
            }
            _ => {}
        };
        for f in flags {
            if f.primary {
                apply(&mut self.primary);
            }
            if f.secondary {
                apply(&mut self.secondary);
            }
            if f.base_button {
                apply(&mut self.base);
            }
            if f.input {
                apply(&mut self.facts.input);
            }
        }
    }

    fn typography_decl(&mut self, flags: &[Sel], prop: &str, value: &str) {
        match prop {
            "font-size" => {
                for f in flags {
                    if f.root {
                        self.root_font = Some(value.to_owned());
                    }
                    let key = if f.body_el {
                        Some("body")
                    } else if f.small {
                        Some("small")
                    } else {
                        f.heading.map(|n| HEADING_KEYS[usize::from(n) - 1])
                    };
                    if let Some(k) = key {
                        let replace = self.size_raw.get(k).is_none_or(|(bare, _)| f.bare || !*bare);
                        if replace {
                            self.size_raw.insert(k, (f.bare, value.to_owned()));
                        }
                    }
                }
            }
            "line-height" => {
                for f in flags {
                    if f.body {
                        self.line_raw.insert("body", value.to_owned());
                    } else if f.heading.is_some() {
                        self.line_raw.insert("heading", value.to_owned());
                    }
                }
            }
            "font-weight" => {
                if let Some(w) = weight_of(value) {
                    self.weights.add(w, 1);
                }
            }
            _ => {}
        }
    }

    fn motion_decl(&mut self, prop: &str, value: &str) {
        let (times_ok, easing_ok) = match prop {
            "transition" | "animation" => (true, true),
            "transition-duration" | "animation-duration" => (true, false),
            "transition-timing-function" | "animation-timing-function" => (false, true),
            _ => return,
        };
        for segment in comma_list(value) {
            let tokens = split_top_level(segment);
            if times_ok {
                if let Some(t) = tokens.iter().find(|t| is_time(t)).and_then(|t| normalize_time(t)) {
                    self.durations.add(t, 1);
                }
            }
            if easing_ok {
                if let Some(e) = tokens.iter().find(|t| is_easing(t)) {
                    self.easings.add((*e).to_owned(), 1);
                }
            }
        }
    }

    fn layout_decl(&mut self, flags: &[Sel], prop: &str, value: &str) {
        match prop {
            "max-width" => {
                if flags.iter().any(|f| f.container) {
                    if let Some(px) = to_px(value, 16.0).filter(|px| (480.0..=4096.0).contains(px)) {
                        self.max_widths.add(fmt_px(px), 1);
                    }
                }
            }
            "grid-template-columns" => {
                if let Some(n) = repeat_count(value) {
                    self.columns.add(n, 1);
                }
            }
            "height" => {
                for f in flags {
                    if f.header && self.facts.header_height.is_none() && to_px(value, 16.0).is_some() {
                        self.facts.header_height = Some(normalize_len(value, 16.0));
                    }
                    if f.footer && self.facts.footer_height.is_none() && to_px(value, 16.0).is_some() {
                        self.facts.footer_height = Some(normalize_len(value, 16.0));
                    }
                }
            }
            _ => {}
        }
    }

    fn decl(&mut self, flags: &[Sel], d: &Decl, value: &str) {
        match d.prop.as_str() {
            "color" => {
                if let Some(Paint::Color(c)) = first_paint(value) {
                    self.color_decl(flags, c);
                }
                self.component_decl(flags, "color", value);
            }
            "background" | "background-color" => {
                if let Some(Paint::Color(c)) = first_paint(value) {
                    self.background_decl(flags, c);
                }
                self.component_decl(flags, &d.prop, value);
            }
            "border" | "border-color" | "border-top-color" => {
                if let Some(Paint::Color(c)) = first_paint(value) {
                    if !c.is_neutral() {
                        self.pool.add(c, 1);
                    }
                }
                self.component_decl(flags, &d.prop, value);
            }
            "border-radius" => {
                if let Some(r) = value.split_whitespace().next().filter(|r| !r.contains('/')) {
                    if !matches!(r, "0" | "0px" | "50%" | "100%" | "inherit" | "initial")
                        && !r.starts_with("9999")
                    {
                        self.radius.add(r.to_owned(), 1);
                    }
                }
                self.component_decl(flags, "border-radius", value);
            }
            "font-family" => self.font_family_decl(flags, value),
            "font" => {
                for (p, v) in expand_font_shorthand(value) {
                    match p {
                        "font-family" => self.font_family_decl(flags, &v),
                        _ => self.typography_decl(flags, p, &v),
                    }
                }
            }
            "font-size" | "line-height" | "font-weight" => self.typography_decl(flags, &d.prop, value),
            "padding" | "margin" | "gap" | "row-gap" | "column-gap" | "padding-top" | "padding-bottom"
            | "padding-left" | "padding-right" | "margin-top" | "margin-bottom" | "margin-left"
            | "margin-right" => {
                for tok in split_top_level(value) {
                    if to_px(tok, 16.0).is_some_and(|px| px >= 1.0)
                        || tok.ends_with("rem")
                        || tok.ends_with("em")
                    {
                        self.spacing.add(tok.to_owned(), 1);
                    }
                }
            }
            "color-scheme" => {
                let v = value.to_ascii_lowercase();
                if flags.iter().any(|f| f.body) && v.contains("dark") && !v.contains("light") {
                    self.facts.dark_scheme = true;
                }
            }
            _ => {}
        }
        self.motion_decl(&d.prop, value);
        self.layout_decl(flags, &d.prop, value);
    }
}

fn base_unit(spacing: &Tally<String>, root_px: f32) -> Option<u32> {
    let mut px: Tally<u32> = Tally::default();
    for (tok, (count, _)) in &spacing.map {
        let Some(v) = to_px(tok, root_px) else { continue };
        if (1.0..=128.0).contains(&v) && (v - v.round()).abs() < 0.01 {
            // Range-checked above, so the conversion cannot fail.
            if let Ok(n) = format!("{v:.0}").parse::<u32>() {
                px.add(n, *count);
            }
        }
    }
    let total: u32 = px.map.values().map(|(c, _)| *c).sum();
    if total < 4 {
        return None;
    }
    [8u32, 4, 10, 6, 5, 3, 2].into_iter().find(|unit| {
        let covered: u32 = px
            .map
            .iter()
            .filter(|(v, _)| *v % unit == 0)
            .map(|(_, (c, _))| *c)
            .sum();
        covered * 100 >= total * 70
    })
}

fn weight_roles(weights: &Tally<u16>) -> BTreeMap<&'static str, u16> {
    let ranked = weights.ranked();
    let mut out = BTreeMap::new();
    let mut pick = |key: &'static str, f: &dyn Fn(u16) -> bool| {
        if let Some(w) = ranked.iter().copied().find(|w| f(*w)) {
            out.insert(key, w);
        }
    };
    pick("light", &|w| w <= 300);
    pick("regular", &|w| w == 400);
    pick("medium", &|w| w == 500);
    pick("semibold", &|w| w == 600);
    pick("bold", &|w| w >= 700);
    out
}

/// Analyse `sheet`.
pub(super) fn analyze(sheet: &Sheet) -> Facts {
    let live: Vec<&Rule> = sheet.rules.iter().filter(|r| !r.dark).collect();

    // Custom properties: root-like rules win over other rules; later definitions win over
    // earlier ones within a class.
    let mut props: BTreeMap<String, String> = BTreeMap::new();
    let mut root_names: BTreeSet<&str> = BTreeSet::new();
    for rule in &live {
        let root = rule.selectors.iter().any(|s| is_root_selector(s));
        for d in rule.decls.iter().filter(|d| d.prop.starts_with("--")) {
            if props.len() >= MAX_PROPS && !props.contains_key(&d.prop) {
                continue;
            }
            if root {
                props.insert(d.prop.clone(), d.value.clone());
                root_names.insert(&d.prop);
            } else if !root_names.contains(d.prop.as_str()) {
                props.entry(d.prop.clone()).or_insert_with(|| d.value.clone());
            }
        }
    }

    let mut acc = Acc::default();
    acc.facts.roles = roles_from_props(&props);
    for rule in &live {
        let flags: Vec<Sel> = rule
            .selectors
            .iter()
            .filter(|s| !has_state(s))
            .map(|s| sel_flags(s))
            .collect();
        if flags.is_empty() {
            continue;
        }
        for d in rule.decls.iter().filter(|d| !d.prop.starts_with("--")) {
            let Some(value) = resolve(&d.value, &props, 0) else {
                continue;
            };
            acc.decl(&flags, d, &value);
        }
    }
    for face in &sheet.font_faces {
        if let Some(name) = families(face).into_iter().find(|f| !is_generic(f)) {
            acc.fonts.add(name, 0);
        }
    }

    let root_px = acc
        .root_font
        .as_deref()
        .and_then(|v| {
            let (n, unit) = length(v)?;
            match unit {
                "px" => Some(n),
                "%" => Some(16.0 * n / 100.0),
                _ => None,
            }
        })
        .unwrap_or(16.0);

    let mut facts = std::mem::take(&mut acc.facts);
    facts.text_ranked = acc.text.ranked();
    facts.pool = acc.pool.ranked();
    // Fonts: stylesheet usage first (monospace stacks after the text fonts).
    let mut fonts = acc.fonts.ranked();
    for f in acc.mono_fonts.ranked() {
        if !fonts.contains(&f) {
            fonts.push(f);
        }
    }
    facts.fonts = fonts;
    facts.heading_font = acc.heading_fonts.top();
    if facts.code_font.is_none() {
        facts.code_font = acc.mono_fonts.top();
    }
    for (key, (_, raw)) in &acc.size_raw {
        facts.font_sizes.insert(key, normalize_len(raw, root_px));
    }
    // `html { font-size: 16px }` without a `body` rule is the body text size when absolute.
    if !facts.font_sizes.contains_key("body") {
        if let Some((n, "px")) = acc.root_font.as_deref().and_then(length) {
            facts.font_sizes.insert("body", fmt_px(n));
        }
    }
    facts.font_weights = weight_roles(&acc.weights);
    for (key, raw) in &acc.line_raw {
        facts.line_heights.insert(key, json_number_or_string(raw));
    }
    facts.base_unit = base_unit(&acc.spacing, root_px);
    facts.border_radius = props
        .iter()
        .find(|(name, _)| {
            matches!(
                name.as_str(),
                "--radius" | "--border-radius" | "--rounded" | "--radius-md"
            )
        })
        .and_then(|(_, v)| resolve(v, &props, 0))
        .map(|v| normalize_len(&v, root_px))
        .or_else(|| acc.radius.top());
    facts.button_primary = acc.primary.clone().over(&acc.base);
    // A secondary button inherits the base button rules, but only exists when a rule names it.
    facts.button_secondary = if acc.secondary.is_empty() {
        Component::default()
    } else {
        acc.secondary.clone().over(&acc.base)
    };
    facts.transition_duration = acc.durations.top();
    facts.easing = acc.easings.top();
    facts.keyframes = sheet.keyframes.iter().take(10).cloned().collect();
    facts.max_width = acc.max_widths.top().or_else(|| {
        props
            .iter()
            .find(|(n, _)| {
                matches!(
                    n.as_str(),
                    "--container-width"
                        | "--max-width"
                        | "--content-width"
                        | "--container-max-width"
                        | "--site-width"
                )
            })
            .and_then(|(_, v)| resolve(v, &props, 0))
            .map(|v| normalize_len(&v, root_px))
    });
    facts.columns = acc.columns.top();
    facts
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::super::css;
    use super::*;

    fn facts(css_text: &str) -> Facts {
        let mut s = Sheet::default();
        css::parse(css_text, &mut s);
        analyze(&s)
    }

    fn hex(c: Option<Rgb>) -> Option<String> {
        c.map(Rgb::hex)
    }

    #[test]
    fn custom_property_roles_resolve_var_chains_and_prefer_short_names() {
        let f = facts(
            ":root{--brand:#ff6b35;--color-primary:var(--brand);--primary-hover:#000;--secondary:rgb(0,78,137);\
             --accent:#F77F00;--bg:#1a1a1a;--bg-card:#333;--text:#fff;--text-muted:#b0b0b0;--link:#4af;\
             --success:#2ecc71;--warning:#f1c40f;--danger:#e74c3c;--primary-foreground:#fff;--bs-primary-rgb:1,2,3}",
        );
        let r = &f.roles;
        assert_eq!(hex(r.primary), Some("#FF6B35".into()));
        assert_eq!(hex(r.secondary), Some("#004E89".into()));
        assert_eq!(hex(r.accent), Some("#F77F00".into()));
        assert_eq!(hex(r.background), Some("#1A1A1A".into()));
        assert_eq!(hex(r.text_primary), Some("#FFFFFF".into()));
        assert_eq!(hex(r.text_secondary), Some("#B0B0B0".into()));
        assert_eq!(hex(r.link), Some("#44AAFF".into()));
        assert_eq!(hex(r.success), Some("#2ECC71".into()));
        assert_eq!(hex(r.warning), Some("#F1C40F".into()));
        assert_eq!(hex(r.error), Some("#E74C3C".into()));
    }

    #[test]
    fn dark_scoped_rules_do_not_leak_into_the_light_palette() {
        let f = facts(
            ":root{--bg:#fff}@media (prefers-color-scheme: dark){:root{--bg:#000}body{background:#000}}\
             body{background:#fff;color:#222}",
        );
        assert_eq!(hex(f.roles.background), Some("#FFFFFF".into()));
        assert_eq!(hex(f.body_bg), Some("#FFFFFF".into()));
        assert_eq!(hex(f.body_color), Some("#222222".into()));
    }

    #[test]
    fn button_rules_give_components_and_feed_the_colour_pool() {
        let f = facts(
            ".btn{border-radius:8px;padding:8px 16px}\
             .btn-primary{background:#ff6b35;color:#fff;border:1px solid #ff6b35}\
             .btn-secondary{background:transparent;color:#ff6b35;border-color:#ff6b35}\
             .btn-primary:hover{background:#000}\
             input[type=text]{border:1px solid #ccc;border-radius:4px;background:#fff}",
        );
        assert_eq!(
            f.button_primary,
            Component {
                background: Some("#FF6B35".into()),
                text_color: Some("#FFFFFF".into()),
                border_color: Some("#FF6B35".into()),
                border_radius: Some("8px".into()),
            }
        );
        assert_eq!(f.button_secondary.background.as_deref(), Some("transparent"));
        assert_eq!(f.button_secondary.text_color.as_deref(), Some("#FF6B35"));
        assert_eq!(f.input.border_radius.as_deref(), Some("4px"));
        assert_eq!(hex(f.pool.first().copied()), Some("#FF6B35".into()));
    }

    #[test]
    fn typography_fonts_sizes_weights_and_line_heights() {
        let f = facts(
            "html{font-size:62.5%}\
             body{font-family:'Inter',sans-serif;font-size:1.6rem;line-height:1.5}\
             h1,h2{font-family:\"Playfair Display\",serif;font-weight:700;line-height:1.1}\
             h1{font-size:4.8rem}h2{font-size:3.6rem}.prose h2{font-size:9px}h3{font:600 2.4rem/1.2 Inter,sans-serif}\
             code,pre{font-family:'Roboto Mono',monospace}\
             .a{font-weight:400}.b{font-weight:500}.c{font-weight:700}p{font-weight:normal}",
        );
        assert_eq!(f.body_font.as_deref(), Some("Inter"));
        assert_eq!(f.heading_font.as_deref(), Some("Playfair Display"));
        assert_eq!(f.code_font.as_deref(), Some("Roboto Mono"));
        assert_eq!(f.fonts[0], "Inter");
        assert!(f.fonts.contains(&"Roboto Mono".to_owned()));
        assert_eq!(f.font_sizes["body"], "16px");
        assert_eq!(f.font_sizes["h1"], "48px");
        assert_eq!(f.font_sizes["h2"], "36px", "bare h2 beats the descendant rule");
        assert_eq!(f.font_sizes["h3"], "24px");
        assert_eq!(f.font_weights["regular"], 400);
        assert_eq!(f.font_weights["medium"], 500);
        assert_eq!(f.font_weights["bold"], 700);
        assert_eq!(f.line_heights["body"], json!(1.5));
        assert_eq!(f.line_heights["heading"], json!(1.2));
    }

    #[test]
    fn spacing_base_unit_radius_motion_and_layout() {
        let f = facts(
            ".a{padding:8px 16px;margin:24px}.b{padding:16px;gap:8px}.c{margin:0 0 32px}\
             .card{border-radius:12px}.chip{border-radius:12px}.x{border-radius:2px}\
             .btn{transition:all .3s ease-in-out,color .2s ease}.y{transition-duration:300ms}\
             .container{max-width:1200px}.wrapper{max-width:1200px}.grid{grid-template-columns:repeat(12,1fr)}\
             header{height:64px}footer{height:4rem}@keyframes fade{from{opacity:0}to{opacity:1}}",
        );
        assert_eq!(f.base_unit, Some(8));
        assert_eq!(f.border_radius.as_deref(), Some("12px"));
        assert_eq!(f.transition_duration.as_deref(), Some("0.3s"));
        assert_eq!(f.easing.as_deref(), Some("ease-in-out"));
        assert_eq!(f.keyframes, ["fade"]);
        assert_eq!(f.max_width.as_deref(), Some("1200px"));
        assert_eq!(f.columns, Some(12));
        assert_eq!(f.header_height.as_deref(), Some("64px"));
        assert_eq!(f.footer_height.as_deref(), Some("64px"));
    }

    #[test]
    fn semantic_selectors_and_color_scheme_declaration() {
        let f = facts(".alert-success{color:#155724}.text-danger{color:#dc3545}.warning{background:#ffc107}body{color-scheme:dark}");
        assert_eq!(hex(f.success), Some("#155724".into()));
        assert_eq!(hex(f.error), Some("#DC3545".into()));
        assert_eq!(hex(f.warning), Some("#FFC107".into()));
        assert!(f.dark_scheme);
    }

    #[test]
    fn unresolvable_var_and_empty_sheet_yield_nothing() {
        let f = facts("a{color:var(--missing)}b{color:var(--missing, #123456)}");
        assert_eq!(
            f.text_ranked,
            [Rgb {
                r: 0x12,
                g: 0x34,
                b: 0x56
            }]
        );
        let empty = facts("");
        assert!(empty.fonts.is_empty() && empty.pool.is_empty() && empty.base_unit.is_none());
    }

    #[test]
    fn classify_names() {
        assert_eq!(classify("--primary").map(|c| c.0), Some(Role::Primary));
        assert_eq!(classify("--primary-foreground"), None);
        assert!(classify("--blue-500").is_none());
        assert!(classify("--font-size-lg").is_none());
        assert_eq!(
            classify("--wp--preset--color--primary").map(|c| c.0),
            Some(Role::Primary)
        );
    }
}
