//! CSS colour parsing for the branding heuristics: hex, `rgb()/rgba()`, `hsl()/hsla()` and the
//! common named colours. Only fully opaque colours are brand candidates; `transparent` (and any
//! zero-alpha colour) is reported separately because a button may legitimately be transparent.

/// An opaque sRGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// A parsed CSS paint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Paint {
    /// Fully opaque colour.
    Color(Rgb),
    /// `transparent` or any zero-alpha colour.
    Transparent,
}

impl Rgb {
    /// Upper-case `#RRGGBB`.
    pub fn hex(self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }

    /// Perceived brightness 0..=255 (YIQ).
    pub fn brightness(self) -> u32 {
        (u32::from(self.r) * 299 + u32::from(self.g) * 587 + u32::from(self.b) * 114) / 1000
    }

    fn unit(self) -> (f32, f32, f32) {
        (
            f32::from(self.r) / 255.0,
            f32::from(self.g) / 255.0,
            f32::from(self.b) / 255.0,
        )
    }

    /// HSL lightness 0..=1.
    pub fn lightness(self) -> f32 {
        let (r, g, b) = self.unit();
        (r.max(g).max(b) + r.min(g).min(b)) / 2.0
    }

    /// HSL saturation 0..=1.
    pub fn saturation(self) -> f32 {
        let (r, g, b) = self.unit();
        let (max, min) = (r.max(g).max(b), r.min(g).min(b));
        let delta = max - min;
        if delta <= f32::EPSILON {
            return 0.0;
        }
        let l = (max + min) / 2.0;
        delta / (1.0 - (2.0 * l - 1.0).abs())
    }

    /// True for greys, whites and blacks: nothing a brand would call a colour.
    pub fn is_neutral(self) -> bool {
        self.saturation() < 0.18 || self.lightness() > 0.96 || self.lightness() < 0.04
    }

    /// Squared euclidean distance in RGB.
    pub fn distance(self, other: Rgb) -> u32 {
        let d = |a: u8, b: u8| u32::from(a.abs_diff(b)).pow(2);
        d(self.r, other.r) + d(self.g, other.g) + d(self.b, other.b)
    }

    /// Distinct enough to be listed as another brand colour.
    pub fn differs_from(self, other: Rgb) -> bool {
        self.distance(other) > 40 * 40
    }
}

/// First colour token of a declaration value (`background: #fff url(x) no-repeat` → `#fff`).
/// Callers resolve `var()` first.
pub(super) fn first_paint(value: &str) -> Option<Paint> {
    split_top_level(value).into_iter().find_map(parse_paint)
}

/// Whitespace-separated tokens of `value`, keeping parenthesised groups whole.
pub(super) fn split_top_level(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    for (i, c) in value.char_indices() {
        match c {
            '(' => {
                depth += 1;
                start.get_or_insert(i);
            }
            ')' => depth = depth.saturating_sub(1),
            c if c.is_whitespace() && depth == 0 => {
                if let Some(s) = start.take() {
                    out.push(&value[s..i]);
                }
            }
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(s) = start {
        out.push(&value[s..]);
    }
    out
}

/// Parse one CSS colour token.
pub(super) fn parse_paint(token: &str) -> Option<Paint> {
    let t = token.trim().to_ascii_lowercase();
    if t == "transparent" {
        return Some(Paint::Transparent);
    }
    if let Some(hex) = t.strip_prefix('#') {
        return parse_hex(hex);
    }
    if let Some(args) = function_args(&t, &["rgb", "rgba"]) {
        return parse_rgb(args);
    }
    if let Some(args) = function_args(&t, &["hsl", "hsla"]) {
        return parse_hsl(args);
    }
    named(&t).map(|(r, g, b)| Paint::Color(Rgb { r, g, b }))
}

fn function_args<'a>(t: &'a str, names: &[&str]) -> Option<&'a str> {
    let open = t.find('(')?;
    if !names.contains(&&t[..open]) || !t.ends_with(')') {
        return None;
    }
    Some(&t[open + 1..t.len() - 1])
}

fn paint_from(r: u8, g: u8, b: u8, alpha: f32) -> Option<Paint> {
    if alpha <= 0.0 {
        Some(Paint::Transparent)
    } else if alpha >= 1.0 {
        Some(Paint::Color(Rgb { r, g, b }))
    } else {
        None
    }
}

fn parse_hex(hex: &str) -> Option<Paint> {
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let digit = |i: usize| u8::from_str_radix(&hex[i..=i], 16).ok().map(|d| d * 17);
    let pair = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    let (r, g, b, a) = match hex.len() {
        3 => (digit(0)?, digit(1)?, digit(2)?, 255),
        4 => (digit(0)?, digit(1)?, digit(2)?, digit(3)?),
        6 => (pair(0)?, pair(2)?, pair(4)?, 255),
        8 => (pair(0)?, pair(2)?, pair(4)?, pair(6)?),
        _ => return None,
    };
    paint_from(r, g, b, f32::from(a) / 255.0)
}

/// Split function arguments on commas, whitespace and `/`.
fn args(s: &str) -> Vec<&str> {
    s.split(|c: char| c == ',' || c == '/' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .collect()
}

fn number(s: &str) -> Option<f32> {
    s.trim_end_matches('%')
        .parse::<f32>()
        .ok()
        .filter(|v| v.is_finite())
}

fn alpha(s: Option<&&str>) -> Option<f32> {
    match s {
        None => Some(1.0),
        Some(a) => {
            let v = number(a)?;
            Some(if a.ends_with('%') { v / 100.0 } else { v })
        }
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped to 0..=255 first
fn to_u8(v: f32) -> u8 {
    v.round().clamp(0.0, 255.0) as u8
}

fn parse_rgb(a: &str) -> Option<Paint> {
    let p = args(a);
    if p.len() < 3 || p.len() > 4 {
        return None;
    }
    let channel = |s: &str| -> Option<u8> {
        let v = number(s)?;
        Some(to_u8(if s.ends_with('%') { v * 2.55 } else { v }))
    };
    paint_from(channel(p[0])?, channel(p[1])?, channel(p[2])?, alpha(p.get(3))?)
}

fn parse_hsl(a: &str) -> Option<Paint> {
    let p = args(a);
    if p.len() < 3 || p.len() > 4 {
        return None;
    }
    let h = number(p[0].trim_end_matches("deg"))?.rem_euclid(360.0);
    let s = (number(p[1])? / 100.0).clamp(0.0, 1.0);
    let l = (number(p[2])? / 100.0).clamp(0.0, 1.0);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match h {
        h if h < 60.0 => (c, x, 0.0),
        h if h < 120.0 => (x, c, 0.0),
        h if h < 180.0 => (0.0, c, x),
        h if h < 240.0 => (0.0, x, c),
        h if h < 300.0 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    paint_from(
        to_u8((r + m) * 255.0),
        to_u8((g + m) * 255.0),
        to_u8((b + m) * 255.0),
        alpha(p.get(3))?,
    )
}

/// The CSS named colours that appear in real brand stylesheets.
fn named(name: &str) -> Option<(u8, u8, u8)> {
    Some(match name {
        "black" => (0, 0, 0),
        "white" => (255, 255, 255),
        "red" => (255, 0, 0),
        "green" => (0, 128, 0),
        "blue" => (0, 0, 255),
        "yellow" => (255, 255, 0),
        "orange" => (255, 165, 0),
        "purple" => (128, 0, 128),
        "gray" | "grey" => (128, 128, 128),
        "silver" => (192, 192, 192),
        "maroon" => (128, 0, 0),
        "olive" => (128, 128, 0),
        "lime" => (0, 255, 0),
        "aqua" | "cyan" => (0, 255, 255),
        "teal" => (0, 128, 128),
        "navy" => (0, 0, 128),
        "fuchsia" | "magenta" => (255, 0, 255),
        "pink" => (255, 192, 203),
        "brown" => (165, 42, 42),
        "gold" => (255, 215, 0),
        "indigo" => (75, 0, 130),
        "violet" => (238, 130, 238),
        "crimson" => (220, 20, 60),
        "coral" => (255, 127, 80),
        "tomato" => (255, 99, 71),
        "salmon" => (250, 128, 114),
        "khaki" => (240, 230, 140),
        "beige" => (245, 245, 220),
        "ivory" => (255, 255, 240),
        "lavender" => (230, 230, 250),
        "turquoise" => (64, 224, 208),
        "darkgray" | "darkgrey" => (169, 169, 169),
        "lightgray" | "lightgrey" => (211, 211, 211),
        "dimgray" | "dimgrey" => (105, 105, 105),
        "slategray" | "slategrey" => (112, 128, 144),
        "whitesmoke" => (245, 245, 245),
        "gainsboro" => (220, 220, 220),
        "darkblue" => (0, 0, 139),
        "darkgreen" => (0, 100, 0),
        "darkred" => (139, 0, 0),
        "steelblue" => (70, 130, 180),
        "royalblue" => (65, 105, 225),
        "dodgerblue" => (30, 144, 255),
        "skyblue" => (135, 206, 235),
        "orangered" => (255, 69, 0),
        "firebrick" => (178, 34, 34),
        "forestgreen" => (34, 139, 34),
        "seagreen" => (46, 139, 87),
        "limegreen" => (50, 205, 50),
        "midnightblue" => (25, 25, 112),
        "rebeccapurple" => (102, 51, 153),
        "hotpink" => (255, 105, 180),
        "deeppink" => (255, 20, 147),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn hex(v: &str) -> String {
        match parse_paint(v) {
            Some(Paint::Color(c)) => c.hex(),
            other => panic!("{v}: {other:?}"),
        }
    }

    #[test]
    fn hex_forms() {
        assert_eq!(hex("#f63"), "#FF6633");
        assert_eq!(hex("#FF6B35"), "#FF6B35");
        assert_eq!(hex("#ff6b35ff"), "#FF6B35");
        assert_eq!(parse_paint("#ff6b3500"), Some(Paint::Transparent));
        assert_eq!(parse_paint("#ff6b3580"), None);
        assert_eq!(parse_paint("#12"), None);
        assert_eq!(parse_paint("#ggg"), None);
    }

    #[test]
    fn rgb_forms() {
        assert_eq!(hex("rgb(255, 107, 53)"), "#FF6B35");
        assert_eq!(hex("rgba(255,107,53,1)"), "#FF6B35");
        assert_eq!(hex("rgb(255 107 53 / 100%)"), "#FF6B35");
        assert_eq!(hex("rgb(100%, 0%, 0%)"), "#FF0000");
        assert_eq!(parse_paint("rgba(0,0,0,0)"), Some(Paint::Transparent));
        assert_eq!(parse_paint("rgba(0,0,0,.5)"), None);
        assert_eq!(parse_paint("rgb(1,2)"), None);
    }

    #[test]
    fn hsl_forms() {
        assert_eq!(hex("hsl(0, 100%, 50%)"), "#FF0000");
        assert_eq!(hex("hsl(120deg 100% 25%)"), "#008000");
        assert_eq!(hex("hsla(240, 100%, 50%, 1)"), "#0000FF");
    }

    #[test]
    fn names_and_keywords() {
        assert_eq!(hex("Navy"), "#000080");
        assert_eq!(parse_paint("transparent"), Some(Paint::Transparent));
        assert_eq!(parse_paint("currentcolor"), None);
        assert_eq!(parse_paint("inherit"), None);
    }

    #[test]
    fn first_paint_scans_shorthand_values() {
        assert_eq!(
            first_paint("url(data:image/png;base64,AAA) no-repeat #123456 center"),
            Some(Paint::Color(Rgb {
                r: 0x12,
                g: 0x34,
                b: 0x56
            }))
        );
        assert_eq!(
            first_paint("1px solid rgb(10, 20, 30)").map(|p| p == Paint::Color(Rgb { r: 10, g: 20, b: 30 })),
            Some(true)
        );
        assert_eq!(first_paint("none"), None);
    }

    #[test]
    fn colour_metrics() {
        let white = Rgb {
            r: 255,
            g: 255,
            b: 255,
        };
        let black = Rgb { r: 0, g: 0, b: 0 };
        let orange = Rgb {
            r: 0xFF,
            g: 0x6B,
            b: 0x35,
        };
        assert!(white.brightness() > 250 && black.brightness() == 0);
        assert!(white.is_neutral() && black.is_neutral());
        assert!(!orange.is_neutral());
        assert!(orange.saturation() > 0.9);
        assert!(orange.differs_from(white));
        assert!(!orange.differs_from(Rgb {
            r: 0xFF,
            g: 0x6C,
            b: 0x36
        }));
    }
}
