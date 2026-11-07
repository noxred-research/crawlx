//! Native input: key definitions, modifier masks and pointer/keyboard sequences over
//! `Input.dispatch*`. Every event goes through the browser's input pipeline,
//! so pages see trusted events.

use crate::cdp::CdpSession;
use crawlx_core::action::{KeyChord, Modifiers, PointerButton};
use crawlx_core::browser::BrowserError;
use serde_json::{json, Value};

/// One key as CDP wants it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyDef {
    /// DOM `KeyboardEvent.key` value (`Enter`, `a`, `ArrowDown`).
    pub key: String,
    /// DOM `KeyboardEvent.code` value (physical key, e.g. `KeyA`, `Enter`).
    pub code: String,
    /// Windows virtual-key code, sent as both `windowsVirtualKeyCode` and `nativeVirtualKeyCode`.
    pub vk: i64,
    /// Text the key produces, when printable.
    pub text: Option<String>,
}

fn named(key: &str, code: &str, vk: i64, text: Option<&str>) -> KeyDef {
    KeyDef {
        key: key.to_owned(),
        code: code.to_owned(),
        vk,
        text: text.map(str::to_owned),
    }
}

/// Resolve a key name (`Enter`, `ArrowDown`, `a`, `F5`, ...). Case-insensitive for named keys.
#[must_use]
pub fn key_def(name: &str) -> Option<KeyDef> {
    let lower = name.to_ascii_lowercase();
    let def = match lower.as_str() {
        "enter" | "return" => named("Enter", "Enter", 13, Some("\r")),
        "tab" => named("Tab", "Tab", 9, None),
        "escape" | "esc" => named("Escape", "Escape", 27, None),
        "backspace" => named("Backspace", "Backspace", 8, None),
        "delete" | "del" => named("Delete", "Delete", 46, None),
        "insert" => named("Insert", "Insert", 45, None),
        "arrowup" | "up" => named("ArrowUp", "ArrowUp", 38, None),
        "arrowdown" | "down" => named("ArrowDown", "ArrowDown", 40, None),
        "arrowleft" | "left" => named("ArrowLeft", "ArrowLeft", 37, None),
        "arrowright" | "right" => named("ArrowRight", "ArrowRight", 39, None),
        "home" => named("Home", "Home", 36, None),
        "end" => named("End", "End", 35, None),
        "pageup" => named("PageUp", "PageUp", 33, None),
        "pagedown" => named("PageDown", "PageDown", 34, None),
        "space" | " " => named(" ", "Space", 32, Some(" ")),
        other => {
            if let Some(n) = other.strip_prefix('f').and_then(|n| n.parse::<i64>().ok()) {
                if (1..=12).contains(&n) {
                    return Some(named(&format!("F{n}"), &format!("F{n}"), 111 + n, None));
                }
            }
            let mut chars = name.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            return Some(char_def(c));
        }
    };
    Some(def)
}

fn char_def(c: char) -> KeyDef {
    let (code, vk) = if c.is_ascii_alphabetic() {
        (
            format!("Key{}", c.to_ascii_uppercase()),
            i64::from(u32::from(c.to_ascii_uppercase())),
        )
    } else if c.is_ascii_digit() {
        (format!("Digit{c}"), i64::from(u32::from(c)))
    } else {
        (String::new(), 0)
    };
    KeyDef {
        key: c.to_string(),
        code,
        vk,
        text: Some(c.to_string()),
    }
}

/// CDP modifier bitmask: Alt=1, Ctrl=2, Meta=4, Shift=8.
#[must_use]
pub const fn modifier_bits(m: &Modifiers) -> u32 {
    (m.alt as u32) | ((m.ctrl as u32) << 1) | ((m.meta as u32) << 2) | ((m.shift as u32) << 3)
}

/// CDP button name and the `buttons` bit for a pointer button.
#[must_use]
pub const fn button_info(b: PointerButton) -> (&'static str, u32) {
    match b {
        PointerButton::Left => ("left", 1),
        PointerButton::Right => ("right", 2),
        PointerButton::Middle => ("middle", 4),
    }
}

/// Editing command a Ctrl/Meta chord maps to (CDP does not run shortcuts by itself).
fn chord_command(key: &KeyDef, bits: u32) -> Option<&'static str> {
    if bits & 0b110 == 0 {
        return None;
    }
    match key.key.to_ascii_lowercase().as_str() {
        "a" => Some("selectAll"),
        "c" => Some("copy"),
        "x" => Some("cut"),
        "v" => Some("paste"),
        "z" => Some("undo"),
        _ => None,
    }
}

/// Dispatch key down + key up for `key` with `bits` modifiers held.
///
/// A `keyDown` carrying `text` is sent for unmodified printable keys, otherwise a
/// `rawKeyDown` (with an editing command for Ctrl/Meta chords such as copy/paste).
///
/// # Errors
/// Returns the [`CdpSession::dispatch_key`] errors: [`BrowserError::Transport`],
/// [`BrowserError::Protocol`], [`BrowserError::TargetClosed`] or [`BrowserError::Timeout`].
pub async fn press(session: &CdpSession, key: &KeyDef, bits: u32) -> Result<(), BrowserError> {
    let printable = key.text.is_some() && bits & 0b111 == 0;
    let mut down: Value = json!({
        "type": if printable { "keyDown" } else { "rawKeyDown" },
        "modifiers": bits,
        "key": key.key,
        "code": key.code,
        "windowsVirtualKeyCode": key.vk,
        "nativeVirtualKeyCode": key.vk,
    });
    if printable {
        if let Some(t) = &key.text {
            down["text"] = json!(t);
            down["unmodifiedText"] = json!(t);
        }
    }
    if let Some(cmd) = chord_command(key, bits) {
        down["commands"] = json!([cmd]);
    }
    session.dispatch_key(down).await?;
    session
        .dispatch_key(json!({
            "type": "keyUp",
            "modifiers": bits,
            "key": key.key,
            "code": key.code,
            "windowsVirtualKeyCode": key.vk,
            "nativeVirtualKeyCode": key.vk,
        }))
        .await
}

/// Press a chord (`Shift+Tab`): the modifiers from the chord are held for the key.
///
/// # Errors
/// Returns [`BrowserError::Unsupported`] if `chord.key` is not a known key name, otherwise
/// the errors of [`press`].
pub async fn press_chord(session: &CdpSession, chord: &KeyChord) -> Result<(), BrowserError> {
    let def = key_def(&chord.key)
        .ok_or_else(|| BrowserError::Unsupported(format!("unknown key {:?}", chord.key)))?;
    press(session, &def, modifier_bits(&chord.modifiers)).await
}

/// Press a named key with no modifiers.
///
/// # Errors
/// Returns [`BrowserError::Unsupported`] if `name` is not a known key name, otherwise the
/// errors of [`press`].
pub async fn press_named(session: &CdpSession, name: &str) -> Result<(), BrowserError> {
    let def = key_def(name).ok_or_else(|| BrowserError::Unsupported(format!("unknown key {name:?}")))?;
    press(session, &def, 0).await
}

/// move → press → release at `(x, y)`.
///
/// `x`/`y` are CSS px relative to the viewport.
///
/// # Errors
/// Returns the [`CdpSession::dispatch_mouse`] errors: [`BrowserError::Transport`],
/// [`BrowserError::Protocol`], [`BrowserError::TargetClosed`] or [`BrowserError::Timeout`].
pub async fn click_at(
    session: &CdpSession,
    x: f64,
    y: f64,
    button: PointerButton,
    modifiers: &Modifiers,
) -> Result<(), BrowserError> {
    let (name, bit) = button_info(button);
    let mods = modifier_bits(modifiers);
    session
        .dispatch_mouse("mouseMoved", x, y, "none", 0, 0, mods, None)
        .await?;
    session
        .dispatch_mouse("mousePressed", x, y, name, bit, 1, mods, None)
        .await?;
    session
        .dispatch_mouse("mouseReleased", x, y, name, 0, 1, mods, None)
        .await
}

/// Hover: a single `mouseMoved`.
///
/// # Errors
/// Returns the [`CdpSession::dispatch_mouse`] errors: [`BrowserError::Transport`],
/// [`BrowserError::Protocol`], [`BrowserError::TargetClosed`] or [`BrowserError::Timeout`].
pub async fn hover_at(session: &CdpSession, x: f64, y: f64) -> Result<(), BrowserError> {
    session
        .dispatch_mouse("mouseMoved", x, y, "none", 0, 0, 0, None)
        .await
}

/// `mouseWheel` at `(x, y)`.
///
/// `dx`/`dy` are the horizontal and vertical wheel deltas in CSS px.
///
/// # Errors
/// Returns the [`CdpSession::dispatch_mouse`] errors: [`BrowserError::Transport`],
/// [`BrowserError::Protocol`], [`BrowserError::TargetClosed`] or [`BrowserError::Timeout`].
pub async fn wheel_at(session: &CdpSession, x: f64, y: f64, dx: f64, dy: f64) -> Result<(), BrowserError> {
    session
        .dispatch_mouse("mouseWheel", x, y, "none", 0, 0, 0, Some((dx, dy)))
        .await
}

/// Intermediate points from `from` to `to`, excluding `from`, ending exactly at `to`.
#[must_use]
pub fn drag_path(from: (f64, f64), to: (f64, f64), steps: u32) -> Vec<(f64, f64)> {
    let steps = steps.max(1);
    (1..=steps)
        .map(|i| {
            let t = f64::from(i) / f64::from(steps);
            (from.0 + (to.0 - from.0) * t, from.1 + (to.1 - from.1) * t)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn named_and_char_keys() {
        let enter = key_def("enter").unwrap();
        assert_eq!((enter.key.as_str(), enter.vk), ("Enter", 13));
        assert_eq!(enter.text.as_deref(), Some("\r"));
        let a = key_def("a").unwrap();
        assert_eq!((a.code.as_str(), a.vk), ("KeyA", 65));
        let five = key_def("5").unwrap();
        assert_eq!(five.code, "Digit5");
        assert_eq!(key_def("F5").unwrap().vk, 116);
        assert_eq!(key_def("ArrowDown").unwrap().vk, 40);
        assert_eq!(key_def("Space").unwrap().text.as_deref(), Some(" "));
        assert!(key_def("NotAKey").is_none());
        assert!(key_def("F13").is_none());
    }

    #[test]
    fn modifier_masks() {
        let m = Modifiers {
            alt: true,
            ctrl: false,
            meta: false,
            shift: true,
        };
        assert_eq!(modifier_bits(&m), 1 | 8);
        let all = Modifiers {
            alt: true,
            ctrl: true,
            meta: true,
            shift: true,
        };
        assert_eq!(modifier_bits(&all), 15);
        assert_eq!(modifier_bits(&Modifiers::default()), 0);
    }

    #[test]
    fn chords_map_to_editing_commands() {
        let a = key_def("a").unwrap();
        assert_eq!(chord_command(&a, 2), Some("selectAll"));
        assert_eq!(chord_command(&a, 0), None);
        assert_eq!(chord_command(&key_def("q").unwrap(), 2), None);
    }

    #[test]
    fn drag_path_ends_at_destination() {
        let p = drag_path((0.0, 0.0), (100.0, 50.0), 4);
        assert_eq!(p.len(), 4);
        assert_eq!(p[3], (100.0, 50.0));
        assert_eq!(p[0], (25.0, 12.5));
        assert_eq!(drag_path((1.0, 1.0), (1.0, 1.0), 0), vec![(1.0, 1.0)]);
    }

    #[test]
    fn button_bits() {
        assert_eq!(button_info(PointerButton::Left), ("left", 1));
        assert_eq!(button_info(PointerButton::Right), ("right", 2));
    }
}
