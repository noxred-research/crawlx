//! Role-driven action vocabulary.

use crate::identity::ActionKind;
use crate::ids::{FixtureFileId, TabId};
use crate::observation::RuntimeLocator;
use crate::secret::SecretOr;
use serde::{Deserialize, Serialize};

/// Pointer button for `Click`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum PointerButton {
    /// Primary button (the default).
    #[default]
    Left,
    /// Middle (wheel) button.
    Middle,
    /// Secondary (context-menu) button.
    Right,
}

/// Keyboard modifiers held during an action.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub struct Modifiers {
    /// `Alt` (`Option` on macOS) is held.
    pub alt: bool,
    /// `Control` is held.
    pub ctrl: bool,
    /// `Meta` (`Command` on macOS, `Windows` key elsewhere) is held.
    pub meta: bool,
    /// `Shift` is held.
    pub shift: bool,
}

/// Key chord such as `Enter`, `Escape`, `Shift+Tab`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct KeyChord {
    /// Key name as in `KeyboardEvent.key`, e.g. `Enter`, `Escape`, `Tab`, or a single character.
    pub key: String,
    /// Modifiers held while `key` is pressed.
    pub modifiers: Modifiers,
}

/// A `<select>`/listbox option, by value or by visible label.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum OptionKey {
    /// Match the option's `value` attribute.
    Value(String),
    /// Match the option's visible label text.
    Label(String),
    /// Zero-based position of the option within its `<select>`/listbox.
    Index(u32),
}

/// Scroll amount in CSS pixels.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ScrollDelta {
    /// Horizontal scroll in CSS pixels; positive scrolls right.
    pub dx: f64,
    /// Vertical scroll in CSS pixels; positive scrolls down.
    pub dy: f64,
}

/// The browser-level action the Session Actor performs. Locators are runtime
/// handles valid for one epoch; the enum is not persisted, only its `kind()`.
#[derive(Clone, Debug)]
pub enum BrowserAction {
    /// Pointer click on `target` with the given button and held modifiers.
    Click {
        /// Element to click.
        target: RuntimeLocator,
        /// Pointer button pressed.
        button: PointerButton,
        /// Keyboard modifiers held during the click.
        modifiers: Modifiers,
    },
    /// Focus `target` and activate it with the keyboard (Enter/Space) instead of the pointer.
    KeyboardActivate {
        /// Element to activate.
        target: RuntimeLocator,
    },
    /// Type text into `target`.
    Type {
        /// Text field to type into.
        target: RuntimeLocator,
        /// Text to enter; secret values are never logged or persisted in clear.
        value: SecretOr<String>,
        /// Replace the existing content when `true`; append to it when `false`.
        clear_first: bool,
    },
    /// Choose one or more options in a `<select>`/listbox.
    Select {
        /// The `<select>` or listbox element.
        target: RuntimeLocator,
        /// Options to select; several only make sense for multi-select controls.
        options: Vec<OptionKey>,
    },
    /// Set a checkbox, radio, or switch to a definite state.
    SetChecked {
        /// The checkable control.
        target: RuntimeLocator,
        /// Desired checked state.
        checked: bool,
    },
    /// Set a range input (slider) to a value.
    SetRange {
        /// The range control.
        target: RuntimeLocator,
        /// Desired value, in the control's own units (within its `min`..`max`).
        value: f64,
    },
    /// Move the pointer over `target` without clicking.
    Hover {
        /// Element to hover.
        target: RuntimeLocator,
    },
    /// Drag one element and drop it onto another.
    Drag {
        /// Element the drag starts on.
        source: RuntimeLocator,
        /// Element the drag is dropped onto.
        destination: RuntimeLocator,
    },
    /// Attach a fixture file through a file input.
    Upload {
        /// File input or control that opens the file chooser.
        target: RuntimeLocator,
        /// Registered fixture file to upload.
        fixture: FixtureFileId,
    },
    /// Scroll with the mouse wheel.
    Scroll {
        /// Element to scroll over; `None` scrolls at the centre of the viewport.
        container: Option<RuntimeLocator>,
        /// Wheel distance in CSS pixels.
        delta: ScrollDelta,
    },
    /// Press a sequence of key chords in order on the focused element.
    Keys {
        /// Chords pressed one after another.
        sequence: Vec<KeyChord>,
    },
    /// Navigate the current tab to a URL.
    Navigate {
        /// Destination URL.
        url: url::Url,
    },
    /// Solve detected CAPTCHA widgets and deliver their secret tokens after kernel admission.
    SolveCaptcha,
    /// Bring another tab to the front and make it the active tab.
    SwitchTab {
        /// Tab to activate.
        tab: TabId,
    },
    /// Close a tab.
    CloseTab {
        /// Tab to close.
        tab: TabId,
    },
    /// Only when `dynamic.syntheticClick = true`; `fidelity = synthetic_dom_event`, lane `diagnostic`.
    SyntheticClick {
        /// Element that receives the dispatched DOM click event.
        target: RuntimeLocator,
    },
}

impl BrowserAction {
    /// The persisted action kind.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::Click { .. } => ActionKind::Click,
            Self::KeyboardActivate { .. } => ActionKind::KeyboardActivate,
            Self::Type { .. } => ActionKind::Type,
            Self::Select { .. } => ActionKind::Select,
            Self::SetChecked { .. } => ActionKind::SetChecked,
            Self::SetRange { .. } => ActionKind::SetRange,
            Self::Hover { .. } => ActionKind::Hover,
            Self::Drag { .. } => ActionKind::Drag,
            Self::Upload { .. } => ActionKind::Upload,
            Self::Scroll { .. } => ActionKind::Scroll,
            Self::Keys { .. } => ActionKind::Keys,
            Self::Navigate { .. } => ActionKind::Navigate,
            Self::SolveCaptcha => ActionKind::SolveCaptcha,
            Self::SwitchTab { .. } => ActionKind::SwitchTab,
            Self::CloseTab { .. } => ActionKind::CloseTab,
            Self::SyntheticClick { .. } => ActionKind::SyntheticClick,
        }
    }

    /// Primary target locator, if the action has one.
    #[must_use]
    pub fn target(&self) -> Option<&RuntimeLocator> {
        match self {
            Self::Click { target, .. }
            | Self::KeyboardActivate { target }
            | Self::Type { target, .. }
            | Self::Select { target, .. }
            | Self::SetChecked { target, .. }
            | Self::SetRange { target, .. }
            | Self::Hover { target }
            | Self::Upload { target, .. }
            | Self::SyntheticClick { target } => Some(target),
            Self::Drag { source, .. } => Some(source),
            Self::Scroll { container, .. } => container.as_ref(),
            Self::SolveCaptcha => None,
            Self::Keys { .. } | Self::Navigate { .. } | Self::SwitchTab { .. } | Self::CloseTab { .. } => {
                None
            }
        }
    }

    /// Does this variant mutate the page through a native input path?
    /// Synthetic clicks and scripted navigation are `diagnostic` lane.
    #[must_use]
    pub const fn fidelity(&self) -> crate::traffic::Fidelity {
        use crate::traffic::Fidelity;
        match self {
            Self::Click { .. } | Self::Hover { .. } | Self::Drag { .. } | Self::Scroll { .. } => {
                Fidelity::NativePointer
            }
            Self::KeyboardActivate { .. }
            | Self::Keys { .. }
            | Self::Select { .. }
            | Self::SetChecked { .. }
            | Self::SetRange { .. } => Fidelity::NativeKeyboard,
            Self::Type { .. } => Fidelity::NativeTextInput,
            Self::Upload { .. } => Fidelity::FileChooser,
            Self::Navigate { .. } | Self::SwitchTab { .. } | Self::CloseTab { .. } => {
                Fidelity::ScriptedNavigation
            }
            Self::SolveCaptcha => Fidelity::SyntheticDomEvent,
            Self::SyntheticClick { .. } => Fidelity::SyntheticDomEvent,
        }
    }
}
