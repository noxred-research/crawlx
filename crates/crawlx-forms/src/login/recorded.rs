//! Recorded login flows: a Chrome DevTools
//! Recorder export or katana's explicit step list compiled into [`LoginStep`]s.
//!
//! Ported from projectdiscovery/katana `pkg/engine/headless/auth/recording.go` and
//! `pkg/engine/headless/auth/step.go` at commit 9662cd7 (MIT).
//!
//! The flow is **data**: it never carries a credential. `change` values typed into a
//! control that looks like a username or password field become [`FillValue::Placeholder`]
//! at parse time (the recorded literal is dropped, never stored), and `{{username}}` /
//! `{{password}}` placeholders stay placeholders through `Debug` and serde. They are
//! resolved only by [`FillValue::resolve`], immediately before the native-input step, into a
//! `SecretOr<String>`. Replay itself lives in `crawlx-worker` (every step is a
//! kernel-adjudicated action on the trusted lane).

use super::{CredentialPart, LoginStep};
use crawlx_core::secret::SecretOr;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Upper bound on steps in one flow; longer flows are rejected by [`RecordedFlow::validate`].
pub const MAX_STEPS: usize = 100;

/// Default deadline of a `waitvisible` step without an explicit duration.
pub const DEFAULT_WAIT_VISIBLE_TIMEOUT_MS: u64 = 10_000;

/// Path stems that log a session out; excluded from the frontier while authenticated.
/// Matched per path segment by [`is_logout_path`].
pub const LOGOUT_PATHS: [&str; 4] = ["/logout", "/signout", "/log_out", "/sign-out"];

/// Does `path` (the URL path, no query) contain a logout segment from [`LOGOUT_PATHS`]?
/// A segment matches with or without an extension (`/logout`, `/account/logout.php`).
#[must_use]
pub fn is_logout_path(path: &str) -> bool {
    path.split('/').filter(|s| !s.is_empty()).any(|segment| {
        let stem = segment.split_once('.').map_or(segment, |(stem, _)| stem);
        LOGOUT_PATHS.iter().any(|p| stem.eq_ignore_ascii_case(&p[1..]))
    })
}

/// How a [`Selector`] expression is to be interpreted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SelectorKind {
    /// A CSS selector.
    Css,
    /// An XPath expression (`xpath=` in explicit steps, `xpath/` in Recorder exports).
    XPath,
    /// An accessible name (`aria/` in Recorder exports): match by `aria-label` / AX name.
    Aria,
    /// Visible text (`text/` in Recorder exports): match by contained text.
    Text,
}

/// A control reference inside a recorded flow.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct Selector {
    /// How `expr` is interpreted.
    pub kind: SelectorKind,
    /// The selector expression without its kind prefix.
    pub expr: String,
}

impl Selector {
    /// A CSS selector.
    #[must_use]
    pub fn css(expr: impl Into<String>) -> Self {
        Self {
            kind: SelectorKind::Css,
            expr: expr.into(),
        }
    }

    /// Parse one selector string. Prefixes `xpath=` / `xpath/`, `aria/` and `text/` select
    /// the kind; `pierce/` (shadow-DOM piercing) is unsupported; anything else is CSS.
    /// `None` for an empty expression or an unsupported prefix.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        let (kind, expr) = if let Some(x) = s.strip_prefix("xpath=").or_else(|| s.strip_prefix("xpath/")) {
            (SelectorKind::XPath, x)
        } else if let Some(a) = s.strip_prefix("aria/") {
            (SelectorKind::Aria, a)
        } else if let Some(t) = s.strip_prefix("text/") {
            (SelectorKind::Text, t)
        } else if s.starts_with("pierce/") {
            return None;
        } else {
            (SelectorKind::Css, s)
        };
        let expr = expr.trim();
        (!expr.is_empty()).then(|| Self {
            kind,
            expr: expr.to_owned(),
        })
    }

    /// Choose the most engine-friendly candidate of a Recorder `selectors` list: CSS, then
    /// XPath, then ARIA name, then text. Each inner list is one selector; lists with more
    /// than one entry pierce shadow roots and are skipped.
    #[must_use]
    pub fn pick(groups: &[Vec<String>]) -> Option<Self> {
        let mut best: Option<Self> = None;
        for group in groups {
            let [single] = group.as_slice() else { continue };
            let Some(sel) = Self::parse(single) else { continue };
            let better = match &best {
                None => true,
                Some(b) => sel.kind.priority() < b.kind.priority(),
            };
            if better {
                best = Some(sel);
            }
        }
        best
    }

    /// Does the selector name a username / e-mail control (katana heuristics)?
    #[must_use]
    pub fn looks_like_username(&self) -> bool {
        let s = self.expr.to_ascii_lowercase();
        [
            "username",
            "user-name",
            "email",
            "e-mail",
            "autocomplete=\"username\"",
            "autocomplete=username",
        ]
        .iter()
        .any(|m| s.contains(m))
    }

    /// Does the selector name a password control (katana heuristics)?
    #[must_use]
    pub fn looks_like_password(&self) -> bool {
        let s = self.expr.to_ascii_lowercase();
        [
            "password",
            "passwd",
            "pwd",
            "type=\"password\"",
            "type=password",
            "current-password",
            "new-password",
        ]
        .iter()
        .any(|m| s.contains(m))
    }
}

impl SelectorKind {
    const fn priority(self) -> u8 {
        match self {
            Self::Css => 0,
            Self::XPath => 1,
            Self::Aria => 2,
            Self::Text => 3,
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            SelectorKind::Css => f.write_str(&self.expr),
            SelectorKind::XPath => write!(f, "xpath={}", self.expr),
            SelectorKind::Aria => write!(f, "aria/{}", self.expr),
            SelectorKind::Text => write!(f, "text/{}", self.expr),
        }
    }
}

/// What a `fill` step types: a literal or a credential placeholder.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FillValue {
    /// Text typed as is (never a credential).
    Literal(String),
    /// `{{username}}` / `{{password}}`: resolved by [`FillValue::resolve`] right before use.
    Placeholder(CredentialPart),
}

/// The `{{username}}` placeholder.
pub const USERNAME_PLACEHOLDER: &str = "{{username}}";
/// The `{{password}}` placeholder.
pub const PASSWORD_PLACEHOLDER: &str = "{{password}}";

impl FillValue {
    /// Parse a step value: exactly `{{username}}` / `{{password}}` is a placeholder, text
    /// without a placeholder is a literal; a literal that embeds a placeholder is rejected
    /// (the expansion could not be kept out of the journal).
    ///
    /// # Errors
    /// [`RecordedFlowError::MixedPlaceholder`] when `raw` contains a placeholder along with
    /// other text.
    pub fn parse(raw: &str) -> Result<Self, RecordedFlowError> {
        let trimmed = raw.trim();
        if trimmed == USERNAME_PLACEHOLDER {
            return Ok(Self::Placeholder(CredentialPart::Username));
        }
        if trimmed == PASSWORD_PLACEHOLDER {
            return Ok(Self::Placeholder(CredentialPart::Password));
        }
        if raw.contains(USERNAME_PLACEHOLDER) || raw.contains(PASSWORD_PLACEHOLDER) {
            return Err(RecordedFlowError::MixedPlaceholder);
        }
        Ok(Self::Literal(raw.to_owned()))
    }

    /// Resolve for execution: the username as plain text, the password as the secret it
    /// came in as, a literal as plain text.
    #[must_use]
    pub fn resolve(&self, username: &str, password: &SecretOr<String>) -> SecretOr<String> {
        match self {
            Self::Literal(s) => SecretOr::Plain(s.clone()),
            Self::Placeholder(CredentialPart::Username) => SecretOr::Plain(username.to_owned()),
            Self::Placeholder(CredentialPart::Password) => match password {
                SecretOr::Secret(_) => password.clone(),
                SecretOr::Plain(p) => SecretOr::secret(p.clone()),
            },
        }
    }

    /// Is this a credential placeholder?
    #[must_use]
    pub const fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder(_))
    }
}

/// Keys a `press` step may send (katana's key set).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PressKey {
    /// Enter / Return / NumpadEnter.
    Enter,
    /// Tab.
    Tab,
    /// Escape.
    Escape,
    /// Space.
    Space,
}

impl PressKey {
    /// Normalize a key name (`Enter`, `return`, `NumpadEnter`, `Tab`, `Escape`, `esc`,
    /// `Space`); `None` for any other key (character keys are captured by `change` steps).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        if name == " " {
            return Some(Self::Space);
        }
        match name.trim().to_ascii_lowercase().as_str() {
            "enter" | "return" | "numpadenter" => Some(Self::Enter),
            "tab" => Some(Self::Tab),
            "escape" | "esc" => Some(Self::Escape),
            "space" | " " => Some(Self::Space),
            _ => None,
        }
    }

    /// The name used in explicit steps.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enter => "enter",
            Self::Tab => "tab",
            Self::Escape => "escape",
            Self::Space => "space",
        }
    }
}

/// Why a flow cannot be parsed or replayed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedFlowError {
    /// The payload is not JSON of either supported shape.
    #[error("recorded flow is not valid json: {0}")]
    Json(String),
    /// The payload has no `steps`, or none survived compilation.
    #[error("recorded flow contains no replayable steps")]
    NoSteps,
    /// Neither a Recorder export (`type`) nor an explicit step list (`action`).
    #[error("recorded flow steps must be chrome recorder steps (type) or explicit steps (action)")]
    UnknownFormat,
    /// An explicit step uses an action outside katana's set.
    #[error("step {index} has unknown action {action:?}")]
    UnknownAction {
        /// 0-based index of the step.
        index: usize,
        /// The offending action.
        action: String,
    },
    /// A Recorder step type the compiler does not replay (`evaluate`, custom steps, ...).
    #[error("recording step {index} has unsupported type {step_type:?}")]
    UnsupportedStepType {
        /// 0-based index of the step.
        index: usize,
        /// The offending type.
        step_type: String,
    },
    /// A step that targets a control has no usable selector.
    #[error("step {index} ({action}) has no supported selector")]
    MissingSelector {
        /// 0-based index of the step.
        index: usize,
        /// Action of the step.
        action: &'static str,
    },
    /// A `navigate` step has no URL or one that is not `http`/`https`.
    #[error("step {index} (navigate) must target an http or https url: {url:?}")]
    NonHttpNavigate {
        /// 0-based index of the step.
        index: usize,
        /// The offending URL text.
        url: String,
    },
    /// A `press` step names a key outside [`PressKey`].
    #[error("step {index} (press) has unsupported key {key:?}")]
    UnsupportedKey {
        /// 0-based index of the step.
        index: usize,
        /// The offending key.
        key: String,
    },
    /// A `wait`/`waitvisible` duration is not a Go-style duration (`2s`, `500ms`).
    #[error("step {index} ({action}) has invalid duration {value:?}")]
    InvalidDuration {
        /// 0-based index of the step.
        index: usize,
        /// Action of the step.
        action: &'static str,
        /// The offending duration text.
        value: String,
    },
    /// More than [`MAX_STEPS`] steps.
    #[error("recorded flow has {count} steps, more than the {MAX_STEPS} allowed")]
    TooManySteps {
        /// Number of steps in the flow.
        count: usize,
    },
    /// A literal embeds `{{username}}` / `{{password}}` along with other text.
    #[error("a fill value must be a literal or exactly one placeholder, not a mix")]
    MixedPlaceholder,
    /// The flow is not a `recorded:` plan.
    #[error("login plan is not a recorded flow: {0:?}")]
    NotRecorded(String),
}

/// Chrome DevTools Recorder / `@puppeteer/replay` export (the fields that matter).
#[derive(Deserialize)]
struct RecordingFile {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    steps: Vec<RecordingStep>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RecordingStep {
    #[serde(rename = "type")]
    step_type: String,
    url: String,
    selectors: Vec<Vec<String>>,
    value: String,
    key: String,
}

/// Explicit `{ "steps": [ { "action", "selector", "value" } ] }` (katana's `LoginStep`).
#[derive(Deserialize)]
struct ExplicitFile {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    steps: Vec<ExplicitStep>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ExplicitStep {
    action: String,
    selector: String,
    value: String,
}

/// A compiled recorded flow.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RecordedFlow {
    /// Title of the Recorder export, if any.
    pub title: Option<String>,
    /// Steps in replay order; only selector-targeted and navigation variants of [`LoginStep`].
    pub steps: Vec<LoginStep>,
}

impl RecordedFlow {
    /// Parse a Recorder export or an explicit step list and validate the result.
    ///
    /// # Errors
    /// [`RecordedFlowError::Json`] / [`RecordedFlowError::UnknownFormat`] for an unreadable
    /// payload, and every compilation and [`Self::validate`] error.
    pub fn parse(json: &str) -> Result<Self, RecordedFlowError> {
        let probe: serde_json::Value =
            serde_json::from_str(json).map_err(|e| RecordedFlowError::Json(e.to_string()))?;
        let steps = probe
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .ok_or(RecordedFlowError::NoSteps)?;
        let Some(first) = steps.first() else {
            return Err(RecordedFlowError::NoSteps);
        };
        let flow = if first.get("type").is_some() {
            let file: RecordingFile =
                serde_json::from_value(probe).map_err(|e| RecordedFlowError::Json(e.to_string()))?;
            Self::from_recording(file)?
        } else if first.get("action").is_some() {
            let file: ExplicitFile =
                serde_json::from_value(probe).map_err(|e| RecordedFlowError::Json(e.to_string()))?;
            Self::from_explicit(file)?
        } else {
            return Err(RecordedFlowError::UnknownFormat);
        };
        flow.validate()?;
        Ok(flow)
    }

    fn from_recording(file: RecordingFile) -> Result<Self, RecordedFlowError> {
        let mut steps = Vec::with_capacity(file.steps.len());
        for (index, rs) in file.steps.into_iter().enumerate() {
            let step_type = rs.step_type.trim().to_ascii_lowercase();
            match step_type.as_str() {
                "navigate" => {
                    let raw = rs.url.trim();
                    // Recorder exports often start on `about:blank`; that is not replayable
                    // and not an error.
                    if raw.eq_ignore_ascii_case("about:blank") {
                        continue;
                    }
                    steps.push(LoginStep::NavigateTo {
                        url: parse_http_url(index, raw)?,
                    });
                }
                "click" | "doubleclick" => {
                    let action = if step_type == "click" {
                        "click"
                    } else {
                        "doubleclick"
                    };
                    let selector = Selector::pick(&rs.selectors)
                        .ok_or(RecordedFlowError::MissingSelector { index, action })?;
                    steps.push(if action == "click" {
                        LoginStep::ClickSelector { selector }
                    } else {
                        LoginStep::DoubleClickSelector { selector }
                    });
                }
                "change" => {
                    let selector =
                        Selector::pick(&rs.selectors).ok_or(RecordedFlowError::MissingSelector {
                            index,
                            action: "change",
                        })?;
                    let value = parameterize(&rs.value, &selector)?;
                    steps.push(LoginStep::FillSelector { selector, value });
                }
                "keydown" => {
                    // Character keys are captured by `change`; the paired keyUp is ignored.
                    if let Some(key) = PressKey::parse(&rs.key) {
                        steps.push(LoginStep::Press { key });
                    }
                }
                "waitforelement" => {
                    let selector =
                        Selector::pick(&rs.selectors).ok_or(RecordedFlowError::MissingSelector {
                            index,
                            action: "waitForElement",
                        })?;
                    steps.push(LoginStep::WaitVisible {
                        selector,
                        timeout_ms: DEFAULT_WAIT_VISIBLE_TIMEOUT_MS,
                    });
                }
                // Arbitrary expressions are not evaluated; settle instead.
                "waitforexpression" => steps.push(LoginStep::Wait { duration_ms: 0 }),
                "setviewport" | "keyup" | "scroll" | "close" | "emulatenetworkconditions" | "hover" => {}
                _ => {
                    return Err(RecordedFlowError::UnsupportedStepType {
                        index,
                        step_type: rs.step_type,
                    })
                }
            }
        }
        Ok(Self {
            title: file.title.filter(|t| !t.trim().is_empty()),
            steps,
        })
    }

    fn from_explicit(file: ExplicitFile) -> Result<Self, RecordedFlowError> {
        let mut steps = Vec::with_capacity(file.steps.len());
        for (index, es) in file.steps.into_iter().enumerate() {
            let action = es.action.trim().to_ascii_lowercase();
            let selector = || {
                Selector::parse(&es.selector).ok_or(RecordedFlowError::MissingSelector {
                    index,
                    action: explicit_action_name(&action),
                })
            };
            let step = match action.as_str() {
                "navigate" => LoginStep::NavigateTo {
                    url: parse_http_url(index, es.value.trim())?,
                },
                "fill" | "input" | "type" => LoginStep::FillSelector {
                    selector: selector()?,
                    value: FillValue::parse(&es.value)?,
                },
                "click" => LoginStep::ClickSelector {
                    selector: selector()?,
                },
                "doubleclick" => LoginStep::DoubleClickSelector {
                    selector: selector()?,
                },
                "waitvisible" => LoginStep::WaitVisible {
                    selector: selector()?,
                    timeout_ms: match es.value.trim() {
                        "" => DEFAULT_WAIT_VISIBLE_TIMEOUT_MS,
                        v => duration_ms(index, "waitvisible", v)?,
                    },
                },
                "wait" => LoginStep::Wait {
                    duration_ms: match es.value.trim() {
                        "" => 0,
                        v => duration_ms(index, "wait", v)?,
                    },
                },
                "press" => LoginStep::Press {
                    key: PressKey::parse(&es.value).ok_or_else(|| RecordedFlowError::UnsupportedKey {
                        index,
                        key: es.value.clone(),
                    })?,
                },
                // Selector is optional: replay falls back to the form's submit control or
                // Enter in the focused password field.
                "submit" => LoginStep::SubmitSelector {
                    selector: Selector::parse(&es.selector),
                },
                _ => {
                    return Err(RecordedFlowError::UnknownAction {
                        index,
                        action: es.action,
                    })
                }
            };
            steps.push(step);
        }
        Ok(Self {
            title: file.title.filter(|t| !t.trim().is_empty()),
            steps,
        })
    }

    /// Reject flows that cannot be replayed deterministically: no steps, more than
    /// [`MAX_STEPS`], a non-http navigation, a selector-targeted step without a selector, or
    /// a step kind that is not part of a recorded flow (the `builtin:form` variants).
    ///
    /// # Errors
    /// The matching [`RecordedFlowError`].
    pub fn validate(&self) -> Result<(), RecordedFlowError> {
        if self.steps.is_empty() {
            return Err(RecordedFlowError::NoSteps);
        }
        if self.steps.len() > MAX_STEPS {
            return Err(RecordedFlowError::TooManySteps {
                count: self.steps.len(),
            });
        }
        for (index, step) in self.steps.iter().enumerate() {
            let selector = match step {
                LoginStep::NavigateTo { url } => {
                    if !matches!(url.scheme(), "http" | "https") {
                        return Err(RecordedFlowError::NonHttpNavigate {
                            index,
                            url: url.to_string(),
                        });
                    }
                    continue;
                }
                LoginStep::FillSelector { selector, .. } => Some((selector, "fill")),
                LoginStep::ClickSelector { selector } => Some((selector, "click")),
                LoginStep::DoubleClickSelector { selector } => Some((selector, "doubleclick")),
                LoginStep::WaitVisible { selector, .. } => Some((selector, "waitvisible")),
                LoginStep::SubmitSelector { selector } => selector.as_ref().map(|s| (s, "submit")),
                LoginStep::Wait { .. } | LoginStep::Press { .. } => None,
                LoginStep::FindField { .. }
                | LoginStep::Type { .. }
                | LoginStep::Submit { .. }
                | LoginStep::Expect { .. } => {
                    return Err(RecordedFlowError::UnknownAction {
                        index,
                        action: "builtin:form step".to_owned(),
                    })
                }
            };
            if let Some((sel, action)) = selector {
                if sel.expr.trim().is_empty() {
                    return Err(RecordedFlowError::MissingSelector { index, action });
                }
            }
        }
        Ok(())
    }

    /// Does any `fill` step still need a credential (`{{username}}` / `{{password}}`)?
    #[must_use]
    pub fn needs_credentials(&self) -> bool {
        self.steps.iter().any(|s| {
            matches!(
                s,
                LoginStep::FillSelector {
                    value: FillValue::Placeholder(_),
                    ..
                }
            )
        })
    }

    /// Does the flow end by asserting an authenticated-only element (`waitvisible` last)?
    /// This is the explicit success signal for applications whose server-side session does
    /// not mutate browser state.
    #[must_use]
    pub fn has_terminal_visible_assertion(&self) -> bool {
        matches!(self.steps.last(), Some(LoginStep::WaitVisible { selector, .. }) if !selector.expr.trim().is_empty())
    }

    /// The first `http(s)` navigation of the flow, the anonymous-session baseline.
    #[must_use]
    pub fn first_navigate_url(&self) -> Option<&url::Url> {
        self.steps.iter().find_map(|s| match s {
            LoginStep::NavigateTo { url } => Some(url),
            _ => None,
        })
    }
}

fn explicit_action_name(action: &str) -> &'static str {
    match action {
        "fill" | "input" | "type" => "fill",
        "click" => "click",
        "doubleclick" => "doubleclick",
        "waitvisible" => "waitvisible",
        "submit" => "submit",
        _ => "step",
    }
}

fn parse_http_url(index: usize, raw: &str) -> Result<url::Url, RecordedFlowError> {
    let non_http = || RecordedFlowError::NonHttpNavigate {
        index,
        url: raw.to_owned(),
    };
    let url = url::Url::parse(raw).map_err(|_| non_http())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(non_http());
    }
    Ok(url)
}

/// A recorded `change` value: a placeholder when the control looks like a credential field
/// (the recorded literal is dropped), the literal otherwise.
fn parameterize(value: &str, selector: &Selector) -> Result<FillValue, RecordedFlowError> {
    if selector.looks_like_password() {
        return Ok(FillValue::Placeholder(CredentialPart::Password));
    }
    if selector.looks_like_username() {
        return Ok(FillValue::Placeholder(CredentialPart::Username));
    }
    FillValue::parse(value)
}

fn duration_ms(index: usize, action: &'static str, value: &str) -> Result<u64, RecordedFlowError> {
    parse_go_duration(value)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .ok_or_else(|| RecordedFlowError::InvalidDuration {
            index,
            action,
            value: value.to_owned(),
        })
}

/// Go `time.ParseDuration` subset: `[0-9]+(\.[0-9]*)?(ns|us|µs|ms|s|m|h)` repeated, or `0`.
#[must_use]
pub fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s == "0" {
        return Some(Duration::ZERO);
    }
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let mut total = Duration::ZERO;
    let mut rest = s;
    while !rest.is_empty() {
        let num_len = rest
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_digit() || *c == '.'))
            .map_or(rest.len(), |(i, _)| i);
        if num_len == 0 {
            return None;
        }
        let number: f64 = rest[..num_len].parse().ok()?;
        rest = &rest[num_len..];
        let unit_len = rest
            .char_indices()
            .find(|(_, c)| c.is_ascii_digit() || *c == '.')
            .map_or(rest.len(), |(i, _)| i);
        let unit = &rest[..unit_len];
        rest = &rest[unit_len..];
        let unit_secs = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        let secs = number * unit_secs;
        if !secs.is_finite() {
            return None;
        }
        total = total.checked_add(Duration::try_from_secs_f64(secs).ok()?)?;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::login::LoginPlan;

    /// A real Recorder export shape (`@puppeteer/replay` schema) of a two-step login.
    const RECORDING: &str = r##"{
  "title": "acme login",
  "steps": [
    { "type": "setViewport", "width": 1280, "height": 720, "deviceScaleFactor": 1, "isMobile": false, "hasTouch": false, "isLandscape": false },
    { "type": "navigate", "url": "about:blank", "assertedEvents": [] },
    { "type": "navigate", "url": "https://app.example.test/login", "assertedEvents": [ { "type": "navigation", "url": "https://app.example.test/login", "title": "Sign in" } ] },
    { "type": "change", "value": "dave@example.test", "selectors": [ [ "aria/Email" ], [ "#email" ], [ "xpath///*[@id=\"email\"]" ], [ "pierce/#email" ], [ "text/Email" ] ], "target": "main" },
    { "type": "click", "target": "main", "selectors": [ [ "aria/Next" ], [ "#next" ] ], "offsetY": 10, "offsetX": 20 },
    { "type": "waitForElement", "selectors": [ [ "#password" ] ] },
    { "type": "change", "value": "p@ss", "selectors": [ [ "#password" ] ], "target": "main" },
    { "type": "keyDown", "target": "main", "key": "Enter" },
    { "type": "keyUp", "key": "Enter", "target": "main" },
    { "type": "click", "selectors": [ [ "#submit" ] ] },
    { "type": "waitForElement", "selectors": [ [ "aria/Sign out" ], [ "#signout" ] ] }
  ]
}"##;

    const EXPLICIT: &str = r##"{
  "steps": [
    { "action": "navigate", "value": "https://app.example.test/login" },
    { "action": "fill", "selector": "#user", "value": "{{username}}" },
    { "action": "fill", "selector": "xpath=//input[@type='password']", "value": "{{password}}" },
    { "action": "fill", "selector": "#otp", "value": "000000" },
    { "action": "doubleclick", "selector": "#remember" },
    { "action": "press", "value": "Tab" },
    { "action": "wait", "value": "1.5s" },
    { "action": "submit" },
    { "action": "waitvisible", "selector": "#dashboard", "value": "2m" }
  ]
}"##;

    #[test]
    fn recorder_export_compiles_to_steps() {
        let flow = RecordedFlow::parse(RECORDING).unwrap();
        assert_eq!(flow.title.as_deref(), Some("acme login"));
        assert_eq!(
            flow.steps,
            vec![
                LoginStep::NavigateTo {
                    url: url::Url::parse("https://app.example.test/login").unwrap()
                },
                LoginStep::FillSelector {
                    selector: Selector::css("#email"),
                    value: FillValue::Placeholder(CredentialPart::Username),
                },
                LoginStep::ClickSelector {
                    selector: Selector::css("#next")
                },
                LoginStep::WaitVisible {
                    selector: Selector::css("#password"),
                    timeout_ms: DEFAULT_WAIT_VISIBLE_TIMEOUT_MS,
                },
                LoginStep::FillSelector {
                    selector: Selector::css("#password"),
                    value: FillValue::Placeholder(CredentialPart::Password),
                },
                LoginStep::Press { key: PressKey::Enter },
                LoginStep::ClickSelector {
                    selector: Selector::css("#submit")
                },
                LoginStep::WaitVisible {
                    selector: Selector::css("#signout"),
                    timeout_ms: DEFAULT_WAIT_VISIBLE_TIMEOUT_MS,
                },
            ]
        );
        assert!(flow.needs_credentials());
        assert!(flow.has_terminal_visible_assertion());
        assert_eq!(
            flow.first_navigate_url().map(url::Url::as_str),
            Some("https://app.example.test/login")
        );
    }

    #[test]
    fn recorded_literals_in_credential_fields_are_never_stored() {
        let flow = RecordedFlow::parse(RECORDING).unwrap();
        let json = serde_json::to_string(&flow).unwrap();
        assert!(!json.contains("p@ss"), "{json}");
        assert!(!json.contains("dave@example.test"), "{json}");
        let debug = format!("{flow:?}");
        assert!(!debug.contains("p@ss") && !debug.contains("dave@example.test"));
        assert!(json.contains("\"placeholder\":\"password\""), "{json}");
        let back: RecordedFlow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, flow);
    }

    #[test]
    fn explicit_steps_compile() {
        let flow = RecordedFlow::parse(EXPLICIT).unwrap();
        assert_eq!(flow.title, None);
        assert_eq!(flow.steps.len(), 9);
        assert_eq!(
            flow.steps[2],
            LoginStep::FillSelector {
                selector: Selector {
                    kind: SelectorKind::XPath,
                    expr: "//input[@type='password']".to_owned()
                },
                value: FillValue::Placeholder(CredentialPart::Password),
            }
        );
        assert_eq!(
            flow.steps[3],
            LoginStep::FillSelector {
                selector: Selector::css("#otp"),
                value: FillValue::Literal("000000".to_owned()),
            }
        );
        assert_eq!(
            flow.steps[4],
            LoginStep::DoubleClickSelector {
                selector: Selector::css("#remember")
            }
        );
        assert_eq!(flow.steps[5], LoginStep::Press { key: PressKey::Tab });
        assert_eq!(flow.steps[6], LoginStep::Wait { duration_ms: 1_500 });
        assert_eq!(flow.steps[7], LoginStep::SubmitSelector { selector: None });
        assert_eq!(
            flow.steps[8],
            LoginStep::WaitVisible {
                selector: Selector::css("#dashboard"),
                timeout_ms: 120_000,
            }
        );
        assert!(flow.has_terminal_visible_assertion());
    }

    #[test]
    fn selector_priority_and_prefixes() {
        let groups = |v: &[&str]| v.iter().map(|s| vec![(*s).to_owned()]).collect::<Vec<_>>();
        assert_eq!(
            Selector::pick(&groups(&["aria/Save", "xpath///button[1]", "#real"])),
            Some(Selector::css("#real"))
        );
        assert_eq!(
            Selector::pick(&groups(&["pierce/#shadow", "xpath///div[2]"])),
            Some(Selector {
                kind: SelectorKind::XPath,
                expr: "//div[2]".to_owned()
            })
        );
        assert_eq!(
            Selector::pick(&groups(&["aria/Submit"])),
            Some(Selector {
                kind: SelectorKind::Aria,
                expr: "Submit".to_owned()
            })
        );
        assert_eq!(
            Selector::pick(&groups(&["text/Continue"])).map(|s| s.to_string()),
            Some("text/Continue".to_owned())
        );
        // shadow-piercing chains are skipped
        assert_eq!(
            Selector::pick(&[vec!["#host".to_owned(), "#inner".to_owned()]]),
            None
        );
        assert_eq!(Selector::pick(&groups(&["pierce/#x", ""])), None);
        assert_eq!(
            Selector::parse("xpath=//a").map(|s| s.kind),
            Some(SelectorKind::XPath)
        );
        assert_eq!(Selector::parse("  "), None);
    }

    #[test]
    fn validation_errors() {
        let e = |json: &str| RecordedFlow::parse(json).unwrap_err();
        assert!(matches!(e("not json"), RecordedFlowError::Json(_)));
        assert_eq!(e(r#"{"steps": []}"#), RecordedFlowError::NoSteps);
        assert_eq!(e(r#"{"title": "x"}"#), RecordedFlowError::NoSteps);
        assert_eq!(
            e(r#"{"steps": [{"type":"setViewport"}]}"#),
            RecordedFlowError::NoSteps
        );
        assert_eq!(
            e(r#"{"steps": [{"foo":"bar"}]}"#),
            RecordedFlowError::UnknownFormat
        );
        assert_eq!(
            e(r##"{"steps": [{"action":"hack","selector":"#x"}]}"##),
            RecordedFlowError::UnknownAction {
                index: 0,
                action: "hack".to_owned()
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"type":"evaluate","expression":"alert(1)"}]}"#),
            RecordedFlowError::UnsupportedStepType {
                index: 0,
                step_type: "evaluate".to_owned()
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"type":"click","selectors":[]}]}"#),
            RecordedFlowError::MissingSelector {
                index: 0,
                action: "click"
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"action":"fill","value":"x"}]}"#),
            RecordedFlowError::MissingSelector {
                index: 0,
                action: "fill"
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"action":"navigate","value":"javascript:alert(1)"}]}"#),
            RecordedFlowError::NonHttpNavigate {
                index: 0,
                url: "javascript:alert(1)".to_owned()
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"type":"navigate","url":"file:///etc/passwd"}]}"#),
            RecordedFlowError::NonHttpNavigate {
                index: 0,
                url: "file:///etc/passwd".to_owned()
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"action":"press","value":"F5"}]}"#),
            RecordedFlowError::UnsupportedKey {
                index: 0,
                key: "F5".to_owned()
            }
        );
        assert_eq!(
            e(r#"{"steps": [{"action":"wait","value":"soon"}]}"#),
            RecordedFlowError::InvalidDuration {
                index: 0,
                action: "wait",
                value: "soon".to_owned()
            }
        );
        assert_eq!(
            e(r##"{"steps": [{"action":"fill","selector":"#x","value":"pre-{{password}}"}]}"##),
            RecordedFlowError::MixedPlaceholder
        );
        // mixed formats: the first step decides, the rest must match
        assert!(matches!(
            e(
                r##"{"steps": [{"type":"navigate","url":"https://e.test"},{"action":"click","selector":"#s"}]}"##
            ),
            RecordedFlowError::UnsupportedStepType { index: 1, .. }
        ));
        let many = format!(
            r#"{{"steps": [{}]}}"#,
            vec![r##"{"action":"click","selector":"#a"}"##; MAX_STEPS + 1].join(",")
        );
        assert_eq!(e(&many), RecordedFlowError::TooManySteps { count: MAX_STEPS + 1 });
        let flow = RecordedFlow {
            title: None,
            steps: vec![LoginStep::Submit {
                method: crate::login::SubmitMethod::PressEnter,
            }],
        };
        assert!(matches!(
            flow.validate(),
            Err(RecordedFlowError::UnknownAction { index: 0, .. })
        ));
    }

    #[test]
    fn placeholders_resolve_only_at_execution_and_stay_secret() {
        let user = FillValue::parse("{{username}}").unwrap();
        let pass = FillValue::parse("{{password}}").unwrap();
        let lit = FillValue::parse("hello").unwrap();
        let secret = SecretOr::secret("Hunter2-secret".to_owned());
        let u = user.resolve("alice", &secret);
        let p = pass.resolve("alice", &secret);
        let l = lit.resolve("alice", &secret);
        assert_eq!(u.plain().map(String::as_str), Some("alice"));
        assert!(p.is_secret());
        assert_eq!(p.expose(), "Hunter2-secret");
        assert_eq!(l.plain().map(String::as_str), Some("hello"));
        assert!(!format!("{p:?}").contains("Hunter2"));
        // a plain password still leaves as a secret
        let p2 = pass.resolve("alice", &SecretOr::Plain("pw".to_owned()));
        assert!(p2.is_secret());
        // the placeholder itself never expands
        assert_eq!(
            serde_json::to_string(&pass).unwrap(),
            r#"{"placeholder":"password"}"#
        );
        assert_eq!(format!("{pass:?}"), "Placeholder(Password)");
        assert!(user.is_placeholder() && !lit.is_placeholder());
    }

    #[test]
    fn login_plan_parses_recorded_and_builtin_specs() {
        let plan = LoginPlan::parse(&format!("recorded:{EXPLICIT}")).unwrap();
        assert_eq!(plan.source, crate::login::LoginPlanSource::Recorded);
        assert_eq!(plan.steps.len(), 9);
        assert!(plan.types_password_only_into_password_field());
        let builtin = LoginPlan::parse("builtin:form").unwrap();
        assert_eq!(builtin, LoginPlan::builtin_form());
        assert_eq!(builtin.source, crate::login::LoginPlanSource::BuiltinForm);
        assert!(matches!(
            LoginPlan::parse("magic:wand").unwrap_err(),
            RecordedFlowError::NotRecorded(_)
        ));
        assert!(matches!(
            LoginPlan::parse("recorded:").unwrap_err(),
            RecordedFlowError::Json(_)
        ));
        // the whole plan round-trips through serde with the placeholders intact
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains(r#""op":"fill_selector""#), "{json}");
        assert!(json.contains(r#""source":"recorded""#), "{json}");
        assert_eq!(serde_json::from_str::<LoginPlan>(&json).unwrap(), plan);
        // a plan stored without `source` is a builtin plan
        let legacy: LoginPlan = serde_json::from_str(r#"{"steps":[]}"#).unwrap();
        assert_eq!(legacy.source, crate::login::LoginPlanSource::BuiltinForm);
    }

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("2s"), Some(Duration::from_secs(2)));
        assert_eq!(parse_go_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_go_duration("1.5s"), Some(Duration::from_millis(1_500)));
        assert_eq!(parse_go_duration("1m30s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_go_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_go_duration("2h"), Some(Duration::from_secs(7_200)));
        assert_eq!(parse_go_duration("250µs"), Some(Duration::from_micros(250)));
        assert_eq!(parse_go_duration("5"), None);
        assert_eq!(parse_go_duration("-1s"), None);
        assert_eq!(parse_go_duration("1x"), None);
        assert_eq!(parse_go_duration(""), None);
    }

    #[test]
    fn logout_paths() {
        for p in [
            "/logout",
            "/LogOut/",
            "/account/logout.php",
            "/signout",
            "/log_out",
            "/sign-out",
            "/app/sign-out/now",
        ] {
            assert!(is_logout_path(p), "{p}");
        }
        for p in ["/", "/login", "/logoutlist", "/signout-help", "/users/sign_in"] {
            assert!(!is_logout_path(p), "{p}");
        }
        assert_eq!(LOGOUT_PATHS.len(), 4);
    }

    #[test]
    fn press_keys_normalize_like_katana() {
        assert_eq!(PressKey::parse("Enter"), Some(PressKey::Enter));
        assert_eq!(PressKey::parse("NumpadEnter"), Some(PressKey::Enter));
        assert_eq!(PressKey::parse("return"), Some(PressKey::Enter));
        assert_eq!(PressKey::parse("Esc"), Some(PressKey::Escape));
        assert_eq!(PressKey::parse(" "), Some(PressKey::Space));
        assert_eq!(PressKey::parse("a"), None);
        assert_eq!(PressKey::Tab.as_str(), "tab");
    }
}
