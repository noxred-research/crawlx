//! Static form filling (`extract.formFill`, compatibility flags `-aff` / `-fc`).
//!
//! [`fill_form`] turns a [`StaticForm`] into the request a browser would
//! send after a user filled it in: a GET form becomes its action URL with the
//! encoded query, any other method a body in the form's `enctype`
//! (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`,
//! or a JSON object for `application/json`).
//!
//! Value rules, ported from an MIT-licensed upstream (see THIRD_PARTY_NOTICES.md),
//! in this order per control:
//!
//! * `disabled` controls are not submitted; `button`, `reset` and `image`
//!   controls never are; of several named `submit` controls the first is.
//! * A control that already carries a `value` keeps it. `hidden` controls
//!   keep their value verbatim (empty when absent) and `file` controls stay
//!   empty (multipart sends an empty file part).
//! * `radio`: one value per name, the `checked` one else the first.
//!   `checkbox`: always submitted (`on` without a `value`). `select`: the
//!   selected option, else the first non-empty option.
//! * `color`: [`FormFill::color`]. `number` / `range`: `min + step` (reference
//!   defaults: min 1, step 1), kept within `max`.
//! * Text-like controls: an answer in `decided` (keyed by field name), else
//!   the family of the control (`type`, `autocomplete`, the words of `name`
//!   and `id`; [`FormFill::email`], `phone` and `password` for those three,
//!   the reference constants for the rest), else the *fallback*: a value
//!   generated from the `pattern`, else the `placeholder` attribute, else
//!   [`FormFill::placeholder`], else eight seeded letters. Controls that took
//!   the fallback are listed in [`FilledForm::unresolved`] so a caller can
//!   ask a model for better values and call [`fill_form`] again with the
//!   answers in `decided`.
//! * Every text value then honours `pattern` (a value the anchored pattern
//!   rejects is regenerated), `maxlength` (truncated) and `minlength` (padded).
//!
//! Differences from the reference: values it draws at random (the email)
//! or fixes to a brand string derive from the run's [`CrawlSeed`], so the
//! same inputs always yield the same form; `-fc` values may name the
//! deterministic helpers `rand_email()`, `rand_phone()`, `rand_first_name()`,
//! `rand_last_name()`, `rand_password(n)`, `rand_base(n[, charset])`,
//! `rand_text_alpha(n)`, `rand_text_alphanumeric(n)`, `rand_text_numeric(n)` and
//! `rand_int(min, max)` (anything else stays a literal) and nothing is ever
//! executed; the loopback `ip` constant is a documentation address.
//!
//! No clock, no global randomness: draws come from
//! [`CrawlSeed::rng`](crawlx_core::seed::CrawlSeed::rng) with purpose
//! strings under `extract/form_fill/`.

mod config;
mod encode;
mod pattern;
pub(crate) mod semantic;
mod values;

use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::config::FormFill;
use crawlx_core::seed::CrawlSeed;
use url::Url;

use crate::forms::{StaticForm, StaticInput};
use encode::Encoding;
use pattern::Pattern;

pub use config::{parse_form_config, FormConfigError};

/// The `-fc` values a run configures, with the `rand_*` helpers already evaluated for the run's
/// seed (the same per-class streams [`fill_form`] draws from, so both planes type the same
/// value). A class the config leaves out is `None`: the plane's own default applies.
/// `color` is not here: the browser plane has no colour entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedFormValues {
    /// `email` (also used for the browser plane's `email` inputs).
    pub email: Option<String>,
    /// `phone`.
    pub phone: Option<String>,
    /// `password`.
    pub password: Option<String>,
    /// `placeholder`: every other text-like input.
    pub placeholder: Option<String>,
}

/// Resolve the configured values of `cfg` for `seed` (see [`ResolvedFormValues`]). Empty when
/// `cfg.enabled` is false: filling forms was not asked for.
#[must_use]
pub fn configured_values(cfg: &FormFill, seed: &CrawlSeed) -> ResolvedFormValues {
    if !cfg.enabled {
        return ResolvedFormValues::default();
    }
    let resolve = |value: &Option<String>, class: &str| {
        value
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| values::resolve(v, seed, class))
    };
    ResolvedFormValues {
        email: resolve(&cfg.email, "email"),
        phone: resolve(&cfg.phone, "phone"),
        password: resolve(&cfg.password, "password"),
        placeholder: resolve(&cfg.placeholder, "placeholder"),
    }
}

/// Cap on the padding applied for `minlength` (the attribute is page controlled).
const MAX_PAD: usize = 1024;

/// A text control no rule classified: nothing but the fallback filled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedField {
    /// Control `name`.
    pub name: String,
    /// Control type (`text`, `search`, `textarea`, or an unknown `type` value).
    pub input_type: String,
    /// `placeholder` attribute.
    pub placeholder: Option<String>,
    /// `pattern` attribute.
    pub pattern: Option<String>,
}

/// A form filled in, ready to be requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilledForm {
    /// Upper-case method of the form.
    pub method: String,
    /// Where to send it. GET forms carry the encoded fields as the query
    /// (replacing the action's own); the fragment is dropped.
    pub action: Url,
    /// `Content-Type` of [`body`](Self::body); `None` for GET forms.
    pub content_type: Option<String>,
    /// Encoded fields; `None` for GET forms.
    pub body: Option<String>,
    /// Submitted fields by name; a repeated name keeps its last value (the
    /// first selected radio of a group).
    pub fields: BTreeMap<String, String>,
    /// Text controls only the fallback filled, in document order.
    pub unresolved: Vec<UnresolvedField>,
}

/// Fill `form`, found on the page `base`, as described in the [module docs](self).
///
/// `cfg` supplies the configured values (`cfg.enabled` is the caller's gate
/// and is not consulted), `seed` every generated one, `decided` model answers
/// by field name for text controls. `base` scopes the generated filler text,
/// so the same field on two pages may differ while one page is reproducible.
#[must_use]
pub fn fill_form(
    form: &StaticForm,
    base: &Url,
    cfg: &FormFill,
    seed: &CrawlSeed,
    decided: &BTreeMap<String, String>,
) -> FilledForm {
    let mut filler = Filler {
        page: base.as_str(),
        cfg,
        seed,
        decided,
        values: BTreeMap::new(),
        order: Vec::new(),
        files: BTreeSet::new(),
        radios: BTreeMap::new(),
        submit_taken: false,
        unresolved: Vec::new(),
    };
    for input in &form.inputs {
        filler.visit(input);
    }
    filler.finish(form)
}

struct Filler<'a> {
    page: &'a str,
    cfg: &'a FormFill,
    seed: &'a CrawlSeed,
    decided: &'a BTreeMap<String, String>,
    values: BTreeMap<String, String>,
    /// Field names in the order they first appeared (document order).
    order: Vec<String>,
    files: BTreeSet<String>,
    /// Radio groups seen: whether the chosen member was `checked`.
    radios: BTreeMap<String, bool>,
    submit_taken: bool,
    unresolved: Vec<UnresolvedField>,
}

fn non_empty(v: Option<&String>) -> Option<&str> {
    v.map(String::as_str).filter(|s| !s.is_empty())
}

/// `pattern` is defined for textual types only.
fn pattern_applies(kind: &str) -> bool {
    !matches!(
        kind,
        "textarea" | "date" | "time" | "datetime-local" | "month" | "week"
    )
}

/// `minlength` / `maxlength` are defined for textual types and textareas.
fn length_applies(kind: &str) -> bool {
    !matches!(kind, "date" | "time" | "datetime-local" | "month" | "week")
}

impl Filler<'_> {
    fn put(&mut self, name: &str, value: String) {
        if self.values.insert(name.to_owned(), value).is_none() {
            self.order.push(name.to_owned());
        }
    }

    fn visit(&mut self, input: &StaticInput) {
        if input.disabled {
            return;
        }
        let name = input.name.as_str();
        match input.kind.as_str() {
            "radio" => self.radio(input),
            "checkbox" => self.put(name, input.value.clone().unwrap_or_else(|| "on".to_owned())),
            "submit" => {
                if !self.submit_taken {
                    self.submit_taken = true;
                    self.put(name, input.value.clone().unwrap_or_else(|| "Submit".to_owned()));
                }
            }
            "button" | "reset" | "image" => {}
            "hidden" => self.put(name, input.value.clone().unwrap_or_default()),
            "file" => {
                self.files.insert(name.to_owned());
                self.put(name, String::new());
            }
            "select" => {
                let picked = input.value.clone().unwrap_or_default();
                let value = if picked.is_empty() {
                    input
                        .options
                        .iter()
                        .find(|o| !o.is_empty())
                        .cloned()
                        .unwrap_or(picked)
                } else {
                    picked
                };
                self.put(name, value);
            }
            "color" => {
                let value = non_empty(input.value.as_ref()).map_or_else(|| self.color(), str::to_owned);
                self.put(name, value);
            }
            "number" | "range" => {
                let value = non_empty(input.value.as_ref()).map_or_else(|| number(input), str::to_owned);
                self.put(name, value);
            }
            _ => self.text(input),
        }
    }

    fn radio(&mut self, input: &StaticInput) {
        let value = input.value.clone().unwrap_or_else(|| "on".to_owned());
        match self.radios.get(&input.name) {
            None => {
                self.radios.insert(input.name.clone(), input.checked);
                self.put(&input.name, value);
            }
            Some(false) if input.checked => {
                self.radios.insert(input.name.clone(), true);
                self.put(&input.name, value);
            }
            Some(_) => {}
        }
    }

    fn text(&mut self, input: &StaticInput) {
        if let Some(kept) = non_empty(input.value.as_ref()) {
            self.put(&input.name, kept.to_owned());
            return;
        }
        let (value, fallback) = if let Some(answer) = self.decided.get(&input.name) {
            (answer.clone(), false)
        } else if let Some(sem) = semantic::classify(input) {
            (self.semantic_value(sem), false)
        } else {
            (self.fallback(input), true)
        };
        let value = self.constrain(input, value);
        if fallback && !self.unresolved.iter().any(|u| u.name == input.name) {
            self.unresolved.push(UnresolvedField {
                name: input.name.clone(),
                input_type: input.kind.clone(),
                placeholder: input.placeholder.clone(),
                pattern: input.pattern.clone(),
            });
        }
        self.put(&input.name, value);
    }

    fn configured(&self, configured: Option<&String>, class: &str) -> Option<String> {
        non_empty(configured).map(|v| values::resolve(v, self.seed, class))
    }

    fn color(&self) -> String {
        self.configured(self.cfg.color.as_ref(), "color")
            .unwrap_or_else(|| values::default_color(self.seed))
    }

    fn semantic_value(&self, sem: semantic::Semantic) -> String {
        use semantic::Semantic::{Email, Password, Phone};
        match sem {
            Email => self
                .configured(self.cfg.email.as_ref(), "email")
                .unwrap_or_else(|| values::default_email(self.seed)),
            Phone => self
                .configured(self.cfg.phone.as_ref(), "phone")
                .unwrap_or_else(|| values::default_phone(self.seed)),
            Password => self
                .configured(self.cfg.password.as_ref(), "password")
                .unwrap_or_else(|| values::default_password(self.seed)),
            other => other.fixed_value().unwrap_or_default().to_owned(),
        }
    }

    fn pattern_rng(&self, name: &str) -> rand_chacha::ChaCha8Rng {
        self.seed.rng(
            "extract/form_fill/pattern/v1",
            &[self.page.as_bytes(), name.as_bytes()],
        )
    }

    /// Value for a control no rule recognised: pattern, `placeholder`
    /// attribute, configured placeholder, seeded letters.
    fn fallback(&self, input: &StaticInput) -> String {
        if pattern_applies(&input.kind) {
            let max = if length_applies(&input.kind) {
                input.maxlength
            } else {
                None
            };
            let generated = input
                .pattern
                .as_deref()
                .and_then(Pattern::new)
                .and_then(|p| p.generate(&mut self.pattern_rng(&input.name), max));
            if let Some(v) = generated {
                return v;
            }
        }
        if let Some(p) = input.placeholder.as_deref().filter(|p| !p.is_empty()) {
            return p.to_owned();
        }
        self.configured(self.cfg.placeholder.as_ref(), "placeholder")
            .unwrap_or_else(|| values::filler(self.seed, self.page, &input.name))
    }

    /// Make `value` satisfy `pattern`, `maxlength` and `minlength`.
    fn constrain(&self, input: &StaticInput, mut value: String) -> String {
        let max = if length_applies(&input.kind) {
            input.maxlength
        } else {
            None
        };
        let pattern = if pattern_applies(&input.kind) {
            input.pattern.as_deref().and_then(Pattern::new)
        } else {
            None
        };
        let fits = |v: &str| {
            max.is_none_or(|m| v.chars().count() <= m) && pattern.as_ref().is_none_or(|p| p.is_match(v))
        };
        if !fits(&value) {
            if let Some(generated) = pattern
                .as_ref()
                .and_then(|p| p.generate(&mut self.pattern_rng(&input.name), max))
            {
                value = generated;
            }
        }
        if let Some(m) = max {
            if value.chars().count() > m {
                value = value.chars().take(m).collect();
            }
        }
        if length_applies(&input.kind) {
            if let Some(min) = input.minlength.map(|m| m.min(MAX_PAD)) {
                let seed_chars: Vec<char> = if value.is_empty() {
                    vec!['a']
                } else {
                    value.chars().collect()
                };
                let mut i = 0;
                while value.chars().count() < min {
                    value.push(seed_chars[i % seed_chars.len()]);
                    i += 1;
                }
            }
        }
        value
    }

    fn finish(self, form: &StaticForm) -> FilledForm {
        let pairs: Vec<(String, String)> = self
            .order
            .iter()
            .filter_map(|n| self.values.get(n).map(|v| (n.clone(), v.clone())))
            .collect();
        let method = form.method.to_ascii_uppercase();
        let mut action = form.action.clone();
        action.set_fragment(None);
        let (content_type, body) = if matches!(method.as_str(), "GET" | "HEAD") {
            let query = encode::urlencoded(&pairs);
            action.set_query((!query.is_empty()).then_some(query.as_str()));
            (None, None)
        } else {
            let (content_type, body) = encode::encode(
                Encoding::from_enctype(form.enctype.as_deref()),
                &pairs,
                &self.files,
                self.seed,
                action.as_str(),
            );
            (Some(content_type), Some(body))
        };
        FilledForm {
            method,
            action,
            content_type,
            body,
            fields: self.values,
            unresolved: self.unresolved,
        }
    }
}

/// `min + step` for `number` / `range` controls: the reference defaults are
/// min 1 and step 1, and an attribute that is not an integer (`any`, a
/// decimal) counts as absent. A sum above `max` falls back to `min`, the
/// one value guaranteed to be valid.
fn number(input: &StaticInput) -> String {
    let int = |v: Option<&String>| v.and_then(|s| s.trim().parse::<i64>().ok());
    let min = int(input.min.as_ref()).unwrap_or(1);
    let step = int(input.step.as_ref()).filter(|s| *s > 0).unwrap_or(1);
    let mut value = min.saturating_add(step);
    if let Some(max) = int(input.max.as_ref()) {
        if value > max {
            value = min.min(max);
        }
    }
    value.to_string()
}
