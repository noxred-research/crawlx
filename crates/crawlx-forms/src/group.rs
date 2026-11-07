//! Form grouping.
//!
//! Inputs are attached to forms in this order:
//!
//! 1. **DOM ownership**: trusted `crawlx:form` backend ownership takes priority
//!    over author-supplied HTML `form=` references. Backend keys and author ids
//!    occupy separate, frame-scoped namespaces. Form declarations bridge only
//!    their own `id` to their own observed owner; their `method`/`action`
//!    attributes become the group's method/action.
//! 2. **AX landmarks**: nearest `form`/`search` ancestor role (and `group`
//!    when the observer supplied a `crawlx:container` id).
//! 3. **Proximity**: the same container (`crawlx:container`, else the stable
//!    ancestor-role path in the same frame) containing exactly one submit-like
//!    control.
//!
//! Everything else is an orphan; orphans form one group of their own. Output
//! order is first appearance of any member in the candidate slice, orphans last.

use crate::classify::{FieldRole, FormSemantics, InputClass2, InputClassifier, InputKind, COMMENT_WORDS};
use crate::text::Norm;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{ObservedDescriptor, RuntimeLocator};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Deterministic group id (`g-<16 hex>` or `orphan`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct FormGroupId(pub String);

impl FormGroupId {
    /// The id of the orphan group.
    pub const ORPHAN: &'static str = "orphan";

    fn of(key: &str) -> Self {
        let hex = Digest::of("crawlx/form-group/v1", key.as_bytes()).to_hex();
        Self(format!("g-{}", &hex[..16]))
    }
}

/// How a group was established.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GroupOrigin {
    /// Declared by a `<form>` element or `form=` ownership.
    ExplicitForm,
    /// Established by an AX `form`/`search` landmark.
    AxLandmark,
    /// Same container with exactly one submit-like control.
    Proximity,
    /// Leftover inputs that belong to no form.
    Orphan,
}

/// Form submission method.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FormMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `dialog`.
    Dialog,
}

impl FormMethod {
    /// Parse a form `method` attribute (trimmed, case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "get" => Some(Self::Get),
            "post" => Some(Self::Post),
            "dialog" => Some(Self::Dialog),
            _ => None,
        }
    }
}

/// One classified input inside a group.
#[derive(Clone, PartialEq, Debug)]
pub struct FormInput {
    /// Index into the candidate slice given to [`FormGrouper::group`].
    pub index: usize,
    /// Locator of the input element.
    pub locator: RuntimeLocator,
    /// Deterministic classification of the input.
    pub class: InputClass2,
    /// Whether the input is visible.
    pub visible: bool,
    /// Whether the input is disabled.
    pub disabled: bool,
}

impl FormInput {
    /// Visible, enabled and not a hidden field.
    #[must_use]
    pub fn fillable(&self) -> bool {
        self.visible && !self.disabled && self.class.kind != InputKind::Hidden
    }
}

/// A group of inputs that are submitted together.
#[derive(Clone, PartialEq, Debug)]
pub struct FormGroup {
    /// Deterministic group id.
    pub id: FormGroupId,
    /// How the group was established.
    pub origin: GroupOrigin,
    /// Member inputs in candidate order.
    pub inputs: Vec<FormInput>,
    /// Primary submit control.
    pub submit: Option<RuntimeLocator>,
    /// Candidate index of the primary submit control.
    pub submit_index: Option<usize>,
    /// Candidate indices of further submit controls (secondary actions).
    pub alt_submit_indices: Vec<usize>,
    /// Candidate index of the `<form>` declaration descriptor, when observed.
    pub form_index: Option<usize>,
    /// What the form means.
    pub semantics: FormSemantics,
    /// Submission method from the `<form>` declaration, when observed.
    pub method: Option<FormMethod>,
    /// Submission action from the `<form>` declaration, when observed.
    pub action: Option<String>,
}

impl FormGroup {
    /// Hint string for `crawlx-safety` (`SafetyContext::form_hint`).
    /// Contains any of `external_communication`, `payment`, `credentials`,
    /// `authentication`, `search`, `settings`; external communication carries a `:sms` or
    /// `:webhook` suffix when the channel is not email.
    #[must_use]
    pub fn form_hint(&self) -> Option<String> {
        if self.semantics == FormSemantics::Login
            && self
                .inputs
                .iter()
                .any(|input| input.class.role == Some(FieldRole::CurrentPassword))
            && self.inputs.iter().any(|input| {
                input.class.role == Some(FieldRole::Username) || input.class.kind == InputKind::Email
            })
        {
            return Some("authentication".to_owned());
        }
        // Current+new password forms are settings, but still change credentials.
        // Do not let the generic settings hint hide their security risk.
        if self.semantics == FormSemantics::Settings
            && self
                .inputs
                .iter()
                .any(|input| input.class.kind == InputKind::Password)
        {
            return Some("credentials settings".to_owned());
        }
        let base = self.semantics.form_hint()?;
        if !self.semantics.is_external_communication() {
            return Some(base.to_owned());
        }
        let channel = crate::sinks::channel_of(self);
        let tagged = match channel {
            crate::sinks::SinkKind::Email => "external_communication".to_owned(),
            other => format!("external_communication:{}", other.as_str()),
        };
        Some(base.replace("external_communication", &tagged))
    }

    /// Is submitting this group an external communication?
    #[must_use]
    pub fn is_external_communication(&self) -> bool {
        self.semantics.is_external_communication()
    }

    /// Inputs a filler may act on.
    pub fn fillable_inputs(&self) -> impl Iterator<Item = &FormInput> {
        self.inputs.iter().filter(|i| i.fillable())
    }
}

/// Stateless grouper.
#[derive(Clone, Copy, Debug, Default)]
pub struct FormGrouper;

enum Cand {
    Decl,
    Submit,
    Field(Box<InputClass2>),
    Other,
}

struct Bucket {
    origin: GroupOrigin,
    first: usize,
    decl: Option<usize>,
    fields: Vec<usize>,
    submits: Vec<usize>,
}

impl Bucket {
    fn new(origin: GroupOrigin, first: usize) -> Self {
        Self {
            origin,
            first,
            decl: None,
            fields: Vec::new(),
            submits: Vec::new(),
        }
    }
}

impl FormGrouper {
    /// Create the stateless grouper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Group `candidates` into forms. Pure and deterministic.
    #[must_use]
    pub fn group(&self, candidates: &[ObservedDescriptor]) -> Vec<FormGroup> {
        let classifier = InputClassifier::new();
        let kinds: Vec<Cand> = candidates
            .iter()
            .map(|d| match candidate_kind(d) {
                RawKind::Decl => Cand::Decl,
                RawKind::Submit => Cand::Submit,
                RawKind::Field => Cand::Field(Box::new(classifier.classify(d))),
                RawKind::Other => Cand::Other,
            })
            .collect();

        let aliases = alias_map(candidates, &kinds);
        let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
        let mut orphans: Vec<usize> = Vec::new();

        for (i, d) in candidates.iter().enumerate() {
            let kind = &kinds[i];
            if matches!(kind, Cand::Other) {
                continue;
            }
            let is_hidden = matches!(kind, Cand::Field(c) if c.kind == InputKind::Hidden);
            match owner_key(d, matches!(kind, Cand::Decl), &aliases) {
                Some((origin, key)) => {
                    let b = buckets.entry(key).or_insert_with(|| Bucket::new(origin, i));
                    b.first = b.first.min(i);
                    match kind {
                        Cand::Decl => b.decl = Some(b.decl.map_or(i, |p| p.min(i))),
                        Cand::Submit => b.submits.push(i),
                        Cand::Field(_) => b.fields.push(i),
                        Cand::Other => {}
                    }
                }
                None => {
                    if matches!(kind, Cand::Field(_)) && !is_hidden {
                        orphans.push(i);
                    }
                }
            }
        }

        // Proximity buckets need exactly one submit; otherwise their visible fields are orphans.
        let mut accepted: Vec<(String, Bucket)> = Vec::new();
        for (key, b) in buckets {
            match b.origin {
                GroupOrigin::Proximity => {
                    if !b.fields.is_empty() && b.submits.len() == 1 {
                        accepted.push((key, b));
                    } else {
                        orphans.extend(b.fields.iter().copied().filter(|&i| !is_hidden_field(&kinds[i])));
                    }
                }
                _ => {
                    if !b.fields.is_empty() || !b.submits.is_empty() {
                        accepted.push((key, b));
                    }
                }
            }
        }
        accepted.sort_by(|(ka, a), (kb, b)| (a.first, ka).cmp(&(b.first, kb)));

        let mut out: Vec<FormGroup> = accepted
            .into_iter()
            .map(|(key, b)| build_group(FormGroupId::of(&key), b, candidates, &kinds))
            .collect();

        orphans.sort_unstable();
        if !orphans.is_empty() {
            let mut b = Bucket::new(GroupOrigin::Orphan, orphans[0]);
            b.fields = orphans;
            let mut g = build_group(FormGroupId(FormGroupId::ORPHAN.to_owned()), b, candidates, &kinds);
            g.method = None;
            out.push(g);
        }
        out
    }
}

fn is_hidden_field(c: &Cand) -> bool {
    matches!(c, Cand::Field(cl) if cl.kind == InputKind::Hidden)
}

// ---------------------------------------------------------------- candidates

enum RawKind {
    Decl,
    Submit,
    Field,
    Other,
}

fn attr<'a>(d: &'a ObservedDescriptor, k: &str) -> Option<&'a str> {
    d.attributes.get(k).map(|v| v.trim()).filter(|v| !v.is_empty())
}

fn candidate_kind(d: &ObservedDescriptor) -> RawKind {
    let tag = d.tag.as_deref().unwrap_or_default().to_ascii_lowercase();
    let role = d.role.to_ascii_lowercase();
    let ty = attr(d, "type").map(str::to_ascii_lowercase);
    if tag == "form" || role == "form" {
        return RawKind::Decl;
    }
    match tag.as_str() {
        "input" => match ty.as_deref() {
            Some("submit" | "image") => RawKind::Submit,
            Some("button" | "reset") => RawKind::Other,
            _ => RawKind::Field,
        },
        "button" => match ty.as_deref() {
            None | Some("submit") => RawKind::Submit,
            _ => RawKind::Other,
        },
        "select" | "textarea" => RawKind::Field,
        "a" => RawKind::Other,
        _ => {
            if role == "button" && ty.as_deref() == Some("submit") {
                RawKind::Submit
            } else if matches!(
                role.as_str(),
                "textbox"
                    | "searchbox"
                    | "combobox"
                    | "listbox"
                    | "checkbox"
                    | "radio"
                    | "switch"
                    | "slider"
                    | "spinbutton"
            ) {
                RawKind::Field
            } else {
                RawKind::Other
            }
        }
    }
}

/// Frame-scoped author ids mapped to their declaration's owner key.
fn alias_map(candidates: &[ObservedDescriptor], kinds: &[Cand]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (d, k) in candidates.iter().zip(kinds) {
        if !matches!(k, Cand::Decl) {
            continue;
        }
        let Some(id) = attr(d, "id") else {
            continue;
        };
        let lin = lineage(d);
        map.entry(format!("{lin}|{id}"))
            .or_insert_with(|| match attr(d, "crawlx:form") {
                Some(observed) => format!("form:observer:{lin}|{observed}"),
                None => format!("form:author:{lin}|{id}"),
            });
    }
    map
}

fn lineage(d: &ObservedDescriptor) -> String {
    d.frame_lineage.join("/")
}

const GENERIC_ROLES: &[&str] = &["generic", "none", "presentation", "group", ""];

fn owner_key(
    d: &ObservedDescriptor,
    is_decl: bool,
    aliases: &BTreeMap<String, String>,
) -> Option<(GroupOrigin, String)> {
    let lin = lineage(d);
    // 1. Observed backend custody cannot be redirected by author attributes.
    if let Some(observed) = attr(d, "crawlx:form") {
        return Some((
            GroupOrigin::ExplicitForm,
            format!("form:observer:{lin}|{observed}"),
        ));
    }
    let author = if is_decl { attr(d, "id") } else { attr(d, "form") };
    if let Some(id) = author {
        let raw = format!("{lin}|{id}");
        let owner = aliases
            .get(&raw)
            .cloned()
            .unwrap_or_else(|| format!("form:author:{raw}"));
        return Some((GroupOrigin::ExplicitForm, owner));
    }
    if is_decl {
        return None;
    }
    // 2. AX landmark
    let roles: Vec<String> = d.ancestor_roles.iter().map(|r| r.to_ascii_lowercase()).collect();
    let container = attr(d, "crawlx:container");
    let landmark = roles.iter().rposition(|r| r == "form" || r == "search");
    let group_with_id = container.is_some() && roles.iter().any(|r| r == "group");
    if landmark.is_some() || group_with_id {
        let ident = match (container, landmark) {
            (Some(c), _) => c.to_owned(),
            (None, Some(i)) => roles[..=i].join("/"),
            (None, None) => String::new(),
        };
        return Some((GroupOrigin::AxLandmark, format!("ax:{lin}|{ident}")));
    }
    // 3. proximity
    let ident = match container {
        Some(c) => c.to_owned(),
        None => {
            let path: Vec<&str> = roles
                .iter()
                .map(String::as_str)
                .filter(|r| !GENERIC_ROLES.contains(r))
                .collect();
            if path.is_empty() {
                return None;
            }
            path.join("/")
        }
    };
    Some((GroupOrigin::Proximity, format!("prox:{lin}|{ident}")))
}

// --------------------------------------------------------------------- build

fn build_group(id: FormGroupId, b: Bucket, candidates: &[ObservedDescriptor], kinds: &[Cand]) -> FormGroup {
    let inputs: Vec<FormInput> = b
        .fields
        .iter()
        .filter_map(|&i| match &kinds[i] {
            Cand::Field(c) => Some(FormInput {
                index: i,
                locator: candidates[i].locator.clone(),
                class: (**c).clone(),
                visible: candidates[i].visible,
                disabled: candidates[i].disabled,
            }),
            _ => None,
        })
        .collect();

    let explicit_submit = b
        .submits
        .iter()
        .copied()
        .find(|&i| attr(&candidates[i], "type").is_some_and(|t| t.eq_ignore_ascii_case("submit")));
    let submit_index = explicit_submit.or_else(|| b.submits.first().copied());
    let alt_submit_indices: Vec<usize> = b
        .submits
        .iter()
        .copied()
        .filter(|&i| Some(i) != submit_index)
        .collect();

    let submit = submit_index.map(|i| &candidates[i]);
    let decl = b.decl.map(|i| &candidates[i]);

    let method = submit
        .and_then(|s| attr(s, "formmethod"))
        .or_else(|| decl.and_then(|f| attr(f, "method")))
        .or_else(|| member_attr(&b, candidates, "form-method"))
        .and_then(FormMethod::parse)
        .or_else(|| decl.map(|_| FormMethod::Get));
    let action = submit
        .and_then(|s| attr(s, "formaction"))
        .or_else(|| decl.and_then(|f| attr(f, "action")))
        .or_else(|| member_attr(&b, candidates, "form-action"))
        .map(str::to_owned);

    let mut meta = String::new();
    if let Some(a) = &action {
        meta.push_str(a);
        meta.push(' ');
    }
    if let Some(f) = decl {
        for v in [
            attr(f, "name"),
            attr(f, "id"),
            attr(f, "aria-label"),
            f.accessible_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            meta.push_str(v);
            meta.push(' ');
        }
    }
    let submit_text = submit.map(submit_label).unwrap_or_default();
    let search_landmark = b.fields.iter().any(|&i| {
        candidates[i]
            .ancestor_roles
            .iter()
            .any(|r| r.eq_ignore_ascii_case("search"))
    });
    let semantics = classify_group(&inputs, &submit_text, &meta, search_landmark);

    FormGroup {
        id,
        origin: b.origin,
        inputs,
        submit: submit.map(|s| s.locator.clone()),
        submit_index,
        alt_submit_indices,
        form_index: b.decl,
        semantics,
        method,
        action,
    }
}

fn member_attr<'a>(b: &Bucket, candidates: &'a [ObservedDescriptor], key: &str) -> Option<&'a str> {
    b.fields
        .iter()
        .chain(&b.submits)
        .find_map(|&i| attr(&candidates[i], key))
}

fn submit_label(d: &ObservedDescriptor) -> String {
    [
        d.accessible_name.as_deref(),
        d.text.as_deref(),
        attr(d, "value"),
        attr(d, "aria-label"),
        attr(d, "name"),
        attr(d, "id"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

// ----------------------------------------------------------------- semantics

const LOGIN_WORDS: &[&str] = &[
    "login",
    "logon",
    "signin",
    "anmelden",
    "anmeldung",
    "einloggen",
    "connexion",
    "connecter",
    "iniciarsesion",
    "acceder",
    "=entrar",
    "giris",
    "oturumac",
];
const REGISTER_WORDS: &[&str] = &[
    "register",
    "signup",
    "createaccount",
    "newaccount",
    "joinnow",
    "registrieren",
    "registrierung",
    "kontoerstellen",
    "inscription",
    "sinscrire",
    "creeruncompte",
    "registrarse",
    "crearcuenta",
    "=kayit",
    "uyeol",
    "hesapolustur",
];
const PAYMENT_WORDS: &[&str] = &[
    "checkout",
    "payment",
    "paynow",
    "bezahlen",
    "zahlung",
    "=kasse",
    "paiement",
    "=payer",
    "=pago",
    "=pagar",
    "odeme",
    "satinal",
    "purchase",
    "buynow",
    "placeorder",
    "kaufen",
];
const SEARCH_WORDS: &[&str] = &[
    "search",
    "suche",
    "suchen",
    "recherche",
    "rechercher",
    "buscar",
    "busqueda",
    "=arama",
    "=ara",
    "=find",
];
const SETTINGS_WORDS: &[&str] = &[
    "settings",
    "einstellungen",
    "parametres",
    "preferences",
    "preferencias",
    "ajustes",
    "ayarlar",
    "savechanges",
    "changepassword",
    "passwortandern",
    "=profile",
    "=profil",
    "=perfil",
    "=account",
    "=konto",
];
const CONTACT_WORDS: &[&str] = &[
    "contact",
    "kontakt",
    "contactez",
    "contacto",
    "iletisim",
    "sendmessage",
    "nachrichtsenden",
    "enviarmensaje",
    "subscribe",
    "newsletter",
    "abonnieren",
    "suscribir",
    "=abone",
    "feedback",
    "support",
];
const INVITE_WORDS: &[&str] = &[
    "invite",
    "einladen",
    "einladung",
    "inviter",
    "invitar",
    "invitacion",
    "davet",
];

fn classify_group(
    inputs: &[FormInput],
    submit_text: &str,
    meta: &str,
    search_landmark: bool,
) -> FormSemantics {
    let text = Norm::of(&format!("{submit_text} {meta}"));
    let visible: Vec<&FormInput> = inputs
        .iter()
        .filter(|i| i.class.kind != InputKind::Hidden)
        .collect();
    let role_of = |r: FieldRole| visible.iter().any(|i| i.class.role == Some(r));
    let kind_count = |k: InputKind| visible.iter().filter(|i| i.class.kind == k).count();

    // Payment
    if [FieldRole::CardNumber, FieldRole::CardExpiry, FieldRole::CardCvc]
        .into_iter()
        .any(role_of)
        || text.has_any(PAYMENT_WORDS)
    {
        return FormSemantics::Payment;
    }

    // Credentials
    let passwords = kind_count(InputKind::Password);
    if passwords > 0 {
        let has_current = role_of(FieldRole::CurrentPassword);
        let has_new = role_of(FieldRole::NewPassword) || role_of(FieldRole::ConfirmPassword);
        if has_current && (has_new || passwords >= 2) {
            return FormSemantics::Settings;
        }
        if has_new || passwords >= 2 {
            return FormSemantics::Registration;
        }
        if text.has_any(REGISTER_WORDS) && !text.has_any(LOGIN_WORDS) {
            return FormSemantics::Registration;
        }
        if text.has_any(SETTINGS_WORDS) && !text.has_any(LOGIN_WORDS) {
            return FormSemantics::Settings;
        }
        return FormSemantics::Login;
    }

    // Search
    let few_fields = visible.len() <= 3;
    if few_fields
        && (kind_count(InputKind::Search) > 0 || search_landmark || text.has_any(SEARCH_WORDS))
        && kind_count(InputKind::File) == 0
    {
        return FormSemantics::Search;
    }

    if kind_count(InputKind::File) > 0 {
        return FormSemantics::Upload;
    }
    if text.has_any(INVITE_WORDS) || (role_of(FieldRole::Recipient) && !role_of(FieldRole::Message)) {
        return FormSemantics::Invite;
    }
    if role_of(FieldRole::Comment) || (role_of(FieldRole::Message) && text.has_any(COMMENT_WORDS)) {
        return FormSemantics::Comment;
    }
    if role_of(FieldRole::Message) || text.has_any(CONTACT_WORDS) {
        return FormSemantics::Contact;
    }
    if text.has_any(SETTINGS_WORDS) {
        return FormSemantics::Settings;
    }
    if text.has_any(REGISTER_WORDS) && kind_count(InputKind::Email) > 0 {
        return FormSemantics::Registration;
    }
    FormSemantics::Unknown
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::classify::testutil::{desc, input};

    fn with(mut d: ObservedDescriptor, k: &str, v: &str) -> ObservedDescriptor {
        d.attributes.insert(k.to_owned(), v.to_owned());
        d
    }

    fn submit(n: i64, label: &str) -> ObservedDescriptor {
        let mut d = desc(n, "button", "button", &[("type", "submit")]);
        d.accessible_name = Some(label.to_owned());
        d
    }

    #[test]
    fn two_forms_and_an_orphan() {
        let c = vec![
            desc(
                1,
                "form",
                "form",
                &[
                    ("id", "login"),
                    ("crawlx:form", "login"),
                    ("method", "post"),
                    ("action", "/session"),
                ],
            ),
            with(
                input(2, &[("type", "email"), ("name", "email")]),
                "crawlx:form",
                "login",
            ),
            with(input(3, &[("type", "password")]), "crawlx:form", "login"),
            with(submit(4, "Sign in"), "crawlx:form", "login"),
            desc(
                5,
                "form",
                "form",
                &[("id", "newsletter"), ("action", "/subscribe"), ("method", "post")],
            ),
            // owned through the HTML `form=` attribute from outside the element
            with(
                input(6, &[("type", "email"), ("name", "mail")]),
                "form",
                "newsletter",
            ),
            with(submit(7, "Subscribe"), "form", "newsletter"),
            // no owner at all
            input(8, &[("type", "text"), ("name", "q")]),
        ];
        let groups = FormGrouper::new().group(&c);
        assert_eq!(groups.len(), 3, "{groups:#?}");

        let login = &groups[0];
        assert_eq!(login.origin, GroupOrigin::ExplicitForm);
        assert_eq!(login.inputs.iter().map(|i| i.index).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(login.submit_index, Some(3));
        assert_eq!(login.semantics, FormSemantics::Login);
        assert_eq!(login.method, Some(FormMethod::Post));
        assert_eq!(login.action.as_deref(), Some("/session"));
        assert_eq!(login.form_index, Some(0));

        let news = &groups[1];
        assert_eq!(news.inputs.iter().map(|i| i.index).collect::<Vec<_>>(), [5]);
        assert_eq!(news.submit_index, Some(6));
        assert_eq!(news.semantics, FormSemantics::Contact);
        assert_eq!(news.form_hint().as_deref(), Some("external_communication"));

        let orphan = &groups[2];
        assert_eq!(orphan.origin, GroupOrigin::Orphan);
        assert_eq!(orphan.id.0, "orphan");
        assert_eq!(orphan.inputs.iter().map(|i| i.index).collect::<Vec<_>>(), [7]);
        assert_eq!(orphan.submit, None);
        assert_eq!(orphan.method, None);
    }

    #[test]
    fn form_alias_bridges_html_id_and_observer_key() {
        let c = vec![
            desc(
                1,
                "form",
                "form",
                &[("id", "signup"), ("crawlx:form", "n42"), ("method", "POST")],
            ),
            with(
                input(2, &[("type", "text"), ("name", "name")]),
                "crawlx:form",
                "n42",
            ),
            with(input(3, &[("type", "email")]), "form", "signup"),
            with(submit(4, "Go"), "crawlx:form", "n42"),
        ];
        let groups = FormGrouper::new().group(&c);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].inputs.len(), 2);
        assert_eq!(groups[0].method, Some(FormMethod::Post));
    }

    #[test]
    fn numeric_author_ids_cannot_merge_backend_owners_or_redirect_observed_controls() {
        use crate::sinks::{channel_of, requires_sink, SinkKind};

        let mut c = vec![
            desc(
                10,
                "form",
                "form",
                &[
                    ("id", "20"),
                    ("crawlx:form", "10"),
                    ("form", "10"),
                    ("method", "post"),
                    ("action", "/invite/sms"),
                ],
            ),
            desc(
                20,
                "form",
                "form",
                &[
                    ("id", "10"),
                    ("crawlx:form", "20"),
                    ("form", "20"),
                    ("method", "post"),
                    ("action", "/invite/webhook"),
                ],
            ),
            input(
                11,
                &[
                    ("type", "tel"),
                    ("name", "phone"),
                    ("crawlx:form", "10"),
                    ("form", "10"),
                ],
            ),
            input(21, &[("name", "webhook"), ("crawlx:form", "20"), ("form", "20")]),
            input(12, &[("type", "tel"), ("name", "phone"), ("form", "20")]),
            input(22, &[("name", "webhook"), ("form", "10")]),
            with(with(submit(13, "Send invite"), "crawlx:form", "10"), "form", "10"),
            with(submit(14, "Send invite"), "form", "20"),
            with(with(submit(23, "Invite"), "crawlx:form", "20"), "form", "20"),
            with(submit(24, "Invite"), "form", "10"),
        ];
        // Nested fields and submitters still follow observed custody, not author aliases.
        for i in [2, 3, 6, 8] {
            c[i].ancestor_roles = vec!["main".into(), "form".into(), "group".into()];
        }

        let groups = FormGrouper::new().group(&c);
        assert_eq!(groups.len(), 2, "{groups:#?}");
        let sms = &groups[0];
        let webhook = &groups[1];
        assert_ne!(sms.id, webhook.id);
        assert_eq!(sms.form_index, Some(0));
        assert_eq!(sms.inputs.iter().map(|i| i.index).collect::<Vec<_>>(), [2, 4]);
        assert_eq!(sms.submit_index, Some(6));
        assert_eq!(sms.submit.as_ref(), Some(&c[6].locator));
        assert_eq!(sms.alt_submit_indices, [7]);
        assert_eq!(sms.method, Some(FormMethod::Post));
        assert_eq!(sms.action.as_deref(), Some("/invite/sms"));
        assert_eq!(sms.semantics, FormSemantics::Invite);
        assert_eq!(sms.form_hint().as_deref(), Some("external_communication:sms"));
        assert_eq!(channel_of(sms), SinkKind::Sms);
        assert_eq!(requires_sink(sms), Some(SinkKind::Sms));
        assert_eq!(webhook.form_index, Some(1));
        assert_eq!(webhook.inputs.iter().map(|i| i.index).collect::<Vec<_>>(), [3, 5]);
        assert_eq!(webhook.submit_index, Some(8));
        assert_eq!(webhook.submit.as_ref(), Some(&c[8].locator));
        assert_eq!(webhook.alt_submit_indices, [9]);
        assert_eq!(webhook.method, Some(FormMethod::Post));
        assert_eq!(webhook.action.as_deref(), Some("/invite/webhook"));
        assert_eq!(webhook.semantics, FormSemantics::Invite);
        assert_eq!(
            webhook.form_hint().as_deref(),
            Some("external_communication:webhook")
        );
        assert_eq!(channel_of(webhook), SinkKind::Webhook);
        assert_eq!(requires_sink(webhook), Some(SinkKind::Webhook));
    }

    #[test]
    fn undeclared_backend_keys_and_declaration_form_attributes_do_not_create_aliases() {
        let c = vec![
            desc(
                10,
                "form",
                "form",
                &[
                    ("id", "20"),
                    ("crawlx:form", "10"),
                    ("form", "30"),
                    ("action", "/invite/sms"),
                ],
            ),
            input(11, &[("type", "tel"), ("crawlx:form", "10")]),
            with(submit(12, "Invite"), "crawlx:form", "10"),
            input(21, &[("name", "webhook"), ("crawlx:form", "20")]),
            input(31, &[("name", "webhook"), ("form", "30")]),
        ];
        let groups = FormGrouper::new().group(&c);
        assert_eq!(groups.len(), 3, "{groups:#?}");
        assert_eq!(
            groups[0].form_hint().as_deref(),
            Some("external_communication:sms")
        );
        assert_eq!(groups[0].action.as_deref(), Some("/invite/sms"));
        assert_eq!(groups[0].inputs[0].index, 1);
        for (group, index) in groups[1..].iter().zip([3, 4]) {
            assert_eq!(group.inputs.len(), 1);
            assert_eq!(group.inputs[0].index, index);
            assert_eq!(group.form_index, None);
            assert_eq!(group.action, None);
            assert_eq!(group.submit_index, None);
        }
    }

    #[test]
    fn observed_owners_and_author_aliases_stay_in_their_frames() {
        let mut c = vec![
            desc(
                10,
                "form",
                "form",
                &[("id", "20"), ("crawlx:form", "10"), ("action", "/invite/sms")],
            ),
            input(11, &[("type", "tel"), ("form", "20")]),
            with(submit(12, "Invite"), "crawlx:form", "10"),
            desc(
                10,
                "form",
                "form",
                &[("id", "20"), ("crawlx:form", "10"), ("action", "/invite/webhook")],
            ),
            input(11, &[("name", "webhook"), ("form", "20")]),
            with(submit(12, "Invite"), "crawlx:form", "10"),
        ];
        for (index, d) in c.iter_mut().enumerate() {
            d.frame_lineage = vec![if index < 3 { "a" } else { "b" }.into()];
        }
        let groups = FormGrouper::new().group(&c);
        assert_eq!(groups.len(), 2, "{groups:#?}");
        assert_ne!(groups[0].id, groups[1].id);
        assert_eq!(groups[0].inputs[0].index, 1);
        assert_eq!(groups[0].submit_index, Some(2));
        assert_eq!(groups[0].form_index, Some(0));
        assert_eq!(
            groups[0].form_hint().as_deref(),
            Some("external_communication:sms")
        );
        assert_eq!(groups[0].action.as_deref(), Some("/invite/sms"));
        assert_eq!(groups[1].inputs[0].index, 4);
        assert_eq!(groups[1].submit_index, Some(5));
        assert_eq!(groups[1].form_index, Some(3));
        assert_eq!(
            groups[1].form_hint().as_deref(),
            Some("external_communication:webhook")
        );
        assert_eq!(groups[1].action.as_deref(), Some("/invite/webhook"));
    }

    #[test]
    fn ax_form_landmark_groups_without_form_element() {
        let mut a = input(1, &[("type", "search")]);
        a.ancestor_roles = vec!["main".into(), "search".into()];
        let mut b = submit(2, "Go");
        b.ancestor_roles = vec!["main".into(), "search".into()];
        let mut c = input(3, &[("type", "email")]);
        c.ancestor_roles = vec!["main".into(), "form".into()];
        let mut d = submit(4, "Send");
        d.ancestor_roles = vec!["main".into(), "form".into()];
        let groups = FormGrouper::new().group(&[a, b, c, d]);
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g.origin == GroupOrigin::AxLandmark));
        assert_eq!(groups[0].semantics, FormSemantics::Search);
        assert_eq!(groups[0].submit_index, Some(1));
        assert_eq!(groups[1].submit_index, Some(3));
        assert_ne!(groups[0].id, groups[1].id);
    }

    #[test]
    fn proximity_needs_exactly_one_submit() {
        let mk = |mut d: ObservedDescriptor| {
            d.ancestor_roles = vec!["main".into(), "dialog".into()];
            d
        };
        let one = vec![
            mk(input(1, &[("type", "email")])),
            mk(input(2, &[("type", "password")])),
            mk(submit(3, "Log in")),
        ];
        let g = FormGrouper::new().group(&one);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].origin, GroupOrigin::Proximity);
        assert_eq!(g[0].semantics, FormSemantics::Login);

        let two = vec![
            mk(input(1, &[("type", "email")])),
            mk(submit(2, "Save")),
            mk(submit(3, "Save and add another")),
        ];
        let g = FormGrouper::new().group(&two);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].origin, GroupOrigin::Orphan);
    }

    #[test]
    fn container_attribute_separates_siblings() {
        let mk = |d: ObservedDescriptor, c: &str| {
            let mut d = with(d, "crawlx:container", c);
            d.ancestor_roles = vec!["main".into()];
            d
        };
        let cands = vec![
            mk(input(1, &[("type", "email")]), "a"),
            mk(submit(2, "Join"), "a"),
            mk(input(3, &[("type", "search")]), "b"),
            mk(submit(4, "Go"), "b"),
        ];
        let g = FormGrouper::new().group(&cands);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].inputs[0].index, 0);
        assert_eq!(g[1].inputs[0].index, 2);
    }

    #[test]
    fn same_ids_in_different_frames_do_not_merge() {
        let mut f1 = with(input(1, &[("type", "email")]), "form", "x");
        f1.frame_lineage = vec!["a".into()];
        let mut f2 = with(input(2, &[("type", "email")]), "form", "x");
        f2.frame_lineage = vec!["b".into()];
        assert_eq!(FormGrouper::new().group(&[f1, f2]).len(), 2);
    }

    #[test]
    fn ids_are_deterministic_and_input_order_independent_of_hashing() {
        let c = vec![
            desc(1, "form", "form", &[("id", "f"), ("crawlx:form", "f")]),
            with(input(2, &[("type", "text")]), "crawlx:form", "f"),
        ];
        let a = FormGrouper::new().group(&c);
        let b = FormGrouper::new().group(&c);
        assert_eq!(a, b);
        assert!(a[0].id.0.starts_with("g-") && a[0].id.0.len() == 18);
    }

    #[test]
    fn hidden_only_orphans_are_dropped_and_hidden_inputs_in_forms_are_kept() {
        let c = vec![
            input(1, &[("type", "hidden"), ("name", "csrf")]),
            desc(2, "form", "form", &[("id", "f"), ("crawlx:form", "f")]),
            with(
                input(3, &[("type", "hidden"), ("name", "csrf")]),
                "crawlx:form",
                "f",
            ),
            with(input(4, &[("type", "text")]), "crawlx:form", "f"),
        ];
        let g = FormGrouper::new().group(&c);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].inputs.len(), 2);
        assert_eq!(g[0].fillable_inputs().count(), 1);
    }

    #[test]
    fn method_defaults_and_submit_overrides() {
        let c = vec![
            desc(1, "form", "form", &[("id", "f"), ("crawlx:form", "f")]),
            with(input(2, &[("type", "text")]), "crawlx:form", "f"),
        ];
        assert_eq!(FormGrouper::new().group(&c)[0].method, Some(FormMethod::Get));
        let mut s = with(submit(3, "Go"), "crawlx:form", "f");
        s.attributes.insert("formmethod".into(), "post".into());
        s.attributes.insert("formaction".into(), "/other".into());
        let mut c2 = c.clone();
        c2.push(s);
        let g = &FormGrouper::new().group(&c2)[0];
        assert_eq!(g.method, Some(FormMethod::Post));
        assert_eq!(g.action.as_deref(), Some("/other"));
    }

    fn semantics_of(fields: Vec<ObservedDescriptor>, label: &str, action: &str) -> FormSemantics {
        let mut c = vec![desc(
            100,
            "form",
            "form",
            &[("id", "f"), ("crawlx:form", "f"), ("action", action)],
        )];
        c.extend(fields.into_iter().map(|d| with(d, "crawlx:form", "f")));
        c.push(with(submit(200, label), "crawlx:form", "f"));
        FormGrouper::new().group(&c)[0].semantics
    }

    #[test]
    fn semantics_table() {
        use FormSemantics as S;
        let email = || input(1, &[("type", "email"), ("name", "email")]);
        let pw = || input(2, &[("type", "password"), ("name", "password")]);
        assert_eq!(semantics_of(vec![email(), pw()], "Continue", "/x"), S::Login);
        assert_eq!(
            semantics_of(vec![email(), pw(), pw()], "Continue", "/x"),
            S::Registration
        );
        assert_eq!(
            semantics_of(vec![email(), pw()], "Create account", "/x"),
            S::Registration
        );
        assert_eq!(
            semantics_of(vec![email(), pw()], "Registrieren", "/x"),
            S::Registration
        );
        assert_eq!(
            semantics_of(
                vec![
                    input(3, &[("type", "password"), ("autocomplete", "current-password")]),
                    input(4, &[("type", "password"), ("autocomplete", "new-password")]),
                ],
                "Save",
                "/x"
            ),
            S::Settings
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("autocomplete", "cc-number")])], "Pay", "/x"),
            S::Payment
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("name", "x")])], "Buy now", "/x"),
            S::Payment
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("type", "search")])], "Go", "/x"),
            S::Search
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("name", "q")])], "Suche", "/find"),
            S::Search
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("type", "file")])], "Upload", "/x"),
            S::Upload
        );
        assert_eq!(
            semantics_of(
                vec![email(), desc(5, "textarea", "textbox", &[("name", "message")])],
                "Send",
                "/contact"
            ),
            S::Contact
        );
        assert_eq!(
            semantics_of(
                vec![desc(5, "textarea", "textbox", &[("name", "comment")])],
                "Post",
                "/x"
            ),
            S::Comment
        );
        assert_eq!(semantics_of(vec![email()], "Invitar", "/x"), S::Invite);
        assert_eq!(
            semantics_of(vec![input(1, &[("name", "theme")])], "Save changes", "/x"),
            S::Settings
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("name", "ayar")])], "Kaydet", "/ayarlar"),
            S::Settings
        );
        assert_eq!(
            semantics_of(vec![input(1, &[("name", "foo")])], "OK", "/x"),
            S::Unknown
        );
    }

    #[test]
    fn hint_channel_suffix() {
        let sms = vec![
            desc(
                1,
                "form",
                "form",
                &[("id", "f"), ("crawlx:form", "f"), ("action", "/invite")],
            ),
            with(
                input(2, &[("type", "tel"), ("name", "phone")]),
                "crawlx:form",
                "f",
            ),
            with(submit(3, "Send invite"), "crawlx:form", "f"),
        ];
        let g = &FormGrouper::new().group(&sms)[0];
        assert_eq!(g.semantics, FormSemantics::Invite);
        assert_eq!(g.form_hint().as_deref(), Some("external_communication:sms"));

        let hook = vec![
            desc(
                1,
                "form",
                "form",
                &[("id", "f"), ("crawlx:form", "f"), ("action", "/invite")],
            ),
            with(input(2, &[("name", "webhook")]), "crawlx:form", "f"),
            with(submit(3, "Invite"), "crawlx:form", "f"),
        ];
        let g = &FormGrouper::new().group(&hook)[0];
        assert_eq!(g.form_hint().as_deref(), Some("external_communication:webhook"));
    }
}
