//! Side-effect classification.
//!
//! `classify` maps an [`ActionProposal`] plus the live facts in a
//! [`SafetyContext`] to a [`RiskClass`]. Every piece of evidence yields a
//! *signal* (a minimum class and a rule id); the result is the signal with
//! the highest [`severity`] (monotone: more evidence never lowers risk).
//!
//! Page text is attacker-controlled, so text matches only **raise**:
//!
//! * `NavigationReveal` and `ReversibleLocalPreference` need *structural*
//!   evidence (an in-scope link, a disclosure/tab/menu pattern, a form control
//!   role, a GET form submit), never a name alone.
//! * Without structural evidence and without a risk signal the class is
//!   `Unclassified` (denied under `read_only`: the positive classification
//!   rule).
//! * A hint (`ActionProposal::hinted_risk`, `ModelHint::risk_floor`) is applied
//!   by [`raise`](crate::profiles::raise) after classification and can only
//!   raise.
//!
//! Structural attributes are read from `LiveTargetFacts::attributes`
//! (`aria-expanded`, `aria-haspopup`, `aria-pressed`, `type`, `form-method`,
//! `form-action`, `confirm-dialog`, `observed-methods`). Observers that
//! default a form's method to GET MUST report `form-method=get` explicitly;
//! a submit control without it counts as a write.

use crate::lexicon::{self, Normalized};
use crate::provenance::{redact, Provenance, RedactedText};
use crawlx_core::action::BrowserAction;
use crawlx_core::identity::{ActionKind, ResourceContext};
use crawlx_core::observation::LiveTargetFacts;
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::RiskClass;
use url::Url;

/// Total order of how much damage a class can do, used for "raise only"
/// comparisons. `RiskClass`'s own `Ord` follows declaration order and is not a
/// severity order. `Unclassified` sits between the local classes and the
/// write classes: it is "no evidence", treated as an own write by the table.
#[must_use]
pub const fn severity(c: RiskClass) -> u8 {
    match c {
        RiskClass::NavigationReveal => 0,
        RiskClass::ReversibleLocalPreference => 1,
        RiskClass::Unclassified => 2,
        RiskClass::PersistentWriteOwn => 3,
        RiskClass::FileUpload => 4,
        RiskClass::PersistentWriteOtherPrincipal => 5,
        RiskClass::ExternalCommunication => 6,
        RiskClass::FinancialTransaction => 7,
        RiskClass::Destructive => 8,
        RiskClass::SecurityChange => 9,
        RiskClass::OutOfScope => 10,
    }
}

/// One piece of evidence: the minimum class it implies and the rule that fired.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signal {
    /// Minimum risk class this signal implies.
    pub class: RiskClass,
    /// Stable rule identifier that fired.
    pub rule: &'static str,
}

/// What the classification was based on. Contains no raw page text: the
/// accessible name is truncated and hashed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Evidence {
    /// Kind of the proposed action.
    pub kind: ActionKind,
    /// ARIA role of the target, if any.
    pub role: Option<String>,
    /// HTML tag of the target, if any.
    pub tag: Option<String>,
    /// Redacted accessible name of the target, if any.
    pub name: Option<RedactedText>,
    /// Scope verdict for the destination or page, when one could be computed.
    pub destination_in_scope: Option<bool>,
    /// All signals in evaluation order.
    pub signals: Vec<Signal>,
}

/// Classification result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Classification {
    /// Highest risk class implied by the signals.
    pub risk: RiskClass,
    /// Rule ids of every signal that fired, in evaluation order, without duplicates.
    pub rules: Vec<&'static str>,
    /// What the classification was based on.
    pub evidence: Evidence,
}

/// The crawl scope as the kernel sees it. The kernel trusts
/// `SafetyContext::in_scope` (decided by `crawlx-policy`) **and** re-checks
/// every destination against the seed origin, so a policy bug cannot widen
/// scope on its own.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ScopeRules {
    /// `scope.allowSubdomains`: hosts below the seed host are in scope.
    pub allow_subdomains: bool,
    /// Additional exact hosts (same scheme and port as the seed).
    pub extra_hosts: Vec<String>,
}

impl ScopeRules {
    /// Is `candidate` inside the scope rooted at `seed`? Only `http`/`https`
    /// URLs can be in scope.
    #[must_use]
    pub fn contains(&self, seed: &Url, candidate: &Url) -> bool {
        if !matches!(candidate.scheme(), "http" | "https") || candidate.scheme() != seed.scheme() {
            return false;
        }
        if candidate.port_or_known_default() != seed.port_or_known_default() {
            return false;
        }
        let (Some(sh), Some(ch)) = (seed.host_str(), candidate.host_str()) else {
            return false;
        };
        if sh.eq_ignore_ascii_case(ch) {
            return true;
        }
        if self.allow_subdomains
            && ch.len() > sh.len()
            && ch
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", sh.to_ascii_lowercase()))
        {
            return true;
        }
        self.extra_hosts.iter().any(|h| h.eq_ignore_ascii_case(ch))
    }
}

/// Classifier with explicit scope rules.
#[derive(Clone, Debug, Default)]
pub struct Classifier {
    scope: ScopeRules,
}

/// Classify with the default scope rules (exact seed origin only).
#[must_use]
pub fn classify(p: &ActionProposal, c: &SafetyContext) -> Classification {
    Classifier::default().classify(p, c)
}

/// What an `href` turned out to be.
enum Href {
    Fragment,
    Http { url: Url, in_scope: bool },
    Messaging,
    Javascript,
    OtherScheme,
    Unresolvable,
}

/// Query parameters that carry an action verb.
const ACTION_PARAMS: &[&str] = &["action", "do", "cmd", "command", "op", "operation", "act"];
/// Action-parameter values known to be read-only.
const BENIGN_ACTION_VALUES: &[&str] = &[
    "view", "show", "list", "read", "get", "search", "display", "open", "browse",
];
const DISCLOSURE_ROLES: &[&str] = &["tab", "tablist", "menu", "menubar", "summary", "treeitem"];
const CONTROL_ROLES: &[&str] = &[
    "combobox",
    "listbox",
    "option",
    "radio",
    "switch",
    "checkbox",
    "slider",
    "spinbutton",
    "menuitemradio",
    "menuitemcheckbox",
];
/// Keys that move focus or scroll without activating anything.
const PASSIVE_KEYS: &[&str] = &[
    "tab",
    "escape",
    "esc",
    "arrowup",
    "arrowdown",
    "arrowleft",
    "arrowright",
    "home",
    "end",
    "pageup",
    "pagedown",
];

impl Classifier {
    /// Classifier enforcing `scope`.
    #[must_use]
    pub fn new(scope: ScopeRules) -> Self {
        Self { scope }
    }

    /// The scope rules this classifier enforces.
    #[must_use]
    pub const fn scope(&self) -> &ScopeRules {
        &self.scope
    }

    /// Classify `p` under the facts in `c`.
    #[must_use]
    pub fn classify(&self, p: &ActionProposal, c: &SafetyContext) -> Classification {
        let kind = p.action.kind();
        let f = &c.target;
        let view = View::new(self, c, f);
        let mut sig: Vec<Signal> = Vec::with_capacity(8);

        if kind != ActionKind::CloseTab {
            self.scope_signals(&view, c, &mut sig);
        }

        match kind {
            ActionKind::Hover | ActionKind::Scroll => {
                push(&mut sig, RiskClass::NavigationReveal, "kind.hover_scroll")
            }
            ActionKind::SwitchTab | ActionKind::CloseTab => {
                push(&mut sig, RiskClass::NavigationReveal, "kind.tab_management");
            }
            ActionKind::Navigate => self.navigate_signals(&view, &p.action, &mut sig),
            ActionKind::SolveCaptcha => {
                push(&mut sig, RiskClass::Unclassified, "kind.captcha_callback");
                self.activation_signals(&view, &mut sig);
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Keys => {
                self.keys_signals(&view, &p.action, &mut sig);
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Drag => {
                push(&mut sig, RiskClass::PersistentWriteOwn, "kind.drag");
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Upload => {
                push(&mut sig, RiskClass::FileUpload, "kind.upload");
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Click | ActionKind::KeyboardActivate | ActionKind::SyntheticClick => {
                self.activation_signals(&view, &mut sig);
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Type => {
                self.type_signals(&view, p, &mut sig);
                self.common_signals(&view, c, &mut sig);
            }
            ActionKind::Select | ActionKind::SetChecked | ActionKind::SetRange => {
                self.value_signals(&view, &mut sig);
                self.common_signals(&view, c, &mut sig);
            }
        }

        if sig.is_empty() {
            push(&mut sig, RiskClass::Unclassified, "evidence.insufficient");
        }

        let mut risk = RiskClass::NavigationReveal;
        for s in &sig {
            if severity(s.class) > severity(risk) {
                risk = s.class;
            }
        }

        // A write on another principal's resource is a cross-principal write.
        let foreign = matches!(
            p.key.resource_context,
            ResourceContext::OtherUserSameRole | ResourceContext::HigherRole
        );
        if foreign
            && matches!(
                risk,
                RiskClass::PersistentWriteOwn | RiskClass::Unclassified | RiskClass::FileUpload
            )
        {
            push(
                &mut sig,
                RiskClass::PersistentWriteOtherPrincipal,
                "context.cross_principal_write",
            );
            risk = RiskClass::PersistentWriteOtherPrincipal;
        }

        // Proposer hint: raise only.
        if let Some(h) = p.hinted_risk {
            if severity(h) > severity(risk) {
                push(&mut sig, h, "hint.proposal_raise");
                risk = h;
            }
        }

        let mut rules: Vec<&'static str> = Vec::with_capacity(sig.len());
        for s in &sig {
            if !rules.contains(&s.rule) {
                rules.push(s.rule);
            }
        }

        Classification {
            risk,
            rules,
            evidence: Evidence {
                kind,
                role: view.role_for_evidence(),
                tag: view.tag_for_evidence(),
                name: f
                    .name
                    .as_deref()
                    .filter(|n| !n.trim().is_empty())
                    .map(|n| redact(n, Provenance::AccessibleName)),
                destination_in_scope: view.destination_in_scope,
                signals: sig,
            },
        }
    }

    // ---- scope ---------------------------------------------------------

    fn scope_signals(&self, v: &View<'_>, c: &SafetyContext, sig: &mut Vec<Signal>) {
        if !c.in_scope {
            push(sig, RiskClass::OutOfScope, "scope.context_out_of_scope");
        }
        if v.seed.is_none() {
            push(sig, RiskClass::OutOfScope, "scope.seed_origin_invalid");
            return;
        }
        if !v.f.current_url.trim().is_empty() {
            match &v.current {
                Some(u) if self.in_scope(v, u) => {}
                _ => push(sig, RiskClass::OutOfScope, "scope.page_outside"),
            }
        }
        if let Some(fu) = v.f.frame_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            // about:blank / srcdoc frames inherit the parent's origin; only
            // real network frames are scope-checked.
            if let Ok(u) = Url::parse(fu) {
                if matches!(u.scheme(), "http" | "https") && !self.in_scope(v, &u) {
                    push(sig, RiskClass::OutOfScope, "scope.frame_outside");
                }
            }
        }
    }

    fn in_scope(&self, v: &View<'_>, u: &Url) -> bool {
        v.seed.as_ref().is_some_and(|s| self.scope.contains(s, u))
    }

    fn resolve_href(&self, v: &View<'_>, href: &str) -> Href {
        let h = href.trim();
        if h.starts_with('#') {
            return Href::Fragment;
        }
        let parsed = match Url::parse(h) {
            Ok(u) => u,
            Err(url::ParseError::RelativeUrlWithoutBase) => match v.current.as_ref().map(|b| b.join(h)) {
                Some(Ok(u)) => u,
                _ => return Href::Unresolvable,
            },
            Err(_) => return Href::Unresolvable,
        };
        match parsed.scheme() {
            "http" | "https" => {
                let in_scope = self.in_scope(v, &parsed);
                Href::Http {
                    url: parsed,
                    in_scope,
                }
            }
            "mailto" | "tel" | "sms" => Href::Messaging,
            "javascript" => Href::Javascript,
            _ => Href::OtherScheme,
        }
    }

    // ---- per action kind -------------------------------------------------

    fn navigate_signals(&self, v: &View<'_>, a: &BrowserAction, sig: &mut Vec<Signal>) {
        let BrowserAction::Navigate { url } = a else {
            push(sig, RiskClass::Unclassified, "kind.navigate_malformed");
            return;
        };
        if !matches!(url.scheme(), "http" | "https") {
            push(sig, RiskClass::OutOfScope, "scope.navigate_scheme");
            return;
        }
        if self.in_scope(v, url) {
            push(sig, RiskClass::NavigationReveal, "kind.navigate");
            url_signals(url, sig);
        } else {
            push(sig, RiskClass::OutOfScope, "scope.navigate_outside");
        }
    }

    fn keys_signals(&self, v: &View<'_>, a: &BrowserAction, sig: &mut Vec<Signal>) {
        let BrowserAction::Keys { sequence } = a else {
            push(sig, RiskClass::Unclassified, "kind.keys_malformed");
            return;
        };
        let passive = sequence.iter().all(|k| {
            !k.modifiers.ctrl
                && !k.modifiers.meta
                && !k.modifiers.alt
                && PASSIVE_KEYS.contains(&k.key.to_ascii_lowercase().as_str())
        });
        if passive {
            push(sig, RiskClass::NavigationReveal, "kind.keys_passive");
        } else {
            push(sig, RiskClass::Unclassified, "kind.keys_unscoped");
        }
        // The focused element's own name can still reveal a dangerous control.
        if let Some(n) = &v.name {
            self.name_signals(n, NameScope::RiskOnly, sig);
        }
    }

    fn activation_signals(&self, v: &View<'_>, sig: &mut Vec<Signal>) {
        let href =
            v.f.href
                .as_deref()
                .filter(|h| !h.trim().is_empty())
                .map(|h| self.resolve_href(v, h));
        let is_link = v.role == "link" || matches!(v.tag.as_str(), "a" | "area");
        let mut link_nav = false;
        if let Some(h) = &href {
            match h {
                Href::Fragment => link_nav = is_link,
                Href::Http { url, in_scope } => {
                    if *in_scope {
                        link_nav = is_link;
                        url_signals(url, sig);
                    } else {
                        push(sig, RiskClass::OutOfScope, "scope.href_outside");
                    }
                }
                Href::Messaging => push(sig, RiskClass::ExternalCommunication, "href.messaging_scheme"),
                Href::Javascript => push(sig, RiskClass::Unclassified, "href.javascript"),
                Href::OtherScheme => push(sig, RiskClass::OutOfScope, "scope.href_scheme"),
                Href::Unresolvable => push(sig, RiskClass::Unclassified, "href.unresolvable"),
            }
        }
        if link_nav {
            push(sig, RiskClass::NavigationReveal, "structural.link_in_scope");
        }

        let disclosure = v.attr("aria-expanded").is_some()
            || DISCLOSURE_ROLES.contains(&v.role.as_str())
            || matches!(v.tag.as_str(), "summary" | "details")
            || v.attr("aria-haspopup")
                .is_some_and(|p| !p.eq_ignore_ascii_case("false"));
        if disclosure {
            push(sig, RiskClass::NavigationReveal, "structural.disclosure");
        }

        // Preference toggles: vocabulary AND a structural control.
        let structural_control = CONTROL_ROLES.contains(&v.role.as_str()) || v.attr("aria-pressed").is_some();
        if structural_control
            && v.name
                .as_ref()
                .is_some_and(|n| n.matches_any(lexicon::PREFERENCE, false))
        {
            push(
                sig,
                RiskClass::ReversibleLocalPreference,
                "structural.preference_toggle",
            );
        }

        // Submit semantics.
        if v.attr("type")
            .is_some_and(|t| t.eq_ignore_ascii_case("submit") || t.eq_ignore_ascii_case("image"))
        {
            if v.attr("form-method")
                .is_some_and(|m| m.eq_ignore_ascii_case("get"))
            {
                push(sig, RiskClass::NavigationReveal, "structural.form_get_submit");
            } else {
                push(sig, RiskClass::PersistentWriteOwn, "structural.submit");
            }
        }

        if let Some(n) = &v.name {
            let scope = if link_nav {
                NameScope::LinkNavigation
            } else if disclosure {
                NameScope::VerbsOnly
            } else {
                NameScope::Full
            };
            self.name_signals(n, scope, sig);
        }
    }

    fn type_signals(&self, v: &View<'_>, p: &ActionProposal, sig: &mut Vec<Signal>) {
        let searchy =
            v.role == "searchbox" || v.attr("type").is_some_and(|t| t.eq_ignore_ascii_case("search"));
        if searchy {
            push(
                sig,
                RiskClass::ReversibleLocalPreference,
                "structural.search_input",
            );
        }
        match input_kind(&p.key.input_class.0).as_str() {
            "password" => push(sig, RiskClass::SecurityChange, "input.password"),
            "card" | "cc" | "creditcard" | "credit_card" | "cvv" | "iban" | "payment" => {
                push(sig, RiskClass::FinancialTransaction, "input.payment");
            }
            _ => {}
        }
        if let Some(n) = &v.name {
            self.name_signals(n, NameScope::RiskOnly, sig);
        }
    }

    fn value_signals(&self, v: &View<'_>, sig: &mut Vec<Signal>) {
        if v.name
            .as_ref()
            .is_some_and(|n| n.matches_any(lexicon::PREFERENCE, false))
        {
            push(
                sig,
                RiskClass::ReversibleLocalPreference,
                "structural.preference_toggle",
            );
        }
        if let Some(n) = &v.name {
            self.name_signals(n, NameScope::RiskOnly, sig);
        }
    }

    /// Signals shared by every kind that acts on a control.
    fn common_signals(&self, v: &View<'_>, c: &SafetyContext, sig: &mut Vec<Signal>) {
        if let Some(hint) = c.form_hint.as_deref() {
            let h = hint.to_ascii_lowercase();
            if h.contains("external_communication") {
                push(
                    sig,
                    RiskClass::ExternalCommunication,
                    "form.external_communication",
                );
            }
            if h.contains("payment") {
                push(sig, RiskClass::FinancialTransaction, "form.payment");
            }
            if h.contains("credentials") {
                push(sig, RiskClass::SecurityChange, "form.credentials");
            }
        }
        match v.attr("type").map(str::to_ascii_lowercase).as_deref() {
            Some("file") => push(sig, RiskClass::FileUpload, "structural.file_input"),
            Some("password") => push(sig, RiskClass::SecurityChange, "structural.password_input"),
            _ => {}
        }
        if v.attr("form-method").is_some_and(|m| {
            ["post", "put", "patch", "delete"]
                .iter()
                .any(|w| m.eq_ignore_ascii_case(w))
        }) {
            push(sig, RiskClass::PersistentWriteOwn, "structural.form_post");
        }
        if let Some(action) = v.attr("form-action").filter(|a| !a.trim().is_empty()) {
            match self.resolve_href(v, action) {
                Href::Http { url, in_scope: true } => url_signals(&url, sig),
                Href::Http { in_scope: false, .. } => {
                    push(sig, RiskClass::OutOfScope, "scope.form_action_outside")
                }
                Href::Fragment => {}
                Href::Messaging => push(sig, RiskClass::ExternalCommunication, "form.action_messaging"),
                Href::Javascript | Href::Unresolvable => {
                    push(sig, RiskClass::Unclassified, "form.action_unresolvable")
                }
                Href::OtherScheme => push(sig, RiskClass::OutOfScope, "scope.form_action_scheme"),
            }
        }
        if v.attr("confirm-dialog")
            .is_some_and(|d| d.eq_ignore_ascii_case("true"))
        {
            push(sig, RiskClass::Destructive, "dialog.confirm");
        }
        if let Some(methods) = v.attr("observed-methods") {
            let up = methods.to_ascii_uppercase();
            let has = |m: &str| up.split(',').any(|x| x.trim() == m);
            if has("DELETE") {
                push(sig, RiskClass::Destructive, "traffic.delete_method");
            }
            if has("POST") || has("PUT") || has("PATCH") || has("GRAPHQL_MUTATION") {
                push(sig, RiskClass::PersistentWriteOwn, "traffic.mutating_method");
            }
        }
    }

    fn name_signals(&self, n: &Normalized, scope: NameScope, sig: &mut Vec<Signal>) {
        let (verbs_only, classes): (bool, &[RiskClass]) = match scope {
            NameScope::LinkNavigation => (true, &HIGH_SEVERITY),
            NameScope::VerbsOnly => (true, &ALL_LEXICON),
            NameScope::Full => (false, &ALL_LEXICON),
            NameScope::RiskOnly => (false, &HIGH_SEVERITY),
        };
        for &class in classes {
            if n.matches_any(lexicon::lexicon_for(class), verbs_only) {
                push(sig, class, rule_for_lexicon(class));
            }
        }
    }
}

/// Which lexicons apply to a name.
#[derive(Clone, Copy)]
enum NameScope {
    /// In-scope GET link: destructive, financial and security verbs only.
    LinkNavigation,
    /// Disclosure control: every class, verbs only.
    VerbsOnly,
    /// Activation control: every class, verbs and nouns.
    Full,
    /// Value entry / focus: destructive, financial and security terms.
    RiskOnly,
}

const HIGH_SEVERITY: [RiskClass; 3] = [
    RiskClass::Destructive,
    RiskClass::FinancialTransaction,
    RiskClass::SecurityChange,
];
const ALL_LEXICON: [RiskClass; 6] = [
    RiskClass::Destructive,
    RiskClass::FinancialTransaction,
    RiskClass::SecurityChange,
    RiskClass::ExternalCommunication,
    RiskClass::PersistentWriteOwn,
    RiskClass::FileUpload,
];

const fn rule_for_lexicon(c: RiskClass) -> &'static str {
    match c {
        RiskClass::Destructive => "lexicon.destructive",
        RiskClass::FinancialTransaction => "lexicon.financial",
        RiskClass::SecurityChange => "lexicon.security",
        RiskClass::ExternalCommunication => "lexicon.external_communication",
        RiskClass::PersistentWriteOwn => "lexicon.persistent_write",
        RiskClass::FileUpload => "lexicon.file_upload",
        RiskClass::NavigationReveal
        | RiskClass::ReversibleLocalPreference
        | RiskClass::PersistentWriteOtherPrincipal
        | RiskClass::OutOfScope
        | RiskClass::Unclassified => "lexicon.none",
    }
}

fn push(sig: &mut Vec<Signal>, class: RiskClass, rule: &'static str) {
    sig.push(Signal { class, rule });
}

/// Kind prefix of an `InputClass` (`password:secret_ref` → `password`).
fn input_kind(input_class: &str) -> String {
    input_class
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Destructive, financial and security *verbs* in `text` (a path segment or
/// query component) raise the matching class under `rule`.
fn high_verbs(text: &str, sig: &mut Vec<Signal>, rule: fn(RiskClass) -> &'static str) {
    let n = Normalized::new(text);
    for class in HIGH_SEVERITY {
        if n.matches_any(lexicon::lexicon_for(class), true) {
            push(sig, class, rule(class));
        }
    }
}

/// Signals from a destination URL: such verbs in path segments and query
/// keys, and `ACTION_BEARING` parameters (their values are scanned too).
fn url_signals(url: &Url, sig: &mut Vec<Signal>) {
    if let Some(segments) = url.path_segments() {
        for seg in segments {
            high_verbs(&percent_decode(seg), sig, url_path_rule);
        }
    }
    for (k, v) in url.query_pairs() {
        high_verbs(&k, sig, url_query_rule);
        if ACTION_PARAMS.contains(&k.to_ascii_lowercase().as_str()) {
            let value = v.trim().to_ascii_lowercase();
            if !BENIGN_ACTION_VALUES.contains(&value.as_str()) {
                push(sig, RiskClass::PersistentWriteOwn, "url.action_param");
            }
            high_verbs(&v, sig, url_query_rule);
            if Normalized::new(&v).matches_any(lexicon::EXTERNAL, true) {
                push(sig, RiskClass::ExternalCommunication, "url.query_external");
            }
        }
    }
}

const fn url_path_rule(c: RiskClass) -> &'static str {
    match c {
        RiskClass::Destructive => "url.path_destructive",
        RiskClass::FinancialTransaction => "url.path_financial",
        _ => "url.path_security",
    }
}

const fn url_query_rule(c: RiskClass) -> &'static str {
    match c {
        RiskClass::Destructive => "url.query_destructive",
        RiskClass::FinancialTransaction => "url.query_financial",
        _ => "url.query_security",
    }
}

/// Minimal percent-decoder (lossy UTF-8) so `%64elete` cannot hide a verb.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hi = b.get(i + 1).copied().and_then(hex);
            let lo = b.get(i + 2).copied().and_then(hex);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Borrowed, pre-digested view of the live facts.
struct View<'a> {
    f: &'a LiveTargetFacts,
    role: String,
    tag: String,
    name: Option<Normalized>,
    seed: Option<Url>,
    current: Option<Url>,
    destination_in_scope: Option<bool>,
}

impl<'a> View<'a> {
    fn new(cl: &Classifier, c: &SafetyContext, f: &'a LiveTargetFacts) -> Self {
        let seed = Url::parse(c.seed_origin.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"));
        let current = Url::parse(f.current_url.trim()).ok();
        let destination_in_scope = match (&seed, &current) {
            (Some(s), Some(u)) => Some(cl.scope.contains(s, u)),
            _ => None,
        };
        Self {
            f,
            role: f.role.as_deref().unwrap_or_default().trim().to_ascii_lowercase(),
            tag: f.tag.as_deref().unwrap_or_default().trim().to_ascii_lowercase(),
            name: f
                .name
                .as_deref()
                .filter(|n| !n.trim().is_empty())
                .map(Normalized::new),
            seed,
            current,
            destination_in_scope,
        }
    }

    fn attr(&self, key: &str) -> Option<&str> {
        self.f.attributes.get(key).map(String::as_str)
    }

    fn role_for_evidence(&self) -> Option<String> {
        sanitize_token(&self.role)
    }

    fn tag_for_evidence(&self) -> Option<String> {
        sanitize_token(&self.tag)
    }
}

/// Keep only `[a-z0-9-]` (max 24 chars): roles and tags are page-influenced
/// strings and must not carry free text into audit rows.
fn sanitize_token(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(24)
        .collect();
    (!t.is_empty()).then_some(t)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn percent_decode_accepts_both_hex_cases_and_digits() {
        assert_eq!(percent_decode("%64%65%6c%65%74%65"), "delete");
        assert_eq!(percent_decode("%44%45%4C%45%54%45"), "DELETE");
        assert_eq!(percent_decode("%31%2b%2B%7a%5A"), "1++zZ");
        assert_eq!(percent_decode("%30%39%61%66%41%46"), "09afAF");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn percent_decode_leaves_malformed_escapes_alone() {
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%g1%1g"), "%g1%1g");
        assert_eq!(percent_decode("%6"), "%6");
    }

    #[test]
    fn sanitize_token_keeps_only_lowercase_alphanumerics_and_dashes() {
        assert_eq!(
            sanitize_token("custom-el ement!").as_deref(),
            Some("custom-element")
        );
        assert_eq!(sanitize_token("a_b.c/d").as_deref(), Some("abcd"));
        assert_eq!(sanitize_token("<>! \n"), None);
        assert_eq!(sanitize_token(""), None);
        assert_eq!(sanitize_token(&"x".repeat(40)).map(|t| t.len()), Some(24));
    }
}
