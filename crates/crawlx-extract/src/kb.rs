//! Knowledge base (`extract.knowledgeBase`, `-kb`, `-kb-endpoints`,
//! `-kb-validate-secrets`): the structured facts katana attaches to each
//! response under `knowledgebase`.
//!
//! Katana classifies pages and forms with a trained model (`dit`) and
//! endpoints with the heuristics of
//! `pkg/knowledgebase/extractors/endpoints/endpoints.go` (MIT, commit
//! 9662cd7). crawlx ships no model: the page type is the deterministic
//! [`PageType`] of [`crate::page_type`], forms are classified by structural
//! rules ([`classify_form`]) and endpoints by [`classify_endpoint`], the same
//! decision tree as `crawlx_observe::network::classify_endpoint` (class names
//! included). The table is mirrored because this crate may not depend on
//! `crawlx-observe`; a dev-only parity test keeps the two in step. Beyond the
//! observe tree, [`classify_endpoint`] also reads a request tag (script
//! requests, form submissions, `SOAPAction`) and treats a `soap` path segment
//! or an `.asmx` path as SOAP.
//!
//! [`KnowledgeBase`] is the serializable record: `PageType`, `Forms`,
//! `secrets` and `endpoints`, each omitted when empty.
//!
//! # Form labels
//!
//! [`classify_form`] returns one of `payment`, `password_recovery`,
//! `registration`, `login`, `search`, `order`, `contact`, `upload`,
//! `newsletter` or `other`, the first whose rule holds:
//!
//! 1. `payment`: a card number, expiry or security-code field.
//! 2. `password_recovery`: a "forgot / reset / recover" cue in the action
//!    path or a submit label and at most two password fields.
//! 3. `registration`: two or more password fields (a confirmation); or one
//!    password plus an email and a username, a person-name field or a
//!    "register / sign up / create account / join" cue; or such a cue with
//!    no password but at least two fields among email, username and names.
//! 4. `login`: exactly one password field; or a "login / sign in" cue with
//!    an email or username field.
//! 5. `search`: a search-typed or search-named field in a GET form (or any
//!    form with a `type=search` field), or a "search" cue with at most two
//!    visible fields.
//! 6. `order`: a quantity field with a "cart / buy / order / checkout" cue,
//!    or an "add to cart / buy / order / purchase" submit label.
//! 7. `contact`: a textarea or a "contact / comment / feedback / message /
//!    enquiry / support" cue.
//! 8. `upload`: a file input.
//! 9. `newsletter`: an email field with a "subscribe / newsletter / mailing
//!    list" cue, or an email as the only visible field of a non-GET form.
//! 10. `other`.
//!
//! Cues are read from the action path and the submit labels only, never from
//! page text.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::endpoints::DiscoveredEndpoint;
use crate::form_fill::semantic::{self, Semantic};
use crate::forms::{StaticForm, StaticInput};
use crate::page_type::PageType;
use crate::secret_validation::Validity;
use crate::secrets::SecretFinding;

/// Family of a request. Katana's "skip" outcome is [`Static`](Self::Static).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EndpointClass {
    /// JSON/XML or form submission to an API-looking path or with a mutating verb.
    Rest,
    /// `graphql` path segment or `application/graphql`.
    Graphql,
    /// `soap+xml` content type, a `soap` path segment, an `.asmx` path or a `SOAPAction` header.
    Soap,
    /// JSON `GET` to a non-API path, or a script-issued request of unknown type (AJAX data load).
    Xhr,
    /// Everything else: documents, assets, unknown.
    Static,
}

impl EndpointClass {
    /// Wire name (`rest`, `graphql`, `soap`, `xhr`, `static`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Graphql => "graphql",
            Self::Soap => "soap",
            Self::Xhr => "xhr",
            Self::Static => "static",
        }
    }
}

/// Path substrings that suggest an API endpoint (katana `apiPathSegments`).
const API_PATH_SEGMENTS: &[&str] = &[
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/rpc/",
    "/jsonrpc",
    "/.well-known/",
    "/oauth/",
    "/openapi",
];

/// Tags of requests a script issues; their content type is assumed to be
/// JSON when none is known.
const SCRIPT_TAGS: &[&str] = &["xhr", "fetch", "ajax", "axios", "http", "htmx"];

fn media_type(content_type: Option<&str>) -> String {
    content_type
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Classify a request. Decision order, first match wins: SOAP, GraphQL, REST
/// (JSON/XML body with a mutating verb or an API path), XHR (JSON `GET`
/// elsewhere), REST (form body with a mutating verb), else static.
///
/// `content_type` is the request or response media type. `tag` says where the
/// request came from: `xhr`, `fetch`, `ajax`, `axios`, `http` and `htmx` are
/// script requests, which count as JSON when `content_type` is absent;
/// `form` is a form submission, urlencoded when `content_type` is absent;
/// `soapaction` marks a request that carried a `SOAPAction` header; any other
/// tag has no effect.
#[must_use]
pub fn classify_endpoint(url: &Url, method: &str, content_type: Option<&str>, tag: &str) -> EndpointClass {
    let method = method.trim().to_ascii_uppercase();
    let tag = tag.trim().to_ascii_lowercase();
    let path = url.path().to_ascii_lowercase();
    let ct = media_type(content_type);
    let segment = |name: &str| path.split('/').any(|s| s == name);

    if ct.contains("soap+xml") || tag == "soapaction" || segment("soap") || path.ends_with(".asmx") {
        return EndpointClass::Soap;
    }
    if segment("graphql") || ct.contains("application/graphql") {
        return EndpointClass::Graphql;
    }

    let scripted = SCRIPT_TAGS.contains(&tag.as_str());
    let is_json = ct.contains("application/json") || ct.ends_with("+json") || (ct.is_empty() && scripted);
    let is_xml = ct.contains("application/xml") || ct.ends_with("+xml") || ct == "text/xml";
    let is_form = ct.contains("application/x-www-form-urlencoded")
        || ct.contains("multipart/form-data")
        || (ct.is_empty() && tag == "form");
    let api_path = API_PATH_SEGMENTS.iter().any(|seg| path.contains(seg));
    let mutating = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");

    if (is_json || is_xml) && (mutating || api_path) {
        return EndpointClass::Rest;
    }
    if is_json && method == "GET" {
        return EndpointClass::Xhr;
    }
    if is_form && mutating {
        return EndpointClass::Rest;
    }
    EndpointClass::Static
}

/// [`classify_endpoint`] of a discovered endpoint: the request tag derives
/// from its source (`js/fetch` is `fetch`, `htmx/post` is `htmx`, `form/action`
/// is `form`), and a script-set `SOAPAction` header makes it SOAP.
#[must_use]
pub fn classify_discovered(endpoint: &DiscoveredEndpoint) -> EndpointClass {
    let source = endpoint.source;
    let tag = if source.tag == "js" {
        source.attribute
    } else {
        source.tag
    };
    let tag = if endpoint.headers.iter().any(|h| h == "soapaction") {
        "soapaction"
    } else {
        tag
    };
    classify_endpoint(
        &endpoint.url,
        endpoint.method.as_str(),
        endpoint.content_type.as_deref(),
        tag,
    )
}

/// One classified request as katana's endpoints extractor reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KbEndpoint {
    /// Request family; never [`EndpointClass::Static`].
    pub class: EndpointClass,
    /// Upper-case HTTP verb.
    pub method: String,
    /// URL without userinfo and fragment.
    pub url: String,
    /// Lower-case media type without parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Lower-case authorization scheme (`bearer`, `basic`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    /// Query parameter names in first-seen order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
}

impl KbEndpoint {
    /// Describe a request; `None` when it is [`EndpointClass::Static`].
    /// `authorization` is the request's `Authorization` header value, of which
    /// only the scheme is kept.
    #[must_use]
    pub fn new(
        url: &Url,
        method: &str,
        content_type: Option<&str>,
        tag: &str,
        authorization: Option<&str>,
    ) -> Option<Self> {
        let class = classify_endpoint(url, method, content_type, tag);
        Self::build(class, url, method, content_type, authorization)
    }

    /// Describe a discovered endpoint (see [`classify_discovered`]); `None`
    /// when static. Header values are not recorded for discovered endpoints,
    /// so `auth` stays empty.
    #[must_use]
    pub fn from_discovered(endpoint: &DiscoveredEndpoint) -> Option<Self> {
        let class = classify_discovered(endpoint);
        Self::build(
            class,
            &endpoint.url,
            endpoint.method.as_str(),
            endpoint.content_type.as_deref(),
            None,
        )
    }

    fn build(
        class: EndpointClass,
        url: &Url,
        method: &str,
        content_type: Option<&str>,
        authorization: Option<&str>,
    ) -> Option<Self> {
        if class == EndpointClass::Static {
            return None;
        }
        let mut clean = url.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);
        clean.set_fragment(None);
        let mut params: Vec<String> = Vec::new();
        for (name, _) in url.query_pairs() {
            if !name.is_empty() && !params.iter().any(|p| *p == name) {
                params.push(name.into_owned());
            }
        }
        let ct = media_type(content_type);
        let auth = authorization
            .map(str::trim)
            .and_then(|a| a.split_once(' '))
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        Some(Self {
            class,
            method: method.trim().to_ascii_uppercase(),
            url: clean.to_string(),
            content_type: (!ct.is_empty()).then_some(ct),
            auth,
            params,
        })
    }
}

/// Classification of one form: its [`classify_form`] label and the role of
/// each visible field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KbForm {
    /// Label from [`classify_form`].
    #[serde(rename = "type")]
    pub form_type: String,
    /// Field name to role (`username or email`, `password`, `search query`, ...).
    pub fields: BTreeMap<String, String>,
}

impl KbForm {
    /// Classify `form` and name the role of its fields (see [`field_roles`]).
    #[must_use]
    pub fn new(form: &StaticForm) -> Self {
        let form_type = classify_form(form);
        Self {
            form_type: form_type.to_owned(),
            fields: field_roles(form, form_type),
        }
    }
}

/// A detected secret with the outcome of its online validation. Carries no
/// part of the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KbSecret {
    /// The finding (kind, location, keyed hash, length).
    #[serde(flatten)]
    pub finding: SecretFinding,
    /// Verdict when `extract.validateSecrets` ran for this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validity>,
}

impl KbSecret {
    /// A finding with its verdict, if one was obtained.
    #[must_use]
    pub const fn new(finding: SecretFinding, validation: Option<Validity>) -> Self {
        Self { finding, validation }
    }
}

/// The `knowledgebase` record of one response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KnowledgeBase {
    /// Page classification (`PageType` in katana's output).
    #[serde(rename = "PageType", default, skip_serializing_if = "Option::is_none")]
    pub page_type: Option<PageType>,
    /// Form classifications, in document order (`Forms`).
    #[serde(rename = "Forms", default, skip_serializing_if = "Vec::is_empty")]
    pub forms: Vec<KbForm>,
    /// Detected secrets (`-kb-secrets`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<KbSecret>,
    /// Classified non-static requests (`-kb-endpoints`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<KbEndpoint>,
}

impl KnowledgeBase {
    /// Assemble the record; every form is classified with [`KbForm::new`].
    #[must_use]
    pub fn new(
        page_type: Option<PageType>,
        forms: &[StaticForm],
        secrets: Vec<KbSecret>,
        endpoints: Vec<KbEndpoint>,
    ) -> Self {
        Self {
            page_type,
            forms: forms.iter().map(KbForm::new).collect(),
            secrets,
            endpoints,
        }
    }

    /// Nothing to report.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.page_type.is_none()
            && self.forms.is_empty()
            && self.secrets.is_empty()
            && self.endpoints.is_empty()
    }
}

/// Controls a user fills in (named, enabled, not a button or hidden field).
fn visible(input: &&StaticInput) -> bool {
    !input.disabled
        && !matches!(
            input.kind.as_str(),
            "hidden" | "submit" | "button" | "reset" | "image"
        )
}

struct Facts {
    passwords: usize,
    email: bool,
    username: bool,
    person_name: bool,
    card: bool,
    quantity: bool,
    file: bool,
    textarea: bool,
    search_field: bool,
    search_typed: bool,
    visible: usize,
    get: bool,
    /// Lower-case action path and submit labels.
    cues: String,
}

impl Facts {
    fn of(form: &StaticForm) -> Self {
        let mut f = Self {
            passwords: 0,
            email: false,
            username: false,
            person_name: false,
            card: false,
            quantity: false,
            file: false,
            textarea: false,
            search_field: false,
            search_typed: false,
            visible: 0,
            get: matches!(form.method.as_str(), "GET" | "HEAD"),
            cues: format!("{} {}", form.action.path(), form.submit_labels.join(" ")).to_ascii_lowercase(),
        };
        for input in form.inputs.iter().filter(visible) {
            f.visible += 1;
            match input.kind.as_str() {
                "file" => f.file = true,
                "textarea" => f.textarea = true,
                "search" => f.search_typed = true,
                _ => {}
            }
            if is_search_name(input) {
                f.search_field = true;
            }
            match semantic::classify(input) {
                Some(Semantic::Password) => f.passwords += 1,
                Some(Semantic::Email) => f.email = true,
                Some(Semantic::Username) => f.username = true,
                Some(Semantic::Name | Semantic::FirstName | Semantic::LastName) => f.person_name = true,
                Some(Semantic::CardNumber | Semantic::CardExpiry | Semantic::Cvv) => f.card = true,
                Some(Semantic::Amount) => f.quantity = true,
                _ => {}
            }
        }
        f
    }

    fn cue(&self, words: &[&str]) -> bool {
        words.iter().any(|w| self.cues.contains(w))
    }
}

fn is_search_name(input: &StaticInput) -> bool {
    let words = semantic::field_words(&format!("{} {}", input.name, input.id.as_deref().unwrap_or("")));
    input.kind == "search"
        || [
            "q",
            "query",
            "search",
            "s",
            "keyword",
            "keywords",
            "term",
            "searchterm",
            "searchquery",
        ]
        .iter()
        .any(|w| words.contains(*w))
}

const RECOVERY_CUES: &[&str] = &[
    "forgot",
    "reset",
    "recover",
    "lostpassword",
    "lost-password",
    "retrieve",
    "change-password",
    "change password",
    "changepassword",
    "update-password",
    "update password",
];
const REGISTER_CUES: &[&str] = &[
    "register",
    "signup",
    "sign-up",
    "sign up",
    "create account",
    "create-account",
    "join",
    "enroll",
];
const LOGIN_CUES: &[&str] = &[
    "login",
    "log in",
    "log-in",
    "signin",
    "sign in",
    "sign-in",
    "logon",
    "authenticate",
];
const SEARCH_CUES: &[&str] = &["search", "find"];
const ORDER_CUES: &[&str] = &["cart", "buy", "order", "checkout", "purchase"];
const CONTACT_CUES: &[&str] = &[
    "contact", "comment", "feedback", "message", "enquiry", "inquiry", "support",
];
const NEWSLETTER_CUES: &[&str] = &["subscribe", "newsletter", "mailing"];

/// Label a form by structure (see the [module docs](self) for the rules).
#[must_use]
pub fn classify_form(form: &StaticForm) -> &'static str {
    let f = Facts::of(form);
    if f.card {
        return "payment";
    }
    if f.cue(RECOVERY_CUES) && f.passwords <= 2 {
        return "password_recovery";
    }
    let identities = usize::from(f.email) + usize::from(f.username) + usize::from(f.person_name);
    let register_cue = f.cue(REGISTER_CUES);
    let registration = f.passwords >= 2
        || (f.passwords == 1 && (register_cue || f.person_name || (f.email && f.username)))
        || (f.passwords == 0 && register_cue && identities >= 2);
    if registration {
        return "registration";
    }
    if f.passwords == 1 || (f.passwords == 0 && f.cue(LOGIN_CUES) && (f.email || f.username)) {
        return "login";
    }
    if f.search_typed || (f.get && f.search_field) || (f.cue(SEARCH_CUES) && f.visible <= 2) {
        return "search";
    }
    if (f.quantity && f.cue(ORDER_CUES)) || f.cue(&["add to cart", "buy now", "place order", "purchase"]) {
        return "order";
    }
    if f.textarea || f.cue(CONTACT_CUES) {
        return "contact";
    }
    if f.file {
        return "upload";
    }
    if f.email && (f.cue(NEWSLETTER_CUES) || (f.visible == 1 && !f.get)) {
        return "newsletter";
    }
    "other"
}

/// Role of each visible field of `form` (a form of the given
/// [`classify_form`] label): `username or email` for the identity field of a
/// login form, `password` (`password confirmation` for later ones),
/// `search query`, `message`, `file`, `captcha`, a person, address or card
/// role from the field's meaning, `remember me` / `terms acceptance` /
/// `newsletter opt-in` for such checkboxes, else `choice` for selects and
/// radios and `other`.
#[must_use]
pub fn field_roles(form: &StaticForm, form_type: &str) -> BTreeMap<String, String> {
    let mut roles = BTreeMap::new();
    let mut passwords = 0usize;
    for input in form.inputs.iter().filter(visible) {
        let words = semantic::field_words(&format!("{} {}", input.name, input.id.as_deref().unwrap_or("")));
        let has = |ws: &[&str]| ws.iter().any(|w| words.contains(*w));
        let role: &str = if has(&["captcha", "recaptcha", "hcaptcha"]) {
            "captcha"
        } else if input.kind == "file" {
            "file"
        } else if input.kind == "textarea" {
            "message"
        } else if is_search_name(input) {
            "search query"
        } else if input.kind == "checkbox" {
            if has(&["remember", "persist", "stay", "keep"]) {
                "remember me"
            } else if has(&["terms", "tos", "agree", "accept", "consent", "privacy"]) {
                "terms acceptance"
            } else if has(&["newsletter", "subscribe", "optin", "marketing"]) {
                "newsletter opt-in"
            } else {
                "checkbox"
            }
        } else {
            match semantic::classify(input) {
                Some(Semantic::Password) => {
                    passwords += 1;
                    if passwords > 1 || has(&["confirm", "repeat", "retype", "verify", "again"]) {
                        "password confirmation"
                    } else {
                        "password"
                    }
                }
                Some(Semantic::Email | Semantic::Username) if form_type == "login" => "username or email",
                Some(s) => s.role(),
                None if matches!(input.kind.as_str(), "select" | "radio") => "choice",
                None => "other",
            }
        };
        roles.entry(input.name.clone()).or_insert_with(|| role.to_owned());
    }
    roles
}
