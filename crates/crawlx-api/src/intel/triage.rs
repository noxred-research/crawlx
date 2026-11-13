//! Passive, evidence-backed endpoint and vulnerability-surface triage.
//!
//! Deterministic rules read what a crawl already retained (pages, their static forms, observed
//! traffic) and group it into *surfaces*: one per host, method and route template, with values
//! dropped and parameter names kept. Each surface lists the observable facts that were found,
//! each with the evidence it came from, and the labels those facts support. A label that rests
//! on a route name alone (`/admin`) is a hypothesis, never a finding. Nothing here fetches,
//! enqueues or exploits anything; an optional model may add a short cited explanation, which
//! [`validate_explanations`] checks against the surface's own evidence.

use crawlx_core::hash::Digest;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

/// Prompt label of the explanation call.
pub const PROMPT_VERSION: &str = "surface-triage.prompt.v1";
/// Schema label of the explanation reply.
pub const SCHEMA_VERSION: &str = "surface-explanations.v1";
/// Most surfaces one triage keeps.
pub const MAX_SURFACES: usize = 500;
/// Most evidence references kept per surface.
pub const MAX_REFS: usize = 12;

/// Closed set of manual verification categories a model may suggest.
pub const MANUAL_CHECKS: [&str; 8] = [
    "review_authentication_flow",
    "compare_roles",
    "review_upload_handling",
    "review_access_control",
    "review_input_handling",
    "review_export_scope",
    "review_state_change_protection",
    "none",
];

/// One retained page as triage input.
#[derive(Clone, Debug)]
pub struct PageFact {
    /// Evidence reference (`artifact:<id>` or `page:<frontier id>`).
    pub reference: String,
    /// Canonical URL.
    pub url: Url,
    /// HTTP status.
    pub status: u16,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// Role the page was fetched as.
    pub role: String,
    /// Digest of the page content.
    pub content_digest: String,
    /// Static forms found in the retained HTML, when it was retained.
    pub forms: Vec<crawlx_extract::StaticForm>,
}

/// One observed request as triage input.
#[derive(Clone, Debug)]
pub struct TrafficFact {
    /// Evidence reference (`traffic:<id>`).
    pub reference: String,
    /// HTTP method.
    pub method: String,
    /// Request URL (redacted by the store).
    pub url: Url,
    /// Response status.
    pub status: Option<u16>,
    /// Role of the issuing session.
    pub role: String,
    /// Response headers as a JSON object.
    pub response_headers: Value,
    /// Request headers as a JSON object.
    pub request_headers: Value,
}

#[derive(Default)]
struct Surface {
    host: String,
    method: String,
    route: String,
    params: BTreeSet<String>,
    roles: BTreeSet<String>,
    content_types: BTreeSet<String>,
    statuses_by_role: BTreeMap<String, BTreeSet<u16>>,
    digests_by_role: BTreeMap<String, BTreeSet<String>>,
    refs: Vec<String>,
    facts: Vec<(&'static str, String, Vec<String>)>,
    names: BTreeSet<&'static str>,
}

fn looks_like_id(segment: &str) -> bool {
    let digits = segment.chars().all(|c| c.is_ascii_digit());
    let hex = segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    (digits && !segment.is_empty()) || hex
}

/// The route template of `url`: id-like segments become `{id}`; returns it with the query
/// parameter names (values are never kept).
#[must_use]
pub fn route_of(url: &Url) -> (String, BTreeSet<String>) {
    let segments: Vec<String> = url
        .path_segments()
        .map(|s| {
            s.filter(|p| !p.is_empty())
                .map(|p| {
                    if looks_like_id(p) {
                        "{id}".to_owned()
                    } else {
                        p.to_ascii_lowercase()
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let route = format!("/{}", segments.join("/"));
    let params = url.query_pairs().map(|(k, _)| k.to_ascii_lowercase()).collect();
    (route, params)
}

fn has_word(route: &str, words: &[&str]) -> bool {
    route
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| words.contains(&part))
}

const AUTH_WORDS: [&str; 14] = [
    "login", "signin", "logout", "signout", "oauth", "sso", "auth", "token", "password", "reset", "register",
    "signup", "saml", "mfa",
];
const ADMIN_WORDS: [&str; 9] = [
    "admin",
    "administrator",
    "manage",
    "console",
    "backoffice",
    "internal",
    "staff",
    "superuser",
    "cms",
];
const EXPORT_WORDS: [&str; 7] = ["export", "download", "report", "csv", "backup", "dump", "extract"];
const UPLOAD_WORDS: [&str; 4] = ["upload", "attachment", "import", "avatar"];
const SEARCH_PARAMS: [&str; 7] = ["q", "query", "search", "s", "keyword", "term", "filter"];
const ID_PARAMS: [&str; 9] = [
    "id", "uid", "user", "user_id", "account", "order", "order_id", "doc", "file",
];

fn host_of(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn header<'a>(headers: &'a Value, name: &str) -> Option<&'a str> {
    headers.as_object()?.iter().find_map(|(k, v)| {
        k.eq_ignore_ascii_case(name)
            .then(|| v.as_str().or_else(|| v.get(0).and_then(Value::as_str)))
            .flatten()
    })
}

fn entry<'a>(
    map: &'a mut BTreeMap<String, Surface>,
    host: &str,
    method: &str,
    route: &str,
) -> &'a mut Surface {
    let key = format!("{host}\u{1}{method}\u{1}{route}");
    let surface = map.entry(key).or_default();
    if surface.route.is_empty() {
        surface.host = host.to_owned();
        surface.method = method.to_owned();
        surface.route = route.to_owned();
    }
    surface
}

fn push_ref(surface: &mut Surface, reference: &str) {
    if surface.refs.len() < MAX_REFS && !surface.refs.iter().any(|r| r == reference) {
        surface.refs.push(reference.to_owned());
    }
}

fn add_fact(surface: &mut Surface, label: &'static str, fact: String, refs: &[&str]) {
    surface.names.insert(label);
    if !surface.facts.iter().any(|(l, f, _)| *l == label && *f == fact) {
        surface
            .facts
            .push((label, fact, refs.iter().map(|r| (*r).to_owned()).collect()));
    }
}

fn observe_status(surface: &mut Surface, role: &str, status: Option<u16>) {
    surface.roles.insert(role.to_owned());
    if let Some(status) = status {
        surface
            .statuses_by_role
            .entry(role.to_owned())
            .or_default()
            .insert(status);
    }
}

fn class(status: u16) -> u16 {
    status / 100
}

/// The triage of one run.
#[derive(Debug)]
pub struct Triage {
    /// Surface objects in route order.
    pub surfaces: Vec<Value>,
    /// Whether the surface cap cut the list.
    pub truncated: bool,
    /// Counts by label.
    pub label_counts: BTreeMap<String, u64>,
}

/// Group `pages` and `traffic` into surfaces and apply the rules.
#[must_use]
pub fn triage(pages: &[PageFact], traffic: &[TrafficFact], max_surfaces: usize) -> Triage {
    let mut map: BTreeMap<String, Surface> = BTreeMap::new();
    for page in pages {
        let (route, params) = route_of(&page.url);
        let host = host_of(&page.url);
        {
            let s = entry(&mut map, &host, "GET", &route);
            s.params.extend(params.iter().cloned());
            if let Some(ct) = &page.content_type {
                s.content_types
                    .insert(ct.split(';').next().unwrap_or(ct).trim().to_ascii_lowercase());
            }
            s.digests_by_role
                .entry(page.role.clone())
                .or_default()
                .insert(page.content_digest.clone());
            observe_status(s, &page.role, Some(page.status));
            push_ref(s, &page.reference);
        }
        for form in &page.forms {
            let (action_route, action_params) = route_of(&form.action);
            let action_host = host_of(&form.action);
            let method = form.method.to_ascii_uppercase();
            let s = entry(&mut map, &action_host, &method, &action_route);
            s.params.extend(action_params);
            s.params
                .extend(form.inputs.iter().map(|i| i.name.to_ascii_lowercase()));
            s.roles.insert(page.role.clone());
            push_ref(s, &page.reference);
            let refs = [page.reference.as_str()];
            add_fact(
                s,
                "form",
                format!(
                    "a {method} form posts to this route (seen on {})",
                    page.url.path()
                ),
                &refs,
            );
            if method != "GET" {
                add_fact(
                    s,
                    "state_change",
                    format!("a {method} form targets this route"),
                    &refs,
                );
            }
            if form.inputs.iter().any(|i| i.kind == "password") {
                add_fact(s, "auth", "the form has a password field".to_owned(), &refs);
            }
            if form.inputs.iter().any(|i| i.kind == "file")
                || form.enctype.as_deref().is_some_and(|e| e.contains("multipart"))
            {
                add_fact(
                    s,
                    "upload",
                    "the form has a file field or multipart encoding".to_owned(),
                    &refs,
                );
            }
            if form
                .inputs
                .iter()
                .any(|i| i.kind == "search" || SEARCH_PARAMS.contains(&i.name.to_ascii_lowercase().as_str()))
            {
                add_fact(
                    s,
                    "search_input",
                    "the form has a search or query field".to_owned(),
                    &refs,
                );
            }
        }
    }
    for event in traffic {
        let (route, params) = route_of(&event.url);
        let host = host_of(&event.url);
        let method = event.method.to_ascii_uppercase();
        let s = entry(&mut map, &host, &method, &route);
        s.params.extend(params);
        observe_status(s, &event.role, event.status);
        push_ref(s, &event.reference);
        let refs = [event.reference.as_str()];
        if let Some(ct) = header(&event.response_headers, "content-type") {
            s.content_types
                .insert(ct.split(';').next().unwrap_or(ct).trim().to_ascii_lowercase());
        }
        if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            add_fact(
                s,
                "state_change",
                format!("a {method} request was observed"),
                &refs,
            );
        }
        if header(&event.request_headers, "content-type")
            .is_some_and(|c| c.to_ascii_lowercase().contains("multipart/"))
        {
            add_fact(s, "upload", "a multipart request was observed".to_owned(), &refs);
        }
        if event.status == Some(401) && header(&event.response_headers, "www-authenticate").is_some() {
            add_fact(
                s,
                "auth",
                "a 401 response carried a WWW-Authenticate challenge".to_owned(),
                &refs,
            );
        }
        if header(&event.response_headers, "content-disposition")
            .is_some_and(|d| d.to_ascii_lowercase().contains("attachment"))
        {
            add_fact(
                s,
                "export",
                "a response was served as an attachment".to_owned(),
                &refs,
            );
        }
    }
    let mut surfaces = Vec::new();
    let mut label_counts: BTreeMap<String, u64> = BTreeMap::new();
    let total = map.len();
    for (_, mut s) in map {
        if surfaces.len() >= max_surfaces.min(MAX_SURFACES) {
            break;
        }
        finish(&mut s);
        let value = surface_json(&s);
        for label in value["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            *label_counts.entry(label.to_owned()).or_default() += 1;
        }
        surfaces.push(value);
    }
    Triage {
        truncated: total > surfaces.len(),
        surfaces,
        label_counts,
    }
}

/// Facts that depend on the whole surface: statuses across roles, content types, parameters.
fn finish(s: &mut Surface) {
    let refs: Vec<String> = s.refs.clone();
    let ref_slice: Vec<&str> = refs.iter().map(String::as_str).collect();
    if s.roles.len() >= 2 {
        let classes: BTreeSet<u16> = s
            .statuses_by_role
            .values()
            .flatten()
            .map(|st| class(*st))
            .collect();
        let digests: BTreeSet<&String> = s.digests_by_role.values().flatten().collect();
        let differing = classes.len() > 1 || (s.digests_by_role.len() >= 2 && digests.len() > 1);
        if differing {
            let per_role: Vec<String> = s
                .statuses_by_role
                .iter()
                .map(|(role, st)| {
                    format!(
                        "{role}: {}",
                        st.iter().map(u16::to_string).collect::<Vec<_>>().join("/")
                    )
                })
                .collect();
            let fact = if classes.len() > 1 {
                format!("responses differ by role ({})", per_role.join(", "))
            } else {
                "the response content differs by role".to_owned()
            };
            add_fact(s, "role_boundary", fact, &ref_slice);
        }
    }
    let statuses: BTreeSet<u16> = s.statuses_by_role.values().flatten().copied().collect();
    if s.content_types
        .iter()
        .any(|c| matches!(c.as_str(), "text/csv" | "application/zip" | "application/pdf"))
    {
        add_fact(
            s,
            "export",
            "the response content type is a downloadable file type".to_owned(),
            &ref_slice,
        );
    }
    if s.params.iter().any(|p| SEARCH_PARAMS.contains(&p.as_str())) {
        add_fact(
            s,
            "search_input",
            "a search-like query parameter was observed".to_owned(),
            &ref_slice,
        );
    }
    if s.params.iter().any(|p| ID_PARAMS.contains(&p.as_str())) || s.route.contains("{id}") {
        add_fact(
            s,
            "object_reference",
            "the route or its parameters carry an object identifier".to_owned(),
            &ref_slice,
        );
    }
    if !statuses.is_empty()
        && statuses.iter().all(|st| matches!(st, 401 | 403))
        && has_word(&s.route, &ADMIN_WORDS)
    {
        add_fact(
            s,
            "admin",
            "every observed response was 401 or 403: access was refused".to_owned(),
            &ref_slice,
        );
    }
    // name-only hints are recorded separately as hypotheses
}

fn surface_json(s: &Surface) -> Value {
    let id_source = format!("{}\u{1}{}\u{1}{}", s.host, s.method, s.route);
    let id = Digest::of("crawlx.surface.v1", id_source.as_bytes()).to_hex();
    let surface_id = id.get(..16).unwrap_or(&id).to_owned();
    let mut labels: BTreeSet<&'static str> = s.names.clone();
    labels.remove("form");
    let mut hypotheses = Vec::new();
    let mut name_only: BTreeSet<&'static str> = BTreeSet::new();
    for (words, label) in [
        (AUTH_WORDS.as_slice(), "auth"),
        (ADMIN_WORDS.as_slice(), "admin"),
        (EXPORT_WORDS.as_slice(), "export"),
        (UPLOAD_WORDS.as_slice(), "upload"),
    ] {
        if has_word(&s.route, words) && !labels.contains(label) {
            name_only.insert(label);
        }
    }
    for label in &name_only {
        hypotheses.push(json!({
            "label": label,
            "basis": "name_only",
            "status": "hypothesis",
            "statement": format!("the route name suggests a {label} surface; nothing observed confirms it"),
        }));
    }
    if has_word(&s.route, &ADMIN_WORDS) && labels.contains("admin") {
        hypotheses.push(json!({
            "label": "admin",
            "basis": "structural",
            "status": "hypothesis",
            "statement": "access to an administrative-looking route was refused; that is not evidence of exposure",
        }));
    }
    let facts: Vec<Value> = s
        .facts
        .iter()
        .map(|(label, fact, refs)| json!({"label": label, "fact": fact, "evidence": refs}))
        .collect();
    let fact_kinds: BTreeSet<&str> = s.facts.iter().map(|(l, _, _)| *l).collect();
    let confidence = if fact_kinds.len() >= 2 {
        "high"
    } else if !fact_kinds.is_empty() {
        "medium"
    } else if !name_only.is_empty() {
        "low"
    } else {
        "none"
    };
    let abstained = labels.is_empty() && name_only.is_empty();
    let mut shown: Vec<&str> = labels.iter().copied().collect();
    if abstained {
        shown.push("unknown");
    }
    json!({
        "surfaceId": surface_id,
        "host": s.host,
        "route": s.route,
        "method": s.method,
        "roles": s.roles,
        "contentTypes": s.content_types,
        "parameterNames": s.params,
        "statuses": s.statuses_by_role,
        "labels": shown,
        "observedFacts": facts,
        "hypotheses": hypotheses,
        "evidenceRefs": s.refs,
        "confidence": confidence,
        "abstained": abstained,
        "reviewStatus": "unreviewed",
        "explanation": Value::Null,
    })
}

/// The `(record id, text)` pairs a model sees: one per surface, built only from rule output.
#[must_use]
pub fn explanation_records(surfaces: &[Value], batch: usize) -> Vec<(String, String)> {
    surfaces
        .iter()
        .filter(|s| s["abstained"] != Value::Bool(true))
        .take(batch)
        .map(|s| {
            let facts: Vec<String> = s["observedFacts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| f["fact"].as_str().map(str::to_owned))
                .collect();
            let text = format!(
                "route: {} {}\nlabels: {}\nobserved facts: {}\nparameter names: {}\nevidence ids: {}",
                s["method"].as_str().unwrap_or_default(),
                s["route"].as_str().unwrap_or_default(),
                s["labels"],
                facts.join("; "),
                s["parameterNames"],
                s["evidenceRefs"],
            );
            (s["surfaceId"].as_str().unwrap_or_default().to_owned(), text)
        })
        .collect()
}

/// The JSON Schema of the explanation reply.
#[must_use]
pub fn explanation_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["explanations"],
        "properties": {"explanations": {
            "type": "array",
            "maxItems": 100,
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["surfaceId", "text", "manualCheck", "cites"],
                "properties": {
                    "surfaceId": {"type": "string", "maxLength": 64},
                    "text": {"type": "string", "maxLength": 600},
                    "manualCheck": {"type": "string", "enum": MANUAL_CHECKS},
                    "cites": {"type": "array", "minItems": 1, "maxItems": 12, "items": {"type": "string", "maxLength": 128}},
                },
            },
        }},
    })
}

const PAYLOAD_MARKERS: [&str; 9] = [
    "<script",
    "union select",
    "' or ",
    "\" or ",
    "../",
    "; rm ",
    "$(",
    "javascript:",
    "curl ",
];

/// Attach the explanations that cite only the surface's own evidence and carry no payload-like
/// text; returns what was rejected and why.
pub fn validate_explanations(surfaces: &mut [Value], reply: &Value) -> Vec<Value> {
    let mut rejected = Vec::new();
    let empty = Vec::new();
    for item in reply
        .get("explanations")
        .and_then(Value::as_array)
        .unwrap_or(&empty)
    {
        let id = item.get("surfaceId").and_then(Value::as_str).unwrap_or_default();
        let Some(surface) = surfaces.iter_mut().find(|s| s["surfaceId"] == id) else {
            rejected.push(json!({"surfaceId": id, "reason": "unknown_surface"}));
            continue;
        };
        let evidence: BTreeSet<String> = surface["evidenceRefs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let cites: Vec<String> = item
            .get("cites")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        if cites.is_empty() || !cites.iter().all(|c| evidence.contains(c)) {
            rejected.push(json!({"surfaceId": id, "reason": "citation_not_in_surface_evidence"}));
            continue;
        }
        let check = item
            .get("manualCheck")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !MANUAL_CHECKS.contains(&check) {
            rejected.push(json!({"surfaceId": id, "reason": "manual_check_not_allowed"}));
            continue;
        }
        let text = crawlx_model::provenance::sanitize_untrusted(
            item.get("text").and_then(Value::as_str).unwrap_or_default(),
            600,
        );
        let lower = text.to_lowercase();
        if text.is_empty() || PAYLOAD_MARKERS.iter().any(|m| lower.contains(m)) {
            rejected.push(json!({"surfaceId": id, "reason": "text_not_acceptable"}));
            continue;
        }
        if let Some(obj) = surface.as_object_mut() {
            obj.insert(
                "explanation".to_owned(),
                json!({"text": text, "manualCheck": check, "cites": cites, "status": "generated_unverified"}),
            );
        }
    }
    rejected
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn page(reference: &str, url: &str, status: u16, role: &str, digest: &str) -> PageFact {
        PageFact {
            reference: reference.to_owned(),
            url: Url::parse(url).unwrap(),
            status,
            content_type: Some("text/html".to_owned()),
            role: role.to_owned(),
            content_digest: digest.to_owned(),
            forms: Vec::new(),
        }
    }

    fn traffic(
        reference: &str,
        method: &str,
        url: &str,
        status: u16,
        role: &str,
        resp: Value,
    ) -> TrafficFact {
        TrafficFact {
            reference: reference.to_owned(),
            method: method.to_owned(),
            url: Url::parse(url).unwrap(),
            status: Some(status),
            role: role.to_owned(),
            response_headers: resp,
            request_headers: json!({}),
        }
    }

    fn find<'a>(t: &'a Triage, method: &str, route: &str) -> &'a Value {
        t.surfaces
            .iter()
            .find(|s| s["method"] == method && s["route"] == route)
            .unwrap()
    }

    #[test]
    fn misleading_names_are_hypotheses_not_findings() {
        let t = triage(
            &[
                page("page:1", "https://app.test/admin-guide", 200, "anonymous", "d1"),
                page("page:2", "https://app.test/admin/users", 200, "anonymous", "d2"),
            ],
            &[],
            100,
        );
        let guide = find(&t, "GET", "/admin-guide");
        assert!(guide["observedFacts"].as_array().unwrap().is_empty());
        assert_eq!(guide["labels"], json!([]), "a name alone supports no label");
        assert_eq!(guide["hypotheses"][0]["status"], "hypothesis");
        let users = find(&t, "GET", "/admin/users");
        assert_eq!(users["hypotheses"][0]["label"], "admin");
        assert_eq!(users["hypotheses"][0]["basis"], "name_only");
        assert_eq!(users["confidence"], "low");
        assert_eq!(users["observedFacts"], json!([]));
    }

    #[test]
    fn inaccessible_admin_routes_are_not_claimed_exposed() {
        let t = triage(
            &[],
            &[traffic(
                "traffic:1",
                "GET",
                "https://app.test/admin",
                403,
                "user",
                json!({}),
            )],
            100,
        );
        let s = find(&t, "GET", "/admin");
        assert_eq!(s["labels"], json!(["admin"]));
        assert_eq!(s["hypotheses"][0]["status"], "hypothesis");
        assert!(s["hypotheses"][0]["statement"]
            .as_str()
            .unwrap()
            .contains("not evidence of exposure"));
        assert!(s["observedFacts"][0]["fact"]
            .as_str()
            .unwrap()
            .contains("refused"));
    }

    #[test]
    fn role_specific_views_become_a_role_boundary_fact() {
        let t = triage(
            &[
                page("page:1", "https://app.test/reports/7", 200, "admin", "d1"),
                page("page:2", "https://app.test/reports/9", 403, "user", "d2"),
            ],
            &[],
            100,
        );
        let s = find(&t, "GET", "/reports/{id}");
        let labels: Vec<&str> = s["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(labels.contains(&"role_boundary") && labels.contains(&"object_reference"));
        assert_eq!(s["roles"], json!(["admin", "user"]));
        assert_eq!(s["confidence"], "high");
    }

    #[test]
    fn get_and_post_are_distinct_surfaces() {
        let t = triage(
            &[page("page:1", "https://app.test/profile", 200, "user", "d1")],
            &[traffic(
                "traffic:1",
                "POST",
                "https://app.test/profile",
                302,
                "user",
                json!({}),
            )],
            100,
        );
        let get = find(&t, "GET", "/profile");
        let post = find(&t, "POST", "/profile");
        assert!(get["labels"]
            .as_array()
            .unwrap()
            .iter()
            .all(|l| l != "state_change"));
        assert_eq!(post["labels"], json!(["state_change"]));
        assert_eq!(post["observedFacts"][0]["evidence"], json!(["traffic:1"]));
    }

    #[test]
    fn forms_headers_and_attachments_are_observed_facts() {
        let mut p = page("artifact:a1", "https://app.test/account", 200, "user", "d1");
        p.forms = crawlx_extract::forms::extract_str(
            r#"<form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="f"><input type="password" name="pw"></form>
               <form action="/find"><input type="search" name="q"></form>"#,
            &p.url,
        )
        .unwrap();
        let t = triage(
            &[p],
            &[
                traffic(
                    "traffic:1",
                    "GET",
                    "https://app.test/api/export",
                    200,
                    "user",
                    json!({"Content-Disposition": "attachment; filename=a.csv"}),
                ),
                traffic(
                    "traffic:2",
                    "GET",
                    "https://app.test/basic",
                    401,
                    "anonymous",
                    json!({"WWW-Authenticate": "Basic"}),
                ),
            ],
            100,
        );
        let upload = find(&t, "POST", "/upload");
        let labels: Vec<&str> = upload["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(labels, vec!["auth", "state_change", "upload"]);
        assert_eq!(upload["evidenceRefs"], json!(["artifact:a1"]));
        assert!(find(&t, "GET", "/find")["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "search_input"));
        assert!(find(&t, "GET", "/api/export")["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "export"));
        assert!(find(&t, "GET", "/basic")["labels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "auth"));
    }

    #[test]
    fn values_never_enter_surfaces_and_output_is_deterministic() {
        let a = triage(
            &[page(
                "page:1",
                "https://app.test/search?q=secret-term&id=42",
                200,
                "u",
                "d",
            )],
            &[],
            10,
        );
        let b = triage(
            &[page(
                "page:1",
                "https://app.test/search?q=secret-term&id=42",
                200,
                "u",
                "d",
            )],
            &[],
            10,
        );
        assert_eq!(a.surfaces, b.surfaces);
        let text = serde_json::to_string(&a.surfaces).unwrap();
        assert!(!text.contains("secret-term") && !text.contains("42"));
        assert!(text.contains("\"q\"") && text.contains("\"id\""));
    }

    #[test]
    fn explanations_must_cite_the_surfaces_own_evidence() {
        let mut t = triage(
            &[],
            &[traffic(
                "traffic:1",
                "POST",
                "https://app.test/profile",
                302,
                "user",
                json!({}),
            )],
            10,
        );
        let id = t.surfaces[0]["surfaceId"].as_str().unwrap().to_owned();
        let reply = json!({"explanations": [
            {"surfaceId": id, "text": "A state-changing request was observed.", "manualCheck": "review_state_change_protection", "cites": ["traffic:1"]},
            {"surfaceId": "nope", "text": "x", "manualCheck": "none", "cites": ["traffic:1"]},
            {"surfaceId": id, "text": "see ../../etc/passwd", "manualCheck": "none", "cites": ["traffic:1"]},
            {"surfaceId": id, "text": "fine", "manualCheck": "run_exploit", "cites": ["traffic:1"]},
            {"surfaceId": id, "text": "fine", "manualCheck": "none", "cites": ["traffic:99"]},
        ]});
        let rejected = validate_explanations(&mut t.surfaces, &reply);
        assert_eq!(rejected.len(), 4);
        assert_eq!(t.surfaces[0]["explanation"]["status"], "generated_unverified");
        assert_eq!(t.surfaces[0]["explanation"]["cites"], json!(["traffic:1"]));
    }
}
