//! Natural-language engagement specifications compiled to native crawl configurations.
//!
//! A model (or an operator) produces a bounded [`CrawlIntentV1`]; this module turns it into a
//! [`CreateCrawl`] with a deterministic compiler. The intent can only *narrow* what the
//! operator's base configuration already allows: budgets take the smaller value, exclusions
//! add, inclusions fill an empty list, widening requests are refused with a warning, and a
//! contradiction between a goal and a prohibition fails the compile instead of being repaired
//! by guessing. Anything the compiler cannot represent is reported in `unsupportedIntents`,
//! never silently dropped. The intent has no field for credentials, authorization, verified
//! scope, safety-profile ceilings, egress, robots policy, provider endpoints or the target.

use crawlx_core::config::{CreateCrawl, DestructiveActions, ExternalCommunication, SafetyProfile};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

/// Prompt label of the model compile call.
pub const PROMPT_VERSION: &str = "crawl-spec.prompt.v1";
/// Schema label of the intent.
pub const SCHEMA_VERSION: &str = "crawl-intent.v1";
/// Most path prefixes per list.
pub const MAX_PATHS: usize = 20;
/// Longest path prefix.
pub const MAX_PATH_LEN: usize = 128;
/// Most unsupported-intent notes kept.
pub const MAX_UNSUPPORTED: usize = 20;

/// What the engagement is trying to learn. Informational: goals never add permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Goal {
    /// Broad page coverage.
    Coverage,
    /// Find API and XHR endpoints.
    ApiDiscovery,
    /// Find forms and inputs (discovery only).
    Forms,
    /// Find authentication surfaces.
    AuthSurfaces,
    /// Submit forms. Not representable by the compiler; reported as unsupported.
    FormSubmission,
}

/// Prohibitions the operator states. The compiler enforces each one or fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Forbid {
    /// Never submit forms or change target state.
    FormSubmission,
    /// Never run destructive actions.
    DestructiveActions,
    /// Never communicate outside the target.
    ExternalCommunication,
    /// Never follow links to other hosts.
    ExternalLinks,
    /// Never follow links to subdomains.
    Subdomains,
}

/// HTTP methods an intent may name. Only `GET` and `HEAD` are representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

/// The bounded intent of an engagement. Unknown fields are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrawlIntentV1 {
    /// Document version; must be `1`.
    pub version: u32,
    /// Goals.
    #[serde(default)]
    pub goals: Vec<Goal>,
    /// Prohibitions.
    #[serde(default)]
    pub forbid: Vec<Forbid>,
    /// Methods the engagement may use.
    #[serde(default)]
    pub methods: Vec<Method>,
    /// Path prefixes to crawl (`/app`, `/api/v2`); never regular expressions.
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Path prefixes to skip.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Deepest link distance from the seed.
    #[serde(default)]
    pub max_depth: Option<u16>,
    /// Most URLs.
    #[serde(default)]
    pub max_pages: Option<u32>,
    /// Longest run in seconds.
    #[serde(default)]
    pub duration_seconds: Option<u32>,
    /// Minimum milliseconds between requests to one origin.
    #[serde(default)]
    pub min_delay_ms: Option<u32>,
    /// Things the requester wanted that the schema cannot express (free text, kept short).
    #[serde(default)]
    pub unsupported: Vec<String>,
}

/// Failures of intent parsing and compiling.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecError {
    /// The intent is malformed (unknown field, wrong type, bad path).
    #[error("invalid intent: {0}")]
    Invalid(String),
    /// A goal contradicts a prohibition.
    #[error("conflicting intent: {0}")]
    Conflict(&'static str),
}

/// The JSON Schema a model reply must satisfy.
#[must_use]
pub fn intent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["version"],
        "properties": {
            "version": {"type": "integer", "enum": [1]},
            "goals": {"type": "array", "maxItems": 8, "items": {"type": "string",
                "enum": ["coverage", "api_discovery", "forms", "auth_surfaces", "form_submission"]}},
            "forbid": {"type": "array", "maxItems": 8, "items": {"type": "string",
                "enum": ["form_submission", "destructive_actions", "external_communication", "external_links", "subdomains"]}},
            "methods": {"type": "array", "maxItems": 6, "items": {"type": "string",
                "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]}},
            "includePaths": {"type": "array", "maxItems": MAX_PATHS, "items": {"type": "string", "maxLength": MAX_PATH_LEN}},
            "excludePaths": {"type": "array", "maxItems": MAX_PATHS, "items": {"type": "string", "maxLength": MAX_PATH_LEN}},
            "maxDepth": {"type": "integer", "minimum": 0, "maximum": 100},
            "maxPages": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
            "durationSeconds": {"type": "integer", "minimum": 1, "maximum": 604_800},
            "minDelayMs": {"type": "integer", "minimum": 50, "maximum": 60_000},
            "unsupported": {"type": "array", "maxItems": MAX_UNSUPPORTED, "items": {"type": "string", "maxLength": 200}},
        },
    })
}

/// Parse an intent strictly.
///
/// # Errors
/// [`SpecError::Invalid`] for unknown fields, wrong types, another version or oversized lists.
pub fn parse_intent(value: &Value) -> Result<CrawlIntentV1, SpecError> {
    let intent: CrawlIntentV1 =
        serde_json::from_value(value.clone()).map_err(|e| SpecError::Invalid(short(&e.to_string())))?;
    if intent.version != 1 {
        return Err(SpecError::Invalid("version must be 1".to_owned()));
    }
    if intent.include_paths.len() > MAX_PATHS || intent.exclude_paths.len() > MAX_PATHS {
        return Err(SpecError::Invalid(format!("at most {MAX_PATHS} paths per list")));
    }
    for path in intent.include_paths.iter().chain(&intent.exclude_paths) {
        check_path(path)?;
    }
    Ok(intent)
}

fn short(text: &str) -> String {
    text.chars().take(200).collect()
}

fn check_path(path: &str) -> Result<(), SpecError> {
    let ok = path.starts_with('/')
        && path.len() <= MAX_PATH_LEN
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b'~' | b'%'));
    if ok {
        Ok(())
    } else {
        Err(SpecError::Invalid(format!(
            "path prefix {:?} must start with '/' and use only letters, digits and /_-.~%",
            short(path)
        )))
    }
}

/// The native path pattern for a prefix: the prefix itself or anything below it.
fn pattern(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    let escaped = trimmed.replace('.', "\\.");
    format!("^{escaped}(?:/|$)")
}

/// A non-fatal note of the compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// Stable code.
    pub code: &'static str,
    /// JSON pointer into the configuration.
    pub path: &'static str,
    /// Explanation.
    pub message: String,
}

impl Note {
    /// As JSON.
    #[must_use]
    pub fn to_value(&self) -> Value {
        json!({"code": self.code, "path": self.path, "message": self.message})
    }
}

/// The result of compiling.
#[derive(Debug)]
pub struct Compiled {
    /// The compiled configuration.
    pub config: CreateCrawl,
    /// Narrowings the compiler applied or refused to widen.
    pub warnings: Vec<Note>,
    /// Intents the compiler could not represent.
    pub unsupported: Vec<Value>,
}

fn narrow_u32(value: &mut u32, requested: Option<u32>, path: &'static str, warnings: &mut Vec<Note>) {
    let Some(requested) = requested else { return };
    if requested > *value {
        warnings.push(Note {
            code: "widening_refused",
            path,
            message: format!(
                "the intent asked for {requested}; the operator configuration allows {value}, which is kept"
            ),
        });
    } else {
        *value = requested;
    }
}

/// Compile `intent` against the operator's `base` configuration.
///
/// # Errors
/// [`SpecError::Conflict`] when a goal contradicts a prohibition.
pub fn compile(base: &CreateCrawl, intent: &CrawlIntentV1) -> Result<Compiled, SpecError> {
    let forbids = |f: Forbid| intent.forbid.contains(&f);
    if forbids(Forbid::FormSubmission) && intent.goals.contains(&Goal::FormSubmission) {
        return Err(SpecError::Conflict(
            "the intent both asks to submit forms and forbids form submission",
        ));
    }
    let mut cfg = base.clone();
    let mut warnings = Vec::new();
    let mut unsupported = Vec::new();

    narrow_u32(
        &mut cfg.limits.urls,
        intent.max_pages,
        "/limits/urls",
        &mut warnings,
    );
    narrow_u32(
        &mut cfg.limits.duration_seconds,
        intent.duration_seconds,
        "/limits/durationSeconds",
        &mut warnings,
    );
    if let Some(depth) = intent.max_depth {
        if depth > cfg.scope.max_discovery_depth {
            warnings.push(Note {
                code: "widening_refused",
                path: "/scope/maxDiscoveryDepth",
                message: format!(
                    "the intent asked for depth {depth}; the operator configuration allows {}, which is kept",
                    cfg.scope.max_discovery_depth
                ),
            });
        } else {
            cfg.scope.max_discovery_depth = depth;
        }
    }
    if let Some(delay) = intent.min_delay_ms {
        cfg.politeness.delay_ms = cfg.politeness.delay_ms.max(delay);
    }

    if !intent.include_paths.is_empty() {
        if cfg.scope.include_paths.is_empty() {
            cfg.scope.include_paths = intent.include_paths.iter().map(|p| pattern(p)).collect();
        } else {
            warnings.push(Note {
                code: "include_paths_ignored",
                path: "/scope/includePaths",
                message:
                    "the operator configuration already lists include paths; the intent cannot widen them"
                        .to_owned(),
            });
        }
    }
    for path in &intent.exclude_paths {
        let p = pattern(path);
        if !cfg.scope.exclude_paths.contains(&p) {
            cfg.scope.exclude_paths.push(p);
        }
    }

    if forbids(Forbid::ExternalLinks) {
        cfg.scope.allow_external_links = false;
    }
    if forbids(Forbid::Subdomains) {
        cfg.scope.allow_subdomains = false;
    }
    if forbids(Forbid::FormSubmission) && cfg.safety.profile != SafetyProfile::ReadOnly {
        cfg.safety.profile = SafetyProfile::ReadOnly;
    }
    if forbids(Forbid::DestructiveActions) {
        cfg.safety.destructive_actions = DestructiveActions::Deny;
    }
    if forbids(Forbid::ExternalCommunication) {
        cfg.safety.external_communication = ExternalCommunication::Deny;
    }

    for goal in &intent.goals {
        if *goal == Goal::FormSubmission {
            unsupported.push(json!({
                "intent": "form_submission",
                "reason": "submitting forms needs an operator-chosen safety profile and approvals; the compiler never enables it",
            }));
        }
    }
    for method in &intent.methods {
        if !matches!(method, Method::Get | Method::Head) {
            unsupported.push(json!({
                "intent": format!("method:{method:?}").to_uppercase(),
                "reason": "state-changing methods are not representable; the crawl stays read-only",
            }));
        }
    }
    for text in intent.unsupported.iter().take(MAX_UNSUPPORTED) {
        unsupported.push(json!({
            "intent": crawlx_model::provenance::sanitize_untrusted(text, 200),
            "reason": "not representable in a crawl configuration",
        }));
    }
    Ok(Compiled {
        config: cfg,
        warnings,
        unsupported,
    })
}

/// Leaf-level differences between two JSON documents, as `{path, before, after}` objects in
/// path order. Arrays are compared whole.
#[must_use]
pub fn diff(before: &Value, after: &Value) -> Vec<Value> {
    fn walk(path: &str, before: &Value, after: &Value, out: &mut Vec<Value>) {
        match (before, after) {
            (Value::Object(a), Value::Object(b)) => {
                let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
                for key in keys {
                    let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                    walk(
                        &child,
                        a.get(key).unwrap_or(&Value::Null),
                        b.get(key).unwrap_or(&Value::Null),
                        out,
                    );
                }
            }
            (a, b) if a == b => {}
            (a, b) => {
                let mut entry = Map::new();
                entry.insert("path".to_owned(), Value::String(path.to_owned()));
                entry.insert("before".to_owned(), a.clone());
                entry.insert("after".to_owned(), b.clone());
                out.push(Value::Object(entry));
            }
        }
    }
    let mut out = Vec::new();
    walk("", before, after, &mut out);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn base() -> CreateCrawl {
        serde_json::from_value(json!({"seedUrl": "https://app.example.test/", "limits": {"urls": 500}}))
            .unwrap()
    }

    fn intent(v: Value) -> CrawlIntentV1 {
        parse_intent(&v).unwrap()
    }

    #[test]
    fn narrows_and_never_widens() {
        let compiled = compile(
            &base(),
            &intent(json!({"version": 1, "maxPages": 100, "maxDepth": 3, "excludePaths": ["/logout"], "includePaths": ["/app"]})),
        )
        .unwrap();
        assert_eq!(compiled.config.limits.urls, 100);
        assert_eq!(compiled.config.scope.max_discovery_depth, 3);
        assert_eq!(
            compiled.config.scope.exclude_paths,
            vec!["^/logout(?:/|$)".to_owned()]
        );
        assert_eq!(
            compiled.config.scope.include_paths,
            vec!["^/app(?:/|$)".to_owned()]
        );
        let wider = compile(
            &base(),
            &intent(json!({"version": 1, "maxPages": 10_000, "maxDepth": 99})),
        )
        .unwrap();
        assert_eq!(
            wider.config.limits.urls, 500,
            "operator budget wins over a larger request"
        );
        assert_eq!(
            wider
                .warnings
                .iter()
                .filter(|n| n.code == "widening_refused")
                .count(),
            2
        );
    }

    #[test]
    fn existing_include_paths_win() {
        let mut b = base();
        b.scope.include_paths = vec!["^/only(?:/|$)".to_owned()];
        let c = compile(&b, &intent(json!({"version": 1, "includePaths": ["/other"]}))).unwrap();
        assert_eq!(c.config.scope.include_paths, vec!["^/only(?:/|$)".to_owned()]);
        assert!(c.warnings.iter().any(|n| n.code == "include_paths_ignored"));
    }

    #[test]
    fn prohibitions_are_enforced_or_the_compile_fails() {
        let mut b = base();
        b.scope.allow_external_links = true;
        b.safety.profile = SafetyProfile::TestEnvironment;
        b.safety.destructive_actions = DestructiveActions::Approval;
        let c = compile(
            &b,
            &intent(
                json!({"version": 1, "forbid": ["external_links", "form_submission", "destructive_actions"]}),
            ),
        )
        .unwrap();
        assert!(!c.config.scope.allow_external_links);
        assert_eq!(c.config.safety.profile, SafetyProfile::ReadOnly);
        assert_eq!(c.config.safety.destructive_actions, DestructiveActions::Deny);
        let conflict = compile(
            &b,
            &intent(json!({"version": 1, "goals": ["form_submission"], "forbid": ["form_submission"]})),
        );
        assert!(matches!(conflict, Err(SpecError::Conflict(_))));
    }

    #[test]
    fn unrepresentable_intents_are_reported_not_dropped() {
        let c = compile(
            &base(),
            &intent(json!({"version": 1, "goals": ["form_submission"], "methods": ["GET", "POST", "DELETE"], "unsupported": ["log in as admin"]})),
        )
        .unwrap();
        assert_eq!(c.unsupported.len(), 4);
        assert_eq!(c.config.safety.profile, SafetyProfile::ReadOnly);
    }

    #[test]
    fn malformed_intents_are_rejected() {
        assert!(parse_intent(&json!({"version": 2})).is_err());
        assert!(
            parse_intent(&json!({"version": 1, "safety": {"profile": "authorized_security_test"}})).is_err()
        );
        assert!(parse_intent(&json!({"version": 1, "authorizationRecordRef": "x"})).is_err());
        assert!(parse_intent(&json!({"version": 1, "includePaths": [".*"]})).is_err());
        assert!(parse_intent(&json!({"version": 1, "includePaths": ["/a(b+)+$"]})).is_err());
        assert!(parse_intent(&json!({"version": 1, "excludePaths": ["https://evil.test/"]})).is_err());
        assert!(parse_intent(&json!({"version": 1, "methods": ["TRACE"]})).is_err());
    }

    #[test]
    fn diff_lists_leaf_changes() {
        let a = json!({"a": {"b": 1, "c": [1]}, "d": 2});
        let b = json!({"a": {"b": 2, "c": [1, 2]}, "d": 2, "e": true});
        let d = diff(&a, &b);
        let paths: Vec<&str> = d.iter().map(|v| v["path"].as_str().unwrap()).collect();
        assert_eq!(paths, vec!["/a/b", "/a/c", "/e"]);
    }
}
