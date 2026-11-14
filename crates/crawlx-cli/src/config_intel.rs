//! The LLM provider settings of `crawlx config check`.
//!
//! The self-host provider variables (`CRAWLX_LLM_*`, `CRAWLX_EMBEDDING_MODEL`,
//! `EXTRACTION_PROVIDER_*`, `BRANDING_LLM_*`, ...) are read by `serve` and `worker` straight from
//! the environment, so `config check` reads them the same way (through
//! [`IntelConfig::from_lookup`]) and prints what those commands will use: endpoint, model, the
//! *reference* of every API key with whether it resolves, routing shares and limits. It never
//! prints a key: references (`env:NAME`) are names, endpoint URLs lose their user info and query,
//! and a compatibility variable crawlx cannot act on is listed by name with the reason, never with
//! its value.

use crate::config_check::Finding;
use crawlx_api::config::{
    resolve_secret_ref_with, BrandingSettings, EmbeddingSettings, ExtractionSettings, IntelConfig,
    LlmSettings, PolicySettings, UNSUPPORTED_ENV,
};
use crawlx_model::llm::chat_completions::DEFAULT_ENDPOINT;
use crawlx_model::llm::{ChatCompletionsClient, HttpEmbeddings};
use serde_json::{json, Map, Value};

/// The effective provider settings and what is wrong with them.
#[derive(Debug)]
pub(crate) struct IntelReport {
    /// JSON object, one entry per configured provider section plus `unsupported`; no secret.
    pub effective: Value,
    /// Errors (the commands would refuse to start) and warnings (settings without effect).
    pub findings: Vec<Finding>,
}

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn finding(key: &str, message: impl Into<String>, error: bool) -> Finding {
    Finding {
        key: key.to_owned(),
        message: message.into(),
        error,
    }
}

/// `endpoint` without user info, query or fragment; text that is not a URL is not echoed.
fn redact_endpoint(endpoint: &str) -> String {
    let Ok(mut url) = url::Url::parse(endpoint.trim()) else {
        return "<unparseable>".to_owned();
    };
    let had_user_info = !url.username().is_empty() || url.password().is_some();
    let had_query = url.query().is_some();
    // clearing cannot fail for a URL that has a host
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    let mut shown = url.to_string();
    if had_user_info {
        shown = shown.replacen("://", "://<redacted>@", 1);
    }
    if had_query {
        shown.push_str("?<redacted>");
    }
    shown
}

/// How an API key is configured: its reference and whether it resolves; never its value.
fn key_status(reference: Option<&str>, get: Env<'_>, key: &str, findings: &mut Vec<Finding>) -> Value {
    let Some(reference) = reference else {
        return json!({ "configured": false });
    };
    let resolved = resolve_secret_ref_with(reference, get);
    if let Err(e) = &resolved {
        findings.push(finding(key, e.to_string(), true));
    }
    json!({
        "configured": true,
        "ref": reference,
        "status": if resolved.is_ok() { "present" } else { "missing" },
    })
}

fn llm_section(s: &LlmSettings, get: Env<'_>, findings: &mut Vec<Finding>) -> Value {
    let key = key_status(s.api_key_ref.as_deref(), get, "intel.llm.apiKey", findings);
    // a key reference that does not resolve is already reported by `key_status`
    if let Ok(cfg) = s.resolve_with(get) {
        if let Err(e) = ChatCompletionsClient::new(cfg) {
            findings.push(finding("intel.llm", e.to_string(), true));
        }
    }
    json!({
        "endpoint": redact_endpoint(&s.endpoint),
        "model": s.model,
        "apiKey": key,
        "timeoutMs": s.timeout_ms,
    })
}

fn embeddings_section(
    s: &EmbeddingSettings,
    llm: Option<&LlmSettings>,
    get: Env<'_>,
    findings: &mut Vec<Finding>,
) -> Value {
    let endpoint = s
        .endpoint
        .as_deref()
        .or_else(|| llm.map(|l| l.endpoint.as_str()))
        .unwrap_or(DEFAULT_ENDPOINT);
    let key_ref = s
        .api_key_ref
        .as_deref()
        .or_else(|| llm.and_then(|l| l.api_key_ref.as_deref()));
    let key = key_status(key_ref, get, "intel.embeddings.apiKey", findings);
    if let Ok(cfg) = s.resolve_with(llm, get) {
        if let Err(e) = HttpEmbeddings::new(cfg) {
            findings.push(finding("intel.embeddings", e.to_string(), true));
        }
    }
    json!({
        "model": s.model,
        "endpoint": redact_endpoint(endpoint),
        "endpointFrom": if s.endpoint.is_some() { "embedding endpoint override" } else { "default llm" },
        "apiKey": key,
        "topN": s.top_n,
        "timeoutMs": s.timeout_ms,
    })
}

fn extraction_section(
    s: &ExtractionSettings,
    llm: Option<&LlmSettings>,
    get: Env<'_>,
    findings: &mut Vec<Finding>,
) -> Value {
    let key = key_status(s.api_key_ref.as_deref(), get, "intel.extraction.apiKey", findings);
    if llm.is_none() {
        findings.push(finding(
            "intel.extraction",
            "the extraction provider falls back to the default LLM, which is not configured \
             (set CRAWLX_LLM_BASE_URL / CRAWLX_LOCAL_LLM_BASE_URL / CRAWLX_LLM_API_KEY)",
            true,
        ));
    }
    if let Err(e) = s.policy() {
        findings.push(finding("intel.extraction", e.to_string(), true));
    }
    if let Ok(cfg) = s.resolve_with(get) {
        if let Err(e) = ChatCompletionsClient::new(cfg) {
            findings.push(finding("intel.extraction", e.to_string(), true));
        }
    }
    json!({
        "endpoint": redact_endpoint(&s.endpoint),
        "model": s.model,
        "apiKey": key,
        "timeoutMs": s.timeout_ms,
        "rolloutPercent": s.rollout_percent,
        "shadowPercent": s.shadow_percent,
        "teamIds": s.team_ids,
        "maxInputBytes": s.max_input_bytes,
        "steps": ["extract", "json"],
        "fallback": "default llm",
    })
}

fn branding_section(
    s: &BrandingSettings,
    llm: Option<&LlmSettings>,
    get: Env<'_>,
    findings: &mut Vec<Finding>,
) -> Value {
    let endpoint = s
        .endpoint
        .as_deref()
        .or_else(|| llm.map(|l| l.endpoint.as_str()))
        .unwrap_or(DEFAULT_ENDPOINT);
    let model = s
        .model
        .as_deref()
        .or_else(|| llm.map(|l| l.model.as_str()))
        .unwrap_or(crawlx_model::llm::chat_completions::DEFAULT_MODEL);
    let key_ref = s
        .api_key_ref
        .as_deref()
        .or_else(|| llm.and_then(|l| l.api_key_ref.as_deref()));
    let key = key_status(key_ref, get, "intel.branding.apiKey", findings);
    if let Ok(cfg) = s.resolve_with(llm, get) {
        if let Err(e) = ChatCompletionsClient::new(cfg) {
            findings.push(finding("intel.branding", e.to_string(), true));
        }
    }
    json!({
        "endpoint": redact_endpoint(endpoint),
        "model": model,
        "apiKey": key,
        "timeoutMs": s.timeout_ms.unwrap_or(crawlx_api::config::DEFAULT_BRANDING_TIMEOUT_MS),
    })
}

/// Whether `reference` names an `env:` variable or a `file:` path (the only credential references).
fn is_secret_reference(reference: &str) -> bool {
    reference.starts_with("env:") || reference.starts_with("file:")
}

/// Refuse a policy that carries a credential inline: a provider key must be a reference
/// (`env:NAME`, `file:/path`) and an endpoint must not hold user info, a query or a fragment.
/// The message names the provider, never the offending value.
///
/// # Errors
/// The first provider with an inline credential.
pub(crate) fn check_policy_inline(policy: &PolicySettings) -> Result<(), String> {
    for (id, provider) in &policy.providers {
        if provider
            .api_key_ref
            .as_deref()
            .is_some_and(|r| !is_secret_reference(r))
        {
            return Err(format!(
                "provider {id}: apiKeyRef must be env:NAME or file:/path; keys are never configured inline"
            ));
        }
        if let Some(endpoint) = &provider.endpoint {
            let inline = url::Url::parse(endpoint.trim()).is_ok_and(|u| {
                !u.username().is_empty()
                    || u.password().is_some()
                    || u.query().is_some()
                    || u.fragment().is_some()
            });
            if inline {
                return Err(format!(
                    "provider {id}: endpoint must not carry user info, a query or a fragment; credentials go in apiKeyRef"
                ));
            }
        }
    }
    Ok(())
}

/// `[intel.policy]` as the commands will apply it: endpoints without user info, key references with
/// whether they resolve, never a key. Findings: an inline credential, a provider that cannot be
/// built, and a master switch that disagrees with the approved providers.
fn policy_section(
    policy: &PolicySettings,
    intel: &IntelConfig,
    get: Env<'_>,
    findings: &mut Vec<Finding>,
) -> Value {
    let inline = check_policy_inline(policy);
    if let Err(e) = &inline {
        findings.push(finding("intel.policy", e.clone(), true));
    } else if let Err(e) = crawlx_api::intel::ai_policy_with(
        &IntelConfig {
            policy: Some(policy.clone()),
            ..intel.clone()
        },
        get,
    ) {
        findings.push(finding("intel.policy", e.to_string(), true));
    }
    if policy.external_processing && policy.providers.is_empty() {
        findings.push(finding(
            "intel.policy",
            "externalProcessing is true but no provider is approved: every model call is refused",
            false,
        ));
    }
    if !policy.external_processing && !policy.providers.is_empty() {
        findings.push(finding(
            "intel.policy",
            "providers are configured but externalProcessing is false: the native AI endpoints answer 403 external_processing_disabled",
            false,
        ));
    }
    let llm = intel.llm.as_ref();
    let providers: Map<String, Value> = policy
        .providers
        .iter()
        .map(|(id, p)| {
            let endpoint = p.endpoint.as_deref().or_else(|| llm.map(|l| l.endpoint.as_str()));
            // a credential is inherited only together with the endpoint it belongs to
            let key_ref = p.api_key_ref.as_deref().or_else(|| {
                if p.endpoint.is_some() {
                    None
                } else {
                    llm.and_then(|l| l.api_key_ref.as_deref())
                }
            });
            let key = match key_ref {
                Some(r) if !is_secret_reference(r) => {
                    json!({ "configured": true, "ref": "<invalid>", "status": "invalid" })
                }
                other => key_status(other, get, "intel.policy.apiKey", &mut Vec::new()),
            };
            (
                id.clone(),
                json!({
                    "endpoint": endpoint.map(redact_endpoint),
                    "endpointFrom": if p.endpoint.is_some() { "provider" } else { "default llm" },
                    "model": p.model.as_deref().or_else(|| llm.map(|l| l.model.as_str())),
                    "apiKey": key,
                    "timeoutMs": p.timeout_ms,
                    "revision": p.revision.as_deref().unwrap_or("1"),
                    "retentionCapability": p.retention_capability,
                    "allowedPurposes": p.allowed_purposes,
                }),
            )
        })
        .collect();
    json!({
        "externalProcessing": policy.external_processing,
        "providers": providers,
        "maxInputBytes": policy.max_input_bytes,
        "maxOutputTokens": policy.max_output_tokens,
        "maxResponseBytes": policy.max_response_bytes,
        "maxRunCalls": policy.max_run_calls,
        "maxRunTokens": policy.max_run_tokens,
        "deadlineMs": policy.deadline_ms,
        "proposalTtlSecs": policy.proposal_ttl_secs,
        "allowSelfApproval": policy.allow_self_approval,
    })
}

/// The provider settings `serve` and `worker` will read from the environment `get`, and the
/// `[intel.policy]` of the configuration file when there is one.
pub(crate) fn report(get: Env<'_>, policy: Option<&PolicySettings>) -> IntelReport {
    let mut findings = Vec::new();
    let mut effective = Map::new();
    let intel = match IntelConfig::default().from_lookup(|k| get(k)) {
        Ok(intel) => intel,
        Err(e) => {
            findings.push(finding("intel", e.to_string(), true));
            IntelConfig::default()
        }
    };
    let llm = intel.llm.as_ref();
    if let Some(s) = llm {
        effective.insert("llm".to_owned(), llm_section(s, get, &mut findings));
    }
    if let Some(s) = &intel.embeddings {
        effective.insert(
            "embeddings".to_owned(),
            embeddings_section(s, llm, get, &mut findings),
        );
    }
    if let Some(s) = &intel.extraction {
        effective.insert(
            "extraction".to_owned(),
            extraction_section(s, llm, get, &mut findings),
        );
    }
    if let Some(s) = &intel.branding {
        effective.insert(
            "branding".to_owned(),
            branding_section(s, llm, get, &mut findings),
        );
    }
    if let Some(policy) = policy {
        effective.insert(
            "policy".to_owned(),
            policy_section(policy, &intel, get, &mut findings),
        );
    }
    let unsupported: Vec<Value> = UNSUPPORTED_ENV
        .iter()
        .filter(|(name, _)| get(name).is_some_and(|v| !v.trim().is_empty()))
        .map(|(name, why)| {
            findings.push(finding(
                name,
                format!("set but has no effect in crawlx: {why}"),
                false,
            ));
            json!({ "variable": name, "reason": why })
        })
        .collect();
    effective.insert("unsupported".to_owned(), Value::Array(unsupported));
    IntelReport {
        effective: Value::Object(effective),
        findings,
    }
}

/// `value` without `null`s (TOML has none).
fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), without_nulls(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

/// The report as `[intel.*]` TOML tables, ready to follow the effective `crawlx.toml` values.
///
/// # Errors
/// The TOML serializer rejects the value (not expected for a report built by [`report`]).
pub(crate) fn to_toml(effective: &Value) -> anyhow::Result<String> {
    let mut intel = Map::new();
    intel.insert("intel".to_owned(), without_nulls(effective));
    Ok(toml::to_string_pretty(&Value::Object(intel))?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn run(vars: &BTreeMap<String, String>) -> IntelReport {
        report(&|k| vars.get(k).cloned(), None)
    }

    const SECRETS: [&str; 6] = [
        "sk-default-1111",
        "sk-extract-2222",
        "sk-brand-3333",
        "tsk-typesafe-4444",
        "hunter2",
        "tokenInQuery",
    ];

    fn secret_env() -> BTreeMap<String, String> {
        env(&[
            (
                "CRAWLX_LLM_BASE_URL",
                "https://svc:hunter2@llm.internal:8443/v1?token=tokenInQuery",
            ),
            ("CRAWLX_LLM_API_KEY", SECRETS[0]),
            ("CRAWLX_LLM_MODEL", "chat-model"),
            ("CRAWLX_EMBEDDING_MODEL", "embed-model"),
            ("EXTRACTION_PROVIDER_BASE_URL", "http://llm-server:8000/v1"),
            ("EXTRACTION_PROVIDER_API_KEY", SECRETS[1]),
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "25"),
            ("EXTRACTION_PROVIDER_TEAM_IDS", "team-a,team-b"),
            ("BRANDING_LLM_MODEL", "vision-model"),
            ("BRANDING_LLM_API_KEY", SECRETS[2]),
            ("TYPESAFE_API_KEY", SECRETS[3]),
            ("BRANDING_JEV", "true"),
        ])
    }

    #[test]
    fn no_variable_value_secret_reaches_the_report() {
        let r = run(&secret_env());
        let json = r.effective.to_string();
        let toml = to_toml(&r.effective).unwrap();
        let findings = format!("{:?}", r.findings);
        for secret in SECRETS {
            assert!(!json.contains(secret), "{secret} leaked into JSON: {json}");
            assert!(!toml.contains(secret), "{secret} leaked into TOML: {toml}");
            assert!(
                !findings.contains(secret),
                "{secret} leaked into findings: {findings}"
            );
        }
        // what is shown instead
        assert!(json.contains("env:CRAWLX_LLM_API_KEY") && json.contains("env:EXTRACTION_PROVIDER_API_KEY"));
        assert!(json.contains("env:BRANDING_LLM_API_KEY"));
        assert!(
            toml.contains("https://<redacted>@llm.internal:8443/v1?<redacted>"),
            "{toml}"
        );
        assert_eq!(r.effective["llm"]["apiKey"]["status"], "present");
        assert_eq!(r.effective["extraction"]["rolloutPercent"], 25);
        assert_eq!(r.effective["extraction"]["teamIds"], json!(["team-a", "team-b"]));
        assert_eq!(r.effective["embeddings"]["model"], "embed-model");
        assert_eq!(r.effective["embeddings"]["endpointFrom"], "default llm");
        assert_eq!(r.effective["branding"]["model"], "vision-model");
        assert_eq!(r.effective["branding"]["timeoutMs"], 5000);
        assert!(
            toml.contains("[intel.llm]") && toml.contains("[intel.extraction]"),
            "{toml}"
        );
    }

    #[test]
    fn unsupported_variables_are_named_with_the_reason_and_not_their_value() {
        let r = run(&secret_env());
        let names: Vec<&str> = r.effective["unsupported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["variable"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["TYPESAFE_API_KEY", "BRANDING_JEV"]);
        let w: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.key == "TYPESAFE_API_KEY")
            .collect();
        assert_eq!(w.len(), 1);
        assert!(!w[0].error && w[0].message.contains("hosted"), "{:?}", w[0]);
        assert!(r.findings.iter().all(|f| !f.error), "{:?}", r.findings);
    }

    #[test]
    fn an_unconfigured_environment_reports_nothing() {
        let r = run(&BTreeMap::new());
        assert_eq!(r.effective, json!({ "unsupported": [] }));
        assert!(r.findings.is_empty());
    }

    #[test]
    fn a_key_reference_that_does_not_resolve_is_an_error_without_a_value() {
        let resolving = report(
            &|k| match k {
                "CRAWLX_LLM_BASE_URL" => Some("http://x/v1".to_owned()),
                "EXTRACTION_PROVIDER_BASE_URL" => Some("http://y/v1".to_owned()),
                "EXTRACTION_PROVIDER_API_KEY" => Some("k".to_owned()),
                _ => None,
            },
            None,
        );
        assert!(
            resolving.findings.iter().all(|f| !f.error),
            "{:?}",
            resolving.findings
        );

        // a reference whose variable is gone, as when the secret was unset after the settings
        // were written down
        let s = ExtractionSettings {
            endpoint: "http://y/v1".to_owned(),
            model: "m".to_owned(),
            api_key_ref: Some("env:NOT_SET_ANYWHERE".to_owned()),
            timeout_ms: None,
            rollout_percent: 0,
            shadow_percent: 0,
            team_ids: Vec::new(),
            max_input_bytes: 10,
        };
        let mut findings = Vec::new();
        let llm = LlmSettings {
            endpoint: "http://x/v1".to_owned(),
            model: "m".to_owned(),
            api_key_ref: None,
            timeout_ms: None,
            transcribe_endpoint: None,
            transcribe_model: None,
        };
        let section = extraction_section(&s, Some(&llm), &|_| None, &mut findings);
        assert_eq!(section["apiKey"]["status"], "missing");
        assert!(
            findings.iter().any(|f| f.error
                && f.key == "intel.extraction.apiKey"
                && f.message.contains("NOT_SET_ANYWHERE")),
            "{findings:?}"
        );
    }

    #[test]
    fn extraction_without_a_default_llm_is_an_error() {
        let r = run(&env(&[("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1")]));
        assert!(
            r.findings.iter().any(|f| f.error && f.key == "intel.extraction"),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn bad_numbers_and_overlapping_shares_are_errors_that_do_not_echo_the_text() {
        let r = run(&env(&[
            ("CRAWLX_LLM_BASE_URL", "http://x/v1"),
            ("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1"),
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "sk-oops-not-a-number"),
        ]));
        let f = r.findings.iter().find(|f| f.error && f.key == "intel").unwrap();
        assert!(f.message.contains("EXTRACTION_PROVIDER_ROLLOUT_PERCENT"), "{f:?}");
        assert!(!f.message.contains("sk-oops"), "{f:?}");
        let r = run(&env(&[
            ("CRAWLX_LLM_BASE_URL", "http://x/v1"),
            ("EXTRACTION_PROVIDER_BASE_URL", "http://y/v1"),
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "80"),
            ("EXTRACTION_PROVIDER_SHADOW_PERCENT", "30"),
        ]));
        assert!(
            r.findings
                .iter()
                .any(|f| f.error && f.message.contains("must not exceed 100")),
            "{:?}",
            r.findings
        );
    }

    #[test]
    fn unparseable_endpoints_are_not_echoed() {
        assert_eq!(redact_endpoint("sk-secret-in-the-url-field"), "<unparseable>");
        assert_eq!(redact_endpoint("http://h:1/v1"), "http://h:1/v1");
    }

    fn policy_from(json: Value) -> PolicySettings {
        serde_json::from_value(json).unwrap()
    }

    fn report_policy(vars: &BTreeMap<String, String>, policy: &PolicySettings) -> IntelReport {
        report(&|k| vars.get(k).cloned(), Some(policy))
    }

    #[test]
    fn a_policy_is_reported_with_redacted_endpoints_and_resolvable_key_references() {
        let policy = policy_from(json!({
            "externalProcessing": true,
            "providers": { "analysis": {
                "endpoint": "https://models.internal.example/v1",
                "model": "reviewer-1",
                "apiKeyRef": "env:POLICY_PROVIDER_KEY",
                "allowedPurposes": ["crawl_spec"]
            }},
            "maxRunCalls": 4,
        }));
        let r = report_policy(&env(&[("POLICY_PROVIDER_KEY", "sk-policy-9999")]), &policy);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        let p = &r.effective["policy"];
        assert_eq!(p["externalProcessing"], true);
        assert_eq!(p["maxRunCalls"], 4);
        assert_eq!(p["providers"]["analysis"]["apiKey"]["status"], "present");
        assert_eq!(
            p["providers"]["analysis"]["apiKey"]["ref"],
            "env:POLICY_PROVIDER_KEY"
        );
        let text = format!("{}{}", r.effective, to_toml(&r.effective).unwrap());
        assert!(!text.contains("sk-policy-9999"), "{text}");
        // a key reference whose variable is missing fails the check, still without a value
        let r = report_policy(&BTreeMap::new(), &policy);
        let f = r
            .findings
            .iter()
            .find(|f| f.error && f.key == "intel.policy")
            .unwrap();
        assert!(f.message.contains("POLICY_PROVIDER_KEY"), "{f:?}");
    }

    #[test]
    fn a_policy_with_an_inline_credential_is_refused_without_echoing_it() {
        let policy = policy_from(json!({
            "externalProcessing": true,
            "providers": { "analysis": { "endpoint": "https://m.example/v1", "model": "m", "apiKeyRef": "sk-inline-5555" } },
        }));
        let err = check_policy_inline(&policy).unwrap_err();
        assert!(err.contains("analysis") && !err.contains("sk-inline"), "{err}");
        let r = report_policy(&BTreeMap::new(), &policy);
        let text = format!("{} {:?}", r.effective, r.findings);
        assert!(
            r.findings.iter().any(|f| f.error && f.key == "intel.policy"),
            "{text}"
        );
        assert!(!text.contains("sk-inline-5555"), "{text}");
        let policy = policy_from(json!({
            "externalProcessing": true,
            "providers": { "analysis": { "endpoint": "https://svc:hunter2@m.example/v1?token=tok-9", "model": "m" } },
        }));
        let err = check_policy_inline(&policy).unwrap_err();
        assert!(!err.contains("hunter2") && !err.contains("tok-9"), "{err}");
        let r = report_policy(&BTreeMap::new(), &policy);
        let text = format!("{} {:?}", r.effective, r.findings);
        assert!(!text.contains("hunter2") && !text.contains("tok-9"), "{text}");
    }

    #[test]
    fn a_policy_whose_switch_and_providers_disagree_warns() {
        let on = policy_from(json!({ "externalProcessing": true }));
        let r = report_policy(&BTreeMap::new(), &on);
        assert!(
            r.findings
                .iter()
                .any(|f| !f.error && f.message.contains("no provider")),
            "{:?}",
            r.findings
        );
        let off = policy_from(json!({
            "providers": { "analysis": { "endpoint": "https://m.example/v1", "model": "m" } },
        }));
        let r = report_policy(&BTreeMap::new(), &off);
        assert!(
            r.findings
                .iter()
                .any(|f| !f.error && f.message.contains("external_processing_disabled")),
            "{:?}",
            r.findings
        );
        assert!(r.findings.iter().all(|f| !f.error), "{:?}", r.findings);
    }
}
