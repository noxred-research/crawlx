//! Versioned first-match protocol selection. Only scheduler-owned facts select routes.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

/// Admission or protocol capability refusal.
#[derive(Debug, thiserror::Error)]
#[error("protocol policy refused: {0}")]
pub struct ProtocolPolicyError(pub &'static str);

/// Native backend or explicitly registered isolated delegate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProtocolBackendV1 {
    /// Existing checked HTTP transport.
    Http,
    /// Existing Session Actor browser transport.
    Browser,
    /// Operator-registered capability, never an arbitrary endpoint.
    Delegate,
}

/// Bounded ordered selector and acquisition limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ProtocolRouteV1 {
    /// Stable rule identifier.
    pub id: String,
    /// Exact permitted schemes; empty matches any supported scheme.
    pub schemes: Vec<String>,
    /// Exact serialized origin, when present.
    pub origin: Option<String>,
    /// Bounded Rust regex over the URL path only.
    pub path_pattern: Option<String>,
    /// Exact scheduler facts; page metadata never enters this map.
    pub scheduler_metadata: BTreeMap<String, String>,
    /// Selected transport.
    pub backend: ProtocolBackendV1,
    /// Operator registry key, required only for delegates.
    pub delegate_id: Option<String>,
    /// Required capability names.
    pub required_capabilities: BTreeSet<String>,
    /// Maximum returned bytes.
    pub max_body_bytes: u32,
    /// Whole operation ceiling, including queueing and cancellation.
    pub max_elapsed_ms: u32,
    /// Operator policy revision.
    pub policy_revision: String,
}

/// Empty routes preserve existing native behavior.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ProtocolConfigV1 {
    /// Contract version.
    pub schema_version: u8,
    /// First match wins, then the existing HTTP/browser classifier.
    pub routes: Vec<ProtocolRouteV1>,
}
impl Default for ProtocolConfigV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            routes: Vec::new(),
        }
    }
}

/// Admission-compiled routing table.
#[derive(Debug)]
pub struct CompiledProtocolRoutes {
    routes: Vec<(ProtocolRouteV1, Option<Regex>)>,
    origin_required: bool,
}

impl ProtocolConfigV1 {
    /// Validate and compile once at admission.
    ///
    /// # Errors
    /// Refuses unknown schemas, untrusted metadata selectors, unsafe schemes and oversized regexes or budgets.
    pub fn compile(&self) -> Result<CompiledProtocolRoutes, ProtocolPolicyError> {
        if self.schema_version != 1 || self.routes.len() > 32 {
            return Err(ProtocolPolicyError("schema or route count"));
        }
        let mut seen = BTreeSet::new();
        let mut routes = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            if route.id.is_empty()
                || route.id.len() > 128
                || !seen.insert(&route.id)
                || route.policy_revision.is_empty()
                || route.policy_revision.len() > 128
                || route.schemes.len() > 6
                || route.required_capabilities.len() > 16
                || route
                    .required_capabilities
                    .iter()
                    .any(|s| s.is_empty() || s.len() > 128)
                || !(1..=67_108_864).contains(&route.max_body_bytes)
                || !(1..=90_000).contains(&route.max_elapsed_ms)
            {
                return Err(ProtocolPolicyError("route bounds"));
            }
            if route
                .schemes
                .iter()
                .any(|s| !matches!(s.as_str(), "http" | "https" | "file" | "ftp" | "sftp" | "whois"))
                || (route.backend != ProtocolBackendV1::Delegate
                    && route.schemes.iter().any(|s| s != "http" && s != "https"))
            {
                return Err(ProtocolPolicyError("scheme requires registered delegate"));
            }
            if (route.backend == ProtocolBackendV1::Delegate) != route.delegate_id.is_some()
                || route
                    .delegate_id
                    .as_ref()
                    .is_some_and(|id| id.is_empty() || id.len() > 128)
            {
                return Err(ProtocolPolicyError("delegate id"));
            }
            if route.backend != ProtocolBackendV1::Delegate
                && route.required_capabilities.iter().any(|id| {
                    !matches!(id.as_str(), "checked_egress" | "bounded_body" | "cancellation")
                        && !(route.backend == ProtocolBackendV1::Browser && id == "session_actor")
                })
            {
                return Err(ProtocolPolicyError("native capability unavailable"));
            }
            if let Some(origin) = &route.origin {
                let parsed = Url::parse(origin).map_err(|_| ProtocolPolicyError("origin"))?;
                if protocol_origin(&parsed).as_deref() != Some(origin.as_str())
                    || parsed.username() != ""
                    || parsed.password().is_some()
                {
                    return Err(ProtocolPolicyError("exact origin required"));
                }
            }
            if route.scheduler_metadata.len() > 3
                || route.scheduler_metadata.iter().any(|(key, value)| {
                    !matches!(key.as_str(), "request_class" | "source_kind" | "media_class")
                        || value.len() > 128
                })
            {
                return Err(ProtocolPolicyError("scheduler metadata allowlist"));
            }
            let pattern = route
                .path_pattern
                .as_ref()
                .map(|pattern| {
                    if pattern.len() > 2048 {
                        return Err(ProtocolPolicyError("path regex length"));
                    }
                    RegexBuilder::new(pattern)
                        .size_limit(64 * 1024)
                        .dfa_size_limit(64 * 1024)
                        .build()
                        .map_err(|_| ProtocolPolicyError("path regex"))
                })
                .transpose()?;
            routes.push((route.clone(), pattern));
        }
        let origin_required = routes.iter().any(|(route, _)| route.origin.is_some());
        Ok(CompiledProtocolRoutes {
            routes,
            origin_required,
        })
    }

    /// Public HTTP admission must never authorize local corpus reads.
    ///
    /// # Errors
    /// Refuses a file route, even when an operator registered a local root elsewhere.
    pub fn validate_public(&self) -> Result<(), ProtocolPolicyError> {
        self.compile()?;
        if self
            .routes
            .iter()
            .any(|r| r.schemes.is_empty() || r.schemes.iter().any(|s| s == "file"))
        {
            return Err(ProtocolPolicyError("public routes must explicitly exclude file"));
        }
        Ok(())
    }
    /// Ensure explicitly routed native backends are admitted by the caller's acquisition policy.
    ///
    /// # Errors
    /// Refuses a route that would silently add native HTTP or browser capability.
    pub fn validate_acquisition(
        &self,
        policy: &crate::acquisition::AcquisitionPolicyV1,
    ) -> Result<(), ProtocolPolicyError> {
        for route in &self.routes {
            let required = match route.backend {
                ProtocolBackendV1::Http => Some("native_http"),
                ProtocolBackendV1::Browser => Some("native_browser"),
                ProtocolBackendV1::Delegate => None,
            };
            if required.is_some_and(|backend| !policy.backend_ids.iter().any(|id| id == backend)) {
                return Err(ProtocolPolicyError(
                    "routed native backend excluded by acquisition policy",
                ));
            }
        }
        Ok(())
    }
}

impl CompiledProtocolRoutes {
    /// Select first matching explicit route; `None` retains native HTTP/browser classification.
    #[must_use]
    pub fn select(
        &self,
        url: &Url,
        scheduler_metadata: &BTreeMap<String, String>,
    ) -> Option<&ProtocolRouteV1> {
        let selected_origin = self.origin_required.then(|| protocol_origin(url)).flatten();
        self.routes
            .iter()
            .find(|(route, regex)| {
                (route.schemes.is_empty() || route.schemes.iter().any(|s| s == url.scheme()))
                    && route
                        .origin
                        .as_ref()
                        .is_none_or(|origin| selected_origin.as_ref() == Some(origin))
                    && regex.as_ref().is_none_or(|regex| regex.is_match(url.path()))
                    && route
                        .scheduler_metadata
                        .iter()
                        .all(|(key, value)| scheduler_metadata.get(key) == Some(value))
            })
            .map(|(route, _)| route)
    }
}

/// Native prerequisites for an automatically derived policy: HTTP default plus explicitly routed browser work.
/// Operator delegate IDs are never native worker capability labels.
#[must_use]
pub fn required_native_backend_ids(config: &ProtocolConfigV1) -> Vec<String> {
    let mut ids = vec!["native_http".to_owned()];
    if config
        .routes
        .iter()
        .any(|route| route.backend == ProtocolBackendV1::Browser)
    {
        ids.push("native_browser".to_owned());
    }
    ids
}

/// Exact hierarchical origin for supported network protocols, including non-WHATWG SFTP and WHOIS.
#[must_use]
pub fn protocol_origin(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    if matches!(url.scheme(), "http" | "https" | "ftp") {
        return Some(url.origin().ascii_serialization());
    }
    let default_port = match url.scheme() {
        "sftp" => 22,
        "whois" => 43,
        _ => return None,
    };
    Some(match url.port().filter(|port| *port != default_port) {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// Operator-approved remote enforcement contract. Advertisement alone is not approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DelegateCapabilitiesV1 {
    /// Contract version.
    pub schema_version: u8,
    /// Supported URL schemes.
    pub schemes: BTreeSet<String>,
    /// Fixed capability identifiers established by operator conformance approval.
    pub capabilities: BTreeSet<String>,
    /// Enforced response cap.
    pub max_bytes: u32,
    /// Provider supports bounded response streaming.
    pub body_streaming: bool,
    /// Provider can follow redirects under the approved policy.
    pub redirects: bool,
    /// Provider enforces network policy for frames, workers, popups and downloads.
    pub subresource_enforcement: bool,
    /// Provider honors cancellation or the enforceable finite lease deadline.
    pub cancellation: bool,
    /// Immutable browser build when this provider executes browser work.
    pub browser_build: Option<String>,
    /// Remote work stops no later than the signed request lease deadline.
    pub deadline_enforced: bool,
    /// Every control/data/subresource/redirect socket uses approved pinned DNS and peer checks.
    pub checked_egress: bool,
    /// Browser isolation and principal separation are enforced.
    pub identity_isolation: bool,
    /// No durable provider retention; required for ZDR.
    pub zero_retention: bool,
    /// Immutable implementation build digest.
    pub build_digest: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn unknown_schema_and_page_metadata_refused() {
        let config = ProtocolConfigV1 {
            schema_version: 2,
            ..ProtocolConfigV1::default()
        };
        assert!(config.compile().is_err());
        let raw = r#"{"schemaVersion":1,"routes":[],"pageMetadata":{}}"#;
        assert!(serde_json::from_str::<ProtocolConfigV1>(raw).is_err());
    }
    fn route(id: &str, backend: ProtocolBackendV1) -> ProtocolRouteV1 {
        ProtocolRouteV1 {
            id: id.into(),
            schemes: vec!["https".into()],
            origin: None,
            path_pattern: Some("^/docs".into()),
            scheduler_metadata: BTreeMap::new(),
            backend,
            delegate_id: (backend == ProtocolBackendV1::Delegate).then(|| "approved".into()),
            required_capabilities: BTreeSet::new(),
            max_body_bytes: 4096,
            max_elapsed_ms: 1000,
            policy_revision: "revision-1".into(),
        }
    }
    #[test]
    fn first_match_wins_and_scheduler_facts_do_not_come_from_page_metadata() {
        let mut config = ProtocolConfigV1::default();
        let mut first = route("first", ProtocolBackendV1::Delegate);
        first
            .scheduler_metadata
            .insert("request_class".into(), "stateless_get".into());
        config.routes = vec![first, route("second", ProtocolBackendV1::Http)];
        let compiled = config.compile().unwrap();
        let url = Url::parse("https://example.test/docs/a").unwrap();
        assert_eq!(compiled.select(&url, &BTreeMap::new()).unwrap().id, "second");
        let facts = BTreeMap::from([("request_class".into(), "stateless_get".into())]);
        assert_eq!(compiled.select(&url, &facts).unwrap().id, "first");
        config.routes[0]
            .scheduler_metadata
            .insert("credentials".into(), "page-chosen".into());
        assert!(config.compile().is_err());
    }
    #[test]
    fn public_admission_never_enables_file_or_unbounded_regex() {
        let mut config = ProtocolConfigV1::default();
        let mut file = route("file", ProtocolBackendV1::Delegate);
        file.schemes = vec!["file".into()];
        config.routes = vec![file];
        assert!(config.compile().is_ok());
        assert!(config.validate_public().is_err());
        config.routes[0].schemes = vec!["https".into()];
        config.routes[0].path_pattern = Some("(".into());
        assert!(config.compile().is_err());
    }
}
