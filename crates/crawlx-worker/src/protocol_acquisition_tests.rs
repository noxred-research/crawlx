#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crawlx_core::{
    error::CoreError,
    secret::{CredentialRef, SecretOr},
};
use crawlx_fetch::{resolver::StaticResolver, GovernorConfig};
use serde_json::{json, Value};

const REQUIRED: [&str; 10] = [
    "checked_egress",
    "all_resource_guard",
    "bounded_body",
    "deadline",
    "cancellation",
    "identity_isolation",
    "read_only_effects",
    "secret_free_response",
    "shared_origin_admission",
    "external_processing",
];

struct Scoped {
    available: bool,
}

#[async_trait::async_trait]
impl SecretResolver for Scoped {
    async fn resolve(&self, _: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        if self.available {
            Ok(SecretOr::secret("scoped-secret-value".to_owned()))
        } else {
            Err(CoreError::Invalid {
                field: "credential",
                reason: "unavailable".to_owned(),
            })
        }
    }
}

fn service(build: &str, guard: &str, zdr: bool) -> Value {
    let mut capabilities: Vec<&str> = REQUIRED.to_vec();
    if zdr {
        capabilities.push("zdr_compatible");
    }
    json!({
        "endpoint": "https://service.test/acquire", "audience": "fixture-audience",
        "buildDigest": build.repeat(64), "guardDigest": guard.repeat(64),
        "capabilities": capabilities, "credentialRef": "env://SCOPED_FIXTURE", "maxConcurrency": 1
    })
}

async fn load(file: Value, available: bool) -> Result<Arc<ProtocolRegistry>, WorkerError> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("registry.json");
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    ProtocolRegistry::from_file(&path, &Scoped { available }).await
}

fn file(tenant: TenantId, services: Value, acquisition: Value) -> Value {
    json!({
        "schemaVersion": 1, "approvedTenants": [tenant.to_string()],
        "services": services, "acquisitionServices": acquisition
    })
}

fn runtime(registry: Arc<ProtocolRegistry>) -> ProtocolRuntime {
    ProtocolRuntime {
        registry,
        policy: Arc::new(EgressPolicy::new(true)),
        resolver: Arc::new(StaticResolver::new()),
        governor: Arc::new(OriginGovernor::new(GovernorConfig::default())),
    }
}

#[tokio::test]
async fn registry_publishes_one_aggregate_capability_bound_to_every_registration() {
    let tenant = TenantId::new();
    let empty = load(file(tenant, json!({}), json!({})), true).await.unwrap();
    assert!(empty.acquisition_capability().unwrap().is_none());

    let both = load(
        file(
            tenant,
            json!({}),
            json!({"b": service("2", "3", false), "a": service("1", "3", true)}),
        ),
        true,
    )
    .await
    .unwrap();
    let capability = both.acquisition_capability().unwrap().unwrap();
    assert_eq!(capability.backend_id, "acquisition_service");
    assert!(capability.available);
    capability.validate_evidence().unwrap();

    let swapped = load(
        file(
            tenant,
            json!({}),
            json!({"a": service("1", "3", true), "b": service("2", "3", false)}),
        ),
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        swapped.acquisition_capability().unwrap().unwrap().build_digest,
        capability.build_digest
    );
    let changed_guard = load(
        file(
            tenant,
            json!({}),
            json!({"a": service("1", "4", true), "b": service("2", "3", false)}),
        ),
        true,
    )
    .await
    .unwrap();
    assert_ne!(
        changed_guard
            .acquisition_capability()
            .unwrap()
            .unwrap()
            .build_digest,
        capability.build_digest,
        "guard digests are part of the published identity"
    );
    let renamed = load(
        file(
            tenant,
            json!({}),
            json!({"c": service("1", "3", true), "b": service("2", "3", false)}),
        ),
        true,
    )
    .await
    .unwrap();
    assert_ne!(
        renamed.acquisition_capability().unwrap().unwrap().build_digest,
        capability.build_digest,
        "operator ids are part of the published identity"
    );

    let report = capability_report(Some(&both));
    let ids: Vec<_> = report.delegates.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(ids, ["a", "b"]);
    let text = serde_json::to_string(&report).unwrap();
    assert!(!text.contains("service.test") && !text.contains("scoped-secret-value"));
}

#[tokio::test]
async fn admission_requires_a_registered_id_an_approved_tenant_and_zdr_capability() {
    let tenant = TenantId::new();
    let registry = load(
        file(
            tenant,
            json!({}),
            json!({"plain": service("1", "3", false), "zdr": service("2", "3", true)}),
        ),
        true,
    )
    .await
    .unwrap();
    let runtime = runtime(registry);
    runtime.admit_acquisition_service("plain", tenant, false).unwrap();
    runtime.admit_acquisition_service("zdr", tenant, true).unwrap();
    assert!(
        runtime
            .admit_acquisition_service("missing", tenant, false)
            .is_err(),
        "unknown selector"
    );
    assert!(
        runtime
            .admit_acquisition_service("plain", TenantId::new(), false)
            .is_err(),
        "unapproved tenant"
    );
    assert!(
        runtime.admit_acquisition_service("plain", tenant, true).is_err(),
        "no zdr_compatible capability"
    );
    assert!(runtime.acquisition_service("plain").is_some());
    assert!(runtime.acquisition_service("missing").is_none());
    assert!(runtime.external_processing_approved(tenant));
    assert!(!runtime.external_processing_approved(TenantId::new()));
}

#[tokio::test]
async fn absent_registration_never_admits_a_selector() {
    let runtime = runtime(Arc::new(ProtocolRegistry::default()));
    assert!(runtime
        .admit_acquisition_service("anything", TenantId::new(), false)
        .is_err());
}

#[tokio::test]
async fn registry_refuses_reserved_unavailable_incomplete_and_excess_registrations() {
    let tenant = TenantId::new();
    for acquisition in [
        json!({"native_ftp": service("1", "3", false)}),
        json!({"native_whois": service("1", "3", false)}),
        json!({"": service("1", "3", false)}),
    ] {
        assert!(load(file(tenant, json!({}), acquisition), true).await.is_err());
    }
    assert!(
        load(
            file(tenant, json!({}), json!({"a": service("1", "3", false)})),
            false
        )
        .await
        .is_err(),
        "an unavailable scoped credential fails registry loading"
    );
    let many: serde_json::Map<String, Value> = (0..17)
        .map(|i| (format!("svc-{i}"), service("1", "3", false)))
        .collect();
    assert!(load(file(tenant, json!({}), Value::Object(many)), true)
        .await
        .is_err());
    let mut incomplete = service("1", "3", false);
    incomplete["capabilities"] = json!(["checked_egress"]);
    assert!(load(file(tenant, json!({}), json!({"a": incomplete})), true)
        .await
        .is_err());
}
