#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authorization records over the API: `POST /v1/authorizations` with the three
//! ownership proofs, immutability, revocation, re-verification, the audit trail, admission of runs
//! that reference a record, and the deployment lists. Every scenario runs on the in-memory store
//! and, when `CRAWLX_TEST_DATABASE_URL` is set, again on PostgreSQL in its own schema.

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::ownership::StaticProbe;
use crawlx_api::{ApiConfig, AppState, CompatConfig, Repos, Scope, Settings};
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, SystemClock, TenantId};
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::authorization::{AuthorizationRecord, OwnershipProof};
use crawlx_policy::egress_lists::{EgressLists, SharedEgressLists};
use crawlx_policy::testkit::sample_record;
use crawlx_storage::{FsArtifactStore, MemoryArtifactStore, MemoryStore, Pg, PgConfig};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const APP: &str = "https://app.example.test";
const OPERATOR_KEYS: &str = "ops-1 00112233445566778899aabbccddeeff\n";

/// One audit row as the scenarios compare it.
#[derive(Clone, Debug)]
struct Audit {
    event: String,
    run: Option<CrawlRunId>,
    actor: String,
    subject: Value,
}

enum Backend {
    Memory(Arc<crawlx_api::MemoryApiStore>),
    Pg(Pg, tempfile::TempDir),
}

#[derive(Clone, Default)]
struct Opts {
    lists: Option<SharedEgressLists>,
    robots_record: Option<AuthorizationRecordId>,
}

struct Harness {
    name: &'static str,
    app: Router,
    state: AppState,
    backend: Backend,
    probe: Arc<StaticProbe>,
    keys: OperatorKeys,
    /// All scopes, tenant `acme`.
    key: String,
    tenant: TenantId,
    /// All scopes, tenant `globex`.
    other_key: String,
    evidence: crawlx_core::ArtifactRef,
}

fn config(opts: &Opts, probe: &Arc<StaticProbe>, keys: &OperatorKeys) -> ApiConfig {
    ApiConfig {
        rate_limit_per_minute: 0,
        operator_keys: keys.clone(),
        ownership_probe: Some(probe.clone()),
        egress_lists: opts.lists.clone(),
        compat: CompatConfig {
            robots_authorization: opts.robots_record,
            ..CompatConfig::default()
        },
        ..ApiConfig::default()
    }
}

async fn memory(opts: &Opts) -> Harness {
    let probe = Arc::new(StaticProbe::new());
    let keys = OperatorKeys::parse(OPERATOR_KEYS).unwrap();
    let config = config(opts, &probe, &keys);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = Arc::new(MemoryStore::new());
    let artifacts = Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()));
    let (repos, api) = Repos::memory_with_api(store, artifacts);
    finish_rig("memory", repos, Backend::Memory(api), config, probe, keys, clock).await
}

async fn postgres(opts: &Opts) -> Option<Harness> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("authz_{}", CrawlRunId::new().0.simple())),
            max_connections: 8,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let artifacts = Arc::new(
        FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let repos = Repos::pg(&pg, artifacts);
    let probe = Arc::new(StaticProbe::new());
    let keys = OperatorKeys::parse(OPERATOR_KEYS).unwrap();
    let config = config(opts, &probe, &keys);
    Some(
        finish_rig(
            "postgres",
            repos,
            Backend::Pg(pg, dir),
            config,
            probe,
            keys,
            clock,
        )
        .await,
    )
}

async fn finish_rig(
    name: &'static str,
    repos: Repos,
    backend: Backend,
    config: ApiConfig,
    probe: Arc<StaticProbe>,
    keys: OperatorKeys,
    clock: Arc<dyn Clock>,
) -> Harness {
    let mut keys_of = Vec::new();
    for tenant in ["acme", "globex"] {
        let key = generate_key();
        let rec = key_record(&key, tenant_id_for(tenant), Scope::all_set()).unwrap();
        repos.api.key_insert(&rec, tenant).await.unwrap();
        keys_of.push(key);
    }
    let evidence_run = crawlx_storage::testkit::crawl_run(
        tenant_id_for("acme"),
        crawlx_storage::testkit::create_crawl(APP, &[], 1),
    );
    repos.runs.create(&evidence_run, None).await.unwrap();
    let evidence = repos
        .artifacts
        .put_evidence(evidence_run.id, b"signed fixture scope letter")
        .await
        .unwrap();
    let policy = crawlx_api::admission_policy(&config, clock.clone());
    let state = AppState::builder(repos, policy, config)
        .settings(Settings::default())
        .clock(clock)
        .build();
    Harness {
        name,
        app: crawlx_api::router(state.clone()),
        state,
        backend,
        probe,
        keys,
        tenant: tenant_id_for("acme"),
        other_key: keys_of.pop().unwrap(),
        key: keys_of.pop().unwrap(),
        evidence,
    }
}

/// The scenario on every available backend.
async fn backends(opts: Opts) -> Vec<Harness> {
    let mut all = vec![memory(&opts).await];
    all.extend(postgres(&opts).await);
    all
}

impl Harness {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        key: &str,
        body: Option<&Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {key}"));
        let req = match body {
            Some(v) => builder
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 16 * 1024 * 1024).await.unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (parts.status, parts.headers, json)
    }

    async fn post(&self, uri: &str, body: &Value) -> (StatusCode, HeaderMap, Value) {
        self.call(Method::POST, uri, &self.key, Some(body)).await
    }

    async fn post_empty(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        self.call(Method::POST, uri, &self.key, None).await
    }

    async fn get(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        self.call(Method::GET, uri, &self.key, None).await
    }

    /// A key of `tenant` limited to `scopes`.
    async fn key_with(&self, tenant: &str, scopes: &[Scope]) -> String {
        let key = generate_key();
        let rec = key_record(&key, tenant_id_for(tenant), scopes.iter().copied().collect()).unwrap();
        self.state.repos.api.key_insert(&rec, tenant).await.unwrap();
        key
    }

    /// The audit rows of tenant `acme`, oldest first.
    async fn audit(&self) -> Vec<Audit> {
        match &self.backend {
            Backend::Memory(api) => api
                .audit_entries()
                .into_iter()
                .filter(|a| a.tenant == self.tenant)
                .map(|a| Audit {
                    event: a.event,
                    run: a.run,
                    actor: a.actor,
                    subject: a.subject,
                })
                .collect(),
            Backend::Pg(pg, _) => {
                let rows: Vec<(String, Option<uuid::Uuid>, String, Value)> = sqlx::query_as(
                    "SELECT event, run_id, actor, subject FROM audit_events WHERE tenant_id = $1 ORDER BY audit_id",
                )
                .bind(self.tenant.0)
                .fetch_all(pg.pool())
                .await
                .unwrap();
                rows.into_iter()
                    .map(|(event, run, actor, subject)| Audit {
                        event,
                        run: run.map(CrawlRunId),
                        actor,
                        subject,
                    })
                    .collect()
            }
        }
    }

    async fn events(&self) -> Vec<String> {
        self.audit().await.into_iter().map(|a| a.event).collect()
    }

    async fn teardown(self) {
        if let Backend::Pg(pg, _dir) = self.backend {
            pg.drop_schema().await.unwrap();
        }
    }
}

fn txt_name(host: &str) -> String {
    format!("_crawlx-authz.{host}")
}

fn evidence_record(h: &Harness, origins: &[&str]) -> AuthorizationRecord {
    let mut record = sample_record(h.tenant, SystemClock.now(), origins);
    record.evidence.artifact_id = Some(h.evidence.id);
    record.evidence.digest = h.evidence.digest;
    record
}

fn dns_record(h: &Harness, origins: &[&str]) -> AuthorizationRecord {
    let mut r = evidence_record(h, origins);
    r.ownership = Some(OwnershipProof::DnsTxt {});
    r
}

/// `r` signed by `ops-1`.
fn signed(h: &Harness, mut r: AuthorizationRecord) -> AuthorizationRecord {
    r.ownership = Some(OwnershipProof::OperatorSignature {
        key_id: "ops-1".to_owned(),
        signature: String::new(),
    });
    let signature = h.keys.sign("ops-1", &r).unwrap();
    r.ownership = Some(OwnershipProof::OperatorSignature {
        key_id: "ops-1".to_owned(),
        signature,
    });
    r
}

/// The create body of `r`: `tenant` left out, the server fills it.
fn body_of(r: &AuthorizationRecord) -> Value {
    let mut v = serde_json::to_value(r).unwrap();
    v.as_object_mut().unwrap().remove("tenant");
    v
}

fn crawl_body(seed: &str, record: AuthorizationRecordId) -> Value {
    json!({
        "seedUrl": seed,
        "seed": 7,
        "safety": { "profile": "authorized_security_test", "authorizationRecordRef": record },
    })
}

/// Publish `r`'s id at the DNS name of every host of its target.
fn publish_dns(h: &Harness, r: &AuthorizationRecord) {
    for host in r.challenge_hosts() {
        h.probe.set_txt(&txt_name(&host), &[&r.id.to_string()]);
    }
}

/// Create `r` over the API (publishing its DNS challenge first) and return the response.
async fn create_dns(h: &Harness, r: &AuthorizationRecord) -> Value {
    publish_dns(h, r);
    let (s, _, v) = h.post("/v1/authorizations", &body_of(r)).await;
    assert_eq!(s, StatusCode::CREATED, "{}: {v}", h.name);
    v
}

fn detail_messages(v: &Value) -> Vec<String> {
    v["error"]["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["message"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_dns_txt_proof_creates_a_verified_record_and_two_audit_events() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        publish_dns(&h, &r);
        let (s, headers, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        assert_eq!(
            headers["location"],
            format!("/v1/authorizations/{}", r.id).as_str()
        );
        assert_eq!(v["status"], "active");
        assert_eq!(v["bodyDigest"], r.body_digest().unwrap().to_string());
        assert_eq!(v["verification"]["kind"], "dns_txt");
        assert_eq!(v["verification"]["hosts"], json!(["app.example.test"]));
        assert_eq!(v["record"]["id"], r.id.to_string());
        assert_eq!(
            v["record"]["tenant"],
            h.tenant.0.to_string(),
            "the server filled the tenant"
        );
        assert!(v["record"]["verifiedAt"].is_string());
        assert!(v["record"].get("revokedAt").is_none());
        assert_eq!(
            v["record"]["authorizer"]["organization"],
            r.authorizer.organization
        );

        // the same resource is readable
        let (s, _, got) = h.get(&format!("/v1/authorizations/{}", r.id)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(got, v);

        // created, then verified; subjects hold ids and the digest, never record content
        let audit = h.audit().await;
        assert_eq!(
            audit.iter().map(|a| a.event.as_str()).collect::<Vec<_>>(),
            ["authorization.created", "authorization.verified"]
        );
        for a in &audit {
            assert!(a.actor.starts_with("api_key:"), "{a:?}");
            assert_eq!(a.run, None);
            assert_eq!(a.subject["record_id"], r.id.to_string());
            assert_eq!(a.subject["version"], 1);
            assert_eq!(a.subject["bodyDigest"], r.body_digest().unwrap().to_string());
            let text = a.subject.to_string();
            for secret in [
                r.authorizer.name.as_str(),
                r.authorizer.contact.as_str(),
                r.emergency_contact.as_str(),
                r.title.as_str(),
                "app.example.test",
            ] {
                assert!(!text.contains(secret), "{} leaks {secret}: {text}", a.event);
            }
        }
        assert_eq!(audit[1].subject["kind"], "dns_txt");
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_missing_txt_record_is_422_ownership_unverified_and_stores_nothing() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &["https://a.example.test", "https://b.example.test"]);
        h.probe.set_txt(&txt_name("a.example.test"), &[&r.id.to_string()]);
        h.probe
            .set_txt(&txt_name("b.example.test"), &["someone else's value"]);
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "ownership_unverified");
        let details = v["error"]["details"].as_array().unwrap();
        assert_eq!(details.len(), 1, "only b.example.test fails: {v}");
        assert_eq!(details[0]["code"], "ownership_unverified");
        let message = details[0]["message"].as_str().unwrap();
        assert!(
            message.contains("b.example.test") && message.contains("_crawlx-authz.b.example.test"),
            "{message}"
        );
        assert!(!message.contains("a.example.test"));

        let (s, _, _) = h.get(&format!("/v1/authorizations/{}", r.id)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "a failed proof stores nothing");
        assert!(h.audit().await.is_empty(), "and writes no audit event");

        // a failing lookup says so; the record is still refused
        h.probe.fail_txt(&txt_name("b.example.test"), "timed out");
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(detail_messages(&v)[0].contains("timed out"), "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_well_known_file_proof_needs_every_origin() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let mut r = evidence_record(&h, &[APP]);
        r.url_prefixes = vec!["https://docs.example.test/guides/".to_owned()];
        r.ownership = Some(OwnershipProof::WellKnownFile {});
        h.probe.set_well_known(APP, &format!("{}\n", r.id));
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(
            detail_messages(&v)[0].starts_with("https://docs.example.test:"),
            "names the failing origin: {v}"
        );

        h.probe
            .set_well_known("https://docs.example.test", &format!("  {}  ", r.id));
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        assert_eq!(v["verification"]["kind"], "well_known_file");
        assert_eq!(
            v["verification"]["origins"],
            json!([APP, "https://docs.example.test"])
        );
        assert!(h
            .probe
            .queries()
            .contains(&"well-known https://docs.example.test".to_owned()));
        h.teardown().await;
    }
}

#[tokio::test]
async fn an_operator_signature_verifies_offline_and_a_tampered_record_does_not() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let mut r = evidence_record(&h, &["http://10.0.0.5"]);
        r.authorized_networks = vec!["10.0.0.0/24".parse().unwrap()];
        let r = signed(&h, r);
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        assert_eq!(v["verification"]["kind"], "operator_signature");
        assert_eq!(v["verification"]["keyId"], "ops-1");
        assert_eq!(v["record"]["authorizedNetworks"], json!(["10.0.0.0/24"]));
        assert!(h.probe.queries().is_empty(), "no DNS, no HTTP");

        // any edit after signing breaks the signature
        let mut tampered = r.clone();
        tampered.id = AuthorizationRecordId::new();
        tampered.title = "edited after signing".to_owned();
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&tampered)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "ownership_unverified");
        assert!(
            detail_messages(&v)[0].contains("operator signature does not match"),
            "{v}"
        );

        // a key the deployment does not hold
        let mut unknown = r.clone();
        unknown.id = AuthorizationRecordId::new();
        unknown.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "ops-9".to_owned(),
            signature: "00".repeat(32),
        });
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&unknown)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(detail_messages(&v)[0].contains("ops-9"), "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_body_that_is_not_a_valid_record_is_422_invalid_request_with_details() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        publish_dns(&h, &r);
        let good = body_of(&r);
        let expect = |v: &Value, path: &str, code: &str| {
            assert_eq!(v["error"]["code"], "invalid_request", "{v}");
            let found = v["error"]["details"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["path"] == path && d["code"] == code);
            assert!(found, "no {code} detail at {path}: {v}");
        };

        let mut body = good.clone();
        body["bogus"] = json!(1);
        let (s, _, v) = h.post("/v1/authorizations", &body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        expect(&v, "/bogus", "unknown_field");

        for key in ["verifiedAt", "revokedAt", "revokedReason"] {
            let mut body = good.clone();
            body[key] = if key == "revokedReason" {
                json!("x")
            } else {
                json!("2026-01-01T00:00:00Z")
            };
            let (s, _, v) = h.post("/v1/authorizations", &body).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{key}: {v}");
            expect(&v, &format!("/{key}"), "read_only");
        }

        let mut body = good.clone();
        body.as_object_mut().unwrap().remove("id");
        let (s, _, v) = h.post("/v1/authorizations", &body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        expect(&v, "/id", "required");

        let mut body = good.clone();
        body.as_object_mut().unwrap().remove("ownership");
        let (s, _, v) = h.post("/v1/authorizations", &body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        expect(&v, "/ownership", "required");

        // another tenant's id in `tenant`
        let mut body = good.clone();
        body["tenant"] = json!(tenant_id_for("globex").0.to_string());
        let (s, _, v) = h.post("/v1/authorizations", &body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        expect(&v, "/tenant", "tenant_mismatch");

        // structural validation: a private network cannot be proven by DNS
        let mut private = r.clone();
        private.authorized_networks = vec!["10.0.0.0/24".parse().unwrap()];
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&private)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(detail_messages(&v)[0].contains("operator signature"), "{v}");

        // a window that already ended
        let mut past = r.clone();
        past.valid_from = SystemClock.now() - chrono::Duration::days(10);
        past.valid_to = SystemClock.now() - chrono::Duration::days(1);
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&past)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        expect(&v, "/validTo", "out_of_range");

        // not an object, not JSON
        let (s, _, v) = h.post("/v1/authorizations", &json!([1, 2])).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "invalid_request");

        // nothing above was stored; the caller's own tenant and an omitted tenant both work
        assert!(h.events().await.is_empty());
        let mut body = good.clone();
        body["tenant"] = json!(h.tenant.0.to_string());
        let (s, _, v) = h.post("/v1/authorizations", &body).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn records_are_immutable_and_an_identical_create_is_an_idempotent_replay() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        let first = create_dns(&h, &r).await;
        let probes = h.probe.queries().len();
        assert_eq!(probes, 1);

        // the same body again: 200 and the stored record, no new proof check, no new audit
        h.probe.clear();
        let (s, _, again) = h.post("/v1/authorizations", &body_of(&r)).await;
        assert_eq!(s, StatusCode::OK, "{again}");
        assert_eq!(again, first, "the replay is the stored resource");
        assert!(h.probe.queries().is_empty(), "a replay does not probe again");
        assert_eq!(h.events().await.len(), 2);

        // the same id with another body is a conflict; the stored record stays as it was
        publish_dns(&h, &r);
        let mut changed = r.clone();
        changed.title = "another engagement".to_owned();
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&changed)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["error"]["code"], "authorization_exists");
        let (_, _, got) = h.get(&format!("/v1/authorizations/{}", r.id)).await;
        assert_eq!(got["bodyDigest"], first["bodyDigest"]);
        assert_eq!(got["record"]["title"], r.title);

        // another tenant cannot take the id either, and never learns the record
        let foreign_run = crawlx_storage::testkit::crawl_run(
            tenant_id_for("globex"),
            crawlx_storage::testkit::create_crawl(APP, &[], 1),
        );
        h.state.repos.runs.create(&foreign_run, None).await.unwrap();
        let foreign_evidence = h
            .state
            .repos
            .artifacts
            .put_evidence(foreign_run.id, b"other tenant signed scope letter")
            .await
            .unwrap();
        let mut other_record = r.clone();
        other_record.evidence.artifact_id = Some(foreign_evidence.id);
        other_record.evidence.digest = foreign_evidence.digest;
        let (s, _, v) = h
            .call(
                Method::POST,
                "/v1/authorizations",
                &h.other_key,
                Some(&body_of(&other_record)),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["error"]["code"], "authorization_exists");
        assert_eq!(h.events().await.len(), 2, "conflicts write no audit event");
        h.teardown().await;
    }
}

#[tokio::test]
async fn another_tenant_cannot_read_revoke_or_verify_a_record() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        create_dns(&h, &r).await;
        let uri = format!("/v1/authorizations/{}", r.id);
        let (s, _, _) = h.call(Method::GET, &uri, &h.other_key, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = h
            .call(
                Method::POST,
                &format!("{uri}/revoke"),
                &h.other_key,
                Some(&json!({})),
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = h
            .call(Method::POST, &format!("{uri}/verify"), &h.other_key, None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        // unknown and malformed ids
        for bad in [AuthorizationRecordId::new().to_string(), "not-a-uuid".to_owned()] {
            let (s, _, _) = h.get(&format!("/v1/authorizations/{bad}")).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{bad}");
        }
        // the record is still active for its owner
        let (_, _, v) = h.get(&uri).await;
        assert_eq!(v["status"], "active");
        assert_eq!(h.events().await.len(), 2);
        h.teardown().await;
    }
}

#[tokio::test]
async fn scopes_gate_the_authorization_routes() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        let reader = h.key_with("acme", &[Scope::AuthorizationsRead]).await;
        let writer = h.key_with("acme", &[Scope::AuthorizationsWrite]).await;
        let crawler = h.key_with("acme", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
        publish_dns(&h, &r);
        let post = |key: &str| {
            let key = key.to_owned();
            let body = body_of(&r);
            let h = &h;
            async move {
                h.call(Method::POST, "/v1/authorizations", &key, Some(&body))
                    .await
            }
        };
        for key in [&reader, &crawler] {
            let (s, _, v) = post(key).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
            assert_eq!(v["error"]["code"], "scope_missing");
            assert!(v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("authorizations:write"));
        }
        let (s, _, v) = post(&writer).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");

        let uri = format!("/v1/authorizations/{}", r.id);
        let (s, _, _) = h.call(Method::GET, &uri, &writer, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "write does not imply read");
        let (s, _, _) = h.call(Method::GET, &uri, &crawler, None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = h.call(Method::GET, &uri, &reader, None).await;
        assert_eq!(s, StatusCode::OK);
        for verb in ["revoke", "verify"] {
            let (s, _, _) = h
                .call(Method::POST, &format!("{uri}/{verb}"), &reader, Some(&json!({})))
                .await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{verb}");
        }
        let (s, _, _) = h
            .call(
                Method::POST,
                "/v1/authorizations",
                "cx_live_nope",
                Some(&body_of(&r)),
            )
            .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_verified_record_admits_a_crawl_and_the_run_is_bound_to_its_digest() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        let created = create_dns(&h, &r).await;
        let digest = r.body_digest().unwrap();

        let (s, _, run) = h.post("/v1/crawls", &crawl_body(&format!("{APP}/"), r.id)).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{run}");
        let run_id: CrawlRunId = run["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            h.state.repos.api.authorization_run_digest(run_id).await.unwrap(),
            Some(digest),
            "the run row carries the digest of the body it was admitted under"
        );
        assert_eq!(created["bodyDigest"], digest.to_string());

        let audit = h.audit().await;
        let used: Vec<&Audit> = audit.iter().filter(|a| a.event == "authorization.used").collect();
        assert_eq!(used.len(), 1, "{audit:?}");
        assert_eq!(used[0].run, Some(run_id));
        assert_eq!(
            used[0].subject,
            json!({
                "record_id": r.id.to_string(),
                "version": 1,
                "bodyDigest": digest.to_string(),
                "run_id": run_id.to_string(),
            })
        );
        let order: Vec<&str> = audit.iter().map(|a| a.event.as_str()).collect();
        assert_eq!(
            order,
            [
                "authorization.created",
                "authorization.verified",
                "crawl.accepted",
                "authorization.used"
            ]
        );

        // a run without a record is bound to nothing and writes no `used` event
        let (s, _, plain) = h
            .post(
                "/v1/crawls",
                &json!({"seedUrl": "https://other.example.test/", "seed": 7}),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{plain}");
        let plain_id: CrawlRunId = plain["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            h.state
                .repos
                .api
                .authorization_run_digest(plain_id)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            h.events()
                .await
                .iter()
                .filter(|e| *e == "authorization.used")
                .count(),
            1
        );

        // the record bounds the run: a seed outside its target is refused at admission
        let (s, _, v) = h
            .post("/v1/crawls", &crawl_body("https://elsewhere.example.test/", r.id))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "authorization_required");
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_revoked_record_refuses_new_runs_and_revocation_is_idempotent() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        create_dns(&h, &r).await;
        let seed = format!("{APP}/");
        let (s, _, _) = h.post("/v1/crawls", &crawl_body(&seed, r.id)).await;
        assert_eq!(s, StatusCode::ACCEPTED);

        let uri = format!("/v1/authorizations/{}", r.id);
        let (s, _, first) = h
            .post(&format!("{uri}/revoke"), &json!({"reason": "engagement over"}))
            .await;
        assert_eq!(s, StatusCode::OK, "{first}");
        assert_eq!(first["status"], "revoked");
        assert_eq!(first["record"]["revokedReason"], "engagement over");
        assert!(first["record"]["revokedAt"].is_string());
        assert_eq!(
            first["bodyDigest"],
            r.body_digest().unwrap().to_string(),
            "the body is untouched"
        );

        // the second call answers with the first revocation; no second audit event
        let (s, _, second) = h
            .post(&format!("{uri}/revoke"), &json!({"reason": "a different reason"}))
            .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(second, first);
        let (s, _, third) = h.post_empty(&format!("{uri}/revoke")).await;
        assert_eq!(s, StatusCode::OK, "the reason is optional");
        assert_eq!(third, first);
        let (_, _, got) = h.get(&uri).await;
        assert_eq!(got, first);
        let revoked: Vec<Audit> = h
            .audit()
            .await
            .into_iter()
            .filter(|a| a.event == "authorization.revoked")
            .collect();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].subject["record_id"], r.id.to_string());
        assert!(!revoked[0].subject.to_string().contains("engagement over"));

        // admission now refuses the record
        let (s, _, v) = h.post("/v1/crawls", &crawl_body(&seed, r.id)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "authorization_required");
        assert!(
            detail_messages(&v).iter().any(|m| m.contains("revoked")),
            "the refusal names the revocation: {v}"
        );

        // a revoked record cannot be verified again
        let (s, _, v) = h.post_empty(&format!("{uri}/verify")).await;
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["error"]["code"], "invalid_state");

        // bad revoke bodies
        for body in [
            json!({"reason": 5}),
            json!({"why": "x"}),
            json!([1]),
            json!({"reason": "x".repeat(1001)}),
        ] {
            let (s, _, v) = h.post(&format!("{uri}/revoke"), &body).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {v}");
            assert_eq!(v["error"]["code"], "invalid_request");
        }
        h.teardown().await;
    }
}

#[tokio::test]
async fn verify_runs_the_proof_again_and_changes_only_the_lifecycle() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        let created = create_dns(&h, &r).await;
        let uri = format!("/v1/authorizations/{}", r.id);

        // the TXT record disappeared: the proof no longer holds, nothing changes
        h.probe.clear();
        let (s, _, v) = h.post_empty(&format!("{uri}/verify")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "ownership_unverified");
        let (_, _, got) = h.get(&uri).await;
        assert_eq!(got, created, "a failed re-check leaves the record as it was");
        assert_eq!(h.events().await.len(), 2);

        // published again: verified again, verifiedAt moves, the body and its digest do not
        publish_dns(&h, &r);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (s, _, again) = h.post_empty(&format!("{uri}/verify")).await;
        assert_eq!(s, StatusCode::OK, "{again}");
        assert_eq!(again["bodyDigest"], created["bodyDigest"]);
        assert_ne!(again["record"]["verifiedAt"], created["record"]["verifiedAt"]);
        assert_eq!(again["verification"]["kind"], "dns_txt");
        let mut before = created["record"].clone();
        let mut after = again["record"].clone();
        before["verifiedAt"] = Value::Null;
        after["verifiedAt"] = Value::Null;
        assert_eq!(before, after, "only verifiedAt changed");
        assert_eq!(
            h.events().await,
            [
                "authorization.created",
                "authorization.verified",
                "authorization.verified"
            ]
        );
        h.teardown().await;
    }
}

#[tokio::test]
async fn the_audit_trail_of_a_record_lifecycle_is_ordered_and_content_free() {
    for h in backends(Opts::default()).await {
        println!("backend: {}", h.name);
        let r = dns_record(&h, &[APP]);
        create_dns(&h, &r).await;
        let uri = format!("/v1/authorizations/{}", r.id);
        let (s, _, _) = h.post_empty(&format!("{uri}/verify")).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = h.post(&format!("{uri}/revoke"), &json!({"reason": "done"})).await;
        assert_eq!(s, StatusCode::OK);
        let audit = h.audit().await;
        assert_eq!(
            audit.iter().map(|a| a.event.as_str()).collect::<Vec<_>>(),
            [
                "authorization.created",
                "authorization.verified",
                "authorization.verified",
                "authorization.revoked"
            ]
        );
        let keys: BTreeSet<&str> = audit
            .iter()
            .flat_map(|a| a.subject.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["bodyDigest", "kind", "record_id", "version"]),
            "subjects carry ids, the version, the digest and the proof kind only"
        );
        h.teardown().await;
    }
}

#[tokio::test]
async fn a_record_that_was_never_verified_is_refused_at_admission() {
    // a local registration (`crawlx crawl --authorization-record`) never checks an ownership
    // proof: the API refuses to admit a run against it
    let h = memory(&Opts::default()).await;
    let mut r = evidence_record(&h, &[APP]);
    let Backend::Memory(api) = &h.backend else {
        panic!("memory harness");
    };
    api.add_authorization(r.clone());
    let (s, _, v) = h.post("/v1/crawls", &crawl_body(&format!("{APP}/"), r.id)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"]["code"], "authorization_required");
    assert!(
        detail_messages(&v).iter().any(|m| m.contains("not verified")),
        "{v}"
    );
    // the same record, verified, is admitted
    r.verified_at = Some(SystemClock.now());
    api.add_authorization(r.clone());
    let (s, _, v) = h.post("/v1/crawls", &crawl_body(&format!("{APP}/"), r.id)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    // an expired or not yet valid window is refused too, even when verified
    let mut late = r.clone();
    late.id = AuthorizationRecordId::new();
    late.valid_from = SystemClock.now() + chrono::Duration::days(1);
    late.valid_to = SystemClock.now() + chrono::Duration::days(2);
    api.add_authorization(late.clone());
    let (s, _, v) = h
        .post("/v1/crawls", &crawl_body(&format!("{APP}/"), late.id))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        detail_messages(&v).iter().any(|m| m.contains("not yet valid")),
        "{v}"
    );
    let (_, _, got) = h.get(&format!("/v1/authorizations/{}", r.id)).await;
    assert_eq!(got["status"], "active");
}

#[tokio::test]
async fn the_deployment_allowlist_bounds_a_private_network_record() {
    let allow = EgressLists::parse_allowlist("10.1.0.0/16\n").unwrap();
    let lists = SharedEgressLists::new(EgressLists::new(Some(allow), Vec::<String>::new()).unwrap());
    for h in backends(Opts {
        lists: Some(lists),
        ..Opts::default()
    })
    .await
    {
        println!("backend: {}", h.name);
        let private_body = |id: AuthorizationRecordId, seed: &str| {
            json!({
                "seedUrl": seed,
                "seed": 7,
                "safety": {
                    "profile": "authorized_security_test",
                    "allowPrivateNetworks": true,
                    "authorizationRecordRef": id,
                },
            })
        };
        // 10.0.0.0/24 lies outside the deployment allowlist: the record is stored (the operator
        // vouched for it), but no run may use the network
        let mut outside = evidence_record(&h, &["http://10.0.0.5"]);
        outside.authorized_networks = vec!["10.0.0.0/24".parse().unwrap()];
        let outside = signed(&h, outside);
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&outside)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let (s, _, v) = h
            .post("/v1/crawls", &private_body(outside.id, "http://10.0.0.5/"))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let refused = v["error"]["details"].as_array().unwrap().iter().any(|d| {
            d["code"] == "authorization_required"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("outside the deployment allowlist"))
        });
        assert!(refused, "{v}");

        // 10.1.2.0/24 lies inside it
        let mut inside = evidence_record(&h, &["http://10.1.2.5"]);
        inside.authorized_networks = vec!["10.1.2.0/24".parse().unwrap()];
        let inside = signed(&h, inside);
        let (s, _, v) = h.post("/v1/authorizations", &body_of(&inside)).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let (s, _, v) = h
            .post("/v1/crawls", &private_body(inside.id, "http://10.1.2.5/"))
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn the_operator_blocklist_refuses_a_seed_even_under_a_record() {
    let block = EgressLists::parse_blocklist("blocked.example.test\n").unwrap();
    let lists = SharedEgressLists::new(EgressLists::new(None, block.clone()).unwrap());
    for h in backends(Opts {
        lists: Some(lists.clone()),
        ..Opts::default()
    })
    .await
    {
        println!("backend: {}", h.name);
        lists.replace(EgressLists::new(None, block.clone()).unwrap());
        let r = dns_record(&h, &["https://blocked.example.test"]);
        create_dns(&h, &r).await;
        let (s, _, v) = h
            .post("/v1/crawls", &crawl_body("https://blocked.example.test/", r.id))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "url_denied");
        assert_eq!(v["error"]["details"][0]["path"], "/seedUrl");

        // hosts below a blocked host are blocked too; unrelated hosts are not
        let (s, _, v) = h
            .post(
                "/v1/crawls",
                &json!({"seedUrl": "https://sub.blocked.example.test/", "seed": 1}),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert_eq!(v["error"]["code"], "url_denied");
        let (s, _, v) = h
            .post(
                "/v1/crawls",
                &json!({"seedUrl": "https://fine.example.test/", "seed": 1}),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");

        // the list is live: replacing it reaches the next admission
        lists.replace(EgressLists::new(None, Vec::<String>::new()).unwrap());
        let (s, _, v) = h
            .post("/v1/crawls", &crawl_body("https://blocked.example.test/", r.id))
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn the_facade_robots_record_must_be_a_verified_record_and_writes_authorization_used() {
    let record_id = AuthorizationRecordId::new();
    let opts = Opts {
        robots_record: Some(record_id),
        ..Opts::default()
    };
    for h in backends(opts).await {
        println!("backend: {}", h.name);
        let crawl = json!({"url": format!("{APP}/"), "ignoreRobotsTxt": true, "limit": 1});

        // no such record yet: the override is refused
        let (s, _, v) = h.post("/compat/v2/crawl", &crawl).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "ROBOTS_OVERRIDE_NOT_AUTHORIZED");

        // created through the API, acknowledging the override
        let mut r = dns_record(&h, &[APP]);
        r.id = record_id;
        r.robots_override_acknowledged = true;
        create_dns(&h, &r).await;
        let (s, _, v) = h.post("/compat/v2/crawl", &crawl).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let run_id: CrawlRunId = v["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            h.state.repos.api.authorization_run_digest(run_id).await.unwrap(),
            Some(r.body_digest().unwrap())
        );
        assert!(h
            .audit()
            .await
            .iter()
            .any(|a| a.event == "authorization.used" && a.run == Some(run_id)));

        // revoked: the facade refuses again, naming the record as the reason
        let (s, _, _) = h
            .post_empty(&format!("/v1/authorizations/{record_id}/revoke"))
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, v) = h.post("/compat/v2/crawl", &crawl).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["code"], "ROBOTS_OVERRIDE_NOT_AUTHORIZED");
        assert!(v["error"].as_str().unwrap().contains("revoked"), "{v}");
        h.teardown().await;
    }
}

#[tokio::test]
async fn evidence_is_resolved_in_tenant_scope_and_reverified() {
    for h in backends(Opts::default()).await {
        let mut missing = dns_record(&h, &[APP]);
        missing.evidence.artifact_id = None;
        publish_dns(&h, &missing);
        let (status, _, body) = h.post("/v1/authorizations", &body_of(&missing)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["details"][0]["code"], "evidence_unverified");

        missing.evidence.artifact_id = Some(crawlx_core::ArtifactId::new());
        let (status, _, _) = h.post("/v1/authorizations", &body_of(&missing)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let mut mismatch = dns_record(&h, &[APP]);
        mismatch.evidence.digest = crawlx_core::hash::Digest::of("test", b"wrong letter");
        publish_dns(&h, &mismatch);
        let (status, _, _) = h.post("/v1/authorizations", &body_of(&mismatch)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let foreign_run = crawlx_storage::testkit::crawl_run(
            tenant_id_for("globex"),
            crawlx_storage::testkit::create_crawl(APP, &[], 1),
        );
        h.state.repos.runs.create(&foreign_run, None).await.unwrap();
        let foreign = h
            .state
            .repos
            .artifacts
            .put_evidence(foreign_run.id, b"foreign letter")
            .await
            .unwrap();
        let mut cross_tenant = dns_record(&h, &[APP]);
        cross_tenant.evidence.artifact_id = Some(foreign.id);
        cross_tenant.evidence.digest = foreign.digest;
        publish_dns(&h, &cross_tenant);
        let (status, _, _) = h.post("/v1/authorizations", &body_of(&cross_tenant)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _, _) = h
            .post(
                "/v1/authorizations/evidence",
                &json!({
                    "runId": foreign_run.id, "document": "not mine",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let own_run = h
            .state
            .repos
            .artifacts
            .row(h.evidence.id)
            .await
            .unwrap()
            .unwrap()
            .run;
        let (status, _, uploaded) = h
            .post(
                "/v1/authorizations/evidence",
                &json!({
                    "runId": own_run, "document": "owner supplied scope letter",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{uploaded}");
        let mut good = dns_record(&h, &[APP]);
        good.evidence.artifact_id = Some(serde_json::from_value(uploaded["artifactId"].clone()).unwrap());
        good.evidence.digest = serde_json::from_value(uploaded["digest"].clone()).unwrap();
        create_dns(&h, &good).await;
        let verify = format!("/v1/authorizations/{}/verify", good.id);
        assert_eq!(h.post_empty(&verify).await.0, StatusCode::OK);
        h.state.repos.artifacts.purge_run(own_run).await.unwrap();
        let (status, _, body) = h.post_empty(&verify).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["details"][0]["code"], "evidence_unverified");
        h.teardown().await;
    }
}

#[tokio::test]
async fn production_admission_requires_declared_role_and_exact_credential_reference() {
    for h in backends(Opts::default()).await {
        let mut record = dns_record(&h, &[APP]);
        record.test_accounts = vec![crawlx_policy::TestAccount {
            role: "member".to_owned(),
            credential_ref: "env://TEST_MEMBER".to_owned(),
        }];
        create_dns(&h, &record).await;
        let mut body = crawl_body(APP, record.id);
        body["roles"] = json!([{ "name": "member", "credentialRef": "env://TEST_MEMBER" }]);
        assert_eq!(h.post("/v1/crawls", &body).await.0, StatusCode::ACCEPTED);
        for role in [
            json!({ "name": "member", "credentialRef": "env://OTHER_MEMBER" }),
            json!({ "name": "admin", "credentialRef": "env://TEST_MEMBER" }),
        ] {
            body["roles"] = json!([role]);
            let (status, _, error) = h.post("/v1/crawls", &body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{error}");
            assert!(error["error"]["details"]
                .as_array()
                .unwrap()
                .iter()
                .any(|detail| detail["path"] == "/roles/0/credentialRef"));
        }
        body["safety"] = json!({ "profile": "read_only" });
        assert_eq!(
            h.post("/v1/crawls", &body).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        h.teardown().await;
    }
}
