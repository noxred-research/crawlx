//! `crawlx authz`: the offline `sign` and `challenge`, and `create`, `show`,
//! `revoke`, `verify` against an in-process API (the real router over the in-memory store; the
//! ownership probe is the API's `StaticProbe`, operator signatures use a keys file). Every command
//! runs as the `crawlx` binary, so exit codes, stdout and stderr are the ones a user sees.
//! Router fixtures store real, tenant-owned evidence before records are signed or submitted.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::ownership::StaticProbe;
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_core::{ArtifactRef, Clock, SystemClock, TenantId};
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AdmissionPolicy, AuthorizationRecord, OwnershipProof};
use crawlx_storage::{DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

const KEY_HEX: &str = "00112233445566778899aabbccddeeff";

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Run `crawlx ARGS` with a clean API environment.
async fn crawlx(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.args(args)
        .env_remove("CRAWLX_API_URL")
        .env_remove("CRAWLX_API_KEY")
        .env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().await.unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

fn json_out(o: &Output) -> Value {
    assert!(
        o.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        o.status.code(),
        out(o),
        err(o)
    );
    serde_json::from_str(&out(o)).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", out(o)))
}

fn record(tenant: TenantId, origins: &[&str]) -> AuthorizationRecord {
    sample_record(tenant, SystemClock.now(), origins)
}

fn record_file(dir: &Path, name: &str, record: &AuthorizationRecord) -> PathBuf {
    write(dir, name, &serde_json::to_string_pretty(record).unwrap())
}

// ---------------------------------------------------------------------------------------------
// offline: sign and challenge

fn signable(origin: &str) -> AuthorizationRecord {
    AuthorizationRecord {
        authorized_networks: vec!["10.20.0.0/16".parse().unwrap()],
        ownership: Some(OwnershipProof::OperatorSignature {
            key_id: "op1".to_owned(),
            signature: String::new(),
        }),
        ..record(TenantId::new(), &[origin])
    }
}

#[tokio::test]
async fn sign_fills_the_operator_signature_the_deployment_key_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let keys_text = format!(
        "# operator keys\nop1 {KEY_HEX}\nop2 {}\n",
        KEY_HEX.chars().rev().collect::<String>()
    );
    let keys = write(dir.path(), "keys", &keys_text);
    let rec = record_file(dir.path(), "record.json", &signable("http://10.20.0.5:8090"));

    // to a file
    let signed_path = dir.path().join("signed.json");
    let o = crawlx(
        &[
            "authz",
            "sign",
            "--record",
            s(&rec),
            "--key-id",
            "op1",
            "--key-file",
            s(&keys),
            "--out",
            s(&signed_path),
        ],
        &[],
    )
    .await;
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("signed record") && out(&o).contains("op1"),
        "{}",
        out(&o)
    );
    let signed: AuthorizationRecord = serde_json::from_slice(&std::fs::read(&signed_path).unwrap()).unwrap();
    let Some(OwnershipProof::OperatorSignature { key_id, signature }) = &signed.ownership else {
        panic!("not an operator signature: {:?}", signed.ownership);
    };
    assert_eq!(key_id, "op1");
    assert_eq!(signature.len(), 64, "HMAC-SHA256 as hex");
    assert!(signature.bytes().all(|b| b.is_ascii_hexdigit()));
    let deployment = OperatorKeys::parse(&keys_text).unwrap();
    deployment.verify(&signed).unwrap();

    // to stdout: the same record, the same signature (HMAC is deterministic)
    let o = crawlx(
        &[
            "authz",
            "sign",
            "--record",
            s(&rec),
            "--key-id",
            "op1",
            "--key-file",
            s(&keys),
        ],
        &[],
    )
    .await;
    let again: AuthorizationRecord = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(again, signed);

    // editing the record after signing breaks the signature
    let mut edited = signed.clone();
    edited.title = "another engagement".to_owned();
    assert!(deployment.verify(&edited).is_err());

    // the key itself is never printed
    assert!(!out(&o).contains(KEY_HEX) && !err(&o).contains(KEY_HEX));

    // a file holding one bare hex key signs under --key-id
    let bare = write(dir.path(), "bare.key", &format!("{KEY_HEX}\n"));
    let o = crawlx(
        &[
            "authz",
            "sign",
            "--record",
            s(&rec),
            "--key-id",
            "op1",
            "--key-file",
            s(&bare),
        ],
        &[],
    )
    .await;
    let from_bare: AuthorizationRecord = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(from_bare, signed, "same key, same signature");
}

#[tokio::test]
async fn sign_refuses_what_cannot_be_signed() {
    let dir = tempfile::tempdir().unwrap();
    let keys = write(dir.path(), "keys", &format!("op1 {KEY_HEX}\n"));
    let sign = |rec: PathBuf, key_id: &'static str, key_file: PathBuf| async move {
        crawlx(
            &[
                "authz",
                "sign",
                "--record",
                s(&rec),
                "--key-id",
                key_id,
                "--key-file",
                s(&key_file),
            ],
            &[],
        )
        .await
    };

    // a key the file does not hold
    let rec = record_file(
        dir.path(),
        "a.json",
        &AuthorizationRecord {
            ownership: None,
            ..signable("http://10.20.0.5:8090")
        },
    );
    let o = sign(rec.clone(), "op9", keys.clone()).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("unknown operator key"), "{}", err(&o));

    // the record names another key
    let named = record_file(dir.path(), "b.json", &signable("http://10.20.0.5:8090"));
    let o = sign(named, "op2", keys.clone()).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("names operator key"), "{}", err(&o));

    // another proof kind is not silently replaced
    let dns = record_file(
        dir.path(),
        "c.json",
        &AuthorizationRecord {
            authorized_networks: Vec::new(),
            ownership: Some(OwnershipProof::DnsTxt {}),
            ..signable("https://shop.example.test")
        },
    );
    let o = sign(dns, "op1", keys.clone()).await;
    assert!(err(&o).contains("another ownership proof"), "{}", err(&o));

    // lifecycle state is the API's to set
    let verified = record_file(
        dir.path(),
        "d.json",
        &AuthorizationRecord {
            verified_at: Some(SystemClock.now()),
            ..signable("http://10.20.0.5:8090")
        },
    );
    let o = sign(verified, "op1", keys.clone()).await;
    assert!(err(&o).contains("lifecycle"), "{}", err(&o));

    // an invalid record (window over 90 days) is not worth signing
    let long = record_file(
        dir.path(),
        "e.json",
        &AuthorizationRecord {
            valid_to: SystemClock.now() + chrono::Duration::days(200),
            ..signable("http://10.20.0.5:8090")
        },
    );
    let o = sign(long, "op1", keys.clone()).await;
    assert!(err(&o).contains("not valid"), "{}", err(&o));

    // the signature covers `tenant`: a record without one cannot be signed
    let mut v = serde_json::to_value(signable("http://10.20.0.5:8090")).unwrap();
    v.as_object_mut().unwrap().remove("tenant");
    let no_tenant = write(dir.path(), "f.json", &v.to_string());
    let o = sign(no_tenant, "op1", keys.clone()).await;
    assert!(err(&o).contains("tenant"), "{}", err(&o));

    // a malformed key file is an error that never quotes the key
    let bad = write(dir.path(), "bad", "op1 not-hex-at-all\n");
    let o = sign(rec, "op1", bad).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(!err(&o).contains("not-hex-at-all"), "{}", err(&o));
}

#[tokio::test]
async fn challenge_prints_the_dns_names_and_well_known_files_to_publish() {
    let dir = tempfile::tempdir().unwrap();
    let mut rec = record(
        TenantId::new(),
        &[
            "https://shop.example.test",
            "http://gym.example.test:8090",
            "http://127.0.0.1:8090",
        ],
    );
    rec.url_prefixes = vec!["https://docs.example.test/api/".to_owned()];
    rec.ownership = Some(OwnershipProof::DnsTxt {});
    // the challenge needs the id and the target only: `tenant` may be missing
    let mut v = serde_json::to_value(&rec).unwrap();
    v.as_object_mut().unwrap().remove("tenant");
    let file = write(dir.path(), "record.json", &v.to_string());
    let id = rec.id.to_string();

    let o = crawlx(&["authz", "challenge", "--record", s(&file)], &[]).await;
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains(&format!("record {id}")), "{text}");
    assert!(text.contains("ownership: dns_txt"), "{text}");
    for host in ["shop.example.test", "gym.example.test", "docs.example.test"] {
        assert!(
            text.contains(&format!("_crawlx-authz.{host} TXT \"{id}\"")),
            "{host}: {text}"
        );
    }
    for url in [
        "https://shop.example.test/.well-known/crawlx-authorization",
        "http://gym.example.test:8090/.well-known/crawlx-authorization",
        "https://docs.example.test/.well-known/crawlx-authorization",
    ] {
        assert!(text.lines().any(|l| l.trim() == url), "{url}: {text}");
    }
    assert!(text.contains(&format!("body: {id}")), "{text}");
    assert!(text.contains("IP address cannot carry a TXT record"), "{text}");

    let o = crawlx(&["authz", "challenge", "--record", s(&file), "--json"], &[]).await;
    let doc = json_out(&o);
    assert_eq!(doc["id"], id.as_str());
    assert_eq!(doc["ownership"], "dns_txt");
    let names: Vec<&str> = doc["dnsTxt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    // the hosts of the record in canonical (sorted) order
    assert_eq!(
        names,
        [
            "_crawlx-authz.127.0.0.1",
            "_crawlx-authz.docs.example.test",
            "_crawlx-authz.gym.example.test",
            "_crawlx-authz.shop.example.test",
        ]
    );
    assert_eq!(doc["dnsTxt"].as_array().unwrap().len(), 4);
    assert!(doc["dnsTxt"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["type"] == "TXT" && e["value"] == id.as_str()));
    let files: Vec<&str> = doc["wellKnownFile"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["url"].as_str().unwrap())
        .collect();
    assert_eq!(files.len(), 4, "{files:?}");
    assert!(doc["wellKnownFile"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["body"] == id.as_str()));

    // an operator-signed record has nothing to publish
    let signed = record_file(dir.path(), "signed.json", &signable("http://10.20.0.5:8090"));
    let o = crawlx(&["authz", "challenge", "--record", s(&signed)], &[]).await;
    assert!(
        out(&o).contains("operator_signature: nothing to publish"),
        "{}",
        out(&o)
    );
}

#[tokio::test]
async fn help_lists_the_subcommands_and_never_shows_the_key() {
    let o = crawlx(&["authz", "--help"], &[]).await;
    assert!(o.status.success());
    let h = out(&o);
    for sub in ["create", "show", "revoke", "verify", "sign", "challenge"] {
        assert!(h.contains(sub), "`{sub}` missing from:\n{h}");
    }
    let o = crawlx(
        &["authz", "create", "--help"],
        &[("CRAWLX_API_KEY", "cx_live_do_not_print")],
    )
    .await;
    let h = out(&o);
    assert!(
        h.contains("--api-url") && h.contains("--api-key") && h.contains("--record"),
        "{h}"
    );
    assert!(
        h.contains("http://127.0.0.1:8080") && h.contains("CRAWLX_API_URL"),
        "{h}"
    );
    assert!(!h.contains("cx_live_do_not_print"), "{h}");
    let o = crawlx(&["--help"], &[]).await;
    assert!(out(&o).contains("authz"), "{}", out(&o));
}

// ---------------------------------------------------------------------------------------------
// against an in-process API

struct Api {
    base: String,
    key: String,
    tenant: TenantId,
    evidence: ArtifactRef,
    probe: Arc<StaticProbe>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_api(keys: OperatorKeys) -> Api {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = Arc::new(MemoryStore::new());
    let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
    let artifacts = Arc::new(
        MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock)).with_zdr_buffer(zdr.clone()),
    );
    let (repos, api) = Repos::memory_with_api(store, artifacts);
    let tenant = tenant_id_for("acme");
    let evidence_run = crawlx_storage::testkit::crawl_run(
        tenant,
        crawlx_storage::testkit::create_crawl("https://shop.example.test", &[], 1),
    );
    repos.runs.create(&evidence_run, None).await.unwrap();
    let evidence = repos
        .artifacts
        .put_evidence(evidence_run.id, b"signed fixture scope letter")
        .await
        .unwrap();
    let probe = Arc::new(StaticProbe::new());
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        operator_keys: keys,
        ownership_probe: Some(probe.clone()),
        ..ApiConfig::default()
    };
    let state = AppState::builder(repos, AdmissionPolicy::new(clock.clone()), config)
        .clock(clock)
        .zdr_buffer(zdr)
        .build();
    let router = crawlx_api::router(state);
    let key = generate_key();
    let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
    crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Api {
        base,
        key,
        tenant,
        evidence,
        probe,
        task,
    }
}

impl Api {
    fn record(&self, origins: &[&str]) -> AuthorizationRecord {
        let mut record = record(self.tenant, origins);
        record.evidence.artifact_id = Some(self.evidence.id);
        record.evidence.digest = self.evidence.digest;
        record
    }

    /// `crawlx authz ARGS --api-url BASE`, the key given by flag.
    async fn authz(&self, args: &[&str]) -> Output {
        let mut argv = vec!["authz"];
        argv.extend_from_slice(args);
        argv.extend_from_slice(&["--api-url", &self.base, "--api-key", &self.key]);
        crawlx(&argv, &[]).await
    }
}

fn error_envelope(o: &Output) -> Value {
    assert_eq!(o.status.code(), Some(1), "stdout: {}\nstderr: {}", out(o), err(o));
    assert!(out(o).is_empty(), "an error prints nothing on stdout: {}", out(o));
    serde_json::from_str(&err(o))
        .unwrap_or_else(|e| panic!("stderr is not the error envelope ({e}): {}", err(o)))
}

#[tokio::test]
async fn create_show_verify_and_revoke_a_dns_proven_record() {
    let api = start_api(OperatorKeys::new()).await;
    let dir = tempfile::tempdir().unwrap();
    let rec = api.record(&["https://shop.example.test"]);
    let rec = AuthorizationRecord {
        ownership: Some(OwnershipProof::DnsTxt {}),
        ..rec
    };
    let id = rec.id.to_string();
    // the API fills in the tenant of the key
    let mut body = serde_json::to_value(&rec).unwrap();
    body.as_object_mut().unwrap().remove("tenant");
    let file = write(dir.path(), "record.json", &body.to_string());
    api.probe.set_txt("_crawlx-authz.shop.example.test", &[&id]);

    let o = api.authz(&["create", "--record", s(&file)]).await;
    let created = json_out(&o);
    assert_eq!(created["record"]["id"], id.as_str());
    assert_eq!(created["record"]["tenant"], api.tenant.to_string().as_str());
    assert_eq!(created["status"], "active");
    assert!(created["record"]["verifiedAt"].is_string(), "{created}");
    assert_eq!(created["verification"]["kind"], "dns_txt");
    let digest = created["bodyDigest"].as_str().unwrap().to_owned();
    assert!(!digest.is_empty());
    assert!(
        !out(&o).contains(&api.key) && !err(&o).contains(&api.key),
        "the key is never printed"
    );

    // creating it again is idempotent: same record, same digest
    let again = json_out(&api.authz(&["create", "--record", s(&file)]).await);
    assert_eq!(again["bodyDigest"], digest.as_str());

    // show: the stored record
    let shown = json_out(&api.authz(&["show", &id]).await);
    assert_eq!(shown["record"]["id"], id.as_str());
    assert_eq!(shown["bodyDigest"], digest.as_str());
    assert_eq!(shown["status"], "active");

    // verify probes DNS again
    let before = api.probe.queries().len();
    let verified = json_out(&api.authz(&["verify", &id]).await);
    assert_eq!(verified["status"], "active");
    assert!(api.probe.queries().len() > before, "verify re-ran the DNS check");

    // revoke: the record shows revoked with the reason; a second call returns the first revocation
    let revoked = json_out(&api.authz(&["revoke", &id, "--reason", "engagement ended"]).await);
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["record"]["revokedReason"], "engagement ended");
    let first_at = revoked["record"]["revokedAt"].clone();
    assert!(first_at.is_string());
    let second = json_out(&api.authz(&["revoke", &id, "--reason", "something else"]).await);
    assert_eq!(second["record"]["revokedAt"], first_at);
    assert_eq!(second["record"]["revokedReason"], "engagement ended");
    assert_eq!(json_out(&api.authz(&["show", &id]).await)["status"], "revoked");

    // a revoked record cannot be verified again: the envelope is on stderr, exit 1
    let o = api.authz(&["verify", &id]).await;
    let envelope = error_envelope(&o);
    assert_eq!(envelope["error"]["code"], "invalid_state", "{envelope}");
}

#[tokio::test]
async fn failures_exit_one_with_the_error_envelope_on_stderr() {
    let api = start_api(OperatorKeys::new()).await;
    let dir = tempfile::tempdir().unwrap();

    // no proof published: 422 ownership_unverified naming the host
    let rec = AuthorizationRecord {
        ownership: Some(OwnershipProof::DnsTxt {}),
        ..api.record(&["https://unproven.example.test"])
    };
    let file = record_file(dir.path(), "unproven.json", &rec);
    let envelope = error_envelope(&api.authz(&["create", "--record", s(&file)]).await);
    assert_eq!(envelope["error"]["code"], "ownership_unverified", "{envelope}");
    assert!(
        envelope.to_string().contains("unproven.example.test"),
        "{envelope}"
    );
    assert!(envelope["error"]["requestId"].is_string());

    // an unknown field is refused with the serde message
    let mut v = serde_json::to_value(&rec).unwrap();
    v["surprise"] = json!(1);
    let file = write(dir.path(), "unknown.json", &v.to_string());
    let envelope = error_envelope(&api.authz(&["create", "--record", s(&file)]).await);
    assert_eq!(envelope["error"]["code"], "invalid_request", "{envelope}");
    assert!(envelope.to_string().contains("surprise"), "{envelope}");

    // an unknown record is a 404
    let envelope = error_envelope(&api.authz(&["show", &TenantId::new().to_string()]).await);
    assert_eq!(envelope["error"]["code"], "not_found", "{envelope}");

    // no key: 401, still the envelope
    let o = crawlx(
        &[
            "authz",
            "show",
            &TenantId::new().to_string(),
            "--api-url",
            &api.base,
        ],
        &[],
    )
    .await;
    let envelope = error_envelope(&o);
    assert!(envelope["error"]["code"].is_string(), "{envelope}");

    // the URL and the key come from the environment too
    let o = crawlx(
        &["authz", "show", &TenantId::new().to_string()],
        &[("CRAWLX_API_URL", &api.base), ("CRAWLX_API_KEY", &api.key)],
    )
    .await;
    assert_eq!(error_envelope(&o)["error"]["code"], "not_found");
    assert!(!err(&o).contains(&api.key));

    // a record that does not parse as JSON and an id that is not a UUID fail before any request
    let junk = write(dir.path(), "junk.json", "{not json");
    let o = api.authz(&["create", "--record", s(&junk)]).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("junk.json"), "{}", err(&o));
    let o = api.authz(&["show", "not-a-uuid"]).await;
    assert_eq!(o.status.code(), Some(2));

    // an API that is not there: a transport error that does not print the key
    let o = crawlx(
        &[
            "authz",
            "show",
            &TenantId::new().to_string(),
            "--api-url",
            "http://127.0.0.1:9",
            "--api-key",
            "cx_live_secret_value",
        ],
        &[],
    )
    .await;
    assert_eq!(o.status.code(), Some(2));
    assert!(err(&o).contains("cannot reach the crawlx API"), "{}", err(&o));
    assert!(!err(&o).contains("cx_live_secret_value"));
}

#[tokio::test]
async fn an_operator_signed_record_from_sign_is_created_and_a_tampered_one_is_not() {
    let keys_text = format!("op1 {KEY_HEX}\n");
    let api = start_api(OperatorKeys::parse(&keys_text).unwrap()).await;
    let dir = tempfile::tempdir().unwrap();
    let keys = write(dir.path(), "keys", &keys_text);

    // sign, then create: the API holds the same key
    let rec = AuthorizationRecord {
        authorized_networks: vec!["10.20.0.0/16".parse().unwrap()],
        ownership: Some(OwnershipProof::OperatorSignature {
            key_id: "op1".to_owned(),
            signature: String::new(),
        }),
        ..api.record(&["http://10.20.0.5:8090"])
    };
    let unsigned = record_file(dir.path(), "unsigned.json", &rec);
    let signed = dir.path().join("signed.json");
    let o = crawlx(
        &[
            "authz",
            "sign",
            "--record",
            s(&unsigned),
            "--key-id",
            "op1",
            "--key-file",
            s(&keys),
            "--out",
            s(&signed),
        ],
        &[],
    )
    .await;
    assert!(o.status.success(), "{}", err(&o));
    let created = json_out(&api.authz(&["create", "--record", s(&signed)]).await);
    assert_eq!(created["status"], "active");
    assert_eq!(created["verification"]["kind"], "operator_signature", "{created}");
    assert_eq!(created["record"]["ownership"]["kind"], "operator_signature");
    assert_eq!(created["record"]["authorizedNetworks"][0], "10.20.0.0/16");

    // a record that was never signed (empty signature, a fresh id) does not verify
    let never_signed = record_file(
        dir.path(),
        "never-signed.json",
        &AuthorizationRecord {
            id: crawlx_core::AuthorizationRecordId::new(),
            ..rec.clone()
        },
    );
    let envelope = error_envelope(&api.authz(&["create", "--record", s(&never_signed)]).await);
    assert_eq!(envelope["error"]["code"], "ownership_unverified", "{envelope}");

    // a signature edited after signing no longer matches the record
    let other = AuthorizationRecord {
        id: crawlx_core::AuthorizationRecordId::new(),
        ..rec
    };
    let other_file = record_file(dir.path(), "other.json", &other);
    let other_signed = dir.path().join("other-signed.json");
    let o = crawlx(
        &[
            "authz",
            "sign",
            "--record",
            s(&other_file),
            "--key-id",
            "op1",
            "--key-file",
            s(&keys),
            "--out",
            s(&other_signed),
        ],
        &[],
    )
    .await;
    assert!(o.status.success(), "{}", err(&o));
    let mut v: Value = serde_json::from_slice(&std::fs::read(&other_signed).unwrap()).unwrap();
    v["emergencyContact"] = json!("+1 555 0199");
    let tampered = write(dir.path(), "tampered.json", &v.to_string());
    let envelope = error_envelope(&api.authz(&["create", "--record", s(&tampered)]).await);
    assert_eq!(envelope["error"]["code"], "ownership_unverified", "{envelope}");
}
