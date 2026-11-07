//! `crawlx serve` wires the deployment lists and the operator keys (RB-10
//! step 5): the real binary, the real HTTP API on a loopback port, files named by the
//! environment. An operator-signed record is accepted (the keys file reached the API), a seed on
//! the operator blocklist is refused at admission, and a host added to the blocklist file is
//! refused from the next request after `SIGHUP`, without a restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::generate_key;
use crawlx_core::{hash::Digest, Clock, SystemClock};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AuthorizationRecord, OwnershipProof};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const KEY_HEX: &str = "ffeeddccbbaa99887766554433221100";

/// The child process, killed when the test ends.
struct Serve {
    child: Child,
    base: String,
    log: std::path::PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn crawlx() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    for var in [
        "CRAWLX_API_URL",
        "CRAWLX_API_KEY",
        "CRAWLX_CONFIG",
        "CRAWLX_DATABASE_URL",
        "CRAWLX_DATABASE_URL_FILE",
        "CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE",
        "CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE",
        "CRAWLX_AUTHZ_OPERATOR_KEYS_FILE",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("NO_COLOR", "1");
    cmd
}

async fn start(dir: &Path, key: &str, env: &[(&str, &Path)]) -> Serve {
    let port = free_loopback_port();
    let log = dir.join("serve.log");
    let mut cmd = crawlx();
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd
        .args([
            "serve",
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--api-key",
            &format!("acme={key}"),
        ])
        .arg("--artifacts-dir")
        .arg(dir.join("artifacts"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let mut serve = Serve {
        child,
        base: format!("http://127.0.0.1:{port}"),
        log,
    };
    for _ in 0..400 {
        if let Some(status) = serve.child.try_wait().unwrap() {
            panic!(
                "crawlx serve exited early ({status}): {}",
                std::fs::read_to_string(&serve.log).unwrap()
            );
        }
        if let Ok(r) = reqwest::get(format!("{}/v0/health/liveness", serve.base)).await {
            if r.status().is_success() {
                return serve;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "crawlx serve did not come up: {}",
        std::fs::read_to_string(&serve.log).unwrap()
    );
}

async fn create_crawl(serve: &Serve, key: &str, seed: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}/v1/crawls", serve.base))
        .bearer_auth(key)
        .json(&json!({ "seedUrl": seed, "mode": "static", "limits": { "urls": 1 } }))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

fn sighup(serve: &Serve) {
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(serve.child.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
}

fn authz(serve: &Serve, key: &str, args: &[&str]) -> std::process::Output {
    crawlx()
        .arg("authz")
        .args(args)
        .args(["--api-url", &serve.base, "--api-key", key])
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_loads_the_operator_keys_and_reloads_the_blocklist_on_sighup() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let keys = dir.path().join("operator-keys");
    std::fs::write(&keys, format!("# operator keys\nop1 {KEY_HEX}\n")).unwrap();
    let block = dir.path().join("blocklist.txt");
    std::fs::write(&block, "# takedown requests\nblocked-at-start.test\n").unwrap();
    let serve = start(
        dir.path(),
        &key,
        &[
            ("CRAWLX_AUTHZ_OPERATOR_KEYS_FILE", &keys),
            ("CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE", &block),
        ],
    )
    .await;

    // Store real evidence through the running API before signing its artifact reference.
    let (status, run) = create_crawl(&serve, &key, "https://www.evidence.test/").await;
    assert!((200..300).contains(&status), "{status} {run}");
    let document = "owner supplied scope letter for the operator-key serve test";
    let response = reqwest::Client::new()
        .post(format!("{}/v1/authorizations/evidence", serve.base))
        .bearer_auth(&key)
        .json(&json!({ "runId": run["id"], "document": document }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let evidence: Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::CREATED, "{evidence}");
    let digest = Digest::of("crawlx/artifact/v1", document.as_bytes());
    assert_eq!(evidence["digest"], serde_json::to_value(digest).unwrap());

    // The signature covers `tenant`, so use the tenant of bootstrap key `acme`.
    let tenant = crawlx_api::auth::tenant_id_for("acme");
    let mut record = AuthorizationRecord {
        authorized_networks: vec!["10.20.0.0/16".parse().unwrap()],
        ownership: Some(OwnershipProof::OperatorSignature {
            key_id: "op1".to_owned(),
            signature: String::new(),
        }),
        ..sample_record(tenant, SystemClock.now(), &["http://10.20.0.5:8090"])
    };
    record.evidence.artifact_id = Some(serde_json::from_value(evidence["artifactId"].clone()).unwrap());
    record.evidence.digest = digest;
    // The operator keys reached the API: a record signed with `op1` is created.
    let unsigned = dir.path().join("record.json");
    std::fs::write(&unsigned, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let signed = dir.path().join("signed.json");
    let o = crawlx()
        .args(["authz", "sign", "--record"])
        .arg(&unsigned)
        .args(["--key-id", "op1", "--key-file"])
        .arg(&keys)
        .arg("--out")
        .arg(&signed)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = authz(&serve, &key, &["create", "--record", signed.to_str().unwrap()]);
    assert!(
        o.status.success(),
        "create: {}\nserve log: {}",
        String::from_utf8_lossy(&o.stderr),
        std::fs::read_to_string(&serve.log).unwrap()
    );
    let created: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(created["status"], "active");
    assert_eq!(created["verification"]["kind"], "operator_signature");

    // the blocklist file reached admission: a seed on it is refused with url_denied
    let (status, body) = create_crawl(&serve, &key, "https://www.blocked-at-start.test/").await;
    assert_eq!(status, 422, "{body}");
    assert!(body.to_string().contains("url_denied"), "{body}");
    assert!(body.to_string().contains("operator_blocklist"), "{body}");

    // a host that is not listed yet is admitted
    let (status, body) = create_crawl(&serve, &key, "https://www.later.test/").await;
    assert!((200..300).contains(&status), "{status} {body}");

    // RB-10 step 5: the origin joins the file; SIGHUP applies it without a restart
    std::fs::write(&block, "# takedown requests\nblocked-at-start.test\nlater.test\n").unwrap();
    sighup(&serve);
    let mut refused = false;
    for _ in 0..200 {
        let (status, body) = create_crawl(&serve, &key, "https://www.later.test/").await;
        if status == 422 && body.to_string().contains("operator_blocklist") {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        refused,
        "SIGHUP did not reach admission; serve log: {}",
        std::fs::read_to_string(&serve.log).unwrap()
    );

    // a malformed file keeps the lists in force (the old entries still apply) and the API keeps serving
    std::fs::write(&block, "later.test\nnot a host\n").unwrap();
    sighup(&serve);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (status, body) = create_crawl(&serve, &key, "https://www.later.test/").await;
    assert_eq!(status, 422, "{body}");
    let (status, _) = create_crawl(&serve, &key, "https://www.blocked-at-start.test/").await;
    assert_eq!(status, 422, "the previous snapshot stays in force");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_refuses_to_start_with_a_list_file_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let port = free_loopback_port();
    let bad = dir.path().join("block.txt");
    std::fs::write(&bad, "ok.test\nnot a host\n").unwrap();
    for (var, path) in [
        ("CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE", bad.clone()),
        (
            "CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE",
            dir.path().join("missing.txt"),
        ),
        ("CRAWLX_AUTHZ_OPERATOR_KEYS_FILE", dir.path().join("missing-keys")),
    ] {
        let o = crawlx()
            .env(var, &path)
            .args([
                "serve",
                "--bind",
                &format!("127.0.0.1:{port}"),
                "--api-key",
                &format!("acme={key}"),
            ])
            .output()
            .unwrap();
        assert_eq!(
            o.status.code(),
            Some(2),
            "{var}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let stderr = String::from_utf8_lossy(&o.stderr);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(stderr.contains(name), "{var}: {stderr}");
    }
}
