#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native FTP credential login and bounded directory discovery through the worker registry.

use super::*;
use crawlx_core::{
    error::CoreError,
    secret::{CredentialRef, SecretOr},
};
use crawlx_fetch::{resolver::StaticResolver, GovernorConfig};
use serde_json::json;
use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

const USER: &str = "worker-account";
const PASSWORD: &str = "worker-password-canary";

struct Secrets;

#[async_trait::async_trait]
impl SecretResolver for Secrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        match reference.0.as_str() {
            "env://FTP_USER" => Ok(SecretOr::secret(USER.to_owned())),
            "env://FTP_PASSWORD" => Ok(SecretOr::secret(PASSWORD.to_owned())),
            _ => Err(CoreError::Invalid {
                field: "credential",
                reason: "unavailable".to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Behavior {
    /// Advertise this host in PASV (EPSV is then refused).
    pasv_host: Option<&'static str>,
}

struct Fixture {
    url: Url,
    origin: String,
    policy: EgressPolicy,
    commands: Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

async fn say(control: &mut BufReader<TcpStream>, text: &str) {
    let _ = control
        .get_mut()
        .write_all(format!("{text}\r\n").as_bytes())
        .await;
}

async fn fixture(behavior: Behavior, connections: usize) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.push(port);
    let mut data = Vec::new();
    for _ in 0..6 {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        policy.extra_ports.push(socket.local_addr().unwrap().port());
        data.push(socket);
    }
    let url = Url::parse(&format!("ftp://fixture.test:{port}/")).unwrap();
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&commands);
    let task = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(5), async move {
            let mut data = data.into_iter();
            for _ in 0..connections {
                let (socket, _) = listener.accept().await.unwrap();
                let mut control = BufReader::new(socket);
                say(&mut control, "220 ready").await;
                let mut pending: Option<TcpListener> = None;
                loop {
                    let mut line = String::new();
                    if !matches!(control.read_line(&mut line).await, Ok(count) if count > 0) {
                        break;
                    }
                    let line = line.trim_end().to_owned();
                    seen.lock().unwrap().push(line.clone());
                    let (verb, argument) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                    match (verb, argument) {
                        ("USER", USER) => say(&mut control, "331 password").await,
                        ("USER", other) => say(&mut control, &format!("530 no account {other}")).await,
                        ("PASS", PASSWORD) => say(&mut control, "230 welcome").await,
                        ("PASS", other) => say(&mut control, &format!("530 bad password {other}")).await,
                        ("TYPE", _) => say(&mut control, "200 binary").await,
                        ("EPSV", _) if behavior.pasv_host.is_some() => say(&mut control, "502 no").await,
                        ("EPSV" | "PASV", _) => {
                            let listener = data.next().unwrap();
                            let port = listener.local_addr().unwrap().port();
                            if verb == "EPSV" {
                                say(&mut control, &format!("229 passive (|||{port}|)")).await;
                            } else {
                                let host = behavior.pasv_host.unwrap_or("127.0.0.1").replace('.', ",");
                                say(
                                    &mut control,
                                    &format!("227 passive ({host},{},{})", port / 256, port % 256),
                                )
                                .await;
                            }
                            pending = Some(listener);
                        }
                        ("MLSD" | "RETR", path) => {
                            let payload: &[u8] = match path {
                                "/" => b"type=file; a.txt\r\ntype=dir; docs\r\n",
                                "/docs" => b"type=file; b.txt\r\n",
                                "/a.txt" => b"alpha",
                                _ => b"",
                            };
                            let Some(listener) = pending.take() else {
                                say(&mut control, "550 no passive").await;
                                continue;
                            };
                            let Ok(Ok((mut socket, _))) =
                                tokio::time::timeout(Duration::from_secs(1), listener.accept()).await
                            else {
                                break;
                            };
                            say(&mut control, "150 data").await;
                            socket.write_all(payload).await.unwrap();
                            socket.shutdown().await.unwrap();
                            say(&mut control, "226 done").await;
                        }
                        _ => say(&mut control, "500 unknown").await,
                    }
                }
            }
        })
        .await;
    });
    let origin = crawlx_core::protocol::protocol_origin(&url).unwrap();
    Fixture {
        url,
        origin,
        policy,
        commands,
        task,
    }
}

impl Fixture {
    fn target(&self, path: &str) -> Url {
        self.url.join(path).unwrap()
    }
}

fn route(capabilities: &[&str]) -> ProtocolRouteV1 {
    serde_json::from_value(json!({
        "id":"credentialed-tree", "schemes":["ftp"], "origin":null, "pathPattern":null,
        "schedulerMetadata":{}, "backend":"delegate", "delegateId":"native_ftp",
        "requiredCapabilities":capabilities, "maxBodyBytes":4096, "maxElapsedMs":3000,
        "policyRevision":"fixture-policy"
    }))
    .unwrap()
}

async fn load(
    root: &std::path::Path,
    tenant: TenantId,
    ftp: serde_json::Value,
) -> Result<Arc<ProtocolRegistry>, WorkerError> {
    let path = root.join("registry.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schemaVersion":1, "approvedTenants":[tenant.to_string()], "services":{}, "ftp":ftp
        }))
        .unwrap(),
    )
    .unwrap();
    ProtocolRegistry::from_file(&path, &Secrets).await
}

fn ftp_registration(origin: &str, refs: serde_json::Value) -> serde_json::Value {
    json!({
        "origins":[origin], "policyDigests":["fixture-policy"],
        "credentialRefs":{ origin: refs },
        "recursion":{"maxDepth":2,"maxEntries":16}
    })
}

fn good_refs() -> serde_json::Value {
    json!({"usernameRef":"env://FTP_USER","passwordRef":"env://FTP_PASSWORD"})
}

fn runtime(registry: Arc<ProtocolRegistry>, policy: EgressPolicy) -> ProtocolRuntime {
    ProtocolRuntime {
        registry,
        policy: Arc::new(policy),
        resolver: Arc::new(StaticResolver::new().with("fixture.test", ["127.0.0.1".parse().unwrap()])),
        governor: Arc::new(OriginGovernor::new(GovernorConfig::default())),
    }
}

#[tokio::test]
async fn credentialed_directory_route_walks_within_the_request_allowance_and_hides_secrets() {
    let ftp = fixture(Behavior::default(), 2).await;
    let root = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let registry = load(root.path(), tenant, ftp_registration(&ftp.origin, good_refs()))
        .await
        .unwrap();
    let runtime = runtime(Arc::clone(&registry), ftp.policy.clone());
    let walk = route(&[
        "ftp_passive_pinned",
        "ftp_credential_login",
        "ftp_bounded_recursion",
    ]);
    let directory = ftp.target("/");
    runtime
        .admit(std::slice::from_ref(&walk), run, tenant, &directory, true)
        .unwrap();

    // Capabilities are per-route decisions, never implied by the registry alone.
    for (capabilities, target, label) in [
        (
            &["ftp_passive_pinned", "ftp_bounded_recursion"][..],
            "/",
            "credentialed origin without login capability",
        ),
        (
            &["ftp_passive_pinned", "ftp_credential_login"][..],
            "/",
            "directory without recursion capability",
        ),
        (
            &[
                "ftp_anonymous_file",
                "ftp_credential_login",
                "ftp_bounded_recursion",
            ][..],
            "/",
            "anonymous claim on a credentialed origin",
        ),
        (
            &["ftp_credential_login", "ftp_bounded_recursion"][..],
            "/a%2f..%2f",
            "unsafe path",
        ),
    ] {
        assert!(
            runtime
                .admit(&[route(capabilities)], run, tenant, &ftp.target(target), true)
                .is_err(),
            "{label}"
        );
    }
    assert!(runtime
        .admit(
            std::slice::from_ref(&walk),
            run,
            TenantId::new(),
            &directory,
            true
        )
        .is_err());

    let requests = Arc::new(AtomicU32::new(8));
    let resource = runtime
        .acquire(
            &walk,
            &directory,
            run,
            tenant,
            "attempt",
            true,
            &requests,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        resource.children.iter().map(Url::path).collect::<Vec<_>>(),
        ["/a.txt", "/docs/b.txt"]
    );
    assert!(resource.body.is_empty());
    assert_eq!(resource.network_requests, 2);
    assert_eq!(
        requests.load(Ordering::Acquire),
        6,
        "each listing charges the shared allowance"
    );
    let metadata = resource_metadata(&resource, &walk, &directory, run, tenant);
    assert_eq!(metadata.network_requests, 2);
    assert!(metadata
        .backend
        .limitations
        .iter()
        .any(|item| item == "native_credentialed_ftp_without_http_status"));
    let rendered = format!(
        "{} {resource:?} {registry:?} {}",
        serde_json::to_string(&metadata).unwrap(),
        serde_json::to_string(&capability_report(Some(&registry))).unwrap()
    );
    assert!(
        !rendered.contains(PASSWORD) && !rendered.contains(USER),
        "{rendered}"
    );

    // One request left: the second listing exceeds the allowance, so nothing partial escapes.
    let tight = Arc::new(AtomicU32::new(1));
    assert!(matches!(
        runtime
            .acquire(
                &walk,
                &directory,
                run,
                tenant,
                "tight",
                true,
                &tight,
                &CancellationToken::new()
            )
            .await,
        Err(ProtocolError::Limit)
    ));
    ftp.task.await.unwrap();
    let seen = ftp.commands.lock().unwrap().clone();
    assert_eq!(seen.iter().filter(|c| c.starts_with("PASS")).count(), 2);
    assert_eq!(
        seen.iter().filter(|c| c.starts_with("MLSD")).collect::<Vec<_>>(),
        ["MLSD /", "MLSD /docs", "MLSD /"]
    );
}

#[tokio::test]
async fn credentialed_file_read_and_probe_report_the_login_capability() {
    let ftp = fixture(Behavior::default(), 1).await;
    let root = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let registry = load(root.path(), tenant, ftp_registration(&ftp.origin, good_refs()))
        .await
        .unwrap();
    let runtime = runtime(Arc::clone(&registry), ftp.policy.clone());
    let read = route(&["ftp_passive_pinned", "ftp_credential_login"]);
    let requests = Arc::new(AtomicU32::new(2));
    let file = runtime
        .acquire(
            &read,
            &ftp.target("/a.txt"),
            CrawlRunId::new(),
            tenant,
            "attempt",
            true,
            &requests,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(file.body.as_ref(), b"alpha");
    assert_eq!(file.build_digest, "native-ftp-credential-v1");
    ftp.task.await.unwrap();

    let report = capability_report(Some(&registry));
    for id in [
        "ftp_credential_login",
        "ftp_bounded_recursion",
        "ftp_anonymous_file",
        "ftp_passive_pinned",
    ] {
        assert!(report.delegates[0].capabilities.contains(id), "{id}");
    }
    let anonymous = load(
        root.path(),
        tenant,
        json!({"origins":[ftp.origin],"policyDigests":["fixture-policy"]}),
    )
    .await
    .unwrap();
    let report = capability_report(Some(&anonymous));
    assert!(!report.delegates[0].capabilities.contains("ftp_credential_login"));
    assert!(!report.delegates[0].capabilities.contains("ftp_bounded_recursion"));
}

#[tokio::test]
async fn registry_load_fails_closed_on_unresolvable_or_misplaced_credentials() {
    let root = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let origin = "ftp://fixture.test".to_owned();
    for (refs, registered) in [
        (
            json!({"usernameRef":"env://FTP_MISSING","passwordRef":"env://FTP_PASSWORD"}),
            origin.as_str(),
        ),
        (
            json!({"usernameRef":"env://FTP_USER","passwordRef":"env://FTP_NONE"}),
            origin.as_str(),
        ),
        (good_refs(), "ftp://elsewhere.test"),
        (
            json!({"usernameRef":"literal-user","passwordRef":"env://FTP_PASSWORD"}),
            origin.as_str(),
        ),
    ] {
        let mut ftp = ftp_registration(&origin, refs.clone());
        ftp["credentialRefs"] = json!({ registered: refs });
        let error = load(root.path(), tenant, ftp).await.unwrap_err().to_string();
        for hidden in ["FTP_MISSING", "FTP_NONE", "literal-user", PASSWORD, USER] {
            assert!(!error.contains(hidden), "{error}");
        }
    }
    // A password in the registry file itself is not a field: references only.
    let mut ftp = ftp_registration(&origin, good_refs());
    ftp["credentialRefs"][&origin]["password"] = json!(PASSWORD);
    assert!(load(root.path(), tenant, ftp).await.is_err());
}

#[tokio::test]
async fn off_path_data_peer_is_refused_through_the_runtime_for_credentialed_transfers() {
    let ftp = fixture(
        Behavior {
            pasv_host: Some("127.0.0.2"),
        },
        1,
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let registry = load(root.path(), tenant, ftp_registration(&ftp.origin, good_refs()))
        .await
        .unwrap();
    let runtime = runtime(registry, ftp.policy.clone());
    let walk = route(&["ftp_credential_login", "ftp_bounded_recursion"]);
    let requests = Arc::new(AtomicU32::new(4));
    let error = runtime
        .acquire(
            &walk,
            &ftp.target("/"),
            CrawlRunId::new(),
            tenant,
            "attempt",
            true,
            &requests,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Refused("FTP passive bounce")),
        "{error}"
    );
    assert!(!format!("{error} {error:?}").contains(PASSWORD));
    ftp.task.await.unwrap();
    let seen = ftp.commands.lock().unwrap().clone();
    assert!(
        !seen
            .iter()
            .any(|c| c.starts_with("MLSD") || c.starts_with("RETR")),
        "{seen:?}"
    );
}
