//! Local TLS contracts for distinct, authenticated HTML acquisition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::{engine::general_purpose::STANDARD, Engine};
use crawlx_core::{
    acquisition::UrlEvidenceV1,
    hash::Digest,
    secret::{CredentialRef, SecretOr},
    CrawlRunId, SessionId, TenantId,
};
use crawlx_fetch::{
    acquisition_service::{
        AcquisitionServiceAdapter, AcquisitionServiceError, AcquisitionServiceRegistrationV1,
        AcquisitionServiceScopeV1,
    },
    governor::{GovernorConfig, Origin, OriginGovernor},
    StaticResolver,
};
use crawlx_policy::egress::EgressPolicy;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    future::{poll_fn, Future},
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};
use tokio_util::sync::CancellationToken;
use url::Url;

const CREDENTIAL: &str = "fixture-scoped-secret-123456";
const TARGET_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const LEASE: Duration = Duration::from_secs(5);
type Edit = Arc<dyn Fn(&mut Value) + Send + Sync>;

enum Reply {
    Echo(Edit),
    Raw(Vec<u8>),
    StreamOverflow,
    Hanging,
}

struct Fixture {
    endpoint: Url,
    requests: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<Value>>>,
    body_started: Arc<Semaphore>,
    disconnected: Arc<Semaphore>,
    task: JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn echo(edit: impl Fn(&mut Value) + Send + Sync + 'static) -> Self {
        Self::start(Reply::Echo(Arc::new(edit))).await
    }

    async fn start(reply: Reply) -> Self {
        let certificates = CertificateDer::pem_slice_iter(include_bytes!("fixtures/proxy-leaf.crt"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/proxy-leaf.key")).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = Url::parse(&format!(
            "https://localhost:{}/acquire",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let body_started = Arc::new(Semaphore::new(0));
        let disconnected = Arc::new(Semaphore::new(0));
        let task = {
            let requests = Arc::clone(&requests);
            let connections = Arc::clone(&connections);
            let captured = Arc::clone(&captured);
            let body_started = Arc::clone(&body_started);
            let disconnected = Arc::clone(&disconnected);
            let reply = Arc::new(reply);
            tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok((tcp, _)) = accepted else { return; };
                            connections.fetch_add(1, Ordering::SeqCst);
                            let acceptor = acceptor.clone();
                            let requests = Arc::clone(&requests);
                            let captured = Arc::clone(&captured);
                            let body_started = Arc::clone(&body_started);
                            let disconnected = Arc::clone(&disconnected);
                            let reply = Arc::clone(&reply);
                            children.spawn(async move {
                                let Ok(mut tls) = acceptor.accept(tcp).await else { return; };
                                let mut received = Vec::new();
                                let mut buffer = [0; 4096];
                                let header_end = loop {
                                    let Ok(n) = tls.read(&mut buffer).await else { return; };
                                    if n == 0 { return; }
                                    received.extend_from_slice(&buffer[..n]);
                                    if let Some(n) = received.windows(4).position(|s| s == b"\r\n\r\n") { break n + 4; }
                                    assert!(received.len() <= 65536);
                                };
                                let headers = std::str::from_utf8(&received[..header_end]).unwrap();
                                assert!(headers.starts_with("POST /acquire HTTP/1.1\r\n"));
                                assert!(headers.to_ascii_lowercase().contains(&format!("authorization: bearer {CREDENTIAL}\r\n")));
                                let length: usize = headers.lines().find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                                }).unwrap();
                                assert!(length <= 65536);
                                while received.len() - header_end < length {
                                    let n = tls.read(&mut buffer).await.unwrap();
                                    if n == 0 { return; }
                                    received.extend_from_slice(&buffer[..n]);
                                }
                                let request: Value = serde_json::from_slice(&received[header_end..header_end + length]).unwrap();
                                requests.fetch_add(1, Ordering::SeqCst);
                                captured.lock().unwrap().push(request.clone());
                                match reply.as_ref() {
                                    Reply::Hanging => {
                                        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n").await.unwrap();
                                        tls.flush().await.unwrap();
                                        body_started.add_permits(1);
                                        let _ = tls.read(&mut buffer).await;
                                        disconnected.add_permits(1);
                                    }
                                    Reply::StreamOverflow => {
                                        tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
                                        let chunk = vec![b'x'; 4096];
                                        for _ in 0..20 {
                                            if tls.write_all(b"1000\r\n").await.is_err()
                                                || tls.write_all(&chunk).await.is_err()
                                                || tls.write_all(b"\r\n").await.is_err() { return; }
                                        }
                                        let _ = tls.write_all(b"0\r\n\r\n").await;
                                    }
                                    reply => {
                                        let body = match reply {
                                            Reply::Raw(bytes) => bytes.clone(),
                                            Reply::Echo(edit) => {
                                                let mut response = echo(&request);
                                                edit(&mut response);
                                                serde_json::to_vec(&response).unwrap()
                                            }
                                            Reply::Hanging | Reply::StreamOverflow => unreachable!(),
                                        };
                                        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                                        let _ = tls.write_all(head.as_bytes()).await;
                                        let _ = tls.write_all(&body).await;
                                        let _ = tls.shutdown().await;
                                    }
                                }
                            });
                        }
                        _ = children.join_next(), if !children.is_empty() => {}
                    }
                }
            })
        };
        Self {
            endpoint,
            requests,
            connections,
            captured,
            body_started,
            disconnected,
            task,
        }
    }

    fn registration(&self) -> AcquisitionServiceRegistrationV1 {
        let mut registration = AcquisitionServiceRegistrationV1::new(
            self.endpoint.clone(),
            "fixture-html-audience".to_owned(),
            digest("build"),
            digest("guard"),
            capabilities(),
            CredentialRef("env://SCOPED_ACQUISITION_FIXTURE".to_owned()),
        );
        registration.ca_pem = Some(include_str!("fixtures/proxy-ca.crt").to_owned());
        registration.service_networks = vec!["127.0.0.1/32".parse().unwrap()];
        registration
    }

    fn adapter(&self) -> AcquisitionServiceAdapter {
        AcquisitionServiceAdapter::new(self.registration(), SecretOr::secret(CREDENTIAL.to_owned())).unwrap()
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn digest(value: &str) -> Digest {
    Digest::of("acquisition-service-fixture", value.as_bytes())
}
fn capabilities() -> BTreeSet<String> {
    [
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
        "zdr_compatible",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn target() -> Url {
    Url::parse("https://target.invalid/page").unwrap()
}
fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with("localhost", [LOOPBACK])
        .with("target.invalid", [TARGET_IP])
}
fn governor() -> OriginGovernor {
    OriginGovernor::new(GovernorConfig {
        base_delay: Duration::ZERO,
        ..GovernorConfig::default()
    })
}
fn scope() -> AcquisitionServiceScopeV1 {
    let mut scope = AcquisitionServiceScopeV1::new(
        TenantId::new(),
        CrawlRunId::new(),
        digest("principal"),
        "attempt-1".to_owned(),
        digest("policy"),
        digest("canonical-request"),
    );
    scope.session = Some(SessionId::new());
    scope.session_generation = Some(7);
    scope.external_processing_approved = true;
    scope
}
fn echo(request: &Value) -> Value {
    let scope = &request["scope"];
    let target = Url::parse(request["target"].as_str().unwrap()).unwrap();
    json!({
        "schemaVersion": 1, "kind": "html_acquisition", "audience": request["audience"],
        "nonce": request["nonce"], "idempotencyKey": request["idempotencyKey"],
        "tenant": scope["tenant"], "run": scope["run"], "session": scope["session"],
        "sessionGeneration": scope["sessionGeneration"], "principal": scope["principal"],
        "attempt": scope["attempt"], "policyDigest": scope["policyDigest"],
        "buildDigest": request["buildDigest"], "guardDigest": request["guardDigest"],
        "capabilities": request["requiredCapabilities"], "leaseCompleted": true, "bodyComplete": true,
        "networkRequests": 1,
        "peers": [{"host": target.host_str().unwrap(), "port": target.port_or_known_default().unwrap(), "ip": request["targetAddresses"][0]}],
        "representation": {"format": "native", "bodyBase64": STANDARD.encode("<html>denied</html>"),
            "targetStatus": 403, "contentType": "text/html", "finalUrl": request["target"]}
    })
}

#[tokio::test]
async fn native_target_403_stays_distinct_from_gateway_200_and_ticket_binds_scope() {
    let fixture = Fixture::echo(|_| {}).await;
    let adapter = fixture.adapter();
    let mut scope = scope();
    scope.zdr = true;
    let result = adapter
        .acquire(
            &scope,
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.body.as_ref(), b"<html>denied</html>");
    assert_eq!(result.metadata.target_status, Some(403));
    assert_eq!(result.metadata.gateway_status, Some(200));
    assert_eq!(result.metadata.tenant, scope.tenant);
    assert_eq!(result.metadata.run, scope.run);
    assert_eq!(result.metadata.request_digest, scope.request_digest);
    assert_eq!(result.metadata.session, scope.session);
    assert_eq!(result.metadata.session_generation, Some(7));
    assert_eq!(result.metadata.final_url, Some(target()));
    assert_eq!(result.metadata.final_url_evidence, UrlEvidenceV1::Declared);
    assert_eq!(result.metadata.backend.backend_id, "acquisition_service");
    assert_eq!(result.metadata.backend.build_digest, Some(digest("build")));
    assert!(result.metadata.backend.browser.is_none());
    assert_eq!(result.network_requests, 1);
    assert_eq!(fixture.request_count(), 1);
    let mut request = fixture.captured.lock().unwrap()[0].clone();
    assert_eq!(request["schemaVersion"], 1);
    assert_eq!(request["kind"], "html_acquisition");
    assert_eq!(request["followRedirects"], false);
    assert_eq!(request["allowSubresources"], false);
    assert_eq!(request["allowBrowserWrites"], false);
    assert_eq!(request["cancelOnDisconnect"], true);
    assert!(request.get("headers").is_none());
    assert!(request.get("credentialRef").is_none());
    assert!(!serde_json::to_string(&request).unwrap().contains(CREDENTIAL));
    let ticket = request["ticket"].as_str().unwrap().to_owned();
    request["ticket"] = json!("");
    request.sort_all_objects();
    assert_eq!(
        ticket,
        Digest::keyed(
            blake3::hash(CREDENTIAL.as_bytes()).as_bytes(),
            "html-acquisition-ticket-v1",
            &serde_json::to_vec(&request).unwrap()
        )
        .to_hex()
    );
    assert!(!format!("{adapter:?} {result:?}").contains(CREDENTIAL));
}

#[tokio::test]
async fn legacy_missing_url_remains_unavailable_and_page_error_preserves_403() {
    let fixture = Fixture::echo(|response| {
        // wire-compat: preserve exact legacy response keys.
        response["representation"] = json!({"format":"legacy", "content":"<html>legacy</html>",
            "pageStatusCode":403, "pageError":"private remote error and credential", "contentType":"text/html"});
    }).await;
    let result = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.metadata.target_status, Some(403));
    assert_eq!(result.metadata.final_url, None);
    assert_eq!(result.metadata.final_url_evidence, UrlEvidenceV1::Unavailable);
    assert_eq!(result.page_error.as_deref(), Some("remote_page_error"));
    assert_eq!(result.body.as_ref(), b"<html>legacy</html>");
}

#[tokio::test]
async fn strict_schema_refuses_malformed_unknown_and_artifact_responses() {
    for raw in [b"not-json".to_vec(), b"{\"schemaVersion\":1}".to_vec()] {
        let fixture = Fixture::start(Reply::Raw(raw)).await;
        let error = fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AcquisitionServiceError::Schema));
    }
    for field in ["unknown", "artifactHandle", "redirects", "subresources"] {
        let fixture = Fixture::echo(move |response| {
            response[field] = json!(CREDENTIAL);
        })
        .await;
        let error = fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, AcquisitionServiceError::Schema));
        assert!(!format!("{error:?} {error}").contains(CREDENTIAL));
    }
    let fixture = Fixture::echo(|response| {
        response["representation"]["unexpected"] = json!(true);
    })
    .await;
    assert!(matches!(
        fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Schema)
    ));
}

#[tokio::test]
async fn every_authenticated_binding_and_completion_fact_is_required() {
    for field in [
        "nonce",
        "audience",
        "idempotencyKey",
        "tenant",
        "run",
        "session",
        "sessionGeneration",
        "principal",
        "attempt",
        "capabilities",
        "guardDigest",
        "buildDigest",
        "policyDigest",
        "schemaVersion",
        "kind",
        "leaseCompleted",
        "bodyComplete",
        "networkRequests",
    ] {
        let fixture = Fixture::echo(move |response| {
            response[field] = match field {
                "tenant" => json!(TenantId::new()),
                "run" => json!(CrawlRunId::new()),
                "session" => json!(SessionId::new()),
                "sessionGeneration" => json!(8),
                "principal" | "guardDigest" | "buildDigest" | "policyDigest" => json!(digest("wrong")),
                "capabilities" => json!(["checked_egress"]),
                "schemaVersion" | "networkRequests" => json!(2),
                "leaseCompleted" | "bodyComplete" => json!(false),
                _ => json!("wrong"),
            };
        })
        .await;
        let error = fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, AcquisitionServiceError::Refused(_)),
            "field {field}: {error:?}"
        );
    }
}

#[tokio::test]
async fn attempt_is_consumed_once_even_after_a_bad_response() {
    let fixture = Fixture::echo(|response| {
        response["nonce"] = json!("wrong");
    })
    .await;
    let adapter = fixture.adapter();
    let scope = scope();
    for expected_replay in [false, true] {
        let error = adapter
            .acquire(
                &scope,
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(matches!(error, AcquisitionServiceError::Replay), expected_replay);
    }
    assert_eq!(fixture.request_count(), 1);
    assert_eq!(fixture.connection_count(), 1);
}

#[tokio::test]
async fn changed_request_digest_cannot_reopen_consumed_attempt() {
    let fixture = Fixture::echo(|_| {}).await;
    let adapter = fixture.adapter();
    let mut scope = scope();
    adapter
        .acquire(
            &scope,
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    scope.request_digest = digest("different-canonical-request");
    assert!(matches!(
        adapter
            .acquire(
                &scope,
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Replay)
    ));
    assert_eq!(fixture.request_count(), 1);
}

#[tokio::test]
async fn bounded_attempt_ledger_does_not_evict_consumed_attempts() {
    let fixture = Fixture::echo(|_| {}).await;
    let adapter = fixture.adapter();
    let mut scope = scope();
    let forbidden = Url::parse("https://127.0.0.1/private").unwrap();
    let policy = EgressPolicy::new(false);
    let resolver = resolver();
    let governor = governor();
    let cancel = CancellationToken::new();
    for ordinal in 0..4096 {
        scope.attempt = format!("ledger-{ordinal}");
        assert!(matches!(
            adapter
                .acquire(&scope, &forbidden, 32, LEASE, &policy, &resolver, &governor, &cancel)
                .await,
            Err(AcquisitionServiceError::Refused(_))
        ));
    }
    scope.attempt = "ledger-new".to_owned();
    assert!(matches!(
        adapter
            .acquire(&scope, &forbidden, 32, LEASE, &policy, &resolver, &governor, &cancel)
            .await,
        Err(AcquisitionServiceError::Replay)
    ));
    scope.attempt = "ledger-0".to_owned();
    assert!(matches!(
        adapter
            .acquire(&scope, &forbidden, 32, LEASE, &policy, &resolver, &governor, &cancel)
            .await,
        Err(AcquisitionServiceError::Replay)
    ));
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn private_final_redirect_and_unapproved_peer_evidence_are_refused() {
    for case in 0..5 {
        let fixture = Fixture::echo(move |response| match case {
            0 => response["representation"]["finalUrl"] = json!("http://127.0.0.1/private"),
            1 => response["peers"][0]["ip"] = json!("127.0.0.1"),
            2 => response["peers"][0]["host"] = json!("other.invalid"),
            3 => response["peers"][0]["port"] = json!(444),
            _ => {
                response["peers"] = json!([]);
            }
        })
        .await;
        assert!(matches!(
            fixture
                .adapter()
                .acquire(
                    &scope(),
                    &target(),
                    4096,
                    LEASE,
                    &EgressPolicy::new(false),
                    &resolver(),
                    &governor(),
                    &CancellationToken::new()
                )
                .await,
            Err(AcquisitionServiceError::Refused(_))
        ));
    }
}

#[tokio::test]
async fn encoded_stream_and_decoded_representations_are_bounded() {
    let fixture = Fixture::start(Reply::StreamOverflow).await;
    assert!(matches!(
        fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                32,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Limit)
    ));
    for legacy in [false, true] {
        let fixture = Fixture::echo(move |response| {
            if legacy {
                // wire-compat: legacy content is already decoded UTF-8.
                response["representation"] = json!({"format":"legacy", "content":"x".repeat(33),
                    "pageStatusCode":200, "pageError":null, "contentType":"text/html"});
            } else {
                response["representation"]["bodyBase64"] = json!(STANDARD.encode(vec![b'x'; 33]));
            }
        })
        .await;
        assert!(matches!(
            fixture
                .adapter()
                .acquire(
                    &scope(),
                    &target(),
                    32,
                    LEASE,
                    &EgressPolicy::new(false),
                    &resolver(),
                    &governor(),
                    &CancellationToken::new()
                )
                .await,
            Err(AcquisitionServiceError::Limit)
        ));
    }
}

#[tokio::test]
async fn decoded_credential_is_masked_before_return() {
    let fixture = Fixture::echo(|response| {
        response["representation"]["bodyBase64"] = json!(STANDARD.encode(format!("<p>{CREDENTIAL}</p>")));
    })
    .await;
    let result = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!std::str::from_utf8(&result.body).unwrap().contains(CREDENTIAL));
    assert!(std::str::from_utf8(&result.body).unwrap().contains("[REDACTED]"));
    assert!(Arc::strong_count(&result.body_permit) >= 2);
    let retained = result.body.clone();
    let permit = Arc::clone(&result.body_permit);
    drop(result);
    assert!(Arc::strong_count(&permit) >= 2);
    drop(retained);
    assert_eq!(Arc::strong_count(&permit), 1);
}

#[tokio::test]
async fn cancellation_closes_running_body_and_refuses_queued_send() {
    let fixture = Fixture::start(Reply::Hanging).await;
    let adapter = Arc::new(fixture.adapter());
    let resolver = Arc::new(resolver());
    let governor = Arc::new(governor());
    let cancel_running = CancellationToken::new();
    let running = {
        let adapter = Arc::clone(&adapter);
        let resolver = Arc::clone(&resolver);
        let governor = Arc::clone(&governor);
        let cancel = cancel_running.clone();
        tokio::spawn(async move {
            adapter
                .acquire(
                    &scope(),
                    &target(),
                    4096,
                    LEASE,
                    &EgressPolicy::new(false),
                    resolver.as_ref(),
                    governor.as_ref(),
                    &cancel,
                )
                .await
        })
    };
    tokio::time::timeout(LEASE, fixture.body_started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let cancel_queued = CancellationToken::new();
    let mut queued_scope = scope();
    queued_scope.attempt = "queued-attempt".to_owned();
    let queued_target = target();
    let queued_policy = EgressPolicy::new(false);
    let mut queued = Box::pin(adapter.acquire(
        &queued_scope,
        &queued_target,
        4096,
        LEASE,
        &queued_policy,
        resolver.as_ref(),
        governor.as_ref(),
        &cancel_queued,
    ));
    poll_fn(|cx| {
        assert!(queued.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    cancel_queued.cancel();
    assert!(matches!(queued.await, Err(AcquisitionServiceError::Cancelled)));
    assert_eq!(fixture.request_count(), 1);
    cancel_running.cancel();
    assert!(matches!(
        running.await.unwrap(),
        Err(AcquisitionServiceError::Cancelled)
    ));
    tokio::time::timeout(LEASE, fixture.disconnected.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(fixture.connection_count(), 1);
}

#[tokio::test]
async fn governor_queue_and_running_body_share_whole_call_deadline() {
    let fixture = Fixture::echo(|_| {}).await;
    let governor = governor();
    let _held = governor
        .acquire(&Origin::new("https://target.invalid"))
        .await
        .unwrap();
    let error = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            Duration::from_millis(20),
            &EgressPolicy::new(false),
            &resolver(),
            &governor,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AcquisitionServiceError::Deadline));
    assert_eq!(fixture.connection_count(), 0);
    let fixture = Fixture::start(Reply::Hanging).await;
    let error = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            Duration::from_millis(200),
            &EgressPolicy::new(false),
            &resolver(),
            &self::governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AcquisitionServiceError::Deadline));
}

#[tokio::test]
async fn external_processing_and_retention_refuse_before_network() {
    let fixture = Fixture::echo(|_| {}).await;
    let mut scope = scope();
    scope.external_processing_approved = false;
    assert!(matches!(
        fixture
            .adapter()
            .acquire(
                &scope,
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Refused(_))
    ));
    scope.external_processing_approved = true;
    scope.zdr = true;
    let mut registration = fixture.registration();
    registration.capabilities.remove("zdr_compatible");
    let adapter =
        AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())).unwrap();
    assert!(matches!(
        adapter
            .acquire(
                &scope,
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Refused(_))
    ));
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn checked_dns_refuses_every_forbidden_answer_without_connecting() {
    let forbidden = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let forbidden_url = Url::parse(&format!(
        "http://target.invalid:{}/private",
        forbidden.local_addr().unwrap().port()
    ))
    .unwrap();
    let fixture = Fixture::echo(|_| {}).await;
    let resolver = resolver();
    resolver.set("target.invalid", [TARGET_IP, LOOPBACK]);
    let policy = EgressPolicy::new(false).with_seed_port(&forbidden_url);
    assert!(matches!(
        fixture
            .adapter()
            .acquire(
                &scope(),
                &forbidden_url,
                4096,
                LEASE,
                &policy,
                &resolver,
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Refused(_))
    ));
    assert_eq!(fixture.connection_count(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), forbidden.accept())
            .await
            .is_err()
    );
    resolver.set("target.invalid", [TARGET_IP]);
    resolver.set("localhost", [LOOPBACK, "169.254.169.254".parse().unwrap()]);
    assert!(matches!(
        fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver,
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Refused(_))
    ));
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn target_permission_does_not_authorize_control_plane_private_networks() {
    let fixture = Fixture::echo(|_| {}).await;
    let mut registration = fixture.registration();
    registration.service_networks.clear();
    let adapter =
        AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())).unwrap();
    assert!(matches!(
        adapter
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(true),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Refused(_))
    ));
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn registration_is_strict_https_scoped_and_complete() {
    let fixture = Fixture::echo(|_| {}).await;
    for endpoint in [
        "http://crawlx-test.invalid/acquire",
        "https://user@crawlx-test.invalid/acquire",
        "https://crawlx-test.invalid/acquire?q=1",
        "https://crawlx-test.invalid/acquire#part",
    ] {
        let mut registration = fixture.registration();
        registration.endpoint = Url::parse(endpoint).unwrap();
        assert!(matches!(
            AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())),
            Err(AcquisitionServiceError::Registration)
        ));
    }
    for missing in capabilities() {
        if missing == "zdr_compatible" {
            continue;
        }
        let mut registration = fixture.registration();
        registration.capabilities.remove(&missing);
        assert!(matches!(
            AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())),
            Err(AcquisitionServiceError::Registration)
        ));
    }
    for concurrency in [0, 33] {
        let mut registration = fixture.registration();
        registration.max_concurrency = concurrency;
        assert!(
            AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())).is_err()
        );
    }
    let mut registration = fixture.registration();
    registration.credential_ref = CredentialRef("unscoped".to_owned());
    assert!(AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())).is_err());
    let raw = json!({"endpoint":fixture.endpoint, "audience":"fixed", "buildDigest":digest("build"),
        "guardDigest":digest("guard"), "capabilities":capabilities(), "credentialRef":"env://SCOPED_FIXTURE",
        "maxConcurrency":1, "unexpected":true});
    assert!(serde_json::from_value::<AcquisitionServiceRegistrationV1>(raw).is_err());
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn native_unknown_url_and_status_are_not_fabricated() {
    let fixture = Fixture::echo(|response| {
        response["representation"]["targetStatus"] = Value::Null;
        response["representation"]["finalUrl"] = Value::Null;
    })
    .await;
    let result = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.metadata.target_status, None);
    assert_eq!(result.metadata.final_url, None);
    assert_eq!(result.metadata.final_url_evidence, UrlEvidenceV1::Unavailable);
    assert!(!result.metadata.transport_succeeded);
}

#[tokio::test]
async fn invalid_native_encoding_status_media_and_duplicate_capabilities_are_refused() {
    for case in 0..6 {
        let fixture = Fixture::echo(move |response| match case {
            0 => response["representation"]["bodyBase64"] = json!("not-base64!"),
            1 => response["representation"]["targetStatus"] = json!(600),
            2 => response["representation"]["contentType"] = json!("text/html\r\ninjected"),
            3 => response["representation"]["contentType"] = json!("x".repeat(257)),
            4 => {
                let capability = response["capabilities"][0].clone();
                response["capabilities"].as_array_mut().unwrap().push(capability);
            }
            _ => {
                let peer = response["peers"][0].clone();
                response["peers"].as_array_mut().unwrap().push(peer);
            }
        })
        .await;
        assert!(fixture
            .adapter()
            .acquire(
                &scope(),
                &target(),
                4096,
                LEASE,
                &EgressPolicy::new(false),
                &resolver(),
                &governor(),
                &CancellationToken::new()
            )
            .await
            .is_err());
    }
}

#[tokio::test]
async fn tls_requires_operator_ca_and_matching_fixture_hostname() {
    let fixture = Fixture::echo(|_| {}).await;
    for wrong_host in [false, true] {
        let mut registration = fixture.registration();
        let resolver = resolver();
        if wrong_host {
            registration
                .endpoint
                .set_host(Some("not-in-fixture.invalid"))
                .unwrap();
            resolver.set("not-in-fixture.invalid", [LOOPBACK]);
        } else {
            registration.ca_pem = None;
        }
        let adapter =
            AcquisitionServiceAdapter::new(registration, SecretOr::secret(CREDENTIAL.to_owned())).unwrap();
        assert!(matches!(
            adapter
                .acquire(
                    &scope(),
                    &target(),
                    4096,
                    LEASE,
                    &EgressPolicy::new(false),
                    &resolver,
                    &governor(),
                    &CancellationToken::new()
                )
                .await,
            Err(AcquisitionServiceError::Transport(_))
        ));
    }
    assert_eq!(fixture.request_count(), 0);
    assert_eq!(fixture.connection_count(), 2);
}

struct PendingResolver;
#[async_trait::async_trait]
impl crawlx_fetch::Resolver for PendingResolver {
    async fn resolve(&self, _: &str) -> Result<Vec<IpAddr>, crawlx_fetch::FetchError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn cancellation_and_deadline_include_injected_dns() {
    let fixture = Fixture::echo(|_| {}).await;
    let adapter = fixture.adapter();
    let scope = scope();
    let target = target();
    let policy = EgressPolicy::new(false);
    let governor = governor();
    let cancel = CancellationToken::new();
    let mut pending = Box::pin(adapter.acquire(
        &scope,
        &target,
        4096,
        LEASE,
        &policy,
        &PendingResolver,
        &governor,
        &cancel,
    ));
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    cancel.cancel();
    assert!(matches!(pending.await, Err(AcquisitionServiceError::Cancelled)));
    let mut second_scope = scope.clone();
    second_scope.attempt = "dns-deadline".to_owned();
    assert!(matches!(
        adapter
            .acquire(
                &second_scope,
                &target,
                4096,
                Duration::from_millis(20),
                &policy,
                &PendingResolver,
                &governor,
                &CancellationToken::new()
            )
            .await,
        Err(AcquisitionServiceError::Deadline)
    ));
    assert_eq!(fixture.connection_count(), 0);
}

#[tokio::test]
async fn target_rate_limit_updates_the_existing_shared_governor() {
    let fixture = Fixture::echo(|response| {
        response["representation"]["targetStatus"] = json!(429);
    })
    .await;
    let governor = OriginGovernor::new(GovernorConfig {
        base_delay: Duration::from_millis(100),
        ..GovernorConfig::default()
    });
    let result = fixture
        .adapter()
        .acquire(
            &scope(),
            &target(),
            4096,
            LEASE,
            &EgressPolicy::new(false),
            &resolver(),
            &governor,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.metadata.target_status, Some(429));
    assert!(governor.cooldown_remaining(&Origin::from_url(&target())) > Duration::ZERO);
    assert_eq!(fixture.request_count(), 1);
}

#[tokio::test]
async fn service_waits_for_the_same_physical_ip_cap_across_distinct_origins() {
    let fixture = Fixture::echo(|_| {}).await;
    let resolver = resolver().with("alias.invalid", [TARGET_IP]);
    let policy = EgressPolicy::new(false);
    let alias = Url::parse("https://alias.invalid/").unwrap();
    let checked = crawlx_fetch::resolver::CheckedResolution::resolve(&resolver, &policy, &alias)
        .await
        .unwrap();
    let governor = OriginGovernor::new(GovernorConfig {
        base_delay: Duration::ZERO,
        global_per_origin_cap: 1,
        ..GovernorConfig::default()
    });
    let held = governor
        .acquire_resolved(&Origin::from_url(&alias), &checked)
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let adapter = fixture.adapter();
    let scope = scope();
    let target = target();
    let mut pending = Box::pin(adapter.acquire(
        &scope, &target, 4096, LEASE, &policy, &resolver, &governor, &cancel,
    ));
    poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(fixture.connection_count(), 0);
    cancel.cancel();
    assert!(matches!(pending.await, Err(AcquisitionServiceError::Cancelled)));
    assert_eq!(fixture.request_count(), 0);
    drop(held);
}
