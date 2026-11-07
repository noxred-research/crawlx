#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{governor::GovernorConfig, resolver::StaticResolver};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

#[derive(Clone, Copy)]
enum Case {
    Normal,
    Audience,
    Nonce,
    Tenant,
    Schema,
    MissingFinal,
    Hang,
    Bounce,
    WrongKey,
    PrivatePeer,
}
fn pem_bytes(pem: &str) -> Vec<u8> {
    STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .unwrap()
}
fn registration(endpoint: Url) -> ServiceRegistration {
    serde_json::from_value(json!({
        "endpoint":endpoint, "audience":"local-acquisition", "approvalDigest":"a".repeat(64),
        "credentialRef":"env://FIXTURE_SERVICE_TOKEN", "policyDigests":["fixture-policy-v1"],
        "capabilities":{"schemaVersion":1,"schemes":["https","ftp","sftp"],
            "capabilities":["ftp_passive_pinned","sftp_key_pinned","shared_origin_admission","read_only_effects","secret_free_response"],"maxBytes":4096,
            "deadlineEnforced":true,"checkedEgress":true,"identityIsolation":true,"zeroRetention":true,
            "buildDigest":"b".repeat(64),
            "bodyStreaming":true,"redirects":true,"subresourceEnforcement":true,"cancellation":true,"browserBuild":null},
        "sftpHostKeys":{"target.invalid":"SHA256:fixture-pinned-key"},"whoisRegistries":[],
        "targetCredentialRefs":{"sftp://target.invalid":["vault://fixture/ssh-key"]},
        "originAdmissionRef":"fixture-shared-network-broker-v1",
        "caPem":include_str!("../../tests/fixtures/proxy-ca.crt"), "serviceNetworks":["127.0.0.1/32"]
    })).unwrap()
}
fn route(scheme: &str) -> ProtocolRouteV1 {
    serde_json::from_value(json!({"id":"fixture", "schemes":[scheme],"origin":null,"pathPattern":null,
        "schedulerMetadata":{},"backend":"delegate","delegateId":"fixture-service",
        "requiredCapabilities":[],"maxBodyBytes":4096,"maxElapsedMs":1000,"policyRevision":"fixture-policy-v1"})).unwrap()
}
fn scope() -> DelegateScope {
    DelegateScope {
        tenant: "tenant-a".into(),
        run: "run-a".into(),
        attempt: "attempt-a".into(),
        policy_digest: "fixture-policy-v1".into(),
        external_processing_approved: true,
        zdr: true,
    }
}
fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with("localhost", ["127.0.0.1".parse().unwrap()])
        .with("target.invalid", ["93.184.216.34".parse().unwrap()])
}
fn policy() -> EgressPolicy {
    let mut policy = EgressPolicy::new(false);
    policy.extra_ports = vec![21, 22, 5000];
    policy
}
async fn fixture(case: Case) -> (ServiceAdapter, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cert = CertificateDer::from(pem_bytes(include_str!("../../tests/fixtures/proxy-leaf.crt")));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pem_bytes(include_str!(
        "../../tests/fixtures/proxy-leaf.key"
    ))));
    let provider = rustls::crypto::ring::default_provider();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 16_384);
            if bytes.ends_with(b"\r\n\r\n") {
                break bytes.len();
            }
        };
        let headers = String::from_utf8(bytes.clone()).unwrap();
        assert!(headers
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-scoped-secret"));
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(length < 16_384);
        bytes.resize(header_end + length, 0);
        stream.read_exact(&mut bytes[header_end..]).await.unwrap();
        let mut request: Value = serde_json::from_slice(&bytes[header_end..]).unwrap();
        assert_eq!(request["audience"], "local-acquisition");
        assert_eq!(request["schemaVersion"], 1);
        assert_eq!(request["scope"]["tenant"], "tenant-a");
        assert!(request.get("storageCredentials").is_none());
        assert_eq!(request["allowBrowserWrites"], false);
        let ticket = request["ticket"].as_str().unwrap().to_owned();
        request["ticket"] = json!("");
        request.sort_all_objects();
        let signed = serde_json::to_vec(&request).unwrap();
        let expected = blake3::keyed_hash(blake3::hash(b"fixture-scoped-secret").as_bytes(), &signed)
            .to_hex()
            .to_string();
        assert_eq!(ticket, expected);
        if matches!(case, Case::Hang) {
            std::future::pending::<()>().await;
        }
        let target = request["target"].as_str().unwrap();
        let is_sftp = target.starts_with("sftp:");
        let mut response = json!({"schemaVersion":1,"audience":request["audience"],"nonce":request["nonce"],
            "idempotencyKey":request["idempotencyKey"],"tenant":request["scope"]["tenant"],"run":request["scope"]["run"],
            "attempt":request["scope"]["attempt"],"buildDigest":"b".repeat(64),"finalUrl":target,
            "targetStatus":if target.starts_with("https:") {json!(403)} else {Value::Null},
            "mediaType":"text/html","bodyBase64":STANDARD.encode(b"<html>denied fixture-scoped-secret</html>"),
            "peers":[{"host":"target.invalid","ip":"93.184.216.34","port":if is_sftp {22} else if target.starts_with("ftp:") {21} else {443},"ftpData":false}],
            "sftpHostKey":if is_sftp {json!("SHA256:fixture-pinned-key")} else {Value::Null},
            "redactionPolicyDigest":request["scope"]["policyDigest"],
            "leaseCompleted":true,"bodyComplete":true,"networkRequests":1});
        match case {
            Case::Audience => response["audience"] = json!("another-service"),
            Case::Nonce => response["nonce"] = json!("replayed-nonce"),
            Case::Tenant => response["tenant"] = json!("tenant-b"),
            Case::Schema => response["schemaVersion"] = json!(2),
            Case::MissingFinal => response["finalUrl"] = Value::Null,
            Case::Bounce => {
                response["peers"][0]["ftpData"] = json!(true);
                response["peers"][0]["ip"] = json!("8.8.8.8");
            }
            Case::WrongKey => response["sftpHostKey"] = json!("SHA256:wrong-key"),
            Case::PrivatePeer => response["peers"][0]["ip"] = json!("169.254.169.254"),
            Case::Normal | Case::Hang => {}
        }
        let body = serde_json::to_vec(&response).unwrap();
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let adapter = ServiceAdapter::new(
        registration(Url::parse(&format!("https://localhost:{port}/acquire")).unwrap()),
        SecretOr::secret("fixture-scoped-secret".to_owned()),
    )
    .unwrap();
    (adapter, task)
}
async fn call(adapter: &ServiceAdapter, scheme: &str) -> Result<ProtocolResource, ProtocolError> {
    let target = Url::parse(&format!("{scheme}://target.invalid/document")).unwrap();
    adapter
        .acquire(
            &route(scheme),
            &target,
            &scope(),
            &[],
            64,
            &policy(),
            &resolver(),
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            &CancellationToken::new(),
        )
        .await
}
#[tokio::test]
async fn gateway_200_keeps_target_403_and_missing_final_unavailable() {
    for case in [Case::Normal, Case::MissingFinal] {
        let (adapter, task) = fixture(case).await;
        let result = call(&adapter, "https").await.unwrap();
        assert_eq!(result.gateway_status, Some(200));
        assert_eq!(result.target_status, Some(403));
        assert_eq!(result.final_url.is_none(), matches!(case, Case::MissingFinal));
        assert!(!String::from_utf8_lossy(&result.body).contains("fixture-scoped-secret"));
        task.await.unwrap();
        assert!(matches!(
            call(&adapter, "https").await,
            Err(ProtocolError::Refused("attempt replay or nonce window full"))
        ));
    }
}
#[tokio::test]
async fn local_service_refuses_wrong_scope_nonce_schema_and_protocol_attestation() {
    for (case, scheme) in [
        (Case::Audience, "https"),
        (Case::Nonce, "https"),
        (Case::Tenant, "https"),
        (Case::Schema, "https"),
        (Case::Bounce, "ftp"),
        (Case::WrongKey, "sftp"),
        (Case::PrivatePeer, "https"),
    ] {
        let (adapter, task) = fixture(case).await;
        let expected = match case {
            Case::Bounce => "FTP passive bounce",
            Case::WrongKey => "SFTP host key mismatch",
            Case::PrivatePeer => "service target peer policy",
            _ => "service response scope, schema or evidence",
        };
        assert!(
            matches!(call(&adapter, scheme).await, Err(ProtocolError::Refused(reason)) if reason == expected)
        );
        task.await.unwrap();
    }
}
#[tokio::test]
async fn cancellation_releases_local_call_without_claiming_remote_ack() {
    let (adapter, task) = fixture(Case::Hang).await;
    let token = CancellationToken::new();
    let signal = token.clone();
    let cancel_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        signal.cancel();
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        adapter.acquire(
            &route("https"),
            &Url::parse("https://target.invalid/a").unwrap(),
            &scope(),
            &[],
            64,
            &policy(),
            &resolver(),
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            &token,
        ),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(ProtocolError::Cancelled)));
    cancel_task.await.unwrap();
    task.abort();
    let _ = task.await;
}
#[tokio::test]
async fn private_target_dns_refused_before_service_socket() {
    let registration = registration(Url::parse("https://localhost:9/acquire").unwrap());
    let adapter =
        ServiceAdapter::new(registration, SecretOr::secret("fixture-scoped-secret".to_owned())).unwrap();
    let resolver = StaticResolver::new().with("target.invalid", ["169.254.169.254".parse().unwrap()]);
    let result = adapter
        .acquire(
            &route("https"),
            &Url::parse("https://target.invalid/a").unwrap(),
            &scope(),
            &[],
            64,
            &policy(),
            &resolver,
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            &CancellationToken::new(),
        )
        .await;
    assert!(matches!(result, Err(ProtocolError::Refused("target DNS policy"))));
}

#[tokio::test]
async fn unavailable_capability_and_cross_origin_credential_refs_fail_before_dns() {
    let adapter = ServiceAdapter::new(
        registration(Url::parse("https://localhost:9/acquire").unwrap()),
        SecretOr::secret("fixture-scoped-secret".to_owned()),
    )
    .unwrap();
    let resolver = StaticResolver::new();
    let target = Url::parse("https://target.invalid/a").unwrap();
    let mut required = route("https");
    required.required_capabilities.insert("raw_cdp".to_owned());
    let result = adapter
        .acquire(
            &required,
            &target,
            &scope(),
            &[],
            64,
            &policy(),
            &resolver,
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            &CancellationToken::new(),
        )
        .await;
    assert!(matches!(result, Err(ProtocolError::CapabilityUnavailable(_))));
    let ssh_reference = [CredentialRef("vault://fixture/ssh-key".to_owned())];
    let result = adapter
        .acquire(
            &route("https"),
            &target,
            &scope(),
            &ssh_reference,
            64,
            &policy(),
            &resolver,
            &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            &CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        result,
        Err(ProtocolError::Refused(
            "credential reference outside approved target scope"
        ))
    ));
}
