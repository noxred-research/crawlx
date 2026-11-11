//! Real worker requests retain seeded synthetic TLS behavior without claiming browser identity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::tls::TlsImpersonation;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig};
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{version, ProtocolVersion, ServerConfig, SupportedProtocolVersion};
use tokio_rustls::LazyConfigAcceptor;
use url::Url;

const DEADLINE: Duration = Duration::from_secs(20);
const BODY: &str = "<html><title>Worker TLS</title><main><h1>Worker TLS</h1><p>Actual encrypted worker response.</p></main></html>";

fn server_config(version: &'static SupportedProtocolVersion) -> Arc<ServerConfig> {
    // Reuse the fetch crate's local-only certificate, never external PKI or network access.
    let certs =
        CertificateDer::pem_slice_iter(include_bytes!("../../crawlx-fetch/tests/fixtures/selfsigned.crt"))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("../../crawlx-fetch/tests/fixtures/selfsigned.key"))
            .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn serve_one(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    expected_version: ProtocolVersion,
    skip_verification: bool,
) -> Vec<u16> {
    let (stream, peer) = listener.accept().await.unwrap();
    assert!(peer.ip().is_loopback());
    let start = LazyConfigAcceptor::new(Default::default(), stream).await.unwrap();
    let hello = start.client_hello();
    assert_eq!(hello.server_name(), Some("localhost"));
    assert!(hello.alpn().unwrap().any(|protocol| protocol == b"http/1.1"));
    let offered: Vec<u16> = hello.cipher_suites().iter().copied().map(u16::from).collect();
    let mut tls = match start.into_stream(config).await {
        Ok(tls) => {
            assert!(
                skip_verification,
                "worker accepted an untrusted certificate by default"
            );
            tls
        }
        Err(error) => {
            assert!(
                !skip_verification,
                "explicit insecure fixture handshake failed: {error}"
            );
            return offered;
        }
    };
    assert_eq!(tls.get_ref().1.protocol_version(), Some(expected_version));
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
    let negotiated_cipher = u16::from(tls.get_ref().1.negotiated_cipher_suite().unwrap().suite());
    assert!(offered.contains(&negotiated_cipher));
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        assert!(headers.len() < 16_384, "request headers too large");
        headers.push(tls.read_u8().await.unwrap());
    }
    let headers = String::from_utf8(headers).unwrap();
    assert!(headers.starts_with("GET /worker HTTP/1.1\r\n"), "{headers}");
    assert!(
        headers.to_ascii_lowercase().contains("\r\nuser-agent: crawlx/"),
        "{headers}"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    tls.write_all(response.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    offered
}

async fn worker_request(
    mode: TlsImpersonation,
    seed: u64,
    version: &'static SupportedProtocolVersion,
    skip_verification: bool,
) -> Vec<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = Url::parse(&format!(
        "https://localhost:{}/worker",
        listener.local_addr().unwrap().port()
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(target.clone());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(seed);
    crawl.safety.allow_private_networks = true;
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.max_discovery_depth = 0;
    crawl.politeness.delay_ms = 0;
    crawl.fetch.retries = 0;
    crawl.fetch.timeout_ms = 5_000;
    crawl.fetch.tls_impersonation = mode;
    crawl.fetch.skip_tls_verification = skip_verification;
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    // The generic HTTP fixture helper scopes loopback prefixes to HTTP, not this TLS origin.
    record.url_prefixes = vec![target.origin().ascii_serialization()];
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(
                StaticResolver::new().with("localhost", [IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            )),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let local = LocalRun::new(crawl, config)
        .with_stores(stores.clone())
        .with_authorization(record);
    let server = serve_one(
        listener,
        server_config(version),
        version.version,
        skip_verification,
    );
    let (offered, report) =
        tokio::time::timeout(DEADLINE, async { tokio::join!(server, run_local_with(local)) })
            .await
            .unwrap();
    let report = report.unwrap();
    assert_eq!(report.counters.urls.attempted, 1);
    assert!(report.counters.urls.invariants_hold());
    let pages = stores.pages.list(report.run_id).await.unwrap();
    if !skip_verification {
        assert!(pages.is_empty());
        assert_eq!(report.counters.urls.succeeded, 0);
        assert_eq!(report.counters.urls.failed, 0);
        assert_eq!(report.counters.urls.unreachable, 1);
        return offered;
    }
    assert_eq!(report.counters.urls.succeeded, 1);
    assert_eq!(report.counters.urls.failed, 0);
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].title.as_deref(), Some("Worker TLS"));
    let receipt = &pages[0].metadata["acquisition"];
    assert_eq!(receipt["targetStatus"], 200);
    assert_eq!(receipt["transportSucceeded"], true);
    assert_eq!(
        receipt["connection"]["checkedOrigin"],
        target.origin().ascii_serialization()
    );
    assert_eq!(receipt["connection"]["peer"], "127.0.0.1");
    assert_eq!(receipt["connection"]["peerChecked"], true);
    assert_eq!(receipt["connection"]["proxyRoute"], "direct");
    assert_eq!(receipt["connection"]["tlsVerification"], "explicit_insecure");
    // The leaf the server presented is read from the request's own connection; observation is
    // not verification, and the receipt says verification was explicitly skipped.
    assert_eq!(receipt["connection"]["certificateObserved"], true);
    let certificate = &receipt["connection"]["certificate"];
    assert_eq!(
        certificate["sha256"],
        "1bb0682e7256efceefe2d64c65a6af436cfcc6431d967774f1048d71e043d947"
    );
    assert_eq!(certificate["selfIssued"], true);
    assert!(receipt["backend"]["browser"].is_null());
    assert!(receipt["backend"]["buildDigest"].is_null());
    assert!(!receipt["backend"]["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "certificate_evidence_unavailable"));
    let implementation = if mode == TlsImpersonation::Randomized {
        "crawlx-fetch/wreq-boringssl-synthetic"
    } else {
        "crawlx-fetch/reqwest-rustls"
    };
    assert_eq!(receipt["backend"]["implementation"], implementation);
    offered
}

#[tokio::test]
async fn worker_uses_seeded_synthetic_client_hello_for_real_tls12_and_tls13_requests() {
    for version in [&version::TLS12, &version::TLS13] {
        let mut previous = None;
        for seed in [42, 42, 13] {
            let offered = worker_request(TlsImpersonation::Randomized, seed, version, true).await;
            // Verify the wire's seeded cipher order, not merely the worker's chosen config.
            let mut tls12 = [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8];
            tls12.shuffle(&mut CrawlSeed(seed).rng("tls-client-hello-v1", &[]));
            let expected: Vec<u16> = [0x1301, 0x1302, 0x1303].into_iter().chain(tls12).collect();
            assert_eq!(offered, expected, "seed {seed}");
            if seed == 42 {
                if let Some(previous) = previous.as_ref() {
                    assert_eq!(&offered, previous, "same seed must preserve offered cipher order");
                }
                previous = Some(offered);
            }
        }
        let standard = worker_request(TlsImpersonation::Off, 42, version, true).await;
        assert_ne!(
            Some(standard),
            previous,
            "off must retain the default TLS transport"
        );
    }
}

#[tokio::test]
async fn randomized_worker_does_not_silently_disable_certificate_verification() {
    worker_request(TlsImpersonation::Randomized, 42, &version::TLS13, false).await;
}
