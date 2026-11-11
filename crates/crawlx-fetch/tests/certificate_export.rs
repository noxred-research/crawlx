#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The leaf certificate a request observed on its own connection is exported, capped, as DER
//! and PEM, for matching and mismatched host names, over HTTP/2 and HTTP/1.1, and no second
//! socket is ever opened to obtain it.

use bytes::Bytes;
use crawlx_core::config::Fetch;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::tls::TlsImpersonation;
use crawlx_core::traffic::Protocol;
use crawlx_fetch::certificate::{CertificateExport, MAX_CERTIFICATE_BYTES, PEER_CERTIFICATE_HEADER};
use crawlx_fetch::{FetchConfig, FetchOptions, Fetcher, GovernorConfig, RetryPolicy, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest as _, Sha256};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use url::Url;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEADLINE: Duration = Duration::from_secs(10);
/// SHA-256 of `fixtures/selfsigned.crt` (`openssl x509 -fingerprint -sha256`).
const FIXTURE_SHA256: &str = "1bb0682e7256efceefe2d64c65a6af436cfcc6431d967774f1048d71e043d947";
const CERTIFICATE_PEM: &[u8] = include_bytes!("fixtures/selfsigned.crt");

fn acceptor() -> TlsAcceptor {
    let certificates = CertificateDer::pem_slice_iter(CERTIFICATE_PEM)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// Serves every accepted connection with the protocol ALPN selected and counts the accepts.
/// Returns the connections accepted and the protocols negotiated, in order.
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: the in-process TLS/H2 origin serves raw http messages and never crosses a typed fetch boundary"
)]
fn serve(listener: TcpListener) -> (Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let negotiated = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (count, seen) = (Arc::clone(&accepted), Arc::clone(&negotiated));
    let acceptor = acceptor();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .unwrap_or_default();
                seen.lock().unwrap().push(alpn.clone());
                if alpn == "h2" {
                    let service = service_fn(|_| async {
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(http::header::CONTENT_TYPE, "text/plain")
                                .body(Full::new(Bytes::from_static(b"h2 ok")))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                } else {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = tls.read_u8().await else {
                            return;
                        };
                        request.push(byte);
                    }
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nh1 ok")
                        .await;
                    let _ = tls.flush().await;
                }
            });
        }
    });
    (accepted, negotiated)
}

async fn fetcher(mode: TlsImpersonation, host: &str, port: u16, export: bool) -> Fetcher {
    let mut config = FetchConfig {
        tls_impersonation: mode,
        seed: CrawlSeed(7),
        connect_timeout: DEADLINE,
        request_timeout: DEADLINE,
        retry: RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        },
        governor: GovernorConfig {
            base_delay: Duration::ZERO,
            ..GovernorConfig::default()
        },
        ..FetchConfig::default()
    };
    config.controls = RequestControls::resolve(
        &Fetch {
            skip_tls_verification: true,
            ..Fetch::default()
        },
        host,
        None,
    )
    .await
    .unwrap();
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(port);
    let fetcher = Fetcher::new(
        config,
        Arc::new(policy),
        Arc::new(StaticResolver::new().with(host, [LOOPBACK])),
    )
    .unwrap();
    if export {
        fetcher.with_peer_certificate_export()
    } else {
        fetcher
    }
}

fn der() -> Vec<u8> {
    CertificateDer::pem_slice_iter(CERTIFICATE_PEM)
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn matching_and_mismatched_hosts_export_the_same_observed_leaf_on_one_connection() {
    for mode in [TlsImpersonation::Off, TlsImpersonation::Randomized] {
        // `localhost` is in the fixture's names, `mismatch.example.test` is not: a hostname
        // mismatch is exactly the case where verification would refuse, so the facts and the
        // export are only reachable under the explicit insecure mode the receipt records.
        for host in ["localhost", "mismatch.example.test"] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (accepted, negotiated) = serve(listener);
            let client = fetcher(mode, host, port, true).await;
            let target = Url::parse(&format!("https://{host}:{port}/")).unwrap();
            let response = tokio::time::timeout(DEADLINE, client.fetch(&target, &FetchOptions::default()))
                .await
                .unwrap()
                .unwrap();
            let label = format!("{mode:?} {host}");
            assert_eq!(response.status.as_u16(), 200, "{label}");
            let evidence = response.certificate_evidence();
            let facts = evidence
                .observed()
                .unwrap_or_else(|| panic!("{label}: {evidence:?}"));
            assert_eq!(facts.sha256, FIXTURE_SHA256, "{label}");
            let export = response.certificate_export().unwrap_or_else(|| panic!("{label}"));
            assert_eq!(export.der(), der().as_slice(), "{label}");
            assert_eq!(export.sha256(), facts.sha256, "{label}");
            assert_eq!(
                u32::try_from(export.der().len()).unwrap(),
                facts.der_len,
                "{label}"
            );
            // The PEM decodes back to the very DER whose digest the facts carry.
            let pem = export.pem();
            assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{label}");
            assert!(pem.ends_with("-----END CERTIFICATE-----\n"), "{label}");
            assert!(pem.lines().all(|line| line.len() <= 64), "{label}");
            let parsed = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(parsed.as_ref())),
                FIXTURE_SHA256,
                "{label}"
            );
            // The observation is not a second probe: exactly one connection reached the
            // server, no other is pending, and the connection carried this very request.
            assert!(
                tokio::time::timeout(Duration::from_millis(300), async {
                    while accepted.load(Ordering::SeqCst) < 2 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .is_err(),
                "{label}: a second connection was opened"
            );
            assert_eq!(accepted.load(Ordering::SeqCst), 1, "{label}");
            // The protocol on the response is the one the server negotiated, never assumed.
            let alpn = negotiated.lock().unwrap().clone();
            assert_eq!(alpn.len(), 1, "{label}");
            let expected = if alpn[0] == "h2" {
                Protocol::H2
            } else {
                Protocol::Http11
            };
            assert_eq!(response.negotiated_protocol, Some(expected), "{label}");
            assert_eq!(
                response.body.as_ref(),
                if alpn[0] == "h2" { b"h2 ok" } else { b"h1 ok" }
            );
        }
    }
}

#[tokio::test]
async fn randomized_transport_negotiates_h2_and_exports_the_leaf_over_it() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted, negotiated) = serve(listener);
    let client = fetcher(TlsImpersonation::Randomized, "localhost", port, true).await;
    let target = Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let response = tokio::time::timeout(DEADLINE, client.fetch(&target, &FetchOptions::default()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(negotiated.lock().unwrap().as_slice(), ["h2"]);
    assert_eq!(response.negotiated_protocol, Some(Protocol::H2));
    assert_eq!(response.body.as_ref(), b"h2 ok");
    assert_eq!(response.certificate_export().unwrap().sha256(), FIXTURE_SHA256);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_export_is_opt_in_and_never_forgeable_from_the_wire() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (_accepted, _negotiated) = serve(listener);
    let client = fetcher(TlsImpersonation::Off, "localhost", port, false).await;
    let target = Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let response = tokio::time::timeout(DEADLINE, client.fetch(&target, &FetchOptions::default()))
        .await
        .unwrap()
        .unwrap();
    // Facts are always recorded; the certificate bytes only when the fetcher was asked for them.
    assert!(response.certificate_evidence().observed().is_some());
    assert!(response.certificate_export().is_none());
    assert!(response.headers.get(PEER_CERTIFICATE_HEADER).is_none());
}

#[test]
fn export_refuses_oversized_malformed_and_mismatched_material() {
    assert!(CertificateExport::from_der(&der()).is_some());
    assert!(CertificateExport::from_der(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]).is_none());
    assert!(CertificateExport::from_der(b"not a certificate").is_none());
    let mut truncated = der();
    truncated.truncate(truncated.len() - 1);
    assert!(CertificateExport::from_der(&truncated).is_none());
    // A header that carries a well-formed certificate other than the observed one is rejected.
    let other = CertificateExport::from_der(&der()).unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(PEER_CERTIFICATE_HEADER, other.to_header_value().unwrap());
    let observed = crawlx_fetch::CertificateEvidence::from_der(Some(&der()));
    assert_eq!(CertificateExport::from_headers(&headers, &observed), Some(other));
    let unrelated =
        crawlx_fetch::CertificateEvidence::unavailable(crawlx_fetch::CertificateUnavailable::NotTls);
    assert_eq!(CertificateExport::from_headers(&headers, &unrelated), None);
    // A well-formed certificate that is not the observed one never passes as the export.
    let leaf = CertificateDer::pem_slice_iter(include_bytes!("fixtures/proxy-leaf.crt"))
        .next()
        .unwrap()
        .unwrap()
        .to_vec();
    let foreign = CertificateExport::from_der(&leaf).unwrap();
    headers.insert(PEER_CERTIFICATE_HEADER, foreign.to_header_value().unwrap());
    assert_eq!(CertificateExport::from_headers(&headers, &observed), None);
    headers.insert(PEER_CERTIFICATE_HEADER, http::HeaderValue::from_static("AAAA"));
    assert_eq!(CertificateExport::from_headers(&headers, &observed), None);
}
