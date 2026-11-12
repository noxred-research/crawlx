//! TLS client certificates by credential reference (`fetch.clientCertificate`) against a
//! loopback HTTPS server that *requires* a client certificate issued by a test CA. The same
//! cases run on both transports (the default rustls client and the synthetic-hello client).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::{fast_config, LOOPBACK};
use crawlx_core::config::Fetch;
use crawlx_core::error::CoreError;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::tls::TlsImpersonation;
use crawlx_core::transport_policy::ClientCertificate;
use crawlx_fetch::{FetchConfig, FetchError, FetchOptions, Fetcher, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use url::Url;

const CLIENT_CERT: &str = include_str!("fixtures/mtls-client.crt");
const CLIENT_KEY: &str = include_str!("fixtures/mtls-client.key");
const ROGUE_CERT: &str = include_str!("fixtures/mtls-rogue.crt");
const ROGUE_KEY: &str = include_str!("fixtures/mtls-rogue.key");

/// The base64 body of a PEM key: the text that must never leave the process.
fn key_body(pem: &str) -> String {
    pem.lines().filter(|line| !line.starts_with("-----")).collect()
}

struct Store;

#[async_trait::async_trait]
impl SecretResolver for Store {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        let value = match reference.0.as_str() {
            "env://MTLS_CERT" => CLIENT_CERT,
            "env://MTLS_KEY" => CLIENT_KEY,
            "env://ROGUE_CERT" => ROGUE_CERT,
            "env://ROGUE_KEY" => ROGUE_KEY,
            _ => return Err(CoreError::CredentialUnavailable(reference.0.clone())),
        };
        Ok(SecretOr::secret(value.to_owned()))
    }
}

fn identity(cert: &str, key: &str, hosts: &[&str]) -> ClientCertificate {
    let mut identity = ClientCertificate::new(cert, key);
    identity.hosts = hosts.iter().map(|host| (*host).to_owned()).collect();
    identity
}

async fn controls(identity: Option<ClientCertificate>) -> RequestControls {
    let fetch = Fetch {
        skip_tls_verification: true,
        client_certificate: identity,
        ..Fetch::default()
    };
    RequestControls::resolve(&fetch, "localhost", Some(&Store))
        .await
        .unwrap()
}

/// HTTPS server that requires a client certificate from the test CA and answers with the hex
/// of the DER certificate the client presented.
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: the in-process HTTPS origin serves raw hyper messages and never crosses a typed fetch boundary"
)]
async fn mtls_server() -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(include_bytes!("fixtures/mtls-ca.crt")) {
        roots.add(cert.unwrap()).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()
        .unwrap();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(include_bytes!("fixtures/selfsigned.crt"))
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let presented = tls
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|leaf| {
                        leaf.as_ref()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    })
                    .unwrap_or_default();
                let svc = service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                    let presented = presented.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                            bytes::Bytes::from(presented),
                        )))
                    }
                });
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, task)
}

fn client_der_hex() -> String {
    let leaf = CertificateDer::pem_slice_iter(CLIENT_CERT.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    leaf.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn transports() -> [(&'static str, TlsImpersonation); 2] {
    [
        ("rustls", TlsImpersonation::Off),
        ("randomized", TlsImpersonation::Randomized),
    ]
}

fn fetcher(controls: RequestControls, tls: TlsImpersonation, port: u16) -> Result<Fetcher, FetchError> {
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(port);
    let resolver = StaticResolver::new();
    resolver.set("localhost", [LOOPBACK]);
    let config = FetchConfig {
        tls_impersonation: tls,
        seed: CrawlSeed(7),
        retry: crawlx_fetch::RetryPolicy {
            max_retries: 0,
            ..crawlx_fetch::RetryPolicy::default()
        },
        ..fast_config()
    }
    .with_controls(controls);
    Fetcher::new(config, Arc::new(policy), Arc::new(resolver))
}

async fn get(fetcher: &Fetcher, host: &str, port: u16) -> Result<String, FetchError> {
    let url = Url::parse(&format!("https://{host}:{port}/")).unwrap();
    let response = fetcher.fetch(&url, &FetchOptions::default()).await?;
    Ok(response.text().unwrap().into_owned())
}

#[tokio::test]
async fn the_referenced_certificate_is_the_one_the_server_receives() {
    let (port, task) = mtls_server().await;
    for (name, tls) in transports() {
        let controls = controls(Some(identity("env://MTLS_CERT", "env://MTLS_KEY", &[]))).await;
        let fetcher = fetcher(controls, tls, port).unwrap();
        let presented = get(&fetcher, "localhost", port).await.unwrap();
        assert_eq!(
            presented,
            client_der_hex(),
            "{name}: the server saw the referenced leaf"
        );
    }
    task.abort();
}

#[tokio::test]
async fn a_client_without_the_certificate_or_with_an_untrusted_one_is_refused() {
    let (port, task) = mtls_server().await;
    for (name, tls) in transports() {
        let none = fetcher(controls(None).await, tls, port).unwrap();
        let error = get(&none, "localhost", port).await.unwrap_err();
        assert!(matches!(error, FetchError::Transport(_)), "{name}: {error}");

        let rogue = controls(Some(identity("env://ROGUE_CERT", "env://ROGUE_KEY", &[]))).await;
        let rogue = fetcher(rogue, tls, port).unwrap();
        let error = get(&rogue, "localhost", port).await.unwrap_err();
        assert!(matches!(error, FetchError::Transport(_)), "{name}: {error}");
    }
    task.abort();
}

#[tokio::test]
async fn the_identity_is_presented_only_to_the_hosts_it_is_scoped_to() {
    let (port, task) = mtls_server().await;
    for (name, tls) in transports() {
        let scoped = controls(Some(identity(
            "env://MTLS_CERT",
            "env://MTLS_KEY",
            &["localhost"],
        )))
        .await;
        let fetcher = fetcher(scoped, tls, port).unwrap();
        assert_eq!(
            get(&fetcher, "localhost", port).await.unwrap(),
            client_der_hex(),
            "{name}: scoped host"
        );
        // Same server, another host name: no certificate is offered, so the server refuses.
        let error = get(&fetcher, "127.0.0.1", port).await.unwrap_err();
        assert!(matches!(error, FetchError::Transport(_)), "{name}: {error}");
    }
    task.abort();
}

#[tokio::test]
async fn a_key_that_does_not_belong_to_the_certificate_is_refused_before_any_connection() {
    let controls = controls(Some(identity("env://MTLS_CERT", "env://ROGUE_KEY", &[]))).await;
    for (name, tls) in transports() {
        let error = fetcher(controls.clone(), tls, 1).unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(text.contains("does not match"), "{name}: {text}");
        for secret in [
            key_body(ROGUE_KEY),
            key_body(CLIENT_KEY),
            "PRIVATE KEY".to_owned(),
        ] {
            assert!(!text.contains(&secret), "{name}: {text}");
        }
    }
}

#[tokio::test]
async fn malformed_identities_fail_with_fixed_messages() {
    for (cert, key, expected) in [
        ("env://MTLS_KEY", "env://MTLS_KEY", "certificate"),
        ("env://MTLS_CERT", "env://MTLS_CERT", "key"),
    ] {
        let fetch = Fetch {
            client_certificate: Some(identity(cert, key, &[])),
            ..Fetch::default()
        };
        // The store hands back whatever the reference names; shape checks run at resolution.
        let Err(error) = RequestControls::resolve(&fetch, "localhost", Some(&Store)).await else {
            panic!("a certificate that is a key, or a key that is a certificate, must be refused");
        };
        let text = error.to_string();
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains(&key_body(CLIENT_KEY)), "{text}");
    }
}

/// Collects everything the fetch plane logs while a test runs.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = CapturedWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CapturedWriter(Arc::clone(&self.0))
    }
}

#[tokio::test]
async fn the_key_never_appears_in_logs_errors_debug_output_or_results() {
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (port, task) = mtls_server().await;
    let secret_body = key_body(CLIENT_KEY);
    let mut observed = Vec::new();
    for (_, tls) in transports() {
        let controls = controls(Some(identity("env://MTLS_CERT", "env://MTLS_KEY", &[]))).await;
        observed.push(format!("{controls:?}"));
        observed.push(format!("{:?}", controls.client_identity()));
        let fetcher = fetcher(controls, tls, port).unwrap();
        observed.push(format!("{fetcher:?}"));
        let url = Url::parse(&format!("https://localhost:{port}/")).unwrap();
        let response = fetcher.fetch(&url, &FetchOptions::default()).await.unwrap();
        observed.push(format!("{response:?}"));
        let none = crate::controls(None).await;
        let error = get(&self::fetcher(none, tls, port).unwrap(), "localhost", port)
            .await
            .unwrap_err();
        observed.push(format!("{error} {error:?}"));
    }
    task.abort();
    observed.push(String::from_utf8(logs.0.lock().clone()).unwrap());
    for text in &observed {
        assert!(!text.contains(&secret_body), "key body leaked: {text}");
        assert!(!text.contains("PRIVATE KEY"), "key armor leaked: {text}");
    }
    // The redaction registry knows the key, so even an echo through another channel is masked.
    let controls = controls(Some(identity("env://MTLS_CERT", "env://MTLS_KEY", &[]))).await;
    let first_line = CLIENT_KEY.lines().nth(1).unwrap();
    assert!(controls.secret_values().any(|value| value.contains(first_line)));
}
