//! Realm-scoped credentials (`fetch.realmCredentials`): a credential goes only to the origin and
//! realm it names, after a matching `401` challenge or inside a protection space learned
//! earlier, and never after a redirect left the origin or downgraded `https` to `http`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::{fast_config, LOOPBACK};
use crawlx_core::config::Fetch;
use crawlx_core::error::CoreError;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::transport_policy::RealmCredentialRef;
use crawlx_fetch::{FetchConfig, FetchError, FetchOptions, Fetcher, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use http::header;
use parking_lot::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use url::Url;
use wiremock::matchers::{header as header_is, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `Basic base64("alice:s3cr3t-pass")`.
const BASIC: &str = "Basic YWxpY2U6czNjcjN0LXBhc3M=";
const SECRET: &str = "alice:s3cr3t-pass";

struct Secrets;

#[async_trait::async_trait]
impl SecretResolver for Secrets {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        match reference.0.as_str() {
            "env://REALM_MEMBERS" => Ok(SecretOr::secret(SECRET.to_owned())),
            _ => Err(CoreError::CredentialUnavailable(reference.0.clone())),
        }
    }
}

fn resolver() -> Arc<StaticResolver> {
    let resolver = StaticResolver::new();
    for host in ["a.test", "b.test", "localhost"] {
        resolver.set(host, [LOOPBACK]);
    }
    Arc::new(resolver)
}

async fn controls(credentials: Vec<RealmCredentialRef>, skip_tls: bool) -> RequestControls {
    let fetch = Fetch {
        realm_credentials: credentials,
        skip_tls_verification: skip_tls,
        ..Fetch::default()
    };
    RequestControls::resolve(&fetch, "a.test", Some(&Secrets))
        .await
        .unwrap()
}

fn members(origin: &str, realm: &str) -> RealmCredentialRef {
    RealmCredentialRef::basic(Url::parse(origin).unwrap(), realm, "env://REALM_MEMBERS")
}

fn fetcher(controls: RequestControls, ports: &[u16]) -> Fetcher {
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.extend_from_slice(ports);
    let config = FetchConfig {
        retry: crawlx_fetch::RetryPolicy {
            max_retries: 0,
            ..crawlx_fetch::RetryPolicy::default()
        },
        ..fast_config()
    }
    .with_controls(controls);
    Fetcher::new(config, Arc::new(policy), resolver()).unwrap()
}

/// A server with a `members` realm under `/members/`: the right credential gets `200` (or a
/// redirect to `redirect_to` for `/members/go`), everything else a `401` challenge.
async fn realm_server(realm: &str, redirect_to: Option<&str>) -> MockServer {
    let server = MockServer::start().await;
    if let Some(target) = redirect_to {
        Mock::given(method("GET"))
            .and(path("/members/go"))
            .and(header_is("authorization", BASIC))
            .respond_with(ResponseTemplate::new(302).insert_header("location", target))
            .with_priority(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path_regex("^/members/.*"))
        .and(header_is("authorization", BASIC))
        .respond_with(ResponseTemplate::new(200).set_body_raw("members area", "text/plain"))
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/members/.*"))
        .respond_with(
            ResponseTemplate::new(401).insert_header("www-authenticate", format!("Basic realm=\"{realm}\"")),
        )
        .with_priority(5)
        .mount(&server)
        .await;
    server
}

fn origin_of(server: &MockServer, host: &str) -> String {
    format!("http://{host}:{}", server.address().port())
}

async fn authorizations(server: &MockServer) -> Vec<Option<String>> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            request
                .headers
                .get("authorization")
                .map(|value| value.to_str().unwrap().to_owned())
        })
        .collect()
}

fn page(server: &MockServer, host: &str, path: &str) -> Url {
    Url::parse(&format!("{}{path}", origin_of(server, host))).unwrap()
}

#[tokio::test]
async fn the_matching_challenge_is_answered_once_and_the_protection_space_is_promoted() {
    let server = realm_server("members", None).await;
    let fetcher = fetcher(
        controls(vec![members(&origin_of(&server, "a.test"), "members")], false).await,
        &[server.address().port()],
    );
    let first = fetcher
        .fetch(
            &page(&server, "a.test", "/members/one.html"),
            &FetchOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.attempts, 2, "one unauthenticated request, one answer");
    assert_eq!(authorizations(&server).await, [None, Some(BASIC.to_owned())]);

    // The learned protection space (`/members/`) is offered preemptively: no second 401.
    let second = fetcher
        .fetch(
            &page(&server, "a.test", "/members/two.html"),
            &FetchOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!((second.status.as_u16(), second.attempts), (200, 1));
    assert_eq!(authorizations(&server).await.len(), 3);

    // Outside the learned directory nothing is offered until that space asks.
    Mock::given(method("GET"))
        .and(path("/public/open.html"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    fetcher
        .fetch(
            &page(&server, "a.test", "/public/open.html"),
            &FetchOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(authorizations(&server).await.last().unwrap(), &None);
}

#[tokio::test]
async fn a_different_realm_or_origin_never_receives_the_credential() {
    let server = realm_server("members", None).await;
    let other = MockServer::start().await;
    let ports = [server.address().port(), other.address().port()];

    // Right origin, wrong realm: the 401 is the final answer and nothing was sent.
    let wrong_realm = fetcher(
        controls(vec![members(&origin_of(&server, "a.test"), "staff")], false).await,
        &ports,
    );
    let response = wrong_realm
        .fetch(&page(&server, "a.test", "/members/x"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(authorizations(&server).await, [None]);

    // Right realm, another port: a different origin than the one that challenged.
    let wrong_origin = fetcher(
        controls(vec![members(&origin_of(&other, "a.test"), "members")], false).await,
        &ports,
    );
    let response = wrong_origin
        .fetch(&page(&server, "a.test", "/members/y"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(response.status, 401);
    // Right realm, another host name on the same port.
    let wrong_host = fetcher(
        controls(vec![members(&origin_of(&server, "b.test"), "members")], false).await,
        &ports,
    );
    let response = wrong_host
        .fetch(&page(&server, "a.test", "/members/z"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(response.status, 401);
    assert!(
        authorizations(&server).await.iter().all(Option::is_none),
        "no request of the three fetchers carried a credential"
    );
}

#[tokio::test]
async fn a_cross_origin_redirect_never_carries_the_credential_even_on_the_way_back() {
    let other = MockServer::start().await;
    // The origin redirects to `other`, which bounces straight back into the protected area.
    let server = MockServer::start().await;
    let target = format!("{}/landing", origin_of(&other, "b.test"));
    for (priority, guarded_by_credential) in [(1_u8, true), (5, false)] {
        let mut mock = Mock::given(method("GET")).and(path_regex("^/members/.*"));
        if guarded_by_credential {
            mock = mock.and(header_is("authorization", BASIC));
        }
        let response = if !guarded_by_credential {
            ResponseTemplate::new(401).insert_header("www-authenticate", "Basic realm=\"members\"")
        } else {
            ResponseTemplate::new(302).insert_header("location", target.as_str())
        };
        mock.respond_with(response)
            .with_priority(priority)
            .mount(&server)
            .await;
    }
    let back = format!("{}/members/back", origin_of(&server, "a.test"));
    Mock::given(method("GET"))
        .and(path("/landing"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", back.as_str()))
        .mount(&other)
        .await;

    let fetcher = fetcher(
        controls(vec![members(&origin_of(&server, "a.test"), "members")], false).await,
        &[server.address().port(), other.address().port()],
    );
    let response = fetcher
        .fetch(&page(&server, "a.test", "/members/go"), &FetchOptions::default())
        .await
        .unwrap();
    // 401 -> answered -> 302 to `other` (no credential there) -> 302 back to the origin (the
    // chain already left it, so the challenge is not answered): the final answer is the 401.
    assert_eq!(response.status, 401);
    assert_eq!(response.redirects.len(), 2);
    assert_eq!(authorizations(&other).await, [None]);
    assert_eq!(
        authorizations(&server).await,
        [None, Some(BASIC.to_owned()), None],
        "the way back carried no credential and no retry"
    );
}

/// `https://localhost` origin that redirects `/members/go` (with the credential) to `location`.
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: the in-process HTTPS origin serves raw hyper messages and never crosses a typed fetch boundary"
)]
async fn tls_realm_server(
    location: String,
    seen: Arc<Mutex<Vec<Option<String>>>>,
) -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(include_bytes!("fixtures/selfsigned.crt"))
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
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
            let (acceptor, location, seen) = (acceptor.clone(), location.clone(), Arc::clone(&seen));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (location, seen) = (location.clone(), Arc::clone(&seen));
                    async move {
                        let auth = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        seen.lock().push(auth.clone());
                        let mut response =
                            hyper::Response::new(http_body_util::Full::new(bytes::Bytes::new()));
                        if auth.as_deref() == Some(BASIC) {
                            *response.status_mut() = http::StatusCode::FOUND;
                            response
                                .headers_mut()
                                .insert(header::LOCATION, location.parse().unwrap());
                        } else {
                            *response.status_mut() = http::StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                header::WWW_AUTHENTICATE,
                                "Basic realm=\"members\"".parse().unwrap(),
                            );
                        }
                        Ok::<_, std::convert::Infallible>(response)
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

#[tokio::test]
async fn an_https_to_http_downgrade_never_carries_the_credential() {
    let plain = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/landing"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("plain landing", "text/plain"))
        .mount(&plain)
        .await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let landing = format!("http://localhost:{}/landing", plain.address().port());
    let (tls_port, task) = tls_realm_server(landing, Arc::clone(&seen)).await;
    // The credential belongs to the `https` origin; the `http` landing page is another origin.
    let fetcher = fetcher(
        controls(
            vec![members(&format!("https://localhost:{tls_port}"), "members")],
            true,
        )
        .await,
        &[tls_port, plain.address().port()],
    );
    let url = Url::parse(&format!("https://localhost:{tls_port}/members/go")).unwrap();
    let response = fetcher.fetch(&url, &FetchOptions::default()).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.final_url.scheme(), "http");
    assert_eq!(response.text().unwrap(), "plain landing");
    // The secure origin saw the challenge round trip; the downgraded hop saw no credential.
    assert_eq!(*seen.lock(), [None, Some(BASIC.to_owned())]);
    assert_eq!(authorizations(&plain).await, [None]);
    task.abort();
}

#[tokio::test]
async fn a_refused_credential_is_dropped_and_not_promoted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", "Basic realm=\"members\""))
        .mount(&server)
        .await;
    let fetcher = fetcher(
        controls(vec![members(&origin_of(&server, "a.test"), "members")], false).await,
        &[server.address().port()],
    );
    for expected in [2_usize, 4] {
        let response = fetcher
            .fetch(&page(&server, "a.test", "/members/x"), &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(response.status, 401);
        // Each fetch asks once and answers once; a refused credential is not offered
        // preemptively next time and is never repeated for the same challenge.
        assert_eq!(authorizations(&server).await.len(), expected);
    }
    assert_eq!(
        authorizations(&server).await,
        [None, Some(BASIC.to_owned()), None, Some(BASIC.to_owned())]
    );
}

#[tokio::test]
async fn the_answer_is_charged_to_the_acquisition_allowance() {
    let server = realm_server("members", None).await;
    let fetcher = fetcher(
        controls(vec![members(&origin_of(&server, "a.test"), "members")], false).await,
        &[server.address().port()],
    );
    let options = FetchOptions {
        request_allowance: Some(Arc::new(AtomicU32::new(1))),
        ..FetchOptions::default()
    };
    let error = fetcher
        .fetch(&page(&server, "a.test", "/members/x"), &options)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::AcquisitionAllowance), "{error}");
    assert_eq!(
        authorizations(&server).await,
        [None],
        "the second request was never sent"
    );
}

#[tokio::test]
async fn a_callers_authorization_wins_and_the_secret_stays_out_of_captures_and_debug_output() {
    let server = realm_server("members", None).await;
    let controls = controls(vec![members(&origin_of(&server, "a.test"), "members")], false).await;
    for text in [
        format!("{controls:?}"),
        format!("{:?}", controls.realm_credentials()),
    ] {
        for secret in [SECRET, "s3cr3t-pass", "YWxpY2U6"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
    assert!(controls.secret_values().any(|value| value == SECRET));

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let fetcher = fetcher(controls, &[server.address().port()]).with_capture(tx);
    assert!(!format!("{fetcher:?}").contains("s3cr3t"));
    let mut options = FetchOptions::default();
    options
        .headers
        .insert(header::AUTHORIZATION, "Bearer caller-token".parse().unwrap());
    let response = fetcher
        .fetch(&page(&server, "a.test", "/members/x"), &options)
        .await
        .unwrap();
    assert_eq!(response.status, 401, "the caller's own header is never replaced");
    assert_eq!(
        authorizations(&server).await,
        [Some("Bearer caller-token".to_owned())]
    );

    // An answered challenge is captured with its credential masked.
    fetcher
        .fetch(&page(&server, "a.test", "/members/y"), &FetchOptions::default())
        .await
        .unwrap();
    let mut flows = Vec::new();
    while let Ok(flow) = rx.try_recv() {
        flows.push(flow);
    }
    let answered: Vec<_> = flows
        .iter()
        .flat_map(|flow| flow.request_headers.iter())
        .filter(|(name, _)| name == "authorization")
        .map(|(_, value)| value.as_str())
        .collect();
    assert!(answered.contains(&"[redacted]"), "{answered:?}");
    assert!(
        flows.iter().all(|flow| !format!("{flow:?}").contains("YWxpY2U6")),
        "the encoded credential never reaches a capture"
    );
}

#[tokio::test]
async fn a_digest_challenge_is_answered_with_a_hash_and_never_with_the_password() {
    use wiremock::matchers::header_regex;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/members/.*"))
        .and(header_regex(
            "authorization",
            r#"^Digest username="alice", realm="members", nonce="n0nce", uri="/members/[a-z]+", response="[0-9a-f]{32}", algorithm=MD5, qop=auth, nc=0000000[12], cnonce="[0-9a-f]{16}"$"#,
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw("digest ok", "text/plain"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            r#"Digest realm="members", nonce="n0nce", qop="auth", algorithm=MD5"#,
        ))
        .with_priority(5)
        .mount(&server)
        .await;
    let mut credential = members(&origin_of(&server, "a.test"), "members");
    credential.scheme = crawlx_core::transport_policy::RealmScheme::Digest;
    let fetcher = fetcher(
        controls(vec![credential], false).await,
        &[server.address().port()],
    );
    for (page, attempts) in [("/members/one", 2), ("/members/two", 1)] {
        let response = fetcher
            .fetch(&page_url(&server, page), &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(
            (response.status.as_u16(), response.attempts),
            (200, attempts),
            "{page}"
        );
    }
    let sent = authorizations(&server).await;
    assert!(
        sent.iter().flatten().all(|value| !value.contains("s3cr3t-pass")),
        "{sent:?}"
    );
    assert!(sent[1].as_deref().unwrap().contains("nc=00000001"), "{sent:?}");
    assert!(
        sent[2].as_deref().unwrap().contains("nc=00000002"),
        "preemptive reuse counts up: {sent:?}"
    );
}

fn page_url(server: &MockServer, path: &str) -> Url {
    page(server, "a.test", path)
}
