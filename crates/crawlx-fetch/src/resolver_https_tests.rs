#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Owned loopback protocol fixtures; plaintext permission exists only in this test module.

use super::*;
use hickory_resolver::proto::rr::rdata::{A, CNAME};
use hickory_resolver::proto::rr::Record;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinSet;

const PUBLIC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));
const DEADLINE: Duration = Duration::from_secs(2);

type Reply = dyn Fn(&mut Message) + Send + Sync;

enum Behavior {
    Dns(Arc<Reply>),
    Redirect,
    Raw(Vec<u8>),
    ChunkedOversize,
    Stall,
}

/// Possession of an owned bound loopback listener permits plaintext for this fixture only.
struct LoopbackFixture {
    addr: SocketAddr,
    seen: Arc<AtomicUsize>,
    observed: Arc<Notify>,
    _tasks: JoinSet<()>,
}

impl LoopbackFixture {
    #[allow(
        clippy::disallowed_types,
        reason = "owned loopback resolver fixture receives raw HTTP requests and builds bounded authored responses"
    )]
    async fn start(behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        let seen = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Notify::new());
        let requests = Arc::clone(&seen);
        let notification = Arc::clone(&observed);
        let behavior = Arc::new(behavior);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        let behavior = Arc::clone(&behavior);
                        let requests = Arc::clone(&requests);
                        let notification = Arc::clone(&notification);
                        connections.spawn(async move {
                            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let behavior = Arc::clone(&behavior);
                                let requests = Arc::clone(&requests);
                                let notification = Arc::clone(&notification);
                                async move {
                                    let body = request.into_body().collect().await.unwrap().to_bytes();
                                    requests.fetch_add(1, Ordering::SeqCst);
                                    notification.notify_one();
                                    let response = match behavior.as_ref() {
                                        Behavior::Dns(answer) => {
                                            let mut reply = Message::from_vec(&body).unwrap().into_response();
                                            answer(&mut reply);
                                            hyper::Response::builder()
                                                .header("content-type", "application/dns-message")
                                                .body(Full::new(Bytes::from(reply.to_vec().unwrap()))).unwrap()
                                        }
                                        Behavior::Redirect => hyper::Response::builder()
                                            .status(302)
                                            .header("location", "/forbidden-followup")
                                            .body(Full::new(Bytes::new())).unwrap(),
                                        Behavior::Raw(bytes) => hyper::Response::builder()
                                            .header("content-type", "application/dns-message")
                                            .body(Full::new(Bytes::copy_from_slice(bytes))).unwrap(),
                                        Behavior::ChunkedOversize => hyper::Response::builder()
                                            .header("content-type", "application/dns-message")
                                            .header("transfer-encoding", "chunked")
                                            .body(Full::new(Bytes::from(vec![0; 1024]))).unwrap(),
                                        Behavior::Stall => std::future::pending().await,
                                    };
                                    Ok::<_, Infallible>(response)
                                }
                            });
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service),
                            ).await;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Self {
            addr,
            seen,
            observed,
            _tasks: tasks,
        }
    }

    fn config(&self) -> HttpsResolverConfig {
        let mut config = HttpsResolverConfig::new(
            Url::parse(&format!("http://resolver.test:{}/dns-query", self.addr.port())).unwrap(),
            vec![self.addr.ip()],
        );
        config.deadline = DEADLINE;
        config
    }

    fn resolver(&self, config: HttpsResolverConfig) -> HttpsResolver {
        assert_eq!(config.endpoint.scheme(), "http");
        assert_eq!(config.endpoint.host_str(), Some("resolver.test"));
        assert_eq!(config.endpoint.port(), Some(self.addr.port()));
        assert_eq!(config.bootstrap_pins, [self.addr.ip()]);
        let endpoint_policy = EgressPolicy::new(true).with_seed_port(&config.endpoint);
        config.validate_endpoint(&endpoint_policy).unwrap();
        HttpsResolver::build_validated(
            config,
            Arc::new(endpoint_policy),
            Arc::new(EgressPolicy::default()),
            CancellationToken::new(),
        )
        .unwrap()
    }
}

fn address(reply: &mut Message, ip: IpAddr) {
    let query = &reply.queries[0];
    let data = match (query.query_type, ip) {
        (RecordType::A, IpAddr::V4(ip)) => RData::A(A(ip)),
        (RecordType::AAAA, IpAddr::V6(ip)) => RData::AAAA(ip.into()),
        _ => return,
    };
    reply.add_answer(Record::from_rdata(query.name.clone(), 60, data));
}

#[tokio::test]
async fn pinned_endpoint_resolves_both_families_and_preserves_ttl() {
    let ipv6: IpAddr = "2600::1".parse().unwrap();
    let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(move |reply| {
        address(reply, PUBLIC);
        address(reply, ipv6);
    })))
    .await;
    let resolver = fixture.resolver(fixture.config());
    let (addresses, ttl) = resolver.resolve_with_ttl("owned.test").await.unwrap();
    assert_eq!(addresses, [PUBLIC, ipv6]);
    assert!(ttl.unwrap() <= Duration::from_secs(60));
    assert!(ttl.unwrap() > Duration::from_secs(55));
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 2);
    assert!(resolver
        .client
        .get("http://unapproved.test/")
        .send()
        .await
        .unwrap_err()
        .is_connect());
}

#[tokio::test]
async fn private_metadata_and_mixed_answers_fail_closed() {
    for unsafe_ip in [
        "10.1.2.3",
        "169.254.169.254",
        "127.0.0.1",
        "::ffff:169.254.169.254",
    ] {
        let unsafe_ip: IpAddr = unsafe_ip.parse().unwrap();
        let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(move |reply| {
            address(reply, PUBLIC);
            let data = match unsafe_ip {
                IpAddr::V4(ip) => RData::A(A(ip)),
                IpAddr::V6(ip) => RData::AAAA(ip.into()),
            };
            // Unsafe unrelated glue must also poison the entire response.
            reply.add_additional(Record::from_rdata(
                Name::from_ascii("glue.test.").unwrap(),
                60,
                data,
            ));
        })))
        .await;
        let resolver = fixture.resolver(fixture.config());
        assert!(matches!(
            resolver.resolve("owned.test").await,
            Err(FetchError::EgressDenied(_))
        ));
        assert_eq!(fixture.seen.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unsafe_second_family_cannot_hide_behind_first_family_success() {
    let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(|reply| {
        address(reply, PUBLIC);
        address(reply, "fd00::1".parse().unwrap());
    })))
    .await;
    let resolver = fixture.resolver(fixture.config());
    assert!(matches!(
        resolver.resolve("owned.test").await,
        Err(FetchError::EgressDenied(_))
    ));
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn malformed_mismatched_and_refused_replies_never_succeed() {
    let mutations: Vec<Arc<Reply>> = vec![
        Arc::new(|reply| reply.metadata.id = 1),
        Arc::new(|reply| reply.metadata.message_type = MessageType::Query),
        Arc::new(|reply| reply.metadata.op_code = OpCode::Status),
        Arc::new(|reply| reply.metadata.truncation = true),
        Arc::new(|reply| reply.metadata.response_code = ResponseCode::Refused),
        Arc::new(|reply| reply.queries[0].name = Name::from_ascii("other.test.").unwrap()),
        Arc::new(|reply| reply.queries[0].query_type = RecordType::TXT),
        Arc::new(|reply| reply.queries[0].query_class = DNSClass::CH),
        Arc::new(|reply| {
            reply.queries.clear();
        }),
        Arc::new(|reply| {
            reply.queries.push(reply.queries[0].clone());
        }),
        Arc::new(|reply| {
            reply.answers[0].dns_class = DNSClass::CH;
        }),
        Arc::new(|reply| {
            reply.answers[0].data = RData::AAAA("2600::1".parse::<std::net::Ipv6Addr>().unwrap().into());
        }),
    ];
    for mutate in mutations {
        let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(move |reply| {
            address(reply, PUBLIC);
            mutate(reply);
        })))
        .await;
        assert!(fixture
            .resolver(fixture.config())
            .resolve("owned.test")
            .await
            .is_err());
        assert_eq!(fixture.seen.load(Ordering::SeqCst), 1);
    }
    for malformed in [vec![0; 3], vec![0xff; 30]] {
        let fixture = LoopbackFixture::start(Behavior::Raw(malformed)).await;
        assert!(fixture
            .resolver(fixture.config())
            .resolve("owned.test")
            .await
            .is_err());
    }
}

#[tokio::test]
async fn aliases_follow_checked_endpoint_and_cycles_depth_and_conflicts_fail() {
    let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(|reply| {
        let query = &reply.queries[0];
        if query.name == Name::from_ascii("owned.test.").unwrap() {
            reply.add_answer(Record::from_rdata(
                query.name.clone(),
                20,
                RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
            ));
        } else {
            address(reply, PUBLIC);
        }
    })))
    .await;
    let (answers, ttl) = fixture
        .resolver(fixture.config())
        .resolve_with_ttl("owned.test")
        .await
        .unwrap();
    assert_eq!(answers, [PUBLIC]);
    assert!(ttl.unwrap() <= Duration::from_secs(20));
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 4);

    for mode in 0..4 {
        let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(move |reply| {
            let name = reply.queries[0].name.clone();
            let target = if mode == 0 {
                name.clone()
            } else {
                Name::from_ascii("target.test.").unwrap()
            };
            reply.add_answer(Record::from_rdata(name.clone(), 20, RData::CNAME(CNAME(target))));
            if mode == 1 {
                reply.add_answer(Record::from_rdata(
                    name,
                    20,
                    RData::CNAME(CNAME(Name::from_ascii("conflict.test.").unwrap())),
                ));
            } else if mode == 2 {
                address(reply, PUBLIC);
            } else if mode == 3 {
                reply.add_answer(Record::from_rdata(
                    Name::from_ascii("target.test.").unwrap(),
                    20,
                    RData::CNAME(CNAME(Name::from_ascii("last.test.").unwrap())),
                ));
            }
        })))
        .await;
        let mut config = fixture.config();
        config.max_cname_depth = 1;
        assert!(fixture.resolver(config).resolve("owned.test").await.is_err());
    }
}

#[tokio::test]
async fn redirects_and_byte_and_record_caps_refuse_without_followup() {
    let fixture = LoopbackFixture::start(Behavior::Redirect).await;
    assert!(fixture
        .resolver(fixture.config())
        .resolve("owned.test")
        .await
        .is_err());
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 1);
    for behavior in [Behavior::Raw(vec![0; 1024]), Behavior::ChunkedOversize] {
        let fixture = LoopbackFixture::start(behavior).await;
        let mut config = fixture.config();
        config.max_response_bytes = 512;
        assert!(fixture.resolver(config).resolve("owned.test").await.is_err());
    }
    let fixture = LoopbackFixture::start(Behavior::Dns(Arc::new(|reply| {
        address(reply, PUBLIC);
        address(reply, PUBLIC);
    })))
    .await;
    let mut config = fixture.config();
    config.max_records = 1;
    assert!(fixture.resolver(config).resolve("owned.test").await.is_err());
}

#[tokio::test]
async fn finite_deadline_and_inflight_cancellation_stop_endpoint_io() {
    let fixture = LoopbackFixture::start(Behavior::Stall).await;
    let resolver = Arc::new(fixture.resolver(fixture.config()));
    let mut deadlines = JoinSet::new();
    deadlines.spawn(async move { resolver.resolve("owned.test").await });
    tokio::time::timeout(DEADLINE, fixture.observed.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    let error = deadlines.join_next().await.unwrap().unwrap().unwrap_err();
    tokio::time::resume();
    match error {
        FetchError::AcquisitionDeadline => {}
        FetchError::Transport(crate::error::HttpError::Rustls(source)) => assert!(source.is_timeout()),
        other => panic!("expected lookup deadline, got {other:?}"),
    }
    let fixture = LoopbackFixture::start(Behavior::Stall).await;
    let resolver = Arc::new(fixture.resolver(fixture.config()));
    let token = CancellationToken::new();
    let child = token.clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move { resolver.resolve_cancellable("owned.test", &child).await });
    tokio::time::timeout(DEADLINE, fixture.observed.notified())
        .await
        .unwrap();
    token.cancel();
    assert!(matches!(
        tasks.join_next().await.unwrap().unwrap(),
        Err(FetchError::AcquisitionCancelled)
    ));
}

#[tokio::test]
async fn production_requires_https_pins_and_checked_endpoint_policy() {
    let fixture = LoopbackFixture::start(Behavior::Stall).await;
    assert!(HttpsResolver::new(
        fixture.config(),
        Arc::new(EgressPolicy::new(true)),
        Arc::new(EgressPolicy::default()),
        CancellationToken::new()
    )
    .is_err());
    let mut config = fixture.config();
    config.endpoint.set_scheme("https").unwrap();
    assert!(HttpsResolver::new(
        config.clone(),
        Arc::new(EgressPolicy::default()),
        Arc::new(EgressPolicy::default()),
        CancellationToken::new()
    )
    .is_err());
    config.bootstrap_pins.clear();
    assert!(HttpsResolver::new(
        config,
        Arc::new(EgressPolicy::new(true)),
        Arc::new(EgressPolicy::default()),
        CancellationToken::new()
    )
    .is_err());
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_operator_capability_sends_no_requests() {
    let fixture = LoopbackFixture::start(Behavior::Stall).await;
    let resolver = fixture.resolver(fixture.config());
    resolver.cancel.cancel();
    assert!(matches!(
        resolver.resolve("owned.test").await,
        Err(FetchError::AcquisitionCancelled)
    ));
    assert_eq!(fixture.seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn production_tls_rejects_untrusted_owned_endpoint_certificate() {
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let certificates = CertificateDer::pem_slice_iter(include_bytes!("../tests/fixtures/selfsigned.crt"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../tests/fixtures/selfsigned.key")).unwrap();
    let tls =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (socket, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(tokio::time::timeout(DEADLINE, acceptor.accept(socket))
            .await
            .unwrap()
            .is_err());
    });
    let endpoint = Url::parse(&format!("https://resolver.test:{}/dns-query", addr.port())).unwrap();
    let mut config = HttpsResolverConfig::new(endpoint.clone(), vec![addr.ip()]);
    config.deadline = DEADLINE;
    let resolver = HttpsResolver::new(
        config,
        Arc::new(EgressPolicy::new(true).with_seed_port(&endpoint)),
        Arc::new(EgressPolicy::default()),
        CancellationToken::new(),
    )
    .unwrap();
    assert!(matches!(
        resolver.resolve("owned.test").await,
        Err(FetchError::Transport(_))
    ));
    tasks.join_next().await.unwrap().unwrap();
}

fn assert_no_canary(error: &FetchError, canary: &str) {
    use std::error::Error as _;
    assert!(!format!("{error}").contains(canary));
    assert!(!format!("{error:?}").contains(canary));
    let mut source = error.source();
    while let Some(cause) = source {
        assert!(!cause.to_string().contains(canary));
        assert!(!format!("{cause:?}").contains(canary));
        source = cause.source();
    }
}

#[tokio::test]
async fn query_secrets_are_rejected_and_failing_transport_strips_url_without_losing_sources() {
    use std::error::Error as _;
    const CANARY: &str = "operator-dns-secret-canary";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = Url::parse(&format!("https://resolver.test:{}/dns-query", addr.port())).unwrap();
    let policy = Arc::new(EgressPolicy::new(true).with_seed_port(&endpoint));
    let mut config = HttpsResolverConfig::new(endpoint, vec![addr.ip()]);
    config.deadline = DEADLINE;
    config.endpoint.set_query(Some(&format!("key={CANARY}")));
    assert!(!format!("{config:?}").contains(CANARY));
    let error = HttpsResolver::new(
        config.clone(),
        Arc::clone(&policy),
        Arc::new(EgressPolicy::default()),
        CancellationToken::new(),
    )
    .unwrap_err();
    assert_no_canary(&error, CANARY);

    config.endpoint.set_query(None);
    let mut resolver = HttpsResolver::new(
        config,
        policy,
        Arc::new(EgressPolicy::default()),
        CancellationToken::new(),
    )
    .unwrap();
    // Inject stale invalid state only inside this test to prove defense-in-depth:
    // URL stripping remains effective even if validation was bypassed by a future caller.
    resolver.config.endpoint.set_query(Some(&format!("key={CANARY}")));
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (socket, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop(socket);
    });
    let error = resolver.resolve("owned.test").await.unwrap_err();
    assert_no_canary(&error, CANARY);
    let FetchError::Transport(crate::error::HttpError::Rustls(source)) = &error else {
        panic!("expected owned endpoint transport failure, got {error:?}");
    };
    assert!(source.url().is_none());
    assert!(source.source().is_some());
    assert!(error.source().is_some());
    tasks.join_next().await.unwrap().unwrap();
}
