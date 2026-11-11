//! Deterministic loopback coverage for named HTTP sessions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{CrawlSession, SessionStatus};
use crawlx_core::session_binding::SessionIdentityV1;
use crawlx_core::time::ManualClock;
use crawlx_core::SessionId;
use crawlx_fetch::StaticResolver;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

struct TestAuthority;

#[async_trait::async_trait]
impl HttpSessionAuthority for TestAuthority {
    async fn verify(&self, binding: &SessionBindingV1) -> Result<(), FetchError> {
        assert_eq!(binding.identity.tenant, owner().tenant);
        assert_eq!(binding.lease_fence, 7);
        assert!(binding.generation > 0);
        Ok(())
    }

    async fn record_use(
        &self,
        before: &SessionBindingV1,
        after: &SessionBindingV1,
    ) -> Result<(), FetchError> {
        assert_eq!(before.identity, after.identity);
        assert_eq!(before.generation, after.generation);
        assert_eq!(before.lease_fence, after.lease_fence);
        assert_eq!(after.state_version, before.state_version + 1);
        assert!(after.usage == before.usage || after.usage == before.usage + 1);
        Ok(())
    }
}

struct PersistedAuthority {
    current: Mutex<SessionBindingV1>,
    writes: AtomicUsize,
    fail_write: bool,
}

impl PersistedAuthority {
    fn new(binding: &SessionBindingV1) -> Self {
        Self {
            current: Mutex::new(binding.clone()),
            writes: AtomicUsize::new(0),
            fail_write: false,
        }
    }
}

#[async_trait::async_trait]
impl HttpSessionAuthority for PersistedAuthority {
    async fn verify(&self, binding: &SessionBindingV1) -> Result<(), FetchError> {
        if *self.current.lock() != *binding {
            return Err(FetchError::AcquisitionUnavailable);
        }
        Ok(())
    }

    async fn record_use(
        &self,
        before: &SessionBindingV1,
        after: &SessionBindingV1,
    ) -> Result<(), FetchError> {
        let mut current = self.current.lock();
        if self.fail_write || *current != *before {
            return Err(FetchError::AcquisitionUnavailable);
        }
        assert_eq!(before.identity, after.identity);
        assert_eq!(before.generation, after.generation);
        assert_eq!(after.state_version, before.state_version + 1);
        assert!(after.health_errors.abs_diff(before.health_errors) <= 1);
        *current = after.clone();
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ObservedRequest {
    path: String,
    cookie: String,
    connection: usize,
}

struct Fixture {
    url: Url,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
    task: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn start(cross: Option<Url>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&connections);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut handlers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let connection = count.fetch_add(1, Ordering::SeqCst) + 1;
                        let cross = cross.clone();
                        let requests = Arc::clone(&observed);
                        handlers.spawn(async move {
                            loop {
                                let mut bytes = Vec::new();
                                loop {
                                    let mut byte = [0];
                                    if stream.read_exact(&mut byte).await.is_err() {
                                        return;
                                    }
                                    bytes.push(byte[0]);
                                    if bytes.ends_with(b"\r\n\r\n") {
                                        break;
                                    }
                                    assert!(bytes.len() <= 16 * 1024);
                                }
                                let request = String::from_utf8(bytes).unwrap();
                                let path = request.lines().next().unwrap().split_whitespace().nth(1).unwrap();
                                let cookie = request.lines().find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("cookie").then(|| value.trim())
                                }).unwrap_or("");
                                let auth = request.lines().find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("authorization").then(|| value.trim())
                                }).unwrap_or("");
                                requests.lock().push(ObservedRequest {
                                    path: path.to_owned(), cookie: cookie.to_owned(), connection,
                                });
                                let body = if path == "/robots.txt" {
                                    "User-agent: *\nAllow: /\n".to_owned()
                                } else if path.starts_with("/bound-") {
                                    format!("<html><head><title>Owned session fixture {path}</title></head><body><main><h1>Owned HTTP session</h1><p>This deterministic native producer fixture exercises checked HTTP acquisition, bounded parsing, extraction and fenced result publication for route {path}.</p></main></body></html>")
                                } else {
                                    format!("{connection}|{cookie}|{auth}")
                                };
                                let (status, headers) = match path {
                                    "/set-a" => ("200 OK", "Set-Cookie: sid=alpha; Path=/; Max-Age=10\r\n".to_owned()),
                                    "/set-b" => ("200 OK", "Set-Cookie: sid=beta; Path=/\r\n".to_owned()),
                                    "/delete" => ("200 OK", "Set-Cookie: sid=gone; Path=/; Max-Age=0\r\n".to_owned()),
                                    "/scoped" => ("200 OK", "Set-Cookie: scoped=only; Path=/private\r\nSet-Cookie: secure=hidden; Secure; Path=/\r\nSet-Cookie: foreign=hidden; Domain=other.test; Path=/\r\n".to_owned()),
                                    "/many" => ("200 OK", "Set-Cookie: first=1; Path=/\r\nSet-Cookie: second=2; Path=/\r\n".to_owned()),
                                    "/redirect" => ("302 Found", "Location: /echo\r\nSet-Cookie: sid=redirected; Path=/\r\n".to_owned()),
                                    "/cross" => ("302 Found", format!("Location: {}\r\n", cross.as_ref().unwrap())),
                                    "/unauthorized" => ("401 Unauthorized", String::new()),
                                    "/bound-first" => ("200 OK", "Set-Cookie: sid=producer-cookie; Path=/\r\n".to_owned()),
                                    "/limited" => ("429 Too Many Requests", String::new()),
                                    _ => ("200 OK", String::new()),
                                };
                                let content_type = if path.starts_with("/bound-") { "text/html" } else { "text/plain" };
                                let response = format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nContent-Type: {content_type}\r\n\r\n{body}", body.len());
                                if stream.write_all(response.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                    Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap();
                    }
                }
            }
        });
        Self {
            url,
            connections,
            requests,
            task,
        }
    }

    fn at(&self, path: &str) -> Url {
        self.url.join(path).unwrap()
    }
}

fn owner() -> HttpSessionOwner {
    HttpSessionOwner::new(
        TenantId(Uuid::from_u128(1)),
        CrawlRunId(Uuid::from_u128(2)),
        PrincipalId("reader".to_owned()),
    )
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    ))
}

fn binding(clock: &ManualClock, slot: u128) -> SessionBindingV1 {
    let owner = owner();
    let session = CrawlSession {
        id: SessionId(Uuid::from_u128(slot)),
        run: owner.run,
        kind: crawlx_core::repo::SessionKind::HttpCoordinator,
        role: owner.principal,
        run_index: 1,
        schedule_slot: 0,
        status: SessionStatus::Running,
        browser: None,
        action_seq: 0,
    };
    let digest = Digest::of("crawlx/http-session/test", b"approved");
    SessionBindingV1::new(
        SessionIdentityV1::new(owner.tenant, &session, digest, digest, digest, digest, None),
        7,
        clock.now() + chrono::Duration::minutes(30),
    )
}

fn manager(clock: &Arc<ManualClock>, limits: HttpSessionLimits) -> NamedHttpSessions {
    NamedHttpSessions::new(
        owner(),
        limits,
        clock.clone(),
        Arc::new(OriginGovernor::new(crawlx_fetch::GovernorConfig {
            base_delay: Duration::ZERO,
            ..crawlx_fetch::GovernorConfig::default()
        })),
    )
    .unwrap()
}

fn config(manager: &NamedHttpSessions) -> FetchConfig {
    let mut config = FetchConfig {
        shared_governor: Some(Arc::clone(&manager.governor)),
        ..FetchConfig::default()
    };
    config.retry.max_retries = 0;
    config.request_timeout = Duration::from_secs(2);
    config
}

fn register(manager: &NamedHttpSessions, fixture: &Fixture, sid: &str, binding: &SessionBindingV1) {
    manager
        .register(
            sid,
            binding.clone(),
            config(manager),
            Arc::new(EgressPolicy::new(true).with_seed_port(&fixture.url)),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
}

async fn fetch(
    manager: &NamedHttpSessions,
    fixture: &Fixture,
    sid: &str,
    binding: &SessionBindingV1,
    path: &str,
) -> FetchResponse {
    manager
        .fetch_with_authority(
            sid,
            binding,
            &fixture.at(path),
            &FetchOptions::default(),
            &|| std::future::ready(Ok(())),
            &TestAuthority,
        )
        .await
        .unwrap()
}

fn fields(response: &FetchResponse) -> Vec<&str> {
    std::str::from_utf8(&response.body).unwrap().split('|').collect()
}

#[tokio::test]
async fn two_calls_reuse_only_named_owned_cookies_and_tcp_connection() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let first = binding(&clock, 3);
    let second = binding(&clock, 4);
    register(&manager, &fixture, DEFAULT_HTTP_SESSION, &first);
    register(&manager, &fixture, "other", &second);
    assert!(manager
        .entries
        .lock()
        .values()
        .all(|entry| entry.fetcher.is_none()));
    let set = fetch(&manager, &fixture, DEFAULT_HTTP_SESSION, &first, "/set-a").await;
    let echo = fetch(&manager, &fixture, DEFAULT_HTTP_SESSION, &first, "/echo").await;
    assert_eq!(fields(&set)[0], fields(&echo)[0]);
    assert_eq!(fields(&echo)[1], "sid=alpha");
    let other = fetch(&manager, &fixture, "other", &second, "/echo").await;
    assert_ne!(fields(&echo)[0], fields(&other)[0]);
    assert_eq!(fields(&other)[1], "");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    assert_eq!(manager.snapshot(DEFAULT_HTTP_SESSION, &first).unwrap().usage, 2);
    assert!(matches!(
        manager.snapshot("other", &first),
        Err(HttpSessionError::Unavailable)
    ));
}

#[tokio::test]
async fn strict_owner_generation_fence_and_sid_fail_before_starting_client() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let original = binding(&clock, 3);
    register(&manager, &fixture, "owned", &original);
    let mut foreign = original.clone();
    foreign.identity.tenant = TenantId(Uuid::from_u128(99));
    let mut wrong_run = original.clone();
    wrong_run.identity.run = CrawlRunId(Uuid::from_u128(99));
    let mut wrong_principal = original.clone();
    wrong_principal.identity.principal = PrincipalId::anonymous();
    let mut stale = original.clone();
    stale.generation += 1;
    let mut wrong_slot = original.clone();
    wrong_slot.identity.session = SessionId(Uuid::from_u128(99));
    let mut wrong_acquisition = original.clone();
    wrong_acquisition.identity.acquisition = Digest::of("crawlx/http-session/test", b"different");
    let mut wrong_fence = original.clone();
    wrong_fence.lease_fence += 1;
    for denied in [
        foreign,
        wrong_run,
        wrong_principal,
        stale,
        wrong_slot,
        wrong_acquisition,
        wrong_fence,
    ] {
        assert!(manager
            .fetch_with_authority(
                "owned",
                &denied,
                &fixture.url,
                &FetchOptions::default(),
                &|| { std::future::ready(Ok(())) },
                &TestAuthority
            )
            .await
            .is_err());
    }
    assert!(matches!(
        manager
            .fetch_with_authority(
                DEFAULT_HTTP_SESSION,
                &original,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Unavailable)
    ));
    assert!(manager.entries.lock()["owned"].fetcher.is_none());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cookies_obey_paths_expiry_deletion_and_reject_foreign_and_insecure_secure_values() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    register(&manager, &fixture, "owned", &binding);
    fetch(&manager, &fixture, "owned", &binding, "/set-a").await;
    fetch(&manager, &fixture, "owned", &binding, "/scoped").await;
    let public = fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert_eq!(fields(&public)[1], "sid=alpha");
    let private = fetch(&manager, &fixture, "owned", &binding, "/private/echo").await;
    assert_eq!(fields(&private)[1], "scoped=only; sid=alpha");
    let unrelated = fetch(&manager, &fixture, "owned", &binding, "/privately").await;
    assert_eq!(fields(&unrelated)[1], "sid=alpha");
    clock.advance_ms(10_000);
    let expired = fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert_eq!(fields(&expired)[1], "");
    fetch(&manager, &fixture, "owned", &binding, "/set-b").await;
    fetch(&manager, &fixture, "owned", &binding, "/delete").await;
    let deleted = fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert_eq!(fields(&deleted)[1], "");
}

#[tokio::test]
async fn redirect_cookie_is_applied_before_next_same_origin_hop() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    register(&manager, &fixture, "owned", &binding);
    let checks = AtomicUsize::new(0);
    let response = manager
        .fetch_with_authority(
            "owned",
            &binding,
            &fixture.at("/redirect"),
            &FetchOptions::default(),
            &|| {
                checks.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(()))
            },
            &TestAuthority,
        )
        .await
        .unwrap();
    assert_eq!(fields(&response)[1], "sid=redirected");
    assert_eq!(response.redirects, vec![fixture.at("/redirect").to_string()]);
    assert_eq!(response.hops.len(), 1);
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cross_origin_redirect_strips_initial_and_learned_session_secrets() {
    let target = Fixture::start(None).await;
    let fixture = Fixture::start(Some(target.at("/echo"))).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    let mut config = config(&manager);
    let mut controls = crawlx_core::config::Fetch::default();
    controls
        .extra_headers
        .insert("authorization", "Bearer session-secret");
    config.controls = crawlx_core::request_controls::RequestControls::resolve(&controls, "127.0.0.1", None)
        .await
        .unwrap();
    let mut policy = EgressPolicy::new(true).with_seed_port(&fixture.url);
    policy.extra_ports.push(target.url.port().unwrap());
    manager
        .register(
            "owned",
            binding.clone(),
            config,
            Arc::new(policy),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
    fetch_session_cookie(&manager, &fixture, &binding).await;
    let response = fetch(&manager, &fixture, "owned", &binding, "/cross").await;
    assert_eq!(fields(&response)[1..], ["", ""]);
    let own = fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert_eq!(fields(&own)[1..], ["sid=alpha", "Bearer session-secret"]);
}

async fn fetch_session_cookie(manager: &NamedHttpSessions, fixture: &Fixture, binding: &SessionBindingV1) {
    fetch(manager, fixture, "owned", binding, "/set-a").await;
}

#[tokio::test]
async fn bounded_registration_ttl_usage_and_retirement_never_replace_jars() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let mut limits = HttpSessionLimits {
        max_sessions: 1,
        max_age: Duration::from_secs(2),
        ..HttpSessionLimits::default()
    };
    limits.binding.max_usage = 1;
    let manager = manager(&clock, limits);
    let binding = binding(&clock, 3);
    register(&manager, &fixture, "owned", &binding);
    assert!(matches!(
        manager.register(
            "other",
            super::tests::binding(&clock, 4),
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::PoolFull)
    ));
    fetch(&manager, &fixture, "owned", &binding, "/set-a").await;
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Binding(_))
    ));
    let retired = manager
        .retire("owned", &binding, RetirementReason::Revoked, &TestAuthority)
        .await
        .unwrap();
    assert_eq!(retired.state, BindingState::Retired);
    assert!(manager.entries.lock()["owned"].cookies.is_empty());
    assert!(manager.entries.lock()["owned"].fetcher.is_none());
    assert!(matches!(
        manager.register(
            "owned",
            binding.clone(),
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Collision)
    ));
    let expired_manager = super::tests::manager(&clock, limits);
    register(&expired_manager, &fixture, "expired", &binding);
    clock.advance_ms(2_000);
    assert!(matches!(
        expired_manager
            .fetch_with_authority(
                "expired",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Expired)
    ));
    assert!(expired_manager.entries.lock()["expired"].fetcher.is_none());
}

#[tokio::test]
async fn authority_loss_capacity_and_cookie_override_fail_without_jar_rotation() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let limits = HttpSessionLimits {
        max_cookies: 1,
        ..HttpSessionLimits::default()
    };
    let manager = manager(&clock, limits);
    let binding = binding(&clock, 3);
    register(&manager, &fixture, "owned", &binding);
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Err(FetchError::AcquisitionCancelled)),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Fetch(FetchError::AcquisitionCancelled))
    ));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    let mut options = FetchOptions::default();
    options
        .headers
        .insert(header::COOKIE, HeaderValue::from_static("sid=foreign"));
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &options,
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::CookieOverride)
    ));
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.at("/many"),
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::CookieCapacity)
    ));
    let response = fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert_eq!(fields(&response)[1], "first=1");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_start_is_single_writer_and_cancellation_charges_one_use() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = Arc::new(manager(&clock, HttpSessionLimits::default()));
    let binding = binding(&clock, 3);
    register(&manager, &fixture, "owned", &binding);
    let entered = Arc::new(Notify::new());
    let task = {
        let manager = Arc::clone(&manager);
        let entered = Arc::clone(&entered);
        let binding = binding.clone();
        let url = fixture.url.clone();
        tokio::spawn(async move {
            manager
                .fetch_with_authority(
                    "owned",
                    &binding,
                    &url,
                    &FetchOptions::default(),
                    &|| async {
                        entered.notify_one();
                        std::future::pending::<Result<(), FetchError>>().await
                    },
                    &TestAuthority,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let client = Arc::clone(manager.entries.lock()["owned"].fetcher.as_ref().unwrap());
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Busy)
    ));
    assert!(matches!(
        manager
            .retire("owned", &binding, RetirementReason::Revoked, &TestAuthority)
            .await,
        Err(HttpSessionError::Busy)
    ));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(manager.snapshot("owned", &binding).unwrap().usage, 1);
    fetch(&manager, &fixture, "owned", &binding, "/echo").await;
    assert!(Arc::ptr_eq(
        &client,
        manager.entries.lock()["owned"].fetcher.as_ref().unwrap()
    ));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_lazy_start_is_not_retried() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    let mut config = config(&manager);
    config.proxy = Some(Url::parse("ftp://unsupported.test/").unwrap());
    manager
        .register(
            "owned",
            binding.clone(),
            config,
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::Fetch(_))
    ));
    assert!(matches!(
        manager
            .fetch_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &TestAuthority
            )
            .await,
        Err(HttpSessionError::StartupFailed)
    ));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn cookie_security_attributes_and_public_suffixes_are_enforced() {
    let now = clock().now();
    let secure = Url::parse("https://www.example.com/private/set").unwrap();
    let plain = Url::parse("http://www.example.com/private/set").unwrap();
    let cookie = StoredCookie::parse("sid=secret; Secure; Max-Age=2", &secure, now).unwrap();
    assert!(cookie.matches("www.example.com", "/private/next", true));
    assert!(!cookie.matches("other.www.example.com", "/private/next", true));
    assert!(!cookie.matches("www.example.com", "/private/next", false));
    assert_eq!(cookie.expires_at, Some(now + chrono::Duration::seconds(2)));
    assert!(StoredCookie::parse("sid=secret; Secure", &plain, now).is_none());
    assert!(StoredCookie::parse("sid=secret; Domain=com", &secure, now).is_none());
    assert!(StoredCookie::parse("sid=secret; Domain=foreign.test", &secure, now).is_none());
    assert!(StoredCookie::parse(
        "__Host-sid=secret; Secure; Domain=example.com; Path=/",
        &secure,
        now
    )
    .is_none());
    assert!(StoredCookie::parse("__Secure-sid=secret", &secure, now).is_none());
    let domain = StoredCookie::parse("sid=shared; Domain=example.com; Path=/", &secure, now).unwrap();
    assert!(domain.matches("api.example.com", "/", true));
    let expired =
        StoredCookie::parse("sid=gone; Expires=Wed, 09 Jun 2021 10:18:14 GMT", &secure, now).unwrap();
    assert!(expired.expires_at.unwrap() < now);
    let precedence = StoredCookie::parse(
        "sid=live; Max-Age=2; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
        &secure,
        now,
    )
    .unwrap();
    assert_eq!(precedence.expires_at, Some(now + chrono::Duration::seconds(2)));
}

#[tokio::test]
async fn durable_reservations_preserve_cookie_identity_and_distinguish_auth_from_rate_limits() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let mut limits = HttpSessionLimits::default();
    limits.binding.max_health_errors = 2;
    let registry = crawlx_core::captcha::CaptchaSecrets::default();
    let manager = manager(&clock, limits)
        .with_secret_registry(registry.clone())
        .unwrap();
    let mut binding = binding(&clock, 3);
    binding.health_errors = 1;
    let authority = PersistedAuthority::new(&binding);
    let mut config = config(&manager);
    let mut controls = crawlx_core::config::Fetch::default();
    controls
        .cookies
        .push(crawlx_core::request_controls::FetchCookie::new(
            "sid",
            "kept-secret",
        ));
    config.controls = crawlx_core::request_controls::RequestControls::resolve(&controls, "127.0.0.1", None)
        .await
        .unwrap();
    manager
        .register(
            "owned",
            binding.clone(),
            config,
            Arc::new(EgressPolicy::new(true).with_seed_port(&fixture.url)),
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
    assert!(registry.has_values().unwrap());
    let limited = manager
        .fetch_once_with_authority(
            "owned",
            &binding,
            &fixture.at("/limited"),
            &FetchOptions::default(),
            &|| std::future::ready(Ok(())),
            &authority,
        )
        .await
        .unwrap();
    assert_eq!(limited.status.as_u16(), 429);
    assert_eq!(fields(&limited)[1], "sid=kept-secret");
    assert_eq!(authority.current.lock().health_errors, 1);
    assert_eq!(authority.current.lock().usage, 1);
    assert_eq!(authority.writes.load(Ordering::SeqCst), 1);
    let unauthorized = manager
        .fetch_once_with_authority(
            "owned",
            &binding,
            &fixture.at("/unauthorized"),
            &FetchOptions::default(),
            &|| std::future::ready(Ok(())),
            &authority,
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status.as_u16(), 401);
    let persisted = authority.current.lock().clone();
    assert_eq!(persisted.health_errors, 2);
    assert_eq!(persisted.usage, 2);
    assert_eq!(persisted.state, BindingState::Draining);
    assert_eq!(persisted.retirement, Some(RetirementReason::Unhealthy));
    assert_eq!(manager.snapshot("owned", &binding).unwrap(), persisted);
    assert_eq!(
        manager.entries.lock()["owned"].cookies[0].cookie.value.expose(),
        "kept-secret"
    );
    assert_eq!(authority.writes.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_durable_reservation_never_sends_or_reuses_uncertain_authority() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    let mut authority = PersistedAuthority::new(&binding);
    authority.fail_write = true;
    register(&manager, &fixture, "owned", &binding);
    assert!(matches!(
        manager
            .fetch_once_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &authority
            )
            .await,
        Err(HttpSessionError::Fetch(FetchError::AcquisitionUnavailable))
    ));
    assert!(matches!(
        manager
            .fetch_once_with_authority(
                "owned",
                &binding,
                &fixture.url,
                &FetchOptions::default(),
                &|| std::future::ready(Ok(())),
                &authority
            )
            .await,
        Err(HttpSessionError::Unavailable)
    ));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    assert_eq!(authority.current.lock().usage, 0);
    assert_eq!(manager.snapshot("owned", &binding).unwrap().usage, 1);
}

#[tokio::test]
async fn cancellation_keeps_the_usage_reservation_in_existing_authority() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = Arc::new(manager(&clock, HttpSessionLimits::default()));
    let binding = binding(&clock, 3);
    let authority = Arc::new(PersistedAuthority::new(&binding));
    register(&manager, &fixture, "owned", &binding);
    let entered = Arc::new(Notify::new());
    let task = {
        let manager = Arc::clone(&manager);
        let binding = binding.clone();
        let authority = Arc::clone(&authority);
        let entered = Arc::clone(&entered);
        let url = fixture.url.clone();
        tokio::spawn(async move {
            manager
                .fetch_once_with_authority(
                    "owned",
                    &binding,
                    &url,
                    &FetchOptions::default(),
                    &|| async {
                        entered.notify_one();
                        std::future::pending::<Result<(), FetchError>>().await
                    },
                    authority.as_ref(),
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(authority.current.lock().usage, 1);
    assert_eq!(
        manager.snapshot("owned", &binding).unwrap(),
        *authority.current.lock()
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    let response = manager
        .fetch_once_with_authority(
            "owned",
            &binding,
            &fixture.at("/echo"),
            &FetchOptions::default(),
            &|| std::future::ready(Ok(())),
            authority.as_ref(),
        )
        .await
        .unwrap();
    assert!(response.status.is_success());
    assert_eq!(authority.current.lock().usage, 2);
}

struct BoundAdmission<'a> {
    manager: &'a NamedHttpSessions,
    binding: &'a SessionBindingV1,
    authority: &'a PersistedAuthority,
    origin: Url,
}

#[async_trait::async_trait]
impl crate::acquisition::HopAdmission for BoundAdmission<'_> {
    async fn admit(
        &self,
        url: &Url,
        _options: &FetchOptions,
        _budget: &mut crate::acquisition::AcquisitionBudgetV1,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<(), FetchError> {
        if cancel.is_cancelled() || url.origin() != self.origin.origin() {
            return Err(FetchError::AcquisitionUnavailable);
        }
        self.check_authority().await
    }

    async fn check_authority(&self) -> Result<(), FetchError> {
        self.manager
            .snapshot("owned", self.binding)
            .map(|_| ())
            .map_err(|_| FetchError::AcquisitionUnavailable)
    }

    fn requires_checked_hops(&self) -> bool {
        true
    }

    async fn fetch_attempt(
        &self,
        _fetcher: &Fetcher,
        url: &Url,
        options: &FetchOptions,
    ) -> Result<FetchResponse, FetchError> {
        self.manager
            .fetch_once_with_authority(
                "owned",
                self.binding,
                url,
                options,
                &|| self.check_authority(),
                self.authority,
            )
            .await
            .map_err(|error| match error {
                HttpSessionError::Fetch(error) => error,
                _ => FetchError::AcquisitionUnavailable,
            })
    }
}

#[tokio::test]
async fn native_get_uses_bound_session_transport_and_existing_acquisition_budget() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    let authority = PersistedAuthority::new(&binding);
    register(&manager, &fixture, "owned", &binding);
    manager
        .fetch_once_with_authority(
            "owned",
            &binding,
            &fixture.at("/set-a"),
            &FetchOptions::default(),
            &|| std::future::ready(Ok(())),
            &authority,
        )
        .await
        .unwrap();
    let ordinary = Fetcher::new(
        config(&manager),
        Arc::new(EgressPolicy::new(true).with_seed_port(&fixture.url)),
        Arc::new(StaticResolver::new()),
    )
    .unwrap();
    let policy = crawlx_core::acquisition::AcquisitionPolicyV1::default();
    let mut budget = crate::acquisition::AcquisitionBudgetV1::new(&policy).unwrap();
    let admission = BoundAdmission {
        manager: &manager,
        binding: &binding,
        authority: &authority,
        origin: fixture.url.clone(),
    };
    let acquired = crate::acquisition::fetch_native(
        &ordinary,
        &fixture.at("/echo"),
        &FetchOptions::default(),
        &policy,
        &mut budget,
        &tokio_util::sync::CancellationToken::new(),
        &crawlx_extract::ExtractOptions::default(),
        &crate::runtime::CpuPool::default(),
        owner().run,
        owner().tenant,
        &|_, _| {},
        true,
        Some(&manager.secrets),
        Some(&admission),
    )
    .await
    .unwrap();
    assert_eq!(fields(&acquired.response)[1], "sid=alpha");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    assert_eq!(authority.current.lock().usage, 2);
    assert!(acquired.metadata.network_requests > 0);
}

#[tokio::test]
async fn a_used_generation_cannot_be_recreated_with_a_fresh_volatile_jar() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let mut used = binding(&clock, 3);
    used.usage = 1;
    assert!(matches!(
        manager.register(
            "owned",
            used,
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Unavailable)
    ));
    assert!(manager.entries.lock().is_empty());
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registration_rejects_foreign_names_duplicate_slots_and_private_governors() {
    let fixture = Fixture::start(None).await;
    let clock = clock();
    let manager = manager(&clock, HttpSessionLimits::default());
    let binding = binding(&clock, 3);
    let mut foreign = binding.clone();
    foreign.identity.tenant = TenantId(Uuid::from_u128(99));
    assert!(matches!(
        manager.register(
            "foreign",
            foreign,
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Unavailable)
    ));
    assert!(matches!(
        manager.register(
            "bad name",
            binding.clone(),
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Configuration)
    ));
    assert!(matches!(
        manager.register(
            "private",
            binding.clone(),
            FetchConfig::default(),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Configuration)
    ));
    register(&manager, &fixture, "owned", &binding);
    assert!(matches!(
        manager.register(
            "alias",
            binding.clone(),
            config(&manager),
            Arc::new(EgressPolicy::new(true)),
            Arc::new(StaticResolver::new())
        ),
        Err(HttpSessionError::Collision)
    ));
    assert_eq!(manager.entries.lock().len(), 1);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_url_producer_routes_strict_generations_through_the_real_coordinator_lease() {
    use crate::url_plane::{UrlPlaneDeps, UrlPlaneRunner};
    use crawlx_core::config::{CrawlMode, SitemapMode};
    use crawlx_core::counters::RunStatus;
    use crawlx_core::orchestration::{OrchestrationConfigV1, RequestBatchV1};
    use crawlx_core::repo::FrontierStatus;
    use crawlx_core::request::RequestEnvelopeV1;
    use crawlx_core::{CreateCrawl, SystemClock};

    let fixture = Fixture::start(None).await;
    let directory = tempfile::tempdir().unwrap();
    let stores = crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut authorization =
        crawlx_policy::testkit::sample_record(stores.tenant, clock.now(), &[fixture.url.as_str()]);
    authorization.verified_at = Some(clock.now());
    authorization.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
    let source = Arc::new(crate::authorization::StaticAuthorizationSource::new(
        authorization.clone(),
    ));
    let mut crawl = CreateCrawl::new(fixture.at("/bound-first"));
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(73);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(authorization.id);
    crawl.politeness.delay_ms = 0;
    crawl.politeness.max_concurrency = 1;
    crawl.politeness.max_in_flight_per_origin = 1;
    crawl.scope.crawl_entire_domain = true;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files.clear();
    crawl.orchestration = Some(OrchestrationConfigV1::default());
    crawl.normalize().unwrap();
    let mut run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl.clone());
    run.id = CrawlRunId(Uuid::from_u128(0x4854_5450));
    run.status = RunStatus::Running;
    run.started_at = Some(clock.now());
    stores.runs.create(&run, None).await.unwrap();
    let config = crate::WorkerConfig {
        artifacts_dir: directory.path().to_path_buf(),
        egress: crate::EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..crate::EgressConfig::default()
        },
        gates: crate::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..crate::WorkerConfig::default()
    };
    let guard = crate::authorization::AuthorizationGuard::admit(
        run.id,
        None,
        Some(authorization.id),
        source,
        clock,
        Arc::clone(&stores.events),
        Duration::ZERO,
    )
    .await
    .unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let rc = Arc::new(
        crate::RunContext::build(
            &run,
            &config,
            stores.clone(),
            None,
            None,
            cancel.clone(),
            None,
            Some(guard),
        )
        .await
        .unwrap(),
    );
    let session = crawlx_scheduler::RunSlot {
        role_index: 0,
        role: PrincipalId::anonymous(),
        run_index: 1,
        schedule_slot: 0,
    }
    .into_session(run.id);
    stores
        .runs
        .create_sessions(std::slice::from_ref(&session))
        .await
        .unwrap();
    let scheduler = crawlx_scheduler::Scheduler::new(Arc::clone(&stores.leases));
    let lease = scheduler
        .lease_in_run(run.id, rc.worker, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.id, session.id);
    let (fetcher, _) = crate::run::build_fetcher(
        &crawl,
        run.id,
        run.seed,
        &config,
        rc.controls.clone(),
        rc.authorization.as_ref().map(|guard| guard.record()),
        Arc::clone(&rc.origin_governor),
    )
    .unwrap();
    let registration = crate::session_lifecycle::register_http_session(&rc, &lease, &fetcher)
        .await
        .unwrap();
    let manager = Arc::clone(&registration.manager);
    let authority = Arc::clone(&registration.authority);
    let mut requests = Vec::new();
    for (index, (path, generation)) in [("/bound-first", 1), ("/bound-second", 1), ("/bound-stale", 2)]
        .into_iter()
        .enumerate()
    {
        let url = crawlx_url::Canonicalizer::canonicalize_url(&fixture.at(path), &rc.canon).unwrap();
        let mut envelope = RequestEnvelopeV1::get(url, 0, None);
        envelope.session_generation = Some(generation);
        envelope.priority = i32::try_from(3 - index).unwrap();
        requests.push(envelope);
    }
    let batch = RequestBatchV1::new(
        stores.tenant,
        run.id,
        "anonymous".to_owned(),
        Digest::of("crawlx/http-session/producer-fixture", b"strict-generations"),
        requests,
    );
    let receipt = stores.frontier.append_batch(batch).await.unwrap();
    assert_eq!(receipt.inserted.len(), 3);
    let deps = UrlPlaneDeps {
        runs: Arc::clone(&stores.runs),
        frontier: Arc::clone(&stores.frontier),
        request_commits: Arc::clone(&stores.request_commits),
        source_memo: Arc::clone(&stores.source_memo),
        leases: Arc::clone(&stores.leases),
        pages: Arc::clone(&stores.pages),
        events: Arc::clone(&stores.events),
        artifacts: Arc::clone(&stores.artifacts),
        archives: Arc::clone(&stores.archives),
        clock: Arc::clone(&rc.clock),
    };
    let plane = UrlPlaneRunner::new(
        run.id,
        crawl,
        rc.worker,
        deps,
        fetcher,
        rc.counters.clone(),
        rc.canon.clone(),
    )
    .unwrap()
    .with_cpu_pool(rc.cpu_pool.clone())
    .with_surface_services(&rc)
    .with_authorization(rc.authorization.clone())
    .with_http_sessions(Arc::clone(&manager), Arc::clone(&authority));
    plane.seed_if_empty().await.unwrap();
    let producer = stores.session_producer(run.id, &lease);
    tokio::time::timeout(
        Duration::from_secs(10),
        crawlx_core::custody::with_producer(producer, Box::pin(plane.run(&cancel))),
    )
    .await
    .unwrap()
    .unwrap();
    for id in &receipt.inserted[..2] {
        let queued = stores.frontier.get_request(run.id, *id).await.unwrap();
        assert_eq!(queued.entry.status, FrontierStatus::Succeeded);
    }
    let stale = stores
        .frontier
        .get_request(run.id, receipt.inserted[2])
        .await
        .unwrap();
    assert_eq!(stale.entry.status, FrontierStatus::Failed);
    {
        let seen = fixture.requests.lock();
        let first = seen
            .iter()
            .find(|request| request.path == "/bound-first")
            .unwrap();
        let second = seen
            .iter()
            .find(|request| request.path == "/bound-second")
            .unwrap();
        assert_eq!(first.cookie, "");
        assert_eq!(second.cookie, "sid=producer-cookie");
        assert_eq!(first.connection, second.connection);
        assert!(!seen.iter().any(|request| request.path == "/bound-stale"));
    }
    let current = manager.binding(DEFAULT_HTTP_SESSION).unwrap();
    assert_eq!(current.identity.session, lease.session.id);
    assert_eq!(current.lease_fence, lease.fencing_token);
    assert_eq!(current.generation, 1);
    assert!(current.usage >= 2);
    manager
        .retire(
            DEFAULT_HTTP_SESSION,
            &current,
            RetirementReason::Revoked,
            authority.as_ref(),
        )
        .await
        .unwrap();
    scheduler.release(&lease, SessionStatus::Completed).await.unwrap();
}
