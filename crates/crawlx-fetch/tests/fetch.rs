//! Integration tests of the HTTP fetch plane against a local mock server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::{allow_private_policy, fast_config, fetcher, loopback_only_policy, url, LOOPBACK};
use crawlx_fetch::{FetchError, FetchOptions, StaticResolver, Validators};
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use http::{header, HeaderValue, Method};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;
use wiremock::matchers::{header as header_is, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver(hosts: &[&str]) -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    for h in hosts {
        r.set(h, [LOOPBACK]);
    }
    Arc::new(r)
}

#[tokio::test]
async fn returns_200_body_with_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("hi there", "text/plain; charset=utf-8"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let resp = f
        .fetch(&url("pub.test", &server, "/hello"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body[..], b"hi there");
    assert!(!resp.truncated);
    assert!(resp.redirects.is_empty());
    assert_eq!(resp.resolved_ip, LOOPBACK);
    assert_eq!(resp.content_type.as_deref(), Some("text/plain; charset=utf-8"));
    assert_eq!(resp.attempts, 1);
    assert_eq!(resp.final_url.path(), "/hello");

    // Host keeps the hostname although the connection went to the pinned IP;
    // the User-Agent names the contact.
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let host = reqs[0].headers.get("host").unwrap().to_str().unwrap().to_owned();
    assert_eq!(host, format!("pub.test:{}", server.address().port()));
    let ua = reqs[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        ua,
        format!("crawlx/{} (+ops@example.test)", env!("CARGO_PKG_VERSION"))
    );
}

#[tokio::test]
async fn capture_reports_each_fetch_plane_response_as_a_fetch_plane_flow() {
    use crawlx_core::traffic::{BodyDigest, Protocol, ProxyFlowSource, REDACTED_PLACEHOLDER};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/b"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "s=server-secret")
                .set_body_string("final"),
        )
        .mount(&server)
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    )
    .with_capture(tx);
    let mut opts = FetchOptions::default();
    opts.headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer client-secret"),
    );
    let resp = f.fetch(&url("pub.test", &server, "/a"), &opts).await.unwrap();
    assert_eq!(resp.status.as_u16(), 200);

    let first = rx.try_recv().unwrap();
    let second = rx.try_recv().unwrap();
    assert!(rx.try_recv().is_err(), "one flow per response");
    for flow in [&first, &second] {
        assert_eq!(flow.source, ProxyFlowSource::FetchPlane);
        assert_eq!(flow.method, "GET");
        assert_eq!(flow.protocol, Protocol::Http11);
        assert_eq!(flow.peer, None);
        assert!(flow.tunnel.is_none());
        assert!(flow.finished_at >= flow.started_at);
        assert!(!format!("{flow:?}").contains("secret"), "{flow:?}");
        let auth = flow.request_headers.iter().find(|(k, _)| k == "authorization");
        assert_eq!(auth.map(|(_, v)| v.as_str()), Some(REDACTED_PLACEHOLDER));
    }
    assert_eq!(first.status, Some(302));
    assert!(first.url.ends_with("/a"));
    assert_eq!(first.response_body, None);
    assert_eq!(second.status, Some(200));
    assert!(second.url.ends_with("/b"));
    assert_eq!(second.response_body, Some(BodyDigest::of_prefix(b"final", 5)));
}

#[tokio::test]
async fn retries_429_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/r"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/r"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let resp = f
        .fetch(&url("pub.test", &server, "/r"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body[..], b"ok");
    assert_eq!(resp.attempts, 2);
    // The 429 widened the origin spacing.
    let o = crawlx_fetch::Origin::from_url(&resp.final_url);
    assert!(f.governor().current_delay(&o) >= Duration::from_millis(5));
}

#[tokio::test]
async fn honors_retry_after_seconds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("back"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let t = Instant::now();
    let resp = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap();
    assert!(t.elapsed() >= Duration::from_millis(950), "{:?}", t.elapsed());
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.attempts, 2);
}

#[tokio::test]
async fn exhausted_retries_return_last_throttle_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let resp = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 503);
    assert_eq!(resp.attempts, 4); // 1 + max_retries
}

#[tokio::test]
async fn borrowed_authority_is_checked_before_every_configured_retry() {
    for permitted_sends in [1u32, 4] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let f = fetcher(
            fast_config(),
            allow_private_policy(&server),
            resolver(&["pub.test"]),
        );
        let checks = std::sync::atomic::AtomicU32::new(0);
        let authority = || {
            let check = checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if check < permitted_sends {
                Ok(())
            } else {
                Err(FetchError::AcquisitionCancelled)
            })
        };
        let target = url("pub.test", &server, "/");
        let options = FetchOptions::default();
        let result = f.fetch_with_authority(&target, &options, &authority).await;
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            usize::try_from(permitted_sends).unwrap()
        );
        if permitted_sends == 1 {
            assert!(matches!(result, Err(FetchError::AcquisitionCancelled)));
            assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 2);
        } else {
            let response = result.unwrap();
            assert_eq!(response.status.as_u16(), 503);
            assert_eq!(response.attempts, permitted_sends);
            assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), permitted_sends);
        }
    }
}

#[tokio::test]
async fn huge_retry_after_is_not_waited_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let t = Instant::now();
    let resp = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 429);
    assert_eq!(resp.attempts, 1);
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn follows_redirect_chain_with_recheck() {
    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/b"))
        .mount(&server)
        .await;
    Mock::given(path("/b"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("Location", format!("http://other.test:{port}/c").as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(path("/c"))
        .respond_with(ResponseTemplate::new(200).set_body_string("end"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    let resp = f
        .fetch(&url("pub.test", &server, "/a"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body[..], b"end");
    assert_eq!(resp.final_url.as_str(), format!("http://other.test:{port}/c"));
    assert_eq!(
        resp.redirects,
        vec![
            format!("http://pub.test:{port}/a"),
            format!("http://pub.test:{port}/b")
        ]
    );
    assert_eq!(resp.attempts, 3);
    // Each hop was re-resolved: the last Host header is the new name.
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(
        reqs.last()
            .unwrap()
            .headers
            .get("host")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("other.test:{port}")
    );
}

#[tokio::test]
async fn redirect_to_host_resolving_to_denied_range_is_refused() {
    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(path("/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("http://evil.test:{port}/x").as_str()),
        )
        .mount(&server)
        .await;
    // Only 127.0.0.1 is exempt (allow_private=false otherwise); evil.test maps to another loopback address.
    let r = resolver(&["pub.test"]);
    r.set("evil.test", [IpAddr::from([127, 0, 0, 2])]);
    let f = fetcher(fast_config(), loopback_only_policy(&server), r);
    let err = f
        .fetch(&url("pub.test", &server, "/start"), &FetchOptions::default())
        .await
        .unwrap_err();
    match err {
        FetchError::EgressDenied(d) => assert_eq!(d.rule, DenyRule::Loopback),
        other => panic!("expected EgressDenied, got {other:?}"),
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "only the first hop may reach the network"
    );
}

#[tokio::test]
async fn redirect_to_metadata_literal_is_refused() {
    let server = MockServer::start().await;
    Mock::given(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "http://169.254.169.254/latest/meta-data/"),
        )
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        loopback_only_policy(&server),
        resolver(&["pub.test"]),
    );
    let err = f
        .fetch(&url("pub.test", &server, "/start"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::EgressDenied(_)), "{err:?}");
}

#[tokio::test]
async fn first_hop_to_private_address_is_refused_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut policy = EgressPolicy::new(false);
    policy.extra_ports.push(server.address().port());
    let f = fetcher(fast_config(), policy, resolver(&["pub.test"]));
    let denials = Metrics::global().counter(names::EGRESS_DENIALS);
    let labels = [("plane", "http"), ("reason", DenyRule::Loopback.as_str())];
    let denied_before = denials.get(&labels);
    let responses = Metrics::global().counter(names::FETCH_RESPONSES);
    let errors_before = responses.get(&[("outcome", "error")]);
    let err = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, FetchError::EgressDenied(d) if d.rule == DenyRule::Loopback),
        "{err:?}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    // metrics are process-global; sibling tests deny concurrently, so assert lower bounds
    assert!(denials.get(&labels) > denied_before, "http-plane denial counted");
    assert!(
        responses.get(&[("outcome", "error")]) > errors_before,
        "failed fetch counted as error outcome"
    );
}

#[tokio::test]
async fn localhost_name_and_ip_literals_are_refused() {
    let server = MockServer::start().await;
    let mut policy = EgressPolicy::new(false);
    policy.extra_ports.push(server.address().port());
    let f = fetcher(fast_config(), policy, Arc::new(StaticResolver::new()));
    for u in [
        format!("http://localhost:{}/", server.address().port()),
        format!("http://127.0.0.1:{}/", server.address().port()),
        format!("http://[::1]:{}/", server.address().port()),
    ] {
        let err = f
            .fetch(&url::Url::parse(&u).unwrap(), &FetchOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::EgressDenied(_)), "{u}: {err:?}");
    }
}

#[tokio::test]
async fn mixed_public_and_private_answer_is_refused() {
    let server = MockServer::start().await;
    let r = StaticResolver::new().with("rebind.test", [IpAddr::from([93, 184, 216, 34]), LOOPBACK]);
    let f = fetcher(fast_config(), allow_private_policy_strict(&server), Arc::new(r));
    let err = f
        .fetch(&url("rebind.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::EgressDenied(_)), "{err:?}");
}

fn allow_private_policy_strict(server: &MockServer) -> EgressPolicy {
    let mut p = EgressPolicy::new(false);
    p.extra_ports.push(server.address().port());
    p
}

#[tokio::test]
async fn rebinding_between_fetches_is_caught_by_re_resolution() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let r = resolver(&["pub.test"]);
    let f = fetcher(fast_config(), loopback_only_policy(&server), Arc::clone(&r));
    let u = url("pub.test", &server, "/");
    assert_eq!(
        f.fetch(&u, &FetchOptions::default())
            .await
            .unwrap()
            .status
            .as_u16(),
        200
    );
    // The name now answers with a private address; the pooled connection must not be a way around the check.
    r.set("pub.test", [IpAddr::from([10, 0, 0, 5])]);
    let err = f.fetch(&u, &FetchOptions::default()).await.unwrap_err();
    assert!(
        matches!(&err, FetchError::EgressDenied(d) if d.rule == DenyRule::Private),
        "{err:?}"
    );
}

#[tokio::test]
async fn redirect_limit_is_enforced() {
    let server = MockServer::start().await;
    Mock::given(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/loop"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let opts = FetchOptions {
        max_redirects: Some(3),
        ..FetchOptions::default()
    };
    let err = f
        .fetch(&url("pub.test", &server, "/loop"), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::TooManyRedirects { limit: 3 }),
        "{err:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn redirects_can_be_left_to_the_caller() {
    let server = MockServer::start().await;
    Mock::given(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/b"))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let opts = FetchOptions {
        follow_redirects: false,
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/a"), &opts).await.unwrap();
    assert_eq!(resp.status.as_u16(), 302);
    assert_eq!(resp.headers.get(header::LOCATION).unwrap(), "/b");
}

#[tokio::test]
async fn cross_origin_redirect_drops_credentials() {
    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(path("/a"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("http://other.test:{port}/b").as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(path("/b"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    let mut opts = FetchOptions::default();
    opts.headers
        .insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
    f.fetch(&url("pub.test", &server, "/a"), &opts).await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    assert!(reqs[0].headers.contains_key("authorization"));
    assert!(!reqs[1].headers.contains_key("authorization"));
}

#[tokio::test]
async fn body_is_truncated_at_the_cap() {
    let server = MockServer::start().await;
    Mock::given(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 20_000]))
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let opts = FetchOptions {
        max_body_bytes: Some(1024),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/big"), &opts).await.unwrap();
    assert!(resp.truncated);
    assert_eq!(resp.body.len(), 1024);
    // A body of exactly the cap is complete, not truncated.
    let opts = FetchOptions {
        max_body_bytes: Some(20_000),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/big"), &opts).await.unwrap();
    assert!(!resp.truncated);
    assert_eq!(resp.body.len(), 20_000);
}

#[tokio::test]
async fn default_body_cap_is_8_mib() {
    let f = fetcher(
        fast_config(),
        EgressPolicy::new(false),
        Arc::new(StaticResolver::new()),
    );
    assert_eq!(f.config().max_body_bytes, 8 * 1024 * 1024);
    assert_eq!(f.config().max_redirects, 10);
}

#[tokio::test]
async fn conditional_request_gets_304() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/doc"))
        .and(header_is("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304).insert_header("ETag", "\"v1\""))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/doc"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("ETag", "\"v1\"")
                .insert_header("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT")
                .set_body_string("content"),
        )
        .mount(&server)
        .await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let u = url("pub.test", &server, "/doc");
    let first = f.fetch(&u, &FetchOptions::default()).await.unwrap();
    assert!(!first.not_modified());
    let validators = first.validators();
    assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
    assert!(validators.last_modified.is_some());

    let second = f
        .fetch(
            &u,
            &FetchOptions {
                validators: Some(validators),
                ..FetchOptions::default()
            },
        )
        .await
        .unwrap();
    assert!(second.not_modified());
    assert!(second.body.is_empty());
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs[1].headers.get("if-none-match").unwrap(), "\"v1\"");
    assert_eq!(
        reqs[1].headers.get("if-modified-since").unwrap(),
        "Sun, 06 Nov 1994 08:49:37 GMT"
    );
}

#[tokio::test]
async fn only_get_and_head_are_supported() {
    #[derive(Debug)]
    struct UnavailableBodySink(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl crawlx_core::browser::ResponseBodySink for UnavailableBodySink {
        async fn store(
            &self,
            _: &str,
            _: &[u8],
            _: bool,
        ) -> Result<Option<crawlx_core::ArtifactRef>, crawlx_core::StoreError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crawlx_core::StoreError::Unavailable(
                "owned fixture body store unavailable".into(),
            ))
        }
    }
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-A", "1")
                .insert_header("Content-Length", "1000000")
                .insert_header("Content-Encoding", "gzip"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("owned GET body"))
        .mount(&server)
        .await;
    let sink = Arc::new(UnavailableBodySink(std::sync::atomic::AtomicUsize::new(0)));
    let (capture, mut captured) = tokio::sync::mpsc::channel(4);
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    )
    .with_response_body_sink(
        crawlx_core::config::ResponseBodies::Full,
        sink.clone(),
        url("pub.test", &server, "/"),
    )
    .with_capture(capture);
    let u = url("pub.test", &server, "/");
    let err = f
        .fetch(
            &u,
            &FetchOptions {
                method: Method::POST,
                ..FetchOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::UnsupportedMethod(_)));
    let head = f
        .fetch(
            &u,
            &FetchOptions {
                method: Method::HEAD,
                ..FetchOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(head.status.as_u16(), 200);
    assert!(head.body.is_empty());
    assert_eq!(head.headers["x-a"], "1");
    assert_eq!(head.headers["content-length"], "1000000");
    assert_eq!(head.headers["content-encoding"], "gzip");
    let evidence = head.evidence().unwrap();
    assert!(!evidence.body.decoded);
    assert_eq!(evidence.body.wire_bytes, 0);
    assert_eq!(evidence.body.decoded_bytes, 0);
    assert_eq!(evidence.body.declared_length, Some(1_000_000));
    assert!(head.retained_response_body().is_none());
    assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let flow = captured.try_recv().unwrap();
    assert_eq!(flow.method, "HEAD");
    assert!(flow.response_body.is_none());
    let get = f.fetch(&u, &FetchOptions::default()).await.unwrap();
    assert_eq!(get.body.as_ref(), b"owned GET body");
    assert_eq!(get.headers["x-crawlx-stream-body-capture"], "storage_error");
    assert_eq!(sink.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let flow = captured.try_recv().unwrap();
    assert_eq!(flow.method, "GET");
    assert_eq!(
        flow.response_body,
        Some(crawlx_core::traffic::BodyDigest::of_prefix(b"owned GET body", 14))
    );
}

#[tokio::test]
async fn proxy_environment_variables_are_ignored() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("direct"))
        .mount(&server)
        .await;
    // A dead proxy: any request routed through it would fail.
    std::env::set_var("HTTP_PROXY", "http://127.0.0.1:9");
    std::env::set_var("http_proxy", "http://127.0.0.1:9");
    std::env::set_var("ALL_PROXY", "http://127.0.0.1:9");
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test"]),
    );
    let resp = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(&resp.body[..], b"direct");
}

#[tokio::test]
async fn unresolvable_host_is_a_resolve_error() {
    let server = MockServer::start().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        Arc::new(StaticResolver::new()),
    );
    let err = f
        .fetch(&url("nowhere.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Resolve { .. }), "{err:?}");
}

#[tokio::test]
async fn governor_spaces_requests_to_one_origin() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut cfg = fast_config();
    cfg.governor.base_delay = Duration::from_millis(150);
    let f = fetcher(cfg, allow_private_policy(&server), resolver(&["pub.test"]));
    let u = url("pub.test", &server, "/");
    let t = Instant::now();
    for _ in 0..3 {
        f.fetch(&u, &FetchOptions::default()).await.unwrap();
    }
    assert!(t.elapsed() >= Duration::from_millis(290), "{:?}", t.elapsed());
}

#[test]
fn validators_type_is_reexported() {
    assert!(Validators::default().is_empty());
}

// ---------------------------------------------------------------------------
// Upstream proxy and request-level fetch tuning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upstream_http_proxy_receives_the_absolute_request() {
    // wiremock plays the upstream proxy: an HTTP proxy receives `GET http://target/...`.
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("via proxy"))
        .mount(&proxy)
        .await;
    let mut cfg = fast_config();
    cfg.proxy = Some(url("proxy.test", &proxy, "/"));
    // the target lives on an address the resolver never maps: only the proxy is dialed
    let r = StaticResolver::new()
        .with("proxy.test", [LOOPBACK])
        .with("target.test", [IpAddr::from([93, 184, 216, 34])]);
    let f = fetcher(cfg, allow_private_policy(&proxy), Arc::new(r));
    let resp = f
        .fetch(&url("target.test", &proxy, "/hello"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(&resp.body[..], b"via proxy");
    assert_eq!(resp.resolved_ip, LOOPBACK, "the connection went to the proxy");
    let reqs = proxy.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let host = reqs[0].headers.get("host").unwrap().to_str().unwrap().to_owned();
    assert_eq!(host, format!("target.test:{}", proxy.address().port()));
}

#[tokio::test]
async fn target_is_still_egress_checked_behind_a_proxy() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&proxy)
        .await;
    let mut cfg = fast_config();
    cfg.proxy = Some(url("proxy.test", &proxy, "/"));
    let r = StaticResolver::new()
        .with("proxy.test", [LOOPBACK])
        .with("internal.test", [IpAddr::from([10, 0, 0, 7])]);
    let f = fetcher(cfg, loopback_only_policy(&proxy), Arc::new(r));
    let err = f
        .fetch(&url("internal.test", &proxy, "/"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::EgressDenied(_)), "{err:?}");
    assert!(proxy.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn proxy_on_a_denied_address_is_egress_denied() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut cfg = fast_config();
    cfg.proxy = Some(Url::parse("http://proxy.test:3128/").unwrap());
    let r = StaticResolver::new()
        .with("pub.test", [LOOPBACK])
        .with("proxy.test", [IpAddr::from([10, 0, 0, 9])]);
    let f = fetcher(cfg, loopback_only_policy(&server), Arc::new(r));
    let err = f
        .fetch(&url("pub.test", &server, "/"), &FetchOptions::default())
        .await
        .unwrap_err();
    match err {
        FetchError::EgressDenied(d) => assert_eq!(d.rule, DenyRule::Private, "{d:?}"),
        other => panic!("{other:?}"),
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn proxy_scheme_is_validated_at_build_time() {
    let mut cfg = fast_config();
    cfg.proxy = Some(Url::parse("ftp://proxy.test/").unwrap());
    let err = crawlx_fetch::Fetcher::new(
        cfg,
        Arc::new(EgressPolicy::new(false)),
        Arc::new(StaticResolver::new()),
    )
    .err()
    .unwrap();
    assert!(matches!(err, FetchError::InvalidUrl { .. }), "{err:?}");
    for ok in [
        "http://p.test:3128",
        "socks5://p.test:1080",
        "socks5h://p.test:1080",
    ] {
        let mut cfg = fast_config();
        cfg.proxy = Some(Url::parse(ok).unwrap());
        assert!(crawlx_fetch::Fetcher::new(
            cfg,
            Arc::new(EgressPolicy::new(false)),
            Arc::new(StaticResolver::new()),
        )
        .is_ok());
    }
}

#[tokio::test]
async fn config_follow_redirects_false_returns_the_redirect() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/b"))
        .mount(&server)
        .await;
    let mut cfg = fast_config();
    cfg.follow_redirects = false;
    let f = fetcher(cfg, allow_private_policy(&server), resolver(&["pub.test"]));
    let resp = f
        .fetch(&url("pub.test", &server, "/a"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 302);
    assert!(resp.redirects.is_empty());
    assert_eq!(resp.final_url.path(), "/a");
}

#[test]
fn fetch_config_from_request_maps_every_field() {
    let fetch = crawlx_core::config::Fetch {
        max_response_bytes: 1_048_576,
        timeout_ms: 2_500,
        retries: 4,
        follow_redirects: false,
        proxy: Some(Url::parse("socks5h://p.test:1080").unwrap()),
        tls_impersonation: crawlx_core::tls::TlsImpersonation::Randomized,
        ..crawlx_core::config::Fetch::default()
    };
    let cfg = crawlx_fetch::FetchConfig::from_request(&fetch);
    assert_eq!(cfg.max_body_bytes, 1_048_576);
    assert_eq!(cfg.request_timeout, Duration::from_millis(2_500));
    assert!(cfg.connect_timeout <= cfg.request_timeout);
    assert_eq!(cfg.retry.max_retries, 4);
    assert!(!cfg.follow_redirects);
    assert_eq!(cfg.proxy.as_ref().map(Url::as_str), Some("socks5h://p.test:1080"));
    assert_eq!(
        cfg.tls_impersonation,
        crawlx_core::tls::TlsImpersonation::Randomized
    );
    let defaults = crawlx_fetch::FetchConfig::from_request(&crawlx_core::config::Fetch::default());
    assert_eq!(defaults.max_body_bytes, 8 * 1024 * 1024);
    assert_eq!(defaults.request_timeout, Duration::from_millis(10_000));
    assert_eq!(defaults.retry.max_retries, 1);
    assert!(defaults.follow_redirects);
    assert!(defaults.proxy.is_none());
    assert_eq!(
        defaults.tls_impersonation,
        crawlx_core::tls::TlsImpersonation::Off
    );
}
