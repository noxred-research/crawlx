//! Admitted writes through the fetch plane: exact bodies, one dispatch, no retry, no redirect.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use bytes::Bytes;
use common::{allow_private_policy, fast_config, fetcher, url, LOOPBACK};
use crawlx_fetch::client::WriteRequest;
use crawlx_fetch::{FetchError, FetchOptions, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use http::Method;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver() -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    r.set("pub.test", [LOOPBACK]);
    Arc::new(r)
}

fn ready() -> impl Fn() -> std::future::Ready<Result<(), FetchError>> + Sync {
    || std::future::ready(Ok(()))
}

#[tokio::test]
async fn form_json_delete_and_patch_bodies_arrive_byte_for_byte() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(201).set_body_raw("created", "text/plain"))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let target = url("pub.test", &server, "/api/item");
    let json: &[u8] = r#"{"name":"naïve \"quoted\"","n":[1,2,3]}"#.as_bytes();
    let binary: Vec<u8> = (0..=255u8).collect();
    let cases: Vec<(Method, Vec<u8>, Option<&str>)> = vec![
        (
            Method::POST,
            b"a=1&b=two+words&c=%E2%9C%93".to_vec(),
            Some("application/x-www-form-urlencoded"),
        ),
        (Method::PUT, json.to_vec(), Some("application/json")),
        (
            Method::DELETE,
            b"{\"reason\":\"cleanup\"}".to_vec(),
            Some("application/json"),
        ),
        (Method::PATCH, binary.clone(), Some("application/octet-stream")),
        (Method::DELETE, Vec::new(), None),
    ];
    for (method, body, content_type) in &cases {
        let write = WriteRequest::new(method.clone(), Bytes::from(body.clone()), *content_type).unwrap();
        let response = f
            .send_write(&target, &write, &FetchOptions::default(), &ready())
            .await
            .unwrap();
        assert_eq!(response.status.as_u16(), 201);
        assert_eq!(response.attempts, 1);
    }
    let seen = server.received_requests().await.unwrap();
    assert_eq!(seen.len(), cases.len(), "one dispatch per write");
    for (received, (method, body, content_type)) in seen.iter().zip(&cases) {
        assert_eq!(received.method.as_str(), method.as_str());
        assert_eq!(received.url.path(), "/api/item");
        assert_eq!(&received.body, body, "{method}");
        assert_eq!(
            received.headers.get("content-type").map(|v| v.to_str().unwrap()),
            *content_type,
            "{method}"
        );
    }
}

#[tokio::test]
async fn a_retryable_status_is_answered_once_and_never_retried() {
    let server = MockServer::start().await;
    for status in [429, 500, 502, 503] {
        server.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "0"))
            .mount(&server)
            .await;
        // `fast_config` allows three read retries: a write must still get none.
        let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
        let write = WriteRequest::new(Method::POST, Bytes::from_static(b"once"), Some("text/plain")).unwrap();
        let response = f
            .send_write(
                &url("pub.test", &server, "/charge"),
                &write,
                &FetchOptions::default(),
                &ready(),
            )
            .await
            .unwrap();
        assert_eq!(response.status.as_u16(), status);
        assert_eq!(response.attempts, 1, "{status}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1, "{status}");
    }
}

#[tokio::test]
async fn redirects_are_returned_as_answers_never_followed_with_the_body() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/elsewhere"))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let write = WriteRequest::new(Method::PUT, Bytes::from_static(b"payload"), None).unwrap();
    // Even a caller that asks for redirects gets none: a write is never re-sent to a new target.
    let options = FetchOptions {
        follow_redirects: true,
        ..FetchOptions::default()
    };
    let response = f
        .send_write(&url("pub.test", &server, "/start"), &write, &options, &ready())
        .await
        .unwrap();
    assert_eq!(response.status.as_u16(), 307);
    assert!(response.redirects.is_empty());
    let seen = server.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url.path(), "/start");
}

#[tokio::test]
async fn failures_before_dispatch_say_so_and_failures_after_it_say_unknown() {
    // Refused by the egress policy: nothing was handed to the transport.
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut deny = EgressPolicy::new(false);
    deny.extra_ports.push(server.address().port());
    let f = fetcher(fast_config(), deny, resolver());
    let write = WriteRequest::new(Method::POST, Bytes::from_static(b"x"), None).unwrap();
    let failure = f
        .send_write(
            &url("pub.test", &server, "/"),
            &write,
            &FetchOptions::default(),
            &ready(),
        )
        .await
        .unwrap_err();
    assert!(matches!(failure.error, FetchError::EgressDenied(_)));
    assert!(!failure.dispatched);
    assert!(server.received_requests().await.unwrap().is_empty());

    // Refused by the caller's authority check right before the send.
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let refused = || std::future::ready(Err(FetchError::AcquisitionCancelled));
    let failure = f
        .send_write(
            &url("pub.test", &server, "/"),
            &write,
            &FetchOptions::default(),
            &refused,
        )
        .await
        .unwrap_err();
    assert!(matches!(failure.error, FetchError::AcquisitionCancelled));
    assert!(!failure.dispatched);

    // The shared request allowance is charged before dispatch, too.
    let options = FetchOptions {
        request_allowance: Some(Arc::new(AtomicU32::new(0))),
        ..FetchOptions::default()
    };
    let failure = f
        .send_write(&url("pub.test", &server, "/"), &write, &options, &ready())
        .await
        .unwrap_err();
    assert!(matches!(failure.error, FetchError::AcquisitionAllowance));
    assert!(!failure.dispatched);
    assert!(server.received_requests().await.unwrap().is_empty());

    // A peer that takes the connection and closes it without answering: the request was
    // handed to the transport, so the outcome is unknown and must not be reported as unsent.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(port);
    let f = fetcher(fast_config(), policy, resolver());
    let failure = f
        .send_write(
            &Url::parse(&format!("http://pub.test:{port}/")).unwrap(),
            &write,
            &FetchOptions::default(),
            &ready(),
        )
        .await
        .unwrap_err();
    accepted.await.unwrap();
    assert!(failure.dispatched, "{:?}", failure.error);
}

#[tokio::test]
async fn read_entry_points_still_refuse_mutating_methods_and_non_write_methods_cannot_be_wrapped() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let target = url("pub.test", &server, "/");
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let options = FetchOptions {
            method,
            ..FetchOptions::default()
        };
        assert!(matches!(
            f.fetch(&target, &options).await.unwrap_err(),
            FetchError::UnsupportedMethod(_)
        ));
        assert!(matches!(
            f.fetch_once(&target, &options).await.unwrap_err(),
            FetchError::UnsupportedMethod(_)
        ));
    }
    for method in [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::CONNECT,
    ] {
        assert!(matches!(
            WriteRequest::new(method, Bytes::new(), None).unwrap_err(),
            FetchError::UnsupportedMethod(_)
        ));
    }
    assert!(matches!(
        WriteRequest::new(Method::POST, Bytes::new(), Some("text/plain\r\nx-injected: 1")).unwrap_err(),
        FetchError::InvalidHeader { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}
