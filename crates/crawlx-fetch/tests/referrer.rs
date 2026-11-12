//! Outbound `Referer` of the fetch plane: the policy is judged per hop, secret query parameters
//! never leave, and an explicit `Referer` is never replaced.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::{allow_private_policy, fast_config, fetcher, url, LOOPBACK};
use crawlx_core::config::{Fetch, ReferrerPolicy};
use crawlx_core::request_controls::RequestControls;
use crawlx_fetch::redirect::Referrer;
use crawlx_fetch::{FetchOptions, StaticResolver};
use http::{header, HeaderValue};
use std::sync::Arc;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver(hosts: &[&str]) -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    for h in hosts {
        r.set(h, [LOOPBACK]);
    }
    Arc::new(r)
}

/// `pub.test/a` redirects to `other.test/b`.
async fn redirecting_server() -> MockServer {
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
    server
}

fn referer_of(request: &wiremock::Request) -> Option<String> {
    request
        .headers
        .get("referer")
        .map(|value| value.to_str().unwrap().to_owned())
}

fn options(server: &MockServer, policy: ReferrerPolicy) -> FetchOptions {
    let source = url(
        "pub.test",
        server,
        "/dir/page?keep=1&token=hunter2hunter2&utm_source=x#frag",
    );
    FetchOptions {
        referrer: Referrer::new(&source, policy, &|_| false),
        ..FetchOptions::default()
    }
}

#[tokio::test]
async fn the_policy_is_judged_for_every_hop_and_secrets_are_redacted() {
    let server = redirecting_server().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    let port = server.address().port();
    f.fetch(
        &url("pub.test", &server, "/a"),
        &options(&server, ReferrerPolicy::OriginWhenCrossOrigin),
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    // same origin: the full page URL, minus the credentials-like parameter and the fragment
    assert_eq!(
        referer_of(&requests[0]),
        Some(format!("http://pub.test:{port}/dir/page?keep=1&utm_source=x"))
    );
    // the redirect crosses origins: only the page's origin travels
    assert_eq!(referer_of(&requests[1]), Some(format!("http://pub.test:{port}/")));
}

#[tokio::test]
async fn same_origin_policy_sends_nothing_across_origins() {
    let server = redirecting_server().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    f.fetch(
        &url("pub.test", &server, "/a"),
        &options(&server, ReferrerPolicy::SameOrigin),
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert!(referer_of(&requests[0]).is_some());
    assert_eq!(referer_of(&requests[1]), None);
}

#[tokio::test]
async fn no_referrer_and_no_option_send_nothing() {
    let server = redirecting_server().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    f.fetch(&url("pub.test", &server, "/a"), &FetchOptions::default())
        .await
        .unwrap();
    f.fetch(
        &url("pub.test", &server, "/a"),
        &options(&server, ReferrerPolicy::NoReferrer),
    )
    .await
    .unwrap();
    for request in server.received_requests().await.unwrap() {
        assert_eq!(referer_of(&request), None);
    }
}

#[tokio::test]
async fn an_explicit_or_configured_referer_is_never_replaced() {
    let server = redirecting_server().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    let mut explicit = options(&server, ReferrerPolicy::UnsafeUrl);
    explicit.headers.insert(
        header::REFERER,
        HeaderValue::from_static("https://operator.test/"),
    );
    f.fetch(&url("pub.test", &server, "/b"), &explicit).await.unwrap();

    let mut fetch = Fetch::default();
    fetch.extra_headers.insert("referer", "https://configured.test/");
    let controls = RequestControls::resolve(&fetch, "pub.test", None).await.unwrap();
    let f = fetcher(
        fast_config().with_controls(controls),
        allow_private_policy(&server),
        resolver(&["pub.test", "other.test"]),
    );
    f.fetch(
        &url("pub.test", &server, "/b"),
        &options(&server, ReferrerPolicy::UnsafeUrl),
    )
    .await
    .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        referer_of(&requests[0]).as_deref(),
        Some("https://operator.test/")
    );
    assert_eq!(
        referer_of(&requests[1]).as_deref(),
        Some("https://configured.test/")
    );
}
