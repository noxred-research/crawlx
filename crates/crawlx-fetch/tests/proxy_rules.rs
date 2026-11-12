//! Ordered, named per-host proxy rules (`fetch.proxyRules`): the first matching rule routes a
//! request, a host no rule matches follows the base route, and a selected rule never falls back
//! to another rule or to a direct connection. The upstream proxies are in-process servers that
//! answer plain `http://` requests themselves (`via <name>`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use bytes::Bytes;
use common::{fast_config, LOOPBACK};
use crawlx_core::transport_policy::ProxyRule;
use crawlx_fetch::{FetchConfig, FetchError, FetchOptions, Fetcher, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: raw http messages used only by the in-process upstream proxy fixture"
)]
use http::{Request, Response};
use http_body_util::Full;
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: raw hyper body type used only by the in-process upstream proxy fixture"
)]
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An HTTP proxy that answers every request `via <name>` and records the request targets.
struct Upstream {
    url: Url,
    seen: Arc<Mutex<Vec<String>>>,
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: the in-process upstream proxy serves raw hyper/http messages and never crosses a typed fetch boundary"
)]
async fn upstream(name: &'static str) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        log.lock().push(req.uri().to_string());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("via {name}")))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Upstream { url, seen }
}

fn rule(name: &str, hosts: &[&str], proxy: &Upstream) -> ProxyRule {
    ProxyRule::new(
        name,
        hosts.iter().map(|host| (*host).to_owned()).collect(),
        proxy.url.clone(),
    )
}

fn resolver(hosts: &[&str]) -> Arc<StaticResolver> {
    let resolver = StaticResolver::new();
    for host in hosts {
        resolver.set(host, [LOOPBACK]);
    }
    Arc::new(resolver)
}

fn fetcher(config: FetchConfig, ports: &[u16], hosts: &[&str]) -> Fetcher {
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.extend_from_slice(ports);
    Fetcher::new(config, Arc::new(policy), resolver(hosts)).unwrap()
}

async fn origin() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("origin", "text/plain"))
        .mount(&server)
        .await;
    server
}

async fn body(fetcher: &Fetcher, host: &str, origin: &MockServer) -> Result<String, FetchError> {
    let url = Url::parse(&format!("http://{host}:{}/page", origin.address().port())).unwrap();
    let response = fetcher.fetch(&url, &FetchOptions::default()).await?;
    Ok(response.text().unwrap().into_owned())
}

#[tokio::test]
async fn the_first_matching_rule_routes_each_host_and_other_hosts_use_the_base_route() {
    let (alpha, beta, base) = (
        upstream("alpha").await,
        upstream("beta").await,
        upstream("base").await,
    );
    let origin = origin().await;
    let hosts = ["x.alpha.test", "y.alpha.test", "b.beta.test", "plain.test"];
    let config = FetchConfig {
        proxy: Some(base.url.clone()),
        proxy_rules: vec![
            rule("wide", &["*.alpha.test"], &alpha),
            rule("narrow", &["x.alpha.test"], &beta),
            rule("beta", &["b.beta.test"], &beta),
        ],
        ..fast_config()
    };
    let fetcher = fetcher(config, &[origin.address().port()], &hosts);
    for _ in 0..3 {
        // `wide` precedes `narrow`, so it keeps x.alpha.test however often it is asked.
        assert_eq!(
            body(&fetcher, "x.alpha.test", &origin).await.unwrap(),
            "via alpha"
        );
        assert_eq!(
            body(&fetcher, "y.alpha.test", &origin).await.unwrap(),
            "via alpha"
        );
        assert_eq!(body(&fetcher, "b.beta.test", &origin).await.unwrap(), "via beta");
        // A host no rule matches follows the base route (`fetch.proxy`), not a direct dial.
        assert_eq!(body(&fetcher, "plain.test", &origin).await.unwrap(), "via base");
    }
    assert_eq!(alpha.seen.lock().len(), 6);
    assert_eq!(beta.seen.lock().len(), 3);
    assert_eq!(base.seen.lock().len(), 3);
    assert!(
        origin.received_requests().await.unwrap().is_empty(),
        "no request reached the origin directly"
    );
}

#[tokio::test]
async fn rule_order_not_specificity_decides_and_reordering_changes_the_route() {
    let (alpha, beta) = (upstream("alpha").await, upstream("beta").await);
    let origin = origin().await;
    let ports = [origin.address().port()];
    let wide_first = fetcher(
        FetchConfig {
            proxy_rules: vec![
                rule("wide", &["*.alpha.test"], &alpha),
                rule("narrow", &["x.alpha.test"], &beta),
            ],
            ..fast_config()
        },
        &ports,
        &["x.alpha.test"],
    );
    assert_eq!(
        body(&wide_first, "x.alpha.test", &origin).await.unwrap(),
        "via alpha"
    );
    let narrow_first = fetcher(
        FetchConfig {
            proxy_rules: vec![
                rule("narrow", &["x.alpha.test"], &beta),
                rule("wide", &["*.alpha.test"], &alpha),
            ],
            ..fast_config()
        },
        &ports,
        &["x.alpha.test"],
    );
    assert_eq!(
        body(&narrow_first, "x.alpha.test", &origin).await.unwrap(),
        "via beta"
    );
}

#[tokio::test]
async fn a_selected_rule_whose_proxy_is_down_fails_closed_without_a_direct_fallback() {
    let origin = origin().await;
    let healthy = upstream("healthy").await;
    // A port that was bound a moment ago and is closed now.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap()
    };
    let config = FetchConfig {
        proxy_rules: vec![
            ProxyRule::new("down", vec!["down.test".to_owned()], dead),
            rule("later", &["down.test"], &healthy),
        ],
        retry: crawlx_fetch::RetryPolicy {
            max_retries: 0,
            ..crawlx_fetch::RetryPolicy::default()
        },
        ..fast_config()
    };
    let fetcher = fetcher(config, &[origin.address().port()], &["down.test"]);
    let error = body(&fetcher, "down.test", &origin).await.unwrap_err();
    assert!(matches!(error, FetchError::Transport(_)), "{error}");
    // Neither the target (direct) nor the later matching rule's proxy was tried.
    assert!(origin.received_requests().await.unwrap().is_empty());
    assert!(healthy.seen.lock().is_empty());
}

#[tokio::test]
async fn the_proxy_host_of_a_selected_rule_is_egress_checked_before_any_connection() {
    let origin = origin().await;
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.push(origin.address().port());
    let config = FetchConfig {
        proxy_rules: vec![ProxyRule::new(
            "private",
            vec!["rule.test".to_owned()],
            Url::parse("http://10.255.255.1:3128").unwrap(),
        )],
        ..fast_config()
    };
    let fetcher = Fetcher::new(config, Arc::new(policy), resolver(&["rule.test"])).unwrap();
    let error = body(&fetcher, "rule.test", &origin).await.unwrap_err();
    assert!(matches!(error, FetchError::EgressDenied(_)), "{error}");
    assert!(origin.received_requests().await.unwrap().is_empty());
}
