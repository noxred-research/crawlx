//! Header admission precedes body reads, retries and redirect transitions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{fast_config, LOOPBACK};
use crawlx_fetch::client::ResponseHeaderGate;
use crawlx_fetch::{FetchError, FetchOptions, Fetcher, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use url::Url;

type ObservedHeaders = (u16, Option<String>, Option<u64>);

#[derive(Debug)]
struct Gate {
    reject: u16,
    observed: Mutex<Vec<ObservedHeaders>>,
}

impl Gate {
    fn rejecting(status: u16) -> Arc<Self> {
        Arc::new(Self {
            reject: status,
            observed: Mutex::new(Vec::new()),
        })
    }
}

impl ResponseHeaderGate for Gate {
    fn check(
        &self,
        status: u16,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<(), FetchError> {
        self.observed
            .lock()
            .push((status, content_type.map(str::to_owned), content_length));
        if status == self.reject {
            Err(FetchError::ExtensionHeaderSkipped)
        } else {
            Ok(())
        }
    }
}

struct HeadersOnlyServer {
    addr: SocketAddr,
    release: oneshot::Sender<()>,
    tasks: JoinSet<()>,
}

impl HeadersOnlyServer {
    async fn start(responses: Vec<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, wait) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut connections = Vec::new();
            for headers in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                stream.write_all(headers.as_bytes()).await.unwrap();
                // Keep every declared body absent and its connection open. A body
                // read cannot complete or observe EOF until the test releases it.
                connections.push(stream);
            }
            let _ = wait.await;
            drop(connections);
        });
        Self { addr, release, tasks }
    }

    fn fetcher(&self) -> Fetcher {
        let mut policy = EgressPolicy::new(true);
        policy.extra_ports.push(self.addr.port());
        Fetcher::new(
            fast_config(),
            Arc::new(policy),
            Arc::new(StaticResolver::new().with("gate.test", [LOOPBACK])),
        )
        .unwrap()
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://gate.test:{}/start", self.addr.port())).unwrap()
    }

    async fn stop(mut self) {
        self.release.send(()).unwrap();
        self.tasks.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn rejected_final_headers_return_without_polling_an_unavailable_body() {
    let server = HeadersOnlyServer::start(vec![
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 123\r\nConnection: close\r\n\r\n",
    ])
    .await;
    let gate = Gate::rejecting(200);
    let options = FetchOptions {
        header_gate: Some(gate.clone()),
        ..FetchOptions::default()
    };
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        server.fetcher().fetch(&server.url(), &options),
    )
    .await
    .expect("header refusal must not wait for the absent body")
    .unwrap_err();
    assert!(matches!(error, FetchError::ExtensionHeaderSkipped));
    assert_eq!(error.code(), "extension_header_skipped");
    assert_eq!(
        gate.observed.lock().as_slice(),
        &[(200, Some("application/octet-stream".to_owned()), Some(123))]
    );
    server.stop().await;
}

#[tokio::test]
async fn rejected_redirect_headers_abort_before_body_or_location_processing() {
    // Missing Location would produce InvalidRedirect if redirect handling ran first.
    let server = HeadersOnlyServer::start(vec![
        "HTTP/1.1 302 Found\r\nContent-Type: application/octet-stream\r\nContent-Length: 999\r\nConnection: close\r\n\r\n",
    ])
    .await;
    let gate = Gate::rejecting(302);
    let options = FetchOptions {
        header_gate: Some(gate.clone()),
        ..FetchOptions::default()
    };
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        server.fetcher().fetch(&server.url(), &options),
    )
    .await
    .expect("redirect header refusal must not read its absent body")
    .unwrap_err();
    assert!(matches!(error, FetchError::ExtensionHeaderSkipped));
    assert_eq!(
        gate.observed.lock().as_slice(),
        &[(302, Some("application/octet-stream".to_owned()), Some(999))]
    );
    server.stop().await;
}

#[tokio::test]
async fn gate_runs_again_on_the_response_after_an_accepted_redirect() {
    let server = HeadersOnlyServer::start(vec![
        "HTTP/1.1 302 Found\r\nLocation: /target\r\nContent-Length: 999\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 456\r\nConnection: close\r\n\r\n",
    ])
    .await;
    let gate = Gate::rejecting(200);
    let options = FetchOptions {
        header_gate: Some(gate.clone()),
        ..FetchOptions::default()
    };
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        server.fetcher().fetch(&server.url(), &options),
    )
    .await
    .expect("neither redirect nor final response may await its body")
    .unwrap_err();
    assert!(matches!(error, FetchError::ExtensionHeaderSkipped));
    assert_eq!(
        gate.observed.lock().as_slice(),
        &[
            (302, None, Some(999)),
            (200, Some("text/plain".to_owned()), Some(456))
        ]
    );
    server.stop().await;
}

#[tokio::test]
async fn gate_also_rejects_retryable_headers_without_a_retry() {
    let server = HeadersOnlyServer::start(vec![
        "HTTP/1.1 503 Unavailable\r\nContent-Length: 999\r\nConnection: close\r\n\r\n",
    ])
    .await;
    let gate = Gate::rejecting(503);
    let options = FetchOptions {
        header_gate: Some(gate.clone()),
        ..FetchOptions::default()
    };
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        server.fetcher().fetch(&server.url(), &options),
    )
    .await
    .expect("header refusal must precede retries")
    .unwrap_err();
    assert!(matches!(error, FetchError::ExtensionHeaderSkipped));
    assert_eq!(gate.observed.lock().len(), 1);
    server.stop().await;
}

#[tokio::test]
async fn native_compressed_wire_count_and_admission_follow_all_body_clones() {
    use async_compression::tokio::write::GzipEncoder;
    use common::{allow_private_policy, url};
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let plain = b"decoded bytes differ from transport bytes ".repeat(200);
    let mut wire = Vec::new();
    let mut encoder = GzipEncoder::new(&mut wire);
    encoder.write_all(&plain).await.unwrap();
    encoder.shutdown().await.unwrap();
    drop(encoder);
    assert_ne!(plain.len(), wire.len());
    let wire_len = u64::try_from(wire.len()).unwrap();
    let server = MockServer::start().await;
    Mock::given(path("/compressed"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(wire),
        )
        .mount(&server)
        .await;
    let fetcher = Fetcher::new(
        fast_config(),
        Arc::new(allow_private_policy(&server)),
        Arc::new(StaticResolver::new().with("gate.test", [LOOPBACK])),
    )
    .unwrap();
    let response = fetcher
        .fetch(
            &url("gate.test", &server, "/compressed"),
            &FetchOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(response.body.as_ref(), plain.as_slice());
    assert_eq!(response.wire_bytes, Some(wire_len));
    let permit = response.body_permit.as_ref().unwrap();
    assert!(permit.bytes() >= plain.len());
    let weak = Arc::downgrade(permit);
    let response_clone = response.clone();
    let bytes_clone = response.body.clone();
    drop(response);
    assert_eq!(response_clone.wire_bytes, Some(wire_len));
    assert!(weak.upgrade().is_some());
    drop(response_clone);
    assert!(weak.upgrade().is_some(), "standalone Bytes must retain admission");
    assert_eq!(bytes_clone.as_ref(), plain.as_slice());
    drop(bytes_clone);
    assert!(weak.upgrade().is_none());
}
