//! Real browser coverage for request ownership across same-document and full navigation.
//!
//! The loopback fixture holds response headers until navigation finishes. Same-document
//! navigation proves successful late completion; full navigation proves aborted-request ownership.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_support;

use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::BrowserContext;
use crawlx_core::dom_ops::XhrRecord;
use crawlx_core::page_op::{PageOp, PageOpResult};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use surface_support::{canonical, context_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const DEADLINE: Duration = Duration::from_secs(30);
const PAGE_A: &str = r#"<!doctype html><title>page A</title><script>
window.lateController = new AbortController();
window.lateRequest = fetch('/late', {signal: window.lateController.signal}).then(response => response.text()).then(
    body => ({body, url: location.href}),
    error => ({error: String(error)})
);
</script>"#;
const PAGE_B: &str = "<!doctype html><title>page B</title><h1>page B</h1>";

struct Fixture {
    base: String,
    started: Arc<Notify>,
    release: Arc<Notify>,
    cancel: CancellationToken,
    tasks: JoinSet<()>,
}

impl Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let server_started = Arc::clone(&started);
        let server_release = Arc::clone(&release);
        let server_cancel = cancel.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    () = server_cancel.cancelled() => break,
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().expect("fixture connection task must finish");
                    }
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let started = Arc::clone(&server_started);
                        let release = Arc::clone(&server_release);
                        connections.spawn(async move {
                            timeout(DEADLINE, respond(socket, &started, &release))
                                .await
                                .expect("fixture request must finish within deadline");
                        });
                    }
                }
            }
            connections.abort_all();
            while let Some(result) = connections.join_next().await {
                if let Err(error) = result {
                    assert!(error.is_cancelled(), "fixture connection failed: {error}");
                }
            }
        });
        Self {
            base,
            started,
            release,
            cancel,
            tasks,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn wait_for_late_request(&self) {
        timeout(DEADLINE, self.started.notified())
            .await
            .expect("page A must issue its held request before navigation");
    }

    async fn close(mut self) {
        self.cancel.cancel();
        while let Some(result) = self.tasks.join_next().await {
            result.expect("fixture server must finish");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn respond(mut socket: TcpStream, started: &Notify, release: &Notify) {
    let mut header = Vec::new();
    let mut chunk = [0; 1024];
    while !header.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let read = socket.read(&mut chunk).await.unwrap();
        if read == 0 {
            return;
        }
        header.extend_from_slice(&chunk[..read]);
        assert!(header.len() <= 16 * 1024, "fixture request headers exceed bound");
    }
    let request = String::from_utf8(header).unwrap();
    let path = request.split_whitespace().nth(1).unwrap();
    let (status, content_type, body) = match path {
        "/page-a" => ("200 OK", "text/html", PAGE_A),
        "/page-b" => ("200 OK", "text/html", PAGE_B),
        "/late" => {
            started.notify_one();
            release.notified().await;
            ("200 OK", "text/plain", "late response")
        }
        "/from-b" => ("200 OK", "text/plain", "page B response"),
        _ => ("404 Not Found", "text/plain", "not found"),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    // A full navigation intentionally closes the held fetch's socket before release.
    if let Err(error) = socket.write_all(response.as_bytes()).await {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ),
            "fixture response write failed: {error}"
        );
    }
}

async fn launch() -> Option<ChromiumBackend> {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: CRAWLX_CHROMIUM_PATH is unset");
        return None;
    };
    let mut config = LaunchConfig::new();
    config.executable = executable.into();
    config.allow_unpinned = true;
    Some(
        ChromiumBackend::launch(config)
            .await
            .expect("browser must launch"),
    )
}

async fn evaluate(ctx: &mut CdpContext, script: &str) -> Value {
    match ctx
        .page_op(PageOp::EvaluateScript {
            script: script.to_owned(),
        })
        .await
        .unwrap()
    {
        PageOpResult::Json(value) => value,
        other => panic!("expected script result, got {other:?}"),
    }
}

async fn take_records(ctx: &mut CdpContext, count: usize) -> Vec<XhrRecord> {
    timeout(Duration::from_secs(5), async {
        let mut records = Vec::new();
        loop {
            records.extend(ctx.drain_xhr());
            assert!(records.len() <= count, "unexpected extra requests: {records:?}");
            if records.len() == count {
                return records;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("request lifecycle events must reach the browser context")
}

fn assert_ownership(records: &[XhrRecord], fixture: &Fixture, late_status: Option<u16>) {
    let late_url = fixture.url("/late");
    let from_b_url = fixture.url("/from-b");
    let late = records.iter().find(|record| record.url == late_url).unwrap();
    let from_b = records.iter().find(|record| record.url == from_b_url).unwrap();
    assert_eq!(late.page_url, fixture.url("/page-a"), "{records:?}");
    assert_eq!(late.status, late_status, "{records:?}");
    assert_eq!(from_b.page_url, fixture.url("/page-b"), "{records:?}");
    assert_eq!(from_b.status, Some(200), "{records:?}");
    assert_eq!(from_b.content_type.as_deref(), Some("text/plain"));
    for record in records {
        assert_eq!(record.method, "GET");
        assert_eq!(record.resource_type, "fetch");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_late_xhr_keeps_issuing_page_across_navigation_and_resets_drain() {
    timeout(DEADLINE, async {
        let Some(backend) = launch().await else {
            return;
        };
        let fixture = Fixture::start().await;
        let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();
        ctx.navigate(&canonical(&fixture.url("/page-a"))).await.unwrap();
        fixture.wait_for_late_request().await;
        assert!(ctx.drain_xhr().is_empty(), "held response must not finish early");

        // A same-document navigation cannot abort the old request, unlike a full load.
        assert_eq!(
            evaluate(&mut ctx, "history.pushState({}, '', '/page-b'); location.href").await,
            json!(fixture.url("/page-b"))
        );
        assert!(
            ctx.drain_xhr().is_empty(),
            "navigation must not fabricate completion"
        );
        fixture.release.notify_one();
        assert_eq!(
            evaluate(&mut ctx, "window.lateRequest").await,
            json!({"body": "late response", "url": fixture.url("/page-b")})
        );
        assert_eq!(
            evaluate(&mut ctx, "fetch('/from-b').then(response => response.text())").await,
            json!("page B response")
        );
        let records = take_records(&mut ctx, 2).await;
        assert_ownership(&records, &fixture, Some(200));
        let late = records
            .iter()
            .find(|record| record.url == fixture.url("/late"))
            .unwrap();
        assert_eq!(late.content_type.as_deref(), Some("text/plain"));
        assert!(ctx.drain_xhr().is_empty(), "first repeat drain must be empty");
        assert!(ctx.drain_xhr().is_empty(), "second repeat drain must stay empty");
        backend.close().await.unwrap();
        fixture.close().await;
    })
    .await
    .expect("late successful request attribution proof must finish within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_cross_document_abort_keeps_issuing_page_and_resets_drain() {
    timeout(DEADLINE, async {
        let Some(backend) = launch().await else {
            return;
        };
        let fixture = Fixture::start().await;
        let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();
        ctx.navigate(&canonical(&fixture.url("/page-a"))).await.unwrap();
        fixture.wait_for_late_request().await;
        assert!(ctx.drain_xhr().is_empty(), "held response must not finish early");

        // Cancel explicitly before loading another document: navigation can retain the old
        // document instead of cancelling its fetch. Drain only after page B loads, proving
        // that the failed request's page A ownership survives a real document replacement.
        let aborted = timeout(
            Duration::from_secs(5),
            evaluate(&mut ctx, "window.lateController.abort(); window.lateRequest"),
        )
        .await
        .expect("explicit cancellation of page A fetch must finish");
        assert!(
            aborted.get("error").and_then(Value::as_str).is_some(),
            "held fetch must reject after explicit cancellation: {aborted:?}"
        );
        timeout(
            Duration::from_secs(5),
            ctx.navigate(&canonical(&fixture.url("/page-b"))),
        )
        .await
        .expect("full navigation to page B must finish after cancelling page A fetch")
        .unwrap();
        assert_eq!(
            evaluate(&mut ctx, "location.href").await,
            json!(fixture.url("/page-b"))
        );
        let mut records = take_records(&mut ctx, 1).await;
        assert_eq!(records[0].page_url, fixture.url("/page-a"), "{records:?}");
        assert_eq!(records[0].status, None, "no response headers were released");
        fixture.release.notify_one();
        assert_eq!(
            evaluate(&mut ctx, "fetch('/from-b').then(response => response.text())").await,
            json!("page B response")
        );
        records.extend(take_records(&mut ctx, 1).await);
        assert_ownership(&records, &fixture, None);
        let late = records
            .iter()
            .find(|record| record.url == fixture.url("/late"))
            .unwrap();
        assert_eq!(
            late.content_type, None,
            "aborted request received no response headers"
        );
        assert!(ctx.drain_xhr().is_empty(), "first repeat drain must be empty");
        assert!(ctx.drain_xhr().is_empty(), "second repeat drain must stay empty");
        timeout(Duration::from_secs(5), backend.close())
            .await
            .expect("browser shutdown must finish after request attribution assertions")
            .unwrap();
        timeout(Duration::from_secs(5), fixture.close())
            .await
            .expect("fixture shutdown must finish");
    })
    .await
    .expect("cross-document aborted request attribution proof must finish within deadline");
}
