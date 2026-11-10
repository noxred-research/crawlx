//! Deterministic local TCP contracts; no external provider account or network is used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::captcha::TaskCaptchaClient;
use crawlx_core::captcha::{CaptchaChallenge, CaptchaConfig, CaptchaError, CaptchaKind, CaptchaProvider};
use crawlx_core::secret::{CredentialRef, SecretOr};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

enum Reply {
    Json(Value),
    Raw(String),
    Disconnect,
    Stall,
    PartialBody,
    Redirect,
    ChunkedOversize,
}

struct Request {
    path: String,
    body: Value,
}

struct Fixture {
    config: CaptchaConfig,
    requests: Arc<Mutex<Vec<Request>>>,
    seen: Arc<Notify>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Fixture {
    async fn new(replies: Vec<Reply>) -> Self {
        assert!(!replies.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Notify::new());
        let stop = CancellationToken::new();
        let task_requests = Arc::clone(&requests);
        let task_seen = Arc::clone(&seen);
        let task_stop = stop.clone();
        let task = tokio::spawn(async move {
            let mut index = 0_usize;
            loop {
                tokio::select! {
                    biased;
                    () = task_stop.cancelled() => break,
                    result = async {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let request = read_request(&mut stream).await;
                        task_requests.lock().unwrap().push(request);
                        task_seen.notify_one();
                        let reply = &replies[index.min(replies.len() - 1)];
                        index = index.saturating_add(1);
                        respond(&mut stream, reply).await;
                    } => result,
                }
            }
        });
        let mut config = CaptchaConfig::new(CaptchaProvider::TaskApi, CredentialRef("env://TEST_KEY".into()));
        config.endpoint = format!("http://{address}/").parse().unwrap();
        config.poll_interval_ms = 1;
        config.timeout_seconds = 2;
        Self {
            config,
            requests,
            seen,
            stop,
            task: Some(task),
        }
    }

    fn client(&self) -> TaskCaptchaClient {
        TaskCaptchaClient::new(&self.config, SecretOr::secret("private-service-key".into())).unwrap()
    }

    async fn finish(mut self) {
        self.stop.cancel();
        self.task.take().unwrap().await.unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let (header_end, content_length) = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 65_536);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            break (end + 4, length);
        }
    };
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 65_536);
    }
    let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let path = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    assert!(headers.starts_with("POST "));
    let body = serde_json::from_slice(&bytes[header_end..header_end + content_length]).unwrap();
    Request { path, body }
}

async fn respond(stream: &mut TcpStream, reply: &Reply) {
    let body = match reply {
        Reply::Json(value) => value.to_string(),
        Reply::Raw(body) => body.clone(),
        Reply::Disconnect => return,
        Reply::Stall => std::future::pending::<String>().await,
        Reply::PartialBody => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
                .await
                .unwrap();
            std::future::pending::<String>().await
        }
        Reply::Redirect => {
            stream.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            return;
        }
        Reply::ChunkedOversize => {
            let headers =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n";
            if stream.write_all(headers).await.is_ok() {
                let body = vec![b'x'; 65_537];
                if stream.write_all(&body).await.is_ok() {
                    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                }
            }
            return;
        }
    };
    let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    // A cancelled client may close before the fixture finishes writing.
    if stream.write_all(headers.as_bytes()).await.is_ok() {
        let _ = stream.write_all(body.as_bytes()).await;
    }
}

fn challenge(kind: CaptchaKind) -> CaptchaChallenge {
    CaptchaChallenge::new(
        kind,
        "https://example.test/challenge".into(),
        "public-site-key".into(),
    )
}

fn created() -> Reply {
    Reply::Json(json!({"errorId": 0, "taskId": "task-123"}))
}

fn ready(kind: CaptchaKind) -> Reply {
    let solution = if kind == CaptchaKind::ChallengeWidgetT {
        json!({"token": "private-solved-token"})
    } else {
        json!({"gRecaptchaResponse": "private-solved-token"}) // wire-compat: provider solution field
    };
    Reply::Json(json!({"errorId": 0, "status": "ready", "solution": solution}))
}

#[tokio::test]
async fn maps_all_challenge_tasks_and_returns_secret_ready_tokens() {
    for (kind, task_type) in [
        (CaptchaKind::CheckboxV2, "ReCaptchaV2TaskProxyLess"), // wire-compat: provider task type
        (CaptchaKind::ScoreV3, "ReCaptchaV3TaskProxyLess"),    // wire-compat: provider task type
        (
            CaptchaKind::CheckboxV2Enterprise,
            "ReCaptchaV2EnterpriseTaskProxyLess", // wire-compat: provider task type
        ),
        (
            CaptchaKind::ScoreV3Enterprise,
            "ReCaptchaV3EnterpriseTaskProxyLess", // wire-compat: provider task type
        ),
        (CaptchaKind::ChallengeWidgetT, "AntiTurnstileTaskProxyLess"), // wire-compat: provider task type
        (CaptchaKind::ChallengeWidgetH, "HCaptchaTaskProxyLess"),      // wire-compat: provider task type
    ] {
        let fixture = Fixture::new(vec![
            created(),
            Reply::Json(json!({"errorId":0,"status":"processing"})),
            ready(kind),
        ])
        .await;
        let mut challenge = challenge(kind);
        challenge.action = Some("login".into());
        challenge.enterprise_payload = Some(json!({"s": "enterprise-data"}));
        challenge.data = Some("challenge-data".into());
        challenge.pagedata = Some("challenge-page-data".into());
        let client = fixture.client();
        assert!(!format!("{client:?}").contains("private-service-key"));
        let token = client.solve(&challenge, &CancellationToken::new()).await.unwrap();
        assert!(token.is_secret());
        assert_eq!(token.expose(), "private-solved-token");
        assert!(!format!("{token:?}").contains("private-solved-token"));
        {
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].path, "/createTask");
            assert_eq!(requests[0].body["clientKey"], "private-service-key");
            let task = &requests[0].body["task"];
            assert_eq!(task["type"], task_type);
            assert_eq!(task["websiteURL"], "https://example.test/challenge");
            assert_eq!(task["websiteKey"], "public-site-key");
            let v3 = matches!(kind, CaptchaKind::ScoreV3 | CaptchaKind::ScoreV3Enterprise);
            assert_eq!(task.get("pageAction"), v3.then_some(&json!("login")));
            let enterprise = matches!(
                kind,
                CaptchaKind::CheckboxV2Enterprise | CaptchaKind::ScoreV3Enterprise
            );
            assert_eq!(
                task.get("enterprisePayload"),
                enterprise.then_some(&json!({"s":"enterprise-data"}))
            );
            if kind == CaptchaKind::ChallengeWidgetT {
                assert_eq!(
                    task["metadata"],
                    json!({"action":"login","cdata":"challenge-data","chlpagedata":"challenge-page-data"}) // wire-compat: provider metadata fields
                );
            } else {
                assert!(task.get("metadata").is_none());
            }
            for request in &requests[1..] {
                assert_eq!(request.path, "/getTaskResult");
                assert_eq!(
                    request.body,
                    json!({"clientKey":"private-service-key","taskId":"task-123"})
                );
            }
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn provider_errors_are_bounded_and_secret_free() {
    for replies in [
        vec![Reply::Json(
            json!({"errorId":1,"errorCode":"private-service-key","errorDescription":"private-solved-token"}),
        )],
        vec![
            created(),
            Reply::Json(json!({"errorId":1,"errorDescription":"private-service-key"})),
        ],
    ] {
        let fixture = Fixture::new(replies).await;
        let error = fixture
            .client()
            .solve(&challenge(CaptchaKind::CheckboxV2), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error, CaptchaError::Service);
        assert!(!format!("{error:?}: {error}").contains("private"));
        fixture.finish().await;
    }
}

#[tokio::test]
async fn complete_deadline_bounds_create_headers_and_response_body() {
    for replies in [
        vec![Reply::Stall],
        vec![Reply::PartialBody],
        vec![created(), Reply::PartialBody],
    ] {
        let mut fixture = Fixture::new(replies).await;
        fixture.config.timeout_seconds = 1;
        let error = fixture
            .client()
            .solve(&challenge(CaptchaKind::CheckboxV2), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error, CaptchaError::Timeout);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn cancellation_interrupts_inflight_create_and_poll_body() {
    for replies in [vec![Reply::Stall], vec![created(), Reply::PartialBody]] {
        let expected_requests = replies.len();
        let fixture = Fixture::new(replies).await;
        let cancel = CancellationToken::new();
        let stop = async {
            loop {
                fixture.seen.notified().await;
                if fixture.requests.lock().unwrap().len() >= expected_requests {
                    cancel.cancel();
                    break;
                }
            }
        };
        let client = fixture.client();
        let challenge = challenge(CaptchaKind::ChallengeWidgetT);
        let (result, ()) = tokio::join!(client.solve(&challenge, &cancel), stop);
        assert_eq!(result.unwrap_err(), CaptchaError::Cancelled);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn pre_cancelled_solve_sends_no_create() {
    let fixture = Fixture::new(vec![created()]).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let error = fixture
        .client()
        .solve(&challenge(CaptchaKind::ChallengeWidgetH), &cancel)
        .await
        .unwrap_err();
    assert_eq!(error, CaptchaError::Cancelled);
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn rejects_malformed_unknown_missing_and_oversized_responses() {
    for replies in [
        vec![Reply::Raw("not json private-service-key".into())],
        vec![Reply::Json(json!({"taskId":"task-123"}))],
        vec![Reply::Json(json!({"errorId":0,"taskId":""}))],
        vec![Reply::Json(json!({"errorId":0}))],
        vec![Reply::Json(json!({"errorId":0,"taskId":123}))],
        vec![Reply::Json(
            json!({"errorId":0,"taskId":"task","status":"unknown"}),
        )],
        vec![created(), Reply::Json(json!({"errorId":0,"status":"unknown"}))],
        vec![
            created(),
            Reply::Json(json!({"errorId":0,"status":"ready","solution":{}})),
        ],
        vec![
            created(),
            Reply::Json(json!({"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":""}})), // wire-compat: provider solution field
        ],
        vec![
            created(),
            Reply::Json(json!({"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":123}})), // wire-compat: provider solution field
        ],
        vec![
            created(),
            Reply::Json(
                json!({"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":"x".repeat(16_385)}}), // wire-compat: provider solution field
            ),
        ],
        vec![Reply::Raw("x".repeat(65_537))],
        vec![Reply::ChunkedOversize],
    ] {
        let fixture = Fixture::new(replies).await;
        let error = fixture
            .client()
            .solve(&challenge(CaptchaKind::CheckboxV2), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error, CaptchaError::InvalidResponse);
        assert!(!format!("{error:?}: {error}").contains("private"));
        fixture.finish().await;
    }
}

#[tokio::test]
async fn ambiguous_create_disconnect_is_never_retried() {
    let fixture = Fixture::new(vec![Reply::Disconnect]).await;
    let error = fixture
        .client()
        .solve(&challenge(CaptchaKind::CheckboxV2), &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error, CaptchaError::Transport);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn redirects_are_not_followed_or_retried() {
    let fixture = Fixture::new(vec![Reply::Redirect]).await;
    let error = fixture
        .client()
        .solve(&challenge(CaptchaKind::CheckboxV2), &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error, CaptchaError::Service);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn cancellation_interrupts_poll_delay() {
    let mut fixture = Fixture::new(vec![created()]).await;
    fixture.config.poll_interval_ms = 1000;
    let cancel = CancellationToken::new();
    let client = fixture.client();
    let challenge = challenge(CaptchaKind::CheckboxV2);
    let stop = async {
        fixture.seen.notified().await;
        // Let createTask complete, then cancel while the solver sleeps.
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();
    };
    let (result, ()) = tokio::join!(client.solve(&challenge, &cancel), stop);
    assert_eq!(result.unwrap_err(), CaptchaError::Cancelled);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}
