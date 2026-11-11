//! Bounded projection evidence from real browser requests to a controlled loopback origin.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, ContextConfig, ResponseBodySink};
use crawlx_core::browser_capture::BrowserEvidenceConfig;
use crawlx_core::browser_projection::{BrowserProjection, CaptureAvailability, ConsoleAvailability};
use crawlx_core::config::{LaunchProfile, ResponseBodies};
use crawlx_core::error::StoreError;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, ArtifactRef, SessionId};
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::secret::SecretOr;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

const SECRET: &str = "projection-private-canary-7193";
const PAGE: &str = r#"<!doctype html><html><body><p>Projection</p><script>
(async () => {
  await (await fetch('/api/one')).text();
  await new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest(); xhr.open('GET', '/api/two');
    xhr.onload = resolve; xhr.onerror = reject; xhr.send();
  });
  await (await fetch('/excluded')).text();
  await (await fetch('/api/secret')).text();
  console.log('projection-private-canary-7193');
  console.log('controlled-console-canary-834');
  console.log('Bearer unknown-console-credential-942');
  console.log('public console ' + 'é'.repeat(5000));
  document.body.dataset.ready = 'yes';
})();
</script></body></html>"#;

struct Origin {
    base: url::Url,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Origin {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        connections.spawn(async move {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                let Ok(byte) = stream.read_u8().await else { return };
                                request.push(byte);
                                assert!(request.len() <= 16384);
                            }
                            let head = String::from_utf8(request).unwrap();
                            let path = head.split_whitespace().nth(1).unwrap();
                            let (kind, body) = match path {
                                "/" => ("text/html", PAGE),
                                "/api/one" => ("text/plain", "public API one"),
                                "/api/two" => ("text/plain", "public API two"),
                                "/api/secret" => ("text/plain", SECRET),
                                _ => ("text/plain", "excluded response"),
                            };
                            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nX-Projection-Fixture: retained\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = stream.write_all(response.as_bytes()).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        Self { base, task }
    }
}

#[derive(Debug)]
struct PublicBodies(tempfile::TempDir);

#[async_trait]
impl ResponseBodySink for PublicBodies {
    async fn store(
        &self,
        _kind: &str,
        bytes: &[u8],
        truncated: bool,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        if truncated || !matches!(bytes, b"public API one" | b"public API two") {
            return Ok(None);
        }
        let artifact = ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("crawlx/projection-fixture/v1", bytes),
        };
        tokio::fs::write(self.0.path().join(artifact.id.to_string()), bytes)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(Some(artifact))
    }
}

fn launch() -> Option<LaunchConfig> {
    let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")?;
    let mut launch = LaunchConfig::new();
    launch.executable = executable.into();
    launch.allow_unpinned = true;
    Some(launch)
}

fn evidence(max_records: u32, max_bytes: u64) -> BrowserEvidenceConfig {
    serde_json::from_value(serde_json::json!({
        "xhr": {"urlPatterns": ["*/api/*"], "maxRecords": max_records, "maxBytes": max_bytes},
        "diagnostics": {"maxRecords": max_records, "maxBytes": max_bytes}
    }))
    .unwrap()
}

async fn context(backend: &ChromiumBackend, origin: &Origin, config: ContextConfig) -> CdpContext {
    let mut context = backend.new_cdp_context(config).await.unwrap();
    let url = Canonicalizer::canonicalize("/", &origin.base, &CanonicalizeOptions::default()).unwrap();
    context.navigate(&url).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if context
                .evaluate_isolated("document.body.dataset.ready")
                .await
                .unwrap()
                .as_str()
                == Some("yes")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    context.settle(QuiescencePolicy::default()).await.unwrap();
    context
}

async fn project(context: &mut CdpContext) -> BrowserProjection {
    let PageOpResult::Projection(projection) = context.page_op(PageOp::CaptureProjection).await.unwrap()
    else {
        panic!("wrong page operation result");
    };
    projection
}

#[tokio::test]
async fn real_xhr_fetch_projection_keeps_order_body_provenance_and_redacted_diagnostics() {
    let Some(launch) = launch() else { return };
    let backend = ChromiumBackend::launch(launch).await.unwrap();
    let origin = Origin::start().await;
    let bodies = Arc::new(PublicBodies(tempfile::tempdir().unwrap()));
    let mut config = ContextConfig::new(SessionId::new());
    config.browser_evidence = evidence(100, 1_000_000);
    config.console_capture = true;
    config.response_bodies = ResponseBodies::Full;
    config.response_body_sink = Some(bodies.clone());
    config
        .captcha_secrets
        .register(SecretOr::secret(SECRET.to_owned()))
        .unwrap();
    let mut fetch = crawlx_core::config::Fetch::default();
    fetch
        .extra_headers
        .insert("x-projection-secret", "controlled-console-canary-834");
    config.request_controls =
        crawlx_core::request_controls::RequestControls::resolve(&fetch, "127.0.0.1", None)
            .await
            .unwrap();
    let mut context = context(&backend, &origin, config).await;
    // Exercise the ordinary drain hook, then prove repeated projection does not duplicate it.
    let traffic = context.drain_traffic();
    assert!(traffic.iter().any(|event| event.url.ends_with("/excluded")));
    let projection = project(&mut context).await;
    assert_eq!(projection.capture_source, "cdp");
    assert_eq!(
        projection.service_worker_bootstrap,
        CaptureAvailability::UnavailableBeforeTargetAttachment,
    );
    let xhr = projection.xhr.as_ref().unwrap();
    assert_eq!(
        xhr.records
            .iter()
            .map(|record| url::Url::parse(&record.url).unwrap().path().to_owned())
            .collect::<Vec<_>>(),
        ["/api/one", "/api/two", "/api/secret"]
    );
    assert!(xhr.records.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    for record in &xhr.records[..2] {
        assert_eq!(record.status, Some(200));
        assert_eq!(record.page_url.as_deref(), Some(origin.base.as_str()));
        assert!(record
            .response_headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-projection-fixture") && value == "retained"));
        let artifact = record.response_body.as_ref().unwrap();
        let bytes = tokio::fs::read(bodies.0.path().join(artifact.id.to_string()))
            .await
            .unwrap();
        assert!(matches!(bytes.as_slice(), b"public API one" | b"public API two"));
    }
    assert!(xhr.records[2].response_body.is_none());
    assert_eq!(xhr.records[2].body_state.as_deref(), Some("policy_denied"));
    let diagnostics = projection.diagnostics.as_ref().unwrap();
    assert_eq!(diagnostics.console.availability, ConsoleAvailability::Available);
    assert!(!diagnostics.console.messages.is_empty());
    assert!(diagnostics
        .console
        .messages
        .iter()
        .all(|message| message.len() <= 4096));
    assert!(diagnostics.console.truncated);
    assert!(!serde_json::to_string(&projection).unwrap().contains(SECRET));
    let serialized = serde_json::to_string(&projection).unwrap();
    assert!(!serialized.contains("controlled-console-canary-834"));
    assert!(!serialized.contains("unknown-console-credential-942"));
    assert_eq!(project(&mut context).await, projection);
    Box::new(context).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test]
async fn real_projection_count_byte_caps_and_unavailable_console_are_explicit() {
    let Some(launch) = launch() else { return };
    let origin = Origin::start().await;
    for (profile, console_capture, cap, bytes, availability) in [
        (
            LaunchProfile::Standard,
            true,
            1,
            100_000,
            ConsoleAvailability::Available,
        ),
        (
            LaunchProfile::Standard,
            false,
            10,
            1,
            ConsoleAvailability::Disabled,
        ),
        (
            LaunchProfile::Stealth,
            true,
            10,
            100_000,
            ConsoleAvailability::Stealth,
        ),
    ] {
        let mut profile_launch = launch.clone();
        profile_launch.launch_profile = profile;
        let backend = ChromiumBackend::launch(profile_launch).await.unwrap();
        let mut config = ContextConfig::new(SessionId::new());
        config.browser_evidence = evidence(cap, bytes);
        config.console_capture = console_capture;
        config.launch_profile = profile;
        let mut context = context(&backend, &origin, config).await;
        // Pending completed traffic is copied, not consumed solely for projection.
        let projection = project(&mut context).await;
        assert!(!context.drain_traffic().is_empty());
        let xhr = projection.xhr.as_ref().unwrap();
        assert!(xhr.records.len() <= usize::try_from(cap).unwrap());
        assert!(xhr.metadata_bytes <= bytes);
        assert_eq!(
            xhr.metadata_bytes,
            xhr.records
                .iter()
                .map(|record| u64::try_from(serde_json::to_vec(record).unwrap().len()).unwrap())
                .sum::<u64>()
        );
        if cap == 1 || bytes == 1 {
            assert!(xhr.truncated);
            assert!(xhr.dropped_records >= 2);
        }
        let diagnostics = projection.diagnostics.unwrap();
        assert!(
            diagnostics.network.records.len() + diagnostics.console.messages.len()
                <= usize::try_from(cap).unwrap()
        );
        assert!(diagnostics.network.metadata_bytes + diagnostics.console.metadata_bytes <= bytes);
        assert_eq!(diagnostics.console.availability, availability);
        if availability != ConsoleAvailability::Available {
            assert!(diagnostics.console.messages.is_empty());
        }
        Box::new(context).close().await.unwrap();
        backend.close().await.unwrap();
    }
}
