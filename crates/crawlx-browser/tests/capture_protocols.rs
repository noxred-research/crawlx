//! Capture against controlled loopback HTTP, WebSocket, SSE and worker origins.
//! HTTPS uses a real local CA installed into an isolated Chromium NSS trust database.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use base64::Engine;
use crawlx_browser::launch::find_executable;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, ContextConfig, ResponseBodySink};
use crawlx_core::config::ResponseBodies;
use crawlx_core::error::StoreError;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, ArtifactRef, SessionId};
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::traffic::{Protocol, TrafficEvent, TrafficOrigin, UnattributedReason};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use sha1::{Digest as _, Sha1};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;

const BODY: &[u8] = b"controlled public capture response";
const WS_CLIENT: &[u8] = b"controlled-client-message";
const WS_SERVER: &str = "controlled-server-message";
const SSE_DATA: &str = "controlled-event-message";
const DEADLINE: Duration = Duration::from_secs(30);
const TEXT_PREFIX_BYTES: usize = 64 * 1024;
const TEXT_BODY_BYTES: usize = 128 * 1024;
const TEXT_START: &[u8] = b"<!doctype html><html><body>";

fn large_text() -> Vec<u8> {
    let end = b"</body></html>";
    let mut body = Vec::with_capacity(TEXT_BODY_BYTES);
    body.extend_from_slice(TEXT_START);
    body.resize(TEXT_BODY_BYTES - end.len(), b'x');
    body.extend_from_slice(end);
    body
}

const PAGE: &str = r#"<!doctype html><html><head><title>Capture protocols</title></head>
<body data-capture="pending"><iframe src="/frame"></iframe><script>
(async function () {
  const frame = new Promise(resolve => window.addEventListener('message', function done(e) {
    if (e.source === document.querySelector('iframe').contentWindow && e.data === 'frame-ready') resolve();
  }));
  const http = (async function () {
    for (let i = 0; i < 2; i++) {
      const response = await fetch('/data', {cache: 'no-store'});
      if (await response.text() !== 'controlled public capture response') throw new Error('http body');
    }
    await (await fetch('/oversized')).arrayBuffer();
  })();
  const ws = new Promise((resolve, reject) => {
    const socket = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
    socket.onopen = () => socket.send('controlled-client-message');
    socket.onerror = reject;
    socket.onmessage = event => {
      if (event.data !== 'controlled-server-message') return reject(new Error('ws body'));
      socket.close(); resolve();
    };
  });
  const sse = new Promise((resolve, reject) => {
    const stream = new EventSource('/sse');
    stream.onerror = reject;
    stream.addEventListener('capture', event => {
      stream.close();
      if (event.data !== 'controlled-event-message' || event.lastEventId !== 'capture-1') return reject(new Error('sse body'));
      resolve();
    });
  });
  const worker = (async function () {
    const reply = new Promise(resolve => navigator.serviceWorker.addEventListener('message', event => {
      if (event.data === 'worker-ready') resolve();
    }));
    await navigator.serviceWorker.register('/worker.js', {scope: '/'});
    const registration = await navigator.serviceWorker.ready;
    registration.active.postMessage('capture');
    await reply;
  })();
  await Promise.all([http, ws, sse, worker, frame]);
  document.body.dataset.capture = 'ready';
})().catch(error => { document.body.dataset.capture = 'error:' + String(error); });
</script></body></html>"#;

const FRAME: &str = r#"<!doctype html><html><body><script>
fetch('/frame-data').then(r => r.text()).then(() => parent.postMessage('frame-ready', location.origin));
</script></body></html>"#;

const WORKER: &str = r#"self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  event.waitUntil(fetch('/worker-data').then(r => r.text()).then(() => event.source.postMessage('worker-ready')));
});"#;

struct Origin {
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Origin {
    async fn start(tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let tls = tls.clone();
                        connections.spawn(async move {
                            let exchange = async move {
                                if let Some(acceptor) = tls {
                                    // The negative trust control intentionally rejects this handshake.
                                    if let Ok(stream) = acceptor.accept(socket).await {
                                        exchange(stream).await;
                                    }
                                } else {
                                    exchange(socket).await;
                                }
                            };
                            let _ = tokio::time::timeout(DEADLINE, exchange).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        Self { port, task }
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let mut head = Vec::new();
    loop {
        let byte = stream.read_u8().await;
        let Ok(byte) = byte else { return };
        head.push(byte);
        assert!(head.len() <= 16 * 1024, "fixture request headers too large");
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(head).unwrap();
    let path = head.split_whitespace().nth(1).unwrap();
    if path == "/ws" {
        websocket(&mut stream, &head).await;
        return;
    }
    let (content_type, body) = match path {
        "/" => ("text/html", PAGE.as_bytes().to_vec()),
        "/frame" => ("text/html", FRAME.as_bytes().to_vec()),
        "/worker.js" => ("application/javascript", WORKER.as_bytes().to_vec()),
        "/data" | "/frame-data" | "/worker-data" => ("text/plain", BODY.to_vec()),
        "/oversized" => ("application/octet-stream", vec![b'x'; 1024 * 1024 + 1]),
        "/text-large" => ("text/html", large_text()),
        "/sse" => (
            "text/event-stream",
            format!("id: capture-1\nevent: capture\ndata: {SSE_DATA}\n\n").into_bytes(),
        ),
        _ => ("text/plain", Vec::new()),
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(response.as_bytes()).await.is_ok() {
        let _ = stream.write_all(&body).await;
        let _ = stream.shutdown().await;
    }
}

async fn websocket<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, head: &str) {
    let key = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key")
                .then_some(value.trim())
        })
        .unwrap();
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let accept = base64::engine::general_purpose::STANDARD.encode(digest.finalize());
    stream.write_all(format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    ).as_bytes()).await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 0x81, "one final text frame");
    let length = stream.read_u8().await.unwrap();
    assert_ne!(length & 0x80, 0, "browser frame must be masked");
    assert_eq!(usize::from(length & 0x7f), WS_CLIENT.len());
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).await.unwrap();
    let mut payload = vec![0; WS_CLIENT.len()];
    stream.read_exact(&mut payload).await.unwrap();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    assert_eq!(payload, WS_CLIENT);
    let mut frame = vec![0x81, u8::try_from(WS_SERVER.len()).unwrap()];
    frame.extend_from_slice(WS_SERVER.as_bytes());
    stream.write_all(&frame).await.unwrap();
    // Complete the client's close handshake instead of ending the TCP stream abruptly.
    let mut close = [0; 2];
    if stream.read_exact(&mut close).await.is_ok() && close[0] == 0x88 {
        stream.write_all(&[0x88, 0]).await.unwrap();
    }
    let _ = stream.shutdown().await;
}

#[derive(Debug)]
struct PublicBodyStore {
    dir: tempfile::TempDir,
    calls: AtomicUsize,
}

impl PublicBodyStore {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ResponseBodySink for PublicBodyStore {
    async fn store(
        &self,
        content_type: &str,
        bytes: &[u8],
        truncated: bool,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        // The fixture policy permits only its known public text and bounded HTML prefix.
        let public_text = !truncated && content_type.starts_with("text/plain") && bytes == BODY;
        let public_prefix = truncated
            && content_type.starts_with("text/html")
            && bytes.len() == TEXT_PREFIX_BYTES
            && bytes.starts_with(TEXT_START)
            && bytes[TEXT_START.len()..].iter().all(|byte| *byte == b'x');
        if !public_text && !public_prefix {
            return Ok(None);
        }
        let reference = ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("crawlx/capture-fixture/v1", bytes),
        };
        tokio::fs::write(self.dir.path().join(reference.id.to_string()), bytes)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(Some(reference))
    }
}

fn metadata<'a>(event: &'a TrafficEvent, name: &str) -> Option<&'a str> {
    event
        .response_headers
        .iter()
        .chain(&event.request_headers)
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn path(event: &TrafficEvent) -> String {
    url::Url::parse(&event.url).unwrap().path().to_owned()
}

async fn wait_for_fixture(context: &mut CdpContext) {
    // Do not drain in-flight metadata-only requests: later CDP completion updates must
    // still find their original records. Synchronize on browser-visible completion.
    tokio::time::timeout(DEADLINE, async {
        loop {
            let state = context
                .evaluate_isolated("document.body.dataset.capture")
                .await
                .unwrap();
            let state = state.as_str().unwrap();
            assert!(!state.starts_with("error:"), "fixture failed: {state}");
            if state == "ready" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all controlled browser exchanges must finish");
    let report = context.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(
        !report.settle_timeout,
        "controlled origin did not settle: {report:?}"
    );
}

fn assert_body_commands(backend: &ChromiumBackend, start: usize, mode: ResponseBodies) {
    let commands = backend.cdp_transcript();
    let commands = &commands[start..];
    match mode {
        ResponseBodies::MetadataOnly => assert!(
            commands.iter().all(|method| {
                method != "Network.getResponseBody" && method != "Network.streamResourceContent"
            }),
            "metadata-only mode requested body bytes: {commands:?}"
        ),
        ResponseBodies::Full => assert!(
            commands.iter().any(|method| method == "Network.getResponseBody"),
            "full mode never read actual browser response bytes"
        ),
        ResponseBodies::TextCapped => assert!(
            commands
                .iter()
                .any(|method| method == "Network.streamResourceContent"),
            "text-capped mode never enabled bounded response streaming"
        ),
    }
}

async fn capture(
    backend: &ChromiumBackend,
    origin: &Origin,
    scheme: &str,
    mode: ResponseBodies,
) -> (Vec<TrafficEvent>, Arc<PublicBodyStore>) {
    let command_start = backend.cdp_transcript().len();
    let store = Arc::new(PublicBodyStore::new());
    let mut config = ContextConfig::new(SessionId::new());
    assert!(!config.request_controls.skip_tls_verification());
    config.response_bodies = mode;
    config.response_body_sink = Some(store.clone());
    let mut context = backend.new_cdp_context(config).await.unwrap();
    let base = url::Url::parse(&format!("{scheme}://127.0.0.1:{}/", origin.port)).unwrap();
    let url = Canonicalizer::canonicalize("/", &base, &CanonicalizeOptions::default()).unwrap();
    let navigation = context.navigate(&url).await.unwrap();
    assert_eq!(navigation.status, Some(200));
    wait_for_fixture(&mut context).await;
    let events = tokio::time::timeout(DEADLINE, async {
        let mut events = Vec::new();
        loop {
            events.extend(context.drain_traffic());
            let state = context
                .evaluate_isolated("document.body.dataset.capture")
                .await
                .unwrap();
            let state = state.as_str().unwrap();
            assert!(!state.starts_with("error:"), "fixture failed: {state}");
            let has = |method: &str, target: &str| {
                events.iter().any(|event| {
                    event.method == method
                        && path(event) == target
                        && metadata(event, "x-crawlx-body-state") != Some("pending")
                })
            };
            if state == "ready"
                && has("GET", "/worker-data")
                && has("GET", "/frame-data")
                && has("WS_SEND", "/ws")
                && has("WS_RECV", "/ws")
                && has("SSE_RECV", "/sse")
                && has("GET", "/oversized")
                && events
                    .iter()
                    .filter(|event| {
                        event.method == "GET"
                            && path(event) == "/data"
                            && event.status == Some(200)
                            && metadata(event, "x-crawlx-body-state") != Some("pending")
                    })
                    .count()
                    >= 2
            {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all controlled protocols and body captures must complete");
    assert_capture(&events, mode, &store).await;
    assert_body_commands(backend, command_start, mode);
    Box::new(context).close().await.unwrap();
    (events, store)
}

async fn assert_capture(events: &[TrafficEvent], mode: ResponseBodies, store: &PublicBodyStore) {
    assert!(
        events.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "raw capture order: {events:?}"
    );
    assert!(events
        .iter()
        .all(|event| metadata(event, "x-crawlx-capture-source") == Some("cdp")));
    let completed = |target: &str| {
        events
            .iter()
            .find(|event| {
                event.method == "GET"
                    && path(event) == target
                    && event.status == Some(200)
                    && metadata(event, "x-crawlx-body-state") != Some("pending")
            })
            .unwrap_or_else(|| panic!("missing {target}: {events:?}"))
    };
    let document = completed("/");
    let data = completed("/data");
    let observed_bytes: u64 = metadata(data, "x-crawlx-body-bytes")
        .expect("HTTP response byte count")
        .parse()
        .unwrap();
    assert!(observed_bytes >= u64::try_from(BODY.len()).unwrap());
    let child = completed("/frame");
    let child_data = completed("/frame-data");
    let main_id = metadata(document, "x-crawlx-frame-id").expect("main frame id");
    let child_id = metadata(child, "x-crawlx-frame-id").expect("child frame id");
    assert!(!main_id.is_empty());
    assert!(!child_id.is_empty());
    assert_ne!(main_id, child_id, "iframe traffic was flattened into its parent");
    assert_eq!(metadata(data, "x-crawlx-frame-id"), Some(main_id));
    assert_eq!(metadata(child_data, "x-crawlx-frame-id"), Some(child_id));
    for event in [document, data, child, child_data] {
        assert_eq!(event.origin, TrafficOrigin::Page);
        assert_eq!(event.protocol, Some(Protocol::Http11));
    }
    let worker = completed("/worker-data");
    assert_eq!(worker.origin, TrafficOrigin::ServiceWorker);
    assert_eq!(worker.epoch_id, None);
    assert_eq!(
        worker.unattributed_reason,
        Some(UnattributedReason::NotApplicable)
    );
    assert_eq!(worker.protocol, Some(Protocol::Http11));
    for (method, size) in [("WS_SEND", WS_CLIENT.len()), ("WS_RECV", WS_SERVER.len())] {
        let event = events
            .iter()
            .find(|event| event.method == method)
            .expect("WebSocket frame");
        assert_eq!(event.origin, TrafficOrigin::WebSocket);
        assert_eq!(metadata(event, "x-ws-opcode"), Some("1"));
        assert_eq!(
            metadata(event, "x-ws-payload-bytes"),
            Some(size.to_string().as_str())
        );
        assert!(event.request_body.is_none() && event.response_body.is_none());
    }
    let sse = events
        .iter()
        .find(|event| event.method == "SSE_RECV")
        .expect("SSE message");
    assert_eq!(sse.origin, TrafficOrigin::EventSource);
    assert_eq!(
        metadata(sse, "x-crawlx-stream-payload-bytes"),
        Some(SSE_DATA.len().to_string().as_str())
    );
    assert!(sse.request_body.is_none() && sse.response_body.is_none());
    let headers = events
        .iter()
        .flat_map(|event| event.request_headers.iter().chain(&event.response_headers));
    for (_, value) in headers {
        assert!(!value.contains(WS_SERVER) && !value.contains(SSE_DATA));
        assert!(!value.contains(std::str::from_utf8(WS_CLIENT).unwrap()));
    }
    let data_events: Vec<_> = events
        .iter()
        .filter(|event| event.method == "GET" && path(event) == "/data")
        .collect();
    assert_eq!(
        data_events.len(),
        2,
        "identical HTTP requests must remain separate raw events"
    );
    let operations: BTreeSet<_> = events
        .iter()
        .map(|event| (event.method.as_str(), path(event)))
        .collect();
    assert!(
        operations.len() < events.len(),
        "raw capture was replaced by a deduped view"
    );
    match mode {
        ResponseBodies::MetadataOnly => {
            assert_eq!(
                store.calls.load(Ordering::Relaxed),
                0,
                "metadata-only read body bytes"
            );
            assert!(events
                .iter()
                .all(|event| event.request_body.is_none() && event.response_body.is_none()));
            assert_eq!(metadata(data, "x-crawlx-body-state"), Some("metadata_only"));
        }
        ResponseBodies::Full => {
            assert!(store.calls.load(Ordering::Relaxed) > 0);
            for event in data_events {
                assert_eq!(metadata(event, "x-crawlx-body-state"), Some("stored"));
                let reference = event
                    .response_body
                    .as_ref()
                    .expect("retained HTTP body reference");
                let bytes = tokio::fs::read(store.dir.path().join(reference.id.to_string()))
                    .await
                    .unwrap();
                assert_eq!(bytes, BODY);
                assert_eq!(reference.digest, Digest::of("crawlx/capture-fixture/v1", &bytes));
            }
            assert_eq!(metadata(document, "x-crawlx-body-state"), Some("policy_denied"));
            assert!(document.response_body.is_none());
            let oversized = completed("/oversized");
            assert_eq!(metadata(oversized, "x-crawlx-body-state"), Some("oversized"));
            let observed_bytes: u64 = metadata(oversized, "x-crawlx-body-bytes")
                .expect("oversized response byte count")
                .parse()
                .unwrap();
            assert!(observed_bytes > 1024 * 1024);
            assert!(oversized.response_body.is_none());
        }
        ResponseBodies::TextCapped => unreachable!("this fixture exercises metadata_only and full"),
    }
}

fn chromium() -> Option<LaunchConfig> {
    let Some(executable) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut config = LaunchConfig::new();
    config.executable = executable;
    config.allow_unpinned = true;
    Some(config)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_http_ws_sse_and_service_worker_preserve_metadata_and_full_bodies() {
    let Some(config) = chromium() else { return };
    let backend = ChromiumBackend::launch(config).await.unwrap();
    let origin = Origin::start(None).await;
    for mode in [ResponseBodies::MetadataOnly, ResponseBodies::Full] {
        capture(&backend, &origin, "http", mode).await;
    }
    backend.close().await.unwrap();
}

struct LocalPki {
    home: tempfile::TempDir,
    tls: ServerConfig,
}

async fn command(program: &str, args: &[&str], directory: &Path) {
    let output = Command::new(program)
        .args(args)
        .current_dir(directory)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{program}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl LocalPki {
    async fn create() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            eprintln!("SKIP: trusted HTTPS fixture needs Linux Chromium NSS trust support");
            return None;
        }
        for program in ["openssl", "certutil"] {
            if Command::new(program)
                .arg("-H")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .is_err()
            {
                eprintln!("SKIP: trusted HTTPS fixture needs openssl and NSS certutil on PATH; no TLS bypass is allowed");
                return None;
            }
        }
        let home = tempfile::tempdir().unwrap();
        command(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-subj",
                "/CN=Crawlx Capture Fixture CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
            ],
            home.path(),
        )
        .await;
        command(
            "openssl",
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-subj",
                "/CN=127.0.0.1",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
            ],
            home.path(),
        )
        .await;
        tokio::fs::write(home.path().join("server.ext"), b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n").await.unwrap();
        command(
            "openssl",
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                "2",
                "-days",
                "2",
                "-sha256",
                "-extfile",
                "server.ext",
                "-out",
                "server.pem",
            ],
            home.path(),
        )
        .await;
        // Chromium versions use one of these two user-scoped NSS database locations.
        // Neither touches the developer's HOME or the system trust store.
        for relative in [".pki/nssdb", ".local/share/pki/nssdb"] {
            let directory = home.path().join(relative);
            tokio::fs::create_dir_all(&directory).await.unwrap();
            let database = format!("sql:{}", directory.display());
            command(
                "certutil",
                &["-N", "-d", &database, "--empty-password"],
                home.path(),
            )
            .await;
            command(
                "certutil",
                &[
                    "-A",
                    "-d",
                    &database,
                    "-n",
                    "crawlx-capture-local-ca",
                    "-t",
                    "C,,",
                    "-i",
                    "ca.pem",
                ],
                home.path(),
            )
            .await;
        }
        let certificate = tokio::fs::read(home.path().join("server.pem")).await.unwrap();
        let key = tokio::fs::read(home.path().join("server.key")).await.unwrap();
        let certificates = CertificateDer::pem_slice_iter(&certificate)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(&key).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        Some(Self { home, tls: config })
    }
}

struct IsolatedBrowser {
    child: Child,
    stderr: JoinHandle<()>,
    _profile: tempfile::TempDir,
}

impl Drop for IsolatedBrowser {
    fn drop(&mut self) {
        self.stderr.abort();
        let _ = self.child.start_kill();
    }
}

impl IsolatedBrowser {
    async fn launch(config: LaunchConfig, home: &Path) -> (Self, ChromiumBackend) {
        let profile = tempfile::tempdir().unwrap();
        let flags = config.launch_flags(profile.path());
        assert!(flags
            .iter()
            .all(|flag| !flag.contains("ignore-certificate") && !flag.contains("allow-insecure")));
        let mut child = Command::new(&config.executable)
            .args(flags)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let endpoint = tokio::time::timeout(DEADLINE, async {
            let mut diagnostic = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(endpoint) = line.strip_prefix("DevTools listening on ") {
                    return endpoint.to_owned();
                }
                diagnostic.push_str(&line);
                diagnostic.push('\n');
            }
            panic!("Chromium exited before DevTools: {diagnostic}");
        })
        .await
        .unwrap();
        let stderr = tokio::spawn(async move { while lines.next_line().await.ok().flatten().is_some() {} });
        let backend = ChromiumBackend::attach(&url::Url::parse(&endpoint).unwrap(), config)
            .await
            .unwrap();
        (
            Self {
                child,
                stderr,
                _profile: profile,
            },
            backend,
        )
    }

    async fn close(mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_https_uses_a_trusted_ca_and_rejects_the_same_ca_when_untrusted() {
    let Some(config) = chromium() else { return };
    let Some(pki) = LocalPki::create().await else {
        return;
    };
    let origin = Origin::start(Some(tokio_rustls::TlsAcceptor::from(Arc::new(pki.tls.clone())))).await;
    let (process, backend) = IsolatedBrowser::launch(config.clone(), pki.home.path()).await;
    for mode in [ResponseBodies::MetadataOnly, ResponseBodies::Full] {
        capture(&backend, &origin, "https", mode).await;
    }
    backend.close().await.unwrap();
    process.close().await;

    // A second browser has no imported CA. Its default verifier must reject the same
    // certificate; successful capture above cannot be explained by a TLS bypass.
    let empty_home = tempfile::tempdir().unwrap();
    let (process, backend) = IsolatedBrowser::launch(config, empty_home.path()).await;
    let mut context: CdpContext = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    let base = url::Url::parse(&format!("https://127.0.0.1:{}/", origin.port)).unwrap();
    let url = Canonicalizer::canonicalize("/", &base, &CanonicalizeOptions::default()).unwrap();
    let rejected = tokio::time::timeout(DEADLINE, context.navigate(&url))
        .await
        .unwrap();
    assert!(
        rejected.is_err(),
        "Chromium accepted an untrusted fixture CA: {rejected:?}"
    );
    Box::new(context).close().await.unwrap();
    backend.close().await.unwrap();
    process.close().await;
}

const H3_PAGE: &str = r#"<!doctype html><html><head><title>HTTP/3 capture</title></head>
<body data-capture="pending"><script>
(async function () {
  for (let index = 0; index < 2; index++) {
    const response = await fetch('/h3-data', {cache: 'no-store'});
    if (await response.text() !== 'controlled public capture response') throw new Error('h3 body');
  }
  document.body.dataset.capture = 'ready';
})().catch(error => { document.body.dataset.capture = 'error:' + String(error); });
</script></body></html>"#;

struct H3Origin {
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
    requests: Arc<AtomicUsize>,
}

impl Drop for H3Origin {
    fn drop(&mut self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"fixture shutdown");
        self.task.abort();
    }
}

impl H3Origin {
    fn start(pki: &LocalPki) -> Self {
        let mut tls = pki.tls.clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let accepting = endpoint.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = accepting.accept() => {
                        let Some(incoming) = incoming else { break };
                        let counted = Arc::clone(&counted);
                        connections.spawn(async move {
                            let connection = incoming.await.unwrap();
                            let mut h3 = h3::server::Connection::new(
                                h3_quinn::Connection::new(connection),
                            ).await.unwrap();
                            let mut streams = JoinSet::new();
                            loop {
                                tokio::select! {
                                    request = h3.accept() => {
                                        let resolver = match request {
                                            Ok(Some(resolver)) => resolver,
                                            // Chromium closes the context between retention modes.
                                            Ok(None) | Err(_) => break,
                                        };
                                        let counted = Arc::clone(&counted);
                                        streams.spawn(async move {
                                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                                            let (content_type, body) = match request.uri().path() {
                                                "/h3" => ("text/html", H3_PAGE.as_bytes()),
                                                "/h3-data" => {
                                                    assert_eq!(request.method(), http::Method::GET);
                                                    counted.fetch_add(1, Ordering::Relaxed);
                                                    ("text/plain", BODY)
                                                }
                                                _ => ("text/plain", &[][..]),
                                            };
                                            let response = http::Response::builder()
                                                .status(200)
                                                .header("content-type", content_type)
                                                .header("content-length", body.len().to_string())
                                                .header("cache-control", "no-store")
                                                .header("alt-svc", format!("h3=\":{port}\"; ma=60"))
                                                .body(()).unwrap();
                                            stream.send_response(response).await.unwrap();
                                            stream.send_data(bytes::Bytes::from_static(body)).await.unwrap();
                                            stream.finish().await.unwrap();
                                        });
                                    }
                                    completed = streams.join_next(), if !streams.is_empty() => {
                                        completed.unwrap().unwrap();
                                    }
                                }
                            }
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            endpoint,
            task,
            requests,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_trusted_http3_reports_h3_and_retains_only_full_policy_bodies() {
    let Some(mut config) = chromium() else { return };
    let Some(pki) = LocalPki::create().await else {
        return;
    };
    let origin = H3Origin::start(&pki);
    let port = origin.endpoint.local_addr().unwrap().port();
    // These flags only reach this manually launched, loopback-only fixture browser.
    // Production launch validation correctly rejects forcing QUIC around an egress proxy.
    config.extra_args.push("--enable-quic".to_owned());
    config
        .extra_args
        .push(format!("--origin-to-force-quic-on=127.0.0.1:{port}"));
    let (process, backend) = IsolatedBrowser::launch(config, pki.home.path()).await;
    for mode in [ResponseBodies::MetadataOnly, ResponseBodies::Full] {
        let command_start = backend.cdp_transcript().len();
        let store = Arc::new(PublicBodyStore::new());
        let mut config = ContextConfig::new(SessionId::new());
        assert!(!config.request_controls.skip_tls_verification());
        config.response_bodies = mode;
        config.response_body_sink = Some(store.clone());
        let mut context = backend.new_cdp_context(config).await.unwrap();
        let base = url::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let url = Canonicalizer::canonicalize("/h3", &base, &CanonicalizeOptions::default()).unwrap();
        let navigation = tokio::time::timeout(DEADLINE, context.navigate(&url))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(navigation.status, Some(200));
        wait_for_fixture(&mut context).await;
        let events = tokio::time::timeout(DEADLINE, async {
            let mut events = Vec::new();
            loop {
                events.extend(context.drain_traffic());
                let state = context
                    .evaluate_isolated("document.body.dataset.capture")
                    .await
                    .unwrap();
                let state = state.as_str().unwrap();
                assert!(!state.starts_with("error:"), "{state}");
                let completed = events
                    .iter()
                    .filter(|event| {
                        event.method == "GET"
                            && path(event) == "/h3-data"
                            && event.status == Some(200)
                            && metadata(event, "x-crawlx-body-state") != Some("pending")
                    })
                    .count();
                if state == "ready" && completed == 2 {
                    break events;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("controlled HTTP/3 requests must complete without an HTTP fallback");
        assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        let captured: Vec<_> = events
            .iter()
            .filter(|event| event.method == "GET" && matches!(path(event).as_str(), "/h3" | "/h3-data"))
            .collect();
        assert_eq!(captured.len(), 3, "document plus two distinct HTTP/3 requests");
        for event in captured {
            assert_eq!(event.origin, TrafficOrigin::Page);
            assert_eq!(
                event.protocol,
                Some(Protocol::H3),
                "no protocol guess or fallback: {event:?}"
            );
            assert_eq!(metadata(event, "x-crawlx-capture-source"), Some("cdp"));
            assert!(metadata(event, "alt-svc").is_some_and(|value| value.starts_with("h3=")));
            if mode == ResponseBodies::MetadataOnly {
                assert!(event.response_body.is_none());
                assert_eq!(metadata(event, "x-crawlx-body-state"), Some("metadata_only"));
            } else if path(event) == "/h3-data" {
                assert_eq!(metadata(event, "x-crawlx-body-state"), Some("stored"));
                let reference = event.response_body.as_ref().expect("retained HTTP/3 body");
                let bytes = tokio::fs::read(store.dir.path().join(reference.id.to_string()))
                    .await
                    .unwrap();
                assert_eq!(bytes, BODY);
                assert_eq!(reference.digest, Digest::of("crawlx/capture-fixture/v1", &bytes));
            }
        }
        if mode == ResponseBodies::MetadataOnly {
            assert_eq!(store.calls.load(Ordering::Relaxed), 0);
        }
        assert_body_commands(&backend, command_start, mode);
        Box::new(context).close().await.unwrap();
    }
    assert_eq!(
        origin.requests.load(Ordering::Relaxed),
        4,
        "H3 server saw every application request"
    );
    backend.close().await.unwrap();
    process.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controlled_text_capped_html_stores_a_real_bounded_prefix_with_truncation_metadata() {
    let Some(config) = chromium() else { return };
    let backend = ChromiumBackend::launch(config).await.unwrap();
    let origin = Origin::start(None).await;
    let store = Arc::new(PublicBodyStore::new());
    let mut config = ContextConfig::new(SessionId::new());
    config.response_bodies = ResponseBodies::TextCapped;
    config.response_body_sink = Some(store.clone());
    let mut context = backend.new_cdp_context(config).await.unwrap();
    let base = url::Url::parse(&format!("http://127.0.0.1:{}/", origin.port)).unwrap();
    let url = Canonicalizer::canonicalize("/text-large", &base, &CanonicalizeOptions::default()).unwrap();
    let navigation = context.navigate(&url).await.unwrap();
    assert_eq!(navigation.status, Some(200));
    let settled = context.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(!settled.settle_timeout, "{settled:?}");
    let events = context.drain_traffic();
    let html = events
        .iter()
        .find(|event| event.method == "GET" && path(event) == "/text-large" && event.status == Some(200))
        .expect("completed local HTML document");
    assert_eq!(html.protocol, Some(Protocol::Http11));
    assert_eq!(metadata(html, "x-crawlx-body-state"), Some("stored_prefix"));
    assert_eq!(metadata(html, "x-crawlx-capture-source"), Some("cdp"));
    let reference = html.response_body.as_ref().expect("retained real HTML prefix");
    let bytes = tokio::fs::read(store.dir.path().join(reference.id.to_string()))
        .await
        .unwrap();
    assert_eq!(bytes, large_text()[..TEXT_PREFIX_BYTES]);
    assert_eq!(bytes.len(), TEXT_PREFIX_BYTES);
    assert_eq!(reference.digest, Digest::of("crawlx/capture-fixture/v1", &bytes));
    assert!(store.calls.load(Ordering::Relaxed) > 0);
    assert_body_commands(&backend, 0, ResponseBodies::TextCapped);
    Box::new(context).close().await.unwrap();
    backend.close().await.unwrap();
}

impl Origin {
    async fn start_http2(pki: &LocalPki) -> (Self, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut tls = pki.tls.clone();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let counted = Arc::clone(&counted);
                        connections.spawn(async move {
                            // A browser may abandon a speculative connection before TLS completes.
                            // End that connection, not the origin serving subsequent h2 requests.
                            let stream = match acceptor.accept(socket).await {
                                Ok(stream) => stream,
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::UnexpectedEof
                                            | std::io::ErrorKind::ConnectionReset
                                    ) => return,
                                Err(error) => panic!("HTTP/2 fixture TLS handshake failed: {error}"),
                            };
                            let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let counted = Arc::clone(&counted);
                                async move {
                                    assert_eq!(request.version(), http::Version::HTTP_2);
                                    let (status, body) = if request.uri().path() == "/h2-data" {
                                        assert_eq!(request.method(), http::Method::GET);
                                        counted.fetch_add(1, Ordering::Relaxed);
                                        (200, BODY)
                                    } else {
                                        (404, &[][..])
                                    };
                                    let response = http::Response::builder()
                                        .status(status)
                                        .header("content-type", "text/plain")
                                        .header("content-length", body.len().to_string())
                                        .header("cache-control", "no-store")
                                        .body(http_body_util::Full::new(bytes::Bytes::from_static(body)))
                                        .unwrap();
                                    Ok::<_, std::convert::Infallible>(response)
                                }
                            });
                            // The listener only negotiates h2. No HTTP/1 fallback can make
                            // the protocol assertions pass without a genuine ALPN h2 exchange.
                            let _ = hyper::server::conn::http2::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            ).serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                }
            }
        });
        (Self { port, task }, requests)
    }
}

async fn capture_http2(
    backend: &ChromiumBackend,
    origin: &Origin,
    mode: ResponseBodies,
) -> (SessionId, Vec<TrafficEvent>, Arc<PublicBodyStore>) {
    let command_start = backend.cdp_transcript().len();
    let store = Arc::new(PublicBodyStore::new());
    let session = SessionId::new();
    let mut config = ContextConfig::new(session);
    assert!(!config.request_controls.skip_tls_verification());
    config.response_bodies = mode;
    config.response_body_sink = Some(store.clone());
    let mut context = backend.new_cdp_context(config).await.unwrap();
    let base = url::Url::parse(&format!("https://127.0.0.1:{}/", origin.port)).unwrap();
    let mut events = Vec::new();
    for index in 0..2 {
        let url = Canonicalizer::canonicalize(
            &format!("/h2-data?iteration={index}"),
            &base,
            &CanonicalizeOptions::default(),
        )
        .unwrap();
        let navigation = tokio::time::timeout(DEADLINE, context.navigate(&url))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(navigation.status, Some(200));
        let settled = context.settle(QuiescencePolicy::default()).await.unwrap();
        assert!(!settled.settle_timeout, "{settled:?}");
        events.extend(context.drain_traffic());
    }
    assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    let captured: Vec<_> = events
        .iter()
        .filter(|event| event.method == "GET" && path(event) == "/h2-data")
        .collect();
    assert_eq!(
        captured.len(),
        2,
        "both controlled HTTP/2 navigations must be raw events"
    );
    for event in captured {
        assert_eq!(event.origin, TrafficOrigin::Page);
        assert_eq!(event.protocol, Some(Protocol::H2));
        assert_eq!(event.status, Some(200));
        assert_eq!(metadata(event, "x-crawlx-capture-source"), Some("cdp"));
        if mode == ResponseBodies::MetadataOnly {
            assert_eq!(metadata(event, "x-crawlx-body-state"), Some("metadata_only"));
            assert!(event.response_body.is_none());
        } else {
            assert_eq!(mode, ResponseBodies::Full);
            assert_eq!(metadata(event, "x-crawlx-body-state"), Some("stored"));
            let reference = event.response_body.as_ref().expect("retained HTTP/2 body");
            let bytes = tokio::fs::read(store.dir.path().join(reference.id.to_string()))
                .await
                .unwrap();
            assert_eq!(bytes, BODY);
            assert_eq!(reference.digest, Digest::of("crawlx/capture-fixture/v1", &bytes));
        }
    }
    if mode == ResponseBodies::MetadataOnly {
        assert_eq!(store.calls.load(Ordering::Relaxed), 0);
    }
    assert_body_commands(backend, command_start, mode);
    Box::new(context).close().await.unwrap();
    (session, events, store)
}

fn http2_operations(events: &[TrafficEvent]) -> BTreeSet<(String, String, Option<u16>)> {
    events
        .iter()
        .filter(|event| event.method != "CONNECT")
        .filter_map(|event| {
            let path = path(event);
            (path == "/h2-data").then(|| (event.method.clone(), path, event.status))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_http2_cdp_and_proxy_views_match_without_decrypting_connect() {
    let Some(config) = chromium() else { return };
    let Some(pki) = LocalPki::create().await else {
        return;
    };
    let (origin, requests) = Origin::start_http2(&pki).await;
    // An abandoned TCP preconnect must not kill the listener before a valid TLS/h2 client.
    drop(
        tokio::net::TcpStream::connect(("127.0.0.1", origin.port))
            .await
            .unwrap(),
    );
    for mode in [ResponseBodies::MetadataOnly, ResponseBodies::Full] {
        let (direct_process, direct_backend) = IsolatedBrowser::launch(config.clone(), pki.home.path()).await;
        let (_, direct, _direct_store) = capture_http2(&direct_backend, &origin, mode).await;
        direct_backend.close().await.unwrap();
        direct_process.close().await;

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let mut policy = crawlx_policy::egress::EgressPolicy::new(true);
        policy.extra_ports.push(origin.port);
        let proxy = crawlx_fetch::EgressProxy::serve_with_capture(
            Arc::new(policy),
            Arc::new(crawlx_fetch::resolver::StaticResolver::new()),
            tx,
        )
        .await
        .unwrap();
        let mut proxy_config = config.clone();
        proxy_config.egress_proxy_port = Some(proxy.port());
        proxy_config.extra_args.push("--disable-quic".to_owned());
        let (proxy_process, proxy_backend) = IsolatedBrowser::launch(proxy_config, pki.home.path()).await;
        let (session, cdp, _proxy_store) = capture_http2(&proxy_backend, &origin, mode).await;
        let mut source =
            crawlx_observe::capture::ProxyTraffic::new(rx, crawlx_observe::traffic::Redactor::new([12; 32]));
        source.set_page_origin(format!("https://127.0.0.1:{}", origin.port));
        source.push_cdp(session, cdp);
        proxy_backend.close().await.unwrap();
        // Closing the browser ends its opaque TCP tunnels, making their real byte
        // counters available. The proxy never terminates TLS or sees HTTP/2 plaintext.
        proxy_process.close().await;
        let authority = format!("127.0.0.1:{}", origin.port);
        let merged = tokio::time::timeout(DEADLINE, async {
            let mut merged = Vec::new();
            loop {
                source.pump();
                merged.extend(source.take_for(session));
                if merged
                    .iter()
                    .any(|event| event.method == "CONNECT" && event.url == authority)
                {
                    break merged;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("closed browser must produce its raw CONNECT flow");
        assert!(merged.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        let connect = merged
            .iter()
            .find(|event| event.method == "CONNECT" && event.url == authority)
            .expect("raw opaque tunnel preserved");
        assert_eq!(metadata(connect, "x-crawlx-capture-source"), Some("proxy"));
        assert_eq!(metadata(connect, "x-crawlx-stream-opaque"), Some("true"));
        assert!(connect.status.is_none());
        assert!(connect.request_body.is_none() && connect.response_body.is_none());
        assert!(
            metadata(connect, "content-type").is_none(),
            "tunnel invented decrypted headers"
        );
        for name in ["x-crawlx-stream-bytes-up", "x-crawlx-stream-bytes-down"] {
            assert!(metadata(connect, name).unwrap().parse::<u64>().unwrap() > 0);
        }
        let supplements: Vec<_> = merged
            .iter()
            .filter(|event| event.method == "GET" && path(event) == "/h2-data")
            .collect();
        assert_eq!(supplements.len(), 2);
        for event in supplements {
            assert_eq!(metadata(event, "x-crawlx-capture-source"), Some("cdp_supplement"));
            assert_eq!(event.protocol, Some(Protocol::H2));
            assert_eq!(event.origin, TrafficOrigin::Page);
            assert_eq!(event.response_body.is_some(), mode == ResponseBodies::Full);
        }
        let expected = BTreeSet::from([("GET".to_owned(), "/h2-data".to_owned(), Some(200))]);
        assert_eq!(http2_operations(&direct), expected);
        assert_eq!(http2_operations(&merged), expected);
        assert!(
            merged.len() > http2_operations(&merged).len(),
            "raw events were deduplicated"
        );
        assert_eq!(
            crawlx_observe::capture::TrafficSource::protocols_disabled(&source),
            &[Protocol::H3]
        );
        assert_eq!(proxy.capture_dropped(), 0, "proxy capture dropped raw flows");
        proxy.shutdown().await;
    }
    assert_eq!(
        requests.load(Ordering::Relaxed),
        8,
        "both transports reached the controlled h2 origin"
    );
}
