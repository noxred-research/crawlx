#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Owned-loopback TLS/H2 reference capture, not a claim of native transport equality.
//!
//! Run `CRAWLX_CHROMIUM_PATH=/absolute/path/to/chromium cargo test -p crawlx-fetch
//! --test identity_wire pinned_chromium_owned_wire_reference -- --nocapture`.
//! The `CRAWLX_IDENTITY_WIRE_REFERENCE=` line contains one JSON observation. Ordered
//! wire fields retain GREASE and extension permutation; decoded header iteration
//! is not presented as HPACK or pseudo-header order. The first HPACK block is raw.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

const DEADLINE: Duration = Duration::from_secs(30);
const CAPTURE_LIMIT: usize = 256 * 1024;
const CONNECTION_LIMIT: usize = 8;
const FIXTURE_PATH: &str = "/identity-wire";
// SHA-256 of the fixture's DER SubjectPublicKeyInfo, not the leaf certificate.
// openssl x509 -in fixtures/selfsigned.crt -pubkey -noout |
// openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A
const FIXTURE_SPKI: &str = "eoCEKRjDezDZKtGR96Hn3TXhXa1UslS6o80Q0ZlJyZA=";
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTML: &[u8] = b"<!doctype html><html><head><meta charset=utf-8><link rel=icon href=data:,><title>owned wire fixture</title></head><body>owned wire fixture</body></html>";

type Capture = Arc<Mutex<Vec<u8>>>;

/// Read-only tee: never consumes bytes ahead of the protocol implementation.
struct ReadTee<T> {
    inner: T,
    capture: Capture,
}

impl<T: AsyncRead + Unpin> AsyncRead for ReadTee<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = &buf.filled()[before..];
                let mut capture = this.capture.lock().unwrap();
                if bytes.len() > CAPTURE_LIMIT.saturating_sub(capture.len()) {
                    return Poll::Ready(Err(io::Error::other("wire capture exceeds fixture limit")));
                }
                capture.extend_from_slice(bytes);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ReadTee<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

/// Reserved GREASE slots (`0x0a0a`, `0x1a1a`, ... `0xfafa`); the pinned reference randomizes them per connection.
const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

// Measured from one pinned-reference sample; extension order is permuted per connection so it is not asserted.
const REFERENCE_CIPHER_SUITES: [u16; 15] = [
    4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53,
];
const REFERENCE_GROUPS: [u16; 4] = [4588, 29, 23, 24];
const REFERENCE_SIGNATURE_ALGORITHMS: [u16; 11] =
    [2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537];
const REFERENCE_SETTINGS: [(u16, u32); 4] = [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)];
const REFERENCE_CONNECTION_WINDOW_INCREMENT: u32 = 15_663_105;

#[derive(Debug, Serialize)]
struct ClientHello {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extension_ids: Vec<u16>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    ec_point_formats: Vec<u8>,
    alpn: Vec<String>,
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> &'a [u8] {
    assert!(length <= bytes.len(), "truncated owned wire capture");
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    value
}

fn u8_field(bytes: &mut &[u8]) -> u8 {
    take(bytes, 1)[0]
}

fn u16_field(bytes: &mut &[u8]) -> u16 {
    u16::from_be_bytes(take(bytes, 2).try_into().unwrap())
}

fn u32_field(bytes: &mut &[u8]) -> u32 {
    u32::from_be_bytes(take(bytes, 4).try_into().unwrap())
}

fn u16_vector(bytes: &mut &[u8]) -> Vec<u16> {
    let length = usize::from(u16_field(bytes));
    assert_eq!(length % 2, 0);
    let (pairs, rest) = take(bytes, length).as_chunks::<2>();
    assert!(rest.is_empty());
    pairs.iter().map(|pair| u16::from_be_bytes(*pair)).collect()
}

fn parse_hello(mut bytes: &[u8]) -> ClientHello {
    let legacy_version = u16_field(&mut bytes);
    take(&mut bytes, 32);
    let session_length = usize::from(u8_field(&mut bytes));
    take(&mut bytes, session_length);
    let cipher_suites = u16_vector(&mut bytes);
    let compression_length = usize::from(u8_field(&mut bytes));
    take(&mut bytes, compression_length);
    let extension_length = usize::from(u16_field(&mut bytes));
    let mut extensions = take(&mut bytes, extension_length);
    assert!(bytes.is_empty(), "trailing ClientHello bytes");
    let mut hello = ClientHello {
        legacy_version,
        cipher_suites,
        extension_ids: Vec::new(),
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        ec_point_formats: Vec::new(),
        alpn: Vec::new(),
    };
    while !extensions.is_empty() {
        let kind = u16_field(&mut extensions);
        let length = usize::from(u16_field(&mut extensions));
        let mut payload = take(&mut extensions, length);
        hello.extension_ids.push(kind);
        match kind {
            10 => hello.supported_groups = u16_vector(&mut payload),
            13 => hello.signature_algorithms = u16_vector(&mut payload),
            11 => {
                let length = usize::from(u8_field(&mut payload));
                hello.ec_point_formats = take(&mut payload, length).to_vec();
            }
            16 => {
                let length = usize::from(u16_field(&mut payload));
                let mut protocols = take(&mut payload, length);
                while !protocols.is_empty() {
                    let length = usize::from(u8_field(&mut protocols));
                    hello
                        .alpn
                        .push(String::from_utf8(take(&mut protocols, length).to_vec()).unwrap());
                }
            }
            _ => continue,
        }
        assert!(payload.is_empty(), "trailing parsed extension bytes");
    }
    hello
}

fn captured_hello(mut records: &[u8]) -> ClientHello {
    let mut handshake = Vec::new();
    while !records.is_empty() {
        let header = take(&mut records, 5);
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let payload = take(&mut records, length);
        assert_eq!(header[0], 22, "expected ClientHello handshake record");
        handshake.extend_from_slice(payload);
        if handshake.len() < 4 {
            continue;
        }
        assert_eq!(handshake[0], 1, "expected ClientHello");
        let length =
            usize::try_from(u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]])).unwrap();
        let end = length.checked_add(4).unwrap();
        assert!(end <= CAPTURE_LIMIT, "oversized ClientHello");
        if handshake.len() >= end {
            return parse_hello(&handshake[4..end]);
        }
    }
    panic!("no complete ClientHello captured")
}

#[derive(Debug, Serialize)]
struct H2Observation {
    /// SETTINGS frames and entries in receive order; ACK frames have no entries.
    settings: Vec<Vec<(u16, u32)>>,
    connection_window_updates: Vec<u32>,
    first_headers_stream_id: u32,
    first_headers_flags: u8,
    first_headers_frame_payload: Vec<u8>,
    /// HPACK fragments in wire order, excluding frame padding and priority fields.
    first_headers_block: Vec<u8>,
}

fn captured_h2(mut bytes: &[u8]) -> H2Observation {
    assert_eq!(take(&mut bytes, H2_PREFACE.len()), H2_PREFACE);
    let mut observation = H2Observation {
        settings: Vec::new(),
        connection_window_updates: Vec::new(),
        first_headers_stream_id: 0,
        first_headers_flags: 0,
        first_headers_frame_payload: Vec::new(),
        first_headers_block: Vec::new(),
    };
    let mut header_block_complete = false;
    while bytes.len() >= 9 {
        let header = take(&mut bytes, 9);
        let length = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]])).unwrap();
        if bytes.len() < length {
            break; // A tee may end partway through a later, unrelated frame.
        }
        let mut payload = take(&mut bytes, length);
        let kind = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        match kind {
            4 => {
                assert_eq!(stream_id, 0);
                assert_eq!(payload.len() % 6, 0);
                let mut settings = Vec::with_capacity(payload.len() / 6);
                while !payload.is_empty() {
                    settings.push((u16_field(&mut payload), u32_field(&mut payload)));
                }
                observation.settings.push(settings);
            }
            8 if stream_id == 0 => {
                assert_eq!(payload.len(), 4);
                observation
                    .connection_window_updates
                    .push(u32_field(&mut payload) & 0x7fff_ffff);
            }
            1 if observation.first_headers_stream_id == 0 => {
                assert_ne!(stream_id, 0);
                observation.first_headers_stream_id = stream_id;
                observation.first_headers_flags = flags;
                observation.first_headers_frame_payload = payload.to_vec();
                let padding = if flags & 0x08 != 0 {
                    usize::from(u8_field(&mut payload))
                } else {
                    0
                };
                if flags & 0x20 != 0 {
                    take(&mut payload, 5);
                }
                let fragment_length = payload.len().checked_sub(padding).unwrap();
                observation
                    .first_headers_block
                    .extend_from_slice(take(&mut payload, fragment_length));
                header_block_complete = flags & 0x04 != 0;
            }
            9 if !header_block_complete && stream_id == observation.first_headers_stream_id => {
                observation.first_headers_block.extend_from_slice(payload);
                header_block_complete = flags & 0x04 != 0;
            }
            _ => {}
        }
    }
    assert!(!observation.settings.is_empty(), "no client SETTINGS captured");
    assert!(header_block_complete, "no complete first HEADERS block captured");
    observation
}

#[derive(Debug, Serialize)]
struct RequestObservation {
    method: String,
    uri: String,
    http_version: String,
    /// Decoded values only; Hyper's HeaderMap is not a wire-order capture.
    headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
struct ConnectionObservation {
    client_hello: ClientHello,
    negotiated_tls: String,
    negotiated_cipher_suite: String,
    negotiated_alpn: String,
    h2: H2Observation,
    request: RequestObservation,
}

fn fixture_acceptor() -> TlsAcceptor {
    let certificates = CertificateDer::pem_slice_iter(include_bytes!("fixtures/selfsigned.crt"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: the in-process TLS/H2 origin serves raw hyper/http messages and never crosses a typed fetch boundary"
)]
async fn serve_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    observations: mpsc::Sender<ConnectionObservation>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encrypted = Arc::new(Mutex::new(Vec::with_capacity(CAPTURE_LIMIT)));
    let tls = acceptor
        .accept(ReadTee {
            inner: socket,
            capture: Arc::clone(&encrypted),
        })
        .await?;
    let session = tls.get_ref().1;
    let negotiated_tls = format!("{:?}", session.protocol_version().unwrap());
    let negotiated_cipher_suite = format!("{:?}", session.negotiated_cipher_suite().unwrap().suite());
    let negotiated_alpn = String::from_utf8(session.alpn_protocol().unwrap().to_vec()).unwrap();
    let decrypted = Arc::new(Mutex::new(Vec::with_capacity(CAPTURE_LIMIT)));
    let capture = Arc::clone(&decrypted);
    let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
        if request.uri().path() == FIXTURE_PATH {
            let observation = ConnectionObservation {
                client_hello: captured_hello(&encrypted.lock().unwrap()),
                negotiated_tls: negotiated_tls.clone(),
                negotiated_cipher_suite: negotiated_cipher_suite.clone(),
                negotiated_alpn: negotiated_alpn.clone(),
                h2: captured_h2(&capture.lock().unwrap()),
                request: RequestObservation {
                    method: request.method().to_string(),
                    uri: request.uri().to_string(),
                    http_version: format!("{:?}", request.version()),
                    headers: request
                        .headers()
                        .iter()
                        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
                        .collect(),
                },
            };
            // A speculative duplicate must not block the protocol task.
            match observations.try_send(observation) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
        async {
            Ok::<_, Infallible>(
                http::Response::builder()
                    .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(
                        http::header::CONTENT_SECURITY_POLICY,
                        "default-src 'none'; img-src data:",
                    )
                    .body(Full::new(Bytes::from_static(HTML)))
                    .unwrap(),
            )
        }
    });
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(
            TokioIo::new(ReadTee {
                inner: tls,
                capture: decrypted,
            }),
            service,
        )
        .await?;
    Ok(())
}

#[derive(Deserialize)]
struct PinFile {
    chromium: PinSection,
}

#[derive(Deserialize)]
struct PinSection {
    version: String,
}

#[tokio::test]
async fn pinned_chromium_owned_wire_reference() {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is absent");
        return;
    };
    assert!(
        Path::new(&executable).is_absolute(),
        "Chromium executable must be an absolute path"
    );
    let pin: PinFile = toml::from_str(include_str!("../../../chromium-pin.toml")).unwrap();
    let version = timeout(
        DEADLINE,
        Command::new(&executable)
            .env_clear()
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("Chromium --version timed out")
    .expect("cannot run configured Chromium executable");
    assert!(version.status.success(), "Chromium --version failed");
    let version_text = String::from_utf8(version.stdout).unwrap();
    assert!(
        version_text
            .split_whitespace()
            .any(|word| word == pin.chromium.version),
        "configured Chromium does not match pin {}: {version_text:?}",
        pin.chromium.version
    );

    let profile = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    assert!(address.ip().is_loopback());
    // The certificate covers this name; the resolver rule maps it to the owned loopback listener.
    let url = format!("https://crawlx-test.invalid:{}{FIXTURE_PATH}", address.port());
    let acceptor = fixture_acceptor();
    let flags = [
        "--headless=new",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-breakpad",
        "--disable-client-side-phishing-detection",
        "--safebrowsing-disable-auto-update",
        "--metrics-recording-only",
        "--no-pings",
        "--no-proxy-server",
        "--disable-quic",
        "--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn,AsyncDns,MediaRouter,OptimizationHints,AutofillServerCommunication,CertificateTransparencyComponentUpdater",
        "--host-resolver-rules=MAP crawlx-test.invalid 127.0.0.1, MAP * ~NOTFOUND",
        "--dump-dom",
        // This fixed-page fixture is not deployment sandbox/isolation evidence.
        "--no-sandbox",
    ];
    let mut child = Command::new(&executable)
        .env_clear()
        .env("HOME", profile.path())
        .env("XDG_CONFIG_HOME", profile.path())
        .env("XDG_CACHE_HOME", profile.path())
        .env("TMPDIR", profile.path())
        .env("LANG", "C")
        .env("TZ", "UTC")
        .args(flags)
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg(format!("--ignore-certificate-errors-spki-list={FIXTURE_SPKI}"))
        .arg(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("cannot launch pinned Chromium");
    let (observations, mut received) = mpsc::channel(1);
    let mut workers = JoinSet::new();
    let result = timeout(DEADLINE, async {
        let mut accepted = 0_usize;
        let mut connection_errors = Vec::new();
        loop {
            tokio::select! {
                observation = received.recv() => break observation.expect("capture channel closed"),
                socket = listener.accept(), if accepted < CONNECTION_LIMIT => {
                    let (socket, peer) = socket.unwrap();
                    assert!(peer.ip().is_loopback(), "nonfixture peer");
                    accepted = accepted.checked_add(1).unwrap();
                    workers.spawn(serve_connection(socket, acceptor.clone(), observations.clone()));
                }
                Some(done) = workers.join_next(), if !workers.is_empty() => {
                    if let Err(error) = done.expect("wire server task panicked") {
                        connection_errors.push(error.to_string());
                        eprintln!("owned wire connection failed: {connection_errors:?}");
                    }
                }
            }
        }
    })
    .await;
    // Let --dump-dom finish the fixed-page navigation, then reap even on timeout.
    let mut navigation_finished = false;
    let mut waited = None;
    if result.is_ok() {
        if let Ok(status) = timeout(DEADLINE, child.wait()).await {
            navigation_finished = true;
            waited = Some(status);
        }
    }
    if waited.is_none() {
        child.start_kill().expect("cannot stop Chromium child");
        waited = Some(
            timeout(DEADLINE, child.wait())
                .await
                .expect("Chromium child reap timed out"),
        );
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    let observation = result.expect("pinned Chromium made no owned fixture request before deadline");
    assert!(
        navigation_finished,
        "Chromium did not finish the owned fixture navigation"
    );
    assert!(
        waited.unwrap().expect("cannot reap Chromium child").success(),
        "Chromium navigation failed"
    );
    assert_eq!(observation.negotiated_alpn, "h2");
    assert_eq!(observation.request.method, "GET");
    assert!(observation.request.uri.ends_with(FIXTURE_PATH));
    assert!(!observation.client_hello.cipher_suites.is_empty());
    assert!(!observation.h2.first_headers_block.is_empty());
    let hello = &observation.client_hello;
    assert_eq!(without_grease(&hello.cipher_suites), REFERENCE_CIPHER_SUITES);
    assert_eq!(without_grease(&hello.supported_groups), REFERENCE_GROUPS);
    let signatures = without_grease(&hello.signature_algorithms);
    assert_eq!(signatures, REFERENCE_SIGNATURE_ALGORITHMS);
    for algorithm in [2308, 2309, 2310] {
        assert!(
            signatures.contains(&algorithm),
            "missing signature algorithm {algorithm}"
        );
    }
    assert_eq!(hello.alpn, ["h2", "http/1.1"]);
    assert_eq!(observation.h2.settings.first().unwrap(), &REFERENCE_SETTINGS);
    assert_eq!(
        observation.h2.connection_window_updates.first(),
        Some(&REFERENCE_CONNECTION_WINDOW_INCREMENT)
    );
    let reference = serde_json::json!({
        "schema_version": 1,
        "source": "owned_local_chromium_reference",
        "pinned_chromium_version": pin.chromium.version,
        "executable_version_output": version_text.trim(),
        "fixture_url": url,
        "fixture_spki_sha256_base64": FIXTURE_SPKI,
        "capture_limit_bytes_per_layer": CAPTURE_LIMIT,
        "launch_flags": flags,
        "environment_cleared": true,
        "isolated_temporary_profile": true,
        "observation": observation,
    });
    println!(
        "CRAWLX_IDENTITY_WIRE_REFERENCE={}",
        serde_json::to_string(&reference).unwrap()
    );
}
