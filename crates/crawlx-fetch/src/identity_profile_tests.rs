#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Native coherent profile: owned-listener TLS/H2 recipe capture and checked-fetch behavior.
//!
//! Nothing here claims exact Chromium parity. The measured 155 reference signs with the
//! post-quantum algorithms 2308, 2309 and 2310, advertises newer extensions and accepts
//! `zstd`; the native recipe has none of them and the profile declares each as a limitation.
//! The tests assert those differences explicitly instead of hiding them.
//!
//! Run `cargo test -p crawlx-fetch --lib identity_profile -- --nocapture`; the
//! `CRAWLX_NATIVE_IDENTITY_WIRE` line carries the ordered ClientHello fields and the raw
//! first HTTP/2 HEADERS block (HPACK bytes) for measurement.

use super::{capabilities, check_request_headers, emulation_with_root, validate_selection};
use crate::{
    FetchConfig, FetchError, FetchOptions, Fetcher, GlobalOriginCap, GovernorConfig, Origin, RetryPolicy,
    StaticResolver,
};
use crawlx_core::config::Fetch;
use crawlx_core::hash::Digest;
use crawlx_core::identity_profile::{
    IdentityProfileError, IdentityProfileV1, IdentitySelectionV1, NATIVE_USER_AGENT,
};
use crawlx_core::request_controls::RequestControls;
use crawlx_core::session_binding::SessionIdentityV1;
use crawlx_core::tls::TlsImpersonation;
use crawlx_core::traffic::Protocol;
use crawlx_core::PrincipalId;
use crawlx_policy::egress::EgressPolicy;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use url::Url;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DEADLINE: Duration = Duration::from_secs(20);
const CAPTURE_LIMIT: usize = 256 * 1024;
const FRAME_LIMIT: usize = 1 << 20;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// RFC 9113 initial connection window; the profile's window is this plus the WINDOW_UPDATE.
const H2_INITIAL_CONNECTION_WINDOW: u32 = 65_535;
const H2_BODY: &[u8] = b"owned native identity h2 fixture";
const HTTP_BODY: &[u8] = b"owned native identity http fixture";

// Measured from the pinned reference (Chromium 155.0.8059.84). Extension order is permuted
// per connection by both stacks, so it is never asserted.
const REFERENCE_CIPHER_SUITES: [u16; 15] = [
    4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53,
];
const REFERENCE_GROUPS: [u16; 4] = [4588, 29, 23, 24];
const REFERENCE_SIGNATURE_ALGORITHMS: [u16; 11] =
    [2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537];
/// Post-quantum signature algorithms the native transport cannot offer.
const UNAVAILABLE_SIGNATURE_ALGORITHMS: [u16; 3] = [2308, 2309, 2310];
const REFERENCE_SETTINGS: [(u16, u32); 4] = [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)];
const REFERENCE_CONNECTION_WINDOW_INCREMENT: u32 = 15_663_105;
/// TLS certificate compression algorithm identifiers (RFC 8879).
const CERT_COMPRESSION_BROTLI: u16 = 2;
const CERT_COMPRESSION_ZSTD: u16 = 3;

// ---------------------------------------------------------------------------------------
// Selection and configuration helpers
// ---------------------------------------------------------------------------------------

fn selection() -> IdentitySelectionV1 {
    let profile = IdentityProfileV1::pinned_chromium();
    let id = "00000000-0000-0000-0000-000000000001";
    let session: SessionIdentityV1 = serde_json::from_value(serde_json::json!({
        "tenant": id,
        "run": id,
        "principal": PrincipalId::anonymous(),
        "session": id,
        "acquisition": Digest::of("test/acquisition", b"native-identity"),
        "backend_build": profile.backend_build_digest(),
        "egress": Digest::of("test/egress", b"native-identity"),
        "identity_policy": profile.digest().unwrap(),
        "profile": null,
    }))
    .unwrap();
    IdentitySelectionV1::new(session, 1).unwrap()
}

fn identity_config(selection: IdentitySelectionV1) -> FetchConfig {
    FetchConfig {
        identity_profile: Some(selection),
        connect_timeout: DEADLINE,
        request_timeout: DEADLINE,
        retry: RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        },
        governor: GovernorConfig {
            base_delay: Duration::ZERO,
            ..GovernorConfig::default()
        },
        ..FetchConfig::default()
    }
}

fn allowed_policy(ports: &[u16]) -> EgressPolicy {
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.extend_from_slice(ports);
    policy
}

fn fetcher(config: FetchConfig, policy: EgressPolicy, resolver: StaticResolver) -> Fetcher {
    Fetcher::new(config, Arc::new(policy), Arc::new(resolver)).unwrap()
}

/// Construction refusal of `config`; a fetcher that builds is a failed test.
fn refusal(config: FetchConfig) -> IdentityProfileError {
    match Fetcher::new(
        config,
        Arc::new(allowed_policy(&[])),
        Arc::new(StaticResolver::new()),
    ) {
        Err(FetchError::Identity(error)) => error,
        Err(other) => panic!("expected an identity refusal, got {other:?}"),
        Ok(_) => panic!("an invalid identity selection built a fetcher"),
    }
}

async fn controls(configure: impl FnOnce(&mut Fetch)) -> RequestControls {
    let mut fetch = Fetch::default();
    configure(&mut fetch);
    RequestControls::resolve(&fetch, "identity.test", None)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------------------
// Wire capture: read-only tee, ClientHello and HTTP/2 frame parsing
// ---------------------------------------------------------------------------------------

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

/// RFC 8701 reserved slots (`0x0a0a`, `0x1a1a`, ... `0xfafa`); randomized per connection.
const fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0x00ff
}

/// Only the documented GREASE slots are removed; order is never normalized.
fn without_grease(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect()
}

#[derive(Debug, Serialize)]
struct ClientHello {
    /// Raw wire order including the randomized GREASE slot.
    cipher_suites: Vec<u16>,
    extension_ids: Vec<u16>,
    supported_groups: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn: Vec<String>,
    cert_compression: Vec<u16>,
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

fn u16_pairs(mut bytes: &[u8]) -> Vec<u16> {
    assert_eq!(bytes.len() % 2, 0);
    let mut values = Vec::with_capacity(bytes.len() / 2);
    while !bytes.is_empty() {
        values.push(u16_field(&mut bytes));
    }
    values
}

fn u16_vector(bytes: &mut &[u8]) -> Vec<u16> {
    let length = usize::from(u16_field(bytes));
    u16_pairs(take(bytes, length))
}

fn parse_hello(mut bytes: &[u8]) -> ClientHello {
    take(&mut bytes, 2); // legacy_version
    take(&mut bytes, 32); // random
    let session_length = usize::from(u8_field(&mut bytes));
    take(&mut bytes, session_length);
    let cipher_suites = u16_vector(&mut bytes);
    let compression_length = usize::from(u8_field(&mut bytes));
    take(&mut bytes, compression_length);
    let extension_length = usize::from(u16_field(&mut bytes));
    let mut extensions = take(&mut bytes, extension_length);
    assert!(bytes.is_empty(), "trailing ClientHello bytes");
    let mut hello = ClientHello {
        cipher_suites,
        extension_ids: Vec::new(),
        supported_groups: Vec::new(),
        signature_algorithms: Vec::new(),
        alpn: Vec::new(),
        cert_compression: Vec::new(),
    };
    while !extensions.is_empty() {
        let kind = u16_field(&mut extensions);
        let length = usize::from(u16_field(&mut extensions));
        let mut payload = take(&mut extensions, length);
        assert!(!hello.extension_ids.contains(&kind), "duplicate extension {kind}");
        hello.extension_ids.push(kind);
        match kind {
            10 => hello.supported_groups = u16_vector(&mut payload),
            13 => hello.signature_algorithms = u16_vector(&mut payload),
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
            27 => {
                let length = usize::from(u8_field(&mut payload));
                hello.cert_compression = u16_pairs(take(&mut payload, length));
            }
            _ => continue,
        }
        assert!(payload.is_empty(), "trailing parsed extension bytes");
    }
    hello
}

/// First complete ClientHello of the pre-handshake TCP capture.
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

#[derive(Debug, Default, Serialize)]
struct H2Observation {
    /// Frame types received before the response, in wire order.
    frame_types: Vec<u8>,
    /// Entries of every non-ACK SETTINGS frame, in wire order.
    settings: Vec<Vec<(u16, u32)>>,
    connection_window_updates: Vec<u32>,
    headers_stream_id: u32,
    headers_flags: u8,
    /// Five-byte priority fields of the first HEADERS frame, when flagged.
    headers_priority: Option<[u8; 5]>,
    /// HPACK fragments in wire order, excluding padding and priority fields.
    #[serde(skip)]
    hpack_block: Vec<u8>,
    hpack_block_hex: String,
}

#[derive(Debug, Serialize)]
struct Observation {
    profile: &'static str,
    negotiated_tls: String,
    negotiated_cipher_suite: String,
    negotiated_alpn: String,
    client_hello: ClientHello,
    h2: H2Observation,
}

/// One HTTP/2 frame: `(type, flags, stream id, payload)`.
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    stream.read_exact(&mut header).await.unwrap();
    let length = usize::try_from(u32::from_be_bytes([0, header[0], header[1], header[2]])).unwrap();
    assert!(length <= FRAME_LIMIT, "oversized HTTP/2 frame");
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    let stream_id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    (header[3], header[4], stream_id, payload)
}

fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn fixture_acceptor(alpn: &[&[u8]]) -> TlsAcceptor {
    let certificates = CertificateDer::pem_slice_iter(include_bytes!("../tests/fixtures/proxy-leaf.crt"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../tests/fixtures/proxy-leaf.key")).unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsAcceptor::from(Arc::new(config))
}

/// Accept one TLS/H2 connection, capture its first flight and answer the first request.
///
/// The connection stays open until `release` fires, so unread client frames never turn the
/// close into a reset that could discard the response.
async fn serve_h2(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    release: oneshot::Receiver<()>,
) -> Observation {
    let (socket, _) = listener.accept().await.unwrap();
    let encrypted: Capture = Arc::default();
    let mut tls = acceptor
        .accept(ReadTee {
            inner: socket,
            capture: Arc::clone(&encrypted),
        })
        .await
        .unwrap();
    let (negotiated_tls, negotiated_cipher_suite, negotiated_alpn) = {
        let session = tls.get_ref().1;
        (
            format!("{:?}", session.protocol_version().unwrap()),
            format!("{:?}", session.negotiated_cipher_suite().unwrap().suite()),
            String::from_utf8(session.alpn_protocol().unwrap().to_vec()).unwrap(),
        )
    };
    let client_hello = captured_hello(&encrypted.lock().unwrap());

    tls.write_all(&frame(4, 0, 0, &[])).await.unwrap();
    tls.flush().await.unwrap();
    let mut preface = [0; 24];
    tls.read_exact(&mut preface).await.unwrap();
    assert_eq!(preface.as_slice(), H2_PREFACE);

    let mut h2 = H2Observation::default();
    let mut block_open = false;
    loop {
        let (kind, flags, stream_id, frame_payload) = read_frame(&mut tls).await;
        h2.frame_types.push(kind);
        let mut payload: &[u8] = &frame_payload;
        match kind {
            4 if flags & 0x1 == 0 => {
                assert_eq!(stream_id, 0);
                assert_eq!(payload.len() % 6, 0);
                let mut entries = Vec::with_capacity(payload.len() / 6);
                while !payload.is_empty() {
                    entries.push((u16_field(&mut payload), u32_field(&mut payload)));
                }
                h2.settings.push(entries);
                tls.write_all(&frame(4, 0x1, 0, &[])).await.unwrap();
                tls.flush().await.unwrap();
            }
            8 if stream_id == 0 => {
                assert_eq!(payload.len(), 4);
                h2.connection_window_updates
                    .push(u32_field(&mut payload) & 0x7fff_ffff);
            }
            1 if h2.headers_stream_id == 0 => {
                assert_ne!(stream_id, 0);
                h2.headers_stream_id = stream_id;
                h2.headers_flags = flags;
                let padding = if flags & 0x08 != 0 {
                    usize::from(u8_field(&mut payload))
                } else {
                    0
                };
                if flags & 0x20 != 0 {
                    h2.headers_priority = Some(take(&mut payload, 5).try_into().unwrap());
                }
                let fragment = payload.len().checked_sub(padding).unwrap();
                h2.hpack_block.extend_from_slice(take(&mut payload, fragment));
                if flags & 0x04 != 0 {
                    break;
                }
                block_open = true;
            }
            9 if block_open && stream_id == h2.headers_stream_id => {
                h2.hpack_block.extend_from_slice(payload);
                if flags & 0x04 != 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    h2.hpack_block_hex = hex::encode(&h2.hpack_block);

    // `:status 200` as one indexed HPACK byte, then the body with END_STREAM.
    let mut response = frame(1, 0x4, h2.headers_stream_id, &[0x88]);
    response.extend_from_slice(&frame(0, 0x1, h2.headers_stream_id, H2_BODY));
    tls.write_all(&response).await.unwrap();
    tls.flush().await.unwrap();
    let _ = timeout(DEADLINE, release).await;
    let _ = tls.shutdown().await;
    Observation {
        profile: IdentityProfileV1::pinned_chromium().id,
        negotiated_tls,
        negotiated_cipher_suite,
        negotiated_alpn,
        client_hello,
        h2,
    }
}

// ---------------------------------------------------------------------------------------
// (1) Native recipe against an owned TLS/H2 listener
// ---------------------------------------------------------------------------------------

/// Client built from the exact private profile recipe plus one explicit trust root.
#[allow(
    clippy::disallowed_types,
    reason = "owned wire fixture exercises checked transport boundary"
)]
fn native_client(host: &str, port: u16) -> wreq::Client {
    let root = wreq::CertStore::builder()
        .add_pem_cert(include_bytes!("../tests/fixtures/proxy-ca.crt"))
        .build()
        .unwrap();
    wreq::Client::builder()
        .emulation(emulation_with_root(Some(root)).unwrap())
        .redirect(wreq::redirect::Policy::none())
        .referer(false)
        .no_proxy()
        .resolve_to_addrs(host, &[SocketAddr::new(LOOPBACK, port)])
        .connect_timeout(DEADLINE)
        .timeout(DEADLINE)
        .gzip(false)
        .brotli(false)
        .http2_max_retry_count(0)
        .build()
        .unwrap()
}

/// `0x82 :method GET`, `:authority` as literal with name index 1, `0x87 :scheme https`,
/// `0x84 :path /`; the authority value (Huffman or not) is skipped by its length prefix.
fn assert_pseudo_header_prefix(block: &[u8]) {
    assert_eq!(
        block[0], 0x82,
        ":method GET must be the first HPACK byte: {block:02x?}"
    );
    assert!(
        matches!(block[1], 0x41 | 0x01 | 0x11),
        ":authority must follow as a literal with name index 1: {block:02x?}"
    );
    let length = usize::from(block[2] & 0x7f);
    assert!(
        length < 0x7f,
        "authority length uses a multi-byte integer: {block:02x?}"
    );
    let rest = &block[3 + length..];
    assert_eq!(
        &rest[..2],
        &[0x87, 0x84],
        ":scheme https then :path / must follow :authority: {block:02x?}"
    );
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "owned wire fixture exercises checked transport boundary"
)]
async fn native_recipe_emits_declared_profile_over_owned_tls_h2_listener() {
    let profile = IdentityProfileV1::pinned_chromium();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = fixture_acceptor(&[b"h2"]);
    let client = native_client("localhost", port);
    let (release, released) = oneshot::channel();

    let server = serve_h2(&listener, &acceptor, released);
    let request = async {
        // Certificate chain and hostname verification are the profile's own; only the
        // fixture root was added to the store.
        let response = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let version = response.version();
        let body = response.bytes().await.unwrap();
        let _ = release.send(());
        (status, version, body)
    };
    let (observed, (status, version, body)) = timeout(DEADLINE, async { tokio::join!(server, request) })
        .await
        .unwrap();

    println!(
        "CRAWLX_NATIVE_IDENTITY_WIRE {}",
        serde_json::to_string(&observed).unwrap()
    );

    // The request completed through the owned listener.
    assert_eq!(status.as_u16(), 200);
    assert_eq!(version, http::Version::HTTP_2);
    assert_eq!(body.as_ref(), H2_BODY);
    assert_eq!(observed.negotiated_alpn, "h2");

    // ClientHello: ordered fields equal the declared core profile; only GREASE is removed.
    let hello = &observed.client_hello;
    assert!(
        hello.cipher_suites.len() > profile.cipher_suites.len(),
        "the GREASE cipher slot is missing: {:?}",
        hello.cipher_suites
    );
    assert_eq!(without_grease(&hello.cipher_suites), profile.cipher_suites);
    assert_eq!(without_grease(&hello.supported_groups), profile.groups);
    assert_eq!(
        without_grease(&hello.signature_algorithms),
        profile.signature_algorithms
    );
    assert_eq!(hello.alpn, ["h2", "http/1.1"]);
    for extension in [0, 5, 10, 13, 16, 18, 27, 43, 51] {
        assert!(
            hello.extension_ids.contains(&extension),
            "extension {extension} missing: {:?}",
            hello.extension_ids
        );
    }

    // Matches the measured reference everywhere except the declared limitations.
    assert_eq!(profile.cipher_suites, REFERENCE_CIPHER_SUITES);
    assert_eq!(profile.groups, REFERENCE_GROUPS);
    assert_eq!(
        profile.signature_algorithms,
        &REFERENCE_SIGNATURE_ALGORITHMS[UNAVAILABLE_SIGNATURE_ALGORITHMS.len()..]
    );

    // Declared limitation: no exact Chromium parity.
    for unavailable in UNAVAILABLE_SIGNATURE_ALGORITHMS {
        assert!(
            !hello.signature_algorithms.contains(&unavailable),
            "native recipe unexpectedly offers {unavailable}"
        );
    }
    assert_ne!(
        without_grease(&hello.signature_algorithms),
        REFERENCE_SIGNATURE_ALGORITHMS,
        "a reference-equal signature list would contradict the declared limitation"
    );
    assert_eq!(
        hello.cert_compression,
        [CERT_COMPRESSION_BROTLI],
        "only brotli certificate compression is advertised"
    );
    assert!(!hello.cert_compression.contains(&CERT_COMPRESSION_ZSTD));
    let accept_encoding = profile
        .headers
        .iter()
        .find(|(name, _)| *name == "accept-encoding")
        .map(|(_, value)| *value)
        .unwrap();
    assert!(!accept_encoding.contains("zstd"));
    for limitation in [
        "derived_profile_not_exact_wire_equivalence",
        "reference_extension_order_is_randomized",
        "response_zstd_unsupported_not_advertised",
        "reference_post_quantum_signature_algorithms_unavailable",
        "reference_new_tls_extensions_unavailable",
        "http3_unsupported",
    ] {
        assert!(
            profile.limitations.contains(&limitation),
            "limitation {limitation} is not declared"
        );
    }

    // HTTP/2: raw frames in wire order.
    let h2 = &observed.h2;
    assert_eq!(
        h2.frame_types[..2],
        [4, 8],
        "SETTINGS then connection WINDOW_UPDATE: {:?}",
        h2.frame_types
    );
    assert_eq!(h2.settings[0], REFERENCE_SETTINGS);
    assert_eq!(
        h2.settings[0],
        profile
            .h2_settings
            .iter()
            .map(|setting| (setting.id, setting.value))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        h2.connection_window_updates[0],
        REFERENCE_CONNECTION_WINDOW_INCREMENT
    );
    assert_eq!(
        h2.connection_window_updates[0],
        profile.h2_connection_window - H2_INITIAL_CONNECTION_WINDOW
    );
    assert_ne!(h2.headers_stream_id, 0);
    assert_eq!(
        h2.headers_priority,
        Some([0x80, 0, 0, 0, 255]),
        "exclusive dependency on stream 0 with weight byte 255, flags {:#04x}",
        h2.headers_flags
    );
    assert_pseudo_header_prefix(&h2.hpack_block);
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "owned wire fixture exercises checked transport boundary"
)]
async fn native_recipe_verifies_hostname_even_with_the_fixture_root_trusted() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = fixture_acceptor(&[b"h2"]);
    // The leaf certificate names localhost and 127.0.0.1 only, so the fixture CA is trusted.
    let client = native_client("wrong-host.invalid", port);

    let server = async {
        let (socket, _) = listener.accept().await.unwrap();
        acceptor.accept(socket).await.is_err()
    };
    let request = async {
        client
            .get(format!("https://wrong-host.invalid:{port}/"))
            .send()
            .await
            .is_err()
    };
    let (server_refused, client_refused) = timeout(DEADLINE, async { tokio::join!(server, request) })
        .await
        .unwrap();
    assert!(
        client_refused,
        "a trusted root must not bypass hostname verification"
    );
    assert!(
        server_refused,
        "the server completed a handshake with a mismatched name"
    );
}

// ---------------------------------------------------------------------------------------
// (2) Production Fetcher over plain HTTP: ordered native headers through the checked path
// ---------------------------------------------------------------------------------------

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 16_384, "request head too large");
        head.push(stream.read_u8().await.unwrap());
    }
    head
}

/// Serve one HTTP/1.1 request; returns the raw head and the origin slots free while it was in flight.
async fn serve_http(listener: &TcpListener, cap: &GlobalOriginCap, origin: &Origin) -> (String, usize) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let head = String::from_utf8(read_head(&mut stream).await).unwrap();
    let available = cap.available(origin);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        HTTP_BODY.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.write_all(HTTP_BODY).await.unwrap();
    stream.flush().await.unwrap();
    let _ = stream.shutdown().await;
    (head, available)
}

/// Wire header lines in order, names lower-cased; the request line is returned separately.
fn wire_headers(head: &str) -> (&str, Vec<(String, String)>) {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap();
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    (request_line, headers)
}

#[tokio::test]
async fn fetcher_sends_ordered_native_headers_once_through_the_checked_path() {
    let profile = IdentityProfileV1::pinned_chromium();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = Url::parse(&format!("http://identity.test:{port}/")).unwrap();
    let origin = Origin::from_url(&url);
    let cap = Arc::new(GlobalOriginCap::new(GlobalOriginCap::DEFAULT_LIMIT));
    let config = FetchConfig {
        shared_origin_cap: Some(Arc::clone(&cap)),
        ..identity_config(selection())
    };
    assert_eq!(config.user_agent(), NATIVE_USER_AGENT);
    let client = fetcher(
        config,
        allowed_policy(&[port]),
        StaticResolver::new().with("identity.test", [LOOPBACK]),
    );
    assert_eq!(cap.available(&origin), cap.limit());

    let options = FetchOptions::default();
    let ((head, available_in_flight), result) = timeout(DEADLINE, async {
        tokio::join!(serve_http(&listener, &cap, &origin), client.fetch(&url, &options))
    })
    .await
    .unwrap();
    let response = result.unwrap();

    // Ordered selected default headers, no extras and no duplicates (Host is the transport's).
    let (request_line, headers) = wire_headers(&head);
    assert_eq!(request_line, "GET / HTTP/1.1");
    let hosts: Vec<_> = headers.iter().filter(|(name, _)| name == "host").collect();
    assert_eq!(hosts.len(), 1, "{head}");
    assert_eq!(hosts[0].1, format!("identity.test:{port}"));
    let observed: Vec<(&str, &str)> = headers
        .iter()
        .filter(|(name, _)| name != "host")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        observed, profile.headers,
        "wire headers diverge from the selected profile:\n{head}"
    );
    let agents: Vec<_> = headers.iter().filter(|(name, _)| name == "user-agent").collect();
    assert_eq!(agents.len(), 1, "duplicate User-Agent:\n{head}");
    assert_eq!(agents[0].1, NATIVE_USER_AGENT);
    let languages: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "accept-language")
        .collect();
    assert_eq!(languages.len(), 1);
    assert!(languages[0].1.starts_with(profile.locale), "{:?}", languages[0].1);
    let encodings: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == "accept-encoding")
        .collect();
    assert_eq!(encodings.len(), 1);
    assert!(!encodings[0].1.contains("zstd"));

    // The ordinary checked peer/governor/metadata path produced the response.
    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(response.body.as_ref(), HTTP_BODY);
    assert_eq!(response.negotiated_protocol, Some(Protocol::Http11));
    assert!(
        response.peer_observed,
        "the transport peer must be observed, not assumed"
    );
    assert_eq!(response.resolved_ip, LOOPBACK);
    assert_eq!(response.attempts, 1);
    assert!(response.redirects.is_empty());
    assert_eq!(
        available_in_flight,
        cap.limit() - 1,
        "the origin governor must hold a slot while the request is in flight"
    );
    assert_eq!(
        cap.available(&origin),
        cap.limit(),
        "the slot must be released afterwards"
    );
}

#[tokio::test]
async fn fetcher_with_identity_still_refuses_unallowed_ports_before_any_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = Url::parse(&format!("http://identity.test:{port}/")).unwrap();
    let client = fetcher(
        identity_config(selection()),
        allowed_policy(&[]),
        StaticResolver::new().with("identity.test", [LOOPBACK]),
    );
    let error = client.fetch(&url, &FetchOptions::default()).await.unwrap_err();
    assert!(matches!(error, FetchError::EgressDenied(_)), "{error:?}");
    assert_eq!(error.code(), "egress_denied");
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "a denied request opened a socket"
    );
}

#[tokio::test]
async fn incompatible_or_unknown_selection_fails_construction_before_any_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();

    // Alternate TLS selector.
    let mut config = identity_config(selection());
    config.tls_impersonation = TlsImpersonation::Randomized;
    assert!(matches!(
        refusal(config),
        IdentityProfileError::ConflictingControls
    ));

    // Custom User-Agent, custom header, and insecure TLS.
    for controls in [
        controls(|fetch| fetch.user_agent = Some("custom-agent/1.0".to_owned())).await,
        controls(|fetch| fetch.set_header("x-extra", "1").unwrap()).await,
        controls(|fetch| fetch.skip_tls_verification = true).await,
    ] {
        let config = identity_config(selection()).with_controls(controls);
        assert!(matches!(
            refusal(config),
            IdentityProfileError::ConflictingControls
        ));
    }

    // Unknown profile, HTTP/3, exact-wire claim, and mutated session binding.
    let mut unknown = selection();
    unknown.profile_digest = Digest::of("test/profile", b"unknown");
    assert!(matches!(
        refusal(identity_config(unknown)),
        IdentityProfileError::Unavailable
    ));
    let mut http3 = selection();
    http3.require_http3 = true;
    assert!(matches!(
        refusal(identity_config(http3)),
        IdentityProfileError::Http3Unsupported
    ));
    let mut exact = selection();
    exact.require_exact_wire = true;
    assert!(matches!(
        refusal(identity_config(exact)),
        IdentityProfileError::ExactWireUnavailable
    ));
    let mut stale = selection();
    stale.generation = 0;
    assert!(matches!(
        refusal(identity_config(stale)),
        IdentityProfileError::BindingMismatch
    ));
    let mut foreign = selection();
    foreign.session.backend_build = Digest::of("test/build", b"foreign");
    assert!(matches!(
        refusal(identity_config(foreign)),
        IdentityProfileError::BindingMismatch
    ));

    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "construction opened a socket"
    );
}

#[test]
fn validate_selection_and_capabilities_report_the_installed_profile() {
    let profile = IdentityProfileV1::pinned_chromium();
    let selected = selection();
    validate_selection(&selected, &identity_config(selected.clone())).unwrap();

    let mut randomized = identity_config(selected.clone());
    randomized.tls_impersonation = TlsImpersonation::Randomized;
    assert!(matches!(
        validate_selection(&selected, &randomized),
        Err(IdentityProfileError::ConflictingControls)
    ));

    let capability = capabilities(&selected).unwrap();
    assert_eq!(capability.implementation, profile.implementation);
    assert_eq!(capability.build_digest, None);
    assert_eq!(capability.identity_profile, Some(selected.profile_digest));
    assert_eq!(
        capability.limitations,
        profile
            .limitations
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert!(capability
        .limitations
        .iter()
        .any(|value| value == "derived_profile_not_exact_wire_equivalence"));

    let mut exact = selected;
    exact.require_exact_wire = true;
    assert!(
        capabilities(&exact).is_err(),
        "no exact-wire capability may be advertised"
    );
}

// ---------------------------------------------------------------------------------------
// (3) Header gate
// ---------------------------------------------------------------------------------------

fn header_map(entries: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in entries {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn assert_header_conflict(headers: &HeaderMap) {
    let result = check_request_headers(headers);
    assert!(
        matches!(
            result,
            Err(FetchError::Identity(IdentityProfileError::ConflictingControls))
        ),
        "{headers:?} -> {result:?}"
    );
}

#[test]
fn header_gate_refuses_identity_overrides_and_accepts_scoped_credentials() {
    let profile = IdentityProfileV1::pinned_chromium();
    let user_agent = NATIVE_USER_AGENT;

    // Exactly the selected profile headers, and credentials/validators scoped by the caller.
    check_request_headers(&HeaderMap::new()).unwrap();
    check_request_headers(&header_map(&[("user-agent", user_agent)])).unwrap();
    let mut complete = header_map(profile.headers);
    check_request_headers(&complete).unwrap();
    for (name, value) in [
        ("authorization", "Bearer scoped"),
        ("cookie", "sid=scoped"),
        ("if-none-match", "\"etag\""),
        ("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT"),
    ] {
        complete.append(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    check_request_headers(&complete).unwrap();

    // A second User-Agent splits the identity, even with the identical value.
    assert_header_conflict(&header_map(&[
        ("user-agent", user_agent),
        ("user-agent", user_agent),
    ]));
    assert_header_conflict(&header_map(&[("user-agent", "custom-agent/1.0")]));
    // Locale is part of the profile: custom or repeated Accept-Language is refused.
    assert_header_conflict(&header_map(&[("accept-language", "fr-FR,fr;q=0.9")]));
    assert_header_conflict(&header_map(&[
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-language", "en-US,en;q=0.9"),
    ]));
    // Other layers of the header policy are fixed too.
    assert_header_conflict(&header_map(&[("accept-encoding", "gzip, deflate, br, zstd")]));
    assert_header_conflict(&header_map(&[("sec-ch-ua-platform", "\"Windows\"")]));
    assert_header_conflict(&header_map(&[("x-custom", "1")]));
    // Credentials are single-valued as well.
    assert_header_conflict(&header_map(&[("cookie", "a=1"), ("cookie", "b=2")]));
    assert_header_conflict(&header_map(&[("authorization", "one"), ("authorization", "one")]));
}

// ---------------------------------------------------------------------------------------
// (4) Production Fetcher over TLS without a custom root
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn fetcher_with_identity_refuses_untrusted_certificate_without_fallback() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let acceptor = fixture_acceptor(&[b"h2", b"http/1.1"]);
    let client = fetcher(
        identity_config(selection()),
        allowed_policy(&[port]),
        StaticResolver::new().with("localhost", [LOOPBACK]),
    );

    let server = async {
        let (socket, _) = listener.accept().await.unwrap();
        // The client aborts after seeing a certificate outside its default roots; no
        // application byte can follow a failed handshake.
        acceptor.accept(socket).await.is_err()
    };
    let options = FetchOptions::default();
    let (server_refused, result) = timeout(DEADLINE, async {
        tokio::join!(server, client.fetch(&url, &options))
    })
    .await
    .unwrap();
    assert!(
        server_refused,
        "the server completed a handshake with an untrusted certificate"
    );
    let error = result.unwrap_err();
    assert_eq!(error.code(), "transport");
    assert!(error.to_string().to_ascii_lowercase().contains("cert"), "{error}");

    // Neither a retry, a downgrade to another engine, nor insecure verification reconnects.
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "a second connection followed the refused certificate"
    );
}

#[test]
fn selected_identity_never_injects_an_alternate_proxy_backend() {
    let config = identity_config(selection());
    let fetcher = fetcher(config, EgressPolicy::new(false), StaticResolver::new());
    let alternative = Url::parse("http://route.invalid:8080").unwrap();
    assert!(matches!(
        fetcher.with_enhanced_proxy(&alternative),
        Err(FetchError::Identity(IdentityProfileError::ConflictingControls))
    ));
}
