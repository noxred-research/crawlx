#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Loopback wire regressions for the standard engine's synthetic TLS profiles.

use super::SelectedHello;
use crate::{FetchConfig, FetchError, FetchOptions, Fetcher, GovernorConfig, RetryPolicy, StaticResolver};
use crawlx_core::config::Fetch;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::tls::TlsImpersonation;
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener as BlockingListener};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{version, ProtocolVersion, ServerConfig, SupportedProtocolVersion};
use tokio_rustls::TlsAcceptor;
use url::Url;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const OTHER_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const DEADLINE: Duration = Duration::from_secs(10);

fn randomized_config(seed: u64) -> FetchConfig {
    FetchConfig {
        tls_impersonation: TlsImpersonation::Randomized,
        seed: CrawlSeed(seed),
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

// JA3's ordered fields, not random bytes, session IDs, or key-share material.
#[derive(Debug, PartialEq, Eq)]
struct HelloFields {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> &'a [u8] {
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    value
}

fn read_u8(bytes: &mut &[u8]) -> u8 {
    take(bytes, 1)[0]
}

fn read_u16(bytes: &mut &[u8]) -> u16 {
    u16::from_be_bytes(take(bytes, 2).try_into().unwrap())
}

fn vector_u16(bytes: &mut &[u8]) -> Vec<u16> {
    let length = usize::from(read_u16(bytes));
    let mut values = take(bytes, length);
    assert_eq!(values.len() % 2, 0);
    let mut result = Vec::with_capacity(length / 2);
    while !values.is_empty() {
        result.push(read_u16(&mut values));
    }
    result
}

fn parse_hello(mut bytes: &[u8]) -> HelloFields {
    let version = read_u16(&mut bytes);
    take(&mut bytes, 32); // Client random.
    let session_length = usize::from(read_u8(&mut bytes));
    take(&mut bytes, session_length);
    let ciphers = vector_u16(&mut bytes);
    let compression_length = usize::from(read_u8(&mut bytes));
    assert_eq!(take(&mut bytes, compression_length), &[0]);
    let extension_length = usize::from(read_u16(&mut bytes));
    let mut extension_bytes = take(&mut bytes, extension_length);
    assert!(bytes.is_empty(), "trailing ClientHello bytes");
    let mut hello = HelloFields {
        version,
        ciphers,
        extensions: Vec::new(),
        groups: Vec::new(),
        point_formats: Vec::new(),
    };
    while !extension_bytes.is_empty() {
        let kind = read_u16(&mut extension_bytes);
        let length = usize::from(read_u16(&mut extension_bytes));
        let mut payload = take(&mut extension_bytes, length);
        assert!(!hello.extensions.contains(&kind), "duplicate extension {kind}");
        hello.extensions.push(kind);
        match kind {
            10 => {
                hello.groups = vector_u16(&mut payload);
                assert!(payload.is_empty());
            }
            11 => {
                let length = usize::from(read_u8(&mut payload));
                hello.point_formats = take(&mut payload, length).to_vec();
                assert!(payload.is_empty());
            }
            _ => {}
        }
    }
    hello
}

async fn read_hello(stream: &mut TcpStream) -> HelloFields {
    let mut handshake = Vec::new();
    loop {
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22, "expected TLS handshake record");
        assert_eq!(header[1], 3, "expected TLS record version");
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        assert!((1..=16_384).contains(&length));
        let start = handshake.len();
        handshake.resize(start.checked_add(length).unwrap(), 0);
        stream.read_exact(&mut handshake[start..]).await.unwrap();
        if handshake.len() < 4 {
            continue;
        }
        assert_eq!(handshake[0], 1, "expected ClientHello");
        let hello_length =
            usize::try_from(u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]])).unwrap();
        let end = hello_length.checked_add(4).unwrap();
        assert!(end <= 65_536, "unreasonably large ClientHello");
        if handshake.len() >= end {
            assert_eq!(handshake.len(), end, "unexpected following handshake");
            return parse_hello(&handshake[4..end]);
        }
    }
}

async fn capture(seed: u64, through_proxy: bool) -> HelloFields {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = randomized_config(seed);
    let target = if through_proxy {
        config.proxy = Some(Url::parse(&format!("http://proxy.test:{port}/")).unwrap());
        Url::parse("https://target.test/wire").unwrap()
    } else {
        Url::parse(&format!("https://target.test:{port}/wire")).unwrap()
    };
    let client = fetcher(
        config,
        allowed_policy(&[port]),
        StaticResolver::new()
            .with("target.test", [LOOPBACK])
            .with("proxy.test", [LOOPBACK]),
    );
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        if through_proxy {
            let headers = read_headers(&mut stream).await;
            let request = std::str::from_utf8(&headers).unwrap();
            assert!(
                request.starts_with("CONNECT target.test:443 HTTP/1.1\r\n"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        }
        read_hello(&mut stream).await
    };
    let options = FetchOptions::default();
    let (hello, result) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(server, client.fetch(&target, &options))
    })
    .await
    .unwrap();
    // The capture endpoint intentionally closes after ClientHello, before ServerHello.
    assert_eq!(result.unwrap_err().code(), "transport");
    hello
}

fn assert_selected(hello: &HelloFields, seed: u64) {
    let selected = SelectedHello::from_seed(CrawlSeed(seed));
    assert_eq!(hello.version, 0x0303);
    assert!(hello.ciphers.len() > selected.cipher_ids.len());
    let prefix_length = hello.ciphers.len() - selected.cipher_ids.len();
    assert_eq!(&hello.ciphers[..prefix_length], &[0x1301, 0x1302, 0x1303]);
    assert_eq!(&hello.ciphers[prefix_length..], selected.cipher_ids);
    assert_eq!(hello.groups, selected.group_ids);
    assert_eq!(hello.extensions.contains(&5), selected.ocsp);
    assert_eq!(hello.extensions.contains(&18), selected.sct);
    // BoringSSL's permutation uses native extension slots, not TLS extension IDs.
    // Padding is library-controlled and depends on the encoded ClientHello length.
    let expected_extensions: Vec<u16> = selected
        .permutation
        .iter()
        .filter_map(|slot| match *slot {
            0 => Some(0),
            2 => Some(23),
            3 => Some(65_281),
            4 => Some(10),
            5 => Some(11),
            6 => Some(35),
            7 => Some(16),
            8 if selected.ocsp => Some(5),
            9 => Some(13),
            11 if selected.sct => Some(18),
            14 => Some(51),
            15 => Some(45),
            17 => Some(43),
            _ => None,
        })
        .collect();
    let actual_extensions: Vec<u16> = hello
        .extensions
        .iter()
        .copied()
        .filter(|extension| *extension != 21)
        .collect();
    assert_eq!(actual_extensions, expected_extensions, "seed {seed}");
    assert!(hello.extensions.contains(&0), "SNI missing");
    assert!(hello.extensions.contains(&13), "signature algorithms missing");
    assert!(hello.extensions.contains(&43), "supported versions missing");
    assert!(hello.extensions.contains(&51), "key share missing");
    assert_eq!(hello.point_formats, [0]);
}

#[tokio::test]
async fn same_seed_emits_identical_ordered_ja3_fields() {
    let first = capture(42, false).await;
    let second = capture(42, false).await;
    assert_selected(&first, 42);
    assert_selected(&second, 42);
    assert_eq!(first, second);
}

#[tokio::test]
async fn different_seeds_change_emitted_hello_not_only_the_plan() {
    let first = capture(0, false).await;
    assert_selected(&first, 0);
    let mut changed = false;
    for seed in 1..8 {
        let hello = capture(seed, false).await;
        assert_selected(&hello, seed);
        changed |= hello != first;
    }
    assert!(changed, "different seeds emitted identical JA3 fields");
}

#[tokio::test]
async fn https_connect_tunnel_preserves_seeded_client_hello() {
    let direct = capture(13, false).await;
    let proxied = capture(13, true).await;
    assert_selected(&proxied, 13);
    assert_eq!(direct, proxied);
}

async fn capture_socks(seed: u64, scheme: &str) -> HelloFields {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = randomized_config(seed);
    config.proxy = Some(Url::parse(&format!("{scheme}://proxy.test:{port}/")).unwrap());
    let target = Url::parse("https://target.test/wire").unwrap();
    let client = fetcher(
        config,
        allowed_policy(&[port]),
        StaticResolver::new()
            .with("target.test", [OTHER_LOOPBACK])
            .with("proxy.test", [LOOPBACK]),
    );
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0], "expected SOCKS5 without authentication");
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[5, 1, 0], "expected SOCKS5 CONNECT");
        if scheme == "socks5" {
            assert_eq!(request[3], 1, "socks5 must use the checked target IP");
            let mut address = [0; 4];
            stream.read_exact(&mut address).await.unwrap();
            assert_eq!(address, [127, 0, 0, 2]);
        } else {
            assert_eq!(scheme, "socks5h");
            assert_eq!(request[3], 3, "socks5h must preserve the target domain");
            let length = usize::from(stream.read_u8().await.unwrap());
            let mut domain = vec![0; length];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"target.test");
        }
        let mut target_port = [0; 2];
        stream.read_exact(&mut target_port).await.unwrap();
        assert_eq!(u16::from_be_bytes(target_port), 443);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        read_hello(&mut stream).await
    };
    let options = FetchOptions::default();
    let (hello, result) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(server, client.fetch(&target, &options))
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code(), "transport");
    hello
}

#[tokio::test]
async fn socks_proxies_use_static_dns_and_preserve_seeded_client_hello() {
    let direct = capture(13, false).await;
    for scheme in ["socks5", "socks5h"] {
        let proxied = capture_socks(13, scheme).await;
        assert_selected(&proxied, 13);
        assert_eq!(direct, proxied, "{scheme} changed the ClientHello fingerprint");
    }
}

async fn read_headers(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        assert!(headers.len() < 16_384, "request headers too large");
        headers.push(stream.read_u8().await.unwrap());
    }
    headers
}

fn fixture_acceptor() -> TlsAcceptor {
    fixture_acceptor_with_versions(&[&version::TLS13, &version::TLS12])
}

fn fixture_acceptor_with_versions(versions: &[&'static SupportedProtocolVersion]) -> TlsAcceptor {
    let certs = CertificateDer::pem_slice_iter(include_bytes!("../tests/fixtures/selfsigned.crt"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("../tests/fixtures/selfsigned.key")).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

#[tokio::test]
async fn certificate_verification_stays_secure_and_skip_remains_explicit() {
    for mode in [TlsImpersonation::Off, TlsImpersonation::Randomized] {
        for skip in [false, true] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let target = Url::parse(&format!("https://localhost:{port}/")).unwrap();
            let mut config = randomized_config(42);
            config.tls_impersonation = mode;
            if skip {
                config.controls = RequestControls::resolve(
                    &Fetch {
                        skip_tls_verification: true,
                        ..Fetch::default()
                    },
                    "localhost",
                    None,
                )
                .await
                .unwrap();
            }
            let client = fetcher(
                config,
                allowed_policy(&[port]),
                StaticResolver::new().with("localhost", [LOOPBACK]),
            );
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut tls = fixture_acceptor().accept(stream).await?;
                let headers = read_headers(&mut tls).await;
                assert!(headers.starts_with(b"GET / HTTP/1.1\r\n"));
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure")
                    .await?;
                tls.flush().await?;
                Ok::<_, io::Error>(())
            };
            let options = FetchOptions::default();
            let (server_result, result) = tokio::time::timeout(DEADLINE, async {
                tokio::join!(server, client.fetch(&target, &options))
            })
            .await
            .unwrap();
            if skip {
                server_result.unwrap();
                let response = result.unwrap();
                assert_eq!(response.status.as_u16(), 200);
                assert_eq!(response.body.as_ref(), b"secure");
            } else {
                assert!(server_result.is_err(), "server accepted an untrusted certificate");
                let error = result.unwrap_err();
                assert_eq!(error.code(), "transport");
                assert!(error.to_string().to_ascii_lowercase().contains("cert"), "{error}");
            }
        }
    }
}

#[tokio::test]
async fn randomized_transport_negotiates_each_supported_tls_version() {
    for (supported, negotiated) in [
        (&version::TLS12, ProtocolVersion::TLSv1_2),
        (&version::TLS13, ProtocolVersion::TLSv1_3),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = Url::parse(&format!("https://localhost:{port}/")).unwrap();
        let mut config = randomized_config(42);
        config.controls = RequestControls::resolve(
            &Fetch {
                skip_tls_verification: true,
                ..Fetch::default()
            },
            "localhost",
            None,
        )
        .await
        .unwrap();
        let client = fetcher(
            config,
            allowed_policy(&[port]),
            StaticResolver::new().with("localhost", [LOOPBACK]),
        );
        let acceptor = fixture_acceptor_with_versions(&[supported]);
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await?;
            assert_eq!(tls.get_ref().1.protocol_version(), Some(negotiated));
            let headers = read_headers(&mut tls).await;
            assert!(headers.starts_with(b"GET / HTTP/1.1\r\n"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure")
                .await?;
            tls.flush().await?;
            Ok::<_, io::Error>(())
        };
        let options = FetchOptions::default();
        let (server_result, result) = tokio::time::timeout(DEADLINE, async {
            tokio::join!(server, client.fetch(&target, &options))
        })
        .await
        .unwrap();
        server_result.unwrap();
        let response = result.unwrap();
        assert_eq!(response.status.as_u16(), 200);
        assert_eq!(response.body.as_ref(), b"secure");
    }
}

fn blocked_listener(ip: IpAddr) -> BlockingListener {
    let listener = BlockingListener::bind((ip, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_not_dialed(listener: &BlockingListener) {
    let error = listener.accept().expect_err("egress-denied socket was dialed");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[tokio::test]
async fn https_target_denial_prevents_any_socket_connection() {
    let listener = blocked_listener(LOOPBACK);
    let port = listener.local_addr().unwrap().port();
    let mut policy = EgressPolicy::new(false);
    policy.extra_ports.push(port);
    let client = fetcher(
        randomized_config(42),
        policy,
        StaticResolver::new().with("target.test", [LOOPBACK]),
    );
    let target = Url::parse(&format!("https://target.test:{port}/")).unwrap();
    let error = client.fetch(&target, &FetchOptions::default()).await.unwrap_err();
    assert!(matches!(&error, FetchError::EgressDenied(denied) if denied.rule == DenyRule::Loopback));
    assert_not_dialed(&listener);
}

#[tokio::test]
async fn denied_https_target_never_dials_an_allowed_proxy() {
    let target_listener = blocked_listener(LOOPBACK);
    let proxy_listener = blocked_listener(OTHER_LOOPBACK);
    let target_port = target_listener.local_addr().unwrap().port();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let mut config = randomized_config(42);
    config.proxy = Some(Url::parse(&format!("http://proxy.test:{proxy_port}/")).unwrap());
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.2/32".parse().unwrap());
    policy.extra_ports.extend([target_port, proxy_port]);
    let client = fetcher(
        config,
        policy,
        StaticResolver::new()
            .with("target.test", [LOOPBACK])
            .with("proxy.test", [OTHER_LOOPBACK]),
    );
    let target = Url::parse(&format!("https://target.test:{target_port}/")).unwrap();
    let error = client.fetch(&target, &FetchOptions::default()).await.unwrap_err();
    assert!(matches!(&error, FetchError::EgressDenied(denied) if denied.rule == DenyRule::Loopback));
    assert_not_dialed(&target_listener);
    assert_not_dialed(&proxy_listener);
}

#[tokio::test]
async fn denied_proxy_never_gets_a_socket_for_an_allowed_https_target() {
    let target_listener = blocked_listener(OTHER_LOOPBACK);
    let proxy_listener = blocked_listener(LOOPBACK);
    let target_port = target_listener.local_addr().unwrap().port();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let mut config = randomized_config(42);
    config.proxy = Some(Url::parse(&format!("http://proxy.test:{proxy_port}/")).unwrap());
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.2/32".parse().unwrap());
    policy.extra_ports.extend([target_port, proxy_port]);
    let client = fetcher(
        config,
        policy,
        StaticResolver::new()
            .with("target.test", [OTHER_LOOPBACK])
            .with("proxy.test", [LOOPBACK]),
    );
    let target = Url::parse(&format!("https://target.test:{target_port}/")).unwrap();
    let error = client.fetch(&target, &FetchOptions::default()).await.unwrap_err();
    assert!(matches!(&error, FetchError::EgressDenied(denied) if denied.rule == DenyRule::Loopback));
    assert_not_dialed(&target_listener);
    assert_not_dialed(&proxy_listener);
}

#[tokio::test]
async fn https_redirect_rechecks_egress_before_dialing_the_next_hop() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let denied_listener = blocked_listener(OTHER_LOOPBACK);
    let denied_port = denied_listener.local_addr().unwrap().port();
    let target = Url::parse(&format!("https://localhost:{port}/redirect")).unwrap();
    let mut config = randomized_config(42);
    config.controls = RequestControls::resolve(
        &Fetch {
            skip_tls_verification: true,
            ..Fetch::default()
        },
        "localhost",
        None,
    )
    .await
    .unwrap();
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    policy.extra_ports.extend([port, denied_port]);
    let client = fetcher(
        config,
        policy,
        StaticResolver::new()
            .with("localhost", [LOOPBACK])
            .with("denied.test", [OTHER_LOOPBACK]),
    );
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = fixture_acceptor().accept(stream).await?;
        let headers = read_headers(&mut tls).await;
        assert!(headers.starts_with(b"GET /redirect HTTP/1.1\r\n"));
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://denied.test:{denied_port}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(response.as_bytes()).await?;
        tls.flush().await?;
        Ok::<_, io::Error>(())
    };
    let options = FetchOptions::default();
    let (server_result, result) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(server, client.fetch(&target, &options))
    })
    .await
    .unwrap();
    server_result.unwrap();
    let error = result.unwrap_err();
    assert!(matches!(&error, FetchError::EgressDenied(denied) if denied.rule == DenyRule::Loopback));
    assert_not_dialed(&denied_listener);
}
