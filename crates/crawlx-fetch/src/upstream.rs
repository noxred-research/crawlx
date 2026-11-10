//! Upstream proxy chaining of the loopback egress proxy (katana
//! `-proxy` / `-headless-options --proxy-server`, Firecrawl `proxy: basic` on rendered pages).
//!
//! Chromium is always pointed at the loopback [`crate::EgressProxy`], which applies the egress
//! policy to every request. With an [`UpstreamProxy`] the proxy then reaches the target through
//! the operator's proxy (`fetch.proxy`) instead of dialing it:
//!
//! * `http://` and `https://` proxies: `CONNECT host:port` tunnels (TLS stays end to end) and
//!   absolute-form HTTP/1.1 forwarding for plain `http://` pages, both carrying
//!   `Proxy-Authorization: Basic …` when the URL has credentials. An `https://` proxy is
//!   reached over TLS validated against the bundled Mozilla roots.
//! * `socks5://` (the target address the policy checked is sent) and `socks5h://` (the host
//!   name is sent and the proxy resolves it), with RFC 1929 user/password authentication.
//!
//! The egress policy runs first on the target name and on every address the local resolver
//! returns for it, and then on the proxy host itself: a proxy on a denied address is refused
//! like any other target. The proxy resolves host names itself, so a name that answers with a
//! public address here and a private one there is outside what the policy can pin; that is
//! the same trust the fetch plane places in `fetch.proxy`.

use crate::error::FetchError;
use crate::proxyx::{ProxyxRoute, TunnelLog};
use base64::Engine as _;
use http::HeaderValue;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use url::{Host, Url};

/// Bound on the proxy handshake (TLS, `CONNECT` answer, SOCKS5 negotiation).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest `CONNECT` answer header block read from the proxy.
const MAX_CONNECT_HEAD: usize = 16 * 1024;
/// Target addresses tried through a local-DNS SOCKS5 proxy before giving up.
const MAX_SOCKS_ATTEMPTS: usize = 4;

/// A bidirectional byte stream to the target or to the proxy.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
/// Boxed [`Io`]: the direct, TLS-wrapped and SOCKS5 streams share one type.
pub(crate) type BoxIo = Box<dyn Io>;

/// Scheme of the operator's proxy URL.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum UpstreamScheme {
    /// `http://`: plain TCP to the proxy.
    Http,
    /// `https://`: TLS to the proxy.
    Https,
    /// `socks5://`: SOCKS5 with the target address resolved locally.
    Socks5,
    /// `socks5h://`: SOCKS5 with the host name resolved by the proxy.
    Socks5h,
}

#[derive(Clone)]
struct Credentials {
    user: String,
    password: String,
    /// `Basic base64(user:password)`, marked sensitive.
    basic: HeaderValue,
}

/// Operator-supplied proxy routes. A tier is a plain proxy URL or a ProxyX pool route, never
/// both; no other provider-specific behavior is assumed.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ProxyRoutes {
    /// Basic route; absence preserves the request's existing proxy or direct route.
    pub basic: Option<Url>,
    /// Enhanced route; required for both enhanced and automatic scrape modes.
    pub enhanced: Option<Url>,
    /// Basic route through a ProxyX pool gateway; replaces `basic`.
    pub basic_pool: Option<ProxyxRoute>,
    /// Enhanced route through a ProxyX pool gateway; replaces `enhanced`.
    pub enhanced_pool: Option<ProxyxRoute>,
}

impl fmt::Debug for ProxyRoutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRoutes")
            .field("basic", &self.basic.as_ref().map(|_| "[configured]"))
            .field("enhanced", &self.enhanced.as_ref().map(|_| "[configured]"))
            .field("basic_pool", &self.basic_pool)
            .field("enhanced_pool", &self.enhanced_pool)
            .finish()
    }
}

/// The operator's upstream proxy (`fetch.proxy`) the egress proxy chains to.
///
/// `Debug` never prints the credentials.
#[derive(Clone)]
pub struct UpstreamProxy {
    scheme: UpstreamScheme,
    host: String,
    port: u16,
    credentials: Option<Credentials>,
    tls: Option<TlsConnector>,
    /// A ProxyX pool gateway: `CONNECT` only (it answers an absolute-form request with `405`),
    /// and every `CONNECT` answer is recorded in the log.
    pool: Option<Arc<TunnelLog>>,
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credentials", &self.credentials.is_some())
            .finish()
    }
}

/// `scheme://host[:port]` of `url` without its userinfo, for error messages.
fn redacted(url: &Url) -> String {
    format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""))
}

fn decode(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8_lossy()
        .into_owned()
}

impl UpstreamProxy {
    /// Parse `fetch.proxy`: `http`, `https`, `socks5` or `socks5h` with a host, an optional
    /// port (default 80, 443 and 1080) and optional percent-encoded `user:password`.
    ///
    /// # Errors
    /// [`FetchError::InvalidUrl`] (the message never contains the credentials) for another
    /// scheme, a missing host, or SOCKS5 credentials longer than the 255 bytes RFC 1929 allows.
    pub fn from_url(url: &Url) -> Result<Self, FetchError> {
        let scheme = match url.scheme() {
            "http" => UpstreamScheme::Http,
            "https" => UpstreamScheme::Https,
            "socks5" => UpstreamScheme::Socks5,
            "socks5h" => UpstreamScheme::Socks5h,
            _ => {
                return Err(FetchError::InvalidUrl {
                    url: redacted(url),
                    reason: "proxy scheme must be http, https, socks5 or socks5h",
                })
            }
        };
        let host = match url.host() {
            Some(Host::Domain(d)) => d.to_ascii_lowercase(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            None => {
                return Err(FetchError::InvalidUrl {
                    url: redacted(url),
                    reason: "proxy URL has no host",
                })
            }
        };
        let port = url.port().unwrap_or(match scheme {
            UpstreamScheme::Http => 80,
            UpstreamScheme::Https => 443,
            UpstreamScheme::Socks5 | UpstreamScheme::Socks5h => 1080,
        });
        let user = decode(url.username());
        let password = url.password().map(decode);
        let credentials = if user.is_empty() && password.is_none() {
            None
        } else {
            let password = password.unwrap_or_default();
            if matches!(scheme, UpstreamScheme::Socks5 | UpstreamScheme::Socks5h)
                && (user.len() > 255 || password.len() > 255)
            {
                return Err(FetchError::InvalidUrl {
                    url: redacted(url),
                    reason: "SOCKS5 credentials are at most 255 bytes each",
                });
            }
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            let mut basic =
                HeaderValue::from_str(&format!("Basic {token}")).map_err(|_| FetchError::InvalidUrl {
                    url: redacted(url),
                    reason: "proxy credentials are not valid in a header",
                })?;
            basic.set_sensitive(true);
            Some(Credentials {
                user,
                password,
                basic,
            })
        };
        let tls = (scheme == UpstreamScheme::Https)
            .then(|| tls_connector(&[]))
            .transpose()
            .map_err(|_| FetchError::InvalidUrl {
                url: redacted(url),
                reason: "TLS client configuration for the https proxy failed",
            })?;
        Ok(Self {
            scheme,
            host,
            port,
            credentials,
            tls,
            pool: None,
        })
    }

    /// The upstream of a ProxyX pool gateway at `gateway` (`http` or `https`, no userinfo):
    /// the typed `username` and the org key as Basic credentials, `CONNECT` only, with every
    /// answer recorded in `log`.
    ///
    /// # Errors
    /// [`FetchError::InvalidUrl`] for another scheme, a missing host or a credential that
    /// cannot be sent in a header. The message never contains the credentials.
    pub(crate) fn pool(
        gateway: &Url,
        username: &str,
        org_key: &str,
        log: Arc<TunnelLog>,
    ) -> Result<Self, FetchError> {
        if !matches!(gateway.scheme(), "http" | "https") {
            return Err(FetchError::InvalidUrl {
                url: redacted(gateway),
                reason: "a pool gateway is an http or https proxy",
            });
        }
        let mut with_credentials = gateway.clone();
        with_credentials
            .set_username(username)
            .and_then(|()| with_credentials.set_password(Some(org_key)))
            .map_err(|()| FetchError::InvalidUrl {
                url: redacted(gateway),
                reason: "pool credentials cannot be attached to the gateway URL",
            })?;
        let mut upstream = Self::from_url(&with_credentials)?;
        upstream.pool = Some(log);
        Ok(upstream)
    }

    /// Scheme of the proxy URL.
    #[must_use]
    pub const fn scheme(&self) -> UpstreamScheme {
        self.scheme
    }

    /// Lower-cased proxy host (IP literals without brackets).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Proxy port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Does the proxy take absolute-form HTTP requests (`http`/`https`), as opposed to
    /// SOCKS5 where plain HTTP is sent in origin form over the tunnel? A pool gateway takes
    /// `CONNECT` only, so plain HTTP targets are tunneled and sent in origin form.
    pub(crate) const fn speaks_http(&self) -> bool {
        self.pool.is_none() && matches!(self.scheme, UpstreamScheme::Http | UpstreamScheme::Https)
    }

    /// `Proxy-Authorization` for HTTP proxies, `None` without credentials.
    pub(crate) fn authorization(&self) -> Option<&HeaderValue> {
        self.credentials.as_ref().map(|c| &c.basic)
    }

    /// Trust `extra` in addition to the bundled roots when this is an `https://` proxy (a
    /// proxy with a private CA, or a test proxy).
    #[cfg(test)]
    pub(crate) fn with_extra_roots(mut self, extra: &[CertificateDer<'static>]) -> Self {
        if self.scheme == UpstreamScheme::Https {
            self.tls = tls_connector(extra).ok();
        }
        self
    }

    /// Connect to the proxy (TLS-wrapped for `https://`) at one of its checked addresses.
    async fn dial_proxy(&self, addrs: &[SocketAddr]) -> Result<BoxIo, String> {
        let tcp = crate::egress::connect_any(addrs)
            .await
            .map_err(|e| format!("cannot reach the upstream proxy: {e}"))?;
        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some(connector) => {
                let name = ServerName::try_from(self.host.clone())
                    .map_err(|e| format!("upstream proxy host is not a valid TLS name: {e}"))?;
                let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, tcp))
                    .await
                    .map_err(|_| "upstream proxy TLS handshake timed out".to_owned())?
                    .map_err(|e| format!("upstream proxy TLS handshake failed: {e}"))?;
                Ok(Box::new(tls))
            }
        }
    }

    /// A connection to an HTTP(S) proxy on which an absolute-form request is sent.
    ///
    /// # Errors
    /// The failure text when no proxy address is reachable or the TLS handshake fails.
    pub(crate) async fn connect_for_forward(&self, proxy_addrs: &[SocketAddr]) -> Result<BoxIo, String> {
        self.dial_proxy(proxy_addrs).await
    }

    /// A stream that is a plain pipe to `host:port` through the proxy: `CONNECT` for HTTP(S)
    /// proxies, a SOCKS5 `CONNECT` otherwise. `target_addrs` are the policy-checked addresses
    /// of `host`; only `socks5://` sends one of them, the others send the name.
    ///
    /// # Errors
    /// The failure text (never the credentials): proxy unreachable, handshake refused or timed
    /// out, or the proxy's refusal to reach the target.
    pub(crate) async fn tunnel(
        &self,
        proxy_addrs: &[SocketAddr],
        host: &str,
        port: u16,
        target_addrs: &[SocketAddr],
    ) -> Result<BoxIo, String> {
        match self.scheme {
            UpstreamScheme::Http | UpstreamScheme::Https => {
                let mut io = self.dial_proxy(proxy_addrs).await?;
                let answer = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    http_connect(&mut io, host, port, self.authorization()),
                )
                .await
                .map_err(|_| "upstream proxy CONNECT timed out".to_owned())?;
                match (answer, &self.pool) {
                    (Ok(answer), log) => {
                        if let Some(log) = log {
                            log.opened(host, port, answer.session.as_deref(), answer.exit_ip.as_deref());
                        }
                        Ok(io)
                    }
                    (Err(error), Some(log)) => {
                        if let ConnectError::Refused { status, reason } = &error {
                            log.refused(host, port, *status, reason);
                        }
                        Err(error.message(true))
                    }
                    (Err(error), None) => Err(error.message(false)),
                }
            }
            UpstreamScheme::Socks5h => {
                let dest = host
                    .parse::<IpAddr>()
                    .map_or(Destination::Domain(host), Destination::Ip);
                self.socks_attempt(proxy_addrs, dest, port).await
            }
            UpstreamScheme::Socks5 => {
                let mut last = "no target address".to_owned();
                for addr in target_addrs.iter().take(MAX_SOCKS_ATTEMPTS) {
                    match self
                        .socks_attempt(proxy_addrs, Destination::Ip(addr.ip()), port)
                        .await
                    {
                        Ok(io) => return Ok(io),
                        Err(e) => last = e,
                    }
                }
                Err(last)
            }
        }
    }

    async fn socks_attempt(
        &self,
        proxy_addrs: &[SocketAddr],
        dest: Destination<'_>,
        port: u16,
    ) -> Result<BoxIo, String> {
        let mut io = self.dial_proxy(proxy_addrs).await?;
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            socks5_connect(&mut io, dest, port, self.credentials.as_ref()),
        )
        .await
        .map_err(|_| "upstream SOCKS5 proxy handshake timed out".to_owned())??;
        Ok(io)
    }
}

/// Root store of the bundled Mozilla roots plus `extra`, and a TLS 1.2/1.3 client over it.
fn tls_connector(extra: &[CertificateDer<'static>]) -> Result<TlsConnector, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots.add(cert.clone()).map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// `host:port`, with an IPv6 literal bracketed.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// What a `2xx` `CONNECT` answer carries that a caller may need: the ProxyX pool gateway
/// names the session and the exit IP of the tunnel in two response headers.
#[derive(Default)]
struct ConnectAnswer {
    session: Option<String>,
    exit_ip: Option<String>,
}

/// Why a `CONNECT` did not open a tunnel.
enum ConnectError {
    /// The proxy answered with a non-`2xx` status line.
    Refused { status: u16, reason: String },
    /// Anything else: write or read failure, malformed or oversized answer.
    Failed(String),
}

impl ConnectError {
    /// The failure text, never carrying credentials or arbitrary remote text.
    fn message(&self, pool: bool) -> String {
        match self {
            Self::Failed(text) => text.clone(),
            Self::Refused { status, reason } if pool => {
                let reason: String = reason
                    .chars()
                    .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                    .take(32)
                    .collect();
                format!("pool gateway refused CONNECT: {status} {reason}")
            }
            Self::Refused { status: 407, .. } => "upstream proxy requires authentication (407)".to_owned(),
            Self::Refused { status, .. } => format!("upstream proxy refused CONNECT: {status}"),
        }
    }
}

/// Send `CONNECT host:port` and require a `2xx` answer. The answer is read byte by byte so
/// no tunnel byte is consumed.
async fn http_connect(
    io: &mut BoxIo,
    host: &str,
    port: u16,
    auth: Option<&HeaderValue>,
) -> Result<ConnectAnswer, ConnectError> {
    let failed = |text: String| ConnectError::Failed(text);
    let authority = authority(host, port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(value) = auth.and_then(|v| v.to_str().ok()) {
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes())
        .await
        .map_err(|e| failed(format!("upstream proxy CONNECT write failed: {e}")))?;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_CONNECT_HEAD {
            return Err(failed("upstream proxy CONNECT answer is too long".to_owned()));
        }
        let n = io
            .read(&mut byte)
            .await
            .map_err(|e| failed(format!("upstream proxy CONNECT read failed: {e}")))?;
        if n == 0 {
            return Err(failed(
                "upstream proxy closed the connection during CONNECT".to_owned(),
            ));
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut fields = status_line.splitn(3, ' ');
    let code = fields.nth(1).and_then(|c| c.trim().parse::<u16>().ok());
    match code {
        Some(c) if (200..300).contains(&c) => {
            let mut answer = ConnectAnswer::default();
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("x-proxyx-pool-session") {
                    answer.session = Some(value.trim().to_owned());
                } else if name.trim().eq_ignore_ascii_case("x-proxyx-exit-ip") {
                    answer.exit_ip = Some(value.trim().to_owned());
                }
            }
            Ok(answer)
        }
        Some(status) => Err(ConnectError::Refused {
            status,
            reason: status_line
                .splitn(3, ' ')
                .nth(2)
                .unwrap_or_default()
                .trim()
                .to_owned(),
        }),
        None => Err(failed(
            "upstream proxy sent a malformed CONNECT answer".to_owned(),
        )),
    }
}

/// What a SOCKS5 `CONNECT` names.
#[derive(Clone, Copy)]
enum Destination<'a> {
    Ip(IpAddr),
    Domain(&'a str),
}

/// RFC 1928 `CONNECT` (with RFC 1929 user/password when `creds` is set).
async fn socks5_connect(
    io: &mut BoxIo,
    dest: Destination<'_>,
    port: u16,
    creds: Option<&Credentials>,
) -> Result<(), String> {
    let io_err = |what: &'static str| move |e: std::io::Error| format!("SOCKS5 {what} failed: {e}");
    let greeting: &[u8] = if creds.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    io.write_all(greeting).await.map_err(io_err("greeting"))?;
    let mut choice = [0u8; 2];
    io.read_exact(&mut choice).await.map_err(io_err("greeting"))?;
    if choice[0] != 0x05 {
        return Err("upstream proxy is not a SOCKS5 server".to_owned());
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let creds =
                creds.ok_or_else(|| "SOCKS5 proxy demands credentials the URL does not have".to_owned())?;
            let user = creds.user.as_bytes();
            let pass = creds.password.as_bytes();
            let (Ok(ulen), Ok(plen)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
                return Err("SOCKS5 credentials are too long".to_owned());
            };
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(ulen);
            auth.extend_from_slice(user);
            auth.push(plen);
            auth.extend_from_slice(pass);
            io.write_all(&auth).await.map_err(io_err("authentication"))?;
            let mut status = [0u8; 2];
            io.read_exact(&mut status)
                .await
                .map_err(io_err("authentication"))?;
            if status[1] != 0x00 {
                return Err("SOCKS5 proxy rejected the credentials".to_owned());
            }
        }
        0xFF => return Err("SOCKS5 proxy accepts none of the offered authentication methods".to_owned()),
        other => {
            return Err(format!(
                "SOCKS5 proxy chose unsupported authentication method {other:#04x}"
            ))
        }
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match dest {
        Destination::Ip(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Destination::Ip(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Destination::Domain(name) => {
            let len = u8::try_from(name.len())
                .map_err(|_| "SOCKS5 host name is longer than 255 bytes".to_owned())?;
            request.push(0x03);
            request.push(len);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    io.write_all(&request).await.map_err(io_err("request"))?;
    let mut reply = [0u8; 4];
    io.read_exact(&mut reply).await.map_err(io_err("reply"))?;
    if reply[0] != 0x05 {
        return Err("SOCKS5 reply has the wrong version".to_owned());
    }
    if reply[1] != 0x00 {
        let why = match reply[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(format!("SOCKS5 proxy could not reach the target: {why}"));
    }
    // drain the bound address so the first tunnel byte is the target's
    let bound = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            io.read_exact(&mut len).await.map_err(io_err("reply"))?;
            usize::from(len[0])
        }
        _ => return Err("SOCKS5 reply has an unknown address type".to_owned()),
    };
    let mut rest = vec![0u8; bound + 2];
    io.read_exact(&mut rest).await.map_err(io_err("reply"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn parse(s: &str) -> Result<UpstreamProxy, FetchError> {
        UpstreamProxy::from_url(&Url::parse(s).unwrap())
    }

    #[test]
    fn schemes_default_ports_and_hosts_parse() {
        let p = parse("http://Proxy.Example").unwrap();
        assert_eq!(
            (p.scheme(), p.host(), p.port()),
            (UpstreamScheme::Http, "proxy.example", 80)
        );
        assert_eq!(parse("https://p.test").unwrap().port(), 443);
        assert_eq!(parse("socks5://p.test").unwrap().port(), 1080);
        let p = parse("socks5h://[::1]:9050").unwrap();
        assert_eq!(
            (p.scheme(), p.host(), p.port()),
            (UpstreamScheme::Socks5h, "::1", 9050)
        );
        assert!(!p.speaks_http());
        assert!(parse("http://p.test:3128").unwrap().speaks_http());
    }

    #[test]
    fn credentials_are_percent_decoded_and_never_printed() {
        let p = parse("http://us%40er:p%3Ass@proxy.test:3128").unwrap();
        // base64("us@er:p:ss")
        assert_eq!(
            p.authorization().unwrap().to_str().unwrap(),
            "Basic dXNAZXI6cDpzcw=="
        );
        assert!(p.authorization().unwrap().is_sensitive());
        let shown = format!("{p:?}");
        assert!(
            !shown.contains("us@er") && !shown.contains("p:ss") && !shown.contains("dXNAZXI6"),
            "{shown}"
        );
        assert!(shown.contains("credentials: true"), "{shown}");
        assert!(parse("http://proxy.test").unwrap().authorization().is_none());
    }

    #[test]
    fn errors_name_the_proxy_without_its_credentials() {
        let err = parse("ftp://secret:hunter2@proxy.test/").unwrap_err().to_string();
        assert!(err.contains("ftp://proxy.test"), "{err}");
        assert!(!err.contains("hunter2") && !err.contains("secret"), "{err}");
        let long = format!("socks5://{}:x@p.test", "u".repeat(256));
        assert!(parse(&long).is_err());
    }

    #[tokio::test]
    async fn an_https_proxy_is_reached_over_tls_that_trusts_the_configured_roots() {
        use tokio::net::TcpListener;
        use tokio_rustls::rustls::pki_types::pem::PemObject;
        use tokio_rustls::rustls::pki_types::PrivateKeyDer;
        use tokio_rustls::rustls::ServerConfig;

        // a private CA and a leaf for 127.0.0.1 signed by it (a self-signed CA-as-leaf is refused)
        let ca_pem = include_bytes!("../tests/fixtures/proxy-ca.crt");
        let cert_pem = include_bytes!("../tests/fixtures/proxy-leaf.crt");
        let key_pem = include_bytes!("../tests/fixtures/proxy-leaf.key");
        let ca = CertificateDer::from_pem_slice(ca_pem).unwrap().into_owned();
        let cert = CertificateDer::from_pem_slice(cert_pem).unwrap().into_owned();
        let key = PrivateKeyDer::from_pem_slice(key_pem).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tls.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut ping = [0u8; 4];
            tls.read_exact(&mut ping).await.unwrap();
            tls.write_all(b"pong").await.unwrap();
            String::from_utf8(head).unwrap()
        });

        let url = Url::parse(&format!("https://user:pw@127.0.0.1:{}", addr.port())).unwrap();
        let proxy = UpstreamProxy::from_url(&url).unwrap().with_extra_roots(&[ca]);
        let target = [SocketAddr::from(([93, 184, 216, 34], 443))];
        let mut io = proxy.tunnel(&[addr], "target.test", 443, &target).await.unwrap();
        io.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        io.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        let head = server.await.unwrap();
        assert!(head.starts_with("CONNECT target.test:443 HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"),
            "{head}"
        );

        // without the extra root the private CA's certificate is refused
        let strict = UpstreamProxy::from_url(&url).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let err = match strict.tunnel(&[addr], "target.test", 443, &target).await {
            Ok(_) => panic!("an untrusted proxy certificate must not be accepted"),
            Err(e) => e,
        };
        assert!(err.contains("TLS handshake"), "{err}");
    }
}
