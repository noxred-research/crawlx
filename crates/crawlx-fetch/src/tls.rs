//! Opt-in synthetic ClientHello randomization for the URL plane.
//!
//! The compatibility flag for randomized ClientHellos selects a fully randomized hello, not a random browser
//! template. This implementation deliberately uses a narrower, modern profile:
//! seeded TLS 1.2 AEAD cipher, group, signature and extension ordering, plus seeded
//! OCSP/SCT requests. TLS 1.3 remains enabled with an explicit modern cipher prefix.
//! EMS, padding and ALPN retain BoringSSL defaults. These are synthetic fingerprints,
//! not faithful mainstream-browser fingerprints or an exact probability distribution of another stack.
//!
//! Only fingerprint choices use `CrawlSeed`; cryptographic randomness stays inside
//! BoringSSL. Disabling impersonation leaves the existing rustls transport unchanged.

use crate::client::FetchConfig;
use crate::error::FetchError;
use crate::resolver::Resolver;
use crate::{EgressOptions, EgressProxy, EgressProxyHandle, UpstreamProxy};
use boring2::ssl::SslCurve;
use bytes::Bytes;
use crawlx_core::seed::CrawlSeed;
use crawlx_policy::egress::EgressPolicy;
use http::{HeaderMap, Method, StatusCode, Version};
use rand::seq::SliceRandom;
use rand::RngExt as _;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

struct SelectedHello {
    cipher_list: String,
    curves: Vec<SslCurve>,
    sigalgs_list: String,
    permutation: Vec<u8>,
    ocsp: bool,
    sct: bool,
    #[cfg(test)]
    cipher_ids: Vec<u16>,
    #[cfg(test)]
    group_ids: Vec<u16>,
}

impl SelectedHello {
    fn from_seed(seed: CrawlSeed) -> Self {
        let mut rng = seed.rng("tls-client-hello-v1", &[]);
        // Every offered TLS 1.2 cipher uses ECDHE and AEAD. Randomization never
        // enables legacy CBC, RC4, static RSA, or an unimplemented capability.
        let mut ciphers = [
            ("ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02b),
            ("ECDHE-RSA-AES128-GCM-SHA256", 0xc02f),
            ("ECDHE-ECDSA-AES256-GCM-SHA384", 0xc02c),
            ("ECDHE-RSA-AES256-GCM-SHA384", 0xc030),
            ("ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca9),
            ("ECDHE-RSA-CHACHA20-POLY1305", 0xcca8),
        ];
        ciphers.shuffle(&mut rng);
        let mut groups = [
            (SslCurve::X25519, 29),
            (SslCurve::SECP256R1, 23),
            (SslCurve::SECP384R1, 24),
        ];
        groups.shuffle(&mut rng);
        let mut sigalgs = [
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
        ];
        sigalgs.shuffle(&mut rng);
        // Include each documented configurable extension slot once, preserving
        // required TLS capabilities. Disabled extensions remain disabled.
        let mut permutation: Vec<u8> = (0..25).collect();
        permutation.shuffle(&mut rng);
        Self {
            // boring2's bundled patch puts TLS 1.3 suites in the configurable
            // list instead of automatically prefixing them. Replacing that list
            // with TLS 1.2 names alone advertises TLS 1.3 without usable suites.
            cipher_list: joined(
                [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ]
                .into_iter()
                .chain(ciphers.iter().map(|(name, _)| *name)),
            ),
            curves: groups.iter().map(|(curve, _)| *curve).collect(),
            sigalgs_list: joined(sigalgs.into_iter()),
            permutation,
            ocsp: rng.random_bool(0.5),
            sct: rng.random_bool(0.5),
            #[cfg(test)]
            cipher_ids: ciphers.iter().map(|(_, id)| *id).collect(),
            #[cfg(test)]
            group_ids: groups.iter().map(|(_, id)| *id).collect(),
        }
    }

    fn into_config(self, skip_verification: bool) -> wreq::tls::TlsConfig {
        wreq::tls::TlsConfig::builder()
            .cert_verification(!skip_verification)
            .verify_hostname(!skip_verification)
            .min_tls_version(wreq::tls::TlsVersion::TLS_1_2)
            .max_tls_version(wreq::tls::TlsVersion::TLS_1_3)
            .cipher_list(self.cipher_list)
            .curves(self.curves)
            .sigalgs_list(self.sigalgs_list)
            .extension_permutation_indices(self.permutation)
            .permute_extensions(false)
            .grease_enabled(false)
            .enable_ocsp_stapling(self.ocsp)
            .enable_signed_cert_timestamps(self.sct)
            .random_aes_hw_override(false)
            .build()
    }
}

fn joined<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let mut joined = String::new();
    for name in names {
        if !joined.is_empty() {
            joined.push(':');
        }
        joined.push_str(name);
    }
    joined
}

pub(crate) enum HttpClient {
    Rustls(reqwest::Client),
    Randomized {
        client: wreq::Client,
        socks: Option<Box<SocksAdapter>>,
    },
}

/// wreq's SOCKS connector uses system DNS rather than its configured resolver.
/// Route those requests through the existing checked connector instead. Each
/// request owns one loopback adapter until its response body is consumed/dropped.
pub(crate) struct SocksAdapter {
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
    upstream: UpstreamProxy,
}

impl HttpClient {
    pub(crate) fn randomized<R: wreq::dns::Resolve + 'static>(
        cfg: &FetchConfig,
        pins: Arc<R>,
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, FetchError> {
        let tls = SelectedHello::from_seed(cfg.seed).into_config(cfg.controls.skip_tls_verification());
        let provider = wreq::EmulationProvider::builder().tls_config(tls).build();
        let mut builder = wreq::Client::builder()
            .emulation(provider)
            .user_agent(cfg.user_agent())
            .redirect(wreq::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .dns_resolver(pins)
            .connect_timeout(cfg.connect_timeout)
            .timeout(cfg.request_timeout)
            .gzip(true)
            .brotli(true);
        let mut socks = None;
        if let Some(proxy) = &cfg.proxy {
            if matches!(proxy.scheme(), "socks5" | "socks5h") {
                // Never construct wreq::Proxy from a SOCKS URL: it resolves the
                // proxy eagerly, before a policy check, through system DNS.
                socks = Some(Box::new(SocksAdapter {
                    policy,
                    resolver,
                    upstream: UpstreamProxy::from_url(proxy)?,
                }));
            } else {
                builder = builder.proxy(
                    wreq::Proxy::all(proxy.as_str())
                        .map_err(|error| FetchError::ClientBuild(error.into()))?,
                );
            }
        }
        let client = builder
            .build()
            .map_err(|error| FetchError::ClientBuild(error.into()))?;
        Ok(Self::Randomized { client, socks })
    }

    pub(crate) async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
    ) -> Result<HttpResponse, FetchError> {
        match self {
            Self::Rustls(client) => client
                .request(method, url)
                .headers(headers)
                .send()
                .await
                .map(HttpResponse::Rustls)
                .map_err(FetchError::from_reqwest),
            Self::Randomized { client, socks } => {
                let adapter = match socks {
                    Some(route) => Some(
                        EgressProxy::serve_with(
                            Arc::clone(&route.policy),
                            Arc::clone(&route.resolver),
                            EgressOptions::new().with_upstream(route.upstream.clone()),
                        )
                        .await?,
                    ),
                    None => None,
                };
                let mut request = client.request(method, url).headers(headers);
                if let Some(proxy) = &adapter {
                    request = request.proxy(
                        wreq::Proxy::all(format!("http://{}", proxy.addr()))
                            .map_err(|error| FetchError::ClientBuild(error.into()))?,
                    );
                }
                let response = request.send().await.map_err(FetchError::from_wreq)?;
                Ok(HttpResponse::Randomized { response, adapter })
            }
        }
    }
}

pub(crate) enum HttpResponse {
    Rustls(reqwest::Response),
    Randomized {
        response: wreq::Response,
        adapter: Option<EgressProxyHandle>,
    },
}

impl HttpResponse {
    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Rustls(response) => response.remote_addr(),
            Self::Randomized { response, adapter } => {
                // The loopback socket is an internal adapter, not the network
                // peer. EgressProxy pins/checks the real SOCKS proxy socket.
                if adapter.is_some() {
                    None
                } else {
                    response.remote_addr()
                }
            }
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Rustls(response) => response.status(),
            Self::Randomized { response, .. } => response.status(),
        }
    }

    pub(crate) fn headers(&self) -> &HeaderMap {
        match self {
            Self::Rustls(response) => response.headers(),
            Self::Randomized { response, .. } => response.headers(),
        }
    }

    pub(crate) fn version(&self) -> Version {
        match self {
            Self::Rustls(response) => response.version(),
            Self::Randomized { response, .. } => response.version(),
        }
    }

    pub(crate) async fn chunk(&mut self) -> Result<Option<Bytes>, FetchError> {
        match self {
            Self::Rustls(response) => response.chunk().await.map_err(FetchError::from_reqwest),
            Self::Randomized { response, .. } => response.chunk().await.map_err(FetchError::from_wreq),
        }
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
