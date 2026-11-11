//! One profile-exclusive native HTTP identity; checked fetch remains the effect owner.
//!
//! TLS, HTTP/2, header order, User-Agent and locale are selected together. No global
//! environment variable, process-wide header policy, browser execution or hidden fallback exists.

use crate::{FetchConfig, FetchError};
use crawlx_core::identity_profile::{IdentityProfileError, IdentityProfileV1, IdentitySelectionV1};
use crawlx_core::tls::TlsImpersonation;
use http::{HeaderMap, HeaderName, HeaderValue};
use wreq::{AlpnProtos, AlpsProtos, CertCompressionAlgorithm, PseudoOrder, SettingsOrder, SslCurve};

/// Validate selection and custom controls before any client or proxy adapter starts.
///
/// # Errors
/// Refuses unknown/exact-wire/H3 profiles, mismatched sessions, synthetic TLS selection,
/// insecure TLS, and custom User-Agent/header injection that would invalidate coherence.
pub fn validate_selection(
    selection: &IdentitySelectionV1,
    config: &FetchConfig,
) -> Result<(), IdentityProfileError> {
    selection.validate()?;
    if config.tls_impersonation != TlsImpersonation::Off
        || config.controls.skip_tls_verification()
        || config.controls.user_agent().is_some()
        || !config.controls.headers().is_empty()
        || config.pool.as_ref().is_some_and(|pool| pool.rotates_each())
    {
        return Err(IdentityProfileError::ConflictingControls);
    }
    Ok(())
}

/// Native capability facts, not exact-reference equivalence or a JavaScript claim.
///
/// # Errors
/// Refuses invalid selections before advertising an installed profile.
pub fn capabilities(
    selection: &IdentitySelectionV1,
) -> Result<crawlx_core::acquisition::BackendCapabilitiesV1, IdentityProfileError> {
    selection.validate()?;
    let profile = IdentityProfileV1::pinned_chromium();
    let mut capability = crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
        profile.implementation,
        env!("CARGO_PKG_VERSION"),
    );
    capability.identity_profile = Some(selection.profile_digest);
    capability.limitations = profile
        .limitations
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    Ok(capability)
}

pub(crate) fn emulation() -> Result<wreq::EmulationProvider, FetchError> {
    emulation_with_root(None)
}

fn emulation_with_root(root: Option<wreq::CertStore>) -> Result<wreq::EmulationProvider, FetchError> {
    let profile = IdentityProfileV1::pinned_chromium();
    let mut headers = HeaderMap::with_capacity(profile.headers.len());
    let mut order = Vec::with_capacity(profile.headers.len());
    for &(name, value) in profile.headers {
        let name = HeaderName::from_static(name);
        let value = HeaderValue::from_static(value);
        if headers.insert(name.clone(), value).is_some() {
            return Err(IdentityProfileError::ConflictingControls.into());
        }
        order.push(name);
    }
    // One fixed recipe selects every layer. GREASE and cryptographic random material
    // stay inside the TLS engine; they never use CrawlSeed.
    let mut tls = wreq::TlsConfig::builder()
        .cert_verification(true)
        .verify_hostname(true)
        .min_tls_version(wreq::TlsVersion::TLS_1_2)
        .max_tls_version(wreq::TlsVersion::TLS_1_3)
        .alpn_protos(AlpnProtos::ALL)
        .alps_protos(AlpsProtos::HTTP2)
        .alps_use_new_codepoint(true)
        .cipher_list("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA")
        .curves(&[SslCurve::X25519_MLKEM768, SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1][..])
        .sigalgs_list("ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512")
        .grease_enabled(true)
        .permute_extensions(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .enable_ech_grease(true)
        .cert_compression_algorithm([CertCompressionAlgorithm::Brotli])
        .build();
    if let Some(root) = root {
        tls.cert_store = Some(std::borrow::Cow::Owned(root));
    }
    let h2 = wreq::Http2Config::builder()
        .header_table_size(65536)
        .enable_push(false)
        .initial_stream_window_size(6291456)
        .initial_connection_window_size(profile.h2_connection_window)
        .max_header_list_size(262144)
        .headers_priority((0, 255, true))
        .headers_pseudo_order([
            PseudoOrder::Method,
            PseudoOrder::Authority,
            PseudoOrder::Scheme,
            PseudoOrder::Path,
        ])
        .settings_order([
            SettingsOrder::HeaderTableSize,
            SettingsOrder::EnablePush,
            SettingsOrder::InitialWindowSize,
            SettingsOrder::MaxHeaderListSize,
            SettingsOrder::MaxConcurrentStreams,
            SettingsOrder::MaxFrameSize,
            SettingsOrder::UnknownSetting8,
            SettingsOrder::UnknownSetting9,
        ])
        .build();
    Ok(wreq::EmulationProvider::builder()
        .tls_config(tls)
        .http2_config(h2)
        .default_headers(headers)
        .headers_order(order)
        .build())
}

pub(crate) fn check_request_headers(headers: &HeaderMap) -> Result<(), FetchError> {
    let profile = IdentityProfileV1::pinned_chromium();
    for (name, value) in headers {
        if headers.get_all(name).iter().nth(1).is_some() {
            return Err(IdentityProfileError::ConflictingControls.into());
        }
        if matches!(
            name.as_str(),
            "authorization" | "cookie" | "if-none-match" | "if-modified-since"
        ) {
            continue;
        }
        if !profile.headers.iter().any(|(expected, expected_value)| {
            name.as_str() == *expected && value.as_bytes() == expected_value.as_bytes()
        }) {
            return Err(IdentityProfileError::ConflictingControls.into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "identity_profile_tests.rs"]
mod tests;
