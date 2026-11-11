//! Immutable, digest-bound HTTP identity derived from the pinned Chromium build.
//!
//! A derived HTTP profile is not a browser, a JavaScript engine, or a claim of exact
//! wire equivalence. Ordered owned-listener measurements remain separate evidence.

use crate::hash::Digest;
use crate::session_binding::SessionIdentityV1;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Exact reference build used to derive this profile.
pub const REFERENCE_VERSION: &str = "155.0.8059.84";
/// SHA-256 of the archive recorded by the repository's Chromium pin.
pub const REFERENCE_ARCHIVE_SHA256: &str = "cf0f049892dea22e6a6db26d47ed0d7776b7158edcbec4634086633df8bafcbc";
/// SHA-256 measured from the selected Linux x86_64 executable.
pub const REFERENCE_EXECUTABLE_SHA256: &str =
    "b866a2964538c825538c454de4867973b926650da57ec12dc3328807d768247b";
/// SHA-256 of the reference executable's complete embedded notice page.
pub const REFERENCE_NOTICES_SHA256: &str = "fc63eda353b7cc0cf797c7d7e5ae823096b8a2d1734f83afb078a405d3a0fb65";
/// Frozen wire-compatible native User-Agent selected with the profile's other layers.
// wire-compat: HTTP User-Agent product tokens required by the pinned reference policy.
pub const NATIVE_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/155.0.0.0 Safari/537.36"; // wire-compat

/// One ordered, immutable HTTP/2 setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct IdentitySettingV1 {
    /// Registered HTTP/2 setting identifier.
    pub id: u16,
    /// Value advertised by this profile.
    pub value: u32,
}

/// Fixed native profile; callers select its digest, never mutate individual layers.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityProfileV1 {
    /// Profile contract version.
    pub schema_version: u8,
    /// Versioned native profile identifier, not an unversioned browser alias.
    pub id: &'static str,
    /// Exact reference version, independent of the native implementation version.
    pub reference_version: &'static str,
    /// Exact reference archive hash.
    pub reference_archive_sha256: &'static str,
    /// Exact reference executable hash.
    pub reference_executable_sha256: &'static str,
    /// Embedded transitive notice bundle hash; redistribution still needs approval.
    pub reference_notices_sha256: &'static str,
    /// Actual native transport implementation and pinned package versions.
    pub implementation: &'static str,
    /// Explicit locale policy, shared by User-Agent/header identity and cache binding.
    pub locale: &'static str,
    /// Fixed ordered cipher identifiers, excluding the randomized GREASE slot.
    pub cipher_suites: &'static [u16],
    /// Fixed ordered named groups, excluding the randomized GREASE slot.
    pub groups: &'static [u16],
    /// Ordered signature algorithms supported by the native transport.
    pub signature_algorithms: &'static [u16],
    /// Ordered advertised HTTP/2 settings.
    pub h2_settings: &'static [IdentitySettingV1],
    /// Initial connection receive window.
    pub h2_connection_window: u32,
    /// Fixed pseudo-header order.
    pub pseudo_headers: &'static [&'static str],
    /// Ordered native default header policy. Values contain no caller secrets.
    pub headers: &'static [(&'static str, &'static str)],
    /// Known differences are explicit, never hidden by a profile label.
    pub limitations: &'static [&'static str],
}

impl IdentityProfileV1 {
    /// Borrow the one installed native profile.
    #[must_use]
    pub fn pinned_chromium() -> &'static Self {
        static PROFILE: LazyLock<IdentityProfileV1> = LazyLock::new(|| {
            IdentityProfileV1 {
            schema_version: 1,
            id: "chromium-155-linux-x86_64-http-v1",
            reference_version: REFERENCE_VERSION,
            reference_archive_sha256: REFERENCE_ARCHIVE_SHA256,
            reference_executable_sha256: REFERENCE_EXECUTABLE_SHA256,
            reference_notices_sha256: REFERENCE_NOTICES_SHA256,
            implementation: "wreq/0.15.3+boring2/4.15.15",
            locale: "en-US",
            cipher_suites: &[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
            groups: &[4588, 29, 23, 24],
            signature_algorithms: &[1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
            h2_settings: &[
                IdentitySettingV1 { id: 1, value: 65536 },
                IdentitySettingV1 { id: 2, value: 0 },
                IdentitySettingV1 { id: 4, value: 6291456 },
                IdentitySettingV1 { id: 6, value: 262144 },
            ],
            h2_connection_window: 15728640,
            pseudo_headers: &[":method", ":authority", ":scheme", ":path"],
            headers: &[
                // wire-compat: client hints measured from the pinned headless reference.
                ("sec-ch-ua", "\"Chromium\";v=\"155\", \"Not(A:Brand\";v=\"24\""),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Linux\""),
                ("accept-language", "en-US,en;q=0.9"),
                ("upgrade-insecure-requests", "1"),
                ("user-agent", NATIVE_USER_AGENT),
                ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-user", "?1"),
                ("sec-fetch-dest", "document"),
                ("accept-encoding", "gzip, deflate, br"),
                ("priority", "u=0, i"),
            ],
            limitations: &[
                "derived_profile_not_exact_wire_equivalence",
                "reference_extension_order_is_randomized",
                "response_zstd_unsupported_not_advertised",
                "reference_post_quantum_signature_algorithms_unavailable",
                "reference_new_tls_extensions_unavailable",
                "http3_unsupported",
                "no_javascript_execution",
                "redistribution_approval_external_required",
                "native_executable_digest_unavailable",
            ],
        }
        });
        &PROFILE
    }

    /// Stable profile identity covering every TLS/H2/header/build/locale field.
    ///
    /// # Errors
    /// Returns a serialization error before selecting a profile.
    pub fn digest(&self) -> Result<Digest, IdentityProfileError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crawlx/http-identity-profile/v1\0");
        serde_json::to_writer(&mut hasher, self).map_err(IdentityProfileError::Serialization)?;
        Ok(Digest(*hasher.finalize().as_bytes()))
    }

    /// Native dependency-contract identity used by the existing static session binding.
    /// This is not an executable/image artifact hash and must not be reported as one.
    #[must_use]
    pub fn backend_build_digest(&self) -> Digest {
        Digest::of("crawlx/http-identity-backend/v1", self.implementation.as_bytes())
    }
}

/// Unsupported profile or an identity mutation on a live session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityProfileError {
    /// Profile encoding failed before selecting any transport.
    #[error("http identity profile encoding failed")]
    Serialization(#[source] serde_json::Error),
    /// The caller requested a profile unavailable in this executable.
    #[error("http identity profile unavailable")]
    Unavailable,
    /// The selected native transport has no exact-reference equivalence receipt.
    #[error("exact reference wire equivalence unavailable")]
    ExactWireUnavailable,
    /// Session generation, build, or policy binding does not match.
    #[error("http identity session binding mismatch")]
    BindingMismatch,
    /// HTTP/3 cannot be provided by this profile.
    #[error("http3 identity transport unsupported")]
    Http3Unsupported,
    /// An alternate TLS selector, custom User-Agent, or header would split the profile.
    #[error("custom transport controls invalidate coherent http identity")]
    ConflictingControls,
}

/// Explicit profile selection subordinate to the existing tenant/principal session identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct IdentitySelectionV1 {
    /// Installed immutable profile digest.
    pub profile_digest: Digest,
    /// Existing complete session identity; never a second cookie/session registry.
    pub session: SessionIdentityV1,
    /// Exact existing generation.
    pub generation: u64,
    /// Exact equivalence must fail closed until independently measured and approved.
    pub require_exact_wire: bool,
    /// Explicit unsupported protocol requests fail before network I/O.
    pub require_http3: bool,
}

impl IdentitySelectionV1 {
    /// Select the installed profile for an already-authorized immutable session.
    ///
    /// # Errors
    /// Rejects mismatched build, identity policy, or absent generation.
    pub fn new(session: SessionIdentityV1, generation: u64) -> Result<Self, IdentityProfileError> {
        let selected = Self {
            profile_digest: IdentityProfileV1::pinned_chromium().digest()?,
            session,
            generation,
            require_exact_wire: false,
            require_http3: false,
        };
        selected.validate()?;
        Ok(selected)
    }

    /// Validate every deserialized or reconstructed selection before client construction.
    ///
    /// # Errors
    /// Rejects unknown profiles, unsupported protocols, exact-wire claims, and session mutation.
    pub fn validate(&self) -> Result<(), IdentityProfileError> {
        let profile = IdentityProfileV1::pinned_chromium();
        if self.profile_digest != profile.digest()? {
            return Err(IdentityProfileError::Unavailable);
        }
        if self.require_http3 {
            return Err(IdentityProfileError::Http3Unsupported);
        }
        if self.require_exact_wire {
            return Err(IdentityProfileError::ExactWireUnavailable);
        }
        if self.generation == 0
            || self.session.backend_build != profile.backend_build_digest()
            || self.session.identity_policy != self.profile_digest
        {
            return Err(IdentityProfileError::BindingMismatch);
        }
        Ok(())
    }

    /// Cache/connection namespace including every existing authority binding and generation.
    ///
    /// # Errors
    /// Rejects invalid selections or serialization failure before returning an identity.
    pub fn cache_digest(&self) -> Result<Digest, IdentityProfileError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crawlx/http-identity-session/v1\0");
        serde_json::to_writer(&mut hasher, self).map_err(IdentityProfileError::Serialization)?;
        Ok(Digest(*hasher.finalize().as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn profile_digest_covers_reference_and_all_layers() {
        let profile = IdentityProfileV1::pinned_chromium();
        assert_eq!(profile.reference_version, REFERENCE_VERSION);
        assert_ne!(profile.digest().unwrap(), profile.backend_build_digest());
        assert_eq!(
            profile.pseudo_headers,
            [":method", ":authority", ":scheme", ":path"]
        );
        assert!(profile.limitations.contains(&"http3_unsupported"));
        let pin = include_str!("../../../chromium-pin.toml");
        assert!(pin.contains(REFERENCE_VERSION));
        assert!(pin.contains(REFERENCE_ARCHIVE_SHA256));
    }

    fn selection() -> IdentitySelectionV1 {
        let profile = IdentityProfileV1::pinned_chromium();
        let id = "\"00000000-0000-0000-0000-000000000001\"";
        IdentitySelectionV1::new(
            SessionIdentityV1 {
                tenant: serde_json::from_str(id).unwrap(),
                run: serde_json::from_str(id).unwrap(),
                principal: crate::PrincipalId::anonymous(),
                session: serde_json::from_str(id).unwrap(),
                acquisition: Digest::of("test/acquisition", b"one"),
                backend_build: profile.backend_build_digest(),
                egress: Digest::of("test/egress", b"one"),
                identity_policy: profile.digest().unwrap(),
                profile: None,
            },
            1,
        )
        .unwrap()
    }

    #[test]
    fn profile_rejects_unknown_exact_h3_and_session_mutation() {
        let original = selection();
        let mut changed = original.clone();
        changed.profile_digest = Digest::of("test/profile", b"unknown");
        assert!(matches!(
            changed.validate(),
            Err(IdentityProfileError::Unavailable)
        ));
        changed = original.clone();
        changed.require_exact_wire = true;
        assert!(matches!(
            changed.validate(),
            Err(IdentityProfileError::ExactWireUnavailable)
        ));
        changed = original.clone();
        changed.require_http3 = true;
        assert!(matches!(
            changed.validate(),
            Err(IdentityProfileError::Http3Unsupported)
        ));
        changed = original.clone();
        changed.session.backend_build = Digest::of("test/build", b"foreign");
        assert!(matches!(
            changed.validate(),
            Err(IdentityProfileError::BindingMismatch)
        ));
        changed = original;
        changed.generation = 0;
        assert!(matches!(
            changed.validate(),
            Err(IdentityProfileError::BindingMismatch)
        ));
    }

    #[test]
    fn cache_namespace_separates_existing_session_authority() {
        let original = selection();
        let baseline = original.cache_digest().unwrap();
        let mut changed = original.clone();
        changed.generation = 2;
        assert_ne!(baseline, changed.cache_digest().unwrap());
        changed = original.clone();
        changed.session.tenant = serde_json::from_str("\"00000000-0000-0000-0000-000000000002\"").unwrap();
        assert_ne!(baseline, changed.cache_digest().unwrap());
        changed = original.clone();
        changed.session.egress = Digest::of("test/egress", b"two");
        assert_ne!(baseline, changed.cache_digest().unwrap());
        changed = original;
        changed.session.profile = Some(Digest::of("test/profile", b"two"));
        assert_ne!(baseline, changed.cache_digest().unwrap());
    }
}
