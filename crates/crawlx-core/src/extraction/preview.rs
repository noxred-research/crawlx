//! Head-metadata preview intents.
//!
//! A preview intent is a parser-produced *request for permission*, shaped like
//! [`super::DiscoveryIntentV1`]: the extractor never fetches, a worker may fulfil the
//! intent under its own scope, robots, egress and governor decisions. The check done here is
//! a scope-style guard applied at intent creation (and again when an intent is deserialized):
//! targets that could reach private infrastructure are refused before an intent exists, so a
//! page cannot steer a preview request towards loopback, private, link-local or
//! otherwise non-public destinations.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Smallest head-byte budget an intent may request.
pub const MIN_PREVIEW_HEAD_BYTES: u32 = 1_024;
/// Largest head-byte budget an intent may request.
pub const MAX_PREVIEW_HEAD_BYTES: u32 = 262_144;
/// Head-byte budget of [`PreviewIntentV1::new`].
pub const DEFAULT_PREVIEW_HEAD_BYTES: u32 = 65_536;

/// Why a preview target was refused at intent creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviewRefusalV1 {
    /// Only `http` and `https` targets can be previewed.
    #[error("preview target scheme is not http or https")]
    Scheme,
    /// The target carries userinfo.
    #[error("preview target carries credentials")]
    Credentials,
    /// The target has no host.
    #[error("preview target has no host")]
    MissingHost,
    /// The host is a local or internal name (`localhost`, `*.local`, single label, ...).
    #[error("preview target host is a local or internal name")]
    LocalName,
    /// The host is an IP literal outside the public address space.
    #[error("preview target address is private, loopback, link-local or reserved")]
    PrivateAddress,
    /// The requested head-byte budget is outside the permitted range.
    #[error("preview head budget is outside the permitted range")]
    Budget,
}

/// What the preview should obtain. Fixed vocabulary, never an acquisition authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviewPurposeV1 {
    /// The document head (title, description, canonical, image) of the linked page.
    HeadMetadata,
}

const LOCAL_SUFFIXES: [&str; 8] = [
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".lan",
    ".home.arpa",
    ".intranet",
    ".corp",
];

fn private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || o[0] >= 240
}

fn private_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if let Some(v4) = ip.to_ipv4_mapped() {
        return private_v4(v4);
    }
    // NAT64 well-known prefix embeds an IPv4 address in the low 32 bits.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return private_v4(Ipv4Addr::new(a, b, c, d));
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Scope-style guard for a preview target.
///
/// # Errors
/// A [`PreviewRefusalV1`] naming the first failed rule.
pub fn check_preview_target(url: &Url) -> Result<(), PreviewRefusalV1> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(PreviewRefusalV1::Scheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PreviewRefusalV1::Credentials);
    }
    match url.host() {
        None => Err(PreviewRefusalV1::MissingHost),
        Some(Host::Ipv4(ip)) => {
            if private_v4(ip) {
                Err(PreviewRefusalV1::PrivateAddress)
            } else {
                Ok(())
            }
        }
        Some(Host::Ipv6(ip)) => {
            if private_v6(ip) {
                Err(PreviewRefusalV1::PrivateAddress)
            } else {
                Ok(())
            }
        }
        Some(Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty()
                || !name.contains('.')
                || name == "localhost"
                || LOCAL_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
            {
                Err(PreviewRefusalV1::LocalName)
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewIntentWire {
    url: Url,
    purpose: PreviewPurposeV1,
    max_head_bytes: u32,
}

/// Parser-produced request to preview the head of a linked page, never an authorization.
///
/// Construction applies [`check_preview_target`]; deserialization re-applies it, so a stored
/// or caller-supplied intent cannot name a private target either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, try_from = "PreviewIntentWire")]
#[non_exhaustive]
pub struct PreviewIntentV1 {
    /// Resolved public HTTP(S) target, still subject to worker scope/robots/egress/governor.
    pub url: Url,
    /// Fixed purpose.
    pub purpose: PreviewPurposeV1,
    /// Upper bound of head bytes the worker may read for this intent.
    pub max_head_bytes: u32,
}

impl TryFrom<PreviewIntentWire> for PreviewIntentV1 {
    type Error = PreviewRefusalV1;
    fn try_from(wire: PreviewIntentWire) -> Result<Self, Self::Error> {
        Self::with_budget(wire.url, wire.purpose, wire.max_head_bytes)
    }
}

impl PreviewIntentV1 {
    /// Create an intent with the default head budget. No request is issued.
    ///
    /// # Errors
    /// [`PreviewRefusalV1`] when the target is not a public HTTP(S) destination.
    pub fn new(url: Url, purpose: PreviewPurposeV1) -> Result<Self, PreviewRefusalV1> {
        Self::with_budget(url, purpose, DEFAULT_PREVIEW_HEAD_BYTES)
    }

    /// Create an intent with an explicit head-byte budget.
    ///
    /// # Errors
    /// [`PreviewRefusalV1`] when the target is refused or the budget leaves
    /// `MIN_PREVIEW_HEAD_BYTES..=MAX_PREVIEW_HEAD_BYTES`.
    pub fn with_budget(
        mut url: Url,
        purpose: PreviewPurposeV1,
        max_head_bytes: u32,
    ) -> Result<Self, PreviewRefusalV1> {
        check_preview_target(&url)?;
        if !(MIN_PREVIEW_HEAD_BYTES..=MAX_PREVIEW_HEAD_BYTES).contains(&max_head_bytes) {
            return Err(PreviewRefusalV1::Budget);
        }
        url.set_fragment(None);
        Ok(Self {
            url,
            purpose,
            max_head_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn refused(raw: &str) -> Option<PreviewRefusalV1> {
        PreviewIntentV1::new(Url::parse(raw).unwrap(), PreviewPurposeV1::HeadMetadata).err()
    }

    #[test]
    fn public_targets_pass_and_drop_fragments() {
        let intent = PreviewIntentV1::new(
            Url::parse("https://example.org/a#frag").unwrap(),
            PreviewPurposeV1::HeadMetadata,
        )
        .unwrap();
        assert_eq!(intent.url.as_str(), "https://example.org/a");
        assert_eq!(intent.max_head_bytes, DEFAULT_PREVIEW_HEAD_BYTES);
        assert_eq!(refused("https://8.8.8.8/"), None);
        assert_eq!(refused("https://[2606:4700::1111]/"), None);
    }

    #[test]
    fn private_and_local_targets_are_refused() {
        for raw in [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://LOCALHOST./",
            "http://app.localhost/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/latest",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://2130706433/",
            "http://0x7f.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fd00::1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[64:ff9b::7f00:1]/",
            "http://printer.local/",
            "http://intranet/",
            "http://router.home.arpa/",
        ] {
            assert!(refused(raw).is_some(), "{raw}");
        }
        assert_eq!(
            refused("https://user:pw@example.org/"),
            Some(PreviewRefusalV1::Credentials)
        );
        assert_eq!(refused("ftp://example.org/"), Some(PreviewRefusalV1::Scheme));
    }

    #[test]
    fn budget_is_bounded_and_deserialization_rechecks() {
        let url = Url::parse("https://example.org/").unwrap();
        assert_eq!(
            PreviewIntentV1::with_budget(url.clone(), PreviewPurposeV1::HeadMetadata, 10).unwrap_err(),
            PreviewRefusalV1::Budget
        );
        let ok = serde_json::json!({"url": "https://example.org/", "purpose": "head_metadata", "maxHeadBytes": 4096});
        assert!(serde_json::from_value::<PreviewIntentV1>(ok).is_ok());
        let private =
            serde_json::json!({"url": "http://127.0.0.1/", "purpose": "head_metadata", "maxHeadBytes": 4096});
        assert!(serde_json::from_value::<PreviewIntentV1>(private).is_err());
    }
}
