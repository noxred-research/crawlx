//! Pool selection: the typed form of the ProxyX gateway's username grammar.
//!
//! The gateway reads the proxy username as `px` followed by `-key-value` pairs:
//!
//! | key    | value                                             |
//! |--------|---------------------------------------------------|
//! | `kind` | `static` or `rotating`                            |
//! | `cc`   | two-letter country                                |
//! | `city` | `[a-z0-9_]{1,48}`, needs `cc`                     |
//! | `prov` | provider id, `[a-z0-9_]+`                         |
//! | `ttl`  | `30s`, `10m`, `2h`, `1d` or plain seconds         |
//! | `rot`  | `sticky` or `each`; `each` cannot carry a `sid`   |
//! | `sid`  | sticky key, `[a-z0-9_]+`                          |
//!
//! Values never contain `-`, no key repeats and the whole username is at most 128 bytes. The
//! gateway refuses anything else with a terminal `403 option_denied` and never repairs it, so
//! this module validates locally and a bad selector fails before any connection is made.

use super::{PoolTier, ProxyxError};
use crawlx_core::session_binding::SessionBindingV1;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Fixed username prefix.
pub const USERNAME_PREFIX: &str = "px";
/// Longest username the gateway accepts, in bytes.
pub const MAX_USERNAME_LEN: usize = 128;
/// Longest city slug.
const MAX_CITY_LEN: usize = 48;
/// Prefix of every derived sticky id.
const SID_PREFIX: &str = "cx";
/// Shortest hash a derived sticky id may fall back to (a 32-bit collision space is too small).
const MIN_SID_HASH_HEX: usize = 32;

/// Pool class.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PoolKind {
    /// Static (ISP or datacenter) addresses.
    Static,
    /// Rotating (residential or mobile) sessions.
    Rotating,
}

impl PoolKind {
    const fn wire(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Rotating => "rotating",
        }
    }
}

/// How exit identities follow connections.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PoolRotation {
    /// One identity for the crawl: every tunnel of the crawl carries the same `sid`.
    Sticky,
    /// A fresh identity per tunnel (`rot-each`, no `sid`). Connection reuse is disabled so each
    /// request opens its own tunnel.
    Each,
}

impl PoolRotation {
    const fn wire(self) -> &'static str {
        match self {
            Self::Sticky => "sticky",
            Self::Each => "each",
        }
    }
}

/// A lease idle time, at least one second.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PoolTtl(u64);

impl PoolTtl {
    /// A TTL of `secs` seconds.
    ///
    /// # Errors
    /// [`ProxyxError::Selector`] for zero.
    pub fn from_secs(secs: u64) -> Result<Self, ProxyxError> {
        if secs == 0 {
            return Err(ProxyxError::selector("ttl", "must be at least one second"));
        }
        Ok(Self(secs))
    }

    /// Parse `30`, `30s`, `10m`, `2h` or `1d`.
    ///
    /// # Errors
    /// [`ProxyxError::Selector`] for another shape, zero or an overflow.
    pub fn parse(text: &str) -> Result<Self, ProxyxError> {
        let bad = || ProxyxError::selector("ttl", "expected seconds, or a number with s, m, h or d");
        let text = text.trim();
        let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
        let (digits, unit) = text.split_at(split);
        let value: u64 = digits.parse().map_err(|_| bad())?;
        let factor = match unit {
            "" | "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            _ => return Err(bad()),
        };
        Self::from_secs(value.checked_mul(factor).ok_or_else(bad)?)
    }

    /// The TTL in seconds.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0
    }

    /// The gateway's spelling: the largest unit that divides the value exactly.
    #[must_use]
    pub fn wire(self) -> String {
        for (factor, unit) in [(86_400, 'd'), (3_600, 'h'), (60, 'm')] {
            if self.0.is_multiple_of(factor) {
                return format!("{}{unit}", self.0 / factor);
            }
        }
        format!("{}s", self.0)
    }
}

impl Serialize for PoolTtl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.wire())
    }
}

impl<'de> Deserialize<'de> for PoolTtl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Secs(u64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Secs(secs) => Self::from_secs(secs),
            Raw::Text(text) => Self::parse(&text),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// What the operator asks of the pool for one tier. Every field is optional: an empty selector
/// takes the org's policy as is.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PoolSelector {
    /// Pool class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<PoolKind>,
    /// Two-letter country.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// City slug; needs `country`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Provider id, for example `oxylabs_res`. Ids containing `-` cannot be selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Lease idle time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<PoolTtl>,
    /// Rotation; `None` is sticky. Session-bound routes refuse per-connection rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<PoolRotation>,
}

fn slug(field: &'static str, value: &str, max: usize) -> Result<String, ProxyxError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(ProxyxError::selector(
            field,
            "must be 1-48 characters of a-z, 0-9 and _ (no `-`)",
        ));
    }
    Ok(value)
}

impl PoolSelector {
    /// Parse the compact form used by flags and environment variables:
    /// `kind=rotating,cc=fr,city=paris,prov=oxylabs_res,ttl=10m,rot=sticky`. Keys are the
    /// gateway's (`cc`) or the config names (`country`). The empty string is the empty selector.
    ///
    /// # Errors
    /// [`ProxyxError::Selector`] for an unknown or repeated key, a missing `=` or a bad value.
    pub fn from_spec(spec: &str) -> Result<Self, ProxyxError> {
        let mut out = Self::default();
        let mut seen: Vec<&str> = Vec::new();
        for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| ProxyxError::selector("spec", "expected key=value pairs"))?;
            let (key, value) = (key.trim(), value.trim());
            let canonical = match key {
                "kind" => "kind",
                "cc" | "country" => "country",
                "city" => "city",
                "prov" | "provider" => "provider",
                "ttl" => "ttl",
                "rot" | "rotation" => "rotation",
                _ => return Err(ProxyxError::selector("spec", "unknown key")),
            };
            if seen.contains(&canonical) {
                return Err(ProxyxError::selector("spec", "a key repeats"));
            }
            seen.push(canonical);
            match canonical {
                "kind" => {
                    out.kind = Some(match value {
                        "static" => PoolKind::Static,
                        "rotating" => PoolKind::Rotating,
                        _ => return Err(ProxyxError::selector("kind", "expected static or rotating")),
                    });
                }
                "country" => out.country = Some(value.to_owned()),
                "city" => out.city = Some(value.to_owned()),
                "provider" => out.provider = Some(value.to_owned()),
                "ttl" => out.ttl = Some(PoolTtl::parse(value)?),
                _ => {
                    out.rotation = Some(match value {
                        "sticky" => PoolRotation::Sticky,
                        "each" => PoolRotation::Each,
                        _ => return Err(ProxyxError::selector("rotation", "expected sticky or each")),
                    });
                }
            }
        }
        out.validate()?;
        Ok(out)
    }

    /// Check every field against the gateway's grammar.
    ///
    /// # Errors
    /// [`ProxyxError::Selector`] naming the field.
    pub fn validate(&self) -> Result<(), ProxyxError> {
        self.parts().map(|_| ())
    }

    /// Does every tunnel of a crawl get its own identity?
    #[must_use]
    pub fn rotates_each(&self) -> bool {
        self.rotation == Some(PoolRotation::Each)
    }

    /// The `(key, value)` pairs in the gateway's order, normalized.
    fn parts(&self) -> Result<Vec<(&'static str, String)>, ProxyxError> {
        let mut parts = Vec::with_capacity(6);
        if let Some(kind) = self.kind {
            parts.push(("kind", kind.wire().to_owned()));
        }
        match (&self.country, &self.city) {
            (Some(country), city) => {
                let country = country.trim().to_ascii_lowercase();
                if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_lowercase()) {
                    return Err(ProxyxError::selector("country", "must be two ASCII letters"));
                }
                parts.push(("cc", country));
                if let Some(city) = city {
                    parts.push(("city", slug("city", city, MAX_CITY_LEN)?));
                }
            }
            (None, Some(_)) => return Err(ProxyxError::selector("city", "needs a country")),
            (None, None) => {}
        }
        if let Some(provider) = &self.provider {
            parts.push(("prov", slug("provider", provider, MAX_USERNAME_LEN)?));
        }
        if let Some(ttl) = self.ttl {
            parts.push(("ttl", ttl.wire()));
        }
        if let Some(rotation) = self.rotation {
            parts.push(("rot", rotation.wire().to_owned()));
        }
        Ok(parts)
    }

    /// The username for one connection identity. `sid` is the sticky key (`[a-z0-9_]+`); it is
    /// refused together with `rotation = each`.
    ///
    /// # Errors
    /// [`ProxyxError::Selector`] for an invalid field or sid, [`ProxyxError::UsernameTooLong`]
    /// when the result exceeds [`MAX_USERNAME_LEN`].
    pub fn username(&self, sid: Option<&str>) -> Result<String, ProxyxError> {
        let mut parts = self.parts()?;
        if let Some(sid) = sid {
            if self.rotates_each() {
                return Err(ProxyxError::selector(
                    "sid",
                    "cannot be combined with rotation = each",
                ));
            }
            parts.push(("sid", slug("sid", sid, MAX_USERNAME_LEN)?));
        }
        let mut username = String::from(USERNAME_PREFIX);
        for (key, value) in parts {
            username.push('-');
            username.push_str(key);
            username.push('-');
            username.push_str(&value);
        }
        if username.len() > MAX_USERNAME_LEN {
            return Err(ProxyxError::UsernameTooLong { len: username.len() });
        }
        Ok(username)
    }

    /// Derive a sticky id from the complete immutable identity and explicit generation.
    ///
    /// Tenant, run, principal, session slot, profile and acquisition settings remain distinct.
    /// Lease renewal does not change the id. Only explicit generation replacement may change
    /// identity. The digest never exposes role names or profile references in proxy credentials.
    ///
    /// # Errors
    /// Returns a selector error for per-connection rotation or a missing generation, or
    /// [`ProxyxError::UsernameTooLong`] when fewer than 128 digest bits fit.
    pub fn sticky_id(&self, tier: PoolTier, session: &SessionBindingV1) -> Result<String, ProxyxError> {
        if self.rotates_each() {
            return Err(ProxyxError::selector(
                "rotation",
                "a session generation requires sticky rotation",
            ));
        }
        if session.generation == 0 {
            return Err(ProxyxError::SessionUnavailable);
        }
        let identity = &session.identity;
        let mut hash = blake3::Hasher::new_derive_key("crawlx/proxy-session-generation/v1");
        hash.update(identity.tenant.0.as_bytes());
        hash.update(identity.run.0.as_bytes());
        hash.update(identity.session.0.as_bytes());
        hash.update(&session.generation.to_be_bytes());
        hash.update(&identity.acquisition.0);
        hash.update(&identity.backend_build.0);
        hash.update(&identity.egress.0);
        hash.update(&identity.identity_policy.0);
        hash.update(&[u8::from(identity.profile.is_some())]);
        if let Some(profile) = identity.profile {
            hash.update(&profile.0);
        }
        // The only variable-width field comes last, after all fixed-width fields.
        hash.update(identity.principal.0.as_bytes());
        self.digest_sid(tier, hash.finalize())
    }

    pub(super) fn run_sticky_id(
        &self,
        tier: PoolTier,
        run: crawlx_core::CrawlRunId,
    ) -> Result<Option<String>, ProxyxError> {
        if self.rotates_each() {
            return Ok(None);
        }
        self.digest_sid(tier, blake3::hash(run.0.as_bytes())).map(Some)
    }

    fn digest_sid(&self, tier: PoolTier, digest: blake3::Hash) -> Result<String, ProxyxError> {
        let base = self.username(None)?;
        let head = format!("{SID_PREFIX}_{}_", tier.tag());
        let budget = MAX_USERNAME_LEN.saturating_sub(base.len() + "-sid-".len() + head.len());
        if budget < MIN_SID_HASH_HEX {
            return Err(ProxyxError::UsernameTooLong {
                len: base.len() + "-sid-".len() + head.len() + MIN_SID_HASH_HEX,
            });
        }
        let digest = digest.to_hex();
        Ok(format!("{head}{}", &digest.as_str()[..budget.min(digest.len())]))
    }
}

impl fmt::Display for PoolSelector {
    /// The compact spec form (`kind=rotating,cc=fr`), without any credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut put = |f: &mut fmt::Formatter<'_>, key: &str, value: &str| {
            let sep = if first { "" } else { "," };
            first = false;
            write!(f, "{sep}{key}={value}")
        };
        if let Some(kind) = self.kind {
            put(f, "kind", kind.wire())?;
        }
        if let Some(country) = &self.country {
            put(f, "cc", country)?;
        }
        if let Some(city) = &self.city {
            put(f, "city", city)?;
        }
        if let Some(provider) = &self.provider {
            put(f, "prov", provider)?;
        }
        if let Some(ttl) = self.ttl {
            put(f, "ttl", &ttl.wire())?;
        }
        if let Some(rotation) = self.rotation {
            put(f, "rot", rotation.wire())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn sel(spec: &str) -> PoolSelector {
        PoolSelector::from_spec(spec).unwrap()
    }

    #[test]
    fn empty_selector_is_the_bare_prefix() {
        assert_eq!(PoolSelector::default().username(None).unwrap(), "px");
        assert_eq!(sel("").username(Some("job42")).unwrap(), "px-sid-job42");
    }

    #[test]
    fn username_follows_the_gateway_grammar_and_order() {
        let s = sel("kind=rotating,cc=FR,ttl=30m");
        assert_eq!(
            s.username(Some("crawl42")).unwrap(),
            "px-kind-rotating-cc-fr-ttl-30m-sid-crawl42"
        );
        let s = sel("cc=us,city=New_York,rot=each");
        assert_eq!(s.username(None).unwrap(), "px-cc-us-city-new_york-rot-each");
        let s = sel("kind=static,prov=oxylabs_isp");
        assert_eq!(s.username(None).unwrap(), "px-kind-static-prov-oxylabs_isp");
    }

    #[test]
    fn spec_and_config_names_agree_and_display_round_trips() {
        let a = sel("kind=rotating,cc=fr,city=paris,prov=oxylabs_res,ttl=10m,rot=sticky");
        let b = sel("rotation=sticky,provider=oxylabs_res,country=fr,city=paris,kind=rotating,ttl=600");
        assert_eq!(a, b);
        assert_eq!(
            a.to_string(),
            "kind=rotating,cc=fr,city=paris,prov=oxylabs_res,ttl=10m,rot=sticky"
        );
        assert_eq!(PoolSelector::from_spec(&a.to_string()).unwrap(), a);
    }

    #[test]
    fn invalid_selectors_are_refused_locally() {
        for spec in [
            "cc=fra",
            "cc=f1",
            "cc=",
            "city=paris",
            "cc=fr,city=new-york",
            "cc=fr,city=",
            "kind=residential",
            "prov=oxy-labs",
            "prov=Oxy Labs",
            "ttl=0",
            "ttl=5w",
            "ttl=abc",
            "ttl=-5",
            "rot=sometimes",
            "kind=static,kind=rotating",
            "cc=fr,country=de",
            "color=red",
            "kind",
        ] {
            assert!(PoolSelector::from_spec(spec).is_err(), "{spec}");
        }
        let long_city = format!("cc=fr,city={}", "a".repeat(49));
        assert!(PoolSelector::from_spec(&long_city).is_err());
        assert!(PoolSelector::from_spec(&format!("cc=fr,city={}", "a".repeat(48))).is_ok());
    }

    #[test]
    fn sid_is_refused_with_rot_each_and_validated() {
        let each = sel("rot=each");
        assert!(each.username(Some("x")).is_err());
        let sticky = sel("");
        for bad in ["", "a-b", "A b", "a.b", "é"] {
            assert!(sticky.username(Some(bad)).is_err(), "{bad:?}");
        }
        // uppercase is folded, as the gateway's grammar is lowercase only
        assert_eq!(sticky.username(Some("Abc_1")).unwrap(), "px-sid-abc_1");
    }

    #[test]
    fn username_budget_is_128_bytes() {
        let s = sel("");
        let fits = "a".repeat(MAX_USERNAME_LEN - "px-sid-".len());
        assert_eq!(s.username(Some(&fits)).unwrap().len(), MAX_USERNAME_LEN);
        let over = "a".repeat(MAX_USERNAME_LEN - "px-sid-".len() + 1);
        assert!(matches!(
            s.username(Some(&over)),
            Err(ProxyxError::UsernameTooLong { len: 129 })
        ));
    }

    #[test]
    fn sticky_id_preserves_full_generation_identity_without_lossy_sanitizing() {
        let s = sel("kind=rotating,cc=fr");
        let route = super::super::tests::route("http://pool.internal", "").unwrap();
        let session = super::super::tests::session(&route, PoolTier::Basic);
        let basic = s.sticky_id(PoolTier::Basic, &session).unwrap();
        assert_eq!(basic, s.sticky_id(PoolTier::Basic, &session).unwrap());
        let mut renewed = session.clone();
        renewed.lease_fence += 1;
        renewed.state_version += 1;
        assert_eq!(basic, s.sticky_id(PoolTier::Basic, &renewed).unwrap());
        for changed in [
            {
                let mut changed = session.clone();
                changed.generation += 1;
                changed
            },
            {
                let mut changed = session.clone();
                changed.identity.principal.0 = "role/a".into();
                changed
            },
            {
                let mut changed = session.clone();
                changed.identity.profile = Some(crawlx_core::hash::Digest::of("test", b"profile"));
                changed
            },
            {
                let mut changed = session.clone();
                changed.identity.tenant = "00000000-0000-0000-0000-000000000009".parse().unwrap();
                changed
            },
        ] {
            assert_ne!(basic, s.sticky_id(PoolTier::Basic, &changed).unwrap());
        }
        assert_ne!(basic, s.sticky_id(PoolTier::Enhanced, &session).unwrap());
        assert!(s.username(Some(&basic)).unwrap().len() <= MAX_USERNAME_LEN);
        assert!(sel("rot=each").sticky_id(PoolTier::Basic, &session).is_err());
        let tight = PoolSelector {
            provider: Some("p".repeat(95)),
            ..PoolSelector::default()
        };
        assert!(matches!(
            tight.sticky_id(PoolTier::Basic, &session),
            Err(ProxyxError::UsernameTooLong { .. })
        ));
    }

    #[test]
    fn config_deserialization_accepts_names_and_rejects_unknown_fields() {
        let s: PoolSelector =
            toml::from_str("kind = 'rotating'\ncountry = 'fr'\nttl = '10m'\nrotation = 'sticky'").unwrap();
        assert_eq!(s.ttl.unwrap().secs(), 600);
        let s: PoolSelector = toml::from_str("ttl = 45").unwrap();
        assert_eq!(s.ttl.unwrap().wire(), "45s");
        assert!(toml::from_str::<PoolSelector>("speed = 'fast'").is_err());
        assert!(toml::from_str::<PoolSelector>("ttl = 0").is_err());
        assert!(toml::from_str::<PoolSelector>("kind = 'both'").is_err());
    }

    #[test]
    fn ttl_spelling_uses_the_largest_exact_unit() {
        for (secs, wire) in [
            (30, "30s"),
            (60, "1m"),
            (600, "10m"),
            (7_200, "2h"),
            (86_400, "1d"),
            (90, "90s"),
        ] {
            assert_eq!(PoolTtl::from_secs(secs).unwrap().wire(), wire);
            assert_eq!(PoolTtl::parse(wire).unwrap().secs(), secs);
        }
        assert!(PoolTtl::parse("99999999999999999999d").is_err());
        assert!(PoolTtl::parse("").is_err());
    }
}
