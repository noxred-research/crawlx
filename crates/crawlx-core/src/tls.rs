//! Opt-in synthetic ClientHello randomization for the URL fetch engine.
//!
//! This mode selects a seeded transport profile, not a browser fingerprint or the
//! exact uTLS randomized distribution. Certificate verification is a separate setting.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// TLS ClientHello policy for the URL fetch engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum TlsImpersonation {
    /// Keep the stock reqwest/rustls transport.
    #[default]
    Off,
    /// Select a deterministic synthetic randomized profile from the crawl seed.
    Randomized,
}

impl fmt::Display for TlsImpersonation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Randomized => "randomized",
        })
    }
}

/// A TLS mode other than `off` or `randomized` was supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid TLS impersonation mode (expected off or randomized)")]
#[non_exhaustive]
pub struct ParseTlsImpersonationError;

impl FromStr for TlsImpersonation {
    type Err = ParseTlsImpersonationError;

    /// Parse the exact wire spelling of a TLS mode.
    ///
    /// # Errors
    /// Returns [`ParseTlsImpersonationError`] for every other value.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "randomized" => Ok(Self::Randomized),
            _ => Err(ParseTlsImpersonationError),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn mode_defaults_off_and_round_trips_exact_spellings() {
        assert_eq!(TlsImpersonation::default(), TlsImpersonation::Off);
        for (value, mode) in [
            ("off", TlsImpersonation::Off),
            ("randomized", TlsImpersonation::Randomized),
        ] {
            assert_eq!(value.parse::<TlsImpersonation>().unwrap(), mode);
            assert_eq!(mode.to_string(), value);
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, format!("\"{value}\""));
            assert_eq!(serde_json::from_str::<TlsImpersonation>(&json).unwrap(), mode);
        }
    }

    #[test]
    fn unknown_modes_fail_in_parser_and_serde() {
        for value in ["", "chrome", "Randomized", "random", " randomized"] {
            assert!(value.parse::<TlsImpersonation>().is_err());
            assert!(serde_json::from_value::<TlsImpersonation>(serde_json::json!(value)).is_err());
        }
    }
}
