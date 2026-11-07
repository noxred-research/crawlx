//! Test-sink requirements for `external_communication` (see
//! `docs/design/safety-model.md`).
//!
//! Outbound email, SMS and webhooks are only ever allowed towards tenant-
//! configured test sinks that have been verified. Without a verified sink of
//! the required kind the class denies regardless of profile.

use crawlx_core::safety::RiskClass;
use crawlx_core::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Kind of outbound channel.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// Outbound email.
    Email,
    /// Outbound SMS.
    Sms,
    /// Outbound webhook call.
    Webhook,
}

impl SinkKind {
    /// Stable snake_case name, matching the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
            Self::Webhook => "webhook",
        }
    }
}

/// One configured sink (a mailbox, a phone number, a webhook URL).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkSpec {
    /// Mailbox, phone number or webhook URL.
    pub address: String,
    /// When the sink was verified to be a tenant-owned test endpoint.
    pub verified_at: Option<Timestamp>,
    /// End of the verification's validity window (exclusive).
    pub expires_at: Timestamp,
}

/// `address` can be a webhook URL carrying a token or a personal phone number,
/// so `Debug` (tracing, `unwrap` panics, test diffs) never prints it.
impl std::fmt::Debug for SinkSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkSpec")
            .field("address", &"<redacted>")
            .field("verified_at", &self.verified_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SinkSpec {
    /// Verified at or before `now`, and not expired.
    #[must_use]
    pub fn is_verified(&self, now: Timestamp) -> bool {
        self.verified_at.is_some_and(|t| t <= now) && now < self.expires_at
    }
}

/// The tenant's test sinks.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct TestSinks {
    /// Email sink.
    pub email: Option<SinkSpec>,
    /// SMS sink.
    pub sms: Option<SinkSpec>,
    /// Webhook sink.
    pub webhook: Option<SinkSpec>,
}

impl TestSinks {
    /// The configured sink of `kind`, verified or not.
    #[must_use]
    pub const fn spec(&self, kind: SinkKind) -> Option<&SinkSpec> {
        match kind {
            SinkKind::Email => self.email.as_ref(),
            SinkKind::Sms => self.sms.as_ref(),
            SinkKind::Webhook => self.webhook.as_ref(),
        }
    }

    /// Is there a verified sink of `kind` at `now`?
    #[must_use]
    pub fn is_verified(&self, kind: SinkKind, now: Timestamp) -> bool {
        self.spec(kind).is_some_and(|s| s.is_verified(now))
    }

    /// Whether the observed destination is exactly the approved endpoint of `kind`.
    /// Unknown destinations fail closed; HTTP endpoints include their path and query.
    #[must_use]
    pub fn permits(&self, kind: SinkKind, destination: Option<&str>, base: &str, now: Timestamp) -> bool {
        let Some(spec) = self.spec(kind).filter(|spec| spec.is_verified(now)) else {
            return false;
        };
        let Some(destination) = destination else {
            return false;
        };
        let approved = spec.address.as_str();
        if approved.trim().is_empty() {
            return false;
        }
        let actual = url::Url::parse(destination)
            .or_else(|_| url::Url::parse(base).and_then(|base| base.join(destination)));
        if let (Ok(actual), Ok(expected)) = (actual, url::Url::parse(approved)) {
            return match (kind, expected.scheme()) {
                (_, "http" | "https") | (SinkKind::Email, "mailto") | (SinkKind::Sms, "sms") => {
                    actual == expected
                }
                _ => false,
            };
        }
        match kind {
            SinkKind::Email => destination.strip_prefix("mailto:") == Some(approved),
            SinkKind::Sms => destination.strip_prefix("sms:") == Some(approved),
            SinkKind::Webhook => false,
        }
    }

    /// Is any sink verified at `now`?
    #[must_use]
    pub fn any_verified(&self, now: Timestamp) -> bool {
        [SinkKind::Email, SinkKind::Sms, SinkKind::Webhook]
            .into_iter()
            .any(|k| self.is_verified(k, now))
    }
}

/// Which sink an action of class `risk` needs. `None` when the class does not
/// communicate externally. The kind comes from the `crawlx-forms` hint
/// (`external_communication`, optionally suffixed `:sms` / `:webhook`);
/// unspecific hints default to email.
#[must_use]
pub fn requires_sink(risk: RiskClass, form_hint: Option<&str>) -> Option<SinkKind> {
    if risk != RiskClass::ExternalCommunication {
        return None;
    }
    let hint = form_hint.map(str::to_ascii_lowercase).unwrap_or_default();
    if hint.contains("sms") {
        Some(SinkKind::Sms)
    } else if hint.contains("webhook") {
        Some(SinkKind::Webhook)
    } else {
        Some(SinkKind::Email)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::TimeZone as _;

    fn t(h: u32) -> Timestamp {
        chrono::Utc.with_ymd_and_hms(2026, 1, 1, h, 0, 0).unwrap()
    }

    #[test]
    fn only_external_communication_needs_a_sink() {
        for c in [
            RiskClass::NavigationReveal,
            RiskClass::PersistentWriteOwn,
            RiskClass::Destructive,
            RiskClass::FinancialTransaction,
            RiskClass::Unclassified,
        ] {
            assert_eq!(requires_sink(c, Some("external_communication")), None, "{c:?}");
        }
        assert_eq!(
            requires_sink(RiskClass::ExternalCommunication, None),
            Some(SinkKind::Email)
        );
        assert_eq!(
            requires_sink(RiskClass::ExternalCommunication, Some("external_communication")),
            Some(SinkKind::Email)
        );
        assert_eq!(
            requires_sink(
                RiskClass::ExternalCommunication,
                Some("external_communication:SMS")
            ),
            Some(SinkKind::Sms)
        );
        assert_eq!(
            requires_sink(
                RiskClass::ExternalCommunication,
                Some("external_communication:webhook")
            ),
            Some(SinkKind::Webhook)
        );
    }

    #[test]
    fn unverified_or_future_verification_does_not_count() {
        let mut s = TestSinks {
            email: Some(SinkSpec {
                address: "qa@sink.test".into(),
                verified_at: None,
                expires_at: t(23),
            }),
            ..TestSinks::default()
        };
        assert!(!s.is_verified(SinkKind::Email, t(12)));
        assert!(!s.any_verified(t(12)));
        s.email = Some(SinkSpec {
            address: "qa@sink.test".into(),
            verified_at: Some(t(13)),
            expires_at: t(23),
        });
        assert!(!s.is_verified(SinkKind::Email, t(12)));
        assert!(s.is_verified(SinkKind::Email, t(13)));
        assert!(!s.is_verified(SinkKind::Sms, t(13)));
        assert!(s.any_verified(t(14)));
        assert!(!s.any_verified(t(23)));
        assert!(s.permits(SinkKind::Email, Some("mailto:qa@sink.test"), "", t(14)));
        assert!(!s.permits(SinkKind::Email, Some("mailto:other@sink.test"), "", t(14)));
        s.webhook = Some(SinkSpec {
            address: "mailto:qa@sink.test".into(),
            verified_at: Some(t(13)),
            expires_at: t(23),
        });
        assert!(!s.permits(SinkKind::Webhook, Some("mailto:qa@sink.test"), "", t(14)));
        s.webhook.as_mut().unwrap().address = "https://sink.test/hook?token=approved".into();
        assert!(s.permits(
            SinkKind::Webhook,
            Some("https://sink.test/hook?token=approved"),
            "",
            t(14)
        ));
        assert!(!s.permits(
            SinkKind::Webhook,
            Some("https://sink.test/hook?token=other"),
            "",
            t(14)
        ));
    }

    #[test]
    fn sink_kind_names_are_the_snake_case_variants() {
        assert_eq!(SinkKind::Email.as_str(), "email");
        assert_eq!(SinkKind::Sms.as_str(), "sms");
        assert_eq!(SinkKind::Webhook.as_str(), "webhook");
        for kind in [SinkKind::Email, SinkKind::Sms, SinkKind::Webhook] {
            // the form hint (`external_communication:<kind>`) round-trips through the name
            assert_eq!(
                requires_sink(
                    RiskClass::ExternalCommunication,
                    Some(&format!("external_communication:{}", kind.as_str()))
                ),
                Some(kind)
            );
        }
    }
}
