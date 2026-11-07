//! Test-sink awareness for forms.
//!
//! `SinkKind` deliberately mirrors `crawlx_safety::sinks::SinkKind`
//! (`Email`, `Sms`, `Webhook`, same snake_case serde names). `crawlx-forms`
//! must not depend on `crawlx-safety` (layering), so the worker adapts the
//! safety crate's `TestSinks` to [`TestSinksLike`].

use crate::classify::InputKind;
use crate::group::FormGroup;
use serde::{Deserialize, Serialize};

/// Kind of outbound channel. Mirror of `crawlx_safety::sinks::SinkKind`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// Mailbox sink.
    Email,
    /// Phone-number sink.
    Sms,
    /// Webhook URL sink.
    Webhook,
}

impl SinkKind {
    /// Stable snake_case name, identical to the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Sms => "sms",
            Self::Webhook => "webhook",
        }
    }
}

/// Read access to the tenant's *verified* test sinks. Implemented by the
/// worker over `crawlx_safety::sinks::TestSinks` (which owns verification
/// timestamps); an unverified or absent sink returns `None`.
pub trait TestSinksLike {
    /// Address of the verified sink of `kind`: a mailbox or `@domain` / bare
    /// domain for email, a phone number for SMS, a URL for webhooks.
    fn verified_address(&self, kind: SinkKind) -> Option<&str>;
}

/// Which channel a form submission would use, assuming it communicates
/// externally. Defaults to email.
#[must_use]
pub fn channel_of(group: &FormGroup) -> SinkKind {
    let any_evidence = |needle: &str| {
        group
            .inputs
            .iter()
            .any(|i| i.class.evidence.iter().any(|e| e.starts_with(needle)))
    };
    let has_kind = |k: InputKind| group.inputs.iter().any(|i| i.class.kind == k);
    if any_evidence("kw:webhook@") {
        SinkKind::Webhook
    } else if has_kind(InputKind::Phone) && !has_kind(InputKind::Email) {
        SinkKind::Sms
    } else {
        SinkKind::Email
    }
}

/// The sink kind a form needs before it may be submitted; `None` when the
/// form does not communicate externally.
#[must_use]
pub fn requires_sink(group: &FormGroup) -> Option<SinkKind> {
    group.is_external_communication().then(|| channel_of(group))
}

/// Domain for `email:valid_new_user` values: the domain of the verified email
/// sink. Accepts `user@domain`, `@domain` and bare `domain` forms. `None`
/// without a verified email sink, in which case values use the reserved
/// `.invalid` domain.
#[must_use]
pub fn sink_domain(sinks: &dyn TestSinksLike) -> Option<String> {
    let addr = sinks.verified_address(SinkKind::Email)?.trim();
    let domain = addr
        .rsplit_once('@')
        .map_or(addr, |(_, d)| d)
        .trim()
        .trim_matches('.');
    (!domain.is_empty() && !domain.contains(char::is_whitespace)).then(|| domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::classify::testutil::{desc, input};
    use crate::group::FormGrouper;
    use std::collections::BTreeMap;

    struct Sinks(BTreeMap<&'static str, String>);
    impl TestSinksLike for Sinks {
        fn verified_address(&self, kind: SinkKind) -> Option<&str> {
            self.0.get(kind.as_str()).map(String::as_str)
        }
    }

    fn sinks(email: Option<&str>) -> Sinks {
        let mut m = BTreeMap::new();
        if let Some(e) = email {
            m.insert("email", e.to_owned());
        }
        Sinks(m)
    }

    #[test]
    fn domain_extraction() {
        assert_eq!(
            sink_domain(&sinks(Some("qa@Sink.Example.test"))).as_deref(),
            Some("sink.example.test")
        );
        assert_eq!(
            sink_domain(&sinks(Some("@sink.example.test"))).as_deref(),
            Some("sink.example.test")
        );
        assert_eq!(
            sink_domain(&sinks(Some("sink.example.test"))).as_deref(),
            Some("sink.example.test")
        );
        assert_eq!(sink_domain(&sinks(Some("  "))), None);
        assert_eq!(sink_domain(&sinks(Some("qa@"))), None);
        assert_eq!(sink_domain(&sinks(None)), None);
    }

    fn group_of(fields: Vec<crawlx_core::observation::ObservedDescriptor>, label: &str) -> FormGroup {
        let mut c = vec![desc(100, "form", "form", &[("id", "f"), ("crawlx:form", "f")])];
        for mut d in fields {
            d.attributes.insert("crawlx:form".into(), "f".into());
            c.push(d);
        }
        let mut s = desc(
            200,
            "button",
            "button",
            &[("type", "submit"), ("crawlx:form", "f")],
        );
        s.accessible_name = Some(label.to_owned());
        c.push(s);
        FormGrouper::new().group(&c).remove(0)
    }

    #[test]
    fn requires_sink_follows_semantics() {
        let contact = group_of(
            vec![
                input(1, &[("type", "email")]),
                desc(2, "textarea", "textbox", &[("name", "message")]),
            ],
            "Send",
        );
        assert_eq!(requires_sink(&contact), Some(SinkKind::Email));
        let search = group_of(vec![input(1, &[("type", "search")])], "Go");
        assert_eq!(requires_sink(&search), None);
        let sms = group_of(vec![input(1, &[("type", "tel")])], "Send invite");
        assert_eq!(requires_sink(&sms), Some(SinkKind::Sms));
        let hook = group_of(vec![input(1, &[("name", "webhook")])], "Invite");
        assert_eq!(requires_sink(&hook), Some(SinkKind::Webhook));
        let signup = group_of(
            vec![
                input(1, &[("type", "email")]),
                input(2, &[("type", "password"), ("autocomplete", "new-password")]),
            ],
            "Join",
        );
        assert_eq!(requires_sink(&signup), Some(SinkKind::Email));
    }

    #[test]
    fn sink_kind_serde_matches_safety_mirror() {
        assert_eq!(serde_json::to_string(&SinkKind::Sms).unwrap(), "\"sms\"");
        assert_eq!(serde_json::to_string(&SinkKind::Webhook).unwrap(), "\"webhook\"");
        assert_eq!(serde_json::to_string(&SinkKind::Email).unwrap(), "\"email\"");
    }
}
