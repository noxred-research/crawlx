//! Value partitions and the validators generated
//! values must satisfy.
//!
//! ```text
//! email:     valid_new_user | existing_user | malformed | long_boundary
//! phone:     valid_e164 | malformed
//! date:      today | future | past | month_boundary
//! text:      short_valid | long_boundary | unicode | empty
//! number:    min | max | typical | out_of_range
//! resource:  own | other_user_same_role | higher_role_owned | shared
//! file:      fixture_small_png | fixture_pdf | oversized
//! ```
//!
//! Two additive partitions cover kinds the base table leaves open:
//! `url:valid_https` and `password:generated`.
//!
//! "Valid" partitions satisfy [`validate`]; the boundary/malformed ones
//! satisfy it only where their name says so (see [`Partition::is_valid_value`]).

use crate::classify::InputKind;
use crawlx_core::config::SafetyProfile;
use crawlx_core::identity::InputClass;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Partition families (`email`, `phone`, ...).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PartitionFamily {
    /// E-mail addresses.
    Email,
    /// Phone numbers.
    Phone,
    /// Dates and times.
    Date,
    /// Free-form text.
    Text,
    /// Numbers.
    Number,
    /// References to resources owned by principals.
    Resource,
    /// File uploads.
    File,
    /// URLs.
    Url,
    /// Passwords.
    Password,
}

impl PartitionFamily {
    /// Family name as used in the `family:name` partition string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Date => "date",
            Self::Text => "text",
            Self::Number => "number",
            Self::Resource => "resource",
            Self::File => "file",
            Self::Url => "url",
            Self::Password => "password",
        }
    }
}

/// Which partitions run (the "default" / "expanded" sets).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum PartitionSet {
    /// Only the valid baseline partition of each family.
    #[default]
    Default,
    /// Every partition of the family (subject to the safety profile).
    Expanded,
}

/// A named value partition.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Partition {
    /// A well-formed, unique address (sink domain when one is verified).
    EmailValidNewUser,
    /// An address that already belongs to an existing user.
    EmailExistingUser,
    /// A syntactically invalid address.
    EmailMalformed,
    /// A valid address at the maximum length boundary.
    EmailLongBoundary,
    /// A valid E.164 phone number.
    PhoneValidE164,
    /// A syntactically invalid phone number.
    PhoneMalformed,
    /// The current date.
    DateToday,
    /// A date after the current date.
    DateFuture,
    /// A date before the current date.
    DatePast,
    /// A month-end boundary date.
    DateMonthBoundary,
    /// Short valid text.
    TextShortValid,
    /// Text at the maximum length boundary.
    TextLongBoundary,
    /// Non-ASCII text.
    TextUnicode,
    /// The empty string.
    TextEmpty,
    /// The minimum accepted number.
    NumberMin,
    /// The maximum accepted number.
    NumberMax,
    /// A typical in-range number.
    NumberTypical,
    /// A number outside the accepted range.
    NumberOutOfRange,
    /// A resource owned by the acting principal.
    ResourceOwn,
    /// A resource of another user with the same role.
    ResourceOtherUserSameRole,
    /// A resource owned by a higher-role user.
    ResourceHigherRoleOwned,
    /// A shared resource.
    ResourceShared,
    /// The small PNG fixture.
    FileFixtureSmallPng,
    /// The PDF fixture.
    FileFixturePdf,
    /// The oversized file fixture.
    FileOversized,
    /// Additive: `url:valid_https`.
    UrlValidHttps,
    /// Additive: `password:generated`.
    PasswordGenerated,
}

/// Every partition in declaration order.
pub const ALL_PARTITIONS: &[Partition] = &[
    Partition::EmailValidNewUser,
    Partition::EmailExistingUser,
    Partition::EmailMalformed,
    Partition::EmailLongBoundary,
    Partition::PhoneValidE164,
    Partition::PhoneMalformed,
    Partition::DateToday,
    Partition::DateFuture,
    Partition::DatePast,
    Partition::DateMonthBoundary,
    Partition::TextShortValid,
    Partition::TextLongBoundary,
    Partition::TextUnicode,
    Partition::TextEmpty,
    Partition::NumberMin,
    Partition::NumberMax,
    Partition::NumberTypical,
    Partition::NumberOutOfRange,
    Partition::ResourceOwn,
    Partition::ResourceOtherUserSameRole,
    Partition::ResourceHigherRoleOwned,
    Partition::ResourceShared,
    Partition::FileFixtureSmallPng,
    Partition::FileFixturePdf,
    Partition::FileOversized,
    Partition::UrlValidHttps,
    Partition::PasswordGenerated,
];

impl Partition {
    /// The family this partition belongs to.
    #[must_use]
    pub const fn family(self) -> PartitionFamily {
        match self {
            Self::EmailValidNewUser
            | Self::EmailExistingUser
            | Self::EmailMalformed
            | Self::EmailLongBoundary => PartitionFamily::Email,
            Self::PhoneValidE164 | Self::PhoneMalformed => PartitionFamily::Phone,
            Self::DateToday | Self::DateFuture | Self::DatePast | Self::DateMonthBoundary => {
                PartitionFamily::Date
            }
            Self::TextShortValid | Self::TextLongBoundary | Self::TextUnicode | Self::TextEmpty => {
                PartitionFamily::Text
            }
            Self::NumberMin | Self::NumberMax | Self::NumberTypical | Self::NumberOutOfRange => {
                PartitionFamily::Number
            }
            Self::ResourceOwn
            | Self::ResourceOtherUserSameRole
            | Self::ResourceHigherRoleOwned
            | Self::ResourceShared => PartitionFamily::Resource,
            Self::FileFixtureSmallPng | Self::FileFixturePdf | Self::FileOversized => PartitionFamily::File,
            Self::UrlValidHttps => PartitionFamily::Url,
            Self::PasswordGenerated => PartitionFamily::Password,
        }
    }

    /// The partition name inside its family (`valid_new_user`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EmailValidNewUser => "valid_new_user",
            Self::EmailExistingUser => "existing_user",
            Self::EmailMalformed | Self::PhoneMalformed => "malformed",
            Self::EmailLongBoundary | Self::TextLongBoundary => "long_boundary",
            Self::PhoneValidE164 => "valid_e164",
            Self::DateToday => "today",
            Self::DateFuture => "future",
            Self::DatePast => "past",
            Self::DateMonthBoundary => "month_boundary",
            Self::TextShortValid => "short_valid",
            Self::TextUnicode => "unicode",
            Self::TextEmpty => "empty",
            Self::NumberMin => "min",
            Self::NumberMax => "max",
            Self::NumberTypical => "typical",
            Self::NumberOutOfRange => "out_of_range",
            Self::ResourceOwn => "own",
            Self::ResourceOtherUserSameRole => "other_user_same_role",
            Self::ResourceHigherRoleOwned => "higher_role_owned",
            Self::ResourceShared => "shared",
            Self::FileFixtureSmallPng => "fixture_small_png",
            Self::FileFixturePdf => "fixture_pdf",
            Self::FileOversized => "oversized",
            Self::UrlValidHttps => "valid_https",
            Self::PasswordGenerated => "generated",
        }
    }

    /// Canonical `family:name` string; the bytes hashed into value derivation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmailValidNewUser => "email:valid_new_user",
            Self::EmailExistingUser => "email:existing_user",
            Self::EmailMalformed => "email:malformed",
            Self::EmailLongBoundary => "email:long_boundary",
            Self::PhoneValidE164 => "phone:valid_e164",
            Self::PhoneMalformed => "phone:malformed",
            Self::DateToday => "date:today",
            Self::DateFuture => "date:future",
            Self::DatePast => "date:past",
            Self::DateMonthBoundary => "date:month_boundary",
            Self::TextShortValid => "text:short_valid",
            Self::TextLongBoundary => "text:long_boundary",
            Self::TextUnicode => "text:unicode",
            Self::TextEmpty => "text:empty",
            Self::NumberMin => "number:min",
            Self::NumberMax => "number:max",
            Self::NumberTypical => "number:typical",
            Self::NumberOutOfRange => "number:out_of_range",
            Self::ResourceOwn => "resource:own",
            Self::ResourceOtherUserSameRole => "resource:other_user_same_role",
            Self::ResourceHigherRoleOwned => "resource:higher_role_owned",
            Self::ResourceShared => "resource:shared",
            Self::FileFixtureSmallPng => "file:fixture_small_png",
            Self::FileFixturePdf => "file:fixture_pdf",
            Self::FileOversized => "file:oversized",
            Self::UrlValidHttps => "url:valid_https",
            Self::PasswordGenerated => "password:generated",
        }
    }

    /// The `input_class` this partition contributes to an `ActionContextKey`.
    #[must_use]
    pub fn input_class(self) -> InputClass {
        InputClass::new(self.family().as_str(), self.name())
    }

    /// Partitions declared `unique_per_use`: they take the `ordinal`
    /// (`action_contexts.attempts`) so reruns do not collide with server-side
    /// uniqueness constraints.
    #[must_use]
    pub const fn unique_per_use(self) -> bool {
        matches!(self, Self::EmailValidNewUser | Self::PasswordGenerated)
    }

    /// Only ever run under `authorized_security_test`.
    #[must_use]
    pub const fn requires_authorized_security_test(self) -> bool {
        matches!(
            self,
            Self::ResourceOtherUserSameRole | Self::ResourceHigherRoleOwned | Self::FileOversized
        )
    }

    /// A value generated by `ValuePartitions::value`. Resource partitions are
    /// resolved from the resource registry instead.
    #[must_use]
    pub const fn is_generated(self) -> bool {
        !matches!(self.family(), PartitionFamily::Resource)
    }

    /// Is this a baseline (all-valid) partition? Used to build the
    /// one-factor-at-a-time baseline combination.
    #[must_use]
    pub const fn is_baseline(self) -> bool {
        matches!(
            self,
            Self::EmailValidNewUser
                | Self::PhoneValidE164
                | Self::DateToday
                | Self::TextShortValid
                | Self::NumberTypical
                | Self::ResourceOwn
                | Self::FileFixtureSmallPng
                | Self::UrlValidHttps
                | Self::PasswordGenerated
        )
    }

    /// Does the generated value satisfy [`validate`] for the family's kind?
    /// False for `malformed` partitions by construction.
    #[must_use]
    pub const fn is_valid_value(self) -> bool {
        !matches!(self, Self::EmailMalformed | Self::PhoneMalformed)
    }

    /// The partition the profile runs by default for `kind`
    /// (`read_only`/`test_environment`/`authorized_security_test` all start
    /// from the valid baseline; `authorized_security_test` then expands via
    /// [`partitions_for`]). `None` for kinds without generated values.
    #[must_use]
    pub const fn default_for(kind: InputKind, _profile: SafetyProfile) -> Option<Self> {
        match kind {
            InputKind::Email => Some(Self::EmailValidNewUser),
            InputKind::Phone => Some(Self::PhoneValidE164),
            InputKind::Date => Some(Self::DateToday),
            InputKind::Text | InputKind::Search => Some(Self::TextShortValid),
            InputKind::Number | InputKind::Range => Some(Self::NumberTypical),
            InputKind::File => Some(Self::FileFixtureSmallPng),
            InputKind::Url => Some(Self::UrlValidHttps),
            InputKind::Password => Some(Self::PasswordGenerated),
            InputKind::Otp
            | InputKind::Checkbox
            | InputKind::Radio
            | InputKind::Select
            | InputKind::Hidden
            | InputKind::Unknown => None,
        }
    }

    /// Resource-ownership partitions a profile may exercise.
    #[must_use]
    pub fn resource_partitions(profile: SafetyProfile) -> Vec<Self> {
        match profile {
            SafetyProfile::AuthorizedSecurityTest => vec![
                Self::ResourceOwn,
                Self::ResourceOtherUserSameRole,
                Self::ResourceHigherRoleOwned,
                Self::ResourceShared,
            ],
            SafetyProfile::ReadOnly | SafetyProfile::TestEnvironment => vec![Self::ResourceOwn],
        }
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unknown `family:name` string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("unknown partition `{0}`")]
pub struct ParsePartitionError(pub String);

impl FromStr for Partition {
    type Err = ParsePartitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ALL_PARTITIONS
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| ParsePartitionError(s.to_owned()))
    }
}

impl Serialize for Partition {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Partition {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The families whose partitions apply to `kind`.
const fn family_for(kind: InputKind) -> Option<PartitionFamily> {
    match kind {
        InputKind::Email => Some(PartitionFamily::Email),
        InputKind::Phone => Some(PartitionFamily::Phone),
        InputKind::Date => Some(PartitionFamily::Date),
        InputKind::Text | InputKind::Search => Some(PartitionFamily::Text),
        InputKind::Number | InputKind::Range => Some(PartitionFamily::Number),
        InputKind::File => Some(PartitionFamily::File),
        InputKind::Url => Some(PartitionFamily::Url),
        InputKind::Password => Some(PartitionFamily::Password),
        InputKind::Otp
        | InputKind::Checkbox
        | InputKind::Radio
        | InputKind::Select
        | InputKind::Hidden
        | InputKind::Unknown => None,
    }
}

/// Partitions to exercise for `kind` under `profile`: the default baseline,
/// except `authorized_security_test`, which expands to every partition of the
/// family. Empty for kinds without generated values.
#[must_use]
pub fn partitions_for(kind: InputKind, profile: SafetyProfile) -> Vec<Partition> {
    let set = match profile {
        SafetyProfile::AuthorizedSecurityTest => PartitionSet::Expanded,
        SafetyProfile::ReadOnly | SafetyProfile::TestEnvironment => PartitionSet::Default,
    };
    partitions_for_set(kind, profile, set)
}

/// Like [`partitions_for`] with an explicit set (`forms.partitions: "expanded"`
/// on `test_environment`). Partitions that need `authorized_security_test`
/// are filtered out under every other profile; `read_only` never expands
/// beyond the default set.
#[must_use]
pub fn partitions_for_set(kind: InputKind, profile: SafetyProfile, set: PartitionSet) -> Vec<Partition> {
    let Some(family) = family_for(kind) else {
        return Vec::new();
    };
    let expanded = set == PartitionSet::Expanded && profile != SafetyProfile::ReadOnly;
    if !expanded {
        return Partition::default_for(kind, profile).into_iter().collect();
    }
    ALL_PARTITIONS
        .iter()
        .copied()
        .filter(|p| p.family() == family)
        .filter(|p| {
            profile == SafetyProfile::AuthorizedSecurityTest || !p.requires_authorized_security_test()
        })
        .collect()
}

/// Number of one-factor-at-a-time submissions for a form whose fields have
/// the given partition counts: `1 + Σ (|P_f| − 1)`.
#[must_use]
pub fn ofat_combinations(partition_counts: &[usize]) -> usize {
    1 + partition_counts
        .iter()
        .map(|n| n.saturating_sub(1))
        .sum::<usize>()
}

// ---------------------------------------------------------------- validators

/// Does `value` satisfy the syntactic validator for `kind`? These are the
/// validators generated values must pass (client-side validators rejecting
/// generated values is the crate's main risk).
#[must_use]
pub fn validate(kind: InputKind, value: &str) -> bool {
    match kind {
        InputKind::Email => valid_email(value),
        InputKind::Phone => valid_e164(value),
        InputKind::Date => valid_date_like(value),
        InputKind::Text | InputKind::Search => valid_text(value),
        InputKind::Number | InputKind::Range => valid_number(value),
        InputKind::Password => valid_password(value),
        InputKind::Otp => (4..=8).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit()),
        InputKind::Url => valid_url(value),
        InputKind::File => crate::fixtures::is_known_fixture(value),
        InputKind::Checkbox => matches!(value, "true" | "false"),
        InputKind::Radio | InputKind::Select | InputKind::Hidden | InputKind::Unknown => true,
    }
}

/// RFC 5321-ish: one `@`, local ≤ 64 of atext + dots, domain labels ≤ 63,
/// total ≤ 254, at least two labels.
fn valid_email(s: &str) -> bool {
    if s.len() > 254 {
        return false;
    }
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    if domain.contains('@') || local.is_empty() || local.len() > 64 {
        return false;
    }
    let atext = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c);
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if !local.chars().all(|c| c == '.' || atext(c)) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// E.164: `+`, first digit 1–9, 7..=15 digits in total.
fn valid_e164(s: &str) -> bool {
    let Some(d) = s.strip_prefix('+') else {
        return false;
    };
    (7..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0')
}

fn valid_date_like(s: &str) -> bool {
    use chrono::{NaiveDate, NaiveTime};
    if NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok() {
        return true;
    }
    if chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").is_ok() {
        return true;
    }
    if NaiveTime::parse_from_str(s, "%H:%M").is_ok() {
        return true;
    }
    if let Some((y, m)) = s.split_once('-') {
        if y.len() == 4
            && m.len() == 2
            && NaiveDate::parse_from_str(&format!("{y}-{m}-01"), "%Y-%m-%d").is_ok()
        {
            return true;
        }
        if let Some(w) = m.strip_prefix('W') {
            if let (Ok(year), Ok(week)) = (y.parse::<i32>(), w.parse::<u32>()) {
                return y.len() == 4
                    && w.len() == 2
                    && NaiveDate::from_isoywd_opt(year, week, chrono::Weekday::Mon).is_some();
            }
        }
    }
    false
}

fn valid_text(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

fn valid_number(s: &str) -> bool {
    !s.is_empty()
        && s.parse::<f64>().is_ok_and(f64::is_finite)
        && !s.contains(['e', 'E', ' ', '+'])
        && s != "-"
}

fn valid_password(s: &str) -> bool {
    s.chars().count() >= 12
        && s.chars().any(|c| c.is_ascii_lowercase())
        && s.chars().any(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| !c.is_ascii_alphanumeric())
        && !s.chars().any(char::is_whitespace)
}

fn valid_url(s: &str) -> bool {
    url::Url::parse(s)
        .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty()))
        && !s.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn strings_round_trip() {
        for p in ALL_PARTITIONS {
            assert_eq!(p.to_string().parse::<Partition>().unwrap(), *p);
            assert_eq!(p.as_str(), format!("{}:{}", p.family().as_str(), p.name()));
            let json = serde_json::to_string(p).unwrap();
            assert_eq!(serde_json::from_str::<Partition>(&json).unwrap(), *p);
        }
        assert!("email:nope".parse::<Partition>().is_err());
        assert_eq!(
            Partition::EmailValidNewUser.input_class(),
            InputClass::new("email", "valid_new_user")
        );
    }

    #[test]
    fn main_table_is_complete() {
        let names = |f: PartitionFamily| -> Vec<&'static str> {
            ALL_PARTITIONS
                .iter()
                .filter(|p| p.family() == f)
                .map(|p| p.name())
                .collect()
        };
        assert_eq!(
            names(PartitionFamily::Email),
            ["valid_new_user", "existing_user", "malformed", "long_boundary"]
        );
        assert_eq!(names(PartitionFamily::Phone), ["valid_e164", "malformed"]);
        assert_eq!(
            names(PartitionFamily::Date),
            ["today", "future", "past", "month_boundary"]
        );
        assert_eq!(
            names(PartitionFamily::Text),
            ["short_valid", "long_boundary", "unicode", "empty"]
        );
        assert_eq!(
            names(PartitionFamily::Number),
            ["min", "max", "typical", "out_of_range"]
        );
        assert_eq!(
            names(PartitionFamily::Resource),
            ["own", "other_user_same_role", "higher_role_owned", "shared"]
        );
        assert_eq!(
            names(PartitionFamily::File),
            ["fixture_small_png", "fixture_pdf", "oversized"]
        );
    }

    #[test]
    fn defaults_are_valid_partitions() {
        for profile in [
            SafetyProfile::ReadOnly,
            SafetyProfile::TestEnvironment,
            SafetyProfile::AuthorizedSecurityTest,
        ] {
            assert_eq!(
                Partition::default_for(InputKind::Email, profile),
                Some(Partition::EmailValidNewUser)
            );
            assert_eq!(
                Partition::default_for(InputKind::Phone, profile),
                Some(Partition::PhoneValidE164)
            );
            assert_eq!(
                Partition::default_for(InputKind::Date, profile),
                Some(Partition::DateToday)
            );
            assert_eq!(
                Partition::default_for(InputKind::Text, profile),
                Some(Partition::TextShortValid)
            );
            assert_eq!(
                Partition::default_for(InputKind::Number, profile),
                Some(Partition::NumberTypical)
            );
            assert_eq!(
                Partition::default_for(InputKind::File, profile),
                Some(Partition::FileFixtureSmallPng)
            );
            assert_eq!(Partition::default_for(InputKind::Select, profile), None);
        }
        assert_eq!(
            Partition::resource_partitions(SafetyProfile::ReadOnly),
            [Partition::ResourceOwn]
        );
    }

    #[test]
    fn profile_dependent_sets() {
        use SafetyProfile::{AuthorizedSecurityTest as Auth, ReadOnly, TestEnvironment};
        assert_eq!(
            partitions_for(InputKind::Email, ReadOnly),
            [Partition::EmailValidNewUser]
        );
        assert_eq!(
            partitions_for(InputKind::Email, TestEnvironment),
            [Partition::EmailValidNewUser]
        );
        assert_eq!(partitions_for(InputKind::Email, Auth).len(), 4);
        assert_eq!(partitions_for(InputKind::File, Auth).len(), 3);
        assert_eq!(partitions_for(InputKind::Number, Auth).len(), 4);
        assert!(partitions_for(InputKind::Checkbox, Auth).is_empty());

        // expanded on test_environment drops the authorized-only partitions
        let exp = partitions_for_set(InputKind::File, TestEnvironment, PartitionSet::Expanded);
        assert_eq!(exp, [Partition::FileFixtureSmallPng, Partition::FileFixturePdf]);
        assert_eq!(
            partitions_for_set(InputKind::Email, TestEnvironment, PartitionSet::Expanded).len(),
            4
        );
        // read_only never expands
        assert_eq!(
            partitions_for_set(InputKind::Text, ReadOnly, PartitionSet::Expanded),
            [Partition::TextShortValid]
        );
        // resources
        assert_eq!(Partition::resource_partitions(Auth).len(), 4);
        for p in partitions_for_set(InputKind::Text, TestEnvironment, PartitionSet::Expanded) {
            assert!(!p.requires_authorized_security_test());
        }
    }

    #[test]
    fn ofat_count() {
        assert_eq!(ofat_combinations(&[]), 1);
        assert_eq!(ofat_combinations(&[4, 2, 1]), 1 + 3 + 1);
    }

    #[test]
    fn validators_accept_and_reject() {
        assert!(validate(InputKind::Email, "a.b+c@example.invalid"));
        for bad in [
            "",
            "a",
            "a@",
            "@b.invalid",
            "a@@b.invalid",
            "a b@c.invalid",
            "a@b",
            "a..b@c.invalid",
            ".a@c.invalid",
            "a@-b.invalid",
        ] {
            assert!(!validate(InputKind::Email, bad), "{bad}");
        }
        assert!(validate(InputKind::Phone, "+12125550123"));
        for bad in [
            "",
            "+",
            "12125550123",
            "+0123456789",
            "+1212555012345678",
            "+1 212",
            "+12a",
        ] {
            assert!(!validate(InputKind::Phone, bad), "{bad}");
        }
        assert!(validate(InputKind::Date, "2026-10-16"));
        assert!(validate(InputKind::Date, "2026-10-16T09:30"));
        assert!(validate(InputKind::Date, "2026-10"));
        assert!(validate(InputKind::Date, "2026-W42"));
        assert!(validate(InputKind::Date, "09:30"));
        assert!(!validate(InputKind::Date, "2026-13-01"));
        assert!(!validate(InputKind::Date, "yesterday"));
        assert!(validate(InputKind::Number, "-3.5"));
        assert!(!validate(InputKind::Number, "abc"));
        assert!(!validate(InputKind::Number, ""));
        assert!(validate(InputKind::Url, "https://example.invalid/a?b=c"));
        assert!(!validate(InputKind::Url, "javascript:alert(1)"));
        assert!(!validate(InputKind::Text, "a\nb"));
        assert!(validate(InputKind::Text, ""));
        assert!(validate(InputKind::Otp, "123456"));
        assert!(!validate(InputKind::Otp, "12"));
    }
}
