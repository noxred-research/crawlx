//! Deterministic value derivation.
//!
//! `value(seed, key, partition, ordinal, generator_version, ctx)` derives its
//! RNG from `CrawlSeed::rng("forms/value/v1", [key.id, partition, ordinal,
//! attempt, generator_version])`. Generators consume only that RNG and
//! `ctx`: no wall time, no global randomness, no platform-width sampling
//! (all draws are `u64 % n`), so the same inputs yield byte-identical values
//! on every platform and release with the same `generator_version`.

use crate::classify::{DateFlavor, InputConstraints};
use crate::fixtures::{FIXTURE_OVERSIZED, FIXTURE_PDF, FIXTURE_SMALL_PNG};
use crate::partition::Partition;
use chrono::{Datelike, Days, NaiveDate};
use crawlx_core::identity::ActionContextKey;
use crawlx_core::secret::SecretOr;
use crawlx_core::seed::CrawlSeed;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

/// Current generator revision. Recorded on `crawl_runs`; bumping it changes
/// every generated value and invalidates cross-version comparisons.
pub const GENERATOR_VERSION: u16 = 1;

/// Domain used for email values when no verified email sink exists
/// (RFC 2606 reserved TLD: never routable).
pub const FALLBACK_EMAIL_DOMAIN: &str = "crawlx.invalid";

/// Operator-configured values for the valid baseline partitions of the four text-like input
/// classes (the `-form-config` compatibility flag: `email`, `phone`, `password`, `placeholder`), already
/// resolved for the run (`rand_*` helpers evaluated). A field whose partition matches takes
/// the configured value instead of the seeded one; boundary and malformed partitions
/// (`email:malformed`, `text:long_boundary`, ...) still generate theirs, because they exist to
/// probe validation rather than to fill a form.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ConfiguredValues {
    /// Value of `email:valid_new_user` fields.
    pub email: Option<String>,
    /// Value of `phone:valid_e164` fields.
    pub phone: Option<String>,
    /// Value of `password:generated` fields (stays a secret).
    pub password: Option<String>,
    /// Value of `text:short_valid` fields: every other text-like input.
    pub placeholder: Option<String>,
}

impl ConfiguredValues {
    /// Does it configure nothing?
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.email.is_none() && self.phone.is_none() && self.password.is_none() && self.placeholder.is_none()
    }

    /// The configured value a field of `partition` takes, if its class has one.
    #[must_use]
    pub fn for_partition(&self, partition: Partition) -> Option<SecretOr<String>> {
        match partition {
            Partition::EmailValidNewUser => self.email.clone().map(SecretOr::Plain),
            Partition::PhoneValidE164 => self.phone.clone().map(SecretOr::Plain),
            Partition::PasswordGenerated => self.password.clone().map(SecretOr::secret),
            Partition::TextShortValid => self.placeholder.clone().map(SecretOr::Plain),
            _ => None,
        }
    }
}

/// Everything a generator may read besides the RNG.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValueContext {
    /// The run's start date from the injected clock (never wall time).
    pub today: NaiveDate,
    /// Domain of the verified email sink, if any.
    pub sink_domain: Option<String>,
    /// Trusted submissions of this key so far (part of the derivation).
    pub attempt: u32,
    /// Constraint attributes of the target input (`maxlength`, `min`, `max`, ...).
    pub constraints: InputConstraints,
    /// Configured values that replace the seeded ones (`-form-config`); empty by default.
    pub configured: ConfiguredValues,
}

impl ValueContext {
    /// Context for `today` with no sink domain, attempt 0 and default constraints.
    #[must_use]
    pub fn new(today: NaiveDate) -> Self {
        Self {
            today,
            sink_domain: None,
            attempt: 0,
            constraints: InputConstraints::default(),
            configured: ConfiguredValues::default(),
        }
    }

    /// Set the verified email sink domain.
    #[must_use]
    pub fn with_sink_domain(mut self, domain: Option<String>) -> Self {
        self.sink_domain = domain;
        self
    }

    /// Set the trusted-submission attempt counter.
    #[must_use]
    pub const fn with_attempt(mut self, attempt: u32) -> Self {
        self.attempt = attempt;
        self
    }

    /// Set the constraint attributes of the target input.
    #[must_use]
    pub fn with_constraints(mut self, constraints: InputConstraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Set the operator-configured values (`-form-config`) that replace the seeded value of
    /// the matching baseline partitions.
    #[must_use]
    pub fn with_configured(mut self, configured: ConfiguredValues) -> Self {
        self.configured = configured;
        self
    }
}

/// Stateless generator namespace.
#[derive(Clone, Copy, Debug, Default)]
pub struct ValuePartitions;

impl ValuePartitions {
    /// Value for `(seed, key, partition)`.
    ///
    /// * Passwords are `SecretOr::secret`; every other value is plain.
    /// * `file:*` partitions return the fixture id (see `FixtureFiles`).
    /// * `resource:*` partitions are not generated: the returned
    ///   `resource:<name>` token must be resolved from the resource ledger and
    ///   is never typed (`Partition::is_generated()` is false).
    /// * `email:existing_user` is the `valid_new_user` address of ordinal 0 and
    ///   attempt 0 for the same key: the account an earlier run created.
    #[must_use]
    pub fn value(
        seed: CrawlSeed,
        key: &ActionContextKey,
        partition: Partition,
        ordinal: u32,
        generator_version: u16,
        ctx: &ValueContext,
    ) -> SecretOr<String> {
        if let Some(configured) = ctx.configured.for_partition(partition) {
            return configured;
        }
        let key_id = key.id();
        let derive = |p: Partition, ord: u32, attempt: u32| {
            seed.rng(
                "forms/value/v1",
                &[
                    &key_id.0,
                    p.as_str().as_bytes(),
                    &ord.to_le_bytes(),
                    &attempt.to_le_bytes(),
                    &generator_version.to_le_bytes(),
                ],
            )
        };
        let c = &ctx.constraints;
        let domain = ctx.sink_domain.as_deref().unwrap_or(FALLBACK_EMAIL_DOMAIN);
        let mut rng = derive(partition, ordinal, ctx.attempt);
        let plain = |s: String| SecretOr::Plain(s);
        match partition {
            Partition::EmailValidNewUser => plain(email_valid(&mut rng, domain, c)),
            Partition::EmailExistingUser => {
                let mut first = derive(Partition::EmailValidNewUser, 0, 0);
                plain(email_valid(&mut first, domain, c))
            }
            Partition::EmailMalformed => plain(pick(&mut rng, MALFORMED_EMAILS).to_string()),
            Partition::EmailLongBoundary => plain(email_long(&mut rng, domain, c)),
            Partition::PhoneValidE164 => plain(phone_valid(&mut rng)),
            Partition::PhoneMalformed => plain(pick(&mut rng, MALFORMED_PHONES).to_string()),
            Partition::DateToday => plain(date_value(&mut rng, ctx.today, c)),
            Partition::DateFuture => {
                let days = 30 + below_u32(&mut rng, 335);
                plain(date_value(&mut rng, add_days(ctx.today, i64::from(days)), c))
            }
            Partition::DatePast => {
                let days = 30 + below_u32(&mut rng, 3620);
                plain(date_value(&mut rng, add_days(ctx.today, -i64::from(days)), c))
            }
            Partition::DateMonthBoundary => {
                let (_, last) = month_bounds(ctx.today);
                let d = if below(&mut rng, 2) == 0 {
                    last
                } else {
                    add_days(last, 1)
                };
                plain(date_value(&mut rng, d, c))
            }
            Partition::TextShortValid => plain(text_short(&mut rng, c)),
            Partition::TextLongBoundary => plain(text_long(&mut rng, c)),
            Partition::TextUnicode => plain(fit_len(pick(&mut rng, UNICODE_CORPUS), c)),
            Partition::TextEmpty => plain(String::new()),
            Partition::NumberMin
            | Partition::NumberMax
            | Partition::NumberTypical
            | Partition::NumberOutOfRange => plain(number_value(&mut rng, partition, c)),
            Partition::ResourceOwn
            | Partition::ResourceOtherUserSameRole
            | Partition::ResourceHigherRoleOwned
            | Partition::ResourceShared => plain(partition.as_str().to_owned()),
            Partition::FileFixtureSmallPng => plain(FIXTURE_SMALL_PNG.to_owned()),
            Partition::FileFixturePdf => plain(FIXTURE_PDF.to_owned()),
            Partition::FileOversized => plain(FIXTURE_OVERSIZED.to_owned()),
            Partition::UrlValidHttps => {
                plain(format!("https://example.invalid/crawlx/{}", base32(&mut rng, 6)))
            }
            Partition::PasswordGenerated => SecretOr::secret(password(&mut rng)),
        }
    }
}

// ------------------------------------------------------------------- helpers

/// Uniform-enough draw in `0..n` (`n > 0`); platform independent.
fn below(rng: &mut ChaCha8Rng, n: u64) -> u64 {
    rng.next_u64() % n.max(1)
}

/// Like [`below`] for a `u32` bound; the draw is `< n`, so it always fits.
fn below_u32(rng: &mut ChaCha8Rng, n: u32) -> u32 {
    u32::try_from(below(rng, u64::from(n))).unwrap_or(0)
}

fn pick<'a, T>(rng: &mut ChaCha8Rng, items: &'a [T]) -> &'a T {
    let i = below(rng, items.len() as u64);
    // `items` is never empty at the call sites (constants); index is in range.
    &items[usize::try_from(i).unwrap_or(0)]
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Lower-case RFC 4648 base32 (no padding) of `n_bytes` random bytes.
fn base32(rng: &mut ChaCha8Rng, n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity((n_bytes * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

fn max_len(c: &InputConstraints) -> Option<usize> {
    c.maxlength.filter(|&m| m > 0).map(|m| m as usize)
}

/// Truncate to `maxlength` chars and pad with `a` up to `minlength`.
fn fit_len(s: &str, c: &InputConstraints) -> String {
    let mut out: String = match max_len(c) {
        Some(m) => s.chars().take(m).collect(),
        None => s.to_owned(),
    };
    let min = c.minlength.unwrap_or(0) as usize;
    let cap = max_len(c).unwrap_or(usize::MAX);
    while out.chars().count() < min && out.chars().count() < cap {
        out.push('a');
    }
    out
}

// --------------------------------------------------------------------- email

const MALFORMED_EMAILS: &[&str] = &[
    "plainaddress",
    "missing-at-sign.example.invalid",
    "@missing-local.example.invalid",
    "two@@signs.example.invalid",
    "trailing-dot.@example.invalid",
    "spaces in@example.invalid",
    "no-tld@localhost",
    "double..dot@example.invalid",
];

fn email_valid(rng: &mut ChaCha8Rng, domain: &str, c: &InputConstraints) -> String {
    let rand = base32(rng, 8);
    let full = format!("crawlx+{rand}@{domain}");
    match max_len(c) {
        Some(m) if full.len() > m => {
            let budget = m.saturating_sub(domain.len() + 1);
            if budget == 0 {
                return full;
            }
            let local: String = rand.chars().take(budget).collect();
            format!("{local}@{domain}")
        }
        _ => full,
    }
}

/// Longest valid address: local part 64, labels ≤ 63, total ≤ 254 (or `maxlength`).
fn email_long(rng: &mut ChaCha8Rng, domain: &str, c: &InputConstraints) -> String {
    let target = max_len(c).map_or(254, |m| m.min(254));
    let local_len = target.saturating_sub(domain.len() + 1).clamp(1, 64);
    let mut local = String::with_capacity(local_len);
    while local.len() < local_len {
        local.push_str(&base32(rng, 8));
    }
    local.truncate(local_len);
    let mut prefix = String::new();
    let mut remaining = target.saturating_sub(local_len + 1 + domain.len());
    while remaining >= 2 {
        let label_len = (remaining - 1).min(63);
        let mut label = String::new();
        while label.len() < label_len {
            label.push_str(&base32(rng, 8));
        }
        label.truncate(label_len);
        prefix.push_str(&label);
        prefix.push('.');
        remaining -= label_len + 1;
    }
    format!("{local}@{prefix}{domain}")
}

// --------------------------------------------------------------------- phone

const AREA_CODES: &[&str] = &[
    "202", "206", "212", "213", "305", "312", "415", "617", "702", "713",
];

const MALFORMED_PHONES: &[&str] = &[
    "12345",
    "+",
    "+0123456789",
    "phone",
    "+1 (555) abc",
    "+99999999999999999",
    "555-0100",
];

/// `+1` + area + `555` + `01xx`: the NANP range reserved for fiction.
fn phone_valid(rng: &mut ChaCha8Rng) -> String {
    let area = pick(rng, AREA_CODES);
    let xx = below(rng, 100);
    format!("+1{area}55501{xx:02}")
}

// ---------------------------------------------------------------------- date

fn add_days(d: NaiveDate, days: i64) -> NaiveDate {
    let n = Days::new(days.unsigned_abs());
    if days >= 0 {
        d.checked_add_days(n)
    } else {
        d.checked_sub_days(n)
    }
    .unwrap_or(d)
}

/// First and last day of `d`'s month.
fn month_bounds(d: NaiveDate) -> (NaiveDate, NaiveDate) {
    let first = d.with_day(1).unwrap_or(d);
    let next_first = if d.month() == 12 {
        NaiveDate::from_ymd_opt(d.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(d.year(), d.month() + 1, 1)
    };
    let last = next_first.and_then(|n| n.pred_opt()).unwrap_or(d);
    (first, last)
}

fn date_value(rng: &mut ChaCha8Rng, d: NaiveDate, c: &InputConstraints) -> String {
    let (hh, mm) = (below(rng, 24), below(rng, 60));
    let (min, max) = (
        c.min
            .as_deref()
            .and_then(|s| NaiveDate::parse_from_str(s.get(..10).unwrap_or(s), "%Y-%m-%d").ok()),
        c.max
            .as_deref()
            .and_then(|s| NaiveDate::parse_from_str(s.get(..10).unwrap_or(s), "%Y-%m-%d").ok()),
    );
    let mut d = d;
    if let Some(lo) = min {
        d = d.max(lo);
    }
    if let Some(hi) = max {
        d = d.min(hi);
    }
    match c.date_flavor {
        DateFlavor::Date => d.format("%Y-%m-%d").to_string(),
        DateFlavor::DateTimeLocal => format!("{}T{hh:02}:{mm:02}", d.format("%Y-%m-%d")),
        DateFlavor::Month => d.format("%Y-%m").to_string(),
        DateFlavor::Week => {
            let w = d.iso_week();
            format!("{}-W{:02}", w.year(), w.week())
        }
        DateFlavor::Time => format!("{hh:02}:{mm:02}"),
    }
}

// ---------------------------------------------------------------------- text

const WORDS: &[&str] = &[
    "Amber", "Birch", "Cedar", "Delta", "Ember", "Fjord", "Garnet", "Harbor", "Indigo", "Juniper", "Kestrel",
    "Lagoon", "Meadow", "Nimbus", "Onyx", "Pebble", "Quartz", "Raven", "Sorrel", "Tundra", "Umber", "Velvet",
    "Willow", "Zephyr",
];

const UNICODE_CORPUS: &[&str] = &[
    "Zoë Müller",
    "Łukasz Żółć",
    "田中太郎",
    "Åsa Öberg",
    "Ñandú Peña",
    "İstanbul Çağrı",
    "Δημήτρης Παπά",
    "Привет мир",
    "Ærøskøbing Ångström",
    "Dvořák Šimůnek",
];

fn text_short(rng: &mut ChaCha8Rng, c: &InputConstraints) -> String {
    let (a, b) = (*pick(rng, WORDS), *pick(rng, WORDS));
    fit_len(&format!("{a} {b}"), c)
}

fn text_long(rng: &mut ChaCha8Rng, c: &InputConstraints) -> String {
    let len = max_len(c).unwrap_or(256);
    let mut s = String::with_capacity(len + 8);
    while s.len() < len {
        s.push_str(pick(rng, WORDS));
        s.push(' ');
    }
    s.truncate(len);
    // never end on a separator (browsers trim trailing spaces)
    if s.ends_with(' ') {
        s.pop();
        s.push('x');
    }
    s
}

// -------------------------------------------------------------------- number

fn parse_num(s: Option<&str>) -> Option<f64> {
    s.and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
}

/// Saturating float-to-integer conversion (`NaN` maps to 0).
#[allow(
    clippy::cast_possible_truncation,
    reason = "saturating float-to-integer conversion is the intended semantics"
)]
fn saturating_i64(v: f64) -> i64 {
    v as i64
}

/// `v` clamped into `0.0..=max` as an integer (`NaN` maps to 0).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to a non-negative range below 2^53 first"
)]
fn clamped_u64(v: f64, max: f64) -> u64 {
    v.clamp(0.0, max) as u64
}

fn fmt_num(v: f64, integral: bool) -> String {
    if integral {
        format!("{}", saturating_i64(v))
    } else {
        let s = format!("{v:.6}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        if s.is_empty() || s == "-" {
            "0".to_owned()
        } else {
            s.to_owned()
        }
    }
}

fn number_value(rng: &mut ChaCha8Rng, partition: Partition, c: &InputConstraints) -> String {
    let (min, max) = (parse_num(c.min.as_deref()), parse_num(c.max.as_deref()));
    let step = parse_num(c.step.as_deref()).filter(|s| *s > 0.0).unwrap_or(1.0);
    let (lo, hi) = match (min, max) {
        (Some(a), Some(b)) => (a.min(b), a.max(b)),
        (Some(a), None) => (a, a + 100.0),
        (None, Some(b)) => (b.min(0.0), b),
        (None, None) => (0.0, 100.0),
    };
    let integral = lo.fract() == 0.0
        && hi.fract() == 0.0
        && step.fract() == 0.0
        && hi.abs() < 9.0e15
        && lo.abs() < 9.0e15;
    let n = clamped_u64(((hi - lo) / step).floor(), 1.0e12);
    let at = |k: u64| lo + step * k as f64;
    let v = match partition {
        Partition::NumberMin => lo,
        Partition::NumberMax => at(n),
        Partition::NumberOutOfRange => {
            if below(rng, 2) == 0 {
                hi + step
            } else {
                lo - step
            }
        }
        _ => at(n / 4 + below(rng, n / 2 + 1)),
    };
    fmt_num(v, integral)
}

// ------------------------------------------------------------------ password

fn password(rng: &mut ChaCha8Rng) -> String {
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGIT: &[u8] = b"23456789";
    const SYMBOL: &[u8] = b"!@#$%^&*-_=+";
    const LEN: usize = 16;
    let all: Vec<u8> = [LOWER, UPPER, DIGIT, SYMBOL].concat();
    let mut chars: Vec<u8> = [LOWER, UPPER, DIGIT, SYMBOL]
        .iter()
        .map(|set| *pick(rng, set))
        .collect();
    while chars.len() < LEN {
        chars.push(*pick(rng, &all));
    }
    // Fisher-Yates so the guaranteed classes are not always first
    for i in (1..chars.len()).rev() {
        let j = usize::try_from(below(rng, i as u64 + 1)).unwrap_or(0);
        chars.swap(i, j);
    }
    chars.into_iter().map(char::from).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::classify::InputKind;
    use crate::partition::{validate, ALL_PARTITIONS};
    use crawlx_core::hash::Digest;
    use crawlx_core::identity::{ActionKind, ElementIdentityHash, InputClass, ResourceContext};
    use crawlx_core::ids::{PrincipalId, StateClusterId};
    use crawlx_core::url::RouteTemplate;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn key(principal: &str, element: &str) -> ActionContextKey {
        ActionContextKey {
            principal: PrincipalId(principal.to_owned()),
            route_template: RouteTemplate("/signup".to_owned()),
            element: ElementIdentityHash(Digest::of("t", element.as_bytes())),
            action_kind: ActionKind::Type,
            input_class: InputClass::none(),
            resource_context: ResourceContext::Own,
            state_cluster: StateClusterId(uuid::Uuid::nil()),
        }
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 16).unwrap()
    }

    fn val(seed: u64, k: &ActionContextKey, p: Partition, ordinal: u32, ctx: &ValueContext) -> String {
        ValuePartitions::value(CrawlSeed(seed), k, p, ordinal, GENERATOR_VERSION, ctx)
            .expose()
            .clone()
    }

    fn kind_of(p: Partition) -> Option<InputKind> {
        use crate::partition::PartitionFamily as F;
        Some(match p.family() {
            F::Email => InputKind::Email,
            F::Phone => InputKind::Phone,
            F::Date => InputKind::Date,
            F::Text => InputKind::Text,
            F::Number => InputKind::Number,
            F::File => InputKind::File,
            F::Url => InputKind::Url,
            F::Password => InputKind::Password,
            F::Resource => return None,
        })
    }

    /// Golden vectors: pinned so any generator change is visible in review.
    #[test]
    fn golden_vectors() {
        let k = key("member", "email-field");
        let ctx = ValueContext::new(today());
        let ctx_sink = ctx.clone().with_sink_domain(Some("sink.example.test".to_owned()));
        let g = |p: Partition, ord: u32, c: &ValueContext| val(42, &k, p, ord, c);
        assert_eq!(
            g(Partition::EmailValidNewUser, 0, &ctx),
            "crawlx+jxbvofytg65rk@crawlx.invalid"
        );
        assert_eq!(
            g(Partition::EmailValidNewUser, 1, &ctx),
            "crawlx+zu4qa5ndv4wk6@crawlx.invalid"
        );
        assert_eq!(
            g(Partition::EmailValidNewUser, 0, &ctx_sink),
            "crawlx+jxbvofytg65rk@sink.example.test"
        );
        assert_eq!(
            g(Partition::EmailExistingUser, 3, &ctx),
            "crawlx+jxbvofytg65rk@crawlx.invalid"
        );
        assert_eq!(g(Partition::EmailMalformed, 0, &ctx), "no-tld@localhost");
        assert_eq!(
            g(Partition::EmailLongBoundary, 0, &ctx),
            "w3enzyrs5ez3wjvtvj4ffisvfsyx46d3boorwmsd4n3xiodhcrtgrvzwpp72i2vj@yhyh5ixxjnpawlgjenj6bqp7dgiajnoujgb6vwyko2j6bky3c7e2yo6xc253spd.233uk5yubdzomy2224mmy656sa5ltevqo5rw4q6zrngzqviy6gb2m3sdlhgc6fh.k34p22ekkpax2kyx2xlqvix6lyot3zsnxftkvtstpdoltw.crawlx.invalid"
        );
        assert_eq!(g(Partition::PhoneValidE164, 0, &ctx), "+12125550195");
        assert_eq!(g(Partition::PhoneMalformed, 0, &ctx), "+0123456789");
        assert_eq!(g(Partition::DateToday, 0, &ctx), "2026-10-16");
        assert_eq!(g(Partition::DateFuture, 0, &ctx), "2027-04-30");
        assert_eq!(g(Partition::DatePast, 0, &ctx), "2017-05-16");
        assert_eq!(g(Partition::DateMonthBoundary, 0, &ctx), "2026-10-31");
        assert_eq!(g(Partition::TextShortValid, 0, &ctx), "Fjord Indigo");
        assert_eq!(g(Partition::TextUnicode, 0, &ctx), "Δημήτρης Παπά");
        assert_eq!(
            g(Partition::TextLongBoundary, 0, &ctx),
            "Pebble Garnet Birch Delta Tundra Birch Quartz Harbor Quartz Velvet Pebble Quartz Meadow Tundra Lagoon Ember Willow Raven Juniper Meadow Quartz Velvet Meadow Indigo Umber Lagoon Willow Sorrel Nimbus Tundra Garnet Harbor Sorrel Willow Sorrel Tundra Birch Kes"
        );
        assert_eq!(g(Partition::NumberTypical, 0, &ctx), "52");
        assert_eq!(g(Partition::PasswordGenerated, 0, &ctx), "R%qgrepHew2XG%Yw");
        assert_eq!(g(Partition::FileFixturePdf, 0, &ctx), "fixture_pdf");
    }

    #[test]
    fn same_inputs_same_bytes_and_any_input_change_changes_output() {
        let k = key("member", "f");
        let ctx = ValueContext::new(today());
        let base = val(1, &k, Partition::EmailValidNewUser, 0, &ctx);
        assert_eq!(base, val(1, &k, Partition::EmailValidNewUser, 0, &ctx));
        assert_ne!(base, val(2, &k, Partition::EmailValidNewUser, 0, &ctx), "seed");
        assert_ne!(
            base,
            val(1, &key("admin", "f"), Partition::EmailValidNewUser, 0, &ctx),
            "principal"
        );
        assert_ne!(
            base,
            val(1, &key("member", "g"), Partition::EmailValidNewUser, 0, &ctx),
            "element"
        );
        assert_ne!(base, val(1, &k, Partition::EmailValidNewUser, 1, &ctx), "ordinal");
        assert_ne!(
            base,
            val(
                1,
                &k,
                Partition::EmailValidNewUser,
                0,
                &ctx.clone().with_attempt(1)
            ),
            "attempt"
        );
        let v2 = ValuePartitions::value(
            CrawlSeed(1),
            &k,
            Partition::EmailValidNewUser,
            0,
            GENERATOR_VERSION + 1,
            &ctx,
        );
        assert_ne!(&base, v2.expose(), "generator_version");
    }

    #[test]
    fn unique_per_use_ordinals_never_repeat() {
        let k = key("member", "email");
        let ctx = ValueContext::new(today());
        for p in [Partition::EmailValidNewUser, Partition::PasswordGenerated] {
            let seen: BTreeSet<String> = (0..100).map(|o| val(7, &k, p, o, &ctx)).collect();
            assert_eq!(seen.len(), 100, "{p}");
        }
        // across attempts too
        let seen: BTreeSet<String> = (0..100)
            .map(|a| {
                val(
                    7,
                    &k,
                    Partition::EmailValidNewUser,
                    0,
                    &ctx.clone().with_attempt(a),
                )
            })
            .collect();
        assert_eq!(seen.len(), 100);
    }

    #[test]
    fn email_uses_sink_domain_or_invalid() {
        let k = key("member", "email");
        let none = val(
            3,
            &k,
            Partition::EmailValidNewUser,
            0,
            &ValueContext::new(today()),
        );
        assert!(none.ends_with(".invalid"), "{none}");
        let with = val(
            3,
            &k,
            Partition::EmailValidNewUser,
            0,
            &ValueContext::new(today()).with_sink_domain(Some("mail.sinks.test".into())),
        );
        assert!(with.ends_with("@mail.sinks.test"), "{with}");
        assert!(validate(InputKind::Email, &none) && validate(InputKind::Email, &with));
        // every email partition honours the same domain rule
        for p in [Partition::EmailExistingUser, Partition::EmailLongBoundary] {
            assert!(
                val(3, &k, p, 0, &ValueContext::new(today())).ends_with(".invalid"),
                "{p}"
            );
        }
    }

    #[test]
    fn existing_user_is_the_first_created_account() {
        let k = key("member", "email");
        let ctx = ValueContext::new(today());
        let first = val(9, &k, Partition::EmailValidNewUser, 0, &ctx);
        assert_eq!(val(9, &k, Partition::EmailExistingUser, 0, &ctx), first);
        assert_eq!(
            val(
                9,
                &k,
                Partition::EmailExistingUser,
                5,
                &ctx.clone().with_attempt(4)
            ),
            first
        );
    }

    #[test]
    fn phone_is_in_the_reserved_fictional_range() {
        let k = key("member", "phone");
        for seed in 0..200 {
            let p = val(
                seed,
                &k,
                Partition::PhoneValidE164,
                0,
                &ValueContext::new(today()),
            );
            assert!(validate(InputKind::Phone, &p), "{p}");
            assert_eq!(p.len(), 12, "{p}");
            assert!(p.starts_with("+1"), "{p}");
            assert_eq!(&p[5..9], "5550", "{p}");
            assert_eq!(&p[9..10], "1", "{p}");
        }
    }

    #[test]
    fn dates_are_relative_to_today() {
        let k = key("member", "d");
        let ctx = ValueContext::new(today());
        let parse = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        for seed in 0..100 {
            assert_eq!(parse(&val(seed, &k, Partition::DateToday, 0, &ctx)), today());
            assert!(parse(&val(seed, &k, Partition::DateFuture, 0, &ctx)) > today());
            assert!(parse(&val(seed, &k, Partition::DatePast, 0, &ctx)) < today());
            let b = parse(&val(seed, &k, Partition::DateMonthBoundary, 0, &ctx));
            let last = NaiveDate::from_ymd_opt(2026, 10, 31).unwrap();
            let next_first = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
            assert!(b == last || b == next_first, "{b}");
        }
        // other today values: leap day, year end
        for t in [
            NaiveDate::from_ymd_opt(2028, 2, 10).unwrap(),
            NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
        ] {
            let c = ValueContext::new(t);
            let b = parse(&val(1, &k, Partition::DateMonthBoundary, 0, &c));
            assert!(
                b.day() == 1 || b.succ_opt().unwrap().day() == 1 || b.month() != t.month(),
                "{b}"
            );
        }
    }

    #[test]
    fn date_flavors_and_bounds() {
        let k = key("member", "d");
        let mut c = InputConstraints::default();
        for (flavor, len) in [
            (DateFlavor::Date, 10),
            (DateFlavor::DateTimeLocal, 16),
            (DateFlavor::Month, 7),
            (DateFlavor::Week, 8),
            (DateFlavor::Time, 5),
        ] {
            c.date_flavor = flavor;
            let ctx = ValueContext::new(today()).with_constraints(c.clone());
            for p in [Partition::DateToday, Partition::DateFuture, Partition::DatePast] {
                let v = val(5, &k, p, 0, &ctx);
                assert_eq!(v.len(), len, "{flavor:?} {v}");
                assert!(validate(InputKind::Date, &v), "{flavor:?} {v}");
            }
        }
        let c = InputConstraints {
            min: Some("2026-12-01".into()),
            max: Some("2026-12-31".into()),
            ..InputConstraints::default()
        };
        let ctx = ValueContext::new(today()).with_constraints(c);
        assert_eq!(val(1, &k, Partition::DateToday, 0, &ctx), "2026-12-01");
        assert_eq!(
            val(1, &k, Partition::DateFuture, 0, &ctx).get(..7),
            Some("2026-12")
        );
    }

    #[test]
    fn text_boundaries_follow_maxlength() {
        let k = key("member", "t");
        let ctx = ValueContext::new(today());
        assert_eq!(
            val(1, &k, Partition::TextLongBoundary, 0, &ctx).chars().count(),
            256
        );
        assert_eq!(val(1, &k, Partition::TextEmpty, 0, &ctx), "");
        let c = InputConstraints {
            maxlength: Some(20),
            minlength: Some(4),
            ..InputConstraints::default()
        };
        let ctx = ValueContext::new(today()).with_constraints(c);
        assert_eq!(
            val(1, &k, Partition::TextLongBoundary, 0, &ctx).chars().count(),
            20
        );
        for seed in 0..50 {
            let s = val(seed, &k, Partition::TextShortValid, 0, &ctx);
            assert!((4..=20).contains(&s.chars().count()), "{s}");
            let u = val(seed, &k, Partition::TextUnicode, 0, &ctx);
            assert!(u.chars().count() <= 20 && validate(InputKind::Text, &u));
        }
        let tiny = InputConstraints {
            maxlength: Some(3),
            ..InputConstraints::default()
        };
        let ctx = ValueContext::new(today()).with_constraints(tiny);
        assert_eq!(val(1, &k, Partition::TextShortValid, 0, &ctx).chars().count(), 3);
    }

    #[test]
    fn long_email_hits_the_boundary_and_stays_valid() {
        let k = key("member", "e");
        for (maxlen, expect) in [(None, 254usize), (Some(100), 100), (Some(60), 60), (Some(40), 40)] {
            let c = InputConstraints {
                maxlength: maxlen,
                ..InputConstraints::default()
            };
            let ctx = ValueContext::new(today()).with_constraints(c);
            let v = val(1, &k, Partition::EmailLongBoundary, 0, &ctx);
            assert!(validate(InputKind::Email, &v), "{v}");
            assert_eq!(v.len(), expect, "{maxlen:?}: {v}");
        }
        let ctx = ValueContext::new(today()).with_sink_domain(Some("sink.example.test".into()));
        let v = val(1, &k, Partition::EmailLongBoundary, 0, &ctx);
        assert!(validate(InputKind::Email, &v));
        assert!(v.ends_with("sink.example.test"));
        assert_eq!(v.len(), 254);
    }

    #[test]
    fn numbers_follow_min_max_step() {
        let k = key("member", "n");
        let mk = |min: &str, max: &str, step: Option<&str>| {
            ValueContext::new(today()).with_constraints(InputConstraints {
                min: Some(min.into()),
                max: Some(max.into()),
                step: step.map(str::to_owned),
                ..InputConstraints::default()
            })
        };
        let ctx = mk("3", "20", Some("5"));
        assert_eq!(val(1, &k, Partition::NumberMin, 0, &ctx), "3");
        assert_eq!(val(1, &k, Partition::NumberMax, 0, &ctx), "18");
        for seed in 0..50 {
            let t: i64 = val(seed, &k, Partition::NumberTypical, 0, &ctx).parse().unwrap();
            assert!((3..=18).contains(&t) && (t - 3) % 5 == 0, "{t}");
            let o: i64 = val(seed, &k, Partition::NumberOutOfRange, 0, &ctx)
                .parse()
                .unwrap();
            assert!(!(3..=20).contains(&o), "{o}");
        }
        let f = mk("0", "1", Some("0.25"));
        assert_eq!(val(1, &k, Partition::NumberMax, 0, &f), "1");
        assert_eq!(val(1, &k, Partition::NumberMin, 0, &f), "0");
        let t = val(1, &k, Partition::NumberTypical, 0, &f);
        assert!(["0.25", "0.5", "0.75"].contains(&t.as_str()), "{t}");
        // inverted bounds are swapped, defaults apply when absent
        let inv = mk("10", "2", None);
        assert_eq!(val(1, &k, Partition::NumberMin, 0, &inv), "2");
        assert_eq!(val(1, &k, Partition::NumberMax, 0, &inv), "10");
        let none = ValueContext::new(today());
        assert_eq!(val(1, &k, Partition::NumberMin, 0, &none), "0");
        assert_eq!(val(1, &k, Partition::NumberMax, 0, &none), "100");
    }

    #[test]
    fn passwords_are_secret_and_strong() {
        let k = key("member", "pw");
        let v = ValuePartitions::value(
            CrawlSeed(1),
            &k,
            Partition::PasswordGenerated,
            0,
            GENERATOR_VERSION,
            &ValueContext::new(today()),
        );
        assert!(v.is_secret());
        assert!(!format!("{v:?}").contains(v.expose().as_str()));
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"[REDACTED]\"");
        assert!(validate(InputKind::Password, v.expose()));
        // everything else is plain
        for p in ALL_PARTITIONS
            .iter()
            .filter(|p| **p != Partition::PasswordGenerated)
        {
            let v = ValuePartitions::value(
                CrawlSeed(1),
                &k,
                *p,
                0,
                GENERATOR_VERSION,
                &ValueContext::new(today()),
            );
            assert!(!v.is_secret(), "{p}");
        }
    }

    #[test]
    fn resource_partitions_return_ledger_tokens() {
        let k = key("member", "r");
        let ctx = ValueContext::new(today());
        for p in ALL_PARTITIONS.iter().filter(|p| !p.is_generated()) {
            assert_eq!(&val(1, &k, *p, 0, &ctx), p.as_str());
        }
    }

    #[test]
    fn files_return_fixture_ids() {
        let k = key("member", "f");
        let ctx = ValueContext::new(today());
        assert_eq!(
            val(1, &k, Partition::FileFixtureSmallPng, 0, &ctx),
            "fixture_small_png"
        );
        assert_eq!(val(1, &k, Partition::FileOversized, 0, &ctx), "oversized");
        assert!(validate(InputKind::File, "oversized"));
        assert!(!validate(InputKind::File, "/etc/passwd"));
    }

    #[test]
    fn base32_is_rfc4648_lowercase() {
        // 8 bytes -> 13 chars, alphabet a-z2-7
        let mut rng = CrawlSeed(1).rng("t", &[]);
        let s = base32(&mut rng, 8);
        assert_eq!(s.len(), 13);
        assert!(s.bytes().all(|b| B32.contains(&b)));
    }

    proptest! {
        /// Every generated partition satisfies its own validator for any seed,
        /// attempt and ordinal; `malformed` partitions never do.
        #[test]
        fn partitions_satisfy_their_validators(
            seed in any::<u64>(),
            ordinal in 0u32..1000,
            attempt in 0u32..50,
            maxlen in prop::option::of(30u32..300),
            sink in prop::option::of("[a-z]{3,10}\\.example\\.test"),
            year in 1990i32..2090,
            month in 1u32..=12,
            day in 1u32..=28,
        ) {
            let k = key("member", "prop");
            let today = NaiveDate::from_ymd_opt(year, month, day).unwrap();
            let ctx = ValueContext::new(today)
                .with_attempt(attempt)
                .with_sink_domain(sink)
                .with_constraints(InputConstraints { maxlength: maxlen, ..InputConstraints::default() });
            for p in ALL_PARTITIONS {
                let Some(kind) = kind_of(*p) else { continue };
                let v = ValuePartitions::value(CrawlSeed(seed), &k, *p, ordinal, GENERATOR_VERSION, &ctx);
                let ok = validate(kind, v.expose());
                prop_assert_eq!(ok, p.is_valid_value(), "{} -> {:?}", p, v.expose());
            }
        }

        #[test]
        fn deterministic_for_any_inputs(seed in any::<u64>(), ordinal in 0u32..100) {
            let k = key("member", "prop");
            let ctx = ValueContext::new(today());
            for p in ALL_PARTITIONS {
                let a = ValuePartitions::value(CrawlSeed(seed), &k, *p, ordinal, GENERATOR_VERSION, &ctx);
                let b = ValuePartitions::value(CrawlSeed(seed), &k, *p, ordinal, GENERATOR_VERSION, &ctx);
                prop_assert_eq!(a.expose(), b.expose());
            }
        }
    }
}
