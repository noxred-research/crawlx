//! Deterministic PII redaction of parsed text (`redactPII`).
//!
//! [`redact`] replaces e-mail addresses, phone numbers, payment card numbers (Luhn-checked),
//! IBANs (mod-97-checked) and credential-looking secrets. `PERSON` and `LOCATION` need a
//! named-entity model; this redactor runs none, so those entities are reported in
//! [`Redaction::unsupported`] instead of being silently skipped. `RedactMode::Fast` and
//! `RedactMode::Accurate` use the same patterns (there is no model to add accuracy);
//! `RedactMode::Aggressive` additionally treats bare 10-15 digit runs as phone numbers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

/// A class of personal data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RedactEntity {
    /// Personal names (needs an NER model; not redacted here).
    Person,
    /// E-mail addresses.
    Email,
    /// Phone numbers.
    Phone,
    /// Places (needs an NER model; not redacted here).
    Location,
    /// Payment card numbers and IBANs.
    Financial,
    /// API keys, tokens and private keys.
    Secret,
}

impl RedactEntity {
    /// Every entity, in the order of the compatibility API's `RedactPIIEntity`.
    pub const ALL: [Self; 6] = [
        Self::Person,
        Self::Email,
        Self::Phone,
        Self::Location,
        Self::Financial,
        Self::Secret,
    ];

    /// The upper-case name used on the wire and in `<TAG>` placeholders.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Person => "PERSON",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Location => "LOCATION",
            Self::Financial => "FINANCIAL",
            Self::Secret => "SECRET",
        }
    }

    /// Parse a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == name)
    }
}

/// Redaction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RedactMode {
    /// The compatibility API's default; here the same as [`RedactMode::Fast`].
    #[default]
    Accurate,
    /// Also redact bare 10-15 digit runs as phone numbers.
    Aggressive,
    /// Patterns only.
    Fast,
}

/// How a match is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReplaceStyle {
    /// `<EMAIL>`
    #[default]
    Tag,
    /// `*` for every character.
    Mask,
    /// Removed.
    Remove,
}

/// Options of [`redact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactOptions {
    /// Strategy.
    pub mode: RedactMode,
    /// Entities to redact; empty means all.
    pub entities: BTreeSet<RedactEntity>,
    /// Replacement style.
    pub replace_style: ReplaceStyle,
}

impl Default for RedactOptions {
    fn default() -> Self {
        Self {
            mode: RedactMode::Accurate,
            entities: BTreeSet::new(),
            replace_style: ReplaceStyle::Tag,
        }
    }
}

/// The redacted text and what was done.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Redaction {
    /// The text with matches replaced.
    pub text: String,
    /// Matches replaced per entity.
    pub counts: BTreeMap<RedactEntity, usize>,
    /// Requested entities this redactor cannot detect.
    pub unsupported: Vec<RedactEntity>,
}

fn rx(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

static EMAIL: LazyLock<Option<Regex>> =
    LazyLock::new(|| rx(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"));
static PHONE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    rx(
        r"(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?|\d{2,4}[\s.\-])\d{3,4}[\s.\-]\d{3,4}(?:[\s.\-]\d{1,4})?",
    )
});
static BARE_PHONE: LazyLock<Option<Regex>> = LazyLock::new(|| rx(r"\+?\b\d{10,15}\b"));
static CARD: LazyLock<Option<Regex>> = LazyLock::new(|| rx(r"\b\d(?:[ \-]?\d){12,18}\b"));
static IBAN: LazyLock<Option<Regex>> =
    LazyLock::new(|| rx(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"));
static SECRET: LazyLock<Option<Regex>> = LazyLock::new(|| {
    rx(concat!(
        r"AKIA[0-9A-Z]{16}",
        r"|ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}",
        r"|sk-[A-Za-z0-9_\-]{20,}",
        r"|xox[baprs]-[A-Za-z0-9\-]{10,}",
        r"|AIza[0-9A-Za-z_\-]{35}",
        r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ))
});

fn digits(s: &str) -> Vec<u32> {
    s.chars().filter_map(|c| c.to_digit(10)).collect()
}

fn luhn(d: &[u32]) -> bool {
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, v)| {
            if i % 2 == 1 {
                let x = v * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                *v
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn iban_ok(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let v = match c {
            '0'..='9' => c.to_digit(10).unwrap_or(0),
            'A'..='Z' => u32::from(c) - u32::from('A') + 10,
            _ => return false,
        };
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem == 1
}

struct Hit {
    start: usize,
    end: usize,
    entity: RedactEntity,
}

fn find_all(text: &str, entity: RedactEntity, opts: &RedactOptions, out: &mut Vec<Hit>) {
    let mut add = |re: &Option<Regex>, ok: &dyn Fn(&str) -> bool| {
        if let Some(re) = re {
            for m in re.find_iter(text) {
                if ok(m.as_str()) {
                    out.push(Hit {
                        start: m.start(),
                        end: m.end(),
                        entity,
                    });
                }
            }
        }
    };
    match entity {
        RedactEntity::Email => add(&EMAIL, &|_| true),
        RedactEntity::Phone => {
            add(&PHONE, &|s| (9..=15).contains(&digits(s).len()));
            if opts.mode == RedactMode::Aggressive {
                add(&BARE_PHONE, &|_| true);
            }
        }
        RedactEntity::Financial => {
            add(&CARD, &|s| luhn(&digits(s)));
            add(&IBAN, &iban_ok);
        }
        RedactEntity::Secret => add(&SECRET, &|_| true),
        RedactEntity::Person | RedactEntity::Location => {}
    }
}

/// Redact `text`.
#[must_use]
pub fn redact(text: &str, opts: &RedactOptions) -> Redaction {
    let wanted: Vec<RedactEntity> = if opts.entities.is_empty() {
        RedactEntity::ALL.to_vec()
    } else {
        opts.entities.iter().copied().collect()
    };
    let unsupported: Vec<RedactEntity> = wanted
        .iter()
        .copied()
        .filter(|e| matches!(e, RedactEntity::Person | RedactEntity::Location))
        .collect();
    let mut hits: Vec<Hit> = Vec::new();
    for e in &wanted {
        find_all(text, *e, opts, &mut hits);
    }
    // earliest first, longest first on a tie; drop overlaps
    hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out = String::with_capacity(text.len());
    let mut counts: BTreeMap<RedactEntity, usize> = BTreeMap::new();
    let mut at = 0usize;
    for h in hits {
        if h.start < at {
            continue;
        }
        out.push_str(&text[at..h.start]);
        match opts.replace_style {
            ReplaceStyle::Tag => {
                out.push('<');
                out.push_str(h.entity.name());
                out.push('>');
            }
            ReplaceStyle::Mask => {
                out.extend(
                    text[h.start..h.end]
                        .chars()
                        .map(|c| if c.is_whitespace() { c } else { '*' }),
                )
            }
            ReplaceStyle::Remove => {}
        }
        *counts.entry(h.entity).or_default() += 1;
        at = h.end;
    }
    out.push_str(&text[at..]);
    Redaction {
        text: out,
        counts,
        unsupported,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // Synthetic detector canary: the cloud-key-shaped key is assembled from parts.
    const SAMPLE: &str = concat!(
        "Mail jane.doe@example.com or call +1 415-555-0132. Card 4111 1111 1111 1111, \
        IBAN GB82 WEST 1234 5698 7654 32, key AKIA",
        "IOSFODNN7EXAMPLE, year 2024, order 1234567."
    );

    #[test]
    fn tags_every_supported_entity() {
        let r = redact(SAMPLE, &RedactOptions::default());
        assert!(r.text.contains("<EMAIL>"), "{}", r.text);
        assert!(r.text.contains("<PHONE>"), "{}", r.text);
        assert_eq!(r.text.matches("<FINANCIAL>").count(), 2, "{}", r.text);
        assert!(r.text.contains("<SECRET>"), "{}", r.text);
        assert!(r.text.contains("year 2024, order 1234567"), "{}", r.text);
        assert_eq!(r.unsupported, vec![RedactEntity::Person, RedactEntity::Location]);
        assert_eq!(r.counts.get(&RedactEntity::Financial), Some(&2));
    }

    #[test]
    fn luhn_failure_is_not_a_card() {
        let r = redact("number 4111 1111 1111 1112 here", &RedactOptions::default());
        assert!(!r.text.contains("<FINANCIAL>"), "{}", r.text);
    }

    #[test]
    fn entity_filter_and_styles() {
        let mut o = RedactOptions::default();
        o.entities.insert(RedactEntity::Email);
        o.replace_style = ReplaceStyle::Mask;
        let r = redact(SAMPLE, &o);
        assert!(r.text.contains("Mail ******************** or"), "{}", r.text);
        assert!(r.text.contains("415-555-0132"), "{}", r.text);
        assert!(r.unsupported.is_empty());
        o.replace_style = ReplaceStyle::Remove;
        let r = redact("a@b.co x", &o);
        assert_eq!(r.text, " x");
    }

    #[test]
    fn aggressive_catches_bare_digit_runs() {
        let text = "id 4155550132 end";
        assert_eq!(redact(text, &RedactOptions::default()).text, text);
        let o = RedactOptions {
            mode: RedactMode::Aggressive,
            ..RedactOptions::default()
        };
        assert_eq!(redact(text, &o).text, "id <PHONE> end");
    }
}
