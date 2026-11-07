//! Seeded value generators and the `rand_*` helper subset of katana's
//! form-config DSL.
//!
//! Katana evaluates `-fc` values such as `rand_email()` through the
//! projectdiscovery/dsl expression engine. crawlx evaluates nothing: a value
//! is either a literal or exactly one call of a known helper with literal
//! arguments, and every random draw comes from a ChaCha stream derived from
//! the run seed (`CrawlSeed::rng`), so the same config under the same seed
//! always resolves to the same value. A call crawlx does not know (or whose
//! arguments do not parse) stays a literal string, as katana does when its
//! expression fails to evaluate.

use crawlx_core::seed::CrawlSeed;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;

const DSL_PURPOSE: &str = "extract/form_fill/dsl/v1";
const VALUE_PURPOSE: &str = "extract/form_fill/value/v1";
/// Domain of generated addresses (RFC 2606: never routable).
const EMAIL_DOMAIN: &str = "example.org";
/// Longest value a helper may generate.
const MAX_LEN: usize = 256;
const DEFAULT_PASSWORD_LEN: usize = 14;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&*+-=?@^_";

const FIRST_NAMES: &[&str] = &[
    "Alice", "Bruno", "Carla", "Dmitri", "Elena", "Farid", "Greta", "Hiro", "Ines", "Jonas", "Katya", "Liam",
    "Mira", "Nikolai", "Olga", "Pedro", "Quinn", "Rosa", "Sven", "Tara", "Umar", "Vera", "Wen", "Yara",
];
const LAST_NAMES: &[&str] = &[
    "Andersson",
    "Barros",
    "Chen",
    "Dubois",
    "Eriksen",
    "Fischer",
    "Garcia",
    "Haddad",
    "Ivanov",
    "Jensen",
    "Kowalski",
    "Lopez",
    "Moreau",
    "Nakamura",
    "Okafor",
    "Petrov",
    "Rossi",
    "Silva",
    "Tanaka",
    "Weber",
];

/// Uniform index in `0..n` (`n == 0` gives 0). Only `u64 % n` draws, so the
/// stream maps to the same value on every platform.
pub(super) fn pick(rng: &mut ChaCha8Rng, n: usize) -> usize {
    let Ok(n64) = u64::try_from(n) else {
        return 0;
    };
    if n64 == 0 {
        return 0;
    }
    usize::try_from(rng.next_u64() % n64).unwrap_or(0)
}

fn chars_from(rng: &mut ChaCha8Rng, alphabet: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| char::from(alphabet[pick(rng, alphabet.len())]))
        .collect()
}

fn alnum(rng: &mut ChaCha8Rng, len: usize) -> String {
    let alphabet: Vec<u8> = LOWER.iter().chain(DIGITS).copied().collect();
    chars_from(rng, &alphabet, len)
}

fn rng_for(seed: &CrawlSeed, class: &str) -> ChaCha8Rng {
    seed.rng(VALUE_PURPOSE, &[class.as_bytes()])
}

/// Default email: `<12 lowercase alphanumerics>@example.org`, one per run.
pub(super) fn default_email(seed: &CrawlSeed) -> String {
    let mut rng = rng_for(seed, "email");
    email(&mut rng)
}

fn email(rng: &mut ChaCha8Rng) -> String {
    format!("{}@{EMAIL_DOMAIN}", alnum(rng, 12))
}

/// Default phone: a fictional North-American number (`212-555-01NN`).
pub(super) fn default_phone(seed: &CrawlSeed) -> String {
    let mut rng = rng_for(seed, "phone");
    phone(&mut rng)
}

fn phone(rng: &mut ChaCha8Rng) -> String {
    format!("21255501{}", chars_from(rng, DIGITS, 2))
}

/// Default password: 14 characters with every class (upper, lower, digit, symbol).
pub(super) fn default_password(seed: &CrawlSeed) -> String {
    let mut rng = rng_for(seed, "password");
    password(&mut rng, DEFAULT_PASSWORD_LEN)
}

fn password(rng: &mut ChaCha8Rng, len: usize) -> String {
    let all: Vec<u8> = [LOWER, UPPER, DIGITS, SYMBOLS].concat();
    let mut out: Vec<char> = (0..len).map(|_| char::from(all[pick(rng, all.len())])).collect();
    // Seat one of each class at a seeded position so policies that demand a
    // class are met whenever the length allows it.
    for (slot, class) in [LOWER, UPPER, DIGITS, SYMBOLS].into_iter().enumerate() {
        if let Some(cell) = out.get_mut(slot) {
            *cell = char::from(class[pick(rng, class.len())]);
        }
    }
    // Fisher-Yates so the seated characters do not always lead.
    for i in (1..out.len()).rev() {
        out.swap(i, pick(rng, i + 1));
    }
    out.into_iter().collect()
}

/// Default colour: `#rrggbb`.
pub(super) fn default_color(seed: &CrawlSeed) -> String {
    let mut rng = rng_for(seed, "color");
    format!("#{}", chars_from(&mut rng, b"0123456789abcdef", 6))
}

/// Filler for a text input no rule classified: eight lowercase letters
/// scoped to the page and the field name.
pub(super) fn filler(seed: &CrawlSeed, page: &str, field: &str) -> String {
    let mut rng = seed.rng(VALUE_PURPOSE, &[b"filler", page.as_bytes(), field.as_bytes()]);
    chars_from(&mut rng, LOWER, 8)
}

/// Resolve a `-fc` value of `class` (`email`, `phone`, ...): a literal
/// stays as is, a known `rand_*` call is evaluated with a stream derived
/// from `seed`, `class` and the expression text.
pub(super) fn resolve(value: &str, seed: &CrawlSeed, class: &str) -> String {
    let Some(call) = Call::parse(value) else {
        return value.to_owned();
    };
    let mut rng = seed.rng(DSL_PURPOSE, &[class.as_bytes(), value.as_bytes()]);
    call.eval(&mut rng).unwrap_or_else(|| value.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
enum Arg {
    Int(i64),
    Text(String),
}

#[derive(Debug, PartialEq, Eq)]
struct Call<'a> {
    name: &'a str,
    args: Vec<Arg>,
}

impl<'a> Call<'a> {
    /// `name(arg, ...)` spanning the whole (trimmed) value.
    fn parse(value: &'a str) -> Option<Self> {
        let value = value.trim();
        let open = value.find('(')?;
        let inner = value.strip_suffix(')')?.get(open + 1..)?;
        let name = &value[..open];
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())
        {
            return None;
        }
        Some(Self {
            name,
            args: parse_args(inner)?,
        })
    }

    fn eval(&self, rng: &mut ChaCha8Rng) -> Option<String> {
        let len = |idx: usize, default: usize| -> Option<usize> {
            match self.args.get(idx) {
                None => Some(default),
                Some(Arg::Int(n)) => usize::try_from(*n).ok().filter(|n| (1..=MAX_LEN).contains(n)),
                Some(Arg::Text(_)) => None,
            }
        };
        match (self.name, self.args.len()) {
            ("rand_email", 0) => Some(email(rng)),
            ("rand_phone", 0) => Some(phone(rng)),
            ("rand_first_name", 0) => Some(FIRST_NAMES[pick(rng, FIRST_NAMES.len())].to_owned()),
            ("rand_last_name", 0) => Some(LAST_NAMES[pick(rng, LAST_NAMES.len())].to_owned()),
            ("rand_password", 0..=1) => Some(password(rng, len(0, DEFAULT_PASSWORD_LEN)?)),
            ("rand_text_alphanumeric", 1) => {
                let n = len(0, 0)?;
                let alphabet: Vec<u8> = [LOWER, UPPER, DIGITS].concat();
                Some(chars_from(rng, &alphabet, n))
            }
            ("rand_text_alpha", 1) => {
                let n = len(0, 0)?;
                let alphabet: Vec<u8> = [LOWER, UPPER].concat();
                Some(chars_from(rng, &alphabet, n))
            }
            ("rand_text_numeric", 1) => Some(chars_from(rng, DIGITS, len(0, 0)?)),
            // `rand_base(length[, charset])`: an empty charset means the default one.
            ("rand_base", 1..=2) => {
                let n = len(0, 0)?;
                let charset = match self.args.get(1) {
                    Some(Arg::Text(set)) if !set.is_empty() => {
                        if !set.is_ascii() {
                            return None;
                        }
                        set.as_bytes().to_vec()
                    }
                    Some(Arg::Text(_)) | None => [LOWER, UPPER, DIGITS].concat(),
                    Some(Arg::Int(_)) => return None,
                };
                Some(chars_from(rng, &charset, n))
            }
            ("rand_int", 2) => {
                let (Some(Arg::Int(lo)), Some(Arg::Int(hi))) = (self.args.first(), self.args.get(1)) else {
                    return None;
                };
                if lo > hi {
                    return None;
                }
                let span = u64::try_from(i128::from(*hi) - i128::from(*lo) + 1).ok()?;
                let offset = i128::from(rng.next_u64() % span);
                Some((i128::from(*lo) + offset).to_string())
            }
            _ => None,
        }
    }
}

/// Split `a, "b, c", 3` at top-level commas; quoted strings may use `"` or `'`.
fn parse_args(inner: &str) -> Option<Vec<Arg>> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in inner.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => {
                quote = None;
                current.push(c);
            }
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                current.push(c);
            }
            (None, ',') => {
                args.push(parse_arg(&current)?);
                current.clear();
            }
            (None, c) => current.push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    args.push(parse_arg(&current)?);
    Some(args)
}

fn parse_arg(raw: &str) -> Option<Arg> {
    let raw = raw.trim();
    for q in ['"', '\''] {
        if let Some(text) = raw.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return Some(Arg::Text(text.to_owned()));
        }
    }
    raw.parse::<i64>().ok().map(Arg::Int)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn literal_values_pass_through() {
        let seed = CrawlSeed(1);
        assert_eq!(resolve("alice@example.com", &seed, "email"), "alice@example.com");
        assert_eq!(resolve("#e66465", &seed, "color"), "#e66465");
        assert_eq!(resolve("", &seed, "email"), "");
        assert_eq!(resolve("f(x", &seed, "email"), "f(x");
    }

    #[test]
    fn unknown_or_malformed_calls_stay_literal() {
        let seed = CrawlSeed(1);
        for v in [
            "rand_nope()",
            "rand_password(0)",
            "rand_password(9999)",
            "rand_password(\"x\")",
            "rand_email(1)",
            "rand_int(5, 1)",
            "system('id')",
        ] {
            assert_eq!(resolve(v, &seed, "password"), v, "{v}");
        }
    }

    #[test]
    fn helpers_are_deterministic_and_shaped() {
        let seed = CrawlSeed(9);
        let a = resolve("rand_email()", &seed, "email");
        assert_eq!(a, resolve("rand_email()", &seed, "email"));
        assert_ne!(a, resolve("rand_email()", &CrawlSeed(10), "email"));
        assert!(a.ends_with("@example.org"), "{a}");
        assert_eq!(resolve("rand_phone()", &seed, "phone").len(), 10);
        assert!(FIRST_NAMES.contains(&resolve("rand_first_name()", &seed, "placeholder").as_str()));
        let pw = resolve("rand_password(16)", &seed, "password");
        assert_eq!(pw.len(), 16);
        assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(pw.bytes().any(|b| b.is_ascii_digit()));
        assert!(pw.bytes().any(|b| SYMBOLS.contains(&b)));
        assert_eq!(resolve(r#"rand_base(16, "")"#, &seed, "password").len(), 16);
        let hex = resolve(r#"rand_base(8, "ab")"#, &seed, "password");
        assert!(hex.bytes().all(|b| b == b'a' || b == b'b'), "{hex}");
        let n: i64 = resolve("rand_int(5, 7)", &seed, "placeholder").parse().unwrap();
        assert!((5..=7).contains(&n));
    }
}
