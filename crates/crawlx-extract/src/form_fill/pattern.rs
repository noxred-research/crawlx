//! The HTML `pattern` attribute: test a candidate value and, when it does
//! not conform, generate one that does.
//!
//! The reference implementation (`matchPattern`) anchors the pattern as
//! `^(?:pattern)$`, keeps a conforming value and otherwise asks a fake-data
//! regex generator for one, ignoring patterns its engine cannot parse. This
//! module does the same with the `regex` crate for matching and a bounded
//! walk of the pattern's HIR for generation, drawing from a seeded stream so
//! the output is reproducible. Patterns using syntax the `regex` crate lacks
//! (look-around, back-references) fail to compile and are ignored.

use rand_chacha::ChaCha8Rng;
use regex::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, ClassUnicode, Hir, HirKind};

use super::values::pick;

/// Longest pattern accepted; a page controls this text.
const MAX_PATTERN_LEN: usize = 1024;
/// Generated values never exceed this many bytes.
const MAX_GENERATED: usize = 512;
/// Generation steps allowed per attempt (bounds nested empty repetitions).
const MAX_STEPS: usize = 4_096;
/// Extra repetitions drawn above the minimum of an unbounded repeat.
const UNBOUNDED_EXTRA: u32 = 8;
/// Generation attempts per request.
const ATTEMPTS: usize = 8;

pub(super) struct Pattern {
    re: Regex,
    hir: Hir,
}

impl Pattern {
    /// Compile `src` as an anchored pattern, `None` when it is too long or the engine rejects it.
    pub(super) fn new(src: &str) -> Option<Self> {
        if src.len() > MAX_PATTERN_LEN {
            return None;
        }
        let anchored = format!("^(?:{src})$");
        let re = RegexBuilder::new(&anchored)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .ok()?;
        let hir = regex_syntax::Parser::new().parse(&anchored).ok()?;
        Some(Self { re, hir })
    }

    pub(super) fn is_match(&self, value: &str) -> bool {
        self.re.is_match(value)
    }

    /// A value matching the pattern with at most `max_chars` characters (when given), drawn from `rng`.
    pub(super) fn generate(&self, rng: &mut ChaCha8Rng, max_chars: Option<usize>) -> Option<String> {
        let limit = max_chars.map_or(MAX_GENERATED, |m| m.min(MAX_GENERATED));
        for _ in 0..ATTEMPTS {
            let mut out = String::new();
            let mut steps = MAX_STEPS;
            if walk(&self.hir, rng, &mut out, &mut steps, limit).is_none() {
                continue;
            }
            if self.is_match(&out) && max_chars.is_none_or(|m| out.chars().count() <= m) {
                return Some(out);
            }
        }
        None
    }
}

/// Append one random member of `hir` to `out`, keeping `out` within `limit`
/// bytes where repetition counts allow; `None` when a budget ran out.
fn walk(hir: &Hir, rng: &mut ChaCha8Rng, out: &mut String, steps: &mut usize, limit: usize) -> Option<()> {
    *steps = steps.checked_sub(1)?;
    if out.len() > limit {
        return None;
    }
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(lit) => out.push_str(&String::from_utf8_lossy(&lit.0)),
        HirKind::Class(Class::Unicode(cls)) => out.push(pick_char(cls, rng)?),
        HirKind::Class(Class::Bytes(cls)) => {
            let ranges = cls.ranges();
            let r = ranges.get(pick(rng, ranges.len()))?;
            let span = usize::from(r.end() - r.start()) + 1;
            let offset = u8::try_from(pick(rng, span)).ok()?;
            out.push(char::from(r.start().checked_add(offset)?));
        }
        HirKind::Capture(cap) => walk(&cap.sub, rng, out, steps, limit)?,
        HirKind::Concat(parts) => {
            for part in parts {
                walk(part, rng, out, steps, limit)?;
            }
        }
        HirKind::Alternation(branches) => {
            walk(branches.get(pick(rng, branches.len()))?, rng, out, steps, limit)?;
        }
        HirKind::Repetition(rep) => {
            let upper = rep.max.unwrap_or_else(|| rep.min.saturating_add(UNBOUNDED_EXTRA));
            let mut upper = upper.min(rep.min.saturating_add(UNBOUNDED_EXTRA));
            // Do not draw more repetitions than still fit.
            let sub_min = rep.sub.properties().minimum_len().unwrap_or(0);
            if let Some(fits) = limit.saturating_sub(out.len()).checked_div(sub_min) {
                upper = upper.min(u32::try_from(fits).unwrap_or(u32::MAX));
            }
            let upper = upper.max(rep.min);
            let span = usize::try_from(upper - rep.min).ok()? + 1;
            let count = rep.min + u32::try_from(pick(rng, span)).ok()?;
            for _ in 0..count {
                walk(&rep.sub, rng, out, steps, limit)?;
            }
        }
    }
    Some(())
}

/// A character of `cls`, preferring ASCII letters and digits, then other
/// printable ASCII, then whatever the class holds.
fn pick_char(cls: &ClassUnicode, rng: &mut ChaCha8Rng) -> Option<char> {
    const ALNUM: &[(u32, u32)] = &[(0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A)];
    const PRINTABLE: &[(u32, u32)] = &[(0x21, 0x7E)];
    let ranges: Vec<(u32, u32)> = cls
        .ranges()
        .iter()
        .map(|r| (u32::from(r.start()), u32::from(r.end())))
        .collect();
    for windows in [ALNUM, PRINTABLE] {
        let total: u64 = ranges
            .iter()
            .map(|&(lo, hi)| {
                windows
                    .iter()
                    .map(|&(wl, wh)| overlap(lo, hi, wl, wh))
                    .sum::<u64>()
            })
            .sum();
        if total == 0 {
            continue;
        }
        let mut k = u64::try_from(pick(rng, usize::try_from(total).ok()?)).ok()?;
        for &(lo, hi) in &ranges {
            for &(wl, wh) in windows {
                let n = overlap(lo, hi, wl, wh);
                if k < n {
                    return char::from_u32(lo.max(wl) + u32::try_from(k).ok()?);
                }
                k -= n;
            }
        }
    }
    // No ASCII member: the first member that is a valid scalar value.
    let &(lo, hi) = ranges.first()?;
    let span = usize::try_from(hi - lo).ok()?.min(63) + 1;
    let offset = u32::try_from(pick(rng, span)).ok()?;
    char::from_u32(lo + offset).or_else(|| char::from_u32(lo))
}

fn overlap(lo: u32, hi: u32, wl: u32, wh: u32) -> u64 {
    let start = lo.max(wl);
    let end = hi.min(wh);
    if start <= end {
        u64::from(end - start) + 1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::seed::CrawlSeed;

    fn rng(n: u64) -> ChaCha8Rng {
        CrawlSeed(n).rng("test", &[])
    }

    #[test]
    fn generated_values_match_their_pattern() {
        for src in [
            r"[A-Z]{3}-\d{4}",
            r"[a-z]+@[a-z]+\.(com|org)",
            r"\d{3}-\d{3}-\d{4}",
            r"(?i)yes|no",
            r"[^a-z]{2}",
            r"\w{4,8}",
            r"https?://[a-z]{3,10}\.test",
        ] {
            let p = Pattern::new(src).unwrap();
            for seed in 0..8 {
                let v = p.generate(&mut rng(seed), None).unwrap();
                assert!(p.is_match(&v), "{src}: {v:?}");
            }
        }
    }

    #[test]
    fn same_seed_same_value_different_seed_differs() {
        let p = Pattern::new(r"[a-z0-9]{12}").unwrap();
        let a = p.generate(&mut rng(1), None).unwrap();
        assert_eq!(a, p.generate(&mut rng(1), None).unwrap());
        assert_ne!(a, p.generate(&mut rng(2), None).unwrap());
    }

    #[test]
    fn max_chars_bounds_the_value() {
        let p = Pattern::new(r"[a-z]{1,40}").unwrap();
        for seed in 0..16 {
            let v = p.generate(&mut rng(seed), Some(5)).unwrap();
            assert!(v.chars().count() <= 5, "{v:?}");
        }
        // No value of the pattern fits in 3 characters.
        assert!(Pattern::new(r"[a-z]{6}")
            .unwrap()
            .generate(&mut rng(1), Some(3))
            .is_none());
    }

    #[test]
    fn unsupported_and_oversized_patterns_are_ignored() {
        assert!(Pattern::new(r"(?=a)a").is_none());
        assert!(Pattern::new(r"(a)\1").is_none());
        assert!(Pattern::new(&"a".repeat(MAX_PATTERN_LEN + 1)).is_none());
    }

    #[test]
    fn nested_empty_repetition_is_bounded() {
        let p = Pattern::new(r"((((()*)*)*)*)*x").unwrap();
        // Must terminate quickly whatever it returns.
        let _ = p.generate(&mut rng(1), None);
    }

    #[test]
    fn anchoring_is_implicit() {
        let p = Pattern::new(r"[a-z]{3}").unwrap();
        assert!(p.is_match("abc"));
        assert!(!p.is_match("abcd"));
        assert!(!p.is_match("xabc"));
    }
}
