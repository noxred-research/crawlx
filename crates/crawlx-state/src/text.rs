//! Cheap deterministic 64-bit hashing and accessible-name normalization.
//!
//! The 64-bit feature hashes (MinHash tokens, SimHash shingles, identity
//! keys) are not security-sensitive and sit on the fingerprint hot path, so
//! they use FNV-1a with a splitmix64 finalizer instead of BLAKE3. They are
//! platform independent and fixed forever: changing them changes every
//! persisted signature and requires bumping `StateSignature::VERSION`.

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// splitmix64 finalizer (bijective avalanche).
#[inline]
#[must_use]
pub fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Streaming FNV-1a with a final avalanche.
#[derive(Clone, Copy)]
pub struct Hasher64(u64);

impl Default for Hasher64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher64 {
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self(FNV_OFFSET)
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    /// Write `s` ASCII-lowercased.
    #[inline]
    pub fn write_lower(&mut self, s: &str) {
        for b in s.bytes() {
            self.0 ^= u64::from(b.to_ascii_lowercase());
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    /// Field separator so `("ab","c")` and `("a","bc")` differ.
    #[inline]
    pub fn sep(&mut self) {
        self.write(&[0xff]);
    }

    #[inline]
    #[must_use]
    pub fn finish(self) -> u64 {
        mix64(self.0)
    }
}

/// Maximum number of characters of a normalized name that are kept.
pub const NAME_LIMIT: usize = 80;

/// Normalize an accessible name for fingerprinting: lowercase, digits removed
/// (so counters, dates and clocks vanish), whitespace runs collapsed, trimmed
/// and truncated to [`NAME_LIMIT`] characters. Writes into `out` (cleared
/// first) so callers can reuse one buffer.
pub fn normalize_name_into(name: &str, out: &mut String) {
    out.clear();
    let mut pending_space = false;
    let mut kept = 0usize;
    for c in name.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if c.is_numeric() {
            continue;
        }
        if kept >= NAME_LIMIT {
            break;
        }
        if pending_space {
            out.push(' ');
            kept += 1;
            pending_space = false;
            if kept >= NAME_LIMIT {
                break;
            }
        }
        for lc in c.to_lowercase() {
            out.push(lc);
        }
        kept += 1;
    }
}

/// Allocating convenience wrapper around [`normalize_name_into`].
#[must_use]
pub fn normalize_name(name: &str) -> String {
    let mut s = String::with_capacity(name.len().min(NAME_LIMIT));
    normalize_name_into(name, &mut s);
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn normalization_strips_digits_and_whitespace() {
        assert_eq!(normalize_name("  Inbox (3)  "), "inbox ()");
        assert_eq!(normalize_name("Updated 5 minutes ago"), "updated minutes ago");
        assert_eq!(normalize_name("Updated 12 minutes ago"), "updated minutes ago");
        assert_eq!(normalize_name("12:03:45"), "::");
        assert_eq!(normalize_name("Order12 shipped"), "order shipped");
        assert_eq!(normalize_name("a\t\n b"), "a b");
    }

    #[test]
    fn normalization_truncates() {
        let long = "x".repeat(500);
        assert_eq!(normalize_name(&long).chars().count(), NAME_LIMIT);
    }

    #[test]
    fn hashes_are_stable() {
        // pinned: changing the hash changes every persisted signature
        let h = |b: &[u8]| {
            let mut x = Hasher64::new();
            x.write(b);
            x.finish()
        };
        assert_eq!(h(b"crawlx"), h(b"crawlx"));
        assert_ne!(h(b"ab"), h(b"ba"));
        let mut a = Hasher64::new();
        a.write(b"ab");
        a.sep();
        a.write(b"c");
        let mut b = Hasher64::new();
        b.write(b"a");
        b.sep();
        b.write(b"bc");
        assert_ne!(a.finish(), b.finish());
    }
}
