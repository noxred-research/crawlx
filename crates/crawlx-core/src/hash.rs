//! BLAKE3 digests with domain separation. Every persisted hash in crawlx is
//! `BLAKE3(domain_tag || canonical bytes)` so identical bytes in different
//! roles never collide.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A 32-byte BLAKE3 digest. Serializes as lowercase hex in human-readable
/// formats (JSON, TOML) and as raw bytes in binary ones (CBOR), so canonical
/// CBOR hashing is unaffected while JSON stays readable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <serde_bytes_like::ByteBuf>::deserialize(d)?;
            let arr: [u8; 32] = bytes
                .0
                .as_slice()
                .try_into()
                .map_err(|_| serde::de::Error::invalid_length(bytes.0.len(), &"32 bytes"))?;
            Ok(Self(arr))
        }
    }
}

/// Minimal byte-buffer visitor so binary formats round-trip without the
/// `serde_bytes` dependency.
mod serde_bytes_like {
    use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
    use std::fmt;

    pub struct ByteBuf(pub Vec<u8>);

    impl<'de> Deserialize<'de> for ByteBuf {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = ByteBuf;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v.to_vec()))
                }
                fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ByteBuf, A::Error> {
                    let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(32));
                    while let Some(b) = seq.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(ByteBuf(out))
                }
            }
            d.deserialize_bytes(V)
        }
    }
}

impl Digest {
    /// Hash `bytes` under `domain`.
    #[must_use]
    pub fn of(domain: &str, bytes: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(domain.as_bytes());
        h.update(&[0]);
        h.update(bytes);
        Self(*h.finalize().as_bytes())
    }

    /// Keyed hash (for correlation hashes of redacted values).
    #[must_use]
    pub fn keyed(key: &[u8; 32], domain: &str, bytes: &[u8]) -> Self {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update(domain.as_bytes());
        h.update(&[0]);
        h.update(bytes);
        Self(*h.finalize().as_bytes())
    }

    /// Hash a serializable value through canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns the CBOR error if `value` fails to serialize.
    pub fn of_value<T: Serialize>(
        domain: &str,
        value: &T,
    ) -> Result<Self, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf)?;
        Ok(Self::of(domain, &buf))
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use std::fmt::Write as _;
            // writing to a String cannot fail
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// First 16 bytes, for compact ids.
    #[must_use]
    pub fn truncate16(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.0[..16]);
        out
    }

    /// Parse lowercase/uppercase hex.
    ///
    /// # Errors
    ///
    /// Returns [`HexError::Length`] unless `s` is exactly 64 bytes long, and
    /// [`HexError::Char`] if it contains a non-hex character.
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        if s.len() != 64 {
            return Err(HexError::Length(s.len()));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or(HexError::Char)?;
            let lo = hex_val(chunk[1]).ok_or(HexError::Char)?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Hex decoding failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexError {
    /// Input length is not 64; carries the length received.
    #[error("expected 64 hex characters, got {0}")]
    Length(usize),
    /// Input contains a character outside `0-9a-fA-F`.
    #[error("non-hex character")]
    Char,
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn domain_separates() {
        assert_ne!(Digest::of("a", b"x"), Digest::of("b", b"x"));
        assert_eq!(Digest::of("a", b"x"), Digest::of("a", b"x"));
    }

    #[test]
    fn hex_roundtrip() {
        let d = Digest::of("t", b"hello");
        assert_eq!(Digest::from_hex(&d.to_hex()), Ok(d));
        assert_eq!(Digest::from_hex("zz"), Err(HexError::Length(2)));
    }
}
