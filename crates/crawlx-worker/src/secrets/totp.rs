//! `totp://<base32-secret>[?digits=6&period=30&algo=sha1]`: a one-time code (RFC 6238 over
//! HOTP, RFC 4226) for MFA through a test account's shared secret (login hygiene). Time comes from the injected [`Clock`], so the resolver never
//! reads the wall clock itself and tests are exact against the RFC 6238 Appendix B vectors.

use super::{strip_scheme, SecretError};
use async_trait::async_trait;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{Clock, CoreError};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

/// HMAC hash of a TOTP secret (`algo=` parameter).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (RFC 6238 default; what authenticator apps use).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl FromStr for TotpAlgorithm {
    type Err = SecretError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(SecretError::Totp("algo must be sha1, sha256 or sha512")),
        }
    }
}

/// Parsed `totp://` reference: the shared secret and its parameters.
struct TotpSpec {
    key: zeroize::Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algo: TotpAlgorithm,
}

const MIN_DIGITS: u32 = 6;
const MAX_DIGITS: u32 = 8;
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u64 = 30;

impl TotpSpec {
    fn parse(reference: &CredentialRef) -> Result<Self, SecretError> {
        let rest = strip_scheme(reference, "totp")?;
        let (secret, query) = rest.split_once('?').unwrap_or((rest, ""));
        let normalized: String = secret
            .chars()
            .filter(|c| !matches!(c, ' ' | '-'))
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let key = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &normalized)
            .map(zeroize::Zeroizing::new)
            .ok_or(SecretError::Totp("secret is not base32"))?;
        if key.is_empty() {
            return Err(SecretError::Totp("secret is empty"));
        }
        let mut spec = Self {
            key,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            algo: TotpAlgorithm::default(),
        };
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair
                .split_once('=')
                .ok_or(SecretError::Totp("query parameters are key=value"))?;
            match k {
                "digits" => {
                    spec.digits = v
                        .parse()
                        .ok()
                        .filter(|d| (MIN_DIGITS..=MAX_DIGITS).contains(d))
                        .ok_or(SecretError::Totp("digits must be 6..=8"))?;
                }
                "period" => {
                    spec.period = v
                        .parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or(SecretError::Totp("period must be a positive number of seconds"))?;
                }
                "algo" | "algorithm" => spec.algo = v.parse()?,
                _ => return Err(SecretError::Totp("unknown query parameter")),
            }
        }
        Ok(spec)
    }
}

/// Resolves `totp://` references to the code valid at the injected clock's `now`.
#[derive(Clone)]
pub struct TotpResolver {
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for TotpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpResolver")
    }
}

impl TotpResolver {
    /// Resolver whose time steps are computed from `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    /// The code valid now, zero-padded to `digits`.
    ///
    /// # Errors
    /// [`SecretError::UnsupportedScheme`] for another scheme, [`SecretError::Totp`] for a
    /// malformed reference (the reference is never echoed, it contains the secret),
    /// [`SecretError::ClockBeforeEpoch`] when the clock is before 1970.
    pub fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let spec = TotpSpec::parse(reference)?;
        let now = u64::try_from(self.clock.now().timestamp()).map_err(|_| SecretError::ClockBeforeEpoch)?;
        let code = totp_at(&spec, now)?;
        let width = usize::try_from(spec.digits).map_err(|_| SecretError::Totp("digits must be 6..=8"))?;
        Ok(SecretOr::secret(format!("{code:0width$}")))
    }
}

#[async_trait]
impl SecretResolver for TotpResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference)?)
    }
}

/// RFC 6238: HOTP over the time step `unix_seconds / period`.
fn totp_at(spec: &TotpSpec, unix_seconds: u64) -> Result<u32, SecretError> {
    let counter = unix_seconds / spec.period;
    match spec.algo {
        TotpAlgorithm::Sha1 => hotp::<Hmac<sha1::Sha1>>(&spec.key, counter, spec.digits),
        TotpAlgorithm::Sha256 => hotp::<Hmac<sha2::Sha256>>(&spec.key, counter, spec.digits),
        TotpAlgorithm::Sha512 => hotp::<Hmac<sha2::Sha512>>(&spec.key, counter, spec.digits),
    }
}

/// RFC 4226 §5.3: HMAC over the big-endian counter, dynamic truncation, modulo 10^digits.
fn hotp<M: Mac + KeyInit>(key: &[u8], counter: u64, digits: u32) -> Result<u32, SecretError> {
    let mut mac = <M as KeyInit>::new_from_slice(key)
        .map_err(|_| SecretError::Totp("secret length is not accepted"))?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[hash.len() - 1] & 0x0f);
    let binary = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let modulus = 10_u32
        .checked_pow(digits)
        .ok_or(SecretError::Totp("digits must be 6..=8"))?;
    Ok(binary % modulus)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::time::ManualClock;

    /// RFC 6238 Appendix B secrets: ASCII `1234567890` repeated to 20, 32 and 64 bytes.
    fn secret_b32(len: usize) -> String {
        let bytes: Vec<u8> = b"1234567890".iter().copied().cycle().take(len).collect();
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    fn at(unix_seconds: i64) -> crawlx_core::Timestamp {
        chrono::DateTime::from_timestamp(unix_seconds, 0).unwrap()
    }

    fn code_at(reference: &str, unix_seconds: i64) -> String {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(at(unix_seconds)));
        let r = TotpResolver::new(clock);
        let v = r.lookup(&CredentialRef(reference.to_owned())).unwrap();
        assert!(v.is_secret());
        v.expose().clone()
    }

    #[test]
    fn rfc6238_appendix_b_sha1_vectors() {
        let reference = format!("totp://{}?digits=8", secret_b32(20));
        assert_eq!(secret_b32(20), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        for (t, expected) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(code_at(&reference, t), expected, "t={t}");
        }
    }

    #[test]
    fn rfc6238_appendix_b_sha256_and_sha512_vectors() {
        let r256 = format!("totp://{}?digits=8&algo=sha256", secret_b32(32));
        let r512 = format!("totp://{}?digits=8&algo=SHA512", secret_b32(64));
        for (t, e256, e512) in [
            (59, "46119246", "90693936"),
            (1_111_111_109, "68084774", "25091201"),
            (1_111_111_111, "67062674", "99943326"),
            (1_234_567_890, "91819424", "93441116"),
            (2_000_000_000, "90698825", "38618901"),
            (20_000_000_000, "77737706", "47863826"),
        ] {
            assert_eq!(code_at(&r256, t), e256, "sha256 t={t}");
            assert_eq!(code_at(&r512, t), e512, "sha512 t={t}");
        }
    }

    #[test]
    fn defaults_period_and_digits_variants() {
        let s = secret_b32(20);
        // defaults: 6 digits, 30 s, sha1 — the last six of the 8-digit vector
        assert_eq!(code_at(&format!("totp://{s}"), 59), "287082");
        // same time step as t=59 until the step boundary
        assert_eq!(code_at(&format!("totp://{s}"), 30), "287082");
        assert_ne!(code_at(&format!("totp://{s}"), 60), "287082");
        // period=60 → counter 0 for t=59 (same as t=0), not counter 1
        assert_eq!(
            code_at(&format!("totp://{s}?period=60"), 59),
            code_at(&format!("totp://{s}?period=60"), 0)
        );
        assert_ne!(
            code_at(&format!("totp://{s}?period=60"), 59),
            code_at(&format!("totp://{s}"), 59)
        );
        // digits=7 is the 8-digit code without its leading digit
        assert_eq!(code_at(&format!("totp://{s}?digits=7"), 59), "4287082");
        // leading zeros are kept
        assert_eq!(
            code_at(&format!("totp://{s}?digits=8"), 1_111_111_109),
            "07081804"
        );
        // lowercase, spaces, dashes and padding in the secret are accepted
        let spaced = "gezd gnbv-gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(code_at(&format!("totp://{spaced}?digits=8"), 59), "94287082");
        let padded = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGE======";
        assert!(!code_at(&format!("totp://{padded}"), 59).is_empty());
    }

    #[test]
    fn malformed_references_are_typed_and_never_echoed() {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(at(59)));
        let r = TotpResolver::new(clock);
        let check = |reference: &str| {
            let err = r.lookup(&CredentialRef(reference.to_owned())).err().unwrap();
            assert!(matches!(err, SecretError::Totp(_)), "{reference}: {err}");
            let core = CoreError::from(err).to_string();
            assert!(!core.contains("GEZD") && !core.contains("1!"), "{core}");
        };
        check("totp://1!notbase32");
        check("totp://");
        check("totp://GEZDGNBVGY3TQOJQ?digits=5");
        check("totp://GEZDGNBVGY3TQOJQ?digits=9");
        check("totp://GEZDGNBVGY3TQOJQ?period=0");
        check("totp://GEZDGNBVGY3TQOJQ?algo=md5");
        check("totp://GEZDGNBVGY3TQOJQ?window=1");
        check("totp://GEZDGNBVGY3TQOJQ?digits");
        assert!(matches!(
            r.lookup(&CredentialRef("env://X".to_owned())),
            Err(SecretError::UnsupportedScheme { .. })
        ));
        assert_eq!(format!("{r:?}"), "TotpResolver");
    }

    #[test]
    fn clock_before_epoch_is_an_error() {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(at(-1)));
        let r = TotpResolver::new(clock);
        assert!(matches!(
            r.lookup(&CredentialRef(format!("totp://{}", secret_b32(20)))),
            Err(SecretError::ClockBeforeEpoch)
        ));
    }
}
