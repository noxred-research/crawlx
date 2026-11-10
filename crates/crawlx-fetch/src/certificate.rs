//! Peer certificate evidence (`certificateEvidence: observed | unavailable`).
//!
//! The fetch plane reads the leaf certificate the transport already received on the
//! request's own connection. It opens no extra socket, so nothing outside the request's
//! egress check, pin set and origin admission is dialled, and the observation costs one
//! bounded copy of the certificate. A response whose certificate the transport did not
//! report carries [`CertificateEvidence::Unavailable`] with a reason: absence is never a
//! successful certificate check, and an observed certificate is never a claim that it
//! verified (the verification mode is configured separately).
//!
//! The DER reader below is deliberately minimal: it walks `Certificate -> TBSCertificate`
//! to the validity period and the issuer/subject names, rejects indefinite lengths and
//! high tag numbers, and never reads past the slice it was given.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Largest leaf certificate accepted as evidence. Longer inputs are not parsed.
pub const MAX_CERTIFICATE_BYTES: usize = 32 * 1024;

/// Why a certificate was not observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertificateUnavailable {
    /// The final response was not received over TLS.
    NotTls,
    /// The transport did not report a peer certificate (tunnelled through a SOCKS route, or
    /// no certificate was presented).
    NotReported,
    /// The reported certificate exceeded [`MAX_CERTIFICATE_BYTES`].
    TooLarge,
    /// The reported bytes were not a well-formed X.509 certificate.
    Malformed,
}

impl CertificateUnavailable {
    /// Stable machine-readable reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotTls => "not_tls",
            Self::NotReported => "not_reported",
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
        }
    }
}

/// Facts of the leaf certificate the peer presented. Contains no key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PeerCertificate {
    /// Lower-case hex SHA-256 of the DER encoding.
    pub sha256: String,
    /// Start of the validity period.
    pub not_before: DateTime<Utc>,
    /// End of the validity period.
    pub not_after: DateTime<Utc>,
    /// Issuer and subject names are byte-identical (a self-issued certificate).
    pub self_issued: bool,
    /// Length of the DER encoding.
    pub der_len: u32,
}

impl PeerCertificate {
    /// The certificate was inside its validity period at `now`. This is evidence of the
    /// dates only; chain, name and revocation checks belong to the TLS verifier.
    #[must_use]
    pub fn valid_at(&self, now: DateTime<Utc>) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

/// Separate `observed` / `unavailable` contract of the connection evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertificateEvidence {
    /// The leaf certificate was read from the request's own TLS connection.
    Observed {
        /// The observed certificate facts.
        certificate: PeerCertificate,
    },
    /// No certificate was observed.
    Unavailable {
        /// Why not.
        reason: CertificateUnavailable,
    },
}

impl CertificateEvidence {
    /// Evidence for a plain-text or otherwise certificate-free response.
    #[must_use]
    pub const fn unavailable(reason: CertificateUnavailable) -> Self {
        Self::Unavailable { reason }
    }

    /// The observed certificate, if any.
    #[must_use]
    pub const fn observed(&self) -> Option<&PeerCertificate> {
        match self {
            Self::Observed { certificate } => Some(certificate),
            Self::Unavailable { .. } => None,
        }
    }

    /// Evidence for the DER leaf certificate a transport reported (`None`: nothing reported).
    #[must_use]
    pub fn from_der(der: Option<&[u8]>) -> Self {
        let Some(der) = der else {
            return Self::unavailable(CertificateUnavailable::NotReported);
        };
        if der.len() > MAX_CERTIFICATE_BYTES {
            return Self::unavailable(CertificateUnavailable::TooLarge);
        }
        match parse(der) {
            Some(certificate) => Self::Observed { certificate },
            None => Self::unavailable(CertificateUnavailable::Malformed),
        }
    }
}

/// One DER element: tag byte and content.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Cursor over a DER byte string.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn read(&mut self) -> Option<Tlv<'a>> {
        let (&tag, rest) = self.0.split_first()?;
        if tag & 0x1f == 0x1f {
            return None; // high tag numbers never occur in the fields read here
        }
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return None; // indefinite or implausible length
            }
            let (len_bytes, rest) = rest.split_at(count);
            let len = len_bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            (len, rest)
        };
        if rest.len() < len {
            return None;
        }
        let (content, rest) = rest.split_at(len);
        self.0 = rest;
        Some(Tlv { tag, content })
    }

    /// The next element, which must carry `tag`.
    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let tlv = self.read()?;
        (tlv.tag == tag).then_some(tlv.content)
    }

    /// The next element with its whole encoding (header included).
    fn next_raw(&mut self) -> Option<(u8, &'a [u8])> {
        let before = self.0;
        let tlv = self.read()?;
        let used = before.len() - self.0.len();
        Some((tlv.tag, &before[..used]))
    }
}

fn two(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [a @ b'0'..=b'9', b @ b'0'..=b'9'] => Some(u32::from(a - b'0') * 10 + u32::from(b - b'0')),
        _ => None,
    }
}

/// `UTCTime` (`YYMMDDHHMMSSZ`, years 1950..=2049) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`).
fn parse_time(tag: u8, content: &[u8]) -> Option<DateTime<Utc>> {
    let (year, rest) = match tag {
        0x17 if content.len() == 13 => {
            let yy = two(&content[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &content[2..])
        }
        0x18 if content.len() == 15 => (two(&content[..2])? * 100 + two(&content[2..4])?, &content[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let field = |i: usize| two(rest.get(i..i + 2)?);
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, field(0)?, field(2)?)?;
    let time = date.and_hms_opt(field(4)?, field(6)?, field(8)?)?;
    Some(time.and_utc())
}

fn parse(der: &[u8]) -> Option<PeerCertificate> {
    let mut outer = Reader(der);
    let certificate = outer.expect(0x30)?;
    if !outer.0.is_empty() {
        return None; // trailing bytes after the certificate
    }
    let mut cert = Reader(certificate);
    let tbs = cert.expect(0x30)?;
    let mut tbs = Reader(tbs);
    let mut next = tbs.read()?;
    if next.tag == 0xa0 {
        next = tbs.read()?; // explicit version
    }
    if next.tag != 0x02 {
        return None; // serialNumber
    }
    tbs.expect(0x30)?; // signature algorithm
    let (issuer_tag, issuer) = tbs.next_raw()?;
    let mut validity = Reader(tbs.expect(0x30)?);
    let not_before = validity.read()?;
    let not_after = validity.read()?;
    let (subject_tag, subject) = tbs.next_raw()?;
    if issuer_tag != 0x30 || subject_tag != 0x30 || !validity.0.is_empty() {
        return None;
    }
    let not_before = parse_time(not_before.tag, not_before.content)?;
    let not_after = parse_time(not_after.tag, not_after.content)?;
    if not_after < not_before {
        return None;
    }
    Some(PeerCertificate {
        sha256: hex::encode(Sha256::digest(der)),
        not_before,
        not_after,
        self_issued: issuer == subject,
        der_len: u32::try_from(der.len()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// DER of the loopback fixture `tests/fixtures/selfsigned.crt`.
    fn fixture_der() -> Vec<u8> {
        use tokio_rustls::rustls::pki_types::pem::PemObject;
        tokio_rustls::rustls::pki_types::CertificateDer::pem_slice_iter(include_bytes!(
            "../tests/fixtures/selfsigned.crt"
        ))
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
    }

    #[test]
    fn fixture_certificate_facts_match_an_independent_decoder() {
        let evidence = CertificateEvidence::from_der(Some(&fixture_der()));
        let cert = evidence.observed().unwrap();
        // `openssl x509 -noout -fingerprint -sha256 -dates` of the committed fixture.
        assert_eq!(
            cert.sha256,
            "1bb0682e7256efceefe2d64c65a6af436cfcc6431d967774f1048d71e043d947"
        );
        assert_eq!(cert.not_before.to_rfc3339(), "2026-10-27T18:43:27+00:00");
        assert_eq!(cert.not_after.to_rfc3339(), "2126-10-03T18:43:27+00:00");
        assert!(cert.self_issued);
        assert!(cert.valid_at("2027-01-01T00:00:00Z".parse().unwrap()));
        assert!(!cert.valid_at("2026-10-26T00:00:00Z".parse().unwrap()));
    }

    #[test]
    fn absent_oversized_and_malformed_input_is_unavailable_never_observed() {
        assert_eq!(
            CertificateEvidence::from_der(None),
            CertificateEvidence::unavailable(CertificateUnavailable::NotReported)
        );
        assert_eq!(
            CertificateEvidence::from_der(Some(&vec![0x30; MAX_CERTIFICATE_BYTES + 1])),
            CertificateEvidence::unavailable(CertificateUnavailable::TooLarge)
        );
        let der = fixture_der();
        for bad in [
            &der[..der.len() - 1],
            &der[..10],
            b"".as_slice(),
            b"\x30\x80\x00\x00".as_slice(),
            b"\x1f\x30\x00".as_slice(),
        ] {
            assert_eq!(
                CertificateEvidence::from_der(Some(bad)),
                CertificateEvidence::unavailable(CertificateUnavailable::Malformed),
                "{bad:?}"
            );
        }
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(CertificateEvidence::from_der(Some(&trailing))
            .observed()
            .is_none());
    }

    #[test]
    fn time_forms_cover_both_century_rules_and_reject_garbage() {
        assert_eq!(
            parse_time(0x17, b"491231235959Z").unwrap().to_rfc3339(),
            "2049-12-31T23:59:59+00:00"
        );
        assert_eq!(
            parse_time(0x17, b"500101000000Z").unwrap().to_rfc3339(),
            "1950-01-01T00:00:00+00:00"
        );
        assert_eq!(
            parse_time(0x18, b"21260101000000Z").unwrap().to_rfc3339(),
            "2126-01-01T00:00:00+00:00"
        );
        for bad in [
            &b"2601011200Z"[..],
            b"261301000000Z",
            b"260230000000Z",
            b"26010100000aZ",
            b"260101000000+",
        ] {
            assert!(parse_time(0x17, bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn evidence_roundtrips_through_json_with_a_state_tag() {
        let evidence = CertificateEvidence::from_der(Some(&fixture_der()));
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["state"], "observed");
        assert_eq!(
            serde_json::from_value::<CertificateEvidence>(json).unwrap(),
            evidence
        );
        let none =
            serde_json::to_value(CertificateEvidence::unavailable(CertificateUnavailable::NotTls)).unwrap();
        assert_eq!(none["state"], "unavailable");
        assert_eq!(none["reason"], "not_tls");
    }
}
