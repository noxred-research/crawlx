//! Pure parts of the host checks (`scope.hostChecks`): the probe path and the classifiers.
//!
//! Nothing here sends a request or reads a clock. The probe path derives from the run seed, so a
//! run repeated under the same seed asks the same question.

use crawlx_core::host_checks::HostCheckVerdict;
use crawlx_core::seed::CrawlSeed;

/// Bytes of the run-seed derivation used as the probe path.
const PROBE_BYTES: usize = 16;

/// Path of the soft-404 probe for `origin`: `/crawlx-absent-` followed by 32 lowercase hex digits
/// derived from the run seed and the origin. The same seed and origin give the same path;
/// another origin or seed gives another.
#[must_use]
pub fn soft_404_probe_path(seed: CrawlSeed, origin: &str) -> String {
    let derived = seed.derive("host-check/soft-404", &[origin.as_bytes()]);
    let mut path = String::from("/crawlx-absent-");
    for byte in &derived[..PROBE_BYTES] {
        path.push(hex_digit(byte >> 4));
        path.push(hex_digit(byte & 0x0f));
    }
    path
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

/// Classify the answer to the soft-404 probe from its status.
///
/// A 2xx answer for a path nothing links to is `soft_404`; 404 and 410 are `not_soft_404`.
/// Every other status (redirects, 401, 403, other 4xx, 5xx) and a missing answer (timeout,
/// refusal, no request) is `inconclusive`.
#[must_use]
pub const fn classify_soft_404(status: Option<u16>) -> HostCheckVerdict {
    match status {
        Some(200..=299) => HostCheckVerdict::Soft404,
        Some(404 | 410) => HostCheckVerdict::NotSoft404,
        _ => HostCheckVerdict::Inconclusive,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn status_table() {
        let table: &[(Option<u16>, HostCheckVerdict)] = &[
            (Some(200), HostCheckVerdict::Soft404),
            (Some(204), HostCheckVerdict::Soft404),
            (Some(299), HostCheckVerdict::Soft404),
            (Some(404), HostCheckVerdict::NotSoft404),
            (Some(410), HostCheckVerdict::NotSoft404),
            (Some(100), HostCheckVerdict::Inconclusive),
            (Some(301), HostCheckVerdict::Inconclusive),
            (Some(302), HostCheckVerdict::Inconclusive),
            (Some(304), HostCheckVerdict::Inconclusive),
            (Some(400), HostCheckVerdict::Inconclusive),
            (Some(401), HostCheckVerdict::Inconclusive),
            (Some(403), HostCheckVerdict::Inconclusive),
            (Some(405), HostCheckVerdict::Inconclusive),
            (Some(429), HostCheckVerdict::Inconclusive),
            (Some(500), HostCheckVerdict::Inconclusive),
            (Some(503), HostCheckVerdict::Inconclusive),
            (None, HostCheckVerdict::Inconclusive),
        ];
        for (status, expected) in table {
            assert_eq!(classify_soft_404(*status), *expected, "status {status:?}");
        }
    }

    #[test]
    fn probe_path_is_reproducible_wide_and_origin_bound() {
        let origin = "http://127.0.0.1:8080";
        let path = soft_404_probe_path(CrawlSeed(7), origin);
        assert_eq!(path, soft_404_probe_path(CrawlSeed(7), origin));
        assert_ne!(path, soft_404_probe_path(CrawlSeed(8), origin));
        assert_ne!(path, soft_404_probe_path(CrawlSeed(7), "http://127.0.0.1:8081"));
        let digits = path.strip_prefix("/crawlx-absent-").unwrap();
        assert_eq!(digits.len(), 32, "32 hex digits");
        assert!(digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    #[test]
    fn probe_path_survives_url_parsing_unchanged() {
        let path = soft_404_probe_path(CrawlSeed(1), "https://example.test");
        let url = url::Url::parse(&format!("https://example.test{path}")).unwrap();
        assert_eq!(url.path(), path);
        assert_eq!(url.query(), None);
    }

    #[test]
    fn hex_digits_cover_the_alphabet() {
        let all: String = (0..16).map(hex_digit).collect();
        assert_eq!(all, "0123456789abcdef");
    }
}
