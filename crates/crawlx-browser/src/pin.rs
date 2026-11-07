//! `chromium-pin.toml`: the Chromium build the workspace was validated against.
//!
//! At launch the backend compares `Browser.getVersion` with the pin and fails with
//! [`BrowserError::PinMismatch`] unless unpinned runs are allowed (development only,
//! recorded as `pinned = false`).

use crawlx_core::browser::BrowserError;
use crawlx_core::observation::BrowserBuildInfo;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Environment variable naming the pin file explicitly.
pub const PIN_FILE_ENV: &str = "CRAWLX_PIN_FILE";
/// Environment variable that allows launching an unpinned build (`1`/`true`).
pub const ALLOW_UNPINNED_ENV: &str = "CRAWLX_ALLOW_UNPINNED";
/// Pin file name searched for while walking up from the working directory.
pub const PIN_FILE_NAME: &str = "chromium-pin.toml";
/// Text of the workspace `chromium-pin.toml`, embedded at build time so test doubles report the
/// pinned build without reading the file system.
pub const REPOSITORY_PIN_TOML: &str = include_str!("../../../chromium-pin.toml");

/// Errors reading or parsing the pin file.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// No pin file exists at `CRAWLX_PIN_FILE` or in the working directory or any ancestor.
    #[error("pin file not found (searched {searched}); set {PIN_FILE_ENV}")]
    NotFound {
        /// Working directory the ancestor walk started from.
        searched: String,
    },
    /// The pin file (or the working directory) could not be read.
    #[error("cannot read pin file {path}: {reason}")]
    Read {
        /// Path of the file (`.` when the working directory itself was unreadable).
        path: String,
        /// Text of the underlying I/O error.
        reason: String,
    },
    /// The pin file is not valid TOML or lacks the `[chromium]` table / `version` key; carries the parser message.
    #[error("invalid pin file: {0}")]
    Parse(String),
    /// `chromium.version` does not have four numeric parts; carries the offending value.
    #[error("pinned version {0:?} is not a four-part Chromium version (MAJOR.MINOR.BUILD.PATCH)")]
    BadVersion(String),
}

#[derive(Deserialize)]
struct PinFile {
    chromium: PinSection,
}

#[derive(Deserialize)]
struct PinSection {
    version: String,
    #[serde(default)]
    cdp_revision: String,
    #[serde(default)]
    chromiumoxide: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    download_url: String,
    #[serde(default)]
    sha256: String,
}

/// The pinned browser build.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChromiumPin {
    /// Four-part version, e.g. `155.0.8059.84`.
    pub version: String,
    /// CDP protocol revision the generated types correspond to.
    pub cdp_revision: String,
    /// Version of the `chromiumoxide` crate (requirement string, e.g. `=0.8.0`) the CDP types come from.
    pub chromiumoxide: String,
    /// Operating system the pinned build targets, e.g. `linux`; empty if unspecified.
    pub os: String,
    /// CPU architecture the pinned build targets, e.g. `x86_64`; empty if unspecified.
    pub arch: String,
    /// Archive URL of the pinned build; empty when a packaged build is verified by version only.
    pub download_url: String,
    /// Hex SHA-256 of the archive at `download_url`; empty when none is recorded.
    pub sha256: String,
}

/// `MAJOR.MINOR.BUILD.PATCH` parsed from a version string (a `Product/` prefix is stripped).
#[must_use]
pub fn parse_version(raw: &str) -> Option<[u32; 4]> {
    let v = raw.rsplit('/').next().unwrap_or(raw).trim();
    let mut parts = v.split('.');
    let mut out = [0u32; 4];
    for slot in &mut out {
        *slot = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

impl ChromiumPin {
    /// Parse the TOML text of a pin file.
    ///
    /// # Errors
    /// Returns [`PinError::Parse`] if the text is not a valid pin file, and
    /// [`PinError::BadVersion`] if `chromium.version` is not a four-part version.
    pub fn parse(text: &str) -> Result<Self, PinError> {
        let file: PinFile = toml::from_str(text).map_err(|e| PinError::Parse(e.to_string()))?;
        let s = file.chromium;
        if parse_version(&s.version).is_none() {
            return Err(PinError::BadVersion(s.version));
        }
        Ok(Self {
            version: s.version,
            cdp_revision: s.cdp_revision,
            chromiumoxide: s.chromiumoxide,
            os: s.os,
            arch: s.arch,
            download_url: s.download_url,
            sha256: s.sha256,
        })
    }

    /// Read and parse a pin file.
    ///
    /// # Errors
    /// Returns [`PinError::Read`] if the file cannot be read, otherwise the errors of
    /// [`Self::parse`].
    pub fn load(path: &Path) -> Result<Self, PinError> {
        let text = std::fs::read_to_string(path).map_err(|e| PinError::Read {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        Self::parse(&text)
    }

    /// Find the pin file: `CRAWLX_PIN_FILE`, else `chromium-pin.toml` in the working
    /// directory or the nearest ancestor that has one.
    ///
    /// # Errors
    /// Returns [`PinError::Read`] if the working directory cannot be determined and
    /// [`PinError::NotFound`] if no pin file exists in it or any ancestor.
    pub fn locate() -> Result<PathBuf, PinError> {
        if let Some(p) = std::env::var_os(PIN_FILE_ENV) {
            return Ok(PathBuf::from(p));
        }
        let cwd = std::env::current_dir().map_err(|e| PinError::Read {
            path: ".".to_owned(),
            reason: e.to_string(),
        })?;
        for dir in cwd.ancestors() {
            let candidate = dir.join(PIN_FILE_NAME);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(PinError::NotFound {
            searched: cwd.display().to_string(),
        })
    }

    /// Locate and load the workspace pin.
    ///
    /// # Errors
    /// Returns the errors of [`Self::locate`] and [`Self::load`].
    pub fn load_default() -> Result<Self, PinError> {
        Self::load(&Self::locate()?)
    }

    /// The pin file found by [`Self::locate`], else the pin embedded in this build.
    ///
    /// An installed binary run outside a checkout verifies Chromium against the pin it
    /// was built with. An explicit `CRAWLX_PIN_FILE` that cannot be read stays an error.
    ///
    /// # Errors
    /// Returns the errors of [`Self::locate`] other than [`PinError::NotFound`], and the
    /// errors of [`Self::load`] and [`repository_pin`].
    pub fn load_or_embedded() -> Result<Self, PinError> {
        match Self::locate() {
            Ok(path) => Self::load(&path),
            Err(PinError::NotFound { .. }) => repository_pin(),
            Err(e) => Err(e),
        }
    }
}

/// The workspace pin parsed from [`REPOSITORY_PIN_TOML`].
///
/// # Errors
/// Returns the errors of [`ChromiumPin::parse`] if the embedded file is malformed.
pub fn repository_pin() -> Result<ChromiumPin, PinError> {
    ChromiumPin::parse(REPOSITORY_PIN_TOML)
}

/// Is `CRAWLX_ALLOW_UNPINNED` set to a truthy value?
#[must_use]
pub fn allow_unpinned_from_env() -> bool {
    std::env::var(ALLOW_UNPINNED_ENV).is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
}

/// Compare the pinned four-part version with the running build.
///
/// # Errors
/// Returns [`BrowserError::PinMismatch`] if either version is not four-part numeric or
/// the two differ.
pub fn verify(pin: &ChromiumPin, info: &BrowserBuildInfo) -> Result<(), BrowserError> {
    let expected = parse_version(&pin.version);
    let actual = parse_version(&info.chromium_version);
    match (expected, actual) {
        (Some(e), Some(a)) if e == a => Ok(()),
        _ => Err(BrowserError::PinMismatch {
            expected: pin.version.clone(),
            actual: info.chromium_version.clone(),
        }),
    }
}

/// Decide whether the running build counts as pinned.
///
/// `Ok(true)` when the build matches the pin, `Ok(false)` when it does not (or no pin
/// could be loaded) and unpinned runs are allowed, `Err` otherwise.
///
/// # Errors
/// Returns [`BrowserError::PinMismatch`] if the build differs from a loaded pin and unpinned
/// runs are not allowed, and [`BrowserError::Launch`] (carrying the [`PinError`] text) if no
/// pin could be loaded and unpinned runs are not allowed.
pub fn resolve_pinned(
    pin: Result<ChromiumPin, PinError>,
    info: &BrowserBuildInfo,
    allow_unpinned: bool,
) -> Result<bool, BrowserError> {
    match pin {
        Ok(pin) => match verify(&pin, info) {
            Ok(()) => Ok(true),
            Err(_) if allow_unpinned => {
                tracing::warn!(
                    pinned = %pin.version,
                    actual = %info.chromium_version,
                    "chromium build differs from chromium-pin.toml; continuing unpinned"
                );
                Ok(false)
            }
            Err(e) => Err(e),
        },
        Err(e) if allow_unpinned => {
            tracing::warn!(error = %e, "no usable chromium pin; continuing unpinned");
            Ok(false)
        }
        Err(e) => Err(BrowserError::Launch(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::LaunchProfile;

    fn pinned_version() -> String {
        repository_pin().unwrap().version
    }

    fn info(version: &str) -> BrowserBuildInfo {
        BrowserBuildInfo {
            chromium_version: version.to_owned(),
            cdp_revision: "1.3".to_owned(),
            user_agent: "ua".to_owned(),
            pinned: false,
            launch_profile: LaunchProfile::Standard,
            console_capture: true,
            attached: false,
        }
    }

    #[test]
    fn parses_pin() {
        let pin = repository_pin().unwrap();
        assert_eq!(pin.cdp_revision, "1.3");
        assert_eq!(pin.chromiumoxide, "=0.8.0");
        assert_eq!(pin.os, "linux");
        assert_eq!(pin.arch, "x86_64");
        assert!(pin.download_url.contains(&pin.version));
        assert_eq!(pin.sha256.len(), 64);
    }

    #[test]
    fn repository_pin_file_matches_the_embedded_copy() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../chromium-pin.toml");
        let pin = ChromiumPin::load(&path).unwrap();
        assert!(parse_version(&pin.version).is_some());
        assert_eq!(pin, repository_pin().unwrap());
    }

    #[test]
    fn rejects_three_part_version() {
        assert!(matches!(
            ChromiumPin::parse("[chromium]\nversion = \"154.0.8037\"\n"),
            Err(PinError::BadVersion(_))
        ));
        assert!(matches!(ChromiumPin::parse("nope"), Err(PinError::Parse(_))));
    }

    #[test]
    fn version_parsing_strips_product_prefix() {
        assert_eq!(
            parse_version("HeadlessChrome/154.0.8037.97"),
            Some([154, 0, 8037, 97])
        );
        assert_eq!(parse_version("154.0.8037.97"), Some([154, 0, 8037, 97]));
        assert_eq!(parse_version("154.0.8037"), None);
        assert_eq!(parse_version("154.0.8037.97.1"), None);
        assert_eq!(parse_version("abc"), None);
    }

    #[test]
    fn verify_matches_and_mismatches() {
        let pin = repository_pin().unwrap();
        let pinned = pinned_version();
        assert!(verify(&pin, &info(&pinned)).is_ok());
        match verify(&pin, &info("1.0.0.1")) {
            Err(BrowserError::PinMismatch { expected, actual }) => {
                assert_eq!(expected, pinned);
                assert_eq!(actual, "1.0.0.1");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(verify(&pin, &info("garbage")).is_err());
    }

    #[test]
    fn unpinned_flag_downgrades_mismatch() {
        let pin = repository_pin().unwrap();
        assert!(resolve_pinned(Ok(pin.clone()), &info(&pinned_version()), false).unwrap());
        assert!(!resolve_pinned(Ok(pin.clone()), &info("1.0.0.1"), true).unwrap());
        assert!(matches!(
            resolve_pinned(Ok(pin), &info("1.0.0.1"), false),
            Err(BrowserError::PinMismatch { .. })
        ));
        let missing = || Err(PinError::NotFound { searched: "x".into() });
        assert!(!resolve_pinned(missing(), &info("1.2.3.4"), true).unwrap());
        assert!(matches!(
            resolve_pinned(missing(), &info("1.2.3.4"), false),
            Err(BrowserError::Launch(_))
        ));
    }
}
