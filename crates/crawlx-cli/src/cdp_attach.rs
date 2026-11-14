//! Attaching to a running browser: where the DevTools websocket URL comes from.
//!
//! The URL of a leased browser is a bearer token: whoever holds it drives the browser. It must not
//! travel on the command line, where any local user reads it from `/proc/<pid>/cmdline` and `ps`.
//! The sources, exactly one of which may be given, are
//!
//! | source | form |
//! | --- | --- |
//! | `--cdp-ws-url-file PATH` | a regular file the owner alone can read, one `ws://` or `wss://` line |
//! | `CRAWLX_CDP_WS_URL_FILE` | the same file, named by the environment |
//! | `CRAWLX_CDP_WS_URL` | the URL in the environment of the process |
//! | `--cdp-ws-url URL` | deprecated: the URL in the process arguments |
//!
//! No error, warning or report of this module carries the URL; a rejected value is described by
//! its source only.

use clap::Args;
use std::convert::Infallible;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

/// Environment variable holding the DevTools websocket URL.
pub const URL_ENV: &str = "CRAWLX_CDP_WS_URL";
/// Environment variable naming the file that holds the DevTools websocket URL.
pub const URL_FILE_ENV: &str = "CRAWLX_CDP_WS_URL_FILE";
/// Largest URL file read; a websocket URL is a few hundred bytes.
pub const MAX_URL_FILE_BYTES: u64 = 4096;
/// Printed to stderr, once, when the URL was passed with `--cdp-ws-url`.
pub const ARGV_DEPRECATION: &str =
    "warning: --cdp-ws-url is deprecated: the DevTools URL is a bearer token and is \
     visible in process arguments; use --cdp-ws-url-file, CRAWLX_CDP_WS_URL_FILE or CRAWLX_CDP_WS_URL";

/// A DevTools URL taken from the command line, unchecked. The parser accepts any text so that a
/// rejected value is never echoed by the argument parser; [`CdpArgs::resolve`] validates it.
#[derive(Clone, PartialEq, Eq)]
pub struct CdpUrlArg(String);

impl std::fmt::Debug for CdpUrlArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

fn cdp_url_arg(value: &str) -> Result<CdpUrlArg, Infallible> {
    Ok(CdpUrlArg(value.to_owned()))
}

impl crate::merge::Unset for CdpArgs {
    fn is_unset(&self) -> bool {
        self.cdp_ws_url.is_none() && self.cdp_ws_url_file.is_none() && !self.no_incognito
    }
}

/// Why the DevTools URL could not be resolved. No variant carries the URL.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CdpAttachError {
    /// More than one source was given.
    #[error("the DevTools URL was given more than once ({0}); pass exactly one source")]
    MoreThanOneSource(String),
    /// `--no-incognito` without a URL source.
    #[error(
        "--no-incognito reuses the default context of an attached browser: give --cdp-ws-url-file, \
         {URL_FILE_ENV} or {URL_ENV}"
    )]
    NoIncognitoWithoutBrowser,
    /// The value is not a `ws://` or `wss://` URL with a host.
    #[error("{origin}: not a ws:// or wss:// URL with a host")]
    InvalidUrl {
        /// The flag, variable or file that supplied the value.
        origin: String,
    },
    /// The path is not a regular file.
    #[error("{0}: not a regular file")]
    NotRegular(PathBuf),
    /// Group or others can read the file.
    #[error("{path}: mode {mode:04o} lets group or others read the URL; run `chmod 600`")]
    Permissions {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The file is longer than [`MAX_URL_FILE_BYTES`].
    #[error("{0}: longer than {MAX_URL_FILE_BYTES} bytes")]
    TooLarge(PathBuf),
    /// The file holds nothing but whitespace.
    #[error("{0}: empty")]
    Empty(PathBuf),
    /// The file holds more than one line.
    #[error("{0}: must hold exactly one line")]
    MultiLine(PathBuf),
    /// The file is not UTF-8.
    #[error("{0}: not UTF-8 text")]
    NotUtf8(PathBuf),
    /// The file cannot be opened or read.
    #[error("cannot read {path}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
}

/// A resolved attachment: the browser endpoint and whether contexts are incognito.
#[derive(Clone, PartialEq, Eq)]
pub struct CdpAttach {
    /// The browser endpoint (a bearer token).
    pub url: url::Url,
    /// Open incognito contexts instead of reusing the default one.
    pub incognito: bool,
}

impl std::fmt::Debug for CdpAttach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdpAttach")
            .field("url", &"<redacted>")
            .field("incognito", &self.incognito)
            .finish()
    }
}

/// The attach flags shared by `crawl` and `worker`.
#[derive(Args, Clone, Debug, Default)]
pub struct CdpArgs {
    /// Attach to the running Chromium at this DevTools websocket instead of launching one
    /// (compatibility `-chrome-ws-url`, `-cwu`). Deprecated: the URL is a bearer token and shows in
    /// process arguments; use `--cdp-ws-url-file`. Refused unless the safety profile is
    /// `test_environment` or `authorized_security_test`.
    #[arg(
        long = "cdp-ws-url",
        visible_alias = "chrome-ws-url",
        value_name = "URL",
        value_parser = cdp_url_arg,
        help_heading = "Headless"
    )]
    pub cdp_ws_url: Option<CdpUrlArg>,
    /// File holding the DevTools websocket URL (one `ws://` or `wss://` line, at most 4096
    /// bytes, a regular file readable by its owner only). `CRAWLX_CDP_WS_URL_FILE` names the file
    /// too and `CRAWLX_CDP_WS_URL` holds the URL itself; give exactly one source.
    #[arg(long, value_name = "FILE", help_heading = "Headless")]
    pub cdp_ws_url_file: Option<PathBuf>,
    /// With an attached browser, reuse its default context (its logged-in session) instead of
    /// opening incognito contexts (compatibility `-no-incognito`, `-noi`).
    #[arg(long, help_heading = "Headless")]
    pub no_incognito: bool,
}

impl CdpArgs {
    /// Fill unset fields from `lower`. The URL sources move together: one given on top hides every
    /// source of the lower layer, so a flag never ends up in conflict with a configuration file.
    pub(crate) fn fill_from(&mut self, lower: Self) {
        let Self {
            cdp_ws_url,
            cdp_ws_url_file,
            no_incognito,
        } = lower;
        if self.cdp_ws_url.is_none() && self.cdp_ws_url_file.is_none() {
            self.cdp_ws_url = cdp_ws_url;
            self.cdp_ws_url_file = cdp_ws_url_file;
        }
        crate::merge::fill(&mut self.no_incognito, no_incognito);
    }

    /// Whether the URL was passed with `--cdp-ws-url`; the command prints [`ARGV_DEPRECATION`].
    #[must_use]
    pub const fn uses_deprecated_argument(&self) -> bool {
        self.cdp_ws_url.is_some()
    }

    /// [`Self::resolve`], first printing [`ARGV_DEPRECATION`] to stderr when the URL was passed as
    /// an argument. The line never contains the URL.
    ///
    /// # Errors
    /// As [`Self::resolve`].
    pub fn resolve_announced(
        &self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<CdpAttach>, CdpAttachError> {
        if self.uses_deprecated_argument() {
            eprintln!("{ARGV_DEPRECATION}");
        }
        self.resolve(getenv)
    }

    /// The attachment these flags and the environment `getenv` describe; `None` when no browser
    /// is attached.
    ///
    /// # Errors
    /// [`CdpAttachError`] when more than one source is given, `--no-incognito` has no source, the
    /// URL file is unsafe or unreadable, or the value is not a `ws://` or `wss://` URL.
    pub fn resolve(
        &self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<CdpAttach>, CdpAttachError> {
        let set = |name: &str| getenv(name).filter(|value| !value.trim().is_empty());
        let env_url = set(URL_ENV);
        let env_file = set(URL_FILE_ENV);
        let given: Vec<&str> = [
            (self.cdp_ws_url.is_some(), "--cdp-ws-url"),
            (self.cdp_ws_url_file.is_some(), "--cdp-ws-url-file"),
            (env_url.is_some(), URL_ENV),
            (env_file.is_some(), URL_FILE_ENV),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect();
        if given.len() > 1 {
            return Err(CdpAttachError::MoreThanOneSource(given.join(", ")));
        }
        let url = if let Some(arg) = &self.cdp_ws_url {
            parse_url(&arg.0, "--cdp-ws-url")?
        } else if let Some(path) = &self.cdp_ws_url_file {
            read_url_file(path)?
        } else if let Some(value) = &env_url {
            parse_url(value, URL_ENV)?
        } else if let Some(path) = &env_file {
            read_url_file(Path::new(path.trim()))?
        } else if self.no_incognito {
            return Err(CdpAttachError::NoIncognitoWithoutBrowser);
        } else {
            return Ok(None);
        };
        Ok(Some(CdpAttach {
            url,
            incognito: !self.no_incognito,
        }))
    }
}

/// `text` as a `ws://` or `wss://` URL with a host; `origin` names where it came from.
fn parse_url(text: &str, origin: &str) -> Result<url::Url, CdpAttachError> {
    let invalid = || CdpAttachError::InvalidUrl {
        origin: origin.to_owned(),
    };
    let url = url::Url::parse(text.trim()).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none() {
        return Err(invalid());
    }
    Ok(url)
}

/// The URL in `path`: a regular file only its owner can read, at most [`MAX_URL_FILE_BYTES`], one
/// line. The checks run on the opened file, so a path swapped after the open changes nothing.
fn read_url_file(path: &Path) -> Result<url::Url, CdpAttachError> {
    let read_error = |source| CdpAttachError::Read {
        path: path.to_path_buf(),
        source,
    };
    let file = std::fs::File::open(path).map_err(read_error)?;
    let meta = file.metadata().map_err(read_error)?;
    if !meta.is_file() {
        return Err(CdpAttachError::NotRegular(path.to_path_buf()));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CdpAttachError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    if meta.len() > MAX_URL_FILE_BYTES {
        return Err(CdpAttachError::TooLarge(path.to_path_buf()));
    }
    // the file may grow after the metadata call: read one byte past the bound and refuse
    let mut bytes = Vec::new();
    file.take(MAX_URL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > MAX_URL_FILE_BYTES) {
        return Err(CdpAttachError::TooLarge(path.to_path_buf()));
    }
    let text = String::from_utf8(bytes).map_err(|_| CdpAttachError::NotUtf8(path.to_path_buf()))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(CdpAttachError::Empty(path.to_path_buf()));
    }
    if text.lines().count() != 1 {
        return Err(CdpAttachError::MultiLine(path.to_path_buf()));
    }
    parse_url(text, &path.display().to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const URL: &str = "ws://127.0.0.1:9222/devtools/browser/lease-token-4242";

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn file(dir: &tempfile::TempDir, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn flag(url: &str) -> CdpArgs {
        CdpArgs {
            cdp_ws_url: Some(CdpUrlArg(url.to_owned())),
            ..CdpArgs::default()
        }
    }

    fn url_file(path: &Path) -> CdpArgs {
        CdpArgs {
            cdp_ws_url_file: Some(path.to_path_buf()),
            ..CdpArgs::default()
        }
    }

    #[test]
    fn no_source_means_no_attachment() {
        assert_eq!(CdpArgs::default().resolve(&no_env).unwrap(), None);
        // an empty variable is unset, as in a templated container environment
        let empty = env(&[(URL_ENV, ""), (URL_FILE_ENV, "  ")]);
        assert_eq!(CdpArgs::default().resolve(&empty).unwrap(), None);
    }

    #[test]
    fn every_source_resolves_to_the_same_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir, "ws-url", &format!("  {URL}\n"), 0o600);
        let from_flag = flag(URL).resolve(&no_env).unwrap().unwrap();
        let from_file_flag = url_file(&path).resolve(&no_env).unwrap().unwrap();
        let from_env = CdpArgs::default()
            .resolve(&env(&[(URL_ENV, URL)]))
            .unwrap()
            .unwrap();
        let from_env_file = CdpArgs::default()
            .resolve(&env(&[(URL_FILE_ENV, path.to_str().unwrap())]))
            .unwrap()
            .unwrap();
        for attach in [&from_flag, &from_file_flag, &from_env, &from_env_file] {
            assert_eq!(attach.url.as_str(), URL);
            assert!(attach.incognito);
        }
        let reuse = CdpArgs {
            no_incognito: true,
            ..url_file(&path)
        };
        assert!(!reuse.resolve(&no_env).unwrap().unwrap().incognito);
    }

    #[test]
    fn more_than_one_source_is_an_error_that_names_sources_not_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(&dir, "ws-url", URL, 0o600);
        let both = CdpArgs {
            cdp_ws_url: Some(CdpUrlArg(URL.to_owned())),
            cdp_ws_url_file: Some(path.clone()),
            no_incognito: false,
        };
        let cases = [
            both.resolve(&no_env).unwrap_err(),
            flag(URL).resolve(&env(&[(URL_ENV, URL)])).unwrap_err(),
            url_file(&path).resolve(&env(&[(URL_ENV, URL)])).unwrap_err(),
            CdpArgs::default()
                .resolve(&env(&[(URL_ENV, URL), (URL_FILE_ENV, path.to_str().unwrap())]))
                .unwrap_err(),
        ];
        for error in cases {
            let text = format!("{error} {error:?}");
            assert!(matches!(error, CdpAttachError::MoreThanOneSource(_)), "{text}");
            assert!(!text.contains("lease-token-4242"), "{text}");
        }
        let text = flag(URL)
            .resolve(&env(&[(URL_ENV, URL)]))
            .unwrap_err()
            .to_string();
        assert!(text.contains("--cdp-ws-url") && text.contains(URL_ENV), "{text}");
    }

    #[test]
    fn no_incognito_needs_a_source() {
        let args = CdpArgs {
            no_incognito: true,
            ..CdpArgs::default()
        };
        assert!(matches!(
            args.resolve(&no_env),
            Err(CdpAttachError::NoIncognitoWithoutBrowser)
        ));
        assert!(args.resolve(&env(&[(URL_ENV, URL)])).unwrap().is_some());
    }

    #[test]
    fn a_url_file_readable_by_group_or_others_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666] {
            let path = file(&dir, "ws-url", URL, mode);
            let error = url_file(&path).resolve(&no_env).unwrap_err();
            assert!(
                matches!(error, CdpAttachError::Permissions { .. }),
                "{mode:o}: {error}"
            );
            let text = error.to_string();
            assert!(
                text.contains(&format!("{mode:04o}")) && !text.contains("lease-token-4242"),
                "{text}"
            );
        }
        for mode in [0o600, 0o400] {
            let path = file(&dir, "ok", URL, mode);
            assert!(url_file(&path).resolve(&no_env).unwrap().is_some(), "{mode:o}");
        }
    }

    #[test]
    fn a_url_file_must_be_one_bounded_regular_file_with_a_ws_url() {
        let dir = tempfile::tempdir().unwrap();
        type Expected = fn(&CdpAttachError) -> bool;
        let cases: Vec<(PathBuf, Expected)> = vec![
            (dir.path().to_path_buf(), |e| {
                matches!(e, CdpAttachError::NotRegular(_))
            }),
            (dir.path().join("missing"), |e| {
                matches!(e, CdpAttachError::Read { .. })
            }),
            (file(&dir, "empty", " \n\n", 0o600), |e| {
                matches!(e, CdpAttachError::Empty(_))
            }),
            (file(&dir, "two-lines", &format!("{URL}\n{URL}\n"), 0o600), |e| {
                matches!(e, CdpAttachError::MultiLine(_))
            }),
            (
                file(&dir, "large", &format!("{URL}{}", "a".repeat(5000)), 0o600),
                |e| matches!(e, CdpAttachError::TooLarge(_)),
            ),
            (file(&dir, "bin", "\u{0}", 0o600), |e| {
                matches!(e, CdpAttachError::InvalidUrl { .. })
            }),
        ];
        for (path, expected) in cases {
            let error = url_file(&path).resolve(&no_env).unwrap_err();
            assert!(expected(&error), "{}: {error}", path.display());
        }
        let raw = dir.path().join("not-utf8");
        std::fs::write(&raw, [0xff, 0xfe, b'w', b's']).unwrap();
        std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            url_file(&raw).resolve(&no_env),
            Err(CdpAttachError::NotUtf8(_))
        ));
    }

    #[test]
    fn a_value_that_is_not_a_ws_url_is_rejected_without_being_echoed() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "https://user:hunter2@browser.example/devtools/browser/tok-9";
        let path = file(&dir, "ws-url", secret, 0o600);
        let errors = [
            flag(secret).resolve(&no_env).unwrap_err(),
            flag("not a url at all hunter2").resolve(&no_env).unwrap_err(),
            flag("ws://?hunter2").resolve(&no_env).unwrap_err(),
            CdpArgs::default()
                .resolve(&env(&[(URL_ENV, secret)]))
                .unwrap_err(),
            url_file(&path).resolve(&no_env).unwrap_err(),
            CdpArgs::default()
                .resolve(&env(&[(URL_FILE_ENV, path.to_str().unwrap())]))
                .unwrap_err(),
        ];
        for error in errors {
            let text = format!("{error} | {error:?} | {error:#}");
            assert!(matches!(error, CdpAttachError::InvalidUrl { .. }), "{text}");
            assert!(!text.contains("hunter2") && !text.contains("tok-9"), "{text}");
        }
        assert!(flag("wss://browser.example/devtools/browser/x")
            .resolve(&no_env)
            .unwrap()
            .is_some());
    }

    #[test]
    fn debug_output_never_shows_the_url() {
        let args = flag(URL);
        let attach = args.resolve(&no_env).unwrap().unwrap();
        let text = format!("{args:?} {attach:?}");
        assert!(
            !text.contains("lease-token-4242") && text.contains("<redacted>"),
            "{text}"
        );
    }

    #[test]
    fn the_deprecation_warning_names_the_risk_and_the_replacements_not_the_url() {
        assert!(flag(URL).uses_deprecated_argument());
        assert!(!url_file(Path::new("/x")).uses_deprecated_argument());
        assert!(!CdpArgs::default().uses_deprecated_argument());
        assert_eq!(ARGV_DEPRECATION.lines().count(), 1);
        assert!(ARGV_DEPRECATION.starts_with("warning: --cdp-ws-url is deprecated"));
        assert!(ARGV_DEPRECATION.contains("visible in process arguments"));
        for replacement in ["--cdp-ws-url-file", URL_FILE_ENV, URL_ENV] {
            assert!(ARGV_DEPRECATION.contains(replacement), "{replacement}");
        }
        assert!(!ARGV_DEPRECATION.contains("ws://"));
    }

    #[test]
    fn a_source_on_top_hides_every_source_of_the_lower_layer() {
        let mut top = CdpArgs::default();
        top.fill_from(CdpArgs {
            cdp_ws_url_file: Some(PathBuf::from("/from/config")),
            no_incognito: true,
            ..CdpArgs::default()
        });
        assert_eq!(top.cdp_ws_url_file.as_deref(), Some(Path::new("/from/config")));
        assert!(top.no_incognito);
        let mut set = flag(URL);
        set.fill_from(url_file(Path::new("/lower")));
        assert!(set.cdp_ws_url.is_some() && set.cdp_ws_url_file.is_none());
        let mut set = url_file(Path::new("/top"));
        set.fill_from(flag(URL));
        assert_eq!(set.cdp_ws_url_file.as_deref(), Some(Path::new("/top")));
        assert!(set.cdp_ws_url.is_none());
    }

    #[test]
    fn flags_parse_without_echoing_a_bad_value() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct Probe {
            #[command(flatten)]
            cdp: CdpArgs,
        }
        let parsed =
            Probe::try_parse_from(["probe", "--chrome-ws-url", "ws://h:1/devtools/browser/x"]).unwrap();
        assert!(parsed.cdp.cdp_ws_url.is_some());
        assert!(Probe::try_parse_from(["probe", "--cdp-ws-url", "u", "--cdp-ws-url-file", "/f"]).is_ok());
        // an unparseable URL is accepted by the parser and refused, unechoed, by `resolve`
        let parsed = Probe::try_parse_from(["probe", "--cdp-ws-url", "tok-hunter2"]).unwrap();
        let error = parsed.cdp.resolve(&no_env).unwrap_err().to_string();
        assert!(!error.contains("hunter2"), "{error}");
    }
}
