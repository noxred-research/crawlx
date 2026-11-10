//! Operator launch options of the compatibility headless group: `-sc/-system-chrome`,
//! `-scp/-system-chrome-path`, `-sb/-show-browser`, `-ho/-headless-options`,
//! `-nos/-no-sandbox` and `-cdd/-chrome-data-dir`, as validated setters on [`LaunchConfig`].
//!
//! These are operator settings, never request fields: a crawl request cannot choose which
//! executable runs, where the profile lives or which switches Chromium gets.
//!
//! | compatibility flag | here |
//! |---|---|
//! | `-sc` | [`LaunchConfig::use_system_chrome`]: use the installed Chromium found through `CRAWLX_CHROMIUM_PATH` or the standard install paths (crawlx never downloads a browser) |
//! | `-scp PATH` | [`LaunchConfig::set_chrome_path`] |
//! | `-sb` | `LaunchConfig::headless = false` (a visible window, needs a display) |
//! | `-ho ARGS` | [`LaunchConfig::add_headless_options`], validated by [`validate_flags`] |
//! | `-nos` | [`LaunchConfig::request_no_sandbox`], accepted only when `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI` is `1`/`true`/`yes` |
//! | `-cdd DIR` | [`LaunchConfig::set_user_data_dir`] |
//!
//! # Refused Chromium switches
//!
//! The browser plane's guarantees depend on a few launch properties, so `-ho` (and any
//! `extra_args` at launch) refuses the switches that would weaken them:
//!
//! * proxy and name resolution (`--proxy-server`, `--proxy-pac-url`, `--proxy-bypass-list`,
//!   `--no-proxy-server`, `--host-resolver-rules`, QUIC and WebRTC routing switches): all browser
//!   traffic must pass through crawlx's loopback egress proxy, which applies the egress policy.
//!   To crawl through an upstream proxy use the request's `fetch.proxy` (`-proxy`);
//! * remote debugging (`--remote-debugging-*`, `--remote-allow-origins`): crawlx owns the DevTools
//!   endpoint;
//! * web security (`--disable-web-security`, `--disable-site-isolation-trials`,
//!   `--allow-running-insecure-content`, `--ignore-certificate-errors*`; certificate
//!   verification is the request's `fetch.skipTlsVerification`);
//! * the sandbox (`--no-sandbox`, `--disable-setuid-sandbox`, `--disable-seccomp-filter-sandbox`;
//!   use `-nos`);
//! * switches crawlx owns (`--headless`, `--user-data-dir`, `--enable-automation`,
//!   `--disable-blink-features`, `--load-extension`).

use crate::launch::{find_executable, LaunchConfig, EXECUTABLE_CANDIDATES, UNSAFE_NO_SANDBOX_ENV};
use std::path::{Path, PathBuf};

/// A launch option an operator supplied is invalid or refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchOptionError {
    /// `-scp` names something that is not a file.
    #[error("chromium path {} is not a file", .0.display())]
    ChromePathMissing(PathBuf),
    /// `-sc` found no installed Chromium.
    #[error(
        "no installed chromium found; set CRAWLX_CHROMIUM_PATH or install one of {}",
        EXECUTABLE_CANDIDATES.join(", ")
    )]
    NoSystemChrome,
    /// `-cdd` names a path that exists but is not a directory, or cannot be created.
    #[error("chrome data dir {}: {reason}", .path.display())]
    DataDir {
        /// The directory the operator asked for.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// A `-ho` switch weakens a launch guarantee (see the module docs).
    #[error("headless option `{flag}` is refused: {reason}")]
    RefusedFlag {
        /// The switch as written (`--name` without its value).
        flag: String,
        /// Which guarantee it would weaken.
        reason: &'static str,
    },
    /// A `-ho` entry is not `--switch` or `--switch=value`, or continues nothing.
    #[error("malformed headless option `{0}`: expected `--switch` or `--switch=value`")]
    MalformedFlag(String),
    /// `-nos` without `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI` set.
    #[error(
        "--no-sandbox is only accepted when CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1 is set (CI containers that cannot create user namespaces); never set it in production"
    )]
    NoSandboxNotAllowed,
}

/// Switch names (without leading dashes, lowercase) that are refused, with the guarantee each
/// one would weaken.
const REFUSED: &[(&str, &str)] = &[
    (
        "proxy-server",
        "browser traffic must use the egress proxy; use fetch.proxy for an upstream proxy",
    ),
    ("proxy-pac-url", "browser traffic must use the egress proxy"),
    ("proxy-auto-detect", "browser traffic must use the egress proxy"),
    ("proxy-bypass-list", "browser traffic must use the egress proxy"),
    ("no-proxy-server", "browser traffic must use the egress proxy"),
    (
        "host-resolver-rules",
        "name resolution is pinned to the egress proxy",
    ),
    ("host-rules", "name resolution is pinned to the egress proxy"),
    ("enable-quic", "QUIC bypasses the egress proxy"),
    ("origin-to-force-quic-on", "QUIC bypasses the egress proxy"),
    (
        "force-webrtc-ip-handling-policy",
        "WebRTC must not reach the network around the proxy",
    ),
    (
        "webrtc-ip-handling-policy",
        "WebRTC must not reach the network around the proxy",
    ),
    ("remote-debugging-port", "crawlx owns the DevTools endpoint"),
    ("remote-debugging-address", "crawlx owns the DevTools endpoint"),
    ("remote-debugging-pipe", "crawlx owns the DevTools endpoint"),
    ("remote-allow-origins", "crawlx owns the DevTools endpoint"),
    ("disable-web-security", "weakens the same-origin policy"),
    ("disable-site-isolation-trials", "weakens site isolation"),
    ("allow-running-insecure-content", "weakens web security"),
    (
        "ignore-certificate-errors",
        "certificate verification is the request's fetch.skipTlsVerification",
    ),
    (
        "ignore-certificate-errors-spki-list",
        "certificate verification is the request's fetch.skipTlsVerification",
    ),
    (
        "no-sandbox",
        "use --no-sandbox only through -nos with CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1",
    ),
    ("disable-setuid-sandbox", "weakens the sandbox"),
    ("disable-seccomp-filter-sandbox", "weakens the sandbox"),
    ("headless", "owned by -show-browser"),
    ("user-data-dir", "owned by -chrome-data-dir"),
    ("enable-automation", "owned by the launch profile"),
    ("disable-blink-features", "owned by the launch profile"),
    (
        "load-extension",
        "extensions can reach the network around the proxy",
    ),
];

/// The switch name of one rendered flag: lowercase, without leading dashes and without value.
fn switch_name(flag: &str) -> String {
    flag.trim_start_matches('-')
        .split('=')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Refuse the switches in `flags` that weaken a launch guarantee (see the module docs).
///
/// # Errors
/// [`LaunchOptionError::RefusedFlag`] naming the first refused switch.
pub fn validate_flags(flags: &[String]) -> Result<(), LaunchOptionError> {
    for flag in flags {
        let name = switch_name(flag);
        if let Some((_, reason)) = REFUSED.iter().find(|(n, _)| *n == name) {
            return Err(LaunchOptionError::RefusedFlag {
                flag: format!("--{name}"),
                reason,
            });
        }
    }
    Ok(())
}

/// Parse compatibility `-headless-options` entries into Chromium switches.
///
/// The accepted forms are the compatibility flags': `--switch`, `--switch=value`, and bare tokens that continue
/// the previous switch's value with a comma (a comma-separated flag list splits
/// `--lang=en,fr` into `--lang=en` and `fr`). Surrounding whitespace is trimmed and empty entries
/// are skipped.
///
/// # Errors
/// [`LaunchOptionError::MalformedFlag`] for an entry that is neither of those forms (or a
/// continuation with nothing to continue, or `--switch=` without a value).
pub fn parse_headless_options(entries: &[String]) -> Result<Vec<String>, LaunchOptionError> {
    let mut flags: Vec<String> = Vec::with_capacity(entries.len());
    let mut last_has_value = false;
    for raw in entries {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(stripped) = entry.strip_prefix("--") {
            let (name, value) = match stripped.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim())),
                None => (stripped.trim(), None),
            };
            if name.is_empty() || value.is_some_and(str::is_empty) {
                return Err(LaunchOptionError::MalformedFlag(entry.to_owned()));
            }
            last_has_value = value.is_some();
            flags.push(value.map_or_else(|| format!("--{name}"), |v| format!("--{name}={v}")));
        } else if last_has_value && !entry.contains('=') {
            if let Some(last) = flags.last_mut() {
                last.push(',');
                last.push_str(entry);
            }
        } else {
            return Err(LaunchOptionError::MalformedFlag(entry.to_owned()));
        }
    }
    Ok(flags)
}

impl LaunchConfig {
    /// `-scp`: run the Chromium at `path`.
    ///
    /// # Errors
    /// [`LaunchOptionError::ChromePathMissing`] when `path` is not a file.
    pub fn set_chrome_path(&mut self, path: impl Into<PathBuf>) -> Result<(), LaunchOptionError> {
        let path = path.into();
        if !path.is_file() {
            return Err(LaunchOptionError::ChromePathMissing(path));
        }
        self.executable = path;
        Ok(())
    }

    /// `-sc`: run the installed Chromium (`CRAWLX_CHROMIUM_PATH`, else the standard install
    /// paths, else the newest build in the Chromium cache). It never downloads (see
    /// `auto_download_chromium`), so it fails when nothing is installed.
    ///
    /// # Errors
    /// [`LaunchOptionError::NoSystemChrome`] when no executable is found.
    pub fn use_system_chrome(&mut self) -> Result<(), LaunchOptionError> {
        self.executable = find_executable().ok_or(LaunchOptionError::NoSystemChrome)?;
        Ok(())
    }

    /// `--chromium-cache`: keep downloaded builds in `dir` (`crawlx browser install`,
    /// `auto_download_chromium`). When no Chromium is selected yet, the newest build already
    /// cached there becomes the executable.
    pub fn set_chromium_cache(&mut self, dir: impl Into<PathBuf>) {
        let dir = dir.into();
        if !self.executable.is_file() && std::env::var_os(crate::launch::CHROMIUM_PATH_ENV).is_none() {
            if let Some(cached) = crate::install::find_cached(&dir) {
                self.executable = cached;
            }
        }
        self.chromium_cache = dir;
    }

    /// `-cdd`: keep the browser profile in `dir` (created when missing, never deleted).
    ///
    /// # Errors
    /// [`LaunchOptionError::DataDir`] when `dir` exists and is not a directory, or cannot be
    /// created.
    pub fn set_user_data_dir(&mut self, dir: impl AsRef<Path>) -> Result<(), LaunchOptionError> {
        let dir = dir.as_ref();
        if dir.exists() && !dir.is_dir() {
            return Err(LaunchOptionError::DataDir {
                path: dir.to_path_buf(),
                reason: "exists and is not a directory".to_owned(),
            });
        }
        std::fs::create_dir_all(dir).map_err(|e| LaunchOptionError::DataDir {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })?;
        self.user_data_dir = Some(dir.to_path_buf());
        Ok(())
    }

    /// `-ho`: append compatibility-format Chromium switches (see [`parse_headless_options`]) after every
    /// crawlx-managed switch, refusing the ones [`validate_flags`] lists. Nothing is added when
    /// any entry is refused.
    ///
    /// # Errors
    /// [`LaunchOptionError::MalformedFlag`] or [`LaunchOptionError::RefusedFlag`].
    pub fn add_headless_options(&mut self, entries: &[String]) -> Result<(), LaunchOptionError> {
        let flags = parse_headless_options(entries)?;
        validate_flags(&flags)?;
        self.extra_args.extend(flags);
        Ok(())
    }

    /// `-nos`: pass `--no-sandbox`, only when `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI` is `1`, `true`
    /// or `yes` in the environment (CI containers that cannot create user namespaces).
    ///
    /// # Errors
    /// [`LaunchOptionError::NoSandboxNotAllowed`] when the variable is not set that way.
    pub fn request_no_sandbox(&mut self) -> Result<(), LaunchOptionError> {
        self.request_no_sandbox_with(|name| std::env::var(name).ok())
    }

    /// [`Self::request_no_sandbox`] reading the environment through `env`.
    ///
    /// # Errors
    /// [`LaunchOptionError::NoSandboxNotAllowed`].
    pub fn request_no_sandbox_with(
        &mut self,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), LaunchOptionError> {
        if env(UNSAFE_NO_SANDBOX_ENV).is_some_and(|v| crate::launch::is_truthy(&v)) {
            self.unsafe_no_sandbox_for_ci = true;
            Ok(())
        } else {
            Err(LaunchOptionError::NoSandboxNotAllowed)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_compat_forms_and_comma_continuations() {
        let parsed = parse_headless_options(&strings(&[
            "--disable-gpu",
            " --window-size=1920,1080 ",
            "",
            "--lang=en",
            "fr",
            "de",
            "--mute-audio",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            [
                "--disable-gpu",
                "--window-size=1920,1080",
                "--lang=en,fr,de",
                "--mute-audio"
            ]
        );
    }

    #[test]
    fn malformed_entries_are_rejected() {
        for bad in [
            &["disable-gpu"][..],
            &["--"],
            &["--lang="],
            &["fr"],
            &["--disable-gpu", "fr"],
        ] {
            let err = parse_headless_options(&strings(bad)).unwrap_err();
            assert!(
                matches!(err, LaunchOptionError::MalformedFlag(_)),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn guarantee_weakening_switches_are_refused_in_any_spelling() {
        for flag in [
            "--proxy-server=http://evil:8080",
            "--PROXY-SERVER=x",
            "--proxy-pac-url=http://x/pac",
            "--host-resolver-rules=MAP * 1.2.3.4",
            "--remote-debugging-port=9222",
            "--remote-debugging-address=0.0.0.0",
            "--disable-web-security",
            "--ignore-certificate-errors",
            "--no-sandbox",
            "--user-data-dir=/tmp/x",
            "--headless=old",
        ] {
            let err = validate_flags(&strings(&[flag])).unwrap_err();
            assert!(
                matches!(err, LaunchOptionError::RefusedFlag { .. }),
                "{flag}: {err}"
            );
        }
        validate_flags(&strings(&["--disable-gpu", "--window-size=800,600", "--lang=de"])).unwrap();
    }

    #[test]
    fn a_refused_headless_option_batch_preserves_existing_options() {
        let mut cfg = LaunchConfig::new();
        cfg.add_headless_options(&strings(&["--disable-gpu", "--lang=en", "fr"]))
            .unwrap();
        let before = cfg.extra_args.clone();
        let err = cfg
            .add_headless_options(&strings(&["--mute-audio", "--proxy-server=x"]))
            .unwrap_err();
        assert!(matches!(err, LaunchOptionError::RefusedFlag { .. }));
        assert_eq!(cfg.extra_args, before);
    }

    #[test]
    fn no_sandbox_needs_the_ci_environment_switch() {
        let mut cfg = LaunchConfig::new();
        cfg.unsafe_no_sandbox_for_ci = false;
        let err = cfg.request_no_sandbox_with(|_| None).unwrap_err();
        assert!(matches!(err, LaunchOptionError::NoSandboxNotAllowed));
        assert!(err.to_string().contains("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI"));
        assert!(!cfg.unsafe_no_sandbox_for_ci);
        assert!(cfg.request_no_sandbox_with(|_| Some("0".to_owned())).is_err());
        cfg.request_no_sandbox_with(|name| {
            (name == "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").then(|| "1".to_owned())
        })
        .unwrap();
        assert!(cfg.unsafe_no_sandbox_for_ci);
        assert!(cfg
            .launch_flags(Path::new("/tmp/p"))
            .contains(&"--no-sandbox".to_owned()));
    }

    #[test]
    fn chrome_path_and_data_dir_are_validated() {
        let mut cfg = LaunchConfig::new();
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            cfg.set_chrome_path(dir.path().join("missing")).unwrap_err(),
            LaunchOptionError::ChromePathMissing(_)
        ));
        let exe = dir.path().join("chrome");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        cfg.set_chrome_path(&exe).unwrap();
        assert_eq!(cfg.executable, exe);

        let profile = dir.path().join("profile/nested");
        cfg.set_user_data_dir(&profile).unwrap();
        assert!(profile.is_dir());
        assert_eq!(cfg.user_data_dir.as_deref(), Some(profile.as_path()));
        let flags = cfg.launch_flags(cfg.user_data_dir.clone().unwrap().as_path());
        assert!(flags.contains(&format!("--user-data-dir={}", profile.display())));
        assert!(matches!(
            cfg.set_user_data_dir(&exe).unwrap_err(),
            LaunchOptionError::DataDir { .. }
        ));
    }
}
