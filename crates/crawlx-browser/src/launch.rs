//! Chromium launch configuration, flag sets and process lifecycle.
//!
//! The browser is spawned here rather than through `chromiumoxide::Browser::launch`
//! because chromiumoxide's `Handler` sends `Runtime.enable` for every target, which the
//! `Stealth` profile must never do, and because the process must lead its own
//! process group so the whole tree can be killed at session end.
//!
//! # Operator switches
//!
//! * `CRAWLX_CHROMIUM_PATH`: the Chromium executable (`-system-chrome-path` sets
//!   [`LaunchConfig::executable`] explicitly, see [`crate::options`]).
//! * `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1` (also `true`/`yes`): the only way `--no-sandbox` is passed.
//!   It is for CI containers that cannot create user namespaces and must never be set in
//!   production; the compatibility `-no-sandbox` flag is accepted only while it is set
//!   ([`LaunchConfig::request_no_sandbox`]).
//! * `CRAWLX_ALLOW_UNPINNED=1`: run a Chromium build that differs from `chromium-pin.toml`.
//! * [`LaunchConfig::headless`]`= false` shows the browser window (`-show-browser`),
//!   [`LaunchConfig::user_data_dir`] keeps the profile (`-chrome-data-dir`) and
//!   [`LaunchConfig::extra_args`] appends Chromium switches (`-headless-options`); switches that
//!   weaken the egress proxy, remote debugging, web security or the sandbox are refused at launch
//!   ([`crate::options::validate_flags`]).

use crate::{egress, profile};
use crawlx_core::browser::BrowserError;
use crawlx_core::browser::ProfileSpec;
use crawlx_core::config::LaunchProfile;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Environment variable naming the Chromium executable.
pub const CHROMIUM_PATH_ENV: &str = "CRAWLX_CHROMIUM_PATH";
/// Environment variable that sets [`LaunchConfig::unsafe_no_sandbox_for_ci`].
pub const UNSAFE_NO_SANDBOX_ENV: &str = "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI";

/// Executables searched when `CRAWLX_CHROMIUM_PATH` is unset.
pub const EXECUTABLE_CANDIDATES: [&str; 3] = [
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome", // wire-compat: installed browser path
];

/// The Chromium executable to use: `CRAWLX_CHROMIUM_PATH` if set (and then nothing else), else
/// the first existing candidate, else the newest verified build in the Chromium cache
/// ([`crate::install::default_cache_root`]). `None` when nothing is installed.
#[must_use]
pub fn find_executable() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(CHROMIUM_PATH_ENV) {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    EXECUTABLE_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .or_else(|| crate::install::find_cached(&crate::install::default_cache_root()))
}

/// How to launch Chromium.
#[derive(Clone, Debug)]
pub struct LaunchConfig {
    /// Path of the Chromium executable to spawn.
    pub executable: PathBuf,
    /// Pass `--headless=new`; `false` opens a visible window.
    pub headless: bool,
    /// Profile directory. `None` (the default) creates a temp directory per browser that
    /// is deleted when the backend drops; a caller-supplied directory is never deleted.
    pub user_data_dir: Option<PathBuf>,
    /// Loopback egress proxy (`crawlx-fetch::EgressProxy`); `None` only in tests.
    pub egress_proxy_port: Option<u16>,
    /// Launch profile selecting the profile-specific flags (and CDP behavior, see `profile`).
    pub launch_profile: LaunchProfile,
    /// Record `pinned = false` instead of failing when the build differs from
    /// `chromium-pin.toml` (also enabled by `CRAWLX_ALLOW_UNPINNED=1`).
    pub allow_unpinned: bool,
    /// Pass `--no-sandbox`. **Unsafe**: only for CI containers that cannot create user
    /// namespaces. Never set it in production; it is the only way `--no-sandbox` is passed.
    /// Also enabled by `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1`.
    pub unsafe_no_sandbox_for_ci: bool,
    /// Extra command-line flags appended last, after every crawlx-managed flag.
    pub extra_args: Vec<String>,
    /// Directory of upload fixtures; `BrowserAction::Upload` resolves `FixtureFileId`s here.
    pub fixtures_dir: Option<PathBuf>,
    /// Explicit pin file; default is `CRAWLX_PIN_FILE` or the nearest `chromium-pin.toml`.
    pub pin_file: Option<PathBuf>,
    /// How long to wait for the DevTools endpoint.
    pub launch_timeout: Duration,
    /// Capacity of the bounded command queue between the adapter and the CDP connection
    /// driver (default [`crate::cdp::COMMAND_QUEUE`]); callers wait when it is full.
    pub cdp_queue: usize,
    /// Attach to a running browser's DevTools endpoint
    /// (`ws://127.0.0.1:<port>/devtools/browser/<id>`, compatibility flag `-chrome-ws-url`)
    /// instead of launching one. Nothing is spawned, no flag above applies,
    /// the pin cannot be verified (`pinned = false`, `attached = true`) and `close` leaves the
    /// browser running. Policy-gated: `test_environment` / `authorized_security_test` only.
    pub cdp_ws_url: Option<url::Url>,
    /// Directory of the named persistent profiles (`--profiles-dir`). A launch with
    /// [`Self::profile`] needs it.
    pub profiles_dir: Option<PathBuf>,
    /// Run in this named persistent profile ([`crate::profiles`]) instead of a temp profile
    /// or [`Self::user_data_dir`]. Set per browser process by the worker's pool.
    pub profile: Option<ProfileSpec>,
    /// When no Chromium is installed, download the build `chromium-pin.toml` names into
    /// [`Self::chromium_cache`] before launching (default false). The
    /// archive is unpacked only if its SHA-256 equals the pinned one.
    pub auto_download_chromium: bool,
    /// Cache of downloaded builds (`--chromium-cache`, `CRAWLX_CHROMIUM_CACHE`, default
    /// `.cache/chromium`); the newest cached build is the fallback of [`find_executable`].
    pub chromium_cache: PathBuf,
    /// Clear inherited process credentials/environment and bind HOME/XDG paths to
    /// the owned temporary profile. Requires a fresh headless owned launch.
    pub isolated_environment: bool,
}

impl LaunchConfig {
    /// Defaults: headless, `Standard` profile, temp profile dir, executable from
    /// `CRAWLX_CHROMIUM_PATH` or the first installed candidate, env switches applied.
    #[must_use]
    pub fn new() -> Self {
        Self {
            executable: find_executable().unwrap_or_else(|| PathBuf::from(EXECUTABLE_CANDIDATES[0])),
            headless: true,
            user_data_dir: None,
            egress_proxy_port: None,
            launch_profile: LaunchProfile::Standard,
            allow_unpinned: crate::pin::allow_unpinned_from_env(),
            unsafe_no_sandbox_for_ci: std::env::var(UNSAFE_NO_SANDBOX_ENV).is_ok_and(|v| is_truthy(&v)),
            extra_args: Vec::new(),
            fixtures_dir: None,
            pin_file: None,
            launch_timeout: Duration::from_secs(30),
            cdp_queue: crate::cdp::COMMAND_QUEUE,
            cdp_ws_url: None,
            profiles_dir: None,
            profile: None,
            auto_download_chromium: false,
            chromium_cache: crate::install::default_cache_root(),
            isolated_environment: false,
        }
    }

    /// The exact argument list passed to Chromium for profile directory `user_data_dir`.
    ///
    /// Order: headless, profile dir, debugging port, common flags, profile flags, egress
    /// flags, render flags, optional `--no-sandbox`, caller extras. Browser-owned
    /// startup-service settings extend the effective feature lists so unrelated
    /// operator feature settings remain in force.
    #[must_use]
    pub fn launch_flags(&self, user_data_dir: &Path) -> Vec<String> {
        let mut flags = Vec::with_capacity(32);
        if self.headless {
            flags.push("--headless=new".to_owned());
        }
        flags.push(format!("--user-data-dir={}", user_data_dir.display()));
        flags.push("--remote-debugging-port=0".to_owned());
        flags.extend(profile::COMMON_FLAGS.iter().map(|s| (*s).to_owned()));
        flags.extend(profile::profile_flags(self.launch_profile));
        flags.extend(egress::egress_flags(self.egress_proxy_port));
        flags.extend(profile::RENDER_FLAGS.iter().map(|s| (*s).to_owned()));
        if self.unsafe_no_sandbox_for_ci {
            flags.push("--no-sandbox".to_owned());
        }
        flags.extend(self.extra_args.iter().cloned());
        // Chromium uses the last occurrence of a switch. Extend the effective
        // feature list rather than replacing unrelated operator feature settings.
        for (switch, managed) in [
            ("--enable-features=", profile::ON_DEMAND_BROWSER_SERVICES),
            ("--disable-features=", profile::NO_STARTUP_AI_ELIGIBILITY),
        ] {
            if let Some(features) = flags.iter_mut().rfind(|flag| flag.starts_with(switch)) {
                features.push(',');
                features.push_str(managed);
            } else {
                flags.push(format!("{switch}{managed}"));
            }
        }
        flags
    }
}

impl Default for LaunchConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Is `value` an affirmative environment switch (`1`, `true`, `yes`; case-insensitive)?
#[must_use]
pub(crate) fn is_truthy(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
}

/// Does Chromium's stderr say the sandbox could not start?
#[must_use]
pub fn is_sandbox_failure(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("no usable sandbox")
        || s.contains("running as root without --no-sandbox")
        || s.contains("failed to move to new namespace")
        || (s.contains("sandbox") && s.contains("fatal"))
}

/// A running Chromium that leads its own process group. Dropping it kills the group and,
/// for a temp profile, deletes the profile directory.
pub struct BrowserProcess {
    child: Child,
    pgid: Option<u32>,
    group_signalled: bool,
    // declared after `child`; removed after the group is killed in `Drop`
    _profile: Option<tempfile::TempDir>,
}

impl BrowserProcess {
    /// OS process id of the browser, `None` once it has been reaped.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Kill the whole process group.
    pub fn kill_group(&mut self) {
        if !self.group_signalled {
            if let Some(pid) = self
                .pgid
                .and_then(|group| i32::try_from(group).ok())
                .and_then(rustix::process::Pid::from_raw)
            {
                // Signal while the owned leader is unreaped: its pid cannot have been reused.
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            self.group_signalled = true;
        }
        let _ = self.child.start_kill();
    }

    /// Wait for a clean exit, kill the isolated owned process group, then confirm death.
    ///
    /// # Errors
    /// Returns a timeout or I/O error if death cannot be confirmed. Callers must keep
    /// capacity charged in that case, even when the Child drop guard also requests a kill.
    pub async fn shutdown_confirmed(&mut self, grace: Duration) -> Result<(), BrowserError> {
        let group = self.pgid;
        if !self.group_signalled {
            if let Some(pid) = group
                .and_then(|group| i32::try_from(group).ok())
                .and_then(rustix::process::Pid::from_raw)
            {
                let deadline = tokio::time::Instant::now() + grace;
                loop {
                    match rustix::process::waitid(
                        rustix::process::WaitId::Pid(pid),
                        rustix::process::WaitIdOptions::EXITED
                            | rustix::process::WaitIdOptions::NOHANG
                            | rustix::process::WaitIdOptions::NOWAIT,
                    ) {
                        Ok(Some(_)) => break,
                        Ok(None) if tokio::time::Instant::now() < deadline => {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        Ok(None) => break,
                        Err(error) => {
                            // An independently reaped leader no longer pins its group id.
                            // Never risk signalling an unrelated reused process group.
                            self.group_signalled = true;
                            return Err(BrowserError::Io(format!(
                                "owned browser exit identity unavailable: {error}"
                            )));
                        }
                    }
                }
            }
        }
        self.kill_group();
        tokio::time::timeout(Duration::from_secs(3), self.child.wait())
            .await
            .map_err(|_| BrowserError::Timeout(3_000))?
            .map_err(|error| BrowserError::Io(error.to_string()))?;
        if let Some(group) = group {
            let raw = i32::try_from(group)
                .map_err(|_| BrowserError::Launch("owned process group id overflow".into()))?;
            let pid = rustix::process::Pid::from_raw(raw)
                .ok_or_else(|| BrowserError::Launch("invalid owned process group id".into()))?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            loop {
                match rustix::process::test_kill_process_group(pid) {
                    Err(rustix::io::Errno::SRCH) => break,
                    Err(error) => {
                        self.pgid = Some(group);
                        return Err(BrowserError::Io(format!(
                            "owned process group death cannot be proved: {error}"
                        )));
                    }
                    Ok(()) => {}
                }
                if tokio::time::Instant::now() >= deadline {
                    // Preserve the group identifier for a later confirmed retirement attempt.
                    self.pgid = Some(group);
                    return Err(BrowserError::Timeout(3_000));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        self.pgid = None;
        Ok(())
    }

    /// Compatibility shutdown for callers which do not reclaim pool capacity.
    pub async fn shutdown(&mut self, grace: Duration) {
        if let Err(error) = self.shutdown_confirmed(grace).await {
            tracing::warn!(error = %error, "browser resource cleanup not confirmed");
        }
    }
}

/// Value in kB of the `<key>:` line of a `/proc/<pid>/status` text.
fn status_field(status_text: &str, key: &str) -> Option<u64> {
    status_text
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Resident set size in bytes from a `/proc/<pid>/status` text (`VmRSS:` is reported
/// in kB); `None` when the line is missing (kernel threads) or malformed.
#[must_use]
pub fn rss_bytes_of(status_text: &str) -> Option<u64> {
    status_field(status_text, "VmRSS").and_then(|kb| kb.checked_mul(1024))
}

/// Parent process id from a `/proc/<pid>/status` text.
fn ppid_of(status_text: &str) -> Option<u32> {
    status_field(status_text, "PPid").and_then(|p| u32::try_from(p).ok())
}

/// Resident set size of `pid` plus every live descendant (renderers, GPU and utility
/// processes hang off Chromium's zygote, so the whole parent chain is followed), summed
/// from `/proc`.
///
/// # Errors
/// Returns the I/O error of reading `/proc/<pid>/status` when `pid` itself is gone;
/// unreadable descendants (raced exits) are skipped.
pub fn tree_rss_bytes(pid: u32) -> std::io::Result<u64> {
    let own = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut total = rss_bytes_of(&own).unwrap_or(0);
    let mut parents: BTreeMap<u32, (u32, u64)> = BTreeMap::new();
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let Some(child) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if child == pid {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if let Some(ppid) = ppid_of(&status) {
            parents.insert(child, (ppid, rss_bytes_of(&status).unwrap_or(0)));
        }
    }
    for (ppid, rss) in parents.values() {
        // `pid` is not in `parents`, so the walk stops there, at init (`PPid: 0`) or at a
        // pid missing from the snapshot; the hop bound guards against a cycle from pid
        // reuse while `/proc` was being read.
        let mut ancestor = *ppid;
        let mut hops = 0;
        while let Some((next, _)) = parents.get(&ancestor) {
            hops += 1;
            if hops > 64 {
                break;
            }
            ancestor = *next;
        }
        if ancestor == pid {
            total = total.saturating_add(*rss);
        }
    }
    Ok(total)
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        self.kill_group();
    }
}

/// Result of a successful spawn.
pub struct Spawned {
    /// Running browser; killing it kills the whole process group.
    pub process: BrowserProcess,
    /// Browser-level DevTools WebSocket URL printed by Chromium on stderr
    /// (`ws://127.0.0.1:<port>/devtools/browser/<id>`).
    pub ws_url: String,
    /// Profile directory Chromium runs with (the temp dir or the caller-supplied one).
    pub user_data_dir: PathBuf,
}

/// Spawn Chromium with `flags` (from [`LaunchConfig::launch_flags`]) and wait for the
/// DevTools WebSocket URL on stderr.
///
/// `profile_dir` is the owned temp profile (deleted with the returned process); `user_data_dir`
/// is the path passed to Chromium.
///
/// # Errors
/// Returns [`BrowserError::Launch`] if the executable cannot be started, its stderr is
/// unavailable, or it exits before printing the DevTools URL, and [`BrowserError::Timeout`]
/// if no URL appears within `config.launch_timeout`.
pub async fn spawn(
    config: &LaunchConfig,
    profile_dir: Option<tempfile::TempDir>,
    user_data_dir: PathBuf,
) -> Result<Spawned, BrowserError> {
    if config.isolated_environment
        && (!config.headless
            || config.profile.is_some()
            || config.user_data_dir.is_some()
            || profile_dir.as_ref().is_none_or(|dir| dir.path() != user_data_dir))
    {
        return Err(BrowserError::Launch(
            "isolated environment requires a fresh owned headless temporary profile".into(),
        ));
    }
    let flags = config.launch_flags(&user_data_dir);
    let mut cmd = Command::new(&config.executable);
    cmd.args(&flags)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if config.isolated_environment {
        isolate_environment(&mut cmd, &user_data_dir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| BrowserError::Launch(format!("cannot start {}: {e}", config.executable.display())))?;
    let pgid = child.id();
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BrowserError::Launch("chromium stderr unavailable".to_owned()))?;
    let mut process = BrowserProcess {
        child,
        pgid,
        group_signalled: false,
        _profile: profile_dir,
    };

    let mut lines = BufReader::new(stderr).lines();
    let mut tail: Vec<String> = Vec::new();
    let found = tokio::time::timeout(config.launch_timeout, async {
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(rest) = line.split("DevTools listening on ").nth(1) {
                        return Some(rest.trim().to_owned());
                    }
                    tracing::debug!(target: "crawlx_browser::chromium", "{line}");
                    tail.push(line);
                    if tail.len() > 40 {
                        tail.remove(0);
                    }
                }
                Ok(None) | Err(_) => return None,
            }
        }
    })
    .await;
    match found {
        Ok(Some(ws_url)) => {
            // Keep draining so Chromium never blocks on a full stderr pipe.
            tokio::spawn(async move {
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "crawlx_browser::chromium", "{line}");
                }
            });
            Ok(Spawned {
                process,
                ws_url,
                user_data_dir,
            })
        }
        Ok(None) => {
            process.kill_group();
            Err(BrowserError::Launch(format!(
                "chromium exited before opening the DevTools endpoint: {}",
                tail.join(" | ")
            )))
        }
        Err(_) => {
            process.kill_group();
            Err(BrowserError::Timeout(
                u64::try_from(config.launch_timeout.as_millis()).unwrap_or(u64::MAX),
            ))
        }
    }
}

fn isolate_environment(command: &mut Command, profile: &Path) {
    command
        .env_clear()
        .env("HOME", profile)
        .env("TMPDIR", profile)
        .env("XDG_CONFIG_HOME", profile.join("config"))
        .env("XDG_CACHE_HOME", profile.join("cache"))
        .env("LANG", "en_US.UTF-8")
        .env("PATH", "/usr/bin:/bin");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn cfg(profile: LaunchProfile, port: Option<u16>) -> LaunchConfig {
        LaunchConfig {
            executable: PathBuf::from("/usr/bin/chromium-browser"),
            headless: true,
            user_data_dir: None,
            egress_proxy_port: port,
            launch_profile: profile,
            allow_unpinned: false,
            unsafe_no_sandbox_for_ci: false,
            extra_args: Vec::new(),
            fixtures_dir: None,
            pin_file: None,
            launch_timeout: Duration::from_secs(30),
            cdp_queue: crate::cdp::COMMAND_QUEUE,
            cdp_ws_url: None,
            profiles_dir: None,
            profile: None,
            auto_download_chromium: false,
            chromium_cache: PathBuf::from(".cache/chromium"),
            isolated_environment: false,
        }
    }

    #[test]
    fn no_proxy_flags_without_port_and_sandbox_only_when_explicit() {
        let mut c = cfg(LaunchProfile::Standard, None);
        let flags = c.launch_flags(Path::new("/tmp/p"));
        assert!(!flags.iter().any(|f| f.starts_with("--proxy-server")));
        assert!(!flags.iter().any(|f| f.starts_with("--host-resolver-rules")));
        assert!(flags
            .iter()
            .any(|f| f.starts_with("--force-webrtc-ip-handling-policy")));
        assert!(!flags.contains(&"--no-sandbox".to_owned()));
        c.unsafe_no_sandbox_for_ci = true;
        c.extra_args.push("--foo".to_owned());
        let flags = c.launch_flags(Path::new("/tmp/p"));
        assert!(flags.iter().any(|flag| flag == "--no-sandbox"));
        assert!(flags.iter().any(|flag| flag == "--foo"));
        c.headless = false;
        assert!(!c
            .launch_flags(Path::new("/tmp/p"))
            .contains(&"--headless=new".to_owned()));
    }

    #[test]
    fn sandbox_failure_detection() {
        assert!(is_sandbox_failure(
            "[1:1:...] No usable sandbox! Update your kernel"
        ));
        assert!(is_sandbox_failure(
            "Running as root without --no-sandbox is not supported."
        ));
        assert!(!is_sandbox_failure("some other error"));
    }

    const STATUS: &str =
        "Name:\tchromium\nPid:\t4242\nPPid:\t17\nVmPeak:\t  900000 kB\nVmRSS:\t  123456 kB\nThreads:\t9\n";

    #[test]
    fn rss_bytes_parses_vmrss_in_kb() {
        assert_eq!(rss_bytes_of(STATUS), Some(123_456 * 1024));
        assert_eq!(ppid_of(STATUS), Some(17));
        assert_eq!(rss_bytes_of("Name:\tkthreadd\nPid:\t2\nPPid:\t0\n"), None);
        assert_eq!(rss_bytes_of("VmRSS:\tlots kB\n"), None);
        assert_eq!(rss_bytes_of("VmRSSx:\t1 kB\n"), None);
    }

    #[test]
    fn tree_rss_counts_own_process() {
        let own = tree_rss_bytes(std::process::id()).unwrap();
        assert!(own > 0, "{own}");
        assert!(tree_rss_bytes(u32::MAX).is_err());
    }

    #[tokio::test]
    async fn isolated_child_environment_contains_only_owned_paths_and_fixed_locale_path() {
        let profile = tempfile::tempdir().unwrap();
        let mut command = Command::new("/usr/bin/env");
        command.env("CRAWLX_OPERATOR_CREDENTIAL_CANARY", "must-not-enter-browser");
        isolate_environment(&mut command, profile.path());
        let output = command.output().await.unwrap();
        assert!(output.status.success());
        let values: BTreeMap<_, _> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| line.split_once('=').unwrap())
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        assert_eq!(values.len(), 6);
        assert_eq!(values["HOME"], profile.path().to_string_lossy());
        // `TMPDIR` is the profile directory too, so Chromium's scratch files stay inside the
        // owned (and cleaned-up) profile rather than the shared system temporary directory.
        assert_eq!(values["TMPDIR"], profile.path().to_string_lossy());
        assert_eq!(
            values["XDG_CONFIG_HOME"],
            profile.path().join("config").to_string_lossy()
        );
        assert_eq!(
            values["XDG_CACHE_HOME"],
            profile.path().join("cache").to_string_lossy()
        );
        assert_eq!(values["LANG"], "en_US.UTF-8");
        assert_eq!(values["PATH"], "/usr/bin:/bin");
        assert!(!values.contains_key("CRAWLX_OPERATOR_CREDENTIAL_CANARY"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hung_owned_process_is_killed_and_reaped_before_cleanup_succeeds() {
        let mut command = Command::new("sleep");
        command.arg("60").process_group(0).kill_on_drop(true);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let mut process = BrowserProcess {
            child,
            pgid: Some(pid),
            group_signalled: false,
            _profile: None,
        };
        process
            .shutdown_confirmed(Duration::from_millis(1))
            .await
            .unwrap();
        assert!(process.child.try_wait().unwrap().is_some());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
}
