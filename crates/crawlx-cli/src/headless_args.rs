//! Browser-plane flags of `crawlx crawl` (the compatibility Headless group).
//!
//! Request-level flags (interaction, scroll, diagnostics, ...) land in `CreateCrawl.dynamic`;
//! operator-level flags (visible window, Chromium path, profile directory, extra Chromium
//! flags, `--no-sandbox`) land in `WorkerConfig.launch`.

use crate::duration::parse_duration;
use crate::merge::fill_fields;
use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use crawlx_core::config::BrowserProfile;
use crawlx_core::CreateCrawl;
use crawlx_worker::WorkerConfig;
use std::path::PathBuf;
use std::time::Duration;

/// Environment variable that permits `--no-sandbox` (CI containers without user namespaces).
pub const UNSAFE_NO_SANDBOX_ENV: &str = "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI";

/// The compatibility "0 is unlimited" for `limits.states` / `limits.interactions`: the largest value
/// the request accepts.
const UNLIMITED: u32 = 100_000;
/// Longest `dynamic.interactionSettleMs`.
const MAX_SETTLE_MS: u128 = 60_000;
/// Longest `dynamic.interactionDurationSeconds` (one week, like `limits.durationSeconds`).
const MAX_DURATION_SECS: u64 = 604_800;

/// Browser flags.
#[derive(Args, Debug, Clone, Default)]
pub struct HeadlessArgs {
    /// Show the browser window instead of running headless.
    #[arg(long, help_heading = "Headless")]
    pub show_browser: bool,
    /// Extra Chromium flags, comma separated (`--window-size=800,600` keeps its comma-joined
    /// value). Flags that would defeat the egress proxy or the sandbox are refused.
    #[arg(long, value_name = "LIST", value_delimiter = ',', help_heading = "Headless")]
    pub headless_options: Vec<String>,
    /// Chromium profile directory (kept after the run).
    #[arg(long, value_name = "DIR", help_heading = "Headless")]
    pub chrome_data_dir: Option<PathBuf>,
    /// Use the Chromium or Chrome installed on this machine (`CRAWLX_CHROMIUM_PATH`, `PATH`,
    /// the usual install paths). crawlx never downloads a browser.
    #[arg(long, conflicts_with = "system_chrome_path", help_heading = "Headless")]
    pub system_chrome: bool,
    /// Use this Chromium or Chrome executable.
    #[arg(long, value_name = "PATH", help_heading = "Headless")]
    pub system_chrome_path: Option<PathBuf>,
    /// Start Chromium with `--no-sandbox`. Refused unless `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1`
    /// is set: a sandbox-less browser is only acceptable inside a throw-away CI container.
    #[arg(long, help_heading = "Headless")]
    pub no_sandbox: bool,
    /// Maximum consecutive interactions from one page state before the driver returns to the
    /// page URL (0 is unlimited, at most 100).
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u8).range(0..=100),
        help_heading = "Headless"
    )]
    pub interaction_depth: Option<u8>,
    /// CSS selector of elements the driver may interact with; repeat for several. When given,
    /// no other element is a candidate.
    #[arg(long, value_name = "CSS", help_heading = "Headless")]
    pub interaction_selector: Vec<String>,
    /// CSS selector of elements (and their descendants) never interacted with; repeatable.
    #[arg(long, value_name = "CSS", help_heading = "Headless")]
    pub interaction_exclude: Vec<String>,
    /// Maximum distinct UI states recorded (0 is unlimited: 100,000).
    #[arg(long, value_name = "N", help_heading = "Headless")]
    pub interaction_max_states: Option<u32>,
    /// Maximum interactions attempted (0 is unlimited: 100,000). `--limit-interactions` is the
    /// crawlx spelling, where 0 means observe only.
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "limit_interactions",
        help_heading = "Headless"
    )]
    pub interaction_max_actions: Option<u32>,
    /// Longest wait for the page to react after each interaction (`500ms`, `2s`; at most 60s).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration, help_heading = "Headless")]
    pub interaction_settle: Option<Duration>,
    /// Longest time one session spends interacting (`30s`, `5m`; 0 is bounded only by
    /// `--crawl-duration`).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration, help_heading = "Headless")]
    pub interaction_duration: Option<Duration>,
    /// Scroll down in viewport steps after a page settles, at most this many (0 is off, at
    /// most 100), to reveal lazy-loaded links.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u8).range(0..=100),
        help_heading = "Headless"
    )]
    pub max_scroll_steps: Option<u8>,
    /// Block cookie-consent banner hosts and scripts in the browser plane.
    #[arg(long, help_heading = "Headless")]
    pub block_consent_banners: bool,
    /// Consecutive dropped actions after which a session stops (0 keeps the default of 30).
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(0..=1000),
        help_heading = "Headless"
    )]
    pub max_failure_count: Option<u32>,
    /// Record per-session driver diagnostics and print them after the summary.
    #[arg(long, help_heading = "Headless")]
    pub enable_diagnostics: bool,
    /// Collect the XHR/fetch requests the browser saw on each page into the page metadata and
    /// the `xhr_requests` JSONL field.
    #[arg(long, help_heading = "Headless")]
    pub xhr_extraction: bool,
    /// Seconds the DOM and network must stay quiet before a page counts as settled.
    #[arg(
        long,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u32).range(0..=60),
        help_heading = "Headless"
    )]
    pub time_stable: Option<u32>,
    /// Chrome DevTools Recorder export (or an explicit step list) replayed to log in; needs a
    /// `--role` whose credential fills it.
    #[arg(long, value_name = "FILE", requires = "roles", help_heading = "Headless")]
    pub recorded_flow: Option<PathBuf>,
    /// Run page timers (`setTimeout`/`setInterval`) this many times faster (2 to 100), so a
    /// 5 s reveal shows after 500 ms with `10`. Changes application behaviour: the session is
    /// tagged `page_hooks` with `timer_acceleration:N`. Refused under `--launch-profile stealth`.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u8).range(2..=100),
        help_heading = "Headless"
    )]
    pub hook_timer_acceleration: Option<u8>,
    /// Make `form.reset()` and the reset event's default action no-ops, so a page that clears a
    /// form after submit keeps what was typed. Changes application behaviour: the session is
    /// tagged `page_hooks` with `prevent_form_reset`.
    #[arg(long, help_heading = "Headless")]
    pub hook_prevent_form_reset: bool,
    /// Make `window.close()` a no-op, so a window the page closes itself stays open. Changes
    /// application behaviour: the session is tagged `page_hooks` with `prevent_window_close`.
    #[arg(long, help_heading = "Headless")]
    pub hook_prevent_window_close: bool,
    /// Inject the stealth patches (`navigator.webdriver`, `plugins`, `languages`,
    /// `window.chrome`, `Permissions.query`, WebGL vendor and renderer). Needs
    /// `--launch-profile stealth`, which needs `--profile test_environment` or stronger.
    #[arg(long, help_heading = "Headless")]
    pub stealth_patches: bool,
    /// Use this encrypted principal/origin/build/egress-bound profile. Requires an existing
    /// session lease and explicit operator retained-profile approval.
    #[arg(long, value_name = "NAME", help_heading = "Headless")]
    pub browser_profile: Option<String>,
    /// Start from the saved `--browser-profile` but discard what this run writes.
    #[arg(long, requires = "browser_profile", help_heading = "Headless")]
    pub browser_profile_discard: bool,
    /// Restore exactly this saved `--browser-profile` generation; 0 starts a new profile.
    #[arg(
        long,
        requires = "browser_profile",
        value_name = "N",
        help_heading = "Headless"
    )]
    pub browser_profile_generation: Option<u64>,
    /// Retired plaintext profile root. Supplying this flag returns a secure migration error.
    #[arg(long, value_name = "DIR", help_heading = "Headless")]
    pub profiles_dir: Option<PathBuf>,
    /// Download the pinned Chromium (`chromium-pin.toml`, SHA-256 verified) into
    /// `--chromium-cache` when no Chromium is installed. `crawlx browser install` does it ahead
    /// of time.
    #[arg(long, help_heading = "Headless")]
    pub auto_download_chromium: bool,
    /// Where downloaded Chromium builds live (default `.cache/chromium`, or
    /// `CRAWLX_CHROMIUM_CACHE`).
    #[arg(long, value_name = "DIR", help_heading = "Headless")]
    pub chromium_cache: Option<PathBuf>,
    /// Attach to a running Chromium instead of launching one (`--cdp-ws-url-file`,
    /// `CRAWLX_CDP_WS_URL_FILE`, `CRAWLX_CDP_WS_URL`, deprecated `--cdp-ws-url`).
    #[command(flatten)]
    pub cdp: crate::cdp_attach::CdpArgs,
}

impl HeadlessArgs {
    /// Fill unset fields from `lower`.
    pub(crate) fn fill_from(&mut self, mut lower: Self) {
        // the attach sources layer together (see `CdpArgs::fill_from`), not flag by flag
        self.cdp.fill_from(std::mem::take(&mut lower.cdp));
        fill_fields!(
            self,
            lower,
            HeadlessArgs {
                show_browser,
                headless_options,
                chrome_data_dir,
                system_chrome,
                system_chrome_path,
                no_sandbox,
                interaction_depth,
                interaction_selector,
                interaction_exclude,
                interaction_max_states,
                interaction_max_actions,
                interaction_settle,
                interaction_duration,
                max_scroll_steps,
                block_consent_banners,
                max_failure_count,
                enable_diagnostics,
                xhr_extraction,
                time_stable,
                recorded_flow,
                hook_timer_acceleration,
                hook_prevent_form_reset,
                hook_prevent_window_close,
                stealth_patches,
                browser_profile,
                browser_profile_discard,
                browser_profile_generation,
                profiles_dir,
                auto_download_chromium,
                chromium_cache,
                cdp,
            }
        );
    }

    /// Write the request-level flags into `crawl`.
    ///
    /// # Errors
    /// A duration outside what the request accepts.
    pub(crate) fn apply_request(&self, crawl: &mut CreateCrawl) -> anyhow::Result<()> {
        let dynamic = &mut crawl.dynamic;
        if let Some(n) = self.interaction_depth {
            dynamic.interaction_depth = n;
        }
        if !self.interaction_selector.is_empty() {
            dynamic
                .interaction_selector
                .clone_from(&self.interaction_selector);
        }
        if !self.interaction_exclude.is_empty() {
            dynamic.interaction_exclude.clone_from(&self.interaction_exclude);
        }
        if let Some(n) = self.interaction_settle {
            if n.as_millis() > MAX_SETTLE_MS {
                bail!("--interaction-settle {n:?} is more than 60s");
            }
            dynamic.interaction_settle_ms = u32::try_from(n.as_millis())?;
        }
        if let Some(n) = self.interaction_duration {
            if n.as_secs() > MAX_DURATION_SECS {
                bail!("--interaction-duration {n:?} is more than 7 days");
            }
            dynamic.interaction_duration_seconds = u32::try_from(n.as_secs())?;
        }
        if let Some(n) = self.max_scroll_steps {
            dynamic.max_scroll_steps = n;
        }
        if self.block_consent_banners {
            dynamic.block_consent_banners = true;
        }
        if let Some(n) = self.max_failure_count {
            dynamic.max_failure_count = n;
        }
        if self.enable_diagnostics {
            dynamic.enable_diagnostics = true;
        }
        if let Some(secs) = self.time_stable {
            dynamic.time_stable_ms = secs
                .checked_mul(1000)
                .ok_or_else(|| anyhow!("--time-stable {secs} overflows the millisecond field"))?;
        }
        if let Some(n) = self.interaction_max_states {
            crawl.limits.states = if n == 0 { UNLIMITED } else { n.min(UNLIMITED) };
        }
        if let Some(n) = self.interaction_max_actions {
            crawl.limits.interactions = if n == 0 { UNLIMITED } else { n.min(UNLIMITED) };
        }
        if self.xhr_extraction {
            crawl.extract.xhr = true;
        }
        if let Some(n) = self.hook_timer_acceleration {
            crawl.dynamic.page_hook_options.timer_acceleration = n;
        }
        if self.hook_prevent_form_reset {
            crawl.dynamic.page_hook_options.prevent_form_reset = true;
        }
        if self.hook_prevent_window_close {
            crawl.dynamic.page_hook_options.prevent_window_close = true;
        }
        if self.stealth_patches {
            crawl.dynamic.stealth_patches = true;
        }
        if let Some(name) = &self.browser_profile {
            crawl.dynamic.browser_profile = Some(BrowserProfile {
                name: name.clone(),
                save_changes: !self.browser_profile_discard,
                generation: self.browser_profile_generation.unwrap_or(0),
            });
        }
        Ok(())
    }

    /// Write the operator-level flags into the launch configuration of `cfg`.
    ///
    /// # Errors
    /// A Chromium path that is not a file, a refused Chromium flag, or `--no-sandbox` without
    /// `CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1`.
    pub(crate) fn apply_launch(
        &self,
        cfg: &mut WorkerConfig,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        if self.show_browser {
            cfg.launch.headless = false;
        }
        if let Some(dir) = &self.chrome_data_dir {
            cfg.launch.set_user_data_dir(dir).context("--chrome-data-dir")?;
        }
        if self.system_chrome {
            cfg.launch.use_system_chrome().context("--system-chrome")?;
        }
        if let Some(path) = &self.system_chrome_path {
            cfg.launch.set_chrome_path(path).context("--system-chrome-path")?;
        }
        if !self.headless_options.is_empty() {
            cfg.launch
                .add_headless_options(&self.headless_options)
                .context("--headless-options")?;
        }
        if self.no_sandbox {
            cfg.launch.request_no_sandbox_with(|name| getenv(name)).map_err(|e| {
                anyhow!(
                    "--no-sandbox is refused ({e}): a browser without its sandbox is only acceptable in a \
                     throw-away CI container; set {UNSAFE_NO_SANDBOX_ENV}=1 to confirm that is where this runs"
                )
            })?;
        }
        if self.profiles_dir.is_some() {
            bail!("--profiles-dir plaintext reuse is retired; use the encrypted profiles catalog and operator CRAWLX_PROFILE_KEY_REF policy");
        }
        if self.auto_download_chromium {
            cfg.auto_download_chromium = true;
        }
        if let Some(dir) = &self.chromium_cache {
            cfg.chromium_cache.clone_from(dir);
        }
        if let Some(attach) = self.cdp.resolve_announced(getenv)? {
            // the policy gate (`test_environment` / `authorized_security_test` only) is the
            // worker's: `RunContext::build` refuses the attach for any other safety profile
            cfg.cdp_ws_url = Some(attach.url);
            cfg.incognito = attach.incognito;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn launch(args: &HeadlessArgs, env: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<WorkerConfig> {
        let mut cfg = WorkerConfig::default();
        args.apply_launch(&mut cfg, env)?;
        Ok(cfg)
    }

    #[test]
    fn opt_in_page_hooks_stealth_profile_and_download_flags_land_where_they_belong() {
        // every one of them is off or empty by default
        let mut crawl = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        HeadlessArgs::default().apply_request(&mut crawl).unwrap();
        assert!(crawl.dynamic.page_hook_options.is_default());
        assert!(!crawl.dynamic.stealth_patches && crawl.dynamic.browser_profile.is_none());
        let default_cfg = launch(&HeadlessArgs::default(), &no_env).unwrap();
        assert!(!default_cfg.auto_download_chromium && default_cfg.cdp_ws_url.is_none());

        let dir = tempfile::tempdir().unwrap();
        let ws_file = dir.path().join("cdp-ws-url");
        std::fs::write(&ws_file, "ws://127.0.0.1:9222/devtools/browser/x\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&ws_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let args = HeadlessArgs {
            hook_timer_acceleration: Some(10),
            hook_prevent_form_reset: true,
            hook_prevent_window_close: true,
            stealth_patches: true,
            browser_profile: Some("main".to_owned()),
            browser_profile_discard: true,
            browser_profile_generation: Some(2),
            profiles_dir: None,
            auto_download_chromium: true,
            chromium_cache: Some(PathBuf::from("/var/chromium")),
            cdp: crate::cdp_attach::CdpArgs {
                cdp_ws_url_file: Some(ws_file.clone()),
                no_incognito: true,
                ..crate::cdp_attach::CdpArgs::default()
            },
            ..HeadlessArgs::default()
        };
        args.apply_request(&mut crawl).unwrap();
        let hooks = crawl.dynamic.page_hook_options;
        assert_eq!(
            hooks.names(),
            [
                "timer_acceleration:10",
                "prevent_form_reset",
                "prevent_window_close"
            ]
        );
        assert!(crawl.dynamic.stealth_patches);
        let profile = crawl.dynamic.browser_profile.unwrap();
        assert_eq!(
            (profile.name.as_str(), profile.save_changes, profile.generation),
            ("main", false, 2)
        );
        let cfg = launch(&args, &no_env).unwrap();
        assert!(cfg.auto_download_chromium);
        assert_eq!(cfg.chromium_cache, PathBuf::from("/var/chromium"));
        assert_eq!(cfg.cdp_ws_url.unwrap().port(), Some(9222));

        let legacy = HeadlessArgs {
            profiles_dir: Some(PathBuf::from("/var/profiles")),
            ..HeadlessArgs::default()
        };
        assert!(
            launch(&legacy, &no_env).is_err(),
            "legacy plaintext roots must never become ignored controls"
        );
        assert!(!cfg.incognito, "--no-incognito rides with the attach URL");
    }

    #[test]
    fn show_browser_turns_headless_off() {
        assert!(launch(&HeadlessArgs::default(), &no_env).unwrap().launch.headless);
        let shown = HeadlessArgs {
            show_browser: true,
            ..HeadlessArgs::default()
        };
        let cfg = launch(&shown, &no_env).unwrap();
        assert!(!cfg.launch.headless);
        let flags = cfg.launch.launch_flags(std::path::Path::new("/tmp/profile"));
        assert!(!flags.iter().any(|f| f.starts_with("--headless")), "{flags:?}");
    }

    #[test]
    fn chrome_data_dir_and_chrome_path_are_applied_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let chrome = dir.path().join("chrome");
        std::fs::write(&chrome, "#!/bin/sh\n").unwrap();
        let args = HeadlessArgs {
            chrome_data_dir: Some(profile.clone()),
            system_chrome_path: Some(chrome.clone()),
            ..HeadlessArgs::default()
        };
        let cfg = launch(&args, &no_env).unwrap();
        assert_eq!(cfg.launch.user_data_dir.as_deref(), Some(profile.as_path()));
        assert!(profile.is_dir());
        assert_eq!(cfg.launch.executable, chrome);

        let missing = HeadlessArgs {
            system_chrome_path: Some(dir.path().join("nope")),
            ..HeadlessArgs::default()
        };
        let err = format!("{:#}", launch(&missing, &no_env).unwrap_err());
        assert!(err.contains("--system-chrome-path"), "{err}");
    }

    #[test]
    fn no_sandbox_needs_the_ci_environment_switch() {
        let args = HeadlessArgs {
            no_sandbox: true,
            ..HeadlessArgs::default()
        };
        let err = launch(&args, &no_env).unwrap_err().to_string();
        assert!(err.contains("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1"), "{err}");
        let with_switch = |name: &str| (name == UNSAFE_NO_SANDBOX_ENV).then(|| "1".to_owned());
        let cfg = launch(&args, &with_switch).unwrap();
        assert!(cfg.launch.unsafe_no_sandbox_for_ci);
        assert!(cfg
            .launch
            .launch_flags(std::path::Path::new("/tmp/profile"))
            .contains(&"--no-sandbox".to_owned()));
    }

    #[test]
    fn request_flags_map_with_compat_semantics() {
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        let args = HeadlessArgs {
            interaction_max_states: Some(0),
            interaction_settle: Some(Duration::from_secs(61)),
            ..HeadlessArgs::default()
        };
        let err = args.apply_request(&mut crawl).unwrap_err().to_string();
        assert!(err.contains("--interaction-settle"), "{err}");
        let args = HeadlessArgs {
            interaction_max_states: Some(0),
            interaction_max_actions: Some(250_000),
            interaction_duration: Some(Duration::from_secs(90)),
            time_stable: Some(3),
            ..HeadlessArgs::default()
        };
        args.apply_request(&mut crawl).unwrap();
        assert_eq!(crawl.limits.states, 100_000, "0 is unlimited");
        assert_eq!(
            crawl.limits.interactions, 100_000,
            "capped at the request maximum"
        );
        assert_eq!(crawl.dynamic.interaction_duration_seconds, 90);
        assert_eq!(crawl.dynamic.time_stable_ms, 3000);
    }
}
