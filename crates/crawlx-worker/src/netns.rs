//! Operator-only namespace settings and fail-closed worker launch preparation.
//!
//! The integrator calls [`NamespaceSettings::from_env`] during worker setup,
//! then [`NamespaceSettings::prepare`] before constructing browser pools. The
//! normal egress proxy remains authoritative; its per-browser port is assigned
//! by the existing pool. Every browser spawn repeats preflight.
//!
//! `CRAWLX_EGRESS_MODE=netns` selects the privileged mode (root worker) and
//! `CRAWLX_EGRESS_MODE=netns-rootless` the rootless mode (ordinary-user worker,
//! subordinate browser identity); see `deploy/isolation/namespace.env.example`.

use crawlx_browser::netns::{NamespaceConfig, NamespaceError, NamespaceMode};
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::BrowserBackend;
use crawlx_fetch::egress::EgressProxy;
use crawlx_fetch::resolver::StaticResolver;
use crawlx_policy::egress::EgressPolicy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Highest namespace-internal id the rootless helper maps.
const ROOTLESS_MAX_ID: u32 = 65_534;

/// Operator namespace launcher settings, never crawl-request configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NamespaceSettings {
    /// Installed absolute path to the deployment helper.
    pub helper: PathBuf,
    /// Privileged (root worker) or rootless (ordinary-user worker) namespace creation.
    pub mode: NamespaceMode,
    /// Non-root Chromium UID: a host id (privileged) or a namespace id (rootless).
    pub browser_uid: u32,
    /// Non-root Chromium GID; supplementary groups are cleared by the helper.
    pub browser_gid: u32,
}

/// Namespace configuration or enforcement preflight failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NamespaceSetupError {
    /// Operator configuration was missing, ambiguous, or inconsistent.
    #[error("namespace settings rejected: {0}")]
    Config(&'static str),
    /// Browser namespace preflight failed; no browser may start.
    #[error("namespace launch preflight failed")]
    Preflight(#[from] NamespaceError),
}

impl NamespaceSettings {
    /// Privileged mode: bind an installed helper to its non-root host browser identity.
    #[must_use]
    pub fn new(helper: PathBuf, browser_uid: u32, browser_gid: u32) -> Self {
        Self {
            helper,
            mode: NamespaceMode::Privileged,
            browser_uid,
            browser_gid,
        }
    }

    /// Rootless mode: bind an installed helper to a namespace-internal browser identity.
    #[must_use]
    pub fn rootless(helper: PathBuf, browser_uid: u32, browser_gid: u32) -> Self {
        Self {
            helper,
            mode: NamespaceMode::Rootless,
            browser_uid,
            browser_gid,
        }
    }

    /// Read strict operator environment, with proxy-only launch as the default.
    ///
    /// `CRAWLX_EGRESS_MODE=netns` (privileged) or `netns-rootless` requires
    /// `CRAWLX_NETNS_HELPER`, `CRAWLX_NETNS_BROWSER_UID`, and
    /// `CRAWLX_NETNS_BROWSER_GID`. Rootless ids are namespace-internal and must
    /// lie in `1..=65534`.
    ///
    /// # Errors
    /// Rejects unknown modes, missing settings, invalid IDs, relative helper
    /// paths, root browser identities, and stray settings in proxy mode.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, NamespaceSetupError> {
        let mode = getenv("CRAWLX_EGRESS_MODE");
        let helper = getenv("CRAWLX_NETNS_HELPER");
        let uid = getenv("CRAWLX_NETNS_BROWSER_UID");
        let gid = getenv("CRAWLX_NETNS_BROWSER_GID");
        let (mode, maximum) = match mode.as_deref() {
            None | Some("proxy") => {
                if helper.is_some() || uid.is_some() || gid.is_some() {
                    return Err(NamespaceSetupError::Config(
                        "namespace settings require CRAWLX_EGRESS_MODE=netns or netns-rootless",
                    ));
                }
                return Ok(None);
            }
            Some("netns") => (NamespaceMode::Privileged, u32::MAX - 1),
            Some("netns-rootless") => (NamespaceMode::Rootless, ROOTLESS_MAX_ID),
            Some(_) => {
                return Err(NamespaceSetupError::Config(
                    "CRAWLX_EGRESS_MODE must be proxy, netns or netns-rootless",
                ));
            }
        };
        let helper = helper.ok_or(NamespaceSetupError::Config("CRAWLX_NETNS_HELPER required"))?;
        let identity = |value: Option<String>, message: &'static str| {
            value
                .as_deref()
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|id| (1..=maximum).contains(id))
                .ok_or(NamespaceSetupError::Config(message))
        };
        let browser_uid = identity(
            uid,
            "non-root CRAWLX_NETNS_BROWSER_UID in the mode's range required",
        )?;
        let browser_gid = identity(
            gid,
            "non-root CRAWLX_NETNS_BROWSER_GID in the mode's range required",
        )?;
        let helper = PathBuf::from(helper);
        if !helper.is_absolute() {
            return Err(NamespaceSetupError::Config(
                "namespace helper path must be absolute",
            ));
        }
        Ok(Some(match mode {
            NamespaceMode::Rootless => Self::rootless(helper, browser_uid, browser_gid),
            _ => Self::new(helper, browser_uid, browser_gid),
        }))
    }

    /// Validate host prerequisites and set the typed browser launch contract.
    ///
    /// # Errors
    /// Rejects attached CDP, non-headless launch, retained/named profiles, CI
    /// sandbox disabling, and unavailable helper or privilege prerequisites for
    /// the selected mode.
    pub async fn prepare(&self, launch: &mut LaunchConfig) -> Result<(), NamespaceSetupError> {
        if launch.cdp_ws_url.is_some()
            || !launch.headless
            || launch.user_data_dir.is_some()
            || launch.profile.is_some()
            || launch.unsafe_no_sandbox_for_ci
        {
            return Err(NamespaceSetupError::Config(
                "namespace mode requires a fresh owned sandboxed headless browser",
            ));
        }
        let config = match self.mode {
            NamespaceMode::Rootless => {
                NamespaceConfig::rootless(self.helper.clone(), self.browser_uid, self.browser_gid)
            }
            _ => NamespaceConfig::new(self.helper.clone(), self.browser_uid, self.browser_gid),
        };
        config.preflight().await?;
        launch.namespace = Some(config);
        Ok(())
    }
}

/// Why a namespace startup probe measured no browser build.
///
/// Every variant is a fail-closed refusal: the probe never falls back to an
/// unisolated launch, an attached browser, or a request-supplied proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceProbeUnavailable {
    /// The launch carries no namespace configuration, so this helper does not apply.
    NotConfigured,
    /// The launch is not an owned, fresh, headless, sandboxed browser.
    UnsupportedLaunch,
    /// The deny-all loopback egress proxy could not start.
    ProxyUnavailable,
    /// Cancelled, timed out, or the namespace launch, attestation or CDP handshake failed.
    StartupFailed,
    /// The browser started but its owned process group death was not confirmed in time.
    ShutdownUnconfirmed,
}

impl NamespaceProbeUnavailable {
    /// Stable limitation text for `BackendCapabilitiesV1::native_browser_unavailable`.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotConfigured => "namespace_probe_not_configured",
            Self::UnsupportedLaunch => "namespace_probe_unsupported_launch",
            Self::ProxyUnavailable => "namespace_probe_proxy_unavailable",
            Self::StartupFailed => "browser_startup_probe_failed",
            Self::ShutdownUnconfirmed => "probe_shutdown_unconfirmed",
        }
    }
}

/// Launch deadline of one startup probe.
const PROBE_LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Confirmed-death deadline of one startup probe.
const PROBE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Derive the probe launch from the operator launch, keeping the namespace contract.
///
/// Everything crawl-specific is cleared (profiles, download, per-run proxy) but
/// the namespace configuration is kept; `proxy` becomes the sole egress authority.
fn probe_launch(launch: &LaunchConfig, proxy: u16) -> Result<LaunchConfig, NamespaceProbeUnavailable> {
    if launch.namespace.is_none() {
        return Err(NamespaceProbeUnavailable::NotConfigured);
    }
    if launch.cdp_ws_url.is_some() || !launch.headless || launch.unsafe_no_sandbox_for_ci {
        return Err(NamespaceProbeUnavailable::UnsupportedLaunch);
    }
    let mut probe = launch.clone();
    probe.user_data_dir = None;
    probe.profile = None;
    probe.profiles_dir = None;
    probe.auto_download_chromium = false;
    probe.egress_proxy_port = Some(proxy);
    Ok(probe)
}

/// Measure the real Chromium build inside the configured namespace, then stop it.
///
/// A fresh owned browser launches under the existing namespace contract (verified
/// evidence, process identity, executable inode, CDP relay) with the existing
/// `EgressProxy` in deny-all form as its only egress authority: no seed port, no
/// record scope, no resolver entries, and every IPv4 and IPv6 destination denied, so
/// the probe can never contact a target. The browser's process group death is
/// confirmed within a bound and the proxy is shut down on every path.
///
/// # Errors
/// [`NamespaceProbeUnavailable`] when namespace isolation is not configured, the
/// launch is unsupported, the proxy cannot start, the launch fails or is cancelled,
/// or shutdown cannot be confirmed. There is no unisolated fallback.
pub async fn probe_namespaced_build(
    launch: &LaunchConfig,
    cancel: &CancellationToken,
) -> Result<BrowserBuildInfo, NamespaceProbeUnavailable> {
    // Validate before binding a listener; the port is patched in afterwards.
    probe_launch(launch, 1)?;
    let mut policy = EgressPolicy::new(false);
    policy.extra_deny = ["0.0.0.0/0", "::/0"]
        .iter()
        .filter_map(|net| net.parse().ok())
        .collect();
    if policy.extra_deny.len() != 2 {
        return Err(NamespaceProbeUnavailable::ProxyUnavailable);
    }
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(StaticResolver::new()))
        .await
        .map_err(|_| NamespaceProbeUnavailable::ProxyUnavailable)?;
    let outcome = run_probe(launch, proxy.port(), cancel).await;
    proxy.shutdown().await;
    outcome
}

async fn run_probe(
    launch: &LaunchConfig,
    proxy: u16,
    cancel: &CancellationToken,
) -> Result<BrowserBuildInfo, NamespaceProbeUnavailable> {
    let probe = probe_launch(launch, proxy)?;
    let browser = tokio::select! {
        biased;
        () = cancel.cancelled() => None,
        result = tokio::time::timeout(PROBE_LAUNCH_TIMEOUT, ChromiumBackend::launch(probe)) => {
            result.ok().and_then(Result::ok)
        }
    }
    .ok_or(NamespaceProbeUnavailable::StartupFailed)?;
    let build = browser.build_info().clone();
    if build.attached {
        // An attached browser has no verified owned namespace; never report it as measured.
        let _ = tokio::time::timeout(PROBE_SHUTDOWN_TIMEOUT, browser.shutdown_confirmed()).await;
        return Err(NamespaceProbeUnavailable::StartupFailed);
    }
    match tokio::time::timeout(PROBE_SHUTDOWN_TIMEOUT, browser.shutdown_confirmed()).await {
        Ok(Ok(())) => Ok(build),
        _ => Err(NamespaceProbeUnavailable::ShutdownUnconfirmed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeMap;

    fn parse(entries: &[(&str, &str)]) -> Result<Option<NamespaceSettings>, NamespaceSetupError> {
        let env: BTreeMap<_, _> = entries.iter().copied().collect();
        NamespaceSettings::from_env(&|key| env.get(key).map(|value| (*value).to_owned()))
    }

    #[test]
    fn normal_launch_remains_default_and_partial_settings_fail_closed() {
        assert!(parse(&[]).unwrap().is_none());
        assert!(parse(&[("CRAWLX_EGRESS_MODE", "proxy")]).unwrap().is_none());
        assert!(parse(&[("CRAWLX_EGRESS_MODE", "netns")]).is_err());
        assert!(parse(&[("CRAWLX_EGRESS_MODE", "netns-rootless")]).is_err());
        assert!(parse(&[("CRAWLX_EGRESS_MODE", "unknown")]).is_err());
        assert!(parse(&[("CRAWLX_NETNS_HELPER", "/opt/helper")]).is_err());
        assert!(parse(&[
            ("CRAWLX_EGRESS_MODE", "proxy"),
            ("CRAWLX_NETNS_BROWSER_UID", "1000")
        ])
        .is_err());
    }

    #[test]
    fn exact_operator_settings_are_required() {
        let settings = [
            ("CRAWLX_EGRESS_MODE", "netns"),
            ("CRAWLX_NETNS_HELPER", "/opt/helper"),
            ("CRAWLX_NETNS_BROWSER_UID", "1000"),
            ("CRAWLX_NETNS_BROWSER_GID", "1000"),
        ];
        let parsed = parse(&settings).unwrap().unwrap();
        assert_eq!(
            (parsed.mode, parsed.browser_uid),
            (NamespaceMode::Privileged, 1000)
        );
        for invalid in ["0", "-1", "4294967295", "not-an-id"] {
            let mut input = settings;
            input[2].1 = invalid;
            assert!(parse(&input).is_err());
            let mut input = settings;
            input[3].1 = invalid;
            assert!(parse(&input).is_err());
        }
        let mut relative = settings;
        relative[1].1 = "helper";
        assert!(parse(&relative).is_err());
    }

    #[test]
    fn rootless_settings_select_mode_and_bound_namespace_identities() {
        let settings = [
            ("CRAWLX_EGRESS_MODE", "netns-rootless"),
            ("CRAWLX_NETNS_HELPER", "/opt/helper"),
            ("CRAWLX_NETNS_BROWSER_UID", "1000"),
            ("CRAWLX_NETNS_BROWSER_GID", "65534"),
        ];
        let parsed = parse(&settings).unwrap().unwrap();
        assert_eq!(
            (parsed.mode, parsed.browser_uid, parsed.browser_gid),
            (NamespaceMode::Rootless, 1000, 65_534)
        );
        for invalid in ["0", "65535", "70000", "4294967294", "4294967295", "-1", "x"] {
            let mut input = settings;
            input[2].1 = invalid;
            assert!(parse(&input).is_err(), "uid {invalid}");
            let mut input = settings;
            input[3].1 = invalid;
            assert!(parse(&input).is_err(), "gid {invalid}");
        }
        let mut relative = settings;
        relative[1].1 = "helper";
        assert!(parse(&relative).is_err());
        // The same ids are legal host ids in privileged mode.
        let mut privileged = settings;
        privileged[0].1 = "netns";
        privileged[2].1 = "70000";
        assert!(parse(&privileged).unwrap().is_some());
    }

    #[tokio::test]
    async fn attached_cdp_is_rejected_without_network_or_privilege() {
        let mut launch = LaunchConfig::new();
        launch.cdp_ws_url = Some(url::Url::parse("ws://127.0.0.1:1/devtools/browser/nope").unwrap());
        for settings in [
            NamespaceSettings::new("/missing/helper".into(), 1000, 1000),
            NamespaceSettings::rootless("/missing/helper".into(), 1000, 1000),
        ] {
            assert!(matches!(
                settings.prepare(&mut launch).await,
                Err(NamespaceSetupError::Config(_))
            ));
            assert!(launch.namespace.is_none());
        }
    }

    #[tokio::test]
    async fn rootless_prepare_leaves_launch_unconfigured_on_unusable_helper() {
        let mut launch = LaunchConfig::new();
        launch.headless = true;
        let settings = NamespaceSettings::rootless("/missing/helper".into(), 1000, 1000);
        assert!(settings.prepare(&mut launch).await.is_err());
        assert!(launch.namespace.is_none());
    }

    fn namespaced_launch() -> LaunchConfig {
        let mut launch = LaunchConfig::new();
        launch.headless = true;
        launch.namespace = Some(NamespaceConfig::rootless("/missing/helper".into(), 1000, 1000));
        launch
    }

    #[test]
    fn probe_launch_keeps_namespace_and_clears_only_crawl_specific_state() {
        let mut launch = namespaced_launch();
        launch.user_data_dir = Some("/retained".into());
        launch.profiles_dir = Some("/profiles".into());
        launch.auto_download_chromium = true;
        launch.egress_proxy_port = Some(1);
        let probe = probe_launch(&launch, 4242).unwrap();
        assert!(probe.namespace.is_some());
        assert_eq!(probe.egress_proxy_port, Some(4242));
        assert!(probe.user_data_dir.is_none() && probe.profiles_dir.is_none() && probe.profile.is_none());
        assert!(!probe.auto_download_chromium);
    }

    #[test]
    fn probe_launch_refuses_unconfigured_attached_visible_and_unsandboxed_launches() {
        assert_eq!(
            probe_launch(&LaunchConfig::new(), 1).unwrap_err(),
            NamespaceProbeUnavailable::NotConfigured
        );
        let mut attached = namespaced_launch();
        attached.cdp_ws_url = Some(url::Url::parse("ws://127.0.0.1:1/devtools/browser/x").unwrap());
        let mut visible = namespaced_launch();
        visible.headless = false;
        let mut unsandboxed = namespaced_launch();
        unsandboxed.unsafe_no_sandbox_for_ci = true;
        for launch in [attached, visible, unsandboxed] {
            assert_eq!(
                probe_launch(&launch, 1).unwrap_err(),
                NamespaceProbeUnavailable::UnsupportedLaunch
            );
        }
    }

    #[tokio::test]
    async fn probe_fails_closed_without_launching_unisolated_or_leaking_the_proxy() {
        let cancel = CancellationToken::new();
        assert_eq!(
            probe_namespaced_build(&LaunchConfig::new(), &cancel)
                .await
                .unwrap_err(),
            NamespaceProbeUnavailable::NotConfigured,
        );
        // The unusable helper makes the namespace launch fail; no plain Chromium may start instead.
        let mut launch = namespaced_launch();
        launch.executable = "/missing/chromium".into();
        assert_eq!(
            probe_namespaced_build(&launch, &cancel).await.unwrap_err(),
            NamespaceProbeUnavailable::StartupFailed,
        );
        cancel.cancel();
        assert_eq!(
            probe_namespaced_build(&launch, &cancel).await.unwrap_err(),
            NamespaceProbeUnavailable::StartupFailed,
        );
    }

    #[test]
    fn probe_unavailable_reasons_are_stable_and_distinct() {
        let reasons = [
            NamespaceProbeUnavailable::NotConfigured,
            NamespaceProbeUnavailable::UnsupportedLaunch,
            NamespaceProbeUnavailable::ProxyUnavailable,
            NamespaceProbeUnavailable::StartupFailed,
            NamespaceProbeUnavailable::ShutdownUnconfirmed,
        ]
        .map(NamespaceProbeUnavailable::reason);
        let unique: std::collections::BTreeSet<_> = reasons.iter().collect();
        assert_eq!(unique.len(), reasons.len());
        assert!(reasons.contains(&"browser_startup_probe_failed"));
        assert!(reasons.contains(&"probe_shutdown_unconfirmed"));
    }
}
