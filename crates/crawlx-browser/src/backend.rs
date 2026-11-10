//! `ChromiumBackend`: launches Chromium (or attaches to a running one),
//! verifies the build against `chromium-pin.toml` and hands out browser contexts.

use crate::cdp::CdpClient;
use crate::context::CdpContext;
use crate::launch::{self, BrowserProcess, LaunchConfig};
use crate::pin::{self, ChromiumPin};
use async_trait::async_trait;
use crawlx_core::browser::{BrowserBackend, BrowserContext, BrowserError, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::time::{Clock, SystemClock};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_url::CanonicalizeOptions;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Everything a context needs from its backend; contexts keep it alive, so the browser
/// process outlives every context that uses it.
pub(crate) struct BackendShared {
    pub client: CdpClient,
    pub launch_profile: LaunchProfile,
    pub egress_proxy_port: Option<u16>,
    pub fixtures_dir: Option<PathBuf>,
    pub clock: Arc<dyn Clock>,
    pub canon: CanonicalizeOptions,
    process: Mutex<Option<BrowserProcess>>,
    /// Stops the `crawlx.browser.rss_bytes` sampler; `None` for an attached browser.
    rss_sampler: Option<CancellationToken>,
}

impl Drop for BackendShared {
    fn drop(&mut self) {
        if let Some(token) = &self.rss_sampler {
            token.cancel();
        }
    }
}

/// How often the browser tree's resident set size is sampled into
/// `crawlx.browser.rss_bytes`.
const RSS_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// Sample `launch::tree_rss_bytes(pid)` every [`RSS_SAMPLE_INTERVAL`] into the gauge until
/// `token` is cancelled. A failed read (the browser is gone) is logged at debug and
/// leaves the gauge at its last value.
fn spawn_rss_sampler(pid: u32, token: CancellationToken) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RSS_SAMPLE_INTERVAL);
        loop {
            tokio::select! {
                () = token.cancelled() => break,
                _ = tick.tick() => {}
            }
            match tokio::task::spawn_blocking(move || launch::tree_rss_bytes(pid)).await {
                Ok(Ok(bytes)) => Metrics::global()
                    .gauge(names::BROWSER_RSS_BYTES)
                    .set(bytes as f64, &[]),
                Ok(Err(e)) => tracing::debug!(error = %e, "browser rss sample failed"),
                Err(_) => break,
            }
        }
    });
}

#[derive(Deserialize)]
struct VersionInfo {
    #[serde(rename = "protocolVersion", default)]
    protocol_version: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "userAgent", default)]
    user_agent: String,
}

/// A launched Chromium. Dropping it kills the browser's process group and deletes a temp
/// profile directory.
pub struct ChromiumBackend {
    shared: Arc<BackendShared>,
    build_info: BrowserBuildInfo,
    launch_flags: Vec<String>,
    sandboxed: bool,
}

impl ChromiumBackend {
    /// Launch Chromium per `config`, connect over CDP and verify the pin; with
    /// `config.cdp_ws_url` set, [`Self::attach`] to that endpoint instead.
    ///
    /// Fails with [`BrowserError::PinMismatch`] when the running build differs from
    /// `chromium-pin.toml`, unless `config.allow_unpinned` (or `CRAWLX_ALLOW_UNPINNED=1`)
    /// is set, in which case `build_info().pinned` is `false`.
    ///
    /// # Errors
    /// Returns [`BrowserError::Io`] if the temp profile directory cannot be created,
    /// [`BrowserError::Launch`] / [`BrowserError::Timeout`] from [`launch::spawn`] (also
    /// [`BrowserError::Launch`] when no pin can be loaded and unpinned runs are not allowed),
    /// [`BrowserError::Transport`] if the DevTools connection fails, the `Browser.getVersion` and
    /// `Target.setDiscoverTargets` call errors, and [`BrowserError::PinMismatch`] on a build mismatch.
    pub async fn launch(config: LaunchConfig) -> Result<Self, BrowserError> {
        if let Some(ws) = config.cdp_ws_url.clone() {
            return Self::attach(&ws, config).await;
        }
        let started = Instant::now();
        let launched = Self::launch_inner(config).await;
        Metrics::global()
            .histogram(names::BROWSER_LAUNCH_DURATION)
            .observe_duration(started.elapsed(), &[]);
        launched
    }

    /// Attach to a running browser's DevTools endpoint (`ws_url`, compatibility flag `-chrome-ws-url`).
    /// Nothing is spawned; `config` supplies the launch profile the contexts
    /// will assume, the fixtures directory, the egress proxy port and the CDP queue size.
    /// The build is recorded with `pinned = false` and `attached = true` (the pin and sandbox
    /// cannot be verified for a browser we did not start); [`Self::close`] disconnects and
    /// leaves the browser running.
    ///
    /// # Errors
    /// [`BrowserError::Transport`] if the WebSocket connection fails, and the
    /// `Browser.getVersion`, `Target.getBrowserContexts` and `Target.setDiscoverTargets` call
    /// errors ([`BrowserError::Protocol`] when `ws_url` is a page endpoint rather than the
    /// browser endpoint).
    pub async fn attach(ws_url: &url::Url, config: LaunchConfig) -> Result<Self, BrowserError> {
        let client = CdpClient::connect_with_queue(ws_url.as_str(), config.cdp_queue).await?;
        let mut build_info = Self::version_info(&client, &config).await?;
        build_info.pinned = false;
        build_info.attached = true;
        // Only the browser endpoint answers this; it also tells apart the default context.
        client.call("Target.getBrowserContexts", None, json!({})).await?;
        client
            .call("Target.setDiscoverTargets", None, json!({ "discover": true }))
            .await?;
        tracing::info!(
            chromium_version = %build_info.chromium_version,
            "attached to a running browser; pin and sandbox unverified"
        );
        Ok(Self {
            shared: Arc::new(Self::shared(client, &config, None, None)),
            build_info,
            launch_flags: Vec::new(),
            sandboxed: false,
        })
    }

    async fn launch_inner(mut config: LaunchConfig) -> Result<Self, BrowserError> {
        crate::options::validate_flags(&config.extra_args)
            .map_err(|e| BrowserError::Launch(e.to_string()))?;
        Self::ensure_executable(&mut config).await?;
        let (tmp, dir) = match (&config.profile, &config.user_data_dir) {
            (Some(spec), _) => {
                let profiles_dir = config.profiles_dir.as_deref().ok_or_else(|| {
                    BrowserError::Launch(
                        "a named browser profile needs a profiles directory (--profiles-dir)".to_owned(),
                    )
                })?;
                let prepared = crate::profiles::prepare(profiles_dir, spec)?;
                (prepared.temp, prepared.dir)
            }
            (None, Some(d)) => (None, d.clone()),
            (None, None) => {
                let t = tempfile::Builder::new()
                    .prefix("crawlx-chromium-")
                    .tempdir()
                    .map_err(|e| BrowserError::Io(e.to_string()))?;
                let p = t.path().to_path_buf();
                (Some(t), p)
            }
        };
        let launch_flags = config.launch_flags(&dir);
        let spawned = launch::spawn(&config, tmp, dir).await?;
        let client = CdpClient::connect_with_queue(&spawned.ws_url, config.cdp_queue).await?;

        let mut build_info = Self::version_info(&client, &config).await?;
        let pin = match &config.pin_file {
            Some(p) => ChromiumPin::load(p),
            None => ChromiumPin::load_or_embedded(),
        };
        build_info.pinned = pin::resolve_pinned(pin, &build_info, config.allow_unpinned)?;

        // Contexts learn about popups from browser-level target events.
        client
            .call("Target.setDiscoverTargets", None, json!({ "discover": true }))
            .await?;

        let rss_sampler = spawned.process.pid().map(|pid| {
            let token = CancellationToken::new();
            spawn_rss_sampler(pid, token.clone());
            token
        });
        let shared = Self::shared(client, &config, Some(spawned.process), rss_sampler);
        Ok(Self {
            shared: Arc::new(shared),
            build_info,
            sandboxed: !launch_flags.iter().any(|f| f == "--no-sandbox"),
            launch_flags,
        })
    }

    /// With `auto_download_chromium` and a configured executable that does not exist, download
    /// the pinned build into the Chromium cache and run that.
    async fn ensure_executable(config: &mut LaunchConfig) -> Result<(), BrowserError> {
        if !config.auto_download_chromium || config.executable.is_file() {
            return Ok(());
        }
        let launch_err =
            |e: &dyn std::fmt::Display| BrowserError::Launch(format!("chromium auto-download: {e}"));
        let pin = crate::install::pin_for_install(config.pin_file.as_deref()).map_err(|e| launch_err(&e))?;
        let installed = crate::install::install(crate::install::InstallRequest {
            pin: &pin,
            cache_root: &config.chromium_cache,
            version: None,
            sha256: None,
        })
        .await
        .map_err(|e| launch_err(&e))?;
        tracing::info!(
            version = %installed.version,
            downloaded = installed.downloaded,
            "using the pinned Chromium from the cache"
        );
        config.executable = installed.binary;
        Ok(())
    }

    /// `Browser.getVersion` as build info (`pinned`/`attached` left false).
    async fn version_info(
        client: &CdpClient,
        config: &LaunchConfig,
    ) -> Result<BrowserBuildInfo, BrowserError> {
        let version: VersionInfo = client.call_as("Browser.getVersion", None, json!({})).await?;
        let chromium_version = version
            .product
            .rsplit('/')
            .next()
            .unwrap_or(&version.product)
            .to_owned();
        Ok(BrowserBuildInfo {
            chromium_version,
            cdp_revision: version.protocol_version,
            user_agent: version.user_agent,
            pinned: false,
            launch_profile: config.launch_profile,
            console_capture: crate::profile::ProfileBehavior::of(config.launch_profile, true).console_capture,
            attached: false,
        })
    }

    fn shared(
        client: CdpClient,
        config: &LaunchConfig,
        process: Option<BrowserProcess>,
        rss_sampler: Option<CancellationToken>,
    ) -> BackendShared {
        BackendShared {
            client,
            launch_profile: config.launch_profile,
            egress_proxy_port: config.egress_proxy_port,
            fixtures_dir: config.fixtures_dir.clone(),
            clock: Arc::new(SystemClock),
            canon: CanonicalizeOptions::default(),
            process: Mutex::new(process),
            rss_sampler,
        }
    }

    /// Did this backend attach to a browser it did not launch?
    #[must_use]
    pub const fn is_attached(&self) -> bool {
        self.build_info.attached
    }

    /// Replace the clock used for timestamps (tests). Must be called before creating contexts.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.clock = clock;
        }
        self
    }

    /// The exact argument list Chromium was started with.
    #[must_use]
    pub fn launch_flags(&self) -> &[String] {
        &self.launch_flags
    }

    /// Was Chromium's sandbox active (`--no-sandbox` not passed)?
    #[must_use]
    pub fn is_sandboxed(&self) -> bool {
        self.sandboxed
    }

    /// Every CDP method sent since launch, in order.
    #[must_use]
    pub fn cdp_transcript(&self) -> Vec<String> {
        self.shared.client.transcript()
    }

    /// Create a context and keep its concrete type (diagnostics such as
    /// [`CdpContext::evaluate_isolated`] and [`CdpContext::console_messages`]).
    ///
    /// The context's launch profile must equal the browser's: launch flags are process-wide.
    ///
    /// # Errors
    /// Returns [`BrowserError::Unsupported`] if `config.launch_profile` differs from the
    /// browser's, otherwise the errors of context creation (CDP call failures).
    pub async fn new_cdp_context(&self, config: ContextConfig) -> Result<CdpContext, BrowserError> {
        if config.launch_profile != self.shared.launch_profile {
            return Err(BrowserError::Unsupported(format!(
                "context profile {} differs from the browser's launch profile {}; \
                 launch flags are process-wide",
                config.launch_profile.as_str(),
                self.shared.launch_profile.as_str()
            )));
        }
        CdpContext::create(Arc::clone(&self.shared), config).await
    }

    /// Ask the browser to exit, then kill its process group. An attached browser
    /// ([`Self::attach`]) is only disconnected from: it belongs to someone else.
    ///
    /// # Errors
    /// Returns an error if the owned process/group cannot be confirmed dead.
    pub async fn close(self) -> Result<(), BrowserError> {
        if self.build_info.attached {
            return Ok(());
        }
        self.terminate().await
    }

    /// Bound graceful shutdown, then reap the owned process and verify its isolated group.
    /// The async resource mutex keeps the Child owned on cancellation and serializes retries.
    async fn terminate(&self) -> Result<(), BrowserError> {
        if self.build_info.attached {
            return Err(BrowserError::Unsupported(
                "attached browser cannot be terminated by this worker".into(),
            ));
        }
        let mut process = self.shared.process.lock().await;
        let Some(p) = process.as_mut() else { return Ok(()) };
        let _ = self
            .shared
            .client
            .call_with_timeout("Browser.close", None, json!({}), Duration::from_secs(5))
            .await;
        if let Some(token) = &self.shared.rss_sampler {
            token.cancel();
        }
        p.shutdown_confirmed(Duration::from_secs(3)).await?;
        process.take();
        Ok(())
    }
}

#[async_trait]
impl BrowserBackend for ChromiumBackend {
    async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError> {
        Ok(Box::new(self.new_cdp_context(config).await?))
    }

    fn build_info(&self) -> &BrowserBuildInfo {
        &self.build_info
    }

    async fn shutdown(&self) {
        if let Err(error) = self.terminate().await {
            tracing::warn!(error = %error, "browser resource cleanup not confirmed");
        }
    }

    async fn shutdown_confirmed(&self) -> Result<(), BrowserError> {
        self.terminate().await
    }
}
