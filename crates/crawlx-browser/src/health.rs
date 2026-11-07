//! The browser half of `-health-check` (katana `-hc`, `internal/runner/healthcheck.go`):
//! can this machine run the browser plane?
//!
//! [`probe`] runs five checks in a fixed order, each reported as a [`HealthCheck`]:
//!
//! 1. `chromium_found`: the configured executable exists (or the run attaches to a browser);
//! 2. `chromium_version`: `<executable> --version` runs and prints a version;
//! 3. `launch`: Chromium starts and its DevTools endpoint answers;
//! 4. `blank_page`: a browser context opens a blank page and runs a script in it;
//! 5. `pin`: the running build matches `chromium-pin.toml`, or unpinned builds are allowed.
//!
//! A check that cannot run because an earlier one failed is reported `ok: false` with a
//! `skipped: ...` detail, so the report always lists the same checks. Nothing is downloaded,
//! no page of the network is requested and no secret is read.

use crate::backend::ChromiumBackend;
use crate::launch::{is_sandbox_failure, LaunchConfig};
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig};
use crawlx_core::ids::SessionId;
use serde::Serialize;
use std::time::Duration;
use tokio::process::Command;

/// How long `<executable> --version` may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the blank-page check may take.
const PAGE_TIMEOUT: Duration = Duration::from_secs(15);

/// One check of a [`HealthReport`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[non_exhaustive]
pub struct HealthCheck {
    /// Stable check name (`chromium_found`, `chromium_version`, `launch`, `blank_page`, `pin`).
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// What was found, or why the check failed or was skipped.
    pub detail: String,
}

impl HealthCheck {
    fn new(name: &str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            ok,
            detail: detail.into(),
        }
    }

    fn skipped(name: &str, because: &str) -> Self {
        Self::new(name, false, format!("skipped: {because}"))
    }
}

/// The result of [`probe`].
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize)]
#[non_exhaustive]
pub struct HealthReport {
    /// The checks in the order they ran.
    pub checks: Vec<HealthCheck>,
}

impl HealthReport {
    /// Did every check pass?
    #[must_use]
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// The check named `name`.
    #[must_use]
    pub fn check(&self, name: &str) -> Option<&HealthCheck> {
        self.checks.iter().find(|c| c.name == name)
    }
}

/// Run the browser health checks for `config` (see the module docs).
///
/// Never fails: a problem is a failed [`HealthCheck`]. The browser it launches is closed before
/// this returns.
pub async fn probe(config: &LaunchConfig) -> HealthReport {
    let mut checks = Vec::with_capacity(5);
    let attach = config.cdp_ws_url.is_some();

    if attach {
        checks.push(HealthCheck::new(
            "chromium_found",
            true,
            "attach mode: no executable is needed",
        ));
        checks.push(HealthCheck::new(
            "chromium_version",
            true,
            "attach mode: the version is read over DevTools",
        ));
    } else if config.executable.is_file() {
        checks.push(HealthCheck::new(
            "chromium_found",
            true,
            config.executable.display().to_string(),
        ));
        checks.push(version_check(config).await);
    } else {
        checks.push(HealthCheck::new(
            "chromium_found",
            false,
            format!(
                "{} is not a file; set CRAWLX_CHROMIUM_PATH or --system-chrome-path",
                config.executable.display()
            ),
        ));
        checks.push(HealthCheck::skipped("chromium_version", "chromium not found"));
        checks.push(HealthCheck::skipped("launch", "chromium not found"));
        checks.push(HealthCheck::skipped("blank_page", "chromium not found"));
        checks.push(HealthCheck::skipped("pin", "chromium not found"));
        return HealthReport { checks };
    }

    // the pin is judged afterwards, from the build the browser reports
    let mut launch_config = config.clone();
    launch_config.allow_unpinned = true;
    let backend = match ChromiumBackend::launch(launch_config).await {
        Ok(b) => b,
        Err(e) => {
            let hint = if is_sandbox_failure(&e.to_string()) {
                " (the sandbox cannot start here; CI containers may set CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI=1)"
            } else {
                ""
            };
            checks.push(HealthCheck::new("launch", false, format!("{e}{hint}")));
            checks.push(HealthCheck::skipped("blank_page", "chromium did not launch"));
            checks.push(HealthCheck::skipped("pin", "chromium did not launch"));
            return HealthReport { checks };
        }
    };
    let info = backend.build_info().clone();
    checks.push(HealthCheck::new(
        "launch",
        true,
        format!(
            "chromium {} (cdp {}, {})",
            info.chromium_version,
            info.cdp_revision,
            if backend.is_attached() {
                "attached"
            } else if backend.is_sandboxed() {
                "sandboxed"
            } else {
                "no sandbox"
            }
        ),
    ));
    checks.push(page_check(&backend, config).await);
    checks.push(if info.pinned {
        HealthCheck::new(
            "pin",
            true,
            format!("matches chromium-pin.toml ({})", info.chromium_version),
        )
    } else if config.allow_unpinned {
        HealthCheck::new(
            "pin",
            true,
            format!(
                "{} differs from chromium-pin.toml; unpinned builds are allowed",
                info.chromium_version
            ),
        )
    } else {
        HealthCheck::new(
            "pin",
            false,
            format!(
                "{} does not match chromium-pin.toml (set CRAWLX_ALLOW_UNPINNED=1 for development)",
                info.chromium_version
            ),
        )
    });
    let _ = backend.close().await;
    HealthReport { checks }
}

/// `<executable> --version`.
async fn version_check(config: &LaunchConfig) -> HealthCheck {
    let run = Command::new(&config.executable)
        .arg("--version")
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(VERSION_TIMEOUT, run).await {
        Err(_) => HealthCheck::new("chromium_version", false, "--version did not finish in 10 s"),
        Ok(Err(e)) => HealthCheck::new("chromium_version", false, format!("cannot run: {e}")),
        Ok(Ok(out)) => {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() && !text.is_empty() {
                HealthCheck::new("chromium_version", true, text)
            } else {
                HealthCheck::new(
                    "chromium_version",
                    false,
                    format!("--version exited with {} and printed {text:?}", out.status),
                )
            }
        }
    }
}

/// Open a context (which opens a blank tab) and run a script in it.
async fn page_check(backend: &ChromiumBackend, config: &LaunchConfig) -> HealthCheck {
    let mut context = ContextConfig::new(SessionId::new());
    context.launch_profile = config.launch_profile;
    let opened = tokio::time::timeout(PAGE_TIMEOUT, async {
        let ctx = backend.new_cdp_context(context).await?;
        let state = ctx.evaluate_isolated("document.readyState").await;
        let _ = Box::new(ctx).close().await;
        state
    })
    .await;
    match opened {
        Err(_) => HealthCheck::new("blank_page", false, "opening a blank page did not finish in 15 s"),
        Ok(Err(e)) => HealthCheck::new("blank_page", false, e.to_string()),
        Ok(Ok(state)) => HealthCheck::new(
            "blank_page",
            true,
            format!("about:blank readyState={}", state.as_str().unwrap_or("unknown")),
        ),
    }
}
