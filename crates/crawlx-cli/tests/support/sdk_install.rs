//! Installing the official SDK packages for the tests that drive them (`sdk_python.rs`,
//! `sdk_upstream_shape.rs`): `pip install --target` of the pinned `tests/sdk/requirements.txt`.
//! Every function reports an unavailable interpreter or registry as `Err(reason)` so the caller can
//! print `skipping: <reason>`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Budget of `pip install` / `npm ci` (a cold pip install resolves and downloads about 20 wheels).
const INSTALL_TIMEOUT: Duration = Duration::from_secs(420);

/// The repository root (two levels above `crates/crawlx-cli`).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/crawlx-cli sits two levels below the repository root")
        .to_path_buf()
}

/// Run `cmd` with a budget; `Err(reason)` for a missing program, a timeout or a failing exit.
pub async fn run_install(what: &str, mut cmd: Command) -> Result<(), String> {
    let out = tokio::time::timeout(
        INSTALL_TIMEOUT,
        cmd.stdin(Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| format!("{what} timed out after {INSTALL_TIMEOUT:?}"))?
    .map_err(|e| format!("{what} could not be started: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
    Err(format!(
        "{what} failed ({}): {}",
        out.status,
        tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
    ))
}

/// The version `tests/sdk/requirements.txt` pins `firecrawl-py` to.
pub fn pinned_python_sdk() -> String {
    let text = std::fs::read_to_string(repo_root().join("tests/sdk/requirements.txt")).unwrap();
    text.lines()
        .find_map(|l| l.trim().strip_prefix("firecrawl-py=="))
        .expect("requirements.txt pins firecrawl-py==X")
        .trim()
        .to_owned()
}

/// Install the pinned Python SDK into `target`; `Err(reason)` when python3, pip or PyPI is
/// unavailable.
pub async fn install_python_sdk(target: &Path) -> Result<(), String> {
    let mut version = Command::new("python3");
    version.arg("--version");
    run_install("python3 --version", version).await?;
    let mut pip = Command::new("python3");
    pip.args([
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--quiet",
    ])
    .arg("--target")
    .arg(target)
    .arg("-r")
    .arg(repo_root().join("tests/sdk/requirements.txt"));
    run_install("pip install of tests/sdk/requirements.txt", pip).await
}
