//! `crawlx browser install`: download the pinned Chromium ahead of time.
//!
//! The compatibility flags download a browser by default; crawlx does it only when asked, either here or with
//! `--auto-download-chromium` on `crawl` and `worker`. The archive is the Chrome-for-Testing
//! build `chromium-pin.toml` names, unpacked only after its SHA-256 equals the pinned digest, into
//! the layout `ci/fetch-chromium.sh` writes (`<cache>/<version>/chrome-linux64/chrome`).

use anyhow::Context as _;
use clap::{Args, Subcommand};
use crawlx_browser::install::{self, InstallRequest};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// Arguments of `crawlx browser`.
#[derive(Args, Debug)]
pub struct BrowserArgs {
    /// What to do with the browser.
    #[command(subcommand)]
    pub command: BrowserCommand,
}

/// Subcommands of `crawlx browser`.
#[derive(Subcommand, Debug)]
pub enum BrowserCommand {
    /// Download the pinned Chromium into the cache (verifying its SHA-256) and print the path of
    /// its `chrome` binary on stdout. A build already cached is reused without a download.
    Install(InstallArgs),
}

/// Arguments of `crawlx browser install`.
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Install this version instead of the pinned one. Its archive URL is the pin's with the
    /// pinned version replaced, and it has no recorded digest: `--sha256` is required. A build
    /// other than the pinned one only launches with `CRAWLX_ALLOW_UNPINNED=1`.
    #[arg(long, value_name = "VERSION", requires = "sha256")]
    pub version: Option<String>,
    /// SHA-256 of the archive of `--version` (64 hexadecimal characters).
    #[arg(long, value_name = "HEX", requires = "version")]
    pub sha256: Option<String>,
    /// Pin file naming the archive (default: `CRAWLX_PIN_FILE`, else the nearest
    /// `chromium-pin.toml`, else the pin built into this binary).
    #[arg(long, value_name = "FILE")]
    pub pin_file: Option<PathBuf>,
    /// Cache directory (default `.cache/chromium`).
    #[arg(long, value_name = "DIR", env = "CRAWLX_CHROMIUM_CACHE")]
    pub chromium_cache: Option<PathBuf>,
}

/// Run `crawlx browser`.
///
/// # Errors
/// An unreadable pin, a download that fails, an archive whose digest is not the pinned one
/// (nothing is unpacked), or an archive that cannot be unpacked.
pub async fn run(args: BrowserArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match args.command {
        BrowserCommand::Install(install_args) => install_chromium(install_args, out).await,
    }
}

async fn install_chromium(args: InstallArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let pin = install::pin_for_install(args.pin_file.as_deref()).context("chromium pin")?;
    let cache = args.chromium_cache.unwrap_or_else(install::default_cache_root);
    let installed = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: args.version.as_deref(),
        sha256: args.sha256.as_deref(),
    })
    .await
    .context("chromium install")?;
    if installed.downloaded {
        eprintln!(
            "crawlx: installed Chromium {} into {}",
            installed.version,
            cache.display()
        );
    } else {
        eprintln!(
            "crawlx: Chromium {} is already cached (sha256 verified)",
            installed.version
        );
    }
    writeln!(out, "{}", installed.binary.display())?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Wrapper {
        #[command(flatten)]
        browser: BrowserArgs,
    }

    #[test]
    fn version_and_sha256_come_together() {
        assert!(Wrapper::try_parse_from(["x", "install"]).is_ok());
        assert!(Wrapper::try_parse_from(["x", "install", "--version", "1.2.3.4"]).is_err());
        assert!(Wrapper::try_parse_from(["x", "install", "--sha256", "ab"]).is_err());
        let ok = Wrapper::try_parse_from(["x", "install", "--version", "1.2.3.4", "--sha256", "ab"]).unwrap();
        let BrowserCommand::Install(i) = ok.browser.command;
        assert_eq!(i.version.as_deref(), Some("1.2.3.4"));
    }
}
