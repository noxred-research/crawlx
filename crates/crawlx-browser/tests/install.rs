//! Chromium auto-download against a local HTTP server that serves a small stand-in archive:
//! the pinned digest decides whether anything is unpacked.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::install::{self, InstallError, InstallRequest, STAMP_FILE};
use crawlx_browser::pin::ChromiumPin;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::BrowserError;
use parking_lot::Mutex;
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VERSION: &str = "155.0.8059.84";

/// A Chrome-for-Testing-shaped zip: `chrome-linux64/chrome` (executable shell script that
/// reports on stderr and exits) and one data file.
fn archive() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let exec = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
    let data = zip::write::SimpleFileOptions::default().unix_permissions(0o644);
    zip.start_file("chrome-linux64/chrome", exec).unwrap();
    zip.write_all(b"#!/bin/sh\necho 'fake chrome ran' >&2\nexit 1\n")
        .unwrap();
    zip.start_file("chrome-linux64/locales/en-US.pak", data).unwrap();
    zip.write_all(b"pak").unwrap();
    zip.finish().unwrap().into_inner()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Serve `body` for every request; the second value counts the requests.
async fn serve(body: Vec<u8>) -> (u16, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let (body, counter) = (body.clone(), Arc::clone(&counter));
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                *counter.lock() += 1;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (port, hits)
}

/// A pin file for a local archive with `sha256`.
fn pin_file(dir: &Path, port: u16, sha256: &str) -> PathBuf {
    let path = dir.join("chromium-pin.toml");
    std::fs::write(
        &path,
        format!(
            "[chromium]\nversion = \"{VERSION}\"\ndownload_url = \"http://127.0.0.1:{port}/{VERSION}/linux64/chrome-linux64.zip\"\nsha256 = \"{sha256}\"\n"
        ),
    )
    .unwrap();
    path
}

fn leftovers(cache: &Path) -> Vec<String> {
    std::fs::read_dir(cache)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn a_matching_digest_installs_a_runnable_build_and_the_cache_is_reused() {
    let zip = archive();
    let (port, hits) = serve(zip.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let pin = ChromiumPin::load(&pin_file(tmp.path(), port, &sha256_hex(&zip))).unwrap();
    let cache = tmp.path().join("cache");

    let first = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: None,
        sha256: None,
    })
    .await
    .unwrap();
    assert!(first.downloaded);
    assert_eq!(first.version, VERSION);
    assert_eq!(first.binary, cache.join(VERSION).join("chrome-linux64/chrome"));
    assert_ne!(
        first.binary.metadata().unwrap().permissions().mode() & 0o111,
        0,
        "chrome stays executable"
    );
    assert_eq!(
        std::fs::read_to_string(cache.join(VERSION).join(STAMP_FILE))
            .unwrap()
            .trim(),
        sha256_hex(&zip)
    );
    assert!(cache
        .join(VERSION)
        .join("chrome-linux64/locales/en-US.pak")
        .is_file());
    assert_eq!(
        leftovers(&cache),
        [VERSION.to_owned()],
        "no download scratch is left behind"
    );
    let ran = std::process::Command::new(&first.binary).output().unwrap();
    assert!(String::from_utf8_lossy(&ran.stderr).contains("fake chrome ran"));

    // second install: the stamp matches, so the network is not touched
    let second = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: None,
        sha256: None,
    })
    .await
    .unwrap();
    assert!(!second.downloaded);
    assert_eq!(second.binary, first.binary);
    assert_eq!(*hits.lock(), 1);
    assert_eq!(install::find_cached(&cache), Some(first.binary));
}

#[tokio::test]
async fn a_wrong_digest_fails_and_leaves_nothing_unpacked() {
    let zip = archive();
    let (port, hits) = serve(zip.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let wrong = "0".repeat(64);
    let pin = ChromiumPin::load(&pin_file(tmp.path(), port, &wrong)).unwrap();
    let cache = tmp.path().join("cache");

    let err = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: None,
        sha256: None,
    })
    .await
    .unwrap_err();
    match &err {
        InstallError::DigestMismatch { expected, actual, .. } => {
            assert_eq!(expected, &wrong);
            assert_eq!(actual, &sha256_hex(&zip));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(*hits.lock(), 1, "the archive was fetched, then refused");
    assert!(!cache.join(VERSION).exists(), "nothing was unpacked");
    assert_eq!(
        leftovers(&cache),
        Vec::<String>::new(),
        "the download scratch is gone too"
    );
    assert!(install::find_cached(&cache).is_none());
}

#[tokio::test]
async fn another_version_needs_its_own_digest_and_uses_the_pinned_url_shape() {
    let zip = archive();
    let (port, _hits) = serve(zip.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let pin = ChromiumPin::load(&pin_file(tmp.path(), port, &sha256_hex(&zip))).unwrap();
    let cache = tmp.path().join("cache");

    let refused = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: Some("156.0.1.2"),
        sha256: None,
    })
    .await
    .unwrap_err();
    assert!(
        matches!(refused, InstallError::UnpinnedVersion { .. }),
        "{refused:?}"
    );

    let ok = install::install(InstallRequest {
        pin: &pin,
        cache_root: &cache,
        version: Some("156.0.1.2"),
        sha256: Some(&sha256_hex(&zip)),
    })
    .await
    .unwrap();
    assert_eq!(ok.version, "156.0.1.2");
    assert!(ok.binary.starts_with(cache.join("156.0.1.2")));
    // the newest cached build is the one `find_executable` falls back to
    assert_eq!(install::find_cached(&cache), Some(ok.binary));
}

#[tokio::test]
async fn a_pin_without_an_archive_cannot_be_installed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("pin.toml");
    std::fs::write(&path, format!("[chromium]\nversion = \"{VERSION}\"\n")).unwrap();
    let pin = ChromiumPin::load(&path).unwrap();
    let err = install::install(InstallRequest {
        pin: &pin,
        cache_root: &tmp.path().join("cache"),
        version: None,
        sha256: None,
    })
    .await
    .unwrap_err();
    assert!(matches!(err, InstallError::NoArchive), "{err:?}");
}

#[tokio::test]
async fn auto_download_installs_the_pinned_build_and_launches_it() {
    let zip = archive();
    let (port, hits) = serve(zip.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let pin = pin_file(tmp.path(), port, &sha256_hex(&zip));
    let cache = tmp.path().join("cache");

    let mut cfg = LaunchConfig::new();
    cfg.executable = tmp.path().join("no-such-chrome");
    cfg.pin_file = Some(pin);
    cfg.chromium_cache = cache.clone();

    // off by default: the missing executable is simply a launch failure
    let off = ChromiumBackend::launch(cfg.clone()).await.err().unwrap();
    assert!(
        matches!(&off, BrowserError::Launch(m) if m.contains("cannot start")),
        "{off}"
    );
    assert_eq!(*hits.lock(), 0, "nothing is downloaded unless asked for");

    cfg.auto_download_chromium = true;
    let err = ChromiumBackend::launch(cfg).await.err().unwrap();
    // the downloaded stand-in ran (and exited before opening a DevTools endpoint)
    assert!(
        matches!(&err, BrowserError::Launch(m) if m.contains("fake chrome ran")),
        "{err}"
    );
    assert_eq!(*hits.lock(), 1);
    assert!(cache.join(VERSION).join("chrome-linux64/chrome").is_file());
}
