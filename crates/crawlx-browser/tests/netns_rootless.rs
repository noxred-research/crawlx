//! Real rootless network-namespace acceptance for `launch::spawn`.
//!
//! Opt in with `CRAWLX_RUN_NETNS_ROOTLESS_ACCEPTANCE=1` and `CRAWLX_CHROMIUM_PATH=/abs/chrome`;
//! without the opt-in the test skips with a message. Once opted in, missing prerequisites
//! (user namespaces, `/etc/subuid` and `/etc/subgid` ranges, `newuidmap`/`newgidmap`, `mount`,
//! `unshare`, `nft`, `setpriv`, a Chromium sandbox) fail the test; they are never a pass.
//! `CRAWLX_NETNS_HELPER` overrides the in-repository helper path. The worker must be an
//! ordinary non-root user.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::cdp::CdpClient;
use crawlx_browser::launch::{self, find_executable};
use crawlx_browser::netns::{NamespaceConfig, NamespaceMode};
use crawlx_browser::LaunchConfig;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const OPT_IN: &str = "CRAWLX_RUN_NETNS_ROOTLESS_ACCEPTANCE";

/// Proxy fixture: serves absolute-URI GETs, denies CONNECT, records every request target.
async fn proxy_fixture() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let mut parts = line.split_whitespace();
                let (method, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
                log.lock().unwrap().push(format!("{method} {target}"));
                let response = if method == "GET" {
                    let body = "<!doctype html><title>rootless fixture</title>";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                };
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// A loopback listener no namespaced browser may ever reach; counts accepted connections.
async fn bypass_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, accepted)
}

fn helper_path() -> PathBuf {
    std::env::var_os("CRAWLX_NETNS_HELPER")
        .map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/isolation/crawlx-netns-helper.py"),
            PathBuf::from,
        )
        .canonicalize()
        .expect("namespace helper path")
}

fn field_of(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Live members of a process group, from `/proc`.
fn group_members(group: u32) -> Vec<u32> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let (state, _ppid, pgrp) = (
            fields.next(),
            fields.next(),
            fields.next().and_then(|v| v.parse::<u32>().ok()),
        );
        if pgrp == Some(group) && state != Some("Z") {
            members.push(pid);
        }
    }
    members
}

/// Whether a seccomp-bpf sandboxed renderer exists in the group (Chromium's own sandbox is live).
fn sandboxed_renderer(group: u32) -> bool {
    group_members(group).into_iter().any(|pid| {
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            return false;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            return false;
        };
        cmdline.windows(15).any(|window| window == b"--type=renderer") && field_of(&status, "Seccomp:") == "2"
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rootless_browser_reaches_only_the_proxy_and_cdp_and_dies_with_its_group() {
    if std::env::var(OPT_IN).as_deref() != Ok("1") {
        eprintln!("SKIP: set {OPT_IN}=1 and CRAWLX_CHROMIUM_PATH for the rootless namespace acceptance");
        return;
    }
    let executable = find_executable().expect("CRAWLX_CHROMIUM_PATH must name the Chromium executable");
    let (proxy_port, seen) = proxy_fixture().await;
    let (_bypass_port, bypassed) = bypass_listener().await;

    let mut config = LaunchConfig::new();
    config.executable = executable.clone();
    config.allow_unpinned = true;
    config.egress_proxy_port = Some(proxy_port);
    config.namespace = Some(NamespaceConfig::rootless(helper_path(), 1000, 1000));
    let profile = tempfile::tempdir().unwrap();
    let profile_path = profile.path().to_path_buf();
    let mut spawned = launch::spawn(&config, Some(profile), profile_path.clone())
        .await
        .expect("rootless namespace launch");

    // `spawn` already verified evidence, process identity, executable inode and the CDP endpoint.
    let launch = spawned.namespace.clone().expect("namespace launch evidence");
    assert_eq!(launch.mode, NamespaceMode::Rootless);
    let group = spawned.process.pid().expect("helper group leader");
    launch
        .verify_process(group)
        .await
        .expect("actual browser identity");
    launch
        .verify_executable(&executable)
        .await
        .expect("configured Chromium inode");
    let own = std::fs::read_to_string("/proc/self/status").unwrap();
    let own_uid: u32 = field_of(&own, "Uid:")
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(
        launch.host_uid, own_uid,
        "Chromium must not share the worker's kernel identity"
    );
    assert_ne!(
        std::fs::read_link(format!("/proc/{}/ns/user", launch.browser_pid)).unwrap(),
        std::fs::read_link("/proc/self/ns/user").unwrap(),
    );
    assert_ne!(
        std::fs::read_link(format!("/proc/{}/ns/net", launch.browser_pid)).unwrap(),
        std::fs::read_link("/proc/self/ns/net").unwrap(),
    );

    // CDP works through the worker-owned relay, and Chromium reaches only the existing proxy.
    let client = CdpClient::connect(&spawned.ws_url)
        .await
        .expect("CDP over the namespace relay");
    let version = client
        .call("Browser.getVersion", None, json!({}))
        .await
        .expect("Browser.getVersion");
    assert!(version["product"]
        .as_str()
        .is_some_and(|product| product.contains("Chrome")));
    client
        .call(
            "Target.createTarget",
            None,
            json!({ "url": "http://fixture.invalid/" }),
        )
        .await
        .expect("Target.createTarget");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !seen
        .lock()
        .unwrap()
        .iter()
        .any(|request| request == "GET http://fixture.invalid/")
    {
        assert!(
            Instant::now() < deadline,
            "Chromium did not use the existing proxy: {:?}",
            seen.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sandboxed_renderer(group) {
        assert!(
            Instant::now() < deadline,
            "no seccomp-sandboxed Chromium renderer observed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        bypassed.load(Ordering::SeqCst),
        0,
        "namespaced browser reached a host loopback listener"
    );
    // Chromium state lives in the namespace tmpfs; only the relay socket directory is on the host.
    for entry in std::fs::read_dir(&profile_path).unwrap().flatten() {
        assert!(
            entry.file_name().to_string_lossy().starts_with(".crawlx-netns-"),
            "host profile polluted"
        );
    }

    // Cancellation: the whole owned group dies and the profile disappears with its guard.
    drop(client);
    spawned
        .process
        .shutdown_confirmed(Duration::from_millis(1))
        .await
        .expect("confirmed group death");
    assert!(
        group_members(group).is_empty(),
        "namespace processes survived group cleanup"
    );
    assert!(!Path::new(&format!("/proc/{}", launch.browser_pid)).exists());
    drop(spawned);
    assert!(!profile_path.exists(), "profile directory was not removed");
}
