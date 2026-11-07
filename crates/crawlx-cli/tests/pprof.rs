//! `--pprof-bind` (katana `-pprof-server`): the in-process listener, its CLI flags and its wiring
//! into the real `crawlx serve` / `crawlx worker` binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_cli::pprof::{
    bind_pprof, parse_seconds, serve_on, InvalidSeconds, PprofArgs, PprofError, PprofListener,
    DEFAULT_PROFILE_SECONDS, MAX_PROFILE_SECONDS, MIN_PROFILE_SECONDS,
};
use pprof::protos::{Message, Profile};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The CPU sampler is process-global: tests that profile must not overlap.
static PROFILER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Server {
    addr: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<Result<(), PprofError>>,
}

impl Server {
    async fn start() -> Self {
        let listener = bind_pprof("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(serve_on(listener, stop.clone()));
        Self { addr, stop, task }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Stop the listener and require it to drain promptly and cleanly.
    async fn finish(self) {
        self.stop.cancel();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("listener did not drain after cancellation")
            .unwrap()
            .unwrap();
    }
}

/// A thread that burns CPU until dropped, so the sampler has something to see.
struct CpuBurner {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<u64>>,
}

#[inline(never)]
fn burn_cpu_for_profile_test(stop: &AtomicBool) -> u64 {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64;
    while !stop.load(Ordering::Relaxed) {
        for _ in 0..10_000 {
            x = std::hint::black_box(
                x.wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407),
            );
        }
    }
    x
}

impl CpuBurner {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || burn_cpu_for_profile_test(&flag));
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for CpuBurner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn decode(body: &[u8]) -> Profile {
    Profile::parse_from_bytes(body).expect("body is a pprof profile.proto message")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_is_a_decodable_pprof_profile_of_the_busy_thread() {
    let _serial = PROFILER.lock().await;
    let server = Server::start().await;
    let _burner = CpuBurner::start();

    let started = Instant::now();
    let response = reqwest::get(server.url("/debug/pprof/profile?seconds=1"))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/octet-stream");
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=profile.pb"
    );
    let body = response.bytes().await.unwrap();
    assert!(!body.is_empty());
    assert!(
        elapsed >= Duration::from_millis(950),
        "profile returned after {elapsed:?}"
    );

    let profile = decode(&body);
    assert!(!profile.sample.is_empty(), "no samples in {profile:?}");
    let total: i64 = profile.sample.iter().map(|s| s.value.iter().sum::<i64>()).sum();
    assert!(
        total >= 10,
        "only {total} sample values from a busy thread at 99 Hz for 1 s"
    );
    // the string table is index-addressed: entry 0 is the empty string, the rest are symbols
    let symbols: Vec<&str> = profile
        .string_table
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    assert!(!symbols.is_empty(), "empty string table");
    assert!(
        profile.function.iter().any(|f| usize::try_from(f.name)
            .ok()
            .is_some_and(|i| i < profile.string_table.len() && !profile.string_table[i].is_empty())),
        "no function resolved to a name"
    );
    assert!(
        symbols.iter().any(|s| s.contains("burn_cpu_for_profile_test")),
        "the busy function is not among the {} symbols: {:?}",
        symbols.len(),
        &symbols[..symbols.len().min(40)]
    );
    // pprof's own sample-type table: samples/count and cpu/nanoseconds
    assert!(!profile.sample_type.is_empty());
    assert!(profile.period > 0);
    server.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn seconds_zero_is_clamped_to_one_second() {
    let _serial = PROFILER.lock().await;
    let server = Server::start().await;
    let _burner = CpuBurner::start();
    let started = Instant::now();
    let response = reqwest::get(server.url("/debug/pprof/profile?seconds=0"))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.status(), 200);
    assert!(!decode(&response.bytes().await.unwrap()).sample.is_empty());
    assert!(
        (Duration::from_millis(950)..Duration::from_secs(8)).contains(&elapsed),
        "seconds=0 took {elapsed:?}, expected the 1 s minimum"
    );
    server.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_concurrent_profile_conflicts_and_seconds_999_is_clamped_not_rejected() {
    let _serial = PROFILER.lock().await;
    let server = Server::start().await;
    let long = tokio::spawn(reqwest::get(server.url("/debug/pprof/profile?seconds=999")));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !long.is_finished(),
        "seconds=999 must be accepted (clamped to 120 s), not answered at once"
    );

    let second = reqwest::get(server.url("/debug/pprof/profile?seconds=1"))
        .await
        .unwrap();
    assert_eq!(second.status(), 409);
    assert!(second.text().await.unwrap().contains("already running"));
    // validation comes first: a bad value is a 400 even while the slot is taken
    assert_eq!(
        reqwest::get(server.url("/debug/pprof/profile?seconds=abc"))
            .await
            .unwrap()
            .status(),
        400
    );
    // the heap summary is not blocked by a running profile
    assert_eq!(
        reqwest::get(server.url("/debug/pprof/heap"))
            .await
            .unwrap()
            .status(),
        200
    );

    // shutdown abandons the 120 s profile instead of waiting for it
    let stopped = Instant::now();
    server.stop.cancel();
    let first = long.await.unwrap().unwrap();
    assert_eq!(first.status(), 503);
    assert!(first.text().await.unwrap().contains("shutting down"));
    assert!(
        stopped.elapsed() < Duration::from_secs(10),
        "shutdown waited for the profile"
    );
    server.finish().await;

    // the slot is free again: a fresh listener profiles normally
    let again = Server::start().await;
    let _burner = CpuBurner::start();
    assert_eq!(
        reqwest::get(again.url("/debug/pprof/profile?seconds=1"))
            .await
            .unwrap()
            .status(),
        200
    );
    again.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_numeric_seconds_is_a_400_before_any_profiling() {
    let server = Server::start().await;
    for bad in ["abc", "-1", "1.5", "", "1e3", "99999999999999999999999"] {
        let response = reqwest::get(server.url(&format!("/debug/pprof/profile?seconds={bad}")))
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "seconds={bad:?}");
        let message = response.text().await.unwrap();
        assert!(
            message.contains("seconds must be a non-negative integer"),
            "{message}"
        );
    }
    server.finish().await;
}

#[test]
fn seconds_rule_defaults_clamps_and_rejects() {
    let secs = |raw: Option<&str>| parse_seconds(raw).map(|d| d.as_secs());
    assert_eq!(secs(None), Ok(DEFAULT_PROFILE_SECONDS));
    assert_eq!(
        (DEFAULT_PROFILE_SECONDS, MIN_PROFILE_SECONDS, MAX_PROFILE_SECONDS),
        (10, 1, 120)
    );
    assert_eq!(secs(Some("0")), Ok(1));
    assert_eq!(secs(Some("5")), Ok(5));
    assert_eq!(secs(Some("999")), Ok(120));
    assert_eq!(secs(Some("abc")), Err(InvalidSeconds("abc".to_owned())));
}

/// A `/proc/self/status` kB value of the test process, read independently of the server.
fn own_status_kib(key: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heap_reports_what_the_memory_sampler_measures() {
    if !std::path::Path::new("/proc/self/status").exists() {
        eprintln!("skipping: no /proc, the memory sampler reads procfs");
        return;
    }
    let server = Server::start().await;
    let client = reqwest::Client::new();
    let get = || async {
        let response = client.get(server.url("/debug/pprof/heap")).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "application/json");
        response.json::<Value>().await.unwrap()
    };

    let before = get().await;
    assert_eq!(before["source"], "procfs");
    assert_eq!(before["pid"], std::process::id());
    let rss = before["rss_bytes"].as_u64().unwrap();
    let kib_now = own_status_kib("VmRSS") * 1024;
    assert!(
        rss > 0 && rss.abs_diff(kib_now) < kib_now / 2 + (64 << 20),
        "rss {rss} vs /proc {kib_now}"
    );
    assert!(before["peak_rss_bytes"].as_u64().unwrap() >= rss);
    assert!(before["virtual_bytes"].as_u64().unwrap() >= rss);
    assert!(before["data_bytes"].as_u64().unwrap() > 0);
    assert!(before["swap_bytes"].is_u64());
    assert!(before["threads"].as_u64().unwrap() >= 1);
    // the tree walk of `crawlx_browser::launch::tree_rss_bytes` includes this process itself
    assert!(before["rss_tree_bytes"].as_u64().unwrap() > 0);
    // no browser ran in this process: the gauge exists in the document but has no sample
    assert!(before
        .as_object()
        .unwrap()
        .contains_key("browser_rss_gauge_bytes"));

    // touch 96 MiB: the reported resident size must follow
    let mut ballast = vec![0_u8; 96 << 20];
    for page in ballast.chunks_mut(4096) {
        page[0] = 1;
    }
    let after = get().await;
    let grown = after["rss_bytes"].as_u64().unwrap();
    assert!(
        grown >= rss + (64 << 20),
        "rss {rss} -> {grown} after touching 96 MiB"
    );
    assert!(after["peak_rss_bytes"].as_u64().unwrap() >= grown);
    std::hint::black_box(&ballast);
    drop(ballast);

    assert_eq!(
        client
            .get(server.url("/debug/pprof/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .post(server.url("/debug/pprof/heap"))
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    server.finish().await;
}

#[tokio::test]
async fn non_loopback_binds_are_refused_unless_allowed() {
    for bad in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0", "[2001:db8::1]:0"] {
        let bind: SocketAddr = bad.parse().unwrap();
        let err = bind_pprof(bind, false).await.unwrap_err();
        assert!(
            matches!(err, PprofError::NonLoopback { bind: b } if b == bind),
            "{bad}: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("not a loopback address")
                && message.contains("CRAWLX_PPROF_ALLOW_NON_LOOPBACK=1"),
            "{message}"
        );
    }
    for good in ["127.0.0.1:0", "[::1]:0"] {
        match bind_pprof(good.parse().unwrap(), false).await {
            Ok(listener) => assert!(listener.local_addr().unwrap().ip().is_loopback()),
            // the sandbox may have no IPv6 loopback; a bind failure is still not a refusal
            Err(PprofError::Bind { .. }) if good.starts_with("[::1]") => {}
            Err(e) => panic!("{good}: {e}"),
        }
    }
    // the operator override binds a wildcard address
    let listener = bind_pprof("0.0.0.0:0".parse().unwrap(), true).await.unwrap();
    assert!(listener.local_addr().unwrap().ip().is_unspecified());

    // through the flags: refused without the override, nothing started
    let args = PprofArgs {
        pprof_bind: Some("0.0.0.0:0".parse().unwrap()),
        pprof_allow_non_loopback: false,
    };
    assert!(matches!(
        PprofListener::start(&args).await,
        Err(PprofError::NonLoopback { .. })
    ));
    assert!(PprofListener::start(&PprofArgs::default())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_handle_starts_and_drains() {
    // a loopback listener on a port found by binding first: `PprofListener::start` binds the
    // address given. Another process can take the probed port between the drop and the bind (the
    // whole workspace runs in parallel), so a taken port is probed again.
    let mut taken = 0;
    let (listener, addr) = loop {
        let probe = bind_pprof("127.0.0.1:0".parse().unwrap(), false).await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let args = PprofArgs {
            pprof_bind: Some(addr),
            pprof_allow_non_loopback: false,
        };
        match PprofListener::start(&args).await {
            Ok(listener) => break (listener.expect("--pprof-bind was set"), addr),
            Err(PprofError::Bind { source, .. })
                if source.kind() == std::io::ErrorKind::AddrInUse && taken < 5 =>
            {
                taken += 1;
            }
            Err(error) => panic!("{error}"),
        }
    };
    assert_eq!(
        reqwest::get(format!("http://{addr}/debug/pprof/heap"))
            .await
            .unwrap()
            .status(),
        200
    );
    tokio::time::timeout(Duration::from_secs(10), listener.shutdown())
        .await
        .expect("shutdown drains");
    assert!(
        reqwest::get(format!("http://{addr}/debug/pprof/heap"))
            .await
            .is_err(),
        "listener still up"
    );
}

// ---- the real binary ----------------------------------------------------------------------

fn crawlx() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    for var in [
        "CRAWLX_PPROF_BIND",
        "CRAWLX_PPROF_ALLOW_NON_LOOPBACK",
        "CRAWLX_METRICS_BIND",
        "CRAWLX_DATABASE_URL",
        "CRAWLX_DATABASE_URL_FILE",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn help(args: &[&str]) -> String {
    let out = crawlx().args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn serve_and_worker_help_document_the_pprof_flags() {
    for sub in ["serve", "worker"] {
        let h = help(&[sub, "--help"]);
        assert!(h.contains("--pprof-bind <ADDR>"), "{sub}: {h}");
        assert!(h.contains("CRAWLX_PPROF_BIND"), "{sub}: {h}");
        assert!(h.contains("--pprof-allow-non-loopback"), "{sub}: {h}");
        assert!(h.contains("CRAWLX_PPROF_ALLOW_NON_LOOPBACK"), "{sub}: {h}");
        assert!(h.contains("/debug/pprof/profile"), "{sub}: {h}");
    }
    // `crawl` runs in the foreground: no listener
    assert!(!help(&["crawl", "--help"]).contains("--pprof"));
}

/// A spawned `crawlx` that is killed when the test ends.
struct Spawned(Child);

impl Spawned {
    fn stderr(&mut self) -> String {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let mut text = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut text);
        }
        text
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn heap_of(child: &mut Spawned, port: u16) -> Value {
    try_heap_of(child, port).await.unwrap_or_else(|e| panic!("{e}"))
}

/// [`heap_of`] reporting a failure (the child died or never listened) instead of panicking.
async fn try_heap_of(child: &mut Spawned, port: u16) -> Result<Value, String> {
    let url = format!("http://127.0.0.1:{port}/debug/pprof/heap");
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if let Ok(response) = reqwest::get(&url).await {
            assert_eq!(response.status(), 200);
            return Ok(response.json().await.unwrap());
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            return Err(format!("crawlx exited early ({status}): {}", child.stderr()));
        }
        if Instant::now() >= deadline {
            return Err(format!("no pprof listener on {url}: {}", child.stderr()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test]
fn serve_refuses_a_non_loopback_pprof_bind() {
    let out = crawlx()
        .args(["serve", "--bind", "127.0.0.1:0", "--pprof-bind", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a loopback address") && stderr.contains("CRAWLX_PPROF_ALLOW_NON_LOOPBACK=1"),
        "{stderr}"
    );

    // the same through the environment variable
    let out = crawlx()
        .env("CRAWLX_PPROF_BIND", "[::]:0")
        .args(["serve", "--bind", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a loopback address"));

    // a malformed address is a usage error, not a panic
    let out = crawlx()
        .args(["serve", "--pprof-bind", "not-an-address"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--pprof-bind"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_runs_the_pprof_listener_beside_the_api() {
    let port = free_loopback_port();
    let child = crawlx()
        .args([
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--pprof-bind",
            &format!("127.0.0.1:{port}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut child = Spawned(child);
    let heap = heap_of(&mut child, port).await;
    assert_eq!(heap["pid"], pid);
    assert!(heap["rss_bytes"].as_u64().unwrap() > 0);
    assert!(heap["peak_rss_bytes"].as_u64().unwrap() >= heap["rss_bytes"].as_u64().unwrap());

    let response = reqwest::get(format!("http://127.0.0.1:{port}/debug/pprof/profile?seconds=1"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!decode(&response.bytes().await.unwrap()).string_table.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_allow_env_var_lets_serve_bind_a_wildcard_address() {
    let port = free_loopback_port();
    let child = crawlx()
        .env("CRAWLX_PPROF_ALLOW_NON_LOOPBACK", "1")
        .env("CRAWLX_PPROF_BIND", format!("0.0.0.0:{port}"))
        .args(["serve", "--bind", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = Spawned(child);
    let heap = heap_of(&mut child, port).await;
    assert_eq!(heap["source"], "procfs");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_runs_the_pprof_listener() {
    let Ok(base_url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipping: CRAWLX_TEST_DATABASE_URL is not set, `crawlx worker` leases from PostgreSQL");
        return;
    };
    // a PostgreSQL worker refuses to start without encrypted artifact custody
    let Ok(secret_redis) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        eprintln!("skipping: CRAWLX_TEST_SECRET_REDIS_URL is not set, a PostgreSQL worker needs the secret registry");
        return;
    };
    let Ok(admin) = PgPoolOptions::new().max_connections(1).connect(&base_url).await else {
        eprintln!("skipping: PostgreSQL at CRAWLX_TEST_DATABASE_URL is not reachable");
        return;
    };
    // a throwaway schema, migrated by the binary itself (the chaos suite's recipe)
    let schema = format!("t_pprof_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let sep = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{sep}options=-c%20search_path%3D{schema}");
    let outcome = async {
        let migrated = crawlx()
            .args(["migrate", "--database-url", &database_url])
            .output()
            .unwrap();
        assert!(
            migrated.status.success(),
            "migrate: {}",
            String::from_utf8_lossy(&migrated.stderr)
        );
        let artifacts = tempfile::tempdir().unwrap();
        let key_dir = tempfile::tempdir().unwrap();
        let key_file = key_dir.path().join("artifact.key");
        std::fs::write(&key_file, format!("{}\n", "ab".repeat(32))).unwrap();
        std::fs::set_permissions(&key_file, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let kms = crawlx_storage::testkit::fake_kms::LoopbackKms::start()
            .await
            .unwrap();
        let port = free_loopback_port();
        let child = crawlx()
            .env("CRAWLX_ALLOW_UNPINNED", "1")
            .env("CRAWLX_CHECKPOINT_KMS_KEY_ID", kms.key_id())
            .env("CRAWLX_ARTIFACT_KEY_FILE", &key_file)
            .env("CRAWLX_SECRET_REDIS_URL", &secret_redis)
            .env("AWS_ENDPOINT_URL_KMS", kms.endpoint())
            .env("AWS_REGION", "us-east-1")
            .env("AWS_ACCESS_KEY_ID", "checkpoint-fixture-access-key")
            .env("AWS_SECRET_ACCESS_KEY", "checkpoint-fixture-secret-key")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .args([
                "worker",
                "--database-url",
                &database_url,
                "--pprof-bind",
                &format!("127.0.0.1:{port}"),
            ])
            .arg("--artifacts-dir")
            .arg(artifacts.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut child = Spawned(child);
        let heap = try_heap_of(&mut child, port).await?;
        assert_eq!(heap["pid"], pid);
        assert!(heap["rss_bytes"].as_u64().unwrap() > 0);
        Ok::<(), String>(())
    }
    .await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    outcome.unwrap();
}
