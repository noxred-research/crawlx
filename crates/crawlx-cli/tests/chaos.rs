//! Chaos suite: the built `crawlx`
//! binary crawls a CrawlerGym fixture in dynamic mode against PostgreSQL, is `SIGKILL`ed
//! while an action is `intended`, and `crawlx worker --recover` finishes the run.
//!
//! * `d1` in `read_only`: the interrupted action went `intended -> unknown -> reconciled`
//!   (never re-executed blindly), no row is left `intended` or `unknown`, the gym ledger saw
//!   no more effects than the journal accounts for, and the run completes.
//! * `counter` in `test_environment`: the only control is a button whose handler issues
//!   `POST /counter/api/increment`. The kill lands after the click reached the page but before
//!   T2, so the server count equals the journaled `succeeded` increments plus at most one
//!   in-flight action; `repeated_non_idempotent_actions = 0`.
//!
//! Both end with `crawlx_bench::trail::verify_trail` over the run.
//!
//! Skipped without `CRAWLX_TEST_DATABASE_URL`, `CRAWLX_TEST_SECRET_REDIS_URL` (the
//! persistence-free secret registry every PostgreSQL crawl needs) and a Chromium
//! executable. Each harness gets its own 64-hex artifact root key file. With
//! `--features chaos` the crawl process sleeps at the chosen failpoint, so the kill lands
//! deterministically on an `intended` row. The harness matches the pretty log event's exact
//! failpoint field and pins one executable snapshot for crawl and recovery, preventing a
//! concurrent non-chaos build from silently changing the subprocess behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::server::{GymHandle, GymServer};
use crawlx_bench::trail::{verify_trail, TrailStore};
use crawlx_core::config::StrategyName;
use crawlx_core::{Clock, CrawlRunId, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::testkit::fake_kms::LoopbackKms;
use crawlx_storage::{Pg, StoreConfig};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row as _};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::process::Command;

// Cargo's unhashed binary path can be replaced by a concurrent non-chaos build. Keep one
// immutable, executable snapshot for the whole suite, including recovery subprocesses.
// Unlink its temporary name after opening it read-only; the OS cleans up the pinned inode.
static CRAWLX: LazyLock<std::fs::File> = LazyLock::new(|| {
    let snapshot = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_crawlx"), snapshot.path()).unwrap();
    std::fs::File::open(snapshot.path()).unwrap()
});
/// How long the crawl may take to reach the kill condition.
const KILL_WINDOW: Duration = Duration::from_secs(180);
/// How long `worker --recover` may take (lease expiry + recovery + idle exit).
const RECOVER_WINDOW: Duration = Duration::from_secs(600);

fn chromium() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CRAWLX_CHROMIUM_PATH") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    [
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome", // wire-compat: installed browser path
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

/// `base?options=-c search_path=<schema>`: every connection of the spawned processes and
/// of this test works inside one throwaway schema of the shared test database.
fn schema_url(base: &str, schema: &str) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}options=-c%20search_path%3D{schema}")
}

fn write_record(dir: &Path, origin: &str) -> PathBuf {
    let now = SystemClock.now();
    let record = AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), now, &[origin])
    };
    let path = dir.join("authz.local.json");
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    path
}

/// A fresh artifact root key (64 hex characters, mode `0600`) in `dir`.
fn write_artifact_key(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("artifact.key");
    std::fs::write(
        &path,
        format!("{}\n", uuid::Uuid::new_v4().simple().to_string().repeat(2)),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// Direct children of `pid` (the Chromium processes the crawl launched), from procfs.
fn children_of(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for task in tasks.flatten() {
        if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(text.split_whitespace().filter_map(|s| s.parse::<u32>().ok()));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// `kill -9` a process and the process group it leads (Chromium leads its own group).
fn kill_hard(pid: u32) {
    for target in [format!("-{pid}"), pid.to_string()] {
        let _ = std::process::Command::new("kill")
            .args(["-9", "--", &target])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Debug)]
struct Counts {
    intended: i64,
    unknown: i64,
    succeeded: i64,
    failed: i64,
    reconciled: i64,
}

async fn counts(pool: &PgPool, run: uuid::Uuid) -> Counts {
    let rows =
        sqlx::query("SELECT status::text AS s, count(*) AS n FROM actions WHERE run_id = $1 GROUP BY 1")
            .bind(run)
            .fetch_all(pool)
            .await
            .unwrap();
    let mut c = Counts {
        intended: 0,
        unknown: 0,
        succeeded: 0,
        failed: 0,
        reconciled: 0,
    };
    for r in rows {
        let s: String = r.get("s");
        let n: i64 = r.get("n");
        match s.as_str() {
            "intended" => c.intended = n,
            "unknown" => c.unknown = n,
            "succeeded" => c.succeeded = n,
            "failed" => c.failed = n,
            "reconciled" => c.reconciled = n,
            _ => {}
        }
    }
    c
}

async fn run_id_for(pool: &PgPool, seed_url: &str) -> Option<uuid::Uuid> {
    sqlx::query(
        "SELECT run_id FROM crawl_runs WHERE config->>'seedUrl' = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(seed_url)
    .fetch_optional(pool)
    .await
    .unwrap()
    .map(|r| r.get::<uuid::Uuid, _>("run_id"))
}

async fn run_status(pool: &PgPool, run: uuid::Uuid) -> String {
    sqlx::query("SELECT status::text AS s FROM crawl_runs WHERE run_id = $1")
        .bind(run)
        .fetch_one(pool)
        .await
        .unwrap()
        .get("s")
}

/// `(action_id, action_kind, status)` of one journal row, as the kill predicate sees it.
type JournalRow = (uuid::Uuid, String, String);

fn succeeded(rows: &[JournalRow]) -> usize {
    rows.iter().filter(|(_, _, s)| s == "succeeded").count()
}

/// Pretty logs put the failpoint field on the line after the sleep event's header.
fn sleeping_at(log: &str, failpoint: &str) -> bool {
    log.lines().zip(log.lines().skip(1)).any(|(header, field)| {
        header.ends_with("failpoint: sleeping") && field.trim().strip_prefix("failpoint: ") == Some(failpoint)
    })
}

/// One throwaway schema, gym, Chromium and output directory per test.
struct Harness {
    schema: String,
    admin: PgPool,
    pool: PgPool,
    db: String,
    gym: GymHandle,
    dir: tempfile::TempDir,
    chromium: PathBuf,
    authz: PathBuf,
    kms: LoopbackKms,
    /// Root key file of the encrypted artifact custody, `0600`, inside `dir`.
    artifact_key: PathBuf,
    /// The persistence-free secret registry the crawl and the recovery worker share.
    secret_redis: String,
}

/// What the crawl left behind when it was killed.
struct Killed {
    run: uuid::Uuid,
    /// Rows `intended` at the moment of the kill.
    intended_at_kill: Vec<uuid::Uuid>,
}

impl Harness {
    /// `None` when PostgreSQL, the secret registry or Chromium is missing (the test skips).
    async fn start(label: &str) -> Option<Self> {
        let Ok(base_url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return None;
        };
        let Ok(secret_redis) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
            eprintln!("skipped: CRAWLX_TEST_SECRET_REDIS_URL is not set");
            return None;
        };
        let Some(chromium) = chromium() else {
            eprintln!("skipped: no Chromium executable (CRAWLX_CHROMIUM_PATH)");
            return None;
        };
        let schema = format!("t_chaos_{label}_{}", uuid::Uuid::now_v7().simple());
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&base_url)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let db = schema_url(&base_url, &schema);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&db)
            .await
            .unwrap();
        let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let authz = write_record(dir.path(), &gym.base_url);
        let kms = LoopbackKms::start().await.unwrap();
        let artifact_key = write_artifact_key(dir.path());
        let h = Self {
            schema,
            admin,
            pool,
            db,
            gym,
            dir,
            chromium,
            authz,
            kms,
            artifact_key,
            secret_redis,
        };
        // 0. schema: `crawlx migrate` inside the throwaway schema
        let status = h
            .command("migrate.log")
            .args(["migrate", "--database-url", &h.db])
            .status()
            .await
            .unwrap();
        assert!(
            status.success(),
            "migrate failed: {status}; log:\n{}",
            h.log("migrate.err")
        );
        Some(h)
    }

    fn command(&self, log: &str) -> Command {
        let log = self.dir.path().join(log);
        let binary = format!("/proc/{}/fd/{}", std::process::id(), CRAWLX.as_raw_fd());
        let mut cmd = Command::new(binary);
        cmd.env("CRAWLX_CHROMIUM_PATH", &self.chromium)
            .env("CRAWLX_ALLOW_UNPINNED", "1")
            .env("CRAWLX_GATES_DIR", self.dir.path().join("absent-gates"))
            .env_remove("CRAWLX_GATE_KEYS_FILE")
            .env("CRAWLX_DATABASE_URL", &self.db)
            .env("CRAWLX_LOG", "info")
            .env("CRAWLX_CHECKPOINT_KMS_KEY_ID", self.kms.key_id())
            .env("CRAWLX_ARTIFACT_KEY_FILE", &self.artifact_key)
            .env("CRAWLX_SECRET_REDIS_URL", &self.secret_redis)
            .env("AWS_ENDPOINT_URL_KMS", self.kms.endpoint()) // wire-compat: SDK environment variable
            .env("AWS_REGION", "us-east-1") // wire-compat: SDK environment variable
            .env("AWS_ACCESS_KEY_ID", "checkpoint-fixture-access-key") // wire-compat: SDK environment variable
            .env("AWS_SECRET_ACCESS_KEY", "checkpoint-fixture-secret-key") // wire-compat: SDK environment variable
            .env("AWS_EC2_METADATA_DISABLED", "true") // wire-compat: SDK environment variable
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&log).unwrap())
            .stderr(std::fs::File::create(log.with_extension("err")).unwrap())
            .kill_on_drop(true);
        cmd.process_group(0);
        cmd
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(name)).unwrap_or_default()
    }

    fn out_dir(&self) -> PathBuf {
        self.dir.path().join("out")
    }

    /// Step 1: crawl `seed_url`, killed hard once `done(rows)` holds over the journal rows.
    /// With `--features chaos`, also wait for the exact failpoint's sleep marker. This
    /// distinguishes an open T2 transaction from the earlier committed T1.
    async fn crawl_and_kill(
        &self,
        seed_url: &str,
        profile: &str,
        limit: &str,
        failpoint: &str,
        done: impl Fn(&[JournalRow]) -> bool,
    ) -> Killed {
        let out_dir = self.out_dir();
        // The chaos evidence precedes G1. Exercise real journal/recovery behavior with
        // ungated strategies rather than fabricating a passing gate to bootstrap itself.
        let mut request = crawlx_core::CreateCrawl::new(seed_url.parse().unwrap());
        request.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::EventDriven];
        let request_path = self.dir.path().join("chaos-request.json");
        std::fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        let mut crawl = self.command("crawl.log");
        crawl.args([
            "crawl",
            seed_url,
            "--mode",
            "dynamic",
            "--request",
            request_path.to_str().unwrap(),
            "--profile",
            profile,
            "--authorization-record",
            self.authz.to_str().unwrap(),
            "--allow-private-networks",
            "--seed",
            "20261019",
            "--delay-ms",
            "0",
            "--limit-interactions",
            limit,
            "--database-url",
            &self.db,
            "--output",
            out_dir.to_str().unwrap(),
        ]);
        if cfg!(feature = "chaos") {
            if failpoint.starts_with("t2.") || failpoint.starts_with("artifact.") {
                crawl.env("CRAWLX_STORAGE_PAUSE_AT", failpoint);
            } else {
                crawl.env("CRAWLX_FAILPOINTS", format!("{failpoint}=sleep(60000)"));
            }
        }
        let mut child = crawl.spawn().unwrap();
        let pid = child.id().unwrap();

        let started = Instant::now();
        let mut run = None;
        let (run, intended_at_kill): (uuid::Uuid, Vec<(uuid::Uuid, String)>) = loop {
            assert!(
                started.elapsed() < KILL_WINDOW,
                "crawl never reached the kill condition; log:\n{}",
                self.log("crawl.err")
            );
            if let Some(code) = child.try_wait().unwrap() {
                panic!(
                    "crawl exited ({code}) before it could be killed; log:\n{}",
                    self.log("crawl.err")
                );
            }
            if run.is_none() {
                run = run_id_for(&self.pool, seed_url).await;
            }
            if let Some(run) = run {
                let rows = sqlx::query(
                    "SELECT action_id, status::text AS s, action_kind::text AS k FROM actions WHERE run_id = $1",
                )
                .bind(run)
                .fetch_all(&self.pool)
                .await
                .unwrap();
                let rows: Vec<JournalRow> = rows
                    .iter()
                    .map(|r| {
                        (
                            r.get::<uuid::Uuid, _>("action_id"),
                            r.get::<String, _>("k"),
                            r.get::<String, _>("s"),
                        )
                    })
                    .collect();
                let reached = !cfg!(feature = "chaos") || sleeping_at(&self.log("crawl.err"), failpoint);
                if reached && done(&rows) {
                    break (
                        run,
                        rows.into_iter()
                            .filter(|(_, _, s)| s == "intended")
                            .map(|(id, k, _)| (id, k))
                            .collect(),
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let browsers = children_of(pid);
        kill_hard(pid);
        let _ = child.wait().await;
        for b in browsers {
            kill_hard(b);
        }
        let at_kill = counts(&self.pool, run).await;
        eprintln!(
            "killed pid {pid}: intended={:?} succeeded={} failed={}",
            intended_at_kill, at_kill.succeeded, at_kill.failed
        );
        let intended_at_kill: Vec<uuid::Uuid> = intended_at_kill.into_iter().map(|(id, _)| id).collect();
        // Before COMMIT, readers still see the committed T1. Post-T2 boundaries have
        // no in-flight action; the outcome is already durable.
        if cfg!(feature = "chaos")
            && matches!(
                failpoint,
                crawlx_worker::chaos::AFTER_INTENT_BEFORE_PERFORM
                    | crawlx_worker::chaos::AFTER_PERFORM_BEFORE_OUTCOME
                    | "t2.commit"
            )
        {
            assert!(
                !intended_at_kill.is_empty(),
                "the failpoint should have held an intended row"
            );
        }
        // the dead holder's rows are exactly what it left: nothing moves without a worker
        assert_eq!(run_status(&self.pool, run).await, "running");
        Killed {
            run,
            intended_at_kill,
        }
    }

    /// Step 2: wait for the session lease to expire (30 s TTL), then `crawlx worker --recover`.
    async fn recover(&self, run: uuid::Uuid) {
        let started = Instant::now();
        loop {
            let expired: bool = sqlx::query(
                "SELECT bool_and(lease_expires_at IS NULL OR lease_expires_at < now()) AS e FROM crawl_sessions WHERE run_id = $1",
            )
            .bind(run)
            .fetch_one(&self.pool)
            .await
            .unwrap()
            .get::<Option<bool>, _>("e")
            .unwrap_or(true);
            if expired {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(90),
                "session lease never expired"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let artifacts = self.out_dir().join("artifacts");
        let status = tokio::time::timeout(
            RECOVER_WINDOW,
            self.command("worker.log")
                .args([
                    "worker",
                    "--recover",
                    "--database-url",
                    &self.db,
                    "--artifacts-dir",
                    artifacts.to_str().unwrap(),
                ])
                .status(),
        )
        .await
        .expect("worker --recover did not exit in time")
        .unwrap();
        assert!(
            status.success(),
            "worker --recover failed: {status}; log:\n{}",
            self.log("worker.err")
        );
    }

    /// Step 3: journal invariants after recovery: nothing in flight, every row that
    /// was `intended` at the kill carries a reconciliation, and no id ran more than twice.
    async fn assert_journal_recovered(&self, killed: &Killed) -> Counts {
        let after = counts(&self.pool, killed.run).await;
        assert_eq!(
            (after.intended, after.unknown),
            (0, 0),
            "rows left in flight after recovery"
        );
        for id in &killed.intended_at_kill {
            let row = sqlx::query(
                "SELECT status::text AS s, reconcile_resolution, reconciled_at IS NOT NULL AS reconciled, attempt FROM actions WHERE action_id = $1",
            )
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .unwrap();
            let status: String = row.get("s");
            let resolution: Option<String> = row.get("reconcile_resolution");
            let reconciled: bool = row.get("reconciled");
            let attempt: i16 = row.get("attempt");
            assert!(reconciled, "{id}: intended row was never reconciled ({status})");
            assert!(resolution.is_some(), "{id}: reconciled without a resolution");
            match status.as_str() {
                "reconciled" => assert_ne!(resolution.as_deref(), Some("not_applied"), "{id}"),
                // a `not_applied` verdict re-intends the same id once; only then may it run
                "succeeded" | "failed" => {
                    assert_eq!(resolution.as_deref(), Some("not_applied"), "{id}");
                    assert_eq!(attempt, 1, "{id}: re-executed more than once");
                }
                other => panic!("{id}: unexpected final status {other}"),
            }
        }
        let reexecuted: i64 =
            sqlx::query("SELECT count(*) AS n FROM actions WHERE run_id = $1 AND attempt > 1")
                .bind(killed.run)
                .fetch_one(&self.pool)
                .await
                .unwrap()
                .get("n");
        assert_eq!(reexecuted, 0, "an action was executed more than twice");
        after
    }

    /// Step 5: the run finished and its trail verifies.
    async fn assert_completed_with_a_valid_trail(&self, run: uuid::Uuid) {
        assert_eq!(
            run_status(&self.pool, run).await,
            "completed",
            "worker log:\n{}",
            self.log("worker.err")
        );
        let pg = Pg::connect(&self.db, StoreConfig::default()).await.unwrap();
        let run = CrawlRunId(run);
        let owner = crawlx_core::repo::RunRepo::get(&pg, run).await.unwrap();
        // The crawl sealed its artifacts: read them back through the same root key the
        // processes used, exactly as `crawlx inspect` does.
        let key_file = self.artifact_key.to_string_lossy().into_owned();
        let (custody, keys) = crawlx_worker::config::read_only_custody_from_lookup(
            &crawlx_worker::DurableStore::Postgres(pg.clone()),
            &|name| (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| key_file.clone()),
        )
        .await
        .unwrap();
        let artifacts = crawlx_storage::FsArtifactStore::open(
            self.out_dir().join("artifacts"),
            std::sync::Arc::new(pg.clone()),
            std::sync::Arc::new(SystemClock),
        )
        .await
        .unwrap()
        .with_custody(custody, keys, crawlx_storage::CustodyWrites::ReadOnly)
        .with_read_scope(owner.tenant, run);
        let report = verify_trail(
            run,
            TrailStore::Database {
                store: &crawlx_worker::DurableStore::Postgres(pg.clone()),
                artifacts: Some(&artifacts),
            },
        )
        .await
        .unwrap();
        assert!(
            report.is_clean(),
            "trail violations or unverifiable evidence after the chaos run:\n{report:#?}"
        );
    }

    async fn teardown(self) {
        self.gym.shutdown().await;
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sigkill_mid_action_is_reconciled_once_and_the_run_completes_after_recovery() {
    let Some(h) = Harness::start("d1").await else {
        return;
    };
    let seed_url = h.gym.fixture_url("d1");
    // killed hard while an action is `intended` (failpoint) or after 3 successes
    let killed = h
        .crawl_and_kill(
            &seed_url,
            "read_only",
            "14",
            "after_intent_before_perform",
            |rows| rows.iter().any(|(_, _, s)| s == "intended") || succeeded(rows) >= 3,
        )
        .await;
    let clicks_at_kill = h.gym.ledger().clicks("d1").len();
    h.recover(killed.run).await;
    let after = h.assert_journal_recovered(&killed).await;

    // 4. ground truth: the ledger saw no more effects than the journal accounts for
    let clicks = h.gym.ledger().clicks("d1").len();
    let accounted = after.succeeded + after.failed + after.reconciled;
    assert!(
        i64::try_from(clicks).unwrap() <= accounted,
        "ledger saw {clicks} handler runs but the journal accounts for {accounted} \
         (succeeded {} + failed {} + reconciled {})",
        after.succeeded,
        after.failed,
        after.reconciled
    );
    assert!(clicks >= clicks_at_kill, "the ledger is append-only");

    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// Kill with all T2 statements applied but COMMIT not sent. PostgreSQL must roll the
/// transaction back, leaving exactly the committed T1 for the recovery worker.
#[cfg(feature = "chaos")]
#[tokio::test]
async fn sigkill_inside_t2_rolls_back_before_recovery() {
    let Some(h) = Harness::start("inside_t2").await else {
        return;
    };
    let seed_url = h.gym.fixture_url("d1");
    let killed = h
        .crawl_and_kill(&seed_url, "read_only", "14", "t2.commit", |rows| {
            rows.iter().any(|(_, _, status)| status == "intended")
        })
        .await;
    let unfinished_transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM transitions WHERE run_id = $1 AND action_id = ANY($2)")
            .bind(killed.run)
            .bind(&killed.intended_at_kill)
            .fetch_one(&h.pool)
            .await
            .unwrap();
    assert_eq!(unfinished_transitions, 0, "uncommitted T2 leaked a transition");
    h.recover(killed.run).await;
    h.assert_journal_recovered(&killed).await;
    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// A committed T2 survives death before the actor replies or asks for another proposal.
#[cfg(feature = "chaos")]
#[tokio::test]
async fn sigkill_after_t2_preserves_the_committed_outcome() {
    let Some(h) = Harness::start("after_t2").await else {
        return;
    };
    let seed_url = h.gym.fixture_url("d1");
    let killed = h
        .crawl_and_kill(
            &seed_url,
            "read_only",
            "14",
            crawlx_worker::chaos::AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL,
            |rows| succeeded(rows) >= 1,
        )
        .await;
    assert!(killed.intended_at_kill.is_empty());
    let committed: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT action_id FROM actions WHERE run_id = $1 AND status = 'succeeded'")
            .bind(killed.run)
            .fetch_all(&h.pool)
            .await
            .unwrap();
    h.recover(killed.run).await;
    h.assert_journal_recovered(&killed).await;
    let preserved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM actions WHERE action_id = ANY($1) AND status = 'succeeded' AND attempt = 0",
    )
    .bind(&committed)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    assert_eq!(preserved, i64::try_from(committed.len()).unwrap());
    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// A real process dies after object upload but before its artifact reference exists.
/// The reaper must honor the grace period, then remove the unreachable object.
#[cfg(feature = "chaos")]
#[tokio::test]
async fn sigkill_after_object_put_leaves_only_a_collectible_orphan() {
    use crawlx_storage::{ArtifactBlobs, FsArtifactStore, FsBlobs, RetentionSweeper};
    use std::sync::Arc;

    let Some(h) = Harness::start("object_put").await else {
        return;
    };
    let killed = h
        .crawl_and_kill(
            &h.gym.fixture_url("d1"),
            "read_only",
            "14",
            "artifact.after_object_put",
            |_| true,
        )
        .await;
    let root = h.out_dir().join("artifacts");
    let blobs = FsBlobs::open(&root).await.unwrap();
    let objects = blobs.list("").await.unwrap();
    assert_eq!(objects.len(), 1, "the first uploaded object survives SIGKILL");
    let orphan = &objects[0].key;
    let references: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE object_key = $1")
        .bind(orphan)
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(references, 0, "object upload must precede its durable reference");
    let pg = Pg::connect(&h.db, StoreConfig::default()).await.unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(root, Arc::new(pg.clone()), Arc::new(SystemClock))
            .await
            .unwrap(),
    );
    let sweeper = RetentionSweeper::new(pg).with_artifacts(artifacts);
    let now = SystemClock.now();
    assert_eq!(
        sweeper
            .collect_orphans(now, chrono::Duration::hours(1))
            .await
            .unwrap(),
        0,
    );
    assert!(blobs.exists(orphan).await.unwrap());
    assert_eq!(
        sweeper
            .collect_orphans(now + chrono::Duration::hours(2), chrono::Duration::hours(1))
            .await
            .unwrap(),
        1,
    );
    assert!(!blobs.exists(orphan).await.unwrap());
    h.recover(killed.run).await;
    h.assert_journal_recovered(&killed).await;
    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// The `counter` fixture's only control is a button whose handler issues a non-idempotent
/// `POST /counter/api/increment`. The kill lands after `perform` (the click reached the page
/// and the POST was sent) but before T2, so exactly one action is in flight: the server count
/// must equal the journaled `succeeded` increments plus at most that one action, and no key
/// may succeed twice (`repeated_non_idempotent_actions = 0`).
#[tokio::test]
async fn sigkill_on_counter_fixture_repeats_no_non_idempotent_action() {
    let Some(h) = Harness::start("counter").await else {
        return;
    };
    let seed_url = h.gym.fixture_url("counter");
    // The failpoint sleeps after `perform`: kill once a button press is `intended` *and* its
    // POST reached the server (the count exceeds the presses that already succeeded), so the
    // kill lands with the effect applied and T2 unwritten.
    let gym = &h.gym;
    let killed = h
        .crawl_and_kill(
            &seed_url,
            "test_environment",
            "6",
            "after_perform_before_outcome",
            |rows| {
                // The button is pressed by a `click` or a `keyboard_activate`; the seeded
                // strategies may pick either for the same control.
                let activation = |k: &str| k == "click" || k == "keyboard_activate";
                let intended_press = rows.iter().any(|(_, k, s)| activation(k) && s == "intended");
                let succeeded_presses = rows
                    .iter()
                    .filter(|(_, k, s)| activation(k) && s == "succeeded")
                    .count();
                (intended_press && gym.counter() > u64::try_from(succeeded_presses).unwrap())
                    || succeeded(rows) >= 2
            },
        )
        .await;
    let count_at_kill = h.gym.counter();
    assert!(count_at_kill > 0, "the crawl never pressed the button");
    h.recover(killed.run).await;
    let after = h.assert_journal_recovered(&killed).await;

    // 4. ground truth: server count == journaled increments (+ at most one in-flight action).
    // Only an activation of the button increments (`click`/`keyboard_activate`); hovers and
    // scrolls the strategies also propose are journaled but have no backend effect.
    let count = h.gym.counter();
    assert!(count >= count_at_kill, "the server count never decreases");
    let ledger_doc = reqwest_free_ledger(&h.gym.base_url).await;
    assert_eq!(
        ledger_doc["counter"], count,
        "/__gym/ledger mirrors the backend count"
    );
    let by_kind: Vec<(String, String, Option<String>, i64)> = sqlx::query(
        "SELECT action_kind::text AS k, status::text AS s, reconcile_resolution AS r, count(*) AS n \
         FROM actions WHERE run_id = $1 GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
    )
    .bind(killed.run)
    .fetch_all(&h.pool)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get("k"), r.get("s"), r.get("r"), r.get("n")))
    .collect();
    eprintln!("journal by kind/status/resolution: {by_kind:?}; server count {count}");
    let activates = |k: &str| k == "click" || k == "keyboard_activate" || k == "synthetic_click";
    let succeeded: i64 = by_kind
        .iter()
        .filter(|(k, s, _, _)| activates(k) && s == "succeeded")
        .map(|(_, _, _, n)| n)
        .sum();
    let in_flight: i64 = by_kind
        .iter()
        .filter(|(k, s, r, _)| {
            activates(k) && s == "reconciled" && matches!(r.as_deref(), Some("applied" | "indeterminate"))
        })
        .map(|(_, _, _, n)| n)
        .sum();
    assert!(
        in_flight <= 1,
        "more than one activation without a known outcome: {by_kind:?}"
    );
    let succeeded = u64::try_from(succeeded).unwrap();
    let in_flight = u64::try_from(in_flight).unwrap();
    assert!(
        count >= succeeded,
        "server count {count} below the journaled succeeded increments {succeeded}: {by_kind:?}"
    );
    let repeated_non_idempotent_actions = count.saturating_sub(succeeded + in_flight);
    assert_eq!(
        repeated_non_idempotent_actions, 0,
        "server count {count}, journal succeeded {succeeded} + in flight {in_flight}: {by_kind:?} {after:?}"
    );
    // the interrupted `action_id` is never re-intended after an `applied`/`indeterminate`
    // verdict (`assert_journal_recovered` already checked `attempt`); a later *proposal* of
    // the same key is a new action the crawler chose on an exercised key (the single-control
    // page only has repeats left) and is accounted for above, so it is reported, not asserted
    let later_same_key: Vec<(uuid::Uuid, i64)> = sqlx::query(
        "SELECT u.action_id, count(later.action_id) AS n FROM actions u \
         LEFT JOIN actions later ON later.run_id = u.run_id AND later.context_id = u.context_id \
           AND later.seq > u.seq AND later.status IN ('intended', 'succeeded', 'failed') \
         WHERE u.run_id = $1 AND u.status = 'reconciled' AND u.reconcile_resolution IN ('applied', 'indeterminate') \
         GROUP BY u.action_id",
    )
    .bind(killed.run)
    .fetch_all(&h.pool)
    .await
    .unwrap()
    .iter()
    .map(|r| (r.get("action_id"), r.get("n")))
    .collect();
    eprintln!("later proposals of the interrupted key: {later_same_key:?}");
    let reintended: i64 = sqlx::query(
        "SELECT count(*) AS n FROM actions WHERE run_id = $1 AND attempt > 0 \
         AND (reconcile_resolution IS NULL OR reconcile_resolution <> 'not_applied')",
    )
    .bind(killed.run)
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(
        reintended, 0,
        "an action id was re-intended without a not_applied verdict"
    );
    let increments = h.gym.ledger().effects("counter").len();
    assert_eq!(
        u64::try_from(increments).unwrap(),
        count,
        "one effect row per increment"
    );

    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// `interactions.{succeeded,failed}` as stored in `crawl_runs.counters`.
async fn stored_interactions(pool: &PgPool, run: uuid::Uuid) -> (i64, i64) {
    let row = sqlx::query(
        "SELECT (counters->'interactions'->>'succeeded')::bigint AS s, \
                (counters->'interactions'->>'failed')::bigint AS f \
         FROM crawl_runs WHERE run_id = $1",
    )
    .bind(run)
    .fetch_one(pool)
    .await
    .unwrap();
    (row.get("s"), row.get("f"))
}

/// Run counters are derived state: the process is killed after T2 of an action
/// committed and before `crawl_runs.counters` was flushed (failpoint
/// `after_outcome_before_counter_flush`; without `--features chaos` the kill lands wherever
/// the first success is observed). `crawlx worker --recover` re-derives the interaction
/// counters from the journal before the session acts again, so the stored counters equal the
/// journal counts and the trail verifies (`counter_mismatch` is the rule that failed before).
#[tokio::test]
async fn sigkill_between_t2_and_the_counter_flush_is_repaired_by_recovery() {
    let Some(h) = Harness::start("d1").await else {
        return;
    };
    let seed_url = h.gym.fixture_url("d1");
    let killed = h
        .crawl_and_kill(
            &seed_url,
            "read_only",
            "14",
            crawlx_worker::chaos::AFTER_OUTCOME_BEFORE_COUNTER_FLUSH,
            |rows| succeeded(rows) >= 1,
        )
        .await;
    if cfg!(feature = "chaos") {
        // the failpoint holds the process between T2 and the flush: the window is open
        let (stored, _) = stored_interactions(&h.pool, killed.run).await;
        let journal = counts(&h.pool, killed.run).await.succeeded;
        assert!(
            stored < journal,
            "the kill should land before the flush: stored succeeded {stored}, journal {journal}"
        );
    }
    h.recover(killed.run).await;
    let after = h.assert_journal_recovered(&killed).await;
    let (stored_succeeded, stored_failed) = stored_interactions(&h.pool, killed.run).await;
    assert_eq!(
        (stored_succeeded, stored_failed),
        (after.succeeded, after.failed),
        "stored counters differ from the journal after recovery: {after:?}"
    );
    h.assert_completed_with_a_valid_trail(killed.run).await;
    h.teardown().await;
}

/// `GET /__gym/ledger` without a dependency on an HTTP client crate.
async fn reqwest_free_ledger(base_url: &str) -> serde_json::Value {
    let url = url::Url::parse(base_url).unwrap();
    let addr = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut stream,
        b"GET /__gym/ledger HTTP/1.0\r\nHost: gym\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut raw = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut raw)
        .await
        .unwrap();
    let text = String::from_utf8(raw).unwrap();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    serde_json::from_str(body).unwrap()
}

#[test]
fn sleep_marker_requires_the_exact_failpoint_on_the_same_event() {
    let log = "2026-11-04T23:29:23Z WARN crawlx_storage::chaos: failpoint: sleeping\n\
                   failpoint: t2.commit\n\
                   in action{action_id=example}\n";
    assert!(sleeping_at(log, "t2.commit"));
    assert!(!sleeping_at(log, "t2"));
    assert!(!sleeping_at(log, "artifact.after_object_put"));
    assert!(!sleeping_at(
        "WARN failpoint: sleeping\n    ms: 60000\n\
         WARN unrelated event\n    failpoint: t2.commit\n",
        "t2.commit"
    ));
    assert!(!sleeping_at(
        "WARN failpoint: sleeping\n    failpoint: t2.com",
        "t2.commit"
    ));
}
