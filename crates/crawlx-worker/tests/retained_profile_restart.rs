//! Run-level retained-profile restart: a real Chromium run creates cookie and local-storage
//! state in a named retained profile and commits it as generation one under key custody; a
//! second run with the same profile identity restores that generation into its new browser and
//! commits generation two. A stale or zero generation never reaches a browser, and no plaintext
//! profile byte exists outside custody: not in any file under the artifact root, not in any
//! database column.
//!
//! Skipped without Chromium (`CRAWLX_CHROMIUM_PATH`), PostgreSQL (`CRAWLX_TEST_DATABASE_URL`)
//! or the secret registry (`CRAWLX_TEST_SECRET_REDIS_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::{extract::RawQuery, extract::State, http::header, routing::get, Router};
use crawlx_core::{
    config::{BrowserProfile, CrawlMode},
    counters::RunStatus,
    AuthorizationRecordId, CreateCrawl,
};
use crawlx_fetch::StaticResolver;
use crawlx_storage::{Pg, StoreConfig};
use crawlx_worker::{EgressConfig, LocalRun, RetainedProfilePolicy, Stores, WorkerConfig};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PROFILE: &str = "retained-restart";

/// What the page's script observed in the browser, before it wrote anything.
#[derive(Clone, Debug)]
struct Beacon {
    had_storage: bool,
    had_cookie: bool,
    storage: String,
    cookie: String,
}

type Beacons = Arc<Mutex<Vec<Beacon>>>;

struct Canaries {
    storage: String,
    cookie: String,
}

impl Canaries {
    fn new() -> Self {
        let id = uuid::Uuid::now_v7().simple().to_string();
        Self {
            storage: format!("localCanary{id}"),
            cookie: format!("cookieCanary{id}"),
        }
    }

    /// The page source never holds a canary whole, so a scan of captured documents stays honest.
    fn page(&self) -> String {
        let (storage_a, storage_b) = self.storage.split_at(9);
        let (cookie_a, cookie_b) = self.cookie.split_at(9);
        format!(
            "<!doctype html><html><head><title>Retained profile</title></head><body>\
             <h1>Retained profile</h1><script>\
             var K='profile-key',C='sid';\
             var hs=localStorage.getItem(K)!==null,hc=document.cookie.indexOf(C+'=')!==-1;\
             if(!hs){{localStorage.setItem(K,['{storage_a}','{storage_b}'].join(''));}}\
             if(!hc){{document.cookie=C+'='+['{cookie_a}','{cookie_b}'].join('')+\
             '; Max-Age=86400; Path=/; SameSite=Lax';}}\
             var x=new XMLHttpRequest();\
             x.open('GET','/beacon?hs='+(hs?1:0)+'&hc='+(hc?1:0)\
             +'&ls='+encodeURIComponent(localStorage.getItem(K))\
             +'&ck='+encodeURIComponent(document.cookie),false);x.send();\
             </script></body></html>"
        )
    }
}

async fn serve(canaries: &Canaries) -> (String, Beacons, tokio::task::JoinHandle<()>) {
    let beacons = Beacons::default();
    let page = canaries.page();
    let app = Router::new()
        .route(
            "/app",
            get(move || {
                let page = page.clone();
                async move { ([(header::CONTENT_TYPE, "text/html")], page) }
            }),
        )
        .route(
            "/beacon",
            get(
                |State(beacons): State<Beacons>, RawQuery(query): RawQuery| async move {
                    let query = query.unwrap_or_default();
                    let field = |name: &str| {
                        url::form_urlencoded::parse(query.as_bytes())
                            .find(|(key, _)| key == name)
                            .map(|(_, value)| value.into_owned())
                            .unwrap_or_default()
                    };
                    beacons.lock().unwrap().push(Beacon {
                        had_storage: field("hs") == "1",
                        had_cookie: field("hc") == "1",
                        storage: field("ls"),
                        cookie: field("ck"),
                    });
                    ([(header::CONTENT_TYPE, "text/plain")], "ok")
                },
            ),
        )
        .with_state(Arc::clone(&beacons));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, beacons, task)
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

fn hex(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn schema_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-c%20search_path%3D{schema}")
}

struct Rig {
    pg: Pg,
    stores: Stores,
    cfg: WorkerConfig,
    record: crawlx_policy::AuthorizationRecord,
    authorization: AuthorizationRecordId,
    artifacts: tempfile::TempDir,
    _keys: tempfile::TempDir,
}

/// `None` when Chromium, PostgreSQL or the secret registry is missing.
async fn rig(base: &str) -> Option<Rig> {
    let Ok(database) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return None;
    };
    let Ok(redis) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        eprintln!("skipped: CRAWLX_TEST_SECRET_REDIS_URL is not set");
        return None;
    };
    let Some(executable) = crawlx_browser::launch::find_executable() else {
        eprintln!("skipped: no Chromium binary (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let schema = format!("t_retained_{}", uuid::Uuid::now_v7().simple());
    let migrated = Pg::connect(
        &database,
        StoreConfig {
            schema: Some(schema.clone()),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    migrated.migrate().await.unwrap();

    let keys = tempfile::tempdir().unwrap();
    let key_file = keys.path().join("artifact.key");
    std::fs::write(
        &key_file,
        format!("{}\n", uuid::Uuid::new_v4().simple().to_string().repeat(2)),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let artifacts = tempfile::tempdir().unwrap();
    let mut cfg = WorkerConfig {
        artifacts_dir: artifacts.path().to_owned(),
        database_url: Some(schema_url(&database, &schema)),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let key_path = key_file.to_string_lossy().into_owned();
    cfg.load_artifact_custody_from_lookup(&|name| match name {
        "CRAWLX_ARTIFACT_KEY_FILE" => Some(key_path.clone()),
        "CRAWLX_SECRET_REDIS_URL" => Some(redis.clone()),
        _ => None,
    })
    .await
    .unwrap();
    cfg.retained_profiles = RetainedProfilePolicy::from_env(&|name| match name {
        "CRAWLX_RETAINED_PROFILES_ENABLED" => Some("true".into()),
        "CRAWLX_PROFILE_KEY_REF" => Some("env://CRAWLX_RETAINED_PROFILE_KEY".into()),
        _ => None,
    })
    .unwrap();
    cfg.launch.executable = executable;
    cfg.launch.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
        // Containers commonly lack user namespaces; the launcher reports a clear error otherwise.
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |user| user == "root");
    }

    let mut stores = Stores::open(&cfg).await.unwrap();
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let authorization = AuthorizationRecordId::new();
    let record = common::authorization::verified_record(&crawl(base, authorization, 0), stores.tenant);
    common::authorization::register_verified(&migrated, &record).await;
    Some(Rig {
        pg: migrated,
        stores,
        cfg,
        record,
        authorization,
        artifacts,
        _keys: keys,
    })
}

fn crawl(base: &str, authorization: AuthorizationRecordId, generation: u64) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(format!("{base}/app").parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.observe_only = true;
    crawl.limits.states = 1;
    crawl.seed = Some(20_261_115);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(authorization);
    crawl.politeness.delay_ms = 0;
    crawl.dynamic.browser_profile = Some(BrowserProfile {
        name: PROFILE.into(),
        save_changes: true,
        generation,
    });
    crawl
}

/// One committed generation as the catalog stores it.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    generation: i64,
    owner_run: String,
    custody_format: i32,
    ciphertext_bytes: i32,
}

impl Rig {
    async fn run(
        &self,
        base: &str,
        generation: u64,
    ) -> Result<crawlx_worker::RunReport, crawlx_worker::WorkerError> {
        let local = LocalRun::new(crawl(base, self.authorization, generation), self.cfg.clone())
            .with_stores(self.stores.clone())
            .with_authorization(self.record.clone());
        Box::pin(tokio::time::timeout(
            Duration::from_secs(240),
            crawlx_worker::run_local_with(local),
        ))
        .await
        .expect("retained profile run finished in time")
    }

    async fn row(&self) -> Option<Row> {
        let row: Option<(i64, String, i32, i32)> = sqlx::query_as(
            "SELECT generation, owner_run::text, custody_format, octet_length(encrypted_bundle) \
             FROM browser_profiles WHERE name=$1",
        )
        .bind(PROFILE)
        .fetch_optional(self.pg.pool())
        .await
        .unwrap();
        row.map(|(generation, owner_run, custody_format, ciphertext_bytes)| Row {
            generation,
            owner_run,
            custody_format,
            ciphertext_bytes,
        })
    }

    /// Every database column of every table in the isolated schema, as text and as bytea hex.
    async fn database_hits(&self, schema: &str, needles: &[&str]) -> Vec<String> {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema=$1 AND table_type='BASE TABLE'",
        )
        .bind(schema)
        .fetch_all(self.pg.pool())
        .await
        .unwrap();
        assert!(tables.iter().any(|table| table == "browser_profiles"));
        let patterns: Vec<String> = needles
            .iter()
            .flat_map(|needle| [format!("%{needle}%"), format!("%{}%", hex(needle))])
            .collect();
        let mut hits = Vec::new();
        for table in tables {
            let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) FROM \"{schema}\".\"{table}\" row WHERE row::text LIKE ANY($1)"
            )))
            .bind(&patterns)
            .fetch_one(self.pg.pool())
            .await
            .unwrap();
            if count > 0 {
                hits.push(format!("{table}: {count} rows"));
            }
        }
        hits
    }
}

#[tokio::test]
async fn retained_profile_state_survives_a_restart_and_the_generation_advances_under_custody() {
    // The run this drives nests deeply on the test thread, so the scenario's own frame lives on
    // the heap.
    Box::pin(scenario()).await;
}

async fn scenario() {
    let canaries = Canaries::new();
    let (base, beacons, server) = serve(&canaries).await;
    let Some(rig) = Box::pin(rig(&base)).await else {
        server.abort();
        return;
    };
    let schema = rig.pg.config().schema.clone().unwrap();

    // Run one: a new namespace (generation zero) starts empty, the page writes cookie and
    // local storage, and the run commits that state as generation one.
    let first = rig.run(&base, 0).await.unwrap();
    assert_eq!(first.status, RunStatus::Completed, "{:?}", first.terminal_reason);
    {
        let seen = beacons.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(!seen[0].had_storage && !seen[0].had_cookie, "{:?}", seen[0]);
        assert_eq!(seen[0].storage, canaries.storage);
        assert!(seen[0].cookie.contains(&canaries.cookie), "{:?}", seen[0]);
    }
    let committed = rig.row().await.expect("generation one committed");
    assert_eq!(committed.generation, 1);
    assert_eq!(committed.owner_run, first.run_id.0.to_string());
    assert_eq!(
        committed.custody_format, 1,
        "profile rows are custody-format ciphertext"
    );
    assert!(committed.ciphertext_bytes > 0);

    // Run two: the same identity restores generation one into a brand-new browser. The page
    // sees its cookie and local storage before it writes anything, and the run commits
    // generation two.
    let second = rig.run(&base, 1).await.unwrap();
    assert_eq!(
        second.status,
        RunStatus::Completed,
        "{:?}",
        second.terminal_reason
    );
    {
        let seen = beacons.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[1].had_storage && seen[1].had_cookie, "{:?}", seen[1]);
        assert_eq!(seen[1].storage, canaries.storage);
        assert!(seen[1].cookie.contains(&canaries.cookie), "{:?}", seen[1]);
    }
    let advanced = rig.row().await.expect("generation two committed");
    assert_eq!(advanced.generation, 2);
    assert_eq!(advanced.owner_run, second.run_id.0.to_string());
    assert_eq!(advanced.custody_format, 1);

    // Generation rules: a stale generation and a second "new" namespace are refused before a
    // browser ever loads the page, and neither moves the committed generation.
    for requested in [1_u64, 0] {
        match rig.run(&base, requested).await {
            Err(_) => {}
            Ok(report) => assert_ne!(
                report.status,
                RunStatus::Completed,
                "generation {requested} must not complete: {:?}",
                report.terminal_reason
            ),
        }
        assert_eq!(
            beacons.lock().unwrap().len(),
            2,
            "generation {requested} loaded the page"
        );
        assert_eq!(
            rig.row().await.unwrap().generation,
            2,
            "generation {requested} advanced"
        );
    }
    server.abort();

    // No plaintext profile byte outside custody: every file under the artifact root and every
    // column of every table holds neither the cookie nor the local-storage value.
    let needles = [canaries.storage.as_str(), canaries.cookie.as_str()];
    for file in files_under(rig.artifacts.path()) {
        let bytes = std::fs::read(&file).unwrap();
        for needle in needles {
            assert!(
                !contains(&bytes, needle.as_bytes()) && !contains(&bytes, hex(needle).as_bytes()),
                "plaintext profile value found in {}",
                file.display()
            );
        }
    }
    assert_eq!(rig.database_hits(&schema, &needles).await, Vec::<String>::new());

    let Rig { pg, stores, .. } = rig;
    drop(stores);
    pg.drop_schema().await.unwrap();
}
