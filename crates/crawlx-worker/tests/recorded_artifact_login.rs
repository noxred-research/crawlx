//! Native recorded login references retain artifact authority and use the existing actor.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{CrawlRun, CrawlSession, Sensitivity};
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{
    ArtifactId, ArtifactRef, BrowserBackend, Clock, CoreError, CrawlRunId, SystemClock, TenantId, Timestamp,
};
use crawlx_storage::{ArtifactIndex, FsArtifactStore, MemoryStore, Pg, PgConfig};
use crawlx_worker::actor::ShutdownReason;
use crawlx_worker::login::MAX_RECORDED_ARTIFACT_BYTES;
use crawlx_worker::{RunContext, StateAnalyzer, Stores, WorkerConfig};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "artifact-login-password-canary";
const FLOW: &str = r##"{"title":"artifact login","steps":[
  {"type":"navigate","url":"https://example.test/"},
  {"type":"change","selectors":[["#username"]],"value":"{{username}}"},
  {"type":"change","selectors":[["[type=\"password\"]"]],"value":"{{password}}"},
  {"type":"click","selectors":[["aria/Sign in[role=\"button\"]"]]},
  {"type":"waitForElement","selectors":[["aria/Reports"]]}
]}"##;

struct TestClock(Mutex<Timestamp>);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock()
    }
}

#[derive(Default)]
struct CountedSecrets(AtomicUsize);

#[async_trait]
impl SecretResolver for CountedSecrets {
    async fn resolve(&self, _: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SecretOr::secret(format!("artifact-user:{PASSWORD}")))
    }
}

struct Fixture {
    rc: RunContext,
    session: CrawlSession,
    backend: Arc<FakeBackend>,
    browser: Arc<dyn BrowserBackend>,
    secrets: Arc<CountedSecrets>,
    clock: Arc<TestClock>,
    index: Arc<dyn ArtifactIndex>,
    dir: tempfile::TempDir,
}

async fn fixture(postgres: bool) -> Option<Fixture> {
    fixture_with_browser(postgres, None).await
}

async fn fixture_with_browser(
    postgres: bool,
    browser: Option<(url::Url, Arc<dyn BrowserBackend>)>,
) -> Option<Fixture> {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(TestClock(Mutex::new(SystemClock.now())));
    // Only fake-browser fixtures advance the expiry clock; Chromium uses real capture time.
    let run_clock: Arc<dyn Clock> = if browser.is_some() {
        Arc::new(SystemClock)
    } else {
        clock.clone()
    };
    let (mut stores, index): (Stores, Arc<dyn ArtifactIndex>) = if postgres {
        let Ok(database) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return None;
        };
        let pg = Pg::connect(
            &database,
            PgConfig {
                schema: Some(format!("t_login_artifact_{}", uuid::Uuid::now_v7().simple())),
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let tenant = TenantId::new();
        pg.ensure_tenant(tenant, "recorded-login").await.unwrap();
        let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), run_clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone()));
        (
            Stores::over_pg(pg.clone(), Arc::new(artifacts), tenant),
            Arc::new(pg),
        )
    } else {
        let memory = Arc::new(MemoryStore::with_clock(run_clock.clone()));
        let mut stores = Stores::over_memory(memory.clone(), dir.path()).await.unwrap();
        stores.artifacts = Arc::new(
            FsArtifactStore::open(dir.path(), memory.clone(), run_clock.clone())
                .await
                .unwrap()
                .with_index(memory.clone()),
        );
        (stores, memory)
    };
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    let mut crawl = common::crawl(crawlx_core::SafetyProfile::TestEnvironment);
    if let Some((url, _)) = &browser {
        crawl.seed_url = url.clone();
        crawl.safety.allow_private_networks = true;
    }
    crawl.mode = CrawlMode::Dynamic;
    crawl.roles = vec![Role {
        name: "admin".into(),
        credential_ref: Some(CredentialRef("env://ARTIFACT_LOGIN".into())),
        login_plan: None,
        replica_base_url: None,
    }];
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    let record = common::authorization::verified_record_with_clock(&crawl, stores.tenant, run_clock.as_ref());
    if let Some(pg) = &stores.pg {
        common::authorization::register_verified(pg, &record).await;
    }
    stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Running,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl,
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: run_clock.now(),
        started_at: Some(run_clock.now()),
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    let sessions = crawlx_scheduler::RunPlanner::sessions(run.id, &run.config);
    stores.runs.create_sessions(&sessions).await.unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_owned(),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        egress: crawlx_worker::EgressConfig {
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            extra_allow: if browser.is_some() {
                vec!["127.0.0.1/32".parse().unwrap()]
            } else {
                Vec::new()
            },
            ..crawlx_worker::EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let guard = common::authorization::admit_with_clock(&stores, &run, &cfg, run_clock.clone()).await;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(
                FakeScript::new()
                    .page(
                        FakePage::new("https://example.test/")
                            .node(
                                FakeAxSpec::textbox("username", "Username")
                                    .attr("autocomplete", "username")
                                    .attr("crawlx:form", "login"),
                            )
                            .node(
                                FakeAxSpec::textbox("password", "Password")
                                    .attr("type", "password")
                                    .attr("autocomplete", "current-password")
                                    .attr("crawlx:form", "login"),
                            )
                            .node(
                                FakeAxSpec::button("submit", "Sign in")
                                    .attr("type", "submit")
                                    .attr("crawlx:form", "login"),
                            )
                            .on_click(
                                "submit",
                                vec![
                                    FakeEffect::SetStorage(BTreeMap::from([("sid".into(), "yes".into())])),
                                    FakeEffect::Navigate("https://example.test/home".into()),
                                ],
                            ),
                    )
                    .page(
                        FakePage::new("https://example.test/home")
                            .node(FakeAxSpec::link("reports", "Reports", "/reports")),
                    ),
            )
            .clock(run_clock.clone())
            .build(),
    );
    let secrets = Arc::new(CountedSecrets::default());
    let browser = browser.map_or_else(
        || backend.clone() as Arc<dyn BrowserBackend>,
        |(_, backend)| backend,
    );
    let mut rc = RunContext::build(
        &run,
        &cfg,
        stores,
        Some(browser.clone()),
        Some(secrets.clone()),
        CancellationToken::new(),
        None,
        Some(guard),
    )
    .await
    .unwrap();
    common::set_fixture_clock(&mut rc, run_clock, run.started_at.unwrap_or(run.created_at));
    Some(Fixture {
        rc,
        session: sessions[0].clone(),
        backend,
        browser,
        secrets,
        clock,
        index,
        dir,
    })
}

/// Publish a fresh target with the artifact reference in its immutable config.
/// Resolution-only rejection cases mutate the in-memory copy, never persisted config.
async fn bind_target(f: &mut Fixture, spec: String) {
    let mut target = f.rc.stores.runs.get(f.rc.run).await.unwrap();
    target.id = CrawlRunId::new();
    target.created_at = f.rc.clock.now();
    target.started_at = Some(target.created_at);
    target.config.roles[0].login_plan = Some(spec);
    target.config_digest = target.config.digest().unwrap();
    f.rc.stores.runs.create(&target, None).await.unwrap();
    let sessions = crawlx_scheduler::RunPlanner::sessions(target.id, &target.config);
    f.rc.stores.runs.create_sessions(&sessions).await.unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: f.dir.path().to_owned(),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        egress: crawlx_worker::EgressConfig {
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            extra_allow: if target.config.safety.allow_private_networks {
                vec!["127.0.0.1/32".parse().unwrap()]
            } else {
                Vec::new()
            },
            ..crawlx_worker::EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let clock = f.rc.clock.clone();
    let guard = common::authorization::admit_with_clock(&f.rc.stores, &target, &cfg, clock.clone()).await;
    f.rc = RunContext::build(
        &target,
        &cfg,
        f.rc.stores.clone(),
        Some(f.browser.clone()),
        Some(f.secrets.clone()),
        CancellationToken::new(),
        None,
        Some(guard),
    )
    .await
    .unwrap();
    common::set_fixture_clock(&mut f.rc, clock, target.started_at.unwrap_or(target.created_at));
    f.session = sessions[0].clone();
}

fn descriptor(f: &Fixture, artifact: &ArtifactRef) -> serde_json::Value {
    serde_json::json!({
        "tenant": f.rc.stores.tenant,
        "run": f.rc.run,
        "sensitivity": "content",
        "artifact": artifact,
    })
}

fn artifact_spec(descriptor: &serde_json::Value) -> String {
    format!("recorded:artifact://{descriptor}")
}

async fn put(f: &Fixture, bytes: &[u8], sensitivity: Sensitivity) -> ArtifactRef {
    f.rc.stores
        .artifacts
        .put(f.rc.run, sensitivity, "application/json", bytes)
        .await
        .unwrap()
}

async fn reject(f: &mut Fixture, spec: String) {
    f.rc.crawl.roles[0].login_plan = Some(spec.clone());
    let error = f.rc.login_material("admin").await.err().expect("plan must fail");
    assert_eq!(f.secrets.0.load(Ordering::SeqCst), 0);
    assert!(f.backend.context_handles().is_empty());
    let events = f.rc.stores.events.list_after(f.rc.run, 0, 1_000).await.unwrap();
    assert!(!events.iter().any(|event| event.kind == "secret.resolved"));
    let message = error.to_string();
    assert!(!message.contains(&spec), "{message}");
    assert!(!message.contains(PASSWORD), "{message}");
    assert!(!message.contains("error-content-canary"), "{message}");
    assert!(
        !message.contains(&f.dir.path().display().to_string()),
        "{message}"
    );
}

async fn contract_and_actor(mut f: Fixture) {
    let recorded = FLOW
        .replace("{{username}}", "literal-username-canary")
        .replace("{{password}}", "literal-password-canary");
    // A target's immutable role config can explicitly name retained content from
    // another run of the same tenant, without changing either run's config.
    let mut source = f.rc.stores.runs.get(f.rc.run).await.unwrap();
    source.id = CrawlRunId::new();
    source.created_at = f.clock.now() - chrono::Duration::hours(23);
    source.config.retention.days = 1;
    source.config_digest = source.config.digest().unwrap();
    f.rc.stores.runs.create(&source, None).await.unwrap();
    let good =
        f.rc.stores
            .artifacts
            .put(
                source.id,
                Sensitivity::Content,
                "application/json",
                recorded.as_bytes(),
            )
            .await
            .unwrap();
    let mut good_descriptor = descriptor(&f, &good);
    good_descriptor["run"] = serde_json::json!(source.id);
    assert_ne!(source.id, f.rc.run);
    for field in ["tenant", "run", "sensitivity", "artifact"] {
        let mut invalid = good_descriptor.clone();
        invalid.as_object_mut().unwrap().remove(field);
        reject(&mut f, artifact_spec(&invalid)).await;
    }
    for (field, value) in [
        ("tenant", serde_json::json!(TenantId::new())),
        ("run", serde_json::json!(CrawlRunId::new())),
        ("sensitivity", serde_json::json!("credential_bearing")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut invalid = good_descriptor.clone();
        invalid[field] = value;
        reject(&mut f, artifact_spec(&invalid)).await;
    }
    for field in ["id", "digest"] {
        let mut invalid = good_descriptor.clone();
        invalid["artifact"].as_object_mut().unwrap().remove(field);
        reject(&mut f, artifact_spec(&invalid)).await;
    }
    for (field, value) in [
        ("id", serde_json::json!("not-a-uuid")),
        ("digest", serde_json::json!("not-a-digest")),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut invalid = good_descriptor.clone();
        invalid["artifact"][field] = value;
        reject(&mut f, artifact_spec(&invalid)).await;
    }
    for raw in [
        "recorded:artifact://login.json".to_owned(),
        "recorded:artifact://{error-content-canary".to_owned(),
        format!("recorded:artifact://{}", "x".repeat(4_097)),
        format!("recorded:file://{}/error-content-canary", f.dir.path().display()),
    ] {
        reject(&mut f, raw).await;
    }
    // Trailing whitespace is part of the descriptor's byte budget.
    let raw_descriptor = good_descriptor.to_string();
    let padded = format!("{raw_descriptor:width$}", width = 4_097);
    reject(&mut f, format!("recorded:artifact://{padded}")).await;
    let duplicate = raw_descriptor.replacen(
        "\"sensitivity\":\"content\"",
        "\"sensitivity\":\"content\",\"sensitivity\":\"content\"",
        1,
    );
    reject(&mut f, format!("recorded:artifact://{duplicate}")).await;
    let missing = ArtifactRef {
        id: ArtifactId::new(),
        digest: good.digest,
    };
    let missing_spec = artifact_spec(&descriptor(&f, &missing));
    reject(&mut f, missing_spec).await;
    let wrong_digest = ArtifactRef {
        id: good.id,
        digest: Digest::of("fixture/wrong", b"wrong"),
    };
    let wrong_digest_spec = artifact_spec(&descriptor(&f, &wrong_digest));
    reject(&mut f, wrong_digest_spec).await;

    // Caller labels cannot upgrade the actual stored sensitivity or ownership.
    for class in [Sensitivity::Metadata, Sensitivity::CredentialBearing] {
        let artifact = put(&f, FLOW.as_bytes(), class).await;
        let spec = artifact_spec(&descriptor(&f, &artifact));
        reject(&mut f, spec).await;
    }
    for foreign_tenant in [false, true] {
        let mut owner = f.rc.stores.runs.get(f.rc.run).await.unwrap();
        owner.id = CrawlRunId::new();
        if foreign_tenant {
            owner.tenant = TenantId::new();
            if let Some(pg) = &f.rc.stores.pg {
                pg.ensure_tenant(owner.tenant, "foreign-login").await.unwrap();
                // A foreign tenant cannot refer to this fixture's authorization row.
                owner.config.safety.authorization_record_ref = None;
                owner.config_digest = owner.config.digest().unwrap();
            }
        }
        f.rc.stores.runs.create(&owner, None).await.unwrap();
        let artifact =
            f.rc.stores
                .artifacts
                .put(
                    owner.id,
                    Sensitivity::Content,
                    "application/json",
                    FLOW.as_bytes(),
                )
                .await
                .unwrap();
        let spec = artifact_spec(&descriptor(&f, &artifact));
        reject(&mut f, spec).await;
        if foreign_tenant {
            let mut forged = descriptor(&f, &artifact);
            forged["run"] = serde_json::json!(owner.id);
            reject(&mut f, artifact_spec(&forged)).await;
        }
    }
    let until = f.clock.now() + chrono::Duration::hours(1);
    let expires =
        f.rc.stores
            .artifacts
            .put_until(
                f.rc.run,
                Sensitivity::Content,
                "application/json",
                FLOW.as_bytes(),
                until,
            )
            .await
            .unwrap();
    let original_time = f.clock.now();
    *f.clock.0.lock() = until + chrono::Duration::seconds(1);
    let expired_spec = artifact_spec(&descriptor(&f, &expires));
    reject(&mut f, expired_spec).await;
    *f.clock.0.lock() = original_time;
    // The source run can expire after target creation while its artifact row is
    // still retained. Descriptor labels and target lifetime cannot extend it.
    *f.clock.0.lock() = source.created_at + chrono::Duration::days(1);
    reject(&mut f, artifact_spec(&good_descriptor)).await;
    *f.clock.0.lock() = original_time;
    let deleted = put(&f, FLOW.as_bytes(), Sensitivity::Content).await;
    f.index.mark_deleted(&[deleted.id]).await.unwrap();
    let deleted_spec = artifact_spec(&descriptor(&f, &deleted));
    reject(&mut f, deleted_spec).await;

    for invalid in [
        b"{error-content-canary".as_slice(),
        b"\xff\xfe".as_slice(),
        br##"{"steps":[{"type":"navigate","url":"https://example.test/"},{"type":"evaluate","expression":"error-content-canary"}]}"##.as_slice(),
        br##"{"steps":[{"action":"fill","selector":"#password","value":"{{password}}-error-content-canary"}]}"##.as_slice(),
    ] {
        let artifact = put(&f, invalid, Sensitivity::Content).await;
        let spec = artifact_spec(&descriptor(&f, &artifact));
        reject(&mut f, spec).await;
    }
    // Valid caller labels cannot override the source adapter's independent read scope.
    let denied = FsArtifactStore::open(f.dir.path(), f.rc.stores.runs.clone(), f.clock.clone())
        .await
        .unwrap()
        .with_index(f.index.clone())
        .with_read_scope(TenantId::new(), f.rc.run);
    let original = std::mem::replace(&mut f.rc.stores.artifacts, Arc::new(denied));
    reject(&mut f, artifact_spec(&good_descriptor)).await;
    f.rc.stores.artifacts = original;
    let oversized = vec![b' '; usize::try_from(MAX_RECORDED_ARTIFACT_BYTES + 1).unwrap()];
    let artifact = put(&f, &oversized, Sensitivity::Content).await;
    let spec = artifact_spec(&descriptor(&f, &artifact));
    reject(&mut f, spec).await;

    // Same-length corruption reaches the store's fixity check, never the parser.
    let object = f.dir.path().join(crawlx_storage::artifacts::object_key(
        Sensitivity::Content,
        f.rc.stores.tenant,
        source.id,
        &good.digest,
    ));
    tokio::fs::write(&object, vec![b'x'; recorded.len()])
        .await
        .unwrap();
    reject(&mut f, artifact_spec(&good_descriptor)).await;
    // A small declared row cannot hide an oversized source object.
    tokio::fs::write(&object, &oversized).await.unwrap();
    reject(&mut f, artifact_spec(&good_descriptor)).await;
    tokio::fs::write(&object, &recorded).await.unwrap();

    bind_target(&mut f, artifact_spec(&good_descriptor)).await;
    let material = f.rc.login_material("admin").await.unwrap().unwrap();
    assert_eq!(
        material.plan,
        crawlx_forms::LoginPlan::parse(&format!("recorded:{FLOW}")).unwrap()
    );
    assert_eq!(f.secrets.0.load(Ordering::SeqCst), 1);
    let compiled = format!("{:?}", material.plan);
    assert!(!compiled.contains("literal-username-canary"));
    assert!(!compiled.contains("literal-password-canary"));
    assert!(f.backend.context_handles().is_empty());
    let rc = Arc::new(f.rc);
    // Native actions need a live durable lease in both memory and PostgreSQL.
    let scheduler = crawlx_scheduler::Scheduler::new(rc.stores.leases.clone());
    let lease = scheduler
        .lease_in_run(rc.run, rc.worker, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.id, f.session.id);
    let heartbeat_cancel = CancellationToken::new();
    let heartbeat = scheduler.keep_alive(
        lease.clone(),
        std::time::Duration::from_secs(1),
        heartbeat_cancel.clone(),
    );
    let handle = common::fresh_actor_in(&rc.stores, &rc, rc.run, None).await;
    let analyzer = StateAnalyzer::new(
        rc.run,
        f.session.id,
        rc.clusters.clone(),
        rc.stores.artifacts.clone(),
        rc.clock.clone(),
        rc.crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    );
    crawlx_worker::login::login_session(&handle, &rc, &f.session, &analyzer, material)
        .await
        .unwrap();
    let events = rc.stores.events.list_after(rc.run, 0, 1_000).await.unwrap();
    assert!(events.iter().any(|event| event.kind == "session.login"
        && event.payload["ok"] == true
        && event.payload["plan"] == "recorded"
        && event.payload["fallback"] == false));
    let actions = rc.stores.journal.list(rc.run, None).await.unwrap();
    assert!(actions.iter().any(|action| action.strategy == "login"));
    assert!(actions
        .iter()
        .filter(|action| action.strategy == "login")
        .all(|action| action.lane == Some(crawlx_core::TrustLane::TrustedUi)));
    let contexts = f.backend.context_handles();
    assert_eq!(contexts.len(), 1);
    let keys = contexts[0].performed_keys();
    for key in ["type:username", "type:password", "click:submit"] {
        assert_eq!(
            keys.iter().filter(|actual| actual.as_str() == key).count(),
            1,
            "{keys:?}"
        );
    }
    let dump = format!(
        "{events:?}{actions:?}{:?}",
        rc.stores.states.list_states(rc.run).await.unwrap()
    );
    assert!(!dump.contains(PASSWORD));
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    heartbeat_cancel.cancel();
    heartbeat.await.unwrap().unwrap();
    scheduler.complete(&lease).await.unwrap();
}

#[tokio::test]
async fn artifact_login_checks_custody_before_secrets_and_uses_actor_in_memory() {
    contract_and_actor(fixture(false).await.unwrap()).await;
}

#[tokio::test]
async fn artifact_login_checks_custody_before_secrets_and_uses_actor_in_postgres() {
    if let Some(fixture) = fixture(true).await {
        contract_and_actor(fixture).await;
    }
}

#[tokio::test]
async fn artifact_ceiling_is_exact_without_narrowing_inline_or_file_support() {
    let mut f = fixture(false).await.unwrap();
    let json = r#"{"steps":[{"action":"wait","value":"0s"}]}"#;
    let mut bytes = json.as_bytes().to_vec();
    bytes.resize(usize::try_from(MAX_RECORDED_ARTIFACT_BYTES).unwrap(), b' ');
    let artifact = put(&f, &bytes, Sensitivity::Content).await;
    let padded = format!("{:width$}", descriptor(&f, &artifact).to_string(), width = 4_096);
    assert_eq!(padded.len(), 4_096);
    f.rc.crawl.roles[0].login_plan = Some(format!("recorded:artifact://{padded}"));
    let exact = f.rc.login_material("admin").await.unwrap().unwrap().plan;
    assert!(exact.is_recorded());
    // Inline/file flows had no byte ceiling. Keep their prior acceptance contract.
    let large = format!(
        r#"{{"title":"{}","steps":[{{"action":"wait","value":"0s"}}]}}"#,
        "x".repeat(usize::try_from(MAX_RECORDED_ARTIFACT_BYTES).unwrap())
    );
    f.rc.crawl.roles[0].login_plan = Some(format!("recorded:{large}"));
    assert_eq!(f.rc.login_material("admin").await.unwrap().unwrap().plan, exact);
    let file = f.dir.path().join("flow.json");
    tokio::fs::write(&file, large).await.unwrap();
    f.rc.crawl.roles[0].login_plan = Some(format!("recorded:file://{}", file.display()));
    assert_eq!(f.rc.login_material("admin").await.unwrap().unwrap().plan, exact);
    assert!(f.backend.context_handles().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifact_login_types_resolved_credentials_through_pinned_chromium() {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        return;
    };
    let submitted = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&submitted);
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<!doctype html><title>Sign in</title>
              <form method="post" action="/login">
                <label for="username">Username</label>
                <input id="username" name="username" autocomplete="username">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password">
                <button type="submit">Sign in</button>
              </form>"#,
                )
            }),
        )
        .route(
            "/robots.txt",
            axum::routing::get(|| async { "User-agent: *\nAllow: /\n" }),
        )
        .route(
            "/login",
            axum::routing::post(move |axum::Form(fields): axum::Form<BTreeMap<String, String>>| {
                let accepted = Arc::clone(&accepted);
                async move {
                    // A successful POST proves the actor resolved placeholders into
                    // the selected principal's credentials through native input.
                    if fields.get("username").map(String::as_str) == Some("artifact-user")
                        && fields.get("password").map(String::as_str) == Some(PASSWORD)
                    {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        (
                            axum::http::StatusCode::OK,
                            [(
                                "set-cookie",
                                "sid=artifact-session; Path=/; HttpOnly; SameSite=Lax",
                            )],
                            axum::response::Html(
                                "<!doctype html><title>Home</title><a href='/reports'>Reports</a>",
                            ),
                        )
                    } else {
                        (
                            axum::http::StatusCode::UNAUTHORIZED,
                            [("set-cookie", "sid=; Path=/; Max-Age=0")],
                            axum::response::Html("<!doctype html><title>Login refused</title>"),
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut crawl = common::crawl(crawlx_core::SafetyProfile::TestEnvironment);
    crawl.seed_url = url.clone();
    crawl.safety.allow_private_networks = true;
    let egress = crawlx_worker::EgressConfig {
        resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
        extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
        ..crawlx_worker::EgressConfig::default()
    };
    let proxy =
        crawlx_fetch::EgressProxy::serve(Arc::new(egress.policy_for(&crawl)), egress.resolver().unwrap())
            .await
            .unwrap();
    let mut launch = crawlx_browser::LaunchConfig::new();
    launch.executable = executable.into();
    launch.egress_proxy_port = Some(proxy.port());
    // Preserve normal browser pin, sandbox and egress admission.
    let browser = Arc::new(crawlx_browser::ChromiumBackend::launch(launch).await.unwrap());
    let mut f = fixture_with_browser(false, Some((url.clone(), browser.clone())))
        .await
        .unwrap();
    let recording = FLOW.replace("https://example.test/", url.as_str());
    crawlx_worker::login::validate_recorded_login_flow(recording.as_bytes()).unwrap();
    let artifact = put(&f, recording.as_bytes(), Sensitivity::Content).await;
    let source_descriptor = descriptor(&f, &artifact);
    let source = f.rc.run;
    bind_target(&mut f, artifact_spec(&source_descriptor)).await;
    assert_ne!(source, f.rc.run);
    assert_eq!(f.secrets.0.load(Ordering::SeqCst), 0);
    assert_eq!(submitted.load(Ordering::SeqCst), 0);
    let material = f.rc.login_material("admin").await.unwrap().unwrap();
    assert_eq!(f.secrets.0.load(Ordering::SeqCst), 1);
    let rc = Arc::new(f.rc);
    let scheduler = crawlx_scheduler::Scheduler::new(rc.stores.leases.clone());
    let lease = scheduler
        .lease_in_run(rc.run, rc.worker, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.session.id, f.session.id);
    let heartbeat_cancel = CancellationToken::new();
    let heartbeat = scheduler.keep_alive(
        lease.clone(),
        std::time::Duration::from_secs(1),
        heartbeat_cancel.clone(),
    );
    let handle = common::fresh_actor_in(&rc.stores, &rc, rc.run, None).await;
    let analyzer = StateAnalyzer::new(
        rc.run,
        f.session.id,
        rc.clusters.clone(),
        rc.stores.artifacts.clone(),
        rc.clock.clone(),
        rc.crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    );
    crawlx_worker::login::login_session(&handle, &rc, &f.session, &analyzer, material)
        .await
        .unwrap();
    assert_eq!(submitted.load(Ordering::SeqCst), 1);
    let events = rc.stores.events.list_after(rc.run, 0, 1_000).await.unwrap();
    assert!(events.iter().any(|event| event.kind == "session.login"
        && event.payload["ok"] == true
        && event.payload["plan"] == "recorded"
        && event.payload["fallback"] == false));
    let actions = rc.stores.journal.list(rc.run, None).await.unwrap();
    assert!(actions.iter().any(|action| action.strategy == "login"
        && action.status == crawlx_core::counters::ActionStatus::Succeeded));
    let states = rc.stores.states.list_states(rc.run).await.unwrap();
    let dump = format!("{events:?}{actions:?}{states:?}");
    for secret in [PASSWORD, "literal-username-canary", "literal-password-canary"] {
        assert!(!dump.contains(secret));
    }
    handle.shutdown(ShutdownReason::Completed).await.unwrap();
    heartbeat_cancel.cancel();
    heartbeat.await.unwrap().unwrap();
    scheduler.complete(&lease).await.unwrap();
    browser.shutdown_confirmed().await.unwrap();
    proxy.shutdown().await;
    server.abort();
}

#[test]
fn upload_validation_refuses_credential_literals_without_rewriting_source() {
    use crawlx_worker::login::validate_recorded_login_flow;

    validate_recorded_login_flow(FLOW.as_bytes()).unwrap();
    for value in ["literal-password-canary", "{{unknown}}", ""] {
        let recording = FLOW.replace("{{password}}", value);
        let error = validate_recorded_login_flow(recording.as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(value) || value.is_empty());
    }
    for selector in ["#username", "[type=\"password\"]"] {
        let flow = serde_json::json!({
            "steps": [{"action": "fill", "selector": selector, "value": "credential-literal-canary"}],
        })
        .to_string();
        assert!(validate_recorded_login_flow(flow.as_bytes()).is_err());
    }
    for flow in [
        br##"{"steps":[{"action":"fill","selector":"#search","value":"ordinary search text"}]}"##.as_slice(),
        br##"{"steps":[{"action":"fill","selector":"#username","value":"{{username}}"},{"action":"fill","selector":"#password","value":"{{password}}"}]}"##.as_slice(),
    ] {
        validate_recorded_login_flow(flow).unwrap();
    }
    for invalid in [b"{flow-canary".as_slice(), b"\xff".as_slice()] {
        let error = validate_recorded_login_flow(invalid).unwrap_err().to_string();
        assert!(!error.contains("flow-canary"));
    }
    let oversized = vec![b' '; usize::try_from(MAX_RECORDED_ARTIFACT_BYTES + 1).unwrap()];
    assert!(validate_recorded_login_flow(&oversized).is_err());
}

#[test]
fn descriptor_parser_returns_only_strict_source_labels() {
    use crawlx_worker::login::parse_recorded_login_artifact;

    let tenant = TenantId::new();
    let source = CrawlRunId::new();
    let artifact = ArtifactRef {
        id: ArtifactId::new(),
        digest: Digest::of("fixture/login-flow", FLOW.as_bytes()),
    };
    let descriptor = serde_json::json!({
        "tenant": tenant, "run": source, "sensitivity": "content", "artifact": artifact,
    });
    let spec = artifact_spec(&descriptor);
    assert_eq!(
        parse_recorded_login_artifact(&format!(" \t{spec}")).unwrap(),
        Some((tenant, source, artifact))
    );
    for ordinary in ["builtin:form", "recorded:file://flow.json", FLOW] {
        assert!(parse_recorded_login_artifact(ordinary).unwrap().is_none());
    }
    let raw = descriptor.to_string();
    let oversized = format!("recorded:artifact://{raw:width$}", width = 4_097);
    assert!(parse_recorded_login_artifact(&oversized).is_err());
}
