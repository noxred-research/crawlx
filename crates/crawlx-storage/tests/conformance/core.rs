//! Core CRUD repositories on every engine: runs and their status machine, sessions, pages,
//! states and clusters, edges, the ledger, safety decisions, events, checkpoints, identity
//! aliases, model decisions, the credential revocation that replaces the PostgreSQL triggers on
//! `crawl_runs`, and the zero-data-retention projection of all of them.
//!
//! Ported from `tests/pg.rs`, `tests/memory.rs` and `tests/known_pages.rs`; the in-memory store
//! runs the cases whose contract it shares.

use crate::rig::Rig;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{
    CheckpointRecord, ClusterSplitRecord, EdgeRecord, IdentityAlias, LedgerRow, ModelDecisionKind,
    ModelDecisionRecord, PageRecord, SessionStatus, SplitMember, SplitSuccessor,
};
use crawlx_core::safety::SafetyDecision;
use crawlx_core::{
    ArtifactId, ArtifactRef, CheckpointId, CrawlRunId, SessionId, StateClusterId, StoreError, SystemClock,
    TenantId, TrustLane,
};
use crawlx_storage::sql::Built;
use crawlx_storage::testkit::rig::Engine;
use crawlx_storage::testkit::{
    allow_verdict, canonical_url, crawl_run, create_crawl, new_state, proposal, sessions, signature, verdict,
};
use crawlx_storage::{BackendKind, CoreRepos, DeliveryBuffer};
use std::sync::Arc;
use uuid::Uuid;

conformance! { all:
    run_lifecycle_and_status_machine,
    sessions_roundtrip_with_browser_info,
    edges_need_a_ledger_context_and_upsert_by_key,
    identity_aliases_round_trip,
    events_are_monotonic_per_run,
    model_decisions_are_idempotent_on_the_decision_id,
    states_clusters_and_splits_round_trip,
    known_pages_list_the_stored_pages_of_a_site,
}

conformance! { databases:
    replay_creation_checks_the_source_and_is_atomic,
    literal_controls_never_enter_the_database_and_expire_fail_closed,
    pages_roundtrip_and_upsert_by_role_and_url,
    the_site_lookup_reaches_pages_through_the_host_key_index,
    the_host_key_is_the_reversed_lower_case_host_of_every_url_shape,
    ledger_rows_keep_the_coarsened_flag_and_absolute_counters,
    safety_decisions_are_idempotent_on_the_decision_id,
    checkpoints_keep_the_newest_three_and_hide_expired_ones,
    terminal_status_revokes_credentials_in_the_same_transaction,
    zdr_rows_never_hold_content,
    the_database_clock_decodes_on_every_engine,
    the_transaction_clock_never_precedes_an_earlier_database_reading,
    no_lock_wait_is_unbounded,
}

// ---- environment ------------------------------------------------------------------------

struct Env<'a> {
    rig: &'a Rig,
    repos: CoreRepos,
    tenant: TenantId,
}

fn memory(rig: &Rig) -> bool {
    rig.engine() == Engine::Memory
}

async fn env(rig: &Rig) -> Env<'_> {
    env_with(
        rig,
        Arc::new(DeliveryBuffer::with_defaults(Arc::new(SystemClock))),
    )
    .await
}

async fn env_with(rig: &Rig, delivery: Arc<DeliveryBuffer>) -> Env<'_> {
    rig.migrate().await;
    let repos = if memory(rig) {
        CoreRepos::memory(rig.store().clone())
    } else {
        CoreRepos::open(rig.database(), Some(delivery)).unwrap()
    };
    let tenant = tenant(rig).await;
    Env { rig, repos, tenant }
}

async fn tenant(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if !memory(rig) {
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

fn epoch(n: u64, d: u64, m: u64) -> ObservationEpoch {
    ObservationEpoch {
        navigation_seq: n,
        document_seq: d,
        mutation_seq: m,
    }
}

impl Env<'_> {
    async fn run(&self, roles: &[&str], runs: u8) -> crawlx_core::repo::CrawlRun {
        let run = crawl_run(self.tenant, create_crawl("https://example.test/", roles, runs));
        self.repos.runs.create(&run, None).await.unwrap();
        run
    }

    async fn credential_artifact(&self, run: CrawlRunId, expires_at: DateTime<Utc>) -> ArtifactId {
        Raw(self.rig)
            .credential_artifact(self.tenant, run, expires_at)
            .await
    }

    async fn zdr_run(&self) -> crawlx_core::repo::CrawlRun {
        let mut config = create_crawl("https://example.test/", &[], 1);
        config.retention.mode = RetentionMode::Zdr;
        config.retention.days = 0;
        let run = crawl_run(self.tenant, config);
        self.repos.runs.create(&run, None).await.unwrap();
        run
    }

    /// A run with one session row (no lease needed by the repositories under test).
    async fn run_with_session(&self) -> (crawlx_core::repo::CrawlRun, SessionId) {
        let run = self.run(&[], 1).await;
        let slots = sessions(run.id, 1, 1);
        self.repos.runs.create_sessions(&slots).await.unwrap();
        (run, slots[0].id)
    }
}

// ---- raw SQL (what the repositories wrote, read back without them) ------------------------

enum V<'a> {
    Uuid(Uuid),
    Text(&'a str),
    Bytes(&'a [u8]),
    Ts(DateTime<Utc>),
}

macro_rules! bind_values {
    ($query:expr, $args:expr, $ts:expr) => {{
        let mut query = $query;
        for arg in $args {
            query = match arg {
                V::Uuid(v) => query.bind(*v),
                V::Text(v) => query.bind(*v),
                V::Bytes(v) => query.bind(*v),
                V::Ts(v) => query.bind(($ts)(*v)),
            };
        }
        query
    }};
}

/// Raw statements in `$n` template notation (PostgreSQL casts allowed), each placeholder used
/// once and in order.
struct Raw<'a>(&'a Rig);

impl Raw<'_> {
    fn text(&self, template: &str) -> String {
        Built::expand(self.0.kind().unwrap(), template).text().to_owned()
    }

    async fn exec(&self, template: &str, args: &[V<'_>]) -> u64 {
        let sql = self.text(template);
        let database = self.0.database();
        match self.0.kind().unwrap() {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .execute(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .rows_affected()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .execute(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .rows_affected()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .execute(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .rows_affected(),
        }
    }

    /// The first column of every row as text (cast it with `::text` in the template).
    async fn strings(&self, template: &str, args: &[V<'_>]) -> Vec<Option<String>> {
        use sqlx::Row as _;
        let sql = self.text(template);
        let database = self.0.database();
        match self.0.kind().unwrap() {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_all(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .iter()
                .map(|row| row.try_get::<Option<String>, _>(0).unwrap())
                .collect()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_all(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .iter()
                .map(|row| row.try_get::<Option<String>, _>(0).unwrap())
                .collect()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_all(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .iter()
                .map(|row| row.try_get::<Option<String>, _>(0).unwrap())
                .collect(),
        }
    }

    /// The first column of the first row as an integer (`count(*)` or a `bigint` column).
    async fn int(&self, template: &str, args: &[V<'_>]) -> i64 {
        use sqlx::Row as _;
        let sql = self.text(template);
        let database = self.0.database();
        match self.0.kind().unwrap() {
            BackendKind::Sqlite => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .timestamp_micros())
                .fetch_one(database.sqlite_pool().unwrap())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap()
            }
            BackendKind::MariaDb => {
                bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t
                    .naive_utc())
                .fetch_one(database.mariadb_pool().unwrap())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap()
            }
            _ => bind_values!(sqlx::query(sqlx::AssertSqlSafe(sql)), args, |t: DateTime<Utc>| t)
                .fetch_one(database.postgres().unwrap().pool())
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap(),
        }
    }

    /// Every column of every row of `table` for `run`, concatenated as text (binary columns
    /// as hexadecimal).
    async fn dump(&self, table: &str, run: CrawlRunId) -> String {
        let kind = self.0.kind().unwrap();
        let described = match kind {
            BackendKind::Sqlite => {
                self.strings(
                    &format!("SELECT name || '|' || lower(type) FROM pragma_table_info('{table}')"),
                    &[],
                )
                .await
            }
            BackendKind::MariaDb => {
                self.strings(
                    &format!(
                        "SELECT CAST(CONCAT(column_name, '|', data_type) AS CHAR) FROM information_schema.columns \
                         WHERE table_schema = DATABASE() AND table_name = '{table}'"
                    ),
                    &[],
                )
                .await
            }
            _ => {
                self.strings(
                    &format!(
                        "SELECT column_name::text || '|' || data_type::text FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = '{table}'"
                    ),
                    &[],
                )
                .await
            }
        };
        let columns: Vec<(String, bool)> = described
            .into_iter()
            .flatten()
            .map(|entry| {
                let (name, data_type) = entry.split_once('|').unwrap();
                let binary = ["blob", "binary", "varbinary", "bytea", "longblob"].contains(&data_type);
                (name.to_owned(), binary)
            })
            .collect();
        assert!(!columns.is_empty(), "no columns for {table}");
        let cells: Vec<String> = columns
            .iter()
            .map(|(name, binary)| match (kind, binary) {
                (BackendKind::Sqlite, true) => format!("COALESCE(hex(t.{name}), '')"),
                (BackendKind::Sqlite, false) => format!("COALESCE(CAST(t.{name} AS TEXT), '')"),
                (BackendKind::MariaDb, true) => format!("COALESCE(HEX(t.{name}), '')"),
                (BackendKind::MariaDb, false) => format!("COALESCE(CAST(t.{name} AS CHAR), '')"),
                (_, true) => format!("COALESCE(encode(t.{name}, 'hex'), '')"),
                (_, false) => format!("COALESCE(t.{name}::text, '')"),
            })
            .collect();
        let rows = match kind {
            BackendKind::MariaDb => format!(
                "SELECT CAST(CONCAT_WS('|', {}) AS CHAR) FROM {table} t WHERE run_id = $1",
                cells.join(", ")
            ),
            _ => format!(
                "SELECT {} FROM {table} t WHERE run_id = $1",
                cells.join(" || '|' || ")
            ),
        };
        self.strings(&rows, &[V::Uuid(run.0)])
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A `url_frontier` row for `url` (what the frontier repository would have written) and its
    /// id. A zero-data-retention run keeps no URL.
    async fn frontier(&self, tenant: TenantId, run: CrawlRunId, url: &str, zdr: bool) -> i64 {
        let canonical = canonical_url(url);
        let key = canonical.key.0;
        let stored = if zdr { None } else { Some(canonical.url.as_str()) };
        let origin = Digest::of("crawlx/zdr-origin/v1", canonical.origin.as_bytes()).to_hex();
        let origin = if zdr {
            origin.as_str()
        } else {
            canonical.origin.as_str()
        };
        let url_value = stored.map_or(V::Text(""), V::Text);
        let template = if zdr {
            "INSERT INTO url_frontier (run_id, tenant_id, canonical_key, origin, depth, via) \
             VALUES ($1, $2, $3, $4, 0, 'seed')"
        } else {
            "INSERT INTO url_frontier (run_id, tenant_id, canonical_key, origin, depth, via, canonical_url) \
             VALUES ($1, $2, $3, $4, 0, 'seed', $5)"
        };
        let mut args = vec![V::Uuid(run.0), V::Uuid(tenant.0), V::Bytes(&key), V::Text(origin)];
        if !zdr {
            args.push(url_value);
        }
        self.exec(template, &args).await;
        self.int(
            "SELECT frontier_id FROM url_frontier WHERE run_id = $1 AND canonical_key = $2",
            &[V::Uuid(run.0), V::Bytes(&key)],
        )
        .await
    }

    /// A credential-bearing artifact row, expiring at `expires_at`.
    async fn credential_artifact(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        expires_at: DateTime<Utc>,
    ) -> ArtifactId {
        let id = ArtifactId::new();
        let digest = Digest::of("t", id.0.as_bytes());
        let key = format!("k/{}", id.0);
        self.exec(
            "INSERT INTO artifacts (artifact_id, tenant_id, run_id, kind, bucket, object_key, size_bytes, content_digest, \
               content_type, sensitivity, expires_at) \
             VALUES ($1, $2, $3, 'storage_state', 'bucket', $4, 1, $5, 'application/json', 'credential_bearing'::text::sensitivity_class, $6)",
            &[
                V::Uuid(id.0),
                V::Uuid(tenant.0),
                V::Uuid(run.0),
                V::Text(&key),
                V::Bytes(&digest.0),
                V::Ts(expires_at),
            ],
        )
        .await;
        id
    }
}

fn status_error(error: &StoreError) -> &'static str {
    match error {
        StoreError::Conflict(_) => "conflict",
        StoreError::NotFound { .. } => "not_found",
        StoreError::IllegalTransition { .. } => "illegal_transition",
        _ => "other",
    }
}

// ---- cases on every engine ---------------------------------------------------------------

async fn run_lifecycle_and_status_machine(rig: &Rig) {
    let env = env(rig).await;
    let runs = &env.repos.runs;
    let run = env.run(&["admin", "member"], 2).await;
    assert_eq!(runs.get(run.id).await.unwrap(), run);
    assert_eq!(runs.get_metadata(run.id).await.unwrap().id, run.id);

    runs.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let started = runs.get(run.id).await.unwrap().started_at;
    assert!(started.is_some());
    // starting again keeps the first start time
    runs.set_status(run.id, RunStatus::Running, None).await.unwrap();
    assert_eq!(runs.get(run.id).await.unwrap().started_at, started);
    assert!(
        matches!(
            runs.set_status(run.id, RunStatus::Completed, None).await,
            Err(StoreError::Conflict(_))
        ),
        "terminal needs a reason"
    );
    assert!(
        matches!(
            runs.set_status(
                run.id,
                RunStatus::Running,
                Some(TerminalReason::FrontierExhausted)
            )
            .await,
            Err(StoreError::Conflict(_))
        ),
        "a reason needs a terminal status"
    );
    runs.set_status(
        run.id,
        RunStatus::Completed,
        Some(TerminalReason::FrontierExhausted),
    )
    .await
    .unwrap();
    let finished = runs.get(run.id).await.unwrap();
    assert_eq!(finished.status, RunStatus::Completed);
    assert_eq!(finished.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert!(finished.finished_at.is_some());
    // a terminal run never moves again
    for (status, reason) in [
        (RunStatus::Running, None),
        (RunStatus::Failed, Some(TerminalReason::FatalError)),
    ] {
        assert!(
            matches!(
                runs.set_status(run.id, status, reason).await,
                Err(StoreError::IllegalTransition { .. })
            ),
            "{status:?}"
        );
    }
    assert!(matches!(
        runs.set_status(CrawlRunId::new(), RunStatus::Running, None).await,
        Err(StoreError::NotFound { .. })
    ));

    // idempotency: the first create wins, the second leaves nothing behind
    let second = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    runs.create(&second, Some("key-1")).await.unwrap();
    let again = crawl_run(env.tenant, create_crawl("https://example.test/", &[], 1));
    assert_eq!(
        status_error(&runs.create(&again, Some("key-1")).await.unwrap_err()),
        "conflict"
    );
    assert!(
        runs.get(again.id).await.is_err(),
        "the failed create left no run behind"
    );
    // the same key of another tenant is another key
    let other = tenant(rig).await;
    let third = crawl_run(other, create_crawl("https://example.test/", &[], 1));
    runs.create(&third, Some("key-1")).await.unwrap();
    assert_eq!(
        status_error(&runs.create(&run, None).await.unwrap_err()),
        "conflict",
        "a run id is created once"
    );

    let mut counters = run.counters;
    counters.urls.discovered = 3;
    counters.urls.admitted = 3;
    runs.update_counters(run.id, counters).await.unwrap();
    assert_eq!(runs.get(run.id).await.unwrap().counters.urls.discovered, 3);
    assert!(matches!(
        runs.update_counters(CrawlRunId::new(), counters).await,
        Err(StoreError::NotFound { .. })
    ));
    let trace = crawlx_core::TraceId::new();
    runs.set_trace_id(run.id, trace).await.unwrap();
    assert_eq!(runs.get(run.id).await.unwrap().trace_id, Some(trace));
    assert!(matches!(
        runs.set_trace_id(CrawlRunId::new(), trace).await,
        Err(StoreError::NotFound { .. })
    ));
}

async fn sessions_roundtrip_with_browser_info(rig: &Rig) {
    let env = env(rig).await;
    let run = env.run(&["a"], 1).await;
    let slots = sessions(run.id, 1, 1);
    env.repos.runs.create_sessions(&slots).await.unwrap();
    let info = crawlx_core::observation::BrowserBuildInfo {
        chromium_version: "130.0".to_owned(),
        cdp_revision: "r1".to_owned(),
        user_agent: "ua".to_owned(),
        pinned: true,
        launch_profile: crawlx_core::LaunchProfile::Standard,
        console_capture: true,
        attached: false,
    };
    env.repos
        .runs
        .set_session_browser(slots[0].id, &info)
        .await
        .unwrap();
    let listed = env.repos.runs.list_sessions(run.id).await.unwrap();
    assert_eq!(listed[0].browser.as_ref(), Some(&info));
    assert_eq!(listed[0].id, slots[0].id);
    assert!(matches!(
        env.repos.runs.set_session_browser(SessionId::new(), &info).await,
        Err(StoreError::NotFound { .. })
    ));
    env.repos
        .runs
        .set_session_status(slots[0].id, SessionStatus::Cancelled)
        .await
        .unwrap();
    assert!(matches!(
        env.repos
            .runs
            .set_session_status(slots[0].id, SessionStatus::Running)
            .await,
        Err(StoreError::IllegalTransition { .. })
    ));
    assert!(matches!(
        env.repos
            .runs
            .set_session_status(SessionId::new(), SessionStatus::Running)
            .await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        env.repos
            .runs
            .create_sessions(&sessions(CrawlRunId::new(), 1, 1))
            .await,
        Err(StoreError::NotFound { .. })
    ));
    // the session kind survives the round trip
    let run = env.run(&["a"], 2).await;
    let mut kinds = sessions(run.id, 1, 2);
    kinds[1].kind = crawlx_core::repo::SessionKind::HttpCoordinator;
    env.repos.runs.create_sessions(&kinds).await.unwrap();
    assert_eq!(env.repos.runs.list_sessions(run.id).await.unwrap(), kinds);
}

async fn edges_need_a_ledger_context_and_upsert_by_key(rig: &Rig) {
    let env = env(rig).await;
    let (run, _) = env.run_with_session().await;
    let p = proposal("anonymous", StateClusterId::new(), 1);
    let now = Utc::now();
    let edge = EdgeRecord {
        id: crawlx_core::EdgeId::new(),
        run: run.id,
        source: p.key.id(),
        context_cluster: None,
        target: p.key.element,
        support: 3,
        weak_support: 2,
        failures: 1,
        latency_ms_ewma: 12.5,
        risk: 0.25,
        last_observed_at: now,
        last_verified_build: Some("130".to_owned()),
    };
    assert!(matches!(
        env.repos.edges.upsert(&edge).await,
        Err(StoreError::NotFound { .. })
    ));
    env.repos
        .ledger
        .upsert(
            run.id,
            &LedgerRow {
                key: p.key.clone(),
                trusted_exercised: 1,
                diagnostic_exercised: 0,
                failures: 0,
                first_seen: now,
                last_exercised: Some(now),
            },
        )
        .await
        .unwrap();
    env.repos.edges.upsert(&edge).await.unwrap();
    let mut second = edge.clone();
    second.id = crawlx_core::EdgeId::new();
    second.support = 4;
    env.repos.edges.upsert(&second).await.unwrap(); // same key (cluster NULL): one row
    let edges = env.repos.edges.list(run.id).await.unwrap();
    assert_eq!(edges.len(), 1, "a NULL cluster does not defeat the unique key");
    assert_eq!(
        (edges[0].id, edges[0].support, edges[0].weak_support),
        (edge.id, 4, 2)
    );
    assert_eq!(edges[0].last_verified_build.as_deref(), Some("130"));
    assert_eq!(edges[0].context_cluster, None);
    assert!((edges[0].latency_ms_ewma - 12.5).abs() < f32::EPSILON);
    assert!((edges[0].risk - 0.25).abs() < f32::EPSILON);
    // a cluster is a different key
    let mut clustered = edge.clone();
    clustered.id = crawlx_core::EdgeId::new();
    clustered.context_cluster = Some(StateClusterId::new());
    env.repos.edges.upsert(&clustered).await.unwrap();
    assert_eq!(env.repos.edges.list(run.id).await.unwrap().len(), 2);
    if !memory(rig) {
        let cast = match rig.kind().unwrap() {
            BackendKind::Sqlite => "CAST(p_success AS TEXT)",
            BackendKind::MariaDb => "CAST(p_success AS CHAR)",
            _ => "p_success::text",
        };
        let p_success = Raw(rig)
            .strings(
                &format!(
                    "SELECT {cast} FROM enablement_edges WHERE run_id = $1 AND context_cluster_id IS NULL"
                ),
                &[V::Uuid(run.id.0)],
            )
            .await;
        let value: f64 = p_success[0].as_deref().unwrap().parse().unwrap();
        assert!(
            (value - (4.0 + 1.0 + 1.0) / (4.0 + 1.0 + 1.0 + 2.0)).abs() < 1e-9,
            "{value}"
        );
    }
}

async fn identity_aliases_round_trip(rig: &Rig) {
    let env = env(rig).await;
    let (run, _) = env.run_with_session().await;
    let h = |s: &str| crawlx_core::ElementIdentityHash(Digest::of("t", s.as_bytes()));
    let a = IdentityAlias {
        alias: h("minted"),
        canonical: h("known"),
        from_version: 1,
        to_version: 1,
        score: 0.71,
    };
    // an unknown run: a foreign key violation (a conflict) in a database, not found in memory
    assert!(matches!(
        env.repos.aliases.record_alias(CrawlRunId::new(), &a).await,
        Err(StoreError::Conflict(_) | StoreError::NotFound { .. })
    ));
    env.repos.aliases.record_alias(run.id, &a).await.unwrap();
    // the same pair again keeps the first score
    env.repos
        .aliases
        .record_alias(run.id, &IdentityAlias { score: 0.65, ..a })
        .await
        .unwrap();
    let b = IdentityAlias {
        alias: h("v2"),
        canonical: h("known"),
        from_version: 2,
        to_version: 1,
        score: 1.0,
    };
    env.repos.aliases.record_alias(run.id, &b).await.unwrap();
    let mut expected = vec![a, b];
    expected.sort_by_key(|x| x.alias);
    assert_eq!(
        env.repos.aliases.aliases_of(run.id, h("known")).await.unwrap(),
        expected
    );
    assert!(env
        .repos
        .aliases
        .aliases_of(run.id, h("minted"))
        .await
        .unwrap()
        .is_empty());
    if !memory(rig) {
        let raw = Raw(rig);
        assert_eq!(
            raw.int(
                "SELECT count(*) FROM identity_aliases WHERE run_id = $1",
                &[V::Uuid(run.id.0)]
            )
            .await,
            2
        );
        assert_eq!(
            raw.int(
                "SELECT count(*) FROM elements WHERE run_id = $1 AND identity_version = 2",
                &[V::Uuid(run.id.0)]
            )
            .await,
            1
        );
    }
}

async fn events_are_monotonic_per_run(rig: &Rig) {
    let env = env(rig).await;
    let run = env.run(&[], 1).await;
    let other = env.run(&[], 1).await;
    for i in 0..3_u64 {
        assert_eq!(
            env.repos
                .events
                .append(run.id, "progress", serde_json::json!({ "i": i, "text": "é𝄞" }))
                .await
                .unwrap(),
            i + 1
        );
    }
    assert_eq!(
        env.repos
            .events
            .append(other.id, "started", serde_json::json!({}))
            .await
            .unwrap(),
        1,
        "every run has its own sequence"
    );
    let page = env.repos.events.list_after(run.id, 1, 10).await.unwrap();
    assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(page[0].kind, "progress");
    assert_eq!(page[0].payload, serde_json::json!({ "i": 1, "text": "é𝄞" }));
    let metadata = env.repos.events.list_metadata_after(run.id, 0, 2).await.unwrap();
    assert_eq!(metadata.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert!(matches!(
        env.repos
            .events
            .append(CrawlRunId::new(), "progress", serde_json::json!({}))
            .await,
        Err(StoreError::NotFound { .. })
    ));
    // concurrent appends never repeat a sequence number
    let mut writers = Vec::new();
    for _ in 0..6 {
        let events = env.repos.events.clone();
        let run = run.id;
        writers.push(tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..4 {
                seen.push(
                    events
                        .append(run, "progress", serde_json::json!({}))
                        .await
                        .unwrap(),
                );
            }
            seen
        }));
    }
    let mut all = std::collections::BTreeSet::new();
    for writer in writers {
        for seq in writer.await.unwrap() {
            assert!(all.insert(seq), "sequence {seq} handed out twice");
        }
    }
    assert_eq!(all.len(), 24);
    assert_eq!(all.iter().next().copied(), Some(4));
    assert_eq!(all.iter().next_back().copied(), Some(27));
}

fn model_decision(run: CrawlRunId, session: SessionId, marker: &str) -> ModelDecisionRecord {
    ModelDecisionRecord {
        id: crawlx_core::ModelDecisionId::new(),
        run,
        session: Some(session),
        kind: ModelDecisionKind::Plan,
        mode: crawlx_core::config::System1Mode::Shadow,
        provider: marker.to_owned(),
        model: marker.to_owned(),
        model_version: marker.to_owned(),
        calibration_version: Some(marker.to_owned()),
        confidence: Some(0.5),
        output: serde_json::json!({"prompt": marker, "content": marker, "evidence": marker}),
        prompt_digest: Digest::of("test/prompt", marker.as_bytes()),
        latency_ms: Some(12),
        breaker_state: Some(marker.to_owned()),
        created_at: Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap(),
    }
}

async fn model_decisions_are_idempotent_on_the_decision_id(rig: &Rig) {
    let env = env(rig).await;
    let (run, session) = env.run_with_session().await;
    let model = model_decision(run.id, session, "plain-provider");
    env.repos.models.record(&model).await.unwrap();
    let mut duplicate = model.clone();
    duplicate.output = serde_json::json!({"replacement": "must not replace the original"});
    env.repos.models.record(&duplicate).await.unwrap();
    assert_eq!(env.repos.models.list(run.id).await.unwrap(), vec![model.clone()]);
    let mut without = model_decision(run.id, session, "second");
    without.session = None;
    without.calibration_version = None;
    without.confidence = None;
    without.latency_ms = None;
    without.breaker_state = None;
    env.repos.models.record(&without).await.unwrap();
    let listed = env.repos.models.list(run.id).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&without) && listed.contains(&model));
}

async fn states_clusters_and_splits_round_trip(rig: &Rig) {
    let env = env(rig).await;
    let (run, session) = env.run_with_session().await;
    let source = StateClusterId::new();
    let state = new_state(session, source, true, 1, epoch(1, 1, 10));
    assert!(matches!(
        env.repos
            .states
            .put_state(&new_state(SessionId::new(), source, true, 2, epoch(1, 1, 0)))
            .await,
        Err(StoreError::NotFound { .. })
    ));
    env.repos.states.put_state(&state).await.unwrap();
    // states are immutable: a second put of the same id keeps the first
    let mut duplicate = state.clone();
    duplicate.url = canonical_url("https://example.test/not-the-original");
    env.repos.states.put_state(&duplicate).await.unwrap();
    assert_eq!(
        env.repos.states.list_states(run.id).await.unwrap(),
        vec![state.clone()]
    );
    // a member of the same cluster
    let member = new_state(session, source, false, 2, epoch(1, 1, 11));
    env.repos.states.put_state(&member).await.unwrap();
    // an unknown cluster is refused
    assert!(matches!(
        env.repos
            .states
            .put_state(&new_state(
                session,
                StateClusterId::new(),
                false,
                3,
                epoch(1, 1, 12)
            ))
            .await,
        Err(StoreError::NotFound { .. })
    ));
    let clusters = env.repos.states.list_clusters(run.id).await.unwrap();
    assert_eq!(clusters.len(), 1);
    assert_eq!((clusters[0].0, clusters[0].2), (source, 2));

    // a ledger row in the source cluster is re-keyed to the successor by the split
    let mut key = proposal("anonymous", source, 1).key;
    key.state_cluster = source;
    let row = LedgerRow {
        key: key.clone(),
        trusted_exercised: 1,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: Utc::now(),
        last_exercised: None,
    };
    env.repos.ledger.upsert(run.id, &row).await.unwrap();

    let successor = StateClusterId::new();
    let split = ClusterSplitRecord {
        run: run.id,
        source,
        source_version: 1,
        successors: vec![SplitSuccessor {
            cluster: successor,
            version: 2,
            prototype: state.id,
            signature: signature(1),
            members: vec![
                SplitMember {
                    state: state.id,
                    similarity: 1.0,
                },
                SplitMember {
                    state: member.id,
                    similarity: 0.5,
                },
            ],
        }],
        decided_at: Utc::now(),
    };
    let applied = env.repos.states.apply_split(&split).await.unwrap();
    assert_eq!(applied.memberships_moved, 2);
    assert_eq!(applied.action_contexts_rekeyed, 1);
    let states = env.repos.states.list_states(run.id).await.unwrap();
    assert!(states.iter().all(|s| s.cluster == successor));
    let clusters = env.repos.states.list_clusters(run.id).await.unwrap();
    assert_eq!(clusters.iter().map(|c| c.0).collect::<Vec<_>>(), vec![successor]);
    let ledger = env.repos.ledger.list(run.id).await.unwrap();
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].key.state_cluster, successor);
    // a refused re-application (the source is superseded) changes nothing
    assert!(matches!(
        env.repos.states.apply_split(&split).await,
        Err(StoreError::Conflict(_))
    ));
}

// ---- cases on the databases --------------------------------------------------------------

async fn replay_creation_checks_the_source_and_is_atomic(rig: &Rig) {
    let env = env(rig).await;
    let foreign = tenant(rig).await;
    let source = crawl_run(foreign, create_crawl("https://example.test/", &[], 1));
    env.repos.runs.create(&source, None).await.unwrap();
    let replay = crawl_run(env.tenant, source.config.clone());
    let slots = sessions(replay.id, 1, 1);
    for source_id in [source.id, CrawlRunId::new()] {
        let spec = serde_json::json!({"sourceRunId": source_id});
        assert!(matches!(
            env.repos.runs.create_replay(&replay, &slots, &spec).await,
            Err(StoreError::NotFound { .. })
        ));
    }
    let source = env.run(&[], 1).await;
    let spec = serde_json::json!({"sourceRunId": source.id});
    // sessions of another run are refused
    assert!(env
        .repos
        .runs
        .create_replay(&replay, &sessions(source.id, 1, 1), &spec)
        .await
        .is_err());
    assert!(matches!(
        env.repos.runs.get(replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        env.repos.runs.replay_spec(replay.id).await,
        Err(StoreError::NotFound { .. })
    ));
    // a valid replay is created with its sessions in one step
    env.repos
        .runs
        .create_replay(&replay, &slots, &spec)
        .await
        .unwrap();
    assert_eq!(env.repos.runs.replay_spec(replay.id).await.unwrap(), Some(spec));
    assert_eq!(env.repos.runs.list_sessions(replay.id).await.unwrap(), slots);
    assert_eq!(env.repos.runs.replay_spec(source.id).await.unwrap(), None);
    let raw = Raw(rig);
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM crawl_runs WHERE run_id = $1 AND run_kind = 'replay'",
            &[V::Uuid(replay.id.0)]
        )
        .await,
        1
    );
}

#[allow(clippy::field_reassign_with_default)] // BufferLimits is non-exhaustive outside its crate.
async fn literal_controls_never_enter_the_database_and_expire_fail_closed(rig: &Rig) {
    let clock = Arc::new(crawlx_core::time::ManualClock::new(Utc::now()));
    let mut limits = crawlx_storage::BufferLimits::default();
    limits.ttl = std::time::Duration::from_secs(1);
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), limits));
    let env = env_with(rig, buffer).await;
    let mut config = create_crawl("https://example.test/", &[], 1);
    config
        .fetch
        .extra_headers
        .insert("x-password", "db-password-canary");
    config.fetch.extra_headers.insert("x-reference", "env://TOKEN");
    config
        .fetch
        .cookies
        .push(crawlx_core::request_controls::FetchCookie::new(
            "session",
            "db-cookie-canary",
        ));
    let source = crawl_run(env.tenant, config.clone());
    env.repos.runs.create(&source, None).await.unwrap();
    let replay = crawl_run(env.tenant, config.clone());
    env.repos
        .runs
        .create_replay(
            &replay,
            &sessions(replay.id, 1, 1),
            &serde_json::json!({"sourceRunId": source.id}),
        )
        .await
        .unwrap();
    let raw = Raw(rig);
    for run in [&source, &replay] {
        let stored = raw
            .strings(
                "SELECT config::text FROM crawl_runs WHERE run_id = $1",
                &[V::Uuid(run.id.0)],
            )
            .await;
        let stored = stored[0].clone().unwrap();
        assert!(!stored.contains("db-password-canary") && !stored.contains("db-cookie-canary"));
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["fetch"]["extraHeaders"]["x-reference"], "env://TOKEN");
        assert_eq!(
            env.repos.runs.get(run.id).await.unwrap().config.fetch.cookies[0].value,
            "[redacted]"
        );
        assert_eq!(
            env.repos.runs.get_for_execution(run.id).await.unwrap().config,
            config
        );
    }
    clock.advance_ms(2_000);
    for run in [&source, &replay] {
        assert!(env.repos.runs.get(run.id).await.is_ok());
        assert!(env.repos.runs.get_metadata(run.id).await.is_ok());
        assert!(matches!(
            env.repos.runs.get_for_execution(run.id).await,
            Err(StoreError::RetentionDenied(_))
        ));
    }
}

fn page_record(run: CrawlRunId, frontier_id: i64, url: &str, at: DateTime<Utc>) -> PageRecord {
    PageRecord {
        run,
        frontier_id,
        url: canonical_url(url),
        status: 200,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", url.as_bytes()),
        title: Some("Title".to_owned()),
        markdown: Some(ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("t", b"m"),
        }),
        html: None,
        metadata: serde_json::json!({"og:title": "x"}),
        links: vec!["https://example.test/b".to_owned()],
        fetched_at: at,
        lane: TrustLane::Diagnostic,
    }
}

async fn pages_roundtrip_and_upsert_by_role_and_url(rig: &Rig) {
    let env = env(rig).await;
    let run = env.run(&[], 1).await;
    let frontier = Raw(rig)
        .frontier(env.tenant, run.id, "https://example.test/a", false)
        .await;
    let fetched_at = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let page = page_record(run.id, frontier, "https://example.test/a", fetched_at);
    env.repos.pages.put(&page).await.unwrap();
    let mut changed = page.clone();
    changed.title = Some("Second".to_owned());
    changed.links.push("https://example.test/c".to_owned());
    env.repos.pages.put(&changed).await.unwrap(); // upsert on (run, role, url)
    let pages = env.repos.pages.list(run.id).await.unwrap();
    assert_eq!(pages, vec![changed.clone()]);
    assert_eq!(pages[0].markdown, page.markdown);
    assert_eq!(pages[0].url, page.url);
    assert_eq!(
        pages[0].fetched_at, page.fetched_at,
        "timestamps keep their microseconds"
    );
    assert!(env.repos.pages.billing(run.id).await.unwrap().is_none());
    let recent = env
        .repos
        .pages
        .recent_for_url(env.tenant, &page.url, 5)
        .await
        .unwrap();
    assert_eq!(recent, vec![changed]);
    // another tenant sees none of it
    let other = tenant(rig).await;
    assert!(env
        .repos
        .pages
        .recent_for_url(other, &page.url, 5)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        Raw(rig)
            .int(
                "SELECT count(*) FROM pages WHERE run_id = $1",
                &[V::Uuid(run.id.0)]
            )
            .await,
        1
    );
}

/// A page to store for [`known_pages_list_the_stored_pages_of_a_site`].
struct Spec {
    url: &'static str,
    status: u16,
    title: Option<&'static str>,
    description: Option<&'static str>,
    links: &'static [&'static str],
    not_cacheable: bool,
}

impl Spec {
    const fn new(url: &'static str) -> Self {
        Self {
            url,
            status: 200,
            title: None,
            description: None,
            links: &[],
            not_cacheable: false,
        }
    }
}

fn now_ms() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

async fn site_run(
    env: &Env<'_>,
    tenant: TenantId,
    mode: RetentionMode,
    days: u16,
    created_at: DateTime<Utc>,
) -> CrawlRunId {
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = mode;
    config.retention.days = days;
    let mut run = crawl_run(tenant, config);
    run.created_at = created_at;
    env.repos.runs.create(&run, None).await.unwrap();
    run.id
}

async fn store_page(
    env: &Env<'_>,
    tenant: TenantId,
    run: CrawlRunId,
    zdr: bool,
    at: DateTime<Utc>,
    spec: &Spec,
) {
    use crawlx_core::repo::FrontierRepo as _;
    use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
    let frontier = if memory(env.rig) {
        env.rig
            .store()
            .discover(run, &canonical_url(spec.url), 0, None, None)
            .await
            .unwrap()
            .1
            .unwrap()
    } else {
        Raw(env.rig).frontier(tenant, run, spec.url, zdr).await
    };
    let mut metadata = serde_json::json!({});
    if let Some(description) = spec.description {
        metadata["description"] = serde_json::json!(description);
    }
    if spec.not_cacheable {
        // the real document layout, so the flag's JSON path is the one the scrape engine writes
        let mut doc = ScrapeDocument::new(
            spec.url.to_owned(),
            spec.url.to_owned(),
            spec.status,
            ScrapeOptions::default().cache_digest(),
        );
        doc.not_cacheable = true;
        metadata[ScrapeDocument::METADATA_KEY] = serde_json::to_value(&doc).unwrap();
    }
    let page = PageRecord {
        run,
        frontier_id: frontier,
        url: canonical_url(spec.url),
        status: spec.status,
        content_type: Some("text/html".to_owned()),
        content_digest: Digest::of("t", spec.url.as_bytes()),
        title: spec.title.map(str::to_owned),
        markdown: None,
        html: None,
        metadata,
        links: spec.links.iter().map(|l| (*l).to_owned()).collect(),
        fetched_at: at,
        lane: TrustLane::Diagnostic,
    };
    env.repos.pages.put(&page).await.unwrap();
}

async fn known_pages_list_the_stored_pages_of_a_site(rig: &Rig) {
    let env = env(rig).await;
    let alpha = env.tenant;
    let beta = tenant(rig).await;
    let gamma = tenant(rig).await;
    let t0 = now_ms();
    let sec = Duration::seconds;
    let standard = RetentionMode::Standard;
    let main = site_run(&env, alpha, standard, 7, t0).await;
    let later = site_run(&env, alpha, standard, 7, t0).await;
    let zdr = site_run(&env, alpha, RetentionMode::Zdr, 0, t0).await;
    let old = site_run(&env, alpha, standard, 7, t0 - Duration::days(10)).await;
    let other = site_run(&env, beta, standard, 7, t0).await;
    let put = |tenant, run, zdr, at, spec| {
        let env = &env;
        async move { store_page(env, tenant, run, zdr, at, &spec).await }
    };

    let home = Spec {
        title: Some("Home"),
        description: Some("The home page"),
        links: &[
            "https://example.test/a",
            "https://example.test/b",
            "https://other.test/x",
        ],
        ..Spec::new("https://example.test/")
    };
    put(alpha, main, false, t0, home).await;
    let blog = Spec {
        links: &["https://www.example.test/blog/p1"],
        ..Spec::new("https://www.example.test/blog")
    };
    put(alpha, main, false, t0 + sec(1), blog).await;
    // listed: an HTTP status of 0 means none was recorded
    let no_status = Spec {
        status: 0,
        ..Spec::new("https://example.test/nostatus")
    };
    put(alpha, main, false, t0 + sec(4), no_status).await;
    // userinfo and a port do not hide the host
    put(
        alpha,
        main,
        false,
        t0 + sec(8),
        Spec::new("http://user:secret@example.test:8080/auth"),
    )
    .await;
    put(alpha, main, false, t0 + sec(9), Spec::new("http://[::1]:8080/v6")).await;
    // never listed: an error page, a page flagged not cacheable, other hosts (a name that merely
    // ends in the domain, a domain that merely starts with it)
    let gone = Spec {
        status: 404,
        links: &["https://example.test/from-404"],
        ..Spec::new("https://example.test/gone")
    };
    put(alpha, main, false, t0 + sec(2), gone).await;
    let unlisted = Spec {
        not_cacheable: true,
        links: &["https://example.test/from-unlisted"],
        ..Spec::new("https://example.test/unlisted")
    };
    put(alpha, main, false, t0 + sec(3), unlisted).await;
    for (i, u) in [
        "https://example.org/",
        "https://notexample.test/",
        "https://example.test.evil.org/",
    ]
    .into_iter()
    .enumerate()
    {
        put(
            alpha,
            main,
            false,
            t0 + sec(5 + i64::try_from(i).unwrap()),
            Spec::new(u),
        )
        .await;
    }
    put(
        alpha,
        later,
        false,
        t0 + sec(10),
        Spec::new("https://example.test/new"),
    )
    .await;
    put(
        alpha,
        zdr,
        true,
        t0 + sec(11),
        Spec::new("https://example.test/zdr"),
    )
    .await;
    put(
        alpha,
        old,
        false,
        t0 + sec(12),
        Spec::new("https://example.test/expired"),
    )
    .await;
    put(
        beta,
        other,
        false,
        t0 + sec(13),
        Spec::new("https://example.test/beta-only"),
    )
    .await;

    let now = t0 + Duration::minutes(1);
    let known = |tenant, domain: &'static str, subdomains, at, limit| {
        let repos = &env.repos;
        async move {
            repos
                .pages
                .known_pages(tenant, domain, subdomains, at, limit)
                .await
                .unwrap()
        }
    };
    let urls = |pages: &[crawlx_core::repo::KnownPage]| -> Vec<String> {
        pages.iter().map(|p| p.url.url.to_string()).collect()
    };

    // the domain and its subdomains, newest first; the zero-data-retention run, the expired run
    // and the other tenant's pages are never read
    let all = known(alpha, "example.test", true, now, 100).await;
    assert_eq!(
        urls(&all),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth",
            "https://example.test/nostatus",
            "https://www.example.test/blog",
            "https://example.test/",
        ]
    );
    let page = all.last().unwrap();
    assert_eq!(page.title.as_deref(), Some("Home"));
    assert_eq!(page.description.as_deref(), Some("The home page"));
    assert_eq!(
        page.links,
        [
            "https://example.test/a",
            "https://example.test/b",
            "https://other.test/x"
        ]
    );
    assert!(all[0].title.is_none() && all[0].description.is_none() && all[0].links.is_empty());

    // one host only
    assert_eq!(
        urls(&known(alpha, "example.test", false, now, 100).await),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth",
            "https://example.test/nostatus",
            "https://example.test/",
        ]
    );
    assert_eq!(
        urls(&known(alpha, "www.example.test", false, now, 100).await),
        ["https://www.example.test/blog"]
    );
    // case and a trailing dot of the argument do not matter
    assert_eq!(
        known(alpha, "EXAMPLE.test.", true, now, 100).await,
        all,
        "the domain is matched case-insensitively"
    );
    // an IP literal is a host of its own
    assert_eq!(
        urls(&known(alpha, "[::1]", false, now, 100).await),
        ["http://[::1]:8080/v6"]
    );
    // a domain with LIKE metacharacters matches nothing it should not
    assert!(known(alpha, "ex_mple.test", true, now, 100).await.is_empty());
    assert!(known(alpha, "%", true, now, 100).await.is_empty());

    // tenants
    assert_eq!(
        urls(&known(beta, "example.test", true, now, 100).await),
        ["https://example.test/beta-only"]
    );
    assert!(known(gamma, "example.test", true, now, 100).await.is_empty());

    // the limit keeps the newest pages
    assert_eq!(
        urls(&known(alpha, "example.test", true, now, 2).await),
        [
            "https://example.test/new",
            "http://user:secret@example.test:8080/auth"
        ]
    );
    assert!(known(alpha, "example.test", true, now, 0).await.is_empty());

    // `now` decides which runs expired: the standard runs live seven days from their creation
    assert_eq!(
        known(alpha, "example.test", true, t0 + Duration::days(6), 100)
            .await
            .len(),
        5
    );
    assert!(
        known(alpha, "example.test", true, t0 + Duration::days(8), 100)
            .await
            .is_empty(),
        "every run of the tenant has expired"
    );
}

async fn the_host_key_is_the_reversed_lower_case_host_of_every_url_shape(rig: &Rig) {
    let env = env(rig).await;
    let run = site_run(&env, env.tenant, RetentionMode::Standard, 7, now_ms()).await;
    for (i, url) in [
        "https://Example.TEST/p",
        "http://user:pw@example.test:8080/q?x=1#f",
        "http://[::1]:8080/v6",
        "https://sub.example.test./dot",
    ]
    .into_iter()
    .enumerate()
    {
        store_page(
            &env,
            env.tenant,
            run,
            false,
            now_ms() + Duration::seconds(i64::try_from(i).unwrap()),
            &Spec::new(url),
        )
        .await;
    }
    let keys = Raw(rig)
        .strings(
            "SELECT host_key::text FROM pages WHERE run_id = $1 ORDER BY fetched_at",
            &[V::Uuid(run.0)],
        )
        .await;
    let keys: Vec<&str> = keys.iter().map(|key| key.as_deref().unwrap()).collect();
    assert_eq!(
        keys,
        ["tset.elpmaxe", "tset.elpmaxe", "]1::[", ".tset.elpmaxe.bus"]
    );
}

async fn the_site_lookup_reaches_pages_through_the_host_key_index(rig: &Rig) {
    let env = env(rig).await;
    let _ = &env;
    let raw = Raw(rig);
    match rig.kind().unwrap() {
        BackendKind::Postgres => {
            let definition = raw
                .strings(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = 'pages_host_key'",
                    &[],
                )
                .await;
            let definition = definition[0]
                .clone()
                .expect("the migration created pages_host_key");
            assert!(
                definition.contains("host_key") && definition.contains("text_pattern_ops"),
                "{definition}"
            );
            // with sequential scans disabled the planner must reach the table through that
            // index, for the exact host and for the domain with its subdomains
            let pool = rig.database().postgres().unwrap().pool();
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL enable_seqscan = off")
                .execute(&mut *tx)
                .await
                .unwrap();
            let plan: Vec<String> = sqlx::query_scalar(
                "EXPLAIN SELECT p.run_id FROM pages p WHERE p.host_key = 'tset.elpmaxe' OR p.host_key LIKE 'tset.elpmaxe.%'",
            )
            .fetch_all(&mut *tx)
            .await
            .unwrap();
            assert!(plan.iter().any(|l| l.contains("pages_host_key")), "{plan:?}");
        }
        BackendKind::Sqlite => {
            // the range the lookup scans is served by the same index
            let indexes = raw
                .strings(
                    "SELECT name FROM pragma_index_list('pages') WHERE name = 'pages_host_key'",
                    &[],
                )
                .await;
            assert_eq!(indexes.len(), 1);
        }
        _ => {
            let indexes = raw
                .strings(
                    "SELECT CAST(index_name AS CHAR) FROM information_schema.statistics \
                     WHERE table_schema = DATABASE() AND table_name = 'pages' AND index_name = 'pages_host_key'",
                    &[],
                )
                .await;
            assert_eq!(indexes.len(), 1);
        }
    }
}

#[test]
fn the_not_cacheable_flag_is_read_from_the_stored_scrape_document() {
    use crawlx_core::scrape::{ScrapeDocument, ScrapeOptions};
    let mut page = page_record(CrawlRunId::new(), 0, "https://example.test/", now_ms());
    page.metadata = serde_json::Value::Null;
    assert!(!page.is_not_cacheable(), "no metadata");
    let mut doc = ScrapeDocument::new(
        page.url.url.to_string(),
        page.url.url.to_string(),
        200,
        ScrapeOptions::default().cache_digest(),
    );
    page.metadata = serde_json::json!({ ScrapeDocument::METADATA_KEY: serde_json::to_value(&doc).unwrap() });
    assert!(!page.is_not_cacheable(), "a cacheable scrape");
    doc.not_cacheable = true;
    page.metadata = serde_json::json!({ ScrapeDocument::METADATA_KEY: serde_json::to_value(&doc).unwrap() });
    assert!(page.is_not_cacheable());
}

async fn ledger_rows_keep_the_coarsened_flag_and_absolute_counters(rig: &Rig) {
    let env = env(rig).await;
    let run = env.run(&[], 1).await;
    let mut key = proposal("anonymous", StateClusterId::new(), 1).key;
    key.state_cluster = key.coarsened_cluster();
    let now = Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap();
    let row = LedgerRow {
        key: key.clone(),
        trusted_exercised: 0,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: now,
        last_exercised: None,
    };
    env.repos.ledger.upsert(run.id, &row).await.unwrap();
    env.repos.ledger.upsert(run.id, &row).await.unwrap();
    let coarsened = Raw(rig)
        .int(
            "SELECT count(*) FROM action_contexts WHERE run_id = $1 AND context_hash = $2 AND coarsened",
            &[V::Uuid(run.id.0), V::Bytes(&key.id().0)],
        )
        .await;
    assert_eq!(
        coarsened, 1,
        "coarsening must not be silent in durable coverage rows"
    );
    let rows = env.repos.ledger.list(run.id).await.unwrap();
    assert_eq!(rows, vec![row]);
    assert!(rows[0].key.is_coarsened());
    let summary = env.repos.ledger.summary(run.id).await.unwrap();
    assert_eq!((summary.discovered, summary.exercised_trusted), (1, 0));

    // counters are absolute and `first_seen` keeps the earliest value
    let p = proposal("anonymous", StateClusterId::new(), 2);
    let first = LedgerRow {
        key: p.key.clone(),
        trusted_exercised: 2,
        diagnostic_exercised: 1,
        failures: 1,
        first_seen: now,
        last_exercised: Some(now),
    };
    env.repos.ledger.upsert(run.id, &first).await.unwrap();
    env.repos.ledger.upsert(run.id, &first).await.unwrap();
    let later = LedgerRow {
        trusted_exercised: 3,
        first_seen: now + Duration::hours(1),
        last_exercised: Some(now + Duration::hours(2)),
        ..first.clone()
    };
    env.repos.ledger.upsert(run.id, &later).await.unwrap();
    let listed = env.repos.ledger.list(run.id).await.unwrap();
    assert_eq!(listed.len(), 2);
    let stored = listed.iter().find(|r| r.key == p.key).unwrap();
    assert_eq!(
        (
            stored.trusted_exercised,
            stored.diagnostic_exercised,
            stored.failures
        ),
        (3, 1, 1)
    );
    assert_eq!(stored.first_seen, now);
    assert_eq!(stored.last_exercised, Some(now + Duration::hours(2)));
    let summary = env.repos.ledger.summary(run.id).await.unwrap();
    assert_eq!((summary.discovered, summary.exercised_trusted), (2, 1));
}

async fn safety_decisions_are_idempotent_on_the_decision_id(rig: &Rig) {
    let env = env(rig).await;
    let (run, session) = env.run_with_session().await;
    let v = verdict(SafetyDecision::Deny);
    env.repos
        .safety
        .record(run.id, session, &v, "denied: out of scope")
        .await
        .unwrap();
    env.repos
        .safety
        .record(run.id, session, &v, "again")
        .await
        .unwrap();
    let raw = Raw(rig);
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM safety_decisions WHERE run_id = $1",
            &[V::Uuid(run.id.0)]
        )
        .await,
        1
    );
    let evidence = raw
        .strings(
            "SELECT evidence::text FROM safety_decisions WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    assert!(evidence[0].as_deref().unwrap().contains("denied: out of scope"));
    assert!(matches!(
        env.repos
            .safety
            .record(
                CrawlRunId::new(),
                session,
                &verdict(SafetyDecision::Allow),
                "no run"
            )
            .await,
        Err(StoreError::NotFound { .. })
    ));
    env.repos
        .safety
        .record(run.id, session, &allow_verdict(), "allowed")
        .await
        .unwrap();
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM safety_decisions WHERE run_id = $1",
            &[V::Uuid(run.id.0)]
        )
        .await,
        2
    );
}

fn checkpoint(
    run: CrawlRunId,
    session: SessionId,
    artifact: ArtifactId,
    seq: u64,
    expires: DateTime<Utc>,
) -> CheckpointRecord {
    CheckpointRecord {
        id: CheckpointId::new(),
        run,
        session,
        epoch: epoch(1, 2, 3),
        action_seq: seq,
        reason: "cadence_actions".to_owned(),
        storage: ArtifactRef {
            id: artifact,
            digest: Digest::of("t", artifact.0.as_bytes()),
        },
        url_hash: Some(Digest::of("t", b"url")),
        created_at: DateTime::from_timestamp_micros(
            Utc::now().timestamp_micros() + i64::try_from(seq).unwrap(),
        )
        .unwrap(),
        expires_at: expires,
    }
}

async fn checkpoints_keep_the_newest_three_and_hide_expired_ones(rig: &Rig) {
    let env = env(rig).await;
    let (run, session) = env.run_with_session().await;
    // every engine stores microseconds: a nanosecond instant would not round-trip
    let future =
        DateTime::from_timestamp_micros((Utc::now() + Duration::days(1)).timestamp_micros()).unwrap();
    let mut stored = Vec::new();
    for seq in 1..=5_u64 {
        let artifact = env.credential_artifact(run.id, future).await;
        let record = checkpoint(run.id, session, artifact, seq, future);
        env.repos.checkpoints.put(&record).await.unwrap();
        stored.push(record);
    }
    let listed = env.repos.checkpoints.list(session).await.unwrap();
    assert_eq!(
        listed.iter().map(|c| c.action_seq).collect::<Vec<_>>(),
        vec![5, 4, 3],
        "the newest three survive, newest first"
    );
    assert_eq!(listed[0], stored[4]);
    assert_eq!(
        env.repos.checkpoints.latest(session).await.unwrap(),
        Some(stored[4].clone())
    );
    let raw = Raw(rig);
    assert_eq!(
        raw.int(
            "SELECT count(*) FROM checkpoints WHERE session_id = $1",
            &[V::Uuid(session.0)]
        )
        .await,
        3
    );
    // an expired checkpoint, or one whose artifact is deleted, is not offered
    let artifact = env
        .credential_artifact(run.id, Utc::now() - Duration::hours(1))
        .await;
    let expired_artifact = checkpoint(run.id, session, artifact, 9, future);
    env.repos.checkpoints.put(&expired_artifact).await.unwrap();
    assert_eq!(
        env.repos.checkpoints.latest(session).await.unwrap(),
        Some(stored[4].clone()),
        "its artifact expired"
    );
    let other = env.run_with_session().await;
    assert!(env.repos.checkpoints.latest(other.1).await.unwrap().is_none());
    let artifact = env.credential_artifact(other.0.id, future).await;
    let expired = checkpoint(
        other.0.id,
        other.1,
        artifact,
        1,
        Utc::now() - Duration::seconds(1),
    );
    env.repos.checkpoints.put(&expired).await.unwrap();
    assert!(env.repos.checkpoints.list(other.1).await.unwrap().is_empty());
}

async fn terminal_status_revokes_credentials_in_the_same_transaction(rig: &Rig) {
    let env = env(rig).await;
    let (run, session) = env.run_with_session().await;
    let raw = Raw(rig);
    let future = Utc::now() + Duration::days(1);
    let artifact = env.credential_artifact(run.id, future).await;
    let kept = env.credential_artifact(run.id, future).await;
    // a content artifact is not credential-bearing and keeps its retention
    raw.exec(
        "UPDATE artifacts SET sensitivity = 'content'::text::sensitivity_class WHERE artifact_id = $1",
        &[V::Uuid(kept.0)],
    )
    .await;
    env.repos
        .checkpoints
        .put(&checkpoint(run.id, session, artifact, 1, future))
        .await
        .unwrap();
    raw.exec(
        "INSERT INTO session_bindings (session_id, run_id, binding) VALUES ($1, $2, $3::jsonb)",
        &[
            V::Uuid(session.0),
            V::Uuid(run.id.0),
            V::Text(r#"{"state":"active","expires_at":"2099-01-01T00:00:00Z"}"#),
        ],
    )
    .await;
    let live = |table: &'static str| {
        let raw = Raw(rig);
        let run = run.id;
        async move {
            raw.int(
                &format!("SELECT count(*) FROM {table} WHERE run_id = $1 AND expires_at > $2"),
                &[V::Uuid(run.0), V::Ts(Utc::now() + Duration::hours(1))],
            )
            .await
        }
    };
    assert_eq!((live("artifacts").await, live("checkpoints").await), (2, 1));

    // running revokes nothing
    env.repos
        .runs
        .set_status(run.id, RunStatus::Running, None)
        .await
        .unwrap();
    assert_eq!((live("artifacts").await, live("checkpoints").await), (2, 1));
    // a refused transition revokes nothing either
    assert!(env
        .repos
        .runs
        .set_status(run.id, RunStatus::Completed, None)
        .await
        .is_err());
    assert_eq!((live("artifacts").await, live("checkpoints").await), (2, 1));

    env.repos
        .runs
        .set_status(run.id, RunStatus::Failed, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    assert_eq!(
        (live("artifacts").await, live("checkpoints").await),
        (1, 0),
        "only the credential-bearing artifact and the checkpoint expire"
    );
    let binding = raw
        .strings(
            "SELECT binding::text FROM session_bindings WHERE session_id = $1",
            &[V::Uuid(session.0)],
        )
        .await;
    let binding = binding[0].clone().unwrap();
    assert!(binding.contains("retired"), "{binding}");
    assert!(!binding.contains("2099"), "{binding}");
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::field_reassign_with_default)] // BufferLimits is non-exhaustive outside its crate.
async fn zdr_rows_never_hold_content(rig: &Rig) {
    let now = Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap();
    let clock = Arc::new(crawlx_core::time::ManualClock::new(now));
    let buffer = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
    let env = env_with(rig, buffer.clone()).await;
    let run = env.zdr_run().await;
    let slots = sessions(run.id, 1, 1);
    env.repos.runs.create_sessions(&slots).await.unwrap();
    let session = slots[0].id;
    let marker = "zdr-canary-confidential";
    let raw = Raw(rig);

    // states: URL, masks and artifacts stay out of the row
    let cluster = StateClusterId::new();
    let mut state = new_state(session, cluster, true, 1, epoch(1, 1, 0));
    state.url = canonical_url("https://example.test/zdr-canary-confidential?token=zdr-canary-confidential");
    state.observed_at = now;
    state.artifacts.push((
        marker.to_owned(),
        ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("test/artifact", marker.as_bytes()),
        },
    ));
    state
        .masks
        .masked_node_keys
        .push(Digest::of("test/mask", marker.as_bytes()));
    state
        .masks
        .reasons
        .push(crawlx_core::state::MaskReason::Configured);
    env.repos.states.put_state(&state).await.unwrap();
    assert_eq!(env.repos.states.list_states(run.id).await.unwrap()[0], state);
    let mut duplicate = state.clone();
    duplicate.url = canonical_url("https://example.test/not-the-original");
    env.repos.states.put_state(&duplicate).await.unwrap();
    assert_eq!(env.repos.states.list_states(run.id).await.unwrap()[0], state);

    // ledger contexts and edges
    let mut p = proposal("anonymous", cluster, 1);
    p.key.principal.0 = marker.to_owned();
    p.key.route_template.0 = format!("/{marker}");
    p.key.input_class.0 = marker.to_owned();
    let row = LedgerRow {
        key: p.key.clone(),
        trusted_exercised: 1,
        diagnostic_exercised: 0,
        failures: 0,
        first_seen: now,
        last_exercised: Some(now),
    };
    env.repos.ledger.upsert(run.id, &row).await.unwrap();
    assert_eq!(env.repos.ledger.list(run.id).await.unwrap()[0].key, p.key);
    let edge = EdgeRecord {
        id: crawlx_core::EdgeId::new(),
        run: run.id,
        source: p.key.id(),
        context_cluster: None,
        target: p.key.element,
        support: 1,
        weak_support: 0,
        failures: 0,
        latency_ms_ewma: 1.0,
        risk: 0.0,
        last_observed_at: now,
        last_verified_build: Some(marker.to_owned()),
    };
    env.repos.edges.upsert(&edge).await.unwrap();
    assert_eq!(env.repos.edges.list(run.id).await.unwrap()[0], edge);

    // safety decisions: the evidence is a digest
    let v = verdict(SafetyDecision::Deny);
    env.repos
        .safety
        .record(run.id, session, &v, &format!("denied {marker}"))
        .await
        .unwrap();

    // events: kinds that are not known are hashed, payloads reduced to a digest
    let payload =
        serde_json::json!({"url": state.url.url, "headers": {"authorization": marker}, "content": marker});
    env.repos
        .events
        .append(run.id, "navigation", payload.clone())
        .await
        .unwrap();
    env.repos
        .events
        .append(
            run.id,
            "page",
            serde_json::json!({"pageId": 0, "content": marker}),
        )
        .await
        .unwrap();
    env.repos
        .events
        .append(run.id, marker, serde_json::json!({"content": marker}))
        .await
        .unwrap();
    let metadata = env
        .repos
        .events
        .list_metadata_after(run.id, 0, 100)
        .await
        .unwrap();
    assert!(metadata
        .iter()
        .any(|event| event.kind == "page" && event.payload["pageId"] == 0));
    assert!(!serde_json::to_string(&metadata).unwrap().contains(marker));
    let events = env.repos.events.list_after(run.id, 0, 100).await.unwrap();
    assert!(events
        .iter()
        .any(|event| event.kind == "navigation" && event.payload == payload));

    // model decisions: provider, model and output are digests
    let model = model_decision(run.id, session, marker);
    env.repos.models.record(&model).await.unwrap();
    let mut replacement = model.clone();
    replacement.output = serde_json::json!({"replacement": "must not replace the original"});
    env.repos.models.record(&replacement).await.unwrap();
    assert_eq!(env.repos.models.list(run.id).await.unwrap(), vec![model]);

    // pages: no URL, title, content type, links or document metadata
    let frontier = raw
        .frontier(
            env.tenant,
            run.id,
            "https://example.test/zdr-canary-confidential",
            true,
        )
        .await;
    let mut page = page_record(
        run.id,
        frontier,
        "https://example.test/zdr-canary-confidential",
        now,
    );
    page.title = Some(marker.to_owned());
    page.content_type = Some(marker.to_owned());
    page.links = vec![format!("https://example.test/{marker}")];
    page.metadata = serde_json::json!({"description": marker});
    page.markdown = None;
    env.repos.pages.put(&page).await.unwrap();
    let billing = env.repos.pages.billing(run.id).await.unwrap().unwrap();
    assert_eq!(billing.pages, 1);

    for table in [
        "states",
        "action_contexts",
        "enablement_edges",
        "safety_decisions",
        "model_decisions",
        "crawl_events",
        "pages",
    ] {
        let durable = raw.dump(table, run.id).await;
        assert!(!durable.is_empty(), "{table} is empty");
        assert!(
            !durable.contains(marker),
            "{table} persisted confidential content"
        );
        assert!(
            !durable.contains("example.test"),
            "{table} persisted a URL: {durable}"
        );
    }
    let durable = raw
        .strings(
            "SELECT evidence::text FROM safety_decisions WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    let evidence: serde_json::Value = serde_json::from_str(durable[0].as_deref().unwrap()).unwrap();
    assert_eq!(evidence.as_object().unwrap().len(), 1);
    assert_eq!(evidence["digest"].as_str().unwrap().len(), 64);
    let states = raw
        .strings(
            "SELECT observed_url::text FROM states WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    assert_eq!(states, vec![None]);
    let masks = raw
        .strings(
            "SELECT masks::text FROM states WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(masks[0].as_deref().unwrap()).unwrap(),
        serde_json::json!([])
    );
    let urls = raw
        .strings(
            "SELECT canonical_url::text FROM pages WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    assert_eq!(urls, vec![None]);
    let edges = raw
        .strings(
            "SELECT last_verified_build::text FROM enablement_edges WHERE run_id = $1",
            &[V::Uuid(run.id.0)],
        )
        .await;
    assert_eq!(edges, vec![None]);

    // after the delivery window, everything operational fails closed; metadata stays readable
    clock.advance_ms(3_600_001);
    buffer
        .sweep(now + Duration::hours(1) + Duration::seconds(1))
        .await
        .unwrap();
    assert!(matches!(
        env.repos.states.list_states(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        env.repos.ledger.list(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        env.repos.events.list_after(run.id, 0, 100).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        env.repos.models.list(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        env.repos.edges.list(run.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let summary = env.repos.ledger.summary(run.id).await.unwrap();
    assert_eq!((summary.discovered, summary.exercised_trusted), (1, 1));
    let metadata = env
        .repos
        .events
        .list_metadata_after(run.id, 0, 100)
        .await
        .unwrap();
    assert!(metadata
        .iter()
        .any(|event| event.kind == "page" && event.payload["pageId"] == 0));
    assert!(!serde_json::to_string(&metadata).unwrap().contains(marker));
    for table in [
        "states",
        "action_contexts",
        "model_decisions",
        "crawl_events",
        "pages",
    ] {
        assert!(
            !raw.dump(table, run.id).await.contains(marker),
            "{table} leaked after expiry"
        );
    }
}

/// The clock a lease or revocation reads inside a transaction is `clock_timestamp()` or
/// `SYSDATE(6)`: MariaDB reports the latter as `TIMESTAMP`, which a `DATETIME` decoder refused,
/// failing every flow that read it (and leaving its transaction open behind the failure).
#[allow(
    clippy::disallowed_methods,
    reason = "a probe of the clock, not a request-surface statement"
)]
async fn the_database_clock_decodes_on_every_engine(rig: &Rig) {
    use crawlx_storage::backend::{Dialect, MariaBackend, MariaDbDialect};
    use crawlx_storage::sql::{SqlRow, Stmt};
    rig.migrate().await;
    // PostgreSQL and SQLite clocks decode as the stored instants do (the lease and revocation
    // cases cover them); the `TIMESTAMP` typed clock is MariaDB's
    let Some(pool) = rig.database().mariadb_pool() else {
        return;
    };
    let sql = format!("SELECT {} AS now", MariaDbDialect::clock_timestamp());
    let read = Stmt::<MariaBackend>::dynamic(&sql)
        .fetch_one_pool(pool)
        .await
        .unwrap()
        .ts("now")
        .unwrap();
    let skew = (Utc::now() - read).num_seconds().abs();
    assert!(
        skew < 300,
        "the database clock is {read}, {skew}s from this machine's"
    );
}

/// A flow stamps a row with the clock it reads inside its transaction and is checked against
/// `Database::db_now` read just before: on SQLite both are the process clock at microsecond
/// resolution, never SQL `'now'` (milliseconds), which could fall before the earlier reading.
async fn the_transaction_clock_never_precedes_an_earlier_database_reading(rig: &Rig) {
    use crawlx_storage::backend::SqliteBackend;
    rig.migrate().await;
    let database = rig.database();
    let Some(pool) = database.sqlite_pool() else {
        return;
    };
    let mut conn = pool.acquire().await.unwrap();
    for _ in 0..2_000 {
        let before = database.db_now().await.unwrap();
        let inside = crawlx_storage::sql::db_clock::<SqliteBackend>(&mut conn)
            .await
            .unwrap();
        assert!(inside >= before, "transaction clock {inside} precedes {before}");
    }
}

/// Waiting for a lock must end: a metadata lock (a DDL or `DROP DATABASE` behind an open
/// transaction) waits a year on a stock MariaDB server and a row lock waits for the server's
/// timeout, so every session sets a bound. Checked on the settings, which needs no timeout.
async fn no_lock_wait_is_unbounded(rig: &Rig) {
    use sqlx::Row as _;
    rig.migrate().await;
    let Some(pool) = rig.database().mariadb_pool() else {
        return;
    };
    let row =
        sqlx::query("SELECT CAST(@@lock_wait_timeout AS SIGNED), CAST(@@innodb_lock_wait_timeout AS SIGNED)")
            .fetch_one(pool)
            .await
            .unwrap();
    for (index, name) in ["lock_wait_timeout", "innodb_lock_wait_timeout"]
        .into_iter()
        .enumerate()
    {
        let seconds: i64 = row.try_get(index).unwrap();
        assert!((1..=120).contains(&seconds), "{name} is {seconds}s");
    }
}
