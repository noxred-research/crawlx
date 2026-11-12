//! Conformance cases (measured report history), plus the per-engine setup helpers the
//! binding and URL graph families share: raw statements in `$n` notation, tenant creation and
//! repository dispatch with a volatile delivery buffer attached.

use crate::rig::Rig;
use crawlx_core::config::RetentionMode;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::dataset::DeliveryOutboxRepo;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo};
use crawlx_core::repo::{CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::report_history::{
    report_route_key, AlertCodeV1, AlertContextV1, AlertSeverityV1, DnsOutcomeV1, ErrorSnapshotV1,
    PipelineStageV1, PipelineStateV1, ProcessorIdentityV1, ProcessorStageV1, ReportDataV1, ReportFactV1,
    ReportHistoryRepo, ReportKindV1, ReportQueryV1, StageOutcomeV1,
};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::{StoreError, TenantId, Timestamp, WorkerId};
use crawlx_storage::sql::Built;
use crawlx_storage::testkit::{self, Engine};
use crawlx_storage::BackendKind;
use uuid::Uuid;

conformance! { all:
    measured_history_contract,
    query_filters_agree_with_the_specification,
    route_counters_equal_the_committed_frontier_rows_of_each_route,
    direct_facts_are_stamped_with_the_route_of_their_request,
}

conformance! { databases:
    zdr_facts_are_never_durable,
    expired_facts_are_purged_in_bounded_batches,
    pipeline_completion_requires_every_fenced_delivery_ack,
    retained_page_captures_carry_the_source_run_expiry,
    route_counters_and_failure_snapshots_survive_a_restart_and_expire_with_the_run,
}

/// A fresh buffer for volatile operational values of ZDR runs.
pub(crate) fn zdr_buffer() -> std::sync::Arc<crawlx_storage::DeliveryBuffer> {
    std::sync::Arc::new(crawlx_storage::DeliveryBuffer::new(
        std::sync::Arc::new(crawlx_core::SystemClock),
        crawlx_storage::BufferLimits::default(),
    ))
}

/// Like `on_repo!`, with a volatile delivery buffer attached to every database store so ZDR
/// runs can be created and written.
macro_rules! on_zdr_repo {
    ($rig:expr, |$repo:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Memory => {
                let $repo = $rig.store().as_ref();
                $body
            }
            _ => crate::data::reports::on_zdr_db!($rig, |$repo| $body),
        }
    }};
}
pub(crate) use on_zdr_repo;

/// The database engines of the suite only (no in-memory arm), with a volatile delivery buffer.
macro_rules! on_zdr_db {
    ($rig:expr, |$repo:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Sqlite => {
                let store = $rig
                    .database()
                    .sqlite_store()
                    .expect("a sqlite rig has a store")
                    .clone()
                    .with_delivery_buffer(crate::data::reports::zdr_buffer());
                let $repo = &store;
                $body
            }
            Engine::MariaDb => {
                let store = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store")
                    .clone()
                    .with_delivery_buffer(crate::data::reports::zdr_buffer());
                let $repo = &store;
                $body
            }
            Engine::Postgres => {
                let store = $rig
                    .database()
                    .postgres()
                    .expect("a postgres rig has a store")
                    .clone()
                    .with_delivery_buffer(crate::data::reports::zdr_buffer());
                let $repo = &store;
                $body
            }
            _ => panic!("this case runs on the database engines only"),
        }
    }};
}
pub(crate) use on_zdr_db;

/// Migrate the rig and register a fresh tenant (the in-memory store needs neither).
pub(crate) async fn tenant_of(rig: &Rig) -> TenantId {
    rig.migrate().await;
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

/// Open a distinct pool on the same database and namespace, preserving no process-local cache.
pub(crate) async fn reopen(rig: &Rig) -> crawlx_storage::Database {
    let database = rig.database();
    let url = match rig.engine() {
        Engine::Sqlite => {
            let directory = rig.directory().expect("a sqlite file");
            format!("sqlite://{}", directory.join("crawlx.db").display())
        }
        Engine::MariaDb => {
            let mut url = url::Url::parse(&std::env::var("CRAWLX_TEST_MARIADB_URL").unwrap()).unwrap();
            let target = url::Url::parse(database.target()).unwrap();
            url.set_path(target.path());
            url.to_string()
        }
        Engine::Postgres => std::env::var("CRAWLX_TEST_DATABASE_URL").unwrap(),
        _ => panic!("only database rigs can reopen"),
    };
    crawlx_storage::Database::open(&url, database.config().clone())
        .await
        .unwrap()
}

/// Dispatch over a reopened database, rather than its original rig.
macro_rules! on_database {
    ($database:expr, |$repo:ident| $body:expr) => {{
        match $database.kind() {
            crawlx_storage::BackendKind::Sqlite => {
                let $repo = $database.sqlite_store().expect("a sqlite store");
                $body
            }
            crawlx_storage::BackendKind::MariaDb => {
                let $repo = $database.mariadb_store().expect("a mariadb store");
                $body
            }
            _ => {
                let $repo = $database.postgres().expect("a postgres store");
                $body
            }
        }
    }};
}
pub(crate) use on_database;

/// One value of a raw statement.
pub(crate) enum Bind<'a> {
    Uuid(Uuid),
    I64(i64),
    Ts(Timestamp),
    Text(&'a str),
    Bytes(&'a [u8]),
}

macro_rules! bind_each {
    ($query:expr, $binds:expr, $ts:expr) => {{
        let mut query = $query;
        for bind in $binds {
            query = match bind {
                Bind::Uuid(value) => query.bind(*value),
                Bind::I64(value) => query.bind(*value),
                Bind::Ts(value) => query.bind($ts(*value)),
                Bind::Text(value) => query.bind(*value),
                Bind::Bytes(value) => query.bind(*value),
            };
        }
        query
    }};
}

/// The statement text of the rig's engine for a template in `$n` notation. Raw statements use
/// each placeholder once and in order, so the text binds the same way on every engine.
fn raw_text(rig: &Rig, template: &str) -> String {
    let kind: BackendKind = rig.kind().expect("a database rig");
    Built::expand(kind, template).text().to_owned()
}

/// Run one statement on the rig's database; the rows affected.
pub(crate) async fn exec(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> u64 {
    let text = raw_text(rig, template);
    let database = rig.database();
    match rig.kind().expect("a database rig") {
        BackendKind::Sqlite => bind_each!(sqlx::query(sqlx::AssertSqlSafe(text)), binds, |ts: Timestamp| ts
            .timestamp_micros())
        .execute(database.sqlite_pool().expect("sqlite pool"))
        .await
        .unwrap()
        .rows_affected(),
        BackendKind::MariaDb => bind_each!(sqlx::query(sqlx::AssertSqlSafe(text)), binds, |ts: Timestamp| ts
            .naive_utc())
        .execute(database.mariadb_pool().expect("mariadb pool"))
        .await
        .unwrap()
        .rows_affected(),
        _ => bind_each!(sqlx::query(sqlx::AssertSqlSafe(text)), binds, |ts: Timestamp| ts)
            .execute(database.postgres().expect("postgres handle").pool())
            .await
            .unwrap()
            .rows_affected(),
    }
}

/// The first column of the first row as an integer (a count or a generated key).
pub(crate) async fn scalar_i64(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> i64 {
    let text = raw_text(rig, template);
    let database = rig.database();
    match rig.kind().expect("a database rig") {
        BackendKind::Sqlite => bind_each!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.timestamp_micros()
        )
        .fetch_one(database.sqlite_pool().expect("sqlite pool"))
        .await
        .unwrap(),
        BackendKind::MariaDb => bind_each!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.naive_utc()
        )
        .fetch_one(database.mariadb_pool().expect("mariadb pool"))
        .await
        .unwrap(),
        _ => bind_each!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts
        )
        .fetch_one(database.postgres().expect("postgres handle").pool())
        .await
        .unwrap(),
    }
}

/// The first column of the first row as text.
pub(crate) async fn scalar_text(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> String {
    let text = raw_text(rig, template);
    let database = rig.database();
    match rig.kind().expect("a database rig") {
        BackendKind::Sqlite => bind_each!(
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.timestamp_micros()
        )
        .fetch_one(database.sqlite_pool().expect("sqlite pool"))
        .await
        .unwrap(),
        BackendKind::MariaDb => bind_each!(
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.naive_utc()
        )
        .fetch_one(database.mariadb_pool().expect("mariadb pool"))
        .await
        .unwrap(),
        _ => bind_each!(
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts
        )
        .fetch_one(database.postgres().expect("postgres handle").pool())
        .await
        .unwrap(),
    }
}

/// The first column of the first row as bytes.
pub(crate) async fn scalar_bytes(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> Vec<u8> {
    let text = raw_text(rig, template);
    let database = rig.database();
    match rig.kind().expect("a database rig") {
        BackendKind::Sqlite => bind_each!(
            sqlx::query_scalar::<_, Vec<u8>>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.timestamp_micros()
        )
        .fetch_one(database.sqlite_pool().expect("sqlite pool"))
        .await
        .unwrap(),
        BackendKind::MariaDb => bind_each!(
            sqlx::query_scalar::<_, Vec<u8>>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts.naive_utc()
        )
        .fetch_one(database.mariadb_pool().expect("mariadb pool"))
        .await
        .unwrap(),
        _ => bind_each!(
            sqlx::query_scalar::<_, Vec<u8>>(sqlx::AssertSqlSafe(text)),
            binds,
            |ts: Timestamp| ts
        )
        .fetch_one(database.postgres().expect("postgres handle").pool())
        .await
        .unwrap(),
    }
}

async fn fixture<R: RunRepo + FrontierRepo + RequestCommitRepo>(
    repo: &R,
    tenant: TenantId,
    zdr: bool,
) -> (CrawlRun, CustodyLease) {
    let mut config = testkit::create_crawl("https://history.example.test/secret?token=private", &[], 1);
    config.retention.mode = if zdr {
        RetentionMode::Zdr
    } else {
        RetentionMode::Standard
    };
    config.retention.days = if zdr { 0 } else { 1 };
    let run = testkit::crawl_run(tenant, config);
    repo.create(&run, None).await.unwrap();
    let batch = RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/report-batch", run.id.0.as_bytes()),
        vec![RequestEnvelopeV1::get(
            testkit::canonical_url("https://history.example.test/secret?token=private"),
            0,
            None,
        )],
    );
    repo.append_batch(batch).await.unwrap();
    let worker = WorkerId::new();
    let rows = repo.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    let (entry, fence) = &rows[0];
    (
        run.clone(),
        CustodyLease::for_url(tenant, run.id, entry.id, worker, *fence),
    )
}

fn request_of(lease: &CustodyLease) -> Option<i64> {
    match lease.source {
        CustodySource::Url(id) => Some(id),
        _ => None,
    }
}

async fn measured_history_contract(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| contract(repo, tenant).await);
}

async fn contract<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant, false).await;
    let mut unknown = ReportFactV1::new(
        &lease,
        Digest::of("test/report-fact", b"unknown"),
        run.created_at,
        ReportDataV1::Wire {
            received_bytes: None,
            sent_bytes: None,
            duration_us: None,
        },
    );
    unknown.request_id = request_of(&lease);
    let first = repo.append_fact(&lease, &unknown).await.unwrap();
    assert_eq!(repo.append_fact(&lease, &unknown).await.unwrap(), first);
    let mut changed = unknown.clone();
    changed.data = ReportDataV1::Wire {
        received_bytes: Some(0),
        sent_bytes: None,
        duration_us: Some(0),
    };
    assert!(matches!(
        repo.append_fact(&lease, &changed).await,
        Err(StoreError::Conflict(_))
    ));
    for value in [9_u64, 1, 5] {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-fact", &value.to_le_bytes()),
            run.created_at,
            ReportDataV1::Wire {
                received_bytes: Some(value * 10),
                sent_bytes: None,
                duration_us: Some(value),
            },
        );
        fact.request_id = unknown.request_id;
        repo.append_fact(&lease, &fact).await.unwrap();
    }
    let dns = ReportFactV1::new(
        &lease,
        Digest::of("test/report-fact", b"dns"),
        run.created_at,
        ReportDataV1::Dns {
            outcome: DnsOutcomeV1::Resolved,
            duration_us: 13,
            recheck_at: Some(run.created_at + chrono::Duration::minutes(5)),
        },
    );
    repo.append_fact(&lease, &dns).await.unwrap();
    let mut query = ReportQueryV1::default();
    query.kind = Some(ReportKindV1::Wire);
    query.min_duration_us = Some(1);
    query.limit = 2;
    let page = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
    assert_eq!(page.entries.len(), 2);
    assert!(page.next.is_some());
    assert!(page
        .entries
        .iter()
        .all(|entry| entry.fact.data.duration_us().is_some()));
    query.after = page.next.unwrap();
    let tail = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
    assert_eq!(tail.entries.len(), 1);
    assert_eq!(tail.next, None);
    query.after = 0;
    query.min_wire_bytes = Some(60);
    assert_eq!(
        repo.query_facts(tenant, Some(run.id), &query)
            .await
            .unwrap()
            .entries
            .len(),
        1
    );
    let foreign = TenantId::new();
    assert!(repo.query_facts(foreign, Some(run.id), &query).await.is_err());
    assert!(repo
        .query_facts(foreign, None, &query)
        .await
        .unwrap()
        .entries
        .is_empty());
    let (second, second_lease) = fixture(repo, tenant, false).await;
    let fact = ReportFactV1::new(
        &second_lease,
        Digest::of("test/report-fact", b"second"),
        second.created_at,
        ReportDataV1::Loss { dropped: 3 },
    );
    repo.append_fact(&second_lease, &fact).await.unwrap();
    let timeline = repo
        .query_facts(tenant, None, &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(timeline.entries.iter().any(|entry| entry.fact.run == run.id));
    assert!(timeline.entries.iter().any(|entry| entry.fact.run == second.id));
    let serialized = serde_json::to_string(&timeline).unwrap();
    for secret in ["history.example.test", "secret?token", "private"] {
        assert!(!serialized.contains(secret));
    }
    let mut wrong = lease.clone();
    wrong.fence += 1;
    let mut stale = unknown.clone();
    stale.id = Digest::of("test/report-fact", b"stale");
    stale.fence = wrong.fence;
    assert!(matches!(
        repo.append_fact(&wrong, &stale).await,
        Err(StoreError::LeaseLost)
    ));
    let mut invalid = unknown;
    invalid.id = Digest::of("test/report-fact", b"invalid");
    invalid.at = crawlx_core::Timestamp::from_timestamp(-1, 0).unwrap();
    assert!(repo.append_fact(&lease, &invalid).await.is_err());
}

async fn query_filters_agree_with_the_specification(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| filters(repo, tenant).await);
}

/// Every filter, alone and combined, returns exactly the facts the specification
/// (`ReportQueryV1::matches`) selects, in sequence order, across page boundaries.
async fn filters<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant, false).await;
    let base = Timestamp::from_timestamp(run.created_at.timestamp(), 0).unwrap();
    let at = |seconds: i64| base + chrono::Duration::seconds(seconds);
    let url_a = Digest::of("test/url-key", b"a");
    let url_b = Digest::of("test/url-key", b"b");
    let host_1 = Digest::of("test/host-key", b"1");
    let host_2 = Digest::of("test/host-key", b"2");
    let wire = |received: Option<u64>, duration: Option<u64>| ReportDataV1::Wire {
        received_bytes: received,
        sent_bytes: None,
        duration_us: duration,
    };
    let shapes = [
        (wire(Some(10), Some(1)), Some(url_a), Some(host_1), 0),
        (wire(Some(20), Some(5)), Some(url_b), Some(host_1), 10),
        (
            ReportDataV1::Dns {
                outcome: DnsOutcomeV1::Resolved,
                duration_us: 7,
                recheck_at: None,
            },
            None,
            Some(host_2),
            20,
        ),
        (
            ReportDataV1::Alert {
                severity: AlertSeverityV1::Warning,
                code: AlertCodeV1::ProcessorFailure,
                context: AlertContextV1::Processing,
            },
            Some(url_a),
            Some(host_2),
            30,
        ),
        (ReportDataV1::Loss { dropped: 2 }, None, None, 40),
        (wire(None, Some(9)), Some(url_b), Some(host_1), 50),
        (wire(Some(30), None), Some(url_a), Some(host_1), 60),
    ];
    let mut appended = Vec::new();
    for (ordinal, (data, url_key, host_key, seconds)) in shapes.into_iter().enumerate() {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-filter", &[u8::try_from(ordinal).unwrap()]),
            at(seconds),
            data,
        );
        fact.url_key = url_key;
        fact.host_key = host_key;
        fact.request_id = request_of(&lease);
        let sequence = repo.append_fact(&lease, &fact).await.unwrap();
        appended.push((sequence, fact));
    }
    let queries = {
        let mut list = Vec::new();
        let mut push = |change: &dyn Fn(&mut ReportQueryV1)| {
            let mut query = ReportQueryV1::default();
            change(&mut query);
            list.push(query);
        };
        push(&|_| {});
        push(&|q| q.kind = Some(ReportKindV1::Wire));
        push(&|q| q.kind = Some(ReportKindV1::Dns));
        push(&|q| q.kind = Some(ReportKindV1::Pipeline));
        push(&|q| q.url_key = Some(url_a));
        push(&|q| q.host_key = Some(host_1));
        push(&|q| q.since = Some(at(10)));
        push(&|q| q.until = Some(at(30)));
        push(&|q| {
            q.since = Some(at(10));
            q.until = Some(at(50));
        });
        push(&|q| q.min_duration_us = Some(5));
        push(&|q| q.max_duration_us = Some(7));
        push(&|q| {
            q.min_duration_us = Some(2);
            q.max_duration_us = Some(8);
        });
        push(&|q| q.min_wire_bytes = Some(15));
        push(&|q| q.max_wire_bytes = Some(15));
        push(&|q| {
            q.kind = Some(ReportKindV1::Wire);
            q.host_key = Some(host_1);
            q.min_duration_us = Some(2);
            q.since = Some(at(5));
        });
        push(&|q| {
            q.url_key = Some(url_b);
            q.host_key = Some(host_2);
        });
        list
    };
    for query in queries {
        let expected: Vec<u64> = appended
            .iter()
            .filter(|(_, fact)| query.matches(fact))
            .map(|(sequence, _)| *sequence)
            .collect();
        // one page of everything, then pages of two with the cursor
        let whole = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
        assert_eq!(
            whole.entries.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            expected,
            "{query:?}"
        );
        assert_eq!(whole.next, None);
        let mut paged = Vec::new();
        let mut cursor = query.clone();
        cursor.limit = 2;
        loop {
            let page = repo.query_facts(tenant, Some(run.id), &cursor).await.unwrap();
            assert!(page.entries.len() <= 2);
            paged.extend(page.entries.iter().map(|e| e.sequence));
            match page.next {
                Some(next) => cursor.after = next,
                None => break,
            }
        }
        assert_eq!(paged, expected, "paged {query:?}");
        // the run filter is optional: the tenant-wide timeline agrees
        let timeline = repo.query_facts(tenant, None, &query).await.unwrap();
        assert!(timeline
            .entries
            .iter()
            .filter(|e| e.fact.run == run.id)
            .map(|e| e.sequence)
            .eq(expected.iter().copied()));
    }
}

async fn zdr_facts_are_never_durable(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| zdr(rig, repo, tenant).await);
}

async fn zdr<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    rig: &Rig,
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant, true).await;
    let mut fact = ReportFactV1::new(
        &lease,
        Digest::of("test/report-zdr", b"wire"),
        run.created_at,
        ReportDataV1::Wire {
            received_bytes: Some(5),
            sent_bytes: None,
            duration_us: Some(3),
        },
    );
    fact.request_id = request_of(&lease);
    let sequence = repo.append_fact(&lease, &fact).await.unwrap();
    assert_eq!(repo.append_fact(&lease, &fact).await.unwrap(), sequence);
    let mut pipeline = fact.clone();
    pipeline.id = Digest::of("test/report-zdr", b"pipeline");
    pipeline.data = ReportDataV1::Pipeline {
        stage: PipelineStageV1::Fetch,
        state: PipelineStateV1::Succeeded,
    };
    repo.append_fact(&lease, &pipeline).await.unwrap();
    let run_key = [Bind::Uuid(run.id.0)];
    // Only the opaque receipt and its bounds are durable: no fact body, no pipeline row.
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1",
            &run_key
        )
        .await,
        2
    );
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1 AND fact IS NOT NULL",
            &run_key
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM request_pipeline_history WHERE run_id=$1",
            &run_key
        )
        .await,
        0
    );
    assert!(matches!(
        repo.query_facts(tenant, Some(run.id), &ReportQueryV1::default())
            .await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(repo
        .query_facts(tenant, None, &ReportQueryV1::default())
        .await
        .unwrap()
        .entries
        .is_empty());
}

/// A retained page result stores an immutable capture whose deadline is exactly the source
/// run's; SQLite cannot rewrite the row in a trigger, so the repository must write it there.
async fn retained_page_captures_carry_the_source_run_expiry(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| page_capture(rig, repo, tenant).await);
}

async fn page_capture<R: RunRepo + FrontierRepo + RequestCommitRepo>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (run, lease) = fixture(repo, tenant, false).await;
    let request = request_of(&lease).expect("url fixture");
    let mut commit = crawlx_core::orchestration::RequestCommitV1::terminal(
        run.id,
        request,
        lease.fence,
        1,
        FrontierStatus::Succeeded,
        None,
    );
    commit.page = Some(crawlx_core::repo::PageRecord {
        run: run.id,
        frontier_id: request,
        url: testkit::canonical_url("https://history.example.test/secret?token=private"),
        status: 200,
        content_type: Some("text/html".into()),
        content_digest: Digest::of("test/page", b"retained"),
        title: None,
        markdown: None,
        html: None,
        metadata: serde_json::json!({}),
        links: Vec::new(),
        fetched_at: run.created_at,
        lane: crawlx_core::traffic::TrustLane::Diagnostic,
    });
    repo.commit_fenced(commit).await.unwrap();
    let run_key = [Bind::Uuid(run.id.0), Bind::Uuid(run.id.0)];
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM page_captures WHERE run_id=$1 \
             AND expires_at = (SELECT expires_at FROM crawl_runs WHERE run_id=$2)",
            &run_key
        )
        .await,
        1
    );
}

async fn expired_facts_are_purged_in_bounded_batches(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| purge(rig, repo, tenant).await);
}

macro_rules! purge_all {
    ($repo:expr) => {
        $repo.purge_expired_report_history().await.unwrap()
    };
}

async fn purge<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo + Purge>(
    rig: &Rig,
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant, false).await;
    let (kept, kept_lease) = fixture(repo, tenant, false).await;
    let request = request_of(&lease);
    for (ordinal, data) in [
        ReportDataV1::Loss { dropped: 1 },
        ReportDataV1::Pipeline {
            stage: PipelineStageV1::Fetch,
            state: PipelineStateV1::Succeeded,
        },
        ReportDataV1::Loss { dropped: 2 },
    ]
    .into_iter()
    .enumerate()
    {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-purge", &[u8::try_from(ordinal).unwrap()]),
            run.created_at,
            data,
        );
        fact.request_id = request;
        repo.append_fact(&lease, &fact).await.unwrap();
    }
    let survivor = ReportFactV1::new(
        &kept_lease,
        Digest::of("test/report-purge", b"survivor"),
        kept.created_at,
        ReportDataV1::Loss { dropped: 9 },
    );
    repo.append_fact(&kept_lease, &survivor).await.unwrap();
    // Nothing is due yet.
    assert_eq!(purge_all!(repo), 0);
    let run_key = [Bind::Uuid(run.id.0)];
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM request_pipeline_history WHERE run_id=$1",
            &run_key
        )
        .await,
        1
    );
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let expired = [Bind::Ts(past), Bind::Uuid(run.id.0)];
    exec(
        rig,
        "UPDATE report_history SET expires_at=$1 WHERE run_id=$2",
        &expired,
    )
    .await;
    exec(
        rig,
        "UPDATE request_pipeline_history SET expires_at=$1 WHERE run_id=$2",
        &expired,
    )
    .await;
    // Expired facts are invisible before the sweep and gone after it; other runs stay.
    assert!(repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        repo.query_facts(tenant, Some(kept.id), &ReportQueryV1::default())
            .await
            .unwrap()
            .entries
            .len(),
        1
    );
    assert_eq!(purge_all!(repo), 4, "three facts and one pipeline checkpoint");
    assert_eq!(purge_all!(repo), 0);
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1",
            &run_key
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1",
            &[Bind::Uuid(kept.id.0)]
        )
        .await,
        1
    );
}

/// The retention sweep of report history, an inherent method of each database store.
trait Purge {
    async fn purge_expired_report_history(&self) -> Result<u64, StoreError>;
}

macro_rules! impl_purge {
    ($($store:ty),+) => {$(
        impl Purge for $store {
            async fn purge_expired_report_history(&self) -> Result<u64, StoreError> {
                <$store>::purge_expired_report_history(self).await
            }
        }
    )+};
}
impl_purge!(
    crawlx_storage::Store<crawlx_storage::backend::SqliteBackend>,
    crawlx_storage::Store<crawlx_storage::backend::MariaBackend>,
    crawlx_storage::Pg
);

async fn pipeline_completion_requires_every_fenced_delivery_ack(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| acknowledgements(rig, repo, tenant).await);
}

async fn acknowledgements<R>(rig: &Rig, repo: &R, tenant: TenantId)
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo + DeliveryOutboxRepo,
{
    let (run, lease) = fixture(repo, tenant, false).await;
    let request = request_of(&lease).expect("url fixture");
    for (ordinal, stage, state) in [
        (0_u8, PipelineStageV1::Fetch, PipelineStateV1::Succeeded),
        (1, PipelineStageV1::Parse, PipelineStateV1::Succeeded),
        (2, PipelineStageV1::Index, PipelineStateV1::Pending),
        (3, PipelineStageV1::Completion, PipelineStateV1::Pending),
    ] {
        let mut fact = ReportFactV1::new(
            &lease,
            Digest::of("test/report-pipeline", &[ordinal]),
            run.created_at,
            ReportDataV1::Pipeline { stage, state },
        );
        fact.request_id = Some(request);
        repo.append_fact(&lease, &fact).await.unwrap();
    }
    repo.complete_fenced(request, lease.fence, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let mut ids = Vec::new();
    for name in ["first", "second"] {
        let worker = WorkerId::new();
        let id = scalar_i64(
            rig,
            "INSERT INTO dataset_delivery_outbox(tenant_id,run_id,source_request_id,feed,idempotency_key,payload,state,fence,lease_owner,lease_expires_at,expires_at) VALUES($1,$2,$3,'fixture',$4,'{}','leased',1,$5,$6,$7) RETURNING delivery_id",
            &[
                Bind::Uuid(tenant.0),
                Bind::Uuid(run.id.0),
                Bind::I64(request),
                Bind::Text(name),
                Bind::Uuid(worker.0),
                Bind::Ts(now + chrono::Duration::minutes(10)),
                Bind::Ts(now + chrono::Duration::days(1)),
            ],
        )
        .await;
        ids.push(id);
    }
    repo.acknowledge(run.id, ids[0], 1).await.unwrap();
    let page = repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(!page.entries.iter().any(|entry| matches!(
        entry.fact.data,
        ReportDataV1::Pipeline {
            stage: PipelineStageV1::Completion,
            state: PipelineStateV1::Succeeded
        }
    )));
    assert!(matches!(
        repo.acknowledge(run.id, ids[1], 2).await,
        Err(StoreError::LeaseLost)
    ));
    let count_before = page.entries.len();
    // A fact conflict after the delivery UPDATE must roll back the outbox ACK too.
    let collision_id = Digest::of(
        "crawlx/report-delivery-ack/v1",
        &serde_json::to_vec(&(
            tenant,
            run.id,
            request,
            lease.fence,
            1_u16,
            PipelineStageV1::Index,
        ))
        .unwrap(),
    );
    let mut collision = ReportFactV1::new(
        &lease,
        collision_id,
        run.created_at,
        ReportDataV1::Loss { dropped: 1 },
    );
    collision.request_id = Some(request);
    let receipt = Digest::of("crawlx/report-fact/v1", &serde_json::to_vec(&collision).unwrap());
    let body = serde_json::to_string(&collision).unwrap();
    exec(
        rig,
        "INSERT INTO report_history(tenant_id,run_id,fact_id,receipt,kind,observed_at,fact) VALUES($1,$2,$3,$4,'loss',$5,$6::jsonb)",
        &[
            Bind::Uuid(tenant.0),
            Bind::Uuid(run.id.0),
            Bind::Bytes(collision_id.0.as_slice()),
            Bind::Bytes(receipt.0.as_slice()),
            Bind::Ts(run.created_at),
            Bind::Text(&body),
        ],
    )
    .await;
    assert!(matches!(
        repo.acknowledge(run.id, ids[1], 1).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        scalar_text(
            rig,
            "SELECT state FROM dataset_delivery_outbox WHERE delivery_id=$1",
            &[Bind::I64(ids[1])]
        )
        .await,
        "leased"
    );
    exec(
        rig,
        "DELETE FROM report_history WHERE tenant_id=$1 AND run_id=$2 AND fact_id=$3",
        &[
            Bind::Uuid(tenant.0),
            Bind::Uuid(run.id.0),
            Bind::Bytes(collision_id.0.as_slice()),
        ],
    )
    .await;
    repo.acknowledge(run.id, ids[1], 1).await.unwrap();
    let page = repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert_eq!(page.entries.len(), count_before + 2);
    assert!(page.entries.iter().any(|entry| matches!(
        entry.fact.data,
        ReportDataV1::Pipeline {
            stage: PipelineStageV1::Completion,
            state: PipelineStateV1::Succeeded
        }
    )));
    repo.acknowledge(run.id, ids[1], 1).await.unwrap();
    assert_eq!(
        repo.query_facts(tenant, Some(run.id), &ReportQueryV1::default())
            .await
            .unwrap()
            .entries
            .len(),
        page.entries.len()
    );
}

/// A value no stored fact, served page or metric label may ever contain.
const CANARY: &str = "canary-secret-93c1f0d4";

/// What the routed run committed: request id, route label, final status and the reason code of
/// a failure.
type Committed = Vec<(i64, &'static str, FrontierStatus, Option<&'static str>)>;

/// A run with five requests on two routes, each committed once under its own fence. A failing
/// request records an alert whose snapshot carries a producer that skipped redaction.
async fn routed_run<R: RunRepo + FrontierRepo + RequestCommitRepo>(
    repo: &R,
    tenant: TenantId,
) -> (CrawlRun, Committed) {
    let mut config = testkit::create_crawl("https://routes.example.test/", &[], 1);
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 1;
    let run = testkit::crawl_run(tenant, config);
    repo.create(&run, None).await.unwrap();
    let plan: [(&str, u32, FrontierStatus, Option<&str>); 5] = [
        ("listing", 0, FrontierStatus::Succeeded, None),
        ("listing", 1, FrontierStatus::Succeeded, None),
        ("listing", 2, FrontierStatus::Failed, Some("fetch_failed")),
        ("detail", 0, FrontierStatus::Succeeded, None),
        ("detail", 1, FrontierStatus::Unreachable, Some("dns_failure")),
    ];
    let envelopes = plan
        .iter()
        .map(|(route, n, _, _)| {
            let mut envelope = RequestEnvelopeV1::get(
                testkit::canonical_url(&format!("https://routes.example.test/{route}/{n}")),
                0,
                None,
            );
            envelope.route = (*route).to_owned();
            envelope
        })
        .collect();
    let batch = RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/route-batch", run.id.0.as_bytes()),
        envelopes,
    );
    repo.append_batch(batch).await.unwrap();
    let worker = WorkerId::new();
    let rows = repo.lease_batch_fenced(run.id, worker, 5).await.unwrap();
    assert_eq!(rows.len(), 5);
    let mut committed = Vec::new();
    for (entry, fence) in &rows {
        let path = entry.url.url.path().to_owned();
        let (route, _, status, reason) = plan
            .iter()
            .find(|(route, n, _, _)| path == format!("/{route}/{n}"))
            .copied()
            .unwrap();
        let lease = CustodyLease::for_url(tenant, run.id, entry.id, worker, *fence);
        let fact = |label: &str, data| {
            let mut fact = ReportFactV1::new(
                &lease,
                Digest::of("test/route-fact", format!("{}:{label}", entry.id).as_bytes()),
                run.created_at,
                data,
            );
            fact.request_id = Some(entry.id);
            fact
        };
        let failed = status != FrontierStatus::Succeeded;
        let mut facts = vec![
            fact(
                "fetch",
                ReportDataV1::Pipeline {
                    stage: PipelineStageV1::Fetch,
                    state: if failed {
                        PipelineStateV1::Failed
                    } else {
                        PipelineStateV1::Succeeded
                    },
                },
            ),
            fact(
                "wire",
                ReportDataV1::Wire {
                    received_bytes: Some(10),
                    sent_bytes: None,
                    duration_us: Some(5),
                },
            ),
        ];
        if failed {
            facts.push(fact(
                "stage",
                ReportDataV1::Stage {
                    stage: ProcessorStageV1::Fetch,
                    outcome: StageOutcomeV1::Failed,
                    duration_us: 3,
                    processor: ProcessorIdentityV1::NativeHttp,
                    processor_version: 1,
                },
            ));
            let mut alert = fact(
                "alert",
                ReportDataV1::Alert {
                    severity: AlertSeverityV1::Error,
                    code: AlertCodeV1::ProcessorFailure,
                    context: AlertContextV1::Processing,
                },
            );
            let mut snapshot =
                ErrorSnapshotV1::new(Some(ProcessorStageV1::Fetch), "worker_code", Some(502), None).unwrap();
            // a producer that never redacted: the repository must still keep the secret out
            snapshot.detail = Some(format!(
                "GET https://tenant.example.test/p?token={CANARY} failed; authorization: Bearer {CANARY} password={CANARY}"
            ));
            alert.error = Some(snapshot);
            facts.push(alert);
        }
        let mut commit = crawlx_core::orchestration::RequestCommitV1::terminal(
            run.id,
            entry.id,
            *fence,
            1,
            status,
            reason.map(str::to_owned),
        );
        commit.report_facts = facts;
        repo.commit_fenced(commit).await.unwrap();
        committed.push((entry.id, route, status, reason));
    }
    (run, committed)
}

/// The terminal frontier rows of a run grouped by route key, read through the frontier itself:
/// `(committed rows, succeeded rows, failed or unreachable rows)`.
async fn frontier_counts<R: FrontierRepo>(
    repo: &R,
    run: &CrawlRun,
) -> std::collections::BTreeMap<Digest, (u64, u64, u64)> {
    let mut counts = std::collections::BTreeMap::new();
    for entry in repo.page(run.id, 0, 1000).await.unwrap() {
        let queued = repo.get_request(run.id, entry.id).await.unwrap();
        let row = counts
            .entry(report_route_key(&queued.envelope.route))
            .or_insert((0, 0, 0));
        match queued.entry.status {
            FrontierStatus::Succeeded => {
                row.0 += 1;
                row.1 += 1;
            }
            FrontierStatus::Failed | FrontierStatus::Unreachable => {
                row.0 += 1;
                row.2 += 1;
            }
            _ => {}
        }
    }
    counts
}

fn assert_counters_equal_frontier(
    counters: &[crawlx_core::report_history::RouteCountersV1],
    frontier: &std::collections::BTreeMap<Digest, (u64, u64, u64)>,
) {
    assert_eq!(
        counters.len(),
        frontier.len(),
        "one counter set per route: {counters:?}"
    );
    assert!(
        counters
            .windows(2)
            .all(|pair| pair[0].route_key < pair[1].route_key),
        "ordered by route key"
    );
    for counter in counters {
        let (committed, succeeded, failed) = frontier[&counter.route_key];
        assert_eq!(counter.committed(), committed, "terminal results {counter:?}");
        assert_eq!(
            counter.count("pipeline:fetch:succeeded"),
            succeeded,
            "{counter:?}"
        );
        assert_eq!(counter.count("pipeline:fetch:failed"), failed, "{counter:?}");
        assert_eq!(counter.count("alert:error"), failed, "{counter:?}");
        assert_eq!(counter.count("stage:fetch:failed"), failed, "{counter:?}");
    }
}

async fn route_counters_equal_the_committed_frontier_rows_of_each_route(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| route_counters_case(repo, tenant).await);
}

async fn route_counters_case<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    repo: &R,
    tenant: TenantId,
) {
    let (run, committed) = routed_run(repo, tenant).await;
    let listing = report_route_key("listing");
    let detail = report_route_key("detail");
    let frontier = frontier_counts(repo, &run).await;
    assert_eq!(frontier[&listing], (3, 2, 1));
    assert_eq!(frontier[&detail], (2, 1, 1));
    let counters = repo.route_counters(tenant, run.id).await.unwrap();
    assert_counters_equal_frontier(&counters, &frontier);
    // the counters are not a plan restated: the committed rows are exactly what was committed
    assert_eq!(committed.len(), 5);
    // every fact of the run, including checkpoints storage wrote itself, carries its route
    let all = repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert_eq!(
        all.entries.len(),
        24,
        "5 fetch + 5 wire + 2 stage + 2 alert + 10 skipped checkpoints"
    );
    assert!(all.entries.iter().all(|entry| entry.fact.route_key.is_some()));
    for (route, facts) in [(listing, 14), (detail, 10)] {
        let mut query = ReportQueryV1::default();
        query.route_key = Some(route);
        let page = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
        assert_eq!(page.entries.len(), facts);
        assert!(page
            .entries
            .iter()
            .all(|entry| entry.fact.route_key == Some(route)));
    }
    let mut unknown = ReportQueryV1::default();
    unknown.route_key = Some(report_route_key("no-such-route"));
    assert!(repo
        .query_facts(tenant, Some(run.id), &unknown)
        .await
        .unwrap()
        .entries
        .is_empty());
    // failure snapshots: stage and the committed reason code survive, the secret does not
    let snapshots: Vec<_> = all
        .entries
        .iter()
        .filter_map(|entry| entry.fact.error.as_ref())
        .collect();
    assert_eq!(snapshots.len(), 2);
    let mut codes: Vec<_> = snapshots.iter().map(|snapshot| snapshot.code.as_str()).collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        ["dns_failure", "fetch_failed"],
        "the committed reason is the snapshot code"
    );
    for snapshot in snapshots {
        assert_eq!(snapshot.stage, Some(ProcessorStageV1::Fetch));
        assert_eq!(snapshot.http_status, Some(502));
        let detail = snapshot.detail.as_deref().unwrap();
        assert!(
            detail.contains("[url]") && detail.contains("[REDACTED]"),
            "{detail}"
        );
    }
    let served = serde_json::to_string(&all).unwrap();
    for leaked in [CANARY, "tenant.example.test", "token=", "Bearer"] {
        assert!(!served.contains(leaked), "{leaked} leaked: {served}");
    }
    // another tenant sees nothing of this run
    assert!(repo.route_counters(TenantId::new(), run.id).await.is_err());
}

async fn direct_facts_are_stamped_with_the_route_of_their_request(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| stamped_case(repo, tenant).await);
}

async fn stamped_case<R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo>(
    repo: &R,
    tenant: TenantId,
) {
    let (run, lease) = fixture(repo, tenant, false).await;
    let request = request_of(&lease);
    let mut plain = ReportFactV1::new(
        &lease,
        Digest::of("test/route-direct", b"plain"),
        run.created_at,
        ReportDataV1::Loss { dropped: 1 },
    );
    plain.request_id = request;
    let sequence = repo.append_fact(&lease, &plain).await.unwrap();
    assert_eq!(
        repo.append_fact(&lease, &plain).await.unwrap(),
        sequence,
        "a retry stays idempotent"
    );
    let mut query = ReportQueryV1::default();
    query.route_key = Some(report_route_key("default"));
    let routed = repo.query_facts(tenant, Some(run.id), &query).await.unwrap();
    assert_eq!(
        routed.entries.len(),
        1,
        "the repository stamped the request's own route"
    );
    assert_eq!(routed.entries[0].sequence, sequence);
    // a producer cannot file a fact under another request's route
    let mut forged = plain.clone();
    forged.id = Digest::of("test/route-direct", b"forged");
    forged.route_key = Some(report_route_key("somewhere-else"));
    assert!(matches!(
        repo.append_fact(&lease, &forged).await,
        Err(StoreError::Conflict(_))
    ));
    // a credential-shaped code is refused when built and cleaned when a producer smuggles it in
    assert!(ErrorSnapshotV1::new(None, "sk-abcdefghijkl", None, None).is_err());
    let mut alert = ReportFactV1::new(
        &lease,
        Digest::of("test/route-direct", b"alert"),
        run.created_at,
        ReportDataV1::Alert {
            severity: AlertSeverityV1::Error,
            code: AlertCodeV1::ProcessorFailure,
            context: AlertContextV1::Processing,
        },
    );
    alert.request_id = request;
    let mut snapshot = ErrorSnapshotV1::new(None, "ok_code", None, None).unwrap();
    snapshot.code = "sk-abcdefghijkl".to_owned();
    alert.error = Some(snapshot);
    repo.append_fact(&lease, &alert).await.unwrap();
    let page = repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    let stored = page
        .entries
        .iter()
        .find_map(|entry| entry.fact.error.as_ref())
        .expect("the alert was stored");
    assert_eq!(stored.code, "redacted");
}

async fn route_counters_and_failure_snapshots_survive_a_restart_and_expire_with_the_run(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| restart_case(rig, repo, tenant).await);
}

async fn restart_case<R>(rig: &Rig, repo: &R, tenant: TenantId)
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + ReportHistoryRepo + Purge,
{
    let (run, _) = routed_run(repo, tenant).await;
    let before = repo.route_counters(tenant, run.id).await.unwrap();
    assert_eq!(before.len(), 2);
    // a restarted worker opens its own pool: counters come from committed rows, not memory
    let database = reopen(rig).await;
    let (after, frontier) = on_database!(database, |fresh| {
        (
            fresh.route_counters(tenant, run.id).await.unwrap(),
            frontier_counts(fresh, &run).await,
        )
    });
    assert_eq!(after, before);
    assert_counters_equal_frontier(&after, &frontier);
    // the stored bytes hold no secret, in the fact table or the pipeline replay copy
    let like = format!("%{CANARY}%");
    let (fact_text, source_text) = if rig.kind() == Some(BackendKind::Postgres) {
        ("fact::text", "source_fact::text")
    } else {
        ("fact", "source_fact")
    };
    let run_and_pattern = [Bind::Uuid(run.id.0), Bind::Text(&like)];
    for (table, column) in [
        ("report_history", fact_text),
        ("request_pipeline_history", source_text),
    ] {
        let template = format!("SELECT count(*) FROM {table} WHERE run_id=$1 AND {column} LIKE $2");
        assert_eq!(scalar_i64(rig, &template, &run_and_pattern).await, 0, "{table}");
    }
    let run_key = [Bind::Uuid(run.id.0)];
    // positive control: the failure snapshots are stored, with the secrets replaced by the mask
    let masked = [Bind::Uuid(run.id.0), Bind::Text("%[REDACTED]%")];
    let template = format!("SELECT count(*) FROM report_history WHERE run_id=$1 AND {fact_text} LIKE $2");
    assert_eq!(scalar_i64(rig, &template, &masked).await, 2);
    // every fact, snapshot included, expires with the run's retention, at one shared deadline
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1 AND expires_at IS NULL",
            &run_key
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(DISTINCT expires_at) FROM report_history WHERE run_id=$1",
            &run_key
        )
        .await,
        1
    );
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    exec(
        rig,
        "UPDATE report_history SET expires_at=$1 WHERE run_id=$2",
        &[Bind::Ts(past), Bind::Uuid(run.id.0)],
    )
    .await;
    exec(
        rig,
        "UPDATE request_pipeline_history SET expires_at=$1 WHERE run_id=$2",
        &[Bind::Ts(past), Bind::Uuid(run.id.0)],
    )
    .await;
    // expired snapshots are invisible before the sweep, and so are the counters they fed
    let page = repo
        .query_facts(tenant, Some(run.id), &ReportQueryV1::default())
        .await
        .unwrap();
    assert!(page.entries.is_empty());
    assert!(repo.route_counters(tenant, run.id).await.unwrap().is_empty());
    let mut swept = 0;
    loop {
        let batch = purge_all!(repo);
        if batch == 0 {
            break;
        }
        swept += batch;
    }
    assert!(swept >= 24, "{swept}");
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1",
            &run_key
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM report_history WHERE run_id=$1 AND fact IS NOT NULL",
            &run_key
        )
        .await,
        0
    );
}
