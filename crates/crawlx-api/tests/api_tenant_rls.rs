#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real HTTP and PostgreSQL role isolation. No owner role executes request SQL.

use chrono::{Duration, Utc};
use crawlx_api::auth::{generate_key, key_record};
use crawlx_api::pg::PgApiStore;
use crawlx_api::store::ApiStore;
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{EventRepo, FrontierRepo, PageRecord, PageRepo, RunRepo};
use crawlx_core::traffic::TrustLane;
use crawlx_core::{CrawlRunId, SystemClock, TenantId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{
    tenant, AuthorizationRow, FsArtifactStore, IntelRepo, JobKind, JobRecord, JobStatus, Pg, PgApiRepo,
    PgConfig,
};
use reqwest::{Client, Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SNAPSHOT: &str = "11111111-1111-4111-8111-111111111111";

#[tokio::test]
async fn non_owner_http_requests_isolate_tenants_and_clear_transaction_settings() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let schema = format!("api_rls_{}", Uuid::now_v7().simple());
    let role = format!("api_rls_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    let cfg = PgConfig {
        schema: Some(schema.clone()),
        max_connections: 1,
        ..PgConfig::default()
    };
    let owner = Pg::connect(&url, cfg.clone()).await.unwrap();
    owner.migrate().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS NOINHERIT"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA {schema} TO {role}"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    // Grant real DML on tenant tables, but never worker-only operational tables.
    sqlx::query(sqlx::AssertSqlSafe(format!("DO $$ DECLARE t text; BEGIN FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{schema}' AND c.relrowsecurity LOOP EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON {schema}.%I TO {role}', t); END LOOP; END $$")))
        .execute(owner.pool())
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT SELECT ON {schema}.trusted_reachable_states, {schema}.run_errors TO {role}"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "REVOKE UPDATE, DELETE ON {schema}.audit_events FROM {role}"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    let mut api_url = url::Url::parse(&url).unwrap();
    api_url.set_username(&role).unwrap();
    api_url.set_password(Some(&password)).unwrap();
    let restricted = Pg::connect_existing(api_url.as_str(), cfg).await.unwrap();
    assert!(
        owner.with_api_role(&url).await.is_err(),
        "owner must be refused as API role"
    );
    let request_pg = owner.with_api_role(api_url.as_str()).await.unwrap();
    let api = PgApiStore::new(owner.clone());
    let now = Utc::now();
    let mut keys = Vec::new();
    let mut tenants = Vec::new();
    let mut runs = Vec::new();
    let mut jobs = Vec::new();
    let mut records = Vec::new();
    for i in 0..2 {
        let tenant = TenantId::new();
        let key = generate_key();
        api.key_insert(&key_record(&key, tenant, Scope::all_set()).unwrap(), "rls")
            .await
            .unwrap();
        let run = crawl_run(tenant, create_crawl("https://app.example.test/", &[], 1));
        owner.create(&run, None).await.unwrap();
        let page_url = canonical_url(&format!("https://app.example.test/tenant-{i}"));
        let (_, frontier) = owner.discover(run.id, &page_url, 0, None, None).await.unwrap();
        owner
            .put(&PageRecord {
                run: run.id,
                frontier_id: frontier.unwrap(),
                url: page_url,
                status: 200,
                content_type: Some("text/html".to_owned()),
                content_digest: Digest::of("test", &[u8::try_from(i).unwrap()]),
                title: Some(format!("Tenant {i}")),
                markdown: None,
                html: None,
                metadata: json!({}),
                links: Vec::new(),
                fetched_at: now,
                lane: TrustLane::Diagnostic,
            })
            .await
            .unwrap();
        owner
            .append(run.id, "completed", json!({"tenantIndex": i}))
            .await
            .unwrap();
        owner
            .set_status(
                run.id,
                RunStatus::Completed,
                Some(TerminalReason::FrontierExhausted),
            )
            .await
            .unwrap();
        let record = crawlx_policy::testkit::sample_record(tenant, now, &["https://app.example.test"]);
        let body = serde_json::to_value(&record).unwrap();
        owner
            .ensure_authorization_record(&AuthorizationRow {
                tenant,
                record: record.id,
                version: 1,
                body: &body,
                body_digest: &record.body_digest().unwrap().0,
                valid_from: record.valid_from,
                valid_to: record.valid_to,
            })
            .await
            .unwrap();
        let job = JobRecord {
            id: Uuid::now_v7(),
            tenant,
            kind: JobKind::Agent,
            status: JobStatus::Completed,
            request: json!({}),
            result: Some(json!({"tenantIndex": i})),
            error: None,
            stop_reason: None,
            tokens_used: 0,
            credits_used: 0,
            thread_id: None,
            created_at: now,
            updated_at: now,
            finished_at: Some(now),
            expires_at: now + Duration::hours(1),
        };
        owner.job_insert(&job).await.unwrap();
        owner
            .trace_append(job.id, "result", json!({"tenantIndex": i}), now)
            .await
            .unwrap();
        owner
            .snapshot_put(job.id, SNAPSHOT, json!({"tenantIndex": i}), now)
            .await
            .unwrap();
        owner
            .thread_put(tenant, job.id, json!({"tenantIndex": i}), now)
            .await
            .unwrap();
        owner
            .setting_put(tenant, "rls", json!({"tenantIndex": i}), now)
            .await
            .unwrap();
        keys.push(key);
        tenants.push(tenant);
        runs.push(run.id);
        jobs.push(job.id);
        records.push(record.id);
    }

    // A missing middleware scope must not accidentally pass these HTTP tests by
    // falling back to the owner's bypass privileges.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION require_request_role() RETURNS trigger LANGUAGE plpgsql AS $$ \
     BEGIN IF current_user <> '{role}' OR crawlx_current_tenant() IS DISTINCT FROM NEW.tenant_id \
     THEN RAISE EXCEPTION 'request role or transaction-local tenant missing'; END IF; RETURN NEW; END $$"
    )))
    .execute(owner.pool())
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER require_request_role BEFORE INSERT ON crawl_runs FOR EACH ROW EXECUTE FUNCTION require_request_role()")
        .execute(owner.pool()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(SystemClock);
    let artifacts = Arc::new(
        FsArtifactStore::open(dir.path(), Arc::new(request_pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(request_pg.clone())),
    );
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let state = AppState::new(
        Repos::pg(&request_pg, artifacts),
        crawlx_api::admission_policy(&config, clock),
        config,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let stop = CancellationToken::new();
    let drain = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, crawlx_api::router(state))
            .with_graceful_shutdown(drain.cancelled_owned())
            .await
            .unwrap();
    });
    let client = Client::builder()
        .timeout(StdDuration::from_secs(10))
        .build()
        .unwrap();
    // Positive reads are essential: omitting SET LOCAL returns no rows under this role.
    // Alternate tenants on the same one-connection pool to catch stale session settings.
    for _ in 0..2 {
        for i in 0..2 {
            let other = 1 - i;
            for path in [
                format!("/v1/crawls/{}", runs[i]),
                format!("/v1/crawls/{}/pages", runs[i]),
                format!("/v1/crawls/{}/coverage", runs[i]),
                format!("/v1/authorizations/{}", records[i]),
                format!("/compat/firecrawl/v2/agent/{}", jobs[i]),
                format!("/compat/firecrawl/v2/agent/{}/trace", jobs[i]),
                format!("/compat/firecrawl/v2/agent/{}/snapshots/{SNAPSHOT}", jobs[i]),
            ] {
                let response = client
                    .get(format!("{base}{path}"))
                    .bearer_auth(&keys[i])
                    .send()
                    .await
                    .unwrap();
                let status = response.status();
                let body = response.text().await.unwrap();
                assert_eq!(status, StatusCode::OK, "{path}: {body}");
                if path.ends_with("/pages") {
                    let pages: Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(pages["total"], 1);
                    assert!(body.contains(&format!("Tenant {i}")), "{body}");
                }
            }
            for path in [
                format!("/v1/crawls/{}", runs[other]),
                format!("/v1/crawls/{}/pages", runs[other]),
                format!("/v1/crawls/{}/coverage", runs[other]),
                format!("/v1/authorizations/{}", records[other]),
                format!("/compat/firecrawl/v2/agent/{}", jobs[other]),
                format!("/compat/firecrawl/v2/agent/{}/trace", jobs[other]),
                format!("/compat/firecrawl/v2/agent/{}/snapshots/{SNAPSHOT}", jobs[other]),
            ] {
                let response = client
                    .get(format!("{base}{path}"))
                    .bearer_auth(&keys[i])
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{path}: {}",
                    response.text().await.unwrap()
                );
            }
            let response = client
                .get(format!("{base}/v1/crawls/{}/events", runs[i]))
                .bearer_auth(&keys[i])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let events = response.text().await.unwrap();
            assert!(events.contains("event: completed"), "{events}");
            assert!(events.contains(&format!("\"tenantIndex\":{i}")), "{events}");
            for (method, path) in [
                (Method::POST, format!("/v1/crawls/{}:cancel", runs[other])),
                (
                    Method::POST,
                    format!("/v1/authorizations/{}/revoke", records[other]),
                ),
                (
                    Method::DELETE,
                    format!("/compat/firecrawl/v2/agent/{}", jobs[other]),
                ),
            ] {
                let response = client
                    .request(method, format!("{base}{path}"))
                    .bearer_auth(&keys[i])
                    .json(&json!({}))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{path}: {}",
                    response.text().await.unwrap()
                );
            }
        }
    }
    for (i, key) in keys.iter().enumerate() {
        let revoked = client
            .post(format!("{base}/v1/authorizations/{}/revoke", records[i]))
            .bearer_auth(key)
            .json(&json!({"reason": "tenant isolation regression"}))
            .send()
            .await
            .unwrap();
        let status = revoked.status();
        let body = revoked.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        let response = client
            .post(format!("{base}/v1/crawls"))
            .bearer_auth(key)
            .header("Idempotency-Key", "same-key-two-tenants")
            .json(&json!({"seedUrl": "https://app.example.test/"}))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id: CrawlRunId = body["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(owner.get(id).await.unwrap().tenant, tenants[i]);
    }
    // Bypass route-level ownership checks deliberately: RLS must still filter even
    // when a repository receives the other tenant's valid id and explicit tenant.
    tenant::scope(tenants[0], async {
        assert!(restricted.get(runs[1]).await.is_err());
        match PageRepo::list(&restricted, runs[1]).await {
            Ok(rows) => assert!(rows.is_empty(), "foreign pages must not be visible"),
            Err(crawlx_core::StoreError::NotFound { .. }) => {}
            Err(error) => panic!("unexpected page lookup error: {error}"),
        }
        match FrontierRepo::list(&restricted, runs[1]).await {
            Ok(rows) => assert!(rows.is_empty(), "foreign frontier rows must not be visible"),
            Err(crawlx_core::StoreError::NotFound { .. }) => {}
            Err(error) => panic!("unexpected frontier lookup error: {error}"),
        }
        assert!(restricted.job_get(tenants[1], jobs[1]).await.unwrap().is_none());
        assert!(PgApiRepo::new(restricted.clone())
            .authorization_get(tenants[1], records[1])
            .await
            .unwrap()
            .is_none());
        let forged = crawl_run(tenants[1], create_crawl("https://app.example.test/", &[], 1));
        assert!(restricted.create(&forged, None).await.is_err());
        let foreign_job = JobRecord {
            id: Uuid::now_v7(),
            tenant: tenants[1],
            kind: JobKind::Agent,
            status: JobStatus::Completed,
            request: json!({}),
            result: None,
            error: None,
            stop_reason: None,
            tokens_used: 0,
            credits_used: 0,
            thread_id: None,
            created_at: now,
            updated_at: now,
            finished_at: Some(now),
            expires_at: now + Duration::hours(1),
        };
        assert!(restricted.job_insert(&foreign_job).await.is_err());
        assert!(restricted
            .trace_append(jobs[1], "forged", json!({}), now)
            .await
            .is_err());
        assert!(restricted
            .snapshot_put(jobs[1], "forged", json!({}), now)
            .await
            .is_err());
        assert!(restricted
            .thread_put(tenants[1], jobs[1], json!({}), now)
            .await
            .is_err());
        assert!(restricted
            .setting_put(tenants[1], "rls", json!({}), now)
            .await
            .is_err());
        assert_eq!(
            restricted.get(runs[0]).await.unwrap().tenant,
            tenants[0],
            "rollback must not poison reuse"
        );
    })
    .await;
    // Cancel while the scoped SELECT owns a transaction and waits on a table
    // lock. Pool reuse must roll back before handing out that same connection.
    let inspector = Pg::connect(&url, PgConfig::default()).await.unwrap();
    let mut lock = owner.pool().begin().await.unwrap();
    sqlx::query("LOCK TABLE crawl_runs IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let query_pg = restricted.clone();
    let tenant = tenants[0];
    let run = runs[0];
    let blocked = tokio::spawn(tenant::scope(tenant, async move { query_pg.get(run).await }));
    let mut waiting = false;
    for _ in 0..100 {
        waiting = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE a.usename = $1 AND NOT l.granted)"
        ).bind(&role).fetch_one(inspector.pool()).await.unwrap();
        if waiting {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(10)).await;
    }
    assert!(
        waiting,
        "scoped SELECT must reach the locked table before cancellation"
    );
    blocked.abort();
    assert!(blocked.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    let setting: Option<String> =
        sqlx::query_scalar("SELECT NULLIF(current_setting('app.tenant_id', true), '')")
            .fetch_one(restricted.pool())
            .await
            .unwrap();
    assert_eq!(setting, None, "SET LOCAL must not leak after commit or rollback");
    let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM crawl_runs")
        .fetch_one(restricted.pool())
        .await
        .unwrap();
    assert_eq!(hidden, 0, "unscoped restricted pool must fail closed");
    let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys")
        .fetch_one(restricted.pool())
        .await
        .unwrap();
    assert_eq!(hidden, 0, "pre-auth must not expose the api_keys table");
    assert!(
        owner.get(runs[1]).await.is_ok(),
        "worker/admin authority stays cross-tenant"
    );
    // Audit appends must share one global chain despite tenant-local SELECT policies.
    let broken: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT prev_hash, lag(entry_hash) OVER (ORDER BY audit_id) AS expected FROM audit_events) a WHERE expected IS NOT NULL AND prev_hash <> expected"
    ).fetch_one(owner.pool()).await.unwrap();
    assert_eq!(broken, 0);

    stop.cancel();
    server.await.unwrap();
    drop(request_pg);
    restricted.pool().close().await;
    owner.clone().drop_schema().await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP OWNED BY {role}")))
        .execute(inspector.pool())
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(inspector.pool())
        .await
        .unwrap();
}
