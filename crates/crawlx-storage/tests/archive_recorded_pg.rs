//! Existing traffic/artifact projection: real PostgreSQL schema and real retained object references.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::TenantId;
use crawlx_storage::archive::{recorded, retained, Limits};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use std::sync::Arc;

#[tokio::test]
async fn traffic_projection_preserves_chronology_and_never_adopts_foreign_artifacts() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("archive_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-owner").await.unwrap();
    pg.ensure_tenant(other_tenant, "archive-other").await.unwrap();
    let at = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:34:56.789Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let clock = Arc::new(ManualClock::new(at));
    let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    run.created_at = at;
    pg.create(&run, None).await.unwrap();
    let mut foreign = crawl_run(other_tenant, create_crawl("https://other.test/", &[], 1));
    foreign.created_at = at;
    pg.create(&foreign, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let body = store
        .put(
            run.id,
            Sensitivity::Content,
            "application/json",
            b"{\"actual\":true}",
        )
        .await
        .unwrap();
    let foreign_body = store
        .put(foreign.id, Sensitivity::Content, "text/plain", b"foreign-canary")
        .await
        .unwrap();
    for (ordinal, artifact) in [(1, body.id), (2, body.id), (3, foreign_body.id)] {
        sqlx::query("INSERT INTO traffic_events (occurred_at,run_id,epoch_id,unattributed_reason,seq,lane,origin,method,url_redacted,url_hash,status,body_artifact_id) \
            VALUES ($1,$2,NULL,'not_applicable',$3,'diagnostic','fetch_plane','GET','https://example.test/data',$4,200,$5)")
            .bind(at).bind(run.id.0).bind(ordinal).bind(vec![7u8;32]).bind(artifact.0).execute(pg.pool()).await.unwrap();
    }
    let events = crawlx_storage::tenant::scope(tenant, recorded::traffic(&pg, tenant, run.id, 3))
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.windows(2).all(|rows| rows[0].event_id < rows[1].event_id));
    assert_eq!(events[0].response_body, Some(body.clone()));
    assert_eq!(events[1].response_body, Some(body.clone()));
    assert_eq!(events[2].response_body, None);
    let first = recorded::traffic_keyset(&pg, tenant, run.id, 0, 1).await.unwrap();
    assert_eq!(first[0].event_id, events[0].event_id);
    let rest = recorded::traffic_keyset(&pg, tenant, run.id, first[0].event_id.try_into().unwrap(), 2)
        .await
        .unwrap();
    assert_eq!(
        rest.iter().map(|event| event.event_id).collect::<Vec<_>>(),
        events[1..].iter().map(|event| event.event_id).collect::<Vec<_>>()
    );
    assert!(recorded::traffic_keyset(&pg, tenant, run.id, 0, 0).await.is_err());
    assert!(recorded::traffic_keyset(&pg, tenant, run.id, u64::MAX, 1)
        .await
        .is_err());
    assert_eq!(
        retained::read(dir.path(), &body, tenant, run.id, at, Limits::default())
            .unwrap()
            .bytes,
        b"{\"actual\":true}"
    );
    assert!(retained::read(dir.path(), &foreign_body, tenant, run.id, at, Limits::default()).is_err());
    assert!(recorded::traffic(&pg, tenant, run.id, 2).await.is_err());
    assert!(recorded::traffic(&pg, other_tenant, run.id, 3)
        .await
        .unwrap()
        .is_empty());
    pg.drop_schema().await.unwrap();
}
