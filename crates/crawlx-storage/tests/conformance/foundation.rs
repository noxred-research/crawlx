//! Foundation cases: migrations, schema version, tenant registry coverage, URL refusals,
//! typed capability refusals, error mapping and fence sequences.

use crate::rig::{migration_files_latest_version, Rig};
use crawlx_core::StoreError;
use crawlx_storage::tenant_tables::{self, TenantKey};
use crawlx_storage::{BackendKind, Database, DatabaseUrl, Feature, FenceSeq, RefusalCode, StoreConfig};
use std::collections::BTreeSet;

conformance! { databases:
    migrations_apply_and_the_schema_version_matches,
    every_table_is_in_the_tenant_registry,
    constraint_violations_map_to_conflicts,
    fence_sequence_is_unique_and_monotonic,
    pending_features_are_typed_refusals,
}

conformance! { all:
    database_urls_are_parsed_and_refused,
}

async fn migrations_apply_and_the_schema_version_matches(rig: &Rig) {
    let database = rig.database();
    assert_eq!(database.applied_migration_version().await.unwrap_or(None), None);
    rig.migrate().await;
    let kind = database.kind();
    let on_disk = migration_files_latest_version(kind);
    assert_eq!(database.latest_migration_version(), Some(on_disk));
    assert_eq!(database.applied_migration_version().await.unwrap(), Some(on_disk));
    // applying again changes nothing
    rig.migrate().await;
    assert_eq!(database.applied_migration_version().await.unwrap(), Some(on_disk));
    assert!(!rig.tables().await.is_empty());
}

async fn every_table_is_in_the_tenant_registry(rig: &Rig) {
    rig.migrate().await;
    let tables = rig.tables().await;
    let unknown: Vec<&String> = tables
        .iter()
        .filter(|table| tenant_tables::lookup(table).is_none())
        .collect();
    assert!(
        unknown.is_empty(),
        "tables missing from TENANT_TABLES: {unknown:?}"
    );
    // a table that carries a run id is tenant data, never operator-only
    for table in rig.tables_with_column("run_id").await {
        let entry = tenant_tables::lookup(&table).unwrap();
        assert_ne!(entry.key, TenantKey::Global, "{table} has a run_id column");
    }
}

async fn constraint_violations_map_to_conflicts(rig: &Rig) {
    rig.migrate().await;
    let tenant = uuid::Uuid::now_v7();
    rig.insert_tenant(tenant).await.unwrap();
    // unique violation
    let duplicate = rig.insert_tenant(tenant).await.unwrap_err();
    assert!(matches!(duplicate, StoreError::Conflict(_)), "{duplicate:?}");
    // foreign key violation
    let orphan = rig.insert_api_key(uuid::Uuid::now_v7()).await.unwrap_err();
    assert!(matches!(orphan, StoreError::Conflict(_)), "{orphan:?}");
    // the same row is accepted for an existing tenant
    rig.insert_api_key(tenant).await.unwrap();
}

async fn fence_sequence_is_unique_and_monotonic(rig: &Rig) {
    rig.migrate().await;
    let database = rig.database();
    // sequential draws strictly increase
    let mut previous = database.next_fence(FenceSeq::Lease).await.unwrap();
    for _ in 0..5 {
        let next = database.next_fence(FenceSeq::Lease).await.unwrap();
        assert!(next > previous, "{next} after {previous}");
        previous = next;
    }
    // concurrent draws on separate connections never repeat, and every drawer sees its own
    // values strictly increase
    let mut drawers = Vec::new();
    for _ in 0..8 {
        let database = database.clone();
        drawers.push(tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..12 {
                seen.push(database.next_fence(FenceSeq::Lease).await.unwrap());
            }
            seen
        }));
    }
    let mut all = BTreeSet::new();
    for drawer in drawers {
        let seen = drawer.await.unwrap();
        assert!(seen.windows(2).all(|w| w[0] < w[1]), "{seen:?}");
        for value in seen {
            assert!(value > previous);
            assert!(all.insert(value), "fence {value} handed out twice");
        }
    }
    assert_eq!(all.len(), 96);
    // the bootstrap sequence is its own counter
    let first = database.next_fence(FenceSeq::BootstrapProducer).await.unwrap();
    let second = database.next_fence(FenceSeq::BootstrapProducer).await.unwrap();
    assert!(second > first);
}

async fn pending_features_are_typed_refusals(rig: &Rig) {
    let database = rig.database();
    let capabilities = database.capabilities();
    for feature in [
        Feature::Repositories,
        Feature::DurableAdmin,
        Feature::SessionClaims,
        Feature::FrontierClaims,
        Feature::WebhookClaims,
        Feature::MonitorClaims,
        Feature::OutboxClaims,
        Feature::AuditChain,
    ] {
        match database.require(feature) {
            Ok(()) => assert!(capabilities.supports(feature)),
            Err(refusal) => {
                assert!(!capabilities.supports(feature));
                assert_eq!(refusal.code, RefusalCode::BackendUnimplemented);
                assert!(refusal
                    .to_string()
                    .starts_with("refused: backend_unimplemented: "));
            }
        }
    }
    match database.kind() {
        BackendKind::Postgres => assert!(database.postgres().is_ok()),
        _ => assert_eq!(
            database.postgres().unwrap_err().code,
            RefusalCode::BackendUnimplemented
        ),
    }
}

async fn database_urls_are_parsed_and_refused(_rig: &Rig) {
    for (url, kind) in [
        ("postgres://u:p@h/db", BackendKind::Postgres),
        ("postgresql://u:p@h/db", BackendKind::Postgres),
        ("mariadb://u:p@h/db", BackendKind::MariaDb),
        ("mysql://u:p@h/db", BackendKind::MariaDb),
        ("sqlite:///tmp/x.db", BackendKind::Sqlite),
    ] {
        assert_eq!(DatabaseUrl::parse(url).unwrap().kind(), kind, "{url}");
    }
    let refusal = DatabaseUrl::parse("oracle://u:secret@h/db").unwrap_err();
    assert_eq!(refusal.code, RefusalCode::Scheme);
    assert_eq!(
        refusal.to_string(),
        "refused: scheme: unsupported database url scheme; expected postgres, mariadb or sqlite"
    );
    // the password never reaches Debug output
    let debug = format!("{:?}", DatabaseUrl::parse("mysql://crawlx:hunter2@h/db").unwrap());
    assert!(!debug.contains("hunter2"), "{debug}");
    // an unknown scheme is also refused by open
    let error = Database::open("oracle://h/db", StoreConfig::default())
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Conflict(text) if text.contains("refused: scheme:")));
}

#[tokio::test]
async fn sqlite_refuses_memory_outside_tests_and_a_second_worker() {
    let error = Database::open("sqlite::memory:", StoreConfig::default())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, StoreError::Conflict(text) if text.starts_with("refused: sqlite_not_local: :memory: "))
    );
    let rig = Rig::sqlite().await;
    let first = rig.database().acquire_worker_lock().unwrap();
    assert!(first.is_some());
    let second = rig.database().acquire_worker_lock().unwrap_err();
    assert!(
        matches!(&second, StoreError::Conflict(text) if text.starts_with("refused: sqlite_second_worker:"))
    );
    drop(first);
    assert!(rig.database().acquire_worker_lock().unwrap().is_some());
    rig.close().await;
}

#[tokio::test]
async fn sqlite_connections_run_wal_with_foreign_keys_and_a_busy_timeout() {
    let rig = Rig::sqlite().await;
    let pool = rig.database().sqlite_pool().unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(mode, "wal");
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(foreign_keys, 1);
    let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(busy, 5000);
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(synchronous, 2);
    rig.close().await;
}

#[tokio::test]
async fn mariadb_sessions_run_read_committed_utc_with_pipes_as_concat() {
    let Some(rig) = Rig::mariadb().await else { return };
    let pool = rig.database().mariadb_pool().unwrap();
    let (mode, zone, isolation): (String, String, String) = sqlx::query_as(
        "SELECT CAST(@@SESSION.sql_mode AS CHAR), CAST(@@SESSION.time_zone AS CHAR), \
         CAST(@@SESSION.transaction_isolation AS CHAR)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(mode.contains("PIPES_AS_CONCAT"), "{mode}");
    assert!(mode.contains("STRICT_ALL_TABLES"), "{mode}");
    assert_eq!(zone, "+00:00");
    assert_eq!(isolation, "READ-COMMITTED");
    let concat: String = sqlx::query_scalar("SELECT 'a' || 'b'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(concat, "ab");
    rig.close().await;
}
