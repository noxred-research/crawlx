//! The registry of tenant-scoped tables.
//!
//! PostgreSQL enforces tenant isolation with row-level security policies. MariaDB and SQLite
//! have none, so those engines enforce it in the application: every statement of a request
//! handle carries a tenant predicate built by [`crate::tenant::TenantGuard`] from this
//! registry. The registry is the single list of which tables are tenant data, how a row is
//! tied to its tenant, and which tables only operators may touch.
//!
//! It mirrors the policies of the PostgreSQL schema and is checked against the migrated
//! schema of every engine by the conformance suite: each table appears exactly once and no
//! table that has a `run_id` column is [`TenantKey::Global`].

/// How a table row belongs to a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TenantKey {
    /// The table has its own tenant column (the name is the column).
    Column(&'static str),
    /// Through `run_id` to `crawl_runs.tenant_id`.
    ViaRun,
    /// Through `state_id` to `states.run_id` and its run's tenant.
    ViaState,
    /// Through `job_id` to `intel_jobs.tenant_id`.
    ViaJob,
    /// Through `monitor_id` to `monitors.tenant_id`.
    ViaMonitor,
    /// Through `check_id` to `monitor_checks.tenant_id`.
    ViaCheck,
    /// Through `session_id` to `crawl_sessions` and its run.
    ViaSession,
    /// Not tenant data: operator-only. Request handles never read or write it.
    Global,
}

/// One registry entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantTable {
    /// The table name.
    pub name: &'static str,
    /// How its rows belong to a tenant.
    pub key: TenantKey,
}

/// Every table of every engine, sorted by name. The audit chain head, the sequence table and
/// the lock table exist only on the engines without sequences or advisory locks.
pub static TENANT_TABLES: &[TenantTable] = &[
    TenantTable {
        name: "action_contexts",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "actions",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "adaptive_selectors",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "api_keys",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "approvals",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "archive_dependencies",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_exports",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_frozen_grants",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_frozen_outputs",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_frozen_sources",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_history",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_payload_sources",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "archive_records",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "artifact_key_custody",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "artifacts",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "audit_chain_head",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "audit_events",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "authorization_records",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "browser_profiles",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "checkpoints",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "cluster_settings",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "content_digest_registry",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "crawl_events",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "crawl_runs",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "crawl_sessions",
        key: TenantKey::ViaSession,
    },
    TenantTable {
        name: "crawlx_locks",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "crawlx_sequences",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "dataset_delivery_outbox",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "dataset_items",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "dataset_kv",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "dataset_kv_drops",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "datasets",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "elements",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "enablement_edges",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "extension_attempts",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "frontier_batch_receipts",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "frontier_loader_cursors",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "frontier_producers",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "idempotency_keys",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "identity_aliases",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "intel_jobs",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "intel_snapshots",
        key: TenantKey::ViaJob,
    },
    TenantTable {
        name: "intel_threads",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "intel_trace",
        key: TenantKey::ViaJob,
    },
    TenantTable {
        name: "model_decisions",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "monitor_baselines",
        key: TenantKey::ViaMonitor,
    },
    TenantTable {
        name: "monitor_check_pages",
        key: TenantKey::ViaCheck,
    },
    TenantTable {
        name: "monitor_checks",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "monitors",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "network_epochs",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "origin_admission",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "origin_leases",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "page_captures",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "pages",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "report_history",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "request_pipeline_history",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "run_artifact_exposures",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "run_bootstrap_producers",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "run_custody_producers",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "run_secret_authority",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "run_secret_authority_renewals",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "safety_decisions",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "session_bindings",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "session_egress_pins",
        key: TenantKey::ViaSession,
    },
    TenantTable {
        name: "source_category_cache",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "source_memo_control",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "source_memo_seen",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "state_cluster_membership",
        key: TenantKey::ViaState,
    },
    TenantTable {
        name: "state_clusters",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "states",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "tenant_settings",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "tenants",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "traffic_events",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "transitions",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "url_frontier",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "url_graph_edges",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "url_graph_nodes",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "url_graph_ranks",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "url_graph_runs",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "usage_ledger",
        key: TenantKey::Column("tenant_id"),
    },
    TenantTable {
        name: "webhook_deliveries",
        key: TenantKey::ViaRun,
    },
    TenantTable {
        name: "workers",
        key: TenantKey::Global,
    },
    TenantTable {
        name: "workflow_runs",
        key: TenantKey::ViaRun,
    },
];

/// The registry entry of `table`, if it is registered.
#[must_use]
pub fn lookup(table: &str) -> Option<&'static TenantTable> {
    TENANT_TABLES
        .binary_search_by(|entry| entry.name.cmp(table))
        .ok()
        .map(|index| &TENANT_TABLES[index])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn registry_is_sorted_and_unique() {
        for pair in TENANT_TABLES.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} before {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn lookup_finds_every_shape() {
        assert_eq!(lookup("pages").unwrap().key, TenantKey::ViaRun);
        assert_eq!(
            lookup("state_cluster_membership").unwrap().key,
            TenantKey::ViaState
        );
        assert_eq!(lookup("crawl_runs").unwrap().key, TenantKey::Column("tenant_id"));
        assert_eq!(lookup("intel_trace").unwrap().key, TenantKey::ViaJob);
        assert_eq!(lookup("monitor_baselines").unwrap().key, TenantKey::ViaMonitor);
        assert_eq!(lookup("monitor_check_pages").unwrap().key, TenantKey::ViaCheck);
        assert_eq!(lookup("session_egress_pins").unwrap().key, TenantKey::ViaSession);
        assert_eq!(lookup("workers").unwrap().key, TenantKey::Global);
        assert!(lookup("no_such_table").is_none());
    }

    #[test]
    fn operator_tables_are_exactly_the_unpolicied_ones() {
        let global: Vec<&str> = TENANT_TABLES
            .iter()
            .filter(|entry| entry.key == TenantKey::Global)
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            global,
            [
                "audit_chain_head",
                "cluster_settings",
                "crawlx_locks",
                "crawlx_sequences",
                "origin_admission",
                "workers",
            ]
        );
    }
}
