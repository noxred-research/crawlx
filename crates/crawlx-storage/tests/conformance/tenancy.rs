//! Tenant isolation proofs P1-P4 and P6, on every engine.
//!
//! PostgreSQL enforces tenants with row-level security and a restricted login; MariaDB and SQLite
//! with the tenant predicate of the request handle. The same cases prove both: two tenants own
//! rows in every request-surface table, every public method of the request-surface repositories
//! runs under the other tenant's scope against the first tenant's ids, and the first tenant's
//! rows must stay invisible and untouched. A positive control per surface keeps the proofs from
//! passing on an empty database.
//!
//! * P1 `registry_entries_match_every_schema`: the registry and the migrated schema agree.
//! * P2 `two_tenants_cannot_read_each_other`: no read or write crosses tenants.
//! * P3 `missing_scope_fails_closed`: a request handle without a scope is refused, also in a
//!   task that was spawned without inheriting the scope.
//! * P4 `writes_cannot_forge_another_tenant`: inserts and updates naming another tenant's
//!   run, check, monitor or tenant fail and change nothing.
//! * P6 `isolation_proofs_fail_without_the_guard` (feature `unscoped-for-test`): with the guard
//!   off, P2 fails. Run it with `--features unscoped-for-test` (the other cases skip then).

use crate::rig::Rig;
use chrono::Utc;
use crawlx_core::hash::Digest;
use crawlx_core::{ApprovalId, CrawlRunId, StoreError, TenantId};
use crawlx_storage::tenant_tables::{self, TenantKey};
use crawlx_storage::testkit::tenancy::{seed, Handle, Harness, TenantRows};
use crawlx_storage::{
    with_handle, ApiRepo, ApprovalDecision, Baseline, CheckPage, CheckRecord, CheckState, DecideOutcome,
    DeliveryResult, IdemResponse, InspectRepo, IntelRepo, JobKind, JobPatch, JobRecord, JobStatus,
    LaneFilter, MonitorRecord, MonitorStatus, TrafficQuery, TrailReads, TransitionFilter, TrustedCorpus,
    UsageEvent,
};
use serde_json::json;
use std::collections::BTreeSet;
use uuid::Uuid;

conformance! { databases:
    registry_entries_match_every_schema,
    requests_see_their_own_rows,
    two_tenants_cannot_read_each_other,
    missing_scope_fails_closed,
    writes_cannot_forge_another_tenant,
    state_cluster_membership_follows_the_tenant_of_its_state,
}

#[cfg(feature = "unscoped-for-test")]
conformance! { databases:
    isolation_proofs_fail_without_the_guard,
}

/// What a tenant owns on the intel side.
#[derive(Clone, Debug)]
struct IntelRows {
    job: Uuid,
    thread: Uuid,
    monitor: Uuid,
    check: Uuid,
    usage_ref: Uuid,
}

struct World {
    harness: Harness,
    a: TenantRows,
    b: TenantRows,
    a_intel: IntelRows,
    b_intel: IntelRows,
    a_delivery: Uuid,
}

fn guard_off() -> bool {
    cfg!(feature = "unscoped-for-test")
}

/// Tables that exist on one engine only: the registry lists them for the engines that have them.
const ENGINE_EXTRAS: &[&str] = &["audit_chain_head", "crawlx_locks", "crawlx_sequences"];

async fn seed_intel(operator: &Handle, tenant: TenantId) -> Result<IntelRows, StoreError> {
    let now = Utc::now();
    let rows = IntelRows {
        job: Uuid::now_v7(),
        thread: Uuid::now_v7(),
        monitor: Uuid::now_v7(),
        check: Uuid::now_v7(),
        usage_ref: Uuid::now_v7(),
    };
    with_handle!(operator, |store| async {
        store
            .job_insert(&JobRecord {
                id: rows.job,
                tenant,
                kind: JobKind::Extract,
                status: JobStatus::Processing,
                request: json!({ "urls": ["https://app.example.test/"] }),
                result: None,
                error: None,
                stop_reason: None,
                tokens_used: 0,
                credits_used: 0,
                thread_id: None,
                created_at: now,
                updated_at: now,
                finished_at: None,
                expires_at: now + chrono::Duration::days(1),
            })
            .await?;
        store
            .trace_append(rows.job, "step", json!({ "n": 1 }), now)
            .await?;
        store
            .snapshot_put(rows.job, "snap", json!({ "ok": true }), now)
            .await?;
        store
            .thread_put(tenant, rows.thread, json!({ "turns": 1 }), now)
            .await?;
        store
            .monitor_insert(&MonitorRecord {
                id: rows.monitor,
                tenant,
                name: Some("watch".to_owned()),
                status: MonitorStatus::Active,
                schedule: json!({ "cron": "0 * * * *" }),
                cron: "0 * * * *".to_owned(),
                timezone: "UTC".to_owned(),
                goal: None,
                targets: json!([{ "id": "t1" }]),
                retention_days: 7,
                webhook: None,
                notification: json!({}),
                next_run_at: Some(now),
                last_run_at: None,
                last_check_id: None,
                claimed_until: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        store
            .check_insert(&CheckRecord {
                id: rows.check,
                monitor: rows.monitor,
                tenant,
                trigger: "manual".to_owned(),
                state: CheckState::Running,
                status: None,
                summary: json!({}),
                error: None,
                started_at: now,
                finished_at: None,
                expires_at: now + chrono::Duration::days(7),
            })
            .await?;
        store
            .check_pages_put(&[CheckPage {
                check: rows.check,
                target_id: "t1".to_owned(),
                url: "https://app.example.test/a".to_owned(),
                status: "new".to_owned(),
                data: json!({ "title": "a" }),
            }])
            .await?;
        store
            .baselines_put(&[Baseline {
                monitor: rows.monitor,
                url: "https://app.example.test/a".to_owned(),
                digest: "d1".to_owned(),
                markdown: "# a".to_owned(),
                seen_at: now,
            }])
            .await?;
        store
            .usage_record(&UsageEvent {
                tenant,
                at: now,
                endpoint: "extract".to_owned(),
                ref_id: Some(rows.usage_ref),
                status: "ok".to_owned(),
                credits: 3,
                prompt_tokens: 10,
                completion_tokens: 5,
            })
            .await?;
        store
            .setting_put(tenant, "threat-protection", json!({ "on": true }), now)
            .await?;
        Ok::<(), StoreError>(())
    }
    .await)?;
    Ok(rows)
}

async fn world(rig: &Rig) -> World {
    rig.migrate().await;
    let harness = Harness::new(rig).await.unwrap();
    let a = seed(&harness.operator, TenantId::new(), "alpha").await.unwrap();
    let b = seed(&harness.operator, TenantId::new(), "beta").await.unwrap();
    let a_intel = seed_intel(&harness.operator, a.tenant).await.unwrap();
    let b_intel = seed_intel(&harness.operator, b.tenant).await.unwrap();
    let a_delivery = with_handle!(&harness.operator, |store| async {
        ApiRepo::new(store.clone()).webhook_list(a.run).await
    }
    .await)
    .unwrap()
    .first()
    .map(|d| d.id)
    .unwrap();
    World {
        harness,
        a,
        b,
        a_intel,
        b_intel,
        a_delivery,
    }
}

fn hidden<T: std::fmt::Debug>(what: &str, result: Result<Option<T>, StoreError>) {
    assert!(
        matches!(
            result,
            Ok(None) | Err(StoreError::AccessDenied(_) | StoreError::NotFound { .. })
        ),
        "{what}: another tenant's row is visible: {result:?}"
    );
}

fn empty<T: std::fmt::Debug>(what: &str, result: Result<Vec<T>, StoreError>) {
    assert!(
        matches!(&result, Ok(rows) if rows.is_empty())
            || matches!(
                &result,
                Err(StoreError::AccessDenied(_) | StoreError::NotFound { .. })
            ),
        "{what}: another tenant's rows are visible: {result:?}"
    );
}

fn refused<T: std::fmt::Debug>(what: &str, result: Result<T, StoreError>) {
    assert!(
        result.is_err(),
        "{what}: a cross-tenant write was accepted: {result:?}"
    );
}

fn denied<T: std::fmt::Debug>(what: &str, result: Result<T, StoreError>) {
    assert!(
        matches!(result, Err(StoreError::AccessDenied(_))),
        "{what}: expected AccessDenied, got {result:?}"
    );
}

// ---- P1 ---------------------------------------------------------------------------------

async fn registry_entries_match_every_schema(rig: &Rig) {
    rig.migrate().await;
    let tables: BTreeSet<String> = rig.tables().await.into_iter().collect();
    // every table is registered, exactly once (the registry is a sorted, duplicate-free slice)
    for table in &tables {
        assert!(
            tenant_tables::lookup(table).is_some(),
            "{table} is not in TENANT_TABLES"
        );
    }
    // every entry names a table of the schema, except the helpers one engine adds
    for entry in tenant_tables::TENANT_TABLES {
        assert!(
            tables.contains(entry.name) || ENGINE_EXTRAS.contains(&entry.name),
            "{} is registered but no engine creates it",
            entry.name
        );
    }
    // a table with a run id is tenant data, one with a tenant column is keyed by it
    for table in rig.tables_with_column("run_id").await {
        let entry = tenant_tables::lookup(&table).unwrap();
        assert_ne!(entry.key, TenantKey::Global, "{table} has a run_id column");
    }
    for table in rig.tables_with_column("tenant_id").await {
        let entry = tenant_tables::lookup(&table).unwrap();
        assert!(
            matches!(entry.key, TenantKey::Column(_) | TenantKey::ViaRun),
            "{table} has a tenant_id column but is keyed {:?}",
            entry.key
        );
    }
}

// ---- positive control ---------------------------------------------------------------------

async fn requests_see_their_own_rows(rig: &Rig) {
    if guard_off() {
        return;
    }
    let w = world(rig).await;
    for (own, other, intel) in [(&w.a, &w.b, &w.a_intel), (&w.b, &w.a, &w.b_intel)] {
        let (own_tenant, own_run) = (own.tenant, own.run);
        let seen = tenant_run(&w.harness.request, own_tenant, own, other, intel).await;
        assert_eq!(seen, own_run);
    }
    w.harness.finish().await.unwrap();
}

/// Everything one tenant can read about itself under its own scope.
async fn tenant_run(
    request: &Handle,
    tenant: TenantId,
    own: &TenantRows,
    other: &TenantRows,
    intel: &IntelRows,
) -> CrawlRunId {
    crawlx_storage::tenant::scope(tenant, async {
        with_handle!(request, |store| async {
            let api = ApiRepo::new(store.clone());
            let key = api.key_by_prefix(&own.prefix).await.unwrap().unwrap();
            assert_eq!(key.tenant, tenant);
            assert_eq!(api.approvals_list(own.run).await.unwrap().len(), 1);
            assert!(api
                .approval_get(own.run, ApprovalId(own.approval))
                .await
                .unwrap()
                .is_some());
            assert_eq!(
                api.transitions_list(own.run, &TransitionFilter::default())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(api.active_run_count(tenant).await.unwrap(), 1);
            assert_eq!(api.active_runs(tenant).await.unwrap(), vec![own.run]);
            assert_eq!(api.webhook_list(own.run).await.unwrap().len(), 1);
            assert_eq!(api.webhook_cursor(own.run).await.unwrap(), 2);
            assert!(api
                .authorization_stored(tenant, own.record)
                .await
                .unwrap()
                .is_some());
            let inspect = InspectRepo::new(store.clone());
            assert_eq!(inspect.epochs(own.run).await.unwrap().len(), 1);
            assert_eq!(inspect.navigations(own.run).await.unwrap().len(), 1);
            assert_eq!(inspect.transitions(own.run).await.unwrap().len(), 1);
            let trail = TrailReads::new(store.clone());
            assert!(trail
                .artifact_digests(own.run)
                .await
                .unwrap()
                .contains(&Digest(own.artifact_digest)));
            assert_eq!(trail.traffic_attribution(own.run).await.unwrap().len(), 1);
            assert_eq!(trail.safety_decision_ids(own.run).await.unwrap().len(), 1);
            let corpus = TrustedCorpus::new(store.clone());
            assert_eq!(
                corpus
                    .traffic(own.run, LaneFilter::Both, &TrafficQuery::default())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(corpus.coverage(own.run).await.unwrap().len(), 1);
            assert!(store.job_get(tenant, intel.job).await.unwrap().is_some());
            assert!(store.thread_get(tenant, intel.thread).await.unwrap().is_some());
            assert!(store.monitor_get(tenant, intel.monitor).await.unwrap().is_some());
            assert!(store
                .check_get(tenant, intel.monitor, intel.check)
                .await
                .unwrap()
                .is_some());
            assert_eq!(store.trace_list(intel.job, 0, 10).await.unwrap().len(), 1);
            assert_eq!(
                store.snapshot_ids(intel.job).await.unwrap(),
                vec!["snap".to_owned()]
            );
            assert_eq!(
                store.check_pages(intel.check, None, 10, 0).await.unwrap().len(),
                1
            );
            assert_eq!(store.baselines(intel.monitor).await.unwrap().len(), 1);
            assert_eq!(
                store
                    .usage_totals(
                        tenant,
                        Utc::now() - chrono::Duration::hours(1),
                        Utc::now() + chrono::Duration::hours(1)
                    )
                    .await
                    .unwrap()
                    .credits,
                3
            );
            assert!(store
                .usage_by_ref(tenant, intel.usage_ref)
                .await
                .unwrap()
                .is_some());
            // and the other tenant's rows are not among them
            assert!(api
                .approvals_list(other.run)
                .await
                .map_or(true, |rows| rows.is_empty()));
            own.run
        }
        .await)
    })
    .await
}

// ---- P2 -----------------------------------------------------------------------------------

async fn two_tenants_cannot_read_each_other(rig: &Rig) {
    if guard_off() {
        return;
    }
    let w = world(rig).await;
    cross_tenant_sweep(&w).await;
    w.harness.finish().await.unwrap();
}

/// A membership row inherits its tenant from its state: each tenant's request scope reads its
/// own rows and none of the other's, with the registry predicate on every engine and, on
/// PostgreSQL, with row-level security alone.
async fn state_cluster_membership_follows_the_tenant_of_its_state(rig: &Rig) {
    if guard_off() {
        return;
    }
    let w = world(rig).await;
    let operator = &w.harness.operator;
    for rows in [&w.a, &w.b] {
        let cluster = Uuid::now_v7();
        operator
            .run(&format!(
                "INSERT INTO state_clusters (cluster_id, run_id, prototype_state_id, algo_version) VALUES ({}, {}, {}, 1)",
                operator.id(cluster),
                operator.id(rows.run.0),
                operator.id(rows.state)
            ))
            .await
            .unwrap();
        operator
            .run(&format!(
                "INSERT INTO state_cluster_membership (state_id, cluster_id, decision_version, similarity) VALUES ({}, {}, 1, 0.5)",
                operator.id(rows.state),
                operator.id(cluster)
            ))
            .await
            .unwrap();
    }
    // positive control: the owner sees both rows
    assert_eq!(
        operator
            .count("state_cluster_membership", "decision_version = 1")
            .await
            .unwrap(),
        2
    );
    let request = &w.harness.request;
    for (own, other) in [(&w.a, &w.b), (&w.b, &w.a)] {
        assert_eq!(
            request.visible_memberships(own.tenant, true).await.unwrap(),
            vec![own.state]
        );
        assert!(!request
            .visible_memberships(own.tenant, true)
            .await
            .unwrap()
            .contains(&other.state));
    }
    if rig.database().kind() == crawlx_storage::BackendKind::Postgres {
        for own in [&w.a, &w.b] {
            assert_eq!(
                request.visible_memberships(own.tenant, false).await.unwrap(),
                vec![own.state]
            );
        }
    }
    w.harness.finish().await.unwrap();
}
/// Tenant B's request handle against every id of tenant A.
async fn cross_tenant_sweep(w: &World) {
    let (a, b) = (&w.a, &w.b);
    let ai = &w.a_intel;
    let now = Utc::now();
    crawlx_storage::tenant::scope(b.tenant, async {
        with_handle!(&w.harness.request, |store| async {
            let api = ApiRepo::new(store.clone());
            // ---- api keys, idempotency
            api.key_touch(a.key, now).await.ok();
            refused(
                "idem_begin",
                api.idem_begin(a.tenant, &a.idem_key, Digest([3; 32]), now).await,
            );
            api.idem_complete(
                a.tenant,
                &a.idem_key,
                &IdemResponse {
                    status: 200,
                    body: json!({}),
                    run_id: None,
                },
            )
            .await
            .ok();
            api.idem_release(a.tenant, &a.idem_key).await.ok();
            hidden("idem_run", api.idem_run(a.tenant, &a.idem_key).await);
            api.idem_link_run(a.tenant, &a.idem_key, a.run).await.ok();
            // ---- approvals and transitions
            empty("approvals_list", api.approvals_list(a.run).await);
            hidden(
                "approval_get",
                api.approval_get(a.run, ApprovalId(a.approval)).await,
            );
            let decided = api
                .approval_decide(
                    a.run,
                    ApprovalId(a.approval),
                    ApprovalDecision::Approved,
                    b.key,
                    Some("nope"),
                    now,
                )
                .await;
            assert!(
                matches!(
                    decided,
                    Ok(DecideOutcome::NotFound)
                        | Err(StoreError::AccessDenied(_) | StoreError::NotFound { .. })
                ),
                "approval_decide reached another tenant: {decided:?}"
            );
            empty(
                "transitions_list",
                api.transitions_list(a.run, &TransitionFilter::default()).await,
            );
            // ---- runs
            assert_eq!(api.active_run_count(a.tenant).await.unwrap_or(0), 0);
            empty("active_runs", api.active_runs(a.tenant).await);
            refused("shadow_tag", api.shadow_tag(a.run).await);
            // ---- webhooks
            denied("webhook_runs", api.webhook_runs().await);
            assert_eq!(api.webhook_cursor(a.run).await.unwrap_or(0), 0);
            assert_eq!(api.webhook_dead_count(a.run).await.unwrap_or(0), 0);
            empty("webhook_list", api.webhook_list(a.run).await);
            denied("webhook_claim_due", api.webhook_claim_due(now, 10, 30).await);
            refused(
                "webhook_record",
                api.webhook_record(
                    w.a_delivery,
                    &DeliveryResult::Dead {
                        status: None,
                        error: "x".to_owned(),
                    },
                )
                .await,
            );
            // ---- authorization records
            hidden(
                "authorization_stored",
                api.authorization_stored(a.tenant, a.record).await,
            );
            hidden(
                "authorization_get",
                api.authorization_get(a.tenant, a.record).await,
            );
            hidden(
                "authorization_stored (own tenant, foreign id)",
                api.authorization_stored(b.tenant, a.record).await,
            );
            hidden(
                "authorization_revoke",
                api.authorization_revoke(b.tenant, a.record, b.key, None, now)
                    .await
                    .map(|r| r.map(|r| r.first)),
            );
            hidden(
                "authorization_mark_verified",
                api.authorization_mark_verified(b.tenant, a.record, &json!({}), now)
                    .await
                    .map(|r| r.map(|_| ())),
            );
            refused(
                "authorization_bind_run",
                api.authorization_bind_run(a.run, Digest([1; 32])).await,
            );
            refused(
                "authorization_run_digest",
                api.authorization_run_digest(a.run).await,
            );
            hidden(
                "authorization_record_body",
                store.authorization_record_body(a.record).await,
            );
            // ---- inspect, trail, corpus
            let inspect = InspectRepo::new(store.clone());
            empty("epochs", inspect.epochs(a.run).await);
            empty("navigations", inspect.navigations(a.run).await);
            empty("transitions", inspect.transitions(a.run).await);
            hidden(
                "transition_action",
                inspect
                    .transition_action(a.run, crawlx_core::TransitionId(a.transition))
                    .await,
            );
            let trail = TrailReads::new(store.clone());
            assert!(trail.artifact_digests(a.run).await.map_or(true, |d| d.is_empty()));
            empty("traffic_attribution", trail.traffic_attribution(a.run).await);
            assert!(trail
                .safety_decision_ids(a.run)
                .await
                .map_or(true, |d| d.is_empty()));
            let corpus = TrustedCorpus::new(store.clone());
            empty(
                "traffic",
                corpus
                    .traffic(a.run, LaneFilter::Both, &TrafficQuery::default())
                    .await,
            );
            empty("export", corpus.export(a.run).await);
            empty("coverage", corpus.coverage(a.run).await);
            // ---- intel
            hidden("job_get", store.job_get(a.tenant, ai.job).await);
            hidden(
                "job_get (own tenant, foreign id)",
                store.job_get(b.tenant, ai.job).await,
            );
            hidden(
                "job_update",
                store
                    .job_update(
                        b.tenant,
                        ai.job,
                        &JobPatch {
                            status: Some(JobStatus::Cancelled),
                            ..JobPatch::at(now)
                        },
                    )
                    .await,
            );
            empty("job_list", store.job_list(a.tenant, None, 10, None).await);
            assert!(store.job_counts(a.tenant).await.map_or(true, |c| c.is_empty()));
            refused(
                "trace_append",
                store.trace_append(ai.job, "x", json!({}), now).await,
            );
            empty("trace_list", store.trace_list(ai.job, 0, 10).await);
            refused(
                "snapshot_put",
                store
                    .snapshot_put(ai.job, "snap", json!({ "forged": true }), now)
                    .await,
            );
            hidden("snapshot_get", store.snapshot_get(ai.job, "snap").await);
            empty("snapshot_ids", store.snapshot_ids(ai.job).await);
            hidden("thread_get", store.thread_get(a.tenant, ai.thread).await);
            hidden(
                "thread_get (own tenant, foreign id)",
                store.thread_get(b.tenant, ai.thread).await,
            );
            refused(
                "thread_put",
                store
                    .thread_put(b.tenant, ai.thread, json!({ "forged": true }), now)
                    .await,
            );
            hidden("monitor_get", store.monitor_get(a.tenant, ai.monitor).await);
            hidden(
                "monitor_get (own tenant, foreign id)",
                store.monitor_get(b.tenant, ai.monitor).await,
            );
            empty("monitor_list", store.monitor_list(a.tenant, 10, 0).await);
            assert_eq!(store.monitor_count(a.tenant).await.unwrap_or(0), 0);
            assert!(!store.monitor_delete(b.tenant, ai.monitor).await.unwrap_or(false));
            hidden("check_get", store.check_get(a.tenant, ai.monitor, ai.check).await);
            hidden(
                "check_get (own tenant, foreign id)",
                store.check_get(b.tenant, ai.monitor, ai.check).await,
            );
            empty(
                "check_list",
                store.check_list(a.tenant, ai.monitor, None, 10, 0).await,
            );
            empty("check_pages", store.check_pages(ai.check, None, 10, 0).await);
            empty("baselines", store.baselines(ai.monitor).await);
            refused("monitor_claim_due", store.monitor_claim_due(now, now, 10).await);
            refused("purge_expired", store.purge_expired(now, now).await);
            assert_eq!(
                store
                    .usage_totals(
                        a.tenant,
                        now - chrono::Duration::hours(1),
                        now + chrono::Duration::hours(1)
                    )
                    .await
                    .map_or(0, |t| t.credits),
                0
            );
            hidden(
                "usage_by_ref (own tenant, foreign ref)",
                store.usage_by_ref(b.tenant, ai.usage_ref).await,
            );
            hidden(
                "setting_get",
                store.setting_get(a.tenant, "threat-protection").await,
            );
        }
        .await)
    })
    .await;
    // nothing of A changed
    let op = &w.harness.operator;
    assert_eq!(
        op.count(
            "api_keys",
            &format!("key_id = {} AND last_used_at IS NOT NULL", op.id(a.key))
        )
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        op.count(
            "approvals",
            &format!("approval_id = {} AND decision = 'pending'", op.id(a.approval))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "crawl_runs",
            &format!("run_id = {} AND run_kind = 'crawl'", op.id(a.run.0))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "intel_jobs",
            &format!("job_id = {} AND status = 'processing'", op.id(ai.job))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count("intel_trace", &format!("job_id = {}", op.id(ai.job)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("intel_snapshots", &format!("job_id = {}", op.id(ai.job)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("monitors", &format!("monitor_id = {}", op.id(ai.monitor)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "monitor_baselines",
            &format!("monitor_id = {}", op.id(ai.monitor))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "webhook_deliveries",
            &format!(
                "run_id = {} AND status = 'pending' AND attempts = 0",
                op.id(a.run.0)
            )
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "idempotency_keys",
            &format!("tenant_id = {} AND state = 'in_progress'", op.id(a.tenant.0))
        )
        .await
        .unwrap(),
        1
    );
}

// ---- P3 -----------------------------------------------------------------------------------

async fn missing_scope_fails_closed(rig: &Rig) {
    if guard_off() {
        return;
    }
    let w = world(rig).await;
    let (a, ai) = (&w.a, &w.a_intel);
    let now = Utc::now();
    // the request handle, no scope: every statement of the request surface is refused
    with_handle!(&w.harness.request, |store| async {
        let api = ApiRepo::new(store.clone());
        denied("key_touch", api.key_touch(a.key, now).await);
        denied(
            "idem_begin",
            api.idem_begin(a.tenant, &a.idem_key, Digest([3; 32]), now).await,
        );
        denied("approvals_list", api.approvals_list(a.run).await);
        denied(
            "approval_get",
            api.approval_get(a.run, ApprovalId(a.approval)).await,
        );
        denied(
            "transitions_list",
            api.transitions_list(a.run, &TransitionFilter::default()).await,
        );
        denied("active_runs", api.active_runs(a.tenant).await);
        denied("shadow_tag", api.shadow_tag(a.run).await);
        denied("webhook_list", api.webhook_list(a.run).await);
        denied(
            "authorization_stored",
            api.authorization_stored(a.tenant, a.record).await,
        );
        denied(
            "authorization_run_digest",
            api.authorization_run_digest(a.run).await,
        );
        denied("epochs", InspectRepo::new(store.clone()).epochs(a.run).await);
        denied(
            "traffic_attribution",
            TrailReads::new(store.clone()).traffic_attribution(a.run).await,
        );
        denied(
            "coverage",
            TrustedCorpus::new(store.clone()).coverage(a.run).await,
        );
        denied("job_get", store.job_get(a.tenant, ai.job).await);
        denied("trace_list", store.trace_list(ai.job, 0, 10).await);
        denied("baselines", store.baselines(ai.monitor).await);
        denied("usage_totals", store.usage_totals(a.tenant, now, now).await);
        // the pre-authentication lookup is the one statement that carries no tenant
        assert!(api.key_by_prefix(&a.prefix).await.unwrap().is_some());
    }
    .await);
    // a task spawned from a scoped request does not inherit the scope
    let request = w.harness.request.clone();
    let (run, tenant) = (a.run, a.tenant);
    crawlx_storage::tenant::scope(tenant, async move {
        let leaked = tokio::spawn(async move {
            with_handle!(&request, |store| async {
                ApiRepo::new(store.clone()).approvals_list(run).await
            }
            .await)
        })
        .await
        .unwrap();
        denied("approvals_list in a spawned task", leaked);
    })
    .await;
    // the operator handle is unscoped by design: it sees every tenant
    with_handle!(&w.harness.operator, |store| async {
        let api = ApiRepo::new(store.clone());
        assert_eq!(api.approvals_list(a.run).await.unwrap().len(), 1);
        assert_eq!(api.approvals_list(w.b.run).await.unwrap().len(), 1);
    }
    .await);
    w.harness.finish().await.unwrap();
}

// ---- P4 -----------------------------------------------------------------------------------

async fn writes_cannot_forge_another_tenant(rig: &Rig) {
    if guard_off() {
        return;
    }
    let w = world(rig).await;
    let (a, b) = (&w.a, &w.b);
    let (ai, bi) = (&w.a_intel, &w.b_intel);
    let now = Utc::now();
    let tenant_scope = b.tenant;
    crawlx_storage::tenant::scope(tenant_scope, async {
        with_handle!(&w.harness.request, |store| async {
            let api = ApiRepo::new(store.clone());
            // a key for another tenant
            refused(
                "key_insert",
                api.key_insert(
                    &crawlx_storage::ApiKeyRow {
                        key_id: Uuid::now_v7(),
                        tenant: a.tenant,
                        prefix: format!("forged_{}", Uuid::now_v7().simple()),
                        hash: [1; 32],
                        scopes: vec![],
                        expires_at: None,
                        revoked: false,
                    },
                    "forged",
                )
                .await,
            );
            // an authorization record for another tenant
            let body = json!({});
            let verification = json!({});
            refused(
                "authorization_create",
                api.authorization_create(&crawlx_storage::NewAuthorization {
                    tenant: a.tenant,
                    id: crawlx_core::AuthorizationRecordId::new(),
                    version: 1,
                    body: &body,
                    body_digest: &[5; 32],
                    valid_from: now,
                    valid_to: now + chrono::Duration::days(1),
                    created_by: b.key,
                    verified_at: now,
                    verification: &verification,
                })
                .await,
            );
            // a webhook delivery on another tenant's run
            refused(
                "webhook_enqueue",
                api.webhook_enqueue(&crawlx_storage::WebhookDelivery {
                    id: Uuid::now_v7(),
                    run: a.run,
                    event_seq: 1,
                    event_type: "navigation".to_owned(),
                    url: "https://hooks.example.test/forged".to_owned(),
                    status: crawlx_storage::DeliveryStatus::Pending,
                    attempts: 0,
                    next_attempt_at: now,
                    delivered_at: None,
                    last_status: None,
                    last_error: None,
                })
                .await,
            );
            // linking another tenant's run to an idempotency key of this tenant
            api.idem_link_run(b.tenant, &b.idem_key, a.run).await.ok();
            // intel rows that name another tenant, another tenant's monitor or check
            refused(
                "job_insert",
                store
                    .job_insert(&JobRecord {
                        id: Uuid::now_v7(),
                        tenant: a.tenant,
                        kind: JobKind::Agent,
                        status: JobStatus::Processing,
                        request: json!({}),
                        result: None,
                        error: None,
                        stop_reason: None,
                        tokens_used: 0,
                        credits_used: 0,
                        thread_id: None,
                        created_at: now,
                        updated_at: now,
                        finished_at: None,
                        expires_at: now,
                    })
                    .await,
            );
            let forged_check = CheckRecord {
                id: Uuid::now_v7(),
                monitor: ai.monitor,
                tenant: b.tenant,
                trigger: "manual".to_owned(),
                state: CheckState::Running,
                status: None,
                summary: json!({}),
                error: None,
                started_at: now,
                finished_at: None,
                expires_at: now,
            };
            refused(
                "check_insert (foreign monitor)",
                store.check_insert(&forged_check).await,
            );
            refused(
                "check_insert (foreign tenant)",
                store
                    .check_insert(&CheckRecord {
                        tenant: a.tenant,
                        ..forged_check.clone()
                    })
                    .await,
            );
            refused(
                "check_pages_put",
                store
                    .check_pages_put(&[CheckPage {
                        check: ai.check,
                        target_id: "t1".to_owned(),
                        url: "https://app.example.test/forged".to_owned(),
                        status: "new".to_owned(),
                        data: json!({}),
                    }])
                    .await,
            );
            refused(
                "baselines_put",
                store
                    .baselines_put(&[Baseline {
                        monitor: ai.monitor,
                        url: "https://app.example.test/forged".to_owned(),
                        digest: "forged".to_owned(),
                        markdown: "x".to_owned(),
                        seen_at: now,
                    }])
                    .await,
            );
            refused(
                "usage_record",
                store
                    .usage_record(&UsageEvent {
                        tenant: a.tenant,
                        at: now,
                        endpoint: "extract".to_owned(),
                        ref_id: None,
                        status: "forged".to_owned(),
                        credits: 99,
                        prompt_tokens: 0,
                        completion_tokens: 0,
                    })
                    .await,
            );
            refused(
                "setting_put",
                store.setting_put(a.tenant, "forged", json!(1), now).await,
            );
            let _ = bi;
        }
        .await)
    })
    .await;
    // none of it landed in tenant A
    let op = &w.harness.operator;
    assert_eq!(
        op.count("api_keys", &format!("tenant_id = {}", op.id(a.tenant.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "authorization_records",
            &format!("tenant_id = {}", op.id(a.tenant.0))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count("webhook_deliveries", &format!("run_id = {}", op.id(a.run.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("intel_jobs", &format!("tenant_id = {}", op.id(a.tenant.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("monitor_checks", &format!("tenant_id = {}", op.id(a.tenant.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("monitor_check_pages", &format!("check_id = {}", op.id(ai.check)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "monitor_baselines",
            &format!("monitor_id = {}", op.id(ai.monitor))
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        op.count("usage_ledger", &format!("tenant_id = {}", op.id(a.tenant.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count("tenant_settings", &format!("tenant_id = {}", op.id(a.tenant.0)))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        op.count(
            "idempotency_keys",
            &format!(
                "tenant_id = {} AND run_id = {}",
                op.id(b.tenant.0),
                op.id(a.run.0)
            )
        )
        .await
        .unwrap(),
        0
    );
    w.harness.finish().await.unwrap();
}

// ---- P6 -----------------------------------------------------------------------------------

/// With `unscoped-for-test` the tenant guard is off (on PostgreSQL the request handle is the
/// table owner, which row-level security does not bind): the cross-tenant sweep must fail.
#[cfg(feature = "unscoped-for-test")]
async fn isolation_proofs_fail_without_the_guard(rig: &Rig) {
    use futures::FutureExt as _;
    let w = world(rig).await;
    let outcome = std::panic::AssertUnwindSafe(cross_tenant_sweep(&w))
        .catch_unwind()
        .await;
    assert!(
        outcome.is_err(),
        "the isolation sweep passed with the tenant guard disabled"
    );
    w.harness.finish().await.unwrap();
}

#[allow(dead_code, reason = "kept for the sweep's own-tenant probes")]
fn unused(_: CrawlRunId, _: ApprovalId) {}
