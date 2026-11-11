#!/usr/bin/env bash
# SQLite baseline parity helper. Applies crates/crawlx-storage/migrations/sqlite/0046_baseline.sql
# to a fresh database with the sqlite3 CLI (foreign keys on) and checks that
#   * the file applies without error,
#   * every PostgreSQL base table exists (and no unlisted table does), all of them STRICT,
#   * every `CREATE TABLE` of the PostgreSQL migrations is in the expected list, so a new
#     PostgreSQL table fails this check until the SQLite baseline (or a later SQLite migration
#     list entry) covers it,
#   * PRAGMA integrity_check is `ok` and PRAGMA foreign_key_check is empty,
#   * the seed rows and the status-machine trigger behave as the storage layer expects.
#
# Usage: ci/sqlite-baseline-check.sh [path/to/baseline.sql]
# Needs: sqlite3 >= 3.42 (STRICT tables, pragma_table_list.strict, unixepoch('subsec')).
set -euo pipefail
export LC_ALL=C

cd "$(dirname "$0")/.."

BASELINE="${1:-crates/crawlx-storage/migrations/sqlite/0046_baseline.sql}"
PG_MIGRATIONS=crates/crawlx-storage/migrations

command -v sqlite3 >/dev/null || { echo "sqlite-baseline-check: sqlite3 not found" >&2; exit 2; }
[ -f "$BASELINE" ] || { echo "sqlite-baseline-check: $BASELINE not found" >&2; exit 2; }

# The 64 base tables of the PostgreSQL schema at level 46 (traffic_events_default is a partition
# child of traffic_events, not a base table).
PG_TABLES="action_contexts actions adaptive_selectors api_keys approvals archive_dependencies
archive_exports archive_history archive_records artifact_key_custody artifacts audit_events
authorization_records browser_profiles checkpoints cluster_settings crawl_events crawl_runs
crawl_sessions dataset_delivery_outbox dataset_items dataset_kv dataset_kv_drops datasets elements
enablement_edges frontier_batch_receipts frontier_loader_cursors frontier_producers
idempotency_keys identity_aliases intel_jobs intel_snapshots intel_threads intel_trace
model_decisions monitor_baselines monitor_check_pages monitor_checks monitors network_epochs
origin_admission origin_leases page_captures pages run_artifact_exposures run_bootstrap_producers
run_custody_producers run_secret_authority run_secret_authority_renewals safety_decisions
session_bindings state_cluster_membership state_clusters states tenant_settings tenants
traffic_events transitions url_frontier usage_ledger webhook_deliveries workers workflow_runs"
# Tables that exist only on SQLite (sequence rows and the audit chain head).
SQLITE_TABLES="audit_chain_head crawlx_sequences"

fail=0
note() { echo "sqlite-baseline-check: $*" >&2; fail=1; }

expected_pg=$(printf '%s\n' $PG_TABLES | sort)
expected_all=$(printf '%s\n' $PG_TABLES $SQLITE_TABLES | sort)

pg_count=$(printf '%s\n' "$expected_pg" | wc -l)
if [ "$pg_count" -ne 64 ]; then
  note "expected list has $pg_count PostgreSQL tables, want 64"
fi

# Every table the PostgreSQL migrations create (minus the partition child) must be listed.
if [ -d "$PG_MIGRATIONS" ]; then
  from_migrations=$(grep -hoE '^CREATE TABLE [a-z_]+' "$PG_MIGRATIONS"/*.sql | awk '{print $3}' \
    | grep -vx traffic_events_default | sort -u)
  missing=$(comm -13 <(printf '%s\n' "$expected_pg") <(printf '%s\n' "$from_migrations"))
  stale=$(comm -23 <(printf '%s\n' "$expected_pg") <(printf '%s\n' "$from_migrations"))
  [ -z "$missing" ] || note "PostgreSQL tables missing from the expected list: $(echo $missing)"
  [ -z "$stale" ] || note "expected list names tables no PostgreSQL migration creates: $(echo $stale)"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
db="$work/baseline.db"

if ! { echo 'PRAGMA foreign_keys = ON;'; cat "$BASELINE"; } | sqlite3 -bail "$db"; then
  echo "sqlite-baseline-check: $BASELINE failed to apply" >&2
  exit 1
fi

actual=$(sqlite3 "$db" "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")
missing=$(comm -13 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected_all"))
extra=$(comm -23 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected_all"))
[ -z "$missing" ] || note "tables missing from the baseline: $(echo $missing)"
[ -z "$extra" ] || note "unexpected tables in the baseline: $(echo $extra)"

not_strict=$(sqlite3 "$db" "SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND strict = 0 AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'")
[ -z "$not_strict" ] || note "tables that are not STRICT: $(echo $not_strict)"

integrity=$(sqlite3 "$db" 'PRAGMA integrity_check')
[ "$integrity" = ok ] || note "integrity_check: $integrity"
fk=$(sqlite3 "$db" 'PRAGMA foreign_key_check')
[ -z "$fk" ] || note "foreign_key_check reported rows: $fk"

# Seed rows.
seeds=$(sqlite3 "$db" "
  SELECT (SELECT count(*) FROM crawlx_sequences WHERE name IN
            ('lease_fence_seq','run_bootstrap_producer_fence','actions.dataset_page','run_custody_producers.fence') AND v = 0),
         (SELECT count(*) FROM audit_chain_head WHERE id = 1 AND entry_hash = zeroblob(32)),
         (SELECT count(*) FROM cluster_settings WHERE key = 'scheduler.admission' AND value = 'open')")
[ "$seeds" = "4|1|1" ] || note "seed rows: got $seeds, want 4|1|1"

# Status machine: legal step passes, illegal step carries the exact message the error mapper parses.
probe=$(sqlite3 "$db" "
PRAGMA foreign_keys = ON;
INSERT INTO tenants (tenant_id, name, kms_key_id) VALUES (x'01', 't', 'k');
INSERT INTO crawl_runs (run_id, tenant_id, mode, seed, safety_profile, policy_version, identity_version,
  state_algo_version, query_classifier_version, config, config_digest, retention_mode, retention_days)
  VALUES (x'02', x'01', 'static', 1, 'read_only', 1, 1, 1, 1, '{}', x'00', 'standard', 7);
INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot) VALUES (x'03', x'02', 'r', 0, 0);
INSERT INTO action_contexts (run_id, context_hash, principal, route_template, identity_hash, identity_version,
  action_kind, state_cluster_id) VALUES (x'02', x'00', 'p', 'r', x'00', 1, 'click', x'00');
INSERT INTO safety_decisions (decision_id, run_id, risk_class, verdict, profile, rules, evidence, policy_version)
  VALUES (x'04', x'02', 'navigation_reveal', 'allow', 'read_only', '[]', '{}', 1);
INSERT INTO actions (action_id, run_id, session_id, seq, context_id, action_kind, strategy, strategy_version,
  epoch_navigation, epoch_document, epoch_mutation, fidelity, lane, safety_decision_id, dataset_page)
  VALUES (x'05', x'02', x'03', 1, 1, 'scroll', 's', 1, 0, 0, 0, 'scripted_scroll', 'diagnostic', x'04', 1);
UPDATE actions SET status = 'intended';
UPDATE actions SET status = 'proposed';
" 2>&1 || true)
case "$probe" in
  *"illegal actions.status transition intended -> proposed"*) ;;
  *) note "status machine probe did not raise the expected message: $probe" ;;
esac

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "sqlite-baseline-check: ok ($pg_count PostgreSQL tables + $(echo $SQLITE_TABLES | wc -w) SQLite-only tables)"
