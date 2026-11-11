#!/usr/bin/env bash
# SQLite schema parity helper. Applies the level-0046 baseline and every later SQLite
# migration to a fresh database with foreign keys enabled, then checks that
#   * every migration applies without error,
#   * PostgreSQL, SQLite and MariaDB declare the same migration versions from 0047,
#   * every PostgreSQL base table exists (and no unlisted table does), all of them STRICT,
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

# Derive the authoritative base-table set; partition children are not base tables.
PG_TABLES=$(awk '
  toupper($1) == "CREATE" && toupper($2) == "TABLE" {
    if (toupper($0) ~ / PARTITION OF /) next
    name = toupper($3) == "IF" ? $6 : $3
    sub(/\(.*/, "", name)
    gsub(/"/, "", name)
    sub(/^public\./, "", name)
    print name
  }
' "$PG_MIGRATIONS"/*.sql | sort -u)
[ -n "$PG_TABLES" ] || { echo "sqlite-baseline-check: no PostgreSQL tables found" >&2; exit 1; }
# Tables that exist only on SQLite (sequence rows and the audit chain head).
SQLITE_TABLES="audit_chain_head crawlx_sequences"

fail=0
note() { echo "sqlite-baseline-check: $*" >&2; fail=1; }

expected_pg=$(printf '%s\n' $PG_TABLES | sort)
expected_all=$(printf '%s\n' $PG_TABLES $SQLITE_TABLES | sort)

pg_count=$(printf '%s\n' "$expected_pg" | wc -l)

# Strict names and unique versions also reject duplicate or unrecognized migrations.
migration_versions() {
  local directory=$1 file base version previous=-1
  for file in "$directory"/*.sql; do
    base=${file##*/}
    if ! [[ $base =~ ^([0-9]{4})_[a-z0-9_]+\.sql$ ]]; then
      echo "sqlite-baseline-check: invalid migration filename in $directory" >&2
      return 1
    fi
    version=$((10#${BASH_REMATCH[1]}))
    if [ "$version" -le "$previous" ]; then
      echo "sqlite-baseline-check: duplicate or unordered migration version in $directory" >&2
      return 1
    fi
    previous=$version
    if [ "$version" -ge 47 ]; then printf '%04d\n' "$version"; fi
  done
}
pg_versions=$(migration_versions "$PG_MIGRATIONS")
for engine in sqlite mariadb; do
  engine_versions=$(migration_versions "$PG_MIGRATIONS/$engine")
  [ "$pg_versions" = "$engine_versions" ] || note "$engine migration versions differ from PostgreSQL from 0047"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
db="$work/baseline.db"

if ! {
  echo 'PRAGMA foreign_keys = ON;'
  cat "$BASELINE"
  for migration in "$PG_MIGRATIONS/sqlite"/*.sql; do
    name=${migration##*/}
    version=${name%%_*}
    if [ "$((10#$version))" -ge 47 ]; then cat "$migration"; fi
  done
} | sqlite3 -bail "$db"; then
  echo "sqlite-baseline-check: baseline or later migration failed to apply" >&2
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
