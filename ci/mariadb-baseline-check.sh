#!/usr/bin/env bash
# Applies the MariaDB baseline and every later migration twice to a fresh database
# with the `mariadb` client and checks the result:
#   * filenames are strictly increasing and their latest version matches PostgreSQL;
#   * all three engines have the same migration version set from 0047 onward;
#   * every table has a `-- from: NNNN` (ported) or `-- new:` (added by this backend) comment;
#   * the second application changes nothing (schema fingerprint identical);
#   * exactly the expected base tables, sequences, views and triggers exist.
#
# The server is chosen by CRAWLX_TEST_MARIADB_URL (mysql://user:password@host:port/anydb); the
# default is the local test server. The login needs CREATE/DROP DATABASE: the script creates a
# scratch database named crawlx_baseline_check_<pid> and drops it on exit (KEEP_DB=1 keeps it).
# Percent-encoding in the URL is not decoded. Requires MariaDB 10.6 or newer (sequences, SKIP LOCKED).
#
# Compound trigger statements in the migrations contain semicolons and no DELIMITER line (the
# migration runner sends each file as one multi-statement request); this script wraps every
# `CREATE [OR REPLACE] TRIGGER` .. `END;` block in DELIMITER lines for the client. A trigger body
# therefore ends with a line that is exactly `END;` and has no nested BEGIN block.
#
# Usage: ci/mariadb-baseline-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

url="${CRAWLX_TEST_MARIADB_URL:-mysql://crawlx:crawlx@127.0.0.1:3317/crawlx_test}"
re='^(mysql|mariadb)://([^:@/]*)(:([^@/]*))?@([^:/?]*)(:([0-9]+))?(/[^?]*)?(\?.*)?$'
if ! [[ $url =~ $re ]]; then
  echo "mariadb-baseline-check: CRAWLX_TEST_MARIADB_URL is not mysql://user:password@host:port/db" >&2
  exit 2
fi
user="${BASH_REMATCH[2]}"
password="${BASH_REMATCH[4]}"
host="${BASH_REMATCH[5]}"
port="${BASH_REMATCH[7]:-3306}"

if ! command -v mariadb >/dev/null 2>&1; then
  echo "mariadb-baseline-check: the mariadb client is not installed" >&2
  exit 2
fi

dir=crates/crawlx-storage/migrations/mariadb
pg_dir=crates/crawlx-storage/migrations
db="crawlx_baseline_check_$$"
export MYSQL_PWD="$password"
client=(mariadb --no-defaults --batch --skip-column-names --protocol=tcp -h"$host" -P"$port" -u"$user" --skip-ssl)

cleanup() {
  if [ "${KEEP_DB:-0}" != 1 ]; then
    "${client[@]}" -e "DROP DATABASE IF EXISTS \`$db\`" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

fail=0
bad() { echo "mariadb-baseline-check: $*" >&2; fail=1; }

# --- 1. file naming and cross-engine versions -----------------------------------------------
migration_versions() {
  local directory=$1 file base version previous=-1
  for file in "$directory"/*.sql; do
    base=${file##*/}
    if ! [[ $base =~ ^([0-9]{4})_[a-z0-9_]+\.sql$ ]]; then
      echo "mariadb-baseline-check: invalid migration filename in $directory" >&2
      return 1
    fi
    version=$((10#${BASH_REMATCH[1]}))
    if [ "$version" -le "$previous" ]; then
      echo "mariadb-baseline-check: duplicate or unordered migration version in $directory" >&2
      return 1
    fi
    previous=$version
    if [ "$version" -ge 47 ]; then printf '%04d\n' "$version"; fi
  done
}
pg_versions=$(migration_versions "$pg_dir")
for engine in sqlite mariadb; do
  engine_versions=$(migration_versions "$pg_dir/$engine")
  [ "$pg_versions" = "$engine_versions" ] || bad "$engine migration versions differ from PostgreSQL from 0047"
done
files=("$dir"/*.sql)
pg_files=("$pg_dir"/*.sql)
latest_pg=${pg_files[${#pg_files[@]}-1]##*/}
latest_pg=${latest_pg%%_*}
latest_engine=${files[${#files[@]}-1]##*/}
latest_engine=${latest_engine%%_*}
[ "$latest_engine" = "$latest_pg" ] || bad "last migration version is $latest_engine, want PostgreSQL version $latest_pg"

# --- 2. every table is annotated -------------------------------------------------------------
for f in "${files[@]}"; do
  awk -v file="$f" '
    /^-- (from|new):/ { marker = 1 }
    /^CREATE TABLE IF NOT EXISTS / && !marker {
      printf "mariadb-baseline-check: %s: table %s lacks a `-- from: NNNN` or `-- new:` comment\n", file, $6 > "/dev/stderr"
      status = 1
    }
    /;[[:space:]]*$/ && !/^[[:space:]]*--/ { marker = 0 }
    END { exit status }
  ' "$f" || fail=1
done

# --- 3. client-side wrapping of trigger blocks -------------------------------------------------
wrap() {
  awk '
    !in_trigger && /^CREATE (OR REPLACE )?TRIGGER / { print "DELIMITER //"; in_trigger = 1; print; next }
    in_trigger && $0 == "END;" { print "END//"; print "DELIMITER ;"; in_trigger = 0; next }
    { print }
    END { if (in_trigger) { print "unterminated trigger block" > "/dev/stderr"; exit 1 } }
  ' "$1"
}

apply_all() {
  local f
  for f in "${files[@]}"; do
    if ! wrap "$f" | "${client[@]}" "$db"; then
      echo "mariadb-baseline-check: applying $(basename "$f") failed" >&2
      exit 1
    fi
  done
}

# --- 4. fresh database, server version -------------------------------------------------------
version_line=$("${client[@]}" -e "SELECT VERSION()")
case "$version_line" in
  *MariaDB*) ;;
  *) echo "mariadb-baseline-check: server $version_line is not MariaDB" >&2; exit 1 ;;
esac
major=${version_line%%.*}
rest=${version_line#*.}
minor=${rest%%.*}
if [ "$major" -lt 10 ] || { [ "$major" -eq 10 ] && [ "$minor" -lt 6 ]; }; then
  echo "mariadb-baseline-check: MariaDB 10.6 or newer is required (found $version_line)" >&2
  exit 1
fi
echo "server: $version_line"
"${client[@]}" -e "CREATE DATABASE \`$db\` CHARACTER SET utf8mb4 COLLATE utf8mb4_nopad_bin"

# Everything that identifies the schema: columns, indexes, constraints, triggers, routines.
fingerprint() {
  "${client[@]}" "$db" -e "
    SELECT table_name, column_name, column_type, is_nullable, IFNULL(column_default, '-'), extra, IFNULL(generation_expression, '-'), collation_name
      FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY 1, 2;
    SELECT table_name, index_name, seq_in_index, column_name, non_unique, IFNULL(sub_part, 0)
      FROM information_schema.statistics WHERE table_schema = DATABASE() ORDER BY 1, 2, 3;
    SELECT table_name, constraint_name, check_clause FROM information_schema.check_constraints
      WHERE constraint_schema = DATABASE() ORDER BY 1, 2;
    SELECT table_name, constraint_name, referenced_table_name, update_rule, delete_rule
      FROM information_schema.referential_constraints WHERE constraint_schema = DATABASE() ORDER BY 1, 2;
    SELECT trigger_name, event_object_table, action_timing, event_manipulation, action_statement
      FROM information_schema.triggers WHERE trigger_schema = DATABASE() ORDER BY 1;
    SELECT table_name, view_definition, security_type FROM information_schema.views
      WHERE table_schema = DATABASE() ORDER BY 1;
    SELECT * FROM audit_chain_head;
    SELECT \`key\`, value FROM cluster_settings ORDER BY 1;" | sha256sum | cut -d' ' -f1
}

# --- 5. apply twice, compare -----------------------------------------------------------------
apply_all
first=$(fingerprint)
apply_all
second=$(fingerprint)
if [ "$first" != "$second" ]; then
  bad "the second application changed the schema (fingerprint $first -> $second)"
else
  echo "idempotent: yes (fingerprint $first)"
fi

# --- 6. expected objects ----------------------------------------------------------------------
# The PostgreSQL migration set is authoritative; exclude partition children.
mapfile -t expected_pg_tables < <(awk '
  toupper($1) == "CREATE" && toupper($2) == "TABLE" {
    if (toupper($0) ~ / PARTITION OF /) next
    name = toupper($3) == "IF" ? $6 : $3
    sub(/\(.*/, "", name)
    gsub(/"/, "", name)
    sub(/^public\./, "", name)
    print name
  }
' "$pg_dir"/*.sql | sort -u)
[ "${#expected_pg_tables[@]}" -gt 0 ] || { echo "mariadb-baseline-check: no PostgreSQL tables found" >&2; exit 1; }
expected_tables=("${expected_pg_tables[@]}" audit_chain_head crawlx_locks)
expected_sequences=(lease_fence_seq run_bootstrap_producer_fence)
expected_views=(run_errors trusted_reachable_states)

list() { "${client[@]}" -e "SELECT table_name FROM information_schema.tables WHERE table_schema = '$db' AND table_type = '$1' ORDER BY 1"; }
compare() { # kind, expected...
  local kind=$1 label=$2
  shift 2
  local want got
  want=$(printf '%s\n' "$@" | LC_ALL=C sort)
  got=$(list "$kind" | LC_ALL=C sort)
  if [ "$want" != "$got" ]; then
    bad "$label differ:"
    diff <(echo "$want") <(echo "$got") | sed 's/^/    /' >&2 || true
  else
    echo "$label: $(echo "$want" | grep -c .)"
  fi
}
compare 'BASE TABLE' 'base tables' "${expected_tables[@]}"
compare 'SEQUENCE' 'sequences' "${expected_sequences[@]}"
compare 'VIEW' 'views' "${expected_views[@]}"


want_triggers=$(awk '
  /^CREATE OR REPLACE TRIGGER / { print $5 }
  /^CREATE TRIGGER / { print $3 }
' "${files[@]}" | tr -d '`' | sort -u)
got_triggers=$("${client[@]}" -e "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema = '$db' ORDER BY trigger_name")
if [ "$want_triggers" != "$got_triggers" ]; then
  bad "trigger names differ from migration declarations"
  diff <(printf '%s\n' "$want_triggers") <(printf '%s\n' "$got_triggers") >&2 || true
else
  echo "triggers: $(printf '%s\n' "$got_triggers" | wc -l)"
fi

seed=$("${client[@]}" "$db" -e "SELECT id, HEX(entry_hash) FROM audit_chain_head")
[ "$seed" = "$(printf '1\t%064d' 0)" ] || bad "audit_chain_head is not seeded with 32 zero bytes: $seed"
admission=$("${client[@]}" "$db" -e "SELECT value FROM cluster_settings WHERE \`key\` = 'scheduler.admission'")
[ "$admission" = open ] || bad "cluster_settings is not seeded with scheduler.admission=open"

if [ "$fail" -ne 0 ]; then
  echo "mariadb-baseline-check: FAILED" >&2
  exit 1
fi
echo "mariadb-baseline-check: ok"
