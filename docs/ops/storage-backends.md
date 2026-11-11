# Storage backends

CrawlX keeps its system of record (runs, frontier, pages, journal, ledger, datasets, audit chain,
archive catalog, artifact catalog) in one database. Three engines are supported; the engine is
chosen by the scheme of the database URL and nothing else:

| Engine | URL | Server | Intended use |
|---|---|---|---|
| PostgreSQL | `postgres://user:password@host:5432/crawlx` (`postgresql://` too) | 14 or newer | production, several workers and API replicas, database-enforced tenant isolation |
| MariaDB | `mysql://user:password@host:3306/crawlx` (`mariadb://` too) | 10.6 or newer | several workers, application-enforced tenant isolation |
| SQLite | `sqlite:///var/lib/crawlx/crawlx.sqlite` (`sqlite:relative.db` too) | bundled | one host, one worker, evaluation and small deployments |

Any other scheme is refused with `refused: scheme: unsupported database url scheme; expected
postgres, mariadb or sqlite`. The URL is read from `--database-url`, `CRAWLX_DATABASE_URL`,
`CRAWLX_DATABASE_URL_FILE` (the production path, a file with the URL) or `database.url_file` of
`crawlx.toml`. Credentials never appear in logs or error text: diagnostics print the scheme, host,
port and database (or the file path) only.

`crawlx migrate` runs the migrator of the selected engine and creates a missing SQLite file. Every
migration exists once per engine and the three schemas are kept in lock step
(`ci/lint-migrations.sh`). `serve` migrates on start; `worker`, `crawl --database-url` and the
operator commands expect a migrated database (run `crawlx migrate` first).

## What each engine provides

| Capability | PostgreSQL | MariaDB | SQLite |
|---|---|---|---|
| Runs, frontier, pages, journal, state graph, ledger, events, checkpoints, datasets, selectors, archive catalog, audit chain with Merkle export | yes | yes | yes |
| Fenced leases, reaper, round-robin barrier | yes | yes | yes |
| More than one worker process on one database | yes | yes | **no** (`sqlite_second_worker`) |
| API and worker processes at the same time | yes | yes | yes, on the same host and file |
| API and worker on different hosts | yes | yes | **no** (`sqlite_not_local`) |
| Per-origin capacity and pacing across workers | database (advisory locks) | database (row-lock slots) | in the worker process (valid: there is one) |
| Tenant isolation | row-level security, restricted request login, application predicate | application predicate and fail-closed request handle | application predicate and fail-closed request handle |
| Restricted request login (`CRAWLX_API_DATABASE_URL`) | required in production | not available yet (`backend_unimplemented`) | **no** (`sqlite_no_roles`) |
| Several tenants in staging or production | yes | yes | only with `CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1` (`sqlite_multi_tenant`) |
| Independent safety auditor (`crawlx admin safety-audit`) | yes | **no** | **no** (`sqlite_safety_auditor`) |
| Zero-data-retention confidentiality | trigger and Rust | Rust and validator triggers | Rust and validator triggers |
| Traffic partitions | monthly | plain table | plain table |
| Sealed (encrypted) artifacts, key file or KMS | yes | yes | yes |
| S3-compatible artifact store | yes | yes | yes |
| `crawlx archive export`, `profiles`, `replay-response`, `reparse`, `inspect`, `admin` | yes | yes | yes |

Artifact encryption and the artifact store are independent of the database: sealed artifacts,
the key provider (`CRAWLX_ARTIFACT_KEY_FILE` or `CRAWLX_ARTIFACT_KMS_KEY_ID`) and the volatile
secret registry (`CRAWLX_SECRET_REDIS_URL`) are required for `serve` and `worker` on every engine.
Without them startup is refused with `refused: custody_missing: encrypted artifact custody is not
configured: ...`.

## Pool size and statement timeout

`database.pool_max` (default 32) is the pool size on every engine; on SQLite it bounds the readers
(there is one writer, serialised in the process).

`database.statement_timeout_ms` (default 5000) is applied to every pooled connection except
those of `crawlx migrate`, whose schema changes and migration lock wait are not bounded:

* PostgreSQL sets `statement_timeout`.
* MariaDB sets `max_statement_time` for the session; it bounds statements that read.
* SQLite has no server-side statement timeout. A `statement_timeout_ms` other than the default
  with a `sqlite:` URL is **refused** (`crawlx config check`, `serve`, `worker` and every operator
  command) instead of being ignored:
  `database.statement_timeout_ms is <n> but sqlite has no server-side statement timeout; remove
  the setting or use postgres or mariadb`. Lock waits on SQLite are bounded by the busy timeout
  (5 s).

## Refusals

Refusals are raised before anything is served or leased and print as
`refused: <code>: <message>`. Tests assert the text.

| Code | When | Fix |
|---|---|---|
| `scheme` | unknown URL scheme | use `postgres://`, `mysql://` or `sqlite:` |
| `sqlite_second_worker` | a second `crawlx worker` (or any process that takes the worker lock) opens a SQLite file already held through `<file>.worker.lock` | run one worker, or use MariaDB or PostgreSQL |
| `sqlite_not_local` | the SQLite file is on a network or unsupported file system (WAL needs shared memory on one host), or the database is `:memory:` outside tests | use a local path |
| `sqlite_no_roles` | `CRAWLX_API_DATABASE_URL` (or `api_database_url`) next to a SQLite `database_url` | remove it; the API uses the same file |
| `sqlite_multi_tenant` | `CRAWLX_ENVIRONMENT` is `staging` or `prod` and a second tenant exists or is about to be created (`serve --api-key`, tenant registration) | set `CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1` to accept application-only isolation, or use PostgreSQL |
| `sqlite_safety_auditor` | `crawlx admin safety-audit` with SQLite URLs; the Helm chart refuses to render with `safetyAuditor.enabled` on SQLite (and on MariaDB, with `backend_unimplemented`) | the auditor needs two database identities; disable it or use PostgreSQL |
| `mariadb_unsupported_server` | the server is not MariaDB, or older than 10.6 | upgrade |
| `mariadb_multi_primary` | `wsrep_on` is on | use a single primary |
| `mariadb_settings` | `sysdate_is_now`, `binlog_format=STATEMENT` with the binary log on, or a default row format other than DYNAMIC | fix the server setting named in the message |
| `mariadb_request_login` | the request login holds DDL, `SUPER`, `FILE` or `GRANT OPTION`, privileges on global tables, or `UPDATE`/`DELETE` on `audit_events` | revoke the privilege |
| `custody_missing` | `serve` or `worker` without key provider and secret registry | configure both |
| `backend_unimplemented` | a capability the selected engine does not have yet, for example a restricted request login on MariaDB or the safety auditor on MariaDB | use the engine the message names |

Operator commands that read run data (`inspect`, `admin`, `archive export`, `profiles`,
`replay-response`, `reparse`) work on all three engines. They open an existing database and never
create one: a mistyped SQLite path fails with `connecting to the database: ...` instead of making
an empty file. `crawlx config check` reports the preconditions it can evaluate without a server:
unknown scheme, an in-memory SQLite database (`sqlite_not_local`), `sqlite_no_roles` and a non-default `database.statement_timeout_ms` with a SQLite URL.

## Object store

Artifacts live in the filesystem (`--artifacts-dir`) or in an S3-compatible bucket, independently of
the database engine. Set `CRAWLX_S3_BUCKET` (and `CRAWLX_S3_PROFILE`, endpoint, region, ...) for
`serve`, `worker` and `crawl --database-url`; the profiles `standard`, `compatible`, `edge` and
`self-hosted`, their defaults and refusals are in [object-storage.md](object-storage.md). With a
bucket set, nothing is written under `--artifacts-dir`. `serve` and `worker` must name the same
bucket.

## Deployment

### Docker Compose

`docker/docker-compose.yml` is the PostgreSQL stack. Two overlays replace the database:

```sh
docker/init-compose.sh --engine mariadb      # or sqlite; writes the engine's secrets once
docker compose -f docker/docker-compose.yml -f docker/compose.mariadb.yml up -d --build --wait
docker compose -f docker/docker-compose.yml -f docker/compose.sqlite.yml  up -d --build --wait
```

* `compose.mariadb.yml` adds a `mariadb:11.4` service (utf8mb4, `innodb_default_row_format=dynamic`,
  `binlog_format=ROW`, `READ COMMITTED`), points `migrate`, `api`, `worker` and `admin` at
  `secrets/database_url_mariadb`, and drops the restricted request login from `api`. Workers may be
  scaled.
* `compose.sqlite.yml` has no database service. The file `/var/lib/crawlx/db/crawlx.sqlite` lives on
  the `dbdata` volume shared by `migrate`, `api`, `worker` and `admin`; the stack is single host and
  the `worker` service is pinned to one replica. Do not scale it.

Both move the PostgreSQL service and its role provisioning into the `postgres-engine` profile,
which the overlays never enable. The independent safety auditor and `compose` smoke checks that
read PostgreSQL directly (`ci/compose-smoke.sh`) apply to the PostgreSQL stack only.

### Helm

`storage.engine` (`postgres`, `mariadb` or `sqlite`) selects the engine. The `database_url`
secret holds the matching URL. The chart renders nothing and prints the refusal when a rule is
broken:

* `mariadb` and `sqlite` need `safetyAuditor.enabled=false`; the API gets no request-login secret.
* `sqlite` needs `storage.sqlite.existingClaim` (a ReadWriteOnce volume, mounted at
  `/var/lib/crawlx/db` in the API, the worker and the migrate job), `api.replicas=1`,
  `worker.replicas=1` and `worker.canary.enabled=false`.
* `networkPolicy.databaseSelector` and `storage.port` select the database pods and port (5432 or 3306
  by default); SQLite pods get no database egress rule.

`deploy/k8s` holds plain PostgreSQL-only manifests.

### Monitoring

`CrawlxReplicationLag` reads `pg_replication_lag_seconds` and exists on PostgreSQL deployments only;
MariaDB replication is monitored with the operator's own MariaDB exporter.

## Tests

`CRAWLX_TEST_DATABASE_URL` (PostgreSQL) and `CRAWLX_TEST_MARIADB_URL` (MariaDB) point the
conformance suite and the database-gated tests at a server; SQLite needs nothing. Tests skip when
a variable is absent. Each test uses its own schema (PostgreSQL) or database (MariaDB) or file
(SQLite).
