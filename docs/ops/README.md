# Operations

Operator documentation for running CrawlX outside a development checkout. CrawlX is pre-1.0 and
production qualification is in progress; see the [README](../../README.md#release-status).

## Index

| File | Purpose |
|---|---|
| [`runbooks.md`](runbooks.md) | Numbered runbooks RB-01 to RB-12 (stuck crawl, unknown-outcome reconciliation, browser crash loop, lease storm, model provider failure, object-store outage, database failover, retention and ZDR cleanup, webhook backlog, hot target, emergency stop, SEV-1 containment), one card per alert rule, the `crawlx admin` command table, the independent safety auditor, backup, restore and rollback |
| [`release-gates.md`](release-gates.md) | The release-gate checklist computed by CI from evidence files (`release-gate check`), its items, thresholds, evidence layout and waivers |
| [`flaky-tests.md`](flaky-tests.md) | Flake handling: one classifying rerun, quarantine to the nightly suite after 3 events in 14 days, the 30-day flake rate and the `flake-report` tool |
| [`storage-backends.md`](storage-backends.md) | Database engines (PostgreSQL, MariaDB, SQLite): URLs, what each provides, pool size and statement timeout, startup refusals, Compose overlays, chart values |
| [`backends.md`](backends.md) | Backend support matrix (relational, object store, Valkey/Redis, search, ClickHouse, Kafka, RabbitMQ), namespacing on shared instances and the new delivery destination kinds |
| [`object-storage.md`](object-storage.md) | Filesystem and S3-compatible store profiles, credentials, admission and deployment checks |
| This file | Provisioning, validation and rotation of the optional operator capabilities (request-identity key, protocol and delivery registries, language bundle) |

## Where the pieces are

| Need | Look at |
|---|---|
| Alert rules (32) | [`deploy/alerts/crawlx-rules.yaml`](../../deploy/alerts/crawlx-rules.yaml) |
| Dashboards | [`deploy/dashboards/crawlx.json`](../../deploy/dashboards/crawlx.json) |
| Deployment | [`deploy/helm/crawlx/`](../../deploy/helm/crawlx/Chart.yaml), [`deploy/k8s/`](../../deploy/k8s/README.md), [`docker/`](../../docker/) |
| Operator commands | `crawlx admin ...`, `crawlx inspect trail <run-id>`, `crawlx healthcheck`, `crawlx config check`, `crawlx migrate`; the command table is in [`runbooks.md`](runbooks.md#before-any-runbook) |
| Runbooks, backup, restore, rollback | [`runbooks.md`](runbooks.md) |
| Safety, retention and secret behavior | [`../design/safety-model.md`](../design/safety-model.md), [`../design/data-and-secrets.md`](../design/data-and-secrets.md) |

## Storage engines

PostgreSQL, MariaDB and SQLite all run `serve`, `worker`, `migrate`, `inspect` and the
`admin` commands; the engine is chosen by the scheme of the database URL. What each engine
provides, and what it refuses, is in [`storage-backends.md`](storage-backends.md). On
PostgreSQL, API requests require a restricted non-owner login; provision its grants with
[`docker/provision-api-role.sql`](../../docker/provision-api-role.sql) after migrations.
Never use the migration/worker owner login as the API request login. Unknown schemes
return `refused: scheme`. No command silently substitutes an in-memory repository.

Foreground `crawlx crawl` needs no database and writes its local output directory.
Without a database, `crawlx serve` keeps queued runs only in its own process: it
does not execute them, a separate worker cannot see them, and exiting loses them.
The health readiness response in this mode checks the in-memory store, not worker
availability or durable storage.

## API keys, admission and rate limits

Native keys are `cx_live_` followed by exactly 26 characters from lowercase `a-z`
and digits `2-7`. With `--compat-keys`, an `fc-` key containing 16 to 64 ASCII
letters or digits works only under `/compat/`. Native keys work on both surfaces.
Prefer secret files and environment variables over literal command arguments;
secret environment values are hidden in `--help`.

`crawlx serve --rate-limit-per-minute N` uses a token bucket per **tenant**, shared
by all of that tenant's keys. Capacity and refill are `N` per minute, default 6000;
`0` explicitly disables this API request limit. Responses expose `RateLimit-Limit`,
`RateLimit-Remaining` and `RateLimit-Reset`; exhaustion is `429` with `Retry-After`.
These limits do not replace target-side crawl pacing or concurrency admission.

`/v0/health/liveness`, `/v0/health/readiness` and `/v1/openapi.json` need no key.
The main `/metrics` route does require a key with `metrics:read`; the separately
configured loopback metrics listener is unauthenticated.

## Scheduled retention sweeper

`crawlx admin sweep-retention` runs one pass: expired artifacts and the objects behind them,
orphan objects (with `--orphan-grace-s`), expired pages, and whole-run purges. Add `--every
<duration>` to keep it running instead of scheduling a job:

```sh
crawlx admin sweep-retention --every 5m --artifacts-dir /var/lib/crawlx/artifacts
```

- **Cadence.** The first pass starts at once, then one starts every interval (`30s`, `5m`, `1h`,
  bare seconds; at least 1 second, the same floor as `retention.sweep_interval_s`). Passes never
  overlap. A pass that outlasts the interval delays the next one; missed ticks are not replayed
  in a burst.
- **Stop.** SIGINT or SIGTERM ends the loop at once: a pass in flight is dropped, which is safe
  because every object removal is acknowledged on its own and the database deletes are batched,
  so the next pass (or process) finishes what was cut short. The last line printed is
  `stopped after N pass(es), M failed`, and the exit code is 0. `--passes <n>` stops after `n`
  passes instead; a bounded run that saw a failed pass exits 1.
- **Failures.** A failed pass is logged as `retention sweep failed; the next pass retries`
  (error text only, never row or object content), counted in
  `crawlx_retention_sweep_failures_total`, printed as `pass N failed`, and retried on the next
  tick. A pass longer than one hour is abandoned and counted the same way.
- **Signals for alerting.** Every pass refreshes `crawlx_retention_overdue_artifacts{kind}` and
  `crawlx_zdr_violations_total`, the series the retention alert cards read; a pass logs the
  counts it removed (`artifacts_deleted`, `orphans_collected`, `pages_deleted`, `runs_purged`,
  `rows_deleted`, `authorizations_deleted`) and nothing else.
- **Scope.** `--every` cannot be combined with `--mode zdr`: a forced ZDR sweep is a one-time,
  confirmed operation (`--force`). Run one sweeper per deployment; two concurrent sweepers are
  safe (the work is idempotent) but only add database load.

## Exit codes, streams and diagnostics

| Code | Meaning |
|---|---|
| 0 | Success (`crawlx --version` and help included) |
| 1 | A check or audit ran and found failures (`--health-check`, `verify-artifacts`, `durability-audit`, `safety-audit`, a bounded sweep with a failed pass, `healthcheck`) |
| 2 | The command failed or its arguments were refused. Unlike the upstream tool, a failed crawl is never exit 0 |
| 3 | `crawlx extract`: the article-language capability could not be loaded |
| 130 | `crawlx extract`: cancelled |

Results are written to stdout; logs, errors and the update notice go to stderr, so piped JSON
stays parseable under `-v`, `-debug`, `--log`, or `DEBUG=true`. `DEBUG=true` also prints the full
error chain with a backtrace on failure. `-nc`/`--no-color` or `NO_COLOR` plain text; colour is
never written to a pipe. `crawlx crawl` asks for a newer release only when `CRAWLX_UPDATE_CHECK=1`
is set (or with `--update`), never replaces its own binary, and sends no update request by
default; upgrades are an operator deployment action (image or package), not something the crawler
does to itself.

`crawlx crawl --print-config` prints the effective per-run request of every seed, after
defaults, `--compat-defaults`, `--config`, `--request`, flags and admission, as a JSON array of
`{seedUrl, configDigest, request}`. Secrets are redacted and excluded from the digest, so two runs
print the same digest exactly when their effective requests are equal; nothing is crawled and
nothing touches the network. Configuration files accept only known keys: an unknown key (an
executable import, a hook, a class path, a deprecated spelling) is refused naming the key.

`--resolvers` takes inline `ip[:port]` entries or a file of them (commas or white space, `#`
comments, repeats counted once, at most 8). The resolvers only choose which DNS server answers;
the egress checks still judge every returned address, and resolution never grants
authorization. `--known-files` accepts `robots_paths`, `sitemap`, `all` and the spellings
`robotstxt` and `sitemapxml`; a file named twice is visited once.

The pprof listener (`--pprof-bind`, loopback only unless explicitly allowed) answers
`GET /debug/pprof/` (route list), `/debug/pprof/profile?seconds=N` and
`/debug/pprof/heap`, which is the memory summary read from the operating system (JSON, or text
with `?debug=1`). It has no allocator statistics and no labels or content.

`crawlx config features` prints the versioned feature manifest of the `crawl` flag set as JSON:
per baseline row (the pinned release and its inventory id) the flags and compatibility
spellings, the policy (`native`, or `deviation` with the reason it differs, such as a refused
unsafe switch), and the tests that exercise it. The manifest ships in the binary
(`crates/crawlx-cli/data/feature-manifest.json`); a test fails when a row names a flag, a
spelling or a test that does not exist, or when a compatibility spelling has no row.

`config check --format json` returns `ok`, `effective`, `sources`, `secrets` and
`findings` (each finding has `key`, `message` and an `error` boolean), plus capability
diagnostics. Load failures instead return `{"ok":false,"error":"..."}`. The default
environment is `prod`; local inspection can use `CRAWLX_ENVIRONMENT=dev`.
Malformed TOML reports its location without printing source lines that may hold secrets.
The report shows the object-store bucket and key prefix selected by `CRAWLX_S3_BUCKET` and
`CRAWLX_S3_PREFIX` (neither is secret), and the source of the ZDR buffer endpoint
(`CRAWLX_ZDR_REDIS_URL` or `CRAWLX_ZDR_REDIS_URL_FILE`, never both; the URL and the file content are
never printed).

No `doctor` or shell-completion command is provided. Use `config check`,
`crawl ... --health-check`, `protocol --probe`, `healthcheck` and `admin status`
for their distinct diagnostic purposes; `protocol --probe` performs no network check.

`crawlx extract --input-dir DIR --list` prints one JSON line per discovered entry and extracts
nothing. `--backup-dir NEW_DIR` copies each admitted input, with its relative path, into a new
owner-only directory outside the source tree; copies are created exclusively, so two files with
the same name in different directories stay separate and nothing is overwritten. `--zero-retention`
declares that no disk sink may be used and refuses `--output` and `--backup-dir`.

`crawlx extract --extract-config FILE` (also on `crawlx corpus` and `crawlx protocol`) reads a JSON
object of at most 64 KiB with the request's `extract.outputs`, `extract.decode` and `extract.markup`
members, validated by the same code as online runs; unknown members are refused. `--request FILE`
remains the native content policy.

`crawlx source-import` of a Go-collector-style manifest accepts an exported `env` object. Every
supported variable of the pinned release appears in the report with its effective source
(`env`, `options`, or `unset`); programmatic options override variables, as in the source's own
construction order. A convertible report carries `configDigest`. Unsafe or unlimited values
(disabling robots.txt, a limit of `0`) and unmapped variables make the import refuse with a
complete report; values are never echoed.

## Optional operator capabilities

The base Compose stack and Helm chart do not enable request-identity caching, retained
profiles, protocol delegates, or feed destinations. They do not create keys or discover
external services. The Helm OTLP endpoint is unset by default; set
`config.telemetry.otlp_endpoint` only when an operator supplies a collector. Existing
PostgreSQL RLS/request-role separation, ZDR delivery, proxy policy, Chromium seccomp,
and milestone gates remain required.

**Retained browser profiles are unavailable.** While encrypted artifact custody is enabled (always,
in PostgreSQL mode) the worker refuses them with
`profile_unavailable: retained browser profiles are unavailable while encrypted artifact custody is
enabled`, and the Helm chart fails when `capabilities.retainedProfiles.enabled=true`. The profile
overlay and the profile-related notes below describe the capability for when custody covers
profiles; do not enable them.

### Provision secrets once, outside release values

Provision two **different** cryptographically random 32-byte keys: one for keyed request
identity and one for AES-256 encrypted profiles. Store each as exactly 64 hexadecimal
characters, with an optional final LF. Do not put either key in Helm values, shell
arguments, registry JSON, logs, tickets, or rendered manifests. These commands write
files directly, without printing their contents:

```sh
install -d -m 0700 "$HOME/.config/crawlx/operator"
(umask 077; openssl rand -hex 32 > "$HOME/.config/crawlx/operator/request_identity_key")
(umask 077; openssl rand -hex 32 > "$HOME/.config/crawlx/operator/profile_key")
```

Run these commands **only for initial provisioning**, never on restart or upgrade.
Keep a protected backup. All API replicas and workers must use the same request-identity
key. To rotate it, drain admission and workers, expire or invalidate old cache/source-import
identities, then replace the operator secret and restart **all** consumers together.
There is no implicit dual-key/version fallback. Profile-key replacement similarly requires
deleting or re-encrypting retained ciphertext before the old key becomes unavailable.

`CRAWLX_REQUEST_IDENTITY_KEY_FILE` reads a bounded regular file using an opened descriptor.
Group/world-writable files, malformed hex, missing files, and simultaneous
`CRAWLX_REQUEST_IDENTITY_KEY` plus `_FILE` settings fail closed, even when either setting
is empty. The inline form exists for explicit local integrations; production deployment
templates use only the file form. Kubernetes projected-secret symlinks are supported.
No key or key-file contents appear in `config check`.

### Compose: opt-in overlays

Run `docker/init-compose.sh` for existing database/webhook/object-store bootstrap.
That helper validates optional key-file settings when supplied, but never generates
either capability key. The base `docker/docker-compose.yml` adds no optional mounts.
Enable only the required overlays:

```sh
export CRAWLX_REQUEST_IDENTITY_KEY_FILE="$HOME/.config/crawlx/operator/request_identity_key"
docker/init-compose.sh
docker compose -f docker/docker-compose.yml -f docker/compose.identity.yml config --quiet
docker compose -f docker/docker-compose.yml -f docker/compose.identity.yml \
  run --rm --no-deps api config check --format json
docker compose -f docker/docker-compose.yml -f docker/compose.identity.yml up -d --wait
```

Use `config --quiet`, not an unredacted `docker compose config` dump: the pre-existing
bootstrap API-key/object-store environment still contains credentials. Add
`-f docker/compose.profiles.yml`, `-f docker/compose.protocol.yml`, or
`-f docker/compose.delivery.yml` to the **same** command when those capabilities are approved.
Overlay inputs are:

| Overlay | Required host input | Container input |
|---|---|---|
| `compose.identity.yml` | `CRAWLX_REQUEST_IDENTITY_KEY_FILE` | same `/run/secrets/request_identity_key` for API and worker |
| `compose.profiles.yml` | `CRAWLX_PROFILE_KEY_FILE` | worker-only `file:///run/secrets/profile_key` |
| `compose.protocol.yml` | `CRAWLX_PROTOCOL_REGISTRY`, `CRAWLX_PROTOCOL_CREDENTIALS_DIR` | registry `/run/secrets/protocol_registry.json`; credentials `/run/secrets/crawlx-protocol/<filename>` |
| `compose.delivery.yml` | `CRAWLX_DELIVERY_REGISTRY`, `CRAWLX_DELIVERY_CREDENTIALS_DIR` | registry `/run/secrets/delivery_registry.json`; credentials `/run/secrets/crawlx-delivery/<filename>` |

Registry credential directories must exist, even for a credential-free registry; an empty
operator-owned directory is valid. Bind mounts never create missing host directories.
Compose file-backed secrets preserve host permission bits. Profile keys and registry
credential files must be owned by worker UID 10001 and readable only by that UID
(for example, root provisions ownership with `chown 10001:10001` and `chmod 0400`).
Do not broaden them to mode 0444: the existing file-secret resolver rejects world-readable
credentials. Request-identity files must be readable by the workload UID as well.
Keep their containing host directory private.

For a complete worker-capability preflight, run the worker image with the same overlay
set. The shared production checker also validates webhook configuration, so mount that
existing secret into this temporary validation process only:

```sh
docker compose -f docker/docker-compose.yml -f docker/compose.identity.yml \
  -f docker/compose.profiles.yml -f docker/compose.protocol.yml -f docker/compose.delivery.yml \
  run --rm --no-deps \
  -v "$PWD/docker/secrets/webhook_signing_key:/run/secrets/webhook_signing_key:ro" \
  -e CRAWLX_WEBHOOK_SECRET_FILE=/run/secrets/webhook_signing_key \
  worker config check --format json
```

Adjust the host webhook path if `CRAWLX_SECRETS_DIR` is not the default. `config check`
opens actual keys, registry files and file credential references; it does not test remote
endpoint connectivity or claim deployment approval. Its report contains capability
enablement/source and redacted references, never registry bodies or secret values.

### Helm: exact external Secret keys

Create Secrets in the release namespace **before** install/upgrade. No template creates
them. These capability Secrets supplement the chart's existing database, restricted API
database, migration database, webhook, optional object-store, safety-reader and safety-pauser
Secrets:

| Value | Required Secret keys | Consumers |
|---|---|---|
| `artifactCustody.keyFileSecret` (or `artifactCustody.kmsKeyId`) | `artifact_key` (64 hex characters) | API, worker, pre-roll config-check |
| `artifactCustody.secretRedis.existingSecret` | `url` (`redis://:<password>@host:6379/`) | worker, pre-roll config-check only |
| `capabilities.requestIdentity.existingSecret` | `request_identity_key` | API, worker, pre-roll config-check |
| `capabilities.protocolRegistry.existingSecret` | `registry.json` | worker, config-check only |
| `capabilities.protocolRegistry.credentialsSecret` | filenames referenced by registry | worker, config-check only |
| `capabilities.deliveryRegistry.existingSecret` | `registry.json` | worker, config-check only |
| `capabilities.deliveryRegistry.credentialsSecret` | filenames referenced by registry | worker, config-check only |

For example, use existing protected files; these commands never pass secret values as flags:

```sh
kubectl -n crawlx create secret generic crawlx-artifact-key \
  --from-file=artifact_key="$HOME/.config/crawlx/operator/artifact_key"
kubectl -n crawlx create secret generic crawlx-secret-registry \
  --from-file=url=/secure/secret-registry-url.txt
kubectl -n crawlx create secret generic crawlx-request-identity-v1 \
  --from-file=request_identity_key="$HOME/.config/crawlx/operator/request_identity_key"
kubectl -n crawlx create secret generic crawlx-protocol-registry-v1 \
  --from-file=registry.json=/secure/reviewed/protocol-registry.json
kubectl -n crawlx create secret generic crawlx-protocol-credentials-v1 \
  --from-file=/secure/protocol-credentials/
kubectl -n crawlx create secret generic crawlx-delivery-registry-v1 \
  --from-file=registry.json=/secure/reviewed/delivery-registry.json
kubectl -n crawlx create secret generic crawlx-delivery-credentials-v1 \
  --from-file=/secure/delivery-credentials/
helm template crawlx deploy/helm/crawlx --namespace crawlx \
  --set artifactCustody.keyFileSecret=crawlx-artifact-key \
  --set artifactCustody.secretRedis.existingSecret=crawlx-secret-registry \
  --set capabilities.requestIdentity.existingSecret=crawlx-request-identity-v1 \
  --set capabilities.protocolRegistry.existingSecret=crawlx-protocol-registry-v1 \
  --set capabilities.protocolRegistry.credentialsSecret=crawlx-protocol-credentials-v1 \
  --set capabilities.deliveryRegistry.existingSecret=crawlx-delivery-registry-v1 \
  --set capabilities.deliveryRegistry.credentialsSecret=crawlx-delivery-credentials-v1
```

Use the same arguments with `helm upgrade --install` after reviewing the rendered output
and provisioning existing chart prerequisites. Secret names, file references and endpoint
pins are not secret values; secret contents never enter manifests. The pre-install/upgrade
config-check hook receives every configured capability file and credential mount before
the migration hook and workload rollout. A missing Kubernetes Secret prevents that hook
from starting; malformed keys/registries fail its command. Do not disable this hook for an
opt-in deployment. The chart renders no optional Secret reference when its setting is empty.

### Profiles, registries and restricted database grants

Retained profiles require explicit operator enablement and `CRAWLX_PROFILE_KEY_REF`;
the profile overlay supplies both, while the Helm chart requires an existing profile Secret.
Custody mode accepts bounded structured cookies and local/session storage only.
Opaque Chromium directories, executable preferences and extensions are not imported.
TTL is `CRAWLX_PROFILE_MAX_TTL_SECONDS`, or Helm `maxTtlSeconds`, bounded to
1–86400 seconds and additionally narrowed by source authority and retention.
The worker rejects retained profiles for ZDR runs; Helm also refuses combining
profiles with `zdr.enabled`. The fresh browser context receives approved storage
only after owner, principal, origin, build, egress, generation and fence verification
and registration of every opaque name and value. Encrypted profile ciphertext stays
in the separate PostgreSQL catalog. Never mount persistent plaintext profile
directories or use the retired `--profiles-dir` flag.

Protocol registries use strict JSON `schemaVersion: 1`, `approvedTenants`, `services`,
and optional `whois`. Each service uses the real
`crawlx_fetch::protocol::service::ServiceRegistration` contract: reviewed HTTPS endpoint,
audience/build/approval/policy digests, explicit network approval, credential references,
capability contract, and shared-origin-admission policy reference. Service target credentials
are references, never values. Do not fabricate approvals or enable a provider from its own
capability claim. Example file credential references are
`file:///run/secrets/crawlx-protocol/service-token`. Network policy and endpoint peer checks
still apply; adding a Secret does not widen egress.
Required service capabilities include `read_only_effects`, `secret_free_response`, and
`shared_origin_admission`; `originAdmissionRef` names the approved network-broker policy.
The request fixes `allowBrowserWrites=false`. The service response must provide a
`redactionPolicyDigest` matching the scoped policy reference. Missing capabilities or
policy evidence keep the delegate unavailable before acquisition I/O.

Delivery registries use strict JSON `version: 1` and `destinations`. For example, an
operator-reviewed HTTP destination has this shape (documentation addresses below are
non-routable examples, not a ready-to-enable service):

```json
{
  "version": 1,
  "destinations": [{
    "id": "reviewed-export",
    "kind": "http",
    "endpoint": "https://collector.example.invalid/import",
    "addresses": ["192.0.2.40:443"],
    "headers": {
      "authorization": "file:///run/secrets/crawlx-delivery/authorization"
    },
    "allowsZdr": false
  }]
}
```

Replace endpoints/pins only after operator review; the credential file must contain the
complete header value. Supported kinds are `stdout`, `local`, `s3`, `http`, `search_update`,
`search_index`, `stream_rest_v2`, `queue_http_v1`, `object_json_upload`, and `ftp_service_v1`.
These last producer protocols are explicit HTTP contracts, not native stream/queue/FTP
clients. S3 reuses the existing configured object sink and credential chain. Local roots
must have an explicit writable mount; the overlays do not grant an arbitrary filesystem
root. Unknown providers, missing destination IDs, unavailable references and malformed
registries fail rather than creating a fake destination. Standard destinations do not
gain ZDR permission from deployment enablement.

After migration 0034, provision the restricted API role with these exact function grants
in addition to existing tenant/RLS grants (Compose's post-migration role job does this).
Migration 0034 drops the superseded migration-0033 acquisition-only RPCs:

```sql
GRANT EXECUTE ON FUNCTION public.crawlx_live_data_workers(bigint),
  public.crawlx_eligible_data_worker(text[], jsonb, bigint) TO crawlx_api;
```

Use the actual restricted login name if different. The DDL/migration owner creates these
bounded structural projections. Never grant the API role access to raw `workers` rows,
schema ownership, `BYPASSRLS`, superuser, or the migration DSN. Re-run deployment role
provisioning after migrations on upgrades; `CREATE ROLE` alone does not reconcile grants.
The live and eligibility projections expose bounded acquisition and data capability facts
from the same worker. Eligibility combines backend IDs with destination/ZDR and immutable
language-bundle requirements; capability evidence from different workers is never combined.
Both public-facing RPCs revoke default `PUBLIC` execution. Do not grant the API role the
owner-only `crawlx_worker_data_eligible(uuid,jsonb)` predicate.

### Optional pinned article-language bundle and native runtime

`CRAWLX_ARTICLE_LANGUAGE_BUNDLE` is an operator-only **directory** path, not a URL or a
request parameter. It enables local detected-language capability only when the actual
installed bundle and ONNX Runtime load successfully. No model, native library, or tokenizer
is downloaded by the loader, deployment chart, or Docker build.
Real CLI startup and `config check` reject non-Unicode bundle settings before optional
environment lookups can treat them as absent.

Build explicit ONNX-capable binaries/images; the feature stays off by default:

```sh
cargo build --locked --release -p crawlx-cli --bin crawlx --features onnx
export CRAWLX_REGISTRY=registry.example.com/crawlx   # your own registry; no images are published
docker build -f docker/Dockerfile.api --build-arg CRAWLX_CARGO_FEATURES=onnx \
  -t "$CRAWLX_REGISTRY/crawlx-api:v0.1.0-onnx" .
docker build -f docker/Dockerfile.worker --build-arg CRAWLX_CARGO_FEATURES=onnx \
  -t "$CRAWLX_REGISTRY/crawlx-worker:v0.1.0-onnx-chromium155.0.8059.84" .
```

Use approved, immutable copies of the six resources named and SHA-256-pinned by
`crates/crawlx-model/data/lid176-onnx-v1.json`: `lid176.onnx`, `config.json`, `labels.json`,
`vocab.txt`, `hs_tree.json`, and `README.md`. The graph cap is 128 MiB; each auxiliary
resource cap is 1 MiB. The loader checks all fixed digests and schema/graph contracts,
and rejects symlinked/non-regular bundle resources. Never substitute a different model
under the same filename. Keep the directory operator-owned and read-only to workloads.
The embedded provenance manifest records upstream `TigreGotico/lid176-onnx` at immutable
revision `64f7d31b705bc4a7424c82762b323c6ee8c68b94`, with CC-BY-SA-3.0 weights.
Model-card training lineage remains unverified; successful digest/runtime checks do not
establish language-quality or parity evidence. Review licensing and provenance before approval.

After that review, operators may explicitly provision the pinned public weights using
the following command. This is a manual network operation, never a workload startup step:

```sh
bundle=/secure/approved/lid176-onnx-v1
install -d -m 0755 "$bundle"
# The manifest's `source` is the pinned revision's browse URL; weights are served under `/resolve/`.
source=$(jq -r .source crates/crawlx-model/data/lid176-onnx-v1.json)
for file in lid176.onnx config.json labels.json vocab.txt hs_tree.json README.md; do
  curl --fail --location --proto '=https' \
    "${source/\/tree\//\/resolve\/}/$file" \
    --output "$bundle/$file"
done
chmod 0444 "$bundle"/lid176.onnx "$bundle"/config.json "$bundle"/labels.json \
  "$bundle"/vocab.txt "$bundle"/hs_tree.json "$bundle"/README.md
```

The actual preflight loader must still verify every digest; download success alone is
not acceptance. Preserve the upstream `README.md` and required CC-BY-SA-3.0 attribution
and license when distributing the bundle. These weights are not MIT-licensed.

Separately provision an approved ONNX Runtime shared library and its required shared
objects, compatible with the pinned `ort` dependency in `Cargo.toml` and the container
architecture/libc. `ORT_DYLIB_PATH` names that local executable library. This is a native
code trust boundary, not a credential reference: do not use tenant uploads, writable
worker paths, an unreviewed library, or an unpinned “latest” download. Runtime deployment
mounts do not acquire or approve these external artifacts for you.

Compose mounts the bundle and runtime directories read-only only when this overlay is
selected. Existing directories are required; missing paths are never created:

```sh
export CRAWLX_ARTICLE_LANGUAGE_BUNDLE=/secure/approved/lid176-onnx-v1
export CRAWLX_ONNX_RUNTIME_DIR=/secure/approved/onnxruntime
export CRAWLX_TAG=v0.1.0-onnx
docker compose -f docker/docker-compose.yml -f docker/compose.article-language.yml build
docker compose -f docker/docker-compose.yml -f docker/compose.article-language.yml config --quiet
docker compose -f docker/docker-compose.yml -f docker/compose.article-language.yml \
  run --rm --no-deps \
  -v "$PWD/docker/secrets/webhook_signing_key:/run/secrets/webhook_signing_key:ro" \
  -e CRAWLX_WEBHOOK_SECRET_FILE=/run/secrets/webhook_signing_key \
  worker config check --format json
docker compose -f docker/docker-compose.yml -f docker/compose.article-language.yml up -d --wait
```

The runtime directory must expose `libonnxruntime.so`; its required sibling libraries
must also be present. Bundle resources must be readable by UID 10001. Other capability
overlays can be combined with this overlay using the same `-f` arguments on every command.
For local CLI runs, use `CRAWLX_ARTICLE_LANGUAGE_BUNDLE` directly with
`ORT_DYLIB_PATH=/secure/approved/onnxruntime/libonnxruntime.so`.

Helm uses an existing operator-populated PVC, not a Secret or ConfigMap, for these public
model artifacts. Place the six bundle files at its root and the approved runtime directory
under `runtime/`. It must support concurrent read-only mounts by worker and config-check
pods, including separate nodes where applicable. Set:

```sh
helm template crawlx deploy/helm/crawlx --namespace crawlx \
  --set image.tag=v0.1.0-onnx \
  --set capabilities.articleLanguage.existingClaim=crawlx-article-language-v1 \
  --set capabilities.articleLanguage.runtimeLibrary=/opt/crawlx/article-language/runtime/libonnxruntime.so
```

Use the same settings with `helm upgrade --install` after publishing both approved images
and provisioning the PVC. Both worker and pre-roll config-check mount it read-only at
`/opt/crawlx/article-language`; API workloads receive neither path nor mount. Config-check
uses the actual worker loader on the CPU pool and gets a 1 GiB memory limit for this opt-in.
A missing runtime, mismatched resource digest, invalid graph, or unavailable compiled
feature fails preflight rather than advertising language detection. Its report records
capability enablement, not article text. Requests naming a different language-bundle
digest remain unavailable; migration-0034 admission requires a matching live worker.

## Optional independent archive reader

The `archive_interoperability` storage integration target uses an explicitly supplied
local Python interpreter through `CRAWLX_ARCHIVE_READER_PYTHON`. Its environment must
already contain the approved independent archive reader package. The test installs
nothing and makes no network requests. Without the interpreter setting it reports a
skip, not interoperability evidence.

Run `cargo test -p crawlx-storage --test archive_interoperability` with that setting
and the approved local package path. The fixture checks WARC record types, payloads
and digests independently, then checks WACZ ZIP64 metadata, resource fixity, CDXJ
ordering and exact gzip-member ranges. This bounded fixture does not establish
general renderer compatibility, large-collection performance or release acceptance.

## Dataset delivery and source-memory operations

Feed destinations remain operator-registered IDs; imports and page content cannot
choose paths, endpoints or credentials. Keep `CRAWLX_DELIVERY_REGISTRY` identical
across workers that advertise the same destination capabilities. Standard feeds
may use immutable local/S3 objects; stdout can duplicate after a send/receipt crash.
Compression never changes the destination's zero-retention allowance.

For long imports, retain the `feed-import --cursor-file` checkpoint with the exact
source representation and template. A changed representation needs an explicitly
new source identity rather than an edited cursor. `DELETE
/v1/crawls/{id}/source-memo` requires `crawls:write` and resets only source memo
and category-cache state; it does not purge frontier work or loader progress.
See [the reference](../reference.md#dataset-feed-selection-batching-and-compression)
for feed filters, terminal batching, empty-feed policy and codec bounds.

## Metrics, traces and process memory

`crawlx serve` exposes authenticated `GET /metrics` with the `metrics:read` scope.
Both `serve` and `worker` accept `--metrics-bind 127.0.0.1:9464`
(`CRAWLX_METRICS_BIND`) for an optional unauthenticated, loopback-only scraper
listener. Give each process a different port when they share a host. Scrape both:
metrics are process-local, not database aggregates. API metrics count accepted jobs
and HTTP routes; worker metrics count URL acquisition, browser and scheduling work.
A fresh process has no samples for counters or histograms it has not observed.

The authoritative metric catalog is
`crates/crawlx-telemetry/src/metrics/catalog.rs`. Exported names replace dots with
underscores, add `_total` for counters and `_seconds` for duration units.
Request route labels are templates such as `/v1/crawls/{id}`, never raw paths.
Validate the shipped rules with `promtool check rules
deploy/alerts/crawlx-rules.yaml` and their fixtures with `promtool test rules
deploy/alerts/crawlx-rules.test.yaml`.

`crawlx_browser_rss_bytes` sums the latest sampled resident sizes of live launched
browser trees in this process. Samples arrive every five seconds. A stopped
sampler removes its contribution; after the last browser closes the gauge is zero.
Failed samples clear that browser's contribution, not another browser's reading.
The worker's startup capability probe also launches and closes a browser, even
before static work. Attached browsers are not sampled. These are observed process
sizes, not per-request allocation or allocator statistics.

Logs go to stderr and retain structured fields through the redacting formatter.
`--log info` or `--log debug` raises the CLI's default warning-level filter.
`--otlp-endpoint` (`CRAWLX_OTLP_ENDPOINT`) exports only in a binary built with
`--features otlp`; a binary without it warns instead of claiming an export.
Do not treat registered-secret redaction as permission to log page bodies or
credentials. Report APIs deliberately withhold raw URLs and diagnostic text.

The optional pprof listener is unauthenticated and separate from the API and
metrics ports. Keep `--pprof-bind` on loopback; `--pprof-allow-non-loopback`
requires operator-provided access control. CPU profiles at
`/debug/pprof/profile?seconds=N` use protobuf, default to 10 seconds and clamp
to 1–120 seconds. Concurrent profiles return `409`; malformed durations return
`400`. `/debug/pprof/heap` is a JSON OS memory summary, not a heap profile;
`?debug=1` returns text. Neither summary contains allocation contents.

