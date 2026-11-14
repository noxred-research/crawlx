# Data and secrets

This page describes what CrawlX keeps, for how long, in what form, and how secrets are kept out of
everything else. Operator-side provisioning (keys, registries, Helm Secrets) is in
[operations](../ops/README.md).

## Artifact classes

Every stored artifact has a sensitivity class, which decides its retention, whether it is sealed, and
who may read it:

| Class | Examples | Retention | Sealed at rest |
|---|---|---|---|
| `metadata` | Structural records, digests, counters | Until the run is purged | No |
| `content` | Page bodies, Markdown, extracted text | The run's `retention.days` | Yes |
| `sensitive` | Screenshots, DOM snapshots, traffic captures | `retention.days` (images at most 3 days) | Yes |
| `credential_bearing` | Cookie and storage state | At most 1 day | No (plaintext legacy path) |

Artifacts are content-addressed (`{class}/{tenant}/{run}/{blake3}`) so the object-store lifecycle
prefix is the class. Reading `sensitive` content over the API needs the
`artifacts:read_sensitive` scope.

## Retention modes

`retention.mode` is one of:

| Mode | Behavior |
|---|---|
| `standard` (default) | Content kept `retention.days` (default 7, clamped to 1-30). |
| `extended` | Content kept 31-365 days. |
| `zdr` | Zero data retention: page content never reaches durable storage (below). `retention.days` is forced to 0. |

A tenant can enforce ZDR, which forces every one of its runs to `zdr` at admission.

**Deletion.** Expired content is deleted object first, then the index record, then the database
row, so a failure never leaves a row pointing at a deleted object. A run purge removes archives and
objects, then leaf tables in batches, then writes an audit row. Orphan objects (written but never
referenced because a transaction failed) are collected after a grace period you choose
(`--orphan-grace-s`). Authorization records are retained 1,096 days.

**Schedule the sweeper.** `crawlx admin sweep-retention` performs one pass; add `--every 5m`
for the built-in, cancellable loop ([operations](../ops/README.md#scheduled-retention-sweeper)).
The worker and API do not start it automatically. A scheduled one-shot job is also supported.
The volatile ZDR delivery buffer is also swept on each webhook tick and by `crawlx admin sweep-delivery`
(a systemd timer is in `deploy/systemd`). Metrics: `crawlx.retention.overdue_artifacts{kind}`,
`crawlx.retention.sweep.failures`, `crawlx.zdr.violations`.

## Zero data retention

A ZDR run keeps a structural trail (so safety, journal and replay invariants still hold) and nothing
else durable.

- **Write gate.** The artifact store refuses to write any non-`metadata` artifact for a ZDR run
  (`zero-data-retention run may not write {class} artifacts to the durable store`) and counts the
  attempt as a violation.
- **Volatile delivery buffer.** ZDR page content goes only to a bounded buffer: process memory, a
  `zdr/` directory that must be on tmpfs or ramfs, or a Redis-compatible server. The TTL is at most
  one hour, counted from first insertion; reads never renew it. Defaults: 10,000 entries, 256 MiB.
  The Redis adapter refuses to start against a server that could persist or evict data (it requires
  `appendonly no`, no RDB saves, `noeviction`, and a primary with no replicas). With no buffer
  configured, ZDR operations fail ("required volatile operational value is unavailable"); there is no
  silent fallback.
- **Database rewriting.** A database trigger rewrites rows of ZDR runs on 14 tables (frontier,
  pages, states, traffic events, safety decisions, model decisions, actions, approvals, action
  contexts, enablement edges, elements, events, webhook deliveries, workflow runs). For example a
  frontier URL becomes NULL and origins become SHA-256 hashes; event payloads become a digest and a
  page identifier. A second trigger reduces `crawl_runs.config` to a short allow-list.
- **Refused features.** Full response bodies, durable archives and retained browser profiles are
  refused for ZDR runs. Scrape caches, the article cache and change tracking are skipped. Delivery
  destinations must explicitly allow ZDR; local and S3 destinations refuse it. Protocol delegates
  must advertise zero retention. LLM extraction stays on the default model, and branding refinement
  is skipped. Agent runs keep results in an in-memory vault for 24 hours.
- **Models.** Never route a ZDR run to a provider that does not guarantee zero retention.

## Secret boundaries

The rule: secrets and sensitive page content stay out of prompts, logs, snapshots, artifacts,
telemetry and durable storage unless a specific, sealed path is documented here.

**Types.** Credentials move as `SecretOr<T>`: a zeroizing buffer whose `Debug` prints `[REDACTED]`
and whose serialization writes `"[REDACTED]"`. Typed secret values are never logged or persisted
(the typed-input action carries a `SecretOr`). The observation type is deliberately not `Serialize`.

**References, not values.** Configuration holds references. The worker's resolver chain supports
`env://VAR`, `file:///abs/path` (refused if world-readable; 64 KiB cap), `vault://mount/path#key`
(KV v2), `cloud-sm://id[#json-key]` and `totp://<base32>`. Resolution happens immediately before use
and errors never carry the value. Captcha keys accept `env://` and `file://` on the command line.

**Redaction.** One redactor is used by logging, traffic capture and exports:

- Field names: `password`, `passwd`, `authorization`, `cookie`, `set-cookie`, `token`, `secret`,
  `credential`, `apikey` (case-insensitive, ignoring separators).
- Value shapes: JWTs, `Bearer` and `Basic` credentials, `sk-` style keys, long hex strings, and
  session-style `name=value` pairs and query parameters.
- A run-time registry of exact values (resolved credentials, captcha tokens) that are scrubbed
  wherever they appear.
- Traffic metadata keeps header names and replaces values with a keyed BLAKE3 hash under a per-run key,
  so equality can be tested without storing the value. Userinfo and session-class query parameters
  are removed. The egress proxy replaces credential header values before the observer sees them.
- The logging layer fails closed: if a redaction pattern cannot be compiled, output is suppressed.

**Prompts and logs.** LLM prompts and replies are not logged, endpoints print as `[REDACTED]`, and
model engines receive page text only inside provenance-tagged fields.

**Run-wide secret registry.** Secrets discovered *during* a run (for example a captcha token) are
registered in a registry before they are delivered to the page. It lives in PostgreSQL (a fence) and
a dedicated, persistence-free Redis-compatible server (`CRAWLX_SECRET_REDIS_URL`). Limits: 256 values,
1 MiB per run and 16 KiB per value. PostgreSQL grants a renewable fenced use window
(`CRAWLX_SECRET_AUTHORITY_TTL_SECS`, default one hour, maximum 24 hours). Renewal
revalidates current ownership, cancellation, authorization and retention; it never extends
the Redis secret TTL. The original absolute ceiling is the minimum of explicit run
retention, authorization expiry and `CRAWLX_SECRET_AUTHORITY_HARD_MAX_SECS` (default
72 hours). Missing either explicit permission caps that ceiling at 24 hours. Expired
authority cannot be resurrected. The server requires no RDB or AOF persistence,
no replicas, `noeviction` and bounded clock skew.

**Request identity key.** Features that correlate credential-bearing requests (cache identity, source
import) use a keyed digest under `CRAWLX_REQUEST_IDENTITY_KEY` or `_FILE`: exactly 64 hex characters,
from a regular file that is not group- or world-writable. The key is never generated; without it
those features are unavailable (`cache_identity_unavailable`) rather than falling back to unkeyed
hashes.

**Secret detection.** `--detect-secrets` finds nine kinds of secret in fetched content (cloud access key id
and secret, source-host, chat-platform, payment-platform and search-platform tokens, JWT, private keys, generic API keys) and reports
kind, location and a keyed hash only, never the value. Live validation of a finding against a
provider is opt-in and needs an operator-supplied validator file; without one, findings stay
`unknown`.

## Encrypted artifact custody

Worker-produced retained `content` and `sensitive` artifacts, including terminal archive exports,
are sealed before they reach the object store.

Authenticated API and CLI operator inputs, including evidence, login flows and archive replay
saves, remain in custody mode `ReadOnly`: `SecretFree` and retention-gated plaintext writes.
They read sealed artifacts through the catalog. This boundary introduces no API producer leases.

- **Format.** AES-256-GCM in 64 KiB frames (a `CXAR` v1 stream) with a random nonce prefix and an
  authenticated terminal frame. The additional authenticated data binds the domain, the header, the
  tenant, run and artifact ids, the frame index and the frame kind, so a ciphertext cannot be moved
  to another artifact or truncated.
- **Keys.** Each artifact has its own data key, wrapped by exactly one provider: cloud KMS
  (`CRAWLX_ARTIFACT_KMS_KEY_ID`, `GenerateDataKey`/`Decrypt` with an encryption context of tenant,
  run and artifact) or an operator key file (`CRAWLX_ARTIFACT_KEY_FILE`, 64 hex characters, wrapping
  data keys under AES-256-GCM bound to tenant, run and artifact). Setting both is a startup error.
  Never replace the key file or retire a KMS key while sealed artifacts exist.
- **Publish gate.** Live-worker publication atomically writes the catalog row, secret-registry
  epoch check and key-custody envelope. If the registry changed after scanning, publication is
  rejected and a retry rescans; bytes containing the newly registered value are refused and their
  staged ciphertext is deleted. Terminal archive exports instead use a frozen-epoch grant bound
  to their verified source artifacts, classification, retention and export fence. They remain
  encrypted after volatile registry loss without claiming a final-epoch secret rescan.
- **Serving.** Raw presigned object-store URLs are refused for sealed artifacts (presign TTL is at
  most 60 s and only for the plaintext classes); sealed reads go through the catalog, and the API
  serves authenticated decrypted bytes instead.
- **Retained browser profiles.** Custody accepts only complete bounded structured cookies
  and local/session storage, sealed under fresh wrapped artifact keys. Owner, principal,
  origin, build, egress, generation, fence and retention must match. Every opaque name and
  value joins the secret registry before import. Arbitrary Chromium directories remain
  unavailable in custody mode; ZDR refuses profile retention.
- **Local runs.** A local in-process `crawlx crawl` seals under a process-lifetime random key unless an
  operator key provider is configured. Its `pages/*.md`, `metadata.json` and `report.json` are the
  readable output; the sealed objects under `artifacts/` cannot be read after the process exits.
- **Requirements.** PostgreSQL workers need a key provider and `CRAWLX_SECRET_REDIS_URL`; the API needs
  only the key provider. A worker without them refuses to start.
- **Checkpoints.** Session checkpoints (cookies, storage, URL) are sealed in a separate AES-256-GCM
  envelope (`CXCP`) with a fresh data key per seal, wrapped by exactly one provider (see
  [Checkpoint key providers](#checkpoint-key-providers)). Browser checkpoints, and so every
  `dynamic`/`hybrid` run on a database-backed worker, fail without a provider, and plaintext
  checkpoint storage is revoked by migration. A run the worker refuses for this reason ends `failed`
  with `terminalReason: fatal_error` and a `failure` object on `GET /v1/crawls/{id}`
  (`{"code": "checkpoint_keys_required", "message": "…"}`); the worker log carries the same reason.
- **Read authority.** Reads during queued/running work require an unexpired durable use
  window and no pending registration or renewal. Terminal reads retain their approved
  retention because secret registration is closed. This gate does not claim a new
  secret scan on every read or transport-lifetime exposure fencing.

Secrets known at run start (request controls, role credentials, the captcha key) keep their existing
per-producer scans and are not registered run-wide.

### Checkpoint key providers

Set exactly one of these on every worker that runs browser-backed crawls (and on the CLI when it
runs against a database). Setting both is a startup error, and `crawlx config check` reports it.

| Provider | Setting | Wraps data keys with |
|---|---|---|
| Cloud KMS | `CRAWLX_CHECKPOINT_KMS_KEY_ID` (a stable key ARN) | `GenerateDataKey`/`Decrypt` with an encryption context of tenant, run, session and checkpoint |
| Local key-encryption-key file | `CRAWLX_CHECKPOINT_KEK_FILE` (an absolute path) | AES-256-GCM under a key from the file, bound to the key id and the same ownership tuple |

The local key-encryption-key file needs no cloud account or network access and does not depend on
the database engine (PostgreSQL, MariaDB or SQLite) or on the artifact store (filesystem or any
S3-compatible service): it only wraps the per-checkpoint data keys, which are stored with the sealed
checkpoint. The artifact data keys have their own provider (`CRAWLX_ARTIFACT_KEY_FILE` or
`CRAWLX_ARTIFACT_KMS_KEY_ID`, above); a self-hosted deployment sets both files.

**File format.** One key per line: `<key-id>:<64 hexadecimal characters>` (32 random bytes, for
example `openssl rand -hex 32`). Blank lines and lines starting with `#` are ignored. A key id is 1 to
64 characters from `A-Z a-z 0-9 . _ -`. The file lists at most 64 keys and is at most 64 KiB.

```
# checkpoint key-encryption keys, newest first
2026-11:9f2c…(64 hex characters)
2026-05:41ab…(64 hex characters)
```

The **first** key is the primary: every new checkpoint is wrapped with it. Every listed key can still
unwrap checkpoints that name it. The wrapped data key records its key id, so no other state is needed.

**Protection.** The file must be a regular file in one of two shapes:

| Mode | Also required |
|---|---|
| `0600` or `0400` (owner only) | nothing |
| `0440` (read for owner and group, nothing else) | the file's group is the process's effective or a supplementary group, and its owner is the process user or root |

The second shape is a Kubernetes secret volume under `fsGroup`: the kubelet writes the file as root and
adds group read, so the Helm chart mounts it with `defaultMode: 0440`. Any other bit (`0640`, `0444`, group write or execute) and a foreign group are refused; the error names the actual mode and gid.
Symlinks are followed and the target's metadata is judged. The check runs on the opened descriptor.
Nothing generates a key: a missing, unreadable, empty, oversized or
malformed file, a repeated key id, a key that is not exactly 32 bytes, a mode or group outside the
table, or a checkpoint that names a key id the file no longer lists all fail closed with an error
that never contains key material. Key bytes are zeroized in memory and never logged or serialized.
Back the file up with the database: losing a key loses every checkpoint wrapped under it.

**Rotation.**

1. Generate a new key and add it as the **first** line with a new id; keep the old lines.
2. Roll the file out to every worker and restart them. New checkpoints use the new key; checkpoints
   wrapped under the old key still open.
3. Once no checkpoint wrapped under the old key is still needed (for example its run has ended),
   delete the old line and roll the file out again. Deleting a key earlier makes the checkpoints it
   wrapped unreadable, and resuming those runs fails closed.

Switching a deployment from cloud KMS to the file (or back) has the same limit: checkpoints sealed
by the old provider are not readable by the new one, so switch only while no resumable
checkpoint remains.

## Tenant isolation

Tenancy is enforced in the database, not only in the API:

- Every tenant-owned table has row-level security keyed on `app.tenant_id`
  (`crawlx_current_tenant()`); an unset tenant sees no rows. The API sets the tenant for each
  transaction, including streaming responses.
- The API connects as a separate login (`CRAWLX_API_DATABASE_URL`): non-owner, `NOBYPASSRLS`,
  `NOSUPERUSER`, with CRUD only on RLS-protected tables and no `UPDATE` or `DELETE` on the audit
  log. `docker/provision-api-role.sql` provisions it. The API refuses to start against the owner role unless an explicit
  override is set, and the override is itself refused when `CRAWLX_ENVIRONMENT` is anything other than
  `dev` or `ci`.
- Newer tables use `FORCE ROW LEVEL SECURITY`; older tables exempt the owner and worker roles, which
  are never exposed to tenants.
- Idempotency keys are scoped to `(tenant, key)`; a reused key with a different request body answers
  `422 idempotency_key_reuse` and a concurrent repeat `409 idempotency_in_progress`.

## Trust lanes

Browser actions and their network traffic carry a trust lane. Native pointer, keyboard and text input
are `trusted_ui`; file choosers, scripted navigation and scroll, synthetic DOM events and the fetch
plane are `diagnostic`. A trigger enforces that a network epoch's lane equals its action's lane, lanes
are immutable, and coverage and traffic reads go through a single reader that always applies the lane
predicate. Service-worker and fetch-plane traffic is never attributed to the trusted lane.

## Parse-memory budget

HTML parsing allocates unpredictably, so CrawlX admits a parse before it starts. A process-wide budget
(`CRAWLX_PARSE_MEMORY_BYTES`, default 4 GiB for the worker and 512 MiB for the API in the shipped
Compose and Helm files) is charged **500 bytes per input byte**, without waiting, and the charge is held
until the DOM is dropped. The factor is the measured worst case over an adversarial corpus (364 bytes
per input byte at the 16 MiB input cap) plus margin, and is enforced by the
`parse_memory_ceiling` test in `crawlx-extract` (an ignored, slow test; run it with `--ignored`).

Decoded acquisition input, measured parser admission and transient output reservations
share one process-wide byte budget. Owned permits move through blocking work and sink
I/O; cancelling a waiter does not release bytes still owned by a running closure.
The in-process HTML parser builds its tree through a metering sink that spends the admitted
charge before each node and payload allocation and fails with the typed parse-memory error,
dropping the partial tree, when the budget cannot grow; the tokenizer's and tree builder's own
buffers are covered by a modelled allowance inside the per-byte factor.

- A parse that does not fit right now fails as retryable (transient pressure); one larger than the
  whole budget fails terminally. At 4 GiB the largest HTML a worker parses is about 8 MiB.
- Memory is bounded by this ceiling and the budget: the tree is charged allocation by allocation,
  but the parser's own token strings, stacks and vectors are not individually fallible and rely on
  the measured allowance.
- Raise the budget together with the container memory limit.

## Chromium background traffic

Stock Chrome for Testing (the pinned 155.0.8059.84 build) attempts unsolicited background requests to
the browser vendor's services (`accounts.google.com`, `redirector.gvt1.com`, `update.googleapis.com`,
`content-autofill.googleapis.com`, `android.clients.google.com`) and a time-service query at startup.

What CrawlX does:

- Launch flags reduce it (`--disable-background-networking`, `--disable-sync`,
  `--no-startup-window`, `--no-first-run`, component updates and default apps off in the standard
  launch profile, on-demand-only network time, no startup AI eligibility query).
- All browser traffic goes through the loopback egress proxy, with name resolution forced into the
  proxy (`--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`). The proxy applies the run's
  egress policy to every request, so these hosts are refused with `403` and `x-crawlx-egress-denied`
  whenever the run's scope bounds them out (a fixture or authorization-record scope), and no
  connection to them is made. Each denial is logged (`egress denied (browser plane)`) and counted
  in `crawlx.egress.denials{plane="browser",reason}`. Requests a page's tabs issue are also paused
  in the browser and checked against the same policy before dispatch; a refusal there never reaches
  the proxy and is logged (`egress denied (browser network guard)`) and counted in
  `crawlx.egress.denials{plane="browser_guard",reason}`.
- Add the hosts to `egress.operator_blocklist` if a deployment must guarantee that none is ever
  dialed regardless of scope.

What CrawlX does **not** do: prevent the attempts. A browser that makes zero attempts needs a patched
build. `ci/build-chromium.py` builds a candidate from an already-synced Chromium checkout and applies
the patches in `ci/chromium-patches/` (background account and autofill requests, component
bootstrap, policy invalidation, bundled spell-check dictionaries). That build is not the default pin,
and no test claims the combined patch set achieves zero attempts. The launch check compares the
browser version string with `chromium-pin.toml`, so it does not distinguish a patched build from stock.

## Telemetry

Metrics are Prometheus text on `/metrics` (a route needing the `metrics:read` scope, plus an optional
unauthenticated loopback listener); metric names use underscores and a `_total` suffix on counters. OTLP export is off
unless the `otlp` cargo feature is built in and `CRAWLX_OTLP_ENDPOINT` is set; without the feature the
endpoint is ignored with a warning.

## Deployment secrets

Production deployments pass secrets as files: `CRAWLX_DATABASE_URL_FILE`,
`CRAWLX_API_DATABASE_URL_FILE`, `CRAWLX_WEBHOOK_SECRET_FILE` (or `api.webhook.signing_key_file`),
`CRAWLX_ARTIFACT_KEY_FILE`, `CRAWLX_SECRET_REDIS_URL_FILE`, `CRAWLX_ZDR_REDIS_URL_FILE`,
`CRAWLX_REQUEST_IDENTITY_KEY_FILE`, `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`, `CRAWLX_GATE_KEYS_FILE` and
`CRAWLX_PROFILE_KEY_FILE`. The DevTools URL of an attached browser is a bearer token too:
`--cdp-ws-url-file` / `CRAWLX_CDP_WS_URL_FILE` name a `0600` file holding it (`CRAWLX_CDP_WS_URL` is the
environment form); `--cdp-ws-url` is deprecated because the URL shows in process arguments.
`crawlx config check` warns in staging and production when a database URL
or webhook secret is passed inline, and shows secret-bearing environment values as `<redacted>`.
Webhooks are signed `Crawlx-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "{t}.{body}">` (the compatibility
API also sends `X-Firecrawl-Signature: sha256=<hex>` so existing receivers keep verifying). The Helm chart fails to render if both or <!-- wire-compat -->
neither artifact key providers are configured.

## Known limitations

The retention sweeper is an operator-scheduled command. Background Chromium requests
are contained but not prevented. In-process HTML parsing charges the tree it builds against the
parse-memory budget but cannot make the parser's internal buffers fallible; process isolation
provides the separate hard-failure boundary.
