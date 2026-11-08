# Operator runbooks

This page holds the numbered runbooks RB-01 to RB-12 and one card for each rule in
[`deploy/alerts/crawlx-rules.yaml`](../../deploy/alerts/crawlx-rules.yaml). Each alert carries a
`runbook` annotation that points at one of the `#rb-NN` anchors below. A card says what the
alert means, where to look, which commands to run first, which runbook takes over, and how to
undo the likely cause.

Dashboard names are the rows and panel titles of
[`deploy/dashboards/crawlx.json`](../../deploy/dashboards/crawlx.json) (uid `crawlx`, title
`crawlx-ops`). The commands, queries, metric names and configuration keys below exist in this
repository; the on-call rota, paging backend and escalation timers are yours to define.

## Severity scale

The cards suggest a severity. Adapt the response targets to your organization.

| Severity | Meaning | Typical response |
|---|---|---|
| SEV-1 | Safety bypass, tenant isolation failure, credential leak, private-network policy bypass, repeated non-idempotent action, metadata corruption, persisted ZDR content | Page immediately, contain first ([RB-12](#rb-12)), no deploys except the fix |
| SEV-2 | Global crawl stall, widespread browser crash loop, failed database failover, global webhook outage | Page, mitigate within hours, roll back the last change first |
| SEV-3 | Target-specific failure, one degraded model provider, delayed retention cleanup | Ticket, next business day |
| SEV-4 | Degradation with no objective at risk (for example latency slightly over target) | Backlog ticket, weekly triage |

## Before any runbook

**Connection and identity.** Ordinary `crawlx admin` commands read PostgreSQL from `--database-url`, `CRAWLX_DATABASE_URL` or `CRAWLX_DATABASE_URL_FILE` (`database.url_file` in `crawlx.toml`), and record `actor = admin:<operator>` in the hash-chained `audit_events` log. Set your name first: `export CRAWLX_OPERATOR=<you>`. Ids are UUIDs. The independent `safety-audit` command instead requires its own reader and pause DSNs; it never uses these operator credentials.

**Commands the cards use** (all exist in `crates/crawlx-cli/src/admin_ops.rs` and `admin.rs`):

| Command | Effect |
|---|---|
| `crawlx admin status` | admission mode, active crawls, workers (draining count), open `intended` and `unknown` actions |
| `crawlx admin workers` | worker id, hostname, version, draining flag, held leases, last heartbeat |
| `crawlx admin pause\|cancel --crawl <id>\|--tenant <id>\|--all` | pause stops at the next action boundary; `cancel --reason cancelled\|policy-stopped` ends runs (the CLI value is kebab-case, the recorded terminal reason is `policy_stopped`) |
| `crawlx admin resume --crawl <id>\|--tenant <id>\|--all [--admission]` | resume paused runs; `--admission` also sets `scheduler.admission = open`. A selector is required, and `--all` resumes every paused run, so list paused runs first |
| `crawlx admin drain --worker <id>` | no new leases from that worker's next heartbeat; its sessions hand over at the next action boundary (same as SIGTERM) |
| `crawlx admin drain --admission` | `scheduler.admission = drain`: no new leases anywhere |
| `crawlx admin freeze [--all]` | `scheduler.admission = frozen`; with `--all` also pauses every running crawl ([RB-11](#rb-11) level 2) |
| `crawlx admin reconcile [--action <id>]` | list open `intended`/`unknown` rows; with an id, hand the action's session to the reconciler ([RB-02](#rb-02) step 3) |
| `crawlx admin verify-artifacts [--since <rfc3339>] [--artifacts-dir <dir>\|--s3-bucket <b>]` | missing object, digest mismatch, orphan count; exit 1 on defects |
| `crawlx admin sweep-retention [--mode all\|zdr --force] [--orphan-grace-s <n>] [store flags]` | run the sweeper now; `--mode zdr --force` deletes ZDR content first ([RB-08](#rb-08) step 3) |
| `crawlx admin durability-audit [--since <rfc3339>] [--json]` | accepted-job audit against `crawl_runs`; exit 1 when any accepted run is missing |
| `crawlx admin safety-audit --reader-database-url <reader-dsn> --pause-database-url <pause-dsn> [--json]` | independent cross-tenant action-safety audit; automatically pauses violating runs; exit 1 on violations, 0 when clean; errors propagate |
| `crawlx admin engine --tenant <id> [--set crawlx\|firecrawl\|shadow]` | show or set the compat engine flag |
| `crawlx admin audit-export --tenant <id>\|--all [--day <date>]` | write the daily Merkle root of the audit chain |
| `crawlx inspect trail <run-id>` | trail verifier: checks the journal, safety-decision and trust-lane invariants of a run, exit 1 on violations; `inspect actions <run-id> --status unknown` lists rows |
| `crawlx healthcheck --url <url>` | exit 0 for a 2xx answer; `/v0/health/readiness` proves storage answers |
| `crawlx config check` | validate `crawlx.toml` and `CRAWLX_*` before rolling a configuration |
| `crawlx migrate` | apply migrations (pre-deploy Job); never run `down` migrations in production |

### Independent safety auditor

Apply `0022_safety_auditor.sql` through the normal `crawlx migrate` deployment Job using the
DDL credential **before** starting the auditor. The auditor itself never runs migrations.
Migration 0022 creates two capability roles, both `NOLOGIN`:

- `crawlx_safety_reader` can select `safety_auditor_actions`, a cross-tenant view containing
  action/run/tenant identifiers and violation reasons, not raw request or evidence bodies.
- `crawlx_safety_pauser` can execute `safety_auditor_chain_head()` and
  `safety_auditor_pause(uuid,text,bytea,bytea)`. This capability pauses violating runs and records
  the pause in the audit chain; it does not grant arbitrary updates or resume/cancel authority.

Create separate, otherwise unprivileged LOGIN members using an administrative PostgreSQL session.
For example, with `psql` connected to the production `crawlx` database:

```sql
CREATE ROLE crawlx_safety_reader_login LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE crawlx_safety_pause_login LOGIN INHERIT
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT crawlx_safety_reader TO crawlx_safety_reader_login;
GRANT crawlx_safety_pauser TO crawlx_safety_pause_login;
GRANT CONNECT ON DATABASE crawlx TO crawlx_safety_reader_login, crawlx_safety_pause_login;
\password crawlx_safety_reader_login
\password crawlx_safety_pause_login
```

Set unique generated passwords through your secret manager or the interactive `\password`
prompts, never literal SQL in shell history. Adjust the database name if needed. Do not grant
either login any other membership, base-table permissions, object ownership, schema `CREATE`,
DDL, tenant RLS bypass, or the other safety role. Remove broad `PUBLIC` schema-create rights
if your database still grants them. The runtime checks the two distinct LOGIN roles and rejects
privileged or cross-member connections; there is no privileged fallback.

Production one-shot invocation, after injecting both DSNs from the secret manager:

```sh
crawlx admin safety-audit \
  --reader-database-url "$CRAWLX_SAFETY_READER_DATABASE_URL" \
  --pause-database-url "$CRAWLX_SAFETY_PAUSE_DATABASE_URL" \
  --json
```

Prefer `crawlx admin safety-audit --json` when those two environment variables are already set:
this keeps credentials out of process argument listings. Both DSNs must target the same database,
use different provisioned logins, and require authenticated TLS. `CRAWLX_DATABASE_URL`,
`CRAWLX_DATABASE_URL_FILE`, worker configuration, and `--operator` are not auditor inputs.
Never inject API, worker, migration, or ordinary admin credentials into the auditor.

JSON contains `checked`, `violations` (`tenant`, `run`, `action`, `reason`), and `paused`.
Exit 0 means the audit completed without violations. Exit 1 with an audit report means violations
were found; the storage auditor automatically pauses affected active runs through its minimal pause
capability. Connection, role-validation, storage, or output errors propagate as command failures;
do not mistake a missing report for a clean result. Preserve reports and follow [card 13](#13-crawlxsafetyinvariantviolation) for any
violation. Investigate before manually resuming paused runs.

The command increments `names::SAFETY_INVARIANT_VIOLATIONS`
(`crawlx.safety.invariant_violations`, label `reason`) in its short-lived process.
The [Kubernetes deployment guide](../../deploy/k8s/README.md#independent-safety-auditor) provides the
one-minute CronJob, independent credential secrets, and PostgreSQL-only service egress (plus DNS).
The schedule uses the API CLI image, not a browser worker. It does not export process-local metrics;
route failed Jobs and preserved JSON to paging rather than assuming Prometheus scraped the counter.
<a id="rollback-toolbox"></a>

**Rollback toolbox** (cards name these):

| Id | Rollback |
|---|---|
| R-APP | Redeploy the previous image: `helm rollback <release> <revision>` (chart `deploy/helm/crawlx`; API Deployment `<release>-api`, worker Deployments `<release>-<pool>`), or `kubectl rollout undo deploy/<name>` with the plain manifests in `deploy/k8s/`. The previous binary runs on the expanded schema (N and N-1 compatibility). Drain workers first (`crawlx admin drain --worker <id>`); never delete a worker pod mid-action. No `down` migrations. |
| R-CFG | Revert the configuration in version control, run `crawlx config check`, then roll. |
| R-CHROMIUM | Redeploy the previous image tag and revert `chromium-pin.toml`; sessions resume from checkpoint by re-observing. |
| R-MODEL | Roll back to the previous model artifact (versioned independently) and check the calibration version matches ([RB-05](#rb-05) step 3). |
| R-ENGINE | `crawlx admin engine --tenant <id> --set firecrawl`: new compat crawls go to the configured Firecrawl engine instead; in-flight crawls finish where they started. |
| R-ADMISSION | `crawlx admin resume --admission --crawl <id>` (or `--all` after listing paused runs) after a `drain --admission` or `freeze` ([RB-04](#rb-04) step 8, [RB-07](#rb-07) step 7, [RB-11](#rb-11)). |

---

## Runbooks RB-01 to RB-12

Format: trigger, numbered steps in order, exit criteria. Never run a step marked **STOP** out of
order. `drain` fallback: cordon the pod in the orchestrator and wait for its leases to be
released before termination. The [alert cards](#alert-cards) at the end of this file say which
runbook takes over for each alert rule.

<a id="rb-01"></a>

### RB-01 Stuck crawl

Trigger: no progress for 10 minutes on a crawl in `running` (dashboard "Crawl health"), the
`CrawlxQueueStall` alert, or a user report.

1. Identify scope: one crawl, one tenant, or all crawls. If all, treat it as SEV-2 and check
   [RB-07](#rb-07) (database) and [RB-04](#rb-04) (leases) first.
2. **Inspect the lease.**

   ```sql
   SELECT s.session_id, s.role, s.run_index, s.status, s.lease_owner, s.fencing_token,
          s.lease_expires_at, w.last_heartbeat_at AS worker_heartbeat, w.draining
   FROM crawl_sessions s LEFT JOIN workers w ON w.worker_id = s.lease_owner
   WHERE s.run_id = $1 ORDER BY s.schedule_slot;
   ```

   No holder or an expired lease means the reaper has not run or the scheduler is not granting
   turns. Check that `scheduler.admission` is `open` and, for shared targets, that the
   round-robin turn barrier is not waiting on a failed slot of the previous run. A slot in
   `failed` or `cancelled` releases it; a slot stuck in `running` with an expired lease does
   not until the reaper reclaims it.
3. **Inspect the current action state.**

   ```sql
   SELECT action_id, status, hold, lane, intended_at FROM actions
   WHERE session_id = $1 AND status IN ('intended','unknown') ORDER BY intended_at;
   ```

   Any `intended` row older than `scheduler.session_lease_ttl_s`, or any `unknown` row, sends
   you to [RB-02](#rb-02) **before** anything else touches that session.
4. **Inspect browser and CDP health** on the worker holding the lease: `crawlx.browser.sessions`,
   RSS against the cgroup limit, `crawlx.browser.crashes`, `crawlx.session.recoveries` by
   `rung`, and the session's last settle report. A hung CDP socket with a live process is rung 1
   of the recovery ladder (reattach); a dead process is rung 2 (new context plus checkpoint
   restore).
5. **Inspect the frontier:** `SELECT status, count(*) FROM url_frontier WHERE run_id = $1 GROUP BY status;`.
   An empty eligible frontier with open interaction candidates, or all remaining entries
   denied by politeness backoff (`origin_leases.backoff_until`), is not a stall; report the
   reason.
6. Check for journal halts: `crawlx.journal.halts` and the session state `HaltedStorage`. If the
   intent journal is unwritable the session is correctly refusing to mutate; resolve storage
   first ([RB-07](#rb-07)), then proceed.
7. **STOP** if any action is `unknown`: finish [RB-02](#rb-02) for it. Do not retry writes
   manually and do not restart the session before reconciliation.
8. Recover: `crawlx admin resume --crawl <id>` (or `POST /v1/crawls/{id}:resume`). If the
   session cannot recover after the ladder (`recovery_exhausted`), continue to step 9.
9. Terminate with an explicit reason if recovery fails or the target is unusable:
   `POST /v1/crawls/{id}:cancel` (reason `cancelled`) for an operator decision, or leave the
   system to set `fatal_error`. Record the finding in the incident ticket. Never leave a run in
   `running` with no holder.
10. Exit criteria: the crawl is progressing (counters increase over 5 minutes) or terminal with a
    recorded reason; no `intended` or `unknown` rows remain for it.

<a id="rb-02"></a>

### RB-02 Unknown-outcome reconciliation

Trigger: `crawlx.interactions.unknown_unreconciled` above 0 for 10 minutes, any worker kill, or a
hand-off from RB-01, RB-03 or RB-04. Principle: **`unknown` is not `failed`**; the browser may
have acted. The `actions` state machine is
`proposed → intended → {succeeded | failed | unknown} → reconciled`
(see [crawl model](../design/crawl-model.md#intent-journal)).

1. List the rows:

   ```sql
   SELECT action_id, session_id, status, lane, intended_at FROM actions
   WHERE status = 'unknown' ORDER BY intended_at;
   ```

   Check that the lease reaper has already moved expired `intended` rows to `unknown`. If
   `intended` rows persist past the lease TTL, the reaper is not running ([RB-04](#rb-04)).
2. Ensure the session is recoverable: a live Session Actor, or a restored checkpoint (a
   `checkpoints` row for the session). Without either, the reconciler cannot observe; restore
   first through the recovery ladder.
3. Run reconciliation: `crawlx admin reconcile --action <id>`. The reconciler observes the
   restored session (a session in `recovering` is mid-reconciliation), fingerprints it, and
   compares with the action's before-state cluster and recorded expected effect. The outcome is
   stored in `actions.reconcile_resolution`:
   - `not_applied`: still in the before-cluster with no effect markers. The row becomes
     `reconciled` and the same `action_id` is eligible again.
   - `applied`: after-cluster or effect marker present. The row becomes `reconciled`, is counted
     with `confidence = low`, and is never retried for non-idempotent kinds.
   - `indeterminate`: the row becomes `reconciled` and is treated like `applied` for
     non-idempotent kinds.
4. For `indeterminate` results on consequential actions (destructive, persistent write, external
   communication), verify against the **target system's own records** (its audit log, or the
   CrawlerGym ledger in test environments) and attach the evidence to the ticket. If still
   unclear, leave the action `reconciled` and blocked from retry; do not guess.
5. **Never** `UPDATE actions SET status = 'failed' ...` or delete rows to clear the alert. A manual
   status override requires two operators, is limited to setting `reconciled`, and writes an
   admin audit entry.
6. Investigate why outcomes became unknown: worker kill, node drain, OOM, journal T2 failures
   (`crawlx.journal.t2.duration`, database errors). Growth with healthy workers points at storage
   ([RB-07](#rb-07)).
7. If the same `action_id` shows two backend effects, declare SEV-1 and go to [RB-12](#rb-12).
8. Exit criteria: `unknown_unreconciled` is 0; every reconciled row has a recorded outcome class;
   the eligible-actions query returns only `proposed` or `reconciled` rows.

<a id="rb-03"></a>

### RB-03 Browser crash loop

Trigger: crash-rate alert, many sessions in recovery, often after a Chromium or image rollout.

1. Scope: one target (target-specific page crash), one worker (node problem), or all workers (bad
   build). Check `crawlx.browser.crashes` by `reason` and the canary label of crashing workers.
2. If a rollout preceded the incident, **roll back first** ([R-CHROMIUM](#rollback-toolbox)).
   Drain rather than kill: `crawlx admin drain --worker <id>`.
3. Check node health: memory pressure and OOM kills against the Chromium cgroup limits,
   `/dev/shm` exhaustion, PID limits, disk on the tmpfs profile directory, and seccomp denials (a
   profile change can break the sandbox).
4. Compare `chromium-pin.toml` with the running image and the `BrowserBuildInfo` of recent
   sessions; `PinMismatch` errors point at a bad image.
5. If one target crashes renderers: `crawlx admin pause --crawl <id>`, capture the replay bundle
   and a Chromium trace on a canary session, and open a target-specific ticket (SEV-3). Do not
   disable crash handling.
6. Confirm the crash-loop breaker paused the affected runs rather than respawning without bound.
   Any `unknown` actions created follow [RB-02](#rb-02).
7. Reduce load while recovering: lower `worker.max_sessions` and `worker.contexts_per_browser` for
   the affected pool (configuration roll) to avoid memory thrash.
8. Exit criteria: crash rate back to baseline for 30 minutes; paused runs resumed or terminated
   with a reason; `unknown` actions reconciled.

<a id="rb-04"></a>

### RB-04 Lease storm

Trigger: `lease.expired` above 10 per minute, or `lease.stale_unreconciled` above 0 for 5
minutes. Typical causes: database latency, a CPU-starved worker pool, clock problems, or a
network partition between workers and PostgreSQL.

1. Check PostgreSQL first: `crawlx.scheduler.op.duration`, lock waits, connection saturation,
   replication and failover events ([RB-07](#rb-07)). Heartbeats that cannot commit look like
   dead workers.
2. Check workers: CPU throttling (cgroup), event-loop stalls, CPU pool queue depth. Heavy hashing
   or snapshot decoding must run on the CPU pool, not the reactor.
3. Lease expiry uses the database clock only. If lease anomalies coincide with `now()` jumps on the
   database host, treat it as a database incident.
4. Prevent a thundering herd: set `scheduler.admission = drain` (`crawlx admin drain --admission`)
   so no new leases are granted while stale ones are reclaimed, and cap the reaper batch size.
5. Verify **fencing**: `crawlx.lease.fenced` increments when a resumed old holder is refused. Two
   workers must never mutate one session. If two holders acted on one session, declare SEV-1
   and go to [RB-12](#rb-12).
6. Raise `scheduler.session_lease_ttl_s` temporarily (for example 30 → 60 s) only if the cause is
   transient database latency. Revert afterwards; a longer TTL puts the 2-minute reconciliation
   objective at risk.
7. Reconcile the resulting `unknown` rows ([RB-02](#rb-02)).
8. Set `scheduler.admission = open` (`crawlx admin resume --admission`) and scale workers back up
   in steps.
9. Exit criteria: `lease.expired` at baseline; `lease.stale_unreconciled = 0`; round-robin turns
   progressing.

<a id="rb-05"></a>

### RB-05 Model provider failure (breaker)

Trigger: `crawlx.model.breaker.state` open for a provider for 5 minutes, or high
`crawlx.model.requests` failures or latency. Design: the breaker opens, ranking falls back to the
deterministic strategies, safety classification stays fail-closed where required, and there is
no provider retry storm.

1. Confirm the breaker opened and the fallback is active: `crawlx.model.breaker.state`,
   `crawlx.model.abstentions`, and arbiter decisions attributed to deterministic strategies.
   Check that the provider request rate dropped rather than rose.
2. Determine the cause: provider outage, quota or rate limit, credential expiry, model-server GPU
   failure, or a bad model artifact (parity or calibration mismatch at startup).
3. If the decision service or the ONNX ranker artifact is at fault, roll back to the previous
   model version (artifacts are versioned independently) and verify that the calibration
   version matches.
4. If only the LLM planner is down, runs with `llmPlanner: "stalled_only"` continue with
   deterministic strategies; stalled planners wait or finish with a recorded reason rather than
   blocking the crawl.
5. **Never** disable the safety kernel or loosen a profile to compensate. If a safety classifier
   needs a model and none is reachable, the action stays denied (fail-closed).
6. Do not raise breaker thresholds to "keep the model on". If provider flapping causes
   oscillation, increase the cooldown.
7. For ZDR runs, never fail over to a provider that does not guarantee zero retention; those runs proceed
   without the typed-decision engine or the LLM planner.
8. Exit criteria: provider healthy for 15 minutes; the breaker half-open probe succeeded; model
   decisions resumed in `shadow` or `advisory` as configured.

<a id="rb-06"></a>

### RB-06 Object-store outage

Trigger: object-store error-ratio alert, or `spool_bytes` rising.

1. Confirm scope: provider status, credentials (expiry or rotation), endpoint DNS, bucket policy,
   quotas. Distinguish a read failure (artifact serving) from a write failure (capture).
2. Objects complete **before** their index and relational references are published. Queued and
   active uploads share bounded in-memory byte and entry reservations; each caller owns its
   upload lifetime. Retryable backend failures use the configured attempt and deadline bounds.
   Full capacity backpressures callers; exhaustion returns a typed failure. Cancelling or
   shutting down releases reservations and cannot leave a detached upload or a durable
   plaintext spool. A process crash does not preserve this queue; only already-committed
   checkpoints remain authoritative.
3. Watch `crawlx.objectstore.spool_bytes` against `object_store.spool_max_bytes`. At 50 % reduce
   capture load (`capture.screenshot` to `on_novel_state` only, `domSnapshot` to `checkpoint`
   only) by configuration. At 90 % pause new crawls with `scheduler.admission = drain` rather
   than lose artifacts.
4. Checkpoints need the store: a failed checkpoint upload leaves the previous checkpoint
   authoritative. If no checkpoint exists, avoid actions classified `consequential` (the kernel
   already requires a checkpoint before them).
5. Do not shorten retention or delete objects to free space during the outage.
6. After recovery, confirm the spool drains, run
   `crawlx admin verify-artifacts --since <outage start>` to confirm every `artifacts` row has
   its object and digest, and let the orphan sweeper collect objects with no row.
7. Exit criteria: error ratio at baseline; spool empty; `verify-artifacts` reports zero missing;
   paused runs resumed.

<a id="rb-07"></a>

### RB-07 Database failover

Trigger: primary unavailable, planned switchover, or replica promotion. Intent-journal
unavailability halts mutation by design.

1. Declare the incident (SEV-2 if writes are unavailable longer than 5 minutes). Set
   `scheduler.admission = drain` so workers do not take new leases against a flapping primary.
2. Confirm the new primary: promotion completed, old primary fenced (never two writers),
   applications pointing at the new endpoint, `pg_is_in_recovery()` false.
3. Observe sessions: `crawlx.journal.halts` rise and then clear; sessions in `HaltedStorage` resume
   only after a journal write succeeds. No session may have mutated the page while the journal
   was unwritable.
4. Expect lease expiries and `intended` → `unknown` conversions; reconcile them
   ([RB-02](#rb-02)). With asynchronous replication, check for lost recent transactions: run
   `crawlx admin durability-audit` (any missing accepted run is SEV-1) and compare
   `crawl_sessions.action_seq` per session with the latest `checkpoints.action_seq`.
5. Run `crawlx admin verify-artifacts` for the failover window.
6. Restore the replica topology; verify replication lag below 30 s and re-enable API reads from
   the replica.
7. Reopen admission (`scheduler.admission = open`) and scale workers up in steps.
8. Exit criteria: write latency and `crawlx.scheduler.op.duration` p95 at baseline; no missing
   accepted jobs; no unreconciled `unknown`; postmortem if SEV-2.

<a id="rb-08"></a>

### RB-08 Retention and ZDR cleanup failure

Trigger: `retention.overdue_artifacts` above 0, `retention.sweep.failures` increasing, or
`zdr.violations` above 0.

1. Classify by `kind`. **A ZDR violation, or any overdue `zdr` artifact (including the `zdr/`
   delivery buffer past its TTL), is SEV-1**: go to step 2. Overdue `standard` or `extended`
   artifacts are SEV-3: go to step 5.
2. Find the writer that violated the gate:

   ```sql
   SELECT a.artifact_id, a.run_id, a.kind, a.sensitivity, a.expires_at
   FROM artifacts a JOIN crawl_runs r ON r.run_id = a.run_id
   WHERE r.retention_mode = 'zdr' AND a.sensitivity <> 'metadata' AND a.deleted_at IS NULL;
   ```

   Also list the object-store prefixes other than `zdr/` for the same runs. The write gate in
   `crawlx-storage` should make this impossible, so treat it as a bug.
3. Containment: pause new ZDR crawls (`crawlx admin pause --tenant <t>`), then delete the content
   objects first and the rows afterwards (`crawlx admin sweep-retention --mode zdr --force`),
   preserving the structural trail. Record deleted keys (not contents) in the admin audit log.
4. Check backups and replicas that may hold the data, schedule deletion
   ([restore procedure](#backup-and-restore), step 6), and notify the data
   protection contact. Rotate the run data keys for affected runs. Continue to
   [RB-12](#rb-12) if a leak to third parties is possible.
5. For `standard` and `extended`: the sweeper is the command `crawlx admin sweep-retention`, which you
   schedule yourself (a cron job or Kubernetes CronJob; there is no built-in loop). Check that the
   job runs and how often, its logs and `retention.sweep.failures`, permissions on the bucket and the
   database role, and object-store lifecycle conflicts. The sweeper deletes the object first, then
   the row; a failure retries on the next pass and alerts.
6. Run `crawlx admin sweep-retention` manually in batches if the backlog is large; watch database
   and object-store load.
7. Exit criteria: `overdue_artifacts` is 0 for every kind; `zdr.violations` stops increasing; the
   root cause is fixed; a regression test is added.

<a id="rb-09"></a>

### RB-09 Webhook backlog

Trigger: `webhook.oldest_pending_age` above 15 minutes, or the `delivered` ratio falling.

1. Scope: one tenant endpoint (SEV-3) or all (SEV-2). Compare `webhook.deliveries` outcomes across
   tenants.
2. Inspect the delivery queue:

   ```sql
   SELECT status, count(*), min(next_attempt_at) FROM webhook_deliveries
   WHERE status IN ('pending','dead') GROUP BY status;
   ```

   `dead` rows are exhausted deliveries. Look for lock contention, an exhausted worker pool, or a
   poisoned row repeating.
3. Global failure: check API pods (CPU, database pool), outbound DNS and egress rules for the
   webhook sender, signing-key availability (a missing secret file makes every signature fail),
   and TLS trust-store changes.
4. Single endpoint failing: confirm from the delivery log (status code, latency, TLS error); the
   retry schedule continues with backoff. Contact the receiver's owner; do not hammer the
   endpoint, and keep the per-endpoint concurrency cap.
5. If the retry window is about to expire for terminal events, extend `api.webhook.retry_window`
   for the affected tenant, or allow manual replay. `GET /v1/crawls/{id}` always shows the
   terminal state, so integrations can poll.
6. After recovery, redeliver pending events in order. Deliveries are at-least-once and carry an
   idempotency key so receivers can deduplicate.
7. Exit criteria: `oldest_pending_age` under 1 minute; the 7-day delivery ratio back at or above
   99.9 % or a documented exception.

<a id="rb-10"></a>

### RB-10 Hot target (politeness breach)

Trigger: `fetch.politeness_violations` above 0, a target owner complaint, sustained `429` or
`503`, or a spike of `crawlx.fetch.throttles`.

1. Pause the crawl against that origin immediately: `crawlx admin pause --crawl <id>` (or
   `POST /v1/crawls/{id}:pause`). Identify the origin from logs (origin hash to origin mapping in
   the structured log), not from metric labels.
2. Verify defaults: per-origin in-flight is 1 and spacing at least 250 ms
   (`fetch.per_origin_inflight`, `fetch.min_spacing_ms`), and that adaptive back-off activated
   on `429` or `503` (`crawlx.fetch.origin_wait` growth). A violation means two code paths
   bypassed the per-origin limiter; the browser plane counts too, because sessions on the same
   origin multiply load.
3. Compute aggregate load: the number of active sessions against the origin (`crawl_sessions` by
   seed host) times action rate. Several tenants crawling one target multiply load; reduce
   `worker.max_sessions` for that origin through the per-tenant or per-origin cap.
4. Resume with higher spacing (for example 1000 ms) and a lower session count. Honor `Retry-After`.
   A `Crawl-delay` in `robots.txt` (capped at 10 seconds) is applied automatically as the minimum
   spacing of runs that obey robots, on the workers that have read it; set `politeness.delayMs` for
   anything the site asks beyond that cap or for runs that override robots.
5. If the target owner requests no further crawling, add the host to the operator blocklist and
   terminate with `policy_stopped`: write it to the file named by
   `egress.operator_blocklist_file` (`CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE`, one host per line),
   send `SIGHUP` to every `crawlx serve` and `crawlx worker` process (or wait up to 60 s for the
   poll), then `crawlx admin cancel --crawl <id> --reason policy-stopped`. Every run in flight
   refuses the host and its subdomains on its next connection (`operator_blocklist` in
   `crawlx.egress.denials`), and new runs are refused at admission with `url_denied`. A static
   `egress.operator_blocklist` in `crawlx.toml` needs a restart.
6. Exit criteria: no violations for 24 hours; the target owner acknowledged where contacted; a
   regression test added in `crawlx-fetch`.

<a id="rb-11"></a>

### RB-11 Emergency stop (one crawl, one tenant, all crawls)

Trigger: safety concern, target owner request, runaway cost, or SEV-1 containment. Order matters:
stop mutation first, evidence second.

Level 1, one crawl:

1. `crawlx admin pause --crawl <id>` or `POST /v1/crawls/{id}:pause`. The Session Actor stops at
   the next action boundary (between actions; it never abandons an action mid-flight).
2. Verify: `crawl_runs.pause_requested_at` is set, `status` moves `pausing` → `paused`, and no
   `intended` rows remain.
3. To end the crawl: `POST /v1/crawls/{id}:cancel` (reason `cancelled`; for safety-related stops
   use `policy_stopped`).

Level 2, one tenant or all crawls:

1. `crawlx admin pause --tenant <t>` or `crawlx admin pause --all`; also `crawlx admin freeze`,
   which sets `scheduler.admission = frozen`: no new leases, and every Session Actor halts at its
   next boundary when it observes the flag at heartbeat (at most `scheduler.heartbeat_s`).
   SQL fallback:
   `UPDATE crawl_runs SET pause_requested_at = now() WHERE status = 'running' AND tenant_id = $1;`
   (the run coordinator evaluates pause requests).
2. Confirm: `crawlx.crawls.active` unchanged, the `crawlx.interactions.executed` rate zero within
   two heartbeats, no new `intended` rows.

Level 3, hard stop (the actor is not responding, or an incident is actively harmful):

1. Cut egress: apply the deny-all egress `NetworkPolicy` to the worker pool, or set the
   load-balancer rule that blocks the egress NAT. This stops page and HTTP traffic regardless of
   software state.
2. Scale workers to zero (`kubectl scale ... --replicas=0`). This **will** create `intended` rows
   that become `unknown`.
3. Treat every `intended` row as unknown: after the incident, restore workers with
   `scheduler.admission = drain` and run [RB-02](#rb-02) before opening admission.
4. Preserve evidence first when SEV-1 ([RB-12](#rb-12) step 3); a hard stop destroys in-memory
   state.

Resume: `crawlx admin resume`, then `scheduler.admission = open`; resume crawls individually, not
all at once.

<a id="rb-12"></a>

### RB-12 SEV-1 containment

Covers: safety bypass, tenant isolation failure, credential leak, private-network bypass,
duplicated writes, metadata corruption.

1. Page the incident commander; open the incident channel; record the start time.
2. Contain: [RB-11](#rb-11) level 2 for the affected tenant or all crawls. For a credential leak
   also revoke the exposed credential at its source and rotate the secret.
3. Preserve evidence before cleanup: snapshot the relevant `actions`, `safety_decisions`,
   `approvals` and `traffic_events` rows (export them to a restricted evidence bucket), keep worker
   logs and traces, and take a database snapshot if corruption is suspected. Do not delete
   artifacts that are evidence, except ZDR content, which is deleted per [RB-08](#rb-08) with the
   deletion logged.
4. Classify: safety bypass (which profile and rule, which action class), tenant isolation (which
   tenant boundary), credential leakage (where, which secret, how long exposed), private-network
   bypass (which plane, which range), duplicated action (which `action_id`, backend effect
   confirmed on the target), metadata corruption (auditor output).
5. Identify the trigger release and roll back if one is implicated; otherwise ship a targeted fix
   with a regression test (a CrawlerGym fixture or a risk-matrix row) before reopening.
6. Notify affected parties (customers, target owners, regulators where applicable). Involve
   counsel for personal-data incidents.
7. Reopen gradually: one tenant canary, auditor green for 24 hours.
8. Write a postmortem within 5 working days.

## Backup, restore, migrations and rollback

### Backup and restore

| Asset | Backup | Targets |
|---|---|---|
| PostgreSQL | Continuous WAL archiving plus daily base backups, verified by automated restores | RPO 5 minutes, RTO 60 minutes (suggested) |
| Object store | Versioning enabled; optional cross-region replication; lifecycle expiry aligned with retention | Per provider |
| Secrets and keys | Provider-managed with documented recovery (the artifact key file or KMS key must survive: sealed artifacts are unreadable without it) | |
| Configuration, pin file, dashboards | Version control | |

Point-in-time restore:

1. Declare the incident; `crawlx admin freeze` and scale workers to zero; keep the API in
   maintenance mode.
2. Restore the base backup and replay WAL to the chosen timestamp into a **new** cluster. Do not
   overwrite the damaged primary until the restore is validated.
3. Run `crawlx migrate` against the restored cluster and confirm it reports no pending migration
   for the binaries you will deploy.
4. Reconcile with the object store: `crawlx admin verify-artifacts` lists rows whose objects are
   missing and objects without rows (collected by the orphan sweeper). Objects are written before
   the transaction that references them, so rows never legitimately point at objects that never
   existed.
5. Every session whose last action is `intended` becomes `unknown` through normal lease expiry; run
   [RB-02](#rb-02) before reopening admission.
6. **Replay deletions.** Record erasure requests and ZDR or retention deletions in an operations log
   outside the database backup chain, retained at least as long as backups. After any restore,
   replay that log and run `crawlx admin sweep-retention` **before** reopening the API, so a
   restore never resurrects erased or expired data.
7. Reopen admission gradually and record the actual RPO and RTO.

WAL archiving, the deletion operations log and restore drills are infrastructure work outside this
repository.

### Schema migrations

`crawlx migrate` applies sqlx migrations under an advisory lock, as a pre-deploy Job with the
migration role; it is idempotent. The Helm chart runs `crawlx config check` before it.

1. **Expand, then contract.** A release ships only backward-compatible expansions (new nullable
   columns, new tables, `CREATE INDEX CONCURRENTLY`). Contraction (dropping columns, tightening
   constraints) ships at least one release later, when no running binary uses the old shape.
2. **N and N-1 compatibility.** During a rolling deploy, old and new binaries run against the same
   schema.
3. Review the migration for locks and duration on a restored copy, take a fresh base backup or
   confirm WAL is current, run the Job, roll the API and then the workers (drain), and watch the
   storage dashboard for lock waits and replication lag.

### Rollback

1. Application rollback is first and cheap: redeploy the previous image. It works with the expanded
   schema. Workers are drained, not killed.
2. Do not run `down` migrations in production. If an expansion was wrong, ship a forward fix.
3. If a contraction migration was applied and the rollback needs the dropped data, restore to a
   side cluster and copy the data you need; do not revert in place.
4. Configuration rollback goes through version control; `crawlx config check` runs before the roll.
5. A Chromium rollback means redeploying the previous image and reverting `chromium-pin.toml`.

## Alert cards

One card for each of the 32 rules, in file order.

## 1. CrawlxApiAvailabilityFastBurn

**SEV-2, page.** API error ratio at 14.4 times the 0.1 % budget over both 1 h and 5 min, for 2 min. At that rate the 30-day budget (43.2 min) is gone in about two days.

- **Symptom.** Clients see 5xx or timeouts on `/v1` and `/compat` routes.
- **Dashboards.** SLO overview: "API availability (30d)", "API error-budget burn rate (1h / 6h)", "Open alerts". Storage: "DB pool in use / query p95 by op", "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)".
- **First commands.**

  ```sh
  crawlx healthcheck --url http://<api>:8080/v0/health/readiness   # 2xx means storage answers
  crawlx admin status
  ```

  ```promql
  topk(5, sum by (route) (rate(crawlx_api_requests_total{outcome="error"}[5m])))
  ```

- **Then.** Ask what changed in the last two hours (deploy, configuration, migration, secret rotation, Chromium rollout). A change: roll it back first (SEV-2 practice). Storage errors: [RB-07](#rb-07). Otherwise the API tier is stateless: scale it out and read the per-route breakdown.
- **Rollback.** R-APP; R-CFG; for tenants served through the compat facade R-ENGINE.

## 2. CrawlxApiAvailabilitySlowBurn

**SEV-2, page.** Burn of 6 times over 6 h and 30 min, for 5 min; the budget lasts about five days at this rate.

- **Symptom.** A steady fraction of requests fails: one route, one dependency or one tenant's traffic shape.
- **Dashboards.** As card 1.
- **First commands.** The `topk` query of card 1 over `[30m]`; `crawlx admin status`; the release and change log for the last 6 h.
- **Then.** Correlate with a release: roll back. No change: find the failing route and its dependency (database pool, object store, webhook watch); fix forward inside the budget and note the burn in the incident record.
- **Rollback.** R-APP, R-CFG.

## 3. CrawlxApiAvailabilityBudgetTicket

**SEV-3, ticket.** Error rate above budget over 3 days for 1 h.

- **Symptom.** None acute; the monthly budget will be missed at this rate.
- **Dashboards.** SLO overview: "API availability (30d)".
- **First commands.** The `topk` query of card 1 over `[3d]`.
- **Then.** Triage in the daily check; open a reliability item naming the route and cause; apply your error-budget policy.
- **Rollback.** None; this ticket is not an incident.

## 4. CrawlxApiBlackboxProbeFailing

**SEV-2, page.** The external probe of `GET /v1/crawls/{probe_id}` failed three consecutive 30 s probes. The probe needs a stable `probe_id` and a `crawls:read` key; a probe whose key or id was removed fails as an outage would.

- **Symptom.** The API is down, or the path from the probe to it is (DNS, certificate, ingress, load balancer).
- **Dashboards.** SLO overview: "Open alerts". Storage: "DB pool in use / query p95 by op".
- **First commands.**

  ```sh
  crawlx healthcheck --url http://<api>:8080/v0/health/liveness    # process serves requests
  crawlx healthcheck --url http://<api>:8080/v0/health/readiness   # storage answers
  ```

  Internal request metrics flowing normally while the probe fails points at the path, not the API.
- **Then.** Probe path broken: fix DNS, certificate or ingress (outside this repository). API down: card 1 and [RB-07](#rb-07) for storage.
- **Rollback.** R-APP when a deploy preceded it.

## 5. CrawlxAcceptedJobMissing

**SEV-1, page.** `crawlx_jobs_durability_audit_missing_total` increased: an accepted job (a `201` or an idempotent replay) has no `crawl_runs` row. Metadata corruption.

- **Symptom.** A customer holds a crawl id that `GET /v1/crawls/{id}` cannot find.
- **Dashboards.** SLO overview: "Job durability (missing / checked)". Storage: "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)", "Table growth (traffic_events, transitions, actions)".
- **First commands.**

  ```sh
  crawlx admin durability-audit --json                              # which run ids are missing; exit 1
  crawlx admin durability-audit --since <incident-start-rfc3339> --json
  crawlx admin freeze --all                                         # stop mutation first ([RB-11](#rb-11) level 2)
  ```

- **Then.** [RB-12](#rb-12) (SEV-1 containment: evidence before cleanup, classification "metadata corruption", postmortem within 5 working days). After a database failover this is the lost-transaction check of [RB-07](#rb-07) step 4 (asynchronous replication). Compare `crawl_sessions.action_seq` with the latest `checkpoints.action_seq` per session.
- **Rollback.** There is no application rollback for lost rows; restore from backup into a side cluster ([restore procedure](#backup-and-restore)) and copy the missing rows back. Reopen admission with R-ADMISSION only when the audit is clean for 24 h.
- **Caveat.** The audit increments its counters inside the CLI process. Nothing scrapes a short-lived process, so this rule fires only if the audit runs where Prometheus can read it (a textfile collector written by the cron wrapper, or a scraped runner). The exit code (1) is the reliable signal; page from it as well.

## 6. CrawlxDurabilityAuditStale

**SEV-3, ticket** (SEV-2 if stale for over 1 h after a failover: the SEV-1 detector is blind). No audit pass completed for 15 min while crawls are active.

- **Symptom.** None visible; the durability SLO is unmeasured.
- **Dashboards.** SLO overview: "Job durability (missing / checked)".
- **First commands.** Run the audit by hand: `crawlx admin durability-audit --json`. Check the scheduler that runs it (cron job or Kubernetes CronJob) for failures.
- **Then.** Restore the schedule (every 5 minutes is the suggested cadence). While it is down, run the command manually after every failover.
- **Rollback.** None.

## 7. CrawlxWebhookBacklog

**SEV-3, ticket** (SEV-2 when global). Oldest pending webhook older than 15 min and the `retry` rate above 5 % over 15 min.

- **Symptom.** Customers receive completion events late.
- **Dashboards.** Retention and webhooks: "Webhooks: pending, oldest age, outcomes".
- **First commands.**

  ```sql
  SELECT status, count(*), min(next_attempt_at) FROM webhook_deliveries
  WHERE status IN ('pending','dead') GROUP BY status;
  ```

- **Then.** [RB-09](#rb-09) steps 1 to 4: one tenant endpoint (SEV-3, contact the customer, do not hammer it) or all endpoints (SEV-2, card 8).
- **Rollback.** R-APP if the sender was deployed recently.

## 8. CrawlxWebhookGlobalFailure

**SEV-2, page.** Global delivered ratio below 50 % over 15 min with at least 20 attempts.

- **Symptom.** No customer receives events.
- **Dashboards.** Retention and webhooks: "Webhooks: pending, oldest age, outcomes". Storage: "DB pool in use / query p95 by op", for lock contention on the delivery queue.
- **First commands.** The SQL of card 7; API pod CPU and database pool; confirm the signing key file is mounted (a missing secret file fails every signature); outbound DNS and egress rules of the API pods.
- **Then.** [RB-09](#rb-09) step 3 (global failure). A `dead` row caused by crawlx (signing error, our sender's 5xx, queue lock) is a defect: record it.
- **Rollback.** R-APP, R-CFG (signing key reference).

## 9. CrawlxWebhookSliBreach

**SEV-3, ticket.** 7-day terminal-event delivery ratio below 99.9 %.

- **Symptom.** None acute.
- **Dashboards.** Retention and webhooks: "Webhooks: pending, oldest age, outcomes"; SLO overview: "Terminal webhook delivery (7d)".
- **First commands.** `SELECT status, count(*) FROM webhook_deliveries GROUP BY status;` and the exhausted rows by tenant.
- **Then.** Monthly review of retry-exhaustion causes; tenants with disabled endpoints are excluded from the SLI by definition.
- **Rollback.** None.

## 10. CrawlxStaleLeasesUnreconciled

**SEV-2, page** (SEV-1 if two holders acted on one session). `lease.stale_unreconciled` above 0 for 5 min: the reaper has not moved expired leases' `intended` actions to `unknown`.

- **Symptom.** Sessions sit with expired leases; crawls stop progressing.
- **Dashboards.** Scheduler and leases: "Lease expired / fenced / reconcile p99.9", "Scheduler op p95 by op / lease hold p95". Storage: "DB pool in use / query p95 by op".
- **First commands.**

  ```sh
  crawlx admin status
  crawlx admin workers                 # heartbeats stale? draining?
  crawlx admin reconcile               # open intended / unknown rows
  ```

- **Then.** [RB-04](#rb-04) (lease storm), then [RB-02](#rb-02) for the resulting `unknown` rows. Fencing check: `crawlx.lease.fenced` rising means an old holder was refused, which is correct; two holders mutating one session is SEV-1 and [RB-12](#rb-12).
- **Rollback.** R-APP for the scheduler or worker if a deploy preceded it. `crawlx admin drain --admission` stops new grants while reclaiming; reopen with R-ADMISSION.

## 11. CrawlxLeaseReconcileSlow

**SEV-3, ticket.** p99.9 of `lease.reconcile.duration` above 120 s over 30 min; the 2-minute SLO is at risk.

- **Symptom.** Sessions take longer than two minutes to be reclaimed.
- **Dashboards.** Scheduler and leases: "Lease expired / fenced / reconcile p99.9".
- **First commands.** `crawlx admin workers`; database latency on the Storage row.
- **Then.** [RB-04](#rb-04) steps 1 to 3 (database latency, CPU-starved workers, clock anomalies). Do not raise `scheduler.session_lease_ttl_s` as a fix; it puts the 2-minute SLO further at risk ([RB-04](#rb-04) step 6).
- **Rollback.** R-CFG for any TTL change.

## 12. CrawlxLeaseStorm

**SEV-2, page.** More than 10 lease expiries per minute for 2 min.

- **Symptom.** Many sessions lose their leases at once; throughput collapses.
- **Dashboards.** Scheduler and leases: "Lease expired / fenced / reconcile p99.9", "Leases held (scheduler lease_next rate) and crawls active". Storage: "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)".
- **First commands.**

  ```sh
  crawlx admin drain --admission       # stop the thundering herd ([RB-04](#rb-04) step 4)
  crawlx admin workers
  crawlx admin reconcile
  ```

- **Then.** [RB-04](#rb-04) in order: database first (a heartbeat that cannot commit looks like a dead worker), then worker CPU and the CPU-pool queue, then clocks. [RB-02](#rb-02) for the `unknown` rows. Scale workers back up in steps.
- **Rollback.** R-ADMISSION when stable; R-APP if a deploy preceded it.

## 13. CrawlxSafetyInvariantViolation

**SEV-1, page.** `crawlx_safety_invariant_violations_total` increased: the session actor's pre-perform guard saw an action reach `perform` without an `allow` decision (`performed_without_allow`), the trail verifier found an action with no safety decision (`missing_safety_decision`), or the independent safety auditor found invalid action-safety evidence. The scheduled auditor also reports through failed Jobs and JSON; its process-local counter is not automatically scraped. A refused hard-deny attempt is counted separately in `crawlx_safety_hard_deny_violations_total`; this rule does not fire on it.

- **Symptom.** Possibly none visible; the guard counted a breach of the kernel's contract that an action never runs without a decision.
- **Dashboards.** Journal and safety: "Safety verdicts / invariant violations", "Journal T1 / T2 p95, halts". SLO overview: "Safety invariant violations / ZDR violations (24h)".
- **First commands.**

  ```sh
  crawlx admin freeze --all            # [RB-11](#rb-11) level 2 first, evidence second
  crawlx inspect trail <run-id>        # missing_safety_decision and the other invariants; exit 1 on violations
  ```

- **Then.** [RB-12](#rb-12) (classify: which profile, which rule, which action class). Preserve `actions`, `safety_decisions`, `approvals` and `traffic_events` rows before cleanup. Ship a targeted fix with a regression test before reopening.
- **Rollback.** R-APP if a release is implicated; otherwise a fix forward. No deploys during a SEV-1 except the fix.

## 14. CrawlxSafetyBypassDetected

**SEV-1, page.** `crawlx_safety_verdicts_total{verdict="bypass_detected"}` increased.

- **Symptom.** The kernel itself reported a bypass.
- **Dashboards.** Journal and safety: "Safety verdicts / invariant violations", "Egress denials by plane and reason".
- **First commands and then.** As card 13: freeze, `crawlx inspect trail <run-id>`, [RB-12](#rb-12).
- **Rollback.** As card 13.

## 15. CrawlxZdrViolation

**SEV-1, page.** `crawlx_zdr_violations_total` increased, or an overdue `zdr` artifact exists. The counter moves when the ZDR write gate refuses a content or credential-bearing write for a `retention_mode = zdr` run (the gate held, but a writer tried: a bug) and when the retention sweeper finds ZDR rows or objects that must not exist; the overdue condition is the delivery buffer outliving its TTL. The privacy commitment is at risk or broken.

- **Symptom.** A writer attempted, or succeeded in, persisting content, sensitive or credential-bearing data for a ZDR run; or the delivery buffer holds data past its TTL.
- **Dashboards.** Retention and webhooks: "Overdue artifacts by kind / sweep failures / ZDR violations". SLO overview: "Safety invariant violations / ZDR violations (24h)".
- **First commands.**

  ```sh
  crawlx admin pause --tenant <tenant-id>                      # stop new ZDR crawls ([RB-08](#rb-08) step 3)
  crawlx admin sweep-retention --mode zdr --force              # content objects first, rows afterwards, trail kept
  crawlx admin verify-artifacts --since <incident-start-rfc3339>
  ```

- **Then.** [RB-08](#rb-08) steps 1 to 4: find the writer that violated the write gate (it should be impossible; treat it as a bug), check backups and replicas that may hold the data, rotate the run data keys, notify the data protection contact. [RB-12](#rb-12) if a third party may have received the data. Record deleted keys, not contents.
- **Rollback.** R-APP if a release introduced the writer. Reopen ZDR crawls after the writer is fixed and the sweep is clean.

## 16. CrawlxRetentionOverdue

**SEV-3, ticket.** `standard` or `extended` artifacts past `expires_at` plus grace for 1 h.

- **Symptom.** Storage grows; deletion is late.
- **Dashboards.** Retention and webhooks: "Overdue artifacts by kind / sweep failures / ZDR violations".
- **First commands.** `crawlx admin sweep-retention` (prints swept counts and `overdue standard|extended|zdr`).
- **Then.** [RB-08](#rb-08) steps 5 and 6: sweep job failures or missed schedules, bucket and role permissions, lifecycle conflicts. Run the sweep in batches when the backlog is large and watch database and object-store load.
- **Rollback.** None.

## 17. CrawlxRetentionOverdueDay

**SEV-2, page** (SEV-1 when the overdue kind is `zdr`; card 15 fires too). Any artifact kind overdue for 24 h. A non-`zdr` kind is a SEV-3 ticket on its first hour (card 16) and becomes a page after a full day.

- **Symptom.** A deletion deadline has been missed for a full day.
- **Dashboards.** As card 16.
- **First commands and then.** As card 16, plus: check whether the scheduled sweep job is failing (card 18) or blocked by an object-store outage (card 24). A `zdr` kind goes to card 15.
- **Rollback.** None.

## 18. CrawlxRetentionSweepFailing

**SEV-3, ticket.** `crawlx_retention_sweep_failures_total` increased in 15 min.

- **Symptom.** The next overdue alert follows if this is not fixed.
- **Dashboards.** Retention and webhooks: "Overdue artifacts by kind / sweep failures / ZDR violations". Storage: "Object store: latency p95, error ratio, spool bytes".
- **First commands.** `crawlx admin sweep-retention` by hand and read the error; sweeper logs.
- **Then.** [RB-08](#rb-08) step 5: permissions, lifecycle conflicts. The sweeper deletes the object first, then the row, and retries on failure.
- **Rollback.** None.

## 19. CrawlxJournalHalt

**SEV-2, page** (SEV-1 if any mutation happened without a journal row). `crawlx_journal_halts_total` increased: a session halted because the intent journal was unwritable. The halt is correct behaviour; repeated halts mean the journal is unavailable.

- **Symptom.** Sessions in `HaltedStorage`; no mutations.
- **Dashboards.** Journal and safety: "Journal T1 / T2 p95, halts", "Unknown unreconciled". Storage: "DB pool in use / query p95 by op", "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)".
- **First commands.** `crawlx admin status`; `crawlx admin reconcile`; `crawlx admin drain --admission` if the primary is flapping ([RB-07](#rb-07) step 1).
- **Then.** [RB-07](#rb-07) (database failover): sessions resume only after a journal write succeeds, and no session may have mutated the page while the journal was unwritable. [RB-02](#rb-02) for `intended` rows that became `unknown`.
- **Rollback.** R-ADMISSION after the database is stable.

## 20. CrawlxUnknownOutcomesGrowing

**SEV-2, page** (SEV-1 if growth is paired with a duplicated effect). `interactions.unknown_unreconciled` above 0 for 10 min, or hourly `unknown` outcomes above 3 times the 7-day median.

- **Symptom.** Actions whose effect is not known; `unknown` is not `failed`.
- **Dashboards.** Journal and safety: "Unknown unreconciled", "Journal T1 / T2 p95, halts". Sessions and browsers: "Crashes by reason / recoveries by rung".
- **First commands.**

  ```sh
  crawlx admin reconcile                                   # list
  crawlx admin reconcile --action <action-id>              # hand a lease-less session to the reconciler
  crawlx inspect actions <run-id> --status unknown
  ```

- **Then.** [RB-02](#rb-02). Never `UPDATE actions SET status = 'failed'` or delete rows to clear the alert ([RB-02](#rb-02) step 5). Two backend effects for one `action_id` is SEV-1 and [RB-12](#rb-12). Growth with healthy workers points at storage ([RB-07](#rb-07)).
- **Rollback.** None; reconciliation is the remedy.

## 21. CrawlxBrowserCrashLoop

**SEV-3, ticket.** Browser crash rate above 0.2 per minute on one worker for 10 min.

- **Symptom.** One worker's sessions keep restarting.
- **Dashboards.** Sessions and browsers: "Crashes by reason / recoveries by rung", "Browser sessions / RSS", "Launch and settle duration p95".
- **First commands.** `crawlx admin workers`; `crawlx admin drain --worker <id>` for the bad node; node memory, `/dev/shm`, PID limits and seccomp denials ([RB-03](#rb-03) step 3).
- **Then.** [RB-03](#rb-03). One target crashing renderers: `crawlx admin pause --crawl <id>` and a target-specific ticket (SEV-3).
- **Rollback.** R-CHROMIUM when a Chromium or image rollout preceded it.

## 22. CrawlxBrowserCrashLoopWide

**SEV-2, page.** More than 25 % of workers are crash-looping for 10 min, usually after a Chromium or image rollout.

- **Symptom.** Widespread session recoveries; coverage drops.
- **Dashboards.** As card 21; Capacity: "Renderer RSS per session (p95 across workers)".
- **First commands.** Roll back first ([RB-03](#rb-03) step 2), draining rather than killing: `crawlx admin drain --worker <id>` per node, or `crawlx admin drain --admission` to stop new work while recovering.
- **Then.** [RB-03](#rb-03) steps 4 to 8: compare `chromium-pin.toml` with the running image and the recent sessions' `BrowserBuildInfo`; reduce `worker.max_sessions` and `contexts_per_browser`; confirm the crash-loop breaker paused runs. [RB-02](#rb-02) for `unknown` actions.
- **Rollback.** R-CHROMIUM, R-APP.

## 23. CrawlxModelBreakerOpen

**SEV-3, ticket.** `crawlx_model_breaker_state` is not closed for 5 min on a provider. The ranking falls back to the deterministic strategy; safety stays fail-closed.

- **Symptom.** Coverage per unit time drops a little; nothing breaks.
- **Dashboards.** Models: "Model requests / abstentions by provider", "Model latency p95 / breaker state".
- **First commands.** Provider status and credentials; model-server GPU health; check abstentions rose rather than the request rate.
- **Then.** [RB-05](#rb-05). Never loosen a profile or disable the kernel to compensate; never fail ZDR runs over to a provider that does not guarantee zero retention; raise the cooldown, not the thresholds, if the provider flaps. Note: `dynamic.system1Mode` values above `shadow` need a signed gate file (`gates/g3.passed`) that exists only when the operator provisions gate keys, so by default an open breaker affects shadow recording only.
- **Rollback.** R-MODEL.

## 24. CrawlxObjectStoreErrors

**SEV-2, page.** Object-store error ratio above 5 % over 5 min, or `spool_bytes` above 50 % of configured `spool_max_bytes`. The gauge covers queued and active in-memory upload reservations.

- **Symptom.** Artifact writes or reads fail; checkpoints may not upload.
- **Dashboards.** Storage: "Object store: latency p95, error ratio, spool bytes".
- **First commands.** Provider status, credentials and expiry, endpoint DNS, bucket policy, quotas. After recovery: `crawlx admin verify-artifacts --since <outage-start-rfc3339> --s3-bucket <bucket>`.
- **Then.** [RB-06](#rb-06). Objects are written before the transaction that references them, so a failed upload never leaves a dangling reference. Reduce capture load by configuration; `crawlx admin drain --admission` if capture must not be lost. Do not shorten retention or delete objects during the outage.
- **Rollback.** R-CFG for capture-load changes; R-ADMISSION afterwards.

## 25. CrawlxMetadataApiLatency

**SEV-4, ticket.** p95 of API request duration above 150 ms at 100 RPS or more for 15 min.

- **Symptom.** Slow metadata reads; no errors.
- **Dashboards.** SLO overview; Storage: "DB pool in use / query p95 by op".
- **First commands.** `histogram_quantile(0.95, sum by (le, route) (rate(crawlx_api_request_duration_seconds_bucket[15m])))`; slowest `op` in the query histogram.
- **Then.** Triage weekly; scale API replicas or index the slow query; if it approaches the SLO burn thresholds, cards 1 and 2 take over.
- **Rollback.** R-APP when it follows a release.

## 26. CrawlxSchedulerLatency

**SEV-4, ticket** (SEV-2 when the database is saturating). p95 of scheduler operations above 5 ms for 15 min.

- **Symptom.** Slower lease grants.
- **Dashboards.** Scheduler and leases: "Scheduler op p95 by op / lease hold p95". Storage: "DB pool in use / query p95 by op", "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)".
- **First commands.** Slowest `op` (`lease_next`, `lease_in_run`, `heartbeat`, `release`, `reap`); pool saturation; table and index growth.
- **Then.** [RB-07](#rb-07) if the database is the cause; otherwise tune and ticket.
- **Rollback.** R-APP when it follows a release; R-CFG for `database.pool_max`.

## 27. CrawlxCheckpointLatency

**SEV-4, ticket.** p95 of the `checkpoint` span above 2 s for 30 min. Needs the span-metrics connector (a span-metrics connector in the collector).

- **Symptom.** Slow checkpoints; recovery points lag.
- **Dashboards.** Journal and safety; Storage: "Object store: latency p95, error ratio, spool bytes".
- **First commands.** Object-store latency; checkpoint size growth per session.
- **Then.** Triage weekly; if checkpoints fail outright, card 24.
- **Rollback.** R-APP when it follows a release.

## 28. CrawlxSettleTimeoutRate

**SEV-4, ticket** (SEV-3 if global). Settle timeouts above 5 % of executed interactions over 30 min.

- **Symptom.** Pages that never settle; usually one target.
- **Dashboards.** Sessions and browsers: "Settle timeouts / CPU pool queue depth", "Launch and settle duration p95".
- **First commands.** Find the target from logs (origin hash to origin mapping), not from metric labels; CPU pool queue depth.
- **Then.** Target-specific: tune that target's policy and open a ticket. Global: check CPU starvation and Chromium rollout (cards 21, 22).
- **Rollback.** R-CHROMIUM if global and after a rollout.

## 29. CrawlxPolitenessViolation

**SEV-3, ticket** (SEV-2 for that crawl while a target owner is complaining). `crawlx_fetch_politeness_violations_total` increased: a permit was handed out sooner than the origin's spacing floor (`max(politeness.delayMs, Crawl-delay)`) in effect when it was admitted, or above `max_in_flight_per_origin`.

- **Symptom.** A target sees more load than the configuration allows.
- **Dashboards.** Fetch and politeness: "Origin wait p95 / throttles", "Response outcome classes / politeness violations".
- **First commands.**

  ```sh
  crawlx admin pause --crawl <id>      # immediately ([RB-10](#rb-10) step 1); find the origin from logs
  ```

- **Then.** [RB-10](#rb-10): verify the per-origin defaults (one in flight, at least 250 ms spacing), count the aggregate load of all sessions on the origin, resume with higher spacing and fewer sessions, honour `Retry-After`; add the host to the operator blocklist and end with `policy_stopped` if the owner asks: write it to the file named by `egress.operator_blocklist_file` (env `CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE`, one host per line), send `SIGHUP` to every `crawlx serve` and `crawlx worker` process (or wait up to 60 s), then `crawlx admin cancel --crawl <id> --reason policy-stopped`; runs in flight refuse the host on their next connection.
- **Rollback.** R-APP if two code paths bypassed the limiter after a release.

## 30. CrawlxSsrfDenialSpike

**SEV-3, ticket** (SEV-1 if a denied range was actually reached). Egress denials above 10 times the 7-day baseline for 15 min.

- **Symptom.** A tenant or an attacker is probing internal addresses.
- **Dashboards.** Journal and safety: "Egress denials by plane and reason".
- **First commands.** The `reason` and `plane` breakdown (`crawlx_egress_denials_total`); the denying rule names are `DenyRule` identifiers (`loopback`, `private`, `link_local`, `metadata`, ...). Identify the tenant from the API logs.
- **Then.** A denial is the control working. Escalate to SEV-1 and [RB-12](#rb-12) only if the firewall or the node saw a connection to a denied range that the proxy did not deny. Abuse: `crawlx admin pause --tenant <id>` and a ticket to the abuse process.
- **Rollback.** None.

## 31. CrawlxReplicationLag

**SEV-3, ticket** (SEV-2 if writes become unavailable). PostgreSQL replica lag above 30 s for 5 min. Needs `postgres_exporter`.

- **Symptom.** A failover now would lose more than the 5-minute RPO allows; replica reads are stale.
- **Dashboards.** Storage: "PostgreSQL: connections, replication lag, lock waits (postgres_exporter)".
- **First commands.** Replica health and WAL shipping; long-running transactions on the primary.
- **Then.** [RB-07](#rb-07) if the primary is at risk; otherwise ticket. Move API reads off the replica until lag recovers.
- **Rollback.** None in this repository (database operations).

## 32. CrawlxQueueStall

**SEV-2, page.** Crawls are active, the frontier is non-empty, and neither interactions nor URL fetches succeed for 10 min.

- **Symptom.** Everything is running and nothing progresses.
- **Dashboards.** Crawl health: "Stuck-crawl candidates (active, no progress 10m)", "Frontier depth per plane", "URL plane rates", "Interaction rates". Scheduler and leases: "Leases held (scheduler lease_next rate) and crawls active".
- **First commands.**

  ```sh
  crawlx admin status                 # admission mode first: frozen or drain explains it
  crawlx admin workers
  crawlx admin reconcile
  ```

- **Then.** [RB-01](#rb-01) at fleet level: scope (one crawl, one tenant, all), the lease and the current action state, browser and CDP health, the frontier (backoff and politeness waits are not stalls), journal halts. [RB-04](#rb-04) for leases and [RB-07](#rb-07) for the database. **STOP** if any action is `unknown`: finish [RB-02](#rb-02) first.
- **Rollback.** R-ADMISSION if admission was left `drain` or `frozen`; R-APP or R-CHROMIUM when a rollout preceded it.
