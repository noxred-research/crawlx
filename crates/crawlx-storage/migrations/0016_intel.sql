-- crawlx-storage 0016: Firecrawl-parity LLM products: asynchronous `extract` and
-- `agent` jobs with their trace, snapshots and conversation threads, scheduled monitors with
-- their checks and per-page baselines, the usage ledger behind `/team/*`, and per-tenant
-- settings. Implemented by `repos/intel.rs` (`IntelRepo for Pg`).
--
-- Tenancy. Every table is scoped to a tenant (directly through `tenant_id`, or through its
-- parent job / monitor / check) and `tenants(tenant_id)` is the foreign key, as for `api_keys`
-- and `idempotency_keys` (migration 0002). Row-level security (migration 0012) is deliberately
-- NOT enabled here: the monitor ticker claims due monitors of every tenant from one connection
-- and the retention purge sweeps every tenant, neither with `app.tenant_id` set, so a policy
-- keyed on that setting would hide their rows. Isolation is enforced by the repository instead:
-- every query that takes a tenant filters on `tenant_id`, and rows addressed only through a job,
-- monitor or check id are reached after the caller verified ownership of that parent.
--
-- Payload columns (`request`, `result`, `schedule`, `targets`, `summary`, `data`, ...) are
-- opaque jsonb the API shapes itself; columns exist only for what the repository filters or
-- orders by. Counters are non-negative bigints; the repository converts them with checked casts.
--
-- Text keys that the repository orders in Rust byte order (page `(target_id, url)`, baseline
-- `url`) use COLLATE "C" so SQL and in-memory orderings agree regardless of the database locale.

-- asynchronous `extract` / `agent` jobs
CREATE TABLE intel_jobs (
  job_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  kind text NOT NULL CHECK (kind IN ('extract', 'agent')),
  status text NOT NULL CHECK (status IN ('processing', 'completed', 'failed', 'cancelled')),
  request jsonb NOT NULL,
  result jsonb,
  error text,
  stop_reason text,
  tokens_used bigint NOT NULL DEFAULT 0 CHECK (tokens_used >= 0),
  credits_used bigint NOT NULL DEFAULT 0 CHECK (credits_used >= 0),
  thread_id uuid,
  -- last sequence number handed out by `trace_append`; the increment serializes appenders
  trace_seq bigint NOT NULL DEFAULT 0 CHECK (trace_seq >= 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  finished_at timestamptz,
  expires_at timestamptz NOT NULL);
-- `job_list`: newest first with a (created_at, job_id) cursor
CREATE INDEX intel_jobs_tenant_created ON intel_jobs (tenant_id, created_at DESC, job_id DESC);
-- `purge_expired`
CREATE INDEX intel_jobs_expiry ON intel_jobs (expires_at);

-- agent trace (`GET /agent/{id}/trace`)
CREATE TABLE intel_trace (
  job_id uuid NOT NULL REFERENCES intel_jobs ON DELETE CASCADE,
  seq bigint NOT NULL CHECK (seq >= 1),
  kind text NOT NULL,
  data jsonb NOT NULL,
  at timestamptz NOT NULL,
  PRIMARY KEY (job_id, seq));

-- agent snapshots (`GET /agent/{id}/snapshots/{snapshotId}`); `ordinal` is the creation order
CREATE TABLE intel_snapshots (
  job_id uuid NOT NULL REFERENCES intel_jobs ON DELETE CASCADE,
  snapshot_id text NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 255),
  ordinal bigint GENERATED ALWAYS AS IDENTITY,
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (job_id, snapshot_id));
CREATE INDEX intel_snapshots_order ON intel_snapshots (job_id, ordinal);

-- agent conversation threads (`threadId`); the id is global, so a thread cannot move tenants
CREATE TABLE intel_threads (
  thread_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  state jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL);
CREATE INDEX intel_threads_tenant ON intel_threads (tenant_id);

-- scheduled monitors
CREATE TABLE monitors (
  monitor_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  name text,
  status text NOT NULL CHECK (status IN ('active', 'paused')),
  schedule jsonb NOT NULL,
  cron text NOT NULL,
  timezone text NOT NULL,
  goal text,
  targets jsonb NOT NULL,
  retention_days int NOT NULL CHECK (retention_days >= 1),
  webhook jsonb,
  notification jsonb NOT NULL,
  next_run_at timestamptz,
  last_run_at timestamptz,
  last_check_id uuid,
  claimed_until timestamptz,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  -- target of the composite foreign key of `monitor_checks`
  UNIQUE (monitor_id, tenant_id));
-- `monitor_list`: newest first
CREATE INDEX monitors_tenant_created ON monitors (tenant_id, created_at DESC, monitor_id DESC);
-- `monitor_claim_due`: the ticker only ever looks at active monitors, oldest due first
CREATE INDEX monitors_due ON monitors (next_run_at) WHERE status = 'active';

-- one execution of a monitor; `status` is the aggregate page outcome once completed
CREATE TABLE monitor_checks (
  check_id uuid PRIMARY KEY,
  monitor_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  trigger_kind text NOT NULL CHECK (trigger_kind IN ('scheduled', 'manual')),
  state text NOT NULL CHECK (state IN ('running', 'completed', 'failed')),
  status text CHECK (status IN ('same', 'new', 'changed', 'removed', 'error')),
  summary jsonb NOT NULL,
  error text,
  started_at timestamptz NOT NULL,
  finished_at timestamptz,
  expires_at timestamptz NOT NULL,
  -- a check carries the tenant of its monitor
  FOREIGN KEY (monitor_id, tenant_id) REFERENCES monitors (monitor_id, tenant_id) ON DELETE CASCADE);
-- `check_list`: newest first per monitor, optionally one aggregate status
CREATE INDEX monitor_checks_listing ON monitor_checks (monitor_id, started_at DESC, check_id DESC);
CREATE INDEX monitor_checks_status ON monitor_checks (monitor_id, status, started_at DESC, check_id DESC);
-- `purge_expired`
CREATE INDEX monitor_checks_expiry ON monitor_checks (expires_at);

-- pages observed by a check, ordered by (target_id, url)
CREATE TABLE monitor_check_pages (
  check_id uuid NOT NULL REFERENCES monitor_checks ON DELETE CASCADE,
  target_id text COLLATE "C" NOT NULL,
  url text COLLATE "C" NOT NULL,
  status text NOT NULL CHECK (status IN ('same', 'new', 'changed', 'removed', 'error')),
  data jsonb NOT NULL,
  PRIMARY KEY (check_id, target_id, url));
CREATE INDEX monitor_check_pages_status ON monitor_check_pages (check_id, status, target_id, url);

-- last content seen at one URL of one monitor: the baseline the next check diffs against
CREATE TABLE monitor_baselines (
  monitor_id uuid NOT NULL REFERENCES monitors ON DELETE CASCADE,
  url text COLLATE "C" NOT NULL,
  digest text NOT NULL,
  markdown text NOT NULL,
  seen_at timestamptz NOT NULL,
  PRIMARY KEY (monitor_id, url));

-- usage ledger behind `/team/credit-usage`, `/token-usage` and `/activity`; `entry_id` breaks
-- ties between rows with the same `at` (insertion order)
CREATE TABLE usage_ledger (
  entry_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  at timestamptz NOT NULL,
  endpoint text NOT NULL,
  ref_id uuid,
  status text NOT NULL,
  credits bigint NOT NULL DEFAULT 0 CHECK (credits >= 0),
  prompt_tokens bigint NOT NULL DEFAULT 0 CHECK (prompt_tokens >= 0),
  completion_tokens bigint NOT NULL DEFAULT 0 CHECK (completion_tokens >= 0));
-- `usage_totals`, `usage_by_day`, `usage_recent`
CREATE INDEX usage_ledger_tenant_at ON usage_ledger (tenant_id, at);
-- `purge_expired`
CREATE INDEX usage_ledger_at ON usage_ledger (at);

-- per-tenant settings (`threat-protection`, ...)
CREATE TABLE tenant_settings (
  tenant_id uuid NOT NULL REFERENCES tenants,
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key));
