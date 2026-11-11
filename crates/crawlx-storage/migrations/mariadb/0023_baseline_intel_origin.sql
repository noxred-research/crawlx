-- crawlx-storage (MariaDB) baseline 3 of 5: asynchronous LLM jobs, monitors, usage ledger,
-- tenant settings, deployment-wide origin admission.
--
-- Hand-ported final PostgreSQL schema (levels 0016-0023). Conventions are listed in the first
-- baseline file. Idempotent.
--
-- Key-length note: InnoDB indexes are limited to 3072 bytes (utf8mb4 = 4 bytes per character).
-- Text keys that PostgreSQL leaves unbounded are therefore either bounded (VARCHAR) or, for the
-- two urls below, keyed through a 32-byte caller-supplied digest column `url_hash`.

-- from: 0016. Asynchronous `extract` / `agent` jobs.
CREATE TABLE IF NOT EXISTS intel_jobs (
  job_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  kind VARCHAR(40) NOT NULL,
  status VARCHAR(40) NOT NULL,
  request LONGTEXT NOT NULL CHECK (JSON_VALID(request)),
  result LONGTEXT NULL CHECK (JSON_VALID(result)),
  error LONGTEXT NULL,
  stop_reason LONGTEXT NULL,
  tokens_used BIGINT NOT NULL DEFAULT 0,
  credits_used BIGINT NOT NULL DEFAULT 0,
  thread_id BINARY(16) NULL,
  -- last sequence number handed out by `trace_append`; the increment serializes appenders
  trace_seq BIGINT NOT NULL DEFAULT 0,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  finished_at DATETIME(6) NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (job_id),
  KEY intel_jobs_tenant_created (tenant_id, created_at DESC, job_id DESC),
  KEY intel_jobs_expiry (expires_at),
  CONSTRAINT intel_jobs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT intel_jobs_kind_check CHECK (kind IN ('extract', 'agent')),
  CONSTRAINT intel_jobs_status_check CHECK (status IN ('processing', 'completed', 'failed', 'cancelled')),
  CONSTRAINT intel_jobs_tokens_used_check CHECK (tokens_used >= 0),
  CONSTRAINT intel_jobs_credits_used_check CHECK (credits_used >= 0),
  CONSTRAINT intel_jobs_trace_seq_check CHECK (trace_seq >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Agent trace.
CREATE TABLE IF NOT EXISTS intel_trace (
  job_id BINARY(16) NOT NULL,
  seq BIGINT NOT NULL,
  kind VARCHAR(255) NOT NULL,
  data LONGTEXT NOT NULL CHECK (JSON_VALID(data)),
  `at` DATETIME(6) NOT NULL,
  PRIMARY KEY (job_id, seq),
  CONSTRAINT intel_trace_job_fk FOREIGN KEY (job_id) REFERENCES intel_jobs (job_id) ON DELETE CASCADE,
  CONSTRAINT intel_trace_seq_check CHECK (seq >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Agent snapshots; `ordinal` is the creation order. A non-leading AUTO_INCREMENT
-- column needs a key of its own (the (job_id, ordinal) index below serves the ordered reads).
CREATE TABLE IF NOT EXISTS intel_snapshots (
  job_id BINARY(16) NOT NULL,
  snapshot_id VARCHAR(255) NOT NULL,
  ordinal BIGINT NOT NULL AUTO_INCREMENT,
  data LONGTEXT NOT NULL CHECK (JSON_VALID(data)),
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (job_id, snapshot_id),
  UNIQUE KEY intel_snapshots_ordinal (ordinal),
  KEY intel_snapshots_order (job_id, ordinal),
  CONSTRAINT intel_snapshots_job_fk FOREIGN KEY (job_id) REFERENCES intel_jobs (job_id) ON DELETE CASCADE,
  CONSTRAINT intel_snapshots_snapshot_id_check CHECK (CHAR_LENGTH(snapshot_id) BETWEEN 1 AND 255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Agent conversation threads; the id is global, so a thread cannot move tenants.
CREATE TABLE IF NOT EXISTS intel_threads (
  thread_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  state LONGTEXT NOT NULL CHECK (JSON_VALID(state)),
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (thread_id),
  KEY intel_threads_tenant (tenant_id),
  CONSTRAINT intel_threads_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Scheduled monitors.
CREATE TABLE IF NOT EXISTS monitors (
  monitor_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  name LONGTEXT NULL,
  status VARCHAR(40) NOT NULL,
  schedule LONGTEXT NOT NULL CHECK (JSON_VALID(schedule)),
  cron VARCHAR(255) NOT NULL,
  timezone VARCHAR(255) NOT NULL,
  goal LONGTEXT NULL,
  targets LONGTEXT NOT NULL CHECK (JSON_VALID(targets)),
  retention_days INT NOT NULL,
  webhook LONGTEXT NULL CHECK (JSON_VALID(webhook)),
  notification LONGTEXT NOT NULL CHECK (JSON_VALID(notification)),
  next_run_at DATETIME(6) NULL,
  last_run_at DATETIME(6) NULL,
  last_check_id BINARY(16) NULL,
  claimed_until DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (monitor_id),
  -- target of the composite foreign key of `monitor_checks`
  UNIQUE KEY monitors_monitor_id_tenant_id_key (monitor_id, tenant_id),
  KEY monitors_tenant_created (tenant_id, created_at DESC, monitor_id DESC),
  -- partial index WHERE status = 'active': the ticker only looks at active monitors
  KEY monitors_due (status, next_run_at),
  CONSTRAINT monitors_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT monitors_status_check CHECK (status IN ('active', 'paused')),
  CONSTRAINT monitors_retention_days_check CHECK (retention_days >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. One execution of a monitor; `status` is the aggregate page outcome once completed.
CREATE TABLE IF NOT EXISTS monitor_checks (
  check_id BINARY(16) NOT NULL,
  monitor_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  trigger_kind VARCHAR(40) NOT NULL,
  state VARCHAR(40) NOT NULL,
  status VARCHAR(40) NULL,
  summary LONGTEXT NOT NULL CHECK (JSON_VALID(summary)),
  error LONGTEXT NULL,
  started_at DATETIME(6) NOT NULL,
  finished_at DATETIME(6) NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (check_id),
  KEY monitor_checks_listing (monitor_id, started_at DESC, check_id DESC),
  KEY monitor_checks_status (monitor_id, status, started_at DESC, check_id DESC),
  KEY monitor_checks_expiry (expires_at),
  -- a check carries the tenant of its monitor
  CONSTRAINT monitor_checks_monitor_fk FOREIGN KEY (monitor_id, tenant_id) REFERENCES monitors (monitor_id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT monitor_checks_trigger_kind_check CHECK (trigger_kind IN ('scheduled', 'manual')),
  CONSTRAINT monitor_checks_state_check CHECK (state IN ('running', 'completed', 'failed')),
  CONSTRAINT monitor_checks_status_check CHECK (status IS NULL OR status IN ('same', 'new', 'changed', 'removed', 'error'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Pages observed by a check, ordered by (target_id, url) in byte order. The
-- repository writes `url_hash` (a 32-byte digest of the url bytes) and addresses a page by
-- (check_id, target_id, url_hash).
CREATE TABLE IF NOT EXISTS monitor_check_pages (
  check_id BINARY(16) NOT NULL,
  target_id VARCHAR(255) NOT NULL,
  url LONGTEXT NOT NULL,
  url_hash BINARY(32) NOT NULL,
  status VARCHAR(40) NOT NULL,
  data LONGTEXT NOT NULL CHECK (JSON_VALID(data)),
  PRIMARY KEY (check_id, target_id, url_hash),
  KEY monitor_check_pages_status (check_id, status, target_id),
  CONSTRAINT monitor_check_pages_check_fk FOREIGN KEY (check_id) REFERENCES monitor_checks (check_id) ON DELETE CASCADE,
  CONSTRAINT monitor_check_pages_status_check CHECK (status IN ('same', 'new', 'changed', 'removed', 'error'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Last content seen at one url of one monitor: the baseline the next check diffs
-- against. `url_hash` as for monitor_check_pages.
CREATE TABLE IF NOT EXISTS monitor_baselines (
  monitor_id BINARY(16) NOT NULL,
  url LONGTEXT NOT NULL,
  url_hash BINARY(32) NOT NULL,
  digest VARCHAR(255) NOT NULL,
  markdown LONGTEXT NOT NULL,
  seen_at DATETIME(6) NOT NULL,
  PRIMARY KEY (monitor_id, url_hash),
  CONSTRAINT monitor_baselines_monitor_fk FOREIGN KEY (monitor_id) REFERENCES monitors (monitor_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Usage ledger; `entry_id` breaks ties between rows with the same `at`.
CREATE TABLE IF NOT EXISTS usage_ledger (
  entry_id BIGINT NOT NULL AUTO_INCREMENT,
  tenant_id BINARY(16) NOT NULL,
  `at` DATETIME(6) NOT NULL,
  endpoint VARCHAR(255) NOT NULL,
  ref_id BINARY(16) NULL,
  status VARCHAR(255) NOT NULL,
  credits BIGINT NOT NULL DEFAULT 0,
  prompt_tokens BIGINT NOT NULL DEFAULT 0,
  completion_tokens BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (entry_id),
  KEY usage_ledger_tenant_at (tenant_id, `at`),
  KEY usage_ledger_at (`at`),
  CONSTRAINT usage_ledger_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT usage_ledger_credits_check CHECK (credits >= 0),
  CONSTRAINT usage_ledger_prompt_tokens_check CHECK (prompt_tokens >= 0),
  CONSTRAINT usage_ledger_completion_tokens_check CHECK (completion_tokens >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0016. Per-tenant settings.
CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id BINARY(16) NOT NULL,
  `key` VARCHAR(255) NOT NULL,
  value LONGTEXT NOT NULL CHECK (JSON_VALID(value)),
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, `key`),
  CONSTRAINT tenant_settings_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT tenant_settings_key_check CHECK (CHAR_LENGTH(`key`) BETWEEN 1 AND 255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0023, 0031 (feedback columns). Deployment-wide origin capacity and start spacing, shared
-- across tenants and workers (no tenant/run key). `next_ticket` wraps modulo `slot_limit`; each
-- slot is an InnoDB row lock held by an open transaction. '-infinity' is '1000-01-01'.
CREATE TABLE IF NOT EXISTS origin_admission (
  origin VARCHAR(512) NOT NULL,
  next_ticket BIGINT NOT NULL DEFAULT 0,
  slot_limit BIGINT NOT NULL,
  next_allowed_at DATETIME(6) NOT NULL DEFAULT '1000-01-01 00:00:00.000000',
  last_spacing_us BIGINT NOT NULL DEFAULT 0,
  cooldown_until DATETIME(6) NOT NULL DEFAULT '1000-01-01 00:00:00.000000',
  throttle_delay_us BIGINT NOT NULL DEFAULT 0,
  throttle_decays_at DATETIME(6) NOT NULL DEFAULT '1000-01-01 00:00:00.000000',
  PRIMARY KEY (origin),
  CONSTRAINT origin_admission_next_ticket_check CHECK (next_ticket >= 0),
  CONSTRAINT origin_admission_slot_limit_check CHECK (slot_limit > 0),
  CONSTRAINT origin_admission_last_spacing_us_check CHECK (last_spacing_us >= 0),
  CONSTRAINT origin_admission_throttle_delay_us_check CHECK (throttle_delay_us >= 0),
  CONSTRAINT origin_admission_ticket_bound CHECK (next_ticket < slot_limit)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
