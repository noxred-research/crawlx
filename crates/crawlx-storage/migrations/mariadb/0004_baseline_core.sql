-- crawlx-storage (MariaDB) baseline 1 of 5: sequences, tenancy, runs, state graph.
--
-- Hand-ported final PostgreSQL schema (levels 0001-0004 plus every later column added to
-- these tables). Re-applying this file is a no-op: every statement is idempotent.
--
-- Conventions shared by all baseline files
--   * InnoDB, utf8mb4 with the NO PAD binary collation: string comparison is byte-exact and
--     case-sensitive, matching PostgreSQL `text` equality and `COLLATE "C"` ordering.
--   * uuid -> BINARY(16) (RFC 4122 byte order; UUIDv7 keeps time order). No MariaDB UUID type.
--   * timestamptz -> DATETIME(6), UTC (connections run with time_zone = '+00:00').
--     '-infinity' -> '1000-01-01 00:00:00.000000', 'infinity' -> '9999-12-31 23:59:59.999999'.
--   * jsonb -> LONGTEXT with a JSON_VALID check (not the JSON alias, whose utf8mb4_bin
--     collation would clash with the table collation); arrays -> JSON arrays in LONGTEXT.
--   * PostgreSQL enums -> VARCHAR(40) plus a named CHECK, so adding a label is a CHECK swap.
--   * boolean -> TINYINT(1); bigint identity -> BIGINT AUTO_INCREMENT.
--   * Partial indexes become full indexes with the filtered column placed so that the common
--     predicate is an index condition; expression indexes use a generated column.
--   * Row-level security is not ported: tenant isolation is the repository tenant guard.
--   * Triggers only validate (SIGNAL on violation); they never rewrite a row.
--   * Compound trigger statements end with a line that is exactly `END;` and contain no
--     nested BEGIN blocks, so ci/mariadb-baseline-check.sh can wrap them in DELIMITER.

-- from: 0001 -- fencing-token sequence shared by sessions, frontier rows and origin leases.
CREATE SEQUENCE IF NOT EXISTS lease_fence_seq START WITH 1 INCREMENT BY 1 NOCYCLE;

-- new: tx-scoped lock rows. `INSERT .. ON DUPLICATE KEY UPDATE name = name` a name (never INSERT IGNORE: it swallows FK and CHECK errors), then `SELECT .. FOR UPDATE` (exclusive) or
-- `LOCK IN SHARE MODE` (shared) inside a transaction; the lock ends at COMMIT/ROLLBACK like a
-- PostgreSQL advisory transaction lock.
CREATE TABLE IF NOT EXISTS crawlx_locks (
  name VARBINARY(64) NOT NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0002, 0011 (engine), 0045 (engine labels)
CREATE TABLE IF NOT EXISTS tenants (
  tenant_id BINARY(16) NOT NULL,
  name LONGTEXT NOT NULL,
  region VARCHAR(255) NOT NULL DEFAULT 'default',
  zdr_enforced TINYINT(1) NOT NULL DEFAULT 0,
  kms_key_id LONGTEXT NOT NULL,
  plan LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(plan)),
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  disabled_at DATETIME(6) NULL,
  engine VARCHAR(40) NOT NULL DEFAULT 'crawlx',
  PRIMARY KEY (tenant_id),
  CONSTRAINT tenants_engine_check CHECK (engine IN ('crawlx', 'upstream', 'shadow'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0002 (scopes: text[] -> JSON array of strings)
CREATE TABLE IF NOT EXISTS api_keys (
  key_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  prefix VARCHAR(255) NOT NULL,
  key_hash VARBINARY(255) NOT NULL,
  scopes LONGTEXT NOT NULL CHECK (JSON_VALID(scopes)),
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_used_at DATETIME(6) NULL,
  expires_at DATETIME(6) NULL,
  revoked_at DATETIME(6) NULL,
  PRIMARY KEY (key_id),
  UNIQUE KEY api_keys_prefix_key (prefix),
  CONSTRAINT api_keys_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0002
CREATE TABLE IF NOT EXISTS idempotency_keys (
  tenant_id BINARY(16) NOT NULL,
  idem_key VARCHAR(255) NOT NULL,
  request_hash VARBINARY(64) NOT NULL,
  state VARCHAR(40) NOT NULL,
  response_status INT NULL,
  response_body LONGTEXT NULL CHECK (JSON_VALID(response_body)),
  run_id BINARY(16) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, idem_key),
  CONSTRAINT idempotency_keys_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT idempotency_keys_idem_key_check CHECK (CHAR_LENGTH(idem_key) BETWEEN 1 AND 255),
  CONSTRAINT idempotency_keys_state_check CHECK (state IN ('in_progress', 'done'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0002, 0019 (lifecycle columns). The evidence_artifact_id foreign key is added by the
-- next baseline file, after `artifacts` exists.
CREATE TABLE IF NOT EXISTS authorization_records (
  record_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  version INT NOT NULL DEFAULT 1,
  body LONGTEXT NOT NULL CHECK (JSON_VALID(body)),
  body_digest VARBINARY(64) NOT NULL,
  evidence_artifact_id BINARY(16) NULL,
  valid_from DATETIME(6) NOT NULL,
  valid_to DATETIME(6) NOT NULL,
  created_by BINARY(16) NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  revoked_at DATETIME(6) NULL,
  verified_at DATETIME(6) NULL,
  verification LONGTEXT NULL CHECK (JSON_VALID(verification)),
  revoked_reason LONGTEXT NULL,
  revoked_by BINARY(16) NULL,
  PRIMARY KEY (record_id),
  CONSTRAINT authorization_records_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT authorization_records_created_by_fk FOREIGN KEY (created_by) REFERENCES api_keys (key_id),
  CONSTRAINT authorization_records_revoked_by_fk FOREIGN KEY (revoked_by) REFERENCES api_keys (key_id),
  CONSTRAINT authorization_records_valid_to_check CHECK (valid_to > valid_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0003, 0010.. (every column added later is included), 0011 (shadow kind), 0013 (trace_id),
-- 0019 (authorization_body_digest), 0034 (data_requirements)
CREATE TABLE IF NOT EXISTS crawl_runs (
  run_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  run_kind VARCHAR(40) NOT NULL DEFAULT 'crawl',
  replay_of BINARY(16) NULL,
  replay_spec LONGTEXT NULL CHECK (JSON_VALID(replay_spec)),
  status VARCHAR(40) NOT NULL DEFAULT 'queued',
  terminal_reason VARCHAR(40) NULL,
  mode VARCHAR(40) NOT NULL,
  seed BIGINT NOT NULL,
  safety_profile VARCHAR(40) NOT NULL,
  authorization_record_id BINARY(16) NULL,
  policy_version INT NOT NULL,
  identity_version SMALLINT NOT NULL,
  state_algo_version SMALLINT NOT NULL,
  query_classifier_version SMALLINT NOT NULL,
  config LONGTEXT NOT NULL CHECK (JSON_VALID(config)),
  config_digest VARBINARY(64) NOT NULL,
  counters LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(counters)),
  retention_mode VARCHAR(40) NOT NULL,
  retention_days INT NOT NULL,
  expires_at DATETIME(6) NULL,
  lease_owner BINARY(16) NULL,
  lease_expires_at DATETIME(6) NULL,
  fencing_token BIGINT NOT NULL DEFAULT 0,
  event_seq BIGINT NOT NULL DEFAULT 0,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  deadline_at DATETIME(6) NULL,
  pause_requested_at DATETIME(6) NULL,
  cancel_requested_at DATETIME(6) NULL,
  purge_requested_at DATETIME(6) NULL,
  trace_id VARCHAR(32) NULL,
  authorization_body_digest VARBINARY(64) NULL,
  data_requirements LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(data_requirements)),
  PRIMARY KEY (run_id),
  -- both composite keys are foreign-key targets of the tenant-scoped tables
  UNIQUE KEY crawl_runs_run_tenant (run_id, tenant_id),
  UNIQUE KEY crawl_runs_tenant_run (tenant_id, run_id),
  KEY crawl_runs_tenant (tenant_id, run_id DESC),
  -- partial index WHERE status IN (queued, running, pausing, cancelling)
  KEY crawl_runs_active (status, lease_expires_at),
  -- partial index WHERE expires_at IS NOT NULL
  KEY crawl_runs_expiry (expires_at),
  -- partial index WHERE run_kind = 'shadow'
  KEY crawl_runs_shadow (run_kind, created_at),
  CONSTRAINT crawl_runs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT crawl_runs_replay_of_fk FOREIGN KEY (replay_of) REFERENCES crawl_runs (run_id),
  CONSTRAINT crawl_runs_authorization_record_fk FOREIGN KEY (authorization_record_id) REFERENCES authorization_records (record_id),
  CONSTRAINT crawl_runs_run_kind_check CHECK (run_kind IN ('crawl', 'replay', 'shadow')),
  CONSTRAINT crawl_runs_status_check CHECK (status IN ('queued', 'running', 'pausing', 'paused', 'cancelling', 'completed', 'failed', 'cancelled')),
  CONSTRAINT crawl_runs_terminal_reason_check CHECK (terminal_reason IS NULL OR terminal_reason IN ('frontier_exhausted', 'limit_reached', 'deadline_reached', 'policy_stopped', 'cancelled', 'fatal_error', 'recovery_exhausted', 'authorization_revoked')),
  CONSTRAINT crawl_runs_mode_check CHECK (mode IN ('static', 'dynamic', 'hybrid')),
  CONSTRAINT crawl_runs_safety_profile_check CHECK (safety_profile IN ('read_only', 'test_environment', 'authorized_security_test')),
  CONSTRAINT crawl_runs_retention_mode_check CHECK (retention_mode IN ('standard', 'extended', 'zdr')),
  CONSTRAINT crawl_runs_trace_id_check CHECK (trace_id IS NULL OR trace_id REGEXP '^[0-9a-f]{32}$'),
  CONSTRAINT terminal_consistent CHECK ((status IN ('completed', 'failed', 'cancelled')) = (terminal_reason IS NOT NULL)),
  CONSTRAINT auth_required CHECK (safety_profile <> 'authorized_security_test' OR authorization_record_id IS NOT NULL),
  CONSTRAINT zdr_days CHECK (retention_mode <> 'zdr' OR retention_days = 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0003, 0028 (lease_kind)
CREATE TABLE IF NOT EXISTS crawl_sessions (
  session_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  role VARCHAR(255) NOT NULL,
  run_index INT NOT NULL,
  schedule_slot INT NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  browser_build LONGTEXT NULL,
  cdp_revision LONGTEXT NULL,
  action_seq BIGINT NOT NULL DEFAULT 0,
  browser_user_agent LONGTEXT NULL,
  browser_pinned TINYINT(1) NULL,
  launch_profile VARCHAR(40) NOT NULL DEFAULT 'standard',
  console_capture TINYINT(1) NOT NULL DEFAULT 1,
  lease_owner BINARY(16) NULL,
  lease_expires_at DATETIME(6) NULL,
  fencing_token BIGINT NULL,
  last_heartbeat_at DATETIME(6) NULL,
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  lease_kind VARCHAR(40) NOT NULL DEFAULT 'role',
  -- expression index COALESCE(lease_expires_at, '-infinity'): NULL expiry means ready now
  lease_ready_at DATETIME(6) GENERATED ALWAYS AS (COALESCE(lease_expires_at, '1000-01-01 00:00:00.000000')) VIRTUAL,
  PRIMARY KEY (session_id),
  UNIQUE KEY crawl_sessions_run_id_role_run_index_key (run_id, role, run_index),
  UNIQUE KEY crawl_sessions_run_id_schedule_slot_key (run_id, schedule_slot),
  -- partial index WHERE status NOT IN (completed, failed, cancelled): ordered serial-turn barrier
  KEY crawl_sessions_claim (run_id, schedule_slot, status),
  -- partial index WHERE status IN (running, recovering)
  KEY crawl_sessions_reap (status, lease_expires_at),
  -- partial index WHERE status IN (pending, recovering)
  KEY crawl_sessions_ready (run_id, lease_ready_at, schedule_slot, status),
  CONSTRAINT crawl_sessions_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT crawl_sessions_status_check CHECK (status IN ('pending', 'running', 'recovering', 'completed', 'failed', 'cancelled')),
  CONSTRAINT crawl_sessions_launch_profile_check CHECK (launch_profile IN ('standard', 'stealth')),
  CONSTRAINT crawl_sessions_lease_kind_check CHECK (lease_kind IN ('role', 'render'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0003, 0024 (nullable url), 0027 (request envelope, tenant), 0043 (strategy_score)
CREATE TABLE IF NOT EXISTS url_frontier (
  frontier_id BIGINT NOT NULL AUTO_INCREMENT,
  run_id BINARY(16) NOT NULL,
  canonical_key VARBINARY(64) NOT NULL,
  canonical_url LONGTEXT NULL,
  origin VARCHAR(512) NOT NULL,
  query_schema LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(query_schema)),
  depth SMALLINT NOT NULL,
  priority FLOAT NOT NULL DEFAULT 0,
  via VARCHAR(40) NOT NULL,
  parent_id BIGINT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  denial_reason LONGTEXT NULL,
  error_code LONGTEXT NULL,
  attempts SMALLINT NOT NULL DEFAULT 0,
  next_attempt_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  lease_owner BINARY(16) NULL,
  lease_expires_at DATETIME(6) NULL,
  fencing_token BIGINT NULL,
  discovered_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  finished_at DATETIME(6) NULL,
  request_version SMALLINT NOT NULL DEFAULT 1,
  principal VARCHAR(255) NOT NULL DEFAULT 'anonymous',
  route_id VARCHAR(255) NOT NULL DEFAULT 'default',
  revisit_generation INT NOT NULL DEFAULT 0,
  request_envelope LONGTEXT NULL CHECK (JSON_VALID(request_envelope)),
  envelope_bytes BIGINT NOT NULL DEFAULT 0,
  effect_reservations BIGINT NOT NULL DEFAULT 0,
  effect_escrow_fence BIGINT NULL,
  effect_escrow_amount BIGINT NULL,
  effect_escrow_settlement BIGINT NULL,
  acquisition_deadline_at DATETIME(6) NULL,
  acquisition_usage LONGTEXT NULL CHECK (JSON_VALID(acquisition_usage)),
  acquisition_escrow LONGTEXT NULL CHECK (JSON_VALID(acquisition_escrow)),
  acquisition_escrow_fence BIGINT NULL,
  acquisition_settlement LONGTEXT NULL CHECK (JSON_VALID(acquisition_settlement)),
  state_version BIGINT NOT NULL DEFAULT 1,
  acquisition_ref VARBINARY(255) NULL,
  document_ref VARBINARY(255) NULL,
  tenant_id BINARY(16) NOT NULL,
  strategy_score INT NULL,
  PRIMARY KEY (frontier_id),
  UNIQUE KEY url_frontier_request_unique (run_id, canonical_key, revisit_generation),
  UNIQUE KEY frontier_tenant_run_row (tenant_id, run_id, frontier_id),
  -- partial index WHERE status = 'pending' (all four): status leads, equality on 'pending'
  KEY url_frontier_claim (status, run_id, origin, priority DESC, depth, frontier_id),
  KEY url_frontier_reap (status, lease_expires_at),
  KEY url_frontier_eligible (status, run_id, next_attempt_at, priority DESC, depth, frontier_id),
  KEY url_frontier_strategy_claim (status, run_id, priority DESC, strategy_score, depth, frontier_id),
  -- partial index WHERE status IN (pending, leased) AND strategy_score IS NULL
  KEY url_frontier_score_backfill (run_id, strategy_score, frontier_id),
  CONSTRAINT url_frontier_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT url_frontier_parent_fk FOREIGN KEY (parent_id) REFERENCES url_frontier (frontier_id),
  CONSTRAINT url_frontier_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT frontier_tenant_run FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id),
  CONSTRAINT url_frontier_via_check CHECK (via IN ('seed', 'sitemap', 'link', 'interaction')),
  CONSTRAINT url_frontier_status_check CHECK (status IN ('pending', 'leased', 'succeeded', 'failed', 'abandoned', 'unreachable', 'policy_blocked', 'robots_blocked')),
  CONSTRAINT url_frontier_request_version_check CHECK (request_version = 1),
  CONSTRAINT url_frontier_revisit_generation_check CHECK (revisit_generation >= 0),
  CONSTRAINT url_frontier_envelope_bytes_check CHECK (envelope_bytes >= 0),
  CONSTRAINT url_frontier_effect_reservations_check CHECK (effect_reservations >= 0),
  CONSTRAINT url_frontier_state_version_check CHECK (state_version > 0),
  CONSTRAINT url_frontier_strategy_score_check CHECK (strategy_score BETWEEN 0 AND 65539)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0003, 0018 (host_key), 0024 (nullable urls). `host_key` is the page host, lower-case and
-- reversed (`moc.elpmaxe.bus`): generated, so no writer and every stored row is covered. NULL
-- when the url has no scheme://host prefix. Prefix-indexed (255 chars) for `LIKE 'prefix%'`.
CREATE TABLE IF NOT EXISTS pages (
  page_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NULL,
  frontier_id BIGINT NULL,
  role VARCHAR(255) NOT NULL DEFAULT 'anonymous',
  plane VARCHAR(40) NOT NULL,
  url_hash VARBINARY(64) NOT NULL,
  canonical_url LONGTEXT NULL,
  final_url LONGTEXT NULL,
  http_status INT NULL,
  content_type LONGTEXT NULL,
  content_digest VARBINARY(64) NULL,
  markdown_artifact_id BINARY(16) NULL,
  html_artifact_id BINARY(16) NULL,
  raw_html_artifact_id BINARY(16) NULL,
  metadata LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(metadata)),
  links LONGTEXT NULL CHECK (JSON_VALID(links)),
  observation_epoch LONGTEXT NULL CHECK (JSON_VALID(observation_epoch)),
  fetched_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  lane VARCHAR(40) NOT NULL DEFAULT 'diagnostic',
  title LONGTEXT NULL,
  url_meta LONGTEXT NULL CHECK (JSON_VALID(url_meta)),
  markdown_digest VARBINARY(64) NULL,
  html_digest VARBINARY(64) NULL,
  host_key VARCHAR(2048) GENERATED ALWAYS AS (
    CASE WHEN canonical_url REGEXP '^[A-Za-z][A-Za-z0-9+.-]*://' THEN
      REVERSE(LOWER(REGEXP_REPLACE(canonical_url,
        '(?s)^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?(\\[[^]/?#]*\\]|[^/?#:@]*).*$', '\\1')))
    END) STORED,
  PRIMARY KEY (page_id),
  UNIQUE KEY pages_run_id_role_url_hash_key (run_id, role, url_hash),
  -- partial index WHERE expires_at IS NOT NULL
  KEY pages_expiry (expires_at),
  KEY pages_url_recent (url_hash, fetched_at DESC),
  KEY pages_host_key (host_key(255)),
  CONSTRAINT pages_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT pages_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT pages_frontier_fk FOREIGN KEY (frontier_id) REFERENCES url_frontier (frontier_id),
  CONSTRAINT pages_plane_check CHECK (plane IN ('http', 'browser')),
  CONSTRAINT pages_lane_check CHECK (lane IN ('trusted_ui', 'diagnostic'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004. `lsh_prefix` replaces the expression index substring(minhash FROM 1 FOR 8).
CREATE TABLE IF NOT EXISTS states (
  state_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  route_key LONGTEXT NOT NULL,
  semantic_affordance_minhash LONGBLOB NOT NULL,
  dom_structure_simhash BIGINT NOT NULL,
  visible_identity_digest VARBINARY(64) NOT NULL,
  frame_tree_digest VARBINARY(64) NOT NULL,
  network_operation_digest VARBINARY(64) NULL,
  visual_phash BIGINT NULL,
  browser_storage_digest VARBINARY(64) NULL,
  masks LONGTEXT NOT NULL DEFAULT '[]' CHECK (JSON_VALID(masks)),
  epoch_navigation BIGINT NOT NULL,
  epoch_document BIGINT NOT NULL,
  epoch_mutation BIGINT NOT NULL,
  state_algo_version SMALLINT NOT NULL,
  manifest_artifact_id BINARY(16) NULL,
  observed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NULL,
  observed_url LONGTEXT NULL CHECK (JSON_VALID(observed_url)),
  artifacts LONGTEXT NOT NULL DEFAULT '[]' CHECK (JSON_VALID(artifacts)),
  lsh_prefix VARBINARY(8) GENERATED ALWAYS AS (SUBSTRING(semantic_affordance_minhash, 1, 8)) VIRTUAL,
  PRIMARY KEY (state_id),
  KEY states_route (run_id, route_key(255)),
  KEY states_session (session_id, epoch_navigation, epoch_document, epoch_mutation),
  KEY states_lsh (run_id, lsh_prefix),
  CONSTRAINT states_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT states_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004
CREATE TABLE IF NOT EXISTS state_clusters (
  cluster_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  version INT NOT NULL DEFAULT 1,
  prototype_state_id BINARY(16) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'active',
  superseded_by BINARY(16) NULL,
  algo_version SMALLINT NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (cluster_id),
  KEY state_clusters_run (run_id),
  CONSTRAINT state_clusters_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT state_clusters_prototype_fk FOREIGN KEY (prototype_state_id) REFERENCES states (state_id),
  CONSTRAINT state_clusters_superseded_by_fk FOREIGN KEY (superseded_by) REFERENCES state_clusters (cluster_id),
  CONSTRAINT state_clusters_status_check CHECK (status IN ('active', 'superseded'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004. `active_state_id` replaces the unique partial index scm_one_active (WHERE active):
-- NULL while inactive, so only one active membership per state exists.
CREATE TABLE IF NOT EXISTS state_cluster_membership (
  state_id BINARY(16) NOT NULL,
  cluster_id BINARY(16) NOT NULL,
  decision_version INT NOT NULL,
  similarity FLOAT NOT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1,
  assigned_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  active_state_id BINARY(16) GENERATED ALWAYS AS (IF(active, state_id, NULL)) VIRTUAL,
  PRIMARY KEY (state_id, cluster_id, decision_version),
  UNIQUE KEY scm_one_active (active_state_id),
  -- partial index WHERE active
  KEY scm_cluster (cluster_id, active),
  CONSTRAINT state_cluster_membership_state_fk FOREIGN KEY (state_id) REFERENCES states (state_id),
  CONSTRAINT state_cluster_membership_cluster_fk FOREIGN KEY (cluster_id) REFERENCES state_clusters (cluster_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004
CREATE TABLE IF NOT EXISTS elements (
  run_id BINARY(16) NOT NULL,
  identity_hash VARBINARY(64) NOT NULL,
  identity_version SMALLINT NOT NULL,
  components LONGTEXT NULL CHECK (JSON_VALID(components)),
  interactability LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(interactability)),
  first_seen_state_id BINARY(16) NULL,
  first_seen_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_seen_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (run_id, identity_hash, identity_version),
  CONSTRAINT elements_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT elements_first_seen_state_fk FOREIGN KEY (first_seen_state_id) REFERENCES states (state_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004, 0026 (coarsened). state_cluster_id carries no foreign key (a proposal may be
-- journaled before its cluster row lands). The nine-column PostgreSQL unique key is too wide for
-- an InnoDB index, so `context_key_hash` (SHA-256 over length-prefixed key columns) carries it.
CREATE TABLE IF NOT EXISTS action_contexts (
  context_id BIGINT NOT NULL AUTO_INCREMENT,
  run_id BINARY(16) NOT NULL,
  context_hash VARBINARY(64) NOT NULL,
  principal VARCHAR(255) NOT NULL,
  route_template LONGTEXT NOT NULL,
  identity_hash VARBINARY(64) NOT NULL,
  identity_version SMALLINT NOT NULL,
  action_kind VARCHAR(40) NOT NULL,
  input_class VARCHAR(255) NOT NULL DEFAULT 'none',
  resource_context VARCHAR(40) NOT NULL DEFAULT 'none',
  state_cluster_id BINARY(16) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  succeeded INT NOT NULL DEFAULT 0,
  succeeded_trusted INT NOT NULL DEFAULT 0,
  failed INT NOT NULL DEFAULT 0,
  `unknown` INT NOT NULL DEFAULT 0,
  denied INT NOT NULL DEFAULT 0,
  first_seen_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  first_exercised_at DATETIME(6) NULL,
  last_exercised_at DATETIME(6) NULL,
  last_action_id BINARY(16) NULL,
  coarsened TINYINT(1) NOT NULL DEFAULT 0,
  context_key_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(CONCAT(
    CHAR_LENGTH(principal), ':', principal, '|', CHAR_LENGTH(route_template), ':', route_template, '|',
    HEX(identity_hash), '|', identity_version, '|', action_kind, '|',
    CHAR_LENGTH(input_class), ':', input_class, '|', resource_context, '|', HEX(state_cluster_id)), 256))) STORED,
  PRIMARY KEY (context_id),
  UNIQUE KEY action_contexts_run_id_context_hash_key (run_id, context_hash),
  UNIQUE KEY action_contexts_run_id_principal_route_template_identity_ha_key (run_id, context_key_hash),
  CONSTRAINT action_contexts_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT action_contexts_action_kind_check CHECK (action_kind IN ('click', 'keyboard_activate', 'type', 'select', 'set_checked', 'set_range', 'hover', 'drag', 'upload', 'scroll', 'keys', 'navigate', 'switch_tab', 'close_tab', 'synthetic_click', 'solve_captcha')),
  CONSTRAINT action_contexts_resource_context_check CHECK (resource_context IN ('own', 'other_user_same_role', 'higher_role', 'shared', 'none'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004. action_id is not a foreign key (the verdict is written before the action row).
CREATE TABLE IF NOT EXISTS safety_decisions (
  decision_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  action_id BINARY(16) NULL,
  session_id BINARY(16) NULL,
  risk_class VARCHAR(40) NOT NULL,
  verdict VARCHAR(40) NOT NULL,
  profile VARCHAR(40) NOT NULL,
  rules LONGTEXT NOT NULL CHECK (JSON_VALID(rules)),
  evidence LONGTEXT NOT NULL CHECK (JSON_VALID(evidence)),
  policy_version INT NOT NULL,
  authorization_record_id BINARY(16) NULL,
  decided_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (decision_id),
  KEY safety_decisions_action (action_id),
  KEY safety_decisions_run (run_id),
  CONSTRAINT safety_decisions_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT safety_decisions_risk_class_check CHECK (risk_class IN ('navigation_reveal', 'reversible_local_preference', 'persistent_write_own', 'persistent_write_other_principal', 'external_communication', 'financial_transaction', 'destructive', 'security_change', 'file_upload', 'out_of_scope', 'unclassified')),
  CONSTRAINT safety_decisions_verdict_check CHECK (verdict IN ('allow', 'deny', 'approval_required')),
  CONSTRAINT safety_decisions_profile_check CHECK (profile IN ('read_only', 'test_environment', 'authorized_security_test'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004
CREATE TABLE IF NOT EXISTS model_decisions (
  decision_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NULL,
  action_id BINARY(16) NULL,
  kind VARCHAR(40) NOT NULL,
  mode VARCHAR(40) NOT NULL,
  provider VARCHAR(255) NOT NULL,
  model VARCHAR(255) NOT NULL,
  model_version VARCHAR(255) NOT NULL,
  calibration_version VARCHAR(255) NULL,
  confidence FLOAT NULL,
  output LONGTEXT NOT NULL CHECK (JSON_VALID(output)),
  prompt_digest VARBINARY(64) NOT NULL,
  io_artifact_id BINARY(16) NULL,
  latency_ms INT NULL,
  breaker_state VARCHAR(255) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (decision_id),
  CONSTRAINT model_decisions_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT model_decisions_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT model_decisions_kind_check CHECK (kind IN ('rank', 'classify_input', 'classify_form', 'plan', 'risk_hint')),
  CONSTRAINT model_decisions_mode_check CHECK (mode IN ('shadow', 'advisory', 'active'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004, 0013 (trace_id), 0029 (dataset_page identity + dataset_action_run key), 0046 (fidelity).
-- model_decision_id carries no foreign key. `dataset_page` is a non-key identity: AUTO_INCREMENT
-- on a unique key.
CREATE TABLE IF NOT EXISTS actions (
  action_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  seq BIGINT NOT NULL,
  context_id BIGINT NOT NULL,
  action_kind VARCHAR(40) NOT NULL,
  params LONGTEXT NOT NULL DEFAULT '{}' CHECK (JSON_VALID(params)),
  strategy VARCHAR(255) NOT NULL,
  strategy_version INT NOT NULL,
  epoch_navigation BIGINT NOT NULL,
  epoch_document BIGINT NOT NULL,
  epoch_mutation BIGINT NOT NULL,
  fidelity VARCHAR(40) NOT NULL,
  lane VARCHAR(40) NOT NULL,
  safety_decision_id BINARY(16) NOT NULL,
  model_decision_id BINARY(16) NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'proposed',
  hold VARCHAR(40) NOT NULL DEFAULT 'none',
  attempt SMALLINT NOT NULL DEFAULT 0,
  reconcile_resolution VARCHAR(40) NULL,
  outcome LONGTEXT NULL CHECK (JSON_VALID(outcome)),
  proposed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  intended_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  before_state_id BINARY(16) NULL,
  reconciled_at DATETIME(6) NULL,
  trace_id VARCHAR(32) NULL,
  dataset_page BIGINT NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (action_id),
  UNIQUE KEY actions_session_id_seq_key (session_id, seq),
  UNIQUE KEY dataset_action_run (run_id, action_id),
  UNIQUE KEY dataset_action_page (dataset_page),
  -- partial index WHERE status IN (proposed, reconciled) AND hold = 'none'
  KEY actions_schedulable (run_id, session_id, hold, proposed_at, status),
  -- partial index WHERE status IN (intended, unknown)
  KEY actions_needs_reconcile (session_id, status),
  KEY actions_run (run_id, status),
  CONSTRAINT actions_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT actions_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT actions_context_fk FOREIGN KEY (context_id) REFERENCES action_contexts (context_id),
  CONSTRAINT actions_safety_decision_fk FOREIGN KEY (safety_decision_id) REFERENCES safety_decisions (decision_id),
  CONSTRAINT actions_action_kind_check CHECK (action_kind IN ('click', 'keyboard_activate', 'type', 'select', 'set_checked', 'set_range', 'hover', 'drag', 'upload', 'scroll', 'keys', 'navigate', 'switch_tab', 'close_tab', 'synthetic_click', 'solve_captcha')),
  CONSTRAINT actions_fidelity_check CHECK (fidelity IN ('native_pointer', 'native_keyboard', 'native_text_input', 'file_chooser', 'scripted_navigation', 'synthetic_dom_event', 'fetch_plane', 'scripted_scroll')),
  CONSTRAINT actions_lane_check CHECK (lane IN ('trusted_ui', 'diagnostic')),
  CONSTRAINT actions_status_check CHECK (status IN ('proposed', 'intended', 'succeeded', 'failed', 'unknown', 'reconciled')),
  CONSTRAINT actions_hold_check CHECK (hold IN ('none', 'denied', 'awaiting_approval', 'stale')),
  CONSTRAINT actions_reconcile_resolution_check CHECK (reconcile_resolution IS NULL OR reconcile_resolution IN ('applied', 'not_applied', 'indeterminate')),
  CONSTRAINT actions_trace_id_check CHECK (trace_id IS NULL OR trace_id REGEXP '^[0-9a-f]{32}$'),
  CONSTRAINT lane_matches_fidelity CHECK ((lane = 'trusted_ui') = (fidelity IN ('native_pointer', 'native_keyboard', 'native_text_input')))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0004 actions_enforce_transition. Raised message is parsed by crawlx-storage
-- (`illegal actions.status transition A -> B`); it must stay byte-identical.
CREATE OR REPLACE TRIGGER actions_transition BEFORE UPDATE ON actions
FOR EACH ROW
BEGIN
  DECLARE msg VARCHAR(128);
  IF NOT (NEW.status <=> OLD.status) THEN
    IF NOT (
      (OLD.status = 'proposed' AND NEW.status = 'intended')
      OR (OLD.status = 'intended' AND NEW.status IN ('succeeded', 'failed', 'unknown'))
      OR (OLD.status IN ('succeeded', 'failed', 'unknown') AND NEW.status = 'reconciled')
      OR (OLD.status = 'reconciled' AND NEW.status = 'intended'
          AND OLD.reconcile_resolution <=> 'not_applied' AND NEW.attempt = OLD.attempt + 1)
    ) THEN
      SET msg = CONCAT('illegal actions.status transition ', OLD.status, ' -> ', NEW.status);
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = msg;
    END IF;
  END IF;
END;

-- from: 0008 actions_lane_immutable. Once an action is succeeded/failed/unknown/reconciled its
-- lane and fidelity are evidence.
CREATE OR REPLACE TRIGGER actions_lane_immutable BEFORE UPDATE ON actions
FOR EACH ROW
BEGIN
  DECLARE msg VARCHAR(128);
  IF (NOT (NEW.lane <=> OLD.lane) OR NOT (NEW.fidelity <=> OLD.fidelity))
     AND OLD.status IN ('succeeded', 'failed', 'unknown', 'reconciled') THEN
    SET msg = CONCAT('actions.lane/fidelity are immutable after T2 (action ', LOWER(HEX(OLD.action_id)), ', status ', OLD.status, ')');
    SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 4025, CONSTRAINT_NAME = 'actions_lane_immutable', MESSAGE_TEXT = msg;
  END IF;
END;

-- from: 0019 authorization_records_immutable. The body is immutable evidence; only the lifecycle
-- columns (revoked_*, verified_at, verification, evidence_artifact_id) may change.
CREATE OR REPLACE TRIGGER authorization_records_immutable BEFORE UPDATE ON authorization_records
FOR EACH ROW
BEGIN
  DECLARE msg VARCHAR(128);
  IF NOT (NEW.record_id <=> OLD.record_id)
     OR NOT (NEW.tenant_id <=> OLD.tenant_id)
     OR NOT (NEW.version <=> OLD.version)
     OR NOT (NEW.body <=> OLD.body)
     OR NOT (NEW.body_digest <=> OLD.body_digest)
     OR NOT (NEW.valid_from <=> OLD.valid_from)
     OR NOT (NEW.valid_to <=> OLD.valid_to) THEN
    SET msg = CONCAT('authorization_records body is immutable: record ', LOWER(HEX(OLD.record_id)), ' (an amendment is a new record id)');
    SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 4025, MESSAGE_TEXT = msg;
  END IF;
END;

-- from: 0024 enforce_zdr_run_config, validation half only. The projection that rewrites the
-- config of a zero-retention run is done by the repository before the write.
CREATE OR REPLACE TRIGGER zdr_run_config_ins BEFORE INSERT ON crawl_runs
FOR EACH ROW
BEGIN
  IF NEW.retention_mode = 'zdr'
     AND (NOT (JSON_VALUE(NEW.config, '$.privacy') <=> 'zdr') OR JSON_EXTRACT(NEW.config, '$.metadata') IS NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr requires metadata-only durable configuration';
  END IF;
END;

CREATE OR REPLACE TRIGGER zdr_run_config_upd BEFORE UPDATE ON crawl_runs
FOR EACH ROW
BEGIN
  IF NEW.retention_mode = 'zdr'
     AND (NOT (JSON_VALUE(NEW.config, '$.privacy') <=> 'zdr') OR JSON_EXTRACT(NEW.config, '$.metadata') IS NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr requires metadata-only durable configuration';
  END IF;
END;
