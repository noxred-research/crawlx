-- crawlx-storage (MariaDB) baseline 2 of 5: artifacts, network, edges, durability, audit chain,
-- workers, leases, trust lanes, identity aliases, cluster settings.
--
-- Hand-ported final PostgreSQL schema (levels 0005-0012 plus every later column added to these
-- tables). Conventions are listed in the first baseline file. Idempotent.

-- from: 0006, 0040 (sealed-catalog trigger lives in the last baseline file)
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NULL,
  kind VARCHAR(40) NOT NULL,
  bucket VARCHAR(255) NOT NULL,
  object_key VARCHAR(512) NOT NULL,
  size_bytes BIGINT NOT NULL,
  content_digest VARBINARY(64) NOT NULL,
  content_type VARCHAR(255) NOT NULL,
  sensitivity VARCHAR(40) NOT NULL,
  encryption VARCHAR(255) NOT NULL DEFAULT 'sse-kms',
  key_id LONGTEXT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NULL,
  deleted_at DATETIME(6) NULL,
  PRIMARY KEY (artifact_id),
  -- One artifacts row per use: identical content in a run shares an object, so
  -- (bucket, object_key) is indexed but not unique.
  KEY artifacts_object (bucket, object_key),
  -- partial index WHERE deleted_at IS NULL AND expires_at IS NOT NULL
  KEY artifacts_sweep (deleted_at, expires_at),
  KEY artifacts_run (run_id, kind),
  CONSTRAINT artifacts_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT artifacts_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT artifacts_kind_check CHECK (kind IN ('markdown', 'html', 'raw_html', 'dom_snapshot', 'ax_tree', 'screenshot', 'response_body', 'manifest', 'plan', 'storage_state', 'robots', 'model_io', 'evidence')),
  CONSTRAINT artifacts_sensitivity_check CHECK (sensitivity IN ('metadata', 'content', 'sensitive', 'credential_bearing'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0006 (deferred foreign key of authorization_records.evidence_artifact_id)
ALTER TABLE authorization_records
  ADD CONSTRAINT authorization_records_evidence_artifact_fk FOREIGN KEY IF NOT EXISTS (evidence_artifact_id) REFERENCES artifacts (artifact_id);

-- from: 0005, 0010 (nullable epoch_id + unattributed_reason). The monthly range partitions of the
-- PostgreSQL table are omitted: a plain table with the same keys; retention deletes in batches.
-- The primary key keeps (event_id, occurred_at) so the key set matches the partitioned original.
CREATE TABLE IF NOT EXISTS traffic_events (
  event_id BIGINT NOT NULL AUTO_INCREMENT,
  occurred_at DATETIME(6) NOT NULL,
  run_id BINARY(16) NOT NULL,
  epoch_id BINARY(16) NULL,
  seq INT NOT NULL,
  lane VARCHAR(40) NOT NULL,
  origin VARCHAR(40) NOT NULL,
  third_party TINYINT(1) NOT NULL DEFAULT 0,
  late TINYINT(1) NOT NULL DEFAULT 0,
  attribution_confidence VARCHAR(40) NOT NULL DEFAULT 'high',
  method VARCHAR(64) NULL,
  url_redacted LONGTEXT NULL,
  url_hash VARBINARY(64) NOT NULL,
  status INT NULL,
  request_headers LONGTEXT NULL CHECK (JSON_VALID(request_headers)),
  response_headers LONGTEXT NULL CHECK (JSON_VALID(response_headers)),
  secret_value_hashes LONGTEXT NULL CHECK (JSON_VALID(secret_value_hashes)),
  body_artifact_id BINARY(16) NULL,
  request_body_artifact_id BINARY(16) NULL,
  finished_at DATETIME(6) NULL,
  unattributed_reason VARCHAR(40) NULL,
  PRIMARY KEY (event_id, occurred_at),
  KEY traffic_events_epoch (epoch_id, seq),
  KEY traffic_events_run (run_id),
  KEY traffic_events_occurred (occurred_at),
  CONSTRAINT traffic_events_lane_check CHECK (lane IN ('trusted_ui', 'diagnostic')),
  CONSTRAINT traffic_events_origin_check CHECK (origin IN ('page', 'service_worker', 'websocket', 'event_source', 'fetch_plane')),
  CONSTRAINT traffic_events_unattributed_reason_check CHECK (unattributed_reason IS NULL OR unattributed_reason IN ('not_applicable', 'before_first_epoch', 'no_receipt', 'unmatched_proxy_flow')),
  CONSTRAINT traffic_events_attribution CHECK ((epoch_id IS NULL) = (unattributed_reason IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0005
CREATE TABLE IF NOT EXISTS network_epochs (
  epoch_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  action_id BINARY(16) NULL,
  lane VARCHAR(40) NOT NULL,
  started_at DATETIME(6) NOT NULL,
  settled_at DATETIME(6) NULL,
  request_count INT NOT NULL DEFAULT 0,
  unique_operations INT NOT NULL DEFAULT 0,
  settle_timeout TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (epoch_id),
  KEY network_epochs_action (action_id),
  CONSTRAINT network_epochs_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT network_epochs_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT network_epochs_action_fk FOREIGN KEY (action_id) REFERENCES actions (action_id),
  CONSTRAINT network_epochs_lane_check CHECK (lane IN ('trusted_ui', 'diagnostic'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0005
CREATE TABLE IF NOT EXISTS transitions (
  transition_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  before_state_id BINARY(16) NOT NULL,
  action_id BINARY(16) NOT NULL,
  network_epoch_id BINARY(16) NULL,
  after_state_id BINARY(16) NULL,
  lane VARCHAR(40) NOT NULL,
  settle_report LONGTEXT NOT NULL CHECK (JSON_VALID(settle_report)),
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (transition_id),
  UNIQUE KEY transitions_action_id_key (action_id),
  KEY transitions_before (run_id, before_state_id),
  CONSTRAINT transitions_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT transitions_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT transitions_before_state_fk FOREIGN KEY (before_state_id) REFERENCES states (state_id),
  CONSTRAINT transitions_action_fk FOREIGN KEY (action_id) REFERENCES actions (action_id),
  CONSTRAINT transitions_network_epoch_fk FOREIGN KEY (network_epoch_id) REFERENCES network_epochs (epoch_id),
  CONSTRAINT transitions_after_state_fk FOREIGN KEY (after_state_id) REFERENCES states (state_id),
  CONSTRAINT transitions_lane_check CHECK (lane IN ('trusted_ui', 'diagnostic'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0005. context_cluster_id carries no foreign key. UNIQUE NULLS NOT DISTINCT is replaced
-- by `context_cluster_key`, the cluster id with NULL mapped to sixteen zero bytes.
CREATE TABLE IF NOT EXISTS enablement_edges (
  edge_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  source_context_id BIGINT NOT NULL,
  context_cluster_id BINARY(16) NULL,
  target_kind VARCHAR(40) NOT NULL,
  target_key VARBINARY(64) NOT NULL,
  support INT NOT NULL DEFAULT 0,
  failures INT NOT NULL DEFAULT 0,
  weak_support INT NOT NULL DEFAULT 0,
  p_success DOUBLE GENERATED ALWAYS AS ((support + 0.5e0 * weak_support + 1) / (support + 0.5e0 * weak_support + failures + 2)) STORED,
  latency_ms_ewma FLOAT NULL,
  risk FLOAT NOT NULL DEFAULT 0,
  last_observed_at DATETIME(6) NULL,
  last_verified_build LONGTEXT NULL,
  algo_version SMALLINT NOT NULL,
  context_cluster_key BINARY(16) GENERATED ALWAYS AS (COALESCE(context_cluster_id, 0x00000000000000000000000000000000)) STORED,
  PRIMARY KEY (edge_id),
  UNIQUE KEY enablement_edges_run_id_source_context_id_context_cluster_i_key (run_id, source_context_id, context_cluster_key, target_kind, target_key),
  CONSTRAINT enablement_edges_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT enablement_edges_source_context_fk FOREIGN KEY (source_context_id) REFERENCES action_contexts (context_id),
  CONSTRAINT enablement_edges_target_kind_check CHECK (target_kind IN ('element', 'state'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0005
CREATE TABLE IF NOT EXISTS approvals (
  approval_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  action_id BINARY(16) NOT NULL,
  safety_decision_id BINARY(16) NOT NULL,
  risk_class VARCHAR(40) NOT NULL,
  summary LONGTEXT NOT NULL CHECK (JSON_VALID(summary)),
  requested_by VARCHAR(255) NOT NULL DEFAULT 'safety_kernel',
  decision VARCHAR(40) NOT NULL DEFAULT 'pending',
  decided_by BINARY(16) NULL,
  decided_at DATETIME(6) NULL,
  reason LONGTEXT NULL,
  consumed_at DATETIME(6) NULL,
  requested_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (approval_id),
  -- partial index WHERE decision = 'pending'
  KEY approvals_pending (run_id, decision, expires_at),
  CONSTRAINT approvals_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT approvals_action_fk FOREIGN KEY (action_id) REFERENCES actions (action_id),
  CONSTRAINT approvals_safety_decision_fk FOREIGN KEY (safety_decision_id) REFERENCES safety_decisions (decision_id),
  CONSTRAINT approvals_decided_by_fk FOREIGN KEY (decided_by) REFERENCES api_keys (key_id),
  CONSTRAINT approvals_risk_class_check CHECK (risk_class IN ('navigation_reveal', 'reversible_local_preference', 'persistent_write_own', 'persistent_write_other_principal', 'external_communication', 'financial_transaction', 'destructive', 'security_change', 'file_upload', 'out_of_scope', 'unclassified')),
  CONSTRAINT approvals_decision_check CHECK (decision IN ('pending', 'approved', 'denied', 'expired'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0006, 0038 (checkpoints_run_expiry)
CREATE TABLE IF NOT EXISTS checkpoints (
  checkpoint_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  epoch_navigation BIGINT NOT NULL,
  epoch_document BIGINT NOT NULL,
  epoch_mutation BIGINT NOT NULL,
  action_seq BIGINT NOT NULL,
  reason VARCHAR(40) NOT NULL,
  storage_artifact_id BINARY(16) NOT NULL,
  cookies_ref LONGTEXT NULL,
  url_hash VARBINARY(64) NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (checkpoint_id),
  KEY checkpoints_latest (session_id, action_seq DESC),
  KEY checkpoints_run_expiry (run_id, expires_at),
  CONSTRAINT checkpoints_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT checkpoints_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT checkpoints_storage_artifact_fk FOREIGN KEY (storage_artifact_id) REFERENCES artifacts (artifact_id),
  CONSTRAINT checkpoints_reason_check CHECK (reason IN ('cadence_actions', 'cadence_time', 'pre_mutation', 'pause', 'approval_wait', 'shutdown'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0006 (coverage_tags: text[] -> JSON array of strings)
CREATE TABLE IF NOT EXISTS workflow_runs (
  workflow_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  session_id BINARY(16) NULL,
  planner_decision_id BINARY(16) NULL,
  plan_artifact_id BINARY(16) NULL,
  status VARCHAR(40) NOT NULL,
  assertions LONGTEXT NOT NULL DEFAULT '[]' CHECK (JSON_VALID(assertions)),
  coverage_tags LONGTEXT NOT NULL DEFAULT '[]' CHECK (JSON_VALID(coverage_tags)),
  entities_created LONGTEXT NOT NULL DEFAULT '[]' CHECK (JSON_VALID(entities_created)),
  started_at DATETIME(6) NULL,
  finished_at DATETIME(6) NULL,
  PRIMARY KEY (workflow_id),
  CONSTRAINT workflow_runs_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT workflow_runs_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id),
  CONSTRAINT workflow_runs_planner_decision_fk FOREIGN KEY (planner_decision_id) REFERENCES model_decisions (decision_id),
  CONSTRAINT workflow_runs_plan_artifact_fk FOREIGN KEY (plan_artifact_id) REFERENCES artifacts (artifact_id),
  CONSTRAINT workflow_runs_status_check CHECK (status IN ('planned', 'running', 'completed', 'aborted', 'invalid'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0006 (audit chain). `prev_hash`/`entry_hash` form the BLAKE3 chain computed by the
-- repository; the chain head lives in audit_chain_head below, so appending never scans this table.
CREATE TABLE IF NOT EXISTS audit_events (
  audit_id BIGINT NOT NULL AUTO_INCREMENT,
  tenant_id BINARY(16) NULL,
  run_id BINARY(16) NULL,
  actor VARCHAR(255) NOT NULL,
  event VARCHAR(255) NOT NULL,
  subject LONGTEXT NOT NULL CHECK (JSON_VALID(subject)),
  occurred_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  prev_hash VARBINARY(64) NOT NULL,
  entry_hash VARBINARY(64) NOT NULL,
  PRIMARY KEY (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- new: one-row audit chain head, replacing the global advisory lock plus the SECURITY DEFINER
-- head reader. Append = in one transaction `SELECT entry_hash .. WHERE id = 1 FOR UPDATE`,
-- insert the audit_events row, `UPDATE audit_chain_head SET entry_hash = ?`. Seeded with 32 zero
-- bytes (the empty-chain head).
CREATE TABLE IF NOT EXISTS audit_chain_head (
  id TINYINT NOT NULL,
  entry_hash VARBINARY(32) NOT NULL,
  PRIMARY KEY (id),
  CONSTRAINT audit_chain_head_singleton CHECK (id = 1),
  CONSTRAINT audit_chain_head_hash_len CHECK (OCTET_LENGTH(entry_hash) = 32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
INSERT INTO audit_chain_head (id, entry_hash) VALUES (1, UNHEX(REPEAT('00', 32))) ON DUPLICATE KEY UPDATE id = id;

-- from: 0006, 0036 (metadata_only_audit_id)
CREATE TABLE IF NOT EXISTS crawl_events (
  run_id BINARY(16) NOT NULL,
  seq BIGINT NOT NULL,
  type VARCHAR(255) NOT NULL,
  payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  metadata_only_audit_id BIGINT NULL,
  PRIMARY KEY (run_id, seq),
  -- unique partial index WHERE metadata_only_audit_id IS NOT NULL: NULLs never collide
  UNIQUE KEY crawl_events_metadata_only_audit (metadata_only_audit_id),
  CONSTRAINT crawl_events_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT crawl_events_metadata_only_audit_fk FOREIGN KEY (metadata_only_audit_id) REFERENCES audit_events (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0006
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  event_seq BIGINT NOT NULL,
  event_type VARCHAR(255) NOT NULL,
  url LONGTEXT NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  attempts SMALLINT NOT NULL DEFAULT 0,
  next_attempt_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  delivered_at DATETIME(6) NULL,
  last_status INT NULL,
  last_error LONGTEXT NULL,
  PRIMARY KEY (delivery_id),
  -- partial index WHERE status = 'pending'
  KEY webhook_due (status, next_attempt_at),
  CONSTRAINT webhook_deliveries_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT webhook_deliveries_event_fk FOREIGN KEY (run_id, event_seq) REFERENCES crawl_events (run_id, seq),
  CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('pending', 'delivered', 'dead'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0007, 0033/0034 (capacity probes are evaluated by the repository, not in SQL)
CREATE TABLE IF NOT EXISTS workers (
  worker_id BINARY(16) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  version VARCHAR(255) NOT NULL,
  capacity LONGTEXT NOT NULL CHECK (JSON_VALID(capacity)),
  draining TINYINT(1) NOT NULL DEFAULT 0,
  started_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_heartbeat_at DATETIME(6) NOT NULL,
  PRIMARY KEY (worker_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0007, 0023 (run-local admission columns)
CREATE TABLE IF NOT EXISTS origin_leases (
  run_id BINARY(16) NOT NULL,
  origin VARCHAR(512) NOT NULL,
  owner BINARY(16) NULL,
  lease_expires_at DATETIME(6) NULL,
  fencing_token BIGINT NULL,
  next_allowed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  backoff_until DATETIME(6) NULL,
  crawl_delay_ms INT NULL,
  robots_artifact_id BINARY(16) NULL,
  robots_status SMALLINT NULL,
  robots_fetched_at DATETIME(6) NULL,
  admission_next_ticket BIGINT NOT NULL DEFAULT 0,
  admission_limit BIGINT NULL,
  PRIMARY KEY (run_id, origin),
  CONSTRAINT origin_leases_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT origin_leases_owner_fk FOREIGN KEY (owner) REFERENCES workers (worker_id),
  CONSTRAINT origin_leases_robots_artifact_fk FOREIGN KEY (robots_artifact_id) REFERENCES artifacts (artifact_id),
  CONSTRAINT origin_leases_admission_next_ticket_check CHECK (admission_next_ticket >= 0),
  CONSTRAINT origin_leases_admission_limit_check CHECK (admission_limit > 0),
  CONSTRAINT origin_admission_run_ticket_bound CHECK (admission_limit IS NULL OR admission_next_ticket < admission_limit)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0009, 0015 (from_version/to_version)
CREATE TABLE IF NOT EXISTS identity_aliases (
  run_id BINARY(16) NOT NULL,
  alias_hash VARBINARY(64) NOT NULL,
  canonical_hash VARBINARY(64) NOT NULL,
  from_version SMALLINT NOT NULL,
  to_version SMALLINT NOT NULL,
  score FLOAT NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (run_id, alias_hash, canonical_hash, from_version, to_version),
  KEY identity_aliases_canonical (run_id, canonical_hash),
  CONSTRAINT identity_aliases_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id),
  CONSTRAINT identity_aliases_score_check CHECK (score >= 0 AND score <= 1),
  CONSTRAINT identity_alias_versions_positive CHECK (from_version > 0 AND to_version > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0011. Cluster-wide runtime settings flipped by `crawlx admin`.
CREATE TABLE IF NOT EXISTS cluster_settings (
  `key` VARCHAR(255) NOT NULL,
  value LONGTEXT NOT NULL,
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_by VARCHAR(255) NOT NULL DEFAULT 'migration',
  PRIMARY KEY (`key`),
  CONSTRAINT cluster_settings_admission CHECK (`key` <> 'scheduler.admission' OR value IN ('open', 'drain', 'frozen'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
INSERT INTO cluster_settings (`key`, value) VALUES ('scheduler.admission', 'open') ON DUPLICATE KEY UPDATE `key` = `key`;

-- from: 0006 run_errors (security-invoker). Interaction rows expose the action id in the
-- canonical dashed lower-case form.
CREATE OR REPLACE SQL SECURITY INVOKER VIEW run_errors AS
  SELECT run_id, 'url' AS plane, CAST(frontier_id AS CHAR) AS ref, COALESCE(error_code, denial_reason) AS code,
         canonical_url AS subject, finished_at AS occurred_at
    FROM url_frontier WHERE status IN ('failed', 'abandoned', 'unreachable', 'policy_blocked', 'robots_blocked')
  UNION ALL
  SELECT run_id, 'interaction',
         LOWER(CONCAT(HEX(SUBSTR(action_id, 1, 4)), '-', HEX(SUBSTR(action_id, 5, 2)), '-', HEX(SUBSTR(action_id, 7, 2)), '-',
                      HEX(SUBSTR(action_id, 9, 2)), '-', HEX(SUBSTR(action_id, 11, 6)))),
         COALESCE(JSON_VALUE(outcome, '$.code'), status), action_kind, finished_at
    FROM actions WHERE status IN ('failed', 'unknown') OR hold = 'denied';

-- from: 0008 trusted_reachable_states (security-invoker): states reachable from a root state
-- through transitions whose action ran on the trusted lane.
CREATE OR REPLACE SQL SECURITY INVOKER VIEW trusted_reachable_states AS
  WITH RECURSIVE reach AS (
    SELECT s.run_id, s.state_id
      FROM states s
     WHERE NOT EXISTS (SELECT 1 FROM transitions t WHERE t.after_state_id = s.state_id)
    UNION
    SELECT t.run_id, t.after_state_id
      FROM transitions t
      JOIN actions a ON a.action_id = t.action_id
      JOIN reach r ON r.state_id = t.before_state_id
     WHERE a.lane = 'trusted_ui' AND t.after_state_id IS NOT NULL
  )
  SELECT run_id, state_id FROM reach;

-- from: 0008 network_epochs_lane_matches_action (the epoch lane equals the lane of its action).
CREATE OR REPLACE TRIGGER network_epochs_lane_ins BEFORE INSERT ON network_epochs
FOR EACH ROW
BEGIN
  DECLARE action_lane VARCHAR(40);
  DECLARE msg VARCHAR(128);
  IF NEW.action_id IS NOT NULL THEN
    SELECT lane INTO action_lane FROM actions WHERE action_id = NEW.action_id;
    IF action_lane IS NULL THEN
      SET msg = CONCAT('network_epochs.action_id ', LOWER(HEX(NEW.action_id)), ' has no actions row');
      SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 1452, MESSAGE_TEXT = msg;
    END IF;
    IF action_lane <> NEW.lane THEN
      SET msg = CONCAT('network_epochs.lane ', NEW.lane, ' differs from actions.lane ', action_lane, ' (action ', LOWER(HEX(NEW.action_id)), ')');
      SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 4025, CONSTRAINT_NAME = 'network_epochs_lane_matches_action', MESSAGE_TEXT = msg;
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER network_epochs_lane_upd BEFORE UPDATE ON network_epochs
FOR EACH ROW
BEGIN
  DECLARE action_lane VARCHAR(40);
  DECLARE msg VARCHAR(128);
  -- from: 0008 network_epochs_lane_immutable
  IF NOT (NEW.lane <=> OLD.lane) THEN
    SET msg = CONCAT('network_epochs.lane is immutable (epoch ', LOWER(HEX(OLD.epoch_id)), ')');
    SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 4025, CONSTRAINT_NAME = 'network_epochs_lane_immutable', MESSAGE_TEXT = msg;
  END IF;
  IF NEW.action_id IS NOT NULL AND NOT (NEW.action_id <=> OLD.action_id) THEN
    SELECT lane INTO action_lane FROM actions WHERE action_id = NEW.action_id;
    IF action_lane IS NULL THEN
      SET msg = CONCAT('network_epochs.action_id ', LOWER(HEX(NEW.action_id)), ' has no actions row');
      SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 1452, MESSAGE_TEXT = msg;
    END IF;
    IF action_lane <> NEW.lane THEN
      SET msg = CONCAT('network_epochs.lane ', NEW.lane, ' differs from actions.lane ', action_lane, ' (action ', LOWER(HEX(NEW.action_id)), ')');
      SIGNAL SQLSTATE '23000' SET MYSQL_ERRNO = 4025, CONSTRAINT_NAME = 'network_epochs_lane_matches_action', MESSAGE_TEXT = msg;
    END IF;
  END IF;
END;

-- new: audit_events is append-only. PostgreSQL withholds UPDATE/DELETE from the request login;
-- here the table itself refuses both for every login.
CREATE OR REPLACE TRIGGER audit_events_append_only_upd BEFORE UPDATE ON audit_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only';
END;

CREATE OR REPLACE TRIGGER audit_events_append_only_del BEFORE DELETE ON audit_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only';
END;

-- from: 0036 enforce_event_custody, structural half. A row carrying metadata_only_audit_id must be
-- a `paused` event whose canonical audit row (same run, actor, event, timestamp, string
-- action/reason) exists; the link can never be removed or reassigned. The privacy-projected
-- payload equality and the auditor-ownership check of the PostgreSQL trigger are not ported
-- (the independent safety auditor is refused on this backend).
CREATE OR REPLACE TRIGGER zz_event_custody_ins BEFORE INSERT ON crawl_events
FOR EACH ROW
BEGIN
  IF NEW.metadata_only_audit_id IS NOT NULL THEN
    IF NEW.type <> 'paused' OR NOT EXISTS (
      SELECT 1 FROM audit_events a
       WHERE a.audit_id = NEW.metadata_only_audit_id AND a.run_id = NEW.run_id
         AND a.actor = 'safety_auditor' AND a.event = 'safety.invariant_violation'
         AND a.occurred_at = NEW.created_at
         AND JSON_TYPE(JSON_EXTRACT(a.subject, '$.action')) = 'STRING'
         AND JSON_TYPE(JSON_EXTRACT(a.subject, '$.reason')) = 'STRING'
    ) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authenticated event custody does not match safety audit';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER zz_event_custody_upd BEFORE UPDATE ON crawl_events
FOR EACH ROW
BEGIN
  IF NEW.metadata_only_audit_id IS NULL THEN
    IF OLD.metadata_only_audit_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authenticated event custody cannot be removed';
    END IF;
  ELSE
    IF NEW.type <> 'paused' OR NOT EXISTS (
      SELECT 1 FROM audit_events a
       WHERE a.audit_id = NEW.metadata_only_audit_id AND a.run_id = NEW.run_id
         AND a.actor = 'safety_auditor' AND a.event = 'safety.invariant_violation'
         AND a.occurred_at = NEW.created_at
         AND JSON_TYPE(JSON_EXTRACT(a.subject, '$.action')) = 'STRING'
         AND JSON_TYPE(JSON_EXTRACT(a.subject, '$.reason')) = 'STRING'
    ) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authenticated event custody does not match safety audit';
    END IF;
    IF NOT (NEW.run_id <=> OLD.run_id) OR NOT (NEW.seq <=> OLD.seq)
       OR NOT (NEW.metadata_only_audit_id <=> OLD.metadata_only_audit_id) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'authenticated event custody cannot be reassigned';
    END IF;
  END IF;
END;
