-- crawlx-storage (MariaDB) baseline 4 of 5: request orchestration, session bindings and retained
-- profiles, datasets and delivery outbox, adaptive selectors, archive catalog.
--
-- Hand-ported final PostgreSQL schema (levels 0024-0032; the url_frontier columns of 0027 are in
-- the first baseline file). Conventions are listed there. Idempotent.
--
-- Not ported (done by the repository inside the same transaction): the confidentiality
-- projection of zero-retention rows, tenant assignment of frontier rows, expiry of session
-- secrets on run completion or revocation, the archive expiry copy and the archive dependent
-- erasure cascade.

-- from: 0027
CREATE TABLE IF NOT EXISTS frontier_producers (
  run_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  epoch BIGINT NOT NULL DEFAULT 1,
  sealed TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id),
  CONSTRAINT frontier_producers_run_fk FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs (run_id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT frontier_producers_epoch_check CHECK (epoch > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0027
CREATE TABLE IF NOT EXISTS frontier_loader_cursors (
  run_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  source_id VARCHAR(128) NOT NULL,
  `cursor` LONGTEXT NOT NULL CHECK (JSON_VALID(`cursor`)),
  PRIMARY KEY (run_id, source_id),
  CONSTRAINT frontier_loader_cursors_run_fk FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs (run_id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT frontier_loader_cursors_source_id_check CHECK (CHAR_LENGTH(source_id) BETWEEN 1 AND 128)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0027
CREATE TABLE IF NOT EXISTS frontier_batch_receipts (
  run_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  batch_id VARBINARY(32) NOT NULL,
  batch_digest VARBINARY(32) NOT NULL,
  receipt LONGTEXT NOT NULL CHECK (JSON_VALID(receipt)),
  PRIMARY KEY (run_id, batch_id),
  CONSTRAINT frontier_batch_receipts_run_fk FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs (run_id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT frontier_batch_receipts_batch_id_check CHECK (OCTET_LENGTH(batch_id) = 32),
  CONSTRAINT frontier_batch_receipts_batch_digest_check CHECK (OCTET_LENGTH(batch_digest) = 32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0028. Session metadata is subordinate to crawl_sessions' lease fence.
CREATE TABLE IF NOT EXISTS session_bindings (
  session_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  binding LONGTEXT NOT NULL CHECK (JSON_VALID(binding)),
  PRIMARY KEY (session_id),
  KEY session_bindings_run_fk_idx (run_id),
  CONSTRAINT session_bindings_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id) ON DELETE CASCADE,
  CONSTRAINT session_bindings_run_fk FOREIGN KEY (run_id) REFERENCES crawl_runs (run_id) ON DELETE CASCADE,
  CONSTRAINT session_bindings_binding_size CHECK (OCTET_LENGTH(binding) <= 16384)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0028. Profile secret bytes are authenticated ciphertext, separate from artifacts.
CREATE TABLE IF NOT EXISTS browser_profiles (
  tenant_id BINARY(16) NOT NULL,
  principal VARCHAR(255) NOT NULL,
  name VARCHAR(128) NOT NULL,
  generation BIGINT NOT NULL,
  scope LONGTEXT NOT NULL CHECK (JSON_VALID(scope)),
  encrypted_bundle LONGBLOB NOT NULL,
  digest VARBINARY(32) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  owner_run BINARY(16) NOT NULL,
  session_id BINARY(16) NOT NULL,
  lease_fence BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, principal, name),
  KEY browser_profiles_expiry (expires_at),
  KEY browser_profiles_owner_run_idx (owner_run),
  KEY browser_profiles_session_idx (session_id),
  CONSTRAINT browser_profiles_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT browser_profiles_owner_run_fk FOREIGN KEY (owner_run) REFERENCES crawl_runs (run_id) ON DELETE CASCADE,
  CONSTRAINT browser_profiles_session_fk FOREIGN KEY (session_id) REFERENCES crawl_sessions (session_id) ON DELETE CASCADE,
  CONSTRAINT browser_profiles_name_check CHECK (name REGEXP '^[A-Za-z0-9_-]{1,128}$'),
  CONSTRAINT browser_profiles_generation_check CHECK (generation > 0),
  CONSTRAINT browser_profiles_bundle_size CHECK (OCTET_LENGTH(encrypted_bundle) <= 33554432),
  CONSTRAINT browser_profiles_digest_check CHECK (OCTET_LENGTH(digest) = 32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029. Accepted metadata and delivery receipts.
CREATE TABLE IF NOT EXISTS datasets (
  dataset_id BIGINT NOT NULL AUTO_INCREMENT,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  name VARCHAR(128) NOT NULL,
  next_ordinal BIGINT NOT NULL DEFAULT 1,
  item_count BIGINT NOT NULL DEFAULT 0,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (dataset_id),
  UNIQUE KEY datasets_tenant_id_run_id_name_key (tenant_id, run_id, name),
  UNIQUE KEY datasets_tenant_id_run_id_dataset_id_key (tenant_id, run_id, dataset_id),
  CONSTRAINT datasets_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT datasets_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT datasets_name_check CHECK (CHAR_LENGTH(name) BETWEEN 1 AND 128),
  CONSTRAINT datasets_next_ordinal_check CHECK (next_ordinal > 0),
  CONSTRAINT datasets_item_count_check CHECK (item_count >= 0),
  CONSTRAINT datasets_size_bytes_check CHECK (size_bytes >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029
CREATE TABLE IF NOT EXISTS dataset_items (
  item_id BIGINT NOT NULL AUTO_INCREMENT,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  dataset_id BIGINT NOT NULL,
  ordinal BIGINT NOT NULL,
  source_request_id BIGINT NULL,
  source_action_id BINARY(16) NULL,
  identity_key VARBINARY(32) NOT NULL,
  payload LONGTEXT NULL CHECK (JSON_VALID(payload)),
  volatile_page BIGINT NULL,
  size_bytes BIGINT NOT NULL,
  expires_at DATETIME(6) NULL,
  PRIMARY KEY (item_id),
  UNIQUE KEY dataset_items_tenant_id_dataset_id_ordinal_key (tenant_id, dataset_id, ordinal),
  UNIQUE KEY dataset_items_tenant_id_dataset_id_source_request_id_identi_key (tenant_id, dataset_id, source_request_id, identity_key),
  UNIQUE KEY dataset_items_tenant_id_dataset_id_source_action_id_identit_key (tenant_id, dataset_id, source_action_id, identity_key),
  KEY dataset_items_keyset (tenant_id, run_id, dataset_id, ordinal),
  KEY dataset_items_action_fk_idx (run_id, source_action_id),
  KEY dataset_items_request_fk_idx (tenant_id, run_id, source_request_id),
  CONSTRAINT dataset_items_action_fk FOREIGN KEY (run_id, source_action_id) REFERENCES actions (run_id, action_id) ON DELETE CASCADE,
  CONSTRAINT dataset_items_dataset_fk FOREIGN KEY (tenant_id, run_id, dataset_id) REFERENCES datasets (tenant_id, run_id, dataset_id) ON DELETE CASCADE,
  CONSTRAINT dataset_items_request_fk FOREIGN KEY (tenant_id, run_id, source_request_id) REFERENCES url_frontier (tenant_id, run_id, frontier_id) ON DELETE CASCADE,
  CONSTRAINT dataset_items_ordinal_check CHECK (ordinal > 0),
  CONSTRAINT dataset_items_identity_key_check CHECK (OCTET_LENGTH(identity_key) = 32),
  CONSTRAINT dataset_items_size_bytes_check CHECK (size_bytes >= 0),
  CONSTRAINT dataset_items_one_source CHECK ((source_request_id IS NULL) <> (source_action_id IS NULL)),
  CONSTRAINT dataset_items_payload_xor_volatile CHECK ((payload IS NULL) = (volatile_page IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029. Key-value store; `store` is bounded to the 128 characters the drop table allows and
-- `key` to 512 so the primary key stays under the InnoDB key-length limit.
CREATE TABLE IF NOT EXISTS dataset_kv (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  store VARCHAR(128) NOT NULL,
  `key` VARCHAR(512) NOT NULL,
  version BIGINT NOT NULL,
  payload LONGTEXT NULL CHECK (JSON_VALID(payload)),
  volatile_page BIGINT NULL,
  size_bytes BIGINT NOT NULL,
  expires_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, run_id, store, `key`),
  CONSTRAINT dataset_kv_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT dataset_kv_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT dataset_kv_version_check CHECK (version > 0),
  CONSTRAINT dataset_kv_size_bytes_check CHECK (size_bytes >= 0),
  CONSTRAINT dataset_kv_payload_xor_volatile CHECK ((payload IS NULL) = (volatile_page IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029
CREATE TABLE IF NOT EXISTS dataset_delivery_outbox (
  delivery_id BIGINT NOT NULL AUTO_INCREMENT,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  source_request_id BIGINT NULL,
  source_action_id BINARY(16) NULL,
  feed VARCHAR(255) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  payload LONGTEXT NULL CHECK (JSON_VALID(payload)),
  volatile_page BIGINT NULL,
  content_page BIGINT NULL,
  erased_at DATETIME(6) NULL,
  state VARCHAR(40) NOT NULL DEFAULT 'pending',
  attempts INT NOT NULL DEFAULT 0,
  fence BIGINT NOT NULL DEFAULT 0,
  lease_owner BINARY(16) NULL,
  lease_expires_at DATETIME(6) NULL,
  not_before DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (delivery_id),
  UNIQUE KEY dataset_delivery_outbox_tenant_id_run_id_feed_idempotency_k_key (tenant_id, run_id, feed, idempotency_key),
  -- partial index WHERE state IN (pending, leased): state trails so the scan stays ordered
  KEY dataset_delivery_ready (tenant_id, run_id, not_before, delivery_id, state),
  KEY dataset_delivery_outbox_action_fk_idx (run_id, source_action_id),
  KEY dataset_delivery_outbox_request_fk_idx (tenant_id, run_id, source_request_id),
  CONSTRAINT dataset_delivery_outbox_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT dataset_delivery_outbox_action_fk FOREIGN KEY (run_id, source_action_id) REFERENCES actions (run_id, action_id) ON DELETE CASCADE,
  CONSTRAINT dataset_delivery_outbox_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT dataset_delivery_outbox_request_fk FOREIGN KEY (tenant_id, run_id, source_request_id) REFERENCES url_frontier (tenant_id, run_id, frontier_id) ON DELETE CASCADE,
  CONSTRAINT dataset_delivery_outbox_state_check CHECK (state IN ('pending', 'leased', 'delivered', 'content_expired')),
  CONSTRAINT dataset_delivery_outbox_attempts_check CHECK (attempts >= 0),
  CONSTRAINT dataset_delivery_outbox_fence_check CHECK (fence >= 0),
  CONSTRAINT dataset_delivery_outbox_one_source CHECK ((source_request_id IS NULL) <> (source_action_id IS NULL)),
  CONSTRAINT dataset_delivery_outbox_payload_xor_volatile CHECK ((payload IS NULL) = (volatile_page IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029
CREATE TABLE IF NOT EXISTS dataset_kv_drops (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  store VARCHAR(128) NOT NULL,
  PRIMARY KEY (tenant_id, run_id, store),
  CONSTRAINT dataset_kv_drops_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT dataset_kv_drops_store_check CHECK (store REGEXP '^[A-Za-z0-9_.-]{1,128}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0030. Scoped extraction descriptors; no action locator or credential payload.
CREATE TABLE IF NOT EXISTS adaptive_selectors (
  tenant_id BINARY(16) NOT NULL,
  scope_key VARCHAR(64) NOT NULL,
  run_id BINARY(16) NOT NULL,
  payload LONGTEXT NULL CHECK (JSON_VALID(payload)),
  volatile_page BIGINT NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, scope_key),
  KEY adaptive_selectors_expiry (expires_at),
  KEY adaptive_selectors_run_fk_idx (tenant_id, run_id),
  CONSTRAINT adaptive_selectors_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id),
  CONSTRAINT adaptive_selectors_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT adaptive_selectors_scope_key_check CHECK (CHAR_LENGTH(scope_key) = 64),
  CONSTRAINT adaptive_selectors_payload_xor_volatile CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
  CONSTRAINT adaptive_selectors_volatile_page_check CHECK (volatile_page IS NULL OR volatile_page < 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0032. Archive metadata is content, never structural telemetry of a zero-retention run.
CREATE TABLE IF NOT EXISTS archive_exports (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  state VARCHAR(40) NOT NULL,
  fence BIGINT NOT NULL DEFAULT 0,
  lease_until DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
  PRIMARY KEY (tenant_id, export_id),
  UNIQUE KEY archive_exports_tenant_id_run_id_key (tenant_id, run_id),
  KEY archive_recovery (state, lease_until, export_id),
  CONSTRAINT archive_exports_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT archive_exports_state_check CHECK (state IN ('recording', 'published', 'failed', 'deleted')),
  CONSTRAINT archive_exports_fence_check CHECK (fence >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0032
CREATE TABLE IF NOT EXISTS archive_records (
  tenant_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  ordinal BIGINT NOT NULL,
  artifact_id BINARY(16) NOT NULL,
  member_offset BIGINT NOT NULL,
  member_length BIGINT NOT NULL,
  payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
  PRIMARY KEY (tenant_id, export_id, ordinal),
  CONSTRAINT archive_records_export_fk FOREIGN KEY (tenant_id, export_id) REFERENCES archive_exports (tenant_id, export_id) ON DELETE CASCADE,
  CONSTRAINT archive_records_ordinal_check CHECK (ordinal >= 0),
  CONSTRAINT archive_records_member_offset_check CHECK (member_offset >= 0),
  CONSTRAINT archive_records_member_length_check CHECK (member_length > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0032
CREATE TABLE IF NOT EXISTS archive_dependencies (
  tenant_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  ordinal BIGINT NOT NULL,
  source_export BINARY(16) NOT NULL,
  source_ordinal BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, export_id, ordinal),
  KEY archive_dependency_sources (tenant_id, source_export, source_ordinal),
  CONSTRAINT archive_dependencies_record_fk FOREIGN KEY (tenant_id, export_id, ordinal) REFERENCES archive_records (tenant_id, export_id, ordinal) ON DELETE CASCADE,
  CONSTRAINT archive_dependencies_source_fk FOREIGN KEY (tenant_id, source_export, source_ordinal) REFERENCES archive_records (tenant_id, export_id, ordinal) ON DELETE CASCADE,
  CONSTRAINT archive_dependencies_distinct_export CHECK (export_id <> source_export)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0032
CREATE TABLE IF NOT EXISTS archive_history (
  tenant_id BINARY(16) NOT NULL,
  identity_key VARBINARY(32) NOT NULL,
  export_id BINARY(16) NOT NULL,
  ordinal BIGINT NOT NULL,
  captured_at DATETIME(6) NOT NULL,
  payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
  PRIMARY KEY (tenant_id, identity_key, export_id, ordinal),
  KEY archive_history_eligible (tenant_id, identity_key, captured_at DESC),
  KEY archive_history_record_fk_idx (tenant_id, export_id, ordinal),
  CONSTRAINT archive_history_record_fk FOREIGN KEY (tenant_id, export_id, ordinal) REFERENCES archive_records (tenant_id, export_id, ordinal) ON DELETE CASCADE,
  CONSTRAINT archive_history_identity_key_check CHECK (OCTET_LENGTH(identity_key) = 32)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0029 enforce_dataset_zdr. Direct SQL cannot smuggle content into a zero-retention run's
-- dataset rows.
CREATE OR REPLACE TRIGGER dataset_items_zdr_ins BEFORE INSERT ON dataset_items
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER dataset_items_zdr_upd BEFORE UPDATE ON dataset_items
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER dataset_kv_zdr_ins BEFORE INSERT ON dataset_kv
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER dataset_kv_zdr_upd BEFORE UPDATE ON dataset_kv
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER dataset_outbox_zdr_ins BEFORE INSERT ON dataset_delivery_outbox
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

CREATE OR REPLACE TRIGGER dataset_outbox_zdr_upd BEFORE UPDATE ON dataset_delivery_outbox
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
END;

-- from: 0030 enforce_adaptive_selector_retention. The source run is read under a shared row lock.
CREATE OR REPLACE TRIGGER adaptive_selector_retention_ins BEFORE INSERT ON adaptive_selectors
FOR EACH ROW
BEGIN
  DECLARE src_purge DATETIME(6);
  DECLARE src_mode VARCHAR(40);
  DECLARE src_created DATETIME(6);
  DECLARE src_days INT;
  SELECT purge_requested_at, retention_mode, created_at, retention_days
    INTO src_purge, src_mode, src_created, src_days
    FROM crawl_runs WHERE run_id = NEW.run_id AND tenant_id = NEW.tenant_id LOCK IN SHARE MODE;
  IF src_mode IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector source run does not exist';
  END IF;
  IF src_purge IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector source run is purging';
  END IF;
  IF src_mode = 'zdr' THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at > DATE_ADD(src_created, INTERVAL 1 HOUR) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr selectors require shared volatile content and fixed expiry';
    END IF;
  ELSEIF NEW.volatile_page IS NOT NULL OR NEW.expires_at > DATE_ADD(src_created, INTERVAL src_days DAY) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector expiry exceeds source retention';
  END IF;
END;

CREATE OR REPLACE TRIGGER adaptive_selector_retention_upd BEFORE UPDATE ON adaptive_selectors
FOR EACH ROW
BEGIN
  DECLARE src_purge DATETIME(6);
  DECLARE src_mode VARCHAR(40);
  DECLARE src_created DATETIME(6);
  DECLARE src_days INT;
  SELECT purge_requested_at, retention_mode, created_at, retention_days
    INTO src_purge, src_mode, src_created, src_days
    FROM crawl_runs WHERE run_id = NEW.run_id AND tenant_id = NEW.tenant_id LOCK IN SHARE MODE;
  IF src_mode IS NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector source run does not exist';
  END IF;
  IF src_purge IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector source run is purging';
  END IF;
  IF src_mode = 'zdr' THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at > DATE_ADD(src_created, INTERVAL 1 HOUR) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr selectors require shared volatile content and fixed expiry';
    END IF;
  ELSEIF NEW.volatile_page IS NOT NULL OR NEW.expires_at > DATE_ADD(src_created, INTERVAL src_days DAY) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector expiry exceeds source retention';
  END IF;
  IF OLD.run_id = NEW.run_id AND NEW.expires_at > OLD.expires_at THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'selector updates cannot renew fixed expiry';
  END IF;
END;

-- from: 0032 enforce_archive_retention, validation half. The expiry copy from the source run is
-- done by the repository.
CREATE OR REPLACE TRIGGER archive_retention_ins BEFORE INSERT ON archive_exports
FOR EACH ROW
BEGIN
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = NEW.run_id
      AND r.tenant_id = NEW.tenant_id AND r.retention_mode <> 'zdr') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'durable archive requires a retained tenant-owned source';
  END IF;
END;

CREATE OR REPLACE TRIGGER archive_retention_upd BEFORE UPDATE ON archive_exports
FOR EACH ROW
BEGIN
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = NEW.run_id
      AND r.tenant_id = NEW.tenant_id AND r.retention_mode <> 'zdr') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'durable archive requires a retained tenant-owned source';
  END IF;
END;
