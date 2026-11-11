-- crawlx-storage (MariaDB) baseline 5 of 5: page captures, run secret authority, artifact key
-- custody, custody producers, bootstrap producers, renewal records. Last baseline file: the
-- schema is at the level of PostgreSQL migration 0046 after it. Later schema changes ship as
-- 0047 and up in lock-step with the PostgreSQL migrations.
--
-- Conventions are listed in the first baseline file. Idempotent.
--
-- Custody locking. PostgreSQL takes a transaction-scoped advisory lock keyed by
-- 'crawlx/secret-authority/v1:<tenant>:<run>' before any catalog mutation. Here the repository
-- takes the matching `crawlx_locks` row (INSERT .. ON DUPLICATE KEY UPDATE, then SELECT .. FOR UPDATE / LOCK IN SHARE
-- MODE) before it touches artifacts, artifact_key_custody or run_secret_authority. This also
-- closes the gap-lock hole of locking a row that does not exist yet. The triggers below are the
-- final-invariant validators.

-- from: 0039. Immutable descriptors of successful fenced request results.
CREATE TABLE IF NOT EXISTS page_captures (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  frontier_id BIGINT NOT NULL,
  fence BIGINT NOT NULL,
  state_version BIGINT NOT NULL,
  expires_at DATETIME(6) NULL,
  payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
  PRIMARY KEY (run_id, frontier_id),
  -- partial index WHERE expires_at IS NOT NULL
  KEY page_captures_expiry (expires_at),
  KEY page_captures_frontier_idx (frontier_id),
  CONSTRAINT page_captures_frontier_fk FOREIGN KEY (frontier_id) REFERENCES url_frontier (frontier_id) ON DELETE CASCADE,
  CONSTRAINT page_captures_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0040, 0042 (renewal columns). Secret bytes exist only in the volatile secret registry,
-- never here; this table holds commitments and the fence state.
CREATE TABLE IF NOT EXISTS run_secret_authority (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  incarnation BINARY(16) NOT NULL,
  epoch BIGINT NOT NULL,
  pending_operation BINARY(16) NULL,
  last_operation BINARY(16) NULL,
  -- A random salt exists only in the registry: this commitment cannot be used for offline
  -- secret guesses using the durable database alone.
  commitment VARBINARY(32) NULL,
  pending_commitment VARBINARY(32) NULL,
  pending_value_commitment VARBINARY(32) NULL,
  last_value_commitment VARBINARY(32) NULL,
  expires_at DATETIME(6) NOT NULL,
  sealed_at DATETIME(6) NULL,
  pending_renewal_operation BINARY(16) NULL,
  pending_renewal_deadline DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, run_id),
  CONSTRAINT run_secret_authority_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT run_secret_authority_epoch_check CHECK (epoch >= 0),
  CONSTRAINT run_secret_authority_commitment_check CHECK (commitment IS NULL OR OCTET_LENGTH(commitment) = 32),
  CONSTRAINT run_secret_authority_pending_commitment_check CHECK (pending_commitment IS NULL OR OCTET_LENGTH(pending_commitment) = 32),
  CONSTRAINT run_secret_authority_pending_value_commitment_check CHECK (pending_value_commitment IS NULL OR OCTET_LENGTH(pending_value_commitment) = 32),
  CONSTRAINT run_secret_authority_last_value_commitment_check CHECK (last_value_commitment IS NULL OR OCTET_LENGTH(last_value_commitment) = 32),
  CONSTRAINT run_secret_authority_sealed_check CHECK (sealed_at IS NULL OR (epoch > 0 AND pending_operation IS NULL AND pending_commitment IS NULL AND pending_value_commitment IS NULL AND commitment IS NOT NULL)),
  CONSTRAINT secret_authority_pending_renewal CHECK (
    (pending_renewal_operation IS NULL AND pending_renewal_deadline IS NULL)
    OR (pending_renewal_operation IS NOT NULL AND pending_renewal_deadline IS NOT NULL
        AND pending_operation IS NULL AND pending_commitment IS NULL AND pending_value_commitment IS NULL
        AND sealed_at IS NULL AND epoch > 0 AND commitment IS NOT NULL
        AND pending_renewal_deadline > expires_at
        AND pending_renewal_deadline <= DATE_ADD(expires_at, INTERVAL 24 HOUR)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0040. One atomic catalog commit binds ciphertext identity, complete secret epoch and the
-- wrapped key. No plaintext key or registry value enters the database.
CREATE TABLE IF NOT EXISTS artifact_key_custody (
  artifact_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  incarnation BINARY(16) NOT NULL,
  secret_epoch BIGINT NOT NULL,
  object_key VARCHAR(512) NOT NULL,
  plaintext_digest VARBINARY(32) NOT NULL,
  plaintext_size BIGINT NOT NULL,
  ciphertext_digest VARBINARY(32) NOT NULL,
  ciphertext_size BIGINT NOT NULL,
  envelope LONGTEXT NOT NULL CHECK (JSON_VALID(envelope)),
  artifact_payload LONGTEXT NOT NULL CHECK (JSON_VALID(artifact_payload)),
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (artifact_id),
  UNIQUE KEY artifact_key_custody_tenant_id_run_id_object_key_key (tenant_id, run_id, object_key),
  CONSTRAINT artifact_key_custody_artifact_fk FOREIGN KEY (artifact_id) REFERENCES artifacts (artifact_id) ON DELETE CASCADE,
  CONSTRAINT artifact_key_custody_authority_fk FOREIGN KEY (tenant_id, run_id) REFERENCES run_secret_authority (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT artifact_key_custody_secret_epoch_check CHECK (secret_epoch > 0),
  CONSTRAINT artifact_key_custody_plaintext_digest_check CHECK (OCTET_LENGTH(plaintext_digest) = 32),
  CONSTRAINT artifact_key_custody_plaintext_size_check CHECK (plaintext_size >= 0),
  CONSTRAINT artifact_key_custody_ciphertext_digest_check CHECK (OCTET_LENGTH(ciphertext_digest) = 32),
  CONSTRAINT artifact_key_custody_ciphertext_size_check CHECK (ciphertext_size > 0),
  CONSTRAINT artifact_key_custody_envelope_size CHECK (OCTET_LENGTH(envelope) <= 524288)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0040. OPEN survives process death and unknown outcomes. There is deliberately no expiry
-- column: TTL is not evidence that a producer or plaintext queue is dead.
CREATE TABLE IF NOT EXISTS run_artifact_exposures (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  operation BINARY(16) NOT NULL,
  artifact_id BINARY(16) NOT NULL,
  -- Ciphertext digest for retained content; a registry-keyed commitment for zero-retention
  -- runs, never an offline-guessable plaintext digest.
  artifact_binding VARBINARY(32) NOT NULL,
  incarnation BINARY(16) NOT NULL,
  secret_epoch BIGINT NOT NULL,
  -- completion tombstone until run purge
  closed_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, run_id, operation),
  CONSTRAINT run_artifact_exposures_authority_fk FOREIGN KEY (tenant_id, run_id) REFERENCES run_secret_authority (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT run_artifact_exposures_binding_check CHECK (OCTET_LENGTH(artifact_binding) = 32),
  CONSTRAINT run_artifact_exposures_secret_epoch_check CHECK (secret_epoch > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0040. `fence` is an identity column outside the key: AUTO_INCREMENT on a unique key
-- (it starts at 1, so the PostgreSQL `fence > 0` check holds; MariaDB refuses a CHECK on it).
CREATE TABLE IF NOT EXISTS run_custody_producers (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  producer_id BINARY(16) NOT NULL,
  owner BINARY(16) NOT NULL,
  fence BIGINT NOT NULL AUTO_INCREMENT,
  api_key_id BINARY(16) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, run_id, producer_id),
  UNIQUE KEY run_custody_producers_fence (fence),
  KEY run_custody_producers_api_key_idx (api_key_id),
  CONSTRAINT run_custody_producers_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT run_custody_producers_api_key_fk FOREIGN KEY (api_key_id) REFERENCES api_keys (key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0041. Fence sequence for bootstrap ownership.
CREATE SEQUENCE IF NOT EXISTS run_bootstrap_producer_fence START WITH 1 INCREMENT BY 1 NOCYCLE;

-- from: 0041. Dedicated bootstrap ownership, never an origin lease, heartbeat or API identity.
CREATE TABLE IF NOT EXISTS run_bootstrap_producers (
  producer_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  owner BINARY(16) NOT NULL,
  fence BIGINT NOT NULL DEFAULT NEXTVAL(run_bootstrap_producer_fence),
  state VARCHAR(40) NOT NULL,
  leased_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  -- Non-secret, monotonically increasing application cursor.
  progress BIGINT NOT NULL DEFAULT 0,
  completed_at DATETIME(6) NULL,
  PRIMARY KEY (producer_id),
  UNIQUE KEY run_bootstrap_producers_tenant_id_run_id_key (tenant_id, run_id),
  KEY run_bootstrap_producers_owner_idx (owner),
  CONSTRAINT run_bootstrap_producers_owner_fk FOREIGN KEY (owner) REFERENCES workers (worker_id),
  CONSTRAINT run_bootstrap_producers_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT run_bootstrap_producers_fence_check CHECK (fence > 0),
  CONSTRAINT run_bootstrap_producers_state_check CHECK (state IN ('running', 'released', 'completed')),
  CONSTRAINT run_bootstrap_producers_progress_check CHECK (progress >= 0),
  CONSTRAINT run_bootstrap_producers_completed_check CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
  CONSTRAINT run_bootstrap_producers_lease_window CHECK (state <> 'running' OR (expires_at > leased_at AND expires_at <= DATE_ADD(leased_at, INTERVAL 5 MINUTE)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0042. Request tombstones are kept until run purge.
CREATE TABLE IF NOT EXISTS run_secret_authority_renewals (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  operation BINARY(16) NOT NULL,
  incarnation BINARY(16) NOT NULL,
  secret_epoch BIGINT NOT NULL,
  previous_deadline DATETIME(6) NOT NULL,
  deadline DATETIME(6) NOT NULL,
  completed_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, run_id, operation),
  CONSTRAINT run_secret_authority_renewals_authority_fk FOREIGN KEY (tenant_id, run_id) REFERENCES run_secret_authority (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT run_secret_authority_renewals_secret_epoch_check CHECK (secret_epoch > 0),
  CONSTRAINT run_secret_authority_renewals_deadline_check CHECK (deadline > previous_deadline AND deadline <= DATE_ADD(previous_deadline, INTERVAL 24 HOUR))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- from: 0039 enforce_page_capture, validation half. Committed captures are immutable; a new one
-- needs a live retained request fence. The expiry copy from the run is done by the repository.
CREATE OR REPLACE TRIGGER page_capture_custody_ins BEFORE INSERT ON page_captures
FOR EACH ROW
BEGIN
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r JOIN url_frontier f ON f.run_id = r.run_id
      WHERE r.run_id = NEW.run_id AND r.tenant_id = NEW.tenant_id
        AND r.retention_mode <> 'zdr' AND (r.expires_at IS NULL OR r.expires_at > SYSDATE(6))
        AND f.frontier_id = NEW.frontier_id AND f.status = 'leased'
        AND f.fencing_token = NEW.fence AND f.state_version = NEW.state_version
        AND f.lease_expires_at > SYSDATE(6)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'page capture requires a live retained request fence';
  END IF;
END;

CREATE OR REPLACE TRIGGER page_capture_custody_upd BEFORE UPDATE ON page_captures
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'committed page captures are immutable';
END;

-- from: 0040 retain_secret_authority_seal
CREATE OR REPLACE TRIGGER secret_authority_seal BEFORE UPDATE ON run_secret_authority
FOR EACH ROW
BEGIN
  IF OLD.sealed_at IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'artifact secret authority seal is immutable';
  END IF;
END;

-- from: 0040/0044 fence_sealed_artifact_catalog, validation half, artifacts table. A sealed run
-- can only lose content through retention: no new artifact, no changed catalog identity, no
-- revived or extended retention. The authority row is read under a shared lock.
CREATE OR REPLACE TRIGGER artifact_catalog_secret_fence_ins BEFORE INSERT ON artifacts
FOR EACH ROW
BEGIN
  DECLARE sealed DATETIME(6);
  SELECT sealed_at INTO sealed FROM run_secret_authority
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id LOCK IN SHARE MODE;
  IF sealed IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'artifact secret authority is permanently sealed';
  END IF;
END;

CREATE OR REPLACE TRIGGER artifact_catalog_secret_fence_upd BEFORE UPDATE ON artifacts
FOR EACH ROW
BEGIN
  DECLARE sealed DATETIME(6);
  DECLARE previous_seal DATETIME(6);
  SELECT sealed_at INTO sealed FROM run_secret_authority
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id LOCK IN SHARE MODE;
  SELECT sealed_at INTO previous_seal FROM run_secret_authority
    WHERE tenant_id = OLD.tenant_id AND run_id = OLD.run_id LOCK IN SHARE MODE;
  SET sealed = COALESCE(sealed, previous_seal);
  IF sealed IS NOT NULL THEN
    IF NOT (NEW.artifact_id <=> OLD.artifact_id) OR NOT (NEW.tenant_id <=> OLD.tenant_id)
       OR NOT (NEW.run_id <=> OLD.run_id) OR NOT (NEW.kind <=> OLD.kind)
       OR NOT (NEW.bucket <=> OLD.bucket) OR NOT (NEW.object_key <=> OLD.object_key)
       OR NOT (NEW.size_bytes <=> OLD.size_bytes) OR NOT (NEW.content_digest <=> OLD.content_digest)
       OR NOT (NEW.content_type <=> OLD.content_type) OR NOT (NEW.sensitivity <=> OLD.sensitivity)
       OR NOT (NEW.created_at <=> OLD.created_at) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'sealed artifact catalog identity is immutable';
    END IF;
    IF (OLD.deleted_at IS NOT NULL AND NOT (NEW.deleted_at <=> OLD.deleted_at))
       OR (OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at)) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'sealed artifact retention cannot be extended or revived';
    END IF;
  END IF;
END;

-- same fence, artifact_key_custody table: once the authority is sealed no key row can change.
CREATE OR REPLACE TRIGGER artifact_key_secret_fence_ins BEFORE INSERT ON artifact_key_custody
FOR EACH ROW
BEGIN
  DECLARE sealed DATETIME(6);
  SELECT sealed_at INTO sealed FROM run_secret_authority
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id LOCK IN SHARE MODE;
  IF sealed IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'artifact secret authority is permanently sealed';
  END IF;
END;

CREATE OR REPLACE TRIGGER artifact_key_secret_fence_upd BEFORE UPDATE ON artifact_key_custody
FOR EACH ROW
BEGIN
  DECLARE sealed DATETIME(6);
  DECLARE previous_seal DATETIME(6);
  SELECT sealed_at INTO sealed FROM run_secret_authority
    WHERE tenant_id = NEW.tenant_id AND run_id = NEW.run_id LOCK IN SHARE MODE;
  SELECT sealed_at INTO previous_seal FROM run_secret_authority
    WHERE tenant_id = OLD.tenant_id AND run_id = OLD.run_id LOCK IN SHARE MODE;
  SET sealed = COALESCE(sealed, previous_seal);
  IF sealed IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'artifact secret authority is permanently sealed';
  END IF;
END;

-- from: 0041 preserve_bootstrap_progress. Identity, progress and fence never regress; completion
-- is permanent until run purge; a new owner or a restart needs a newer fence.
CREATE OR REPLACE TRIGGER preserve_bootstrap_progress BEFORE UPDATE ON run_bootstrap_producers
FOR EACH ROW
BEGIN
  IF NOT (NEW.producer_id <=> OLD.producer_id)
     OR NOT (NEW.tenant_id <=> OLD.tenant_id)
     OR NOT (NEW.run_id <=> OLD.run_id)
     OR NEW.progress < OLD.progress
     OR NEW.fence < OLD.fence THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bootstrap identity, progress and fence cannot regress';
  END IF;
  IF OLD.state = 'completed' AND (
       NOT (NEW.owner <=> OLD.owner) OR NOT (NEW.fence <=> OLD.fence)
       OR NOT (NEW.state <=> OLD.state) OR NOT (NEW.leased_at <=> OLD.leased_at)
       OR NOT (NEW.expires_at <=> OLD.expires_at) OR NOT (NEW.progress <=> OLD.progress)
       OR NOT (NEW.completed_at <=> OLD.completed_at)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bootstrap completion is permanent until run purge';
  END IF;
  IF (NOT (NEW.owner <=> OLD.owner) OR (NEW.state = 'running' AND OLD.state <> 'running'))
     AND NEW.fence <= OLD.fence THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'bootstrap acquisition requires a newer fence';
  END IF;
END;
