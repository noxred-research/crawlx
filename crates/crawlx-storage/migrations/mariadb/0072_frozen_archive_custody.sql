-- new: terminal archive custody. Durable, secret-free grants binding an archive export to the
-- closed secret epoch of a terminal run and to exact source proofs. Idempotent.
CREATE TABLE IF NOT EXISTS archive_frozen_grants (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  binding BINARY(32) NOT NULL,
  fence BIGINT NOT NULL,
  incarnation BINARY(16) NOT NULL,
  secret_epoch BIGINT NOT NULL,
  sensitivity VARCHAR(16) NOT NULL,
  expires_at DATETIME(6) NULL,
  source_count INT NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (tenant_id, export_id, binding),
  KEY archive_frozen_grant_run_idx (tenant_id, run_id),
  CONSTRAINT archive_frozen_grants_export_fk FOREIGN KEY (tenant_id, export_id) REFERENCES archive_exports (tenant_id, export_id) ON DELETE CASCADE,
  CONSTRAINT archive_frozen_grants_run_fk FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE,
  CONSTRAINT archive_frozen_grants_fence_check CHECK (fence > 0),
  CONSTRAINT archive_frozen_grants_incarnation_check CHECK (incarnation <> UNHEX(REPEAT('00',16))),
  CONSTRAINT archive_frozen_grants_epoch_check CHECK (secret_epoch > 0 AND secret_epoch < 9007199254740000),
  CONSTRAINT archive_frozen_grants_class_check CHECK (sensitivity IN ('content', 'sensitive')),
  CONSTRAINT archive_frozen_grants_sensitive_deadline CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL),
  CONSTRAINT archive_frozen_grants_count_check CHECK (source_count BETWEEN 1 AND 20000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- new: exact source proofs; no foreign key to artifacts so a changed source fails publication closed.
CREATE TABLE IF NOT EXISTS archive_frozen_sources (
  tenant_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  binding BINARY(32) NOT NULL,
  artifact_id BINARY(16) NOT NULL,
  digest VARBINARY(32) NOT NULL,
  sensitivity VARCHAR(16) NOT NULL,
  expires_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, export_id, binding, artifact_id),
  KEY archive_frozen_source_artifact (tenant_id, artifact_id),
  CONSTRAINT archive_frozen_sources_grant_fk FOREIGN KEY (tenant_id, export_id, binding) REFERENCES archive_frozen_grants (tenant_id, export_id, binding) ON DELETE CASCADE,
  CONSTRAINT archive_frozen_sources_digest_check CHECK (OCTET_LENGTH(digest) = 32),
  CONSTRAINT archive_frozen_sources_class_check CHECK (sensitivity IN ('content', 'sensitive')),
  CONSTRAINT archive_frozen_sources_sensitive_deadline CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

-- new: exact output identity validated against a live grant; the only row that may enter a sealed catalog.
CREATE TABLE IF NOT EXISTS archive_frozen_outputs (
  tenant_id BINARY(16) NOT NULL,
  run_id BINARY(16) NOT NULL,
  export_id BINARY(16) NOT NULL,
  binding BINARY(32) NOT NULL,
  artifact_id BINARY(16) NOT NULL,
  kind VARCHAR(40) NOT NULL,
  bucket VARCHAR(255) NOT NULL,
  object_key VARCHAR(512) NOT NULL,
  size_bytes BIGINT NOT NULL,
  content_digest VARBINARY(64) NOT NULL,
  content_type VARCHAR(255) NOT NULL,
  sensitivity VARCHAR(16) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  incarnation BINARY(16) NOT NULL,
  secret_epoch BIGINT NOT NULL,
  ciphertext_digest VARBINARY(32) NOT NULL,
  ciphertext_size BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, artifact_id),
  KEY archive_frozen_output_export (tenant_id, export_id, binding),
  CONSTRAINT archive_frozen_outputs_grant_fk FOREIGN KEY (tenant_id, export_id, binding) REFERENCES archive_frozen_grants (tenant_id, export_id, binding) ON DELETE CASCADE,
  CONSTRAINT archive_frozen_outputs_kind_check CHECK (kind = 'evidence'),
  CONSTRAINT archive_frozen_outputs_size_check CHECK (size_bytes >= 0),
  CONSTRAINT archive_frozen_outputs_digest_check CHECK (OCTET_LENGTH(content_digest) = 32),
  CONSTRAINT archive_frozen_outputs_type_check CHECK (content_type IN ('application/warc', 'application/wacz+zip', 'application/cdxj')),
  CONSTRAINT archive_frozen_outputs_class_check CHECK (sensitivity IN ('content', 'sensitive')),
  CONSTRAINT archive_frozen_outputs_sensitive_deadline CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL),
  CONSTRAINT archive_frozen_outputs_epoch_check CHECK (secret_epoch > 0),
  CONSTRAINT archive_frozen_outputs_cipher_digest_check CHECK (OCTET_LENGTH(ciphertext_digest) = 32),
  CONSTRAINT archive_frozen_outputs_cipher_size_check CHECK (ciphertext_size > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
