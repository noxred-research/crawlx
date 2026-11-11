-- Terminal archive custody: durable, secret-free grants binding an archive export to the closed
-- secret epoch of a terminal run and to exact source proofs. Timestamps are microseconds.
CREATE TABLE archive_frozen_grants (
  tenant_id BLOB NOT NULL,
  run_id BLOB NOT NULL,
  export_id BLOB NOT NULL,
  binding BLOB NOT NULL CHECK (length(binding) = 32),
  fence INTEGER NOT NULL CHECK (fence > 0),
  incarnation BLOB NOT NULL CHECK (length(incarnation) = 16 AND incarnation <> zeroblob(16)),
  secret_epoch INTEGER NOT NULL CHECK (secret_epoch > 0 AND secret_epoch < 9007199254740000),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('content', 'sensitive')),
  expires_at INTEGER,
  source_count INTEGER NOT NULL CHECK (source_count BETWEEN 1 AND 20000),
  created_at INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000000 AS INTEGER)),
  CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL),
  PRIMARY KEY (tenant_id, export_id, binding),
  FOREIGN KEY (tenant_id, export_id) REFERENCES archive_exports (tenant_id, export_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs (tenant_id, run_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE archive_frozen_sources (
  tenant_id BLOB NOT NULL,
  export_id BLOB NOT NULL,
  binding BLOB NOT NULL,
  artifact_id BLOB NOT NULL,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('content', 'sensitive')),
  expires_at INTEGER,
  CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL),
  PRIMARY KEY (tenant_id, export_id, binding, artifact_id),
  FOREIGN KEY (tenant_id, export_id, binding) REFERENCES archive_frozen_grants (tenant_id, export_id, binding) ON DELETE CASCADE
) STRICT;
CREATE INDEX archive_frozen_source_artifact ON archive_frozen_sources (tenant_id, artifact_id);

CREATE TABLE archive_frozen_outputs (
  tenant_id BLOB NOT NULL,
  run_id BLOB NOT NULL,
  export_id BLOB NOT NULL,
  binding BLOB NOT NULL,
  artifact_id BLOB NOT NULL,
  kind TEXT NOT NULL CHECK (kind = 'evidence'),
  bucket TEXT NOT NULL,
  object_key TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
  content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
  content_type TEXT NOT NULL CHECK (content_type IN ('application/warc', 'application/wacz+zip', 'application/cdxj')),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('content', 'sensitive')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  incarnation BLOB NOT NULL,
  secret_epoch INTEGER NOT NULL CHECK (secret_epoch > 0),
  ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32),
  ciphertext_size INTEGER NOT NULL CHECK (ciphertext_size > 0),
  CHECK (sensitivity <> 'sensitive' OR expires_at IS NOT NULL),
  PRIMARY KEY (tenant_id, artifact_id),
  FOREIGN KEY (tenant_id, export_id, binding) REFERENCES archive_frozen_grants (tenant_id, export_id, binding) ON DELETE CASCADE
) STRICT;
CREATE INDEX archive_frozen_output_export ON archive_frozen_outputs (tenant_id, export_id, binding);
