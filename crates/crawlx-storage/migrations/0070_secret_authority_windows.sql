-- Redis retention is frozen; renewable use authority belongs only to the database.
ALTER TABLE run_secret_authority ADD COLUMN retention_ceiling timestamptz;
ALTER TABLE run_secret_authority ADD COLUMN use_window_ms bigint;
UPDATE run_secret_authority SET retention_ceiling=expires_at WHERE retention_ceiling IS NULL AND sealed_at IS NULL;
ALTER TABLE run_secret_authority ADD CONSTRAINT secret_authority_use_window CHECK
  (use_window_ms IS NULL OR (retention_ceiling IS NOT NULL AND use_window_ms>2000 AND use_window_ms<=86400000 AND expires_at<=retention_ceiling));
