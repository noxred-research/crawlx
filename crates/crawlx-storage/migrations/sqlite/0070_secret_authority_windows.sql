-- Timestamps use the baseline's microsecond representation.
ALTER TABLE run_secret_authority ADD COLUMN retention_ceiling INTEGER;
ALTER TABLE run_secret_authority ADD COLUMN use_window_ms INTEGER CHECK
  (use_window_ms IS NULL OR (use_window_ms>2000 AND use_window_ms<=86400000));
UPDATE run_secret_authority SET retention_ceiling=expires_at WHERE retention_ceiling IS NULL AND sealed_at IS NULL;
CREATE TRIGGER secret_authority_use_window_insert BEFORE INSERT ON run_secret_authority
WHEN NEW.use_window_ms IS NOT NULL AND (NEW.retention_ceiling IS NULL OR NEW.expires_at>NEW.retention_ceiling)
BEGIN SELECT RAISE(ABORT, 'secret authority use window exceeds retention'); END;
CREATE TRIGGER secret_authority_use_window_update BEFORE UPDATE ON run_secret_authority
WHEN NEW.use_window_ms IS NOT NULL AND (NEW.retention_ceiling IS NULL OR NEW.expires_at>NEW.retention_ceiling)
BEGIN SELECT RAISE(ABORT, 'secret authority use window exceeds retention'); END;
