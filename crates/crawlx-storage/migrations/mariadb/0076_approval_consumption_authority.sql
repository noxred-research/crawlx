-- A spent request is usable only by the exact lease fence that consumed it.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS consumed_fence BIGINT NULL;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS revoked_at DATETIME(6) NULL;
