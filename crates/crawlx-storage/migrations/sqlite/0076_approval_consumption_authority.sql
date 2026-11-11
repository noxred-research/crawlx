-- A spent request is usable only by the exact lease fence that consumed it.
ALTER TABLE approvals ADD COLUMN consumed_fence INTEGER;
ALTER TABLE approvals ADD COLUMN revoked_at INTEGER;
