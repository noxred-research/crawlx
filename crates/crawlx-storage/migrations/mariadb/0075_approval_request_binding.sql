-- Legacy rows remain unbound and cannot cross the durable approval bridge.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS request_payload JSON NULL;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS bound_action_id BINARY(16) NULL;
