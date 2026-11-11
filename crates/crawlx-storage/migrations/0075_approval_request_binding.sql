-- Legacy rows remain unbound and cannot cross the durable approval bridge.
ALTER TABLE approvals ADD COLUMN request_payload jsonb;
ALTER TABLE approvals ADD COLUMN bound_action_id uuid REFERENCES actions(action_id);
