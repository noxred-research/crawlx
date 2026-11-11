-- Legacy rows remain unbound and cannot cross the durable approval bridge.
ALTER TABLE approvals ADD COLUMN request_payload TEXT CHECK(request_payload IS NULL OR json_valid(request_payload));
ALTER TABLE approvals ADD COLUMN bound_action_id BLOB REFERENCES actions(action_id);
