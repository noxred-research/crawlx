-- Nullable binding preserves legacy rows while preventing duplicate parked-action authority.
CREATE UNIQUE INDEX IF NOT EXISTS approvals_bound_action ON approvals(bound_action_id);
CREATE INDEX IF NOT EXISTS approvals_bridge_lookup ON approvals(run_id, action_id, decision);
