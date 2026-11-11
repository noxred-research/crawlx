-- One durable request per original parked action; NULL legacy bindings are excluded.
CREATE UNIQUE INDEX approvals_bound_action ON approvals(bound_action_id);
CREATE INDEX approvals_bridge_lookup ON approvals(run_id, action_id, decision);
