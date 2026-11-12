-- Report facts gain a route dimension and a finite outcome label. The route key is the opaque
-- digest of the request's route label, the outcome label is `kind:stage:state` of a checkpoint,
-- stage or alert fact. Per-route counters group by both, so they come from committed rows alone.
-- Facts written before this migration keep NULL: their route is unknown, never a default route.
-- Failure snapshots live inside the alert fact payload and share its retention deadline. Idempotent.
ALTER TABLE report_history
    ADD COLUMN IF NOT EXISTS route_key BINARY(32) NULL,
    ADD COLUMN IF NOT EXISTS outcome VARCHAR(64) NULL;
CREATE INDEX IF NOT EXISTS report_history_route_keyset ON report_history(tenant_id,run_id,route_key,fact_sequence);
