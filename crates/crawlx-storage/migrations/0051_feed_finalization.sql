-- Explicit terminal source preserves request/action XOR for every non-terminal manifest.
ALTER TABLE crawl_runs ADD COLUMN feed_finalizing boolean NOT NULL DEFAULT false;
ALTER TABLE crawl_runs ADD COLUMN feed_finalized boolean NOT NULL DEFAULT false,
  ADD COLUMN feed_required boolean NOT NULL DEFAULT false,
  ADD COLUMN feed_terminal_reason terminal_reason;
ALTER TABLE crawl_runs ADD COLUMN feed_finalization_outcome text
  CHECK (feed_finalization_outcome IN ('completed','content_expired'));
UPDATE crawl_runs SET feed_required=coalesce(jsonb_array_length(config->'datasets'->'feeds'),0)>0;
ALTER TABLE dataset_delivery_outbox ADD COLUMN terminal_source boolean NOT NULL DEFAULT false;
DO $$ DECLARE constraint_name text; BEGIN
  SELECT conname INTO constraint_name FROM pg_constraint
    WHERE conrelid='dataset_delivery_outbox'::regclass AND contype='c'
      AND pg_get_constraintdef(oid) LIKE '%source_request_id%source_action_id%';
  IF constraint_name IS NULL THEN RAISE EXCEPTION 'delivery source constraint missing'; END IF;
  EXECUTE format('ALTER TABLE dataset_delivery_outbox DROP CONSTRAINT %I', constraint_name);
END $$;
ALTER TABLE dataset_delivery_outbox ADD CONSTRAINT dataset_delivery_outbox_one_source CHECK (
  (terminal_source AND source_request_id IS NULL AND source_action_id IS NULL)
  OR (NOT terminal_source AND ((source_request_id IS NULL) <> (source_action_id IS NULL)))
);
CREATE INDEX crawl_runs_feed_finalization ON crawl_runs(run_id,tenant_id)
  WHERE NOT feed_finalized AND (feed_required OR feed_finalizing);
