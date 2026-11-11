ALTER TABLE crawl_runs ADD COLUMN IF NOT EXISTS feed_finalizing BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE crawl_runs ADD COLUMN IF NOT EXISTS feed_finalized BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS feed_required BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS feed_terminal_reason VARCHAR(64) NULL;
ALTER TABLE crawl_runs ADD COLUMN IF NOT EXISTS feed_finalization_outcome VARCHAR(32) NULL
  CHECK (feed_finalization_outcome IN ('completed','content_expired'));
UPDATE crawl_runs SET feed_required=COALESCE(JSON_LENGTH(config,'$.datasets.feeds'),0)>0;
ALTER TABLE dataset_delivery_outbox
  ADD COLUMN IF NOT EXISTS terminal_source BOOLEAN NOT NULL DEFAULT FALSE,
  DROP CONSTRAINT IF EXISTS dataset_delivery_outbox_one_source,
  ADD CONSTRAINT dataset_delivery_outbox_one_source CHECK (
    (terminal_source = TRUE AND source_request_id IS NULL AND source_action_id IS NULL)
    OR (terminal_source = FALSE AND ((source_request_id IS NULL) <> (source_action_id IS NULL)))
  );
CREATE INDEX IF NOT EXISTS crawl_runs_feed_finalization
  ON crawl_runs(feed_finalized,feed_required,feed_finalizing,run_id,tenant_id);
