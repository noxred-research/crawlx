-- Fenced custody producer for terminal feed finalization: one owner, one expiry and a fence
-- that grows on each claim, on the run row it finalizes. The lease ends when feed_finalized
-- becomes true. Idempotent.
ALTER TABLE crawl_runs
  ADD COLUMN IF NOT EXISTS feed_finalizer_id BINARY(16) NULL,
  ADD COLUMN IF NOT EXISTS feed_finalizer_owner BINARY(16) NULL,
  ADD COLUMN IF NOT EXISTS feed_finalizer_fence BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS feed_finalizer_expires_at DATETIME(6) NULL;
