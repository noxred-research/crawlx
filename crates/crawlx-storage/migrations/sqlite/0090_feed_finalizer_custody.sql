-- Fenced custody producer for terminal feed finalization: one owner, one expiry and a fence
-- that grows on each claim, on the run row it finalizes. The lease ends when feed_finalized
-- becomes true.
ALTER TABLE crawl_runs ADD COLUMN feed_finalizer_id BLOB;
ALTER TABLE crawl_runs ADD COLUMN feed_finalizer_owner BLOB;
ALTER TABLE crawl_runs ADD COLUMN feed_finalizer_fence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE crawl_runs ADD COLUMN feed_finalizer_expires_at INTEGER;
