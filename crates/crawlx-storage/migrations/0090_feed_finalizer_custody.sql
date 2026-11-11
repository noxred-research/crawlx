-- crawlx-storage 0090: fenced custody producer for terminal feed finalization.
-- Terminal feed batches are sealed artifacts. They need a producer lease like every other sealed
-- write, but finalization runs after the last session or URL lease has ended. The finalizer
-- claim lives on the run row it finalizes: one owner, one expiry and a fence that grows on each
-- claim, so an expired owner can never publish after a takeover. The lease ends when
-- feed_finalized becomes true.
ALTER TABLE crawl_runs
  ADD COLUMN feed_finalizer_id uuid,
  ADD COLUMN feed_finalizer_owner uuid,
  ADD COLUMN feed_finalizer_fence bigint NOT NULL DEFAULT 0,
  ADD COLUMN feed_finalizer_expires_at timestamptz;
