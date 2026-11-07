-- crawlx-storage 0014: logarithmic session claims, including live recovering holders.
-- The existing crawl_sessions_claim index remains the ordered serial-turn barrier.
-- NULL expiry means ready now; the immutable expression permits a bounded range scan
-- without walking running sessions or recovering sessions with a live lease.
CREATE INDEX crawl_sessions_ready ON crawl_sessions
  (run_id, (COALESCE(lease_expires_at, '-infinity'::timestamptz)), schedule_slot)
  WHERE status IN ('pending','recovering');
