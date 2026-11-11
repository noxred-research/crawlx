-- Match PostgreSQL's explicit browser versus HTTP coordinator responsibility.
ALTER TABLE crawl_sessions
  ADD COLUMN IF NOT EXISTS session_kind VARCHAR(32) NOT NULL DEFAULT 'browser',
  DROP CONSTRAINT IF EXISTS crawl_sessions_session_kind_check,
  ADD CONSTRAINT crawl_sessions_session_kind_check
    CHECK (session_kind IN ('browser', 'http_coordinator'));

-- Render children keep browser responsibility even inside static scrape runs.
UPDATE crawl_sessions
SET session_kind = 'http_coordinator'
WHERE lease_kind = 'role' AND run_id IN (SELECT run_id FROM crawl_runs WHERE mode = 'static');
