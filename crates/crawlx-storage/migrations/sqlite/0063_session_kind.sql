-- Match PostgreSQL's explicit browser versus HTTP coordinator responsibility.
ALTER TABLE crawl_sessions
  ADD COLUMN session_kind TEXT NOT NULL DEFAULT 'browser'
    CHECK (session_kind IN ('browser', 'http_coordinator'));

-- Render children keep browser responsibility even inside static scrape runs.
UPDATE crawl_sessions
SET session_kind = 'http_coordinator'
WHERE lease_kind = 'role' AND run_id IN (SELECT run_id FROM crawl_runs WHERE mode = 'static');
