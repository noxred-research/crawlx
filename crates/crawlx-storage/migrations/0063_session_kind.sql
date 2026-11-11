-- Session responsibility is explicit; an unlaunched browser actor is not an HTTP coordinator.
ALTER TABLE crawl_sessions
  ADD COLUMN session_kind text NOT NULL DEFAULT 'browser'
    CHECK (session_kind IN ('browser', 'http_coordinator'));

-- Static role leases coordinate HTTP execution. Diagnostic render children remain browser sessions.
UPDATE crawl_sessions s
SET session_kind = 'http_coordinator'
FROM crawl_runs r
WHERE r.run_id = s.run_id AND r.mode = 'static' AND s.lease_kind = 'role';
