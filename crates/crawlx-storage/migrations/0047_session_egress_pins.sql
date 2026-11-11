-- Observed transport pins remain subordinate to the existing session lease and generation.
CREATE TABLE session_egress_pins (
  session_id uuid NOT NULL REFERENCES crawl_sessions(session_id) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK (generation > 0),
  pin_digest bytea NOT NULL CHECK (octet_length(pin_digest) = 32),
  PRIMARY KEY (session_id, generation)
);

-- PostgreSQL tenant visibility follows the owning session and run through existing RLS.
ALTER TABLE session_egress_pins ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session_egress_pins USING (
  EXISTS (
    SELECT 1 FROM crawl_sessions s JOIN crawl_runs r USING (run_id)
    WHERE s.session_id = session_egress_pins.session_id
  )
);
