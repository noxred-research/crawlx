-- Observed transport pins remain subordinate to the existing session lease and generation.
CREATE TABLE session_egress_pins (
  session_id BLOB NOT NULL REFERENCES crawl_sessions(session_id) ON DELETE CASCADE CHECK (length(session_id) = 16),
  generation INTEGER NOT NULL CHECK (generation > 0),
  pin_digest BLOB NOT NULL CHECK (length(pin_digest) = 32),
  PRIMARY KEY (session_id, generation)
) STRICT;
