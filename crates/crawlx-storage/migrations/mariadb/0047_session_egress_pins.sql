-- Observed transport pins remain subordinate to the existing session lease and generation.
-- new: observed session generation transport pins
CREATE TABLE IF NOT EXISTS session_egress_pins (
  session_id BINARY(16) NOT NULL,
  generation BIGINT NOT NULL CHECK (generation > 0),
  pin_digest BINARY(32) NOT NULL,
  PRIMARY KEY (session_id, generation),
  FOREIGN KEY (session_id) REFERENCES crawl_sessions(session_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin;
