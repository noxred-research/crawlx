-- crawlx-storage 0009: identity aliases (identity versioning and the ambiguity band).
--
-- `alias_hash` resolved toward `canonical_hash` without merging into it: either the
-- weighted matcher's ambiguous band (0.60 <= score < 0.80 mints a new identity whose
-- `alias_candidate_of` is the best known candidate) or a dual-compute release recording
-- `(v1_hash, v2_hash)`. Hashes are stored like `elements.identity_hash` (32-byte bytea).
-- The first row of a pair wins: recording the same pair again is a no-op.
CREATE TABLE identity_aliases (
  run_id uuid NOT NULL REFERENCES crawl_runs,
  alias_hash bytea NOT NULL,
  canonical_hash bytea NOT NULL,
  identity_version smallint NOT NULL,
  score real NOT NULL CHECK (score >= 0 AND score <= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, alias_hash, canonical_hash)
);
CREATE INDEX identity_aliases_canonical ON identity_aliases (run_id, canonical_hash);
