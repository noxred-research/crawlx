-- Preserve both ends of same-version ambiguity and V2 -> V1 rollout aliases.
ALTER TABLE identity_aliases RENAME COLUMN identity_version TO from_version;
ALTER TABLE identity_aliases ADD COLUMN to_version smallint;
UPDATE identity_aliases SET to_version = from_version;
ALTER TABLE identity_aliases ALTER COLUMN to_version SET NOT NULL;
ALTER TABLE identity_aliases ADD CONSTRAINT identity_alias_versions_positive
  CHECK (from_version > 0 AND to_version > 0);
ALTER TABLE identity_aliases DROP CONSTRAINT identity_aliases_pkey;
ALTER TABLE identity_aliases ADD PRIMARY KEY
  (run_id, alias_hash, canonical_hash, from_version, to_version);
