-- crawlx-storage 0019: authorization record lifecycle.
--
-- * A record is created through the verifying API route: `verified_at` and `verification`
--   (`{kind, checkedAt, hosts|keyId}`) say when and how its ownership proof was checked. Records
--   registered by `crawlx crawl --authorization-record` keep both NULL (the operator running the
--   crawl is the authorizer); the API refuses to admit a run against such a record.
-- * Revocation is `revoked_at` plus `revoked_reason` and `revoked_by` (the API key that revoked).
-- * The body is immutable evidence: `authorization_records_immutable` rejects an UPDATE that changes
--   any identity or body column. Only the lifecycle columns (`revoked_at`, `revoked_reason`,
--   `revoked_by`, `verified_at`, `verification`, `evidence_artifact_id`) may change; an amendment is
--   a new record id.
-- * `crawl_runs.authorization_body_digest` binds a run to the exact body it was admitted under, so a
--   later edit of the stored body is detectable from the run row.
-- * `terminal_reason` gains `authorization_revoked` (a running run stopped because its record was
--   revoked, expired or removed). `ALTER TYPE ... ADD VALUE` runs last: the new label cannot be used
--   inside this migration's transaction.
ALTER TABLE authorization_records
  ADD COLUMN verified_at timestamptz,
  ADD COLUMN verification jsonb,
  ADD COLUMN revoked_reason text,
  ADD COLUMN revoked_by uuid REFERENCES api_keys(key_id);

CREATE FUNCTION authorization_records_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.record_id IS DISTINCT FROM OLD.record_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.body IS DISTINCT FROM OLD.body
     OR NEW.body_digest IS DISTINCT FROM OLD.body_digest
     OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
     OR NEW.valid_to IS DISTINCT FROM OLD.valid_to
  THEN
    RAISE EXCEPTION 'authorization_records body is immutable: record % (an amendment is a new record id)', OLD.record_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER authorization_records_immutable BEFORE UPDATE ON authorization_records
  FOR EACH ROW EXECUTE FUNCTION authorization_records_immutable();

ALTER TABLE crawl_runs ADD COLUMN authorization_body_digest bytea;

ALTER TYPE terminal_reason ADD VALUE IF NOT EXISTS 'authorization_revoked';
