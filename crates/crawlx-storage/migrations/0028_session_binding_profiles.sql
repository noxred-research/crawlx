-- Session metadata is subordinate to crawl_sessions' existing lease fence.
-- Internal render actors are atomic leased children, not exploration role slots.
ALTER TABLE crawl_sessions ADD COLUMN lease_kind text NOT NULL DEFAULT 'role'
  CHECK (lease_kind IN ('role','render'));
UPDATE crawl_sessions SET lease_kind='render' WHERE role='scrape' AND schedule_slot>=1000000;
UPDATE actions SET status='unknown' WHERE status='intended' AND session_id IN
  (SELECT session_id FROM crawl_sessions WHERE lease_kind='render' AND fencing_token IS NULL);
UPDATE crawl_sessions SET status='failed',finished_at=COALESCE(finished_at,clock_timestamp())
  WHERE lease_kind='render' AND fencing_token IS NULL AND status NOT IN ('completed','failed','cancelled');

CREATE TABLE session_bindings (
  session_id uuid PRIMARY KEY REFERENCES crawl_sessions ON DELETE CASCADE,
  run_id uuid NOT NULL REFERENCES crawl_runs ON DELETE CASCADE,
  binding jsonb NOT NULL,
  CHECK (octet_length(binding::text) <= 16384)
);
ALTER TABLE session_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session_bindings USING (
  EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = session_bindings.run_id)
);

-- Profile secret bytes are authenticated ciphertext, separate from ordinary artifacts.
CREATE TABLE browser_profiles (
  tenant_id uuid NOT NULL REFERENCES tenants,
  principal text NOT NULL,
  name text NOT NULL CHECK (name ~ '^[A-Za-z0-9_-]{1,128}$'),
  generation bigint NOT NULL CHECK (generation > 0),
  scope jsonb NOT NULL,
  encrypted_bundle bytea NOT NULL CHECK (octet_length(encrypted_bundle) <= 33554432),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  expires_at timestamptz NOT NULL,
  owner_run uuid NOT NULL REFERENCES crawl_runs ON DELETE CASCADE,
  session_id uuid NOT NULL REFERENCES crawl_sessions ON DELETE CASCADE,
  lease_fence bigint NOT NULL,
  PRIMARY KEY (tenant_id, principal, name)
);
CREATE INDEX browser_profiles_expiry ON browser_profiles(expires_at);
ALTER TABLE browser_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON browser_profiles USING (tenant_id = crawlx_current_tenant());

-- End-of-run session checkpoints cannot extend credential lifetime. Retained profile
-- ciphertext is a distinct operator-approved policy; cancellation/revocation erases it.
CREATE FUNCTION expire_bound_session_secrets() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IN ('completed','failed','cancelled')
     OR NEW.cancel_requested_at IS NOT NULL OR NEW.purge_requested_at IS NOT NULL THEN
    UPDATE artifacts SET expires_at = LEAST(COALESCE(expires_at, clock_timestamp()), clock_timestamp())
      WHERE run_id = NEW.run_id AND sensitivity = 'credential_bearing' AND deleted_at IS NULL;
    UPDATE checkpoints SET expires_at = LEAST(expires_at, clock_timestamp()) WHERE run_id = NEW.run_id;
    UPDATE session_bindings SET binding = jsonb_set(
      jsonb_set(binding, '{state}', '"retired"'), '{expires_at}', to_jsonb(clock_timestamp()))
      WHERE run_id = NEW.run_id;
  END IF;
  IF NEW.status IN ('failed','cancelled') OR NEW.cancel_requested_at IS NOT NULL OR NEW.purge_requested_at IS NOT NULL THEN
    DELETE FROM browser_profiles WHERE owner_run = NEW.run_id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER expire_bound_session_secrets AFTER UPDATE OF status,cancel_requested_at,purge_requested_at ON crawl_runs
  FOR EACH ROW EXECUTE FUNCTION expire_bound_session_secrets();

CREATE FUNCTION revoke_retained_profiles() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.revoked_at IS NOT NULL THEN
    DELETE FROM browser_profiles WHERE owner_run IN
      (SELECT run_id FROM crawl_runs WHERE authorization_record_id = NEW.record_id);
    UPDATE artifacts SET expires_at = clock_timestamp()
      WHERE sensitivity = 'credential_bearing' AND deleted_at IS NULL AND run_id IN
      (SELECT run_id FROM crawl_runs WHERE authorization_record_id = NEW.record_id);
    UPDATE checkpoints SET expires_at = LEAST(expires_at, clock_timestamp()) WHERE run_id IN
      (SELECT run_id FROM crawl_runs WHERE authorization_record_id = NEW.record_id);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER revoke_retained_profiles AFTER UPDATE OF revoked_at ON authorization_records
  FOR EACH ROW EXECUTE FUNCTION revoke_retained_profiles();
