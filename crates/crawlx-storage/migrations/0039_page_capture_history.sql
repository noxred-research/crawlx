-- Immutable descriptors belong to successful fenced request results, never URL upserts.
-- Payloads contain approved PageRecord metadata and artifact references, not body bytes.
CREATE TABLE page_captures (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  frontier_id bigint NOT NULL REFERENCES url_frontier(frontier_id) ON DELETE CASCADE,
  fence bigint NOT NULL,
  state_version bigint NOT NULL,
  expires_at timestamptz,
  payload jsonb NOT NULL,
  PRIMARY KEY (run_id, frontier_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE INDEX page_captures_expiry ON page_captures(expires_at) WHERE expires_at IS NOT NULL;
ALTER TABLE page_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE page_captures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON page_captures
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE FUNCTION enforce_page_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'committed page captures are immutable';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r JOIN url_frontier f ON f.run_id=r.run_id
      WHERE r.run_id=NEW.run_id AND r.tenant_id=NEW.tenant_id
        AND r.retention_mode <> 'zdr' AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp())
        AND f.frontier_id=NEW.frontier_id AND f.status='leased'
        AND f.fencing_token=NEW.fence AND f.state_version=NEW.state_version
        AND f.lease_expires_at>clock_timestamp()) THEN
    RAISE EXCEPTION 'page capture requires a live retained request fence';
  END IF;
  NEW.expires_at := (SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id);
  RETURN NEW;
END $$;
CREATE TRIGGER page_capture_custody BEFORE INSERT OR UPDATE ON page_captures
  FOR EACH ROW EXECUTE FUNCTION enforce_page_capture();
-- No backfill: mutable legacy pages cannot prove generation-level custody.
