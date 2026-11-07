-- Request envelopes extend the existing authoritative frontier; no second queue.
ALTER TABLE url_frontier
  ADD COLUMN request_version smallint NOT NULL DEFAULT 1 CHECK (request_version = 1),
  ADD COLUMN principal text NOT NULL DEFAULT 'anonymous',
  ADD COLUMN route_id text NOT NULL DEFAULT 'default',
  ADD COLUMN revisit_generation integer NOT NULL DEFAULT 0 CHECK (revisit_generation >= 0),
  ADD COLUMN request_envelope jsonb,
  ADD COLUMN envelope_bytes bigint NOT NULL DEFAULT 0 CHECK (envelope_bytes >= 0),
  ADD COLUMN effect_reservations bigint NOT NULL DEFAULT 0 CHECK (effect_reservations >= 0),
  ADD COLUMN effect_escrow_fence bigint,
  ADD COLUMN effect_escrow_amount bigint,
  ADD COLUMN effect_escrow_settlement bigint,
  ADD COLUMN acquisition_deadline_at timestamptz,
  ADD COLUMN acquisition_usage jsonb,
  ADD COLUMN acquisition_escrow jsonb,
  ADD COLUMN acquisition_escrow_fence bigint,
  ADD COLUMN acquisition_settlement jsonb,
  ADD COLUMN state_version bigint NOT NULL DEFAULT 1 CHECK (state_version > 0),
  ADD COLUMN acquisition_ref bytea,
  ADD COLUMN document_ref bytea;
ALTER TABLE url_frontier DROP CONSTRAINT url_frontier_run_id_canonical_key_key;
ALTER TABLE url_frontier ADD CONSTRAINT url_frontier_request_unique
  UNIQUE (run_id, canonical_key, revisit_generation);
CREATE INDEX url_frontier_eligible ON url_frontier
  (run_id, next_attempt_at, priority DESC, depth, frontier_id) WHERE status = 'pending';
CREATE UNIQUE INDEX crawl_runs_run_tenant ON crawl_runs(run_id, tenant_id);
CREATE UNIQUE INDEX crawl_runs_tenant_run ON crawl_runs(tenant_id, run_id);
ALTER TABLE url_frontier ADD COLUMN tenant_id uuid REFERENCES tenants;
UPDATE url_frontier f SET tenant_id = r.tenant_id FROM crawl_runs r WHERE r.run_id = f.run_id;
ALTER TABLE url_frontier ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE url_frontier ADD CONSTRAINT frontier_tenant_run
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id);
ALTER TABLE url_frontier ADD CONSTRAINT frontier_tenant_run_row UNIQUE (tenant_id, run_id, frontier_id);
CREATE FUNCTION frontier_assign_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE owner_tenant uuid;
BEGIN
  SELECT tenant_id INTO STRICT owner_tenant FROM crawl_runs WHERE run_id = NEW.run_id;
  IF NEW.tenant_id IS NOT NULL AND NEW.tenant_id <> owner_tenant THEN
    RAISE EXCEPTION 'frontier tenant mismatch' USING ERRCODE = 'check_violation';
  END IF;
  NEW.tenant_id := owner_tenant;
  RETURN NEW;
END $$;
CREATE TRIGGER frontier_assign_tenant BEFORE INSERT OR UPDATE OF run_id, tenant_id ON url_frontier
  FOR EACH ROW EXECUTE FUNCTION frontier_assign_tenant();
CREATE TABLE frontier_producers (
  run_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  epoch bigint NOT NULL DEFAULT 1 CHECK (epoch > 0),
  sealed boolean NOT NULL DEFAULT false,
  FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs(run_id, tenant_id) ON DELETE CASCADE
);
CREATE TABLE frontier_loader_cursors (
  run_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  source_id text NOT NULL CHECK (length(source_id) BETWEEN 1 AND 128),
  cursor jsonb NOT NULL,
  PRIMARY KEY (run_id, source_id),
  FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs(run_id, tenant_id) ON DELETE CASCADE
);
CREATE TABLE frontier_batch_receipts (
  run_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  batch_id bytea NOT NULL CHECK (octet_length(batch_id) = 32),
  batch_digest bytea NOT NULL CHECK (octet_length(batch_digest) = 32),
  receipt jsonb NOT NULL,
  PRIMARY KEY (run_id, batch_id),
  FOREIGN KEY (run_id, tenant_id) REFERENCES crawl_runs(run_id, tenant_id) ON DELETE CASCADE
);
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['frontier_producers','frontier_loader_cursors','frontier_batch_receipts']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = crawlx_current_tenant()) WITH CHECK (tenant_id = crawlx_current_tenant())', t);
  END LOOP;
END $$;
