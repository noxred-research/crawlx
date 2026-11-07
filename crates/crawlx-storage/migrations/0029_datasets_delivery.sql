-- Accepted metadata and delivery receipts. Content bytes always use existing artifact policy.
-- Actions already belong to a tenant through their run. The paired run/action FK
-- plus the owning tenant/run FK prevents cross-tenant action-derived references.
ALTER TABLE actions ADD CONSTRAINT dataset_action_run UNIQUE (run_id, action_id);
ALTER TABLE actions ADD COLUMN dataset_page bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE actions ADD CONSTRAINT dataset_action_page UNIQUE (dataset_page);
CREATE TABLE datasets (
  dataset_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  run_id uuid NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  next_ordinal bigint NOT NULL DEFAULT 1 CHECK (next_ordinal > 0),
  item_count bigint NOT NULL DEFAULT 0 CHECK (item_count >= 0),
  size_bytes bigint NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
  UNIQUE (tenant_id, run_id, name),
  UNIQUE (tenant_id, run_id, dataset_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE TABLE dataset_items (
  item_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  dataset_id bigint NOT NULL,
  ordinal bigint NOT NULL CHECK (ordinal > 0),
  source_request_id bigint,
  source_action_id uuid,
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  payload jsonb,
  volatile_page bigint,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  expires_at timestamptz,
  UNIQUE (tenant_id, dataset_id, ordinal),
  UNIQUE (tenant_id, dataset_id, source_request_id, identity_key),
  UNIQUE (tenant_id, dataset_id, source_action_id, identity_key),
  CHECK ((source_request_id IS NULL) <> (source_action_id IS NULL)),
  FOREIGN KEY (run_id, source_action_id) REFERENCES actions(run_id, action_id) ON DELETE CASCADE,
  CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
  FOREIGN KEY (tenant_id, run_id, dataset_id) REFERENCES datasets(tenant_id, run_id, dataset_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, run_id, source_request_id) REFERENCES url_frontier(tenant_id, run_id, frontier_id) ON DELETE CASCADE
);
CREATE INDEX dataset_items_keyset ON dataset_items(tenant_id, run_id, dataset_id, ordinal);
CREATE TABLE dataset_kv (
  tenant_id uuid NOT NULL REFERENCES tenants,
  run_id uuid NOT NULL,
  store text NOT NULL,
  key text NOT NULL,
  version bigint NOT NULL CHECK (version > 0),
  payload jsonb,
  volatile_page bigint,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  expires_at timestamptz,
  PRIMARY KEY (tenant_id, run_id, store, key),
  CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE TABLE dataset_delivery_outbox (
  delivery_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants,
  run_id uuid NOT NULL,
  source_request_id bigint,
  source_action_id uuid,
  feed text NOT NULL,
  idempotency_key text NOT NULL,
  payload jsonb,
  volatile_page bigint,
  content_page bigint,
  erased_at timestamptz,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','delivered','content_expired')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
  lease_owner uuid,
  lease_expires_at timestamptz,
  not_before timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (tenant_id, run_id, feed, idempotency_key),
  CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
  CHECK ((source_request_id IS NULL) <> (source_action_id IS NULL)),
  FOREIGN KEY (run_id, source_action_id) REFERENCES actions(run_id, action_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, run_id, source_request_id) REFERENCES url_frontier(tenant_id, run_id, frontier_id) ON DELETE CASCADE
);
CREATE INDEX dataset_delivery_ready ON dataset_delivery_outbox(tenant_id, run_id, not_before, delivery_id)
  WHERE state IN ('pending','leased');
CREATE TABLE dataset_kv_drops (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  store text NOT NULL CHECK (store ~ '^[A-Za-z0-9_.-]{1,128}$'),
  PRIMARY KEY (tenant_id,run_id,store),
  FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);

-- Run/frontier tenant composite keys exist from request migration 0027.
DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['datasets','dataset_items','dataset_kv','dataset_kv_drops','dataset_delivery_outbox'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = crawlx_current_tenant()) WITH CHECK (tenant_id = crawlx_current_tenant())', table_name);
  END LOOP;
END $$;

-- Defense in depth: direct SQL cannot smuggle content references into ZDR receipts.
CREATE FUNCTION enforce_dataset_zdr() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr') THEN
    IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at IS NULL THEN
      RAISE EXCEPTION 'zdr dataset rows require volatile metadata and fixed expiry';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER dataset_items_zdr BEFORE INSERT OR UPDATE ON dataset_items FOR EACH ROW EXECUTE FUNCTION enforce_dataset_zdr();
CREATE TRIGGER dataset_kv_zdr BEFORE INSERT OR UPDATE ON dataset_kv FOR EACH ROW EXECUTE FUNCTION enforce_dataset_zdr();
CREATE TRIGGER dataset_outbox_zdr BEFORE INSERT OR UPDATE ON dataset_delivery_outbox FOR EACH ROW EXECUTE FUNCTION enforce_dataset_zdr();
