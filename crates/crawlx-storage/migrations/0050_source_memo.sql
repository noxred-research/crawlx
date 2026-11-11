-- Content-derived hashes are retained only for non-ZDR runs. ZDR uses volatile custody.
CREATE TABLE source_memo_seen (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    lookup_key text NOT NULL CHECK (length(lookup_key) = 64),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, lookup_key),
    FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE INDEX source_memo_seen_eviction ON source_memo_seen(tenant_id, run_id, recorded_at, lookup_key);
CREATE TABLE source_category_cache (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    lookup_key text NOT NULL CHECK (length(lookup_key) = 64),
    payload jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, run_id, lookup_key),
    FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE INDEX source_category_cache_expiry ON source_category_cache(expires_at);
ALTER TABLE source_memo_seen ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_memo_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON source_memo_seen
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
ALTER TABLE source_category_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_category_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON source_category_cache
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE FUNCTION reject_durable_source_memo_zdr() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source crawl_runs%ROWTYPE;
BEGIN
    SELECT * INTO STRICT source FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id FOR SHARE;
    IF source.retention_mode='zdr' OR source.purge_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'source memo metadata requires retained source run';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER source_memo_seen_retention BEFORE INSERT OR UPDATE ON source_memo_seen
    FOR EACH ROW EXECUTE FUNCTION reject_durable_source_memo_zdr();
CREATE TRIGGER source_category_cache_retention BEFORE INSERT OR UPDATE ON source_category_cache
    FOR EACH ROW EXECUTE FUNCTION reject_durable_source_memo_zdr();

-- Reset fencing only: no content-derived source, role, policy, URL, or digest is stored here.
CREATE TABLE source_memo_control (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE source_memo_control ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_memo_control FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON source_memo_control
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
