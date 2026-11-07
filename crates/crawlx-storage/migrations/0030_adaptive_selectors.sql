-- Scoped extraction descriptors. No action locator or credential payload belongs here.
CREATE TABLE adaptive_selectors (
    tenant_id uuid NOT NULL REFERENCES tenants,
    scope_key text NOT NULL CHECK (length(scope_key) = 64),
    run_id uuid NOT NULL,
    payload jsonb,
    volatile_page bigint,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, scope_key),
    FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE,
    CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
    CHECK (volatile_page IS NULL OR volatile_page < 0)
);
CREATE INDEX adaptive_selectors_expiry ON adaptive_selectors(expires_at);
ALTER TABLE adaptive_selectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE adaptive_selectors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON adaptive_selectors
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE FUNCTION enforce_adaptive_selector_retention() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source crawl_runs%ROWTYPE;
BEGIN
    SELECT * INTO STRICT source FROM crawl_runs WHERE run_id = NEW.run_id AND tenant_id = NEW.tenant_id FOR SHARE;
    IF source.purge_requested_at IS NOT NULL THEN
        RAISE EXCEPTION 'selector source run is purging';
    END IF;
    IF source.retention_mode = 'zdr' THEN
        IF NEW.payload IS NOT NULL OR NEW.volatile_page IS NULL OR NEW.expires_at > source.created_at + interval '1 hour' THEN
            RAISE EXCEPTION 'zdr selectors require shared volatile content and fixed expiry';
        END IF;
    ELSIF NEW.volatile_page IS NOT NULL OR NEW.expires_at > source.created_at + make_interval(days => source.retention_days) THEN
        RAISE EXCEPTION 'selector expiry exceeds source retention';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.run_id = NEW.run_id AND NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'selector updates cannot renew fixed expiry';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER adaptive_selector_retention BEFORE INSERT OR UPDATE ON adaptive_selectors
    FOR EACH ROW EXECUTE FUNCTION enforce_adaptive_selector_retention();
