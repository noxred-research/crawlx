-- Dedicated bootstrap ownership, never an origin lease, heartbeat or API identity.
-- Keep the single row and its progress through expiry/release/takeover. A seed or
-- frontier row is not evidence that bootstrap joined successfully.
CREATE SEQUENCE run_bootstrap_producer_fence AS bigint NO CYCLE;
CREATE TABLE run_bootstrap_producers (
    producer_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    owner uuid NOT NULL REFERENCES workers(worker_id),
    fence bigint NOT NULL DEFAULT nextval('run_bootstrap_producer_fence') CHECK (fence > 0),
    state text NOT NULL CHECK (state IN ('running', 'released', 'completed')),
    leased_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- Non-secret, monotonically increasing application cursor. Never store raw
    -- seed/config/credential material or caller-controlled strings here.
    progress bigint NOT NULL DEFAULT 0 CHECK (progress >= 0),
    completed_at timestamptz,
    UNIQUE (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE,
    CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
    CHECK (state <> 'running' OR
           (expires_at > leased_at AND expires_at <= leased_at + interval '5 minutes'))
);
ALTER SEQUENCE run_bootstrap_producer_fence OWNED BY run_bootstrap_producers.fence;
ALTER TABLE run_bootstrap_producers ENABLE ROW LEVEL SECURITY;
-- Match 0012: unscoped table-owner workers bypass RLS, restricted API roles do not.
CREATE POLICY tenant_isolation ON run_bootstrap_producers
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- No TTL cleanup: expiry permits a new fence, not erasure of durable progress,
-- completion, secret authority, or OPEN artifact-exposure intents.
CREATE FUNCTION preserve_bootstrap_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.producer_id IS DISTINCT FROM OLD.producer_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.run_id IS DISTINCT FROM OLD.run_id
       OR NEW.progress < OLD.progress
       OR NEW.fence < OLD.fence THEN
        RAISE EXCEPTION 'bootstrap identity, progress and fence cannot regress';
    END IF;
    IF OLD.state = 'completed' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'bootstrap completion is permanent until run purge';
    END IF;
    IF (NEW.owner IS DISTINCT FROM OLD.owner
        OR (NEW.state = 'running' AND OLD.state <> 'running'))
       AND NEW.fence <= OLD.fence THEN
        RAISE EXCEPTION 'bootstrap acquisition requires a newer fence';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER preserve_bootstrap_progress BEFORE UPDATE ON run_bootstrap_producers
    FOR EACH ROW EXECUTE FUNCTION preserve_bootstrap_progress();
