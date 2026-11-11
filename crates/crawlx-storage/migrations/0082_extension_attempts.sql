-- Bounded digest dedupe for complete extension callback trails. Receipts themselves are
-- the typed `extension_attempt` metadata event written in the same fenced transaction.
CREATE TABLE extension_attempts (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    request_id bigint NOT NULL,
    fence bigint NOT NULL CHECK (fence>0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 32767),
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    event_seq bigint NOT NULL CHECK (event_seq>0),
    PRIMARY KEY (tenant_id,run_id,request_id,fence,attempt),
    FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
);
ALTER TABLE extension_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE extension_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON extension_attempts
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
