-- Request pipeline checkpoints share the original fenced result transaction.
CREATE TABLE request_pipeline_history (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    request_id bigint NOT NULL,
    attempt integer NOT NULL CHECK (attempt>0),
    progress jsonb NOT NULL CHECK (jsonb_typeof(progress)='object' AND octet_length(progress::text)<=4096),
    source_fact jsonb NOT NULL CHECK (jsonb_typeof(source_fact)='object' AND octet_length(source_fact::text)<=4096),
    expires_at timestamptz,
    PRIMARY KEY (tenant_id,run_id,request_id,attempt),
    FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
);
ALTER TABLE request_pipeline_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_pipeline_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON request_pipeline_history
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
