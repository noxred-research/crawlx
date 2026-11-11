-- Cache is separate from graph evidence. Policy/model changes or edge revisions delete it.
-- Original graph expiry remains the ceiling for every rank result.
CREATE TABLE url_graph_ranks (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    version integer NOT NULL CHECK (version=1),
    revision bigint NOT NULL CHECK (revision>=0),
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object' AND octet_length(result::text)<=262144),
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE url_graph_ranks ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_graph_ranks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON url_graph_ranks
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
