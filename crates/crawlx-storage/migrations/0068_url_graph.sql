-- Retained URL link evidence, independent from browser actions and the URL frontier.
-- Handles use tenant/run-keyed domains; no URL bytes, anchor text or privacy keys enter SQL.
CREATE TABLE url_graph_runs (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    version integer NOT NULL CHECK (version=1),
    revision bigint NOT NULL CHECK (revision>=0),
    policy jsonb NOT NULL CHECK (jsonb_typeof(policy)='object' AND octet_length(policy::text)<=4096),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
CREATE TABLE url_graph_nodes (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    handle bytea NOT NULL CHECK (octet_length(handle)=32),
    PRIMARY KEY (tenant_id,run_id,handle),
    FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
);
CREATE TABLE url_graph_edges (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    version integer NOT NULL CHECK (version=1),
    anchor_version integer NOT NULL DEFAULT 1 CHECK (anchor_version=1),
    source_handle bytea NOT NULL CHECK (octet_length(source_handle)=32),
    target_handle bytea NOT NULL CHECK (octet_length(target_handle)=32),
    anchor_handle bytea NOT NULL CHECK (octet_length(anchor_handle) IN (0,32)),
    cost bigint NOT NULL CHECK (cost BETWEEN 1 AND 4294967295),
    producer_fence bigint NOT NULL CHECK (producer_fence>0),
    PRIMARY KEY (tenant_id,run_id,source_handle,target_handle,anchor_handle),
    FOREIGN KEY (tenant_id,run_id,source_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,run_id,target_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE
);
CREATE INDEX url_graph_edges_inverse ON url_graph_edges(tenant_id,run_id,target_handle,source_handle);
ALTER TABLE url_graph_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_graph_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON url_graph_runs
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
ALTER TABLE url_graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_graph_nodes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON url_graph_nodes
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
ALTER TABLE url_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE url_graph_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON url_graph_edges
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
