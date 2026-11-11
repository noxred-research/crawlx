-- Retained URL link graph only. UUIDs are raw bytes; expiry is UTC epoch microseconds.
CREATE TABLE url_graph_runs (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    version INTEGER NOT NULL CHECK (version=1),
    revision INTEGER NOT NULL CHECK (revision>=0),
    policy TEXT NOT NULL CHECK (json_valid(policy) AND json_type(policy)='object' AND length(CAST(policy AS BLOB))<=4096),
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE url_graph_nodes (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    handle BLOB NOT NULL CHECK (length(handle)=32),
    PRIMARY KEY (tenant_id,run_id,handle),
    FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE url_graph_edges (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    version INTEGER NOT NULL CHECK (version=1),
    anchor_version INTEGER NOT NULL DEFAULT 1 CHECK (anchor_version=1),
    source_handle BLOB NOT NULL CHECK (length(source_handle)=32),
    target_handle BLOB NOT NULL CHECK (length(target_handle)=32),
    anchor_handle BLOB NOT NULL CHECK (length(anchor_handle) IN (0,32)),
    cost INTEGER NOT NULL CHECK (cost BETWEEN 1 AND 4294967295),
    producer_fence INTEGER NOT NULL CHECK (producer_fence>0),
    PRIMARY KEY (tenant_id,run_id,source_handle,target_handle,anchor_handle),
    FOREIGN KEY (tenant_id,run_id,source_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,run_id,target_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE
) STRICT;
CREATE INDEX url_graph_edges_inverse ON url_graph_edges(tenant_id,run_id,target_handle,source_handle);
