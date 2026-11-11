-- Retained URL link graph only. UUIDs are BINARY(16); expiry is UTC DATETIME(6).
-- All DDL is idempotent because this engine may commit each DDL statement separately.
-- from: 0068 retained URL graph header with fixed expiry and explicit policy/model binding.
CREATE TABLE IF NOT EXISTS url_graph_runs (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    version INTEGER NOT NULL CHECK (version=1),
    revision BIGINT NOT NULL CHECK (revision>=0),
    policy LONGTEXT NOT NULL CHECK (JSON_VALID(policy) AND JSON_TYPE(policy)='OBJECT' AND OCTET_LENGTH(policy)<=4096),
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (tenant_id,run_id),
    CONSTRAINT url_graph_runs_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
-- from: 0068 tenant/run-keyed URL handles, including orphans; no URL bytes.
CREATE TABLE IF NOT EXISTS url_graph_nodes (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    handle BINARY(32) NOT NULL,
    PRIMARY KEY (tenant_id,run_id,handle),
    CONSTRAINT url_graph_nodes_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
-- from: 0068 deduplicated link evidence keyed by source, target and anchor handle.
CREATE TABLE IF NOT EXISTS url_graph_edges (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    version INTEGER NOT NULL CHECK (version=1),
    anchor_version INTEGER NOT NULL DEFAULT 1 CHECK (anchor_version=1),
    source_handle BINARY(32) NOT NULL,
    target_handle BINARY(32) NOT NULL,
    anchor_handle VARBINARY(32) NOT NULL CHECK (OCTET_LENGTH(anchor_handle) IN (0,32)),
    cost BIGINT NOT NULL CHECK (cost BETWEEN 1 AND 4294967295),
    producer_fence BIGINT NOT NULL CHECK (producer_fence>0),
    PRIMARY KEY (tenant_id,run_id,source_handle,target_handle,anchor_handle),
    CONSTRAINT url_graph_edges_source_fk FOREIGN KEY (tenant_id,run_id,source_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE,
    CONSTRAINT url_graph_edges_target_fk FOREIGN KEY (tenant_id,run_id,target_handle) REFERENCES url_graph_nodes(tenant_id,run_id,handle) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
CREATE INDEX IF NOT EXISTS url_graph_edges_inverse ON url_graph_edges(tenant_id,run_id,target_handle,source_handle);
