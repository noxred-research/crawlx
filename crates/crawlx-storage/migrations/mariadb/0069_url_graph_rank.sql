-- Bounded versioned rank cache, invalidated on graph/policy/model changes.
-- from: 0069 current-revision rank cache, deleted on graph/policy/model change.
CREATE TABLE IF NOT EXISTS url_graph_ranks (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    version INTEGER NOT NULL CHECK (version=1),
    revision BIGINT NOT NULL CHECK (revision>=0),
    result LONGTEXT NOT NULL CHECK (JSON_VALID(result) AND JSON_TYPE(result)='OBJECT' AND OCTET_LENGTH(result)<=262144),
    PRIMARY KEY (tenant_id,run_id),
    CONSTRAINT url_graph_ranks_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
