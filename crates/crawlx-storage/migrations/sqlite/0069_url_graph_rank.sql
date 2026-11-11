-- Versioned bounded rank cache. Invalidated on graph/policy/model changes.
CREATE TABLE url_graph_ranks (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    version INTEGER NOT NULL CHECK (version=1),
    revision INTEGER NOT NULL CHECK (revision>=0),
    result TEXT NOT NULL CHECK (json_valid(result) AND json_type(result)='object' AND length(CAST(result AS BLOB))<=262144),
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES url_graph_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
