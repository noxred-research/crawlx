-- Request pipeline checkpoints share the original fenced result transaction.
CREATE TABLE request_pipeline_history (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    request_id INTEGER NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt>0),
    progress TEXT NOT NULL CHECK (json_valid(progress) AND json_type(progress)='object' AND length(CAST(progress AS BLOB))<=4096),
    source_fact TEXT NOT NULL CHECK (json_valid(source_fact) AND json_type(source_fact)='object' AND length(CAST(source_fact AS BLOB))<=4096),
    expires_at INTEGER,
    PRIMARY KEY (tenant_id,run_id,request_id,attempt),
    FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
) STRICT;
