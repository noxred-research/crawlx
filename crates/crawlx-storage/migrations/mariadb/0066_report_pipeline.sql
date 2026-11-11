-- from: 0066 fenced processing and acknowledgement checkpoints.
-- Request pipeline checkpoints share the original fenced result transaction.
CREATE TABLE IF NOT EXISTS request_pipeline_history (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    request_id BIGINT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt>0),
    progress LONGTEXT NOT NULL CHECK (JSON_VALID(progress) AND JSON_TYPE(progress)='OBJECT' AND OCTET_LENGTH(progress)<=4096),
    source_fact LONGTEXT NOT NULL CHECK (JSON_VALID(source_fact) AND JSON_TYPE(source_fact)='OBJECT' AND OCTET_LENGTH(source_fact)<=4096),
    expires_at DATETIME(6),
    PRIMARY KEY (tenant_id,run_id,request_id,attempt),
    CONSTRAINT request_pipeline_history_request_fk FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
