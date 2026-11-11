-- Hash-only run metadata is ZDR-safe. UUIDs are raw bytes; times are UTC epoch microseconds.
CREATE TABLE content_digest_registry (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest)=32),
    stage TEXT NOT NULL CHECK (stage IN ('content','main')),
    digest BLOB NOT NULL CHECK (length(digest)=32),
    first_frontier_id INTEGER NOT NULL CHECK (first_frontier_id>0),
    committed_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,run_id,scope_digest,stage,digest),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
ALTER TABLE url_frontier ADD COLUMN content_dedupe_outcome TEXT
    CHECK (content_dedupe_outcome IS NULL OR
        (json_valid(content_dedupe_outcome) AND json_type(content_dedupe_outcome)='object' AND length(CAST(content_dedupe_outcome AS BLOB))<=4096));
