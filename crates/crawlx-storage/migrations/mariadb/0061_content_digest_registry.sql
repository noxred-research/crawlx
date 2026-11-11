-- Hash-only run metadata is ZDR-safe. UUIDs are BINARY(16); times are UTC DATETIME(6).
-- from: 0061 first successful page-commit content/main registry, erased with owning run.
CREATE TABLE IF NOT EXISTS content_digest_registry (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    scope_digest BINARY(32) NOT NULL,
    stage VARCHAR(7) NOT NULL CHECK (stage IN ('content','main')),
    digest BINARY(32) NOT NULL,
    first_frontier_id BIGINT NOT NULL CHECK (first_frontier_id>0),
    committed_at DATETIME(6) NOT NULL,
    PRIMARY KEY (tenant_id,run_id,scope_digest,stage,digest),
    CONSTRAINT content_digest_registry_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
ALTER TABLE url_frontier ADD COLUMN IF NOT EXISTS content_dedupe_outcome LONGTEXT
    CHECK (content_dedupe_outcome IS NULL OR
        (JSON_VALID(content_dedupe_outcome) AND JSON_TYPE(content_dedupe_outcome)='OBJECT' AND OCTET_LENGTH(content_dedupe_outcome)<=4096));
