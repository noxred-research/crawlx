-- from: 0065 typed operational history, with volatile-only payloads for ZDR.
-- Typed operational facts; UUIDs are BINARY(16), times UTC DATETIME(6).
CREATE TABLE IF NOT EXISTS report_history (
    fact_sequence BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    fact_id BINARY(32) NOT NULL,
    receipt BINARY(32) NOT NULL,
    kind VARCHAR(8) NOT NULL CHECK (kind IN ('dns','stage','wire','alert','loss','pipeline')),
    observed_at DATETIME(6) NOT NULL,
    url_key BINARY(32),
    host_key BINARY(32),
    duration_us BIGINT CHECK (duration_us IS NULL OR duration_us>=0),
    wire_bytes BIGINT CHECK (wire_bytes IS NULL OR wire_bytes>=0),
    fact LONGTEXT CHECK (fact IS NULL OR (JSON_VALID(fact) AND JSON_TYPE(fact)='OBJECT' AND OCTET_LENGTH(fact)<=4096)),
    expires_at DATETIME(6),
    UNIQUE (tenant_id,run_id,fact_id),
    CONSTRAINT report_history_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
CREATE INDEX IF NOT EXISTS report_history_run_keyset ON report_history(tenant_id,run_id,fact_sequence);
CREATE INDEX IF NOT EXISTS report_history_tenant_keyset ON report_history(tenant_id,fact_sequence);
