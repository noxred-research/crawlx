-- Typed operational facts; UUIDs are raw bytes, times UTC epoch microseconds.
CREATE TABLE report_history (
    fact_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    fact_id BLOB NOT NULL CHECK (length(fact_id)=32),
    receipt BLOB NOT NULL CHECK (length(receipt)=32),
    kind TEXT NOT NULL CHECK (kind IN ('dns','stage','wire','alert','loss','pipeline')),
    observed_at INTEGER NOT NULL,
    url_key BLOB CHECK (url_key IS NULL OR length(url_key)=32),
    host_key BLOB CHECK (host_key IS NULL OR length(host_key)=32),
    duration_us INTEGER CHECK (duration_us IS NULL OR duration_us>=0),
    wire_bytes INTEGER CHECK (wire_bytes IS NULL OR wire_bytes>=0),
    fact TEXT CHECK (fact IS NULL OR (json_valid(fact) AND json_type(fact)='object' AND length(CAST(fact AS BLOB))<=4096)),
    expires_at INTEGER,
    UNIQUE (tenant_id,run_id,fact_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX report_history_run_keyset ON report_history(tenant_id,run_id,fact_sequence);
CREATE INDEX report_history_tenant_keyset ON report_history(tenant_id,fact_sequence);
