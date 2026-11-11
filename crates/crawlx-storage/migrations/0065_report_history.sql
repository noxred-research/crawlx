-- Typed operational facts contain no diagnostic text, addresses, URLs or payloads.
CREATE TABLE report_history (
    fact_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    fact_id bytea NOT NULL CHECK (octet_length(fact_id)=32),
    receipt bytea NOT NULL CHECK (octet_length(receipt)=32),
    kind text NOT NULL CHECK (kind IN ('dns','stage','wire','alert','loss','pipeline')),
    observed_at timestamptz NOT NULL,
    url_key bytea CHECK (url_key IS NULL OR octet_length(url_key)=32),
    host_key bytea CHECK (host_key IS NULL OR octet_length(host_key)=32),
    duration_us bigint CHECK (duration_us IS NULL OR duration_us>=0),
    wire_bytes bigint CHECK (wire_bytes IS NULL OR wire_bytes>=0),
    fact jsonb CHECK (fact IS NULL OR (jsonb_typeof(fact)='object' AND octet_length(fact::text)<=4096)),
    expires_at timestamptz,
    UNIQUE (tenant_id,run_id,fact_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE report_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON report_history
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);
CREATE INDEX report_history_run_keyset ON report_history(tenant_id,run_id,fact_sequence);
CREATE INDEX report_history_tenant_keyset ON report_history(tenant_id,fact_sequence);
