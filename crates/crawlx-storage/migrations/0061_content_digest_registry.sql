-- Hash-only run metadata is permitted in ZDR. No raw text, URL, role or artifact is stored.
CREATE TABLE content_digest_registry (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    scope_digest bytea NOT NULL CHECK (octet_length(scope_digest)=32),
    stage text NOT NULL CHECK (stage IN ('content','main')),
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    first_frontier_id bigint NOT NULL CHECK (first_frontier_id>0),
    committed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,run_id,scope_digest,stage,digest),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE content_digest_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE content_digest_registry FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON content_digest_registry
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
-- Per-frontier receipt cannot overwrite another rendition's evidence.
ALTER TABLE url_frontier ADD COLUMN content_dedupe_outcome jsonb
    CHECK (content_dedupe_outcome IS NULL OR
        (jsonb_typeof(content_dedupe_outcome)='object' AND octet_length(content_dedupe_outcome::text)<=4096));
COMMENT ON TABLE content_digest_registry IS 'Hash-only first successful request commit claims; deleted with owning run';
