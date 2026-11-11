-- Terminal archive custody. A terminal run has permanently closed secret registration, so its
-- archive export is sealed under a durable, secret-free grant instead of a live registry
-- snapshot. The grant binds the exact claimed export fence, the closed secret epoch and
-- incarnation, the aggregate retained class and deadline, and every source artifact proof.
-- No raw secret, commitment or registry value is stored; rows remain valid after the volatile
-- registry expires and are removed with the export or run.
CREATE TABLE archive_frozen_grants (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    export_id uuid NOT NULL,
    -- Domain-separated digest of every bound field; identity of this exact grant.
    binding bytea NOT NULL CHECK (octet_length(binding)=32),
    fence bigint NOT NULL CHECK (fence>0),
    incarnation uuid NOT NULL CHECK (incarnation<>'00000000-0000-0000-0000-000000000000'::uuid),
    secret_epoch bigint NOT NULL CHECK (secret_epoch>0 AND secret_epoch<9007199254740000),
    sensitivity text NOT NULL CHECK (sensitivity IN ('content','sensitive')),
    expires_at timestamptz,
    source_count integer NOT NULL CHECK (source_count BETWEEN 1 AND 20000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (sensitivity<>'sensitive' OR expires_at IS NOT NULL),
    PRIMARY KEY (tenant_id,export_id,binding),
    FOREIGN KEY (tenant_id,export_id) REFERENCES archive_exports(tenant_id,export_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE archive_frozen_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON archive_frozen_grants
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- Exact source proofs. No foreign key to artifacts: a deleted or changed source must make the
-- grant fail closed at publication, never silently delete the proof.
CREATE TABLE archive_frozen_sources (
    tenant_id uuid NOT NULL,
    export_id uuid NOT NULL,
    binding bytea NOT NULL,
    artifact_id uuid NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    sensitivity text NOT NULL CHECK (sensitivity IN ('content','sensitive')),
    expires_at timestamptz,
    CHECK (sensitivity<>'sensitive' OR expires_at IS NOT NULL),
    PRIMARY KEY (tenant_id,export_id,binding,artifact_id),
    FOREIGN KEY (tenant_id,export_id,binding) REFERENCES archive_frozen_grants(tenant_id,export_id,binding) ON DELETE CASCADE
);
CREATE INDEX archive_frozen_source_artifact ON archive_frozen_sources (tenant_id,artifact_id);
ALTER TABLE archive_frozen_sources ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON archive_frozen_sources
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- Exact output identity validated against a live grant. This row, not a flag on the sealed
-- authority, is what lets one catalog row and one key custody row be inserted after the
-- authority seal; see the catalog fence and the validation trigger of later migrations.
CREATE TABLE archive_frozen_outputs (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    export_id uuid NOT NULL,
    binding bytea NOT NULL,
    artifact_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind='evidence'),
    bucket text NOT NULL,
    object_key text NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes>=0),
    content_digest bytea NOT NULL CHECK (octet_length(content_digest)=32),
    content_type text NOT NULL CHECK (content_type IN ('application/warc','application/wacz+zip','application/cdxj')),
    sensitivity text NOT NULL CHECK (sensitivity IN ('content','sensitive')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    incarnation uuid NOT NULL,
    secret_epoch bigint NOT NULL CHECK (secret_epoch>0),
    ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest)=32),
    ciphertext_size bigint NOT NULL CHECK (ciphertext_size>0),
    CHECK (sensitivity<>'sensitive' OR expires_at IS NOT NULL),
    PRIMARY KEY (tenant_id,artifact_id),
    FOREIGN KEY (tenant_id,export_id,binding) REFERENCES archive_frozen_grants(tenant_id,export_id,binding) ON DELETE CASCADE
);
CREATE INDEX archive_frozen_output_export ON archive_frozen_outputs (tenant_id,export_id,binding);
ALTER TABLE archive_frozen_outputs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON archive_frozen_outputs
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());
