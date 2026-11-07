-- Secret bytes exist only in dedicated nonpersistent Redis. Never backfill or
-- recreate an incarnation after volatile loss. Pending operations deny publish.
-- Match 0012: the migration/table-owner worker serves all tenants without
-- app.tenant_id. Do not FORCE RLS; restricted API roles remain tenant-filtered.
CREATE TABLE run_secret_authority (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch >= 0),
    pending_operation uuid,
    last_operation uuid,
    -- A random salt exists only in Redis. This commitment cannot be used for
    -- offline secret guesses using the durable database alone.
    commitment bytea CHECK (commitment IS NULL OR octet_length(commitment)=32),
    pending_commitment bytea CHECK (pending_commitment IS NULL OR octet_length(pending_commitment)=32),
    -- Exact operation/value binding is independent from the deduplicated set.
    pending_value_commitment bytea CHECK (pending_value_commitment IS NULL OR octet_length(pending_value_commitment)=32),
    last_value_commitment bytea CHECK (last_value_commitment IS NULL OR octet_length(last_value_commitment)=32),
    expires_at timestamptz NOT NULL,
    sealed_at timestamptz,
    CHECK (sealed_at IS NULL OR (epoch>0 AND pending_operation IS NULL AND pending_commitment IS NULL AND pending_value_commitment IS NULL AND commitment IS NOT NULL)),
    PRIMARY KEY (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
ALTER TABLE run_secret_authority ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON run_secret_authority
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- One atomic catalog commit binds ciphertext identity, complete secret epoch and
-- KMS-wrapped key. No plaintext key or secret registry value enters PostgreSQL.
CREATE TABLE artifact_key_custody (
    artifact_id uuid PRIMARY KEY REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    secret_epoch bigint NOT NULL CHECK (secret_epoch > 0),
    object_key text NOT NULL,
    plaintext_digest bytea NOT NULL CHECK (octet_length(plaintext_digest)=32),
    plaintext_size bigint NOT NULL CHECK (plaintext_size>=0),
    ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
    ciphertext_size bigint NOT NULL CHECK (ciphertext_size > 0),
    envelope jsonb NOT NULL CHECK (octet_length(envelope::text) <= 524288),
    artifact_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id,run_id,object_key),
    FOREIGN KEY (tenant_id, run_id) REFERENCES run_secret_authority(tenant_id, run_id) ON DELETE CASCADE
);
ALTER TABLE artifact_key_custody ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON artifact_key_custody
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- OPEN survives process death and unknown outcomes. There is deliberately no
-- expiry column: TTL is not evidence that a producer or plaintext queue is dead.
CREATE TABLE run_artifact_exposures (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    operation uuid NOT NULL,
    artifact_id uuid NOT NULL,
    -- Ciphertext digest for retained content; a volatile-secret-keyed commitment
    -- for ZDR, never an offline-guessable plaintext digest.
    artifact_binding bytea NOT NULL CHECK (octet_length(artifact_binding)=32),
    incarnation uuid NOT NULL,
    secret_epoch bigint NOT NULL CHECK (secret_epoch>0),
    -- Keep a completion tombstone until run purge so an old completion retry
    -- cannot clear a new stream that accidentally reuses the same operation.
    closed_at timestamptz,
    PRIMARY KEY (tenant_id,run_id,operation),
    FOREIGN KEY (tenant_id,run_id) REFERENCES run_secret_authority(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE run_artifact_exposures ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON run_artifact_exposures
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

CREATE TABLE run_custody_producers (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    producer_id uuid NOT NULL,
    owner uuid NOT NULL,
    -- Owned identity sequence is granted by the actual restricted-role provisioner.
    fence bigint GENERATED ALWAYS AS IDENTITY CHECK (fence>0),
    api_key_id uuid NOT NULL REFERENCES api_keys(key_id),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,run_id,producer_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
);
ALTER TABLE run_custody_producers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON run_custody_producers
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());

-- Take the same authority lock for every catalog mutation, including legacy
-- ArtifactIndex callers. A sealed run can only lose content through retention;
-- neither a new raw artifact nor modified catalog identity can bypass its seal.
CREATE FUNCTION fence_sealed_artifact_catalog() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE sealed timestamptz; previous_seal timestamptz;
BEGIN
    -- Unlike a row lock, this also fences inserts before initialization exists.
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('crawlx/secret-authority/v1:' || NEW.tenant_id::text || ':' || NEW.run_id::text,0));
    IF TG_OP='UPDATE' THEN
        PERFORM pg_advisory_xact_lock_shared(hashtextextended('crawlx/secret-authority/v1:' || OLD.tenant_id::text || ':' || OLD.run_id::text,0));
    END IF;
    SELECT sealed_at INTO sealed FROM run_secret_authority
      WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id FOR SHARE;
    IF TG_OP='UPDATE' THEN
        SELECT sealed_at INTO previous_seal FROM run_secret_authority
          WHERE tenant_id=OLD.tenant_id AND run_id=OLD.run_id FOR SHARE;
        sealed := COALESCE(sealed,previous_seal);
    END IF;
    IF sealed IS NOT NULL THEN
        IF TG_TABLE_NAME='artifact_key_custody' OR TG_OP='INSERT' THEN
            RAISE EXCEPTION 'artifact secret authority is permanently sealed';
        END IF;
        IF (NEW.artifact_id,NEW.tenant_id,NEW.run_id,NEW.kind,NEW.bucket,NEW.object_key,
            NEW.size_bytes,NEW.content_digest,NEW.content_type,NEW.sensitivity,NEW.created_at)
          IS DISTINCT FROM
           (OLD.artifact_id,OLD.tenant_id,OLD.run_id,OLD.kind,OLD.bucket,OLD.object_key,
            OLD.size_bytes,OLD.content_digest,OLD.content_type,OLD.sensitivity,OLD.created_at) THEN
            RAISE EXCEPTION 'sealed artifact catalog identity is immutable';
        END IF;
        IF (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
          OR (OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>OLD.expires_at)) THEN
            RAISE EXCEPTION 'sealed artifact retention cannot be extended or revived';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER artifact_catalog_secret_fence BEFORE INSERT OR UPDATE ON artifacts
  FOR EACH ROW EXECUTE FUNCTION fence_sealed_artifact_catalog();
CREATE TRIGGER artifact_key_secret_fence BEFORE INSERT OR UPDATE ON artifact_key_custody
  FOR EACH ROW EXECUTE FUNCTION fence_sealed_artifact_catalog();

CREATE FUNCTION retain_secret_authority_seal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.sealed_at IS NOT NULL THEN
        RAISE EXCEPTION 'artifact secret authority seal is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER secret_authority_seal BEFORE UPDATE ON run_secret_authority
  FOR EACH ROW EXECUTE FUNCTION retain_secret_authority_seal();
