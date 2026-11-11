-- Same-export references point backward by event ordinal and cannot form a record cycle.
ALTER TABLE archive_dependencies DROP CONSTRAINT archive_dependencies_check;
ALTER TABLE archive_dependencies ADD CONSTRAINT archive_dependencies_acyclic
    CHECK (export_id <> source_export OR source_ordinal < ordinal);
ALTER TABLE archive_exports
    ADD COLUMN package_artifact_id uuid GENERATED ALWAYS AS ((payload->'artifact'->>'id')::uuid) STORED,
    ADD COLUMN index_artifact_id uuid GENERATED ALWAYS AS ((payload->'index'->>'id')::uuid) STORED;
CREATE INDEX archive_export_package_authority ON archive_exports (tenant_id,package_artifact_id);
CREATE INDEX archive_export_index_authority ON archive_exports (tenant_id,index_artifact_id);

-- Only newly committed approved standalone payloads enter this content-bearing index.
-- Legacy descriptors receive no speculative authority or payload-history backfill.
CREATE TABLE archive_payload_sources (
    tenant_id uuid NOT NULL,
    export_id uuid NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    payload_digest text NOT NULL CHECK (length(payload_digest)=71),
    identity_key bytea NOT NULL CHECK (octet_length(identity_key)=32),
    published boolean NOT NULL DEFAULT false,
    package_artifact_id uuid,
    expires_at timestamptz,
    PRIMARY KEY (tenant_id,export_id,ordinal),
    FOREIGN KEY (tenant_id,export_id,ordinal) REFERENCES archive_records ON DELETE CASCADE
);
CREATE INDEX archive_payload_local ON archive_payload_sources (tenant_id,export_id,payload_digest,identity_key,ordinal);
CREATE INDEX archive_payload_published ON archive_payload_sources (tenant_id,payload_digest,identity_key,published,expires_at,export_id,ordinal);
CREATE INDEX archive_payload_packages ON archive_payload_sources (tenant_id,package_artifact_id);
ALTER TABLE archive_payload_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE archive_payload_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON archive_payload_sources
    USING (tenant_id=current_setting('app.tenant_id',true)::uuid)
    WITH CHECK (tenant_id=current_setting('app.tenant_id',true)::uuid);

CREATE FUNCTION maintain_archive_payload_sources() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Counter/lease writes must remain constant-time rather than rewriting every source row.
    IF NEW.state IS NOT DISTINCT FROM OLD.state AND NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at
        AND (NEW.payload->'custody'->>'sensitivity') IS NOT DISTINCT FROM (OLD.payload->'custody'->>'sensitivity')
        AND (NEW.payload->'config'->>'dedupe') IS NOT DISTINCT FROM (OLD.payload->'config'->>'dedupe')
        AND (NEW.payload->'artifact') IS NOT DISTINCT FROM (OLD.payload->'artifact') THEN
        RETURN NEW;
    END IF;
    IF NEW.state IN ('failed','deleted') OR NEW.payload->'custody'->>'sensitivity'='sensitive'
        OR (NEW.state='published' AND NEW.payload->'config'->>'dedupe' IS DISTINCT FROM 'tenant')
        OR (OLD.state='published' AND (NEW.payload->'artifact') IS DISTINCT FROM (OLD.payload->'artifact')) THEN
        DELETE FROM archive_payload_sources WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
    ELSE
        UPDATE archive_payload_sources SET published=(NEW.state='published'),
            package_artifact_id=CASE WHEN NEW.state='published' THEN NEW.package_artifact_id ELSE NULL END,
            expires_at=CASE WHEN NEW.expires_at IS NULL THEN expires_at
                WHEN expires_at IS NULL THEN NEW.expires_at ELSE LEAST(expires_at,NEW.expires_at) END
            WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER archive_payload_source_state AFTER UPDATE OF state,expires_at,payload ON archive_exports
    FOR EACH ROW EXECUTE FUNCTION maintain_archive_payload_sources();

CREATE FUNCTION invalidate_archive_payload_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' THEN
        IF NEW.sensitivity IS NOT DISTINCT FROM OLD.sensitivity AND NEW.expires_at IS NOT DISTINCT FROM OLD.expires_at
            AND NEW.deleted_at IS NOT DISTINCT FROM OLD.deleted_at AND NEW.content_digest IS NOT DISTINCT FROM OLD.content_digest
            AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id AND NEW.run_id IS NOT DISTINCT FROM OLD.run_id
            AND NEW.content_type IS NOT DISTINCT FROM OLD.content_type AND NEW.size_bytes IS NOT DISTINCT FROM OLD.size_bytes THEN
            RETURN NEW;
        END IF;
    END IF;
    UPDATE archive_exports SET state='deleted',fence=fence+1,
        payload=jsonb_set(jsonb_set(payload,'{state}','"deleted"'),'{manifest}','null')
        WHERE tenant_id=OLD.tenant_id AND state<>'deleted' AND export_id IN (
            WITH RECURSIVE affected(id) AS (
                SELECT export_id FROM archive_exports WHERE tenant_id=OLD.tenant_id
                    AND (package_artifact_id=OLD.artifact_id OR index_artifact_id=OLD.artifact_id)
                UNION SELECT d.export_id FROM archive_dependencies d JOIN affected a ON d.source_export=a.id
                    WHERE d.tenant_id=OLD.tenant_id
            ) SELECT id FROM affected
        );
    DELETE FROM archive_payload_sources WHERE tenant_id=OLD.tenant_id AND package_artifact_id=OLD.artifact_id;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER archive_payload_artifact_update AFTER UPDATE OF sensitivity,expires_at,deleted_at,content_digest,tenant_id,run_id,content_type,size_bytes ON artifacts
    FOR EACH ROW EXECUTE FUNCTION invalidate_archive_payload_artifact();
CREATE TRIGGER archive_payload_artifact_delete AFTER DELETE ON artifacts
    FOR EACH ROW EXECUTE FUNCTION invalidate_archive_payload_artifact();
