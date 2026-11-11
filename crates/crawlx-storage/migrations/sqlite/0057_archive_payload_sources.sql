DROP INDEX archive_dependency_sources;
ALTER TABLE archive_dependencies RENAME TO archive_dependencies_previous;
CREATE TABLE archive_dependencies (
    tenant_id BLOB NOT NULL,
    export_id BLOB NOT NULL,
    ordinal INTEGER NOT NULL,
    source_export BLOB NOT NULL,
    source_ordinal INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,export_id,ordinal),
    CHECK (export_id <> source_export OR source_ordinal < ordinal),
    FOREIGN KEY (tenant_id,export_id,ordinal) REFERENCES archive_records (tenant_id,export_id,ordinal) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,source_export,source_ordinal) REFERENCES archive_records (tenant_id,export_id,ordinal) ON DELETE CASCADE
) STRICT;
INSERT INTO archive_dependencies SELECT tenant_id,export_id,ordinal,source_export,source_ordinal FROM archive_dependencies_previous;
DROP TABLE archive_dependencies_previous;
CREATE INDEX archive_dependency_sources ON archive_dependencies (tenant_id,source_export);
ALTER TABLE archive_exports ADD COLUMN package_artifact_id BLOB GENERATED ALWAYS AS (unhex(replace(json_extract(payload,'$.artifact.id'),'-',''))) VIRTUAL;
ALTER TABLE archive_exports ADD COLUMN index_artifact_id BLOB GENERATED ALWAYS AS (unhex(replace(json_extract(payload,'$.index.id'),'-',''))) VIRTUAL;
CREATE INDEX archive_export_package_authority ON archive_exports (tenant_id,package_artifact_id);
CREATE INDEX archive_export_index_authority ON archive_exports (tenant_id,index_artifact_id);

-- Content-bearing committed source index; legacy rows receive no authority backfill.
CREATE TABLE archive_payload_sources (
    tenant_id BLOB NOT NULL,
    export_id BLOB NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    payload_digest TEXT NOT NULL CHECK (length(payload_digest)=71),
    identity_key BLOB NOT NULL CHECK (length(identity_key)=32),
    published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0,1)),
    package_artifact_id BLOB,
    expires_at INTEGER,
    PRIMARY KEY (tenant_id,export_id,ordinal),
    FOREIGN KEY (tenant_id,export_id,ordinal) REFERENCES archive_records (tenant_id,export_id,ordinal) ON DELETE CASCADE
) STRICT;
CREATE INDEX archive_payload_local ON archive_payload_sources (tenant_id,export_id,payload_digest,identity_key,ordinal);
CREATE INDEX archive_payload_published ON archive_payload_sources (tenant_id,payload_digest,identity_key,published,expires_at,export_id,ordinal);
CREATE INDEX archive_payload_packages ON archive_payload_sources (tenant_id,package_artifact_id);
CREATE TRIGGER archive_payload_source_state AFTER UPDATE OF state,expires_at,payload ON archive_exports
WHEN NEW.state IS NOT OLD.state OR NEW.expires_at IS NOT OLD.expires_at
    OR json_extract(NEW.payload,'$.custody.sensitivity') IS NOT json_extract(OLD.payload,'$.custody.sensitivity')
    OR json_extract(NEW.payload,'$.config.dedupe') IS NOT json_extract(OLD.payload,'$.config.dedupe')
    OR json_extract(NEW.payload,'$.artifact') IS NOT json_extract(OLD.payload,'$.artifact')
BEGIN
    DELETE FROM archive_payload_sources WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id
        AND (NEW.state IN ('failed','deleted') OR json_extract(NEW.payload,'$.custody.sensitivity')='sensitive'
            OR (NEW.state='published' AND COALESCE(json_extract(NEW.payload,'$.config.dedupe'),'none')<>'tenant')
            OR (OLD.state='published' AND json_extract(NEW.payload,'$.artifact') IS NOT json_extract(OLD.payload,'$.artifact')));
    UPDATE archive_payload_sources SET published=(NEW.state='published'),
        package_artifact_id=CASE WHEN NEW.state='published' THEN NEW.package_artifact_id ELSE NULL END,
        expires_at=CASE WHEN NEW.expires_at IS NULL THEN expires_at
            WHEN expires_at IS NULL THEN NEW.expires_at ELSE min(expires_at,NEW.expires_at) END
        WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
END;

CREATE TRIGGER archive_payload_artifact_update AFTER UPDATE OF sensitivity,expires_at,deleted_at,content_digest,tenant_id,run_id,content_type,size_bytes ON artifacts
WHEN NEW.sensitivity IS NOT OLD.sensitivity OR NEW.expires_at IS NOT OLD.expires_at
    OR NEW.deleted_at IS NOT OLD.deleted_at OR NEW.content_digest IS NOT OLD.content_digest
    OR NEW.tenant_id IS NOT OLD.tenant_id OR NEW.run_id IS NOT OLD.run_id
    OR NEW.content_type IS NOT OLD.content_type OR NEW.size_bytes IS NOT OLD.size_bytes
BEGIN
    UPDATE archive_exports SET state='deleted',fence=fence+1,
        payload=json_set(payload,'$.state','deleted','$.manifest',NULL)
        WHERE tenant_id=OLD.tenant_id AND state<>'deleted' AND export_id IN (
            WITH RECURSIVE affected(id) AS (
                SELECT export_id FROM archive_exports WHERE tenant_id=OLD.tenant_id
                    AND (package_artifact_id=OLD.artifact_id OR index_artifact_id=OLD.artifact_id)
                UNION SELECT d.export_id FROM archive_dependencies d JOIN affected a ON d.source_export=a.id
                    WHERE d.tenant_id=OLD.tenant_id
            ) SELECT id FROM affected
        );
    DELETE FROM archive_payload_sources WHERE tenant_id=OLD.tenant_id AND package_artifact_id=OLD.artifact_id;
END;
CREATE TRIGGER archive_payload_artifact_delete AFTER DELETE ON artifacts
BEGIN
    UPDATE archive_exports SET state='deleted',fence=fence+1,
        payload=json_set(payload,'$.state','deleted','$.manifest',NULL)
        WHERE tenant_id=OLD.tenant_id AND state<>'deleted' AND export_id IN (
            WITH RECURSIVE affected(id) AS (
                SELECT export_id FROM archive_exports WHERE tenant_id=OLD.tenant_id
                    AND (package_artifact_id=OLD.artifact_id OR index_artifact_id=OLD.artifact_id)
                UNION SELECT d.export_id FROM archive_dependencies d JOIN affected a ON d.source_export=a.id
                    WHERE d.tenant_id=OLD.tenant_id
            ) SELECT id FROM affected
        );
    DELETE FROM archive_payload_sources WHERE tenant_id=OLD.tenant_id AND package_artifact_id=OLD.artifact_id;
END;
