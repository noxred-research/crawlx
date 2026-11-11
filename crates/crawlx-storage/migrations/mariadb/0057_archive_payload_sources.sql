ALTER TABLE archive_dependencies DROP CONSTRAINT IF EXISTS archive_dependencies_distinct_export;
ALTER TABLE archive_dependencies DROP CONSTRAINT IF EXISTS archive_dependencies_acyclic,
    ADD CONSTRAINT archive_dependencies_acyclic CHECK (export_id <> source_export OR source_ordinal < ordinal);
ALTER TABLE archive_exports
    ADD COLUMN IF NOT EXISTS package_artifact_id BINARY(16) GENERATED ALWAYS AS (UNHEX(REPLACE(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.artifact.id')),'-',''))) PERSISTENT,
    ADD COLUMN IF NOT EXISTS index_artifact_id BINARY(16) GENERATED ALWAYS AS (UNHEX(REPLACE(JSON_UNQUOTE(JSON_EXTRACT(payload,'$.index.id')),'-',''))) PERSISTENT,
    ADD INDEX IF NOT EXISTS archive_export_package_authority (tenant_id,package_artifact_id),
    ADD INDEX IF NOT EXISTS archive_export_index_authority (tenant_id,index_artifact_id);

-- new: content-bearing committed source index; legacy rows receive no authority backfill.
CREATE TABLE IF NOT EXISTS archive_payload_sources (
    tenant_id BINARY(16) NOT NULL,
    export_id BINARY(16) NOT NULL,
    ordinal BIGINT NOT NULL CHECK (ordinal >= 0),
    payload_digest VARCHAR(71) CHARACTER SET ascii COLLATE ascii_bin NOT NULL CHECK (CHAR_LENGTH(payload_digest)=71),
    identity_key BINARY(32) NOT NULL,
    published BOOLEAN NOT NULL DEFAULT false,
    package_artifact_id BINARY(16) NULL,
    expires_at DATETIME(6) NULL,
    PRIMARY KEY (tenant_id,export_id,ordinal),
    KEY archive_payload_local (tenant_id,export_id,payload_digest,identity_key,ordinal),
    KEY archive_payload_published (tenant_id,payload_digest,identity_key,published,expires_at,export_id,ordinal),
    KEY archive_payload_packages (tenant_id,package_artifact_id),
    CONSTRAINT archive_payload_record_fk FOREIGN KEY (tenant_id,export_id,ordinal)
        REFERENCES archive_records (tenant_id,export_id,ordinal) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;

CREATE OR REPLACE TRIGGER archive_payload_source_state AFTER UPDATE ON archive_exports FOR EACH ROW
BEGIN
    IF NOT (NEW.state <=> OLD.state) OR NOT (NEW.expires_at <=> OLD.expires_at)
        OR NOT (JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.sensitivity')) <=> JSON_UNQUOTE(JSON_EXTRACT(OLD.payload,'$.custody.sensitivity')))
        OR NOT (JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.config.dedupe')) <=> JSON_UNQUOTE(JSON_EXTRACT(OLD.payload,'$.config.dedupe')))
        OR NOT (JSON_EXTRACT(NEW.payload,'$.artifact') <=> JSON_EXTRACT(OLD.payload,'$.artifact')) THEN
        IF NEW.state IN ('failed','deleted') OR JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.sensitivity'))='sensitive'
            OR (NEW.state='published' AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.config.dedupe')),'none')<>'tenant')
            OR (OLD.state='published' AND NOT (JSON_EXTRACT(NEW.payload,'$.artifact') <=> JSON_EXTRACT(OLD.payload,'$.artifact'))) THEN
            DELETE FROM archive_payload_sources WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
        ELSE
            UPDATE archive_payload_sources SET published=(NEW.state='published'),
                package_artifact_id=CASE WHEN NEW.state='published' THEN NEW.package_artifact_id ELSE NULL END,
                expires_at=CASE WHEN NEW.expires_at IS NULL THEN expires_at
                    WHEN expires_at IS NULL THEN NEW.expires_at ELSE LEAST(expires_at,NEW.expires_at) END
                WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
        END IF;
    END IF;
END;

CREATE OR REPLACE TRIGGER archive_payload_artifact_update AFTER UPDATE ON artifacts FOR EACH ROW
BEGIN
    IF NOT (NEW.sensitivity <=> OLD.sensitivity) OR NOT (NEW.expires_at <=> OLD.expires_at)
        OR NOT (NEW.deleted_at <=> OLD.deleted_at) OR NOT (NEW.content_digest <=> OLD.content_digest)
        OR NOT (NEW.tenant_id <=> OLD.tenant_id) OR NOT (NEW.run_id <=> OLD.run_id)
        OR NOT (NEW.content_type <=> OLD.content_type) OR NOT (NEW.size_bytes <=> OLD.size_bytes) THEN
        UPDATE archive_exports SET state='deleted',fence=fence+1,
            payload=JSON_SET(payload,'$.state','deleted','$.manifest',NULL)
            WHERE tenant_id=OLD.tenant_id AND state<>'deleted' AND export_id IN (
                WITH RECURSIVE affected(id) AS (
                    SELECT export_id FROM archive_exports WHERE tenant_id=OLD.tenant_id
                        AND (package_artifact_id=OLD.artifact_id OR index_artifact_id=OLD.artifact_id)
                    UNION SELECT d.export_id FROM archive_dependencies d JOIN affected a ON d.source_export=a.id
                        WHERE d.tenant_id=OLD.tenant_id
                ) SELECT id FROM affected
            );
        DELETE FROM archive_payload_sources WHERE tenant_id=OLD.tenant_id AND package_artifact_id=OLD.artifact_id;
    END IF;
END;
CREATE OR REPLACE TRIGGER archive_payload_artifact_delete AFTER DELETE ON artifacts FOR EACH ROW
BEGIN
    UPDATE archive_exports SET state='deleted',fence=fence+1,
        payload=JSON_SET(payload,'$.state','deleted','$.manifest',NULL)
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
