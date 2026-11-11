-- Archive catalog statements stop probing the JSON payloads. The probed fields become
-- columns: the write path fills the record and history columns from the typed value, the
-- export column is generated from its payload (JSON_VALUE of a plain scalar). Idempotent.
ALTER TABLE archive_records
    ADD COLUMN IF NOT EXISTS custody_sensitivity VARCHAR(16) NOT NULL DEFAULT 'content',
    ADD COLUMN IF NOT EXISTS source_artifact_id BINARY(16) NULL,
    ADD COLUMN IF NOT EXISTS source_mime VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS source_digest VARBINARY(64) NULL,
    ADD COLUMN IF NOT EXISTS custody_expires_at DATETIME(6) NULL;
-- Fractional digits beyond microseconds are cut off, never rounded.
UPDATE archive_records SET
    custody_sensitivity = COALESCE(JSON_VALUE(payload, '$.custody.sensitivity'), 'content'),
    source_artifact_id = UNHEX(REPLACE(JSON_VALUE(payload, '$.sourceArtifact.id'), '-', '')),
    source_mime = JSON_VALUE(payload, '$.mime'),
    source_digest = UNHEX(JSON_VALUE(payload, '$.sourceArtifact.digest')),
    custody_expires_at = CAST(SUBSTRING(REPLACE(REPLACE(JSON_VALUE(payload, '$.custody.expiresAt'), 'T', ' '), 'Z', ''), 1, 26) AS DATETIME(6));

ALTER TABLE archive_history
    ADD COLUMN IF NOT EXISTS has_validator TINYINT(1) NOT NULL DEFAULT 0;
UPDATE archive_history SET has_validator =
    (JSON_VALUE(payload, '$.etag') IS NOT NULL OR JSON_VALUE(payload, '$.lastModified') IS NOT NULL);

ALTER TABLE archive_exports
    ADD COLUMN IF NOT EXISTS custody_sensitivity VARCHAR(16)
    AS (COALESCE(JSON_VALUE(payload, '$.custody.sensitivity'), 'content')) VIRTUAL;
