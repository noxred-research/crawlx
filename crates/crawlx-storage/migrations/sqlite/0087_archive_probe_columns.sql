-- Archive catalog statements stop probing the JSON payloads. The probed fields become
-- columns: the write path fills the record and history columns from the typed value, the
-- export column is generated from its payload. Deadlines are integer microseconds; fractional
-- JSON digits are truncated, never rounded up.
ALTER TABLE archive_records ADD COLUMN custody_sensitivity TEXT NOT NULL DEFAULT 'content';
ALTER TABLE archive_records ADD COLUMN source_artifact_id BLOB;
ALTER TABLE archive_records ADD COLUMN source_mime TEXT;
ALTER TABLE archive_records ADD COLUMN source_digest BLOB;
ALTER TABLE archive_records ADD COLUMN custody_expires_at INTEGER;
UPDATE archive_records SET
    custody_sensitivity = COALESCE(json_extract(payload, '$.custody.sensitivity'), 'content'),
    source_artifact_id = unhex(replace(json_extract(payload, '$.sourceArtifact.id'), '-', '')),
    source_mime = json_extract(payload, '$.mime'),
    source_digest = unhex(json_extract(payload, '$.sourceArtifact.digest')),
    custody_expires_at = CASE WHEN json_extract(payload, '$.custody.expiresAt') IS NULL THEN NULL ELSE
        CAST(strftime('%s', substr(json_extract(payload, '$.custody.expiresAt'), 1, 19) || 'Z') AS INTEGER) * 1000000
        + CASE WHEN substr(json_extract(payload, '$.custody.expiresAt'), 20, 1) = '.' THEN
            CAST(substr(substr(rtrim(json_extract(payload, '$.custody.expiresAt'), 'Z'), 21) || '000000', 1, 6) AS INTEGER)
          ELSE 0 END
        END;

ALTER TABLE archive_history ADD COLUMN has_validator INTEGER NOT NULL DEFAULT 0 CHECK (has_validator IN (0, 1));
UPDATE archive_history SET has_validator =
    (json_extract(payload, '$.etag') IS NOT NULL OR json_extract(payload, '$.lastModified') IS NOT NULL);

ALTER TABLE archive_exports ADD COLUMN custody_sensitivity TEXT
    GENERATED ALWAYS AS (COALESCE(json_extract(payload, '$.custody.sensitivity'), 'content')) VIRTUAL;
