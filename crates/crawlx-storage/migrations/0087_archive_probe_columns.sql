-- Archive catalog statements stop probing the JSON payloads. The probed fields become
-- columns: the write path fills the record and history columns from the typed value, the
-- export column is generated from its payload. The same columns exist on every engine.
-- The tables keep FORCE ROW LEVEL SECURITY for application logins; the back-fill runs as the
-- owner without that clause so it sees every tenant's rows.
ALTER TABLE archive_records NO FORCE ROW LEVEL SECURITY;
ALTER TABLE archive_history NO FORCE ROW LEVEL SECURITY;

ALTER TABLE archive_records
    ADD COLUMN custody_sensitivity text NOT NULL DEFAULT 'content',
    ADD COLUMN source_artifact_id uuid,
    ADD COLUMN source_mime text,
    ADD COLUMN source_digest bytea,
    ADD COLUMN custody_expires_at timestamptz;
-- Truncate fractional digits before parsing: a timestamp cast alone rounds up.
UPDATE archive_records SET
    custody_sensitivity = COALESCE(payload->'custody'->>'sensitivity', 'content'),
    source_artifact_id = (payload->'sourceArtifact'->>'id')::uuid,
    source_mime = payload->>'mime',
    source_digest = decode(payload->'sourceArtifact'->>'digest', 'hex'),
    custody_expires_at = regexp_replace(payload->'custody'->>'expiresAt', '(\.[0-9]{6})[0-9]+', '\1')::timestamptz;

ALTER TABLE archive_history ADD COLUMN has_validator boolean NOT NULL DEFAULT false;
UPDATE archive_history SET has_validator =
    (payload->>'etag' IS NOT NULL OR payload->>'lastModified' IS NOT NULL);

ALTER TABLE archive_records FORCE ROW LEVEL SECURITY;
ALTER TABLE archive_history FORCE ROW LEVEL SECURITY;

ALTER TABLE archive_exports
    ADD COLUMN custody_sensitivity text
    GENERATED ALWAYS AS (COALESCE(payload->'custody'->>'sensitivity', 'content')) STORED;
