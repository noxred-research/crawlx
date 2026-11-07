-- Checkpoint terminal revocation runs with a restricted search_path. Resolve the
-- authority table from the actual trigger relation, never the caller's path.
CREATE OR REPLACE FUNCTION fence_sealed_artifact_catalog() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE sealed timestamptz; previous_seal timestamptz;
BEGIN
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('crawlx/secret-authority/v1:' || NEW.tenant_id::text || ':' || NEW.run_id::text,0));
    IF TG_OP='UPDATE' THEN
        PERFORM pg_advisory_xact_lock_shared(hashtextextended('crawlx/secret-authority/v1:' || OLD.tenant_id::text || ':' || OLD.run_id::text,0));
    END IF;
    EXECUTE format('SELECT sealed_at FROM %I.run_secret_authority WHERE tenant_id=$1 AND run_id=$2 FOR SHARE',TG_TABLE_SCHEMA)
      INTO sealed USING NEW.tenant_id,NEW.run_id;
    IF TG_OP='UPDATE' THEN
        EXECUTE format('SELECT sealed_at FROM %I.run_secret_authority WHERE tenant_id=$1 AND run_id=$2 FOR SHARE',TG_TABLE_SCHEMA)
          INTO previous_seal USING OLD.tenant_id,OLD.run_id;
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
