-- A sealed secret authority refuses every new catalog and key custody row. The single narrow
-- exception is an INSERT that exactly matches an `archive_frozen_outputs` row, which is itself
-- validated by a trigger against a live frozen archive grant. The seal is never reopened, no
-- raw key row can be updated, and sealed catalog identity and retention stay immutable.
CREATE OR REPLACE FUNCTION fence_sealed_artifact_catalog() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE sealed timestamptz; previous_seal timestamptz; granted boolean := false;
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
        IF TG_OP='INSERT' THEN
            IF TG_TABLE_NAME='artifacts' THEN
                EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.archive_frozen_outputs o WHERE o.tenant_id=$1 AND o.artifact_id=$2 AND o.run_id=$3 AND o.kind=$4 AND o.bucket=$5 AND o.object_key=$6 AND o.size_bytes=$7 AND o.content_digest=$8 AND o.content_type=$9 AND o.sensitivity=$10 AND o.created_at=$11 AND o.expires_at IS NOT DISTINCT FROM $12)',TG_TABLE_SCHEMA)
                  INTO granted USING NEW.tenant_id,NEW.artifact_id,NEW.run_id,NEW.kind,NEW.bucket,NEW.object_key,
                    NEW.size_bytes,NEW.content_digest,NEW.content_type,NEW.sensitivity::text,NEW.created_at,NEW.expires_at;
            ELSIF TG_TABLE_NAME='artifact_key_custody' THEN
                EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.archive_frozen_outputs o WHERE o.tenant_id=$1 AND o.artifact_id=$2 AND o.run_id=$3 AND o.incarnation=$4 AND o.secret_epoch=$5 AND o.object_key=$6 AND o.content_digest=$7 AND o.size_bytes=$8 AND o.ciphertext_digest=$9 AND o.ciphertext_size=$10 AND o.created_at=$11)',TG_TABLE_SCHEMA)
                  INTO granted USING NEW.tenant_id,NEW.artifact_id,NEW.run_id,NEW.incarnation,NEW.secret_epoch,NEW.object_key,
                    NEW.plaintext_digest,NEW.plaintext_size,NEW.ciphertext_digest,NEW.ciphertext_size,NEW.created_at;
            END IF;
            IF granted THEN
                RETURN NEW;
            END IF;
        END IF;
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
