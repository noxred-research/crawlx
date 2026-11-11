-- Archive packaging may shorten source retention, never reset it to a longer run deadline.
CREATE OR REPLACE FUNCTION enforce_archive_retention() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  source_expiry timestamptz;
  custody_expiry timestamptz;
  classification text;
BEGIN
  SELECT r.expires_at INTO source_expiry FROM crawl_runs r
    WHERE r.run_id=NEW.run_id AND r.tenant_id=NEW.tenant_id AND r.retention_mode<>'zdr' FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'durable archive requires a retained tenant-owned source';
  END IF;
  classification := COALESCE(NEW.payload->'custody'->>'sensitivity','content');
  -- Truncate fractional digits before parsing: a timestamp cast alone rounds up.
  custody_expiry := regexp_replace(NEW.payload->'custody'->>'expiresAt',
    '(\.[0-9]{6})[0-9]+','\1')::timestamptz;
  IF classification NOT IN ('content','sensitive')
      OR (classification='sensitive' AND custody_expiry IS NULL) THEN
    RAISE EXCEPTION 'invalid archive byte authority';
  END IF;
  IF TG_OP='UPDATE' THEN
    IF COALESCE(OLD.payload->'custody'->>'sensitivity','content')='sensitive'
        AND classification<>'sensitive' THEN
      RAISE EXCEPTION 'sensitive archive authority cannot become content';
    END IF;
    NEW.expires_at := LEAST(NEW.expires_at,OLD.expires_at,
      regexp_replace(OLD.payload->'custody'->>'expiresAt',
        '(\.[0-9]{6})[0-9]+','\1')::timestamptz);
  END IF;
  NEW.expires_at := LEAST(NEW.expires_at,source_expiry,custody_expiry);
  NEW.payload := jsonb_set(NEW.payload,'{expiresAt}',COALESCE(to_jsonb(NEW.expires_at),'null'::jsonb));
  NEW.payload := jsonb_set(NEW.payload,'{custody}',jsonb_build_object(
    'sensitivity',classification,'expiresAt',NEW.expires_at));
  RETURN NEW;
END $$;

-- Repair any previously copied physical deadline while retaining the narrower JSON authority.
UPDATE archive_exports SET expires_at=expires_at;
