-- Atomic HEAD observations retain an immutable replay receipt beside the terminal fence.
-- Observation payloads remain in event custody, including volatile zero-retention storage.
ALTER TABLE url_frontier ADD COLUMN head_response_receipt bytea
  CHECK (head_response_receipt IS NULL OR octet_length(head_response_receipt) = 32);

-- HEAD custody is a closed structural request reference, not a digest of response content.
-- Keep the original projection for every other event, including audited safety events.
CREATE FUNCTION enforce_event_confidentiality() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  is_zdr boolean;
  request_id bigint;
BEGIN
  SELECT retention_mode = 'zdr' INTO is_zdr FROM crawl_runs WHERE run_id = NEW.run_id;
  IF NOT COALESCE(is_zdr, false) THEN RETURN NEW; END IF;
  IF NEW.type = 'head_response' THEN
    IF jsonb_typeof(NEW.payload->'requestId') IS DISTINCT FROM 'number'
      OR NEW.payload->>'requestId' !~ '^[1-9][0-9]{0,18}$' THEN
      RAISE EXCEPTION 'invalid volatile HEAD response request reference';
    END IF;
    request_id := (NEW.payload->>'requestId')::bigint;
    IF NEW.payload IS DISTINCT FROM
        jsonb_build_object('volatileHeadResponse', true, 'requestId', request_id)
      OR NOT EXISTS (
        SELECT 1 FROM url_frontier f
        WHERE f.frontier_id = request_id AND f.run_id = NEW.run_id
      ) THEN
      RAISE EXCEPTION 'invalid volatile HEAD response event marker';
    END IF;
  ELSE
    NEW.payload := zdr_json_digest(NEW.payload)
      || CASE WHEN jsonb_typeof(NEW.payload->'pageId') = 'number'
        THEN jsonb_build_object('pageId', NEW.payload->'pageId') ELSE '{}'::jsonb END
      || CASE WHEN jsonb_typeof(NEW.payload->'page_id') = 'number'
        THEN jsonb_build_object('page_id', NEW.payload->'page_id') ELSE '{}'::jsonb END;
  END IF;
  RETURN NEW;
END; $$;

DO $path$
BEGIN
  EXECUTE format(
    'ALTER FUNCTION %I.enforce_event_confidentiality() SET search_path = pg_catalog, %I, pg_temp',
    current_schema(), current_schema());
END;
$path$;

DROP TRIGGER zdr_confidentiality ON crawl_events;
CREATE TRIGGER zdr_confidentiality BEFORE INSERT OR UPDATE ON crawl_events
FOR EACH ROW EXECUTE FUNCTION enforce_event_confidentiality();
