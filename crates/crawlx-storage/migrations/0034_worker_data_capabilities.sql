-- Structural run requirements survive volatile config expiry; never contain endpoints or secrets.
ALTER TABLE crawl_runs ADD COLUMN data_requirements jsonb NOT NULL DEFAULT '{}';
DO $$ BEGIN
  EXECUTE format($definition$
    CREATE FUNCTION crawlx_worker_data_eligible(worker uuid, requirements jsonb) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
      SELECT CASE WHEN COALESCE(requirements,'{}') = '{}'::jsonb OR
        (jsonb_typeof(requirements)='object' AND requirements->'destinations'='{}'::jsonb
          AND (requirements->'languageBundle' IS NULL OR requirements->'languageBundle'='null'::jsonb))
      THEN true ELSE EXISTS (
        SELECT 1 FROM %I.workers w WHERE w.worker_id=worker AND NOT w.draining
          AND w.last_heartbeat_at BETWEEN now()-interval '90 seconds' AND now()
          AND jsonb_typeof(requirements)='object' AND octet_length(requirements::text)<=16384
          AND jsonb_typeof(COALESCE(requirements->'destinations','{}'))='object'
          AND NOT EXISTS (SELECT 1 FROM jsonb_each(CASE WHEN jsonb_typeof(requirements->'destinations')='object' THEN requirements->'destinations' ELSE '{}' END) r
            WHERE r.key !~ '^[A-Za-z0-9_.-]{1,128}$' OR r.value NOT IN ('true'::jsonb,'false'::jsonb)
              OR NOT (COALESCE(w.capacity->'data'->'destinations','{}') ? r.key)
              OR (r.value='true'::jsonb AND w.capacity->'data'->'destinations'->r.key IS DISTINCT FROM 'true'::jsonb))
          AND (requirements->'languageBundle' IS NULL OR requirements->'languageBundle'='null'::jsonb
            OR (requirements->>'languageBundle' ~ '^[0-9a-f]{64}$'
              AND COALESCE(w.capacity->'data'->'languageBundles','[]') ? (requirements->>'languageBundle')))
      ) END
    $body$
  $definition$,current_schema());
  EXECUTE format($definition$
    CREATE FUNCTION crawlx_live_data_workers(max_age_ms bigint)
    RETURNS TABLE(worker_id uuid,last_heartbeat_at timestamptz,capabilities jsonb,data_capabilities jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
      SELECT w.worker_id,w.last_heartbeat_at,w.capacity->'acquisition',COALESCE(w.capacity->'data','{}')
      FROM %I.workers w WHERE NOT w.draining AND w.capacity->'acceptsQueued'='true'::jsonb
        AND max_age_ms>0 AND w.last_heartbeat_at BETWEEN now()-(LEAST(max_age_ms,90000)*interval '1 millisecond') AND now()
        AND CASE WHEN jsonb_typeof(w.capacity->'acquisition')='array' THEN jsonb_array_length(w.capacity->'acquisition') BETWEEN 1 AND 4 ELSE false END
        AND octet_length(w.capacity::text)<=98304 ORDER BY w.worker_id LIMIT 257
    $body$
  $definition$,current_schema());
  EXECUTE format($definition$
    CREATE FUNCTION crawlx_eligible_data_worker(required_backend_ids text[],requirements jsonb,max_age_ms bigint)
    RETURNS TABLE(worker_id uuid,last_heartbeat_at timestamptz,capabilities jsonb,data_capabilities jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
      SELECT w.worker_id,w.last_heartbeat_at,w.capacity->'acquisition',COALESCE(w.capacity->'data','{}')
      FROM %I.workers w WHERE NOT w.draining AND w.capacity->'acceptsQueued'='true'::jsonb
        AND max_age_ms>0 AND w.last_heartbeat_at BETWEEN now()-(LEAST(max_age_ms,90000)*interval '1 millisecond') AND now()
        AND cardinality(required_backend_ids) BETWEEN 0 AND 4
        AND NOT EXISTS(SELECT 1 FROM unnest(required_backend_ids) r(id) WHERE r.id IS NULL OR r.id NOT IN ('native_http','native_browser'))
        AND octet_length(w.capacity::text)<=98304
        AND NOT EXISTS(SELECT 1 FROM unnest(required_backend_ids) r(id) WHERE NOT EXISTS(
          SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.capacity->'acquisition')='array' THEN w.capacity->'acquisition' ELSE '[]' END) capability
          WHERE capability->>'backendId'=r.id AND capability->'available'='true'::jsonb))
        AND %I.crawlx_worker_data_eligible(w.worker_id,requirements)
      ORDER BY w.worker_id LIMIT 1
    $body$
  $definition$,current_schema(),current_schema());
END $$;
REVOKE ALL ON FUNCTION crawlx_worker_data_eligible(uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION crawlx_live_data_workers(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION crawlx_eligible_data_worker(text[],jsonb,bigint) FROM PUBLIC;
DROP FUNCTION crawlx_live_acquisition_workers(bigint);
DROP FUNCTION crawlx_eligible_acquisition_worker(text[],bigint);
