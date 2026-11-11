-- Worker eligibility accepts the operator-registered HTML acquisition service as a required backend.
-- Clean cutover of the 0034 definition: the only change is the added 'acquisition_service' id; the
-- capability probe, freshness window, size bounds and data-requirement check are unchanged.
DROP FUNCTION crawlx_eligible_data_worker(text[],jsonb,bigint);
DO $$ BEGIN
  EXECUTE format($definition$
    CREATE FUNCTION crawlx_eligible_data_worker(required_backend_ids text[],requirements jsonb,max_age_ms bigint)
    RETURNS TABLE(worker_id uuid,last_heartbeat_at timestamptz,capabilities jsonb,data_capabilities jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
      SELECT w.worker_id,w.last_heartbeat_at,w.capacity->'acquisition',COALESCE(w.capacity->'data','{}')
      FROM %I.workers w WHERE NOT w.draining AND w.capacity->'acceptsQueued'='true'::jsonb
        AND max_age_ms>0 AND w.last_heartbeat_at BETWEEN now()-(LEAST(max_age_ms,90000)*interval '1 millisecond') AND now()
        AND cardinality(required_backend_ids) BETWEEN 0 AND 4
        AND NOT EXISTS(SELECT 1 FROM unnest(required_backend_ids) r(id) WHERE r.id IS NULL OR r.id NOT IN ('native_http','native_browser','acquisition_service'))
        AND octet_length(w.capacity::text)<=98304
        AND NOT EXISTS(SELECT 1 FROM unnest(required_backend_ids) r(id) WHERE NOT EXISTS(
          SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.capacity->'acquisition')='array' THEN w.capacity->'acquisition' ELSE '[]' END) capability
          WHERE capability->>'backendId'=r.id AND capability->'available'='true'::jsonb))
        AND %I.crawlx_worker_data_eligible(w.worker_id,requirements)
      ORDER BY w.worker_id LIMIT 1
    $body$
  $definition$,current_schema(),current_schema());
END $$;
REVOKE ALL ON FUNCTION crawlx_eligible_data_worker(text[],jsonb,bigint) FROM PUBLIC;
