-- Reuse workers.capacity; no response content, target URLs, secrets, or profiles are stored here.
-- API request roles read this narrow fixed projection, never an owner connection or raw workers.
DO $$
BEGIN
  EXECUTE format($function$
    CREATE FUNCTION crawlx_live_acquisition_workers(max_age_ms bigint)
    RETURNS TABLE (worker_id uuid, last_heartbeat_at timestamptz, capabilities jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $body$
      SELECT w.worker_id, w.last_heartbeat_at, w.capacity -> 'acquisition'
      FROM %I.workers w
      WHERE NOT w.draining
        AND w.capacity -> 'acceptsQueued' = 'true'::jsonb
        AND max_age_ms > 0
        AND w.last_heartbeat_at >= now() - (LEAST(max_age_ms, 90000) * interval '1 millisecond')
        AND w.last_heartbeat_at <= now()
        AND CASE WHEN jsonb_typeof(w.capacity -> 'acquisition') = 'array'
          THEN jsonb_array_length(w.capacity -> 'acquisition') BETWEEN 1 AND 4
          ELSE false END
        AND octet_length((w.capacity -> 'acquisition')::text) <= 65536
      ORDER BY w.worker_id
      LIMIT 257
    $body$
  $function$, current_schema());
  EXECUTE format($function$
    CREATE FUNCTION crawlx_eligible_acquisition_worker(required_backend_ids text[], max_age_ms bigint)
    RETURNS TABLE (worker_id uuid, last_heartbeat_at timestamptz, capabilities jsonb)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $body$
      SELECT w.worker_id, w.last_heartbeat_at, w.capacity -> 'acquisition'
      FROM %I.workers w
      WHERE NOT w.draining
        AND w.capacity -> 'acceptsQueued' = 'true'::jsonb
        AND max_age_ms > 0
        AND cardinality(required_backend_ids) BETWEEN 1 AND 4
        AND NOT EXISTS (SELECT 1 FROM unnest(required_backend_ids) r(id)
          WHERE r.id NOT IN ('native_http', 'native_browser') OR r.id IS NULL)
        AND w.last_heartbeat_at >= now() - (LEAST(max_age_ms, 90000) * interval '1 millisecond')
        AND w.last_heartbeat_at <= now()
        AND octet_length((w.capacity -> 'acquisition')::text) <= 65536
        AND NOT EXISTS (
          SELECT 1 FROM unnest(required_backend_ids) r(id)
          WHERE NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(
              CASE WHEN jsonb_typeof(w.capacity -> 'acquisition') = 'array'
                THEN w.capacity -> 'acquisition' ELSE '[]'::jsonb END
            ) capability
            WHERE capability ->> 'backendId' = r.id
              AND capability -> 'available' = 'true'::jsonb
          )
        )
      ORDER BY w.worker_id
      LIMIT 1
    $body$
  $function$, current_schema());
END $$;
REVOKE ALL ON FUNCTION crawlx_live_acquisition_workers(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION crawlx_eligible_acquisition_worker(text[], bigint) FROM PUBLIC;
-- As with the existing authentication/audit projections, schema USAGE plus EXECUTE grants
-- only bounded structural facts. Hostnames, configuration and worker mutation remain hidden.
