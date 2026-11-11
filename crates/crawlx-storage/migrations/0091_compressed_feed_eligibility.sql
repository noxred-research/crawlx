-- crawlx-storage 0091: a run whose feed compresses its bytes is only eligible on a worker that
-- published explicit compressed-byte support for that destination. Migration 0034's predicate
-- compared destination presence and ZDR allowance only, so a compressed feed bound for a sink
-- that rejects compressed bytes (queue, stream, search) was leased by a worker that then failed
-- on it. Requirements without `compressedDestinations` (older runs) keep their old meaning.
DO $$ BEGIN
  EXECUTE format($definition$
    CREATE OR REPLACE FUNCTION crawlx_worker_data_eligible(worker uuid, requirements jsonb) RETURNS boolean
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
          AND jsonb_typeof(COALESCE(requirements->'compressedDestinations','[]'))='array'
          AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(requirements->'compressedDestinations','[]')) c
            WHERE jsonb_typeof(c)<>'string'
              OR NOT (COALESCE(w.capacity->'data'->'compressedDestinations','[]') @> jsonb_build_array(c)))
          AND (requirements->'languageBundle' IS NULL OR requirements->'languageBundle'='null'::jsonb
            OR (requirements->>'languageBundle' ~ '^[0-9a-f]{64}$'
              AND COALESCE(w.capacity->'data'->'languageBundles','[]') ? (requirements->>'languageBundle')))
      ) END
    $body$
  $definition$,current_schema());
END $$;
