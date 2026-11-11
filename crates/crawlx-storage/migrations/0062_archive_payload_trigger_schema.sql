-- Terminal checkpoint revocation runs with a restricted search_path. Archive
-- artifact invalidation and its nested source-maintenance trigger must resolve
-- relations in their installation schema, not inherit the caller's search_path.
DO $migration$
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.invalidate_archive_payload_artifact() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
    EXECUTE format(
        'ALTER FUNCTION %I.maintain_archive_payload_sources() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
END
$migration$;
