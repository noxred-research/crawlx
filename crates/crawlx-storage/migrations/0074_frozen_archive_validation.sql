-- Final-invariant validation of frozen archive custody, independent of the application.
-- A grant and its outputs may only exist for an export still recording at exactly the granted
-- fence, for a terminal run whose secret epoch and incarnation are unchanged and settled, and
-- an output stays inside the grant's class, deadline, kind and media types. Grants, source
-- proofs and outputs are immutable; they disappear only with their export or run.
CREATE FUNCTION validate_archive_frozen_grant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE valid boolean;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM archive_exports e
          JOIN crawl_runs r ON r.tenant_id=e.tenant_id AND r.run_id=e.run_id
          JOIN run_secret_authority a ON a.tenant_id=e.tenant_id AND a.run_id=e.run_id
         WHERE e.tenant_id=NEW.tenant_id AND e.export_id=NEW.export_id AND e.run_id=NEW.run_id
           AND e.state='recording' AND e.fence=NEW.fence AND e.lease_until>clock_timestamp()
           AND r.status IN ('completed','failed','cancelled') AND r.retention_mode<>'zdr'
           AND r.purge_requested_at IS NULL
           AND a.incarnation=NEW.incarnation AND a.epoch=NEW.secret_epoch
           AND a.pending_operation IS NULL AND a.pending_renewal_operation IS NULL
           AND (NEW.expires_at IS NULL OR NEW.expires_at>clock_timestamp())
    ) INTO valid;
    IF NOT valid THEN
        RAISE EXCEPTION 'frozen archive grant requires a recording export of a terminal run at its closed epoch';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER archive_frozen_grant_validate BEFORE INSERT ON archive_frozen_grants
  FOR EACH ROW EXECUTE FUNCTION validate_archive_frozen_grant();

CREATE FUNCTION validate_archive_frozen_output() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE valid boolean;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM archive_frozen_grants g
          JOIN archive_exports e ON e.tenant_id=g.tenant_id AND e.export_id=g.export_id
          JOIN crawl_runs r ON r.tenant_id=g.tenant_id AND r.run_id=g.run_id
          JOIN run_secret_authority a ON a.tenant_id=g.tenant_id AND a.run_id=g.run_id
         WHERE g.tenant_id=NEW.tenant_id AND g.export_id=NEW.export_id AND g.binding=NEW.binding
           AND g.run_id=NEW.run_id AND e.run_id=g.run_id
           AND e.state='recording' AND e.fence=g.fence AND e.lease_until>clock_timestamp()
           AND r.status IN ('completed','failed','cancelled') AND r.retention_mode<>'zdr'
           AND r.purge_requested_at IS NULL
           AND a.incarnation=g.incarnation AND a.epoch=g.secret_epoch
           AND a.pending_operation IS NULL AND a.pending_renewal_operation IS NULL
           AND NEW.incarnation=g.incarnation AND NEW.secret_epoch=g.secret_epoch
           AND NEW.sensitivity=g.sensitivity
           AND (g.expires_at IS NULL OR (NEW.expires_at IS NOT NULL AND NEW.expires_at<=g.expires_at))
    ) INTO valid;
    IF NOT valid THEN
        RAISE EXCEPTION 'frozen archive output requires a live grant of its claimed export';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER archive_frozen_output_validate BEFORE INSERT ON archive_frozen_outputs
  FOR EACH ROW EXECUTE FUNCTION validate_archive_frozen_output();

CREATE FUNCTION retain_archive_frozen_custody() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'frozen archive custody is immutable';
END $$;
CREATE TRIGGER archive_frozen_grant_immutable BEFORE UPDATE ON archive_frozen_grants
  FOR EACH ROW EXECUTE FUNCTION retain_archive_frozen_custody();
CREATE TRIGGER archive_frozen_source_immutable BEFORE UPDATE ON archive_frozen_sources
  FOR EACH ROW EXECUTE FUNCTION retain_archive_frozen_custody();
CREATE TRIGGER archive_frozen_output_immutable BEFORE UPDATE ON archive_frozen_outputs
  FOR EACH ROW EXECUTE FUNCTION retain_archive_frozen_custody();

-- Restricted-search-path callers (terminal revocation) must resolve relations in the
-- installation schema, never the caller's path.
DO $migration$
BEGIN
    EXECUTE format(
        'ALTER FUNCTION %I.validate_archive_frozen_grant() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
    EXECUTE format(
        'ALTER FUNCTION %I.validate_archive_frozen_output() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
    EXECUTE format(
        'ALTER FUNCTION %I.retain_archive_frozen_custody() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema()
    );
END
$migration$;
