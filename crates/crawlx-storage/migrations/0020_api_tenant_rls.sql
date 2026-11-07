-- crawlx-storage 0020: complete API-role isolation.
-- Owners retain cross-tenant worker/admin authority, as in migration 0012.
-- The API login must be non-owner, NOBYPASSRLS, without schema CREATE. Requests
-- set app.tenant_id transaction-locally; missing settings fail closed.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'tenants', 'api_keys', 'authorization_records',
    'intel_jobs', 'intel_threads', 'monitors', 'monitor_checks',
    'usage_ledger', 'tenant_settings']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = crawlx_current_tenant()) WITH CHECK (tenant_id = crawlx_current_tenant())', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['intel_trace', 'intel_snapshots']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (EXISTS (SELECT 1 FROM intel_jobs j WHERE j.job_id = %I.job_id)) WITH CHECK (EXISTS (SELECT 1 FROM intel_jobs j WHERE j.job_id = %I.job_id))', t, t, t);
  END LOOP;
END $$;
ALTER TABLE monitor_check_pages ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON monitor_check_pages
  USING (EXISTS (SELECT 1 FROM monitor_checks c WHERE c.check_id = monitor_check_pages.check_id))
  WITH CHECK (EXISTS (SELECT 1 FROM monitor_checks c WHERE c.check_id = monitor_check_pages.check_id));
ALTER TABLE monitor_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON monitor_baselines
  USING (EXISTS (SELECT 1 FROM monitors m WHERE m.monitor_id = monitor_baselines.monitor_id))
  WITH CHECK (EXISTS (SELECT 1 FROM monitors m WHERE m.monitor_id = monitor_baselines.monitor_id));

-- Pre-authentication has no tenant yet. Expose exactly one indexed prefix lookup,
-- never an owner connection or an unrestricted api_keys query to request code.
-- Qualify the table at creation and pin search_path: caller-controlled schemas
-- cannot replace objects used by this SECURITY DEFINER function.
DO $$
BEGIN
  EXECUTE format($function$
    CREATE FUNCTION crawlx_authenticate_key(lookup_prefix text)
    RETURNS TABLE (key_id uuid, tenant_id uuid, prefix text, key_hash bytea,
                   scopes text[], expires_at timestamptz, revoked_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $body$
      SELECT k.key_id, k.tenant_id, k.prefix, k.key_hash, k.scopes, k.expires_at, k.revoked_at
      FROM %I.api_keys k WHERE k.prefix = lookup_prefix
    $body$
  $function$, current_schema());
  -- Only the opaque global chain head crosses tenant boundaries. Appenders hold
  -- the existing global advisory transaction lock before reading it.
  EXECUTE format($function$
    CREATE FUNCTION crawlx_audit_head() RETURNS bytea
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    AS $body$
      SELECT entry_hash FROM %I.audit_events ORDER BY audit_id DESC LIMIT 1
    $body$
  $function$, current_schema());
END $$;
-- EXECUTE is intentionally available to logins granted schema USAGE. The function
-- reveals only the single credential verifier requested by prefix, not key text.
-- Grant API DML on application tables/sequences, but never schema CREATE or role
-- membership in an owner/BYPASSRLS role. Revoke audit_events UPDATE/DELETE.
