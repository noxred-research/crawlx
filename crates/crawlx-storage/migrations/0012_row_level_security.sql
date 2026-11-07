-- crawlx-storage 0012: row-level security on crawl_runs and every run-scoped table.
--
-- Model. The API role runs every request in a transaction that first executes
-- `SET LOCAL app.tenant_id = '<tenant uuid>'`. `crawl_runs` is filtered by that setting;
-- every table with a `run_id` is filtered through its run (the subquery on `crawl_runs`
-- is itself subject to the `crawl_runs` policy), and the tables that carry a `tenant_id`
-- of their own (`artifacts`, `audit_events`, `idempotency_keys`) compare it directly so
-- rows without a run stay scoped too.
--
-- Who is filtered. PostgreSQL applies policies to every role except superusers, roles with
-- BYPASSRLS and — unless FORCE ROW LEVEL SECURITY is set — the table owner. This migration
-- deliberately does NOT set FORCE: the owner is the migration/worker role, and the worker
-- serves runs of every tenant from one connection pool without a tenant setting (its
-- authority is the lease), so forcing the policy on the owner would make
-- every worker query return nothing. The API role is a separate, non-owner login in
-- production (separate roles for API, worker and admin), so the policies
-- bind it. The storage test `row_level_security_isolates_two_tenants` therefore switches
-- to a non-owner role (`SET ROLE crawlx_rls_test`) to observe the filtering, because the
-- test database user owns the tables.
--
-- Unset setting. `current_setting('app.tenant_id', true)` is NULL when the GUC was never
-- set and '' after a RESET; `crawlx_current_tenant()` maps both to NULL so a non-owner
-- role without a tenant sees no rows at all (fail closed) instead of a cast error.
--
-- Views. `run_errors` and `trusted_reachable_states` run with the caller's privileges
-- (security_invoker) so the policies apply through them as well.
--
-- Partitions. `traffic_events` is range-partitioned; a query through the parent uses the
-- parent's policy. The default partition gets its own policy here and
-- `retention::ensure_traffic_partitions` does the same for every monthly partition it
-- creates, so direct partition access is filtered too.

CREATE FUNCTION crawlx_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  RETURN NULLIF(current_setting('app.tenant_id', true), '')::uuid;

ALTER TABLE crawl_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON crawl_runs USING (tenant_id = crawlx_current_tenant());

-- Tables keyed by tenant_id directly (run_id is nullable on them).
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON artifacts USING (tenant_id = crawlx_current_tenant());
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_events USING (tenant_id = crawlx_current_tenant());
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON idempotency_keys USING (tenant_id = crawlx_current_tenant());

-- Run-scoped tables: visible when their run is (migrations 0003-0010), plus every
-- traffic_events partition that already exists.
DO $$
DECLARE
  t text;
BEGIN
  FOR t IN
    SELECT unnest(ARRAY[
      'crawl_sessions', 'url_frontier', 'pages',
      'states', 'state_clusters', 'elements', 'action_contexts', 'safety_decisions', 'model_decisions', 'actions',
      'network_epochs', 'traffic_events', 'transitions', 'enablement_edges', 'approvals',
      'checkpoints', 'workflow_runs', 'crawl_events', 'webhook_deliveries',
      'origin_leases',
      'identity_aliases'])
    UNION ALL
    SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
      WHERE i.inhparent = 'traffic_events'::regclass
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = %I.run_id))',
      t, t);
  END LOOP;
END $$;

ALTER VIEW run_errors SET (security_invoker = true);
ALTER VIEW trusted_reachable_states SET (security_invoker = true);
