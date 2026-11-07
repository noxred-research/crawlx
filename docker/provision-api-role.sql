-- Runs after migrations as the deployment owner. No API request gets this login.
-- psql reads the password from the mounted file, never a process argument.
\set ON_ERROR_STOP on
\set api_password `cat /run/secrets/postgres_api_password`
SELECT format('CREATE ROLE crawlx_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD %L', :'api_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crawlx_api')
\gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM crawlx_api;
GRANT USAGE ON SCHEMA public TO crawlx_api;
-- Reconcile grants on upgrades too: operational worker tables must never retain
-- permissions from an earlier blanket grant.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM crawlx_api;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM crawlx_api;
DO $$
DECLARE
  t record;
  seq text;
  col record;
BEGIN
  FOR t IN SELECT c.oid, c.relname FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relrowsecurity
  LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO crawlx_api', t.relname);
    FOR col IN SELECT attname FROM pg_attribute WHERE attrelid = t.oid AND attnum > 0 AND NOT attisdropped
    LOOP
      seq := pg_get_serial_sequence(format('public.%I', t.relname), col.attname);
      IF seq IS NOT NULL THEN
        EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %s TO crawlx_api', seq);
      END IF;
    END LOOP;
  END LOOP;
END $$;
GRANT SELECT ON public.trusted_reachable_states, public.run_errors TO crawlx_api;
REVOKE UPDATE, DELETE ON public.audit_events FROM crawlx_api;
GRANT EXECUTE ON FUNCTION public.crawlx_current_tenant(), public.crawlx_authenticate_key(text), public.crawlx_audit_head() TO crawlx_api;
-- Migration 0034 replaces the old acquisition-only RPCs with bounded combined worker facts.
-- The private crawlx_worker_data_eligible(uuid,jsonb) predicate stays owner-only.
GRANT EXECUTE ON FUNCTION public.crawlx_live_data_workers(bigint),
  public.crawlx_eligible_data_worker(text[], jsonb, bigint) TO crawlx_api;
