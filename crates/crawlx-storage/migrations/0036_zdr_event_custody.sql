-- SQL-authored safety events have no volatile original. Authenticate this narrow
-- custody exception with the canonical audit row, never by event kind or missing bytes.
-- Authorized run purges delete webhook deliveries, then events, while retaining
-- canonical audit history. Custody must not create a second audit-erasure path.
ALTER TABLE crawl_events ADD COLUMN metadata_only_audit_id bigint
  REFERENCES audit_events(audit_id);
CREATE UNIQUE INDEX crawl_events_metadata_only_audit ON crawl_events(metadata_only_audit_id)
  WHERE metadata_only_audit_id IS NOT NULL;

-- Existing rows qualify only when one canonical audit entry matches the exact
-- transaction timestamp and privacy-projected payload. Ambiguous history stays closed.
WITH matches AS (
  SELECT e.run_id, e.seq, min(a.audit_id) AS audit_id
  FROM crawl_events e
  JOIN crawl_runs r ON r.run_id = e.run_id
  JOIN audit_events a ON a.run_id = e.run_id AND a.occurred_at = e.created_at
    AND a.actor = 'safety_auditor' AND a.event = 'safety.invariant_violation'
  WHERE e.type = 'paused' AND jsonb_typeof(a.subject->'action') = 'string'
    AND jsonb_typeof(a.subject->'reason') = 'string'
    AND e.payload = CASE WHEN r.retention_mode = 'zdr' THEN
      zdr_json_digest(jsonb_build_object('by','safety_auditor',
        'action',a.subject->'action','reason',a.subject->'reason'))
      ELSE jsonb_build_object('by','safety_auditor',
        'action',a.subject->'action','reason',a.subject->'reason') END
  GROUP BY e.run_id, e.seq HAVING count(*) = 1
), unambiguous AS (
  SELECT * FROM matches m WHERE NOT EXISTS (
    SELECT 1 FROM matches other WHERE other.audit_id = m.audit_id
      AND (other.run_id, other.seq) <> (m.run_id, m.seq))
)
UPDATE crawl_events e SET metadata_only_audit_id = m.audit_id
FROM unambiguous m WHERE e.run_id = m.run_id AND e.seq = m.seq;

CREATE FUNCTION enforce_event_custody() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE trusted_owner oid;
BEGIN
  IF NEW.metadata_only_audit_id IS NULL THEN
    IF TG_OP = 'UPDATE' AND OLD.metadata_only_audit_id IS NOT NULL THEN
      RAISE EXCEPTION 'authenticated event custody cannot be removed';
    END IF;
    RETURN NEW;
  END IF;
  SELECT proowner INTO trusted_owner FROM pg_proc
    WHERE oid = 'safety_auditor_pause(uuid,text,bytea,bytea)'::regprocedure;
  IF current_user::regrole::oid IS DISTINCT FROM trusted_owner THEN
    RAISE EXCEPTION 'authenticated event custody requires safety auditor ownership';
  END IF;
  IF NEW.type <> 'paused' OR NOT EXISTS (
    SELECT 1 FROM audit_events a JOIN crawl_runs r ON r.run_id = a.run_id
    WHERE a.audit_id = NEW.metadata_only_audit_id AND a.run_id = NEW.run_id
      AND a.actor = 'safety_auditor' AND a.event = 'safety.invariant_violation'
      AND a.occurred_at = NEW.created_at
      AND jsonb_typeof(a.subject->'action') = 'string'
      AND jsonb_typeof(a.subject->'reason') = 'string'
      AND NEW.payload = CASE WHEN r.retention_mode = 'zdr' THEN
        zdr_json_digest(jsonb_build_object('by','safety_auditor',
          'action',a.subject->'action','reason',a.subject->'reason'))
        ELSE jsonb_build_object('by','safety_auditor',
          'action',a.subject->'action','reason',a.subject->'reason') END
  ) THEN
    RAISE EXCEPTION 'authenticated event custody does not match safety audit';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.run_id, NEW.seq, NEW.metadata_only_audit_id)
    IS DISTINCT FROM (OLD.run_id, OLD.seq, OLD.metadata_only_audit_id) THEN
    RAISE EXCEPTION 'authenticated event custody cannot be reassigned';
  END IF;
  RETURN NEW;
END $$;
DO $$ BEGIN
  EXECUTE format('ALTER FUNCTION %I.enforce_event_custody() SET search_path = pg_catalog, %I, pg_temp',
    current_schema(), current_schema());
END $$;
-- PostgreSQL orders same-timing triggers by name. Validate the final privacy projection.
CREATE TRIGGER zz_event_custody BEFORE INSERT OR UPDATE ON crawl_events
  FOR EACH ROW EXECUTE FUNCTION enforce_event_custody();

DO $migration$
BEGIN
EXECUTE format($function$
CREATE OR REPLACE FUNCTION safety_auditor_pause(target uuid, violation text, previous bytea, next_hash bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE hit record; next_seq bigint; head bytea; custody bigint;
BEGIN
  head := %1$I.safety_auditor_chain_head();
  IF head IS DISTINCT FROM previous OR octet_length(next_hash) <> 32 OR next_hash IS NULL THEN
    RAISE EXCEPTION 'safety auditor audit chain changed or invalid hash';
  END IF;
  SELECT tenant_id, run_id, action_id, reason INTO hit FROM %1$I.safety_auditor_actions
    WHERE action_id = target AND reason = violation;
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE %1$I.crawl_runs SET status = 'paused', pause_requested_at = now(), event_seq = event_seq + 1
    WHERE run_id = hit.run_id AND status IN ('queued','running','pausing') RETURNING event_seq INTO next_seq;
  IF NOT FOUND THEN RETURN false; END IF;
  INSERT INTO %1$I.audit_events(tenant_id, run_id, actor, event, subject, prev_hash, entry_hash)
    VALUES(hit.tenant_id, hit.run_id, 'safety_auditor', 'safety.invariant_violation',
      jsonb_build_object('action',target,'reason',violation), previous, next_hash)
    RETURNING audit_id INTO custody;
  INSERT INTO %1$I.crawl_events(run_id, seq, type, payload, metadata_only_audit_id)
    VALUES(hit.run_id, next_seq, 'paused',
      jsonb_build_object('by','safety_auditor','action',target,'reason',violation), custody);
  RETURN true;
END $body$
$function$, current_schema());
END $migration$;
REVOKE ALL ON FUNCTION safety_auditor_pause(uuid,text,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION safety_auditor_pause(uuid,text,bytea,bytea) TO crawlx_safety_pauser;
