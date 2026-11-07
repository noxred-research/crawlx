-- Independent safety observer. Neither capability can execute browser work.
-- Provision separate LOGIN members of these NOLOGIN roles; never grant both to one login.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'crawlx_safety_reader') THEN
    CREATE ROLE crawlx_safety_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'crawlx_safety_pauser') THEN
    CREATE ROLE crawlx_safety_pauser NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;

-- Owner-executed view deliberately crosses tenant RLS without exposing bodies, credentials,
-- or raw evidence. A single statement sees a single committed MVCC snapshot. Proposed rows
-- (including pending approvals) are not evidence of execution. Unknown/reconciled rows retain
-- their actual intent time; their uncertain outcome is never itself a safety violation.
CREATE VIEW safety_auditor_actions AS
SELECT r.tenant_id, a.run_id, a.action_id,
  CASE
    WHEN a.intended_at IS NULL THEN 'missing_intent_timestamp'
    WHEN d.decision_id IS NULL OR d.run_id <> a.run_id OR d.action_id IS DISTINCT FROM a.action_id
      OR d.session_id IS DISTINCT FROM a.session_id OR s.run_id <> a.run_id
      OR c.run_id <> a.run_id THEN 'decision_link_mismatch'
    WHEN d.profile <> r.safety_profile OR d.policy_version <> r.policy_version
      OR d.authorization_record_id IS DISTINCT FROM r.authorization_record_id
      OR d.decided_at > a.intended_at THEN 'decision_context_mismatch'
    WHEN a.hold <> 'none' OR d.verdict = 'deny' THEN 'denied_action_intended'
    WHEN d.risk_class = 'out_of_scope'
      OR (r.safety_profile = 'read_only' AND d.risk_class NOT IN ('navigation_reveal','reversible_local_preference'))
      OR (d.risk_class = 'financial_transaction' AND r.safety_profile <> 'authorized_security_test')
      OR (d.risk_class = 'security_change' AND r.safety_profile <> 'authorized_security_test')
      OR (d.risk_class = 'destructive' AND COALESCE(r.config->'safety'->>'destructiveActions', 'deny') <> 'approval')
      OR (d.risk_class = 'file_upload' AND a.action_kind <> 'upload')
      OR d.rules && ARRAY['sink.required_unverified','record.class_not_permitted','upload.fixture_required','option.destructive_actions.deny']::text[]
      THEN 'hard_deny_class_intended'
    WHEN (r.safety_profile = 'authorized_security_test' OR r.authorization_record_id IS NOT NULL)
      AND (z.record_id IS NULL OR z.tenant_id <> r.tenant_id
        OR z.valid_from > a.intended_at OR z.valid_to <= a.intended_at
        OR z.revoked_at <= a.intended_at
        OR r.authorization_body_digest IS DISTINCT FROM z.body_digest)
      THEN 'authorization_invalid_at_intent'
    WHEN z.record_id IS NOT NULL AND
      ((r.safety_profile <> 'read_only' AND COALESCE(z.body->>'profileCap','read_only') = 'read_only')
        OR (r.safety_profile = 'authorized_security_test' AND z.body->>'profileCap' IS DISTINCT FROM 'authorized_security_test'))
      THEN 'authorization_profile_exceeded'
    WHEN z.record_id IS NOT NULL AND d.risk_class NOT IN ('navigation_reveal','reversible_local_preference')
      AND NOT COALESCE((z.body->'permittedRiskClasses') ? d.risk_class::text, false)
      THEN 'authorization_class_not_permitted'
    WHEN d.risk_class = 'external_communication' AND
      (COALESCE(r.config->'safety'->>'externalCommunication', 'deny') <> 'test_sinks'
        OR z.record_id IS NULL OR z.verified_at IS NULL OR z.verified_at > a.intended_at
        OR z.valid_from > a.intended_at OR z.valid_to <= a.intended_at OR z.revoked_at <= a.intended_at
        OR jsonb_typeof(z.body->'testSinks') IS DISTINCT FROM 'object'
        OR NOT EXISTS (SELECT 1 FROM jsonb_each_text(
          CASE WHEN jsonb_typeof(z.body->'testSinks') = 'object' THEN z.body->'testSinks' ELSE '{}'::jsonb END
        ) sink WHERE sink.key IN ('email','sms','webhook') AND length(sink.value) > 0))
      THEN 'verified_sink_missing_at_intent'
    WHEN (d.verdict = 'approval_required' OR d.risk_class IN ('destructive','financial_transaction','security_change')
      OR (d.risk_class = 'persistent_write_other_principal' AND r.safety_profile = 'test_environment')
      OR COALESCE((z.body->'approvalRequired') ? d.risk_class::text, false))
      AND NOT EXISTS (SELECT 1 FROM approvals p
        WHERE p.action_id = a.action_id AND p.run_id = a.run_id AND p.safety_decision_id = d.decision_id
          AND p.risk_class = d.risk_class AND p.decision = 'approved'
          AND p.decided_at <= a.intended_at AND p.expires_at > a.intended_at
          AND p.consumed_at <= a.intended_at)
      THEN 'approval_missing_at_intent'
    ELSE NULL
  END AS reason
FROM actions a
JOIN crawl_runs r ON r.run_id = a.run_id
JOIN crawl_sessions s ON s.session_id = a.session_id
JOIN action_contexts c ON c.context_id = a.context_id
LEFT JOIN safety_decisions d ON d.decision_id = a.safety_decision_id
LEFT JOIN authorization_records z ON z.record_id = r.authorization_record_id
WHERE a.status <> 'proposed';
REVOKE ALL ON safety_auditor_actions FROM PUBLIC;
GRANT SELECT ON safety_auditor_actions TO crawlx_safety_reader;
DO $$ BEGIN
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO crawlx_safety_reader, crawlx_safety_pauser', current_schema());
END $$;

-- Keep the existing BLAKE3 hash-chain format in Rust. The pause transaction locks the
-- same chain head as retention::append_audit and supplies the next canonical entry hash.
DO $migration$
BEGIN
EXECUTE format($function$
CREATE FUNCTION safety_auditor_chain_head() RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE head bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('crawlx_audit_chain'));
  SELECT entry_hash INTO head FROM %1$I.audit_events ORDER BY audit_id DESC LIMIT 1;
  RETURN COALESCE(head, decode(repeat('00',32),'hex'));
END $body$
$function$, current_schema());
END $migration$;
REVOKE ALL ON FUNCTION safety_auditor_chain_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION safety_auditor_chain_head() TO crawlx_safety_pauser;

-- Only a still-observable invariant violation can pause its own run. No arbitrary run
-- selector, resume, approval, action mutation, or unverified caller-supplied reason exists.
DO $migration$
BEGIN
EXECUTE format($function$
CREATE FUNCTION safety_auditor_pause(target uuid, violation text, previous bytea, next_hash bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE hit record; next_seq bigint; head bytea;
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
  INSERT INTO %1$I.crawl_events(run_id, seq, type, payload)
    VALUES(hit.run_id, next_seq, 'paused', jsonb_build_object('by','safety_auditor','action',target,'reason',violation));
  INSERT INTO %1$I.audit_events(tenant_id, run_id, actor, event, subject, prev_hash, entry_hash)
    VALUES(hit.tenant_id, hit.run_id, 'safety_auditor', 'safety.invariant_violation',
      jsonb_build_object('action',target,'reason',violation), previous, next_hash);
  RETURN true;
END $body$
$function$, current_schema());
END $migration$;
REVOKE ALL ON FUNCTION safety_auditor_pause(uuid,text,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION safety_auditor_pause(uuid,text,bytea,bytea) TO crawlx_safety_pauser;
