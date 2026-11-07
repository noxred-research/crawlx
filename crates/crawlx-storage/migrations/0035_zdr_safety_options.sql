-- Preserve only non-sensitive safety opt-ins needed by the independent auditor.
-- Earlier ZDR projections discarded these values. Do not reconstruct historical
-- permission from missing data: legacy rows remain fail-closed until a new run.
CREATE OR REPLACE FUNCTION enforce_zdr_run_config() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.retention_mode <> 'zdr' THEN RETURN NEW; END IF;
  IF NEW.config->>'privacy' IS DISTINCT FROM 'zdr' OR NEW.config->'metadata' IS NULL THEN
    RAISE EXCEPTION 'zdr requires metadata-only durable configuration';
  END IF;
  NEW.config := jsonb_build_object(
    'privacy', 'zdr',
    'parallelRolesAllowed', (NEW.config->>'parallelRolesAllowed')::boolean,
    'dynamic', jsonb_build_object('launchProfile',
      CASE WHEN NEW.config->'dynamic'->>'launchProfile' = 'stealth' THEN 'stealth' ELSE 'standard' END),
    'safety', jsonb_build_object(
      'externalCommunication', CASE
        WHEN NEW.config->'safety'->>'externalCommunication' = 'test_sinks' THEN 'test_sinks'
        ELSE 'deny' END,
      'destructiveActions', CASE
        WHEN NEW.config->'safety'->>'destructiveActions' = 'approval' THEN 'approval'
        ELSE 'deny' END),
    'webhookConfigured', (NEW.config->>'webhookConfigured')::boolean,
    'metadata', NEW.config->'metadata'
  );
  NEW.replay_spec := CASE WHEN NEW.replay_spec IS NULL THEN NULL
    ELSE jsonb_build_object('sourceRunId', NEW.replay_spec->'sourceRunId') END;
  RETURN NEW;
END $$;
