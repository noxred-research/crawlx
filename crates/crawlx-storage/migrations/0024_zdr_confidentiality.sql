-- ZDR retains identifiers, hashes, counters, timing and risk evidence only.
-- Runtime URLs and documents are carried by the bounded ephemeral delivery transport.
ALTER TABLE url_frontier ALTER COLUMN canonical_url DROP NOT NULL;
ALTER TABLE pages ALTER COLUMN canonical_url DROP NOT NULL;

CREATE FUNCTION zdr_text_hash(value text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT encode(sha256(convert_to(value, 'UTF8')), 'hex')
$$;

CREATE FUNCTION zdr_json_digest(value jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
  SELECT CASE WHEN jsonb_typeof(value) = 'object'
    AND value->>'digest' ~ '^[0-9a-f]{64}$'
    THEN jsonb_build_object('digest', value->>'digest')
    ELSE jsonb_build_object('digest', zdr_text_hash(value::text)) END
$$;

-- Frozen migration pricing for pre-boundary rows; new writes carry the core pricing result.
CREATE FUNCTION zdr_legacy_page_billing(config jsonb, metadata jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  options jsonb := config->'scrape'->'options';
  doc jsonb := metadata->'scrape';
  base numeric := 1;
  credits numeric := 1;
  format jsonb;
BEGIN
  IF options IS NOT NULL AND doc IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(options->'parsers', '[]')) p
      WHERE p->>'type' = 'pdf') THEN
      base := GREATEST(1, COALESCE((doc->>'numPages')::numeric, 1));
    END IF;
    credits := base;
    IF COALESCE((doc->>'statusCode')::int, 0) < 400 THEN
      FOR format IN SELECT * FROM jsonb_array_elements(COALESCE(options->'formats', '[]')) LOOP
        IF format->>'type' IN ('json','question','query','highlights')
          OR (format->>'type' = 'audio' AND doc->'audio' IS NOT NULL AND doc->'audio' <> 'null')
          OR (format->>'type' = 'video' AND doc->'video' IS NOT NULL AND doc->'video' <> 'null') THEN
          credits := credits + 4;
        END IF;
      END LOOP;
      IF COALESCE((doc->>'promptInjectionChecked')::boolean, false) THEN credits := credits + 4; END IF;
      IF COALESCE((doc->>'piiRedacted')::boolean, false) THEN credits := credits + 4 * base; END IF;
      IF COALESCE((options->>'lockdown')::boolean, false) THEN
        IF doc->>'cacheState' = 'hit' THEN credits := credits + 4; END IF;
      ELSE
        credits := credits + 1;
      END IF;
    END IF;
  END IF;
  RETURN jsonb_build_object('credits', credits,
    'llm_tokens', COALESCE((doc->>'llmTokens')::numeric, 0), 'pages', 1);
END $$;

CREATE FUNCTION enforce_zdr_confidentiality() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  is_zdr boolean;
  billing jsonb;
BEGIN
  SELECT retention_mode = 'zdr' INTO is_zdr FROM crawl_runs WHERE run_id = NEW.run_id;
  IF NOT COALESCE(is_zdr, false) THEN RETURN NEW; END IF;
  -- Partition clones report the physical traffic_events_<month> relation name.
  CASE (CASE WHEN TG_TABLE_NAME LIKE 'traffic_events%' THEN 'traffic_events' ELSE TG_TABLE_NAME END)
    WHEN 'url_frontier' THEN
      NEW.canonical_url := NULL;
      IF NEW.origin !~ '^[0-9a-f]{64}$' THEN NEW.origin := zdr_text_hash(NEW.origin); END IF;
      NEW.query_schema := '{}';
      IF NEW.denial_reason IS NOT NULL AND NEW.denial_reason NOT IN
        ('dedupe:fingerprint', 'dedupe:content_exact', 'dedupe:content_similar')
        AND NEW.denial_reason !~ '^[0-9a-f]{64}$' THEN
        NEW.denial_reason := zdr_text_hash(NEW.denial_reason);
      END IF;
      IF NEW.error_code IS NOT NULL AND NEW.error_code NOT IN
        ('dedupe:fingerprint', 'dedupe:content_exact', 'dedupe:content_similar')
        AND NEW.error_code !~ '^[0-9a-f]{64}$' THEN
        NEW.error_code := zdr_text_hash(NEW.error_code);
      END IF;
    WHEN 'pages' THEN
      billing := NEW.metadata->'billing';
      IF billing IS NULL AND TG_OP = 'UPDATE' THEN billing := OLD.metadata->'billing'; END IF;
      IF billing IS NULL THEN
        SELECT zdr_legacy_page_billing(config, NEW.metadata) INTO billing
        FROM crawl_runs WHERE run_id = NEW.run_id;
      END IF;
      NEW.canonical_url := NULL; NEW.final_url := NULL; NEW.content_type := NULL;
      NEW.title := NULL; NEW.url_meta := NULL; NEW.links := NULL;
      NEW.metadata := jsonb_build_object('billing', jsonb_build_object(
        'credits', (billing->>'credits')::numeric,
        'llm_tokens', (billing->>'llm_tokens')::numeric, 'pages', 1));
      NEW.markdown_artifact_id := NULL; NEW.html_artifact_id := NULL; NEW.raw_html_artifact_id := NULL;
      NEW.markdown_digest := NULL; NEW.html_digest := NULL; NEW.observation_epoch := NULL;
    WHEN 'states' THEN
      NEW.observed_url := NULL; NEW.masks := '[]'; NEW.artifacts := '[]'; NEW.manifest_artifact_id := NULL;
    WHEN 'traffic_events' THEN
      NEW.url_redacted := NULL; NEW.request_headers := NULL; NEW.response_headers := NULL;
      NEW.body_artifact_id := NULL; NEW.request_body_artifact_id := NULL;
    WHEN 'safety_decisions' THEN
      NEW.evidence := zdr_json_digest(NEW.evidence);
    WHEN 'model_decisions' THEN
      NEW.output := zdr_json_digest(NEW.output); NEW.io_artifact_id := NULL;
      IF NEW.provider !~ '^[0-9a-f]{64}$' THEN NEW.provider := zdr_text_hash(NEW.provider); END IF;
      IF NEW.model !~ '^[0-9a-f]{64}$' THEN NEW.model := zdr_text_hash(NEW.model); END IF;
      IF NEW.model_version !~ '^[0-9a-f]{64}$' THEN NEW.model_version := zdr_text_hash(NEW.model_version); END IF;
      IF NEW.calibration_version !~ '^[0-9a-f]{64}$' THEN NEW.calibration_version := zdr_text_hash(NEW.calibration_version); END IF;
      IF NEW.breaker_state !~ '^[0-9a-f]{64}$' THEN NEW.breaker_state := zdr_text_hash(NEW.breaker_state); END IF;
    WHEN 'actions' THEN
      NEW.params := zdr_json_digest(NEW.params); NEW.outcome := zdr_json_digest(NEW.outcome);
      IF NEW.strategy !~ '^[0-9a-f]{64}$' THEN NEW.strategy := zdr_text_hash(NEW.strategy); END IF;
    WHEN 'approvals' THEN
      NEW.summary := zdr_json_digest(NEW.summary);
      IF NEW.reason IS NOT NULL AND NEW.reason !~ '^[0-9a-f]{64}$' THEN NEW.reason := zdr_text_hash(NEW.reason); END IF;
    WHEN 'action_contexts' THEN
      IF NEW.principal !~ '^[0-9a-f]{64}$' THEN NEW.principal := zdr_text_hash(NEW.principal); END IF;
      IF NEW.route_template !~ '^[0-9a-f]{64}$' THEN NEW.route_template := zdr_text_hash(NEW.route_template); END IF;
      IF NEW.input_class !~ '^[0-9a-f]{64}$' THEN NEW.input_class := zdr_text_hash(NEW.input_class); END IF;
    WHEN 'enablement_edges' THEN
      NEW.last_verified_build := NULL;
    WHEN 'elements' THEN
      NEW.components := NULL; NEW.interactability := '{}';
    WHEN 'webhook_deliveries' THEN
      IF NEW.url !~ '^[0-9a-f]{64}$' THEN NEW.url := zdr_text_hash(NEW.url); END IF;
      IF NEW.last_error IS NOT NULL AND NEW.last_error !~ '^[0-9a-f]{64}$' THEN
        NEW.last_error := zdr_text_hash(NEW.last_error);
      END IF;
    WHEN 'workflow_runs' THEN
      NEW.assertions := zdr_json_digest(NEW.assertions);
      NEW.entities_created := zdr_json_digest(NEW.entities_created);
      NEW.coverage_tags := '{}';
    WHEN 'crawl_events' THEN
      NEW.payload := zdr_json_digest(NEW.payload)
        || CASE WHEN jsonb_typeof(NEW.payload->'pageId') = 'number'
          THEN jsonb_build_object('pageId', NEW.payload->'pageId') ELSE '{}'::jsonb END
        || CASE WHEN jsonb_typeof(NEW.payload->'page_id') = 'number'
          THEN jsonb_build_object('page_id', NEW.payload->'page_id') ELSE '{}'::jsonb END;
    ELSE
      RAISE EXCEPTION 'unsupported zdr confidentiality table';
  END CASE;
  RETURN NEW;
END $$;

-- The auditor calls writes with a pg_catalog-only SECURITY DEFINER search path.
-- Bind this invoker trigger to its migration schema so its tables and helper functions
-- resolve identically there, without granting the trigger elevated privileges.
DO $path$
BEGIN
  EXECUTE format(
    'ALTER FUNCTION %I.enforce_zdr_confidentiality() SET search_path = pg_catalog, %I, pg_temp',
    current_schema(), current_schema());
END
$path$;

DO $$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['url_frontier','pages','states','traffic_events','safety_decisions',
    'model_decisions','actions','approvals','action_contexts','enablement_edges','elements','crawl_events',
    'webhook_deliveries','workflow_runs']
  LOOP
    EXECUTE format('CREATE TRIGGER zdr_confidentiality BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION enforce_zdr_confidentiality()', tab);
    -- Scrub rows written before this boundary existed. No durable runtime fallback is retained.
    EXECUTE format('UPDATE %I SET run_id = run_id WHERE run_id IN (SELECT run_id FROM crawl_runs WHERE retention_mode = ''zdr'')', tab);
  END LOOP;
END $$;

-- Legacy ZDR configurations contained URLs, inline extraction prompts and action returns.
-- Keep a separate typed status view; never decode a fabricated operational CreateCrawl.
UPDATE crawl_runs r SET config = jsonb_build_object(
  'privacy', 'zdr',
  'parallelRolesAllowed', COALESCE((config->>'crossPrincipalAttribution')::boolean = false, false),
  'dynamic', jsonb_build_object('launchProfile', COALESCE(config->'dynamic'->>'launchProfile', 'standard')),
  'webhookConfigured', config->'output'->'webhook'->>'url' IS NOT NULL,
  'metadata', jsonb_build_object(
    'id', run_id, 'tenant', tenant_id, 'status', status, 'terminal_reason', terminal_reason,
    'config_digest', encode(config_digest, 'hex'),
    'seed', CASE WHEN seed < 0 THEN seed::numeric + 18446744073709551616 ELSE seed::numeric END,
    'policy_version', policy_version, 'counters', counters, 'created_at', created_at,
    'started_at', started_at, 'finished_at', finished_at, 'trace_id', trace_id,
    'retention', jsonb_build_object('mode', 'zdr', 'days', 0),
    'safety_profile', safety_profile, 'mode', mode,
    'duration_seconds', COALESCE((config->'limits'->>'durationSeconds')::bigint, 300),
    'query_policy', COALESCE(config->'scope'->>'queryPolicy', 'classify'),
    'output_formats', COALESCE(config->'output'->'formats', '["markdown","links","metadata"]'::jsonb),
    'webhook_configured', config->'output'->'webhook'->>'url' IS NOT NULL,
    'scrape_kind', config->'scrape'->>'kind',
    'batch_total', 1 + CASE WHEN jsonb_typeof(config->'scrape'->'urls') = 'array'
      THEN jsonb_array_length(config->'scrape'->'urls') ELSE 0 END
  )
), replay_spec = CASE WHEN replay_spec IS NULL THEN NULL
    ELSE jsonb_build_object('sourceRunId', replay_spec->'sourceRunId') END
WHERE retention_mode = 'zdr' AND config->>'privacy' IS DISTINCT FROM 'zdr';

CREATE FUNCTION enforce_zdr_run_config() RETURNS trigger LANGUAGE plpgsql AS $$
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
    'webhookConfigured', (NEW.config->>'webhookConfigured')::boolean,
    'metadata', NEW.config->'metadata'
  );
  NEW.replay_spec := CASE WHEN NEW.replay_spec IS NULL THEN NULL
    ELSE jsonb_build_object('sourceRunId', NEW.replay_spec->'sourceRunId') END;
  RETURN NEW;
END $$;
CREATE TRIGGER zdr_run_config BEFORE INSERT OR UPDATE ON crawl_runs
FOR EACH ROW EXECUTE FUNCTION enforce_zdr_run_config();
