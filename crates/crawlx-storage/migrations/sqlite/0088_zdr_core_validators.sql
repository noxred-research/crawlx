-- ZDR confidentiality validators for the core tables. The write path projects content away
-- before it binds (zdr_project); these triggers only reject a row of a zero-data-retention run
-- that still holds content, as a second line of defence. They never rewrite a column.
CREATE TRIGGER zdr_states_ins BEFORE INSERT ON states
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.observed_url IS NOT NULL OR NEW.masks <> '[]' OR NEW.artifacts <> '[]' OR NEW.manifest_artifact_id IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of states holds content');
END;
CREATE TRIGGER zdr_states_upd BEFORE UPDATE ON states
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.observed_url IS NOT NULL OR NEW.masks <> '[]' OR NEW.artifacts <> '[]' OR NEW.manifest_artifact_id IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of states holds content');
END;
CREATE TRIGGER zdr_pages_ins BEFORE INSERT ON pages
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.canonical_url IS NOT NULL OR NEW.final_url IS NOT NULL OR NEW.content_type IS NOT NULL OR NEW.title IS NOT NULL OR NEW.url_meta IS NOT NULL OR NEW.links IS NOT NULL OR NEW.host_key IS NOT NULL OR NEW.markdown_artifact_id IS NOT NULL OR NEW.html_artifact_id IS NOT NULL OR NEW.raw_html_artifact_id IS NOT NULL OR NEW.markdown_digest IS NOT NULL OR NEW.html_digest IS NOT NULL OR NEW.observation_epoch IS NOT NULL OR json_remove(NEW.metadata, '$.billing') <> '{}')
BEGIN
  SELECT RAISE(ABORT, 'zdr row of pages holds content');
END;
CREATE TRIGGER zdr_pages_upd BEFORE UPDATE ON pages
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.canonical_url IS NOT NULL OR NEW.final_url IS NOT NULL OR NEW.content_type IS NOT NULL OR NEW.title IS NOT NULL OR NEW.url_meta IS NOT NULL OR NEW.links IS NOT NULL OR NEW.host_key IS NOT NULL OR NEW.markdown_artifact_id IS NOT NULL OR NEW.html_artifact_id IS NOT NULL OR NEW.raw_html_artifact_id IS NOT NULL OR NEW.markdown_digest IS NOT NULL OR NEW.html_digest IS NOT NULL OR NEW.observation_epoch IS NOT NULL OR json_remove(NEW.metadata, '$.billing') <> '{}')
BEGIN
  SELECT RAISE(ABORT, 'zdr row of pages holds content');
END;
CREATE TRIGGER zdr_safety_decisions_ins BEFORE INSERT ON safety_decisions
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NOT (json_type(NEW.evidence) = 'object' AND (SELECT count(*) FROM json_each(NEW.evidence)) = 1 AND length(json_extract(NEW.evidence, '$.digest')) = 64))
BEGIN
  SELECT RAISE(ABORT, 'zdr row of safety_decisions holds content');
END;
CREATE TRIGGER zdr_safety_decisions_upd BEFORE UPDATE ON safety_decisions
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NOT (json_type(NEW.evidence) = 'object' AND (SELECT count(*) FROM json_each(NEW.evidence)) = 1 AND length(json_extract(NEW.evidence, '$.digest')) = 64))
BEGIN
  SELECT RAISE(ABORT, 'zdr row of safety_decisions holds content');
END;
CREATE TRIGGER zdr_model_decisions_ins BEFORE INSERT ON model_decisions
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NOT (json_type(NEW.output) = 'object' AND (SELECT count(*) FROM json_each(NEW.output)) = 1 AND length(json_extract(NEW.output, '$.digest')) = 64) OR (length(NEW.provider) <> 64 OR NEW.provider GLOB '*[^0-9a-f]*') OR (length(NEW.model) <> 64 OR NEW.model GLOB '*[^0-9a-f]*') OR (length(NEW.model_version) <> 64 OR NEW.model_version GLOB '*[^0-9a-f]*') OR (NEW.calibration_version IS NOT NULL AND (length(NEW.calibration_version) <> 64 OR NEW.calibration_version GLOB '*[^0-9a-f]*')) OR (NEW.breaker_state IS NOT NULL AND (length(NEW.breaker_state) <> 64 OR NEW.breaker_state GLOB '*[^0-9a-f]*')) OR NEW.io_artifact_id IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of model_decisions holds content');
END;
CREATE TRIGGER zdr_model_decisions_upd BEFORE UPDATE ON model_decisions
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NOT (json_type(NEW.output) = 'object' AND (SELECT count(*) FROM json_each(NEW.output)) = 1 AND length(json_extract(NEW.output, '$.digest')) = 64) OR (length(NEW.provider) <> 64 OR NEW.provider GLOB '*[^0-9a-f]*') OR (length(NEW.model) <> 64 OR NEW.model GLOB '*[^0-9a-f]*') OR (length(NEW.model_version) <> 64 OR NEW.model_version GLOB '*[^0-9a-f]*') OR (NEW.calibration_version IS NOT NULL AND (length(NEW.calibration_version) <> 64 OR NEW.calibration_version GLOB '*[^0-9a-f]*')) OR (NEW.breaker_state IS NOT NULL AND (length(NEW.breaker_state) <> 64 OR NEW.breaker_state GLOB '*[^0-9a-f]*')) OR NEW.io_artifact_id IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of model_decisions holds content');
END;
CREATE TRIGGER zdr_enablement_edges_ins BEFORE INSERT ON enablement_edges
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.last_verified_build IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of enablement_edges holds content');
END;
CREATE TRIGGER zdr_enablement_edges_upd BEFORE UPDATE ON enablement_edges
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.last_verified_build IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of enablement_edges holds content');
END;
CREATE TRIGGER zdr_action_contexts_ins BEFORE INSERT ON action_contexts
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND ((length(NEW.principal) <> 64 OR NEW.principal GLOB '*[^0-9a-f]*') OR (length(NEW.route_template) <> 64 OR NEW.route_template GLOB '*[^0-9a-f]*') OR (length(NEW.input_class) <> 64 OR NEW.input_class GLOB '*[^0-9a-f]*'))
BEGIN
  SELECT RAISE(ABORT, 'zdr row of action_contexts holds content');
END;
CREATE TRIGGER zdr_action_contexts_upd BEFORE UPDATE ON action_contexts
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND ((length(NEW.principal) <> 64 OR NEW.principal GLOB '*[^0-9a-f]*') OR (length(NEW.route_template) <> 64 OR NEW.route_template GLOB '*[^0-9a-f]*') OR (length(NEW.input_class) <> 64 OR NEW.input_class GLOB '*[^0-9a-f]*'))
BEGIN
  SELECT RAISE(ABORT, 'zdr row of action_contexts holds content');
END;
CREATE TRIGGER zdr_crawl_events_ins BEFORE INSERT ON crawl_events
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.metadata_only_audit_id IS NULL AND json_type(NEW.payload, '$.digest') IS NOT 'text' AND json_type(NEW.payload, '$.volatileHeadResponse') IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of crawl_events holds content');
END;
CREATE TRIGGER zdr_crawl_events_upd BEFORE UPDATE ON crawl_events
FOR EACH ROW WHEN EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
  AND (NEW.metadata_only_audit_id IS NULL AND json_type(NEW.payload, '$.digest') IS NOT 'text' AND json_type(NEW.payload, '$.volatileHeadResponse') IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'zdr row of crawl_events holds content');
END;
