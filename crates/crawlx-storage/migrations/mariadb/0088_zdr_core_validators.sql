-- ZDR confidentiality validators for the core tables. The write path projects content away
-- before it binds (zdr_project); these triggers only reject a row of a zero-data-retention run
-- that still holds content, as a second line of defence. They never rewrite a column.
CREATE OR REPLACE TRIGGER zdr_states_ins BEFORE INSERT ON states
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.observed_url IS NOT NULL OR NEW.masks <> '[]' OR NEW.artifacts <> '[]' OR NEW.manifest_artifact_id IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of states holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_states_upd BEFORE UPDATE ON states
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.observed_url IS NOT NULL OR NEW.masks <> '[]' OR NEW.artifacts <> '[]' OR NEW.manifest_artifact_id IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of states holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_pages_ins BEFORE INSERT ON pages
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.canonical_url IS NOT NULL OR NEW.final_url IS NOT NULL OR NEW.content_type IS NOT NULL OR NEW.title IS NOT NULL OR NEW.url_meta IS NOT NULL OR NEW.links IS NOT NULL OR NEW.markdown_artifact_id IS NOT NULL OR NEW.html_artifact_id IS NOT NULL OR NEW.raw_html_artifact_id IS NOT NULL OR NEW.markdown_digest IS NOT NULL OR NEW.html_digest IS NOT NULL OR NEW.observation_epoch IS NOT NULL OR JSON_REMOVE(NEW.metadata, '$.billing') <> '{}') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of pages holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_pages_upd BEFORE UPDATE ON pages
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.canonical_url IS NOT NULL OR NEW.final_url IS NOT NULL OR NEW.content_type IS NOT NULL OR NEW.title IS NOT NULL OR NEW.url_meta IS NOT NULL OR NEW.links IS NOT NULL OR NEW.markdown_artifact_id IS NOT NULL OR NEW.html_artifact_id IS NOT NULL OR NEW.raw_html_artifact_id IS NOT NULL OR NEW.markdown_digest IS NOT NULL OR NEW.html_digest IS NOT NULL OR NEW.observation_epoch IS NOT NULL OR JSON_REMOVE(NEW.metadata, '$.billing') <> '{}') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of pages holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_safety_decisions_ins BEFORE INSERT ON safety_decisions
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (JSON_TYPE(NEW.evidence) = 'OBJECT' AND JSON_LENGTH(NEW.evidence) = 1 AND CHAR_LENGTH(JSON_VALUE(NEW.evidence, '$.digest')) = 64)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of safety_decisions holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_safety_decisions_upd BEFORE UPDATE ON safety_decisions
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (JSON_TYPE(NEW.evidence) = 'OBJECT' AND JSON_LENGTH(NEW.evidence) = 1 AND CHAR_LENGTH(JSON_VALUE(NEW.evidence, '$.digest')) = 64)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of safety_decisions holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_model_decisions_ins BEFORE INSERT ON model_decisions
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (JSON_TYPE(NEW.output) = 'OBJECT' AND JSON_LENGTH(NEW.output) = 1 AND CHAR_LENGTH(JSON_VALUE(NEW.output, '$.digest')) = 64) OR NOT (NEW.provider REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.model REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.model_version REGEXP '^[0-9a-f]{64}$') OR (NEW.calibration_version IS NOT NULL AND NOT (NEW.calibration_version REGEXP '^[0-9a-f]{64}$')) OR (NEW.breaker_state IS NOT NULL AND NOT (NEW.breaker_state REGEXP '^[0-9a-f]{64}$')) OR NEW.io_artifact_id IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of model_decisions holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_model_decisions_upd BEFORE UPDATE ON model_decisions
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (JSON_TYPE(NEW.output) = 'OBJECT' AND JSON_LENGTH(NEW.output) = 1 AND CHAR_LENGTH(JSON_VALUE(NEW.output, '$.digest')) = 64) OR NOT (NEW.provider REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.model REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.model_version REGEXP '^[0-9a-f]{64}$') OR (NEW.calibration_version IS NOT NULL AND NOT (NEW.calibration_version REGEXP '^[0-9a-f]{64}$')) OR (NEW.breaker_state IS NOT NULL AND NOT (NEW.breaker_state REGEXP '^[0-9a-f]{64}$')) OR NEW.io_artifact_id IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of model_decisions holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_enablement_edges_ins BEFORE INSERT ON enablement_edges
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.last_verified_build IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of enablement_edges holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_enablement_edges_upd BEFORE UPDATE ON enablement_edges
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.last_verified_build IS NOT NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of enablement_edges holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_action_contexts_ins BEFORE INSERT ON action_contexts
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (NEW.principal REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.route_template REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.input_class REGEXP '^[0-9a-f]{64}$')) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of action_contexts holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_action_contexts_upd BEFORE UPDATE ON action_contexts
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NOT (NEW.principal REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.route_template REGEXP '^[0-9a-f]{64}$') OR NOT (NEW.input_class REGEXP '^[0-9a-f]{64}$')) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of action_contexts holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_crawl_events_ins BEFORE INSERT ON crawl_events
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.metadata_only_audit_id IS NULL AND NOT (JSON_VALUE(NEW.payload, '$.digest') IS NOT NULL OR JSON_EXTRACT(NEW.payload, '$.volatileHeadResponse') IS NOT NULL)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of crawl_events holds content';
  END IF;
END;
CREATE OR REPLACE TRIGGER zdr_crawl_events_upd BEFORE UPDATE ON crawl_events
FOR EACH ROW
BEGIN
  IF EXISTS (SELECT 1 FROM crawl_runs WHERE run_id = NEW.run_id AND retention_mode = 'zdr')
     AND (NEW.metadata_only_audit_id IS NULL AND NOT (JSON_VALUE(NEW.payload, '$.digest') IS NOT NULL OR JSON_EXTRACT(NEW.payload, '$.volatileHeadResponse') IS NOT NULL)) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'zdr row of crawl_events holds content';
  END IF;
END;
