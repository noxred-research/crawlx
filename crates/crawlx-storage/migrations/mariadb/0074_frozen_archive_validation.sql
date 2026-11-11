-- Final-invariant validation of frozen archive custody. A grant and its outputs exist only for an
-- export still recording at the granted fence, for a terminal run whose secret epoch and
-- incarnation are unchanged and settled; outputs stay inside the grant. Rows are immutable.
CREATE OR REPLACE TRIGGER archive_frozen_grant_validate BEFORE INSERT ON archive_frozen_grants
FOR EACH ROW
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM archive_exports e
        JOIN crawl_runs r ON r.tenant_id = e.tenant_id AND r.run_id = e.run_id
        JOIN run_secret_authority a ON a.tenant_id = e.tenant_id AND a.run_id = e.run_id
       WHERE e.tenant_id = NEW.tenant_id AND e.export_id = NEW.export_id AND e.run_id = NEW.run_id
         AND e.state = 'recording' AND e.fence = NEW.fence AND e.lease_until > SYSDATE(6)
         AND r.status IN ('completed', 'failed', 'cancelled') AND r.retention_mode <> 'zdr'
         AND r.purge_requested_at IS NULL
         AND a.incarnation = NEW.incarnation AND a.epoch = NEW.secret_epoch
         AND a.pending_operation IS NULL AND a.pending_renewal_operation IS NULL
         AND (NEW.expires_at IS NULL OR NEW.expires_at > SYSDATE(6))) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'frozen archive grant requires a recording export of a terminal run at its closed epoch';
  END IF;
END;

CREATE OR REPLACE TRIGGER archive_frozen_output_validate BEFORE INSERT ON archive_frozen_outputs
FOR EACH ROW
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM archive_frozen_grants g
        JOIN archive_exports e ON e.tenant_id = g.tenant_id AND e.export_id = g.export_id
        JOIN crawl_runs r ON r.tenant_id = g.tenant_id AND r.run_id = g.run_id
        JOIN run_secret_authority a ON a.tenant_id = g.tenant_id AND a.run_id = g.run_id
       WHERE g.tenant_id = NEW.tenant_id AND g.export_id = NEW.export_id AND g.binding = NEW.binding
         AND g.run_id = NEW.run_id AND e.run_id = g.run_id
         AND e.state = 'recording' AND e.fence = g.fence AND e.lease_until > SYSDATE(6)
         AND r.status IN ('completed', 'failed', 'cancelled') AND r.retention_mode <> 'zdr'
         AND r.purge_requested_at IS NULL
         AND a.incarnation = g.incarnation AND a.epoch = g.secret_epoch
         AND a.pending_operation IS NULL AND a.pending_renewal_operation IS NULL
         AND NEW.incarnation = g.incarnation AND NEW.secret_epoch = g.secret_epoch
         AND NEW.sensitivity = g.sensitivity
         AND (g.expires_at IS NULL OR (NEW.expires_at IS NOT NULL AND NEW.expires_at <= g.expires_at))) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'frozen archive output requires a live grant of its claimed export';
  END IF;
END;

CREATE OR REPLACE TRIGGER archive_frozen_grant_immutable BEFORE UPDATE ON archive_frozen_grants
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'frozen archive custody is immutable';
END;

CREATE OR REPLACE TRIGGER archive_frozen_source_immutable BEFORE UPDATE ON archive_frozen_sources
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'frozen archive custody is immutable';
END;

CREATE OR REPLACE TRIGGER archive_frozen_output_immutable BEFORE UPDATE ON archive_frozen_outputs
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'frozen archive custody is immutable';
END;
