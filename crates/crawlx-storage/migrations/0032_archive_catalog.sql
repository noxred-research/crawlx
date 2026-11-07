-- Archive metadata is content, never structural ZDR telemetry.
CREATE TABLE archive_exports (
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,
  export_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('recording','published','failed','deleted')),
  fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
  lease_until timestamptz NOT NULL,
  expires_at timestamptz,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, export_id),
  UNIQUE (tenant_id, run_id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES crawl_runs(tenant_id, run_id) ON DELETE CASCADE
);
CREATE INDEX archive_recovery ON archive_exports(state,lease_until,export_id) WHERE state IN ('recording','published','failed');
CREATE TABLE archive_records (
  tenant_id uuid NOT NULL,
  export_id uuid NOT NULL,
  ordinal bigint NOT NULL CHECK (ordinal >= 0),
  artifact_id uuid NOT NULL,
  member_offset bigint NOT NULL CHECK (member_offset >= 0),
  member_length bigint NOT NULL CHECK (member_length > 0),
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, export_id, ordinal),
  FOREIGN KEY (tenant_id, export_id) REFERENCES archive_exports ON DELETE CASCADE
);
CREATE TABLE archive_dependencies (
  tenant_id uuid NOT NULL,
  export_id uuid NOT NULL,
  ordinal bigint NOT NULL,
  source_export uuid NOT NULL,
  source_ordinal bigint NOT NULL,
  PRIMARY KEY (tenant_id, export_id, ordinal),
  CHECK (export_id <> source_export),
  FOREIGN KEY (tenant_id, export_id, ordinal) REFERENCES archive_records ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, source_export, source_ordinal) REFERENCES archive_records ON DELETE CASCADE
);
CREATE INDEX archive_dependency_sources ON archive_dependencies(tenant_id, source_export);
CREATE TABLE archive_history (
  tenant_id uuid NOT NULL,
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  export_id uuid NOT NULL,
  ordinal bigint NOT NULL,
  captured_at timestamptz NOT NULL,
  payload jsonb NOT NULL,
  PRIMARY KEY (tenant_id, identity_key, export_id, ordinal),
  FOREIGN KEY (tenant_id, export_id, ordinal) REFERENCES archive_records ON DELETE CASCADE
);
CREATE INDEX archive_history_eligible ON archive_history(tenant_id, identity_key, captured_at DESC);
DO $$ DECLARE table_name text; BEGIN
  FOREACH table_name IN ARRAY ARRAY['archive_exports','archive_records','archive_dependencies','archive_history'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true)::uuid)', table_name);
  END LOOP;
END $$;
CREATE FUNCTION enforce_archive_retention() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = NEW.run_id
      AND r.tenant_id = NEW.tenant_id AND r.retention_mode <> 'zdr') THEN
    RAISE EXCEPTION 'durable archive requires a retained tenant-owned source';
  END IF;
  NEW.expires_at := (SELECT expires_at FROM crawl_runs WHERE run_id = NEW.run_id);
  RETURN NEW;
END $$;
CREATE TRIGGER archive_retention BEFORE INSERT OR UPDATE ON archive_exports
  FOR EACH ROW EXECUTE FUNCTION enforce_archive_retention();
-- Expiry and whole-run erasure cannot leave a published dependent export.
-- Dependency deletion erases dependent catalog visibility before source rows disappear.
CREATE FUNCTION erase_archive_dependents() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE archive_exports SET state='deleted', fence=fence+1,
    payload=jsonb_set(jsonb_set(payload, '{state}', '"deleted"'), '{manifest}', 'null')
    WHERE tenant_id=OLD.tenant_id AND export_id IN (
      WITH RECURSIVE affected(id) AS (
        SELECT export_id FROM archive_dependencies WHERE tenant_id=OLD.tenant_id AND source_export=OLD.export_id
        UNION SELECT d.export_id FROM archive_dependencies d JOIN affected a ON d.source_export=a.id
          WHERE d.tenant_id=OLD.tenant_id
      ) SELECT id FROM affected
    );
  RETURN OLD;
END $$;
CREATE TRIGGER archive_source_erasure BEFORE DELETE ON archive_exports
  FOR EACH ROW EXECUTE FUNCTION erase_archive_dependents();
