-- A sealed authority refuses new catalog and key custody rows except an INSERT that exactly
-- matches a validated `archive_frozen_outputs` row. The seal never reopens and key custody
-- UPDATE stays forbidden (artifact_key_secret_fence_upd is unchanged).
DROP TRIGGER IF EXISTS artifact_catalog_secret_fence_ins;
CREATE TRIGGER artifact_catalog_secret_fence_ins BEFORE INSERT ON artifacts
FOR EACH ROW WHEN NEW.run_id IS NOT NULL AND EXISTS (
  SELECT 1 FROM run_secret_authority a
   WHERE a.tenant_id = NEW.tenant_id AND a.run_id = NEW.run_id AND a.sealed_at IS NOT NULL)
  AND NOT EXISTS (
  SELECT 1 FROM archive_frozen_outputs o
   WHERE o.tenant_id = NEW.tenant_id AND o.artifact_id = NEW.artifact_id AND o.run_id = NEW.run_id
     AND o.kind = NEW.kind AND o.bucket = NEW.bucket AND o.object_key = NEW.object_key
     AND o.size_bytes = NEW.size_bytes AND o.content_digest = NEW.content_digest
     AND o.content_type = NEW.content_type AND o.sensitivity = NEW.sensitivity
     AND o.created_at = NEW.created_at AND o.expires_at IS NEW.expires_at)
BEGIN
  SELECT RAISE(ABORT, 'artifact secret authority is permanently sealed');
END;
DROP TRIGGER IF EXISTS artifact_key_secret_fence_ins;
CREATE TRIGGER artifact_key_secret_fence_ins BEFORE INSERT ON artifact_key_custody
FOR EACH ROW WHEN EXISTS (
  SELECT 1 FROM run_secret_authority a
   WHERE a.tenant_id = NEW.tenant_id AND a.run_id = NEW.run_id AND a.sealed_at IS NOT NULL)
  AND NOT EXISTS (
  SELECT 1 FROM archive_frozen_outputs o
   WHERE o.tenant_id = NEW.tenant_id AND o.artifact_id = NEW.artifact_id AND o.run_id = NEW.run_id
     AND o.incarnation = NEW.incarnation AND o.secret_epoch = NEW.secret_epoch
     AND o.object_key = NEW.object_key AND o.content_digest = NEW.plaintext_digest
     AND o.size_bytes = NEW.plaintext_size AND o.ciphertext_digest = NEW.ciphertext_digest
     AND o.ciphertext_size = NEW.ciphertext_size AND o.created_at = NEW.created_at)
BEGIN
  SELECT RAISE(ABORT, 'artifact secret authority is permanently sealed');
END;
