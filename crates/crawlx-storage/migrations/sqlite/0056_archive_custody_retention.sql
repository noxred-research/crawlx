-- SQLite deadlines use integer microseconds; fractional JSON digits are truncated, never rounded up.
DROP TRIGGER archive_retention_ins;
DROP TRIGGER archive_retention_upd;

CREATE TRIGGER archive_retention_ins BEFORE INSERT ON archive_exports
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id=NEW.run_id AND r.tenant_id=NEW.tenant_id AND r.retention_mode<>'zdr')
      THEN RAISE(ABORT,'durable archive requires a retained tenant-owned source')
    WHEN classification NOT IN ('content','sensitive')
      OR (deadline_text IS NOT NULL AND (custody_expiry IS NULL OR substr(deadline_text,-1)<>'Z'))
      OR (classification='sensitive' AND custody_expiry IS NULL)
      THEN RAISE(ABORT,'invalid archive byte authority')
    WHEN (SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id) IS NOT NULL
      AND (NEW.expires_at IS NULL OR NEW.expires_at>(SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id))
      THEN RAISE(ABORT,'archive expiry exceeds source retention')
    WHEN custody_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>custody_expiry)
      THEN RAISE(ABORT,'archive expiry exceeds byte authority')
  END FROM (SELECT COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content') AS classification,
      json_extract(NEW.payload,'$.custody.expiresAt') AS deadline_text,
      CASE WHEN json_extract(NEW.payload,'$.custody.expiresAt') IS NULL THEN NULL ELSE
        CAST(strftime('%s',substr(json_extract(NEW.payload,'$.custody.expiresAt'),1,19)||'Z') AS INTEGER)*1000000
        + CASE WHEN substr(json_extract(NEW.payload,'$.custody.expiresAt'),20,1)='.' THEN
          CAST(substr(substr(json_extract(NEW.payload,'$.custody.expiresAt'),21)||'000000',1,6) AS INTEGER)
          ELSE 0 END END AS custody_expiry);
END;

CREATE TRIGGER archive_retention_upd BEFORE UPDATE ON archive_exports
FOR EACH ROW
BEGIN
  SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id=NEW.run_id AND r.tenant_id=NEW.tenant_id AND r.retention_mode<>'zdr')
      THEN RAISE(ABORT,'durable archive requires a retained tenant-owned source')
    WHEN classification NOT IN ('content','sensitive')
      OR (deadline_text IS NOT NULL AND (custody_expiry IS NULL OR substr(deadline_text,-1)<>'Z'))
      OR (classification='sensitive' AND custody_expiry IS NULL)
      THEN RAISE(ABORT,'invalid archive byte authority')
    WHEN (SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id) IS NOT NULL
      AND (NEW.expires_at IS NULL OR NEW.expires_at>(SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id))
      THEN RAISE(ABORT,'archive expiry exceeds source retention')
    WHEN custody_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>custody_expiry)
      THEN RAISE(ABORT,'archive expiry exceeds byte authority')
    WHEN OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>OLD.expires_at)
      THEN RAISE(ABORT,'archive expiry cannot increase')
    WHEN COALESCE(json_extract(OLD.payload,'$.custody.sensitivity'),'content')='sensitive' AND classification<>'sensitive'
      THEN RAISE(ABORT,'sensitive archive authority cannot become content')
  END FROM (SELECT COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content') AS classification,
      json_extract(NEW.payload,'$.custody.expiresAt') AS deadline_text,
      CASE WHEN json_extract(NEW.payload,'$.custody.expiresAt') IS NULL THEN NULL ELSE
        CAST(strftime('%s',substr(json_extract(NEW.payload,'$.custody.expiresAt'),1,19)||'Z') AS INTEGER)*1000000
        + CASE WHEN substr(json_extract(NEW.payload,'$.custody.expiresAt'),20,1)='.' THEN
          CAST(substr(substr(json_extract(NEW.payload,'$.custody.expiresAt'),21)||'000000',1,6) AS INTEGER)
          ELSE 0 END END AS custody_expiry);
END;

CREATE TRIGGER archive_custody_precision_ins AFTER INSERT ON archive_exports
FOR EACH ROW WHEN NEW.payload IS NOT json_set(NEW.payload,'$.expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END,'$.custody',json_object('sensitivity',COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content'),'expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END))
BEGIN
  UPDATE archive_exports SET payload=json_set(NEW.payload,'$.expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END,'$.custody',json_object('sensitivity',COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content'),'expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END))
    WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
END;

CREATE TRIGGER archive_custody_precision_upd AFTER UPDATE ON archive_exports
FOR EACH ROW WHEN NEW.payload IS NOT json_set(NEW.payload,'$.expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END,'$.custody',json_object('sensitivity',COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content'),'expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END))
BEGIN
  UPDATE archive_exports SET payload=json_set(NEW.payload,'$.expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END,'$.custody',json_object('sensitivity',COALESCE(json_extract(NEW.payload,'$.custody.sensitivity'),'content'),'expiresAt',CASE WHEN NEW.expires_at IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%S',(NEW.expires_at-((NEW.expires_at%1000000+1000000)%1000000))/1000000,'unixepoch') || printf('.%06dZ',(NEW.expires_at%1000000+1000000)%1000000) END))
    WHERE tenant_id=NEW.tenant_id AND export_id=NEW.export_id;
END;

UPDATE archive_exports SET payload=payload;
