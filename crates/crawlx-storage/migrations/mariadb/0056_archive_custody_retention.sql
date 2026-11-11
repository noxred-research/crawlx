-- Preserve the earliest run, source, and previously persisted archive deadline.
CREATE OR REPLACE TRIGGER archive_retention_ins BEFORE INSERT ON archive_exports
FOR EACH ROW
BEGIN
  DECLARE source_expiry DATETIME(6);
  DECLARE custody_expiry DATETIME(6);
  DECLARE deadline_text TEXT;
  DECLARE classification VARCHAR(32);
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id=NEW.run_id
      AND r.tenant_id=NEW.tenant_id AND r.retention_mode<>'zdr') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='durable archive requires a retained tenant-owned source';
  END IF;
  SET source_expiry=(SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id);
  SET classification=COALESCE(JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.sensitivity')),'content');
  SET deadline_text=NULLIF(JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.expiresAt')),'null');
  IF LOCATE('.',deadline_text)>0 THEN
    SET deadline_text=CONCAT(SUBSTRING_INDEX(deadline_text,'.',1),'.',
      LEFT(SUBSTRING_INDEX(SUBSTRING_INDEX(deadline_text,'.',-1),'Z',1),6),'Z');
  END IF;
  SET custody_expiry=CASE WHEN LOCATE('.',deadline_text)>0
    THEN STR_TO_DATE(deadline_text,'%Y-%m-%dT%H:%i:%s.%fZ')
    ELSE STR_TO_DATE(deadline_text,'%Y-%m-%dT%H:%i:%sZ') END;
  IF classification NOT IN ('content','sensitive')
      OR (deadline_text IS NOT NULL AND custody_expiry IS NULL)
      OR (classification='sensitive' AND custody_expiry IS NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='invalid archive byte authority';
  END IF;
  IF source_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>source_expiry) THEN
    SET NEW.expires_at=source_expiry;
  END IF;
  IF custody_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>custody_expiry) THEN
    SET NEW.expires_at=custody_expiry;
  END IF;
  SET NEW.payload=JSON_SET(NEW.payload,'$.expiresAt',DATE_FORMAT(NEW.expires_at,'%Y-%m-%dT%H:%i:%s.%fZ'),
    '$.custody',JSON_OBJECT('sensitivity',classification,'expiresAt',DATE_FORMAT(NEW.expires_at,'%Y-%m-%dT%H:%i:%s.%fZ')));
END;

CREATE OR REPLACE TRIGGER archive_retention_upd BEFORE UPDATE ON archive_exports
FOR EACH ROW
BEGIN
  DECLARE source_expiry DATETIME(6);
  DECLARE custody_expiry DATETIME(6);
  DECLARE deadline_text TEXT;
  DECLARE classification VARCHAR(32);
  IF NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id=NEW.run_id
      AND r.tenant_id=NEW.tenant_id AND r.retention_mode<>'zdr') THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='durable archive requires a retained tenant-owned source';
  END IF;
  SET source_expiry=(SELECT expires_at FROM crawl_runs WHERE run_id=NEW.run_id);
  SET classification=COALESCE(JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.sensitivity')),'content');
  SET deadline_text=NULLIF(JSON_UNQUOTE(JSON_EXTRACT(NEW.payload,'$.custody.expiresAt')),'null');
  IF LOCATE('.',deadline_text)>0 THEN
    SET deadline_text=CONCAT(SUBSTRING_INDEX(deadline_text,'.',1),'.',
      LEFT(SUBSTRING_INDEX(SUBSTRING_INDEX(deadline_text,'.',-1),'Z',1),6),'Z');
  END IF;
  SET custody_expiry=CASE WHEN LOCATE('.',deadline_text)>0
    THEN STR_TO_DATE(deadline_text,'%Y-%m-%dT%H:%i:%s.%fZ')
    ELSE STR_TO_DATE(deadline_text,'%Y-%m-%dT%H:%i:%sZ') END;
  IF classification NOT IN ('content','sensitive')
      OR (deadline_text IS NOT NULL AND custody_expiry IS NULL)
      OR (classification='sensitive' AND custody_expiry IS NULL) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='invalid archive byte authority';
  END IF;
  IF JSON_UNQUOTE(JSON_EXTRACT(OLD.payload,'$.custody.sensitivity'))='sensitive'
      AND classification<>'sensitive' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='sensitive archive authority cannot become content';
  END IF;
  IF OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>OLD.expires_at) THEN
    SET NEW.expires_at=OLD.expires_at;
  END IF;
  IF source_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>source_expiry) THEN
    SET NEW.expires_at=source_expiry;
  END IF;
  IF custody_expiry IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at>custody_expiry) THEN
    SET NEW.expires_at=custody_expiry;
  END IF;
  SET NEW.payload=JSON_SET(NEW.payload,'$.expiresAt',DATE_FORMAT(NEW.expires_at,'%Y-%m-%dT%H:%i:%s.%fZ'),
    '$.custody',JSON_OBJECT('sensitivity',classification,'expiresAt',DATE_FORMAT(NEW.expires_at,'%Y-%m-%dT%H:%i:%s.%fZ')));
END;

UPDATE archive_exports SET expires_at=expires_at;
