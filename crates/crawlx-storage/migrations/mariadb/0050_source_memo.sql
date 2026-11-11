-- UUIDs use BINARY(16), UTC timestamps DATETIME(6), exact text utf8mb4_nopad_bin.
-- new: bounded retained article-seen hashes, scoped to the owning run.
CREATE TABLE IF NOT EXISTS source_memo_seen (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    lookup_key VARCHAR(64) NOT NULL CHECK (CHAR_LENGTH(lookup_key)=64),
    recorded_at DATETIME(6) NOT NULL,
    PRIMARY KEY (tenant_id,run_id,lookup_key),
    KEY source_memo_seen_eviction (tenant_id,run_id,recorded_at,lookup_key),
    CONSTRAINT source_memo_seen_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
-- new: retention-typed category artifact references, never durable ZDR metadata.
CREATE TABLE IF NOT EXISTS source_category_cache (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    lookup_key VARCHAR(64) NOT NULL CHECK (CHAR_LENGTH(lookup_key)=64),
    payload LONGTEXT NOT NULL CHECK (JSON_VALID(payload)),
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (tenant_id,run_id,lookup_key),
    KEY source_category_cache_expiry (expires_at),
    CONSTRAINT source_category_cache_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
CREATE OR REPLACE TRIGGER source_memo_seen_retention_ins BEFORE INSERT ON source_memo_seen FOR EACH ROW
BEGIN
    IF EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL)) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source memo metadata requires retained source run';
    END IF;
END;
CREATE OR REPLACE TRIGGER source_memo_seen_retention_upd BEFORE UPDATE ON source_memo_seen FOR EACH ROW
BEGIN
    IF EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL)) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source memo metadata requires retained source run';
    END IF;
END;
CREATE OR REPLACE TRIGGER source_category_cache_retention_ins BEFORE INSERT ON source_category_cache FOR EACH ROW
BEGIN
    IF EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL)) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source memo metadata requires retained source run';
    END IF;
END;
CREATE OR REPLACE TRIGGER source_category_cache_retention_upd BEFORE UPDATE ON source_category_cache FOR EACH ROW
BEGIN
    IF EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL)) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='source memo metadata requires retained source run';
    END IF;
END;

-- Operational reset generation is permitted for ZDR; it carries no content-derived metadata.
-- new: run-only operational generation fences delayed volatile writes after reset.
CREATE TABLE IF NOT EXISTS source_memo_control (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation>=0),
    PRIMARY KEY (tenant_id,run_id),
    CONSTRAINT source_memo_control_run_fk FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
