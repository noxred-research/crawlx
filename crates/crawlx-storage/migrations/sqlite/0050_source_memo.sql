-- UUIDs are 16 raw bytes; timestamps are UTC epoch microseconds.
CREATE TABLE source_memo_seen (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    lookup_key TEXT NOT NULL CHECK (length(lookup_key)=64),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,run_id,lookup_key),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX source_memo_seen_eviction ON source_memo_seen(tenant_id,run_id,recorded_at,lookup_key);
CREATE TABLE source_category_cache (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    lookup_key TEXT NOT NULL CHECK (length(lookup_key)=64),
    payload TEXT NOT NULL CHECK (json_valid(payload)),
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id,run_id,lookup_key),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX source_category_cache_expiry ON source_category_cache(expires_at);
CREATE TRIGGER source_memo_seen_retention_ins BEFORE INSERT ON source_memo_seen
WHEN EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'source memo metadata requires retained source run'); END;
CREATE TRIGGER source_memo_seen_retention_upd BEFORE UPDATE ON source_memo_seen
WHEN EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'source memo metadata requires retained source run'); END;
CREATE TRIGGER source_category_cache_retention_ins BEFORE INSERT ON source_category_cache
WHEN EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'source memo metadata requires retained source run'); END;
CREATE TRIGGER source_category_cache_retention_upd BEFORE UPDATE ON source_category_cache
WHEN EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=NEW.tenant_id AND run_id=NEW.run_id AND (retention_mode='zdr' OR purge_requested_at IS NOT NULL))
BEGIN SELECT RAISE(ABORT,'source memo metadata requires retained source run'); END;

-- Operational reset generation is permitted for ZDR; it carries no content-derived metadata.
CREATE TABLE source_memo_control (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation>=0),
    PRIMARY KEY (tenant_id,run_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs(tenant_id,run_id) ON DELETE CASCADE
) STRICT;
