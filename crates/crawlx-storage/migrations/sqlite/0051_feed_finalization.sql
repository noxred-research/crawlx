ALTER TABLE crawl_runs ADD COLUMN feed_finalizing INTEGER NOT NULL DEFAULT 0 CHECK (feed_finalizing IN (0,1));
ALTER TABLE crawl_runs ADD COLUMN feed_finalized INTEGER NOT NULL DEFAULT 0 CHECK (feed_finalized IN (0,1));
ALTER TABLE crawl_runs ADD COLUMN feed_required INTEGER NOT NULL DEFAULT 0 CHECK (feed_required IN (0,1));
ALTER TABLE crawl_runs ADD COLUMN feed_terminal_reason TEXT;
ALTER TABLE crawl_runs ADD COLUMN feed_finalization_outcome TEXT
  CHECK (feed_finalization_outcome IN ('completed','content_expired'));
UPDATE crawl_runs SET feed_required=COALESCE(json_array_length(config,'$.datasets.feeds'),0)>0;
CREATE TABLE dataset_delivery_outbox_terminal (
  delivery_id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id BLOB NOT NULL REFERENCES tenants (tenant_id),
  run_id BLOB NOT NULL,
  source_request_id INTEGER,
  source_action_id BLOB,
  feed TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload TEXT CHECK (json_valid(payload)),
  volatile_page INTEGER,
  content_page INTEGER,
  erased_at INTEGER,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','delivered','content_expired')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  fence INTEGER NOT NULL DEFAULT 0 CHECK (fence >= 0),
  lease_owner BLOB,
  lease_expires_at INTEGER,
  not_before INTEGER NOT NULL DEFAULT (CAST(unixepoch('subsec') * 1000000 AS INTEGER)),
  expires_at INTEGER NOT NULL,
  terminal_source INTEGER NOT NULL DEFAULT 0 CHECK (terminal_source IN (0,1)),
  UNIQUE (tenant_id,run_id,feed,idempotency_key),
  CHECK ((payload IS NULL) = (volatile_page IS NOT NULL)),
  CHECK ((terminal_source=1 AND source_request_id IS NULL AND source_action_id IS NULL)
    OR (terminal_source=0 AND ((source_request_id IS NULL) <> (source_action_id IS NULL)))),
  FOREIGN KEY (run_id,source_action_id) REFERENCES actions (run_id,action_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,run_id) REFERENCES crawl_runs (tenant_id,run_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,run_id,source_request_id) REFERENCES url_frontier (tenant_id,run_id,frontier_id) ON DELETE CASCADE
) STRICT;
INSERT INTO dataset_delivery_outbox_terminal
  (delivery_id,tenant_id,run_id,source_request_id,source_action_id,feed,idempotency_key,payload,volatile_page,content_page,erased_at,state,attempts,fence,lease_owner,lease_expires_at,not_before,expires_at)
SELECT delivery_id,tenant_id,run_id,source_request_id,source_action_id,feed,idempotency_key,payload,volatile_page,content_page,erased_at,state,attempts,fence,lease_owner,lease_expires_at,not_before,expires_at FROM dataset_delivery_outbox;
DROP TABLE dataset_delivery_outbox;
ALTER TABLE dataset_delivery_outbox_terminal RENAME TO dataset_delivery_outbox;
CREATE INDEX dataset_delivery_ready ON dataset_delivery_outbox (tenant_id,run_id,not_before,delivery_id)
  WHERE state IN ('pending','leased');
CREATE INDEX crawl_runs_feed_finalization ON crawl_runs(run_id,tenant_id)
  WHERE feed_finalized=0 AND (feed_required=1 OR feed_finalizing=1);
