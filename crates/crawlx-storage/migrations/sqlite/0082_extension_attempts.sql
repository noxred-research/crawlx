-- Bounded digest dedupe for complete extension callback trails. Receipts themselves are
-- the typed `extension_attempt` metadata event written in the same fenced transaction.
CREATE TABLE extension_attempts (
    tenant_id BLOB NOT NULL CHECK (length(tenant_id)=16),
    run_id BLOB NOT NULL CHECK (length(run_id)=16),
    request_id INTEGER NOT NULL,
    fence INTEGER NOT NULL CHECK (fence>0),
    attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 32767),
    digest BLOB NOT NULL CHECK (length(digest)=32),
    event_seq INTEGER NOT NULL CHECK (event_seq>0),
    PRIMARY KEY (tenant_id,run_id,request_id,fence,attempt),
    FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
) STRICT;
