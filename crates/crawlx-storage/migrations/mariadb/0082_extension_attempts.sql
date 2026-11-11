-- Bounded digest dedupe for complete extension callback trails. Receipts themselves are
-- the typed `extension_attempt` metadata event written in the same fenced transaction.
-- from: 0082 bounded extension attempt digest dedupe; UUIDs are BINARY(16).
CREATE TABLE IF NOT EXISTS extension_attempts (
    tenant_id BINARY(16) NOT NULL,
    run_id BINARY(16) NOT NULL,
    request_id BIGINT NOT NULL,
    fence BIGINT NOT NULL CHECK (fence>0),
    attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 32767),
    digest BINARY(32) NOT NULL,
    event_seq BIGINT NOT NULL CHECK (event_seq>0),
    PRIMARY KEY (tenant_id,run_id,request_id,fence,attempt),
    CONSTRAINT extension_attempts_request_fk FOREIGN KEY (tenant_id,run_id,request_id) REFERENCES url_frontier(tenant_id,run_id,frontier_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_nopad_bin ROW_FORMAT=DYNAMIC;
