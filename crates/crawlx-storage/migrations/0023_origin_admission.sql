-- crawlx-storage 0023: deployment-wide origin capacity and start spacing.
-- origin_leases is keyed by (run_id, origin), so it cannot coordinate different
-- runs or tenants. This operational table intentionally has no tenant/run key.
-- Capacity lives in transaction-scoped advisory locks, not expiring row leases.
-- A dropped connection rolls back its permit; no renewal task can outlive a caller.
CREATE TABLE origin_admission (
    origin text PRIMARY KEY,
    next_ticket bigint NOT NULL DEFAULT 0 CHECK (next_ticket >= 0),
    slot_limit bigint NOT NULL CHECK (slot_limit > 0),
    next_allowed_at timestamptz NOT NULL DEFAULT '-infinity',
    last_spacing_us bigint NOT NULL DEFAULT 0 CHECK (last_spacing_us >= 0),
    CHECK (next_ticket < slot_limit)
);


-- Keep the run-local limit separate from the deployment limit. These slots also
-- use held advisory transactions; the old TTL columns no longer own capacity.
ALTER TABLE origin_leases
    ADD COLUMN admission_next_ticket bigint NOT NULL DEFAULT 0 CHECK (admission_next_ticket >= 0),
    ADD COLUMN admission_limit bigint CHECK (admission_limit > 0),
    ADD CONSTRAINT origin_admission_run_ticket_bound
        CHECK (admission_limit IS NULL OR admission_next_ticket < admission_limit);
-- next_ticket wraps modulo slot_limit; each slot has PostgreSQL's advisory-lock
-- waiter queue. Workers must agree on slot_limit; mismatches fail closed.
-- next_allowed_at records the last admitted database start plus its spacing.
-- Admission uses max(previous spacing, current spacing), including HTTP/browser
-- transitions. Waiting never reserves a future timestamp or holds a row lock.
-- This table is owner/worker-only. Do not grant API-role DML or blanket default
-- table privileges: API requests must not read or mutate global origin admission.
REVOKE ALL ON TABLE origin_admission FROM PUBLIC;
