-- Historical renewal recovery metadata only. New lifetime mutations remain
-- unavailable until cross-backend cancellation/fencing can be proved atomic.
-- Pending retention includes the target even though all secret use is blocked.
ALTER TABLE run_secret_authority
    ADD COLUMN pending_renewal_operation uuid,
    ADD COLUMN pending_renewal_deadline timestamptz,
    ADD CONSTRAINT secret_authority_pending_renewal CHECK (
        (pending_renewal_operation IS NULL AND pending_renewal_deadline IS NULL)
        OR (pending_renewal_operation IS NOT NULL AND pending_renewal_deadline IS NOT NULL
            AND pending_operation IS NULL AND pending_commitment IS NULL AND pending_value_commitment IS NULL
            AND sealed_at IS NULL AND epoch > 0 AND commitment IS NOT NULL
            AND pending_renewal_deadline > expires_at
            AND pending_renewal_deadline <= expires_at + interval '24 hours'));

-- Keep request tombstones until run purge. Reusing an operation cannot silently
-- move its deadline, even after another renewal has completed.
CREATE TABLE run_secret_authority_renewals (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    operation uuid NOT NULL,
    incarnation uuid NOT NULL,
    secret_epoch bigint NOT NULL CHECK (secret_epoch > 0),
    previous_deadline timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK (deadline > previous_deadline
        AND deadline <= previous_deadline + interval '24 hours'),
    PRIMARY KEY (tenant_id, run_id, operation),
    FOREIGN KEY (tenant_id, run_id)
        REFERENCES run_secret_authority(tenant_id, run_id) ON DELETE CASCADE
);
ALTER TABLE run_secret_authority_renewals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON run_secret_authority_renewals
    USING (tenant_id = crawlx_current_tenant())
    WITH CHECK (tenant_id = crawlx_current_tenant());
