-- crawlx-storage 0089: tenant isolation for state cluster membership.
-- Membership inherits visibility from its exact state; the existing states policy
-- follows states.run_id through crawl_runs to the transaction-local tenant.
-- API-role provisioning grants this table access only after RLS is enabled.
-- As in migration 0012, the owner retains cross-tenant worker/admin authority.
ALTER TABLE state_cluster_membership ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON state_cluster_membership
  USING (EXISTS (
    SELECT 1 FROM states s
    WHERE s.state_id = state_cluster_membership.state_id
  ));
