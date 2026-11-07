-- crawlx-storage 0010: traffic rows outside every network epoch (lane propagation; trail
-- rule: a `traffic_events` row without `network_epoch_id` needs an explicit
-- `unattributed` reason).
--
-- Fetch-plane requests, flows the proxy backend cannot match to an epoch window and
-- requests captured before the first action opened an epoch have no epoch to carry.
-- Such a row is legal only with an explicit reason; the stores reject one without, and
-- the trail verifier reports any that slips through.
ALTER TABLE traffic_events ALTER COLUMN epoch_id DROP NOT NULL;
ALTER TABLE traffic_events ADD COLUMN unattributed_reason text
  CHECK (unattributed_reason IN ('not_applicable','before_first_epoch','no_receipt','unmatched_proxy_flow'));
ALTER TABLE traffic_events ADD CONSTRAINT traffic_events_attribution
  CHECK ((epoch_id IS NULL) = (unattributed_reason IS NOT NULL));
