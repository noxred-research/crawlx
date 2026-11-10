-- crawlx-storage 0045: the tenant engine flag names the routed-away engine `upstream`.
--   crawlx   - compat requests are served by crawlx (default)
--   upstream - the tenant is routed to the upstream service; the facade refuses non-shadow creates
--   shadow   - only mirrored (`X-Crawlx-Shadow: 1`) requests are accepted
-- Rows that carried the earlier routed-away value (anything other than `crawlx` / `shadow`)
-- are rewritten to `upstream`.
ALTER TABLE tenants DROP CONSTRAINT tenants_engine_check;
UPDATE tenants SET engine = 'upstream' WHERE engine NOT IN ('crawlx', 'shadow');
ALTER TABLE tenants ADD CONSTRAINT tenants_engine_check
  CHECK (engine IN ('crawlx', 'upstream', 'shadow'));
