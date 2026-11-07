-- crawlx-storage 0011: operator controls (§7 RB-11, `crawlx admin`)
-- and the strangler gateway pieces (tenant engine flag, shadow runs).

-- Cluster-wide runtime settings flipped by `crawlx admin` and observed by every worker at its
-- next lease claim / action boundary. One row per key; the admission mode is the first key.
CREATE TABLE cluster_settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL DEFAULT 'migration');
INSERT INTO cluster_settings (key, value) VALUES ('scheduler.admission', 'open');
ALTER TABLE cluster_settings ADD CONSTRAINT cluster_settings_admission
  CHECK (key <> 'scheduler.admission' OR value IN ('open', 'drain', 'frozen'));

-- Per-tenant engine flag read by the gateway and enforced by the compat facade.
--   crawlx    - compat requests are served by crawlx (default; the facade accepts them)
--   firecrawl - the tenant is routed to Firecrawl; the facade refuses non-shadow creates
--   shadow    - only mirrored (`X-Crawlx-Shadow: 1`) requests are accepted
ALTER TABLE tenants ADD COLUMN engine text NOT NULL DEFAULT 'crawlx'
  CHECK (engine IN ('crawlx', 'firecrawl', 'shadow'));

-- Shadow runs are tagged by run_kind; they never deliver webhooks and keep
-- results for 24 hours (the facade rewrites the request before admission).
ALTER TABLE crawl_runs DROP CONSTRAINT crawl_runs_run_kind_check;
ALTER TABLE crawl_runs ADD CONSTRAINT crawl_runs_run_kind_check
  CHECK (run_kind IN ('crawl', 'replay', 'shadow'));
CREATE INDEX crawl_runs_shadow ON crawl_runs (created_at) WHERE run_kind = 'shadow';
