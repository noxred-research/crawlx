-- crawlx-storage 0017: stored-scrape lookup. `maxAge`, `minAge`, `lockdown` and
-- `changeTracking` find the most recent page of one URL across the runs of a tenant.
CREATE INDEX pages_url_recent ON pages (url_hash, fetched_at DESC);
