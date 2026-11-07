-- crawlx-storage 0007: workers and per-origin leases.
CREATE TABLE workers (worker_id uuid PRIMARY KEY, hostname text NOT NULL, version text NOT NULL, capacity jsonb NOT NULL,
  draining boolean NOT NULL DEFAULT false, started_at timestamptz NOT NULL DEFAULT now(), last_heartbeat_at timestamptz NOT NULL);
CREATE TABLE origin_leases (run_id uuid NOT NULL REFERENCES crawl_runs, origin text NOT NULL, owner uuid REFERENCES workers, lease_expires_at timestamptz,
  fencing_token bigint, next_allowed_at timestamptz NOT NULL DEFAULT now(), backoff_until timestamptz, crawl_delay_ms int,
  robots_artifact_id uuid REFERENCES artifacts, robots_status smallint, robots_fetched_at timestamptz, PRIMARY KEY (run_id, origin));
