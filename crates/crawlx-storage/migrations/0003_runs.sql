-- crawlx-storage 0003: runs, sessions, URL frontier, pages.
CREATE TABLE crawl_runs (
  run_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, run_kind text NOT NULL DEFAULT 'crawl' CHECK (run_kind IN ('crawl','replay')),
  replay_of uuid REFERENCES crawl_runs(run_id), replay_spec jsonb, status run_status NOT NULL DEFAULT 'queued', terminal_reason terminal_reason,
  mode crawl_mode NOT NULL, seed bigint NOT NULL, safety_profile safety_profile NOT NULL, authorization_record_id uuid REFERENCES authorization_records,
  policy_version int NOT NULL, identity_version smallint NOT NULL, state_algo_version smallint NOT NULL, query_classifier_version smallint NOT NULL,
  config jsonb NOT NULL, config_digest bytea NOT NULL,
  counters jsonb NOT NULL DEFAULT '{}',
  retention_mode retention_mode NOT NULL, retention_days int NOT NULL, expires_at timestamptz,
  lease_owner uuid, lease_expires_at timestamptz, fencing_token bigint NOT NULL DEFAULT 0, event_seq bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, finished_at timestamptz, deadline_at timestamptz,
  pause_requested_at timestamptz, cancel_requested_at timestamptz, purge_requested_at timestamptz,
  CONSTRAINT terminal_consistent CHECK ((status IN ('completed','failed','cancelled')) = (terminal_reason IS NOT NULL)),
  CONSTRAINT auth_required CHECK (safety_profile <> 'authorized_security_test' OR authorization_record_id IS NOT NULL),
  CONSTRAINT zdr_days CHECK (retention_mode <> 'zdr' OR retention_days = 0));
CREATE INDEX crawl_runs_tenant ON crawl_runs (tenant_id, run_id DESC);
CREATE INDEX crawl_runs_active ON crawl_runs (lease_expires_at) WHERE status IN ('queued','running','pausing','cancelling');
CREATE INDEX crawl_runs_expiry ON crawl_runs (expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE crawl_sessions (session_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, role text NOT NULL, run_index int NOT NULL,
  schedule_slot int NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','recovering','completed','failed','cancelled')),
  browser_build text, cdp_revision text, action_seq bigint NOT NULL DEFAULT 0,
  browser_user_agent text, browser_pinned boolean,               -- additive: BrowserBuildInfo fields the base DDL does not list
  launch_profile text NOT NULL DEFAULT 'standard' CHECK (launch_profile IN ('standard','stealth')),
  console_capture boolean NOT NULL DEFAULT true,
  lease_owner uuid, lease_expires_at timestamptz, fencing_token bigint, last_heartbeat_at timestamptz, started_at timestamptz, finished_at timestamptz,
  UNIQUE (run_id, role, run_index), UNIQUE (run_id, schedule_slot));
CREATE INDEX crawl_sessions_claim ON crawl_sessions (run_id, schedule_slot) WHERE status NOT IN ('completed','failed','cancelled');
CREATE INDEX crawl_sessions_reap ON crawl_sessions (lease_expires_at) WHERE status IN ('running','recovering');
CREATE TABLE url_frontier (frontier_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs,
  canonical_key bytea NOT NULL,
  canonical_url text, origin text NOT NULL,
  query_schema jsonb NOT NULL DEFAULT '{}',                      -- serialized CanonicalUrl (route template + classified params) so the row round-trips
  depth smallint NOT NULL, priority real NOT NULL DEFAULT 0, via text NOT NULL CHECK (via IN ('seed','sitemap','link','interaction')),
  parent_id bigint REFERENCES url_frontier,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','succeeded','failed','abandoned','unreachable','policy_blocked','robots_blocked')),
  denial_reason text, error_code text, attempts smallint NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_owner uuid, lease_expires_at timestamptz, fencing_token bigint, discovered_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
  UNIQUE (run_id, canonical_key));
CREATE INDEX url_frontier_claim ON url_frontier (run_id, origin, priority DESC, depth, frontier_id) WHERE status = 'pending';
CREATE INDEX url_frontier_reap ON url_frontier (lease_expires_at) WHERE status = 'leased';
CREATE TABLE pages (page_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid REFERENCES crawl_sessions, frontier_id bigint REFERENCES url_frontier,
  role text NOT NULL DEFAULT 'anonymous', plane text NOT NULL CHECK (plane IN ('http','browser')), url_hash bytea NOT NULL, canonical_url text, final_url text,
  http_status int, content_type text, content_digest bytea, markdown_artifact_id uuid, html_artifact_id uuid, raw_html_artifact_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}', links jsonb,
  observation_epoch jsonb, fetched_at timestamptz NOT NULL, expires_at timestamptz,
  lane text NOT NULL DEFAULT 'diagnostic' CHECK (lane IN ('trusted_ui','diagnostic')), title text, url_meta jsonb,   -- additive: PageRecord fields
  markdown_digest bytea, html_digest bytea,
  UNIQUE (run_id, role, url_hash));
CREATE INDEX pages_expiry ON pages (expires_at) WHERE expires_at IS NOT NULL;
