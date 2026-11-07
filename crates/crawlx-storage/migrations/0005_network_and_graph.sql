-- crawlx-storage 0005: network epochs, traffic, transitions, enablement edges, approvals.
CREATE TABLE network_epochs (epoch_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid NOT NULL REFERENCES crawl_sessions,
  action_id uuid REFERENCES actions, lane trust_lane NOT NULL, started_at timestamptz NOT NULL, settled_at timestamptz,
  request_count int NOT NULL DEFAULT 0, unique_operations int NOT NULL DEFAULT 0, settle_timeout boolean NOT NULL DEFAULT false);
CREATE INDEX network_epochs_action ON network_epochs (action_id);
-- Origins follow crawlx-core `TrafficOrigin`: 'sse' is 'event_source' and the fetch plane is added.
CREATE TABLE traffic_events (event_id bigint GENERATED ALWAYS AS IDENTITY, occurred_at timestamptz NOT NULL,
  run_id uuid NOT NULL, epoch_id uuid NOT NULL, seq int NOT NULL, lane trust_lane NOT NULL,
  origin text NOT NULL CHECK (origin IN ('page','service_worker','websocket','event_source','fetch_plane')), third_party boolean NOT NULL DEFAULT false,
  late boolean NOT NULL DEFAULT false, attribution_confidence text NOT NULL DEFAULT 'high', method text, url_redacted text, url_hash bytea NOT NULL, status int,
  request_headers jsonb, response_headers jsonb,
  secret_value_hashes bytea[], body_artifact_id uuid, request_body_artifact_id uuid, finished_at timestamptz,
  PRIMARY KEY (event_id, occurred_at)) PARTITION BY RANGE (occurred_at);
-- Rows outside a pre-created monthly partition land here; `retention::ensure_traffic_partitions` creates partitions ahead of time.
CREATE TABLE traffic_events_default PARTITION OF traffic_events DEFAULT;
CREATE INDEX traffic_events_epoch ON traffic_events (epoch_id, seq);
CREATE INDEX traffic_events_run ON traffic_events (run_id);
CREATE TABLE transitions (transition_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid NOT NULL REFERENCES crawl_sessions,
  before_state_id uuid NOT NULL REFERENCES states, action_id uuid NOT NULL UNIQUE REFERENCES actions, network_epoch_id uuid REFERENCES network_epochs,
  after_state_id uuid REFERENCES states, lane trust_lane NOT NULL, settle_report jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX transitions_before ON transitions (run_id, before_state_id);
-- context_cluster_id carries no FK for the same reason as action_contexts.state_cluster_id.
CREATE TABLE enablement_edges (edge_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, source_context_id bigint NOT NULL REFERENCES action_contexts,
  context_cluster_id uuid, target_kind text NOT NULL CHECK (target_kind IN ('element','state')), target_key bytea NOT NULL,
  support int NOT NULL DEFAULT 0, failures int NOT NULL DEFAULT 0,
  weak_support int NOT NULL DEFAULT 0,
  p_success double precision GENERATED ALWAYS AS ((support + 0.5 * weak_support + 1) / (support + 0.5 * weak_support + failures + 2)) STORED,
  latency_ms_ewma real, risk real NOT NULL DEFAULT 0, last_observed_at timestamptz, last_verified_build text, algo_version smallint NOT NULL,
  UNIQUE NULLS NOT DISTINCT (run_id, source_context_id, context_cluster_id, target_kind, target_key));
CREATE TABLE approvals (approval_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, action_id uuid NOT NULL REFERENCES actions,
  safety_decision_id uuid NOT NULL REFERENCES safety_decisions, risk_class risk_class NOT NULL, summary jsonb NOT NULL, requested_by text NOT NULL DEFAULT 'safety_kernel',
  decision text NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approved','denied','expired')), decided_by uuid REFERENCES api_keys(key_id), decided_at timestamptz,
  reason text, consumed_at timestamptz,
  requested_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE INDEX approvals_pending ON approvals (run_id, expires_at) WHERE decision = 'pending';
