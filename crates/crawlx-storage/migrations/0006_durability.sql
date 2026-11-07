-- crawlx-storage 0006: artifacts, checkpoints, workflows, event outbox, webhooks, audit chain, error view.
CREATE TABLE artifacts (artifact_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, run_id uuid REFERENCES crawl_runs,
  kind text NOT NULL CHECK (kind IN ('markdown','html','raw_html','dom_snapshot','ax_tree','screenshot','response_body','manifest','plan','storage_state','robots','model_io','evidence')),
  bucket text NOT NULL, object_key text NOT NULL, size_bytes bigint NOT NULL, content_digest bytea NOT NULL,
  content_type text NOT NULL, sensitivity sensitivity_class NOT NULL, encryption text NOT NULL DEFAULT 'sse-kms', key_id text,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, deleted_at timestamptz);
-- One artifacts row per use: identical content in a run shares an object, so
-- (bucket, object_key) is indexed but not unique.
CREATE INDEX artifacts_object ON artifacts (bucket, object_key);
CREATE INDEX artifacts_sweep ON artifacts (expires_at) WHERE deleted_at IS NULL AND expires_at IS NOT NULL;
CREATE INDEX artifacts_run ON artifacts (run_id, kind);
ALTER TABLE authorization_records ADD FOREIGN KEY (evidence_artifact_id) REFERENCES artifacts;
CREATE TABLE checkpoints (checkpoint_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid NOT NULL REFERENCES crawl_sessions,
  epoch_navigation bigint NOT NULL, epoch_document bigint NOT NULL, epoch_mutation bigint NOT NULL, action_seq bigint NOT NULL,
  reason text NOT NULL CHECK (reason IN ('cadence_actions','cadence_time','pre_mutation','pause','approval_wait','shutdown')),
  storage_artifact_id uuid NOT NULL REFERENCES artifacts,
  cookies_ref text, url_hash bytea, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE INDEX checkpoints_latest ON checkpoints (session_id, action_seq DESC);
CREATE TABLE workflow_runs (workflow_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid REFERENCES crawl_sessions,
  planner_decision_id uuid REFERENCES model_decisions, plan_artifact_id uuid REFERENCES artifacts,
  status text NOT NULL CHECK (status IN ('planned','running','completed','aborted','invalid')), assertions jsonb NOT NULL DEFAULT '[]',
  coverage_tags text[] NOT NULL DEFAULT '{}', entities_created jsonb NOT NULL DEFAULT '[]', started_at timestamptz, finished_at timestamptz);
CREATE TABLE crawl_events (run_id uuid NOT NULL REFERENCES crawl_runs, seq bigint NOT NULL, type text NOT NULL, payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (run_id, seq));
CREATE TABLE webhook_deliveries (delivery_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, event_seq bigint NOT NULL, event_type text NOT NULL,
  url text NOT NULL, status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','dead')), attempts smallint NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz, last_status int, last_error text, FOREIGN KEY (run_id, event_seq) REFERENCES crawl_events);
CREATE INDEX webhook_due ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE TABLE audit_events (audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, tenant_id uuid, run_id uuid, actor text NOT NULL, event text NOT NULL,
  subject jsonb NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(), prev_hash bytea NOT NULL, entry_hash bytea NOT NULL);
CREATE VIEW run_errors AS
  SELECT run_id, 'url'::text AS plane, frontier_id::text AS ref, COALESCE(error_code, denial_reason) AS code, canonical_url AS subject, finished_at AS occurred_at
    FROM url_frontier WHERE status IN ('failed','abandoned','unreachable','policy_blocked','robots_blocked')
  UNION ALL
  SELECT run_id, 'interaction', action_id::text, COALESCE(outcome->>'code', status::text), action_kind::text, finished_at
    FROM actions WHERE status IN ('failed','unknown') OR hold = 'denied';
