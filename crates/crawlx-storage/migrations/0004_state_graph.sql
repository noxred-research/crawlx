-- crawlx-storage 0004: states, clusters, membership, element registry, action-context ledger,
-- safety/model decisions, actions and the status-transition trigger.
CREATE TABLE states (state_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid NOT NULL REFERENCES crawl_sessions,
  route_key text NOT NULL, semantic_affordance_minhash bytea NOT NULL, dom_structure_simhash bigint NOT NULL, visible_identity_digest bytea NOT NULL,
  frame_tree_digest bytea NOT NULL, network_operation_digest bytea, visual_phash bigint, browser_storage_digest bytea,
  masks jsonb NOT NULL DEFAULT '[]',
  epoch_navigation bigint NOT NULL, epoch_document bigint NOT NULL, epoch_mutation bigint NOT NULL, state_algo_version smallint NOT NULL,
  manifest_artifact_id uuid, observed_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
  observed_url jsonb, artifacts jsonb NOT NULL DEFAULT '[]');    -- additive: NewState.url and (kind, ArtifactRef) list
CREATE INDEX states_route ON states (run_id, route_key);
CREATE INDEX states_session ON states (session_id, epoch_navigation, epoch_document, epoch_mutation);
CREATE INDEX states_lsh ON states (run_id, substring(semantic_affordance_minhash FROM 1 FOR 8));
CREATE TABLE state_clusters (cluster_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, version int NOT NULL DEFAULT 1,
  prototype_state_id uuid NOT NULL REFERENCES states, status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','superseded')),
  superseded_by uuid REFERENCES state_clusters, algo_version smallint NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX state_clusters_run ON state_clusters (run_id);
CREATE TABLE state_cluster_membership (state_id uuid NOT NULL REFERENCES states, cluster_id uuid NOT NULL REFERENCES state_clusters,
  decision_version int NOT NULL, similarity real NOT NULL, active boolean NOT NULL DEFAULT true, assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (state_id, cluster_id, decision_version));
CREATE UNIQUE INDEX scm_one_active ON state_cluster_membership (state_id) WHERE active;
CREATE INDEX scm_cluster ON state_cluster_membership (cluster_id) WHERE active;
CREATE TABLE elements (run_id uuid NOT NULL REFERENCES crawl_runs, identity_hash bytea NOT NULL, identity_version smallint NOT NULL,
  components jsonb,
  interactability jsonb NOT NULL DEFAULT '{}', first_seen_state_id uuid REFERENCES states,
  first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (run_id, identity_hash, identity_version));
-- state_cluster_id carries no FK (deviation): a cluster row is created together with its first
-- state, while a proposal may be journaled before that state write has landed.
CREATE TABLE action_contexts (context_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs,
  context_hash bytea NOT NULL,                                   -- additive: ActionContextKey::id() (16 bytes), the key EdgeRecord.source refers to
  principal text NOT NULL, route_template text NOT NULL, identity_hash bytea NOT NULL, identity_version smallint NOT NULL, action_kind action_kind NOT NULL,
  input_class text NOT NULL DEFAULT 'none', resource_context resource_context NOT NULL DEFAULT 'none', state_cluster_id uuid NOT NULL,
  attempts int NOT NULL DEFAULT 0, succeeded int NOT NULL DEFAULT 0, succeeded_trusted int NOT NULL DEFAULT 0, failed int NOT NULL DEFAULT 0,
  unknown int NOT NULL DEFAULT 0, denied int NOT NULL DEFAULT 0, first_seen_at timestamptz NOT NULL DEFAULT now(),
  first_exercised_at timestamptz, last_exercised_at timestamptz, last_action_id uuid,
  UNIQUE (run_id, context_hash),
  UNIQUE (run_id, principal, route_template, identity_hash, identity_version, action_kind, input_class, resource_context, state_cluster_id));
CREATE TABLE safety_decisions (decision_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, action_id uuid,   -- NULL for audit-only verdicts; not an FK (written before the action row)
  session_id uuid,
  risk_class risk_class NOT NULL, verdict text NOT NULL CHECK (verdict IN ('allow','deny','approval_required')), profile safety_profile NOT NULL, rules text[] NOT NULL, evidence jsonb NOT NULL,
  policy_version int NOT NULL, authorization_record_id uuid, decided_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX safety_decisions_action ON safety_decisions (action_id);
CREATE INDEX safety_decisions_run ON safety_decisions (run_id);
CREATE TABLE model_decisions (decision_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid REFERENCES crawl_sessions, action_id uuid,
  kind text NOT NULL CHECK (kind IN ('rank','classify_input','classify_form','plan','risk_hint')), mode text NOT NULL CHECK (mode IN ('shadow','advisory','active')),
  provider text NOT NULL, model text NOT NULL, model_version text NOT NULL, calibration_version text, confidence real, output jsonb NOT NULL,
  prompt_digest bytea NOT NULL, io_artifact_id uuid, latency_ms int, breaker_state text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE actions (action_id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES crawl_runs, session_id uuid NOT NULL REFERENCES crawl_sessions,
  seq bigint NOT NULL, context_id bigint NOT NULL REFERENCES action_contexts, action_kind action_kind NOT NULL,
  params jsonb NOT NULL DEFAULT '{}',
  strategy text NOT NULL, strategy_version int NOT NULL, epoch_navigation bigint NOT NULL, epoch_document bigint NOT NULL, epoch_mutation bigint NOT NULL,
  fidelity action_fidelity NOT NULL, lane trust_lane NOT NULL, safety_decision_id uuid NOT NULL REFERENCES safety_decisions, model_decision_id uuid,   -- no FK (deviation): no repository in this slice writes model_decisions rows
  status action_status NOT NULL DEFAULT 'proposed', hold text NOT NULL DEFAULT 'none' CHECK (hold IN ('none','denied','awaiting_approval','stale')), attempt smallint NOT NULL DEFAULT 0,
  reconcile_resolution text CHECK (reconcile_resolution IN ('applied','not_applied','indeterminate')), outcome jsonb,
  proposed_at timestamptz NOT NULL DEFAULT now(), intended_at timestamptz, finished_at timestamptz,
  before_state_id uuid, reconciled_at timestamptz,               -- additive: reconciliation evidence columns
  UNIQUE (session_id, seq),
  CONSTRAINT lane_matches_fidelity CHECK ((lane = 'trusted_ui') = (fidelity IN ('native_pointer','native_keyboard','native_text_input'))));
CREATE INDEX actions_schedulable ON actions (run_id, session_id, proposed_at) WHERE status IN ('proposed','reconciled') AND hold = 'none';
CREATE INDEX actions_needs_reconcile ON actions (session_id) WHERE status IN ('intended','unknown');
CREATE INDEX actions_run ON actions (run_id, status);
CREATE FUNCTION actions_enforce_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  IF (OLD.status, NEW.status) IN (('proposed','intended'),('intended','succeeded'),('intended','failed'),('intended','unknown'),
       ('succeeded','reconciled'),('failed','reconciled'),('unknown','reconciled'))
     OR (OLD.status = 'reconciled' AND NEW.status = 'intended' AND OLD.reconcile_resolution = 'not_applied' AND NEW.attempt = OLD.attempt + 1)
  THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'illegal actions.status transition % -> %', OLD.status, NEW.status;
END $$;
CREATE TRIGGER actions_transition BEFORE UPDATE OF status ON actions FOR EACH ROW EXECUTE FUNCTION actions_enforce_transition();
