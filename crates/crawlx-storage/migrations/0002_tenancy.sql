-- crawlx-storage 0002: tenancy, API keys, idempotency, authorization records.
CREATE TABLE tenants (tenant_id uuid PRIMARY KEY, name text NOT NULL, region text NOT NULL DEFAULT 'default', zdr_enforced boolean NOT NULL DEFAULT false,
  kms_key_id text NOT NULL, plan jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), disabled_at timestamptz);
CREATE TABLE api_keys (key_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, prefix text NOT NULL UNIQUE, key_hash bytea NOT NULL,
  scopes text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), last_used_at timestamptz, expires_at timestamptz, revoked_at timestamptz);
CREATE TABLE idempotency_keys (tenant_id uuid NOT NULL REFERENCES tenants, idem_key text NOT NULL CHECK (length(idem_key) BETWEEN 1 AND 255),
  request_hash bytea NOT NULL, state text NOT NULL CHECK (state IN ('in_progress','done')), response_status int, response_body jsonb, run_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, idem_key));
CREATE TABLE authorization_records (record_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants, version int NOT NULL DEFAULT 1,
  body jsonb NOT NULL, body_digest bytea NOT NULL, evidence_artifact_id uuid, valid_from timestamptz NOT NULL, valid_to timestamptz NOT NULL CHECK (valid_to > valid_from),
  created_by uuid NOT NULL REFERENCES api_keys(key_id), created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz);
