-- Deployment-wide feedback remains in the existing origin admission authority.
-- Operational origin pacing is deliberately shared across tenants and workers.
ALTER TABLE origin_admission
    ADD COLUMN cooldown_until timestamptz NOT NULL DEFAULT '-infinity',
    ADD COLUMN throttle_delay_us bigint NOT NULL DEFAULT 0 CHECK (throttle_delay_us >= 0),
    ADD COLUMN throttle_decays_at timestamptz NOT NULL DEFAULT '-infinity';
-- Existing owner-only privileges from migration 0023 remain unchanged.
