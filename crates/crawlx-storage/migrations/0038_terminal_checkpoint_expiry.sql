-- Terminal state revokes credential recovery in the same transaction as run completion.
-- Objects remain indexed until the configured artifact reaper acknowledges physical erasure.
CREATE INDEX checkpoints_run_expiry ON checkpoints (run_id, expires_at);
DO $migration$
BEGIN
  EXECUTE format($definition$
    CREATE FUNCTION revoke_terminal_checkpoints() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS $body$
    BEGIN
      IF NEW.status::text IN ('completed', 'failed', 'cancelled') THEN
        UPDATE %1$I.artifacts
           SET expires_at = LEAST(expires_at, COALESCE(NEW.finished_at, clock_timestamp()))
         WHERE run_id = NEW.run_id AND sensitivity::text = 'credential_bearing';
        UPDATE %1$I.checkpoints
           SET expires_at = LEAST(expires_at, COALESCE(NEW.finished_at, clock_timestamp()))
         WHERE run_id = NEW.run_id;
      END IF;
      RETURN NEW;
    END
    $body$
  $definition$, current_schema());
  EXECUTE format($definition$
    CREATE FUNCTION bound_inserted_checkpoint_artifact() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS $body$
    DECLARE owner_status text; owner_finished timestamptz;
    BEGIN
      IF NEW.sensitivity::text = 'credential_bearing' THEN
        -- Match run completion's lock order: run first, then artifact. INSERT has no
        -- existing artifact row whose lock could invert the completion lock order.
        SELECT status::text, finished_at INTO owner_status, owner_finished
          FROM %1$I.crawl_runs WHERE run_id = NEW.run_id FOR UPDATE;
        IF owner_status IN ('completed', 'failed', 'cancelled') THEN
          NEW.expires_at := LEAST(NEW.expires_at, COALESCE(owner_finished, clock_timestamp()));
        END IF;
      END IF;
      RETURN NEW;
    END
    $body$
  $definition$, current_schema());
END
$migration$;

REVOKE ALL ON FUNCTION revoke_terminal_checkpoints() FROM PUBLIC;
REVOKE ALL ON FUNCTION bound_inserted_checkpoint_artifact() FROM PUBLIC;
CREATE TRIGGER terminal_checkpoint_expiry AFTER UPDATE OF status ON crawl_runs
FOR EACH ROW EXECUTE FUNCTION revoke_terminal_checkpoints();
CREATE TRIGGER terminal_checkpoint_artifact BEFORE INSERT ON artifacts
FOR EACH ROW EXECUTE FUNCTION bound_inserted_checkpoint_artifact();

-- Existing terminal runs cannot retain their old one-day recovery window.
UPDATE artifacts a
   SET expires_at = LEAST(a.expires_at, COALESCE(r.finished_at, transaction_timestamp()))
  FROM crawl_runs r
 WHERE a.run_id = r.run_id AND a.sensitivity::text = 'credential_bearing'
   AND r.status::text IN ('completed', 'failed', 'cancelled');
UPDATE checkpoints c
   SET expires_at = LEAST(c.expires_at, COALESCE(r.finished_at, transaction_timestamp()))
  FROM crawl_runs r
 WHERE c.run_id = r.run_id AND r.status::text IN ('completed', 'failed', 'cancelled');
