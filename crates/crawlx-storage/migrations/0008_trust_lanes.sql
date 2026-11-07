-- crawlx-storage 0008: trust-lane constraints.
--
-- * `network_epochs.lane` must equal the lane of the owning action (trigger instead of the
--   composite foreign key so that an epoch without an action stays representable).
-- * `actions.lane` / `actions.fidelity` are set from the executor's receipt at T2 and are
--   immutable afterwards; `network_epochs.lane` is immutable from the start.
-- * `trusted_reachable_states`: states reachable from a root state through transitions whose
--   action ran on the trusted lane. A root is a state no transition leads to (the first
--   observation of a session). Consumers of coverage and the corpus require both
--   `lane = 'trusted_ui'` and `before_state_id` in this set.
CREATE FUNCTION network_epochs_lane_matches_action() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE action_lane trust_lane;
BEGIN
  IF NEW.action_id IS NULL THEN RETURN NEW; END IF;
  SELECT lane INTO action_lane FROM actions WHERE action_id = NEW.action_id;
  IF action_lane IS NULL THEN
    RAISE EXCEPTION 'network_epochs.action_id % has no actions row', NEW.action_id USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF action_lane <> NEW.lane THEN
    RAISE EXCEPTION 'network_epochs.lane % differs from actions.lane % (action %)', NEW.lane, action_lane, NEW.action_id
      USING ERRCODE = 'check_violation', CONSTRAINT = 'network_epochs_lane_matches_action';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER network_epochs_lane BEFORE INSERT OR UPDATE OF action_id, lane ON network_epochs
  FOR EACH ROW EXECUTE FUNCTION network_epochs_lane_matches_action();

CREATE FUNCTION network_epochs_lane_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.lane IS DISTINCT FROM OLD.lane THEN
    RAISE EXCEPTION 'network_epochs.lane is immutable (epoch %)', OLD.epoch_id
      USING ERRCODE = 'check_violation', CONSTRAINT = 'network_epochs_lane_immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER network_epochs_lane_immutable BEFORE UPDATE OF lane ON network_epochs
  FOR EACH ROW EXECUTE FUNCTION network_epochs_lane_immutable();

-- T2 is the outcome write: once an action is succeeded/failed/unknown (or reconciled from
-- one of those) its lane and fidelity are evidence and cannot change. The T2 statement itself
-- runs with OLD.status = 'intended' and may set both from the receipt.
CREATE FUNCTION actions_lane_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.lane IS DISTINCT FROM OLD.lane OR NEW.fidelity IS DISTINCT FROM OLD.fidelity)
     AND OLD.status IN ('succeeded','failed','unknown','reconciled') THEN
    RAISE EXCEPTION 'actions.lane/fidelity are immutable after T2 (action %, status %)', OLD.action_id, OLD.status
      USING ERRCODE = 'check_violation', CONSTRAINT = 'actions_lane_immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER actions_lane_immutable BEFORE UPDATE OF lane, fidelity ON actions
  FOR EACH ROW EXECUTE FUNCTION actions_lane_immutable();

CREATE VIEW trusted_reachable_states AS
  WITH RECURSIVE reach AS (
    SELECT s.run_id, s.state_id
      FROM states s
     WHERE NOT EXISTS (SELECT 1 FROM transitions t WHERE t.after_state_id = s.state_id)
    UNION
    SELECT t.run_id, t.after_state_id
      FROM transitions t
      JOIN actions a ON a.action_id = t.action_id
      JOIN reach r ON r.state_id = t.before_state_id
     WHERE a.lane = 'trusted_ui' AND t.after_state_id IS NOT NULL
  )
  SELECT run_id, state_id FROM reach;
