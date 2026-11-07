-- crawlx-storage 0037: revoke pre-envelope checkpoint recovery and retained reads.
-- Keep artifact/checkpoint rows and foreign keys for the structural/audit trail.
-- Do not mark objects deleted: the ordinary artifact reaper must still erase bytes.
-- Only checkpoint-linked legacy storage_state JSON is affected; encrypted envelopes
-- and unrelated storage/export artifacts retain their existing custody and deadlines.
WITH legacy AS (
  UPDATE artifacts a
     SET expires_at = LEAST(COALESCE(a.expires_at, 'infinity'::timestamptz), transaction_timestamp())
   WHERE a.kind = 'storage_state'
     AND a.content_type = 'application/json'
     AND EXISTS (SELECT 1 FROM checkpoints c WHERE c.storage_artifact_id = a.artifact_id)
  RETURNING a.artifact_id
)
UPDATE checkpoints c
   SET expires_at = LEAST(c.expires_at, transaction_timestamp())
  FROM legacy
 WHERE c.storage_artifact_id = legacy.artifact_id;
