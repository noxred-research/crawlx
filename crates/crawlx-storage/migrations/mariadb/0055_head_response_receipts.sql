-- Atomic HEAD observations retain an immutable replay receipt beside the terminal fence.
-- Observation payloads remain in event custody, including volatile zero-retention storage.
ALTER TABLE url_frontier ADD COLUMN IF NOT EXISTS head_response_receipt VARBINARY(32)
  CHECK (head_response_receipt IS NULL OR OCTET_LENGTH(head_response_receipt) = 32);
