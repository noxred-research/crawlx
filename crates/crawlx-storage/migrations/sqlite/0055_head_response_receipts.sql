-- Atomic HEAD observations retain an immutable replay receipt beside the terminal fence.
-- Observation payloads remain in event custody, including volatile zero-retention storage.
ALTER TABLE url_frontier ADD COLUMN head_response_receipt BLOB
  CHECK (head_response_receipt IS NULL OR length(head_response_receipt) = 32);
