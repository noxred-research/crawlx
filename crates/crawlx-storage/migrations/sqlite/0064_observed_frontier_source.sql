-- Reserve interaction for session-observation custody with surviving exact epoch proof.
UPDATE url_frontier AS f
SET via = 'interaction'
WHERE EXISTS (
  SELECT 1 FROM frontier_batch_receipts AS b
  WHERE b.run_id = f.run_id
    AND json_array_length(b.receipt, '$.inserted') = 1
    AND json_extract(b.receipt, '$.inserted[0]') = f.frontier_id
    AND json_extract(f.request_envelope, '$.metadata.observed_epoch') = lower(hex(b.batch_id))
);
-- Expired volatile envelopes cannot prove provenance; dynamic URL leasing fails closed.
