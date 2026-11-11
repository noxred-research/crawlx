-- Reserve interaction for session-observation custody with surviving exact epoch proof.
UPDATE url_frontier AS f
JOIN frontier_batch_receipts AS b ON b.run_id = f.run_id
SET f.via = 'interaction'
WHERE JSON_LENGTH(b.receipt, '$.inserted') = 1
  AND JSON_UNQUOTE(JSON_EXTRACT(b.receipt, '$.inserted[0]')) = CAST(f.frontier_id AS CHAR)
  AND JSON_UNQUOTE(JSON_EXTRACT(f.request_envelope, '$.metadata.observed_epoch')) = LOWER(HEX(b.batch_id));
-- Expired volatile envelopes cannot prove provenance; dynamic URL leasing fails closed.
