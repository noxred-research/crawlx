-- Reserve the existing interaction source for fenced session-observation custody.
-- Match both the retained epoch marker and its exact singleton append receipt.
UPDATE url_frontier AS f
SET via = 'interaction'
FROM frontier_batch_receipts AS b
WHERE b.run_id = f.run_id
  AND b.receipt->'inserted' = jsonb_build_array(f.frontier_id)
  AND f.request_envelope->'metadata'->>'observed_epoch' = encode(b.batch_id, 'hex');

-- Expired volatile envelopes erase the epoch proof. Do not invent provenance from
-- a batch receipt alone: ordinary batches have the same receipt shape. Dynamic
-- runs are excluded from ordinary URL leasing independently of row provenance.
