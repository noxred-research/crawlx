-- Derived scheduling metadata only: never copy request URLs or methods into new columns.
-- NULL identifies pre-cutover rows. Priority leasing backfills them through the existing
-- retention-aware request reader before selecting a global batch.
ALTER TABLE url_frontier ADD COLUMN strategy_score integer
  CHECK (strategy_score BETWEEN 0 AND 65539);
CREATE INDEX url_frontier_score_backfill ON url_frontier (run_id, frontier_id)
  WHERE status IN ('pending','leased') AND strategy_score IS NULL;
CREATE INDEX url_frontier_strategy_claim ON url_frontier
  (run_id, priority DESC, strategy_score, depth, frontier_id) WHERE status = 'pending';
