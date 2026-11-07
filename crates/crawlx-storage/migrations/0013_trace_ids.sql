-- crawlx-storage 0013: span-to-row join.
--
-- The worker records the trace id of its `crawl` span on the run, and every `actions`
-- row carries the trace id of the span tree it was proposed under, so an exported trace
-- can be joined to the rows it produced without a lookup table. Both columns are nullable:
-- rows written outside a span tree, or by a build whose subscriber has no trace-id layer,
-- have none. A present value is the 32 lowercase hex digits of a 16-byte trace id, the
-- textual form `crawlx_core::TraceId` emits.
ALTER TABLE crawl_runs ADD COLUMN trace_id text
  CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$');
ALTER TABLE actions ADD COLUMN trace_id text
  CHECK (trace_id IS NULL OR trace_id ~ '^[0-9a-f]{32}$');
