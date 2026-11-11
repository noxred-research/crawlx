-- crawlx-storage 0046: `scripted_scroll` joins the `action_fidelity` enum.
--
-- A forced scroll (`DOM.scrollIntoViewIfNeeded` after wheel input failed) is recorded with the
-- `scripted_scroll` fidelity on the diagnostic lane; the enum created in 0001 lacked the label,
-- so finishing such an action failed on PostgreSQL. The `lane_matches_fidelity` CHECK already
-- treats every label outside the three native ones as diagnostic.
-- PostgreSQL-only assumption: `action_fidelity` is a native enum type; a backend without enums
-- (a CHECK-constrained text column) lists the label in that constraint instead.
ALTER TYPE action_fidelity ADD VALUE IF NOT EXISTS 'scripted_scroll';
