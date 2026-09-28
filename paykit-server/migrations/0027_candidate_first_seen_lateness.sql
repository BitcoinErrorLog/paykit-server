-- Lateness is a first-seen fact of an output (design §B.9). A matching
-- output first seen already confirmed enters `bitcoin_observation_candidates`
-- and only becomes a `bitcoin_observations` row after its transaction is
-- resolved, which can happen after the invoice has moved to `expired_tail`.
-- The candidate therefore records whether its outpoint was first seen in the
-- tail, and the observation row inherits that value instead of the state at
-- resolution time.
--
-- NULL means "not recorded": rows written before this migration, or by a
-- binary that predates it during a stop-start window. The observation write
-- then falls back to the invoice state at resolution, which is the previous
-- behavior and never marks a tail sighting on time.
--
-- Backfill: a candidate whose invoice has never entered the tail
-- (`expired_tail_at IS NULL`) was necessarily first seen while `observing`,
-- so it is on time. Candidates of invoices that have entered the tail stay
-- NULL: `created_at`/`updated_at` and `expired_tail_at` come from different
-- transactions' clocks and cannot prove the order safely.

ALTER TABLE bitcoin_observation_candidates
    ADD COLUMN late_settlement BOOLEAN;

UPDATE bitcoin_observation_candidates AS candidates
SET late_settlement = FALSE
FROM invoices
WHERE invoices.id = candidates.invoice_id
  AND invoices.expired_tail_at IS NULL;
