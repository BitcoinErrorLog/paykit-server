-- First-seen payment facts (design §B.9). Every output reported at an
-- invoice address keeps the facts of its first sighting, and no report is
-- dropped or allowed to hide another payment to the same invoice.
--
-- Stop-start: after this migration the candidate key is per outpoint, so a
-- binary that predates it (`ON CONFLICT (invoice_id)`) cannot write
-- candidates. Stop the old image before the first image that contains 0027
-- starts.
--
-- 1. Candidate lateness. A matching output first seen already confirmed is
--    recorded in `bitcoin_observation_candidates` before its transaction is
--    resolved, which can happen after the invoice has moved to
--    `expired_tail`. The candidate records whether its outpoint was first
--    seen in the tail, and the observation row inherits that value and the
--    candidate's `created_at`. NULL means "not recorded" (rows written
--    before this migration); the observation write then falls back to the
--    invoice state at resolution, which never marks a tail sighting on time.
--    Backfill: a candidate whose invoice has never entered the tail
--    (`expired_tail_at IS NULL`) was necessarily first seen while
--    `observing`, so it is on time. Candidates of invoices that have entered
--    the tail stay NULL: their timestamps and `expired_tail_at` come from
--    different transactions' clocks and cannot prove the order safely.
--
-- 2. One candidate per outpoint. The previous key allowed one candidate per
--    invoice and replaced it only with a lower-height output, so a different
--    output first seen later at the same or a higher height was silently
--    dropped. Each outpoint now keeps its own candidate. Existing rows are
--    unique per invoice and therefore unique per outpoint.
--
-- 3. Refused reports. A report that contradicts a recorded first-seen fact
--    (a different amount for a recorded outpoint or candidate, or an outpoint
--    already recorded under another invoice) is refused without quarantining
--    the invoice, so it cannot hide a valid payment. The refusal is kept here
--    for manual handling. No amounts or outpoints are stored in plaintext.

ALTER TABLE bitcoin_observation_candidates
    ADD COLUMN late_settlement BOOLEAN;

UPDATE bitcoin_observation_candidates AS candidates
SET late_settlement = FALSE
FROM invoices
WHERE invoices.id = candidates.invoice_id
  AND invoices.expired_tail_at IS NULL;

ALTER TABLE bitcoin_observation_candidates
    DROP CONSTRAINT bitcoin_observation_candidates_pkey,
    ADD PRIMARY KEY (invoice_id, txid, vout);

CREATE TABLE bitcoin_observation_refusals (
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
    outpoint_lookup_hash BYTEA NOT NULL CHECK (octet_length(outpoint_lookup_hash) = 32),
    reason TEXT NOT NULL CHECK (reason IN ('amount_conflict', 'outpoint_owned_by_other_invoice')),
    first_refused_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_refused_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    refusal_count INTEGER NOT NULL DEFAULT 1 CHECK (refusal_count >= 1),
    PRIMARY KEY (invoice_id, outpoint_lookup_hash, reason)
);

GRANT SELECT, INSERT, UPDATE ON TABLE bitcoin_observation_refusals TO paykit;
GRANT SELECT ON TABLE bitcoin_observation_refusals TO paykit_readonly;
