-- Payment Request expiry, the observation tail, late settlement, and the
-- marketplace `resolve` record (W1.4b, design §B.9 / §B.11.1).
--
-- `expires_at` becomes mandatory: every delivered Payment Request carries an
-- expiry the buyer's wallet enforces, and the observer tick moves the invoice
-- `observing → expired_tail` at `expires_at` and `expired_tail →
-- expired_final` at `expires_at + expiry_tail` (config `bitcoin.expiry_tail`,
-- default 24 h, timestamp-derived from `expires_at` on the server clock).
-- `expired_tail_at` / `expired_final_at` record those transitions.
--
-- Legacy rows — invoices the Locks `/invoices` path created while
-- `expires_at` was still caller-optional (NULL since 0014) — are backfilled
-- to `created_at + 24 hours` (the `max_request_expiry` default) so they enter
-- the normal expiry path rather than being observed forever; the column is
-- then closed to NOT NULL. The backfill covers every NULL row, not only
-- `observing` ones: the value is inert on final states and the NOT NULL
-- invariant is total.
--
-- `bitcoin_observations.late_settlement` marks any eligible observation
-- recorded while its invoice is `expired_tail`: it can never drive `paid` —
-- the marketplace routes it to `manual_review` (§B.9).
--
-- `resolution` / `resolved_at` are the marketplace's one-way money-outcome
-- record written by `POST …/resolve`: `paid_manually` finalizes to
-- `resolved_paid_manually`, `refunded`/`abandoned` to `resolved_closed`, and
-- on `expired_final` the pair is metadata-only (the state never changes).
-- The CHECKs pin: the pair is both-NULL or both-set; a resolved state
-- requires its matching resolution; the 0014 baseline-state CHECK is already
-- total over the §B.11.1 state set and is deliberately NOT rewritten here.

ALTER TABLE invoices
    ADD COLUMN expired_tail_at TIMESTAMPTZ,
    ADD COLUMN expired_final_at TIMESTAMPTZ,
    ADD COLUMN resolution TEXT,
    ADD COLUMN resolved_at TIMESTAMPTZ;

ALTER TABLE bitcoin_observations
    ADD COLUMN late_settlement BOOLEAN NOT NULL DEFAULT false;

UPDATE invoices
SET expires_at = created_at + INTERVAL '24 hours'
WHERE expires_at IS NULL;

ALTER TABLE invoices
    ALTER COLUMN expires_at SET NOT NULL;

ALTER TABLE invoices
    ADD CONSTRAINT invoices_resolution_check CHECK (
        resolution IN ('paid_manually', 'refunded', 'abandoned')
    );

ALTER TABLE invoices
    ADD CONSTRAINT invoices_resolution_pairing_check CHECK (
        (resolution IS NULL) = (resolved_at IS NULL)
    );

ALTER TABLE invoices
    ADD CONSTRAINT invoices_resolved_state_check CHECK (
        (baseline_state NOT IN ('resolved_paid_manually', 'resolved_closed')
         OR resolution IS NOT NULL)
        AND (baseline_state <> 'resolved_paid_manually'
             OR resolution = 'paid_manually')
        AND (baseline_state <> 'resolved_closed'
             OR resolution IN ('refunded', 'abandoned'))
    );
