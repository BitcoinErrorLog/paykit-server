-- Two-phase creation and activation (W1.1c, design §B.11).
--
-- Phase 1 (prepare) commits the invoice in `awaiting_baseline` and lands it in
-- `prepared` once the creation baseline is persisted; phase 2 (activate) flips
-- `prepared → observing` and releases the outbox rows in one transaction. A
-- `prepared` invoice is never observed and never published (§B.11.5), and it
-- dies either by the marketplace's `void` (`void_cancelled`) or by the reaper
-- at `prepare_expires_at` (`void_prepare_expired`).
--
-- The `baseline_state` CHECK is rewritten once to the TOTAL state set of the
-- §B.11.1 table — including the `expired_*` and `resolved_*` states whose
-- edges arrive with the expiry/resolve work — so no later migration has to
-- rewrite this constraint again. 'legacy_unbaselined' (pre-0008 rows) and
-- 'manual_review' (unfetchable-candidate routing, §B.4.3) remain admitted:
-- both are live values the code reads and writes today.
--
-- `prepare_expires_at` is stamped at creation-commit time as
-- `created_at + prepare_ttl` (server clock); `activated_at` records the
-- phase-2 commit; `expires_at` carries the caller-supplied Payment Request
-- expiry echoed in the §B.11.3 bodies (NULL for the Locks /invoices path
-- until the expiry edges land).
--
-- The outbox `status` CHECK is introduced with the full closed set of row
-- states, now including 'prepared': a 'prepared' row is inserted by phase 1
-- and is invisible to `OutboxStore::claim` (which selects only
-- 'queued'/'leased'/'retryable') until activation flips it to 'queued'.
--
-- `invoice_baseline_outpoints.kind` gains 'pre_existing' for the §B.4.6
-- composed first-tick rule: a transaction unconfirmed at the activation
-- (tick-1) snapshot and absent from the creation baseline is written into
-- the baseline set with this kind and is thereafter permanently ineligible,
-- exactly like a baseline member.

ALTER TABLE invoices
    DROP CONSTRAINT invoices_baseline_state_check;

ALTER TABLE invoices
    ADD CONSTRAINT invoices_baseline_state_check CHECK (
        baseline_state IN (
            'legacy_unbaselined',
            'awaiting_baseline',
            'prepared',
            'observing',
            'expired_tail',
            'expired_final',
            'void_baseline_failed',
            'void_prepare_expired',
            'void_cancelled',
            'resolved_paid_manually',
            'resolved_closed',
            'manual_review'
        )
    );

ALTER TABLE invoices
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD COLUMN prepare_expires_at TIMESTAMPTZ,
    ADD COLUMN activated_at TIMESTAMPTZ;

ALTER TABLE invoice_baseline_outpoints
    DROP CONSTRAINT invoice_baseline_outpoints_kind_check;

ALTER TABLE invoice_baseline_outpoints
    ADD CONSTRAINT invoice_baseline_outpoints_kind_check CHECK (
        kind IN ('output', 'replaced_input', 'ineligible', 'pre_existing')
    );

ALTER TABLE outbox
    ADD CONSTRAINT outbox_status_check CHECK (
        status IN (
            'prepared',
            'queued',
            'leased',
            'retryable',
            'handed_off',
            'delivered',
            'permanently_failed'
        )
    );
