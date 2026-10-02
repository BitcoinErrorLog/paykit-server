-- Staging-only hard cutover to rc56 immutable Payment Request terms.
--
-- Existing invoice, outbox, lifecycle, and drain rows encode rc48/rc55
-- semantics and cannot be reinterpreted safely. Paykit Server has not reached
-- production, so reset all dependent staging state before installing the new
-- closed deadline schema. SQLx records this migration transactionally.
TRUNCATE TABLE
    payment_drain_cancellations,
    payment_drain_items,
    payment_drains,
    payment_request_lifecycles,
    invoice_timely_amount_matched_outpoints,
    bitcoin_observations,
    outbox,
    invoices,
    lock_payment_generations,
    reader_assignments,
    creators,
    deployment_metadata;

ALTER TABLE invoices
    DROP CONSTRAINT invoice_payment_deadline_matches_window,
    DROP CONSTRAINT invoices_first_amount_matched_window_check,
    DROP COLUMN payment_in_hours,
    ADD COLUMN proposal_expires_at TIMESTAMPTZ NOT NULL,
    ADD COLUMN proposal_acceptance_seconds BIGINT NOT NULL
        CHECK (proposal_acceptance_seconds > 0),
    ADD COLUMN payment_window_seconds BIGINT NOT NULL
        CHECK (payment_window_seconds > proposal_acceptance_seconds),
    ADD CONSTRAINT invoice_proposal_expiry_after_creation CHECK (
        proposal_expires_at = invoice_created_at
            + proposal_acceptance_seconds * INTERVAL '1 second'
    ),
    ADD CONSTRAINT invoice_payment_deadline_matches_window CHECK (
        payment_deadline = invoice_created_at
            + payment_window_seconds * INTERVAL '1 second'
    ),
    ADD CONSTRAINT invoice_proposal_expiry_before_payment_deadline CHECK (
        proposal_expires_at < payment_deadline
    ),
    ADD CONSTRAINT invoices_first_amount_matched_window_check CHECK (
        first_amount_matched_observed_at IS NULL
        OR first_amount_matched_observed_at >= invoice_created_at
    );
