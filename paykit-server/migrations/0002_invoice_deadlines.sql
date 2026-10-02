-- One-time destructive reset for the undeployed prototype schema.
--
-- Historical invoice rows cannot be backfilled with authoritative payment
-- deadlines or later lock-resource attribution. SQLx records this migration
-- transactionally, so the reset runs once when upgrading from migration 0001
-- and is not repeated on later application starts.
TRUNCATE TABLE
    bitcoin_observations,
    outbox,
    invoices,
    reader_assignments,
    creators,
    deployment_metadata;

ALTER TABLE invoices
    ADD COLUMN invoice_created_at TIMESTAMPTZ NOT NULL,
    ADD COLUMN payment_deadline TIMESTAMPTZ NOT NULL,
    ADD COLUMN payment_in_hours BIGINT NOT NULL CHECK (payment_in_hours > 0),
    ADD CONSTRAINT invoice_payment_deadline_after_creation CHECK (payment_deadline > invoice_created_at),
    ADD CONSTRAINT invoice_payment_deadline_matches_window CHECK (
        payment_deadline = invoice_created_at + payment_in_hours * INTERVAL '1 hour'
    );
