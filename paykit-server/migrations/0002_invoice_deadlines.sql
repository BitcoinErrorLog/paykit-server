ALTER TABLE invoices
    ADD COLUMN invoice_created_at TIMESTAMPTZ NOT NULL,
    ADD COLUMN payment_deadline TIMESTAMPTZ NOT NULL,
    ADD COLUMN payment_in_hours BIGINT NOT NULL CHECK (payment_in_hours > 0),
    ADD CONSTRAINT invoice_payment_deadline_after_creation CHECK (payment_deadline > invoice_created_at),
    ADD CONSTRAINT invoice_payment_deadline_matches_window CHECK (
        payment_deadline = invoice_created_at + payment_in_hours * INTERVAL '1 hour'
    );
