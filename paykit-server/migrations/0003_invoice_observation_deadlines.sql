ALTER TABLE invoices
    ADD COLUMN first_amount_matched_observed_at TIMESTAMPTZ,
    ADD COLUMN payment_expired_at TIMESTAMPTZ,
    ADD CONSTRAINT invoices_first_amount_matched_window_check CHECK (
        first_amount_matched_observed_at IS NULL
        OR (
            first_amount_matched_observed_at >= invoice_created_at
            AND first_amount_matched_observed_at <= payment_deadline
        )
    ),
    ADD CONSTRAINT invoices_payment_expired_deadline_check CHECK (
        payment_expired_at IS NULL OR payment_expired_at >= payment_deadline
    ),
    ADD CONSTRAINT invoices_payment_lifecycle_terminal_check CHECK (
        first_amount_matched_observed_at IS NULL OR payment_expired_at IS NULL
    );
