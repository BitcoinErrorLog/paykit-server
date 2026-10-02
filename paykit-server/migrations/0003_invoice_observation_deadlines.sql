ALTER TABLE invoices
    ADD COLUMN first_amount_matched_observed_at TIMESTAMPTZ,
    ADD COLUMN first_amount_matched_outpoint_lookup_hash BYTEA,
    ADD COLUMN payment_expired_at TIMESTAMPTZ,
    ADD CONSTRAINT invoices_first_amount_matched_outpoint_pair CHECK (
        (first_amount_matched_observed_at IS NULL)
        = (first_amount_matched_outpoint_lookup_hash IS NULL)
    ),
    ADD CONSTRAINT invoices_first_amount_matched_window_check CHECK (
        first_amount_matched_observed_at IS NULL
        OR (
            first_amount_matched_observed_at >= invoice_created_at
            AND first_amount_matched_observed_at <= payment_deadline
        )
    ),
    ADD CONSTRAINT invoices_payment_expired_deadline_check CHECK (
        payment_expired_at IS NULL OR payment_expired_at >= payment_deadline
    );

CREATE TABLE invoice_timely_amount_matched_outpoints (
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    outpoint_lookup_hash BYTEA NOT NULL CHECK (octet_length(outpoint_lookup_hash) = 32),
    PRIMARY KEY (invoice_id, outpoint_lookup_hash)
);
