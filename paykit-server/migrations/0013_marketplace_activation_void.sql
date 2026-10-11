-- Marketplace activation/void lifecycle remains separate from Locks invoices.
ALTER TABLE marketplace_payment_preparations
    DROP CONSTRAINT marketplace_payment_preparations_state_check,
    ADD COLUMN activated_at TIMESTAMPTZ,
    ADD COLUMN payment_deadline TIMESTAMPTZ,
    ADD COLUMN voided_at TIMESTAMPTZ,
    ADD COLUMN business_outcome TEXT CHECK (
        business_outcome IN ('paid_manually', 'refunded', 'abandoned')
    ),
    ADD COLUMN resolved_at TIMESTAMPTZ,
    ADD CONSTRAINT marketplace_preparation_state_check CHECK (
        (state = 'prepared'
            AND activated_at IS NULL
            AND payment_deadline IS NULL
            AND voided_at IS NULL)
        OR (state = 'active'
            AND activated_at IS NOT NULL
            AND payment_deadline IS NOT NULL
            AND payment_deadline > activated_at
            AND voided_at IS NULL)
        OR (state = 'voided'
            AND activated_at IS NULL
            AND payment_deadline IS NULL
            AND voided_at IS NOT NULL)
    ),
    ADD CONSTRAINT marketplace_preparation_resolution_pair CHECK (
        (business_outcome IS NULL) = (resolved_at IS NULL)
    ),
    ADD CONSTRAINT marketplace_preparation_creator_binding
        UNIQUE (id, creator_id);

ALTER TABLE outbox
    ADD COLUMN marketplace_preparation_id UUID UNIQUE,
    ADD CONSTRAINT outbox_marketplace_preparation_creator_binding
        FOREIGN KEY (marketplace_preparation_id, creator_id)
        REFERENCES marketplace_payment_preparations (id, creator_id) ON DELETE RESTRICT,
    ADD CONSTRAINT outbox_one_invoice_owner CHECK (
        NOT (invoice_id IS NOT NULL AND marketplace_preparation_id IS NOT NULL)
    );
