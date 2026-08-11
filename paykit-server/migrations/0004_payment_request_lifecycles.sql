CREATE TABLE payment_request_lifecycles (
    invoice_id UUID PRIMARY KEY REFERENCES invoices (id) ON DELETE RESTRICT,
    sdk_payment_request_id TEXT NOT NULL UNIQUE CHECK (sdk_payment_request_id <> ''),
    request_state TEXT NOT NULL CHECK (
        request_state IN (
            'proposed',
            'proposal_expired',
            'accepted',
            'rejected',
            'canceled',
            'proof_submitted',
            'active_recurring',
            'recovery_required',
            'invalid_conflict'
        )
    ),
    state_event_id TEXT CHECK (state_event_id IS NULL OR state_event_id <> ''),
    last_stream_item_id BIGINT CHECK (last_stream_item_id >= 0),
    last_outbound_message_id BIGINT CHECK (last_outbound_message_id >= 0),
    last_event_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT payment_request_lifecycle_has_source_cursor CHECK (
        last_stream_item_id IS NOT NULL OR last_outbound_message_id IS NOT NULL
    )
);
