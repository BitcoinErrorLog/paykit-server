ALTER TABLE outbox
    ADD COLUMN proposal_lookup_hash BYTEA,
    ADD COLUMN intent_kind TEXT NOT NULL CHECK (
        intent_kind IN (
            'endpoint_publication',
            'payment_request_proposal',
            'payment_request_cancellation'
        )
    ),
    ADD COLUMN cancellation_target_payment_request_id TEXT;

ALTER TABLE outbox
    DROP CONSTRAINT outbox_payment_request_id_pair,
    ADD CONSTRAINT outbox_payment_request_identity CHECK (
        (intent_kind = 'endpoint_publication'
            AND sdk_event_id IS NULL
            AND sdk_payment_request_id IS NULL
            AND cancellation_target_payment_request_id IS NULL)
        OR (intent_kind = 'payment_request_proposal'
            AND cancellation_target_payment_request_id IS NULL
            AND proposal_lookup_hash IS NOT NULL
            AND (sdk_event_id IS NULL) = (sdk_payment_request_id IS NULL))
        OR (intent_kind = 'payment_request_cancellation'
            AND cancellation_target_payment_request_id IS NOT NULL
            AND proposal_lookup_hash IS NULL
            AND (sdk_event_id IS NULL) = (sdk_payment_request_id IS NULL))
    ),
    ADD CONSTRAINT outbox_cancellation_identity_unique
        UNIQUE (id, invoice_id, cancellation_target_payment_request_id, intent_kind),
    ADD CONSTRAINT outbox_invoice_cancellation_unique
        UNIQUE (invoice_id, cancellation_target_payment_request_id, intent_kind);

CREATE INDEX outbox_proposal_lookup_index
    ON outbox (creator_id, proposal_lookup_hash)
    WHERE proposal_lookup_hash IS NOT NULL;

CREATE TABLE payment_request_lifecycles (
    sdk_payment_request_id TEXT PRIMARY KEY CHECK (sdk_payment_request_id <> ''),
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
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
    ),
    UNIQUE (invoice_id, sdk_payment_request_id)
);

CREATE INDEX payment_request_lifecycles_invoice_index
    ON payment_request_lifecycles (invoice_id);
