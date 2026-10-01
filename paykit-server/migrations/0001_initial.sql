-- Pre-production baseline for encrypted Paykit Server persistence.
-- Existing databases from earlier prototypes are intentionally unsupported and must be reset.

CREATE TABLE deployment_metadata (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    bitcoin_network TEXT NOT NULL,
    paykit_client_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    locks_key_fingerprint BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE creators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_lookup_hash BYTEA UNIQUE NOT NULL,
    credential_envelope BYTEA NOT NULL,
    setup_complete BOOLEAN NOT NULL DEFAULT FALSE,
    next_child_index BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE reader_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    reader_lookup_hash BYTEA NOT NULL,
    bundle_lookup_hash BYTEA NOT NULL,
    assignment_envelope BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (creator_id, reader_lookup_hash, bundle_lookup_hash)
);

CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    reader_lookup_hash BYTEA NOT NULL,
    bundle_lookup_hash BYTEA NOT NULL,
    payment_request_lookup_hash BYTEA NOT NULL,
    invoice_envelope BYTEA NOT NULL,
    payment_record_envelope BYTEA NOT NULL,
    bitcoin_address_lookup_hash BYTEA UNIQUE NOT NULL,
    derivation_index_lookup_hash BYTEA NOT NULL,
    payment_status TEXT NOT NULL,
    confirmation_count INTEGER NOT NULL DEFAULT 0,
    amount_matched BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (creator_id, bundle_lookup_hash),
    UNIQUE (creator_id, derivation_index_lookup_hash),
    UNIQUE (payment_request_lookup_hash)
);

CREATE TABLE outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    invoice_id UUID UNIQUE REFERENCES invoices (id) ON DELETE RESTRICT,
    intent_envelope BYTEA NOT NULL,
    status TEXT NOT NULL,
    lease_owner UUID,
    claim_token UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error_class TEXT,
    sdk_outbound_message_id TEXT,
    sdk_event_id TEXT,
    sdk_payment_request_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT outbox_attributable_terminal_state CHECK (
        status NOT IN ('handed_off', 'delivered')
        OR (
            sdk_outbound_message_id IS NOT NULL
            AND sdk_outbound_message_id ~ '^(0|[1-9][0-9]*)$'
        )
    ),
    CONSTRAINT outbox_payment_request_id_pair CHECK (
        (sdk_event_id IS NULL) = (sdk_payment_request_id IS NULL)
    )
);

CREATE INDEX outbox_claim_index ON outbox (status, next_attempt_at);
CREATE INDEX outbox_handed_off_reconciliation_index
    ON outbox (status, next_attempt_at)
    WHERE status = 'handed_off';

CREATE TABLE bitcoin_observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
    observation_envelope BYTEA NOT NULL,
    outpoint_lookup_hash BYTEA UNIQUE NOT NULL,
    confirmations INTEGER NOT NULL CHECK (confirmations >= 0),
    present BOOLEAN NOT NULL DEFAULT TRUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX bitcoin_observations_invoice_id_index ON bitcoin_observations (invoice_id);
CREATE UNIQUE INDEX bitcoin_observations_one_active_invoice
    ON bitcoin_observations (invoice_id)
    WHERE active;
