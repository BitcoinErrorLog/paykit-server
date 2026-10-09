-- Durable Marketplace preparation state. Preparation allocates invoice identity
-- and payment material without creating an active invoice or claimable outbox work.
CREATE TABLE marketplace_payment_preparations (
    id UUID PRIMARY KEY,
    creator_id UUID NOT NULL REFERENCES creators(id) ON DELETE RESTRICT,
    operation_lookup_hash BYTEA NOT NULL CHECK (octet_length(operation_lookup_hash) = 32),
    request_lookup_hash BYTEA NOT NULL CHECK (octet_length(request_lookup_hash) = 32),
    reader_lookup_hash BYTEA NOT NULL CHECK (octet_length(reader_lookup_hash) = 32),
    preparation_envelope BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'prepared' CHECK (state = 'prepared'),
    prepared_at TIMESTAMPTZ NOT NULL,
    prepare_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT marketplace_preparation_operation_binding_key
        UNIQUE (creator_id, operation_lookup_hash),
    CONSTRAINT marketplace_preparation_expiry_after_creation
        CHECK (prepare_expires_at > prepared_at)
);
