-- Direct USDT invoices use an approved shared address and ERC-20 receipt identity.
ALTER TABLE invoices
    ALTER COLUMN bitcoin_address_lookup_hash DROP NOT NULL,
    DROP CONSTRAINT invoices_first_amount_matched_outpoint_pair;

-- Each verified ERC-20 event belongs permanently to one invoice.
CREATE TABLE usdt_observations (
    id UUID PRIMARY KEY,
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
    transfer_lookup_hash BYTEA UNIQUE NOT NULL,
    observation_envelope BYTEA NOT NULL,
    confirmations INTEGER NOT NULL CHECK (confirmations >= 0),
    present BOOLEAN NOT NULL,
    finalized BOOLEAN NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX usdt_observations_invoice_id_index ON usdt_observations (invoice_id);
