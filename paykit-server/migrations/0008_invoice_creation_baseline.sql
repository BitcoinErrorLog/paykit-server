-- Legacy invoices predate the V2 creation baseline and are deliberately
-- excluded from observation. Production and proof databases for this rail
-- are created empty; no migration may silently make a legacy row observable.
ALTER TABLE invoices
    ADD COLUMN baseline_state TEXT NOT NULL DEFAULT 'legacy_unbaselined',
    ADD COLUMN creation_chain_height INTEGER NOT NULL DEFAULT 0,
    ADD CONSTRAINT invoices_baseline_state_check CHECK (
        baseline_state IN (
            'legacy_unbaselined',
            'awaiting_baseline',
            'observing',
            'void_baseline_failed',
            'manual_review'
        )
    ),
    ADD CONSTRAINT invoices_creation_chain_height_check CHECK (creation_chain_height >= 0);

CREATE TABLE invoice_baseline_outpoints (
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL CHECK (vout >= 0),
    kind TEXT NOT NULL CHECK (kind IN ('output', 'replaced_input', 'ineligible')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (invoice_id, txid, vout, kind)
);

CREATE TABLE bitcoin_observation_candidates (
    invoice_id UUID PRIMARY KEY REFERENCES invoices (id) ON DELETE RESTRICT,
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL CHECK (vout >= 0),
    confirmations INTEGER NOT NULL CHECK (confirmations > 0),
    confirmed_height INTEGER NOT NULL CHECK (confirmed_height > 0),
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
