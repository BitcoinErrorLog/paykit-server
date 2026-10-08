CREATE TABLE buyer_contacts (
    invoice_id UUID PRIMARY KEY REFERENCES invoices(id),
    creator_id UUID NOT NULL REFERENCES creators(id),
    reader_lookup_hash BYTEA NOT NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (creator_id, reader_lookup_hash)
);

CREATE INDEX buyer_contacts_pending ON buyer_contacts(next_attempt_at, invoice_id)
    WHERE completed_at IS NULL;
