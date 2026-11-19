-- The Receipt the seller's wallet issued for a Marketplace request, read from
-- the Creator's shared SDK state. One per preparation: the first accepted
-- Receipt is kept, never replaced. Its facts are sealed to the preparation and
-- its Creator; the keyed Receipt ID lookup recognises a repeat without
-- decrypting.
CREATE TABLE marketplace_seller_receipts (
    preparation_id UUID PRIMARY KEY,
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    receipt_lookup_hash BYTEA NOT NULL CHECK (octet_length(receipt_lookup_hash) = 32),
    receipt_envelope BYTEA NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (preparation_id, creator_id)
        REFERENCES marketplace_payment_preparations (id, creator_id) ON DELETE RESTRICT
);

CREATE FUNCTION reject_marketplace_seller_receipt_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'marketplace seller receipts are append-only';
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER marketplace_seller_receipts_append_only
BEFORE UPDATE OR DELETE ON marketplace_seller_receipts
FOR EACH ROW EXECUTE FUNCTION reject_marketplace_seller_receipt_change();

CREATE TRIGGER marketplace_seller_receipts_no_truncate
BEFORE TRUNCATE ON marketplace_seller_receipts
FOR EACH STATEMENT EXECUTE FUNCTION reject_marketplace_seller_receipt_change();
