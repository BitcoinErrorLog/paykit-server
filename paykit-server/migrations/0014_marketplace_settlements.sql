-- Activated Marketplace preparations own settlement state separately from Locks invoices.
-- This branch is pre-production. Existing active preparations cannot be backfilled
-- honestly because their payment record requires application-owned AEAD context.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM marketplace_payment_preparations WHERE state = 'active'
    ) THEN
        RAISE EXCEPTION
            'active Marketplace preparations require reset before settlement ownership migration';
    END IF;
END
$$;

CREATE TABLE marketplace_settlements (
    preparation_id UUID PRIMARY KEY,
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    payment_record_envelope BYTEA NOT NULL,
    bitcoin_address_lookup_hash BYTEA UNIQUE NOT NULL
        CHECK (octet_length(bitcoin_address_lookup_hash) = 32),
    derivation_index_lookup_hash BYTEA NOT NULL
        CHECK (octet_length(derivation_index_lookup_hash) = 32),
    payment_status TEXT NOT NULL DEFAULT 'undetected',
    confirmation_count INTEGER NOT NULL DEFAULT 0 CHECK (confirmation_count >= 0),
    amount_matched BOOLEAN NOT NULL DEFAULT FALSE,
    first_amount_matched_observed_at TIMESTAMPTZ,
    first_amount_matched_outpoint_lookup_hash BYTEA
        CHECK (
            first_amount_matched_outpoint_lookup_hash IS NULL
            OR octet_length(first_amount_matched_outpoint_lookup_hash) = 32
        ),
    payment_expired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (preparation_id, creator_id)
        REFERENCES marketplace_payment_preparations (id, creator_id) ON DELETE RESTRICT,
    UNIQUE (creator_id, derivation_index_lookup_hash),
    CONSTRAINT marketplace_settlements_first_amount_matched_pair CHECK (
        (first_amount_matched_observed_at IS NULL)
        = (first_amount_matched_outpoint_lookup_hash IS NULL)
    )
);

CREATE FUNCTION enforce_marketplace_settlement_active_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM marketplace_payment_preparations
        WHERE id = NEW.preparation_id
          AND creator_id = NEW.creator_id
          AND state = 'active'
    ) THEN
        RAISE EXCEPTION 'Marketplace settlement owner is not active';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER marketplace_settlements_require_active_owner
BEFORE INSERT OR UPDATE ON marketplace_settlements
FOR EACH ROW
EXECUTE FUNCTION enforce_marketplace_settlement_active_owner();

CREATE FUNCTION prevent_marketplace_settlement_owner_regression()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state <> 'active' AND EXISTS (
        SELECT 1 FROM marketplace_settlements WHERE preparation_id = NEW.id
    ) THEN
        RAISE EXCEPTION 'Marketplace settlement owner must remain active';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER marketplace_preparations_preserve_settlement_owner
BEFORE UPDATE OF state ON marketplace_payment_preparations
FOR EACH ROW
EXECUTE FUNCTION prevent_marketplace_settlement_owner_regression();

-- One registry supplies a PostgreSQL-enforced uniqueness boundary across both
-- owner tables. Existing invoice rows are backfilled before triggers are enabled.
CREATE TABLE bitcoin_address_owners (
    bitcoin_address_lookup_hash BYTEA PRIMARY KEY,
    invoice_id UUID UNIQUE REFERENCES invoices (id) ON DELETE CASCADE,
    marketplace_preparation_id UUID UNIQUE
        REFERENCES marketplace_settlements (preparation_id) ON DELETE CASCADE,
    CONSTRAINT bitcoin_address_owners_exactly_one_owner CHECK (
        num_nonnulls(invoice_id, marketplace_preparation_id) = 1
    )
);

INSERT INTO bitcoin_address_owners (bitcoin_address_lookup_hash, invoice_id)
SELECT bitcoin_address_lookup_hash, id
FROM invoices
WHERE bitcoin_address_lookup_hash IS NOT NULL;

CREATE FUNCTION claim_bitcoin_address_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    owned BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'invoices' THEN
        INSERT INTO bitcoin_address_owners (bitcoin_address_lookup_hash, invoice_id)
        VALUES (NEW.bitcoin_address_lookup_hash, NEW.id)
        ON CONFLICT (bitcoin_address_lookup_hash) DO NOTHING;
        SELECT invoice_id = NEW.id AND marketplace_preparation_id IS NULL
        INTO owned
        FROM bitcoin_address_owners
        WHERE bitcoin_address_lookup_hash = NEW.bitcoin_address_lookup_hash;
    ELSE
        INSERT INTO bitcoin_address_owners (
            bitcoin_address_lookup_hash, marketplace_preparation_id
        ) VALUES (NEW.bitcoin_address_lookup_hash, NEW.preparation_id)
        ON CONFLICT (bitcoin_address_lookup_hash) DO NOTHING;
        SELECT marketplace_preparation_id = NEW.preparation_id AND invoice_id IS NULL
        INTO owned
        FROM bitcoin_address_owners
        WHERE bitcoin_address_lookup_hash = NEW.bitcoin_address_lookup_hash;
    END IF;

    IF owned IS DISTINCT FROM TRUE THEN
        RAISE unique_violation USING
            MESSAGE = 'Bitcoin address already belongs to another settlement owner',
            CONSTRAINT = 'bitcoin_address_owners_pkey';
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.bitcoin_address_lookup_hash IS DISTINCT FROM NEW.bitcoin_address_lookup_hash THEN
        IF TG_TABLE_NAME = 'invoices' THEN
            DELETE FROM bitcoin_address_owners
            WHERE bitcoin_address_lookup_hash = OLD.bitcoin_address_lookup_hash
              AND invoice_id = OLD.id;
        ELSE
            DELETE FROM bitcoin_address_owners
            WHERE bitcoin_address_lookup_hash = OLD.bitcoin_address_lookup_hash
              AND marketplace_preparation_id = OLD.preparation_id;
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoices_claim_global_bitcoin_address
AFTER INSERT OR UPDATE OF bitcoin_address_lookup_hash ON invoices
FOR EACH ROW
WHEN (NEW.bitcoin_address_lookup_hash IS NOT NULL)
EXECUTE FUNCTION claim_bitcoin_address_owner();

CREATE TRIGGER marketplace_settlements_claim_global_bitcoin_address
AFTER INSERT OR UPDATE OF bitcoin_address_lookup_hash ON marketplace_settlements
FOR EACH ROW
EXECUTE FUNCTION claim_bitcoin_address_owner();

ALTER TABLE payment_request_lifecycles
    ALTER COLUMN invoice_id DROP NOT NULL,
    ADD COLUMN marketplace_preparation_id UUID
        REFERENCES marketplace_settlements (preparation_id) ON DELETE RESTRICT,
    ADD CONSTRAINT payment_request_lifecycle_exactly_one_owner CHECK (
        num_nonnulls(invoice_id, marketplace_preparation_id) = 1
    ),
    ADD CONSTRAINT payment_request_lifecycle_marketplace_identity_unique
        UNIQUE (marketplace_preparation_id, sdk_payment_request_id);

CREATE INDEX payment_request_lifecycles_marketplace_index
    ON payment_request_lifecycles (marketplace_preparation_id)
    WHERE marketplace_preparation_id IS NOT NULL;
