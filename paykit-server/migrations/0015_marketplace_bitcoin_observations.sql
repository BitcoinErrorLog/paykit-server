-- Marketplace Bitcoin observation ownership and immutable per-outpoint evidence.
ALTER TABLE bitcoin_observations
    ALTER COLUMN invoice_id DROP NOT NULL,
    ADD COLUMN marketplace_preparation_id UUID
        REFERENCES marketplace_settlements (preparation_id) ON DELETE RESTRICT,
    ADD COLUMN first_observed_at TIMESTAMPTZ;

UPDATE bitcoin_observations
SET first_observed_at = created_at
WHERE first_observed_at IS NULL;

ALTER TABLE bitcoin_observations
    ALTER COLUMN first_observed_at SET NOT NULL,
    ADD CONSTRAINT bitcoin_observation_exactly_one_owner CHECK (
        num_nonnulls(invoice_id, marketplace_preparation_id) = 1
    );

CREATE UNIQUE INDEX bitcoin_observations_one_active_marketplace_settlement
    ON bitcoin_observations (marketplace_preparation_id)
    WHERE active AND marketplace_preparation_id IS NOT NULL;

CREATE INDEX bitcoin_observations_marketplace_settlement_index
    ON bitcoin_observations (marketplace_preparation_id)
    WHERE marketplace_preparation_id IS NOT NULL;

CREATE TABLE marketplace_timely_amount_matched_outpoints (
    preparation_id UUID NOT NULL
        REFERENCES marketplace_settlements (preparation_id) ON DELETE RESTRICT,
    outpoint_lookup_hash BYTEA NOT NULL
        CHECK (octet_length(outpoint_lookup_hash) = 32),
    PRIMARY KEY (preparation_id, outpoint_lookup_hash)
);

CREATE FUNCTION reject_bitcoin_observation_evidence_rewrite() RETURNS trigger AS $$
BEGIN
    IF NEW.invoice_id IS DISTINCT FROM OLD.invoice_id
       OR NEW.marketplace_preparation_id IS DISTINCT FROM OLD.marketplace_preparation_id
       OR NEW.observation_envelope IS DISTINCT FROM OLD.observation_envelope
       OR NEW.outpoint_lookup_hash IS DISTINCT FROM OLD.outpoint_lookup_hash
       OR NEW.first_observed_at IS DISTINCT FROM OLD.first_observed_at THEN
        RAISE EXCEPTION 'bitcoin observation evidence is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bitcoin_observation_evidence_immutable
    BEFORE UPDATE OF invoice_id, marketplace_preparation_id, observation_envelope,
        outpoint_lookup_hash, first_observed_at
    ON bitcoin_observations
    FOR EACH ROW
    EXECUTE FUNCTION reject_bitcoin_observation_evidence_rewrite();

CREATE FUNCTION reject_bitcoin_observation_evidence_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'bitcoin observation evidence cannot be deleted'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bitcoin_observation_evidence_delete_protected
    BEFORE DELETE ON bitcoin_observations
    FOR EACH ROW
    EXECUTE FUNCTION reject_bitcoin_observation_evidence_delete();
