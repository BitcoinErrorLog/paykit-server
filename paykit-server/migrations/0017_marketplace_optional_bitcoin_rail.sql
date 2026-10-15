-- A Marketplace request may accept only USDT. Its settlement then has no Bitcoin
-- address to claim or watch; the derivation index stays reserved and unique.
ALTER TABLE marketplace_settlements
    ALTER COLUMN bitcoin_address_lookup_hash DROP NOT NULL;

DROP TRIGGER marketplace_settlements_claim_global_bitcoin_address ON marketplace_settlements;

CREATE TRIGGER marketplace_settlements_claim_global_bitcoin_address
AFTER INSERT OR UPDATE OF bitcoin_address_lookup_hash ON marketplace_settlements
FOR EACH ROW
WHEN (NEW.bitcoin_address_lookup_hash IS NOT NULL)
EXECUTE FUNCTION claim_bitcoin_address_owner();
