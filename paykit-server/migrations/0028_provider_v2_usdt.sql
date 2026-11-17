-- Extend provider-v2 denomination without rewriting existing BTC bindings.
-- BTC remains default for old insert callers and every pre-upgrade row.
ALTER TABLE invoice_provider_v2
    DROP CONSTRAINT invoice_provider_v2_asset_check,
    ADD CONSTRAINT invoice_provider_v2_asset_check
        CHECK (asset IN ('BTC', 'USDT')) NOT VALID;

ALTER TABLE invoice_provider_v2
    VALIDATE CONSTRAINT invoice_provider_v2_asset_check;
