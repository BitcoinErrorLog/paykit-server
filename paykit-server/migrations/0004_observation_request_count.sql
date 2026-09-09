-- Per-invoice measured Electrum request cost: the target's share of the
-- actual request count the adapter issued for the batch that last observed
-- it. NULL means never measured; the structural history estimate is used
-- instead. The next tick budgets each target as
-- max(1 + observation_history_tx_count, observation_request_count).

ALTER TABLE invoices ADD COLUMN observation_request_count INTEGER;
