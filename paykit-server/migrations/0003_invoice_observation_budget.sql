-- Per-invoice Electrum observation budget and scheduling metadata.
-- observation_history_tx_count is the transaction count returned by the
-- previous tick's history fetch; NULL means unknown and is budgeted as 1.
-- last_observed_at is the last successful observation of the invoice and
-- drives oldest-first scheduling and backlog alerting.

ALTER TABLE invoices ADD COLUMN observation_history_tx_count INTEGER;
ALTER TABLE invoices ADD COLUMN last_observed_at TIMESTAMPTZ;
