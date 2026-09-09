-- Retires the observation budget/estimate bookkeeping added by migrations
-- 0003-0005. Observation now uses one raw `script_list_unspent` lookup per
-- tracked address, so a target's Electrum cost is exactly one request and
-- no estimate, measured request count, or overrun flag is read anywhere in
-- the codebase after this change; the columns are dropped (not merely
-- retired) because nothing reads them. `last_observed_at` stays: it drives
-- oldest-first scheduling and backlog alerting. Idempotent via IF EXISTS.

ALTER TABLE invoices DROP COLUMN IF EXISTS observation_history_tx_count;
ALTER TABLE invoices DROP COLUMN IF EXISTS observation_request_count;
ALTER TABLE invoices DROP COLUMN IF EXISTS observation_overrun;
