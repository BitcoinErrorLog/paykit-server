-- Additive index supporting budget-aware delivery health scans over live
-- retryable/handed_off rows. Idempotent; no existing rows change.
CREATE INDEX IF NOT EXISTS outbox_live_budget_health_index
    ON outbox (status, created_at)
    WHERE status IN ('retryable', 'handed_off');
