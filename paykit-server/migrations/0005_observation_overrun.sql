-- Per-invoice observation overrun flag: set when a target's estimated
-- Electrum cost exceeded electrum.max_target_requests under the
-- head-of-line bypass. Flagged targets stay in the observation plan but
-- are excluded from the bypass, so one unbounded-history address can no
-- longer monopolise the endpoint; the count is surfaced on /health.

ALTER TABLE invoices ADD COLUMN observation_overrun BOOLEAN NOT NULL DEFAULT FALSE;
