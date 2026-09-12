-- Failed observation attempts must rotate behind the plan exactly like
-- successful ones. Before this column only successful observations were
-- stamped (`last_observed_at`), so a permanently failing target kept the
-- head of the oldest-first plan and — once the count of failing targets
-- reached the per-tick budget — starved every honest seller of attempts.
-- `last_attempted_at` stamps every attempt (success or failure) and drives
-- oldest-first scheduling; `last_observed_at` keeps its semantics as the
-- last SUCCESSFUL observation and still drives staleness/backlog alerting.
--
-- Numbered after the highest migration in this tree (0006). Sibling W1.x
-- slices that added their own 0007 must renumber on rebase.

ALTER TABLE invoices ADD COLUMN last_attempted_at TIMESTAMPTZ;
