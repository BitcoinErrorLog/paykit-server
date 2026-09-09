# Observer rollout runbook

Operational notes for deploying the r6 observer (per-address
`script_list_unspent` observation, sustained shared request limiter,
per-address failure isolation). Branch state: `marketplace/observer-listunspent-r6`.

## Rollback hazard: schema + binary rollout is one-way

Migration `0006_drop_observation_budget_columns.sql`
(`paykit-server/migrations/0006_drop_observation_budget_columns.sql`)
DROPS the `observation_history_tx_count`, `observation_request_count`, and
`observation_overrun` columns from `invoices`. The last pre-0006 binary
(fb01d87 `fix(observer): recover availability after stamp misses and
correct attribution docs`) still SELECTs those columns in its observation
plan query, so it fails its observer ticks as soon as 0006 has run.

**Consequence:** once migration 0006 is applied, rolling back to fb01d87
(or any earlier binary) is NOT possible without restoring the columns.
Treat schema + binary as a single one-way step:

1. Deploy the new binary first (it runs migrations at startup; 0006 is
   idempotent via `IF EXISTS`).
2. There is no safe rollback window after 0006 lands. If a rollback story
   is required, take a database backup (or at least
   `pg_dump -t invoices`) before deploying.

## Dashboard changes

### Deletions

The following series and readiness fields no longer exist (removed in
9c4f72e `feat(observer): replace BDK sync observation with per-address
script_list_unspent`; verified absent from the tree at HEAD). Delete the
panels and alerts that reference them:

- `paykit_electrum_bypassed_head_requests`
- `paykit_electrum_bypassed_head_budget_violations`
- `paykit_electrum_observation_overrun_targets`
- `paykit_electrum_overrun_lane_admissions`
- the `electrum.overrun_targets` readiness field on `/health/ready`

### Additions

- `paykit_electrum_observation_address_failures{reason="error" |
  "response_too_large" | "deadline"}` — counter family of isolated
  per-address lookup failures. Registered at
  `paykit-server/src/metrics.rs:109`; incremented at
  `paykit-server/src/workers/observer.rs:795`. A rising value localizes
  trouble to specific targets with no endpoint impact.
- `paykit_electrum_zero_success_ticks` — counter of observer ticks that
  attempted ≥1 lookup and succeeded at none. Registered at
  `paykit-server/src/metrics.rs:115`; incremented at
  `paykit-server/src/workers/observer.rs:811`. Each such tick also logs
  ERROR once per streak (the streak resets on the first tick with a
  successful lookup). Alert on a sustained increase: with per-address
  failures isolated from availability, this is the only signal that
  observation is doing no useful work while the endpoint reads healthy.
- Alert on `paykit_electrum_backlog_oldest_age_seconds > 300` — gauge of
  the oldest pending observation. Registered at
  `paykit-server/src/metrics.rs:99`; set at
  `paykit-server/src/workers/observer.rs:734`. 300 s matches the
  code's own `BACKLOG_ALERT_THRESHOLD`
  (`paykit-server/src/workers/observer.rs:39`), past which the observer
  also emits a WARN log (`paykit-server/src/workers/observer.rs:737`):
  the budget is saturated or a target is failing repeatedly.

## Shared request limiter

The Electrum request budget is one process-wide token bucket
(`RequestLimiter`, installed on the runtime at startup from
`electrum.max_requests_per_tick` / `electrum.max_requests_per_second`).
The observer tick and all non-tick Electrum callers (invoice-creation
snapshot fetches, the first-bind candidate fetch, the claim-time history
scan) charge the same bucket, so raising creation/claim traffic directly
shrinks observation admission — size the budget for the joint load, not
just the tick.
