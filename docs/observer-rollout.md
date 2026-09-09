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
  `paykit-server/src/metrics.rs:111`; incremented at
  `paykit-server/src/workers/observer.rs:829`. A rising value localizes
  trouble to specific targets with no endpoint impact.
- `paykit_electrum_zero_success_ticks` — counter of observer ticks that
  attempted ≥1 lookup and succeeded at none. Registered at
  `paykit-server/src/metrics.rs:117`; incremented at
  `paykit-server/src/workers/observer.rs:845`. Each such tick also logs
  ERROR once per streak (the streak resets on the first tick with a
  successful lookup). Alert on a sustained increase: with per-address
  failures isolated from availability, this is the only signal that
  observation is doing no useful work while the endpoint reads healthy.
- `paykit_electrum_budget_exhausted_ticks` — counter of observer ticks
  deferred because the shared request budget could not cover the
  two-request probe reservation; the deferred tick sent no Electrum
  requests and changed no availability. Registered at
  `paykit-server/src/metrics.rs:122`; incremented at
  `paykit-server/src/workers/observer.rs:728` (INFO log with reason
  `budget_exhausted`). A sustained rise means non-tick callers are
  starving observation: raise the budget or shed creation/claim load.
- Alert on `paykit_electrum_backlog_oldest_age_seconds > 300` — gauge of
  the oldest pending observation. Registered at
  `paykit-server/src/metrics.rs:101`; set at
  `paykit-server/src/workers/observer.rs:769`. 300 s matches the
  code's own `BACKLOG_ALERT_THRESHOLD`
  (`paykit-server/src/workers/observer.rs:39`), past which the observer
  also emits a WARN log (`paykit-server/src/workers/observer.rs:772`):
  the budget is saturated or a target is failing repeatedly.
- The transport byte cap surfaces as
  `paykit_electrum_observation_address_failures{reason="error"}` (or a
  probe `Unavailable` when the oversize line answers a probe request):
  an Electrum response line over `electrum.max_response_bytes` fails the
  read with the literal loggable error `electrum response exceeds
  max_response_bytes` before any JSON decode, and the connection is torn
  down and re-established on the next lookup. A sustained rise against
  one address means the endpoint is serving oversize responses — raise
  `electrum.max_response_bytes` only if the address is legitimately
  heavy; otherwise suspect the endpoint.

## Configuration

The `[electrum]` keys the observer honours (see
`config/paykit-server.example.toml` for the full comments):

| Key | Default | Accepted range | Effect |
| --- | --- | --- | --- |
| `poll_interval` | `10s` | ≥ `1s` | Base tick cadence (±20% jitter). |
| `request_timeout` | `10s` | > 0 | Connect, read, and write timeout per connection. |
| `max_requests_per_tick` | `1000` | > 2 effective | Token-bucket capacity (probe reservation included). |
| `max_requests_per_second` | `5` | > 0 | Token-bucket refill rate. |
| `max_utxos_per_address` | `200` | > 0 | Decoded list_unspent item cap per address. |
| `address_deadline` | `5s` | > 0 | Per-address wall-clock deadline. |
| `max_response_bytes` | `1048576` (1 MiB) | `65536`–`16777216` (64 KiB–16 MiB) | Transport cap on one response line; an over-cap line of any length consumes exactly cap + 1 bytes from the source before the read fails with `electrum response exceeds max_response_bytes` (before any decode), and the connection is torn down. |
| `max_tip_age` | `4h` | > 0 | Stale-tip readiness bound. |

**Mainnet transport invariant:** when `bitcoin.network` is `mainnet`,
startup refuses any `electrum.endpoint` whose scheme is not `ssl://`
(plaintext Electrum would expose every tracked invoice address and UTXO
set unauthenticated and in the clear, and could serve fabricated
confirmations). The refusal is a config error at load with the literal
diagnostic `bitcoin.network mainnet requires an ssl://
electrum.endpoint; the <scheme>:// scheme is plaintext and refused`.
`tcp://` stays accepted on regtest/signet/testnet for local
fulcrum-style endpoints. Do not "fix" a mainnet refusal by switching
the endpoint to `tcp://`; point the config at a TLS endpoint instead.

## Shared request limiter

The Electrum request budget is one process-wide token bucket
(`RequestLimiter`, installed on the runtime at startup from
`electrum.max_requests_per_tick` / `electrum.max_requests_per_second`).
The observer tick and all non-tick Electrum callers (invoice-creation
snapshot fetches, the first-bind candidate fetch, the claim-time history
scan) charge the same bucket, so raising creation/claim traffic directly
shrinks observation admission — size the budget for the joint load, not
just the tick. Every Electrum request is reserved before it is sent: the
tick reserves its two probe requests up front, so a bucket drained to
zero defers the whole tick (counted under
`paykit_electrum_budget_exhausted_ticks`) rather than probing uncharged.
