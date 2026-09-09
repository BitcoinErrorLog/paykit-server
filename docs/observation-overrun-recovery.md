# Observation overrun recovery

An invoice whose observation target exceeded `electrum.max_target_requests`
under the head-of-line bypass is flagged `observation_overrun` (ERROR log with
the invoice id, counted on `/health/ready` as `electrum.overrun_targets` and in
the `paykit_electrum_observation_overrun_targets` metric). Flagged targets are
excluded from the bypass and observed only through the slow lane: at most one
flagged target every `electrum.overrun_lane_interval_ticks` ticks (default 10),
each admission counted on `paykit_electrum_overrun_lane_admissions`.

## Automatic clearing

No operator action is normally required. Every stamped observation records the
target's fresh `history_tx_count`, and when the structural estimate
(`1 + history_tx_count`) is at or below `electrum.max_target_requests` the same
UPDATE clears the flag, returning the target to the regular budgeted plan.

## Manual clearing

There is no admin-authenticated endpoint for this operation; clear the flag
directly in the database.

Preconditions:

- You have the invoice id from the ERROR log emitted when the target was
  flagged (invoice addresses are stored only as keyed lookup hashes, so the
  invoice id is the only operator-usable selector).
- You have verified the address's history is again fetchable within
  `electrum.max_target_requests` (for example with a manual Electrum
  `blockchain.scripthash.get_history` call), or you deliberately accept one
  more bypass-cost overrun before the target is re-flagged automatically.

```sql
UPDATE invoices
SET observation_overrun = FALSE, updated_at = NOW()
WHERE id = '<invoice-uuid-from-the-error-log>'
  AND observation_overrun;
```

A manually cleared target that is still over the bound is simply re-flagged
the next time it takes the bypass, so manual clearing without the precondition
only delays recovery.
