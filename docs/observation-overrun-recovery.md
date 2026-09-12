# Observation overrun recovery — SUPERSEDED

This document described the `observation_overrun` flag, the head-of-line
budget bypass, and the slow lane that recovered flagged targets. That
machinery no longer exists: observation now uses one raw
`script_list_unspent` lookup per tracked address, so an address's Electrum
request cost is exactly one regardless of its history or UTXO count, and no
estimate, bypass, flag, or slow lane is needed. The
`electrum.max_target_requests` and `electrum.overrun_lane_interval_ticks`
config keys were removed and are rejected at startup; the
`observation_history_tx_count`, `observation_request_count`, and
`observation_overrun` columns were dropped by migration 0006.

See [observer-threat-model.md](observer-threat-model.md) for the current
threat model, budgeting rule, and per-address failure handling.
