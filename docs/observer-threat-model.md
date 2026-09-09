# Observer threat model

This document is the coherent threat model for the Electrum observation
worker (`paykit-server/src/workers/observer.rs`).

## Protected resource

Two shared resources:

1. **The shared Electrum endpoint's request rate.** The server uses one
   configured endpoint; a public endpoint rate-limit, ban, or overload
   suspends observation for every seller until the endpoint recovers or is
   changed.
2. **Global observer liveness/latency.** Every non-final invoice must be
   observed within a bounded time; a stall in observing one address must
   not delay the others, because `bitcoin_offer_available` on
   `/health/ready` (and with it the ability to take new Bitcoin binds)
   depends on a healthy observation loop.

## Adversary

- **Deliberate dusting of a disclosed invoice address.** A payer learns the
  invoice address through the authenticated marketplace/payment-request
  flow; after disclosure, dusting it needs no server authentication. On
  regtest this is nearly free; on mainnet it costs transactions and fees
  but stays feasible against a chosen seller.
- **Organically heavy addresses.** An address can legitimately accumulate a
  large history or UTXO set. There is no provenance test: deliberate and
  organic load receive the same treatment.

## Why `list_unspent` bounds the request count

Observation previously went through BDK wallet sync, which expands one
`blockchain.scripthash.get_history` call into a `transaction.get` fetch per
history entry —
an attacker-controlled expansion the scheduler then tried to predict. Each
`blockchain.scripthash.listunspent` item already carries `tx_hash`,
`tx_pos`, `value`, and `height`, which is everything the settlement model
needs: outpoint, value, presence, and confirmations derived as
`probe_tip_height - height + 1` (height 0 is the only unconfirmed marker;
the pinned electrum-client 0.25 types `ListUnspentRes.height` as `usize`,
so the `get_history` −1 convention cannot appear). The observation path
therefore costs **exactly one request per tracked address** and never calls
`get_history` or fetches a historical transaction.

**Residual risk:** the request *count* is O(1) per address, but the
*response size* grows with the address's UTXO count, so a heavily dusted
address can still produce a large or slow response. Mitigations: every
address is fetched and failed **independently** (per-address isolation) and
each lookup runs under the configured `electrum.request_timeout`, so an
oversized/slow response fails that address only.

## Claim-time scan

The §B.5 claim-time address-index scan (`ChainHistoryPort`, same adapter;
the observer tick never calls it) issues ONE batched
`blockchain.scripthash.get_history` per 20-address window — presence only,
never a transaction fetch — so the request *count* is bounded by the
50-window scan cap. The response work is bounded three ways:

- **Item-count cap.** A window whose batched response lists more than
  `electrum.max_history_items_per_window` history items across its 20
  scripthashes (default 2,000) is rejected before any per-history domain
  value is materialised — presence is read off the raw response values,
  and the over-cap window is treated as USED (it only advances the start
  index; the 50-window bound still refuses with
  `account_history_too_deep`), never attributed to individual addresses.
  (A pre-decode response-BYTE cap is feasible on the pinned
  electrum-client 0.25 through the public `RawClient<S>` — it accepts
  any `S: Read + Write` via `impl From<S>` (raw_client.rs:191-214), and
  `batch_call` runs over it (raw_client.rs:897-906), so a capped `Read`
  wrapper around the TCP/TLS stream can reject an over-limit response
  before `BufReader` growth or JSON decode. It changes how the shared
  Electrum client is constructed, so it lands as a separate transport
  slice on the observer branch; it is deliberately not part of this
  slice. Until it lands: whole-line client buffering — the client reads
  and buffers the entire response line internally, and the item cap
  applies after that buffering.)
- **Per-window wall-clock deadline.** Connect + call + decode for one
  window must finish within `electrum.claim_scan_window_deadline`
  (default 5s). The blocking socket read cannot be cancelled, so on
  expiry the wait is abandoned, the scan fails the window
  `claim_scan_unavailable`, the stale connection is dropped and never
  reused, and the abandoned read exits at latest when
  `electrum.request_timeout` elapses on the wire.
- **Concurrency bound.** At most `electrum.max_concurrent_claim_scans`
  window fetches run at once process-wide (default 2, config-validated
  non-zero, a semaphore owned by the claim adapter); over the bound a
  claim fails `claim_scan_unavailable` immediately, before any blocking
  task or Electrum call exists — there is no queueing. Each permit is
  owned by the blocking call it admits, not by the awaiting side: it is
  released only when that call's blocking socket read actually returns.
  A read orphaned past its window deadline therefore keeps its slot
  occupied until the read ends — bounded at latest by
  `electrum.request_timeout` on the wire — so the bound holds in live
  blocking threads and sockets, not merely in awaited windows.

**Residual risk:** the request *count* is O(1) per window, but the
*response size* grows with the scanned addresses' history depth, so a
claimed account whose scanned address carries an arbitrarily large
history can still produce a large or slow response. Two residuals stand,
both bounded:

1. **Whole-line client buffering until the transport-level byte cap
   slice lands; the item cap applies after buffering.** A hostile or
   organic single response line is fully read into memory by the client
   before the item-count cap can reject it. The transport-level byte cap
   (capped `Read` wrapper around `RawClient<S>`, above) closes this; the
   per-window deadline and the concurrency bound below cap how long and
   how many such buffers can exist at once.
2. **Thread/socket occupancy by abandoned reads.** The per-window
   wall-clock deadline (`electrum.claim_scan_window_deadline`) bounds
   how long the scan *waits*, but the blocking socket read behind it
   cannot be cancelled: an over-deadline response keeps one
   blocking-pool thread, its socket, and its semaphore permit occupied
   until the read returns — bounded at latest by
   `electrum.request_timeout` on the wire, and bounded in count by the
   `electrum.max_concurrent_claim_scans` semaphore (the permit outlives
   the abandoned wait by construction) — so the residual is never
   unbounded claim latency and never unbounded blocking-pool growth.

## Budgeting rule

A strict oldest-first token bucket: each tick reserves the two probe
requests (`headers.subscribe` + `block_header(0)`) from
`min(electrum.max_requests_per_tick, electrum.max_requests_per_second ×
poll_interval)` and admits exactly as many address lookups as the remainder
allows. No bypass, no slow lane, no unmetered admission. Unadmitted and
failed targets keep their staleness and lead the next tick's plan, so every
target is observed within a bounded number of ticks and only successfully
observed targets are stamped/rotated.

## Bounded transaction fetches

The r5 rule forbids HISTORY-DRIVEN FAN-OUT in the observation tick (never `get_history` and never a `transaction.get` per history entry). It does NOT forbid two bounded, one-shot, per-invoice fetches, each charged to the same token bucket and each with a hard response-byte cap (new config `electrum.max_transaction_bytes`, default 400_000, deny_unknown_fields; over-cap = fetch failure, handled as below):
(1) CREATION-TIME (§B.4.1/§B.4.3): after the bounded history snapshot (cap `electrum.max_creation_history_entries`, default 50; over-cap = void_baseline_failed), fetch `transaction.get` for each UNCONFIRMED baseline transaction only (confirmed ones contribute no inputs, §B.4.3) to record its input outpoints. Bounded by the history cap. Any fetch failure = void_baseline_failed (acceptance 5) — never a partial baseline. For a fresh xpub-derived address the snapshot is normally EMPTY, so this path costs 0 fetches in the honest case.
(2) FIRST-BIND TIME (§B.4.2/§B.4.3): when the observer tick sees an exact-amount UTXO on a tracked address that is not in the baseline outpoint set and is above the floor, it does NOT bind immediately; it records a `candidate` and a separate bounded step fetches that ONE transaction to obtain its inputs, evaluates the replaced-input rule, then binds or marks the outpoint permanently ineligible. At most one candidate fetch per tick per invoice (oldest by height first), and once an invoice is bound no further fetches ever occur for it. Charged to the bucket like any other request. Fetch failure = candidate stays a candidate (retry next tick, isolated, never degrades global availability).

## Acceptable degradation

**Per-address only.** A failed (oversized, timed-out, or errored) lookup
for address A:

- never discards successful observations for addresses B..N in the same
  tick (A's target is simply not stamped and stays stale for the next
  tick);
- never by itself marks Electrum unavailable or triggers global backoff;
- degrades only A's observation cadence.

The endpoint degrades (availability false + exponential backoff) only on
genuine endpoint-level conditions:

1. connect failure before any lookup;
2. tip-probe failure (or wrong-network genesis);
3. three consecutive per-address lookup failures across pairwise-distinct
   addresses with no intervening success
   (`MAX_CONSECUTIVE_ADDRESS_FAILURES`). One address failing on every retry
   cannot trip this rule.

## Operator signal

- `paykit_electrum_observation_address_failures` — counter of isolated
  per-address lookup failures; a rising value localizes the problem to
  specific targets without endpoint impact.
- `paykit_electrum_backlog_oldest_age_seconds` — gauge of the oldest
  pending observation; pins when the budget is saturated or a target fails
  repeatedly (WARN log past five minutes).
- `paykit_electrum_available` and the Electrum section of `/health/ready` —
  endpoint-level degradation only, per the rule above.
- ERROR log "consecutive per-address electrum lookup failures across
  distinct addresses" when the endpoint-level failure rule trips.

## Seller-visible effect

A dusted seller's own invoice may be observed more slowly (its target keeps
failing and stays at the head of the plan, retried once per tick within
budget); every other seller's observation cadence, the shared endpoint's
request rate, and `bitcoin_offer_available` are unaffected. Payment
semantics (outpoint/value/presence, `observed_sats >= required`,
six-confirmation finality) are unchanged.

## Cluster-single observer

Exactly one replica observes cluster-wide, enforced by a session-scoped
PostgreSQL advisory lock (`pg_try_advisory_lock` on the fixed key
`OBSERVER_LEADERSHIP_LOCK_KEY`, persistence/invoices.rs). Takeover is
fail-closed: a live lease keeps other replicas idle (logged once per
transition), an expired lease (dead session) lets the next check acquire
leadership, and a failed leadership check idles the replica. No per-row
database lock is ever held across network I/O. With the current single
Railway instance this is operationally a no-op; it exists so a second
replica can never double-stamp a tick.
