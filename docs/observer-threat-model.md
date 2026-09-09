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
   *attempted* within a bounded number of ticks, and a stall in observing
   one address must not delay the others, because
   `bitcoin_offer_available` on `/health/ready` (and with it the ability
   to take new Bitcoin binds) depends on a healthy observation loop.

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
address can still produce a large or slow response. The per-address
wall-clock deadline below (`electrum.address_deadline`) bounds how long
the tick *waits*, but the blocking socket read behind it cannot be
cancelled: an over-deadline response keeps one blocking-pool thread and
its socket occupied until the read returns — bounded at latest by
`electrum.request_timeout` on the wire — so the residual is thread/socket
occupancy by abandoned reads, never unbounded tick latency. Mitigations:

- **Item-count cap.** A response listing more than
  `electrum.max_utxos_per_address` UTXOs (default 200) is rejected before
  any per-UTXO record is materialised — no record vector is built for it.
  (electrum-client 0.25 does not expose its transport stream — it buffers
  the whole response line and parses JSON internally — so the response
  line itself is still read and JSON-decoded by the client; the cap plus
  the deadline is the strongest bound the pinned client permits.)
- **Per-address wall-clock deadline.** Connect + call + decode for one
  address must finish within `electrum.address_deadline` (default 5s). The
  blocking socket read cannot be cancelled, so on expiry the wait is
  abandoned, the tick moves on, the stale connection is dropped and never
  reused (the next address reconnects), and the abandoned read exits at
  latest when `electrum.request_timeout` elapses on the wire.
- **Per-address isolation.** Over-cap, over-deadline, and errored lookups
  fail that address only; the tick's other addresses are observed
  normally.

## Budgeting rule

A sustained token bucket over a strict oldest-first queue: tokens refill
from elapsed wall time at `electrum.max_requests_per_second` up to
`electrum.max_requests_per_tick`, so no loop cadence — including the
shortest ±20% jitter interval — can sustain a higher request rate (a
window's admissions are bounded by one bucket capacity plus rate × window,
and by rate × window once the bucket is drained). Each tick charges its
two probe requests (`headers.subscribe` + `block_header(0)`) against the
bucket and admits exactly as many address lookups as the remainder allows.
Client-side call retries are pinned at zero: each admitted target is
exactly one request, charged once; the observer's own next tick is the
only retry. No bypass, no slow lane, no unmetered admission. Startup
rejects any configuration whose effective per-tick budget —
`min(max_requests_per_tick, max_requests_per_second × poll_interval
seconds)` — does not exceed the two-request probe reservation, so no
accepted configuration can probe successfully while admitting zero address
lookups forever.

The bucket is process-wide and shared (`RequestLimiter`, owned by the
runtime and installed once at startup): the observer tick charges its
probe and lookups against it, and non-tick Electrum callers —
invoice-creation snapshot fetches, the first-bind candidate fetch, and
the claim-time history scan — reserve from the same bucket before
dispatch. The configured rate therefore bounds the joint load, and a busy
non-tick caller shrinks the next tick's admission instead of drawing from
a separate pool.

Unadmitted and failed targets keep their staleness and lead the next
tick's plan, and only successfully observed targets are stamped/rotated.
**Fairness:** every target is *attempted* at least once per
⌈N ÷ per-tick budget⌉ ticks (N = pending targets). **Residual:** a failed
target keeps its queue position and consumes one admission slot per tick
until it succeeds or its invoice expires, so a permanently failing oldest
target reduces every other seller's effective per-tick capacity by exactly
one slot — it can never take more.

## Acceptable degradation

**Per-address only.** A failed (oversized, over-deadline, timed-out, or
errored) lookup for address A:

- never discards successful observations for addresses B..N in the same
  tick (A's target is simply not stamped and stays stale for the next
  tick);
- never marks Electrum unavailable and never triggers global backoff —
  no number or pattern of per-address failures (one address, three
  distinct addresses, or an A,B,A alternation) is promoted to an
  endpoint-level condition;
- degrades only A's observation cadence, at the cost of the one slot per
  tick stated above.

The endpoint degrades (availability false + exponential backoff) only on
genuine endpoint-level conditions:

1. connect failure before any lookup;
2. tip-probe failure (or wrong-network genesis).

## Operator signal

- `paykit_electrum_observation_address_failures{reason="error" |
  "response_too_large" | "deadline"}` — counter of isolated per-address
  lookup failures by closed reason label; a rising value localizes the
  problem to specific targets without endpoint impact.
- `paykit_electrum_backlog_oldest_age_seconds` — gauge of the oldest
  pending observation; pins when the budget is saturated or a target fails
  repeatedly (WARN log past five minutes).
- `paykit_electrum_available` and the Electrum section of `/health/ready` —
  endpoint-level degradation only, per the rule above.
- `paykit_electrum_zero_success_ticks` — counter of ticks that attempted
  ≥1 lookup and succeeded at none; with failures isolated from
  availability, this is the signal that observation is silently doing no
  work. Each such tick also logs ERROR once per streak (the streak resets
  on the first tick with a successful lookup). No availability change, no
  backoff.
- Rate-limited WARN log per failing address (at most once per five minutes
  per address) naming the address and the failure reason, plus a per-tick
  summary WARN with the tick's failure count.

## Seller-visible effect

A dusted seller's own invoice may be observed more slowly (its target
keeps failing, stays at the head of the plan, and is retried once per tick
within budget, consuming one slot per tick until it succeeds or the
invoice expires). Every other seller's targets are still attempted at
least once per ⌈N ÷ per-tick budget⌉ ticks, the shared endpoint's request
rate stays inside the configured sustained budget, and
`bitcoin_offer_available` never degrades because of per-address failures.
Payment semantics (outpoint/value/presence, `observed_sats >= required`,
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
