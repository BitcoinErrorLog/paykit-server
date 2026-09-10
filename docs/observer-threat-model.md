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
address can still produce a large or slow response. The transport byte
cap below bounds the memory a large response can occupy, and the
per-address wall-clock deadline (`electrum.address_deadline`) bounds how
long the tick *waits*, but the blocking socket read behind the deadline
cannot be cancelled. The socket timeout (`electrum.request_timeout`) is
PER READ, so it does not bound the abandoned task in time: a
drip-feeding endpoint answering one byte per `request_timeout − ε`
keeps the abandoned blocking task and its socket alive for up to
(`max_response_bytes` + 1) × drip interval. The residual is therefore an
abandoned blocking-pool thread + socket PER ABANDONED ATTEMPT, bounded
in count by the attempts spawned (the tick abandons at most one probe
plus one read per batch address, and the tokio blocking pool caps at
512 threads) — never unbounded tick latency or unbounded response
memory. The aggregate tick-wall bound is the probe's deadline plus one
deadline per batch address: worst case batch × `address_deadline` (up to
capacity × deadline ≈ 1000 × 5 s at defaults), versus the per-address
bound of one `address_deadline`. Mitigations:

- **Transport byte cap.** Every Electrum connection wraps its TCP/TLS
  stream in a byte-capped reader (`CappedStream`,
  `paykit-server/src/workers/electrum.rs`) constructed through
  electrum-client's `From<S: Read + Write>` `RawClient` constructor, so
  the cap applies BEFORE the client's `BufReader::read_line` buffers the
  line and before any JSON decode: **no single Electrum response line
  larger than `electrum.max_response_bytes` (default 1 MiB, accepted
  range 64 KiB–16 MiB) is ever held in memory; the connection is torn
  down.** The guarantee includes an exact consumption bound: each read
  requests at most the current line's remaining budget plus one byte
  from the socket, so **an over-cap line of any length consumes exactly
  `max_response_bytes + 1` bytes from the source before the read fails
  — never more**. The over-cap read fails with the literal `electrum
  response exceeds max_response_bytes` error and poisons the stream, so
  a half-read line can never be resumed — the next lookup reconnects on
  a fresh capped connection (connecting sends no Electrum RPC: the TLS
  handshake is transport I/O, not an Electrum request, and the client
  performs no `server.version` negotiation, so a reconnect is never a
  budgeted send).
- **Item-count cap.** A response listing more than
  `electrum.max_utxos_per_address` UTXOs (default 200) is rejected before
  any per-UTXO record is materialised — no record vector is built for it.
  The two caps are coupled at startup: configuration load refuses an
  `electrum.max_utxos_per_address` whose maximum reply (items × the
  176-byte per-item wire bound, plus the JSON-RPC envelope) would exceed
  `electrum.max_response_bytes`, so the item cap can never demand a
  response the transport byte cap refuses.
- **Per-address wall-clock deadline.** Connect + call + decode for one
  address must finish within `electrum.address_deadline` (default 5s),
  and the tick's probe shares the same deadline so a drip-feeding
  endpoint cannot stall the tick before any address is attempted. The
  blocking socket read cannot be cancelled, so on expiry the wait is
  abandoned, the tick moves on, and the stale connection is dropped and
  never reused (the next address reconnects). The abandoned blocking
  task is NOT bounded in time by `electrum.request_timeout` (that
  timeout is per read): a drip-feeding server keeps it and its socket
  alive for up to (`max_response_bytes` + 1) × drip interval; the
  residual is bounded in count — one thread + socket per abandoned
  attempt, under the tokio blocking-pool cap of 512.
- **Per-address isolation.** Over-cap, over-deadline, and errored lookups
  fail that address only; the tick's other addresses are observed
  normally.

**Transport authentication invariant.** Plaintext Electrum carries every
tracked invoice address and UTXO set unauthenticated and in the clear,
and a spoofed plaintext endpoint can feed the observer fabricated
payment confirmations. The guarantee is enforced at configuration load:
**when `bitcoin.network == mainnet`, startup refuses any
`electrum.endpoint` whose scheme is not `ssl://`, with a literal
diagnostic naming the network and the scheme** (`bitcoin.network
mainnet requires an ssl:// electrum.endpoint; the <scheme>:// scheme is
plaintext and refused`). TLS endpoints are built with the webpki root
store and certificate validation ON — there is no `validate_domain`
switch and no custom verifier in this tree. `tcp://` remains accepted on
regtest/signet/testnet for local fulcrum-style endpoints that have no
TLS. (There is no `--check-config` flag in this tree; the refusal is a
config error at load, i.e. at process startup.)

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
  reused, and the abandoned read exits when the socket read returns.
  That return is not bounded by one `electrum.request_timeout`: the
  timeout is PER READ, so the true wire bound is retries ×
  request_timeout + reconnect backoff (client-side retries are pinned
  at zero in this composition, collapsing the formula) plus, for a
  drip-feeding endpoint, up to one request_timeout per delivered byte
  until the `electrum.max_response_bytes` + 1 line cap trips.
- **Concurrency bound.** At most `electrum.max_concurrent_claim_scans`
  window fetches run at once process-wide (default 2, config-validated
  non-zero, a semaphore owned by the claim adapter); over the bound a
  claim fails `claim_scan_unavailable` immediately, before any blocking
  task or Electrum call exists — there is no queueing. Each permit is
  owned by the blocking call it admits, not by the awaiting side: it is
  released only when that call's blocking socket read actually returns.
  A read orphaned past its window deadline therefore keeps its slot
  occupied until the read ends — with the true wire bound named above
  (retries × request_timeout + reconnect backoff, retries pinned at
  zero here, plus the per-read drip-feed extension to the
  `electrum.max_response_bytes` + 1 line cap), not by one
  `electrum.request_timeout` — so the bound holds in live
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
   until the read returns — not bounded by one
   `electrum.request_timeout`: the timeout is per socket read, so the
   true bound is retries × request_timeout + reconnect backoff
   (client-side retries are pinned at zero in this composition) plus,
   for a drip-feeding endpoint, up to one request_timeout per delivered
   byte until the `electrum.max_response_bytes` + 1 line cap trips —
   and bounded in count by the
   `electrum.max_concurrent_claim_scans` semaphore (the permit outlives
   the abandoned wait by construction) — so the residual is never
   unbounded claim latency and never unbounded blocking-pool growth.

## Budgeting rule

A sustained token bucket over a strict oldest-first queue: tokens refill
from elapsed wall time at `electrum.max_requests_per_second` up to
`electrum.max_requests_per_tick`, so no loop cadence — including the
shortest ±20% jitter interval — can sustain a higher request rate (a
window's admissions are bounded by one bucket capacity plus rate × window,
and by rate × window once the bucket is drained). Each tick reserves its
two probe requests (`headers.subscribe` + `block_header(0)`) from the
bucket BEFORE sending them and admits exactly as many address lookups as
the remainder allows. Client-side call retries are pinned at zero: each
admitted target is exactly one request, charged once; the observer's own
next tick is the only retry. No bypass, no slow lane, no unmetered
admission. Startup rejects any configuration whose effective per-tick
budget —
`min(max_requests_per_tick, max_requests_per_second × poll_interval
seconds)` — does not exceed the two-request probe reservation, so no
accepted configuration can probe successfully while admitting zero address
lookups forever.

The bucket is process-wide and shared (`RequestLimiter`, owned by the
runtime and installed once at startup), and the guarantee is strict:
**every Electrum request the process sends is reserved from this bucket
before it is sent.** In THIS tree the callers are exactly:

- **the observer tick's active probe** — two requests
  (`headers.subscribe` + `block_header(0)`) reserved with `try_reserve`
  BEFORE the probe runs; if the bucket cannot cover them the tick sends
  no Electrum requests at all and defers the whole tick (counted under
  the `budget_exhausted` metric/log reason, no availability change, and
  not a zero-success tick since no lookup was attempted), retrying on
  the next poll interval;
- **the observer tick's per-address `list_unspent` lookups** — one
  atomic reserve-up-to against the post-probe balance admits the
  oldest-first prefix and charges exactly what is dispatched.

The **invoice-creation snapshot fetch and the first-bind candidate
fetch** (W1.1, this tree) run on the same capped connection constructor
(`workers/electrum.rs` is the only connection constructor, so their
`get_history` scan is byte-capped identically) and charge `try_reserve`
(or `reserve_or_wait` with a bounded deadline) before dispatch. The
claim-time history scan (W1.2) inherits the same when it rebases onto
this HEAD.

The configured rate therefore bounds the joint load, and a busy non-tick
caller shrinks — or, when it drains the bucket, wholly defers — the next
tick instead of drawing from a separate pool. There is no uncharged send
anywhere: a request that was not reserved is a request that is not sent.

Unadmitted targets keep their position and lead the next tick's plan.
Every ATTEMPTED target is stamped: a success stamps `last_observed_at`
(last successful observation; drives staleness and backlog alerting) AND
`last_attempted_at`, a failure stamps `last_attempted_at` only, and the
plan orders oldest attempt first (`COALESCE(last_attempted_at,
last_observed_at, created_at)`). Failed targets therefore rotate behind
the rest of the plan exactly like successes — a permanently failing
target cannot hold the head. **Fairness:** with F permanently failing
targets and N other pending targets, every target — honest or failing —
is *attempted* at least once per ⌈(N + F) ÷ B⌉ ticks, where B is the
per-tick address budget: the tokens the shared bucket holds for address
lookups after the tick's two probe requests are reserved. B is not a
configured constant: the production limiter starts with a full
1000-token burst, then refills from elapsed wall time at
`max_requests_per_second` (default 5/s) — 40 tokens over the shortest
jittered 8 s poll, so after the 2-token probe reservation the
steady-state default is B = 38 addresses per tick (≈ 4.75
addresses/s) — and concurrent Electrum callers (invoice-creation
snapshots, claim scans, first-bind fetches) draw from the same bucket,
so the initial burst and contention change B tick to tick. The bound
is over a fixed population: continuous invoice creation adds to N, but
a never-attempted row (NULL `last_attempted_at`) falls through the
`COALESCE(last_attempted_at, last_observed_at, created_at)` plan key to
its own `created_at`/`last_observed_at`, so it sorts only among the
never-attempted rows and enters behind every row attempted before it —
new invoices cannot starve already-attempted rows. The attacker's F
addresses cost exactly F slots per rotation, never more. (Before
failure stamping, F ≥ B permanently failing targets — each dusted with
`max_utxos_per_address` + 1 UTXOs, on invoices that never expire out of
the plan — held the head forever and honest sellers were attempted
never.) **Residual:** the attacker still slows every seller's attempt
interval by the F extra targets in the rotation: worst-case
honest-seller delay is ⌈(N + F) ÷ B⌉ ticks including the F attacker
targets, versus ⌈N ÷ B⌉ without them — bounded, not starvation.

**W1.1 creation traffic shrinks B tick to tick.** The creation-time
baseline snapshot and the first-bind candidate fetch draw from the same
shared limiter as the tick, so every creation request directly reduces
the tokens available for address lookups at the next tick. One invoice
creation reserves 3 tokens for the snapshot sequence (history +
listunspent + headers.subscribe) plus `PROBE_REQUESTS_PER_TICK` = 2 for
its post-create probe — 5 tokens per creation — plus 1 token per
unconfirmed baseline transaction whose inputs it fetches (bounded by
`electrum.max_creation_history_entries`, default 50), so a single
maximal creation charges at most 55 tokens, and the 55-token worst case
is charged at most once per invoice: a creation that loses the
`FOR UPDATE` race to an identical in-flight bind receives the winner's
`awaiting_baseline` row under the row lock and answers
`invoice_baseline_in_progress` (exactly as preflight does) instead of
running a second snapshot sequence, while a replay of the already
published invoice returns its existing terms without touching the
limiter. At the defaults (1000-token
cap, 5 tokens/s refill, 10 s ±20 % poll) one 8 s tick window refills 40
tokens, so once the initial 1000-token burst is spent a single maximal
creation in a window (55 > 40) out-consumes the refill, and a sustained
rate of one maximal creation per 11 s consumes it exactly — driving B
to 0, at which point the tick's `try_reserve(PROBE_REQUESTS_PER_TICK)`
fails, the whole tick defers as `budget_exhausted`, and no Electrum
request is sent at all. Creation load therefore slows — and at the
extreme pauses — observation, but the joint Electrum send rate never
exceeds the configured limiter, which is exactly the invariant the
limiter exists to keep.

**W1.4 batching not implemented; why.** JSON-RPC batching was dropped
from W1.4 by coordinator decision (2026-09-09). The accounting above and
the response-cap proof (`workers/electrum.rs`) both assume one address
per request line: the per-tick budget charges exactly one token per
tracked address and the byte/item caps are proven per single-address
response. Batching several addresses into one JSON-RPC request would
require a new aggregate-response-cap design — the caps would have to
bound the SUM of unrelated addresses' replies and apportion failures
back to individual addresses — and it would not reduce the count the
shared limiter charges, which is defined per address lookup, not per
wire request. The fairness and budget invariants in this document are
therefore stated, and remain, one-address/one-request.

## Runtime creation gate

A first-time bind (a new invoice or payment request that would allocate
an address) is gated on the runtime's live `bitcoin_offer_available`
verdict, in this exact order: (1) the static `bitcoin.creation_enabled`
kill switch is checked first and refuses with
`bitcoin_creation_disabled` (403); (2) the runtime availability verdict —
the same fold `/health/ready` publishes: creation flag, three consecutive
successful Electrum probes, Electrum component ready, postgres ready —
refuses with `bitcoin_offer_unavailable` (503) when false, failing
closed if the verdict cannot be read within two seconds; (3) only then
does the creation sequence charge the shared Electrum limiter. A refusal
at either gate consumes no address, advances no cursor, and sends no
Electrum request. Exact replays (W1.1 replay-by-state) are never gated
and return the existing terms. Observation is never coupled to this
gate: while the offer is hidden, existing non-final invoices remain in
`observation_plan()`, the tick still attempts them in budget order, and
a funded observation still applies and settles — only NEW binds wait for
the offer to return.

## Bounded transaction fetches

The r5 rule forbids HISTORY-DRIVEN FAN-OUT in the observation tick (never `get_history` and never a `transaction.get` per history entry). It does NOT forbid two bounded, one-shot, per-invoice fetches, each charged to the same token bucket and each with a hard response-byte cap (new config `electrum.max_transaction_bytes`, default 400_000, deny_unknown_fields; over-cap = fetch failure, handled as below):
(1) CREATION-TIME (§B.4.1/§B.4.3): after the bounded history snapshot (cap `electrum.max_creation_history_entries`, default 50; over-cap = void_baseline_failed), fetch `transaction.get` for each UNCONFIRMED baseline transaction only (confirmed ones contribute no inputs, §B.4.3) to record its input outpoints. Bounded by the history cap. Any fetch failure = void_baseline_failed (acceptance 5) — never a partial baseline. For a fresh xpub-derived address the snapshot is normally EMPTY, so this path costs 0 fetches in the honest case.
(2) FIRST-BIND TIME (§B.4.2/§B.4.3): when the observer tick sees any amount that the current bind predicate can accept on a tracked address, and the UTXO is not in the baseline outpoint set and is above the floor, it does NOT bind immediately; it records a `candidate` and a separate bounded step fetches that ONE transaction to obtain its inputs, evaluates the replaced-input rule, then binds or routes the invoice to manual review. At most one candidate fetch occurs per tick globally, and once an invoice is bound no further fetches ever occur for it. The fetch reserves one token from the shared bucket before dispatch. A failed fetch updates the candidate's durable exponential-backoff state; after twelve fetch attempts it becomes `unfetchable` and the invoice enters manual review. A persistence failure while resolving a candidate never consumes its bounded transaction-fetch retry budget; only a failed transaction fetch does. A transaction response exceeding `electrum.max_transaction_bytes` is deterministically unresolvable and moves the invoice to `manual_review` immediately; W1.4b and W1.15 provide its scheduled Paykit and seller-resolution egress. Candidate failures never degrade Electrum endpoint availability.

Every returned transaction's bytes are verified against the requested txid (`deserialize(raw).compute_txid() == requested_txid`) before its inputs are consumed, on both the creation-snapshot and first-bind fetch paths; an endpoint answering with a different valid transaction is a fetch failure, never resolution input.

Until W1.1c activation-time classification ships, R1 includes any pre-invoice transaction absent from the creation snapshot that later appears above the creation-height floor during the invoice's full observing lifetime; exact per-invoice amounts bound, but do not eliminate, this exposure.

## Acceptable degradation

**Per-address only.** A failed (oversized, over-deadline, timed-out, or
errored) lookup for address A:

- never discards successful observations for addresses B..N in the same
  tick (A's target keeps its staleness for the next tick and rotates
  behind the plan via the failure stamp);
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
- `paykit_electrum_budget_exhausted_ticks` — counter of ticks deferred
  because the shared budget could not cover the two-request probe
  reservation (INFO log with reason `budget_exhausted`); the deferred
  tick sent no Electrum requests, changed no availability, and is not a
  zero-success tick. A sustained rise means non-tick callers are
  starving observation: raise the budget or shed creation/claim load.
- Rate-limited WARN log per failing address (at most once per five minutes
  per address) naming the address and the failure reason, plus a per-tick
  summary WARN with the tick's failure count.

## Seller-visible effect

A dusted seller's own invoice may be observed more slowly: its target
keeps failing, rotates behind the plan via the failure stamp, and is
retried once per rotation, consuming one slot per rotation. Every other
seller's targets are still attempted at least once per
⌈(N + F) ÷ B⌉ ticks (N other pending targets, F of them the
attacker's failing targets, and B the per-tick address budget after the
probe reservation — moved tick to tick by the initial 1000-token burst
and by concurrent Electrum callers — so the F targets stretch the
rotation but can never starve it), the
shared endpoint's request rate stays inside the configured sustained
budget, and `bitcoin_offer_available` never degrades because of
per-address failures. Payment semantics (outpoint/value/presence,
the exact `observed_sats == required` match of W1.1b / §B.8.2 —
overpayment and underpayment are mismatches: the observation is stored
`confirmed` with `amount_matched = false`, the invoice stays `observing`
until resolve (§B.9) or expiry (W1.4b), and the marketplace service — not
paykit-server — routes the order to `manual_review` — six-confirmation
finality) are unchanged. After such a mismatch, observation of the
address continues (budgeted per-address `listunspent`, no extra per-tick
transaction fetch for an already-verified output) until resolve or
expiry, and `baseline_state = 'manual_review'` is reserved for
unfetchable/baseline anomalies.

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
