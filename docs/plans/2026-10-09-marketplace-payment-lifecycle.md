# Marketplace Payment Lifecycle Decision Ledger

Status: preparation, activation, void, activated-settlement ownership, Bitcoin observation, resolution, and signed Marketplace status slices authorized. Prepare and activate carry amount, asset and accepted assets (decision PK1, 15 Oct 2026; see the multi-asset section below).

## Authority and baseline

- Authoritative product contract: [pubky/paykit-server issue #26](https://github.com/pubky/paykit-server/issues/26), section “Marketplace lifecycle contract decisions (2026-10-09)”, read at issue update `2026-10-09T09:50:24Z`.
- Reviewed preparation baseline: `f9079d50424f31ff0a7ca3df3a12ddc43c398ea8` (tree `eb29afe4f58a83c3bb0d769a2bc51ebbcc602445`; merged to `master` with the same tree as `c351f15e6a3da0bc6c9154ebc0fb8b525aba06da`).
- PRs #64 and #65 are included in that baseline. The retained-history, stable-ID SDK retry from #65 is the accepted publication handoff guarantee. No separate pre-SDK fence is required.
- This ledger records accepted issue decisions. It does not authorize production merge or deployment.

## Shared constraints

- Use unified trusted-service authentication: canonical signed method, query-free path, and body bytes. Any allowlisted service key has equal route authority. Credential fingerprint is not operation identity.
- Marketplace routes are `POST /marketplace/payment-requests/{prepare,activate,void,resolve}`.
- All request schemas are closed. Existing `{ "error": { "code", "message" } }` envelope and Paykit error conventions apply.
- Keep existing Locks `POST /invoices` lifecycle and `(creator, bundle_id)` identity unchanged.
- Do not add `stack_id`, per-order endpoint persistence, route-specific principals, or caller-owned SDK idempotency keys.

## Preparation contract — current implementation slice

Request:

```json
{
  "creator": "<Pubky>",
  "reader": "<Pubky>",
  "reference": "<payment reference>",
  "amount": "500",
  "asset": "USD",
  "operation_id": "marketplace-payment:<payment_reference>:<bind_attempt>",
  "payment_window_seconds": 86400,
  "description": "Pubky Shop order 8F3A91"
}
```

`description` is optional. `accepted_assets` (`["BTC"]`, `["USDT"]` or both) is optional and only narrows what the seller's setup offers; omit it to offer every enabled rail. The request binding covers every field present, `accepted_assets` as a sorted set.

Success `200`:

```json
{
  "invoice_id": "<server-issued id>",
  "state": "prepared",
  "amount": "500",
  "asset": "USD",
  "accepted_assets": ["BTC", "USDT"],
  "payment_amounts": {"BTC": "6173", "USDT": "5000000"},
  "rates": {"BTC": "0.000012345679012346", "USDT": "1"},
  "prepare_expires_at": "<RFC3339 UTC>"
}
```

Accepted behavior:

1. Scope caller-chosen `operation_id` by Marketplace workflow namespace and Creator. Keep it separate from SDK `payment_reference`.
2. Hash the complete normalized immutable accepted request separately from operation identity.
3. Same scoped operation identity plus same binding returns the stored `200` response, including after preparation TTL expiry.
4. Same scoped operation identity plus changed binding returns structured `409 operation_conflict` before mutable external work. A new operation ID creates a new invoice.
5. Exact replay/conflict resolution precedes session checks, address allocation, outbox insertion, and SDK work.
6. `payment_window_seconds` is a positive integer. Bind it immutably during preparation and reject values above the relevant configured policy cap; never clamp and never accept an absolute payment deadline.
7. Preparation time and expiry use the database clock. Configured prepare TTL defaults to 15 minutes. The expiry is fixed once, when the quote is accepted (the feed read for a BTC-crossing request, the same point otherwise): the service reads the database clock then and passes `accepted_at + TTL` as an absolute deadline. After acquiring the Creator-row lock, persistence refuses with `PersistenceError::DeadlineElapsed` (HTTP `503 dependency_timeout`, nothing committed) if `clock_timestamp()` has reached it, and never starts a new TTL; `prepared_at` is the instant the quote was fixed, so `prepare_expires_at - prepared_at` is always the TTL. Exact replay is resolved under the same lock before that check and returns the stored result.
8. Preparation remains unpublished: no claimable proposal outbox row and no SDK publication or cancellation.
9. Do not return a payment deadline during preparation. Payment window begins only when activation commits.
10. Reject unknown fields and fork-only fields including `stack_id`, `allocation_mode`, `nonce_sats`, address fingerprint, and caller-provided `resolved_at`.
11. Bound preparation by the same 15-second request deadline as `POST /invoices`, including the process-local operation-lock wait, session and Reader checks, receiving-detail lookup, and entry into durable storage. Deadline exhaustion returns `503 dependency_timeout`. Once a PostgreSQL mutation begins, await its factual commit or rollback result rather than canceling it into an ambiguous response.
12. Retry only a cleanly missing Reader App Registry, with three total reads and the shared full-jitter delay policy. Exhausted absence remains `reader_setup_pending`; malformed and unavailable reads keep their distinct errors.
13. A seller missing a receiving rail the request asked for returns `503 seller_setup_pending`, distinct from malformed buyer input and Reader setup; the message names the missing rail (Bitcoin, USDT, or both).
14. PostgreSQL Creator-row locking and the post-lock operation read serialize commits across processes. The process-local operation mutex only suppresses duplicate external reads within one server process; it is not a horizontal-replica persistence fence.
15. An optional `description` is an immutable part of the request binding and is copied exactly to Payment Request `metadata.note`. It must contain 1–140 Unicode scalar values and cannot be blank, contain control or bidi direction-control characters, or contain Unicode line/paragraph separators. Explicit `null` and non-string values are invalid; accepted text is not trimmed, normalized, or truncated.
16. A scalar-valid description must also fit in the actual complete serialized Payment Request under the pinned Pubky Noise frame. Oversized requests return `400 invalid_request` before persistence. There is no guessed fixed UTF-8 description limit or description-free retry.

## Activation and void contract — current implementation slice

- Activate: closed `{creator, invoice_id, amount, asset}` request; DB-clock activation starts the bound payment window; atomically wins against void; inserts publication work once; replay returns stored success. Activation derives proposal acceptance duration as `min(configured proposal_acceptance_window, bound payment_window / 2)`. Duration arithmetic retains subsecond precision: a bound one-second payment window yields a 500-millisecond acceptance duration, not zero.
- Void: closed `{creator, invoice_id}` request; only prepared invoices transition; no publication or SDK cancellation; replay returns stored success.
- Activation at or after `prepare_expires_at` returns `409 prepare_expired`, signaling a new attempt. Activation after void or prepared-state resolution returns `409 lifecycle_terminal`, signaling terminal stop. Void after activation returns `409 invoice_active`, signaling that payment remains live and observation must continue. An authoritative stored amount or asset mismatch returns `409 total_mismatch`, signaling operator alert. Exact activation and void replay still return stored `200` responses. Void remains permitted for a resolved preparation. Persisted-state and database-integrity faults return `500 internal_error`, not a retryable `503`.
- Prepared rows have no outbox work. Activation updates lifecycle state and inserts one encrypted proposal outbox intent in one PostgreSQL transaction. Marketplace outbox ownership remains separate from Locks invoice and drain linkage.
- Activation applies `min(configured proposal_acceptance_window, bound payment_window / 2)` exactly, including subsecond results. Stable outbox UUID remains the SDK Payment Request ID on every worker retry.

## Resolution contract — current implementation slice

- Resolve: closed `{creator, invoice_id, outcome}` request where outcome is `paid_manually`, `refunded`, or `abandoned`; DB owns `resolved_at`; same outcome replays and a different outcome conflicts; annotation never rewrites protocol or Bitcoin facts.
- Resolution of a prepared invoice blocks later activation but does not block void.

## Verification required for resolution slice

- Signed production route and closed request/response/error fixtures.
- PostgreSQL-backed same-outcome replay and different-outcome conflict races across independent stores.
- DB-authoritative stored timestamp and schema-level outcome immutability.
- Prepared resolution versus activation serialization; no publication when resolution wins first.
- Resolution on prepared, active, and voided rows without Payment Request, Bitcoin observation, or SDK cancellation mutation.

## Activated settlement ownership — current implementation slice

- Activation atomically creates exactly one `marketplace_settlements` row with the active-state transition and proposal outbox row. Prepared and voided preparations have no settlement row.
- Marketplace settlement data remains separate from Locks `invoices`: it owns its encrypted payment record, Creator, Bitcoin address lookup, derivation-index lookup, and lifecycle projection. It does not fabricate a Locks bundle, lock resource, generation, drain membership, or buyer contact.
- Payment Request lifecycle attribution is owner-aware. A delivered Marketplace proposal with `outbox.invoice_id IS NULL` projects against its active Marketplace settlement without making same-Creator Locks status or drain refresh unavailable. Locks lifecycle queries and drain semantics remain invoice-only.
- Bitcoin addresses are globally unique across Locks invoices and Marketplace settlements at the PostgreSQL transaction boundary. Existing per-table invoice uniqueness and immutable activation replay remain intact.
- Settlement ownership uses migration `0014_marketplace_settlements.sql`; the optional Bitcoin rail uses `0017_marketplace_optional_bitcoin_rail.sql`; #74 Bitcoin observation uses `0015_marketplace_bitcoin_observations.sql`; #68 resolution immutability uses `0016_marketplace_resolution_immutability.sql`.

## Marketplace Bitcoin observation — current implementation slice

- Activated Marketplace settlements are Electrum observation targets. Prepared and voided preparations cannot own observation rows by schema construction.
- Shared Bitcoin evidence has exactly one Locks or Marketplace owner. Outpoint identity, encrypted first-observed amount, and first-observed time are immutable; chain presence, confirmations, and active replacement state remain mutable.
- A zero-confirmation, disappeared, or underpaid output may be replaced. Each replacement keeps its own first observation and timeliness; an earlier timely output never lends timeliness to a later outpoint.
- A present amount-matched output is final at six confirmations. Underpayment remains replaceable regardless of confirmation count. Reorg and stale-absence handling match Locks observation semantics.
- Marketplace settlement projection records current Bitcoin status, capped matching confirmations, amount match, historical first match, and expiry without creating Locks invoices, drains, generations, or buyer contacts.
- Existing Locks observation and `{creator, bundle_id}` behavior remains owner-isolated and unchanged apart from enforcing immutable evidence for all Bitcoin outpoints.

## Multi-asset prepare and activate (PK1)

Decision PK1 (John, 15 Oct 2026): one Paykit request carries every asset the seller accepts, so the Shop offers a single "Pay with Paykit" option and the buyer picks BTC or USDT0 in Bitkit.

- Request terms: `amount` is a base-unit integer string in the Locks criterion format; `asset` is the denomination (`BTC`, `USD`, `USDT`). Paykit Server derives the endpoints from the seller's setup, as for Locks invoices: a fresh Bitcoin address from the seller's xpub, and the seller's USDT address when the deployment has `[usdt]`. The optional `accepted_assets` (non-empty, unique subset of `BTC`, `USDT`) only narrows; it never adds a rail. It exists because a shared USDT address cannot be removed on reconnect, so the Shop's "Accept USDT" toggle can only be honoured by narrowing. The retired `amount_sats` body and `total_sats` response and activation fields no longer exist; no compatibility path reads them.
- Every combination is supported. USD and USDT are fixed parity (`"1"`). Anything crossing BTC uses one Blocktank rate fixed at prepare (ten-minute freshness) and stored as `PaymentConversion::Fixed` in the preparation. Activation never refetches the rate. Open question for Paykit maintainers: confirm prepare, not activation, as the fixing point.
- Each payable amount is computed with `invoice_pricing::payment_units` from the stored rates and rounded up to the endpoint's own unit, the same arithmetic Locks invoices use.
- Decision D2: with a filter, an asset that was not asked for never gets an endpoint, a rate or a payable amount. A requested rail the seller has not set up is absent, not a refusal. Only when nothing can be offered is it `503 seller_setup_pending`, naming the rail; a filter asking only for USDT on a deployment without `[usdt]` is `409 asset_unsupported`.
- Decision D4: a window over the applicable cap, `min(payment_window, conversion_payment_window)` when what is offered crosses BTC, is `400 payment_window_exceeds_cap`; it is never clamped.
- The request binding covers amount, asset, the sorted filter when present, window and description, so any change under the same `operation_id` is `409 operation_conflict`.
- Preparation envelope version 2 stores the offered terms. Version 1 envelopes written by rc11 to rc16 still decode as `{BTC, total_sats, [BTC]}` so rows prepared or activated before the upgrade keep activating, observing and reporting status. A version 1 `operation_id` cannot replay under the new binding and is an `operation_conflict`.
- `seller_setup_pending` names only rails the deployment can offer: on a deployment without `[usdt]` a `["BTC","USDT"]` filter on a seller with no Bitcoin names Bitcoin alone.
- Quote age: the feed is at most ten minutes old when read and the preparation ends one TTL (15 minutes) after that, a bound that holds whatever lock waits occur, so a quote is at most about 25 minutes old when it can last be activated, plus the payment window. Fixing the deadline on the database clock, with comparison on the same clock, leaves no app-versus-database skew in the bound.
- A settlement's `payment_expired_at` only stops Electrum discovery of its Bitcoin address after the deadline; the status route derives `expired` from the deadline at read time. A request that offers only USDT has no address to stop watching, so it never needs a stored expiry.
- Migration `0017_marketplace_optional_bitcoin_rail.sql` makes the settlement's Bitcoin address optional: a request that offers only USDT activates with no address to claim or watch, and its settlement is never an Electrum target.

## Marketplace USDT settlement and status (PK1, second slice)

- Migrations `0018` to `0020` give `usdt_observations` the Marketplace owner column (`marketplace_preparation_id`, exactly one of invoice or preparation), as `0015` did for Bitcoin, and make owner and transfer identity immutable. `usdt_observations` is a live Locks table, so `0018` adds the column and the constraints `NOT VALID` (enforced for new rows at once, brief locks), `0019` validates them without blocking Locks reads or writes, and `0020` (`-- no-transaction`, one statement, deliberately without `IF NOT EXISTS` so a retry over an interrupted build's invalid index fails visibly) builds the index `CONCURRENTLY`. Receipt facts are AEAD-bound to the settlement (`marketplace-usdt-observation`).
- Verified `erc20-transfer-eip712` proofs reach active Marketplace requests that offer USDT through the unchanged #47 attestation and canonical Arbitrum receipt checks. Attribution is the request's SDK lifecycle record; the background reconciliation pass observes it (Marketplace has no per-request status-read refresh, as for Bitcoin). A transfer already owned by another request or a Locks invoice is ignored, and the Locks path now treats a Marketplace-owned transfer the same way.
- Status adds `accepted_assets`, `payment_amounts` (every state), `usdt_arbitrum` and `paid_asset`. `usdt_arbitrum` carries `tx_hash`, `observed_amount`, `confirmations`, `amount_matched`, `paid_on_time`, `finalized`, and is `null` when no receipt is present, including after a reorg. The window is block time within `[activation second, deadline]`.
- `paid_asset` is the rail whose receipt is `amount_matched` and `paid_on_time` (earliest first), else `null`. "Earliest" is tracked per rail on the qualifying receipts alone, so a later, higher-ranked USDT receipt shown in `usdt_arbitrum` cannot move USDT behind Bitcoin, and a reorged-out or non-qualifying receipt never counts. It compares Bitcoin's first observation (this server's clock, at poll granularity) with USDT's block time (the chain's clock, whole seconds); it only orders two payments that both qualified, so a close race can name either rail and Bitcoin wins an exact tie. Both rail objects stay populated on a cross-rail double payment; partial payments across rails are never combined. `payment_state` follows Locks: `confirmed` with any included payment, `detected` with a present unconfirmed receipt, `expired` after the deadline with no qualifying payment.
- A proof pass that starts after the payment window closed, or after Bitcoin target discovery stamped the settlement expired, is an ordinary pass: the receipt is judged by its block time. An active settlement cannot leave `active` or be deleted (database triggers and `RESTRICT` keys), so a settlement that is missing under a pass is a broken invariant and stays an error.
- The settlement row and every receipt are read in one repeatable-read snapshot, so a status read overlapping a proof commit sees the request entirely before or entirely after it.

## Explicitly deferred follow-up and release hold

- Marketplace consumer adaptation and exact-revision cross-service status fixtures remain separate follow-up work.
- Marketplace must reject activation after its Marketplace-owned inventory hold expires; that cross-service timing guard belongs to the Marketplace consumer follow-up.
- PR #67 may remain a reviewed draft, but must not merge to `master` until Bitcoin observation/status, Marketplace hold-boundary work, and the accepted base-stack-stability gate are complete. No deployment is authorized.

## Verification required for preparation slice

- Signed production route and closed-schema coverage.
- PostgreSQL-backed new preparation, exact replay, changed-binding conflict, and new-operation-ID tests.
- Replay after TTL expiry.
- Positive duration and configured-cap rejection before side effects.
- DB-clock 15-minute default expiry evidence.
- No outbox or SDK publication before activation.
- Existing Locks invoice behavior remains green.

## Verification required for activation and void slice

- Signed production routes and closed request/response/error fixtures.
- Exact activation and void replay with stored DB timestamps.
- Authoritative-total, preparation-expiry, prepared-resolution, and late competing transition conflicts.
- Independent PostgreSQL stores race activate against void on one row; exactly one transition commits. Activation losing to void returns `lifecycle_terminal`; void losing to activation returns `invoice_active`.
- No claimable work while prepared or voided; activation admits exactly one proposal intent.
- Existing stable-ID outbox handoff consumes the Marketplace proposal without a second lifecycle state machine.

## Verification required for activated settlement ownership slice

- Fresh and upgrade migrations establish owner constraints without changing `usdt_observations`.
- Prepared and voided preparations have no settlement; activation creates one settlement exactly once under replay and activate/void races.
- Cross-owner Bitcoin address collisions fail closed in PostgreSQL; existing Locks invoice address uniqueness remains unchanged.
- Actual SDK-delivered Marketplace proposals project lifecycle state to the Marketplace owner while same-Creator Locks status and drain refresh remain available.
- Existing Locks lifecycle, status, drain, and `buyer_contacts` coverage remains unchanged and green.

## Verification required for Marketplace Bitcoin observation slice

- Fresh and upgrade PostgreSQL migrations preserve Locks evidence while adding exactly-one-owner and immutable-evidence constraints.
- Prepared and voided preparations remain excluded; activated settlements are discovered through authenticated payment records.
- Tests cover active zero-confirmation replacement, immutable first time and amount, no timeliness transfer, reorg, late match, underpayment replacement, six-confirmation finality, and stale absence.
- Cross-owner outpoints conflict; Creator and AEAD parent binding remain isolated.
- Existing Locks observation, status, drain, lifecycle, and buyer-contact suites remain green.

## Verification required for multi-asset prepare and activate

- Every denomination and filter combination prepares over the signed route with the expected endpoints, rates and payable amounts; an omitted filter offers what the seller enabled; exact replay never reads the feed.
- A Creator-row lock wait that outlasts the fixed quote deadline (with and without crossing the request deadline) commits nothing, keeps the address index and never lets the exact retry reuse the old rate; a wait that ends inside it commits with `prepare_expires_at` equal to the fixed deadline; exact replay after the deadline returns the stored preparation.
- Refusals persist nothing and keep the address index: nothing to offer (each missing rail), USDT-only filter without `[usdt]`, window over cap (including 3,601 s on a BTC-crossing request while parity requests keep the ordinary cap), unavailable or stale feed.
- The feed failing at activation does not affect activation; the stored rates are the ones proposed.
- A 1,800 second window gives a 15 minute accept-by and a 30 minute payment deadline.
- A BTC payment on a dual-asset request is matched against the converted sats; rc16 envelopes still activate and report status; a USDT-only request activates and is never an observation target.

## Verification required for Marketplace USDT settlement and status

- A verified proof on a dual-asset request reaches the status route (included, then finalized); a reorg returns `usdt_arbitrum: null` and the receipt returns with the block; a finalized receipt is never un-presented.
- Underpaid, early, late and exact-deadline receipts; BTC payment on a dual request; a cross-rail double payment keeping both observations with the earlier rail as `paid_asset` in both orders; partial payments across rails never combined.
- One transfer, one request: a second request and a Locks invoice cannot take an owned receipt; a request that did not offer USDT ignores a USDT proof; a USDT-only request settles by its proof alone.
- A status read racing a proof submission sees only the state before or after it (bounded, synchronised reads under an explicit request budget).
- With several USDT receipts, `paid_asset` follows the earliest qualifying receipt in either order against Bitcoin, after a reorg of the earliest receipt, and ignores an earlier non-qualifying one.
- The integrity scan authenticates Marketplace receipts and a tampered receipt fails the status read closed; `0018` to `0020` upgrade existing Locks receipts untouched, and an open Locks writer is neither blocked by the validation or the concurrent index build nor waited for by the validation.
