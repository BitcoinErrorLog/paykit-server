# Marketplace Payment Lifecycle Decision Ledger

Status: preparation, activation, void, activated-settlement ownership, Bitcoin observation, resolution, and signed Marketplace status slices authorized.

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
  "amount_sats": 1,
  "operation_id": "marketplace-payment:<payment_reference>:<bind_attempt>",
  "payment_window_seconds": 86400
}
```

Success `200`:

```json
{
  "invoice_id": "<server-issued id>",
  "state": "prepared",
  "total_sats": 1,
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
7. Preparation time and expiry use the database clock. Configured prepare TTL defaults to 15 minutes.
8. Preparation remains unpublished: no claimable proposal outbox row and no SDK publication or cancellation.
9. Do not return a payment deadline during preparation. Payment window begins only when activation commits.
10. Reject unknown fields and fork-only fields including `stack_id`, `allocation_mode`, `nonce_sats`, address fingerprint, and caller-provided `resolved_at`.
11. Bound preparation by the same 15-second request deadline as `POST /invoices`, including the process-local operation-lock wait, session and Reader checks, receiving-detail lookup, and entry into durable storage. Deadline exhaustion returns `503 dependency_timeout`. Once a PostgreSQL mutation begins, await its factual commit or rollback result rather than canceling it into an ambiguous response.
12. Retry only a cleanly missing Reader App Registry, with three total reads and the shared full-jitter delay policy. Exhausted absence remains `reader_setup_pending`; malformed and unavailable reads keep their distinct errors.
13. A seller without Bitcoin receiving details returns `503 seller_setup_pending`, distinct from malformed buyer input and Reader setup.
14. PostgreSQL Creator-row locking and the post-lock operation read serialize commits across processes. The process-local operation mutex only suppresses duplicate external reads within one server process; it is not a horizontal-replica persistence fence.

## Activation and void contract — current implementation slice

- Activate: closed `{creator, invoice_id, total_sats}` request; DB-clock activation starts the bound payment window; atomically wins against void; inserts publication work once; replay returns stored success. Activation derives proposal acceptance duration as `min(configured proposal_acceptance_window, bound payment_window / 2)`. Duration arithmetic retains subsecond precision: a bound one-second payment window yields a 500-millisecond acceptance duration, not zero.
- Void: closed `{creator, invoice_id}` request; only prepared invoices transition; no publication or SDK cancellation; replay returns stored success.
- Activation at or after `prepare_expires_at` returns `409 prepare_expired`, signaling a new attempt. Activation after void or prepared-state resolution returns `409 lifecycle_terminal`, signaling terminal stop. Void after activation returns `409 invoice_active`, signaling that payment remains live and observation must continue. An authoritative stored-total mismatch returns `409 total_mismatch`, signaling operator alert. Exact activation and void replay still return stored `200` responses. Void remains permitted for a resolved preparation. Persisted-state and database-integrity faults return `500 internal_error`, not a retryable `503`.
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
- Settlement ownership uses migration `0014_marketplace_settlements.sql`; #74 Bitcoin observation uses `0015_marketplace_bitcoin_observations.sql`; #68 resolution immutability uses `0016_marketplace_resolution_immutability.sql`.

## Marketplace Bitcoin observation — current implementation slice

- Activated Marketplace settlements are Electrum observation targets. Prepared and voided preparations cannot own observation rows by schema construction.
- Shared Bitcoin evidence has exactly one Locks or Marketplace owner. Outpoint identity, encrypted first-observed amount, and first-observed time are immutable; chain presence, confirmations, and active replacement state remain mutable.
- A zero-confirmation, disappeared, or underpaid output may be replaced. Each replacement keeps its own first observation and timeliness; an earlier timely output never lends timeliness to a later outpoint.
- A present amount-matched output is final at six confirmations. Underpayment remains replaceable regardless of confirmation count. Reorg and stale-absence handling match Locks observation semantics.
- Marketplace settlement projection records current Bitcoin status, capped matching confirmations, amount match, historical first match, and expiry without creating Locks invoices, drains, generations, or buyer contacts.
- Existing Locks observation and `{creator, bundle_id}` behavior remains owner-isolated and unchanged apart from enforcing immutable evidence for all Bitcoin outpoints.

## Explicitly deferred follow-up and release hold

- `usdt_observations` remains unchanged; Marketplace USDT settlement ownership is a later slice.
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
