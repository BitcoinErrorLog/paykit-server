# Lock Payment Draining and Deadline Implementation Plan

> **For Hermes:** Use subagent-driven-development to implement this plan one review-gated commit slice at a time. Stop after each slice; the user commits before the next slice.

**Goal:** Make Paykit Server create bounded Locks invoices, expose durable lifecycle/payment status, and own atomic Payment Request draining for graceful Locks deletion without taking ownership of Locks entitlement policy.

**Architecture:** Paykit Server derives payment terms from the canonical content lock, compares Locks’ signed `payment_in`, commits invoice timestamps and Payment Request intent atomically, and observes Bitcoin through existing BDK Electrum abstractions. A new persisted lock-wide drain snapshots local Payment Request lifecycle, enqueues cancellations for unanswered requests, and exposes aggregate status. Locks polls separate per-Bundle factual status and applies its own `minimum_confirmations` policy.

**Tech Stack:** Rust 2024, Axum, Tokio, SQLx/PostgreSQL, `paykit-lib`/`paykit-sdk`, BDK Electrum, encrypted semantic intents, Ed25519 method/path/body authentication.

**Sibling plan:** Locks `docs/plans/2026-08-10-graceful-content-lock-deletion.md`. Both plans repeat the shared wire contract deliberately.

---

## Status and provenance

- Plan status: **implemented and verified against an isolated PostgreSQL 16 test database**.
- Deadline/lifecycle amendment (2026-09-28): the later Payment Request rejection work
  supersedes this plan's original equal-deadline and stop-observing design. Current
  contract uses separate deployment-configured proposal/payment windows, preserves
  late factual payment evidence, and keeps request lifecycle, payment status,
  deadline eligibility, and observed Bitcoin evidence orthogonal. Historical task
  descriptions below are updated where their old wording would otherwise direct a
  current implementation incorrectly.
- Repository inspected: `/home/u/Projects/Synonym/Paykit/paykit-server`.
- Planning base when written: clean `master` at `f38c791`.
- Current Locks Core dependency is pinned to `df5ea1b...`; implementation must update it to the reviewed Locks revision containing required `payment_in`.
- Current Paykit Rust dependency remains pinned to `52a8529...` unless ordinary compatibility work proves a reviewed update necessary. No new Paykit protocol field/event is planned.
- There has been no production deployment. Migration `0007` performs the approved
  one-time destructive staging reset before installing the separate immutable
  proposal/payment deadline terms; SQLx records it once, so later starts do not
  repeat the reset. Earlier migration `0002` remains historical migration context.

## Explicit requirements and confirmed decisions

1. Signed invoice creation still accepts `payment_in` as a nonzero JSON `u64`
   whole-hour compatibility field. An omitted request value defaults to `24`;
   explicit invalid values remain rejected. It does not configure either persisted
   deadline.
2. Paykit fetches the canonical lock and requires request `payment_in` to equal the
   lock criterion value. An omitted canonical criterion value also defaults to `24`;
   explicit mismatch rejects before invoice/outbox/allocation side effects. Omitted
   and explicit `24` normalize to the same idempotency binding.
3. Paykit Server deployment config owns both windows and computes/persists:

```text
invoice_created_at = authoritative database creation timestamp
proposal_expires_at = checked(invoice_created_at + proposal_acceptance_window)
payment_deadline = checked(invoice_created_at + payment_window)
0 < proposal_acceptance_window < payment_window
```

Defaults are one hour for proposal acceptance and 24 hours for payment. Both are
configurable deployment policy.

Production samples `clock_timestamp()` only after acquiring the decisive Creator or invoice row fence. This prevents lock wait from making a transaction-start timestamp stale across a deadline. Deterministic caller-time seams remain test-only.

4. Integer-to-duration and timestamp addition are checked. Unrepresentable deadlines reject before side effects.
5. Exact invoice replay resolves persisted state before mutable lock fetch and returns original timestamps without recomputation.
6. Payment Request `proposal_expires_at` is strictly earlier than
   `payment_deadline`; it governs proposal acceptance only. Once accepted, proposal
   expiry has no settlement effect.
7. Post-acceptance expiry is Paykit Server/Locks application policy, not a Paykit protocol event or `paykit-sdk` lifecycle change.
8. Payment is timely when Paykit’s durable first amount-matched observation satisfies `first_amount_matched_observed_at <= payment_deadline`. An earlier underpayment does not lend its timestamp to a later qualifying output.
9. Bitcoin has no trusted broadcast time; miner block time is not used. Polling latency is accepted.
10. After the inclusive deadline passes without a timely amount-matched observation,
    payment eligibility expires, but observation continues until factual Bitcoin
    finality. Late or underpaid outputs remain durable evidence and cannot grant
    automatic access.
11. An underpayment may be replaced by a qualifying output after the deadline for
    factual reconciliation, but that replacement is late and cannot become timely.
12. Timely amount-matched payment has no second timeout and may keep graceful deletion blocked during unresolved confirmations/reorg behavior.
13. Paykit reports factual confirmations/amount match only. Locks owns `minimum_confirmations`; drain requests do not carry it.
14. Before a new drain or per-Bundle status result, Paykit receives linked-peer messages and projects the canonical SDK reducer under the same Creator mutation fence. Partial receive or projection failure returns unavailable instead of using stale lifecycle state. A durable lock-wide drain then atomically snapshots lifecycle:
   - acceptance committed before snapshot: accepted and monitored;
   - rejection committed before snapshot: terminal rejected;
   - unanswered before snapshot: durably enqueue cancellation;
   - acceptance arriving after cancellation commit loses, even if emitted earlier.
15. Ambiguous proposal retries reuse one Payment Reference but can create several SDK Payment Request IDs. Paykit persists every semantically matched attempt per invoice. Any accepted/proof-submitted/active-recurring attempt makes that invoice accepted, while every still-proposed sibling attempt still receives its own cancellation intent. Drain activation durably rejects new lifecycle-attempt insertion and prevents queued, retryable, or already-leased proposal handoff after the snapshot. `cancellation_enqueued_count` counts cancellation attempts, while accepted and terminal counts count invoices; a keyed commitment binds the exact frozen cancellation membership, and both exact replay and cleanup fail closed if cancellation ownership, membership, or cardinality diverges.
16. Exact drain replay returns the same frozen per-item classification and never reclassifies delayed lifecycle events. Aggregate progress is monotonic: each frozen accepted item becomes aggregate-terminal when its invoice is application-expired or has a timely durable first amount-matched observation; `accepted_count` decreases by that number, `terminal_count` increases by the same number, `cancellation_enqueued_count` remains fixed, and `completed` is irreversible once `accepted_count == 0`.
17. Durable cancellation enqueue is sufficient; no SDK Sent state or payer acknowledgment blocks cleanup.
18. Rejected and canceled requests do not block Locks cleanup. Accepted requests block until application expiry or factual payment progress permits Locks to satisfy its frozen criterion.
19. Paykit owns the durable drain and aggregate factual status. Locks owns the overall content-deletion job.
20. Locks polls per-Bundle status separately. Bundle IDs stay in signed POST bodies, never URLs or logs.
21. Creator-facing Locks status receives no Paykit identifiers. Internal drain lookup returns aggregates only.
22. After graceful completion, Locks asks Paykit to remove the operational drain record. Invoice/payment records remain terminal financial history.
23. Old delayed lifecycle messages cannot reopen canceled/expired state or contaminate a later fresh publication of the same canonical Lock ID.
24. Reader/payment UI must stop presenting payment at the application deadline. Late payment yields no Locks access or automatic refund; that risk is explicitly accepted.
25. Migration `0007` transactionally clears incompatible staging-only Paykit
    application rows before replacing the old deadline columns. SQLx applies it once;
    it preserves migration history, does not touch the Locks database, and is not a
    recurring startup reset.

## Source-derived constraints

- `PaymentRequestTerms::proposal_expires_at` is documented as expiry before acceptance.
- Paykit SDK derives `ProposalExpired` only when current lifecycle is `Proposed`; accepted state is not expired by this timestamp.
- Existing invoice creation persists encrypted Payment Request intent and invoice allocation atomically.
- Existing exact replay runs before new mutable discovery/creation work and must remain replay-first.
- Existing observer loads all invoices not factual-final at six amount-matched
  confirmations, including business-expired invoices. Persist deadline eligibility
  separately; do not filter late factual reconciliation out of observation targets.
- Existing `/transactions/status` is factual Bitcoin state only. New Payment Request lifecycle status must not silently change that stable contract.
- Existing Bitcoin integration uses `bdk_electrum`; do not add direct ad hoc `electrum-client` scanning.
- Outbox handoff is at-least-once and distinct from counterparty delivery.
- Paykit Server and Locks PostgreSQL cannot transact atomically.

## Explicitly accepted risks

- Late payment can receive no access and no refund.
- Polling latency determines `first_amount_matched_observed_at` and can classify a previously broadcast transaction as late.
- Timely amount-matched payment can remain monitored indefinitely below the Locks confirmation threshold.
- Cancellation may not reach the payer before Locks finishes other cleanup.
- Proposal expiry remains semantically weaker than the application payment deadline.

## Repository ownership matrix

| Contract/state | Owner |
| --- | --- |
| `payment_in` schema and canonical lock validation | Locks Core |
| Signed request production | Locks Server |
| Request/lock `payment_in` compatibility comparison | Paykit Server |
| Deployment proposal/payment windows and invoice timestamps | Paykit Server |
| `proposal_expires_at` population | Paykit Server |
| Payment Request event projection | Paykit SDK consumed by Paykit Server |
| Lock-wide drain classification/cancellations | Paykit Server |
| Bitcoin first-observation/confirmations | Paykit Server |
| `minimum_confirmations` and entitlement | Locks |
| Content/credential/deletion orchestration | Locks |
| Terminal financial history | Paykit Server |

## Shared service-to-service contract

All bodies are closed canonical JSON authenticated by `X-Paykit-Signature` over `b"paykit-http-signature-v1\0" + uppercase_method + b"\0" + exact_query_free_path + b"\0" + exact_raw_body`. Body-only signatures are rejected. Do not log bodies, signatures, Bundle IDs, readers, addresses, Payment Request IDs, payment references, or internal drain IDs.

### Invoice creation

```http
POST /invoices

{
  "bundle_id": "...",
  "lock_resource": "pubky.../pub/locks.app/<lock_id>.json",
  "reader": "pubky...",
  "payment_in": 24
}
```

Success is a closed JSON body for new and exact replay:

```json
{
  "invoice_created_at": "<RFC3339 UTC>",
  "payment_deadline": "<RFC3339 UTC>"
}
```

Reject unknown fields and explicit invalid `payment_in`. Normalize omitted request and canonical-lock values to `24`, then compare them before creating new state. For exact replay, verify the persisted request binding includes normalized `payment_in` and return persisted timestamps before mutable lock lookup.

### Lock-wide drain

```http
POST /payment-request-drains
{ "lock_resource": "..." }
```

Atomically creates/replays a drain keyed by canonical lock resource. It carries no `minimum_confirmations`.

```http
POST /payment-request-drain-lookups
{ "lock_resource": "..." }
```

Both drain endpoints return `200` with the same closed aggregate body:

```json
{
  "status": "active",
  "accepted_count": 0,
  "terminal_count": 0,
  "cancellation_enqueued_count": 0,
  "cleanup_token": "<43-character-unpadded-base64url>"
}
```

`status` is exactly `active` or `completed`. The response contains no drain ID, replay flag, Bundle ID, reader, Payment Request ID, address, payment reference, or raw error. Replay preserves the frozen drain identity, cancellation count, and cleanup token while returning its latest monotonic aggregate progress.

### Per-Bundle lifecycle/payment status

```http
POST /payment-requests/status
{ "creator": "pubky...", "bundle_id": "..." }
```

Return orthogonal fields rather than a combinatorial state enum:

```json
{
  "request_state": "proposed",
  "payment_state": "undetected",
  "invoice_created_at": "<RFC3339 UTC>",
  "payment_deadline": "<RFC3339 UTC>",
  "confirmations": 0,
  "amount_matched": false
}
```

The canonical persisted `request_state` is one of these exact closed snake-case values, mapped one-to-one from Paykit SDK lifecycle state:

- `proposed`
- `proposal_expired`
- `accepted`
- `rejected`
- `canceled`
- `proof_submitted`
- `active_recurring`
- `recovery_required`
- `invalid_conflict`

`payment_state` is exactly one of:

- `undetected`
- `detected`
- `confirmed`
- `expired`

`expired` is returned when the invoice has a durable `payment_expired_at`; otherwise the persisted observation state maps one-to-one to `undetected`, `detected`, or `confirmed`. `confirmations` and `amount_matched` remain orthogonal factual fields.

Exact terminal success fixtures for Locks are published under
`docs/fixtures/payment-request-status/` and are checked byte-for-byte against the
HTTP serializer.

Locks maps `rejected`, `canceled`, and `proposal_expired` requests to `VerificationTaskStatus::Expired`. An `accepted` request whose `payment_state` is `expired` also maps to `Expired`. These terminal outcomes carry no failure message and never map to `Failed`.

Drain classification uses the persisted state without inference from invoice delivery or Bitcoin observation:

- `accepted`, `proof_submitted`, and `active_recurring` are accepted and blocking;
- `rejected`, `canceled`, and `proposal_expired` are terminal and non-blocking;
- `proposed` is unanswered and requires durable cancellation enqueue;
- `recovery_required` returns unavailable and `invalid_conflict` returns conflict.

`recovery_required` maps to `503 unavailable`; `invalid_conflict` maps to `409 conflict`. These mappings do not alter the canonical lifecycle persisted by this projection.

The stable drain-classification error envelopes are:

- `409 {"error":{"code":"conflict","message":"request conflicts with persisted payment state"}}`
- `503 {"error":{"code":"unavailable","message":"payment request state is unavailable"}}`

Absent drain lookups and absent per-Bundle statuses reuse `404 {"error":{"code":"not_found","message":"requested resource was not found"}}`.

### Operational drain cleanup

Drain creation and lookup responses include an opaque `cleanup_token`: the canonical unpadded base64url encoding of 32 server-keyed, domain-separated bytes bound to the immutable drain identity. The token is not an internal drain ID, is not reversible, is stable across restart/exact replay, and must never be logged. Add `POST /payment-request-drain-cleanups`, authenticated by the existing canonical Locks signature boundary. It accepts the exact query-free body:

```json
{"cleanup_token":"<43-character-unpadded-base64url>","lock_resource":"pubky<creator>/pub/locks.app/<lock_id>.json"}
```

On success it returns the exact closed response `200 {"status":"removed"}`. Cleanup is cycle-bound and idempotent: deleting the matching completed drain advances the publication generation once and durably retains the consumed token as the generation boundary's cleanup receipt; replay of that token while no newer drain exists returns the same response without advancing again. A token that cannot be verified against either the current drain or its retained cleanup receipt—including an arbitrary token for a never-known lock or a delayed old token after a newer drain exists—returns the existing coarse `409 conflict` envelope and cannot delete or advance the newer cycle. An active matching drain also returns `409 conflict`. Authenticated envelope mismatch, corrupt receipt/generation state, or unavailable persistence returns the existing coarse `503 unavailable` envelope. The operation rejects query strings, unknown body fields, padding, non-canonical base64url, and token lengths other than exactly 32 decoded bytes. It deletes only a completed operational drain after Locks external cleanup succeeds and must never delete invoices, Bitcoin observations, Payment Request events, cancellation intents, or financial audit history. No lock, Bundle, internal drain ID, invoice, reader, or Payment Request identifier appears in the response or error envelope.

## Persistence model

### Invoice additions

Persist non-null:

- `invoice_created_at` as authoritative UTC database/application commit time;
- `proposal_expires_at` as immutable UTC proposal-acceptance cutoff;
- `payment_deadline` as immutable UTC timestamp;
- `proposal_acceptance_seconds` and `payment_window_seconds` as immutable deployment-policy bindings;
- `first_amount_matched_observed_at` when an amount-matched output first becomes durably observed;
- application eligibility state separate from factual observation state, sufficient
  to retain late/underpaid evidence through factual finality.

The timestamp used to decide timeliness must be assigned in the same transaction that first persists an amount-matched observation. An underpayment does not set this timestamp. Replacing/reorging an output must not move the original timely matched observation later or allow an untimely replacement to become timely.

### Drain additions

Persist:

- canonical lock-resource lookup/binding;
- drain creation/cutoff timestamp;
- immutable snapshot membership/classification or equivalent durable per-invoice relation;
- current aggregate/reconciliation status;
- one cancellation intent relationship/outbox identity per still-proposed SDK attempt;
- cleanup/completion state;
- exact-replay binding.

Do not rely on re-querying current lifecycle on replay. Old delayed acceptance after cancellation remains non-winning.

## Implementation sequence

Each task is a separate review/commit checkpoint. Do not commit automatically.

### Task 1: Consume and validate Locks `payment_in`

**Objective:** Update to the reviewed Locks Core revision and parse the criterion field without changing other payment terms, while normalizing omitted current-Locks values to `24`.

**Files:**
- Modify: root `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `paykit-server/src/domain/invoice.rs`
- Modify: `paykit-server/src/application/create_invoice.rs`
- Test: neighboring unit tests in those files

**Dependency gate:** Locks Core `payment_in` commit must be reviewed first. Pin an anonymously reachable HTTPS Git revision; do not use a local path.

**RED:** Test omitted request/canonical-lock defaulting, zero/string/fraction/out-of-range rejection, exact whole-hour parse, request/canonical-lock mismatch, normalized idempotency binding, and no invocation of allocation/outbox persistence on mismatch.

**GREEN:** Add a typed criterion duration parser, normalize omitted request/canonical-lock values to `24`, and include normalized `payment_in` in `CreateInvoiceRequest` and exact payment binding.

**Verify:**

```bash
cargo test -p paykit-server domain::invoice
cargo test -p paykit-server application::create_invoice
cargo test --workspace --no-run
```

**Suggested commit:** `feat(invoice): validate payment window hours`

### Task 2: Persist authoritative invoice deadlines and return them

**Objective:** Commit original invoice timestamps atomically and make exact replay return them.

**Files:**
- Create: next forward-only SQL file under `paykit-server/migrations/`
- Modify: `paykit-server/src/persistence/invoices.rs`
- Modify: `paykit-server/src/application/create_invoice.rs`
- Modify: `paykit-server/src/http/invoices.rs`
- Test: invoice persistence/application/HTTP tests
- Test: relevant `paykit-server-e2e` invoice tests

**RED:** Test the one-time staging reset and restart preservation, checked
duration/timestamp overflow, one timestamp assignment per new invoice, exact replay
after clock advance, strict proposal-before-payment ordering, strict JSON response,
and rollback of invoice/allocation/outbox on failure.

**GREEN:** Migration `0007` clears incompatible staging application rows
transactionally, removes `payment_in_hours`, and installs separately bound proposal
and payment windows. Generate the authoritative timestamp in the atomic persistence
boundary, persist both strictly ordered deadlines, and return a typed result.
Preserve replay-first behavior; SQLx migration history prevents a second reset.

**Verify:**

```bash
cargo test -p paykit-server application::create_invoice
cargo test -p paykit-server persistence::invoices
cargo test -p paykit-server-e2e
```

**Suggested commit:** `feat(invoice): commit payment deadlines`

### Task 3: Persist first observation and enforce deadline-aware targets

**Objective:** Persist deadline eligibility without stopping factual reconciliation
of expired, late, or underpaid invoices.

**Files:**
- Create: next SQL migration under `paykit-server/migrations/`
- Modify: `paykit-server/src/persistence/invoices.rs`
- Modify: `paykit-server/src/workers/observer.rs`
- Modify: `paykit-server/src/bitcoin.rs`
- Test: observer and invoice persistence tests
- Test: relevant E2E observer tests

**RED:** With an injected clock, cover observation before/equal/after deadline,
underpayment replacement on both sides of the deadline, late qualifying evidence,
timely matched continuation, restart persistence, reorg/replacement behavior, and
continued target inclusion until factual finality.

**GREEN:** Assign `first_amount_matched_observed_at` durably when first persisting an
amount-matched output. Apply inclusive deadline comparison for eligibility. Persist
application expiry independently, then continue all non-final factual observations,
including late and underpaid evidence, to existing factual finality.

**Suggested commit:** `feat(observer): enforce invoice payment deadlines`

### Task 4: Project Payment Request lifecycle durably

**Objective:** Make accepted/rejected/proposed/canceled state queryable and suitable for atomic drain classification.

**Files:**
- Create/modify: persistence module under `paykit-server/src/persistence/` for lifecycle projection
- Modify: `paykit-server/src/persistence/sdk_state.rs`
- Modify: receive/runtime integration in `paykit-server/src/paykit.rs` or the exact existing receiver seam discovered during implementation
- Modify: `paykit-server/src/domain/mod.rs`
- Test: SDK-state/persistence/runtime tests

**RED:** Cover idempotent acceptance/rejection/cancellation events, FIFO conflicts, recovery-required/invalid state, delayed acceptance after local cancellation, and restart persistence. Do not infer acceptance from invoice delivery or payment detection.

**GREEN:** Persist the canonical Paykit SDK-derived lifecycle at the actual receive/outbound state boundary with enough event identity to reject stale/duplicate transitions.

**Implementation-contract gate:** Patch exact lifecycle enum/error mappings into both plans before GREEN.

**Suggested commit:** `feat(payment-request): persist lifecycle projection`

### Task 5: Add atomic lock-wide drain persistence and cancellation intents

**Objective:** Freeze lifecycle classification and enqueue unanswered cancellations in one durable Paykit transaction.

**Files:**
- Create: `paykit-server/src/application/payment_drain.rs`
- Create: `paykit-server/src/persistence/payment_drains.rs`
- Create: next SQL migration under `paykit-server/migrations/`
- Modify: `paykit-server/src/application/mod.rs`
- Modify: `paykit-server/src/persistence/mod.rs`
- Modify: existing outbox semantic intent types only through public Paykit APIs
- Test: payment drain application/persistence tests and PostgreSQL E2E

**RED:** Prove accepted/rejected/unanswered classification, cancellation intent creation, exact replay immutability, late acceptance losing, duplicate drain idempotency, cancellation enqueue sufficient, no `minimum_confirmations`, and no reader/identifier leakage in aggregates.

**GREEN:** Use Paykit’s public cancellation API/semantic intent, not custom private protocol JSON. Link cancellation outbox rows durably to classified invoices.

**Suggested commit:** `feat(payment-request): persist lock payment drains`

### Task 6: Expose signed drain and lifecycle endpoints

**Objective:** Provide the three closed Locks-facing APIs without changing `/transactions/status`.

**Files:**
- Create: `paykit-server/src/http/payment_drains.rs`
- Create: `paykit-server/src/http/payment_requests.rs`
- Modify: `paykit-server/src/http/mod.rs`
- Modify: `paykit-server/src/server.rs`
- Modify: `paykit-server/src/http/error.rs`
- Modify: runtime/setup composition as required by actual constructors
- Test: HTTP/auth tests and `paykit-server-e2e`

**RED:** Test canonical signature authentication, unknown-field rejection, body-only identifiers, drain exact replay, aggregate redaction, per-Bundle orthogonal state, immutable timestamps, and stable 404/conflict/unavailable mappings.

**GREEN:** Implement:

- `POST /payment-request-drains`
- `POST /payment-request-drain-lookups`
- `POST /payment-requests/status`

Keep `/transactions/status` factual and backward-compatible. New lifecycle consumers use `/payment-requests/status` exclusively.

**Implementation-contract gate:** Exact response enums/fields must first be patched identically into both plans.

**Suggested commit:** `feat(http): expose payment drain status`

### Task 7: Remove completed operational drains safely

**Objective:** Let Locks forget a completed graceful deletion without deleting financial history or permitting old events to reactivate.

**Files:**
- Modify: payment drain application/persistence modules
- Modify: payment drain HTTP module
- Test: persistence and HTTP E2E

**RED:** Test idempotent removal, rejection while drain is nonterminal, invoice/observation/event retention, late acceptance remaining terminal, and fresh same-lock-resource drain identity after cleanup using only new Bundle IDs.

**GREEN:** Implement the synchronized signed POST-body cleanup contract. Preserve terminal per-invoice lifecycle guards independently of the operational drain row.

**Suggested commit:** `feat(payment-request): finalize completed drains`

### Task 8: Runtime supervision, metrics, and docs

**Objective:** Keep observer/drain readiness truthful and document late-payment risk without leaking identifiers.

**Files:**
- Modify: `paykit-server/src/runtime.rs`
- Modify: `paykit-server/src/workers.rs`
- Modify: `paykit-server/src/metrics.rs`
- Modify: `paykit-server/src/http/health.rs`
- Modify: `README.md` and operator docs discovered at implementation time
- Test: runtime/readiness/shutdown tests

**RED:** Cover continued targeting of expired/non-final invoices for factual reconciliation while access eligibility remains expired, degraded persistence/provider behavior, shutdown stopping new work, bounded join, and identifier-free metrics/health.

**GREEN:** Reuse existing observer/outbox worker ownership. Do not create a hot-loop drain poller when state can be updated transactionally/through existing workers.

**Suggested commit:** `docs: document Locks payment draining`

## Cross-repository implementation/review order

Locks creator-visible graceful-deletion failure codes use the closed stable vocabulary `tombstone_missing`, `tombstone_replaced`, `retry_exhausted`, and `state_corrupt`. Paykit exposes none of these codes; this synchronized note fixes the cross-repository status contract without changing Paykit routes.

1. Commit synchronized plan-only changes separately.
2. Locks implements and reviews core `payment_in` schema.
3. Paykit Server updates pinned Locks Core revision and implements Tasks 1–3.
4. Patch both plans with exact per-Bundle enums, aggregate drain response, and drain-cleanup route.
5. Paykit Server implements Tasks 4–7 and passes local E2E.
6. Locks implements its timestamp persistence, drain client, deletion worker, and credential lifecycle.
7. Run cross-service acceptance with exact reviewed revisions.
8. Align docs and demos.

## Verification

Repository-local final verification:

```bash
cargo fmt --all
cargo test -p paykit-server
cargo test -p paykit-server-e2e
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
git diff --check
```

Database-backed tests must run against the real PostgreSQL service role and migrations. Do not claim broad green from `cargo check` or unit-only tests.

Cross-service acceptance must prove:

- invoice request/canonical lock `payment_in` equality;
- timestamp checked addition and exact replay;
- separate proposal expiry and payment deadline with strict ordering;
- deployment-configured one-hour/24-hour defaults and immutable replay bindings;
- inclusive durable first amount-matched-observation cutoff;
- continued late/underpaid factual reconciliation without automatic access;
- local atomic acceptance/cancellation snapshot and delayed-acceptance loss;
- durable enqueue without delivery wait;
- no `minimum_confirmations` in Paykit drain;
- orthogonal per-Bundle lifecycle/payment response;
- aggregate drain redaction;
- operational drain cleanup retaining financial history;
- fresh same-ID graceful republication not polluted by old messages.

## Remaining implementation-contract gates

None for Tasks 1–7.


## Out of scope

- New Paykit `payment_due_at` protocol field.
- New accepted-expiry Payment Request event.
- Redefining `proposal_expires_at` after acceptance.
- Paykit ownership of Locks `minimum_confirmations` or entitlement.
- Automatic refunds, wallet payments, or late-payment access.
- Deleting terminal invoices/payment history during graceful cleanup.
- Direct non-BDK Electrum scanning.
- Cross-system atomicity or exactly-once encrypted-message delivery.
- Historical production-data migration.
