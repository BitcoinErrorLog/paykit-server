# Production-Ready Prototype Mitigation Plan

> **For Hermes:** Execute this follow-on plan one task at a time. Use RED → GREEN → refactor for behavioral changes, run the scoped and full verification listed for each task, then stop for user review and commit before continuing.

**Goal:** Turn the existing tested Paykit Server modules into a deployable single-process receiver prototype that supports multiple isolated Creator accounts and completes the documented setup → invoice → Paykit handoff → Bitcoin observation → status workflow.

**Architecture:** Keep one explicit server composition root, PostgreSQL as the only production state authority, one BIP84 account xpub/account index and one SDK state per Creator, fenced at-least-once outbox work, and direct invoice-specific Bitcoin observation. Prefer narrow corrections and deletion over generalized frameworks. Unsupported edge cases are acceptable only when documented and fail safely.

**Tech stack:** Rust 2024/MSRV 1.91.1, Tokio, Axum, SQLx/PostgreSQL, XChaCha20-Poly1305, HKDF-SHA256, Ed25519, pinned `paykit-sdk`/`paykit-lib`, Bitcoin 0.32, and pinned `electrum-client` 0.25.

---

## Status and authority

This plan follows the implementation review at HEAD `ea19f10`. It supplements:

- `0001-receiver-only-prototype-design.md`, which remains the product/security contract;
- `0002-receiver-only-prototype-implementation.md`, which records the original implementation sequence.

Where `0002` marks an isolated seam implemented but this plan identifies missing executable composition or recovery, this plan defines the remaining work and release gate. Do not reintroduce removed payer inbox, proof-event intake, or payload-retention work.

## Supported production-prototype scope

- Exactly one running Paykit Server process.
- PostgreSQL is the only production persistence backend.
- One deployment supports multiple independent Creator accounts.
- Each Creator owns exactly one authenticated authority, BIP84 account xpub/account index, receiver Noise key, derivation counter, and Paykit SDK state.
- Setup and SDK-state mutation are serialized per Creator; different Creators may proceed concurrently within global capacity limits.
- Every invoice receives an address identified by `(creator, reader, bundle_id)`.
- Different Creators may allocate the same numeric child index from different xpubs; addresses and state must never cross Creator boundaries.
- One direct Bitcoin output must equal the invoice amount exactly (W1.1b, design §B.8.2); overpayment and underpayment are both factual mismatches routed to manual review and are not accumulated.
- Amount-matched observations freeze at one confirmation and finalize at six.
- Paykit delivery is at least once; the documented ambiguous handoff window may produce duplicate Payment Requests.
- Restart recovery and bounded shutdown are supported.

## Explicitly deferred

- Multiple server processes, active-active replicas, or distributed leadership.
- Multiple xpubs/account indexes within one Creator, xpub rotation, or per-Creator Bitcoin networks.
- Exactly-once SDK delivery or deduplication beyond the public SDK contract.
- Payer Acceptance, Rejection, Cancellation, Payment Proof, or receipt processing.
- Server retention/pruning and SDK-state compaction.
- Multi-output aggregation, underpayment accumulation, refunds, or overpayment credits.
- Electrum failover pools and uncommon reorg handling after six-confirmation finality.
- Master-key rotation, dynamic config reload, zero-downtime migration orchestration, and per-Creator health enumeration.
- Broad module reorganization or generic dependency-injection/worker frameworks.

---

## Phase 0 — Lock executable adapter contracts

### Mitigation Task 0: Inspect and record Paykit SDK and Electrum runtime contracts

**Objective:** Prove that concrete runtime adapters can be built without inventing private protocols.

**Files:**
- Modify: `docs/plans/0003-production-ready-prototype-mitigation.md`
- Modify if the accepted behavior changes: `docs/plans/0001-receiver-only-prototype-design.md`
- Inspect: pinned `paykit-sdk`, `paykit-lib`, and Electrum dependency APIs

**Steps:**
1. Record the public API used for receiver-marker discovery/publication, Payment Request proposal, durable SDK-state load/save, local handoff, and any observable remote-delivery status.
2. Record the public Electrum API used to monitor an address, canonicalize outpoints, detect presence, and obtain confirmations.
3. Decide the terminal outbox state from evidence:
   - if the SDK exposes remote-delivery reconciliation, retain `handed_off → delivered`;
   - if only durable local enqueue is observable, make `handed_off` terminal and gate dependent work on that state.
4. Record which stable IDs callers can supply. If SDK event IDs are generated internally, retain stable server outbox ID and Payment Reference and explicitly permit new SDK event IDs after an ambiguous retry.
5. Treat inability to construct either concrete adapter as a release blocker; do not substitute a fake adapter in the executable.

**Acceptance:** The plan names the exact supported APIs and no delivery/readiness claim depends on an unobservable state.

#### Task 0 inspected dependency contract (revision `81fd0e5124aac1fd782811fd968109a5972cd323`)

The lockfile resolves both `paykit-lib` and `paykit-sdk` to `0.1.0-rc37` at the pinned revision. The paths below are source paths within that revision; they describe dependency constraints, not new product behavior.

**Receiver Marker discovery and publication**

- `paykit-sdk/src/runtime/public_endpoints.rs` exposes
  `PaykitSdk::paykit_receiver_paths(PubkyPublicKey)`,
  `PaykitSdk::paykit_receiver_marker(PubkyPublicKey, PaykitReceiverPath)`, and
  `PaykitSdk::publish_paykit_receiver_marker(PaykitReceiverCapabilities)`.
  Publication derives the marker Noise public key from the live
  `PubkySessionAccess.receiver_noise_secret_key` and publishes at the configured
  local receiver path.
- The corresponding lower-level public functions are
  `paykit_lib::list_paykit_receiver_paths`,
  `paykit_lib::get_paykit_receiver_marker`, and
  `paykit_lib::publish_paykit_receiver_marker`, defined in
  `paykit-lib/src/payment_endpoint.rs` and
  `paykit-lib/src/receiver_marker.rs`. They require a
  `pubky::PublicStorage` for discovery/read-back and an authenticated
  `pubky::PubkySession` for publication. `PaykitReceiverMarker` contains the
  exact receiver path, capabilities, and receiver Noise public key.

**Private endpoint and Payment Request handoff**

- The invoice-specific private endpoint can be supplied as a public
  `paykit_sdk::ReceivingDetail { identifier, payload }` to
  `PaykitSdk::enqueue_private_payment_list_with_receiving_details` in
  `paykit-sdk/src/runtime/private_lists.rs`. This queues a complete Latest-State
  Private Payment List and returns an `OutboundPrivateMessageRecord` with an
  SDK-assigned `outbound_message_id` and local status. The reservation variant
  additionally accepts `PaymentEndpointReservation.reservation_id`, but the
  explicit receiving-details API does not accept a message or event ID.
- `PaykitSdk::propose_payment_request` in
  `paykit-sdk/src/runtime/payment_requests.rs` is the supported proposal API. It
  accepts counterparty, counterparty receiver path, and
  `paykit_lib::PaymentRequestTerms`, then internally creates both
  `EventId::new_v4()` and `PaymentRequestId::new_v4()`. It returns a
  `PaymentRequestRecord` containing `payment_request_id`,
  `proposal_event_id`, `proposal_outbound_message_id`, and
  `proposal_outbound_status`. Its rustdoc explicitly says this return value is
  local outbound-queue state, not delivery or counterparty processing. Although
  `paykit_lib::PaymentRequest::new(EventId, PaymentRequestId, terms)` is public,
  the SDK raw-enqueue method that accepts that value is `pub(crate)`; the server
  therefore must not claim caller-supplied protocol IDs through the public SDK.

**Durable SDK state and production construction boundary**

- `paykit-sdk/src/storage/mod.rs` exposes `StorageAdapter::transaction_erased`
  and the synchronous `StorageTransaction` contract. The latter exposes
  `export_storage_state`, all queue/link record operations, monotonic ID
  allocation, FIFO/latest-state ordering, and lease-aware writes.
  `paykit_sdk::storage::StorageState` in `storage/records.rs` is public,
  `Clone + Default + Serialize + Deserialize`, and contains identity, link,
  outbound queue, private-stream, dedupe, and counter state. A production
  per-Creator PostgreSQL adapter can therefore lock and decrypt one Creator's
  complete state, run the callback with
  `paykit_sdk::storage::run_storage_state_transaction`, then serialize, encrypt,
  and save the resulting complete state in the same database transaction.
- Runtime construction is `PaykitSdk::new(storage, pubky, payment, config)` in
  `paykit-sdk/src/runtime/mod.rs`. The other required public boundaries are
  `PubkySessionProvider` and `PaymentAdapter` in
  `paykit-sdk/src/domain/adapters/mod.rs`. The SDK supplies no bundled
  production PostgreSQL, Creator-session, or server payment adapter; those
  concrete implementations and their executable composition remain required
  Paykit Server work. The APIs are sufficient to implement them without a
  private Paykit wire protocol, but definitions and test fakes alone are not a
  supported executable adapter.

**Observable send result and terminal outbox decision**

- `PaykitSdk::process_outbound_private_messages(counterparty, receiver_path)`
  and `PaykitSdk::process_pending_private_messages()` in
  `paykit-sdk/src/runtime/outbound_private.rs` perform the actual Encrypted-Link
  send. `OutboundPrivateSendReport.sent` identifies successful sends by the
  exact SDK `outbound_message_id`; the SDK atomically stores
  `OutboundPrivateMessageStatus::Sent`, `sent_at`, and the advanced Encrypted
  Link snapshot before placing that ID in the report. For Payment Requests,
  `PaymentRequestRecord.proposal_outbound_message_id` and
  `proposal_outbound_status` expose the same attributable local record.
- Therefore this plan **retains `handed_off -> delivered`**. `handed_off` means
  that the public enqueue/proposal call completed and the server durably stored
  the returned SDK IDs. `delivered` means that the exact stored SDK outbound ID
  is present in `OutboundPrivateSendReport.sent` or its durable SDK record has
  status `Sent`. Dependent Payment Request work may gate on endpoint
  `delivered`. Here `delivered` is limited to the SDK's successful remote
  Encrypted-Link send; it does not claim payer application read, processing, or
  acknowledgement.
- If the process dies after SDK enqueue commits but before the server stores the
  returned IDs, the public SDK has no proposal method accepting server IDs and
  no exact server-intent lookup. The reclaimed server row invokes the public API
  again and may create a new SDK outbound message, Event ID, and Payment Request
  ID. This is the accepted at-least-once duplicate window, not idempotence.
  Across that window the only unconditional stable correlation values are the
  server outbox intent ID and the caller-supplied `PaymentReference` inside
  `PaymentRequestTerms`; SDK-generated IDs are persisted only after a successful
  attributable handoff.

**Electrum and outpoint contract — release blocker**

- The workspace `Cargo.toml` and `Cargo.lock` contain no Electrum, BDK Electrum,
  or Esplora dependency. `cargo tree --workspace --edges normal` likewise has no
  such runtime crate. Consequently there is no pinned public API with which to
  subscribe to or poll an address, enumerate its outputs, determine whether a
  previously observed output is still present, or obtain its confirmation
  count.
- The current `paykit-server/src/workers/observer.rs::ElectrumPort` is only an
  injected application/test seam returning `Vec<ObservedOutput>`; there is no
  production implementation or construction path. It is not evidence of an
  Electrum protocol contract and must not be used as a fake executable adapter.
- The existing `bitcoin = 0.32.101` dependency does provide
  `bitcoin::OutPoint`, `OutPoint::new(Txid, u32)`, strict
  `FromStr<Err = ParseOutPointError>`, and canonical `Display` as
  `<txid>:<vout>` (`bitcoin/src/blockdata/transaction.rs`). This is sufficient
  to canonicalize an outpoint after a provider returns a transaction ID and
  output index, but it provides no chain observation, presence, or confirmation
  API.
- Selecting an Electrum crate/client or defining a custom wire protocol is out
  of scope for Task 0. Task 7A owns selecting, pinning, inspecting, and
  implementing one supported client/adapter before observation composition,
  acceptance testing, or the live release gate can complete. Until Task 7A
  passes, the production-ready prototype is **release-blocked**.

Task 0 changes no source behavior. It confirms a public construction path for a
concrete Paykit adapter, records that executable Paykit composition is still
absent, and records the missing Electrum dependency as a release blocker.

**Verification:**
```bash
cargo check --workspace
cargo doc --workspace --all-features --no-deps
git diff --check
```

**Suggested commit:** `docs: lock Paykit runtime adapter contracts`

---

## Phase 1 — Fail-closed startup and Creator setup

### Mitigation Task 1: Authenticate every Creator and SDK state before bind

**Objective:** Prevent a syntactically valid wrong key or corrupt Creator state from producing a ready process.

**Files:**
- Modify: `paykit-server/src/main.rs`
- Modify: `paykit-server/src/persistence/creators.rs`
- Test: `paykit-server-e2e/tests/creator_state.rs`

**RED tests:**
- Correct key authenticates two Creators with different xpub/account pairs and SDK states.
- Wrong but correctly shaped master key aborts startup.
- Corrupt Creator credentials or SDK state aborts startup.
- Swapping an encrypted envelope between Creators fails authentication.
- Failure occurs before the HTTP listener is considered ready.

**Implementation:**
- Construct `Crypto` and `CreatorStore` after migration/deployment-invariant validation.
- Run `CreatorStore::scan_integrity()` before binding.
- Validate every persisted Creator independently; one invalid Creator aborts boot for this prototype.
- Keep startup errors and logs free of Creator identity, xpub, state, ciphertext, and database URL.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test creator_state
cargo test --workspace --no-run
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Suggested commit:** `fix: authenticate persisted Creator state at startup`

### Mitigation Task 2: Validate and isolate multi-Creator Bitkit setup

**Objective:** Persist only usable BIP84 account claims and prevent cross-Creator state mutation.

**Files:**
- Modify: `paykit-server/src/real_setup.rs`
- Modify: `paykit-server/src/setup.rs`
- Test: `paykit-server/tests/setup.rs`
- Test: `paykit-server-e2e/tests/creator_state.rs`

**RED tests:**
- Reject xpub with wrong network, depth, or hardened child number for the claimed `account_index`.
- Reject an account xpub from which external-chain/address derivation fails.
- Setup for Creator A cannot replace or read Creator B's xpub, account index, Noise key, derivation counter, or SDK state.
- Concurrent setup for the same Creator is serialized.
- Setup for two different Creators can complete independently.
- Published marker advertises `receipts: false`.

**Implementation:**
- Validate BIP84 account depth and hardened account child before marker publication or persistence.
- Use authenticated Creator Pubky as the ownership boundary.
- Preserve existing same-Creator xpub/account immutability on reauthentication.
- Publish/read back the marker before durable success.
- Do not introduce a deployment-wide xpub or SDK runtime fallback.

**Verification:**
```bash
cargo test -p paykit-server --test setup
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test creator_state
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested commit:** `fix: validate and isolate Creator account setup`

### Mitigation Task 3: Bound setup and signed-request admission

**Objective:** Prevent unauthenticated quota starvation and unbounded secret-bearing setup flows.

**Files:**
- Modify: `paykit-server/src/http/auth.rs`
- Modify: `paykit-server/src/http/error.rs`
- Modify: `paykit-server/src/http/setup.rs`
- Modify: `paykit-server/src/runtime.rs`
- Modify: `paykit-server/src/setup.rs`
- Modify: `paykit-server/src/config.rs`
- Test: `paykit-server/tests/locks_auth.rs`
- Test: `paykit-server/tests/setup.rs`
- Test: `paykit-server/tests/config.rs`

**RED tests:**
- Unsigned/invalid requests do not consume the trusted signed-caller policy bucket.
- Coarse pre-auth capacity still bounds signature-verification work.
- Pending setup reservations never exceed `max_pending_setup_flows`, including concurrent starts.
- Setup rate limiting uses transport peer IP and ignores `X-Forwarded-For`.
- Reservations release on start failure, terminal completion, expiry, and cancellation.
- Sub-second lease/retry durations are rejected instead of truncating to zero.

**Implementation:**
- Apply coarse transport/capacity protection before authentication and charge the signed policy bucket only after signature verification.
- Reserve global setup capacity before external AUTH start.
- Treat failures before consuming the one-shot attempt as `429`/`503`; post-consumption completion failure is terminal `422`, requiring a new flow.
- Preserve raw-body size enforcement before JSON deserialization.

**Implemented evidence:**
- The runtime's existing outer request semaphore rejects exhausted capacity with
  `503` and `Retry-After: 1` before signed-request extraction or signature work.
- The trusted signed-caller bucket is charged only after body-size enforcement,
  signature verification, canonical JSON validation, and closed-schema
  deserialization. Policy rejection is `429` with `Retry-After`.
- Setup admission uses Axum transport `ConnectInfo<SocketAddr>` and ignores
  forwarding headers. The production serve path supplies this transport
  metadata.
- A process-local semaphore reserves `max_pending_setup_flows` capacity before
  external AUTH start. RAII ownership releases reservations after start error,
  terminal success or failure, expiry, canceled start, and canceled completion;
  canceled post-consumption completion also marks the flow terminal failed.
- The per-transport-IP setup window is pruned after one minute and returns
  `429` with `Retry-After`; global setup exhaustion and pre-consumption adapter
  failure return `503` with `Retry-After: 1`.
- Persistence lease/retry durations below one second are rejected before their
  later whole-second PostgreSQL conversion can truncate them to zero.

**Verification:**
```bash
cargo test -p paykit-server --test locks_auth
cargo test -p paykit-server --test setup
cargo test -p paykit-server --test config
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested commit:** `fix: bound setup and signed request admission`

---

## Phase 2 — Make durable Paykit delivery executable

### Mitigation Task 4: Persist one complete versioned delivery intent

**Objective:** Ensure every outbox row created by `POST /invoices` contains all data required for replay and SDK handoff.

**Files:**
- Modify: `paykit-server/src/application/create_invoice.rs`
- Modify: `paykit-server/src/application/semantic_intent.rs`
- Modify: `paykit-server/src/application/reader_marker.rs`
- Modify: `paykit-server/src/persistence/invoices.rs`
- Modify: `paykit-server/src/persistence/outbox.rs`
- Add/modify migration under: `paykit-server/migrations/`
- Test: `paykit-server/tests/create_invoice.rs`
- Test: `paykit-server-e2e/tests/invoices.rs`
- Create or modify: `paykit-server-e2e/tests/outbox.rs`

**RED tests:**
- New invoice discovers/selects one capable marker and durably pins path plus marker fingerprint.
- Invoice success commits invoice-specific allocation, endpoint intent,
  Payment Request server semantic intent, and dependency with complete
  encrypted inputs needed for later public-SDK calls; it does not claim the
  final SDK event or wire payload already exists.
- No claimable row can have a missing semantic intent.
- Exact replay always preserves invoice, address, server outbox IDs, Payment
  Reference, selected path, and marker fingerprint. It preserves SDK-generated
  IDs only when a prior successful enqueue already returned and durably
  associated them with the fenced server row; replay in the pre-association
  crash window may produce new SDK IDs under the accepted at-least-once model.
- Changed replay binding conflicts without replacing durable intent.
- Concurrent invoices for two Creators may allocate the same numeric child index but produce distinct addresses and intents owned by the correct Creator.

**Implementation:**
- Replace the opaque-payload plus optional-semantic-envelope ambiguity with one closed versioned intent representation for endpoint publication and Payment Request proposal.
- Perform marker discovery before the PostgreSQL transaction; persist the selected path/fingerprint with the intent.
- Keep invoice/allocation/outbox insertion atomic where already supported.
- Bind every intent to its internal Creator owner and encrypted Creator context.
- Preserve at-least-once semantics; do not claim exactly-once delivery.

**Implemented:**
- `DeliveryIntentV1` is the single closed representation for endpoint publication
  and Payment Request proposal inputs. It contains no SDK-generated IDs or final
  wire payloads and revalidates canonical values after authenticated decoding.
- Marker discovery precedes the atomic invoice operation; both intents pin the
  selected reader path and the exact canonical marker fingerprint.
- Invoice allocation, reader assignment, endpoint intent, Payment Request intent,
  and dependency insertion commit in one PostgreSQL transaction. Exact replay is
  a separate side-effect-free persistence operation and preserves the original
  allocation and server IDs.
- Replay lookup is scoped by canonical Creator plus bundle identity; the full
  canonical request remains the immutable payment binding, so changed reader or
  lock-resource bindings conflict instead of creating another bundle row.
- The repository revalidates intent structure, operation role, and exact reader
  ownership before the first insert. The shared 15-second budget fences
  preflight, replay, session, lock, marker, and credential work and is checked
  before mutation begins; an entered PostgreSQL transaction is then awaited to
  a factual commit or rollback outcome rather than canceled at the deadline.
- The pre-production baseline contains one non-null `intent_envelope` and one
  current validated Intent codec. Earlier prototype envelopes are intentionally
  unsupported; operators reset the database instead of running compatibility
  readers or row-repair migrations.
- Intents use Creator- and row-bound AEAD context, redact encrypted business
  values from `Debug`, and reject invalid authenticated state without panicking.
- PostgreSQL coverage proves rollback atomicity, replay/conflict behavior,
  current-codec claim/decode, durable intent preservation on replay, dependency
  ordering, and concurrent Creator allocations at the same numeric child index
  with distinct addresses and correctly bound intents.
- The accepted Locks policy API is pinned to revision `06bc63c4` rather than a
  mutable absolute checkout; repository Cargo configuration uses the Git CLI for
  authenticated SSH fetching.

**Verification:**
```bash
cargo test -p paykit-server --test create_invoice
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test invoices
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test outbox
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Suggested commit:** `refactor: persist executable Paykit delivery intents`

### Mitigation Task 5: Complete fenced handoff and terminal-state recovery

**Objective:** Make endpoint publication reach the supported terminal state and unblock its dependent Payment Request.

**Files:**
- Create: `paykit-server/src/paykit.rs`
- Modify: `paykit-server/src/persistence/sdk_state.rs`
- Modify: `paykit-server/src/workers/outbox.rs`
- Modify: `paykit-server/src/persistence/outbox.rs`
- Add a forward migration for attributable SDK outbound IDs under: `paykit-server/migrations/`
- Test: `paykit-server/tests/outbox.rs`
- Test: `paykit-server-e2e/tests/outbox.rs`
- Test: `paykit-server-e2e/tests/migrations.rs`
- Modify: `docs/task12-outbox-recovery.md`

**RED tests:**
- Endpoint intent handoff reaches the Task-0-supported terminal state.
- Dependent Payment Request is unclaimable before endpoint terminal success and claimable afterward.
- A stale lease/fence cannot overwrite reclaimed work.
- Crash after SDK durable enqueue but before PostgreSQL transition recovers according to documented at-least-once behavior.
- Marker fingerprint mismatch never causes silent path reselection.
- Retryable failure remains queued with bounded backoff; corrupt/version-invalid intent becomes retained permanent failure.
- Rows for two Creators mutate only their owning SDK states and may progress concurrently.
- A successful enqueue/proposal stores the returned SDK outbound ID under the
  same fence as `handed_off`; Payment Requests also store returned SDK Event and
  Payment Request IDs.
- Reconciliation marks only that exact SDK outbound ID `delivered` after its
  durable SDK status is `Sent`; recipient application acknowledgement is not
  claimed.
- SDK `Failed` remains retryable; `Invalid` and `Superseded` are retained as
  permanent failures; `RecoveryRequired` remains recoverable without claiming
  delivery.
- The baseline CHECK constraints reject terminal rows without a canonical
  attributable SDK outbound ID and reject unpaired Payment Request identifiers.

**Implementation:**
- Implement one per-Creator encrypted PostgreSQL `StorageAdapter` using
  `StorageAdapter::transaction_erased` and
  `run_storage_state_transaction`; the row lock, callback result, encrypted
  replacement, and commit/rollback must form one database transaction.
- Implement the concrete Creator `PubkySessionProvider` and the minimal server
  `PaymentAdapter` required to construct `PaykitSdk`; unsupported adapter
  methods must fail explicitly and must not implement private Paykit behavior.
- Return and persist the public enqueue/proposal result needed to attribute SDK
  outbound state. Preserve the accepted duplicate window if the SDK transaction
  commits before the fenced server transition.
- Retain fenced claim ownership for every state-changing transition.
- Add a separately fenced reconciliation claim for `handed_off` rows and mark
  `delivered` only when the stored SDK outbound ID is durably `Sent`.
- Serialize SDK transactions per Creator, not globally.

**Verification:**
```bash
cargo test -p paykit-server --test outbox
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test outbox
cargo test --workspace --no-run
```

**Suggested commit:** `feat: recover durable Paykit handoff`

---

## Phase 3 — Restore Bitcoin persistence privacy and observation safety

### Mitigation Task 6: Encrypt invoice allocation and observation values

**Objective:** Restore the accepted encrypted-at-rest boundary without weakening equality lookup or outpoint uniqueness.

**Files:**
- Add forward migrations under: `paykit-server/migrations/`
- Modify: `paykit-server/src/crypto.rs`
- Modify: `paykit-server/src/persistence/invoices.rs`
- Test: `paykit-server-e2e/tests/invoices.rs`
- Test: `paykit-server-e2e/tests/payment_observation.rs`

**RED tests:**
- Raw database rows do not contain fixture Bitcoin addresses, derivation indexes, required/observed amounts, or canonical outpoints.
- Domain-separated keyed address lookup resolves exactly one invoice.
- Domain-separated keyed outpoint lookup remains globally unique across Creators and invoices.
- Same numeric derivation index is valid under different Creators.
- Wrong Creator/type/row AAD fails decryption.
- A fresh baseline creates only non-null encrypted/hash Bitcoin columns.

**Implementation:**
- Encrypt canonical address, derivation index, required amount, outpoint, and observed amount in row-bound versioned envelopes.
- Retain only domain-separated keyed hashes needed for address lookup and global outpoint uniqueness, plus operational state/count/timestamps.
- The pre-production baseline creates only encrypted/hash columns. Earlier
  plaintext prototypes are intentionally unsupported and require a database reset.
- Preserve `(creator_id, derivation_index)` uniqueness and deployment-wide derived-address uniqueness.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test invoices
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test payment_observation
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test migrations
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Suggested commit:** `feat: encrypt Bitcoin payment records`

The reset-only baseline creates encrypted/hash columns directly; there is no
additive backfill or destructive follow-up migration.

### Mitigation Task 7A: Select and implement one concrete Electrum adapter

**Objective:** Replace the injected-only observation seam with one pinned,
inspectable production client without implementing a private Electrum protocol.

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `paykit-server/Cargo.toml`
- Modify: `paykit-server/src/bitcoin.rs`
- Modify: `paykit-server/src/workers/observer.rs`
- Create: `paykit-server/tests/electrum_adapter.rs`

**Steps:**
1. Inspect current maintained Electrum client candidates and pin one exact
   dependency whose public API supports the configured endpoint/network,
   address or script history, transaction/output identity, current chain tip,
   and transaction confirmation or absence checks.
2. Record the selected crate/version and exact symbols in this plan before
   writing the adapter. Reject a candidate that requires custom wire calls for
   the supported path.
   - **Selected and re-verified 2026-07-22, superseded:** the adapter now
     uses `electrum-client = 0.25.0` directly (the `bdk_electrum = 0.24.0`
     wrapper this bullet originally selected was removed); its
     `bitcoin = "0.32"` types unify with this workspace's exact
     `bitcoin = "=0.32.101"` pin.
   - **Construction/config symbols:** `BdkElectrumClient::new`, the re-exported
     `Client::from_config`, and `ConfigBuilder::{new, timeout, retry, build}`.
     Superseded 2026-09-09: the adapter constructs `electrum-client 0.25`'s
     `raw_client::RawClient` directly over the byte-capped transport (no
     `bdk_electrum` wrapper, no `ConfigBuilder::retry` — call retries are
     pinned at zero); see `paykit-server/src/workers/electrum.rs`.
   - **Observation symbols:** `bdk_core::spk_client::SyncRequest`,
     `BdkElectrumClient::sync`, `SyncResponse::{chain_update, tx_update}`,
     `TxUpdate::{txs, anchors, seen_ats, evicted_ats}`, and
     `ConfirmationBlockTime::block_id`.
   - BDK owns script-history batching, transaction retrieval/cache, chain-tip
     agreement, confirmation anchors, and expected-transaction eviction. The
     adapter supplies the configured-network genesis checkpoint and known
     invoice scripts/outpoints, then translates the typed sync response into
     application observations. It does not implement private/custom Electrum
     calls or introduce descriptor-wallet/spending-key custody.
   - Endpoint/client failures are retryable `Unavailable` outcomes and the next
     configured poll retries. The selected client performs finite reconnect
     attempts from its retained URL/config. A positive history height above the
     returned tip is an inconsistent/stale batch and is retryable rather than
     persisted. No wall-clock tip-age threshold is introduced because none is
     accepted. A tracked pre-final outpoint missing from script history is
     emitted as factual absence so existing reorg/replacement rules can regress
     it before finality.
3. Implement the concrete adapter behind `ElectrumPort`; do not expose client
   types above the adapter boundary.
4. Canonicalize provider transaction identity as typed `bitcoin::OutPoint`
   before producing application observations.
5. Define explicit retryable behavior for endpoint outage, reconnect, stale tip,
   and a previously observed transaction disappearing before finality. Reject a
   network mismatch before emitting any observations.
6. Prove the adapter against a deterministic protocol-compatible test server or
   regtest Electrum service. A fake `ElectrumPort` remains useful for composed
   application tests but does not satisfy this task.

**Acceptance:** The production binary can construct one configured Electrum
adapter from public APIs, and focused integration evidence covers output
identity, presence/absence, confirmations, network mismatch, and reconnect.

**Verification:**
```bash
cargo test -p paykit-server --test electrum_adapter
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

**Suggested commit:** `feat: add concrete Electrum observation adapter`

Stop for review before changing observation persistence semantics.

### Mitigation Task 7B: Validate observation batches before persistence

**Objective:** Keep the supported one-output payment policy factual and free of partial invalid-batch effects.

**Files:**
- Modify: `paykit-server/src/bitcoin.rs`
- Modify: `paykit-server/src/workers/observer.rs`
- Modify: `paykit-server/src/persistence/invoices.rs`
- Test: `paykit-server/tests/bitcoin_observer.rs`
- Test: `paykit-server-e2e/tests/payment_observation.rs`

**RED tests:**
- Wrong-network or malformed output anywhere in a fetched batch causes no database write from that batch.
- Canonical typed outpoint is required before persistence.
- One outpoint cannot bind to two invoices, including across Creators.
- Zero-confirmation amount-matched replacement, one-confirmation freeze, pre-final regression, and six-confirmation finality retain existing behavior.
- Underpayment remains factual and replaceable; multiple outputs are not accumulated.

**Implementation:**
- Parse and validate the complete fetched batch before repository calls.
- Keep one-output settlement semantics and configured-network enforcement.
- Document unsupported split payments and uncommon post-finality reorgs; do not implement aggregation or generalized chain repair.
- **Implemented 2026-07-22:** `workers::observer::validate_batch` validates
  configured network, canonical network-valid address text, storage-representable
  confirmations, absence-state consistency, and unique typed outpoints before
  one atomic `InvoiceStore::apply_bitcoin_observation_batch` call. Repository
  observation inputs require `domain::payment::BitcoinOutpoint`; string
  materialization is an internal encrypted-persistence detail. PostgreSQL E2E coverage proves late
  wrong-network, malformed-address, and unrepresentable-confirmation outputs
  and late persistence conflicts cause zero batch writes, and that separate
  underpayments are not accumulated.

**Verification:**
```bash
cargo test -p paykit-server --test bitcoin_observer
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test payment_observation
```

**Suggested commit:** `fix: validate Bitcoin observations before persistence`

Stop for review before simplifying the completed BDK observation slice.

### Mitigation Task 7C: Simplify the BDK/Electrum observation slice

**Objective:** Remove proven duplication and accidental complexity introduced by
Tasks 7A–7B before the adapter is wired into the production composition root,
without weakening validation, persistence atomicity, or payment semantics.

**Review scope:**
- Commit range: `a16f41e..c4ea192` (the Task 7A and 7B commits).
- Primary production files:
  - `paykit-server/src/bitcoin.rs`
  - `paykit-server/src/workers/observer.rs`
  - `paykit-server/src/domain/payment.rs`
  - `paykit-server/src/persistence/invoices.rs`
- Primary tests and documentation:
  - `paykit-server/tests/bitcoin_observer.rs`
  - `paykit-server/tests/electrum_adapter.rs`
  - `paykit-server-e2e/tests/payment_observation.rs`
  - `paykit-server-e2e/tests/migrations.rs`
  - `README.md`
  - this plan
- Modify only files justified by an accepted finding. Do not turn this into a
  repository-wide refactor.

**Baseline:**
1. Capture `git diff a16f41e..c4ea192` and run the focused Task 7 tests before
   editing.
2. Use the `simplify-code` workflow to launch three parallel, read-only reviews
   over the complete Task 7 diff:
   - reuse: identify custom code already supplied by BDK or an existing local
     type/helper;
   - quality: identify redundant state, copy-paste validation/test setup,
     leaky abstractions, and unnecessary conversion layers;
   - efficiency: identify repeated parsing/index construction, redundant BDK
     response processing, avoidable allocation, or blocking-path overhead.
3. Require each finding to name the existing replacement or concrete smaller
   structure, include `path:line` evidence, and classify risk as safe, careful,
   or risky. Apply Chesterton's Fence before removing pre-existing behavior.

**Simplification constraints:**
- Preserve the public `ElectrumPort`, `ObservationTarget`, `ObservedOutput`,
  `TrackedOutput`, and persisted-state contracts unless a separate reviewed
  breaking change is approved.
- Keep `electrum-client` 0.25 as the maintained Electrum transport (the
  `bdk_electrum` abstraction was removed). Do not reintroduce
  direct Electrum history/transaction scanning, custom wire calls, or a
  descriptor wallet/spending-key dependency.
- Do not blindly merge adapter parsing with `validate_batch`: provider output
  remains untrusted, so validation at the application/persistence boundary must
  remain independently enforceable.
- Preserve configured-network genesis agreement, transaction-identity checks,
  factual pre-final absence, canonical address and typed-outpoint validation,
  unique outpoints, deterministic batch ordering, and one-transaction batch
  persistence.
- Preserve one-output settlement, replacement/freeze/regression/six-confirmation
  behavior, non-accumulated underpayments, encrypted persistence, keyed lookup,
  global cross-Creator uniqueness, and redacted diagnostics.
- Apply safe findings first and careful findings one focused edit at a time.
  Record risky findings for manual review; do not implement them in this task.
- Prefer deleting code or reusing an existing type/helper over introducing a
  new generic abstraction. No speculative caching, wallet state, or generalized
  chain-repair framework.

**Implemented 2026-07-22:**
- Three parallel read-only reviews covered reuse, quality, and efficiency over
  `a16f41e..c4ea192`.
- Accepted simplifications reuse one configured-network conversion, share
  address/network parsing mechanics while retaining independent batch
  validation, combine BDK reported-transaction membership and confirmation
  indexing, deduplicate typed provider outpoints before domain-string
  allocation, return before opening an empty batch transaction, reuse checked
  persistence values, parse persisted outpoints through `bitcoin::OutPoint` while
  retaining exact canonical-text validation, and compare deterministic protocol
  script hashes through Electrum's public `ScriptHash` and
  `ToElectrumScriptHash` types.
- Baseline execution found and fixed two stale fixtures introduced by the BDK
  migration: the deterministic Electrum server now serves BDK header/Merkle
  requests, and the encrypted migration success fixture uses a canonical
  outpoint. BDK's documented non-positive-height normalization remains explicit
  in the adapter test; positive heights above the tip remain retryable.
- Risky grouped/N+1 persistence rewrites and active-row query fusion were
  rejected for this cleanup slice.

**Acceptance:**
- The accepted diff is smaller or materially easier to follow, with each edit
  traceable to a reviewer finding and no public/wire/schema behavior change.
- Focused tests prove all Task 7 safety and payment-state invariants still hold.
- Documentation names BDK abstractions accurately and contains no stale direct
  `electrum-client` implementation guidance.
- A no-change outcome is acceptable only if all three evidence-based reviews
  find no safe or careful simplification.

**Verification:**
```bash
cargo fmt --all -- --check
cargo test -p paykit-server --test electrum_adapter
cargo test -p paykit-server --test bitcoin_observer
cargo test -p paykit-server --lib
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test payment_observation
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test migrations
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

**Suggested commit:** `refactor: simplify BDK observation path`

Stop for manual review before Task 8 composition work.

---

## Phase 4 — Compose and supervise the real application

### Mitigation Task 8: Add one explicit multi-Creator server composition root

**Objective:** Make the production executable mount business routes and start the concrete workers proven in earlier phases.

**Files:**
- Create: `paykit-server/src/server.rs`
- Modify: `paykit-server/src/lib.rs`
- Modify: `paykit-server/src/main.rs`
- Modify: `paykit-server/src/config.rs`
- Modify: `paykit-server/src/http/mod.rs`
- Modify: `paykit-server/src/runtime.rs`
- Test: `paykit-server/tests/runtime.rs`
- Create or modify composed tests in: `paykit-server-e2e/tests/`

**RED tests:**
- The same constructor used by `main` mounts setup, signed invoice, signed status, health, and metrics routes.
- Startup constructs concrete setup, Paykit SDK, and Electrum adapters; missing required adapter/config fails startup rather than reporting ready.
- Outbox and observer workers start under supervision.
- Canonical lock Creator selects only its own credentials, xpub/counter, and SDK state; missing Creator has no fallback.
- Two Creators can process invoices concurrently without sharing address allocation or SDK state.

**Implementation:**
- Replace the empty `Server` placeholder with a small explicit owner of config, pool, crypto, stores, services, router, runtime state, adapters, and worker task set.
- Replace unsupported `paykit.relay_url` / `paykit.homeserver_url` keys with closed `paykit.network = "mainnet" | "testnet"` selection and construct the corresponding pinned Pubky client; do not bypass SDK-owned AUTH to force a custom relay.
- Add a closed `electrum.request_timeout` setting with accepted default `"10s"`; production construction must not use the dependency's unbounded socket-timeout default. (The originally proposed `electrum.connect_retries` was dropped: client-side call retries are pinned at zero and the observer's own next tick is the retry.)
- Add closed `outbox.batch_size` with accepted default `16` and use it for enqueue and reconciliation claims.
- Keep `main.rs` to load configuration, connect/migrate, build, and run.
- Bind encrypted Bitcoin observations to their parent invoice in AEAD associated
  data and reject parent reassignment during startup integrity scanning.
- Do not introduce a generic dependency-injection container.
- Do not mount invoice creation until durable intent production and worker terminal-state recovery are available.

**Implemented 2026-07-22:**
- Added one production `Server` composition root used by `main`, mounting setup,
  signed invoice creation, signed payment status, health, and metrics routes.
- The root owns the concrete Pubky setup services, per-claimed-Creator Paykit
  adapter construction, a lazy reconnecting BDK Electrum adapter, and one actual
  `JoinSet` containing enqueue, reconciliation, and observation workers.
- Added closed Paykit network, Electrum timeout/retry, and outbox batch settings.
  Transient Electrum endpoint outage no longer blocks startup; malformed adapter
  configuration still fails construction.
- Claimed outbox work resolves credentials and authenticated SDK state by exact
  Creator UUID with no fallback. Corrupt Creator/SDK state is permanent; storage
  unavailability remains retryable. A feature-gated local-Pubky constructor
  exercises the same private composition path in PostgreSQL E2E: the running
  production workers process two linked Creators in one claim batch, preserve
  independent child-index-zero allocation, and associate each endpoint intent
  with that Creator's distinct persisted SDK outbound counter. Focused tests
  also cover exact-ID lookup.
- Bitcoin observation envelopes authenticate their parent invoice UUID. Unit and
  PostgreSQL regression tests cover cross-Creator and same-Creator parent swaps.
- `cargo test -p paykit-server`, full PostgreSQL E2E execution against an
  ephemeral PostgreSQL 16 container, workspace Clippy with warnings denied,
  rustdoc with warnings denied, formatting, and diff hygiene pass.

**Verification:**
```bash
cargo test -p paykit-server --test runtime
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Suggested commit:** `feat: compose the Paykit Server application`

### Mitigation Task 9: Make readiness and shutdown reflect owned work

**Objective:** Report real component state and guarantee bounded process exit.

**Files:**
- Modify: `paykit-server/src/runtime.rs`
- Modify: `paykit-server/src/http/health.rs`
- Modify: `paykit-server/src/server.rs`
- Test: `paykit-server/tests/runtime.rs`
- Create: `paykit-server-e2e/tests/runtime.rs`

**RED tests:**
- Unstarted Paykit, outbox, or Electrum component is never reported ready.
- PostgreSQL failure yields `not_ready`; running but retrying delivery/Electrum yields `degraded` according to the ledger.
- One Creator's retryable delivery failure degrades aggregate health without naming or blocking other Creators.
- Request cancellation/panic cannot leak admission count.
- Shutdown marks not-ready, stops admissions and claims, drains within the configured deadline, then aborts remaining owned tasks.

**Implementation:**
- Initialize components as starting/unavailable and transition them from worker/provider evidence.
- Use an RAII request/admission guard.
- Use one cancellation signal and one owned task set; bound the complete server/worker join by `shutdown.drain_timeout`.
- Keep health and metrics identifier-free.

**Verification:**
```bash
cargo test -p paykit-server --test runtime
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test runtime
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Implementation record (2026-07-22):**
- Runtime components start `not_ready`; enqueue and reconciliation publish separate evidence, and persisted retryable/handed-off/permanent delivery work keeps aggregate Paykit delivery degraded without exposing Creator or row identifiers.
- Admission accounting is owned by an RAII guard, including semaphore ownership, so request cancellation and panic release both capacity and drain accounting.
- `Server` owns one worker `JoinSet` and one race-safe cancellation signal. Shutdown marks not-ready before cancellation, rejects admissions and claims, joins HTTP/admission/workers within `shutdown.drain_timeout`, and aborts blocked owned work at the deadline.
- PostgreSQL E2E coverage proves empty-worker startup evidence and deadline abort while an outbox claim is actually blocked on a table lock. The composed multi-Creator test proves one unreachable reader remains retryable and degrades aggregate delivery while two other Creator handoffs complete independently.
- The literal workspace test suite passed against ephemeral PostgreSQL 16; all-feature Clippy and warnings-as-errors rustdoc also passed.

**Suggested commit:** `fix: supervise workers and bounded shutdown`

---

## Phase 5 — Prove and document the supported prototype

### Mitigation Task 10: Add one composed two-Creator acceptance workflow

**Objective:** Prove the supported production path through the actual application constructor and PostgreSQL.

**Files:**
- Create: `paykit-server-e2e/tests/server_workflow.rs`
- Add test support only as needed under: `paykit-server-e2e/src/`
- Modify production code only to expose the same explicit constructor used by `main`

**Scenario:**
1. Start the application with PostgreSQL and deterministic injected transport implementations of the same Paykit/Electrum ports used by production adapters.
2. Complete or seed two valid Creators with different xpub/account pairs and SDK states.
3. Submit signed invoices for both Creators concurrently.
4. Verify both may allocate child index `0` while addresses, rows, envelopes, and SDK mutations remain distinct.
5. Verify complete endpoint and Payment Request intents, endpoint terminal success, and dependent Payment Request handoff.
6. Inject one matching Bitcoin output for each invoice and query factual status.
7. Restart with the same database and verify both Creator runtimes and pending work recover.
8. Trigger shutdown and verify no new request admission or worker claim occurs.
9. Inspect raw database fixtures and verify protected Creator, address, amount, and outpoint values are absent.

**Acceptance:** The exact supported flow works through the composed application; no test-only router or direct repository shortcut replaces the path under test.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test server_workflow -- --nocapture
TEST_DATABASE_URL=postgres://... cargo test --workspace --no-fail-fast
```

**Implementation record (2026-07-22):**
- Added `paykit-server-e2e/tests/server_workflow.rs`, which runs two independent
  Creators through signed invoice and status requests over a bound TCP listener,
  the production startup initializer, the composed production workers, controlled
  Pubky transports, and deterministic observations injected only through the
  production `ElectrumPort` worker boundary.
- The first lifecycle waits for `/health/ready`, proving the workers completed their
  initial empty polls, and then uses a long worker interval to prove both complete
  dependent intents remain queued and unclaimed through shutdown. The restart reruns
  `initialize_database`, restores both Creators from the same PostgreSQL database,
  delivers both endpoint lists and Payment Requests through the real SDK adapter,
  records distinct observations, and returns confirmed status through signed HTTP.
- The workflow decrypts the four durable intents to verify complete Creator-scoped
  inputs, proves each Creator independently allocated child index zero, checks
  distinct assignment/invoice/outbox identifiers and encrypted envelopes, and
  searches textual rows and catalog-enumerated values from every `BYTEA` column in
  the six workflow tables for prohibited Creator, reader, xpub, address, lock,
  bundle, amount, transaction, and outpoint representations, including raw public
  keys, txids, endian-specific amounts, and structured numeric amounts.
- Production construction now stores observation behind `Arc<dyn ElectrumPort>`;
  production still constructs the concrete BDK Electrum adapter, while the
  feature-gated test constructor converges immediately on the same private
  composition function.
- The composed test exposed that postcard could not deserialize non-empty
  `serde_json::Map` Payment Request metadata. The sole supported internal codec is
  version 2 and encodes metadata as a JSON string inside postcard. Unsupported
  payload versions and earlier prototype layouts fail closed; operators reset
  prototype databases rather than running compatibility readers.
- `Runtime::begin_shutdown` closes the network listener as part of the same
  cancellation path. Supported invoice/status behavior is exercised over TCP; the
  post-stop 503 admission assertion uses only the retained composed operational
  router because no post-trigger network admission window exists.
- The literal formatting, workspace check/no-run, full PostgreSQL workspace test,
  Clippy, rustdoc, and diff-hygiene chain passes.

**Suggested commit:** `test: verify the multi-Creator receiver workflow`

### Mitigation Task 11: Perform live adapter smoke tests and finalize operator docs

**Objective:** Bound interoperability claims to exercised behavior and document every accepted prototype limitation.

**Files:**
- Modify: `README.md`
- Modify: `config/paykit-server.example.toml`
- Modify: `docs/plans/0001-receiver-only-prototype-design.md`
- Modify: `docs/plans/0002-receiver-only-prototype-implementation.md`
- Modify: this plan's status table
- Add a live-smoke runbook under `docs/` if needed

**Steps:**
1. Exercise marker publication/discovery and Payment Request enqueue against one supported live Paykit relay/homeserver environment.
2. Exercise read-only address observation and confirmation reporting against one
   supported Electrum environment on a chain matching the configured Bitcoin
   network. Mainnet evidence must use a known public output and must not spend funds
   or imply custody/payment execution.
3. Record exact dependency versions, commands, expected observations, and any environment limitation.
4. Document multi-Creator cardinality and isolation, one-process deployment, at-least-once duplicate window, one-output settlement, underpayment behavior, confirmation policy, no payer inbox/proofs, no retention/pruning, and unsupported edge cases.
5. Keep the closed config example limited to keys consumed by the executable.
6. Mark the status table complete only for behavior exercised through the composed application.

**Acceptance:** README and plans contain no claim broader than automated and live verification. If live integration is blocked by missing public API or environment, name that as a release blocker rather than marking the prototype complete.

**Verification:**
```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace --no-run
TEST_DATABASE_URL=postgres://... cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
git diff --check
git status --short
```

**Suggested commit:** `docs: document the supported Paykit prototype`

**Implementation record (2026-07-22):**
- Added ignored, explicit live tests in `paykit-server-e2e/tests/live_adapters.rs`;
  normal workspace runs compile them but do not depend on external services.
- Against Pubky Core static testnet `0.9.3` at revision
  `51db89744f97e33486a5e5aedf442b7e2f9b51c2`, two temporary identities published
  and discovered markers through the separate localhost relay/homeserver process,
  established an Encrypted Link, and sent/received one Payment Request.
- Against Fulcrum `1.11.1` protocol `1.4` over Bitcoin mainnet, the production
  `electrum-client 0.25.0` adapter observed the exact known outpoint, `900000` sats,
  presence, and two confirmations among the address's complete history.
- The supplied Fulcrum TLS port presented a self-signed certificate without a SAN
  and was correctly rejected; the successful plaintext port is bounded protocol
  evidence, not a production TLS endorsement. Other tested public testnet providers
  either disagreed with the selected chain or did not complete within the bounded run.
- `docs/live-adapter-smoke.md` records exact dependency revisions, commands,
  expected observations, timing, cleanup, and environment limitations.
- README/config/design/implementation docs now describe the composed executable,
  multi-Creator one-process model, at-least-once duplicate window, independent-output
  settlement and underpayment behavior, six-confirmation policy, payer/proof/receipt
  exclusions, no retention/pruning, local-only Pubky testnet, and unsupported edges.
- The closed operator example omits `[inbox]`; Mitigation Task 12 removes that parser
  surface and the executable rejects it.
- The literal formatting, workspace check/no-run, full PostgreSQL workspace test,
  Clippy, rustdoc, and diff-hygiene chain passes.

### Mitigation Task 12: Remove only misleading retired surfaces

**Objective:** Reduce false product surface without delaying the working core for broad cleanup.

**Files:**
- Remove or modify: `paykit-server/src/persistence/inbox.rs`
- Modify: `paykit-server/src/persistence/mod.rs`
- Modify: `paykit-server/src/config.rs`
- Modify: `config/paykit-server.example.toml`
- Modify: `README.md`
- Modify: `docs/plans/0001-receiver-only-prototype-design.md`
- Modify: `docs/plans/0002-receiver-only-prototype-implementation.md`
- Modify: `docs/plans/0003-production-ready-prototype-mitigation.md`
- Remove unused `ReaderStore` and duplicate payment-state types/tests where confirmed unreachable
- Squash the unreleased schema into one live-only baseline when reset-only policy is approved

**Implementation:**
- Remove `[inbox]`, payer-lifecycle states, and Rust APIs with no supported caller.
- Under the approved reset-only policy, rewrite the unreleased migration chain into
  one live-only baseline and remove retired tables.
- Keep README, configuration documentation, active plans, and this task's status synchronized with the retained or removed surface.
- Do not split `InvoiceStore` or introduce generalized frameworks as part of this task.

**Implementation record (2026-07-23):**
- Removed the `[inbox]` parser/config types and added a closed-schema regression test.
- Removed the uncomposed `InboxStore`, standalone duplicate `ReaderStore`, inbox AAD
  context, and their obsolete repository tests. Dedicated invoice/outbox tests retain
  supported allocation, same-Creator serialization, encryption, replay, dependency,
  and lease-fencing coverage.
- Removed unreachable `Cancelled` and `Rejected` persisted payment-status variants;
  direct observation retains only undetected, detected, and confirmed states.
- Squashed the unreleased migration chain into one live-schema baseline. Historical
  `inbox_events` and `peer_work_leases` tables are absent, and earlier databases
  must be reset rather than upgraded.
- Synchronized README, closed config example, and active design/implementation plans.
- The literal formatting, workspace check/no-run, full PostgreSQL workspace test,
  Clippy, rustdoc, and diff-hygiene chain passes.

**Verification:**
```bash
cargo test --workspace --no-run
TEST_DATABASE_URL=postgres://... cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

**Suggested commit:** `refactor: remove retired receiver surfaces`

---

## Execution order and release gates

1. Execute Tasks 0–3 before exposing new production behavior.
2. Execute Tasks 4–5 before mounting invoice creation in the executable.
3. Execute Tasks 6–7 before accepting protected Bitcoin payment data in the composed runtime.
4. Execute Tasks 8–9 to create the production application and lifecycle.
5. Task 10 is the automated release gate.
6. Task 11 is the live-integration and documentation release gate.
7. Task 12 is recommended cleanup but may occur after Task 11 if the retained surfaces remain unreachable and truthfully documented.
8. After every task: run scoped tests, full verification appropriate to the change, spec-compliance review, code-quality review, then stop for user review/commit.

## Release checklist

- [x] Concrete Paykit and Electrum adapters are supported by inspected public APIs.
- [x] Startup authenticates every Creator credential and SDK-state envelope.
- [x] Multiple Creators own isolated xpub/account, derivation, Noise, and SDK state.
- [x] Same-Creator mutation is serialized; different Creators can progress concurrently.
- [x] Signed requests cannot be quota-starved by unsigned clients.
- [x] Setup flows and request work are bounded.
- [x] Invoice success includes complete executable delivery intents.
- [x] Endpoint success reaches the actual adapter-supported terminal state and releases Payment Request work.
- [x] At-least-once crash recovery is tested and documented.
- [x] Protected Bitcoin allocation/observation values are encrypted or keyed-hashed.
- [x] Direct observation cannot falsely attribute or finalize payment.
- [x] Production `main` mounts business routes and supervises workers.
- [x] Readiness reflects running dependencies and workers.
- [x] Shutdown stops admission/claims and exits within its deadline.
- [x] The composed two-Creator PostgreSQL workflow passes across restart.
- [x] Live Paykit and Electrum smoke tests pass, or the prototype remains explicitly unreleased.
- [x] README and plans describe only supported behavior and documented deferrals.

## Status table

| Task | Status | Notes |
| --- | --- | --- |
| 0 | Complete (inspection) | Paykit public adapter contract was available; Task 7A subsequently selected and pinned the BDK Electrum contract. |
| 1 | Implemented and PostgreSQL-verified | Startup scans every Creator credential and SDK-state envelope before bind; wrong-key, corrupt, missing, swapped-row, restart, and multi-Creator startup cases pass against PostgreSQL. |
| 2 | Implemented and PostgreSQL-verified | Setup validates a derivable BIP84 account xpub against network, depth, and claimed hardened account index before publication/persistence; marker capabilities and same-/cross-Creator isolation pass against PostgreSQL. |
| 3 | Implemented | Trusted signed policy is charged only after verified closed-schema input; runtime capacity bounds pre-auth work; setup uses transport-IP policy plus cancellation-safe global reservations; sub-second persistence lease/retry durations are rejected. |
| 4 | Implemented and PostgreSQL-verified | Invoice success atomically persists complete Creator-bound endpoint and Payment Request intents with selected marker binding, dependency, current-format validation, and exact replay preservation. |
| 5 | Implemented and PostgreSQL-verified | Creator-scoped public-SDK handoff durably persists SDK-generated IDs, fences exact outbound reconciliation through durable `Sent`, retains terminal failures, and documents the accepted at-least-once pre-association duplicate window. |
| 6–7B | Implemented, PostgreSQL-verified, and live-smoke verified | Bitcoin records are encrypted/keyed-hashed; the concrete adapter uses pinned `electrum-client` 0.25; complete batches are validated before one atomic persistence call; one exact mainnet output passed against Fulcrum. |
| 7C | Implemented and PostgreSQL-verified | Three evidence-driven reviews simplified network/address parsing, BDK metadata indexing, outpoint validation, and idle persistence while preserving the independent provider boundary; stale BDK protocol and canonical migration fixtures were corrected. |
| 8–9 | Implemented and PostgreSQL-verified | Production composition owns all business routes and workers; evidence-driven readiness and one bounded lifecycle supervisor cover startup, retry degradation, admission/claim stop, graceful drain, and forced deadline abort. |
| 10 | Complete | Composed two-Creator PostgreSQL workflow passes through production routes/workers across restart with persistence privacy assertions. |
| 11 | Complete with documented transport/environment bounds | Separate local Pubky relay/homeserver marker and Payment Request delivery passed; one exact mainnet Fulcrum observation passed over plaintext Electrum; operator docs bound claims and require CA-valid TLS for production. |
| 12 | Complete | Retired inbox config/API and tables, duplicate reader repository, and unreachable payer-lifecycle states are removed from the reset-only baseline. |
