# Receiver-Only Paykit Server Prototype Implementation Plan

> **For Hermes:** Use `subagent-driven-development` to implement this plan task-by-task, with a spec-compliance review followed by code-quality review for every task.

**Goal:** Build the PostgreSQL-backed receiver-only Paykit Server described by `0001-receiver-only-prototype-design.md`, including multiple independent Creator accounts, signed Locks APIs, encrypted Creator/runtime state, Paykit delivery, Bitcoin observation, and operational controls.

**Architecture:** A virtual Rust workspace contains one server crate and one black-box E2E crate. `paykit-server` owns HTTP, application workflows, encrypted PostgreSQL persistence, and worker orchestration; it calls `paykit-sdk` rather than recreating Paykit protocols. Creator authority, one BIP84 account xpub/account index, address allocation, receiver Noise key, and SDK state are isolated per Creator inside one supported server process. `paykit-server-e2e` starts the real Axum application against PostgreSQL and verifies committed cross-boundary and cross-Creator isolation contracts.

**Tech Stack:** Rust edition 2024 (MSRV 1.91.1), Tokio, Axum, SQLx/PostgreSQL, `paykit-sdk`/`paykit-lib` pinned to inspected `paykit-rs` commit `81fd0e5124aac1fd782811fd968109a5972cd323`, XChaCha20-Poly1305, HKDF-SHA256, Ed25519, Electrum client.

**Authoritative requirements:**
- `docs/plans/0001-receiver-only-prototype-design.md`
- `../../Pubky/locks/docs/ADRs/0020-locks-paykit-v1-integration-boundary.md`
- Matching Locks behavior in `../../Pubky/locks/locks-server/src/paykit_http_client.rs`

**Hard boundary:** Do not implement unsupported Paykit wire/Encrypted-Link behavior locally. Delegate it to the pinned `paykit-sdk` dependency.

**Human review rule:** Stop after every checkpoint below. The user reviews and commits; do not make commits automatically.

---

## Product-decision removal

### Task 0: Removed — upstream SDK deletion API preflight

Removed by product decision. This server has no payload-deletion worker or SDK-state deletion contract, so no upstream SDK API or dependency-pin gate is required.

---

## Checkpoint 1 — workspace and contract types

### Task 1: Create the virtual Cargo workspace

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `paykit-server/Cargo.toml`
- Create: `paykit-server/src/lib.rs`
- Create: `paykit-server/src/main.rs`
- Create: `paykit-server-e2e/Cargo.toml`
- Create: `paykit-server-e2e/src/lib.rs`

**Steps:**
1. Create a resolver-3 virtual workspace with members `paykit-server` and `paykit-server-e2e`.
2. Set workspace edition to 2024 and MSRV to 1.91.1.
3. Pin `paykit-sdk` and `paykit-lib` to the inspected Git revision; do not use a floating branch dependency.
4. Add only dependencies needed by this checkpoint: Tokio, tracing, anyhow/thiserror, serde, serde_json, UUID, time, and test support.
5. Make `paykit-server` expose an empty `Server` composition placeholder and binary that parses no production config yet.

**Verification:**
```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
```

**Expected:** workspace compiles; no network service or persistence behavior exists yet.

**Suggested user commit:** `build: scaffold paykit server workspace`

### Task 2: Add closed configuration parsing and deployment invariants model

**Files:**
- Create: `paykit-server/src/config.rs`
- Modify: `paykit-server/src/lib.rs`
- Create: `paykit-server/tests/config.rs`

**RED tests:**
- Unknown TOML fields fail parsing.
- Missing `PAYKIT_DATABASE_URL` or malformed `PAYKIT_MASTER_KEY` fails startup configuration.
- Master key accepts only base64url-no-pad that decodes to exactly 32 bytes.
- Invalid network, receiver path, URL/origin, mixed wildcard/concrete origin policy, retired Paykit URL key, zero duration/batch, or inconsistent limit fails.

**Implementation:**
- Parse the closed supported sections: `http`, `locks`, `setup`, `paykit`, `bitcoin`, `electrum`, `outbox`, `limits`, `rate_limits`, `shutdown`; reject retired `[inbox]`.
- Require `locks.trusted_public_key` in canonical `pubky<pubky-key>` form,
  matching Locks `credentials.lock_server_public_key`.
- Use accepted `snake_case` TOML keys and duration strings (`"5s"`, `"30s"`, `"90d"`); initial names are `http.listen_addr`, `locks.trusted_public_key`, `setup.allowed_origins`, `paykit.receiver_path`, `paykit.network`, `bitcoin.network`, `electrum.endpoint`, `electrum.poll_interval`, `electrum.request_timeout`, and `electrum.connect_retries`; accept exact HTTP(S) setup origins or `"*"` only as the sole origin policy, validate `paykit.receiver_path` with `paykit_lib::PaykitReceiverPath` (for example `paykit/server`), and treat `paykit.network` as the closed enum `mainnet | testnet` supported by the pinned SDK/Pubky constructors. `testnet` is the pinned Pubky client's fixed localhost testnet, not a hosted service. Superseded 2026-09-09: `electrum.connect_retries` was retired (the closed `[electrum]` schema rejects it); the electrum-client 0.25 adapter pins call retries at zero and the observer's next tick is the retry.
- Remaining names are `outbox.poll_interval`, `outbox.batch_size`, `outbox.lease_duration`, `outbox.retry_initial`, `outbox.retry_max`, `limits.request_body_bytes`, `limits.lock_resource_bytes`, `limits.lock_fetch_timeout`, `rate_limits.signed_requests_per_second`, `rate_limits.signed_burst`, `rate_limits.setup_per_ip_per_minute`, `rate_limits.max_pending_setup_flows`, `rate_limits.max_completion_polls_per_flow`, `rate_limits.max_completion_polls`, and `shutdown.drain_timeout`; default `outbox.batch_size` to `16`.
- Keep `PAYKIT_DATABASE_URL` and `PAYKIT_MASTER_KEY` environment-only.
- Define typed immutable deployment values: Bitcoin network, receiver path, and trusted Locks-key fingerprint.
- Log only redacted effective configuration.

**Verification:**
```bash
cargo test -p paykit-server --test config
cargo fmt --check
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested user commit:** `feat: add validated server configuration`

### Task 3: Add protocol and domain value objects

**Files:**
- Create: `paykit-server/src/domain/mod.rs`
- Create: `paykit-server/src/domain/locks.rs`
- Create: `paykit-server/src/domain/invoice.rs`
- Create: `paykit-server/src/domain/payment.rs`
- Create: `paykit-server/tests/domain_values.rs`

**RED tests:**
- Reject non-canonical or invalid creator/reader/lock-resource identifiers.
- Accept only positive integer-satoshi criterion amounts and exact `BTC` asset.
- Parse 64-character lowercase-hex `txid` and bounded `u32` `vout`.
- Generate and preserve UUID-v4 Payment Reference.
- Represent `undetected`, `detected`, and `confirmed` status with explicit confirmation count and amount-match fact.

**Implementation:**
- Keep value objects side-effect-free.
- Use `locks-core` https://github.com/pubky/locks, inspected at `0620c96124ac0a9f155912c2ac63e678e6882c56`, for canonical creator, reader, bundle, and addressed lock-resource parsing; do not duplicate their grammar.
- Make invoice identity creator-scoped `(creator, bundle_id)`.
- Encode the user-approved amount-matched/final/reorg/underpayment state transitions as pure domain functions.
- Do not add endpoint, database, or SDK types to domain modules.

**Verification:**
```bash
cargo test -p paykit-server --test domain_values
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested user commit:** `feat: add invoice and payment domain values`

---

## Checkpoint 2 — encrypted PostgreSQL persistence

### Task 4: Create migrations and PostgreSQL test harness

**Files:**
- Create: `paykit-server/migrations/0001_initial.sql`
- Create: `paykit-server/src/persistence/mod.rs`
- Create: `paykit-server/src/persistence/migrations.rs`
- Create: `paykit-server-e2e/src/postgres.rs`
- Create: `paykit-server-e2e/tests/migrations.rs`

**RED tests:**
- Migrations apply once under an advisory lock.
- A second startup sees the existing migration state without error.
- Required logical tables exist: creators, SDK states, reader assignments,
  invoices, outbox, Bitcoin observations, and deployment metadata. Retired
  inbox-event and peer-work tables are absent from the reset-only baseline.

**Implementation:**
- Use one reset-only embedded SQL baseline and SQLx migration support.
- Add only approved plaintext operational/index columns; business data columns are encrypted blobs or keyed lookup hashes.
- Add uniqueness needed for creator-scoped invoice identity, reader assignment, Payment Request identity, and configured-network outpoint binding.
- Keep enum-like state parsing in application code so corruption is diagnosable rather than silently coerced.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test migrations
cargo test --workspace --no-run
```

**Suggested user commit:** `feat: add PostgreSQL schema and migration harness`

### Task 5: Implement envelope encryption and keyed lookups

**Files:**
- Create: `paykit-server/src/crypto.rs`
- Create: `paykit-server/tests/crypto.rs`
- Modify: `paykit-server/src/lib.rs`

**RED tests:**
- Encrypt/decrypt a creator envelope with the correct row/type/creator AAD.
- Reject swapped ciphertext, nonce reuse fixture, wrong creator, wrong type, and wrong master key.
- Same logical lookup value gives same HMAC-SHA256 lookup hash; different values do not.
- Ensure Debug/Display/error output never renders plaintext credentials, xpub, address, identifiers, or master key.

**Implementation:**
- HKDF-SHA256 subkeys: `paykit-server/aead/v1` and `paykit-server/lookup-hmac/v1`.
- XChaCha20-Poly1305 with a fresh random 24-byte nonce on every write.
- Domain/version/creator/row-bound associated data.
- Encode AAD as length-prefixed domain `paykit-server`, version `1`, envelope type, 32-byte creator keyed lookup hash, and internal row UUID; store `BYTEA` as version byte `1`, nonce, then ciphertext/tag.
- Serialize envelope plaintext with server-owned versioned `postcard` payloads: `CreatorCredentialsV1` for Creator Pubky/session/Noise/xpub/account index and `SdkStateV1` for one full SDK `StorageState`.

**Verification:**
```bash
cargo test -p paykit-server --test crypto
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested user commit:** `feat: encrypt persisted server state`

### Task 6: Persist deployment metadata and creator/SDK state

**Files:**
- Create: `paykit-server/src/persistence/deployment.rs`
- Create: `paykit-server/src/persistence/creators.rs`
- Create: `paykit-server/src/persistence/sdk_state.rs`
- Create: `paykit-server-e2e/tests/creator_state.rs`

**RED tests:**
- First initialization persists network, receiver path, and Locks-key fingerprint.
- Later mismatch aborts startup.
- Creator credentials and SDK state round-trip only through encrypted envelopes.
- Boot scan fails for malformed/decryption-failing creator or SDK-state row.
- Reauth preserves Noise secret/index/assignments and rejects changed xpub or account index.
- Two Creators persist different xpub/account pairs and independent SDK states; neither can load or mutate the other's encrypted state.
- Boot scans every Creator and rejects cross-Creator envelope substitution.

**Implementation:**
- Lock one creator SDK-state row for each SDK transaction.
- Decrypt, deserialize, update, serialize, encrypt, and commit one full `StorageState` atomically.
- Store exactly one account xpub/account index and one SDK state per Creator; there is no deployment-wide xpub or SDK runtime fallback.
- Serialize SDK transactions per Creator while allowing transactions for different Creators to proceed independently.
- Do not scan historical invoice/outbox encrypted payloads at boot.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test creator_state
cargo test --workspace
```

**Suggested user commit:** `feat: persist encrypted creators and SDK state`

### Task 7: Implement allocation, invoice, and outbox repositories

**Files:**
- Create: `paykit-server/src/persistence/invoices.rs`
- Create: `paykit-server/src/persistence/outbox.rs`
- Create: dedicated invoice and outbox PostgreSQL integration tests

**RED tests:**
- Concurrent allocation preserves one invoice-scoped `(creator, reader, bundle_id)` assignment and a monotonically allocated Creator-scoped child index.
- Two Creators may allocate the same child index from different xpubs, but their addresses and persisted assignments remain distinct.
- Exact invoice replay preserves invoice/address/request/outbox identity; changed binding conflicts.
- One outpoint cannot bind to two invoices.
- Claims use lease expiry and `SKIP LOCKED` behavior.

**Implementation:**
- Use the approved `READ COMMITTED` plus explicit `FOR UPDATE` rows/unique constraints.
- Encrypt business fields and raw serialized payloads; leave only approved scheduling and lookup metadata plaintext.
- The original repository plan allowed invoice, allocation, endpoint intent, and
  Payment Request intent to commit independently. Mitigation Task 4 superseded that
  design: a new invoice now commits its allocation, invoice, complete endpoint
  intent, complete dependent Payment Request intent, and semantic envelopes in one
  PostgreSQL transaction. Exact replay returns the complete durable result; a failed
  transaction leaves none of those records.
- Use typed AAD labels for reader assignments, invoices, semantic outbox intents,
  payment records, and Bitcoin observations; serialize the reader child index in
  the encrypted server-owned `ReaderAssignmentV1` envelope; use keyed HMAC lookup
  hashes. The standalone `ReaderStore`, inbox repository/API and tables, and
  payer-lifecycle states were later removed by Mitigation Task 12.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test invoices
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test outbox
cargo test --workspace
```

**Suggested user commit:** `feat: add transactional invoice and message repositories`

---

## Checkpoint 3 — setup and signed Locks contract

### Task 8: Implement setup flow state and iframe shell

**Files:**
- Create: `paykit-server/src/setup.rs`
- Create: `paykit-server/src/http/setup.rs`
- Create: `paykit-server/tests/setup.rs`

**RED tests:**
- Reject invalid `return_to`, invalid state, and unknown query fields.
- Generate exactly 43-character base64url flow IDs from 32 random bytes.
- Enforce 5-minute, single-use, memory-only flow lifecycle.
- Return approved completion outcomes: 200, 408, 404, 410, 422, 429/503.
- Iframe response uses exact `frame-ancestors` and postMessage target origin; no secret appears in postMessage.

**Implementation:**
- Keep browser retry behavior in the iframe shell exactly as ledgered.
- Complete setup only after valid session + companion claim, Receiver Marker publication/read-back, and durable creator/SDK commit.
- Treat the authenticated Creator Pubky as the setup ownership boundary: persist one xpub/account index per Creator, serialize same-Creator setup, and never replace or inspect another Creator's state.
- Persist nothing on failed marker publication/read-back or invalid auth/claim.
- Implement server-owned orchestration here for Pubky Auth completion, companion-claim validation, Receiver Marker publication/read-back, and durable creator/SDK persistence using the public `paykit-sdk` APIs.

**Verification:**
```bash
cargo test -p paykit-server --test setup
cargo test --workspace
```

**Suggested user commit:** `feat: add creator setup iframe flow`

### Task 9: Implement signed Locks request verification and error envelope

**Files:**
- Create: `paykit-server/src/http/auth.rs`
- Create: `paykit-server/src/http/error.rs`
- Create: `paykit-server/tests/locks_auth.rs`

**RED tests:**
- Missing, malformed, and invalid signature all return identical 401 envelope.
- Signature verification uses raw bytes before parsing.
- Signed noncanonical JSON, malformed JSON, unknown fields, and invalid schema return 400.
- Raw request limit returns 413 before JSON parsing.
- Errors have the exact safe envelope and leak no dependency/credential detail.

**Implementation:**
- Verify Ed25519 using only the configured trusted Locks public key.
- RFC 8785-canonicalize parsed JSON and require byte-for-byte equality with the received body.
- Apply global signed-endpoint rate limit before expensive downstream work.

**Verification:**
```bash
cargo test -p paykit-server --test locks_auth
cargo clippy -p paykit-server --all-targets -- -D warnings
```

**Suggested user commit:** `feat: verify signed Locks requests`

### Task 10: Implement `POST /invoices`

**Files:**
- Create: `paykit-server/src/application/create_invoice.rs`
- Create: `paykit-server/src/http/invoices.rs`
- Create: `paykit-server/tests/create_invoice.rs`
- Create: `paykit-server-e2e/tests/invoices.rs`

**RED tests:**
- Creator derives only from canonical lock resource.
- The canonical Creator selects only its own persisted credentials, xpub/account index, derivation counter, and SDK state; missing state has no default or cross-Creator fallback.
- Validate exactly one referenced `paykit-payment` criterion with recipient equal to canonical creator, `BTC`, and positive sats.
- Session invalid/unavailable returns approved 409/503 without allocation/commit.
- Exact replay is 204 without refetch/revalidation; changed binding is 409.
- New reader transaction creates assignment, endpoint-publication intent, then dependent Payment Request intent.
- Concurrent invoices for different Creators use independent derivation counters and may share a numeric child index without sharing an address or SDK transaction.
- Handler returns before link establishment/delivery. Cancel-safe dependency work
  respects the shared 15-second budget through the final pre-mutation check; an
  entered PostgreSQL transaction is awaited to a factual commit/rollback result.

**Implementation:**
- Use injected ports for session validation and canonical lock fetch; share the
  15-second pre-mutation dependency budget and map exhaustion to
  `503 dependency_timeout`.
- Snapshot validated terms once; later status never refetches lock.
- Create immutable one-time Paykit Payment Request through SDK, including protocol-required fields and approved metadata.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test invoices
cargo test --workspace
```

**Suggested user commit:** `feat: create idempotent Locks invoices`

### Task 11: Implement `POST /transactions/status`

**Files:**
- Create: `paykit-server/src/application/payment_status.rs`
- Create: `paykit-server/src/http/status.rs`
- Create: `paykit-server/tests/payment_status.rs`

**RED tests:**
- Unknown creator/bundle returns 404.
- Known invoice without an observed output returns exact undetected zero/false response.
- Status never triggers creator-session validation or lock refetch.
- Status serialization contains only `status`, `confirmations`, and `amount_matched`.

**Verification:**
```bash
cargo test -p paykit-server --test payment_status
cargo test --workspace
```

**Suggested user commit:** `feat: expose Locks payment status`

---

## Checkpoint 4 — Paykit runtime and Bitcoin observation

### Task 12: Implement SDK runtime adapter and outbox handoff

**Files:**
- Create: `paykit-server/src/paykit_runtime.rs`
- Create: `paykit-server/src/workers/outbox.rs`
- Create: `paykit-server/tests/outbox.rs`
- Create: `paykit-server-e2e/tests/outbox.rs`

**RED tests:**
- Payment Request intent stores the stable server outbox ID, exact executable
  terms, and caller-supplied Payment Reference before invoice success; the
  public SDK-generated Event ID, Payment Request ID, and outbound message ID do
  not exist until SDK enqueue returns.
- Handoff durably records the SDK-generated IDs returned by that enqueue under
  the server claim fence. A crash before that association may enqueue a new SDK
  event/request/message, so consumers must tolerate duplicate proposals.
- Latest-State Private Payment List re-enqueue is safe after ambiguous handoff.
- Publication confirmation gates dependent Payment Request handoff.
- Leased transient work retries with approved backoff; permanent error remains retained/degraded.
- Every outbox row resolves its owning Creator and mutates only that Creator's SDK state; work for different Creators may execute concurrently without cross-Creator state leakage.

**Implementation:**
- SDK owns Encrypted-Link send/retry after handoff.
- Reconcile the exact stored SDK outbound message ID to durable SDK `Sent`
  before marking the server intent `delivered`; this does not claim recipient
  application acknowledgement.
- Do not use direct custom Encrypted-Link or Payment Request serialization.

**Verification:**
```bash
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test outbox
cargo test --workspace
```

**Suggested user commit:** `feat: deliver Paykit endpoint and payment intents`

### Task 13: Removed — payer event intake and state transitions

Removed by product decision. The server has no payer-facing inbox or proof/event intake; Task 14 observes the invoice-specific address directly.

### Task 14: Implement direct Electrum observation and finality policy

**Files:**
- Create: `paykit-server/src/bitcoin.rs`
- Create: `paykit-server/src/workers/observer.rs`
- Create: `paykit-server/tests/bitcoin_observer.rs`
- Create: `paykit-server-e2e/tests/payment_observation.rs`

**RED tests:**
- Wrong address or no observation stays undetected.
- Underpayment reports real confirmations with `amount_matched=false`, remains non-final, and can be replaced at every confirmation count.
- Amount-matched zero-conf RBF replacement works; one confirmation freezes; pre-six confirmation regression or unseen reorg unfreezes; six confirmations finalizes at reported count 6.
- Outpoint ownership remains globally unique while replaced pre-final observations remain durable history.
- Electrum outage degrades health but does not block invoice creation.

**Implementation:**
- Compare integer satoshis only.
- Preserve the configured single-Electrum-endpoint/no-failover scope.

**Verification:**
```bash
cargo test -p paykit-server --test bitcoin_observer
TEST_DATABASE_URL=postgres://... cargo test -p paykit-server-e2e --test payment_observation
```

**Suggested user commit:** `0002 feat: observe direct Bitcoin payments`

---

## Checkpoint 5 — operation and release verification

### Task 15: Add server lifecycle, health, metrics, and limits

**Files:**
- Create: `paykit-server/src/http/health.rs`
- Create: `paykit-server/src/metrics.rs`
- Create: `paykit-server/src/runtime.rs`
- Create: `paykit-server/tests/runtime.rs`

**RED tests:**
- Live/ready schemas and status codes exactly match ledger.
- PostgreSQL failure yields not-ready; Electrum/delivery failures yield degraded.
- Health/logs/metrics do not expose identifiers or secret-bearing values.
- SIGTERM changes readiness, stops new claims, drains for configured 30 seconds, then cancels remaining tasks.
- Rate limits distinguish 429 policy limiting from 503 capacity exhaustion.

**Verification:**
```bash
cargo test -p paykit-server --test runtime
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**Suggested user commit:** `feat: add operational server controls`

### Task 16: Removed — server payload-deletion worker

Removed by product decision. No server worker, TOML section, SDK API dependency, or test suite will delete persisted payloads.

### Task 17: Final integration and operator documentation

**Files:**
- Create: `README.md`
- Create: `config/paykit-server.example.toml`
- Modify: `docs/plans/0002-receiver-only-prototype-implementation.md` with an implementation-status audit table
- Add: focused route, persistence, worker, and E2E test fixtures as needed

**Steps:**
1. Document required environment variables, immutable deployment values, config shape, migration behavior, readiness semantics, and explicit single-process limitation.
2. Add no credential-bearing example values.
3. Run the complete verification matrix.
4. Audit README, both active plans, and test names for stale behavior/terminology.
5. Run a composed two-Creator acceptance scenario proving distinct xpubs, independent derivation counters and SDK states, cross-Creator isolation under concurrency, and restart recovery for both Creators.

**Verification matrix:**
```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace --no-run
TEST_DATABASE_URL=postgres://... cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
git status --short
```

**Expected:** all scoped checks pass; any unavailable PostgreSQL/Electrum integration is reported as a blocker rather than treated as a green result.

**Suggested user commit:** `docs: document Paykit Server operation`

---

## Execution order and gates

1. Tasks 0, 13, and 16 are removed by product decision and must not be reintroduced without a new product decision.
2. Execute implemented tasks in order, using RED → GREEN → refactor for every behavioral task.
3. After every task: spec-compliance review first, code-quality review second, user review/commit third.
4. If a task discovers a missing public/persistence/security contract, stop, notify and ask about adding it to the design ledger before choosing behavior.
5. Do not claim workspace-wide success from a narrow crate test.

## Follow-on production-prototype mitigation

The original implementation audit found several isolated/tested seams. Mitigation
Tasks 0–11 in `0003-production-ready-prototype-mitigation.md` subsequently composed
and verified startup validation, multi-Creator isolation, executable outbox recovery,
encrypted Bitcoin observation records, concrete adapters, lifecycle supervision, the
two-Creator restart workflow, and bounded live adapter interoperability. Mitigation
Mitigation Task 12 completed the retired-surface cleanup.

## Implementation Status Audit (Task 17)

| Task | Status | Audit result |
| --- | --- | --- |
| 0 | Removed by product decision | No upstream SDK deletion API gate applies. |
| 1–11 | Implemented | Workspace, config, PostgreSQL/encryption, setup/signed-route, invoice/status seams are present and covered by unit/PostgreSQL tests. |
| 12 | Implemented, composed, and live-smoke verified | Outbox behavior is composed through the public SDK. A separate local Pubky relay/homeserver delivered one live-smoke Payment Request. Delivery remains at least once, not a strict end-to-end idempotence guarantee. |
| 13 | Removed by product decision | No payer inbox, proof, acceptance, cancellation, or rejection intake. |
| 14 | Implemented, composed, and live-smoke verified | Direct invoice-specific address observation is PostgreSQL-tested and one exact mainnet output/confirmation result passed through the production BDK adapter against Fulcrum. |
| 15 | Implemented | Operational health, metrics, capacity, and drain behavior are composed by the binary. |
| 16 | Removed by product decision | No payload-deletion worker or config/API contract. |
| 17 | Complete | README, safe closed config template, contract audit, composed acceptance workflow, live adapter runbook, and complete verification matrix. |

**Next execution step:** all production-prototype mitigation tasks are complete; review and commit the exact verified tree.
