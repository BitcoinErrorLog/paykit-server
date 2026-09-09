# Receiver-Only Paykit Server Prototype Design Ledger

Status: design interview complete; ready for implementation planning

## Classification

This document uses:

- **EXPLICIT** — accepted directly by user.
- **AUTHORITATIVE SOURCE** — user-designated external contract.
- **CONSTRAINT** — required boundary or dependency behavior.
- **PROPOSED — NOT APPROVED** — candidate awaiting decision.
- **UNRESOLVED** — missing contract; implementation must not invent one.

Only **EXPLICIT**, **AUTHORITATIVE SOURCE**, and **CONSTRAINT** entries may drive implementation.

## Authoritative sources

### Locks integration

The user designated these as authoritative for Locks Server ↔ Paykit Server HTTP behavior:

- `../../Pubky/locks/docs/ADRs/0020-locks-paykit-v1-integration-boundary.md`
- matching behavior in `../../Pubky/locks/locks-server/src/paykit_http_client.rs`

### Product flow

High-level product source:

- `../Locked Content Payment Flow — Technical Product Spec.md`

Its statement that Paykit Payment Requests are unnecessary is superseded by the explicit decision below.

### Paykit protocol dependency

Current `../paykit-rs` code/specifications define dependency behavior. They are implementation evidence and dependency constraints, not independent product requirements. The inspected branch `codex/receiver-communication-keys` contains the required separation between Pubky homeserver identity and receiver Noise key.

### Locks identifier dependency

**EXPLICIT**:

- Canonical Locks creator, reader, bundle, addressed lock-resource identifiers,
  and Paykit-payment policy validation use `locks-core` pinned at revision
  `06bc63c4b5ff7df194f26f3f3fecb8dab4d28995`; Paykit Server does not duplicate
  their parsing, canonicalization, or policy grammar.

## Actors and key boundaries

**EXPLICIT**:

- Receiver/creator Bitkit authorizes Pubky setup and supplies the account xpub.
- Sender/consumer Bitkit receives and pays the Payment Request.
- Locks Server requests invoices and queries payment status.
- Paykit Server derives invoice-specific addresses, sends Payment Requests through `paykit-rs`, observes Bitcoin through Electrum, and reports facts to Locks.
- Paykit Server never receives Bitcoin spending keys.
- Creator Pubky identity/session owns homeserver auth and routing.
- Paykit Server generates and retains one independent receiver Noise key per creator runtime.
- Sender and receiver Noise public keys are discovered through Paykit Receiver Markers.
- No separate service Pubky identity or custom creator-to-service delegation protocol is required.
- One Paykit Server deployment supports multiple independent Creator accounts. Each Creator owns its own authenticated authority, BIP84 account xpub/account index, receiver Noise key, and Paykit SDK state.

## Prototype scope

**EXPLICIT**:

- Stateful receiver-only prototype.
- Each Locks invoice request creates a one-time `paykit-rs` Payment Request.
- PostgreSQL is the only durable production backend. No SQLite or in-memory production backend.
- Paykit Server uses `paykit-rs`/`paykit-sdk` for Payment Request and Encrypted-Link behavior; it does not recreate those protocols.
- Supported payment asset is exact Locks criterion asset `BTC` only.
- Bitcoin network is selected by config: mainnet, testnet, signet, or regtest.
- Supplied xpub and derived addresses must match configured network.
- The configured Bitcoin network and receiver path are deployment-wide, while Creator credentials, xpubs, derivation counters, and SDK state are Creator-scoped.
- Each Creator has exactly one BIP84 native SegWit account xpub and companion-claimed account index in the prototype.
- Address derivation uses that Creator's account xpub → external chain `0` → monotonically allocated Creator-scoped child index.
- Different Creators may validly use the same child index because their xpubs and derivation sequences are independent.

## Locks HTTP authentication

**AUTHORITATIVE SOURCE + EXPLICIT refinements**:

- `POST /invoices`
- `POST /transactions/status`
- Requests carry `X-Paykit-Signature`.
- Exactly one trusted Lock Server public key is configured statically. No allowlist and no signer-ID header.
- Paykit Server verifies Ed25519 signature over exact received body bytes.
- Parsed JSON must RFC 8785-canonicalize to the exact received bytes. Signed noncanonical JSON is rejected.
- Request schemas are closed according to the authoritative Locks contract.
- Locks API request body limit is 16 KiB, enforced on raw bytes before JSON parsing; excess returns `413 payload_too_large`.
- Public lock-resource response limit is 256 KiB, enforced while reading; excess returns `422 invalid_lock_resource`.
- Public lock-resource fetch timeout is 10 seconds; timeout returns `503 lock_resource_unavailable`.
- Signed Locks endpoints have a shared 15-second dependency budget through the
  final pre-mutation deadline check; preflight, replay, session validation, lock
  fetch, marker discovery, and credential loading consume the same budget.
- Deadline exhaustion before mutation returns `503 dependency_timeout` and
  commits no state. Once atomic PostgreSQL mutation starts, the server awaits a
  factual commit or rollback result without canceling the transaction, so it
  never reports timeout while a concurrent `COMMIT` may have succeeded.
- API error envelope is `{ "error": { "code": "<stable_snake_case>", "message": "<safe text>" } }`.
- Missing, malformed, and invalid `X-Paykit-Signature` all return identical `401 invalid_signature` with message `request authentication failed`.
- A valid signature over malformed, schema-invalid, or noncanonical JSON returns `400 invalid_request`.
- Error responses expose no internal dependency or credential details.

## Creator setup and sensitive state

**EXPLICIT**:

- Pubky.app browser starts setup.
- Paykit Server hosts setup iframe and secret-bearing QR/deep link.
- Iframe/postMessage is the only completion mode; no redirect fallback.
- Setup follows Locks PR #18 as inspiration, without making that PR a Paykit requirement:
  - entry query carries full `return_to` and opaque `state`; delivery mode is fixed to postMessage;
  - server validates `return_to` origin against statically configured exact origins or a sole `"*"` wildcard policy;
  - exact validated origin becomes postMessage `targetOrigin`;
  - response CSP uses exact `frame-ancestors` origin;
  - parent validates `event.origin`, `event.source`, stable event type, and returned state;
  - auth URL, session secret, xpub, and other long-lived credentials never cross postMessage.
- Paykit success callback contains stable event type and opaque state; no frontend session code is needed.
- Setup entry is `GET /setup?return_to=<url>&state=<opaque>`.
- Iframe completion endpoint is `POST /setup/{flow_id}/complete`.
- No `delivery` query parameter exists because iframe/postMessage is the only mode.
- Success message is `{ "type": "paykit-setup-callback", "state": "..." }`.
- Failure message is `{ "type": "paykit-setup-callback", "state": "...", "error": "setup-failed" }`.
- No internal error detail, auth URL, creator identity, xpub, or credential crosses the iframe boundary.
- `return_to` is at most 2048 bytes, must be absolute HTTP(S), must contain no username/password, and its origin must satisfy the configured exact-origin or sole-wildcard policy.
- `state` is 1–512 UTF-8 bytes and contains no control characters.
- `flow_id` is server-generated from 32 random bytes encoded base64url without padding, exactly 43 characters.
- Invalid setup input returns `400 invalid_request`.
- Pending setup flow is memory-only, single-use, expires after 5 minutes, and is lost on restart.
- Iframe calls `POST /setup/{flow_id}/complete` as a long poll.
- Completion returns `200 { "status": "complete" }` on success and `408 { "status": "pending" }` on long-poll timeout.
- Completion returns `404` for unknown flow, `410` for expired flow, `422` for definitive setup failure, and existing `429`/`503` for transient overload.
- The iframe converts terminal completion responses into the approved generic postMessage failure.
- Pending completion requests wait until setup completes, fails, or request timeout.
- Browser retries network failures and HTTP `408`, `425`, `429`, `502`, `503`, and `504`.
- Retry uses exponential backoff starting at 500 ms and capped at 5 seconds.
- Repeated completion calls may continue waiting while pending.
- After durable completion, repeated completion calls return same success until 5-minute flow expiry; this covers a dropped success response.
- Failed or expired flows return definitive failure and are not retried by iframe.
- Completed creator state is durable in PostgreSQL.
- Setup creates or reauthenticates exactly one Creator account; there is no deployment-wide default xpub.
- Setup for one Creator must not read, replace, or serialize another Creator's xpub, account index, credentials, derivation state, or SDK state.
- Concurrent setup for the same Creator is serialized. Setup for different Creators may proceed independently within the global pending-flow and completion limits.
- Setup success requires Receiver Marker publication and read-back before creator credentials/SDK state are atomically persisted and before callback success.
- Marker publish/read-back failure persists nothing.
- DB commit failure after marker publication persists nothing; stale public marker is harmless and next successful setup overwrites it.
- New invoice creation requires persisted creator state, so stale marker alone grants no service capability.
- Setup succeeds atomically only when same Pubky Auth flow yields both:
  - valid creator Pubky session;
  - valid creator-signed `watch-only-account-v1` companion claim containing account xpub.
- Missing/invalid session or claim persists nothing.
- Companion claim `account_index` is parsed from Bitkit payload, imposes no policy, but is stored.
- Companion claim `address_type` must identify BIP84/native SegWit.
- One configured receiver path is shared by all creators. It is not duplicated in creator DB rows.
- Receiver Noise public key is derived from receiver Noise secret and published in Receiver Marker. It is not duplicated in creator DB rows.
- Creator Pubky public key remains inside its encrypted envelope; tenant lookup uses a keyed lookup hash and child rows use an internal creator UUID.
- One versioned encrypted creator credential envelope contains:
  - exported Pubky session secret;
  - `ReceiverNoiseSecretKey`;
  - xpub;
  - companion-claim `account_index`.
- Full per-creator `paykit-sdk` `StorageState` is stored as a separate versioned encrypted blob using same master key and creator-bound AAD policy.
- SDK state encryption covers Encrypted-Link snapshots, private messages, and other SDK-managed private state.
- Envelope encryption:
  - XChaCha20-Poly1305;
  - random 24-byte nonce per write;
  - creator keyed lookup hash as AAD, so boot can authenticate/decrypt creator envelopes without a plaintext Creator Pubky column;
  - deployment master key loaded only from environment variable;
  - master-key rotation is out of prototype scope.
- Master key environment variable is `PAYKIT_MASTER_KEY`.
- Value is base64url without padding and must decode to exactly 32 bytes.
- HKDF-SHA256 derives separate in-memory subkeys labeled `paykit-server/aead/v1` and `paykit-server/lookup-hmac/v1`; lookup hashes use HMAC-SHA256.
- Raw master key is not used directly for AEAD or lookup hashing.
- Envelope AAD is domain-separated by envelope type/version and bound to creator and row identity as applicable; ciphertext swapping across types, rows, or creators must fail authentication. Bitcoin observation envelopes additionally bind the parent invoice UUID, so moving an observation between invoices owned by the same Creator also fails authentication.
- AAD uses unambiguous length-prefixed fields: domain `paykit-server`, version `1`, envelope-type string, 32-byte creator keyed lookup hash, the 16-byte internal row UUID, and, for Bitcoin observations, the 16-byte parent invoice UUID.
- Stored envelope `BYTEA` is version byte `1`, followed by a 24-byte XChaCha nonce and ciphertext/tag. Lookup input is the supplied logical bytes; lookup output is the 32-byte HMAC-SHA256 value.
- Envelope plaintext uses server-owned versioned `postcard` payloads: `CreatorCredentialsV1` contains canonical Creator Pubky, Pubky session secret, 32-byte receiver Noise secret, xpub text, and account index; `SdkStateV1` contains one full `paykit_sdk::storage::StorageState`.
- Reader assignments, invoices, semantic outbox intents, payment records, and
  Bitcoin observations use distinct typed AAD envelope labels. Each reader
  assignment envelope contains a server-owned `ReaderAssignmentV1` with its child
  index and opaque assignment bytes, so the index remains encrypted. Lookup
  digests are keyed HMAC hashes, and repositories retain server-owned semantic
  payloads rather than recreating Paykit wire formats.
- Invalid master-key encoding or length aborts boot.
- Missing/invalid master key or inability to decrypt existing creator envelope causes boot failure.
- Reauthentication for existing creator:
  - replaces encrypted session secret;
  - preserves ReceiverNoiseSecretKey;
  - preserves address derivation index/address assignments;
  - claimed xpub must equal stored xpub;
  - claimed `account_index` must equal stored `account_index`;
  - changed xpub or `account_index` is rejected for prototype.

## Creator runtimes

**EXPLICIT**:

- One creator-scoped `paykit-sdk` runtime per creator.
- Runtime lookup is always keyed by the owning internal Creator UUID/keyed lookup hash; it never falls back to another Creator or a deployment-wide runtime.
- Runtime loads lazily from encrypted PostgreSQL state.
- Loaded runtime remains cached until process exit; no idle eviction in prototype.
- Outbox enqueue/reconciliation work can construct the required Creator SDK adapter
  from authenticated persisted state after restart.
- PostgreSQL SDK adapter locks one creator SDK-state row, decrypts/deserializes full `StorageState`, runs SDK transaction callback, serializes/encrypts updated state, and commits atomically.
- SDK-state mutation and address allocation are serialized per Creator, while work for different Creators may proceed concurrently.
- SDK receive-intake and server inbox persistence APIs and tables have been removed.
  Production composition has no receive/inbox worker, payer-facing behavior,
  readiness component, or metric.

## PostgreSQL privacy boundary

**EXPLICIT**:

- Invoice and reader-assignment business fields are encrypted at rest, not stored as plaintext relational columns.
- Encrypted invoice material includes `bundle_id`, `lock_resource`, reader Pubky, amount, Payment Reference, Payment Request identifiers, and payment binding details.
- Encrypted reader-assignment material includes reader Pubky and assigned child index.
- Keyed lookup hashes support required equality lookups and uniqueness without exposing source values.
- Creator Pubky is encrypted inside the credential envelope; an internal creator UUID and keyed creator lookup hash provide tenancy and relational references.
- Plaintext operational columns are limited to row UUIDs, keyed lookup hashes, state/status enums, lease data, attempt counters, scheduling timestamps, created/updated timestamps, per-creator next-child counter, and final confirmation state/count.
- Original business identifiers/data, reader mapping, address/index assignment, `txid:vout`, amount, serialized messages, SDK state, and credentials remain encrypted.
- Worker scheduling and row locking must not require bulk decryption.
- Logical PostgreSQL tables are:
  - `creators`: internal UUID primary key, keyed creator lookup hash, credential envelope, plaintext next-child counter, timestamps;
  - `sdk_states`: one versioned encrypted SDK state per creator;
  - `reader_assignments`: creator FK, reader and bundle lookup hashes, encrypted
    assignment, unique `(creator, reader_lookup_hash, bundle_lookup_hash)`;
  - `invoices`: creator FK, bundle and Payment Request lookup hashes, encrypted invoice, operational payment state/counts, timestamps, unique creator-scoped lookup hashes;
  - `outbox`: encrypted outbound payload plus scheduling/lease/status metadata;
  - SQLx migration bookkeeping for the single pre-production baseline.
- Bound `txid:vout` uses a unique keyed lookup hash within configured Bitcoin network.
- PostgreSQL transaction isolation is `READ COMMITTED`.
- Creator row is locked `FOR UPDATE` for child-index allocation.
- Child-index uniqueness is Creator-scoped: `(creator_id, derivation_index)` is unique, while the same index under different Creator xpubs is valid.
- Derived address ownership remains unique across the deployment; no invoice may reuse another invoice's address, including across Creators.
- Invoice row is locked `FOR UPDATE` for direct-observation replacement and payment transitions.
- Unique constraints enforce invoice idempotency, reader assignment, Payment Request identity, and `txid:vout` single-use.
- Workers claim rows using `FOR UPDATE SKIP LOCKED`.
- Invoice allocation, invoice insertion, endpoint intent, Payment Request intent,
  and their dependency are committed in one PostgreSQL transaction. Exact replay
  returns the existing complete allocation and intents without reconstructing or
  replacing them.
- `SERIALIZABLE` isolation is not required.
- The unreleased prototype uses one embedded baseline migration. Earlier prototype
  databases are unsupported and must be reset.
- Migrations run automatically at startup under PostgreSQL advisory lock.
- Migration failure aborts boot.
- Prototype provides no automatic down migrations.

## Invoice creation contract

**AUTHORITATIVE SOURCE + EXPLICIT refinements**:

Request:

```json
{
  "bundle_id": "...",
  "lock_resource": "pubky<creator>/pub/locks.app/<lock_id>.json",
  "reader": "pubky<reader>"
}
```

Rules:

- Invoice identity is `(creator, bundle_id)`.
- Creator is derived from canonical `lock_resource`; caller does not supply separate creator field.
- The derived Creator selects only that Creator's persisted credentials, account xpub/index, derivation counter, and SDK state. Missing Creator state fails the request; no default or cross-Creator fallback exists.
- New invoice fetches canonical public lock resource.
- New invoice fails unless the canonical lock satisfies the Locks v1 payment policy: exactly one `paykit-payment` criterion, referenced exactly once by lock logic, with `recipient_pubky` equal to the canonical creator.
- Criterion amount must be positive base-unit integer string.
- Criterion asset must equal `BTC`.
- Paykit Server snapshots validated invoice terms; later status does not refetch lock.
- Generate UUID-v4 Payment Reference once per new invoice; persist and reuse it.
- Exact replay returns `204 No Content` without refetching lock, reallocating address, recreating delivery, or revalidating creator session.
- Same `(creator, bundle_id)` with changed request binding returns `409 Conflict`.
- New invoice requires active network validation of creator Pubky session on every request:
  - revoked/expired → `409 creator_session_invalid`;
  - validation unavailable → `503 creator_session_unavailable`;
  - a non-valid session performs no invoice/address/outbox commit.
- Status queries do not validate creator session.

## Amount conversion

**EXPLICIT**:

- Locks amount is integer satoshis.
- Persist integer satoshi amount as settlement authority.
- Payment Request converts sats to BTC main-unit decimal.
- Payment Request decimal always uses exactly 8 fractional digits.
- Payment Request asset is `BTC`.
- Uppercase Payment Request asset `BTC` and lowercase identifier asset segment in `btc-bitcoin-p2wpkh` are intentional; endpoint matching uses exact identifier and does not normalize asset casing.
- Electrum comparison uses original integer sats; no decimal round trip.

## Address allocation and endpoint publication

**EXPLICIT — supersedes earlier reader-owned address decision**:

- Every invoice receives a distinct direct-observation address; address allocation is invoice-specific, not reader-only.
- Per-creator child index allocation is monotonic starting at `0`.
- The durable allocation identity is `(creator, reader, bundle_id)`.
- Different Creators have independent derivation sequences and may allocate the same child index from different xpubs; their resulting addresses must remain distinct.
- First invoice receives the next child index/address.
- Exact invoice replay reuses its address; a different invoice receives a distinct address.
- Address is shared to reader through reader-specific Paykit private endpoint state.
- Private Payment List endpoint identifier is exact `btc-bitcoin-p2wpkh`.
- Private Payment List endpoint payload is the raw network-valid Bech32 address string.
- Amount and Payment Reference remain Payment Request fields; endpoint payload does not duplicate them.
- The invoice-specific address directly identifies the invoice during Bitcoin observation;
  no payer-originated event is used for attribution.
- One creator-wide address shared by unrelated readers is prohibited.

## Payment Request delivery

**EXPLICIT**:

- Paykit v0.2 Payment Request wire message has `version: 1`, `kind: "paykit.payment_request"`, UUID-v4 `event_id`, UUID-v4 `payment_request_id`, and a `request` wrapper containing the accepted one-time request fields.
- New invoice creates one immutable one-time Payment Request.
- Payment Request `proposal_expires_at` is `null`; prototype has no proposal-expiry timer.
- Payment Request `recurrence` is `null` because request is one-time.
- Request remains payable until verified Bitcoin settlement.
- Payment Request metadata contains exact fields `bundle_id`, `lock_resource`, and `reader` copied from accepted invoice request.
- Metadata does not duplicate amount, asset, Payment Reference, address, or creator identity.
- `POST /invoices` returns success after the invoice and encrypted, versioned
  server semantic intent containing all `PaymentRequestTerms` inputs are durably
  committed. This is not the final SDK Payment Request event or wire JSON.
- API does not wait for Encrypted Link establishment or sender delivery.
- Invoice/allocation/outbox repository writes are one all-or-nothing PostgreSQL
  transaction. Invoice success is impossible without both complete intents and
  their dependency being durable.
- For a new `(creator, reader, bundle_id)`, the server publishes the invoice-specific
  Private Payment List endpoint before the Payment Request intent.
- Payment Request outbox intent depends on successful reader-specific endpoint publication.
- Existing reader may send directly only when endpoint publication is already confirmed; pending/failed publication blocks later Payment Requests behind it.
- PostgreSQL outbox is delivery authority; SDK send state is execution detail.
- Server outbox gives every row a stable intent ID and stores the exact
  versioned server semantic intent before invoice API success. That intent is
  the complete input to the public SDK proposal API, not a pre-serialized final
  SDK event. The SDK allocates its protocol Event ID, Payment Request ID, final
  wire payload, and outbound message ID internally, so those values can be
  persisted only after SDK enqueue returns.
- Payment Request handoff records the SDK-generated IDs returned by the successful public proposal call. Delivery remains at least once; consumers must tolerate duplicates rather than relying on a strict server/SDK idempotence guarantee.
- Private Payment List is Latest-State rather than Event Message: ambiguous handoff may re-enqueue identical latest state, which SDK supersedes safely.
- After handoff, SDK owns Encrypted-Link send/retry; server reconciles SDK state and marks outbox `delivered` only after SDK confirms remote send.
- Crash between SDK enqueue and the fenced server update is an ambiguous at-least-once window: the public proposal API has no caller-supplied IDs or exact server-intent lookup, so retry may create a new SDK outbound message, Event ID, and Payment Request ID. The stable server outbox intent ID and caller-supplied Payment Reference remain the server correlation values.
- Serialized outbox payload is encrypted with deployment master key; IDs, status, lease, attempts, and timestamps remain plaintext for indexing/scheduling.
- Background worker establishes/advances link and sends through `paykit-sdk`.
- Relay or post-validation delivery outage leaves work retryable and reports degraded health.
- Transient outbox failures retry indefinitely with exponential backoff from 1 second to 5 minutes and ±20% jitter.
- Attempt count and `next_attempt_at` are persisted.
- Workers claim outbox work with a 30-second lease; expired lease makes work reclaimable after worker failure.
- Non-retryable SDK/protocol failure marks row `permanently_failed`, retains it with redacted error class, degrades health, and receives no automatic retry.
- Transient failures never dead-letter by attempt count because invoices have no expiry.

## Payer-originated events

**EXPLICIT — out of scope for this receiver-only prototype**:

- Paykit Server has no payer-facing inbox and does not receive or process payer-originated payment events.
- The server's Paykit role is limited to establishing the receiver-side link,
  publishing the invoice-specific endpoint, and sending the Payment Request.
- Bitcoin observation of the invoice-specific `(creator, reader, bundle_id)` address
  is the sole payment-state authority.

## Direct Bitcoin observation

**EXPLICIT**:

- The invoice-specific address is the sole attribution key; payer-originated
  messages are out of scope.
- Output amount matches when `output_sats >= invoice_sats`; overpayment is accepted.
- No aggregation or top-up semantics: one output must satisfy the full invoice amount.
- Wrong-address output or no observed output leaves the invoice `undetected`.
- One `txid:vout` is owned by only one invoice globally, including replaced
  historical observations.
- An amount-matched zero-confirmation output may be replaced by a newer direct
  observation (including RBF). At one or more confirmations it freezes.
- Before six confirmations, an unseen reorg or regression to zero confirmations
  unfreezes that amount-matched output and permits replacement again.
- Underpayments are never final and may be replaced at every confirmation count.
- At six confirmations, an amount-matched output becomes permanently final;
  its persisted and reported confirmation count is exactly `6` and monitoring stops.

## Electrum observation and status

**EXPLICIT**:

- One configured Electrum endpoint; no failover pool in prototype.
- Poll tracked outputs every configurable interval; default 10 seconds.
- Status values:
  - `undetected`: no valid referenced output currently observed;
  - `detected`: valid output observed at 0 confirmations;
  - `confirmed`: valid output observed with at least 1 confirmation.
- Locks applies access threshold from returned confirmation count.
- Before six confirmations, reorg may regress status and confirmation count.
- At six confirmations, an amount-matched payment becomes final, monitoring stops, and persisted/reported confirmation count remains `6`.
- Reorg deeper than six is outside threat model.
- Unknown `(creator, bundle_id)` status query returns `404`.
- Known invoice without detected matching payment returns:

```json
{
  "status": "undetected",
  "confirmations": 0,
  "amount_matched": false
}
```

- Electrum outage does not block invoice creation or delivery. HTTP readiness remains true; health reports Electrum degraded; observation catches up later.

## Availability

**EXPLICIT**:

- PostgreSQL unavailable → readiness false.
- Missing/invalid master key → boot failure/readiness unavailable.
- Existing creator envelope decryption failure detected at boot → boot failure.
- Boot decrypts and deserializes every creator credential envelope and every creator SDK-state blob; any failure aborts boot.
- Boot validates every persisted Creator independently, including its xpub/account metadata and Creator-bound SDK state; cross-Creator envelope substitution fails authentication.
- Boot does not scan every historical invoice, inbox, or outbox payload.
- Runtime encrypted-row corruption is retained, never deleted: request-facing access returns `500 internal_error`; worker row becomes `permanently_failed`; health degrades; logs include only safe error class.
- Electrum outage → server remains ready; health degraded.
- Relay/delivery outage after successful creator-session validation → server remains ready; outbox retries; health degraded.
- One Creator's retryable delivery failure does not make other Creators unavailable; process health degrades without exposing Creator identity.
- A permanently invalid Creator discovered at runtime blocks that Creator's affected work and degrades health without substituting another Creator's state.
- Creator session is actively validated for every new invoice request, so creator homeserver validation outage rejects new creation with `503`.
- Exact invoice replay and status query remain available without session revalidation.
- Prototype supports exactly one running Paykit Server process; multiple async workers may run inside it.
- Horizontal replicas/active-active operation are out of scope because setup flows are memory-only and creator runtimes are process-cached.
- PostgreSQL leases and constraints provide in-process concurrency control and crash recovery, not multi-replica support.
- On SIGTERM/SIGINT, readiness becomes `not_ready`, new requests and worker claims stop, and process drains for configurable default 30 seconds.
- In-flight DB transactions complete or roll back; setup long polls receive retryable `503`; leases release best-effort or expire naturally.
- After a server row has durably recorded returned SDK IDs, SDK send retry uses that SDK outbound record and payload. A crash before that fenced server update may cause the server to invoke the proposal API again with the same terms and a new SDK Event ID, Payment Request ID, and outbound message ID.
- At drain timeout, remaining tasks are cancelled and process exits; pending setup flows are lost as accepted.

## Configuration

**EXPLICIT**:

- Process requires `PAYKIT_CONFIG` to name a TOML file with closed schema; unknown fields are rejected.
- TOML sections are `http`, `locks`, `setup`, `paykit`, `bitcoin`, `electrum`, `outbox`, `limits`, `rate_limits`, and `shutdown`; retired `[inbox]` is rejected.
- `http` configures listen address.
- TOML keys use `snake_case`; duration values use strings such as `"5s"`, `"30s"`, and `"90d"`.
- Initial key names are `http.listen_addr`, `locks.trusted_public_key`, `setup.allowed_origins`, `paykit.receiver_path`, `paykit.receiver_path_priority`, `paykit.network`, `bitcoin.network`, `electrum.endpoint`, `electrum.poll_interval`, `electrum.request_timeout`, and `electrum.connect_retries`; `paykit.receiver_path` is validated as `paykit_lib::PaykitReceiverPath` (for example `paykit/server`) and `paykit.network` is the closed enum `mainnet | testnet` supported by the pinned Pubky constructors. `testnet` is the pinned Pubky client's fixed localhost testnet, not a hosted service. Electrum request timeout and connect retries default to `"10s"` and `1`. Superseded 2026-09-09: `electrum.connect_retries` was retired (the closed `[electrum]` schema rejects it); the electrum-client 0.25 adapter pins call retries at zero and the observer's next tick is the retry.
- Remaining key names are `outbox.poll_interval`, `outbox.batch_size`, `outbox.lease_duration`, `outbox.retry_initial`, `outbox.retry_max`, `limits.request_body_bytes`, `limits.lock_resource_bytes`, `limits.lock_fetch_timeout`, `rate_limits.signed_requests_per_second`, `rate_limits.signed_burst`, `rate_limits.setup_per_ip_per_minute`, `rate_limits.max_pending_setup_flows`, `rate_limits.max_completion_polls_per_flow`, `rate_limits.max_completion_polls`, and `shutdown.drain_timeout`; `outbox.batch_size` defaults to `16`.
- `locks` configures one canonical Pubky-prefixed trusted Lock Server public key
  in the same `pubky<pubky-key>` form as Locks
  `credentials.lock_server_public_key`.
- `setup.allowed_origins` accepts exact HTTP(S) origins or `"*"` as the sole value. The wildcard admits any otherwise-valid HTTP(S) `return_to`, but the server still derives that request's concrete origin for exact `postMessage` targeting and `frame-ancestors` CSP.
- `paykit` configures receiver path and the supported SDK/Pubky network. Arbitrary relay and global homeserver URLs are not accepted because the pinned SDK-owned AUTH bootstrap exposes no relay override and Pubky resolves each identity's homeserver through Pkarr.
- `bitcoin` configures network.
- `electrum` configures endpoint, polling interval, finite request timeout, and connect retry count.
- `outbox` configures executable lease, polling/batch, and backoff values.
- `limits` configures accepted 16 KiB request limit, 256 KiB lock limit, and 10-second fetch timeout.
- `PAYKIT_DATABASE_URL` and `PAYKIT_MASTER_KEY` are env-only secrets and cannot appear in TOML.
- Startup rejects invalid URLs/origins/keys/networks, retired Paykit relay/homeserver URL keys, zero durations/batches, unsafe receiver paths, and inconsistent limits.
- Effective-config logging redacts environment secret values.
- First initialized database persists Bitcoin network, receiver path, and trusted Locks public-key fingerprint as deployment invariants.
- Later mismatch of any invariant aborts boot; prototype has no rotation/migration procedure for them.
- HTTP bind, allowed setup origins, Paykit network, same-network Electrum endpoint, and operational polling/retry/lease/rate/size settings may change across restarts.
- Closed TOML includes `rate_limits` section.
- Default signed Locks API limit is 100 requests/second globally with burst 200.
- Default new-setup limit is 10/minute per transport peer IP with at most 100 pending flows globally.
- Completion permits at most two concurrent long polls per flow and 200 globally.
- `X-Forwarded-For` is ignored; trusted-proxy interpretation is not supported in prototype.
- Policy-limited requests return `429` with `Retry-After`; exhausted capacity/semaphore returns `503` with `Retry-After: 1`; no denied operation commits state.
- Liveness/readiness endpoints are exempt.

## Health

**EXPLICIT**:

- `GET /health/live` performs no dependency checks and returns `200 { "status": "live" }` while process serves requests.
- `GET /health/ready` returns status `ready`, `degraded`, or `not_ready` and component states for `postgres`, `electrum`, `paykit_delivery`, and `outbox`.
- `ready` and `degraded` return HTTP 200; `not_ready` returns HTTP 503.
- Health responses expose no URLs, creator identities, error strings, counters, credentials, or other business data.
- Creator-session health remains request-scoped and is not enumerated globally.

## Observability

**EXPLICIT**:

- Logs are structured JSON.
- Logs may include timestamp, level, target, generated request ID, route, method, status, latency, internal row UUID, worker/action/result, and safe error class.
- Logs never include request/response bodies, signature header, `return_to`, setup state/auth URL, credentials/keys/xpub, creator/reader Pubky, bundle/lock identifiers, Bitcoin address, Payment Reference/Request ID, `txid:vout`, decrypted payload/state, or database URL.
- Prometheus metrics are exposed at `GET /metrics`.
- Metrics have no labels and cover HTTP count/latency, outbox
  depth/retry/permanent failure, Electrum availability/last-success age,
  payment-state counts, process runtime activity, and session-validation result
  counts. No inbox result/lag metric is composed.
- Metrics contain no identifiers or user-controlled labels.

## Data lifecycle

**EXPLICIT**:

- This server has no payload-deletion policy, worker, configuration, or SDK-state deletion contract.
- Operators must treat persisted encrypted invoice/outbox/internal relay data and SDK state as retained according to current database and SDK behavior.
- Any deletion policy requires a separate product and migration decision.

## Verification and release boundary

**EXPLICIT**:

- The composed application is PostgreSQL-verified with two independent Creators,
  concurrent invoice creation, SDK handoff/reconciliation, direct Bitcoin
  observation, status reads, shutdown, startup reauthentication, and restart.
- Live Paykit evidence uses Pubky Core static testnet `0.9.3` at revision
  `51db89744f97e33486a5e5aedf442b7e2f9b51c2`: two temporary identities publish
  and discover receiver markers through the separate relay/homeserver process,
  establish an Encrypted Link, and send/receive one Payment Request.
- Live Electrum evidence uses the production `bdk_electrum` adapter against
  Fulcrum `1.11.1` protocol `1.4` on Bitcoin mainnet: one exact known outpoint,
  satoshi value, presence fact, and confirmation count were observed.
- The successful Fulcrum smoke used plaintext `tcp://`; the server's TLS port had
  a self-signed certificate without a Subject Alternative Name and was correctly
  rejected. This is protocol-interoperability evidence, not a production transport
  recommendation. Production requires a CA-valid `ssl://` endpoint.
- Exact versions, commands, output, and failed provider attempts are recorded in
  `docs/live-adapter-smoke.md`. Claims do not extend to arbitrary providers,
  future versions, a remote production homeserver, or the complete Bitkit
  user-approval journey.

## Current unresolved design questions

None. Final consistency audit completed against the authoritative Locks ADR/client and Paykit v0.2 Payment Request specification.

## Explicitly out of scope

- Bitcoin spending-key custody.
- Assets other than BTC.
- SQLite production storage.
- Electrum failover pool.
- Master-key rotation.
- Xpub replacement/rotation.
- Multiple xpubs or account indexes within one Creator.
- Per-Creator Bitcoin networks or receiver paths.
- Partial startup that quarantines one corrupt Creator while serving other Creators.
- Runtime idle eviction.
- Redirect setup shell.
- Deep reorg handling after six confirmations.
- Refunds, overpayment credits, or change.
- Paykit Receipt issuance, `receipt_access` events, and receipt storage.
- Separate service Pubky identities or custom delegation protocols.
