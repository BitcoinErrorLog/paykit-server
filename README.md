# Paykit Server

A PostgreSQL-backed, receiver-side Paykit service for Locks invoices. It observes invoice-specific Bitcoin addresses and optionally verifies direct USDT0 payments on Arbitrum One using authenticated Paykit ERC-20 proofs. Locks makes the access decision; the server never spends funds.

This repository is pre-production. Persisted-data compatibility, stable releases, and production deployment support are not yet provided.

## Development quickstart

The workspace pins Rust in [`rust-toolchain.toml`](rust-toolchain.toml). PostgreSQL is required only for the database-backed E2E suite.

```bash
git clone https://github.com/pubky/paykit-server.git
cd paykit-server
cargo check --locked
cargo test --locked -p paykit-server -- --test-threads=1
cargo test --locked -p paykit-server-e2e --no-run
```

To run the database-backed E2E suite, set `TEST_DATABASE_URL` to a PostgreSQL database whose role may create and drop databases:

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test --locked -p paykit-server-e2e -- --test-threads=1
```

The two live-adapter tests remain ignored by default because they require either a local Pubky static testnet or a recorded public Electrum fixture. See [`docs/live-adapter-smoke.md`](docs/live-adapter-smoke.md) before running them explicitly.

For a complete local SDK payment without a frontend or Bitkit, run
[`sdk-example/run.sh`](sdk-example/README.md). It starts disposable Docker
infrastructure, authorizes a Creator, delivers an invoice over Paykit, and pays
it with regtest Bitcoin.

Before submitting changes, read [`CONTRIBUTING.md`](CONTRIBUTING.md). Report security problems through the private process in [`SECURITY.md`](SECURITY.md), not a public issue.

The [architecture contract](docs/architecture.md) describes shared identity,
credential ownership, and immutable invoice attribution. Rust dependencies pin
the Paykit `v0.1.0-rc71` release tag in `Cargo.toml`; `Cargo.lock` fixes its
resolved commit at `e4e58d3ee6c6aa19d6262d4cd96a58890a65b6fa`.
Direct `pubky` and `pubky-testnet` dependencies are pinned to `0.15.0`.

## Executable boundary

`paykit-server` composes and supervises the production HTTP routes, Paykit delivery workers, and BDK Electrum observer in one process.

Public operational routes:

- `GET /health/live`
- `GET /health/ready`
- `GET /metrics`

Business routes:

- `GET /setup`
- `GET /setup/reconnect`
- `POST /setup/{flow_id}/complete`
- signed `POST /invoices`
- signed `POST /connections/status`
- signed `POST /transactions/status`
- signed `POST /setup/status`
- signed `POST /payment-requests/status`
- signed `POST /payment-request-drains`
- signed `POST /payment-request-drain-lookups`
- signed `POST /payment-request-drain-cleanups`

Business-route signatures use one shared `signed_services.trusted_public_keys`
authority domain. Every listed Locks or Marketplace Ed25519 key may call every
signed route; there is no route-specific authorization. Shop/browser code must
never receive a service signing secret. Setup uses the Bitkit Pubky Auth
companion-claim flow and an exact configured browser origin.

Successful invoice creation and exact replay return `200 OK` with only RFC 3339
`invoice_created_at` and `payment_deadline` timestamps; they do not expose Noise
state. `POST /connections/status` is the separate read-only lookup. Its closed
body is `{"bundle_id":"...","creator":"pubky..."}`. Paykit Server derives
the exact Reader identity from persisted invoice state, then returns
`{"state":"none|handshake|connected|recovery_required|blocked"}`. Unknown
invoices return `404`; authentication, storage, malformed-state, and dependency
failures remain typed errors. `connected` is the identity's shared Noise state,
not payment or verification completion.

`POST /setup/status` is the readiness check for an authenticated Creator. Its closed body is `{"creator":"pubky..."}` with optional `asset: "BTC"`, `"USD"`, or `"USDT"` to check whether approved receiving details can accept that denomination. Every signed route verifies Ed25519 over `b"paykit-http-signature-v1\0" + uppercase_method + b"\0" + exact_query_free_path + b"\0" + exact_raw_body`; there is no body-only fallback. It returns exactly one coarse state: `ready` when the persisted session, delegated key, App Registry entry, and hosted state are usable; `setup_required` when authority is absent or confirmed invalid; and `unavailable` for validation timeouts and storage, rate-limit, server, DNS, or transport failures. Untyped Pubky 401 responses are also `unavailable`: they cannot distinguish revoked grants from recoverable PoP failures. A revoked grant reported this way requires explicit reconnect. Callers must not convert `unavailable` into a new authorization flow.

### Setup iframe

`GET /setup` is the production Bitkit setup surface. On desktop it renders the
normal secret-bearing Pubky Auth request as a QR code; on touch devices it
offers the same request through a `Continue with Bitkit` deep link. On Android
the link becomes an intent URL naming the Bitkit build for `bitcoin.network`
(`to.bitkit`, `to.bitkit.tnet` or `to.bitkit.dev`), because Pubky Ring also
handles `pubkyauth://` links; signet has no Bitkit build and keeps the plain
link. The QR always carries the plain `pubkyauth://` request. Production
has no companion handle, helper endpoint or state, helper UI, or helper in the
production package/runtime surface.

The iframe continues polling `POST /setup/{flow_id}/complete`. Completion runs
in a server-owned task, so a dropped poll does not fail the flow: on a touch
device the browser is backgrounded while the Creator approves in Bitkit, and
the next poll after the browser returns reports the outcome. pubky-app applies
the same rule to its Pubky Ring sign-in: the hand-off to the signer app does not
cancel the wait for approval (pubky/pubky-app#1411).

The iframe never sends the auth URL, Creator secret, xpub, or companion payload
through `postMessage`.
There is no manual claim route. Completion posts only
`{ type: "paykit-setup-callback", state }` or the same callback with a coarse
error to the exact caller origin.

Before delegation, Bitkit publishes the identity-signed Paykit Noise Key
Authorization using `PAYKIT_AUTHORIZER_SESSION_CAPABILITIES` and
`publish_paykit_noise_key_authorization()`, before publishing private app
capabilities. That owner-only scope includes
`/pub/paykit-authority/v0/current-key.json:rw`; it must never be granted to Server.
The App Registry remains discovery metadata, not key authority.

An existing Creator without signed key authorization is not ready until its
authorizer publishes that record. Reconnect refreshes delegated credentials while
preserving the account and invoices; signed authorization does not require a
database reset.

Bitkit authorizes only `/pub/paykit/:rw` for Server. With USDT disabled, the server requests two independent
permissions as `x-bitkit-claim=paykit-access-v1.watch-only-account-v1` and Bitkit
returns a signed, encrypted companion claim. Its 124-byte payload contains the BIP84
account index, address kind, serialized xpub, Paykit key generation, and 32-byte
Paykit identity secret; the signature adds 64 bytes. The server verifies the
delegated key and generation against the Creator's signed Noise key authorization,
persists credentials, then
publishes only the `paykit-server` app entry through the SDK. Other apps and
shared history remain intact. Failed publication leaves setup incomplete and
retryable. Reauthorization preserves the account/xpub and accepts only the same
key or a newer generation. The server never receives the Pubky root secret or
Bitcoin spending keys.

This Bitcoin setup requires both permissions. With `[usdt]` enabled, setup additionally requests optional `usdt-address-v1` and uses the JSON claim described below. The exact received list order binds the
SDK signature and relay channel; the 124-byte payload always puts watch-only
account bytes before Paykit key material regardless of list order. Empty,
duplicate, unknown, or one-only selections fail setup.
Reconnect uses `GET /setup/reconnect?creator=pubky...&return_to=...&state=...`.
The server requires an existing Creator and requests `paykit-access-v1`
(41 unsigned bytes), adding optional `usdt-address-v1` when enabled. The AUTH identity must match that exact Creator; the xpub
and account index come exclusively from stored credentials under the setup lock.
No watch-only account is selected, allocated, or retransmitted on reconnect.
Initial setup cannot replace an existing binding; use reconnect even when retrying
publication after credentials were stored. Client IDs and display names are never
used to infer account bindings. Rejected
or abandoned approval leaves existing credentials, pending invoices, assignments,
and allocation indexes intact. Successful reauthorization can refresh the session
or rotate the Paykit key without resetting that state. See the
[companion contract](docs/bitkit-companion-claim.md) for exact wire bytes.

The local Locks demo substitutes a Paykit-owned Cargo example for Bitkit. That
example is built and installed only by `Dockerfile.local`; it is not a normal
package binary or production server surface. It accepts exactly one closed
version-1 JSON object on stdin containing `auth_url`, `creator_secret`,
`account_xpub`, `account_index`, and `key_generation`, invokes the canonical `paykit-sdk`
companion-approval operation, and returns only a coarse result. It accepts no
URL, secret, or xpub through argv or `postMessage` and never writes those values
to output. It does not accept a Paykit Server URL or perform a helper-to-server
exchange. See [`docs/local-locks-demo.md`](docs/local-locks-demo.md) for the
local-only logging and trust boundary.

The composed PostgreSQL tests cover two independent Creators across restart and
ephemeral Pubky AUTH/shared-state integration. Separate external adapter tests
remain opt-in; see [`docs/live-adapter-smoke.md`](docs/live-adapter-smoke.md).

## Deployment model and Creator cardinality

Run exactly **one Paykit Server process** for a deployment. Horizontal replicas and active-active operation are unsupported because setup flows are memory-only, Creator SDK runtimes are process-cached, and receive/project/status/drain SDK operations share only an in-process per-Creator mutation fence. PostgreSQL locks, constraints, and leases provide concurrency control and crash recovery inside this one-process model, not multi-replica coordination.

Setup publication and workers share the cached Creator session handle. Restoring
the same Pubky grant independently mints a new bearer and invalidates the prior
one; do not restore a live server grant in a separate diagnostic process.

One process may own multiple Creator accounts. Each Creator has independent:

- Pubky session and generation-bound delegated Paykit key;
- one BIP84 account xpub and hardened account index;
- external-chain address derivation counter;
- identity-wide hosted Paykit state and Encrypted Links shared with authorized apps;
- encrypted invoices, assignments, outbox work, and payment observations.

Different Creators may use the same numeric child index because their xpubs and derivation sequences are isolated. There is no configured Creator-count limit, but all loaded runtimes remain cached until process exit; practical cardinality is therefore bounded by process and database capacity.

## Persistence, startup, and upgrades

PostgreSQL stores server credentials, address allocation, invoices, and delivery intents. The Paykit SDK stores encrypted identity-wide state on the Creator's homeserver under WebDAV locks; it is not cached as an authoritative PostgreSQL SDK blob. Other authorized apps can advance the same links and delivery queue. A background worker receives private messages and processes outbound work without executing wallet payments.

Shared hosted-state deployments require Pubky Homeserver **0.15 or newer**.
Upgrade the deployed homeserver separately; updating Server's client dependencies
does not upgrade that service. The SDK still requires commit-time fencing of
expired lock holders and durable publication of complete files. Its five-minute
uncertain-write cooldown remains in place and does not replace those requirements.

Startup holds a session advisory lock while applying the single schema baseline. Before binding HTTP it verifies immutable deployment metadata and authenticates every persisted Creator credential, invoice payment record, and payment observation. Missing, corrupt, swapped, conflicting, or wrong-key database state aborts startup with a secret-free error. Hosted Paykit state is checked during SDK operations and setup readiness; failures do not create a replacement local state.

Immutable deployment values are:

- Bitcoin network;
- Paykit Pubky client ID;
- Paykit app ID (`paykit-server`).

Changing any of them after database initialization requires resetting the database.
Trusted service keys are credentials rather than immutable deployment identity.
Adding, removing, or replacing allowlisted keys does not alter persisted replay
identity and does not require database reset. During rotation, deploy overlapping
old and new public keys before removing old key. The allowlist is read at startup,
so restart the server after each rotation step: add the new key, switch the signer,
then remove the old key.

Persisted application and schema compatibility across releases is intentionally unsupported during this pre-production phase. The `0.1.0-rc6` Paykit Server and `0.1.0-rc6` Locks rollout is coordinated: stop both services, deploy both versions, then start each service and let its one-time SQLx reset migration clear only its dedicated disposable prototype database while preserving `_sqlx_migrations`. Verify both migrations and services before allowing new invoice or verification work, then reacquire any required prototype state. Do not manually drop/recreate either database. Never run these reset migrations against production, staging, an unidentified database, or a database shared with unrelated applications.

The cryptographic envelope version, domain-separated KDF/AAD labels, and private payload format discriminators remain enforced. They detect unsupported or corrupt bytes; they are not compatibility readers.

## Configuration and secrets

Copy [`config/paykit-server.example.toml`](config/paykit-server.example.toml) to an operator-controlled path. The TOML schema is closed: unknown sections and keys are rejected. Durations are strings such as `"10s"` and `"5m"`.

Configuration rollout is explicit: replace legacy
`locks.trusted_public_key = "pubky..."` with non-empty
`signed_services.trusted_public_keys = ["pubky..."]`. Legacy key is rejected;
there is no compatibility alias that could create two authorities.

Required environment variables:

- `PAYKIT_CONFIG` — path to the TOML file;
- `PAYKIT_DATABASE_URL` — PostgreSQL connection URL;
- `PAYKIT_MASTER_KEY` — unpadded base64url encoding of exactly 32 bytes.

Do not put database credentials or the master key in TOML, logs, shell history, or source control. Effective-config debug output redacts secret values.

Production logging allowlists only the `paykit_server` target at INFO and above. Dependency targets are disabled because upstream diagnostics may contain identities, URLs, or response text.

`POST /invoices` and the Locks-facing `POST /payment-requests/status`,
`POST /connections/status`, and `POST /setup/status` polls emit one coarse
outcome event for each request reaching the application, including admission
rejections. Completed-event fields are HTTP status, elapsed milliseconds, a
closed failure class, and an opaque request ID. Status events also carry a closed
`payment_request_status`, `connection_status`, or `setup_status` operation
label. A request cancelled or unwound before producing a response emits the
same event with failure class `cancelled`, no fabricated HTTP status, and no
response header. Expected status-poll outcomes, including typed dependency
failures and ordinary cancellation, remain DEBUG-only; an unclassified server
error or handler panic is WARN to avoid outage-driven INFO/WARN log storms.
Failures inside these request flows also emit one WARN event at the narrowest
known source. Its closed fields are `operation`, `stage`, `category`, and the
same opaque request ID returned in `X-Request-ID`; raw errors, identities, keys,
signatures, bodies, and URLs are excluded. Outer error mappings are fallback
sites only, so one request emits at most one source-failure warning. When a
source warning was emitted, the coarse completion event remains DEBUG-only.
Locks may supply `X-Request-ID` only as a canonical UUIDv4; other values are ignored
without being echoed or logged, and Paykit Server generates a replacement UUIDv4.
Successful outcomes remain DEBUG-only. A `503` produced by a reverse proxy before the
request reaches Paykit Server cannot produce this application event and must be
diagnosed from proxy telemetry.

`setup.log_authorization_url` defaults to `false` and must remain false for
production. When explicitly enabled in the generated local-demo config, each
new setup flow emits one labeled authorization URL log line for operator
retrieval. The URL is a bearer secret; the local operator owns access to and
retention of those logs.

`rate_limits.setup_per_ip_per_minute` applies to `GET /setup` and
`GET /setup/reconnect` per client IP. With the default `http.trusted_proxy_hops = 0`
that IP is the TCP peer and `X-Forwarded-For` is ignored. Behind a reverse proxy or
load balancer the TCP peer is the proxy, so every client shares one setup bucket.
Set `http.trusted_proxy_hops` to the exact number of proxies in front of the server
that each append one `X-Forwarded-For` entry; the server then uses the entry that
many positions from the right across all header lines, and falls back to the TCP
peer when that entry is missing or not an IP address. Entries further left are
client-supplied and are never used. A value larger than the real proxy count
selects a client-supplied entry, so any client can choose its own bucket and bypass
the limit; only set it when the listener is reachable exclusively through those
proxies. A smaller value keys clients by a proxy address. Values above 8 are rejected.

The parser rejects the retired `[inbox]` section. The executable exposes no payer
inbox API or worker, and the baseline schema contains no payer inbox tables.

`paykit.network = "testnet"` selects the pinned Pubky client's fixed **local** testnet configuration, including the AUTH relay at `http://127.0.0.1:15412/inbox`. It requires the Pubky static testnet on localhost; it is not a hosted public testnet. Native emulators must be able to reach that loopback relay (for example, with Android port reversal). `paykit.network = "mainnet"` uses normal Pkarr/homeserver resolution and the default Pubky AUTH relay. Bitcoin network and Electrum endpoint are configured separately and must agree.

The executable consumes only keys shown in the example. Arbitrary Paykit relay/homeserver URLs are not accepted.

`paykit.client_id` is required and must be exactly `"app.paykit.server"`. It is an
immutable deployment invariant, not an optional label. Missing configuration
fails with the direct error `paykit.client_id is required`.

## Running

With configuration and secrets supplied by an operator-controlled secret manager:

```bash
cargo run -p paykit-server -- --check-config
cargo run -p paykit-server
```

`--check-config` validates the complete TOML, required environment values,
SQLx-supported database URL options, HTTP bind-address syntax, and exact
Electrum endpoint shape including TLS server-name validity,
prints only `configuration valid`, then exits before PostgreSQL connection,
migration, network construction, or HTTP bind. Run it against the exact staged
config and environment before restarting a deployment.

For systemd deployments, gate startup and bound invalid-config restart storms:

```ini
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
ExecStartPre=/usr/local/bin/paykit-server --check-config
ExecStart=/usr/local/bin/paykit-server
Restart=on-failure
RestartSec=5s
```

Both commands must receive the same `PAYKIT_CONFIG`, `PAYKIT_DATABASE_URL`, and
`PAYKIT_MASTER_KEY` environment. Adjust executable path to deployment layout.

Startup fails before bind if configuration, secrets, PostgreSQL, migrations, authenticated persisted state, or immutable deployment values are invalid. Electrum need not be reachable at construction time; its worker reports degraded health and retries.

### Local Locks demo image

`Dockerfile.local` packages this repository for the Locks Compose stack. It
accepts pinned public Git sources or deliberate local-worktree overrides through
named BuildKit contexts, then produces an unprivileged local image containing
the server, the existing reader-demo binary, and the local companion Cargo
example installed as `paykit-companion-auth`.

Build command, image contract, source-rewrite behavior, and generated config contract live in [`docs/local-locks-demo.md`](docs/local-locks-demo.md).

## Health, readiness, metrics, and shutdown

- `GET /health/live` returns `200` with `{ "status": "live" }` while the process serves; it performs no dependency check.
- `GET /health/ready` reports `postgres`, `electrum`, `paykit_delivery`, and `outbox` states. Overall `ready` and `degraded` return `200`; `not_ready` returns `503`.
- PostgreSQL loss is `not_ready`. Electrum or Paykit delivery trouble is `degraded`.
- Shared transport contention retries on the next poll and preserves prior transport health. Actual failures still degrade health, and outstanding undelivered invoices remain unavailable; only a clean pass clears transport failures.
- `GET /metrics` exports identifier-free Prometheus/OpenMetrics data.

Health and metrics do not expose Creator/reader identities, addresses, URLs,
payloads, signatures, credentials, or protocol correlations. Normal production
logs have the same boundary. The sole exception is the explicitly enabled local
demo authorization-URL event described above. Policy rate limiting returns
`429`; exhausted runtime admission returns `503` with `Retry-After: 1`.

Setup completion emits secret-free structured events with
`event="paykit_setup_completion"` and closed `stage`, `outcome`, and `class`
fields. Stages cover AUTH completion, identity/session handling, companion relay
receive, claim verification, xpub validation, setup locking, App Registry
publish/readback, persistence, lock release, and relay ACK. These
events intentionally omit flow IDs, Creator identities, authorization and relay
URLs, sessions, xpubs, payloads, and raw error text; correlate them by timestamp
and request access logs. Closed failure classes preserve typed SDK, registry-data,
and persistence distinctions without formatting their source errors. Pubky's
URL-bearing AUTH relay targets are disabled at every log level; application-owned
setup stages provide the safe replacement diagnostics.

On SIGTERM or SIGINT, readiness changes first, normal admission and new worker claims stop, and admitted work drains for at most `shutdown.drain_timeout`. Remaining work is cancelled at the deadline. Durable leases can be reclaimed after restart; pending memory-only setup flows are lost.

## Invoice and delivery semantics

A successful new invoice transaction atomically allocates an address and persists the Creator/reader assignment, invoice, and complete Payment Request intent. Its terms bind that invoice's address in `payment_endpoints` and require the `paykit-server` app. The request is immediately eligible for handoff without publishing a Private Payment List. Exact replay preserves the address and complete terms; conflicting replay is rejected. Concurrent invoices for the same Reader receive distinct addresses.

The later SDK handoff is not exactly once. Server delivery is at least once:

- a crash before SDK-generated identifiers are durably associated may enqueue another Payment Request with new SDK Event, Payment Request, and outbound-message identifiers;
- consumers must tolerate duplicate proposals and use stable server intent/Payment Reference values where applicable;
- retries preserve the invoice's bound address and terms even when SDK identifiers change;
- marking server work delivered means the exact SDK outbound record reached SDK `Sent`, not that the remote application acknowledged it.

The invoice API returns after durable intent commit. It does not wait for Encrypted Link establishment or remote delivery.

Requests address the Reader identity, not a receiver folder. The Reader's App
Registry must advertise a Noise key and at least one app with `payment_requests`
and `outgoing_payments` enabled. Private Payment List sharing (`private_payments`)
is not required: the invoice includes its payment destination. New
invoice admission reads a cleanly missing registry at most three times, using
full-jitter delays whose combined maximum is one second inside the existing
15-second request deadline. Exhausted clean absence returns `503`
`reader_setup_pending` with the safe message `reader wallet setup needed` and
no `Retry-After` header; a present but incapable registry returns terminal `409`
`reader_not_payable`. Transport/read failures return `503`
`reader_registry_unavailable`, malformed or oversized registry data returns
`502` `reader_registry_malformed`, and request-wide exhaustion remains `503`
`dependency_timeout`. Invalid Reader identifiers return `400` `invalid_request`
before discovery; malformed remote registry data remains a distinct `502`.
These failures occur before xpub loading, address allocation, invoice
persistence, or outbox insertion. Exact replay is checked first and returns its
existing invoice without live registry discovery.

Locks caller policy is code-specific, not status-class-wide. Its backend may
retry `reader_setup_pending` and `reader_registry_malformed` only within the
original fixed 10-minute invoice-admission deadline; retries must never extend
that deadline. `reader_not_payable` is terminal. Marketplace UI must surface
`Reader wallet setup needed` immediately for `reader_setup_pending`, even while
bounded backend retries remain possible, and provide an explicit wallet-setup
or user retry action instead of rendering generic `Paykit unavailable` or
automatically following `503` responses. This UI mapping and retry orchestration
are a required Marketplace-repository follow-up; they are not implemented here.
Readers resolve each Payment Request by ID through the SDK request-aware resolver.
Bound destinations have no Payment List version and never fall back to mutable
private or public lists. Another invoice or app cannot replace the destination.

## Bitcoin settlement semantics

Each invoice accepting Bitcoin receives a unique BIP84 external-chain address. Observation uses the configured `bdk_electrum` adapter and persists complete validated batches atomically.

- Outputs are evaluated independently; split or multi-output payments are not aggregated.
- A single amount-matched output is sufficient for the factual amount match.
- An underpaying output remains a replaceable factual underpayment at every confirmation depth.
- A one-confirmation amount-matched output is frozen against replacement while monitoring continues.
- At six confirmations, an amount-matched output becomes final with stored/reported confirmation count exactly `6`, and Bitcoin monitoring for that invoice stops.
- Overpayment is factual but has no credit/refund workflow.
- Reorg handling is supported before finality; uncommon repair after six-confirmation finality is unsupported.

The server has no Bitcoin spending keys and cannot spend, refund, or create change.

`POST /transactions/status` exposes only the persisted Bitcoin observation without request lifecycle details. USDT payments do not populate this Bitcoin-only response. Its closed `status` vocabulary is `undetected`, `detected`, and
`confirmed`; Payment Request lifecycle never changes those labels.

`POST /payment-requests/status` is the canonical Locks lifecycle contract. It
exposes request lifecycle, payment state and invoice timestamps, with independent
`bitcoin` and `usdt_arbitrum` observations. Each is `null` when no current payment
is observed on that rail. An observation includes `confirmations`, `amount_matched`
and `paid_on_time`; the last requires a full payment within the inclusive invoice
payment window. Arbitrum additionally reports `finalized` from the verified
canonical receipt and the RPC finalized block. Amounts and confirmation counts
are never combined across rails.

`payment_state: confirmed` means a payment is included in a block, not that it
meets Locks' settlement policy. Locks must check the request lifecycle, then
choose a qualifying observation (`amount_matched` and `paid_on_time`) and apply
its Bitcoin confirmation or Arbitrum finality policy to that observation. A large
Arbitrum L2 block count does not substitute for Bitcoin confirmations or Arbitrum
finality. When both assets are paid, both observations remain available.

Deploy this contract together with the matching Locks consumer.

Before returning status, the server performs linked-peer
receive, exact required-target freshness checks, Creator-local SDK mutation
serialization, and transactional target revalidation. Missing, partial,
unrelated, or failed required-peer intake returns unavailable. Exact terminal
response fixtures for Locks are published under
`docs/fixtures/payment-request-status/`.

## Payer, proof, and receipt exclusions

The server receives and durably projects Paykit Payment Request acceptance, rejection, proof, and cancellation records from the identity's shared SDK state. It exposes no payer inbox or proof-submission API. Direct invoice-address observation remains the only Bitcoin payment-attribution input; Paykit Server never decides Locks access.

Paykit Receipt issuance, Receipt Access delivery, and receipt storage are unsupported.

## Retention and data lifecycle

There is no payload-retention or pruning contract, retention worker, runtime idle eviction, or SDK compaction contract. Operators must treat encrypted Creator, SDK, invoice, assignment, outbox, internal relay, and Bitcoin observation records as retained according to current database/SDK behavior. Any deletion policy requires a separate product and migration decision.

### Backup and recovery

Back up the whole PostgreSQL database as one consistent snapshot, including
deployment metadata, Creator credentials and address counters, assignments,
invoices, observations, outbox, and internal relay records.

Encrypted identity-wide SDK state lives on each Creator's homeserver, not in
PostgreSQL. A database backup does not include it, and public homeserver files
alone are not a backup of it. Any separately retained SDK backup contains private
state and must be encrypted and access-controlled. The server does not create a
coordinated database-and-homeserver backup.

Keep the matching `PAYKIT_MASTER_KEY` recoverable in the deployment secret store,
separately from database dumps. The database alone cannot decrypt its records.
Also retain the deployment configuration and exact server release/commit and
`Cargo.lock`: SDK state decoding depends on the pinned Paykit version. Restrict
access to backup files and never include credentials in logs or support bundles.

Test recovery into a separate database with the original release, key, and
deployment configuration. Block outbound network access and do not direct Locks
traffic to the test instance: a running server starts delivery workers. Startup
checks deployment invariants and authenticates Creator credentials and encrypted
payment records before binding. Hosted SDK state is checked by
SDK operations, not database startup. `--check-config` alone does not read or
verify stored data. Confirm record counts and address counters as well;
successful startup does not prove the backup is complete or the hosted state
is usable.

For a live recovery, stop the old instance before starting its replacement.
Other authorized apps can still change hosted state while the server is stopped.
Do not reset a database or generate a new master key to bypass a decode or
integrity failure; retain the original data and investigate with its matching
release. Restoring an older snapshot is not automatically safe to resume:
addresses may have been allocated, invoices paid, or Noise messages sent since
the snapshot. Those differences need reconciliation before delivery resumes to
avoid address reuse, duplicate requests, or stale Encrypted Link state. Backup
preservation does not implement that reconciliation. Do not overwrite current
hosted state with an older blob; coordinate recovery with the identity owner and
other authorized apps through the SDK's recovery flow.

## Known limitations

- One process only; no replicas or active-active deployment.
- One Electrum endpoint; no failover pool.
- `tcp://` Electrum has no transport authentication; use a CA-valid `ssl://` endpoint for production.
- No configured Creator-count bound or runtime eviction.
- One xpub/account index per Creator; no xpub, account, master-key, or immutable-invariant rotation.
- BTC and optional direct USDT0 on Arbitrum One, with fixed denomination conversion; no bridging or asset swaps.
- No public payer inbox or proof-submission API, and no receipt issuance.
- No spending custody, refunds, credits, or change.
- No output aggregation and no deep-reorg repair after finality.
- No retention/pruning contract.
- Shared-state safety inherits the pinned SDK's homeserver lock contract and pending-write cooldown. The cooldown does not guarantee safety if a stale homeserver write finalizes after lock ownership is lost.
- Live Pubky evidence uses a local static testnet, not a remote production homeserver or the complete Bitkit user-approval journey.
- Live Electrum evidence proves one exact mainnet Fulcrum snapshot over plaintext protocol; it is not a production TLS endorsement.

## Direct USDT0 invoices

Enable `[usdt]` with `rpc_url` in the operator config to request optional USDT
sharing and verify Arbitrum One receipts. Without it, the service requests only
Bitcoin receiving details and rejects new USDT invoices. RPC credentials stay on
the server. A standard Arbitrum JSON-RPC endpoint must support `eth_chainId`,
`eth_getTransactionReceipt`, `eth_getBlockByNumber` (including `finalized`) and
`eth_blockNumber`; archive history scanning is unnecessary.

Setup requests the existing Bitcoin account plus `usdt-address-v1`. The user can
skip USDT without blocking Bitcoin. Reconnect can add a previously omitted USDT
address but cannot change an already-approved address or Bitcoin account.
Signed `POST /setup/status` accepts optional `asset: "BTC"`, `"USD"`, or `"USDT"`
and returns the existing `{status}` response for that denomination. Omitting `asset`
checks Pubky/Paykit authority only. Locks should check the selected asset before
publishing a priced lock.

Payment criteria use integer units: satoshis for `BTC`, cents for `USD`, and
millionths for `USDT`. For example, `asset: "USD", amount: "500"` requests $5.
Each request includes every enabled receiving option approved by the creator: a
unique Bitcoin address and/or the shared Arbitrum address, chain 42161, and token
`0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9`. Requests require the `paykit-server`
receiving app. A payer with both options can choose either; this changes the
payment asset, not the requested value.

BTC conversions use Bitkit's feed, `https://api1.blocktank.to/api/fx/rates/btc`.
Only a positive BTC/USD price timestamped within the past ten minutes is accepted.
USD and USDT use fixed 1:1 parity. Published rates are payment-asset units per
requested unit; reciprocal BTC rates round half-even to 18 decimal places. The
required payment rounds up to whole satoshis or millionths of USDT. Fees are
additional. The exact published rates and both destinations are encrypted with
the invoice and reused for delivery, replay, restart, and settlement verification.
The server does not reprice a received payment at the current market rate.

`paykit.conversion_payment_window` defaults to `"1h"` for invoices offering BTC
conversion, capped by `paykit.payment_window`. Acceptance is capped at half the
resulting payment window, leaving time to pay. Same-asset and USD/USDT-only
invoices retain the ordinary configured windows. Unavailable or stale market
rates prevent creation of a new BTC conversion quote, but do not block exact
invoice replay, settlement, or payments that need no BTC rate.

Either full, timely payment can satisfy the invoice. Partial payments are not
combined across assets. Reconciliation on one chain cannot erase a qualifying
payment on the other; reorgs recompute the result from both observations.

The existing SDK receive loop reconciles `erc20-transfer-eip712` proofs. The
server verifies the request-bound sender signature, successful canonical receipt,
exact token, recipient and receipt-relative Transfer event. A single transfer must
cover the full amount; split payments are not aggregated. Underpayments and late
payments remain received funds but do not satisfy the invoice. Payment time comes
from the canonical block timestamp (second precision), within the invoice window.
An RPC outage leaves the last observation intact and returns unavailable when a
fresh status is required. Non-final observations are rechecked for reorgs; finalized
observations stop polling. Chain identity, head and finality reads share a five-second
snapshot across payments. Receipts and their canonical blocks are verified afresh;
a receipt newer than the cached head immediately refreshes the snapshot. Background
checks of detected transfers run at most once per minute, with the last successful
check stored across restarts. New or missing transfers retain the normal receive-loop
cadence. Explicit checkout status checks bypass this background delay. The chain/hash/receipt-index identity is durably unique
across invoices, including restarts. Confirmations are Arbitrum L2 block counts;
Locks must choose an asset-appropriate acceptance policy, not assume Bitcoin timing.

No public transaction-hash submission API is added. Proofs must arrive through the
SDK's authenticated request flow. Address sharing is not proof of a purchase.
The Locks creator/payment UI must offer the denominations and receiving-option
readiness check before an end-to-end Locks checkout can be enabled.

### Draining USDT-capable locks

A timely full payment in either asset advances the existing payment drain. This
means the invoice no longer requires waiting for a payment, not that Locks may
grant access. Drain cleanup retains invoices, lifecycle records and both chains'
observations. Locks must finish its per-bundle status verification using the
appropriate settlement policy, including reorg handling before finality. A late
payment in one asset cannot hide an on-time payment in the other when its proof
arrives later. No refunds or conflict-resolution workflow is introduced.
