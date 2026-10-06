# Paykit Server

A PostgreSQL-backed, receiver-side Paykit prototype for Locks invoice workflows. It derives and observes a direct invoice-specific Bitcoin address. It does not use payer identity, payer inbox messages, or payment-proof messages to attribute payment.

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
credential ownership, and immutable invoice attribution. Rust dependencies use
the published Paykit Git tag `v0.1.0-rc59`, pinned by `Cargo.lock`.

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

Business-route signatures use the configured trusted Locks Ed25519 key. Setup uses the Bitkit Pubky Auth companion-claim flow and an exact configured browser origin.

Successful invoice creation and exact replay return `200 OK` with only RFC 3339
`invoice_created_at` and `payment_deadline` timestamps; they do not expose Noise
state. `POST /connections/status` is the separate read-only lookup. Its closed
body is `{"bundle_id":"...","creator":"pubky..."}`. Paykit Server derives
the exact Reader identity from persisted invoice state, then returns
`{"state":"none|handshake|connected|recovery_required|blocked"}`. Unknown
invoices return `404`; authentication, storage, malformed-state, and dependency
failures remain typed errors. `connected` is the identity's shared Noise state,
not payment or verification completion.

`POST /setup/status` is the Locks-only readiness check for an authenticated Creator. Its closed canonical body is `{"creator":"pubky..."}`. Every signed route verifies Ed25519 over `b"paykit-http-signature-v1\0" + uppercase_method + b"\0" + exact_query_free_path + b"\0" + exact_raw_body`; there is no body-only fallback. It returns exactly one coarse state: `ready` when the persisted session, delegated key, App Registry entry, and hosted state are usable; `setup_required` when authority is absent or confirmed invalid; and `unavailable` for validation timeouts and storage, rate-limit, server, DNS, or transport failures. Untyped Pubky 401 responses are also `unavailable`: they cannot distinguish revoked grants from recoverable PoP failures. A revoked grant reported this way requires explicit reconnect. Callers must not convert `unavailable` into a new authorization flow.

### Setup iframe

`GET /setup` is the production Bitkit setup surface. On desktop it renders the
normal secret-bearing Pubky Auth request as a QR code; on touch devices it
offers the same request through a `Continue with Bitkit` deep link. Production
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

Bitkit authorizes `/pub/paykit/:rw`. The server requests two independent
permissions as `x-bitkit-claim=paykit-access-v1.watch-only-account-v1` and Bitkit
returns a signed, encrypted companion claim. Its 124-byte payload contains the BIP84
account index, address kind, serialized xpub, Paykit key generation, and 32-byte
Paykit identity secret; the signature adds 64 bytes. The server verifies the
delegated key against the Creator's App Registry, persists credentials, then
publishes only the `paykit-server` app entry through the SDK. Other apps and
shared history remain intact. Failed publication leaves setup incomplete and
retryable. Reauthorization preserves the account/xpub and accepts only the same
key or a newer generation. The server never receives the Pubky root secret or
Bitcoin spending keys.

Initial setup requires both permissions. The exact received list order binds the
SDK signature and relay channel; the 124-byte payload always puts watch-only
account bytes before Paykit key material regardless of list order. Empty,
duplicate, unknown, or one-only selections fail setup.
Reconnect uses `GET /setup/reconnect?creator=pubky...&return_to=...&state=...`.
The server requires an existing Creator and requests only `paykit-access-v1`
(41 unsigned bytes). The AUTH identity must match that exact Creator; the xpub
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
- encrypted invoices, assignments, outbox work, and Bitcoin observations.

Different Creators may use the same numeric child index because their xpubs and derivation sequences are isolated. There is no configured Creator-count limit, but all loaded runtimes remain cached until process exit; practical cardinality is therefore bounded by process and database capacity.

## Persistence, startup, and upgrades

PostgreSQL stores server credentials, address allocation, invoices, and delivery intents. The Paykit SDK stores encrypted identity-wide state on the Creator's homeserver under WebDAV locks; it is not cached as an authoritative PostgreSQL SDK blob. Other authorized apps can advance the same links and delivery queue. A background worker receives private messages and processes outbound work without executing wallet payments.

Startup holds a session advisory lock while applying the single schema baseline. Before binding HTTP it verifies immutable deployment metadata and authenticates every persisted Creator credential, invoice payment record, and Bitcoin observation. Missing, corrupt, swapped, conflicting, or wrong-key database state aborts startup with a secret-free error. Hosted Paykit state is checked during SDK operations and setup readiness; failures do not create a replacement local state.

Immutable deployment values are:

- Bitcoin network;
- Paykit Pubky client ID;
- Paykit app ID (`paykit-server`);
- trusted Locks public-key fingerprint.

Changing any of them after database initialization requires resetting the database.

Persisted application and schema compatibility across releases is intentionally unsupported during this pre-production phase. The `0.1.0-rc6` Paykit Server and `0.1.0-rc6` Locks rollout is coordinated: stop both services, deploy both versions, then start each service and let its one-time SQLx reset migration clear only its dedicated disposable prototype database while preserving `_sqlx_migrations`. Verify both migrations and services before allowing new invoice or verification work, then reacquire any required prototype state. Do not manually drop/recreate either database. Never run these reset migrations against production, staging, an unidentified database, or a database shared with unrelated applications.

The cryptographic envelope version, domain-separated KDF/AAD labels, and private payload format discriminators remain enforced. They detect unsupported or corrupt bytes; they are not compatibility readers.

## Configuration and secrets

Copy [`config/paykit-server.example.toml`](config/paykit-server.example.toml) to an operator-controlled path. The TOML schema is closed: unknown sections and keys are rejected. Durations are strings such as `"10s"` and `"5m"`.

Required environment variables:

- `PAYKIT_CONFIG` — path to the TOML file;
- `PAYKIT_DATABASE_URL` — PostgreSQL connection URL;
- `PAYKIT_MASTER_KEY` — unpadded base64url encoding of exactly 32 bytes.

Do not put database credentials or the master key in TOML, logs, shell history, or source control. Effective-config debug output redacts secret values.

Production logging allowlists only the `paykit_server` target at INFO and above. Dependency targets are disabled because upstream diagnostics may contain identities, URLs, or response text.

`setup.log_authorization_url` defaults to `false` and must remain false for
production. When explicitly enabled in the generated local-demo config, each
new setup flow emits one labeled authorization URL log line for operator
retrieval. The URL is a bearer secret; the local operator owns access to and
retention of those logs.

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
Registry must advertise a private-payment app capable of paying requests. When
the Reader's homeserver answers with no App Registry, or with one lacking a Noise
key or such an app, a new invoice returns `409` with code `reader_not_payable`
before any address allocation or persistence. Repeating the request cannot
succeed until the Reader publishes a capable app. Registry read failures and
timeouts remain `503` `dependency_unavailable` and `dependency_timeout`.
Readers resolve each Payment Request by ID through the SDK request-aware resolver.
Bound destinations have no Payment List version and never fall back to mutable
private or public lists. Another invoice or app cannot replace the destination.

## Bitcoin settlement semantics

Each invoice receives a unique BIP84 external-chain address. Observation uses the configured `bdk_electrum` adapter and persists complete validated batches atomically.

- Outputs are evaluated independently; split or multi-output payments are not aggregated.
- A single amount-matched output is sufficient for the factual amount match.
- An underpaying output remains a replaceable factual underpayment at every confirmation depth.
- A one-confirmation amount-matched output is frozen against replacement while monitoring continues.
- At six confirmations, an amount-matched output becomes final with stored/reported confirmation count exactly `6`, and monitoring for that invoice stops.
- Overpayment is factual but has no credit/refund workflow.
- Reorg handling is supported before finality; uncommon repair after six-confirmation finality is unsupported.

The server has no Bitcoin spending keys and cannot spend, refund, or create change.

`POST /transactions/status` remains the legacy Bitcoin-only compatibility
endpoint. Its closed `status` vocabulary is `undetected`, `detected`, and
`confirmed`; Payment Request lifecycle never changes those labels.

`POST /payment-requests/status` is the canonical Locks lifecycle contract. It
exposes request lifecycle, payment state, invoice timestamps, confirmations, and
amount matching as separate facts. Before returning them, it performs linked-peer
receive, exact required-target freshness checks, Creator-local SDK mutation
serialization, and transactional target revalidation. Missing, partial,
unrelated, or failed required-peer intake returns unavailable. Exact terminal
response fixtures for Locks are published under
`docs/fixtures/payment-request-status/`.

## Payer, proof, and receipt exclusions

The server receives and durably projects Paykit Payment Request acceptance, rejection, proof, and cancellation records from its local SDK state. It exposes no payer inbox or proof-submission API. Direct invoice-address observation remains the only Bitcoin payment-attribution input; Paykit Server never decides Locks access.

Paykit Receipt issuance, Receipt Access delivery, and receipt storage are unsupported.

## Retention and data lifecycle

There is no payload-retention or pruning contract, retention worker, runtime idle eviction, or SDK compaction contract. Operators must treat encrypted Creator, SDK, invoice, assignment, outbox, internal relay, and Bitcoin observation records as retained according to current database/SDK behavior. Any deletion policy requires a separate product and migration decision.

## Known limitations

- One process only; no replicas or active-active deployment.
- One Electrum endpoint; no failover pool.
- `tcp://` Electrum has no transport authentication; use a CA-valid `ssl://` endpoint for production.
- No configured Creator-count bound or runtime eviction.
- One xpub/account index per Creator; no xpub, account, master-key, or immutable-invariant rotation.
- BTC only; no other assets.
- No payer inbox/proofs or receipt workflows.
- No spending custody, refunds, credits, or change.
- No output aggregation and no deep-reorg repair after finality.
- No retention/pruning contract.
- Shared-state safety inherits the pinned SDK's homeserver lock contract and pending-write cooldown. The cooldown does not guarantee safety if a stale homeserver write finalizes after lock ownership is lost.
- Live Pubky evidence uses a local static testnet, not a remote production homeserver or the complete Bitkit user-approval journey.
- Live Electrum evidence proves one exact mainnet Fulcrum snapshot over plaintext protocol; it is not a production TLS endorsement.
