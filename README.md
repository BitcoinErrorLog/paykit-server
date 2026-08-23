# Paykit Server

## This fork: Pubky Marketplace project

This is `BitcoinErrorLog/paykit-server` (branch `marketplace-rails`), a fork
of the official [`pubky/paykit-server`](https://github.com/pubky/paykit-server)
used by the Pubky Marketplace's deployed payment rails
(`BitcoinErrorLog/pubky-payment-rails`). No upstream PRs are filed while the
protocol shape settles.

**Added over upstream:**

- **Signed marketplace payment requests**: a payment-request route
  authenticated exactly like `/invoices` (canonical JSON body, single
  `x-paykit-signature` header), whose expected signer is the marketplace
  transaction service — configured via the optional `marketplace`
  trust-anchor config (`marketplace.trusted_public_key`). This is how the
  service requests receiver-side invoices for physical-bitcoin orders
  without ever holding wallet material.
- **Manual watch-only claims**: a companion-claim path used by the composed
  test environment and the live Bitkit wallet-leg proof.

**Fixes:** endpoint identifiers and JSON payloads are advertised
network-correct (and the e2e workflow/reader-demo assertions validate
spec-correct payloads as JSON values rather than strings).

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

The two live-adapter tests remain ignored by default because they require either a local Pubky Core static testnet or a recorded public Electrum fixture. See [`docs/live-adapter-smoke.md`](docs/live-adapter-smoke.md) before running them explicitly.

Before submitting changes, read [`CONTRIBUTING.md`](CONTRIBUTING.md). Report security problems through the private process in [`SECURITY.md`](SECURITY.md), not a public issue.

## Executable boundary

`paykit-server` composes and supervises the production HTTP routes, Paykit delivery workers, and BDK Electrum observer in one process.

Public operational routes:

- `GET /health/live`
- `GET /health/ready`
- `GET /metrics`

Business routes:

- `GET /setup`
- `POST /setup/{flow_id}/complete`
- signed `POST /invoices`
- signed `POST /transactions/status`

Invoice/status signatures use the configured trusted Locks Ed25519 key. Setup uses the Bitkit Pubky Auth companion-claim flow and an exact configured browser origin.

### Setup iframe

`GET /setup` renders the Paykit auth URL and this local approval command instead of automatically navigating the iframe:

```bash
docker compose exec creator-demo npm --prefix examples/js-sdk run authenticate-paykit -- --role content-creator
```

The iframe continues polling `POST /setup/{flow_id}/complete`. It does not receive, store, post, or log an xpub, and there is no manual claim route. Completion posts only `{ type: "paykit-setup-callback", state }` or the same callback with a coarse error to the exact caller origin.

`paykit-companion-auth` accepts one closed version-1 JSON object on stdin with `auth_url`, a base64url 32-byte `creator_secret`, `account_xpub`, and `account_index`. It rejects missing or unknown fields and unsupported versions. Success stdout is exactly `{"version":1,"status":"approved"}\n`; failures remain coarse and do not echo input.

The composed PostgreSQL workflow is tested with two independent Creators across restart. Live adapter evidence covers a separate local Pubky relay/homeserver process and one public mainnet Fulcrum endpoint; see [`docs/live-adapter-smoke.md`](docs/live-adapter-smoke.md). Those checks bound interoperability to the recorded versions and environments rather than claiming compatibility with every provider.

## Deployment model and Creator cardinality

Run exactly **one Paykit Server process** for a deployment. Horizontal replicas and active-active operation are unsupported because setup flows are memory-only and Creator SDK runtimes are process-cached. PostgreSQL locks, constraints, and leases provide concurrency control and crash recovery inside this one-process model, not multi-replica coordination.

One process may own multiple Creator accounts. Each Creator has independent:

- Pubky identity/session and receiver Noise key;
- one BIP84 account xpub and hardened account index;
- external-chain address derivation counter;
- Paykit SDK state and Encrypted Links;
- encrypted invoices, assignments, outbox work, and Bitcoin observations.

Different Creators may use the same numeric child index because their xpubs and derivation sequences are isolated. There is no configured Creator-count limit, but all loaded runtimes remain cached until process exit; practical cardinality is therefore bounded by process and database capacity.

## Persistence, startup, and upgrades

PostgreSQL is the only production persistence backend. SQLite and in-memory adapters are test support only.

Startup holds a session advisory lock while applying the single schema baseline. Before binding HTTP it verifies immutable deployment metadata and authenticates every persisted Creator credential, SDK-state envelope, invoice payment record, and Bitcoin observation. Missing, corrupt, swapped, conflicting, or wrong-key state aborts startup with a secret-free error.

Immutable deployment values are:

- Bitcoin network;
- Paykit receiver path;
- trusted Locks public-key fingerprint.

Changing any of them after database initialization requires resetting the database.

Persisted application and schema compatibility across releases is intentionally unsupported during this pre-production phase. When an upgrade changes the baseline migration or a persisted payload representation:

1. stop the old process;
2. discard and recreate the Paykit Server database;
3. start the new binary so it applies the current baseline.

The cryptographic envelope version, domain-separated KDF/AAD labels, and private payload format discriminators remain enforced. They detect unsupported or corrupt bytes; they are not compatibility readers.

## Configuration and secrets

Copy [`config/paykit-server.example.toml`](config/paykit-server.example.toml) to an operator-controlled path. The TOML schema is closed: unknown sections and keys are rejected. Durations are strings such as `"10s"` and `"5m"`.

Required environment variables:

- `PAYKIT_CONFIG` — path to the TOML file;
- `PAYKIT_DATABASE_URL` — PostgreSQL connection URL;
- `PAYKIT_MASTER_KEY` — unpadded base64url encoding of exactly 32 bytes.

Do not put database credentials or the master key in TOML, logs, shell history, or source control. Effective-config debug output redacts secret values.

The parser rejects the retired `[inbox]` section. The executable exposes no payer
inbox API or worker, and the baseline schema contains no payer inbox tables.

`paykit.network = "testnet"` selects the pinned Pubky client’s fixed **local** testnet configuration. It requires the Pubky Core static testnet on localhost; it is not a hosted public testnet. `paykit.network = "mainnet"` uses normal Pkarr/homeserver resolution. Bitcoin network and Electrum endpoint are configured separately and must agree.

The executable consumes only keys shown in the example. Arbitrary Paykit relay/homeserver URLs are not accepted.

## Running

With configuration and secrets supplied by an operator-controlled secret manager:

```bash
cargo run -p paykit-server
```

Startup fails before bind if configuration, secrets, PostgreSQL, migrations, authenticated persisted state, or immutable deployment values are invalid. Electrum need not be reachable at construction time; its worker reports degraded health and retries.

### Local Locks demo image

`Dockerfile.local` packages this repository for sibling Locks Compose stack. It consumes checked-out Paykit Rust and Locks trees through named BuildKit contexts, then produces unprivileged local image containing server and helper binaries.

Build command, image contract, source-rewrite behavior, and generated config contract live in [`docs/local-locks-demo.md`](docs/local-locks-demo.md).

## Health, readiness, metrics, and shutdown

- `GET /health/live` returns `200` with `{ "status": "live" }` while the process serves; it performs no dependency check.
- `GET /health/ready` reports `postgres`, `electrum`, `paykit_delivery`, and `outbox` states. Overall `ready` and `degraded` return `200`; `not_ready` returns `503`.
- PostgreSQL loss is `not_ready`. Electrum or Paykit delivery trouble is `degraded`.
- `GET /metrics` exports identifier-free Prometheus/OpenMetrics data.

Health, metrics, and logs do not expose Creator/reader identities, addresses, URLs, payloads, signatures, credentials, or protocol correlations. Policy rate limiting returns `429`; exhausted runtime admission returns `503` with `Retry-After: 1`.

On SIGTERM or SIGINT, readiness changes first, normal admission and new worker claims stop, and admitted work drains for at most `shutdown.drain_timeout`. Remaining work is cancelled at the deadline. Durable leases can be reclaimed after restart; pending memory-only setup flows are lost.

## Invoice and delivery semantics

A successful new invoice transaction atomically persists the Creator/reader assignment, invoice, complete endpoint-publication intent, complete dependent Payment Request intent, and address allocation. Exact replay preserves that durable result; conflicting replay is rejected.

The later SDK handoff is not exactly once. Server delivery is at least once:

- a crash before SDK-generated identifiers are durably associated may enqueue another Payment Request with new SDK Event, Payment Request, and outbound-message identifiers;
- consumers must tolerate duplicate proposals and use stable server intent/Payment Reference values where applicable;
- Private Payment List is latest-state data, so identical re-enqueue supersedes safely;
- marking server work delivered means the exact SDK outbound record reached SDK `Sent`, not that the remote application acknowledged it.

The invoice API returns after durable intent commit. It does not wait for Encrypted Link establishment or remote delivery.

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

## Payer, proof, and receipt exclusions

The server does not process payer-originated acceptance, rejection, cancellation, inbox, or payment-proof events. It exposes no payer inbox and no proof-submission API. Direct invoice-address observation is the only payment-attribution input.

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
- Live Pubky evidence uses a local static testnet, not a remote production homeserver or the complete Bitkit user-approval journey.
- Live Electrum evidence proves one exact mainnet Fulcrum snapshot over plaintext protocol; it is not a production TLS endorsement.
