# Live adapter smoke tests

These two tests are ignored by default. Normal PostgreSQL E2E tests use ephemeral
Pubky testnets; the tests here require separately operated infrastructure. A
passing deterministic suite does not establish external interoperability.

## Pubky App Registry and Payment Request

Use a local static Pubky testnet compatible with the pinned `pubky` and
`pubky-testnet` 0.15.0 dependencies, with Pubky Homeserver 0.15 or newer. It must
expose the SDK's fixed localhost testnet ports. Upgrading client dependencies
does not upgrade a separately operated homeserver.
Do not run against a retained integration fixture without its
operator's approval: this test creates identities and sends a test Payment Request.

```bash
cargo test --locked -p paykit-server-e2e --test live_adapters \
  live_pubky_registry_discovery_and_payment_request_delivery \
  -- --ignored --exact --nocapture
```

The test publishes App Registry entries, discovers a capable app, establishes an
Encrypted Link, and delivers a Payment Request. The peer resolves its immutable
destination by request ID with no Payment List version. It does not execute a
Bitcoin payment or cover the mobile companion-approval UI.

## Electrum observation

Supply a known existing output, not a new payment:

```bash
export PAYKIT_LIVE_ELECTRUM_ENDPOINT='ssl://<host>:<port>'
export PAYKIT_LIVE_BITCOIN_NETWORK='mainnet'
export PAYKIT_LIVE_BITCOIN_ADDRESS='<address>'
export PAYKIT_LIVE_BITCOIN_TXID='<transaction-id>'
export PAYKIT_LIVE_BITCOIN_VOUT='<output-index>'
export PAYKIT_LIVE_BITCOIN_SATS='<output-value>'
export PAYKIT_LIVE_MIN_CONFIRMATIONS='1'

cargo test --locked -p paykit-server-e2e --test live_adapters \
  live_electrum_observes_known_output_and_confirmations \
  -- --ignored --exact --nocapture
```

The production BDK Electrum adapter must return the exact outpoint and value as
present with at least the requested confirmation count. Other address history is
allowed. Use a TLS certificate valid for the configured hostname. Plaintext
`tcp://` provides neither endpoint authentication nor transport confidentiality;
there is no failover pool.

Record the server revision, dependency versions, environment, command, and outcome
outside the repository when running either smoke test. Historical runs against
older dependency versions are not evidence for this integration.
