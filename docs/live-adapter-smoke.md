# Live adapter smoke tests

This runbook exercises the external adapter boundaries that normal tests keep deterministic. The tests are ignored by default because they require a separately running Pubky stack or public Electrum service.

## Evidence snapshot

Executed at `2026-07-22T22:53:00Z` from Paykit Server commit `10fd260200e27eb71a8e9e417310f0469df1b713` plus the Task 11 worktree.

Pinned/runtime versions:

- Rust/Cargo `1.91.1`
- Docker `29.6.2`
- `paykit-lib` and `paykit-sdk` `0.1.0-rc37`, Git revision `81fd0e5124aac1fd782811fd968109a5972cd323`
- Paykit dependency `pubky` `0.8.0`
- local Pubky Core static testnet `0.9.3`, Git revision `51db89744f97e33486a5e5aedf442b7e2f9b51c2`
- `electrum-client` `0.25.0` (the adapter uses it directly; the earlier `bdk_electrum` `0.24.0` dependency was removed)
- public Electrum server reported `Fulcrum 1.11.1`, protocol `1.4`

The snapshot proves interoperability only for these versions and environments. It is not a compatibility claim for arbitrary homeservers, relays, Electrum implementations, or future dependency versions.

## Pubky marker and Payment Request smoke

This test signs up two temporary identities, publishes both receiver markers, discovers the payee marker through public storage, establishes an Encrypted Link, proposes and sends one Payment Request, receives it on the peer, and verifies the SDK-derived request identity.

The static testnet uses fixed localhost ports and homeserver identity documented by Pubky Core. It needs the sibling Pubky Core checkout at the exact recorded revision and a PostgreSQL server. From the Paykit Server repository:

```bash
set -euo pipefail

pubky_dir=../../Pubky/pubky-core
required_pubky_revision=51db89744f97e33486a5e5aedf442b7e2f9b51c2
test "$(git -C "$pubky_dir" rev-parse HEAD)" = "$required_pubky_revision"
test -z "$(git -C "$pubky_dir" status --porcelain)"

name=paykit-live-pubky-postgres
postgres_image='postgres@sha256:e013e867e712fec275706a6c51c966f0bb0c93cfa8f51000f85a15f9865a28cb'
docker run --rm -d --name "$name" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  -p 127.0.0.1::5432 "$postgres_image"
port=$(docker port "$name" 5432/tcp | sed 's/.*://')

cd "$pubky_dir"
TEST_PUBKY_CONNECTION_STRING="postgres://postgres:postgres@127.0.0.1:${port}/postgres?pubky-test=true" \
  cargo run -p pubky-testnet
```

Wait for `Testnet running`. In another shell, from the Paykit Server repository:

```bash
cargo test -p paykit-server-e2e --test live_adapters \
  live_pubky_marker_discovery_and_payment_request_delivery \
  -- --ignored --exact --nocapture
```

Expected aggregate output:

```text
live Pubky smoke: 1 marker discovered, 1 Payment Request sent, 1 Payment Request received
test result: ok. 1 passed; 0 failed
```

Stop the testnet with Ctrl+C, then remove PostgreSQL if needed:

```bash
docker rm -f paykit-live-pubky-postgres
```

Observed result: passed in 9.16 seconds against the separate local relay/homeserver process. This proves the SDK transport path, not the complete Bitkit Pubky Auth companion-claim user journey or a remote production homeserver.

## Electrum observation smoke

The test requires one known output and verifies that the production BDK Electrum adapter returns the exact outpoint and satoshi value as present with at least the requested confirmation count. The address may have other history; the adapter correctly returns all matching outputs, and the test locates the exact outpoint.

Evidence command:

```bash
export PAYKIT_LIVE_ELECTRUM_ENDPOINT='tcp://fulcrum-core.1209k.com:50001'
export PAYKIT_LIVE_BITCOIN_NETWORK='mainnet'
export PAYKIT_LIVE_BITCOIN_ADDRESS='bc1qeppj9d8lh4t5s8ku7uccmsc0yvrhtjgjpv0gh3'
export PAYKIT_LIVE_BITCOIN_TXID='624be4762e607da45bad8634260021f7da9cea916e36a6f60649ac1e801fe1ec'
export PAYKIT_LIVE_BITCOIN_VOUT='0'
export PAYKIT_LIVE_BITCOIN_SATS='900000'
export PAYKIT_LIVE_MIN_CONFIRMATIONS='1'

cargo test -p paykit-server-e2e --test live_adapters \
  live_electrum_observes_known_output_and_confirmations \
  -- --ignored --exact --nocapture
```

Observed output at the snapshot time:

```text
live Electrum smoke: known output observed with 2 confirmations in 399 address-history outputs
test result: ok. 1 passed; 0 failed
```

The run took 114.87 seconds. Confirmation count and address-history length can increase, so the durable assertion is a minimum count and exact outpoint/value match.

### Electrum transport limitations observed

- `ssl://fulcrum-core.1209k.com:50002` spoke Electrum but presented a self-signed certificate with no Subject Alternative Name. The production Rust client rejected it as `Unavailable`; raw OpenSSL success without certificate verification is not acceptable evidence.
- Plaintext port `tcp://fulcrum-core.1209k.com:50001` passed, but it provides no server authentication or transport confidentiality. It is evidence for protocol interoperability, not a recommended production transport.
- `ssl://testnet.aranguren.org:51002` responded to raw Electrum protocol probes but the adapter rejected initialization in the selected testnet3 configuration.
- Blockstream testnet ports responded to raw `server.version` probes but did not complete the BDK adapter smoke within the bounded attempts in this environment.

Production operators should use an endpoint whose TLS certificate validates for its configured hostname. The prototype supports one configured `tcp://` or `ssl://` endpoint and has no failover pool.
