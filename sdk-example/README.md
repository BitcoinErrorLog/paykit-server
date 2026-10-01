# Headless SDK payment

From the repository root:

```bash
./sdk-example/run.sh
```

Requires Docker Compose v2, a running Docker daemon, and the repository's Rust
toolchain. The first build can take several minutes. No Bitkit, browser,
frontend, production account, or real Bitcoin is needed.

## Flow

1. Start isolated PostgreSQL, Bitcoin Core regtest, and electrs containers.
2. Start an ephemeral Pubky testnet and auth relay; create fresh Creator and
   Reader identities with hosted SDK state.
3. Authorize Paykit Server with a delegated session, Paykit key, and BIP84
   watch-only account using the SDK's encrypted companion claim.
4. Publish a Content Lock and call the real signed `POST /invoices` route.
5. Let the Reader SDK establish the Encrypted Link, receive the Payment Request,
   and resolve its invoice-specific Payment Endpoint. Claim and accept it.
6. Pay 50,000 regtest sats, mine six confirmations, and require the server's
   signed `POST /transactions/status` response to confirm the matching payment.

The script exits successfully only after the final check. It removes its own
containers and volumes on exit, including failure. Each run uses a unique
Compose project and dynamically assigned loopback ports, so existing local
stacks are not reused or stopped. All identities, credentials, and funds are
disposable; do not use this Compose configuration outside local development.

## Code

[`sdk-payment.rs`](../paykit-server-e2e/examples/sdk-payment.rs) contains the
SDK calls. It uses the repository's pinned Paykit dependencies and real server
workers, Pubky storage, relay, Noise, Bitcoin RPC, and Electrum.

Creator setup calls `SetupService` directly instead of using the iframe. This
lets the example choose an isolated auth relay; the SDK still approves the real
auth flow and the server verifies and stores the companion claim. A temporary
Locks signing key exercises the server API without running a Locks frontend.
Payment confirmation comes from Electrum, not from a fabricated Payment Proof.

This is a disposable happy-path example, not a wallet implementation: it does
not cover UI approval, restart recovery, key rotation, or automatic payment
retries. For fault scenarios, use the database-backed E2E tests in
`paykit-server-e2e/tests`.
