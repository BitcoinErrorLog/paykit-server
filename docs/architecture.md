# Shared Paykit integration

Paykit Server runs as one process with multiple isolated Creator accounts. It owns
Locks invoice workflows and Bitcoin observation, but delegates Paykit protocol
state, Encrypted Links, App Registry updates, and private message delivery to the
published Paykit SDK. Domain terminology follows the dependency's `THESAURUS.md`.

## Authority and setup

Bitkit grants Pubky access to `/pub/paykit/:rw` and delegates a generation-bound
Paykit Identity Secret. Initial setup also requests a BIP84 account xpub; reconnect
requests only Paykit access for an existing Creator. The server never receives
Bitcoin spending keys or the Pubky identity secret. The account index and xpub
cannot change through reauthorization.

The companion claim is bound to the AUTH identity, secret, and exact permission
list. Setup verifies the delegated key against the public App Registry before
persisting credentials. Under the Creator setup lock, it persists credentials,
publishes the `paykit-server` app through SDK locks, reads that app back, and marks
setup complete. Publication failure leaves retryable credentials and never
rewrites another app's registry entry. See [the wire contract](bitkit-companion-claim.md).

Setup, status queries, and workers use one process-owned session cache. Independently
restoring a live grant can invalidate its bearer. A changed persisted session or
delegated key causes the cached provider to refresh its access; unchanged credentials
reuse the live handle.

## State ownership

PostgreSQL owns encrypted Creator credentials, address allocation, reader
assignments, invoices, Bitcoin observations, and fenced delivery intents. AEAD
binds private payloads to their type, Creator, and row; keyed lookup hashes support
queries without plaintext identities or payment details.

The SDK owns encrypted identity-wide homeserver state under WebDAV locks. Apps
share Encrypted Links and history; app IDs attribute requests and outbound records.
The server does not maintain a PostgreSQL copy of SDK state. Its transport worker
receives private events and processes queued delivery without executing payments.
The local reader demo likewise uses hosted SDK state; its encrypted local file
retains only the app/Creator binding and a process ownership lock.

## Invoice and settlement invariants

A database transaction allocates one fresh BIP84 address per invoice and persists
the complete Payment Request with that address in `payment_endpoints` and
`required_app_id = "paykit-server"`. Exact replay returns the same invoice,
assignment, terms, and outbox row. A different invoice cannot reuse its address.
Reader discovery checks that at least one registered app supports private payments,
Payment Requests, and outgoing payments; it does not select a receiver path.

SDK handoff is at least once. Reconciliation identifies the exact outbound ID and
app; only SDK `Sent` means delivered, not payer acknowledgement. See
[outbox recovery](task12-outbox-recovery.md) for leases and retry behavior.

Only direct observation of the invoice address attributes payment. Shared private
events, payer identity, Payment Proofs, and connection state cannot settle an
invoice. One amount-matched output is required; split outputs are not aggregated.
An amount-matched output freezes at one confirmation and becomes final at six.
No spending, refunds, receipt issuance, or horizontal replicas are supported.

Persisted-format compatibility is unsupported before production. No reader for
earlier draft formats is retained. Upgrade policy and operational limits are in
the [README](../README.md); validation commands are in [CONTRIBUTING](../CONTRIBUTING.md).
