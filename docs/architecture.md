# Shared Paykit integration

Paykit Server runs as one process with multiple isolated Creator accounts. It owns
Locks invoice workflows and direct Bitcoin/USDT observation, but delegates Paykit protocol
state, Encrypted Links, App Registry updates, and private message delivery to the
published Paykit SDK. Domain terminology follows the dependency's `THESAURUS.md`.

## Authority and setup

Bitkit grants Pubky access to `/pub/paykit/:rw` and delegates a generation-bound
Paykit Identity Secret. Initial setup also requests a BIP84 account xpub; reconnect
preserves the Bitcoin account for an existing Creator. When USDT is enabled, setup and reconnect also request an optional Arbitrum receiving address. The server never receives
Bitcoin spending keys or the Pubky identity secret. Receiving details cannot change through reauthorization; a previously omitted USDT address may be added.

The companion claim is bound to the AUTH identity, secret, and exact permission
list. Before delegation or private app publication, the identity owner uses
`PAYKIT_AUTHORIZER_SESSION_CAPABILITIES` and
`publish_paykit_noise_key_authorization()` to publish its signed current Noise key.
Only that owner session can write `/pub/paykit-authority/v0/current-key.json`;
Server's ordinary Paykit grant must not include that path.
Setup verifies the delegated key and generation against the identity-signed
Paykit Noise Key Authorization before
persisting credentials. Under the Creator setup lock, it persists credentials,
publishes the `paykit-server` app through SDK locks, reads that app back, and marks
setup complete. Publication failure leaves retryable credentials and never
rewrites another app's registry entry. See [the wire contract](bitkit-companion-claim.md).

Session readiness also verifies the signed authorization. Missing, tampered, or
mismatched records fail validation; the App Registry supplies discovery metadata
and app capabilities, not key authority.

Setup, status queries, and workers use one process-owned session cache. Independently
restoring a live grant can invalidate its bearer. A changed persisted session or
delegated key causes the cached provider to refresh its access; unchanged credentials
reuse the live handle.

## State ownership

PostgreSQL owns encrypted Creator credentials, address allocation, reader
assignments, invoices, payment observations, and fenced delivery intents. AEAD
binds private payloads to their type, Creator, and row; keyed lookup hashes support
queries without plaintext identities or payment details.

The SDK owns encrypted identity-wide homeserver state under WebDAV locks. Apps
share Encrypted Links and history; app IDs attribute requests and outbound records.
The server does not maintain a PostgreSQL copy of SDK state. Its transport worker
receives private events and processes queued delivery without executing payments.
The local reader demo likewise uses hosted SDK state; its encrypted local file
retains only the app/Creator binding and a process ownership lock.

Deployed Pubky Homeserver instances must run 0.15 or newer. Shared-state safety
requires commit-time fencing of expired lock holders and durable publication of
complete files; the SDK's five-minute uncertain-write cooldown remains in place
and is not a substitute for those storage guarantees.

## Invoice and settlement invariants

A database transaction allocates one fresh BIP84 address per invoice and persists
the complete Payment Request with that address in `payment_endpoints` and
`required_app_id = "paykit-server"`. Exact replay returns the same invoice,
assignment, terms, and outbox row. Invoices accepting Bitcoin cannot reuse its address. Invoices accepting USDT share the approved address and attribute individual transfers through verified request proofs. Both options may belong to one invoice; fixed conversion rates and per-option amounts are persisted with its immutable terms.
Reader discovery requires a Noise key and at least one registered app supporting
both Payment Requests and outgoing payments; Private Payment List sharing is not
required. Discovery does not select a receiver path.

SDK proposal handoff uses the durable outbox UUID as its Payment Request ID, so
retries recover one proposal and the same Event and outbound IDs. Transport
remains at least once. Reconciliation identifies the exact outbound ID and app;
only SDK `Sent` means delivered, not payer acknowledgement. See
[outbox recovery](outbox-recovery.md) for leases and retry behavior.

Bitcoin attribution uses direct observation of the invoice-specific address. USDT attribution combines an authenticated, request-bound ERC-20 account signature with independent Arbitrum receipt verification. Neither SDK lifecycle state nor a transaction hash alone proves settlement. One amount-matched output is required; split outputs are not aggregated.
A Bitcoin amount-matched output freezes at one confirmation and becomes final at six. USDT observations remain reorg-sensitive until the RPC finalized block covers the receipt; their unique transfer identity cannot settle another invoice.
USDT verification shares a bounded five-second chain-tip snapshot across Creator adapters. Each receipt and canonical block is read afresh. Persisted observation check times reserve background refreshes before RPC, limiting present transfers to one attempt per minute even during provider outages or after restart. Explicit invoice status reads bypass this delay; unchanged unmatched proof sets retry after 15 seconds. Verification accepts at most 128 proof records per request, checking this limit before parsing or signature recovery.

Larger histories skip new evidence, but still refresh up to eight owned, nonfinal receipts per pass. Explicit invoice status prioritizes the receipt selected for payment status, followed by other owned receipts and then new evidence, with no more than eight distinct candidates per pass. A nonfinal receipt may support the response only if it was successfully refreshed in that call. If a batch removes receipts but leaves an unrefreshed receipt selected, status returns retryable unavailable until the next pass refreshes it. Finalized receipts do not require RPC; provider and persistence failures remain unavailable. Encrypted receipt facts retain the originally attested sender so refreshes preserve account ownership checks without reparsing the proof history. Present receipts keep the one-minute background interval; removed receipts retry after 15 seconds, and explicit invoice status refreshes take priority even while new-proof discovery is deferred. Owned-only refreshes do not reset the discovery cooldown. Existing envelopes without a sender remain readable and gain that anchor on normal verification; if their history exceeds the supported limit, their nonfinal credit is withdrawn until it can be reattested. Finalized receipts are unchanged. Provider outages retain last-known facts; missing or invalid canonical receipts remove payment credit.

Within the proof-count bound, each pass checks at most eight distinct receipt events, rotating through larger candidate sets. Changed proof sets for retained contexts are eligible immediately; discovery of unchanged sets in cooldown skips signature recovery. Multiple account attestations for one event share a receipt read. A scan containing unmatched or unavailable evidence retains its retry delay even when other receipts are present; a truncated discovery batch cannot be marked fully observed.

Retry scheduling retains at most 1,024 request contexts and does not create database observations for missing transfers. Active retry delays are never evicted: new contexts wait when every slot is cooling down. Partially scanned contexts revisited within five minutes keep their cursor until a full proof sweep completes; inactive cursors may be reclaimed and restart on their next visit. The request currently being scanned keeps its slot. One additional deferred context is remembered in circular key order and reserves the next eligible slot so later requests can progress in a stable reconciliation order. Unused reservations expire after 15 seconds.
No spending, refunds, receipt issuance, or horizontal replicas are supported.

### Buyer contacts

A verified, full payment received within the invoice's payment window queues a
private buyer-contact save. This uses Bitcoin output or USDT receipt verification,
not a submitted Payment Proof or an Encrypted Link. It does not change Locks'
confirmation/finality policy or grant access to content.

A separate worker resolves the buyer's Paykit profile first, then Pubky.app when
the Paykit profile is absent. If neither exists, it skips the contact. The worker
inserts into the Creator's encrypted shared SDK contacts, visible to Bitkit on its
next contact refresh. It never publishes a Public Contact Marker, edits an existing
contact, or unblocks a peer. The existing Encrypted Link is unchanged.

Contact work is recorded atomically with payment observation and retried after
transient failures or worker restart, independently of payment delivery and status
responses. Completed or skipped attempts are retained per Creator/buyer so later
purchases do not recreate a contact the Creator removed. Profile resolution runs
outside the shared-state lock. The worker rechecks completion under that lock and
holds it through the contact write and database completion, fencing expired
claims before they can modify shared contacts. These are two durable writes: a
crash after the contact write but before database completion leaves a retryable
attempt, not a completed one. Profile data stays in
encrypted shared state; the queue reuses the encrypted invoice and keyed lookups.

Upgrade policy and operational limits are in the [README](../README.md);
validation commands are in [CONTRIBUTING](../CONTRIBUTING.md).

Invoice pricing uses the same Blocktank BTC/USD feed as Bitkit. Fixed Paykit rates determine exact amounts in either asset; verification never fetches another market price. Bitcoin and USDT observers update their own evidence under the invoice lock and rebuild the shared payment status from both. The published request is the authority for destinations and amounts, avoiding independently supplied settlement amounts.
