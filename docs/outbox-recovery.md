# Durable semantic outbox recovery

`POST /invoices` atomically allocates an invoice address and persists its reader assignment, complete Payment Request terms, and one encrypted outbox intent. The terms bind the address in `payment_endpoints` under the required `paykit-server` app. Exact replay preserves those durable identities, terms, and address. Distinct invoices, including concurrent invoices for the same Reader, receive distinct addresses.

After persistence or exact replay, `POST /invoices` returns `200 OK` with only
the immutable `invoice_created_at` and `payment_deadline` timestamps; it does not
observe Noise state. `POST /connections/status` separately loads the persisted
Reader identity binding and returns `none`, `handshake`, `connected`,
`recovery_required`, or `blocked`. This lookup does not advance handshake,
rewrite SDK state, acquire the worker mutation lock, mutate outbox state, or wait
for delivery. Missing invoices and storage, authentication, malformed-state, or
dependency failures remain typed errors rather than synthetic connection states.

At request time the server checks the Reader's App Registry for an app supporting private payments, Payment Requests, and outgoing payments. It persists the Reader identity in the encrypted, Creator- and row-bound delivery intent. The Reader resolves the request by ID using the SDK request-aware resolver with no consumed Payment List version. The bound destination cannot fall back to mutable private or public endpoints. Exact replay may bypass discovery because it returns the already authenticated intent.

Workers claim fenced rows, decrypt and revalidate the complete intent, and recheck Reader capabilities before handoff. Production handoff uses public Paykit SDK APIs backed by encrypted identity-wide homeserver state. PostgreSQL retains server business state and delivery intents, not a second authoritative SDK state.

Before link establishment or enqueue, the worker asks the SDK to observe the Reader's recovery marker under the Creator mutation lock. Confirmed absence continues normally. A fresh marker abandons the old link generation and starts recovery; lookup or prerequisite failures keep the exact outbox row retryable without SDK handoff identifiers. The server does not publish a marker on the Reader's behalf. This check covers handoffs beginning after marker publication, not SDK records already durably `Sent` before it.

A successful proposal stores the returned SDK outbound, Event, and Payment Request IDs under the same live fence as `handed_off`. If the SDK transaction commits before this server transition, reclaimed work calls the public API again with the persisted terms and address. That accepted crash window is at-least-once and may create duplicate Payment Request proposals.

`handed_off` means durable shared SDK queue association, not remote delivery. A separately fenced reconciliation claim runs the SDK outbound processor and checks the exact stored outbound ID and app ownership in durable Creator SDK state. Only `OutboundPrivateMessageStatus::Sent` advances the row to `delivered`, meaning successful Encrypted Link send, not payer application acknowledgement. SDK `Pending`, `Sending`, and retry-backoff `Failed` records remain retryable. Missing records, `Invalid`, `RecoveryRequired`, and `Superseded` records are retained as `permanently_failed`; they never imply delivery or trigger a new proposal. Transport/storage errors remain retryable, and permanent errors retain only a non-secret error class.

Payment Requests are retained Event Messages. The server neither publishes nor waits on invoice-specific Private Payment Lists, so their latest-state compaction cannot block request delivery or change an invoice's destination.

The schema requires `handed_off` and `delivered` rows to carry a canonical numeric SDK outbound ID. See the [upgrade policy](../README.md#persistence-startup-and-upgrades) before replacing a database or binary.

No part of this design claims exactly-once remote delivery.
