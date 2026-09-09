# Durable semantic outbox recovery

`POST /invoices` atomically persists the invoice, its reader allocation, the endpoint-publication intent, the dependent Payment Request intent, and both encrypted semantic envelopes. Exact replay preserves those durable identities and payloads.

At request time the server discovers capable reader markers and deterministically selects by `paykit.receiver_path_priority` (default `bitkit`), then first path segment and canonical lexical full path. It persists the selected reader path and fingerprint inside the encrypted, Creator- and row-bound delivery intent. Exact replay may bypass discovery because it returns the already authenticated intent.

Workers claim fenced rows, decrypt and revalidate the complete intent, refetch the exact selected marker, and retry if its fingerprint changed. They never reselect another path. Production handoff uses only public Paykit SDK APIs with one encrypted PostgreSQL SDK state per Creator.

A successful public enqueue/proposal stores the returned SDK outbound ID under the same live fence as `handed_off`; Payment Requests also store the returned Event and Payment Request IDs. If the SDK transaction commits before this server transition, reclaimed work calls the public API again. That accepted crash window is at-least-once and may create duplicate Payment Request proposals.

`handed_off` means durable local SDK queue association, not remote delivery. A separately fenced reconciliation claim runs the SDK outbound processor and checks the exact stored outbound ID in durable Creator SDK state. Only `OutboundPrivateMessageStatus::Sent` advances the row to `delivered`, which means successful Encrypted-Link send—not payer application read, processing, or acknowledgement. Endpoint dependents remain blocked until this transition. SDK `Pending`, `Sending`, and retry-backoff `Failed` records remain retryable. `RecoveryRequired` also remains retained and retryable while the separate SDK Encrypted-Link recovery flow is unresolved. `Invalid` and `Superseded` exact records cannot become the required exact `Sent` record and are retained as `permanently_failed`. Missing or changed SDK state is retried; permanent reconciliation errors retain only a non-secret error class.

The baseline schema requires new `handed_off` and `delivered` rows to carry a canonical numeric SDK outbound ID. Earlier prototype rows are not migrated; operators must reset the database when adopting this baseline.

No part of this design claims exactly-once remote delivery.

## Retry budget

Retries are bounded two ways (`[outbox]` config, both must be greater than zero): `max_attempts` (default 50) caps claim attempts per row, and `max_age` (default 7d) caps row age from `created_at`. When a claimed row reaches either ceiling, the same fenced statement that releases the lease transitions the row to `permanently_failed` with error class `retry_budget_exhausted` — atomically, so concurrent workers transition it exactly once. Each exhaustion raises one ERROR log naming the row id, the lane kind (`delivery` or `reconciliation`), and the attempt count (never payload contents), and increments `paykit_outbox_permanent_failures{kind}` exactly once.

Health semantics: `permanently_failed` rows are terminal and never degrade `/health/ready`; `retryable` and `handed_off` rows degrade `paykit_delivery` only while still inside the budget (attempts below `max_attempts` and age below `max_age`), since an over-budget row is already converging on `permanently_failed` at its next fenced scheduling and must not pin the rail degraded. The count of retained `permanently_failed` rows is exposed as the informational `outbox_permanently_failed` field on `/health/ready` (and the `paykit_outbox_permanently_failed_rows` gauge); it never changes readiness status.

Operator requeue of a terminal row, when the underlying cause is fixed:

```sql
UPDATE outbox
SET status = 'queued', attempt_count = 0, error_class = NULL,
    next_attempt_at = NOW(), updated_at = NOW()
WHERE id = '<row-id>' AND status = 'permanently_failed';
```

Requeuing resets the attempt counter so the row gets a fresh budget; without the reset it would be failed again at the next scheduling.
