# Outbox terminal-failure acknowledgement

This server has no operator/admin auth surface: the only authenticated HTTP
surface is the marketplace-signed command auth (`paykit-server/src/http/auth.rs`),
which authorizes marketplace invoice commands, not operator maintenance, and it
is not extended here. Terminal-failure acknowledgement is therefore a
documented operator SQL operation, executed with the same audited
deployment/maintenance credentials that own migrations (the runtime role is a
non-owner role and is never granted this write; see
`paykit-server/migrations/0020_outbox_terminal_trigger_role_barrier.sql`).

## Exact statement

Acknowledge one retained terminal event by id (idempotent: an already
acknowledged row matches zero rows):

```sql
UPDATE outbox_terminal_events
SET acknowledged_at = NOW(),
    acknowledged_by = $1
WHERE id = $2
  AND acknowledged_at IS NULL;
```

`$1` is the operator's deployment identity (closed operator identifier, never
a claim token, session, or credential). `$2` is the event id from
`outbox_terminal_events`. Acknowledgement never deletes or mutates the event's
class, reason, or timestamps; the row remains retained evidence for the
creator-account lifetime, and the monotonic
`paykit_outbox_terminal_transitions_total{class,reason}` counter is unaffected.

## Health and alert semantics

`/health/ready` computes `outbox_terminal_failure_count`,
`outbox_oldest_terminal_failure_age_seconds`, and
`outbox_terminal_failures_by_class` over UNACKNOWLEDGED rows only
(`acknowledged_at IS NULL`), so acknowledgement clears the critical signal.
The alert contract is pinned in `paykit-server/src/metrics.rs`:

- warning: `increase(paykit_outbox_terminal_transitions_total[5m]) > 0`
- critical: oldest unacknowledged age > 900 seconds, or >= 5 transitions in 5
  minutes

## Closed event classes

The closed invoice-lifecycle classes are `invoice_voided`,
`invoice_abandoned`, `invoice_expired` (the `expired_tail → expired_final`
transition terminalizes the invoice's non-handed-off outbox rows in the same
transaction), and `invoice_final_backfill` (the bounded one-time backfill
sweep for rows left inert by invoices that reached a final state before
transition-time terminalization shipped). The remaining classes are
`link_establishment_exhausted`, `dependency_failed`, `permanent`,
`invoice_finalized`, `permanent_sdk_reconciliation`, and
`handoff_unresolved`. Every class writes exactly one event per transitioned
row; `handed_off` and `handoff_started` rows are never terminalized by any
of them. The backfill is bounded to 100 rows per pass and processes the
oldest `created_at` rows first.

## Reconciling an `sdk_invoked_unattributed` row

A `handoff_unresolved` event with reason `sdk_invoked_unattributed` means
the worker crashed after committing the durable pre-SDK invocation marker
but before the handoff result was persisted: an endpoint publication or
payment request MAY exist in the creator's durable SDK state, and recovery
deliberately never attributes it automatically (endpoint identifier sets
are not invoice-unique, so automatic attribution could false-match another
invoice's publication). Find such rows read-only:

```sql
SELECT e.id, e.outbox_id, e.invoice_id, e.creator_id, e.created_at
FROM outbox_terminal_events e
WHERE e.event_class = 'handoff_unresolved'
  AND e.reason = 'sdk_invoked_unattributed'
  AND e.acknowledged_at IS NULL
ORDER BY e.created_at;
```

For each row, inspect the creator's durable SDK outbound records (the
`outbound_private_messages` collection inside the creator's encrypted SDK
state, `sdk_states.state_envelope`, readable only through deployment
tooling holding the master key) for a record to the same reader, receiver
path, and message kind whose COMPLETE content — every endpoint identifier
AND its payload, or the exact payment reference — matches the invoice's
receiving details, and check its status (`Sent` means the effect reached
the reader). Also check the creator's other `outbox` rows for the same
reader carrying an `sdk_outbound_message_id` for the same endpoint
identifier: if a sibling invoice's row already owns the matching `Sent`
publication, that publication belongs to the sibling and this invoice's
effect was never published. The terminal row itself is immutable (the
repair trigger rejects edits), so reconciliation is downstream: if the
exact-payload record is confirmed `Sent`, settle the invoice with the
marketplace per its manual-review procedure; if no exact-payload record
exists, treat the effect as never delivered and re-issue or refund per the
same procedure. Only after that downstream reconciliation, acknowledge the
event with the exact statement above (`$2` = `e.id`), which clears the
critical signal while retaining the row as evidence.
