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
