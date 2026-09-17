# ADR: `outbox.generation` BIGINT is legacy and non-authoritative

Status: accepted (registry note; schema debt tracked, removal is a later,
separately approved compatibility migration).

## Context

Migration `0017_outbox_terminal_events.sql` added `outbox.generation BIGINT
NOT NULL DEFAULT 0` before the generation contract was finalized as the
invoice UUID. Migration `0019_outbox_generation_id.sql` then added
`outbox.generation_id UUID`, backfilled it from `invoice_id`, and extended
the terminal-row repair trigger to protect it. The public delivery status
exposes `delivery_generation = invoices.id` and the aggregate validates
`generation_id` equality across the endpoint/request pair.

## Decision

- The authoritative outbox generation is `outbox.generation_id` (the invoice
  UUID). The public status generation is `invoices.id`.
- `outbox.generation BIGINT` is retained for schema compatibility and is
  **legacy/non-authoritative**. Nothing in the claim path, the aggregate
  status, the transitions, or health/metrics may read it.
- It must **never** be used for repair decisions. Supported repair is a
  fresh invoice/outbox generation (new invoice id, fresh marketplace
  idempotency key); terminal rows are never mutated in place, and the
  `ENABLE ALWAYS` trigger still protects the legacy column from edits on
  terminal rows.
- Destructive retirement (drop/rename) is a later, separately approved
  compatibility migration, matching the additive-only rule for this wave.

## Consequences

Two protected generation fields exist until the retirement migration. The
column carries a schema `COMMENT` (migration
`0022_outbox_legacy_generation_doc.sql`) marking it legacy, and the test
`public_status_never_reads_legacy_bigint_generation`
(`paykit-server-e2e/tests/outbox.rs`) proves the public status is unaffected
by arbitrary, mutually inconsistent values in the legacy column.
