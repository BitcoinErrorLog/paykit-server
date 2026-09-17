-- `outbox.generation BIGINT` is a legacy, non-authoritative duplicate kept
-- for schema compatibility only. The authoritative outbox generation is
-- `outbox.generation_id` (the invoice UUID, protected by the terminal-row
-- trigger) and the public status `delivery_generation` is `invoices.id`;
-- neither the claim path, the aggregate status, nor any transition reads
-- this BIGINT. It must NEVER be used for repair decisions: supported repair
-- is a fresh invoice/outbox generation, never in-place row mutation. See
-- docs/outbox-legacy-generation.md.
COMMENT ON COLUMN outbox.generation IS
    'LEGACY non-authoritative duplicate. Authoritative generation is generation_id (invoice UUID); public delivery_generation is invoices.id. Never use for repair decisions; repair is a fresh invoice/outbox generation. See docs/outbox-legacy-generation.md.';
