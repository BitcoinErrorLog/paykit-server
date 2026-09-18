-- Causal provenance for future fenced handoffs. Historical rows remain
-- untouched: no sidecar token is backfilled and no terminal row is revived.
DO $$
DECLARE
    duplicate_groups BIGINT;
BEGIN
    SELECT COUNT(*) INTO duplicate_groups
    FROM (
        SELECT creator_id, sdk_outbound_message_id
        FROM outbox
        WHERE sdk_outbound_message_id IS NOT NULL
        GROUP BY creator_id, sdk_outbound_message_id
        HAVING COUNT(*) > 1
    ) duplicates;
    IF duplicate_groups > 0 THEN
        RAISE EXCEPTION 'outbox outbound ownership preflight failed: % duplicate group(s); use the read-only inspection path', duplicate_groups;
    END IF;
END $$;

ALTER TABLE outbox
    ADD COLUMN handoff_invocation_token UUID,
    ADD COLUMN recovery_attempts INTEGER NOT NULL DEFAULT 0 CHECK (recovery_attempts >= 0),
    ADD COLUMN recovery_first_at TIMESTAMPTZ,
    ADD COLUMN recovery_last_at TIMESTAMPTZ,
    ADD CONSTRAINT outbox_handoff_invocation_token_requires_marker CHECK (
        handoff_invocation_token IS NULL OR handoff_sdk_invocation_started
    );

CREATE TABLE sdk_outbound_invocations (
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    sdk_outbound_message_id TEXT NOT NULL,
    invocation_token UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (creator_id, sdk_outbound_message_id)
);

CREATE OR REPLACE FUNCTION reject_sdk_outbound_invocation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'sdk outbound invocation provenance is immutable';
END $$;

CREATE TRIGGER sdk_outbound_invocations_immutable
BEFORE UPDATE OR DELETE ON sdk_outbound_invocations
FOR EACH ROW EXECUTE FUNCTION reject_sdk_outbound_invocation_mutation();

CREATE UNIQUE INDEX outbox_creator_outbound_owner_unique
    ON outbox (creator_id, sdk_outbound_message_id)
    WHERE sdk_outbound_message_id IS NOT NULL;

CREATE INDEX sdk_outbound_invocations_creator_outbound_index
    ON sdk_outbound_invocations (creator_id, sdk_outbound_message_id);
