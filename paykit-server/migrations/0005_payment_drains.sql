-- Migration 0002 performs the approved one-time prototype reset before adding
-- authoritative invoice deadlines. Keep this assertion fail-closed: reaching
-- this migration with invoice rows means migration ordering was violated or an
-- unsupported partial deployment admitted data between migrations.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM invoices) THEN
        RAISE EXCEPTION
            'prototype reset invariant violated before payment drain persistence';
    END IF;
END
$$;

ALTER TABLE invoices
    ADD COLUMN lock_resource_lookup_hash BYTEA NOT NULL,
    ADD COLUMN lock_resource_generation BIGINT NOT NULL DEFAULT 0
        CHECK (lock_resource_generation >= 0);

CREATE INDEX invoices_lock_resource_lookup_index
    ON invoices (creator_id, lock_resource_lookup_hash, lock_resource_generation);

-- This non-operational boundary survives drain deletion. It fences invoice
-- creation while a drain exists and isolates later publications of the same
-- canonical Lock ID from retained financial history.
CREATE TABLE lock_payment_generations (
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    lock_resource_lookup_hash BYTEA NOT NULL,
    current_generation BIGINT NOT NULL DEFAULT 0 CHECK (current_generation >= 0),
    active_drain_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (creator_id, lock_resource_lookup_hash)
);

CREATE UNIQUE INDEX lock_payment_generations_active_drain_index
    ON lock_payment_generations (active_drain_id)
    WHERE active_drain_id IS NOT NULL;

CREATE TABLE payment_drains (
    id UUID PRIMARY KEY,
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    lock_resource_lookup_hash BYTEA NOT NULL,
    lock_resource_generation BIGINT NOT NULL CHECK (lock_resource_generation >= 0),
    lock_resource_envelope BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed')),
    accepted_count BIGINT NOT NULL CHECK (accepted_count >= 0),
    terminal_count BIGINT NOT NULL CHECK (terminal_count >= 0),
    cancellation_enqueued_count BIGINT NOT NULL CHECK (cancellation_enqueued_count >= 0),
    cancellation_set_hash BYTEA NOT NULL CHECK (octet_length(cancellation_set_hash) = 32),
    item_set_hash BYTEA NOT NULL CHECK (octet_length(item_set_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (creator_id, lock_resource_lookup_hash),
    UNIQUE (id, creator_id, lock_resource_lookup_hash),
    UNIQUE (id, creator_id, lock_resource_lookup_hash, lock_resource_generation),
    CONSTRAINT payment_drains_completion_check CHECK (
        (status = 'active' AND completed_at IS NULL)
        OR (status = 'completed' AND completed_at IS NOT NULL)
    )
);

ALTER TABLE lock_payment_generations
    ADD CONSTRAINT lock_payment_generations_active_drain_owner_fk
    FOREIGN KEY (active_drain_id, creator_id, lock_resource_lookup_hash)
    REFERENCES payment_drains (id, creator_id, lock_resource_lookup_hash)
    ON DELETE RESTRICT;

CREATE FUNCTION advance_lock_payment_generation_after_drain_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    updated_rows BIGINT;
BEGIN
    IF OLD.status <> 'completed' THEN
        RAISE EXCEPTION 'only a completed payment drain may be deleted';
    END IF;

    UPDATE lock_payment_generations
    SET current_generation = current_generation + 1,
        active_drain_id = NULL,
        updated_at = transaction_timestamp()
    WHERE creator_id = OLD.creator_id
      AND lock_resource_lookup_hash = OLD.lock_resource_lookup_hash
      AND active_drain_id = OLD.id;
    GET DIAGNOSTICS updated_rows = ROW_COUNT;
    IF updated_rows <> 1 THEN
        RAISE EXCEPTION 'payment drain generation boundary is missing or divergent';
    END IF;
    RETURN OLD;
END
$$;

CREATE TRIGGER payment_drains_advance_generation_before_delete
BEFORE DELETE ON payment_drains
FOR EACH ROW
EXECUTE FUNCTION advance_lock_payment_generation_after_drain_delete();

CREATE TABLE payment_drain_items (
    drain_id UUID NOT NULL REFERENCES payment_drains (id) ON DELETE CASCADE,
    invoice_id UUID NOT NULL REFERENCES invoices (id) ON DELETE RESTRICT,
    classification TEXT NOT NULL CHECK (
        classification IN (
            'accepted',
            'rejected',
            'canceled',
            'proposal_expired',
            'cancellation_enqueued'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (drain_id, invoice_id),
    UNIQUE (drain_id, invoice_id, classification),
    UNIQUE (invoice_id)
);

CREATE FUNCTION enforce_payment_drain_item_ownership()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM payment_drains AS drain
        JOIN invoices AS invoice ON invoice.id = NEW.invoice_id
        WHERE drain.id = NEW.drain_id
          AND invoice.creator_id = drain.creator_id
          AND invoice.lock_resource_lookup_hash = drain.lock_resource_lookup_hash
          AND invoice.lock_resource_generation = drain.lock_resource_generation
    ) THEN
        RAISE EXCEPTION 'payment drain item ownership is inconsistent';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER payment_drain_items_enforce_ownership
BEFORE INSERT OR UPDATE ON payment_drain_items
FOR EACH ROW
EXECUTE FUNCTION enforce_payment_drain_item_ownership();

-- One invoice can have multiple still-proposed SDK attempts. Each cancellation
-- is independently durable and replayed through the ordinary outbox.
CREATE TABLE payment_drain_cancellations (
    drain_id UUID NOT NULL,
    invoice_id UUID NOT NULL,
    sdk_payment_request_id TEXT NOT NULL CHECK (sdk_payment_request_id <> ''),
    cancellation_outbox_id UUID NOT NULL REFERENCES outbox (id) ON DELETE RESTRICT,
    outbox_intent_kind TEXT NOT NULL DEFAULT 'payment_request_cancellation'
        CHECK (outbox_intent_kind = 'payment_request_cancellation'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (drain_id, sdk_payment_request_id),
    FOREIGN KEY (drain_id, invoice_id)
        REFERENCES payment_drain_items (drain_id, invoice_id) ON DELETE CASCADE,
    FOREIGN KEY (invoice_id, sdk_payment_request_id)
        REFERENCES payment_request_lifecycles (invoice_id, sdk_payment_request_id)
        ON DELETE RESTRICT,

    FOREIGN KEY (
        cancellation_outbox_id,
        invoice_id,
        sdk_payment_request_id,
        outbox_intent_kind
    ) REFERENCES outbox (
        id,
        invoice_id,
        cancellation_target_payment_request_id,
        intent_kind
    ) ON DELETE RESTRICT,
    UNIQUE (cancellation_outbox_id)
);
