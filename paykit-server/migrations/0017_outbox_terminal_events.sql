ALTER TABLE invoices
    ADD COLUMN delivery_revision BIGINT NOT NULL DEFAULT 0;

ALTER TABLE outbox
    ADD COLUMN failure_reason TEXT,
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;

CREATE TABLE outbox_terminal_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    invoice_id UUID REFERENCES invoices (id) ON DELETE RESTRICT,
    outbox_id UUID NOT NULL REFERENCES outbox (id) ON DELETE RESTRICT,
    event_class TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    CONSTRAINT outbox_terminal_events_ack_pair CHECK (
        (acknowledged_at IS NULL) = (acknowledged_by IS NULL)
    )
);

CREATE INDEX outbox_terminal_events_creator_index
    ON outbox_terminal_events (creator_id, created_at);

CREATE OR REPLACE FUNCTION prevent_outbox_terminal_repair()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'permanently_failed' AND (
        NEW.status <> OLD.status
        OR NEW.invoice_id IS DISTINCT FROM OLD.invoice_id
        OR NEW.depends_on_id IS DISTINCT FROM OLD.depends_on_id
        OR NEW.generation IS DISTINCT FROM OLD.generation
    ) THEN
        RAISE EXCEPTION 'terminal outbox rows are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_terminal_repair_barrier
BEFORE UPDATE ON outbox
FOR EACH ROW
EXECUTE FUNCTION prevent_outbox_terminal_repair();
