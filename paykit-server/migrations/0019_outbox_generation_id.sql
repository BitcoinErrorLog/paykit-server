ALTER TABLE outbox
    ADD COLUMN generation_id UUID;

UPDATE outbox
SET generation_id = invoice_id
WHERE invoice_id IS NOT NULL;

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
        OR NEW.generation_id IS DISTINCT FROM OLD.generation_id
    ) THEN
        RAISE EXCEPTION 'terminal outbox rows are immutable';
    END IF;
    RETURN NEW;
END;
$$;
