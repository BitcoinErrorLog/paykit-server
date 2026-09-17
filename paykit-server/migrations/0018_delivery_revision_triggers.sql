CREATE OR REPLACE FUNCTION bump_invoice_delivery_revision_from_outbox()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.invoice_id IS NOT NULL
       AND (TG_OP = 'INSERT' OR NEW.status IS DISTINCT FROM OLD.status) THEN
        UPDATE invoices
        SET delivery_revision = delivery_revision + 1,
            updated_at = NOW()
        WHERE id = NEW.invoice_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER outbox_delivery_revision_transition
AFTER INSERT OR UPDATE OF status ON outbox
FOR EACH ROW
EXECUTE FUNCTION bump_invoice_delivery_revision_from_outbox();

CREATE OR REPLACE FUNCTION bump_invoice_delivery_revision_from_invoice()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.baseline_state IS DISTINCT FROM OLD.baseline_state
       OR NEW.resolution IS DISTINCT FROM OLD.resolution THEN
        NEW.delivery_revision := OLD.delivery_revision + 1;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER invoice_delivery_revision_transition
BEFORE UPDATE OF baseline_state, resolution ON invoices
FOR EACH ROW
EXECUTE FUNCTION bump_invoice_delivery_revision_from_invoice();
