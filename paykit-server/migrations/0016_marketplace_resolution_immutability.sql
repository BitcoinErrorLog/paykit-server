-- A Marketplace business resolution is a one-way annotation.
CREATE FUNCTION reject_marketplace_resolution_rewrite() RETURNS trigger AS $$
BEGIN
    IF OLD.business_outcome IS NOT NULL
       AND (NEW.business_outcome IS DISTINCT FROM OLD.business_outcome
            OR NEW.resolved_at IS DISTINCT FROM OLD.resolved_at) THEN
        RAISE EXCEPTION 'marketplace business resolution is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER marketplace_resolution_immutable
    BEFORE UPDATE OF business_outcome, resolved_at
    ON marketplace_payment_preparations
    FOR EACH ROW
    EXECUTE FUNCTION reject_marketplace_resolution_rewrite();
