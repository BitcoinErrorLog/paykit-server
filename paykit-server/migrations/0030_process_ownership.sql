-- Durable single-process ownership lease and monotonic generation fence.
-- A serving process holds both the session advisory lock and this row's active
-- lease. A replacement process that acquires the advisory lock after an unclean
-- lock loss fences the previous owner and waits until that owner cleanly clears
-- the lease or the lease expires before starting HTTP admission or workers.
CREATE TABLE process_ownership (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
    owner_id UUID,
    fenced BOOLEAN NOT NULL DEFAULT FALSE,
    lease_expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT process_ownership_lease_consistency CHECK (
        (owner_id IS NULL AND lease_expires_at IS NULL AND NOT fenced)
        OR (owner_id IS NOT NULL AND lease_expires_at IS NOT NULL)
    )
);

CREATE FUNCTION enforce_process_ownership_monotonic_generation() RETURNS trigger AS $$
BEGIN
    IF NEW.generation < OLD.generation THEN
        RAISE EXCEPTION 'process_ownership generation must not decrease';
    END IF;
    IF NEW.owner_id IS NOT NULL
        AND (OLD.owner_id IS NULL OR NEW.owner_id <> OLD.owner_id)
        AND NEW.generation <= OLD.generation
    THEN
        RAISE EXCEPTION 'process_ownership claim must advance generation';
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER process_ownership_monotonic_generation
BEFORE UPDATE ON process_ownership
FOR EACH ROW EXECUTE FUNCTION enforce_process_ownership_monotonic_generation();
