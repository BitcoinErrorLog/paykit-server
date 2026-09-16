-- Runtime connections must use a non-owner role. ALTER TABLE and trigger
-- administration remain with the audited migration-maintenance owner only;
-- emergency maintenance is performed through a reviewed migration, never by
-- the runtime role.
ALTER TABLE outbox
    ENABLE ALWAYS TRIGGER outbox_terminal_repair_barrier;

COMMENT ON TRIGGER outbox_terminal_repair_barrier ON outbox IS
    'Terminal repair barrier. Runtime role is non-owner and cannot disable it; maintenance changes require an audited migration.';
