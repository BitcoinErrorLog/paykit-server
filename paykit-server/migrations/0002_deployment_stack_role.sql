-- Deployment stack role invariant, adopted once on first boot after upgrade.
-- Nullable with no backfill: databases created before this migration are
-- neither production nor proof until the configured role is adopted on boot.

ALTER TABLE deployment_metadata ADD COLUMN stack_role TEXT;
