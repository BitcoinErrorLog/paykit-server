-- Stack identity: the instance half of `stack_id = {stack_role}:{instance_uuid}`.
-- The row is minted once on first boot inside the same transaction that adopts
-- the deployment role, and never rewritten; two stacks can never share a
-- stack_id without sharing a database. The role alone is deliberately not the
-- identity: a replacement production stack carries the same role, which is the
-- same-role/wrong-instance mixup the pin exists to catch.

CREATE TABLE stack_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    instance_uuid UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
