-- Validation scans existing rows under SHARE UPDATE EXCLUSIVE, which does not block
-- Locks reads or writes. It must run in its own transaction, apart from 0018's
-- ACCESS EXCLUSIVE column change, or the scan would hold that lock.
ALTER TABLE usdt_observations
    VALIDATE CONSTRAINT usdt_observations_marketplace_preparation_id_fkey;
ALTER TABLE usdt_observations
    VALIDATE CONSTRAINT usdt_observation_exactly_one_owner;
