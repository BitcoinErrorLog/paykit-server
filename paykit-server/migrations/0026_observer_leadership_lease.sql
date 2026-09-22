-- Cluster-single observer leadership as a TTL row lease with a fencing
-- token. Replaces the session-scoped advisory lock so a replacement replica
-- can probe Electrum (and pass /health/ready) while the previous holder
-- still lives. Additive: the live advisory-lock binary never touches this
-- table, so the first image that contains 0026 is stop-start.

CREATE TABLE observer_leadership (
    name TEXT PRIMARY KEY CHECK (name = 'observer'),
    holder UUID NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    fence BIGINT NOT NULL CHECK (fence >= 1)
);

GRANT SELECT, INSERT, UPDATE ON TABLE observer_leadership TO paykit;
GRANT SELECT ON TABLE observer_leadership TO paykit_readonly;
