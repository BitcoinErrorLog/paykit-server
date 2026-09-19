-- Operations-only role. Deployment creates a LOGIN role that is a member of
-- this NOLOGIN group; credentials never appear in migrations or application
-- configuration defaults.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'paykit_readonly'
    ) THEN
        CREATE ROLE paykit_readonly
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END $$;

CREATE TYPE setup_flow_cancellation_reason AS ENUM ('user_requested');

-- The opaque flow capability is retained only to make repeated cancellation
-- durable and idempotent. It is never returned by the HTTP API or logged.
CREATE TABLE setup_flow_cancellations (
    flow_id TEXT PRIMARY KEY CHECK (length(flow_id) = 43),
    cancelled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason setup_flow_cancellation_reason NOT NULL
);

GRANT USAGE ON SCHEMA public TO paykit_readonly;
GRANT SELECT ON TABLE creators, sdk_states, outbox, outbox_terminal_events,
    sdk_outbound_invocations, _sqlx_migrations TO paykit_readonly;

GRANT INSERT, SELECT ON TABLE setup_flow_cancellations TO paykit;
