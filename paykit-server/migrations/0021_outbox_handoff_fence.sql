-- Pre-SDK handoff fence: `handoff_started` is a closed in-flight state the
-- worker commits under the invoice row lock (exact claim token, unexpired
-- lease, invoice non-final) BEFORE any SDK call. It linearizes the
-- cancellation-versus-handoff race: void/abandonment terminalize only
-- `prepared|queued|leased|retryable` rows, so a committed fence is preserved
-- exactly like `handed_off` (in-flight, auditable, never terminalized),
-- while a cancellation committed first makes the fence CAS match zero rows
-- and the worker performs no SDK call. A crash after the fence with no SDK
-- completion is recovered by the DEDICATED fenced-recovery path added in
-- migration 0023 (never the ordinary claim path, which does not re-admit
-- fenced rows): an expired `handoff_started` row is claimable by
-- `claim_fence_recovery` regardless of invoice finality and resolves to
-- attributed `handed_off` or terminal `handoff_unresolved` per the closed
-- rule stated in migration 0023. The terminal-row repair trigger is
-- unaffected: it guards `permanently_failed` rows only.

ALTER TABLE outbox
    DROP CONSTRAINT outbox_status_check;

ALTER TABLE outbox
    ADD CONSTRAINT outbox_status_check CHECK (
        status IN (
            'prepared',
            'queued',
            'leased',
            'handoff_started',
            'retryable',
            'handed_off',
            'delivered',
            'permanently_failed'
        )
    );

-- Crash recovery scan: re-admit fenced rows whose lease expired before the
-- SDK result was persisted.
CREATE INDEX outbox_handoff_fence_reclaim_index
    ON outbox (lease_expires_at)
    WHERE status = 'handoff_started';
