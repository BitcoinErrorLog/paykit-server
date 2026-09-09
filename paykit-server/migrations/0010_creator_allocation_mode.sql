-- Creator allocation mode (design B.8.6, D1/D2, W1.13). One new column per
-- the design's exact DDL: the check constraint admits 'pasted_auto' so the
-- r4 analysis stays addressable and the seller status API and audit records
-- can express the mode a creator would have been in (B.8.6 r6), but NO code
-- path, flag, migration or seller action ever writes it -- a claim requesting
-- it is refused unconditionally with allocation_mode_not_enabled, and the
-- canary scope is 'exclusive' and 'shared_manual' only (D8). Existing
-- creators backfill to 'shared_manual' via the column default, which is the
-- design's own backfill rule: every pre-W1.13 claim is a paste or a
-- companion setup, and both are shared_manual by construction.
--
-- claim_channel is the `claim_channel` the Shop client submitted on
-- POST /v0/accounts/claim, restricted by CHECK to B.8.6's two values
-- ('manual' or 'bitkit_watch_only_v1') -- the claim refuses any other value
-- with unknown_claim_channel (fail closed; arbitrary strings are never
-- persisted); NULL for creators whose claim predates the field or came
-- through the Bitkit companion flow, which carries no channel assertion and
-- performs no claim-time scan. downgrade_reason is one of B.8.8's five
-- fixed identifiers; NULL when no downgrade reason was ever assigned.

ALTER TABLE creators
    ADD COLUMN allocation_mode TEXT NOT NULL DEFAULT 'shared_manual'
        CHECK (allocation_mode IN ('exclusive', 'pasted_auto', 'shared_manual')),
    ADD COLUMN claim_channel TEXT
        CHECK (claim_channel IS NULL OR claim_channel IN ('manual', 'bitkit_watch_only_v1')),
    ADD COLUMN downgrade_reason TEXT
        CHECK (downgrade_reason IS NULL OR downgrade_reason IN (
            'claim_channel_not_bitkit',
            'account_index_zero',
            'account_index_mismatch',
            'account_has_history',
            'unassigned_sentinel_evidence'
        ));
