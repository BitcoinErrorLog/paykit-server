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
--
-- first_child_index is the creator's CLAIM-TIME child index (W1.13 r3): the
-- derivation cursor value the claim response's first_derived_address was
-- derived at -- the claim-time history scan's start index for a manual
-- claim, 0 for a companion-flow setup, which performs no scan. It is
-- written once at row creation and never updated, so the seller status
-- surface can serve the exact address the claim emitted forever, while
-- next_child_index keeps moving as invoice allocation advances it.
-- Backfill rule for rows created before this column existed: none exist
-- outside tests (this migration is the W1.13 branch's own and unreleased);
-- the UPDATE below still derives the value as the row's next_child_index at
-- migration time, the best available approximation of the claim-time index.

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
        )),
    ADD COLUMN first_child_index BIGINT;

UPDATE creators SET first_child_index = next_child_index;

ALTER TABLE creators
    ALTER COLUMN first_child_index SET NOT NULL;
