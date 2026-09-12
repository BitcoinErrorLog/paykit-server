-- Unassigned-sentinel detection (design B.8.7, W1.14). The sentinel is the
-- creator-level backstop for `exclusive` creators: chain outputs paying an
-- address the server derived but NEVER assigned to any invoice are evidence
-- the account is not exclusive, and the only transition they can drive is the
-- one-way downgrade `exclusive -> shared_manual` with the fixed
-- `unassigned_sentinel_evidence` reason. The sentinel never upgrades, never
-- auto-pays, and never classifies an assigned-address payment as
-- account-wide evidence.
--
-- creators.sentinel_last_scanned_at is the per-creator scan cursor: NULL
-- means never scanned (immediately due), and a creator is re-admitted only
-- after the configured re-scan interval (default 10 minutes). It lives on
-- the creators row so the same row lock that serializes invoice address
-- assignment (create_atomic / exact_replay FOR UPDATE) also serializes the
-- sentinel's scan-state and downgrade writes.
--
-- sentinel_outpoints is the durable candidate/evidence audit log. Following
-- the repo's no-plaintext-Bitcoin convention (enforced by the migration
-- test's forbidden-column scan), the derivation index, address, txid:vout
-- outpoint and value are sealed in sentinel_envelope; only keyed lookup
-- hashes, the confirmation count, the classification and timestamps are
-- plaintext columns. Classification vocabulary:
--   candidate                - mempool-only qualifying-value output at a
--                              never-assigned address; never evidence;
--   evidence                 - confirmed (>= 1 confirmation at observation
--                              time) qualifying-value output at a
--                              never-assigned address; counts one distinct
--                              hit toward the downgrade predicate;
--   superseded_by_assignment - the output's derivation index was assigned
--                              to an invoice before the sentinel's atomic
--                              re-check committed; never evidence, never
--                              downgrades.
-- UNIQUE (creator_id, outpoint_lookup_hash) makes a replayed outpoint
-- idempotent: it can never double-count a distinct hit.
--
-- sentinel_events records the exactly-once seller alert for the mode
-- transition. UNIQUE (creator_id, event_kind) plus the conditional
-- mode-guarded UPDATE in the downgrading transaction guarantee one
-- `sentinel_downgrade` row per creator forever: repeat hits after the
-- downgrade may add evidence but never a second alert, and a restart/retry
-- cannot duplicate the transition. The row is a DURABLE, owner-visible
-- alert, not just a log: the authenticated seller status surface serves it
-- (event kind, fixed reason identifier, created_at, acknowledged_at) and
-- acknowledged_at is the seller's durable read receipt — NULL means
-- unread, set once by the owner's acknowledge call, never cleared.
--
-- RETENTION (design B.8.7, W1.14): sentinel_outpoints evidence and
-- sentinel_events alerts are creator/account audit records retained for
-- the lifetime of the creator account. W1.14 has NO automatic purge and no
-- deletion path; both tables reference creators with ON DELETE RESTRICT so
-- no cascade can silently erase them. Deleting or expiring evidence
-- requires a future approved retention policy and migration; evidence rows
-- are immutable in W1.14 (only the classification promotion
-- candidate -> evidence / superseded_by_assignment, the confirmation count
-- and last_observed_at ever update).

ALTER TABLE creators
    ADD COLUMN sentinel_last_scanned_at TIMESTAMPTZ;

CREATE TABLE sentinel_outpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    sentinel_envelope BYTEA NOT NULL,
    outpoint_lookup_hash BYTEA NOT NULL,
    address_lookup_hash BYTEA NOT NULL,
    derivation_index_lookup_hash BYTEA NOT NULL,
    confirmations INTEGER NOT NULL CHECK (confirmations >= 0),
    classification TEXT NOT NULL CHECK (classification IN (
        'candidate',
        'evidence',
        'superseded_by_assignment'
    )),
    first_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (creator_id, outpoint_lookup_hash)
);

CREATE INDEX sentinel_outpoints_creator_classification_index
    ON sentinel_outpoints (creator_id, classification);

CREATE TABLE sentinel_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_id UUID NOT NULL REFERENCES creators (id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('sentinel_downgrade')),
    reason TEXT NOT NULL CHECK (reason IN ('unassigned_sentinel_evidence')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The seller's durable read receipt: NULL = unread; set exactly once by
    -- the authenticated owner's acknowledge call and never cleared.
    acknowledged_at TIMESTAMPTZ,
    UNIQUE (creator_id, event_kind)
);
