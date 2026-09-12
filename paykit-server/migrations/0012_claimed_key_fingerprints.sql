-- Fingerprint-to-seller binding (design B.8.5): a watch-only account's
-- canonical key material may be claimed by exactly one creator per stack,
-- forever. The primary key is the 65-byte canonical tail of the 78-byte BIP32
-- serialization (32-byte chain code + 33-byte public key, bytes 13..78), NOT
-- the 8-byte display fingerprint returned in the claim response -- the column
-- is named key_tail so the two can never be confused. Because the tail is
-- version-byte-independent, the xpub and zpub encodings of one key produce one
-- entry. Rows are written in the same transaction as the claim commit and are
-- never deleted: a claim is refused with key_claimed_by_other_seller if the
-- tail was ever claimed by a different creator, whether or not that claim is
-- still active, because two sellers watching one key means one seller's
-- payment can confirm the other's order.

CREATE TABLE claimed_key_fingerprints (
    key_tail BYTEA PRIMARY KEY CHECK (octet_length(key_tail) = 65),
    creator_lookup_hash BYTEA NOT NULL,
    first_claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
