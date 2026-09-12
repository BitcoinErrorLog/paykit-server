# Accounts API — claim, allocation status, and CORS

The browser-facing slice of paykit-server's account surface (design
`btc-mainnet.md` §B.6, §B.8.5–§B.8.8). `POST /v0/accounts/claim` claims a
watch-only BIP84 account for a seller; `GET /v0/accounts/{creator}/status`
serves the authenticated seller their own allocation record. Both routes are
called directly from browser clients, so the router answers CORS preflights
for the setup flow's configured origins.

## The claim gate order

`POST /v0/accounts/claim` evaluates its gates in a fixed order: **shape →
rate-limit → token → scan → persist**. Pure request-shape validation (the
`pasted_auto` refusal, the unknown-`claim_channel` refusal) needs no I/O and
runs before the per-minute claim rate limit is charged, so unauthenticated
garbage never consumes claim capacity. Everything I/O-bearing — token
verification, the claim-time history scan, marker publication and
persistence — runs behind the rate limit. The claim response carries the
persisted `account_index`, the claim-time `first_child_index`, the current
`next_child_index` cursor, `key_fingerprint`, and `first_derived_address`
derived at (`account_index`, `first_child_index`).

## The seller status endpoint

`GET /v0/accounts/{creator}/status` returns the addressed seller's own
allocation record — it is the seller's own data about their own creator row,
never public. Authentication is the same capability-scoped Pubky AuthToken
the claim carries, presented as `Authorization: Bearer <token>` and verified
offline; the token's signer must BE the addressed creator. Status codes: 401
(`invalid_token`) when the bearer is missing, malformed, unverifiable, or
carries the wrong capability set; 403 (`forbidden`) for any other valid
authenticated identity; 404 (`not_found`) when the authenticated seller has
no claimed account; 200 for the owner. The 200 body carries the persisted
`allocation_mode`, the nullable `claim_channel` recorded at claim time, the
nullable `downgrade_reason`, the client's required evidence fields
`key_fingerprint` (a hash, not key material) and `first_derived_address`
(what invoices reveal anyway) — the same values the claim response emits —
the derivation coordinates below, and `evidence`, the §B.8.7 sentinel
detection metadata (W1.14): the seller's own durable sentinel rows, oldest
first, each with fixed field names (`classification` — `candidate`,
`evidence`, or `superseded_by_assignment` — `derivation_index`, `address`,
`outpoint` as `txid:vout`, `value_sats`, `confirmations`,
`first_observed_at`, `last_observed_at` as RFC 3339). `evidence` is `[]`
until the sentinel records any. The body also carries `alerts`, the durable
§B.8.7 seller alert (below). `claim_channel` and
`downgrade_reason` are always present in the JSON body — serialized as an
explicit `null` when unset (serde `Option`), never omitted — so clients may
treat them as `.nullish()`. Shape:

```json
{
  "creator": "pubky…",
  "allocation_mode": "shared_manual",
  "claim_channel": "manual",
  "downgrade_reason": "claim_channel_not_bitkit",
  "key_fingerprint": "0011223344556677",
  "first_derived_address": "bc1q…",
  "account_index": 1,
  "first_child_index": 0,
  "next_child_index": 3,
  "evidence": [
    {
      "classification": "evidence",
      "derivation_index": 4,
      "address": "tb1q…",
      "outpoint": "abcd…:1",
      "value_sats": 550,
      "confirmations": 3,
      "first_observed_at": "2026-09-11T00:00:00Z",
      "last_observed_at": "2026-09-11T00:00:00Z"
    }
  ],
  "alerts": [
    {
      "event_kind": "sentinel_downgrade",
      "reason": "unassigned_sentinel_evidence",
      "created_at": "2026-09-11T00:00:00Z",
      "acknowledged_at": null
    }
  ]
}
```

## The durable sentinel seller alert

The one `sentinel_downgrade` mode transition produces exactly one durable
alert row, ever (`UNIQUE (creator_id, event_kind)` plus the conditional
mode-guarded downgrade UPDATE): repeat evidence after the downgrade still
commits to `evidence` but never raises a second alert. **Status polling is
the delivery mechanism** — no push channel, webhook, or outbox entry is
invented; `alerts` is always present in the 200 body (`[]` until a
downgrade commits) and W1.16's Shop client renders it. Each entry carries
only stable identifiers and timestamps — the fixed `event_kind`
(`sentinel_downgrade`), the fixed §B.8.8 `reason` identifier
(`unassigned_sentinel_evidence`), the transition `created_at`, and
`acknowledged_at` — serialized as explicit `null` while UNREAD. No
address, xpub, outpoint, value, or free text is ever interpolated; the
seller-facing copy is W1.16's static rendering of the reason identifier.

`POST /v0/accounts/{creator}/alerts/acknowledge` with body
`{"event_kind": "sentinel_downgrade"}` is the seller's durable read
receipt: it sets `acknowledged_at` exactly once (the first receipt stands;
re-acknowledging changes nothing and returns 200 `{"acknowledged": true}`),
and never clears it. The route shares the status surface's owner-only
authentication and CORS policy: 401 `invalid_token` without a valid bearer,
403 `forbidden` for any other authenticated identity, 400 for an unknown
`event_kind`. A seller with no matching alert gets 200
`{"acknowledged": false}` — acknowledging is a receipt, never an alert
creation path.

**Retention.** Sentinel evidence rows and the alert row are creator/account
audit records retained for the lifetime of the creator account: W1.14 has
no automatic purge and no deletion path, both tables reference `creators`
with `ON DELETE RESTRICT` so no cascade can silently erase them, and
evidence rows are immutable apart from the classification promotion
(`candidate` → `evidence` / `superseded_by_assignment`), the confirmation
count, and `last_observed_at`. Deleting or expiring evidence requires a
future approved retention policy and migration.

The four derivation fields, and what a client verifies with each:

- `key_fingerprint` — the client recomputes the fingerprint from its own
  account xpub and fails closed on mismatch before enabling the Bitcoin
  rail.
- `account_index` — the persisted BIP84 account index; with the client's own
  xpub it anchors every re-derivation below.
- `first_child_index` — the immutable claim-time child index the claim
  response emitted; the client verifies
  `first_derived_address == derive(xpub, account_index, first_child_index)`.
- `first_derived_address` — the address at (`account_index`,
  `first_child_index`), stable forever: it is the exact value the claim
  response emitted and never moves, even as invoices are allocated.
- `next_child_index` — the mutable derivation cursor the next invoice
  address derives from. Informational only: it moves as invoice allocation
  advances it, and no client equality check should be anchored to it.

## Allocation modes and downgrade reasons

A creator's `allocation_mode` decides whether chain observation may move an
order to `paid` automatically. `exclusive` (automatic confirmation) is
granted only to a claim on the `bitkit_watch_only_v1` channel that passes
every corroborating check — account index ≥ 1, declared index equal to the
key's own hardened child number, a history-free §B.8.5/§B.5 scan, and a
fingerprint never claimed by another seller — and only at creation: no edit
moves a creator into `exclusive`, and downgrades are one-way. Every other
claim is `shared_manual` (the seller confirms each payment), and a failed
corroborating check downgrades rather than refuses, recording one of §B.8.8's
five fixed identifiers: `claim_channel_not_bitkit`, `account_index_zero`,
`account_index_mismatch`, `account_has_history`, and (W1.14's sentinel
detection only) `unassigned_sentinel_evidence`.

## `pasted_auto`: reserved but refused

The schema's check constraint admits a third mode, `pasted_auto`, so the r4
analysis and audit records can express the mode a pasted-key creator would
have been in — but no code path, flag, migration, or seller action ever
writes it, and there is deliberately no enum variant to construct. A claim
requesting `allocation_mode = 'pasted_auto'` is refused unconditionally, on
every code path and under every configuration, with 422
`allocation_mode_not_enabled`, before the rate-limit charge, before token
verification, before any gate, persisting nothing. Enabling the mode
requires a separately approved design revision.

## `claim_channel`: two values, fail closed

`POST /v0/accounts/claim` accepts an optional `claim_channel` of `manual` or
`bitkit_watch_only_v1` (§B.8.6), recorded on the creator row and constrained
by a database CHECK to those two values or NULL. A missing channel is
treated — and recorded — as `manual` (a paste is a bare key and nothing
else). Any other value is refused with 422 `unknown_claim_channel`: unknown
channels fail closed, are never canonicalized silently, and are never
persisted verbatim. Like the `pasted_auto` refusal this is pure
request-shape validation, so it runs before the claim rate limit is charged
(see *The claim gate order*).

## CORS

The accounts router answers preflights for the same exact-origin (or `*`)
allow-list the setup flow is configured with; disallowed origins get 403 and
no CORS headers. Allowed methods are `GET, POST, OPTIONS`; allowed headers
are `content-type` (the JSON claim body) and `authorization` (the status
endpoint's bearer token), with `Vary: Origin` on every CORS response.
