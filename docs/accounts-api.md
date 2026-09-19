# Accounts API — removed legacy claim, status, alerts, and CORS

The browser-facing slice of paykit-server's account surface (design
`btc-mainnet.md` §B.6, §B.8.5–§B.8.8).
`GET /v0/accounts/{creator}/status` serves the authenticated seller their own
allocation record. `POST /v0/accounts/claim` is retained only as an explicit
tombstone for the removed legacy cookie-based claim protocol. The accounts
router answers CORS preflights for the setup flow's configured origins.

## Removed legacy claim endpoint

Every `POST /v0/accounts/claim` returns HTTP 410:

```json
{
  "error": {
    "code": "manual_claim_removed",
    "message": "legacy manual account claims were removed; connect with Bitkit setup"
  }
}
```

The refusal occurs before request-body parsing, rate limiting, token or
session minting, Electrum scans, marker publication, and persistence. The
legacy protocol was removed rather than repaired because it minted Pubky
cookie sessions, while Paykit rc55 private and outbox operations require a
grant-backed session. Sellers must use Bitkit setup, which creates and
persists the rc55 grant form.

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
order to `paid` automatically. Existing `exclusive` records remain readable,
and sentinel evidence may still downgrade them one-way to `shared_manual`.
Bitkit companion setup creates `shared_manual` records. With the legacy claim
endpoint removed, no live HTTP path creates a new `exclusive` or
`pasted_auto` record, accepts a `claim_channel`, or upgrades an existing
creator. Historical `claim_channel` and `downgrade_reason` values remain in
the owner-only status response so existing records and audit evidence retain
their meaning.

## CORS

The accounts router answers preflights for the same exact-origin (or `*`)
allow-list the setup flow is configured with; disallowed origins get 403 and
no CORS headers. Allowed methods are `GET, POST, OPTIONS`; allowed headers
are `content-type` (the removed-claim tombstone and alert receipt body) and
`authorization` (the owner-only status/alert bearer), with `Vary: Origin` on
every CORS response.
