# Marketplace payment-request status fixtures

These files are byte-exact bodies emitted by signed `POST /marketplace/payment-requests/status` route tests. The Bitcoin-only files below come from `paykit-server/tests/marketplace_status.rs` with synthetic statuses; the `dual-asset`, `usdt-*`, `btc-on-dual-request` and `cross-rail-*` files are captured from the real preparation, lifecycle, observation and status services over PostgreSQL in `paykit-server-e2e/tests/marketplace_usdt.rs` (feed 81,000 USD per BTC, fake Arbitrum RPC, signed proof fixtures); only `invoice_id`, `activated_at` and `payment_deadline` are replaced by fixed values there. Recapture with `PAYKIT_CAPTURE_FIXTURES=1`. They cover Marketplace consumer branches rather than invented response DTOs:

- `prepared.json`: inactive invoice; no proposal or payment projection.
- `active-unprojected.json`: active invoice whose SDK lifecycle has not been projected yet.
- `proposed-undetected.json`: proposal projected, acceptance not projected yet.
- `detected.json`: active zero-confirmation Bitcoin observation.
- `confirmed-matched.json`: included, amount-matched, timely observation.
- `confirmed-unmatched.json`: included underpayment.
- `expired-late-match.json`: amount-matched observation that cannot qualify because payment eligibility expired.
- `reorged.json`: retained outpoint evidence after active output disappears; confirmations are zero and both `amount_matched` and `paid_on_time` are false.
- Every active and inactive body carries `accepted_assets`, `payment_amounts`, `usdt_arbitrum` and `paid_asset`; the Bitcoin-only files show `usdt_arbitrum: null`.
- `dual-asset.json`: active request offering BTC and USDT, nothing paid yet (62 sats or 50,000 millionths of USDT for USD 0.05).
- `usdt-included.json`: USDT receipt with 2 confirmations, amount-matched and on time, not finalized; `paid_asset: "USDT"`; `bitcoin: null`.
- `usdt-finalized.json`: the same receipt after the chain finalizes it.
- `usdt-reorged.json`: the receipt's block was reorged out; `usdt_arbitrum: null`, `paid_asset: null`, `payment_state: "undetected"`.
- `usdt-underpaid.json`: receipt one unit short; visible with `amount_matched: false`; `paid_asset: null`.
- `usdt-late.json`: receipt after the deadline; `paid_on_time: false`, `payment_state: "expired"`, `paid_asset: null`.
- `btc-on-dual-request.json`: Bitcoin paid on a dual-asset request; `usdt_arbitrum: null`, `paid_asset: "BTC"`.
- `cross-rail-usdt-first.json` and `cross-rail-bitcoin-first.json`: both rails paid on time; both objects stay populated and `paid_asset` names the earlier rail.
- `not-found.json`, `conflict.json`, and `unavailable.json`: exact generic `404`, `409`, and `503` error bodies.
- `recovery-required.json`: exact typed `503` body for a request needing operator recovery.
- `invalid-conflict.json`: exact typed `409` body for an inconsistent request lifecycle.

`request_state: null` and `request_state: "proposed"` are lag states. They mean acceptance has not been projected, not that request was rejected or expired.

`payment_state: "expired"` is projected after inclusive payment deadline passes without current active outpoint carrying durable timely amount-match evidence. Late matches stay visible as evidence but do not regain eligibility.
