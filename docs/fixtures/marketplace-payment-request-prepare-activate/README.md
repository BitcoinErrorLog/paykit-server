# Marketplace prepare and activate fixtures

These files are bodies emitted by the signed `POST /marketplace/payment-requests/prepare` and `/activate` routes in `paykit-server-e2e/tests/marketplace_multi_asset.rs`, running the real preparation, lifecycle and status services over PostgreSQL. Only the BTC/USD feed is a test double, fixed at 81,000. The test replaces just the values the database or RNG chooses (`invoice_id`, `prepare_expires_at`, `activated_at`, `payment_deadline`) with fixed ones; every other byte is as emitted. Recapture with `PAYKIT_CAPTURE_FIXTURES=1 cargo test -p paykit-server-e2e --test marketplace_multi_asset`.

- `prepare-usd-derived-*.json`: the optional filter omitted; the offered rails are the seller's (`btc-usdt`, `btc`, `usdt`) and the deployment's (`btc-without-usdt-config`: the seller has USDT but the server has no `[usdt]`).
- `prepare-<denomination>-<filter>.json`: all nine combinations with an explicit filter. `<denomination>` is `usd` (500 cents), `btc` (50,000 sats) or `usdt` (5,000,000 millionths); `<filter>` is `btc`, `usdt` or `btc-usdt`. `payment_amounts` are in each payment asset's base units, rounded up per endpoint. `rates` are payment-asset units per one requested-asset unit and are `{}` when the denomination is the only accepted asset.
- `activate-usd-btc-usdt.json`: activation echoes `amount`, `asset`, `accepted_assets` and `payment_amounts`; no rates.
- `seller-setup-pending-bitcoin.json`, `seller-setup-pending-usdt.json`, `seller-setup-pending-both.json`: `503`, nothing could be offered; the message names the rail.
- `asset-unsupported.json`: `409`, the filter asks only for USDT on a deployment without `[usdt]`.
- `payment-window-exceeds-cap.json`: `400`, window over the applicable cap.
- `operation-conflict.json`: `409`, changed terms under the same `operation_id`.
- `total-mismatch.json`: `409`, activation with a different amount or asset.
