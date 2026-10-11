# Marketplace payment-request status fixtures

These files are byte-exact bodies emitted by signed `POST /marketplace/payment-requests/status` route tests. They cover Marketplace consumer branches rather than invented response DTOs:

- `prepared.json`: inactive invoice; no proposal or payment projection.
- `active-unprojected.json`: active invoice whose SDK lifecycle has not been projected yet.
- `proposed-undetected.json`: proposal projected, acceptance not projected yet.
- `detected.json`: active zero-confirmation Bitcoin observation.
- `confirmed-matched.json`: included, amount-matched, timely observation.
- `confirmed-unmatched.json`: included underpayment.
- `expired-late-match.json`: amount-matched observation that cannot qualify because payment eligibility expired.
- `reorged.json`: retained outpoint evidence after active output disappears; confirmations are zero and both `amount_matched` and `paid_on_time` are false.
- `not-found.json`, `conflict.json`, and `unavailable.json`: exact generic `404`, `409`, and `503` error bodies.
- `recovery-required.json`: exact typed `503` body for a request needing operator recovery.
- `invalid-conflict.json`: exact typed `409` body for an inconsistent request lifecycle.

`request_state: null` and `request_state: "proposed"` are lag states. They mean acceptance has not been projected, not that request was rejected or expired.

`payment_state: "expired"` is projected after inclusive payment deadline passes without current active outpoint carrying durable timely amount-match evidence. Late matches stay visible as evidence but do not regain eligibility.
