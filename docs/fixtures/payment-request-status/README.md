# Payment Request status fixtures

These files are exact successful `POST /payment-requests/status` response bodies for Locks lifecycle decisions. Consumers must reject unknown fields and unknown enum values.

Closed `request_state` values:

- `proposed`
- `proposal_expired`
- `accepted`
- `rejected`
- `canceled`
- `proof_submitted`
- `active_recurring`

Closed `payment_state` values:

- `undetected`
- `detected`
- `confirmed`
- `expired`

`RecoveryRequired` is returned as HTTP `503` with code `unavailable`. `InvalidConflict` is returned as HTTP `409` with code `conflict`; neither appears in a successful status body.

Fixtures deliberately retain confirmations and amount matching for terminal request states. `proposal-expired.json` differs from `payment-deadline-expired.json`: first is request terminality; second is accepted request plus expired payment state.
