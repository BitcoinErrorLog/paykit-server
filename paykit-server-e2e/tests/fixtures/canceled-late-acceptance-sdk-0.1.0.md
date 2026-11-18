# Canceled request with a late-fetched Acceptance

`canceled-late-acceptance-sdk-0.1.0.json` contains a state blob serialized by
crates.io `paykit-sdk =0.1.0` and the `PaymentRequestRecord` that its unmodified
`PaykitSdk::payment_requests_with` derives from that state. The crate's source
revision is `dd8e75e5588cf7a0b3b45cacbab9125576ee90df`.

The fixture uses artificial public identities and payment data. It contains no
session material or private keys. Its durable event history is:

| Local record time (UTC) | Direction and event | Cursor |
| --- | --- | --- |
| 2027-01-15 07:59:50 | Outbound proposal, expires at 08:00:00 | outbound 1 |
| 2027-01-15 08:00:01 | Outbound payee Cancellation | outbound 2 |
| 2027-01-15 08:00:02 | Inbound first Acceptance | stream 1 |
| 2027-01-15 08:00:03 | Inbound Payment Proof | stream 2 |

The input was checked with 0.1.0's `validate_storage_state`, then encoded with
`encode_storage_state_blob`. Its reducer returns `InvalidConflict` with reason
`Payment Request acceptance arrived after proposal expiry`. It retains the
Cancellation event ID and advances both source cursors through the later Proof.

The regression decodes those bytes with the pinned SDK and runs its real
`payment_requests` replay. It must derive `Canceled` with the same Cancellation
event ID, source cursors and last event time. The new Acceptance record time is
08:00:02, and the valid Proof is retained. Both records pass through the server's
production projection before the PostgreSQL recovery, restart and exact-replay
assertions. The fixture is frozen so future SDK updates cannot silently rewrite
the historical input or old result.
