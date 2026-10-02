use std::sync::Arc;

use paykit_server::{
    application::{
        payment_request_status::{PaymentRequestStatusOperations, PaymentState},
        payment_status::PersistedPaymentStatus,
    },
    crypto::Crypto,
    domain::{
        locks::{parse_bundle_id, parse_creator},
        payment_request_lifecycle::PaymentRequestLifecycleState,
    },
    persistence::{InvoiceStore, run_migrations},
};
use paykit_server_e2e::postgres::TestDatabase;
use time::OffsetDateTime;
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

#[tokio::test]
async fn per_bundle_status_joins_canonical_lifecycle_and_payment_facts() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[31; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let bundle = parse_bundle_id(BUNDLE).unwrap();
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let invoice_id = Uuid::new_v4();
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let deadline = created_at + time::Duration::hours(24);
    let hash = |label: &str| crypto.lookup_hash(label.as_bytes()).as_bytes().to_vec();
    sqlx::query(
        "INSERT INTO invoices (
             id, creator_id, reader_lookup_hash, bundle_lookup_hash,
             lock_resource_lookup_hash, lock_resource_generation,
             payment_request_lookup_hash, invoice_envelope, payment_record_envelope,
             bitcoin_address_lookup_hash, derivation_index_lookup_hash,
             payment_status, confirmation_count, amount_matched,
             invoice_created_at, proposal_expires_at, payment_deadline,
             proposal_acceptance_seconds, payment_window_seconds
         ) VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $10,
                   'confirmed', 3, TRUE, $11, $11 + INTERVAL '1 hour', $12,
                   3600, 86400)",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(hash("reader"))
    .bind(crypto.lookup_hash(BUNDLE.as_bytes()).as_bytes().as_slice())
    .bind(hash("lock"))
    .bind(hash("request"))
    .bind(b"encrypted-invoice".as_slice())
    .bind(b"encrypted-payment".as_slice())
    .bind(hash("address"))
    .bind(hash("index"))
    .bind(created_at)
    .bind(deadline)
    .execute(database.pool())
    .await
    .unwrap();

    let store = InvoiceStore::new(database.pool(), crypto.clone());
    assert!(store.invoice_exists(&creator, &bundle).await.unwrap());
    let missing_lifecycle = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle).await;
    assert_eq!(
        missing_lifecycle,
        Err(paykit_server::application::payment_request_status::PaymentRequestStatusError::Unavailable)
    );

    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, $2, 'accepted', $3, 1, 1, $4)",
    )
    .bind(invoice_id)
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .bind(created_at)
    .execute(database.pool())
    .await
    .unwrap();

    let status = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status.request_state(),
        PaymentRequestLifecycleState::Accepted
    );
    assert_eq!(status.payment_state(), PaymentState::Confirmed);
    assert_eq!(status.invoice_created_at(), created_at);
    assert_eq!(status.payment_deadline(), deadline);
    assert_eq!(status.confirmations(), 3);
    assert!(status.amount_matched());
    assert_confirmed_payment(&store, &creator, &bundle).await;

    let tied_at = created_at + time::Duration::seconds(1);
    for (state, payment_request_id) in [
        ("canceled", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("rejected", "00000000-0000-0000-0000-000000000001"),
    ] {
        sqlx::query(
            "INSERT INTO payment_request_lifecycles (
                 invoice_id, sdk_payment_request_id, request_state, state_event_id,
                 last_stream_item_id, last_outbound_message_id, last_event_at
             ) VALUES ($1, $2, $3, $4, 2, 2, $5)",
        )
        .bind(invoice_id)
        .bind(payment_request_id)
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .bind(tied_at)
        .execute(database.pool())
        .await
        .unwrap();
    }
    assert_confirmed_payment(&store, &creator, &bundle).await;

    for state in ["recovery_required", "invalid_conflict"] {
        sqlx::query(
            "INSERT INTO payment_request_lifecycles (
                 invoice_id, sdk_payment_request_id, request_state, state_event_id,
                 last_stream_item_id, last_outbound_message_id, last_event_at
             ) VALUES ($1, $2, $3, $4, 3, 3, $5)",
        )
        .bind(invoice_id)
        .bind(Uuid::new_v4().to_string())
        .bind(state)
        .bind(Uuid::new_v4().to_string())
        .bind(tied_at + time::Duration::seconds(1))
        .execute(database.pool())
        .await
        .unwrap();
    }
    let conflicted = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        conflicted.request_state(),
        PaymentRequestLifecycleState::InvalidConflict,
        "invalid conflict outranks every attempt and fails closed at the application boundary"
    );
    assert_confirmed_payment(&store, &creator, &bundle).await;
    sqlx::query(
        "DELETE FROM payment_request_lifecycles
         WHERE invoice_id = $1 AND request_state = 'invalid_conflict'",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let recovering = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recovering.request_state(),
        PaymentRequestLifecycleState::RecoveryRequired,
        "recovery remains an availability overlay for application projection"
    );
    assert_confirmed_payment(&store, &creator, &bundle).await;
    sqlx::query(
        "DELETE FROM payment_request_lifecycles
         WHERE invoice_id = $1 AND request_state = 'recovery_required'",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "DELETE FROM payment_request_lifecycles
         WHERE invoice_id = $1 AND request_state = 'accepted'",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let tied = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tied.request_state(), PaymentRequestLifecycleState::Rejected);
    assert_eq!(tied.confirmations(), 3);
    assert!(tied.amount_matched());
    assert_confirmed_payment(&store, &creator, &bundle).await;

    sqlx::query(
        "UPDATE invoices
         SET payment_status = 'undetected', confirmation_count = 0, amount_matched = FALSE
         WHERE id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let rejected_undetected = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rejected_undetected.request_state(),
        PaymentRequestLifecycleState::Rejected
    );
    assert_eq!(
        rejected_undetected.payment_state(),
        PaymentState::Undetected
    );
    assert_eq!(rejected_undetected.confirmations(), 0);
    assert!(!rejected_undetected.amount_matched());
    assert_eq!(
        store.payment_status(&creator, &bundle).await.unwrap(),
        Some(PersistedPaymentStatus::Undetected)
    );

    sqlx::query(
        "UPDATE invoices
         SET payment_status = 'confirmed', confirmation_count = 3, amount_matched = TRUE
         WHERE id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "DELETE FROM payment_request_lifecycles
         WHERE invoice_id = $1 AND request_state = 'rejected'",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let canceled = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        canceled.request_state(),
        PaymentRequestLifecycleState::Canceled
    );
    assert_eq!(canceled.payment_state(), PaymentState::Confirmed);
    assert_eq!(canceled.confirmations(), 3);
    assert!(canceled.amount_matched());
    assert_confirmed_payment(&store, &creator, &bundle).await;

    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, $2, 'rejected', $3, 2, 2, $4)",
    )
    .bind(invoice_id)
    .bind("00000000-0000-0000-0000-000000000001")
    .bind(Uuid::new_v4().to_string())
    .bind(tied_at)
    .execute(database.pool())
    .await
    .unwrap();

    let corrupt_lifecycle = sqlx::query(
        "UPDATE payment_request_lifecycles SET request_state = 'unexpected' WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await;
    assert!(corrupt_lifecycle.is_err());

    sqlx::query("UPDATE invoices SET payment_expired_at = payment_deadline WHERE id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    let expired = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.payment_state(), PaymentState::Expired);
    assert_eq!(expired.confirmations(), 3);
    assert!(expired.amount_matched());
    assert_eq!(
        expired.request_state(),
        PaymentRequestLifecycleState::Rejected
    );
    assert_confirmed_payment(&store, &creator, &bundle).await;

    sqlx::query("DELETE FROM payment_request_lifecycles WHERE invoice_id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, $2, 'accepted', $3, 3, 3, $4)",
    )
    .bind(invoice_id)
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .bind(tied_at + time::Duration::seconds(1))
    .execute(database.pool())
    .await
    .unwrap();
    let accepted_expired = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted_expired.request_state(),
        PaymentRequestLifecycleState::Accepted
    );
    assert_eq!(accepted_expired.payment_state(), PaymentState::Expired);
    assert_eq!(accepted_expired.confirmations(), 3);
    assert!(accepted_expired.amount_matched());
    assert_confirmed_payment(&store, &creator, &bundle).await;

    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'proposal_expired', last_stream_item_id = 4
         WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let proposal_expired = PaymentRequestStatusOperations::lookup(&store, &creator, &bundle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proposal_expired.request_state(),
        PaymentRequestLifecycleState::ProposalExpired
    );
    assert_eq!(proposal_expired.payment_state(), PaymentState::Expired);
    assert_eq!(proposal_expired.confirmations(), 3);
    assert!(proposal_expired.amount_matched());
    assert_confirmed_payment(&store, &creator, &bundle).await;

    let absent = PaymentRequestStatusOperations::lookup(
        &store,
        &creator,
        &parse_bundle_id("000G40R40M30E209185GR38E2W").unwrap(),
    )
    .await
    .unwrap();
    assert!(absent.is_none());
    assert!(
        !store
            .invoice_exists(
                &creator,
                &parse_bundle_id("000G40R40M30E209185GR38E2W").unwrap(),
            )
            .await
            .unwrap()
    );

    database.cleanup().await;
}

async fn assert_confirmed_payment(
    store: &InvoiceStore,
    creator: &paykit_server::domain::locks::CreatorPubky,
    bundle: &paykit_server::domain::locks::BundleId,
) {
    assert_eq!(
        store.payment_status(creator, bundle).await.unwrap(),
        Some(PersistedPaymentStatus::Confirmed {
            confirmations: 3,
            amount_matched: true,
        })
    );
}
