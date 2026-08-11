use std::sync::Arc;

use paykit_server::{
    application::payment_request_status::{PaymentRequestStatusOperations, PaymentState},
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
             invoice_created_at, payment_deadline, payment_in_hours
         ) VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $9, $10,
                   'confirmed', 3, TRUE, $11, $12, 24)",
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

    let absent = PaymentRequestStatusOperations::lookup(
        &store,
        &creator,
        &parse_bundle_id("000G40R40M30E209185GR38E2W").unwrap(),
    )
    .await
    .unwrap();
    assert!(absent.is_none());

    database.cleanup().await;
}
