use std::{sync::Arc, time::Duration};

use paykit_lib::{
    PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    PublicKey,
};
use paykit_server::{
    application::semantic_intent::DeliveryIntentV1,
    crypto::Crypto,
    domain::locks::ReaderPubky,
    persistence::{
        InvoiceStore, OBSERVER_LEADERSHIP_LEASE_NAME, ObserverLease, PgObserverLeadership,
    },
};
use sqlx::PgPool;

/// Current leadership fence, or a newly acquired lease when the row is empty.
///
/// Tests that drive observer writes against a booted server must share the
/// live holder's fence rather than steal the lease.
pub async fn observer_lease(pool: &PgPool) -> ObserverLease {
    if let Some((holder, fence)) = sqlx::query_as::<_, (uuid::Uuid, i64)>(
        "SELECT holder, fence FROM observer_leadership WHERE name = $1",
    )
    .bind(OBSERVER_LEADERSHIP_LEASE_NAME)
    .fetch_optional(pool)
    .await
    .expect("read observer_leadership")
    {
        return ObserverLease { holder, fence };
    }
    PgObserverLeadership::new(pool, Duration::from_secs(30))
        .acquire()
        .await
        .expect("acquire test observer lease")
        .expect("test observer lease")
}

pub async fn fenced_invoice_store(pool: &PgPool, crypto: Arc<Crypto>) -> InvoiceStore {
    InvoiceStore::new(pool, crypto).with_observer_lease(observer_lease(pool).await)
}

fn marker() -> PaykitReceiverMarker {
    PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
    )
}

pub fn endpoint_intent(reader: &ReaderPubky, address: String) -> DeliveryIntentV1 {
    DeliveryIntentV1::endpoint(
        reader.to_string(),
        &marker(),
        PaykitReceiverPath::new("paykit/server").unwrap(),
        vec![(
            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            PaymentEndpointPayload::new(address),
        )],
    )
    .unwrap()
}

pub fn payment_intent(reader: &ReaderPubky) -> DeliveryIntentV1 {
    DeliveryIntentV1::payment_request(
        reader.to_string(),
        &marker(),
        PaykitReceiverPath::new("paykit/server").unwrap(),
        &PaymentRequestTerms {
            amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
            payment_reference: PaymentReference::new(uuid::Uuid::new_v4().to_string()).unwrap(),
            proposal_expires_at: None,
            recurrence: None,
            accepted_payment_endpoint_identifiers: vec![
                PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            ],
            metadata: Default::default(),
        },
    )
    .unwrap()
}
