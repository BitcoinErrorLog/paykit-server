use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use paykit_lib::{
    PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount, PaymentEndpointIdentifier,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    InMemoryStorage, LinkedPeerState, OutboundPrivateMessageStatus, PaykitReceiverCapabilities,
    PaykitSdk, PaykitSdkConfig, PaykitSdkError, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionBootstrap, ReceiverNoiseSecretKey, StorageAdapter, storage::StorageState,
};
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    crypto::Crypto,
    domain::locks::{
        BundleId, CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader,
    },
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, HandoffFenceSeam, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, OutboxStore, PersistenceError,
        PostgresStorageAdapter, SdkStateStore, run_migrations,
    },
    runtime::{
        ElectrumProbe, OutboxTerminalHealth, PostgresDependency, Runtime, operational_router,
    },
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffStage, process_claim,
        process_reconciliation,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use tower::ServiceExt;
use uuid::Uuid;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
}

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).unwrap()
}

fn reader() -> ReaderPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

struct Payloads {
    reader: ReaderPubky,
}

impl NewReaderPayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        let address = format!("outbox-test-address-{child_index}");
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(&self.reader, address.clone()),
            bitcoin_address: address,
        })
    }
}

struct ReconciliationAdapter {
    statuses: Mutex<VecDeque<OutboundPrivateMessageStatus>>,
}

#[async_trait]
impl Adapter for ReconciliationAdapter {
    async fn fetch_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError> {
        Ok(None)
    }

    async fn ensure_link_with_peer(&self, _reader: &str, _path: &str) -> Result<(), HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        _reader: &str,
        _path: &str,
        _details: &[paykit_server::application::semantic_intent::ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _terms: &paykit_server::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        Ok(self.statuses.lock().unwrap().pop_front())
    }
}

async fn assert_reconciliation_status(
    database: &TestDatabase,
    outbox: &OutboxStore,
    outbound_id: u64,
    sdk_status: OutboundPrivateMessageStatus,
    expected_status: &str,
    expected_error_class: &str,
) {
    let row_id: Uuid = sqlx::query_scalar(
        "INSERT INTO outbox \
         (creator_id, intent_envelope, status, sdk_outbound_message_id) \
         SELECT id, decode('00', 'hex'), 'handed_off', $1 FROM creators LIMIT 1 \
         RETURNING id",
    )
    .bind(outbound_id.to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let claims = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    let claim = claims
        .iter()
        .find(|claim| claim.id() == row_id)
        .expect("inserted reconciliation row was claimable");
    let adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([sdk_status])),
    };
    assert!(
        process_reconciliation(outbox, &adapter, claim, Duration::from_secs(5))
            .await
            .unwrap()
    );
    let actual: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status, next_attempt_at > NOW(), error_class FROM outbox WHERE id = $1",
    )
    .bind(row_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(actual.0, expected_status);
    assert_eq!(actual.2.as_deref(), Some(expected_error_class));
    if expected_status == "handed_off" {
        assert!(actual.1, "retryable SDK status did not receive backoff");
    }
    sqlx::query("DELETE FROM outbox_terminal_events WHERE outbox_id = $1")
        .bind(row_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM outbox WHERE id = $1")
        .bind(row_id)
        .execute(database.pool())
        .await
        .unwrap();
}

/// Distinct canonical key tails so the fingerprint-to-seller binding written
/// by every create/reauthenticate never collides within a test database.
fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}

async fn create_activated_invoice(
    database: &TestDatabase,
    crypto: Arc<Crypto>,
    bundle: &str,
) -> (CreatorPubky, BundleId, InvoiceStore, Uuid, Uuid, Uuid) {
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session-secret".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub-secret".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(40),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let invoices = InvoiceStore::new(database.pool(), crypto);
    let invoice = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: bundle.as_bytes(),
            payment_request_binding: b"delivery-status-payment-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    invoices
        .activate_invoice(invoice.invoice_id(), &[], &[])
        .await
        .unwrap();
    (
        creator,
        parse_bundle_id(bundle).unwrap(),
        invoices,
        invoice.invoice_id(),
        invoice.endpoint_publication_outbox_id().unwrap(),
        invoice.payment_request_outbox_id(),
    )
}

async fn create_prepared_invoice(
    database: &TestDatabase,
    crypto: Arc<Crypto>,
    bundle: &str,
) -> (InvoiceStore, Uuid, Uuid, Uuid) {
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session-secret".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub-secret".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(51),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let invoices = InvoiceStore::new(database.pool(), crypto);
    let invoice = invoices
        .create_awaiting_baseline(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: bundle.as_bytes(),
            payment_request_binding: b"prepared-outbox-payment-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    invoices
        .complete_creation_baseline(invoice.invoice_id(), 0, &[], &[])
        .await
        .unwrap();
    (
        invoices,
        invoice.invoice_id(),
        invoice.endpoint_publication_outbox_id().unwrap(),
        invoice.payment_request_outbox_id(),
    )
}

async fn delivery_status(
    invoices: &InvoiceStore,
    creator: &CreatorPubky,
    bundle: &BundleId,
) -> paykit_server::application::payment_status::DeliveryStatus {
    invoices
        .delivery_status(creator, bundle)
        .await
        .unwrap()
        .unwrap()
}

async fn outbox_row(
    database: &TestDatabase,
    id: Uuid,
) -> (String, Option<String>, Option<String>, Option<Uuid>) {
    sqlx::query_as(
        "SELECT status, error_class, failure_reason, claim_token FROM outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(database.pool())
    .await
    .unwrap()
}

struct CountingAdapter {
    sdk_calls: AtomicUsize,
}

#[async_trait]
impl Adapter for CountingAdapter {
    async fn fetch_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError> {
        self.sdk_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    async fn ensure_link_with_peer(&self, _reader: &str, _path: &str) -> Result<(), HandoffError> {
        self.sdk_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        _reader: &str,
        _path: &str,
        _details: &[paykit_server::application::semantic_intent::ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        self.sdk_calls.fetch_add(1, Ordering::SeqCst);
        Err(HandoffError::Permanent)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _terms: &paykit_server::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        self.sdk_calls.fetch_add(1, Ordering::SeqCst);
        Err(HandoffError::Permanent)
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        self.sdk_calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

#[tokio::test]
async fn delivery_aggregate_reports_pending_then_delivered_for_ordinary_invoice() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[41; 32]).unwrap());
    let (creator, bundle, invoices, _invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    let pending = delivery_status(&invoices, &creator, &bundle).await;
    let rows: Vec<(Option<Uuid>, Option<Uuid>, i64, String)> = sqlx::query_as(
        "SELECT invoice_id, depends_on_id, generation, status FROM outbox ORDER BY id",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        rows.iter()
            .filter(|(invoice_id, _, _, _)| invoice_id.is_some())
            .count(),
        2,
        "rows: {rows:?}"
    );
    let pairs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox request \
         JOIN outbox endpoint ON endpoint.id = request.depends_on_id \
         WHERE request.invoice_id = $1 AND endpoint.invoice_id = $1",
    )
    .bind(_invoice_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(pairs, 1, "rows: {rows:?}");
    assert!(
        pending.state == "pending_delivery",
        "state={}, rows={rows:?}",
        pending.state
    );
    assert_eq!(pending.generation, _invoice_id);

    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '1' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let endpoint_delivered = delivery_status(&invoices, &creator, &bundle).await;
    assert_eq!(endpoint_delivered.state, "pending_delivery");
    assert!(endpoint_delivered.revision > pending.revision);

    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '2' WHERE id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();
    let delivered = delivery_status(&invoices, &creator, &bundle).await;
    assert_eq!(delivered.state, "delivered");
    assert!(delivered.revision > endpoint_delivered.revision);

    database.cleanup().await;
}

#[tokio::test]
async fn delivery_aggregate_precedence_and_malformed_shape() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[42; 32]).unwrap());
    let (creator, bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    sqlx::query(
        "INSERT INTO outbox (creator_id, invoice_id, intent_envelope, status, depends_on_id) \
         SELECT creator_id, invoice_id, intent_envelope, 'queued', depends_on_id FROM outbox WHERE id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error"
    );

    sqlx::query("DELETE FROM outbox WHERE invoice_id = $1 AND id != $2 AND id != $3")
        .bind(invoice_id)
        .bind(endpoint_id)
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '4' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE outbox
         SET status = 'delivered', sdk_outbound_message_id = '5', generation_id = gen_random_uuid()
         WHERE id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error"
    );

    sqlx::query("UPDATE outbox SET generation_id = $1 WHERE id = $2")
        .bind(invoice_id)
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("ALTER TABLE outbox DROP CONSTRAINT outbox_status_check")
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET status = 'unknown' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error"
    );

    sqlx::query("UPDATE outbox SET status = 'queued' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '3' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE outbox SET status = 'permanently_failed' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "failed"
    );
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "cancelled"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn creation_ceiling_alarm_and_health_expose_exact_configured_values() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[70; 32]).unwrap());
    // The exact configured production ceilings: 20 attempts and one hour.
    let link_establishment_max_attempts = 20;
    let link_establishment_max_age = Duration::from_secs(60 * 60);
    let metrics = Arc::new(paykit_server::metrics::Metrics::new());
    let invoices = InvoiceStore::new(database.pool(), crypto.clone())
        .with_outbox_ceiling_alarm(link_establishment_max_age, metrics.clone());
    create_creator_once(&database, crypto, 70).await;

    let runtime = health_runtime(database.pool());
    runtime.set_paykit_delivery_available(true);
    runtime.set_outbox_available(true);
    runtime.set_outbox_link_establishment_ceiling(
        link_establishment_max_attempts,
        link_establishment_max_age,
    );
    let app = operational_router(Router::new(), runtime.clone());

    // An invoice whose remaining request lifetime exceeds the ceiling does
    // not alarm.
    let reader = reader();
    invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader,
            bundle_binding: b"ceiling-long-bundle",
            payment_request_binding: b"ceiling-long-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(2),
        })
        .await
        .unwrap();
    // An invoice whose remaining request lifetime is shorter than the exact
    // configured ceiling increments the relationship alarm.
    invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader: &reader,
            bundle_binding: b"ceiling-short-bundle",
            payment_request_binding: b"ceiling-short-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(30),
        })
        .await
        .unwrap();
    let encoded = metrics.encode().unwrap();
    assert!(
        encoded.contains("paykit_outbox_ceiling_exceeds_invoice_total 1"),
        "metrics: {encoded}"
    );

    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["outbox_link_establishment_max_attempts"], 20);
    assert_eq!(ready["outbox_link_establishment_max_age_seconds"], 3600);
    database.cleanup().await;
}

#[tokio::test]
async fn failed_pair_with_extra_invoice_row_reports_contract_error() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[67; 32]).unwrap());
    let (creator, bundle, invoices, invoice_id, _endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    sqlx::query("UPDATE outbox SET status = 'permanently_failed' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "failed"
    );
    sqlx::query(
        "INSERT INTO outbox (creator_id, invoice_id, intent_envelope, status, depends_on_id) \
         SELECT creator_id, invoice_id, intent_envelope, 'queued', depends_on_id FROM outbox WHERE id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a valid failed pair plus an extra invoice-scoped row is malformed"
    );
    let _ = invoice_id;
    database.cleanup().await;
}

#[tokio::test]
async fn failed_pair_with_mixed_generation_reports_contract_error() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[68; 32]).unwrap());
    let (creator, bundle, invoices, _invoice_id, _endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    sqlx::query("UPDATE outbox SET generation_id = gen_random_uuid() WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET status = 'permanently_failed' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a failed pair split across generations is malformed"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn failed_pair_with_malformed_link_reports_contract_error() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[69; 32]).unwrap());
    let (creator, bundle, invoices, _invoice_id, _endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    sqlx::query("UPDATE outbox SET depends_on_id = NULL WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET status = 'permanently_failed' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a failed row without its endpoint dependency link is malformed"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn finality_before_worker_preflight_yields_zero_sdk_calls() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[43; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(!outbox.invoice_is_final(claim.invoice_id()).await.unwrap());
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );

    let adapter = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        !process_claim(
            &outbox,
            &adapter,
            &claim,
            Duration::from_secs(1),
            20,
            Duration::from_secs(60 * 60),
        )
        .await
        .unwrap()
    );
    assert_eq!(adapter.sdk_calls.load(Ordering::SeqCst), 0);
    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE id = $1")
        .bind(endpoint_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_ne!(status, "handed_off");
    database.cleanup().await;
}

/// Counts complete SDK handoffs through the production `execute_handoff`
/// entrypoint and always succeeds with one fixed attributable result.
struct FencedHandoffAdapter {
    handoffs: AtomicUsize,
    result: HandoffResult,
}

#[async_trait]
impl Adapter for FencedHandoffAdapter {
    async fn execute_handoff(
        &self,
        _intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        Ok(self.result.clone())
    }

    async fn fetch_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError> {
        panic!("execute_handoff is overridden; preflight never runs")
    }

    async fn ensure_link_with_peer(&self, _reader: &str, _path: &str) -> Result<(), HandoffError> {
        panic!("execute_handoff is overridden; preflight never runs")
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        _reader: &str,
        _path: &str,
        _details: &[paykit_server::application::semantic_intent::ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        panic!("execute_handoff is overridden; preflight never runs")
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _terms: &paykit_server::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        panic!("execute_handoff is overridden; preflight never runs")
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        panic!("execute_handoff is overridden; reconciliation never runs")
    }
}

/// Barrier winner 1: the production fence commits first. Cancellation must
/// preserve the fenced row as in-flight (never terminalize it), and the SDK
/// effect is attributed on completion.
#[tokio::test]
async fn handoff_fence_committed_before_cancellation_attributes_sdk_effect() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[55; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let fence_committed = Arc::new(tokio::sync::Notify::new());
    let release_worker = Arc::new(tokio::sync::Notify::new());
    let outbox =
        OutboxStore::new(database.pool(), crypto).with_handoff_fence_seam(HandoffFenceSeam {
            after_preflight: None,
            after_fence: Some(Arc::new({
                let fence_committed = fence_committed.clone();
                let release_worker = release_worker.clone();
                move || {
                    let fence_committed = fence_committed.clone();
                    let release_worker = release_worker.clone();
                    Box::pin(async move {
                        fence_committed.notify_one();
                        release_worker.notified().await;
                    })
                }
            })),
        });
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    let adapter = Arc::new(FencedHandoffAdapter {
        handoffs: AtomicUsize::new(0),
        result: HandoffResult::EndpointPublication {
            outbound_message_id: 42,
        },
    });
    let worker = {
        let outbox = outbox.clone();
        let adapter = adapter.clone();
        tokio::spawn(async move {
            process_claim(
                &outbox,
                adapter.as_ref(),
                &claim,
                Duration::from_secs(1),
                20,
                Duration::from_secs(60 * 60),
            )
            .await
        })
    };
    // The production fence is committed; cancellation commits second, on
    // another connection, and must preserve the in-flight row.
    fence_committed.notified().await;
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await.0,
        "handoff_started"
    );
    assert_eq!(
        outbox_row(&database, request_id).await,
        (
            "permanently_failed".into(),
            Some("invoice_abandoned".into()),
            Some("invoice_abandoned".into()),
            None,
        )
    );
    release_worker.notify_one();
    assert!(worker.await.unwrap().unwrap());
    assert_eq!(adapter.handoffs.load(Ordering::SeqCst), 1);
    let attributed: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(attributed, ("handed_off".into(), Some("42".into())));
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(events, 0, "a preserved fenced row is never terminalized");
    database.cleanup().await;
}

/// Barrier winner 2: cancellation commits first. The production fence CAS
/// then matches zero rows and the worker performs zero SDK calls.
#[tokio::test]
async fn cancellation_committed_before_handoff_fence_yields_zero_sdk_calls() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[56; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let preflight_done = Arc::new(tokio::sync::Notify::new());
    let release_worker = Arc::new(tokio::sync::Notify::new());
    let outbox =
        OutboxStore::new(database.pool(), crypto).with_handoff_fence_seam(HandoffFenceSeam {
            after_preflight: Some(Arc::new({
                let preflight_done = preflight_done.clone();
                let release_worker = release_worker.clone();
                move || {
                    let preflight_done = preflight_done.clone();
                    let release_worker = release_worker.clone();
                    Box::pin(async move {
                        preflight_done.notify_one();
                        release_worker.notified().await;
                    })
                }
            })),
            after_fence: None,
        });
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    let adapter = Arc::new(FencedHandoffAdapter {
        handoffs: AtomicUsize::new(0),
        result: HandoffResult::EndpointPublication {
            outbound_message_id: 43,
        },
    });
    let worker = {
        let outbox = outbox.clone();
        let adapter = adapter.clone();
        tokio::spawn(async move {
            process_claim(
                &outbox,
                adapter.as_ref(),
                &claim,
                Duration::from_secs(1),
                20,
                Duration::from_secs(60 * 60),
            )
            .await
        })
    };
    // The production preflight passed against a non-final invoice;
    // cancellation commits first, on another connection, before the fence.
    preflight_done.notified().await;
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    release_worker.notify_one();
    assert!(!worker.await.unwrap().unwrap());
    assert_eq!(adapter.handoffs.load(Ordering::SeqCst), 0);
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("invoice_abandoned".into()),
            Some("invoice_abandoned".into()),
            None,
        )
    );
    database.cleanup().await;
}

#[tokio::test]
async fn link_establishment_attempt_19_proceeds_and_20_exhausts() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[44; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);

    sqlx::query(
        "UPDATE outbox SET attempt_count = 18, error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim_19 = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim_19.attempt_count(), 19);
    assert!(
        !outbox
            .exhaust_claim_if_due(&claim_19, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );

    sqlx::query(
        "UPDATE outbox SET status = 'retryable', lease_owner = NULL, claim_token = NULL, \
         lease_expires_at = NULL, next_attempt_at = NOW(), attempt_count = 19, \
         error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim_20 = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim_20.attempt_count(), 20);
    assert!(
        outbox
            .exhaust_claim_if_due(&claim_20, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("link_establishment_exhausted".into()),
            Some("attempt_ceiling".into()),
            None,
        )
    );
    database.cleanup().await;
}

#[tokio::test]
async fn link_establishment_age_just_before_proceeds_and_at_bound_exhausts() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[45; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);

    sqlx::query(
        "UPDATE outbox SET created_at = NOW() - INTERVAL '59 minutes 59 seconds', \
         error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let before = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        !outbox
            .exhaust_claim_if_due(&before, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );

    sqlx::query(
        "UPDATE outbox SET created_at = NOW() - INTERVAL '60 minutes', \
         error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        outbox
            .exhaust_claim_if_due(&before, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await.2.as_deref(),
        Some("age_ceiling")
    );
    database.cleanup().await;
}

#[tokio::test]
async fn exhaust_claim_if_due_is_noop_with_stale_token() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[46; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    sqlx::query(
        "UPDATE outbox SET attempt_count = 19, error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    sqlx::query("UPDATE outbox SET claim_token = gen_random_uuid() WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        !outbox
            .exhaust_claim_if_due(&claim, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    assert_eq!(outbox_row(&database, endpoint_id).await.0, "leased");
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(events, 0);
    database.cleanup().await;
}

#[tokio::test]
async fn exhaustion_makes_zero_adapter_constructions_and_calls() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[47; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    sqlx::query(
        "UPDATE outbox SET attempt_count = 19, error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let adapter = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_claim(
            &outbox,
            &adapter,
            &claim,
            Duration::ZERO,
            20,
            Duration::from_secs(60 * 60)
        )
        .await
        .unwrap()
    );
    assert_eq!(adapter.sdk_calls.load(Ordering::SeqCst), 0);
    database.cleanup().await;
}

#[tokio::test]
async fn exhaustion_cascades_descendants_with_exactly_one_terminal_event() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[48; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    sqlx::query(
        "UPDATE outbox SET attempt_count = 19, error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        outbox
            .exhaust_claim_if_due(&claim, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    for id in [endpoint_id, request_id] {
        assert_eq!(outbox_row(&database, id).await.0, "permanently_failed");
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
                .bind(id)
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(events, 1);
    }
    assert_eq!(
        outbox_row(&database, request_id).await.1.as_deref(),
        Some("dependency_failed")
    );
    database.cleanup().await;
}

#[tokio::test]
async fn permanent_failure_cascades_dependents_and_reports_failed() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[52; 32]).unwrap());
    let (creator, bundle, invoices, _invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(outbox.mark_permanently_failed(&claim).await.unwrap());

    for id in [endpoint_id, request_id] {
        assert_eq!(outbox_row(&database, id).await.0, "permanently_failed");
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
                .bind(id)
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(events, 1);
    }
    assert_eq!(
        outbox_row(&database, request_id).await.1.as_deref(),
        Some("dependency_failed")
    );
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "failed"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn generation_id_matches_invoice_for_ordinary_invoices() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[53; 32]).unwrap());
    let (_creator, _bundle, _invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;
    let generation_ids: Vec<Option<Uuid>> =
        sqlx::query_scalar("SELECT generation_id FROM outbox WHERE id = ANY($1) ORDER BY id")
            .bind(vec![endpoint_id, request_id])
            .fetch_all(database.pool())
            .await
            .unwrap();
    assert_eq!(generation_ids, vec![Some(invoice_id), Some(invoice_id)]);
    database.cleanup().await;
}

#[tokio::test]
async fn abandonment_first_keeps_resolution_immutable_under_later_observation() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[54; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, _endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query(
        "UPDATE invoices
         SET payment_status = 'confirmed', confirmation_count = 1, amount_matched = TRUE
         WHERE id = $1",
    )
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let resolution: Option<String> =
        sqlx::query_scalar("SELECT resolution FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(resolution.as_deref(), Some("abandoned"));
    database.cleanup().await;
}

#[tokio::test]
async fn final_invoice_rows_are_never_claimed() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[49; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, _endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        OutboxStore::new(database.pool(), crypto)
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn void_and_abandoned_terminalize_non_handed_off_rows() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[50; 32]).unwrap());
    let (prepared_invoices, prepared_id, prepared_endpoint_id, prepared_request_id) =
        create_prepared_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    assert!(
        prepared_invoices
            .void_invoice(prepared_id)
            .await
            .unwrap()
            .is_some()
    );
    for id in [prepared_endpoint_id, prepared_request_id] {
        assert_eq!(outbox_row(&database, id).await.0, "permanently_failed");
        assert_eq!(
            outbox_row(&database, id).await.1.as_deref(),
            Some("invoice_voided")
        );
    }
    database.cleanup().await;

    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[51; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let endpoint_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(outbox.begin_handoff(&endpoint_claim).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(
                &endpoint_claim,
                &HandoffResult::EndpointPublication {
                    outbound_message_id: 99,
                },
            )
            .await
            .unwrap()
    );
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(outbox_row(&database, endpoint_id).await.0, "handed_off");
    assert_eq!(
        outbox_row(&database, request_id).await.0,
        "permanently_failed"
    );
    assert_eq!(
        outbox_row(&database, request_id).await.1.as_deref(),
        Some("invoice_abandoned")
    );
    database.cleanup().await;
}

#[tokio::test]
async fn every_claimed_invoice_row_has_one_complete_decryptable_intent_and_dependency_order() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session-secret".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub-secret".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(20),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let payloads = Payloads {
        reader: reader.clone(),
    };
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"outbox-bundle",
            payment_request_binding: b"outbox-payment-request",
            new_reader_payloads: &payloads,
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: std::time::Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto);

    let endpoint_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(endpoint_claims.len(), 1);
    assert_eq!(
        endpoint_claims[0].id(),
        invoice.endpoint_publication_outbox_id().unwrap()
    );
    assert!(matches!(
        outbox.delivery_intent(&endpoint_claims[0]).unwrap().operation(),
        DeliveryOperationV1::EndpointPublication { receiving_details }
            if receiving_details.len() == 1
    ));
    let retry_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::new()),
    };
    assert!(
        process_claim(
            &outbox,
            &retry_adapter,
            &endpoint_claims[0],
            Duration::from_secs(5),
            20,
            Duration::from_secs(60 * 60),
        )
        .await
        .unwrap()
    );
    let retry_state: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status, next_attempt_at > NOW(), error_class FROM outbox WHERE id = $1",
    )
    .bind(endpoint_claims[0].id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        retry_state,
        ("retryable".into(), true, Some("marker_missing".into()))
    );
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE id = $1")
        .bind(endpoint_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let endpoint_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(endpoint_claims.len(), 1);
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(endpoint_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let reclaimed_endpoint = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reclaimed_endpoint.len(), 1);
    assert!(
        !outbox
            .mark_handed_off(
                &endpoint_claims[0],
                &HandoffResult::EndpointPublication {
                    outbound_message_id: 16,
                },
            )
            .await
            .unwrap(),
        "an expired fence overwrote reclaimed work"
    );
    assert!(outbox.begin_handoff(&reclaimed_endpoint[0]).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(
                &reclaimed_endpoint[0],
                &HandoffResult::EndpointPublication {
                    outbound_message_id: 17,
                },
            )
            .await
            .unwrap()
    );
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "dependent work must remain blocked at handed_off"
    );
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reconciliation.len(), 1);
    assert_eq!(reconciliation[0].sdk_outbound_message_id().unwrap(), 17);
    let reconciliation_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([
            OutboundPrivateMessageStatus::Pending,
            OutboundPrivateMessageStatus::Sent,
        ])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &reconciliation_adapter,
            &reconciliation[0],
            Duration::ZERO,
        )
        .await
        .unwrap()
    );
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "Pending SDK state unblocked dependent work"
    );
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reconciliation.len(), 1);
    assert!(
        process_reconciliation(
            &outbox,
            &reconciliation_adapter,
            &reconciliation[0],
            Duration::ZERO,
        )
        .await
        .unwrap()
    );

    let payment_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(payment_claims.len(), 1);
    assert_eq!(payment_claims[0].id(), invoice.payment_request_outbox_id());
    assert!(matches!(
        outbox
            .delivery_intent(&payment_claims[0])
            .unwrap()
            .operation(),
        DeliveryOperationV1::PaymentRequestProposal { .. }
    ));
    assert!(outbox.begin_handoff(&payment_claims[0]).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(
                &payment_claims[0],
                &HandoffResult::PaymentRequestProposal {
                    outbound_message_id: 18,
                    event_id: "event-18".into(),
                    payment_request_id: "request-18".into(),
                },
            )
            .await
            .unwrap()
    );
    let ids: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id FROM outbox WHERE id = $1",
    )
    .bind(payment_claims[0].id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        ids,
        (
            "18".into(),
            Some("event-18".into()),
            Some("request-18".into())
        )
    );

    let failed_reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(failed_reconciliation.len(), 1);
    let failed_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Failed])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &failed_adapter,
            &failed_reconciliation[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let failed_status: (String, bool) =
        sqlx::query_as("SELECT status, next_attempt_at > NOW() FROM outbox WHERE id = $1")
            .bind(payment_claims[0].id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(failed_status, ("handed_off".into(), true));
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE id = $1")
        .bind(payment_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let sent_reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(sent_reconciliation.len(), 1);
    let sent_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Sent])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &sent_adapter,
            &sent_reconciliation[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let sent_status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE id = $1")
        .bind(payment_claims[0].id())
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(sent_status, "delivered");

    for (offset, status) in [
        OutboundPrivateMessageStatus::Pending,
        OutboundPrivateMessageStatus::Sending,
    ]
    .into_iter()
    .enumerate()
    {
        assert_reconciliation_status(
            &database,
            &outbox,
            100 + offset as u64,
            status,
            "handed_off",
            "reconciliation_pending",
        )
        .await;
    }
    for (offset, status) in [
        OutboundPrivateMessageStatus::Invalid,
        OutboundPrivateMessageStatus::RecoveryRequired,
        OutboundPrivateMessageStatus::Superseded,
    ]
    .into_iter()
    .enumerate()
    {
        assert_reconciliation_status(
            &database,
            &outbox,
            200 + offset as u64,
            status,
            "permanently_failed",
            "permanent_sdk_reconciliation",
        )
        .await;
    }

    let corrupt_id: Uuid = sqlx::query_scalar(
        "INSERT INTO outbox (creator_id, intent_envelope, status) \
         SELECT id, decode('00', 'hex'), 'queued' FROM creators LIMIT 1 RETURNING id",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let corrupt_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(corrupt_claim.len(), 1);
    assert_eq!(corrupt_claim[0].id(), corrupt_id);
    assert!(
        process_claim(
            &outbox,
            &retry_adapter,
            &corrupt_claim[0],
            Duration::from_secs(5),
            20,
            Duration::from_secs(60 * 60),
        )
        .await
        .unwrap()
    );
    let corrupt_status: (String, Option<String>) =
        sqlx::query_as("SELECT status, error_class FROM outbox WHERE id = $1")
            .bind(corrupt_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(
        corrupt_status,
        ("permanently_failed".into(), Some("permanent".into()))
    );

    let missing_intent_insert = sqlx::query(
        "INSERT INTO outbox (creator_id, status) SELECT id, 'queued' FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        missing_intent_insert.is_err(),
        "schema accepted a claimable row without an intent"
    );
    let unattributed_handoff = sqlx::query(
        "INSERT INTO outbox (creator_id, intent_envelope, status) \
         SELECT id, decode('00', 'hex'), 'handed_off' FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        unattributed_handoff.is_err(),
        "schema accepted handed_off without an SDK outbound ID"
    );
    let unpaired_payment_ids = sqlx::query(
        "INSERT INTO outbox (creator_id, intent_envelope, status, sdk_event_id) \
         SELECT id, decode('00', 'hex'), 'queued', 'event-only' FROM creators LIMIT 1",
    )
    .execute(database.pool())
    .await;
    assert!(
        unpaired_payment_ids.is_err(),
        "schema accepted an unpaired SDK Event ID"
    );

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_sdk_payment_request_retry_persists_distinct_ids_and_only_active_claim_associates() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let crypto = Arc::new(Crypto::from_master_key(&[11; 32]).unwrap());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let bootstrap = PubkySessionBootstrap::with_pubky(testnet.sdk().unwrap());

    let creator_receiver_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    let creator_keypair = Keypair::random();
    let creator_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(creator_receiver_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_bootstrap.public_key)).unwrap();
    let creator_row = CreatorStore::new(database.pool(), crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                creator_bootstrap.access.session.export_secret(),
                creator_bootstrap.access.receiver_noise_secret_key.clone(),
                "unused-test-xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(21),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let creator_storage =
        PostgresStorageAdapter::new(database.pool(), crypto.clone(), creator_row.id());
    let creator_sdk = PaykitSdk::new(
        creator_storage.clone(),
        TestSessionProvider::new(creator_bootstrap.access.clone()),
        TestPaymentAdapter,
        PaykitSdkConfig::new(creator_receiver_path.clone()),
    )
    .unwrap();
    creator_sdk.initialize().await.unwrap();
    creator_sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        })
        .await
        .unwrap();

    let peer_receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let peer_keypair = Keypair::random();
    let peer_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(peer_keypair.secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(peer_receiver_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let peer_sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(peer_bootstrap.access.clone()),
        TestPaymentAdapter,
        PaykitSdkConfig::new(peer_receiver_path.clone()),
    )
    .unwrap();
    peer_sdk.initialize().await.unwrap();
    peer_sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        })
        .await
        .unwrap();

    creator_sdk
        .initiate_link_with_peer(
            peer_bootstrap.public_key.clone(),
            peer_receiver_path.clone(),
        )
        .await
        .unwrap();
    peer_sdk
        .accept_link_with_peer(
            creator_bootstrap.public_key.clone(),
            creator_receiver_path.clone(),
        )
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_link = LinkedPeerState::Linking;
    let mut peer_link = LinkedPeerState::Linking;
    while creator_link != LinkedPeerState::Linked || peer_link != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_link != LinkedPeerState::Linked {
            creator_link = creator_sdk
                .advance_link_handshake(
                    peer_bootstrap.public_key.clone(),
                    peer_receiver_path.clone(),
                )
                .await
                .unwrap()
                .state;
        }
        if peer_link != LinkedPeerState::Linked {
            peer_link = peer_sdk
                .advance_link_handshake(
                    creator_bootstrap.public_key.clone(),
                    creator_receiver_path.clone(),
                )
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let reader = parse_reader(&format!("pubky{}", peer_bootstrap.public_key)).unwrap();
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"public-sdk-crash-window-bundle",
            payment_request_binding: b"public-sdk-crash-window-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: std::time::Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '0' WHERE id = $1",
    )
    .bind(invoice.endpoint_publication_outbox_id().unwrap())
    .execute(database.pool())
    .await
    .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let first_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_claim.id(), invoice.payment_request_outbox_id());
    let intent = outbox.delivery_intent(&first_claim).unwrap();
    let terms = match intent.operation() {
        DeliveryOperationV1::PaymentRequestProposal { terms } => PaymentRequestTerms {
            amount: PaymentAmount::new(terms.amount.clone(), terms.asset.clone()).unwrap(),
            payment_reference: PaymentReference::new(terms.payment_reference.clone()).unwrap(),
            proposal_expires_at: terms.proposal_expires_at.clone(),
            recurrence: None,
            accepted_payment_endpoint_identifiers: terms
                .accepted_endpoint_identifiers
                .iter()
                .cloned()
                .map(PaymentEndpointIdentifier::new)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            metadata: terms.metadata.clone(),
        },
        DeliveryOperationV1::EndpointPublication { .. } => panic!("claimed endpoint row"),
    };

    let first = creator_sdk
        .propose_payment_request(
            peer_bootstrap.public_key.clone(),
            peer_receiver_path.clone(),
            terms.clone(),
        )
        .await
        .unwrap();
    let first_result = HandoffResult::PaymentRequestProposal {
        outbound_message_id: first.proposal_outbound_message_id.unwrap(),
        event_id: first.proposal_event_id.unwrap(),
        payment_request_id: first.payment_request_id,
    };

    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(first_claim.id())
        .execute(database.pool())
        .await
        .unwrap();
    let second_claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let second = creator_sdk
        .propose_payment_request(peer_bootstrap.public_key, peer_receiver_path, terms)
        .await
        .unwrap();
    let second_result = HandoffResult::PaymentRequestProposal {
        outbound_message_id: second.proposal_outbound_message_id.unwrap(),
        event_id: second.proposal_event_id.unwrap(),
        payment_request_id: second.payment_request_id,
    };

    let (first_outbound, first_event, first_request) = match &first_result {
        HandoffResult::PaymentRequestProposal {
            outbound_message_id,
            event_id,
            payment_request_id,
        } => (*outbound_message_id, event_id, payment_request_id),
        HandoffResult::EndpointPublication { .. } => unreachable!(),
    };
    let (second_outbound, second_event, second_request) = match &second_result {
        HandoffResult::PaymentRequestProposal {
            outbound_message_id,
            event_id,
            payment_request_id,
        } => (*outbound_message_id, event_id, payment_request_id),
        HandoffResult::EndpointPublication { .. } => unreachable!(),
    };
    assert_ne!(first_outbound, second_outbound);
    assert_ne!(first_event, second_event);
    assert_ne!(first_request, second_request);

    let durable_state = SdkStateStore::new(database.pool(), crypto)
        .load(&creator)
        .await
        .unwrap();
    for (outbound_id, event_id, request_id) in [
        (first_outbound, first_event, first_request),
        (second_outbound, second_event, second_request),
    ] {
        let outbound = durable_state
            .outbound_private_messages
            .iter()
            .find(|record| record.outbound_message_id == outbound_id)
            .expect("SDK-generated outbound ID was not durable");
        assert!(outbound.raw_json.contains(event_id));
        assert!(outbound.raw_json.contains(request_id));
    }

    assert!(
        !outbox
            .mark_handed_off(&first_claim, &first_result)
            .await
            .unwrap()
    );
    assert!(outbox.begin_handoff(&second_claim).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(&second_claim, &second_result)
            .await
            .unwrap()
    );
    let associated: (String, String, String) = sqlx::query_as(
        "SELECT sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id \
         FROM outbox WHERE id = $1",
    )
    .bind(second_claim.id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        associated,
        (
            second_outbound.to_string(),
            second_event.clone(),
            second_request.clone(),
        )
    );

    drop(testnet);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_sdk_transactions_are_durable_and_creator_isolated() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[8; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let first_creator = creator();
    let mut second_creator = None;
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(value) = parse_creator(&candidate)
            && value != first_creator
        {
            second_creator = Some(value);
            break;
        }
    }
    let second_creator = second_creator.expect("second valid creator fixture");
    let first = creators
        .create(
            &CreatorCredentials::new(
                first_creator,
                "first-session".into(),
                ReceiverNoiseSecretKey::new([1; 32]),
                "first-xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(22),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let second = creators
        .create(
            &CreatorCredentials::new(
                second_creator,
                "second-session".into(),
                ReceiverNoiseSecretKey::new([2; 32]),
                "second-xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(23),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let first_storage = PostgresStorageAdapter::new(database.pool(), crypto.clone(), first.id());
    let second_storage = PostgresStorageAdapter::new(database.pool(), crypto, second.id());

    let (first_id, second_id) = tokio::join!(
        first_storage.transaction(|tx| Ok(tx.allocate_receive_batch_id())),
        second_storage.transaction(|tx| Ok(tx.allocate_receive_batch_id())),
    );
    assert_eq!(first_id.unwrap(), 0);
    assert_eq!(second_id.unwrap(), 0);
    assert_eq!(
        first_storage
            .transaction(|tx| Ok(tx.allocate_receive_batch_id()))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        second_storage
            .transaction(|tx| Ok(tx.allocate_receive_batch_id()))
            .await
            .unwrap(),
        1
    );

    let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();
    let (release_first_tx, release_first_rx) = mpsc::channel();
    let held_storage = first_storage.clone();
    let held = tokio::spawn(async move {
        held_storage
            .transaction(move |_| {
                first_entered_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    first_entered_rx.await.unwrap();

    let (same_entered_tx, mut same_entered_rx) = tokio::sync::oneshot::channel();
    let same_storage = first_storage.clone();
    let same = tokio::spawn(async move {
        same_storage
            .transaction(move |_| {
                same_entered_tx.send(()).unwrap();
                Ok(())
            })
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut same_entered_rx)
            .await
            .is_err(),
        "a second callback entered the same Creator transaction concurrently"
    );

    let (other_entered_tx, other_entered_rx) = tokio::sync::oneshot::channel();
    let other_storage = second_storage.clone();
    let other = tokio::spawn(async move {
        other_storage
            .transaction(move |_| {
                other_entered_tx.send(()).unwrap();
                Ok(())
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), other_entered_rx)
        .await
        .expect("different Creator callback did not progress concurrently")
        .unwrap();
    other.await.unwrap().unwrap();

    release_first_tx.send(()).unwrap();
    held.await.unwrap().unwrap();
    same_entered_rx.await.unwrap();
    same.await.unwrap().unwrap();

    let rolled_back: paykit_sdk::Result<()> = first_storage
        .transaction(|transaction| {
            transaction.allocate_receive_batch_id();
            Err(PaykitSdkError::Policy {
                context: "test rollback".into(),
                source: None,
            })
        })
        .await;
    assert!(rolled_back.is_err());
    assert_eq!(
        first_storage
            .transaction(|transaction| Ok(transaction.allocate_receive_batch_id()))
            .await
            .unwrap(),
        2,
        "callback error committed mutated SDK state"
    );

    database.cleanup().await;
}

fn fresh_tip_time() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// A runtime whose non-outbox dependencies report ready, so `/health/ready`
/// reflects only the persisted outbox evidence under test.
fn health_runtime(pool: &sqlx::PgPool) -> Arc<Runtime> {
    let runtime = Arc::new(Runtime::new(
        Arc::new(PostgresDependency::new(pool.clone())),
        8,
    ));
    runtime.set_electrum_available(true);
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(800_000, fresh_tip_time()));
    }
    runtime
}

/// Publishes exactly what the enqueue loop publishes after a claim pass:
/// persisted active-work availability plus durable terminal health into the
/// runtime and metrics surfaces.
async fn publish_outbox_health(outbox: &OutboxStore, runtime: &Runtime) {
    let available = outbox.delivery_available().await.unwrap();
    runtime.set_paykit_delivery_available(available);
    runtime.set_outbox_available(true);
    let health = outbox.terminal_failure_health().await.unwrap();
    runtime
        .metrics()
        .set_outbox_terminal_health(health.count, health.oldest_age_seconds);
    runtime
        .metrics()
        .observe_outbox_terminal_transitions(health.transitions);
    runtime.set_outbox_terminal_health(OutboxTerminalHealth {
        count: health.count,
        oldest_age_seconds: health.oldest_age_seconds,
        by_class: health.by_class,
    });
}

async fn ready_json(app: &Router) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn metrics_text(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

/// Persists the shared test creator once so one test can bind several
/// invoices (and therefore several claimable rows) to it.
async fn create_creator_once(database: &TestDatabase, crypto: Arc<Crypto>, tail: u8) {
    CreatorStore::new(database.pool(), crypto)
        .create(
            &CreatorCredentials::new(
                creator(),
                "session-secret".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub-secret".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(tail),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
}

/// Creates and activates one invoice for an already-persisted creator,
/// returning the (endpoint parent, payment-request child) outbox ids.
async fn create_activated_invoice_for(
    database: &TestDatabase,
    crypto: Arc<Crypto>,
    reader: &ReaderPubky,
    binding_seed: &str,
) -> (Uuid, Uuid) {
    let bundle_binding = format!("partition-bundle-{binding_seed}").into_bytes();
    let request_binding = format!("partition-request-{binding_seed}").into_bytes();
    let invoices = InvoiceStore::new(database.pool(), crypto);
    let invoice = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator(),
            reader,
            bundle_binding: &bundle_binding,
            payment_request_binding: &request_binding,
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(reader),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    invoices
        .activate_invoice(invoice.invoice_id(), &[], &[])
        .await
        .unwrap();
    (
        invoice.endpoint_publication_outbox_id().unwrap(),
        invoice.payment_request_outbox_id(),
    )
}

fn distinct_readers() -> Vec<ReaderPubky> {
    let mut readers: Vec<ReaderPubky> = Vec::new();
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(reader) = parse_reader(&candidate)
            && !readers.contains(&reader)
        {
            readers.push(reader);
        }
    }
    readers
}

#[tokio::test]
async fn terminal_transition_increments_counter_while_readiness_is_ready() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[61; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    sqlx::query(
        "UPDATE outbox SET attempt_count = 19, error_class = 'link_establishment' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        outbox
            .exhaust_claim_if_due(&claim, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("link_establishment_exhausted".into()),
            Some("attempt_ceiling".into()),
            None,
        )
    );
    assert_eq!(
        outbox_row(&database, request_id).await.0,
        "permanently_failed"
    );

    // Permanently failed rows are retained evidence, not active work.
    assert!(outbox.delivery_available().await.unwrap());
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    // A second publication must not double-count the durable transition.
    publish_outbox_health(&outbox, &runtime).await;

    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(ready["outbox_terminal_failure_count"], 2);
    assert!(
        ready["outbox_oldest_terminal_failure_age_seconds"]
            .as_i64()
            .is_some_and(|age| age >= 0)
    );
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["link_establishment_exhausted"],
        1
    );
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["dependency_failed"],
        1
    );

    let metrics = metrics_text(&app).await;
    assert!(
        metrics.contains(
            "paykit_outbox_terminal_transitions_total{class=\"link_establishment_exhausted\",reason=\"attempt_ceiling\"} 1"
        ),
        "metrics: {metrics}"
    );
    assert!(
        metrics.contains(
            "paykit_outbox_terminal_transitions_total{class=\"dependency_failed\",reason=\"parent_link_establishment_exhausted\"} 1"
        ),
        "metrics: {metrics}"
    );
    assert!(
        metrics.contains("paykit_outbox_terminal_failure_count 2"),
        "metrics: {metrics}"
    );
    let oldest = metrics
        .lines()
        .find(|line| line.starts_with("paykit_outbox_terminal_oldest_age_seconds "))
        .expect("oldest terminal age gauge is exported");
    let age: i64 = oldest.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(age >= 0);
    database.cleanup().await;
}

#[tokio::test]
async fn reconciliation_permanent_failure_writes_exactly_one_terminal_event() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[65; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handed_off(
                &claim,
                &HandoffResult::EndpointPublication {
                    outbound_message_id: 77,
                },
            )
            .await
            .unwrap()
    );
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reconciliation.len(), 1);
    let adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Invalid])),
    };
    assert!(
        process_reconciliation(
            &outbox,
            &adapter,
            &reconciliation[0],
            Duration::from_secs(5)
        )
        .await
        .unwrap()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("permanent_sdk_reconciliation".into()),
            Some("permanent_sdk_reconciliation".into()),
            None,
        )
    );
    let events: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_class, reason FROM outbox_terminal_events WHERE outbox_id = $1",
    )
    .bind(endpoint_id)
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![(
            "permanent_sdk_reconciliation".to_owned(),
            "permanent_sdk_reconciliation".to_owned(),
        )],
        "one permanent reconciliation CAS writes exactly one terminal event"
    );

    // A replayed transition with the same claim matches zero rows and
    // inserts no second event.
    assert!(
        !outbox
            .mark_reconciliation_permanently_failed(&reconciliation[0])
            .await
            .unwrap()
    );
    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(event_count, 1);

    // Health and metrics expose the durable event without double-counting
    // across repeated publications.
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["outbox_terminal_failure_count"], 1);
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["permanent_sdk_reconciliation"],
        1
    );
    let metrics = metrics_text(&app).await;
    assert!(
        metrics.contains(
            "paykit_outbox_terminal_transitions_total{class=\"permanent_sdk_reconciliation\",reason=\"permanent_sdk_reconciliation\"} 1"
        ),
        "metrics: {metrics}"
    );
    assert!(
        metrics.contains("paykit_outbox_terminal_failure_count 1"),
        "metrics: {metrics}"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn active_retryable_row_still_degrades_readiness() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[62; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());

    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(
        outbox
            .mark_retryable(
                &claim,
                Duration::from_secs(300),
                RetryableHandoffStage::LinkEstablishment,
            )
            .await
            .unwrap()
    );
    let retryable: (String, bool) =
        sqlx::query_as("SELECT status, next_attempt_at > NOW() FROM outbox WHERE id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(retryable, ("retryable".into(), true));

    // A retryable row whose next attempt is still in the future is active
    // work, so readiness degrades even though nothing is leased right now.
    assert!(!outbox.delivery_available().await.unwrap());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "degraded");
    assert_eq!(ready["paykit_delivery"], "degraded");
    assert_eq!(ready["outbox_terminal_failure_count"], 0);

    // The same row, once exhausted at the attempt ceiling, is retained
    // terminal evidence and no longer degrades readiness.
    sqlx::query("UPDATE outbox SET attempt_count = 19, next_attempt_at = NOW() WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    let exhausted_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(exhausted_claim.id(), endpoint_id);
    assert!(
        outbox
            .exhaust_claim_if_due(&exhausted_claim, 20, Duration::from_secs(60 * 60))
            .await
            .unwrap()
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await.0,
        "permanently_failed"
    );
    assert!(outbox.delivery_available().await.unwrap());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(ready["outbox_terminal_failure_count"], 2);
    database.cleanup().await;
}

#[tokio::test]
async fn flooded_reader_partition_cannot_starve_unrelated_pair() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[63; 32]).unwrap());
    create_creator_once(&database, crypto.clone(), 63).await;
    let readers = distinct_readers();
    assert!(readers.len() >= 2, "reader fixture must yield two readers");
    let (flooded_parent, _) =
        create_activated_invoice_for(&database, crypto.clone(), &readers[0], "flooded").await;
    let (unrelated_parent, _) =
        create_activated_invoice_for(&database, crypto.clone(), &readers[1], "unrelated").await;

    let flooded_assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT reader_assignment_id FROM outbox WHERE id = $1")
            .bind(flooded_parent)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let unrelated_assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT reader_assignment_id FROM outbox WHERE id = $1")
            .bind(unrelated_parent)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(flooded_assignment.is_some());
    assert_ne!(
        flooded_assignment, unrelated_assignment,
        "distinct readers must form distinct claim partitions"
    );

    // Flood the first reader partition with claimable rows that share its
    // root reader assignment.
    for _ in 0..4 {
        sqlx::query(
            "INSERT INTO outbox (creator_id, reader_assignment_id, intent_envelope, status) \
             SELECT creator_id, reader_assignment_id, intent_envelope, 'queued' \
             FROM outbox WHERE id = $1",
        )
        .bind(flooded_parent)
        .execute(database.pool())
        .await
        .unwrap();
    }
    let flooded_parents: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM outbox WHERE reader_assignment_id = $1 AND depends_on_id IS NULL",
    )
    .bind(flooded_assignment.unwrap())
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(flooded_parents.len(), 5);

    let outbox = OutboxStore::new(database.pool(), crypto);
    let claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        claims.len(),
        2,
        "one fair pass admits at most one new claim per partition: {claims:?}"
    );
    assert!(
        claims.iter().any(|claim| claim.id() == unrelated_parent),
        "the flooded partition starved the unrelated pair"
    );
    let flooded_claimed = claims
        .iter()
        .filter(|claim| flooded_parents.contains(&claim.id()))
        .count();
    assert_eq!(flooded_claimed, 1);
    let still_queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox \
         WHERE reader_assignment_id = $1 AND depends_on_id IS NULL AND status = 'queued'",
    )
    .bind(flooded_assignment.unwrap())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        still_queued, 4,
        "the flooded partition consumed extra batch slots"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn single_slot_passes_claim_oldest_due_partition_before_lower_id_flood() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[66; 32]).unwrap());
    create_creator_once(&database, crypto.clone(), 66).await;
    let readers = distinct_readers();
    assert!(readers.len() >= 2, "reader fixture must yield two readers");
    let (flooded_parent, _) =
        create_activated_invoice_for(&database, crypto.clone(), &readers[0], "pass-flooded").await;
    let (_oldest_parent, _) =
        create_activated_invoice_for(&database, crypto.clone(), &readers[1], "pass-oldest").await;
    let flooded_assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT reader_assignment_id FROM outbox WHERE id = $1")
            .bind(flooded_parent)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let oldest_assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT reader_assignment_id FROM outbox WHERE id = $1")
            .bind(_oldest_parent)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(flooded_assignment.is_some());
    assert!(oldest_assignment.is_some());
    assert_ne!(flooded_assignment, oldest_assignment);

    // The flooded partition holds every lexicographically smaller due row
    // id, so id ordering would admit it ahead of the older due partition on
    // every single-slot pass.
    for index in 1..=3u128 {
        sqlx::query(
            "INSERT INTO outbox \
             (id, creator_id, reader_assignment_id, intent_envelope, status, next_attempt_at) \
             SELECT $1, creator_id, $2, decode('00', 'hex'), 'queued', NOW() - INTERVAL '1 minute' \
             FROM outbox WHERE id = $3",
        )
        .bind(Uuid::from_u128(index))
        .bind(flooded_assignment.unwrap())
        .bind(flooded_parent)
        .execute(database.pool())
        .await
        .unwrap();
    }
    let oldest_due = Uuid::from_u128(u128::MAX);
    sqlx::query(
        "INSERT INTO outbox \
         (id, creator_id, reader_assignment_id, intent_envelope, status, next_attempt_at) \
         SELECT $1, creator_id, $2, decode('00', 'hex'), 'queued', NOW() - INTERVAL '2 minutes' \
         FROM outbox WHERE id = $3",
    )
    .bind(oldest_due)
    .bind(oldest_assignment.unwrap())
    .bind(_oldest_parent)
    .execute(database.pool())
    .await
    .unwrap();

    let outbox = OutboxStore::new(database.pool(), crypto);
    // Pass one with a single batch slot: the oldest due unrelated partition
    // wins even though the flooded partition owns every smaller row id.
    let pass_one = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(pass_one.len(), 1);
    assert_eq!(
        pass_one[0].id(),
        oldest_due,
        "the oldest due partition must win a single-slot pass"
    );

    // Complete the winner so its partition is lease-free; the next pass
    // admits the flooded partition's oldest row.
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '1', \
         lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL WHERE id = $1",
    )
    .bind(oldest_due)
    .execute(database.pool())
    .await
    .unwrap();
    let pass_two = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(pass_two.len(), 1);
    let pass_two_assignment: Option<Uuid> =
        sqlx::query_scalar("SELECT reader_assignment_id FROM outbox WHERE id = $1")
            .bind(pass_two[0].id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(pass_two_assignment, flooded_assignment);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partition_lease_cap_holds_across_replicas() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[64; 32]).unwrap());
    let (_creator, _bundle, _invoices, _invoice_id, endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    // A second claimable row in the same (creator, root reader) partition.
    sqlx::query(
        "INSERT INTO outbox (creator_id, reader_assignment_id, intent_envelope, status) \
         SELECT creator_id, reader_assignment_id, intent_envelope, 'queued' \
         FROM outbox WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();

    // Two independent pools simulate two replicas claiming concurrently.
    let replica_b_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(database.database_url())
        .await
        .unwrap();
    let replica_a = OutboxStore::new(database.pool(), crypto.clone());
    let replica_b = OutboxStore::new(&replica_b_pool, crypto);
    let lease = Duration::from_secs(30);

    let (first, second) = tokio::join!(
        replica_a.claim(Uuid::new_v4(), 10, lease),
        replica_b.claim(Uuid::new_v4(), 10, lease),
    );
    let admitted = [first.unwrap(), second.unwrap()].concat();
    assert_eq!(
        admitted.len(),
        1,
        "concurrent replicas leased more than one row in one partition"
    );

    // While that lease is unexpired, neither replica is admitted again.
    let (first, second) = tokio::join!(
        replica_a.claim(Uuid::new_v4(), 10, lease),
        replica_b.claim(Uuid::new_v4(), 10, lease),
    );
    assert_eq!(
        first.unwrap().len() + second.unwrap().len(),
        0,
        "a partition with an unexpired lease admitted another claim"
    );

    // After expiry the partition admits exactly one new claim.
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(admitted[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        replica_a.claim(Uuid::new_v4(), 10, lease),
        replica_b.claim(Uuid::new_v4(), 10, lease),
    );
    let readmitted = [first.unwrap(), second.unwrap()].concat();
    assert_eq!(
        readmitted.len(),
        1,
        "an expired partition lease did not admit exactly one new claim"
    );

    drop(replica_b_pool);
    database.cleanup().await;
}
