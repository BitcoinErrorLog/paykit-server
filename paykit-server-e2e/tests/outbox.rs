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
    PaymentReference, PaymentRequestTerms, PrivateMessageKind,
};
use paykit_sdk::{
    InMemoryStorage, LinkedPeerState, OutboundPrivateMessageStatus, PaykitReceiverCapabilities,
    PaykitSdk, PaykitSdkConfig, PaykitSdkError, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionBootstrap, ReceiverNoiseSecretKey, StorageAdapter, storage::StorageState,
};
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1},
    config::{PaykitConfig, PaykitNetwork, ReceiverPathPriority},
    crypto::{Crypto, EnvelopeContext, LookupHash},
    domain::locks::{
        BundleId, CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader,
    },
    paykit::CreatorSessionProvider,
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, HandoffFenceSeam, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, OutboxStore, PersistenceError,
        PostgresStorageAdapter, SdkStateStore, run_migrations, verify_migrations_applied,
    },
    runtime::{
        ElectrumProbe, OutboxTerminalHealth, PostgresDependency, Runtime, operational_router,
    },
    workers::outbox::{
        Adapter, HandoffError, HandoffFailure, HandoffResult, RetryableHandoffStage,
        handoff_with_invocation_token, process_claim, process_fence_recovery,
        process_final_invoice_sweep, process_reconciliation,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
/// The §B.9 observation tail used by the expiry-transition seam here
/// (`24 h`, matching the production default); the clock itself is injected
/// through SQL timestamp moves, never by sleeping.
const EXPIRY_TAIL: Duration = Duration::from_secs(24 * 60 * 60);

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
}

type DurableTestSdk = PaykitSdk<PostgresStorageAdapter, TestSessionProvider, TestPaymentAdapter>;

struct LinkedPaykitFixture {
    _testnet: EphemeralTestnet,
    creator: CreatorPubky,
    reader: ReaderPubky,
    creator_sdk: DurableTestSdk,
    storage: PostgresStorageAdapter,
    adapter: paykit_server::paykit::PaykitAdapter,
    peer_public_key: PubkyPublicKey,
    peer_receiver_path: PaykitReceiverPath,
    peer_marker: PaykitReceiverMarker,
}

async fn linked_paykit_fixture(
    database: &TestDatabase,
    crypto: Arc<Crypto>,
    key_tail_seed: u8,
) -> LinkedPaykitFixture {
    paykit_fixture(database.pool(), crypto, key_tail_seed, true).await
}

async fn linked_paykit_fixture_on_pool(
    pool: &sqlx::PgPool,
    crypto: Arc<Crypto>,
    key_tail_seed: u8,
) -> LinkedPaykitFixture {
    paykit_fixture(pool, crypto, key_tail_seed, true).await
}

async fn unlinked_paykit_fixture(
    database: &TestDatabase,
    crypto: Arc<Crypto>,
    key_tail_seed: u8,
) -> LinkedPaykitFixture {
    paykit_fixture(database.pool(), crypto, key_tail_seed, false).await
}

async fn paykit_fixture(
    pool: &sqlx::PgPool,
    crypto: Arc<Crypto>,
    key_tail_seed: u8,
    link_peer: bool,
) -> LinkedPaykitFixture {
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit-server").unwrap();

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
    let creator_row = CreatorStore::new(pool, crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                creator_bootstrap
                    .export_session_secret()
                    .await
                    .unwrap()
                    .into_inner(),
                creator_bootstrap.access.receiver_noise_secret_key.clone(),
                "unused-test-xpub".into(),
                0,
            ),
            &StorageState::default(),
            &key_tail(key_tail_seed),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let creator_storage = PostgresStorageAdapter::new(pool, crypto.clone(), creator_row.id());
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
    if link_peer {
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
    }
    // The handoff worker reads the peer's marker through the same public
    // storage boundary as production.  Do not return a "linked" fixture
    // before that independently persisted marker is visible to the creator.
    let marker_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let peer_marker = loop {
        if let Some(marker) = creator_sdk
            .paykit_receiver_marker(
                peer_bootstrap.public_key.clone(),
                peer_receiver_path.clone(),
            )
            .await
            .unwrap()
        {
            break marker;
        }
        assert!(
            tokio::time::Instant::now() < marker_deadline,
            "peer receiver marker did not become visible"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let reader = parse_reader(&format!("pubky{}", peer_bootstrap.public_key)).unwrap();
    let paykit = PaykitConfig {
        client_id: "paykit-server".into(),
        receiver_path: creator_receiver_path,
        receiver_path_priority: vec![ReceiverPathPriority::parse("bitkit".into()).unwrap()],
        network: PaykitNetwork::Testnet,
        auth_relay: Url::parse(pubky::DEFAULT_HTTP_RELAY_INBOX).unwrap(),
    };
    let adapter = paykit_server::paykit::PaykitAdapter::new(
        creator_storage.clone(),
        CreatorSessionProvider::with_pubky(
            CreatorStore::new(pool, crypto),
            creator.clone(),
            pubky,
            &paykit,
        ),
        &paykit,
    )
    .unwrap();
    LinkedPaykitFixture {
        _testnet: testnet,
        creator,
        reader,
        creator_sdk,
        storage: creator_storage,
        adapter,
        peer_public_key: peer_bootstrap.public_key,
        peer_receiver_path,
        peer_marker,
    }
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

struct LinkedPayloads {
    reader: ReaderPubky,
    marker: PaykitReceiverMarker,
}

struct FixedLinkedPayloads {
    reader: ReaderPubky,
    marker: PaykitReceiverMarker,
    address: String,
}

impl NewReaderPayloadFactory for LinkedPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        let address = format!("linked-outbox-test-address-{child_index}");
        Ok(NewReaderPayloads {
            endpoint_intent: DeliveryIntentV1::endpoint(
                self.reader.to_string(),
                &self.marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                vec![(
                    PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    paykit_lib::PaymentEndpointPayload::new(address.clone()),
                )],
            )
            .unwrap(),
            bitcoin_address: address,
        })
    }
}

impl NewReaderPayloadFactory for FixedLinkedPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: DeliveryIntentV1::endpoint(
                self.reader.to_string(),
                &self.marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                vec![
                    (
                        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                        paykit_lib::PaymentEndpointPayload::new(self.address.clone()),
                    ),
                    (
                        PaymentEndpointIdentifier::new("btc-lightning-bolt11").unwrap(),
                        paykit_lib::PaymentEndpointPayload::new("same-historical-invoice"),
                    ),
                ],
            )
            .unwrap(),
            bitcoin_address: format!("fixed-linked-allocated-address-{child_index}"),
        })
    }
}

async fn create_fixed_linked_invoice(
    invoices: &InvoiceStore,
    creator: &CreatorPubky,
    reader: &ReaderPubky,
    marker: &PaykitReceiverMarker,
    seed: &str,
) -> (Uuid, Uuid, Uuid) {
    let bundle = format!("fixed-linked-bundle-{seed}");
    let request = format!("fixed-linked-request-{seed}");
    let invoice = invoices
        .create_atomic(AtomicInvoiceInput {
            creator,
            reader,
            bundle_binding: bundle.as_bytes(),
            payment_request_binding: request.as_bytes(),
            new_reader_payloads: &FixedLinkedPayloads {
                reader: reader.clone(),
                marker: marker.clone(),
                address: "same-historical-address".into(),
            },
            payment_request_intent: DeliveryIntentV1::payment_request(
                reader.to_string(),
                marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                &PaymentRequestTerms {
                    amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                    payment_reference: PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                    proposal_expires_at: None,
                    recurrence: None,
                    accepted_payment_endpoint_identifiers: vec![
                        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    ],
                    metadata: Default::default(),
                },
            )
            .unwrap(),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    (
        invoice.invoice_id(),
        invoice.endpoint_publication_outbox_id().unwrap(),
        invoice.payment_request_outbox_id(),
    )
}

async fn fence_and_emit_exact(
    database: &TestDatabase,
    outbox: &OutboxStore,
    adapter: &dyn Adapter,
    target_id: Uuid,
) -> (Uuid, HandoffResult, DeliveryIntentV1) {
    let claim = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.id() == target_id)
        .expect("target is ordinary-claim eligible");
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
            .await
            .unwrap()
    );
    let token = outbox
        .handoff_invocation_token(&claim)
        .await
        .unwrap()
        .expect("fenced invocation has a durable token");
    let intent = outbox.delivery_intent(&claim).unwrap();
    let result = handoff_with_invocation_token(adapter, &intent, token)
        .await
        .unwrap();
    let sidecar: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations \
         WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
    )
    .bind(claim.creator_id())
    .bind(result.outbound_message_id().to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(sidecar, token);
    (token, result, intent)
}

async fn recover_and_assert_closed(
    database: &TestDatabase,
    outbox: &OutboxStore,
    target_id: Uuid,
    child_id: Uuid,
    reason: &str,
) {
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(target_id)
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.id() == target_id)
        .expect("target is fence-recovery eligible");
    let no_effects = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(outbox, &no_effects, &recovery)
            .await
            .unwrap()
    );
    assert_eq!(no_effects.sdk_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        outbox_row(database, target_id).await.2.as_deref(),
        Some(reason)
    );
    assert_eq!(outbox_row(database, child_id).await.0, "permanently_failed");
}

async fn replace_authenticated_intent(
    database: &TestDatabase,
    crypto: &Crypto,
    target_id: Uuid,
    plaintext: &[u8],
) {
    let creator_lookup_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT creator.creator_lookup_hash FROM creators creator \
         JOIN outbox target ON target.creator_id = creator.id WHERE target.id = $1",
    )
    .bind(target_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let lookup_hash = LookupHash::from_bytes(creator_lookup_hash.try_into().unwrap());
    let envelope = crypto
        .encrypt(
            &EnvelopeContext::outbox_semantic_intent(lookup_hash, target_id),
            plaintext,
        )
        .unwrap();
    sqlx::query("UPDATE outbox SET intent_envelope = $2 WHERE id = $1")
        .bind(target_id)
        .bind(envelope.as_bytes())
        .execute(database.pool())
        .await
        .unwrap();
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

/// Fixed-address payloads so two invoices can carry the SAME endpoint
/// identifier with DIFFERENT payloads (the HF-2 collision shape).
struct AddressPayloads {
    reader: ReaderPubky,
    address: String,
}

impl NewReaderPayloadFactory for AddressPayloads {
    fn for_child_index(&self, _child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent: common::endpoint_intent(&self.reader, self.address.clone()),
            bitcoin_address: self.address.clone(),
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

/// A pair whose endpoint and request generation_id values equal EACH OTHER
/// but not the invoice id is malformed in every precedence shape: the
/// current generation IS the invoice id, so a same-wrong-UUID pair fails
/// closed as contract_error (failed, delivered, and pending shapes).
#[tokio::test]
async fn same_wrong_generation_pair_reports_contract_error_for_failed_delivered_and_pending_shapes()
{
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[72; 32]).unwrap());
    let (creator, bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    let wrong_generation = Uuid::new_v4();
    assert_ne!(wrong_generation, invoice_id);
    sqlx::query("UPDATE outbox SET generation_id = $1 WHERE invoice_id = $2")
        .bind(wrong_generation)
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    // Pending shape: both rows active with a same-wrong-UUID generation.
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a pending same-wrong-UUID generation pair is malformed"
    );
    // Delivered shape (terminal delivered rows must carry attribution).
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', \
         sdk_outbound_message_id = CASE WHEN id = $2 THEN '900' ELSE '901' END \
         WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a delivered same-wrong-UUID generation pair is malformed"
    );
    // Failed shape.
    sqlx::query("UPDATE outbox SET status = 'permanently_failed' WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        delivery_status(&invoices, &creator, &bundle).await.state,
        "contract_error",
        "a failed same-wrong-UUID generation pair is malformed"
    );
    let _ = endpoint_id;
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
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
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
/// entrypoint and returns one fixed result — success or failure — so the
/// fence-first barrier covers non-success SDK results too.
struct FencedHandoffAdapter {
    handoffs: AtomicUsize,
    result: Result<HandoffResult, HandoffFailure>,
}

#[async_trait]
impl Adapter for FencedHandoffAdapter {
    async fn execute_handoff(
        &self,
        _intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
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

/// Fenced-recovery evidence adapter: any attempt to invoke the SDK from the
/// recovery path panics (recovery terminalizes with zero SDK calls).
struct FenceRecoveryAdapter {
    handoffs: AtomicUsize,
}

#[async_trait]
impl Adapter for FenceRecoveryAdapter {
    async fn execute_handoff(
        &self,
        _intent: &DeliveryIntentV1,
    ) -> Result<HandoffResult, HandoffFailure> {
        self.handoffs.fetch_add(1, Ordering::SeqCst);
        panic!("fence recovery never re-runs the SDK effect")
    }

    async fn fetch_marker(
        &self,
        _reader: &str,
        _path: &str,
    ) -> Result<Option<PaykitReceiverMarker>, HandoffError> {
        panic!("fence recovery never runs preflight")
    }

    async fn ensure_link_with_peer(&self, _reader: &str, _path: &str) -> Result<(), HandoffError> {
        panic!("fence recovery never runs preflight")
    }

    async fn enqueue_private_payment_list_with_receiving_details(
        &self,
        _reader: &str,
        _path: &str,
        _details: &[paykit_server::application::semantic_intent::ReceivingDetailV1],
    ) -> Result<HandoffResult, HandoffError> {
        panic!("fence recovery never re-runs the SDK effect")
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _terms: &paykit_server::application::semantic_intent::PaymentTermsV1,
    ) -> Result<HandoffResult, HandoffError> {
        panic!("fence recovery never re-runs the SDK effect")
    }

    async fn outbound_status(
        &self,
        _outbound_message_id: u64,
    ) -> Result<Option<OutboundPrivateMessageStatus>, HandoffError> {
        panic!("fence recovery never runs reconciliation")
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
            ..HandoffFenceSeam::default()
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
        result: Ok(HandoffResult::EndpointPublication {
            outbound_message_id: 42,
        }),
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
            ..HandoffFenceSeam::default()
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
        result: Ok(HandoffResult::EndpointPublication {
            outbound_message_id: 43,
        }),
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

/// Barrier (a): crash/lease expiry BEFORE the SDK effect on a finalized
/// invoice. The fenced row carries no durable invocation marker, so the
/// dedicated fenced-recovery path terminalizes it as `handoff_unresolved`
/// with the static `sdk_not_invoked` reason, exactly one terminal event,
/// and zero SDK calls; readiness is ready.
#[tokio::test]
async fn finalized_fence_crash_before_sdk_effect_terminalizes_with_zero_sdk_calls() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[57; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    // Cancellation finalizes the invoice and preserves the fenced row.
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
    // A final-invoice fenced row is never active work (migration 0023 rule 5).
    assert!(outbox.delivery_available().await.unwrap());
    // The process dies before the invocation marker and the SDK call; the
    // lease expires. The ordinary claim path never re-admits a fenced row.
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "the ordinary claim path must never re-admit an expired fenced row"
    );
    // The dedicated recovery path claims it regardless of invoice finality.
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(recovery.len(), 1);
    assert!(
        !recovery[0].sdk_invocation_started(),
        "the crash happened before the invocation marker committed"
    );
    let adapter = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&outbox, &adapter, &recovery[0])
            .await
            .unwrap()
    );
    assert_eq!(
        adapter.sdk_calls.load(Ordering::SeqCst),
        0,
        "no invocation marker proves the effect absent: zero SDK calls"
    );
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("handoff_unresolved".into()),
            Some("sdk_not_invoked".into()),
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
            "handoff_unresolved".to_string(),
            "sdk_not_invoked".to_string()
        )],
        "exactly one terminal event of the closed handoff_unresolved class"
    );
    assert_eq!(
        outbox_row(&database, request_id).await.0,
        "permanently_failed",
        "cancellation already terminalized the dependent child"
    );
    // Readiness is ready: the terminalized fence leaves no active-work residue.
    assert!(outbox.delivery_available().await.unwrap());
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["handoff_unresolved"],
        1
    );
    database.cleanup().await;
}

/// Barrier (b): crash after the durable token-bearing marker but before SDK
/// storage. No current-token record exists, so recovery terminalizes
/// `sdk_effect_not_found`; it never invokes an SDK API or unblocks the child.
#[tokio::test]
async fn crash_after_token_marker_before_sdk_insert_terminalizes_not_found_without_unblocking() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[58; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    // The process dies after the marker commits, before any SDK callback.
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
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
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(recovery.len(), 1);
    assert!(recovery[0].sdk_invocation_started());
    let adapter = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&outbox, &adapter, &recovery[0])
            .await
            .unwrap()
    );
    assert_eq!(
        adapter.sdk_calls.load(Ordering::SeqCst),
        0,
        "recovery never resolves, attributes, or re-runs an SDK effect"
    );
    // The parent is NOT delivered and never attributed.
    let unattributed: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(unattributed, ("permanently_failed".into(), None));
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("handoff_unresolved".into()),
            Some("sdk_effect_not_found".into()),
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
            "handoff_unresolved".to_string(),
            "sdk_effect_not_found".to_string()
        )],
        "exactly one terminal event of the closed handoff_unresolved class"
    );
    // The dependent payment-request child is never admitted: cancellation
    // already terminalized it and recovery never unblocks it.
    assert_eq!(
        outbox_row(&database, request_id).await.0,
        "permanently_failed"
    );
    // Readiness is ready: the terminalized fence leaves no active-work residue.
    assert!(outbox.delivery_available().await.unwrap());
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["handoff_unresolved"],
        1
    );
    database.cleanup().await;
}

/// HF-2 negative: two invoices for the same creator, reader, and receiver
/// path carry the SAME endpoint identifier (`btc-bitcoin-p2wpkh`) with
/// DIFFERENT payloads. Invoice A's publication is delivered; invoice B
/// commits the durable invocation marker and crashes. Recovery must NEVER
/// attribute A's publication to B: B's fenced row terminalizes as
/// `handoff_unresolved` with the static `sdk_invoked_unattributed` reason,
/// exactly one terminal event, and zero SDK calls; B's parent is not
/// delivered, B's child is never admitted, and A's rows are untouched.
#[tokio::test]
async fn fence_recovery_never_attributes_another_invoices_publication() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[61; 32]).unwrap());
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
            &key_tail(62),
            &paykit_server::allocation::ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let create_invoice = async |bundle: &str, address: &str| {
        let invoice = invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &creator,
                reader: &reader,
                bundle_binding: bundle.as_bytes(),
                payment_request_binding: format!("hf2-payment-request-{bundle}").as_bytes(),
                new_reader_payloads: &AddressPayloads {
                    reader: reader.clone(),
                    address: address.to_owned(),
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
            invoice.invoice_id(),
            invoice.endpoint_publication_outbox_id().unwrap(),
            invoice.payment_request_outbox_id(),
        )
    };
    let (_a_invoice_id, a_endpoint_id, a_request_id) =
        create_invoice("000G40R40M30E209185GR38E2A", "hf2-address-a").await;
    let (_b_invoice_id, b_endpoint_id, b_request_id) =
        create_invoice("000G40R40M30E209185GR38E2B", "hf2-address-b").await;
    // Invoice A's publication reached the reader and is delivered.
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '900' WHERE id = $1",
    )
    .bind(a_endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    // Invoice B commits the fence and the durable invocation marker, then
    // the process crashes before any SDK result is persisted.
    let outbox = OutboxStore::new(database.pool(), crypto);
    let claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    let b_claim = claims
        .iter()
        .find(|claim| claim.id() == b_endpoint_id)
        .expect("invoice B endpoint row was claimable");
    assert!(outbox.begin_handoff(b_claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(b_claim)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(b_endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    let b_recovery = recovery
        .iter()
        .find(|claim| claim.id() == b_endpoint_id)
        .expect("invoice B fenced row was recoverable");
    assert!(b_recovery.sdk_invocation_started());
    // Any SDK invocation from recovery panics: the path is pure persistence.
    let adapter = FenceRecoveryAdapter {
        handoffs: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&outbox, &adapter, b_recovery)
            .await
            .unwrap()
    );
    assert_eq!(
        adapter.handoffs.load(Ordering::SeqCst),
        0,
        "recovery never re-runs the SDK effect"
    );
    // B's parent is NOT delivered and never attributed to A's publication.
    let b_row: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(b_endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(b_row, ("permanently_failed".into(), None));
    assert_eq!(
        outbox_row(&database, b_endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("handoff_unresolved".into()),
            Some("sdk_effect_not_found".into()),
            None,
        )
    );
    let b_events: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_class, reason FROM outbox_terminal_events WHERE outbox_id = $1",
    )
    .bind(b_endpoint_id)
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        b_events,
        vec![(
            "handoff_unresolved".to_string(),
            "sdk_effect_not_found".to_string()
        )],
        "exactly one terminal event of the closed handoff_unresolved class"
    );
    // B's dependent payment-request child is never admitted.
    assert_eq!(
        outbox_row(&database, b_request_id).await,
        (
            "permanently_failed".into(),
            Some("dependency_failed".into()),
            Some("parent_handoff_unresolved".into()),
            None,
        )
    );
    // Invoice A is untouched: its delivered publication stands, its child
    // was never terminalized, and recovery wrote no events for it.
    let a_row: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(a_endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(a_row, ("delivered".into(), Some("900".into())));
    let a_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id IN ($1, $2)",
    )
    .bind(a_endpoint_id)
    .bind(a_request_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(a_events, 0, "recovery never touches the other invoice");
    assert_ne!(
        outbox_row(&database, a_request_id).await.0,
        "permanently_failed"
    );
    assert!(outbox.delivery_available().await.unwrap());
    database.cleanup().await;
}

/// Barrier (c): the fence commits first, cancellation finalizes the invoice,
/// and the SDK then returns a RETRYABLE error. `handoff_started ->
/// retryable` is forbidden for a final invoice (migration 0023 rule 4): the
/// retryable branch checks finality under the invoice lock and terminalizes
/// the row as `handoff_unresolved` with exactly one terminal event instead;
/// readiness is ready.
#[tokio::test]
async fn retryable_sdk_failure_after_cancellation_terminalizes_final_fence() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[60; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, _request_id) =
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
            ..HandoffFenceSeam::default()
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
        result: Err(HandoffFailure::Retryable(
            RetryableHandoffStage::EndpointPublication,
        )),
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
    // The production fence is committed; cancellation commits second and
    // finalizes the invoice before the SDK returns its retryable failure.
    fence_committed.notified().await;
    assert!(
        invoices
            .resolve_invoice(invoice_id, "abandoned", time::OffsetDateTime::now_utc())
            .await
            .unwrap()
            .is_some()
    );
    release_worker.notify_one();
    assert!(worker.await.unwrap().unwrap());
    assert_eq!(adapter.handoffs.load(Ordering::SeqCst), 1);
    // No `retryable` row exists for a final invoice: the fenced row
    // terminalized as `handoff_unresolved` with exactly one terminal event.
    assert_eq!(
        outbox_row(&database, endpoint_id).await,
        (
            "permanently_failed".into(),
            Some("handoff_unresolved".into()),
            Some("handoff_unresolved".into()),
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
            "handoff_unresolved".to_string(),
            "handoff_unresolved".to_string()
        )]
    );
    assert!(outbox.delivery_available().await.unwrap());
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["handoff_unresolved"],
        1
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
async fn public_status_never_reads_legacy_bigint_generation() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[72; 32]).unwrap());
    let (creator, bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto, "000G40R40M30E209185GR38E1W").await;

    // Arbitrary, mutually inconsistent legacy BIGINT values must not move
    // the public status: it is derived from generation_id and invoices.id.
    sqlx::query("UPDATE outbox SET generation = 7 WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE outbox SET generation = 9 WHERE id = $1")
        .bind(request_id)
        .execute(database.pool())
        .await
        .unwrap();
    let pending = delivery_status(&invoices, &creator, &bundle).await;
    assert_eq!(pending.state, "pending_delivery");
    assert_eq!(pending.generation, invoice_id);

    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '6' WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '7' WHERE id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();
    let delivered = delivery_status(&invoices, &creator, &bundle).await;
    assert_eq!(delivered.state, "delivered");
    assert_eq!(delivered.generation, invoice_id);

    let legacy_comment: Option<String> = sqlx::query_scalar(
        "SELECT col_description('outbox'::regclass, attnum) \
         FROM pg_attribute \
         WHERE attrelid = 'outbox'::regclass AND attname = 'generation'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    let legacy_comment = legacy_comment.unwrap_or_default();
    assert!(
        legacy_comment.contains("LEGACY non-authoritative"),
        "the legacy column must carry its schema doc comment: {legacy_comment:?}"
    );
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

/// Drives an activated (`observing`) invoice through both §B.9 expiry
/// transitions to `expired_final`, injecting the clock through SQL
/// timestamp moves (never sleeping): first `observing → expired_tail` at
/// `expires_at`, then `expired_tail → expired_final` at `expires_at +
/// tail`. Acquires the observer lease on a cloned store — the same fence
/// `observation_loop` binds before `observe_tick` — because expiry is an
/// observer write.
async fn expire_invoice(
    database: &TestDatabase,
    invoices: &InvoiceStore,
    invoice_id: Uuid,
) -> InvoiceStore {
    let invoices = invoices
        .clone()
        .with_observer_lease(common::observer_lease(database.pool()).await);
    sqlx::query("UPDATE invoices SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    let first = invoices
        .apply_expiry_transitions(EXPIRY_TAIL)
        .await
        .unwrap();
    assert_eq!((first.tailed, first.finalized), (1, 0));
    sqlx::query("UPDATE invoices SET expires_at = NOW() - INTERVAL '25 hours' WHERE id = $1")
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    let second = invoices
        .apply_expiry_transitions(EXPIRY_TAIL)
        .await
        .unwrap();
    assert_eq!((second.tailed, second.finalized), (0, 1));
    let baseline: String = sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(baseline, "expired_final");
    invoices
}

/// The production residue shape: an `expired_final` invoice whose endpoint
/// parent is `retryable` after unbounded pre-bound attempts and whose
/// payment-request child is still `queued`. The expiry transition itself
/// terminalizes both rows in the same transaction with the closed
/// `invoice_expired` reason, clears every lease field, writes exactly one
/// durable terminal event per row, and readiness is ready.
#[tokio::test]
async fn expiry_terminalizes_retryable_parent_and_queued_child_with_one_event_each() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[59; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    sqlx::query(
        "UPDATE outbox
         SET status = 'retryable', attempt_count = 1100,
             lease_owner = gen_random_uuid(), claim_token = gen_random_uuid(),
             lease_expires_at = NOW()
         WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(outbox_row(&database, request_id).await.0, "queued");

    expire_invoice(&database, &invoices, invoice_id).await;

    for id in [endpoint_id, request_id] {
        assert_eq!(
            outbox_row(&database, id).await,
            (
                "permanently_failed".into(),
                Some("invoice_expired".into()),
                Some("invoice_expired".into()),
                None,
            )
        );
        let lease: (Option<Uuid>, Option<time::OffsetDateTime>) =
            sqlx::query_as("SELECT lease_owner, lease_expires_at FROM outbox WHERE id = $1")
                .bind(id)
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(lease, (None, None), "terminalization clears the lease");
    }
    let events: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT outbox_id, event_class, reason FROM outbox_terminal_events
         WHERE invoice_id = $1 ORDER BY outbox_id",
    )
    .bind(invoice_id)
    .fetch_all(database.pool())
    .await
    .unwrap();
    let mut expected = [endpoint_id, request_id];
    expected.sort();
    assert_eq!(
        events,
        expected
            .iter()
            .map(|id| (
                *id,
                "invoice_expired".to_string(),
                "invoice_expired".to_string()
            ))
            .collect::<Vec<_>>(),
        "exactly one terminal event per transitioned row, closed invoice_expired reason"
    );
    // Readiness is ready: the terminalized pair leaves no active-work residue.
    let outbox = OutboxStore::new(database.pool(), crypto);
    assert!(outbox.delivery_available().await.unwrap());
    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["paykit_delivery"], "ready");
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["invoice_expired"],
        2
    );
    database.cleanup().await;
}

/// Expiry preserves `handed_off` rows exactly like void/abandon do: only
/// the never-handed-off child terminalizes, with one `invoice_expired`
/// event; the attributed parent's SDK identifiers stay intact.
#[tokio::test]
async fn expiry_preserves_handed_off_rows() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[60; 32]).unwrap());
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
                    outbound_message_id: 77,
                },
            )
            .await
            .unwrap()
    );

    expire_invoice(&database, &invoices, invoice_id).await;

    let attributed: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(attributed, ("handed_off".into(), Some("77".into())));
    let endpoint_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(endpoint_events, 0, "a handed_off row is never terminalized");
    assert_eq!(
        outbox_row(&database, request_id).await,
        (
            "permanently_failed".into(),
            Some("invoice_expired".into()),
            Some("invoice_expired".into()),
            None,
        )
    );
    let child_events: Vec<(String, String)> = sqlx::query_as(
        "SELECT event_class, reason FROM outbox_terminal_events WHERE outbox_id = $1",
    )
    .bind(request_id)
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        child_events,
        vec![("invoice_expired".to_string(), "invoice_expired".to_string())]
    );
    database.cleanup().await;
}

/// A second expiry pass is a no-op: the `expired_tail → expired_final`
/// guard matches zero rows for an already-final invoice, so no second
/// terminal event is ever written.
#[tokio::test]
async fn expiry_terminalization_is_idempotent_on_a_second_pass() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[61; 32]).unwrap());
    let (_creator, _bundle, invoices, invoice_id, _endpoint_id, _request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let invoices = expire_invoice(&database, &invoices, invoice_id).await;
    let events_after_first: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(events_after_first, 2);
    let second = invoices
        .apply_expiry_transitions(EXPIRY_TAIL)
        .await
        .unwrap();
    assert_eq!((second.tailed, second.finalized), (0, 0));
    let events_after_second: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(
        events_after_second, events_after_first,
        "a replayed expiry pass writes no second terminal event"
    );
    database.cleanup().await;
}

/// The one-time legacy backfill: 250 inert rows of an already-final
/// invoice (the production residue shape — `retryable` parents after
/// unbounded pre-bound attempts and still-`queued` children) drain over
/// bounded passes of at most [`FINAL_INVOICE_SWEEP_LIMIT`] rows each,
/// oldest `created_at` first, each row terminal with the closed
/// `invoice_final_backfill` reason and exactly one durable terminal
/// event, and zero SDK calls.
#[tokio::test]
async fn final_invoice_backfill_drains_legacy_backlog_over_bounded_passes() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[62; 32]).unwrap());
    let (invoices, invoice_id, _endpoint_id, _request_id) =
        create_prepared_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    // The invoice is final BEFORE its legacy rows accumulate: void it so
    // its two real rows are already terminal (`invoice_voided`) and the
    // sweep never re-touches them.
    assert!(invoices.void_invoice(invoice_id).await.unwrap().is_some());
    let creator_id: Uuid = sqlx::query_scalar("SELECT id FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();
    // 250 legacy rows, oldest first distinguishable by `created_at`.
    sqlx::query(
        "INSERT INTO outbox
             (creator_id, invoice_id, intent_envelope, status, attempt_count, created_at)
         SELECT $1, $2, decode('00', 'hex'),
                CASE WHEN g % 2 = 0 THEN 'queued' ELSE 'retryable' END,
                1100,
                NOW() - make_interval(secs => g)
         FROM generate_series(1, 250) AS g",
    )
    .bind(creator_id)
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto);
    let adapter = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };

    let first = process_final_invoice_sweep(&outbox, &adapter)
        .await
        .unwrap();
    assert_eq!(first, 100, "pass one terminalizes a full bounded batch");
    // Oldest-first: every terminalized legacy row predates every
    // remaining one.
    let (max_terminal, min_remaining): (
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT (SELECT MAX(created_at) FROM outbox
                  WHERE attempt_count = 1100 AND status = 'permanently_failed'),
                (SELECT MIN(created_at) FROM outbox
                  WHERE attempt_count = 1100 AND status <> 'permanently_failed')",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(
        max_terminal.unwrap() < min_remaining.unwrap(),
        "the bounded pass terminalizes the oldest rows first"
    );
    let second = process_final_invoice_sweep(&outbox, &adapter)
        .await
        .unwrap();
    let third = process_final_invoice_sweep(&outbox, &adapter)
        .await
        .unwrap();
    assert_eq!(
        (second, third),
        (100, 50),
        "the backlog drains over three passes"
    );
    let fourth = process_final_invoice_sweep(&outbox, &adapter)
        .await
        .unwrap();
    assert_eq!(fourth, 0, "a drained backlog stays drained");
    assert_eq!(
        adapter.sdk_calls.load(Ordering::SeqCst),
        0,
        "the backfill never invokes the SDK"
    );

    let terminalized: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox
         WHERE attempt_count = 1100 AND status = 'permanently_failed'
           AND error_class = 'invoice_final_backfill'
           AND failure_reason = 'invoice_final_backfill'
           AND lease_owner IS NULL AND claim_token IS NULL AND lease_expires_at IS NULL",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(terminalized, 250);
    let backfill_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_terminal_events
         WHERE event_class = 'invoice_final_backfill' AND reason = 'invoice_final_backfill'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        backfill_events, 250,
        "exactly one terminal event per legacy row"
    );
    let voided_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_terminal_events WHERE event_class = 'invoice_voided'",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        voided_events, 2,
        "the pre-existing terminal evidence is untouched"
    );
    database.cleanup().await;
}

/// The backfill touches ONLY inert rows of final invoices: a live lease,
/// `handed_off`, and `handoff_started` rows of a final invoice are
/// preserved, and every row of a non-final invoice is left alone.
#[tokio::test]
async fn final_invoice_backfill_never_touches_live_leases_handed_off_or_live_invoice_rows() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[63; 32]).unwrap());
    let (invoices, voided_id, _endpoint_id, _request_id) =
        create_prepared_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    assert!(invoices.void_invoice(voided_id).await.unwrap().is_some());
    let creator_id: Uuid = sqlx::query_scalar("SELECT id FROM creators LIMIT 1")
        .fetch_one(database.pool())
        .await
        .unwrap();
    fn legacy_insert(status: &str, lease_and_sdk: &str) -> String {
        format!(
            "INSERT INTO outbox (creator_id, invoice_id, intent_envelope, status, attempt_count,
                                 claim_token, lease_owner, lease_expires_at, sdk_outbound_message_id)
             SELECT $1, $2, decode('00', 'hex'), '{status}', 1100, {lease_and_sdk}
             RETURNING id"
        )
    }
    let live_lease_id: Uuid = sqlx::query_scalar(&legacy_insert(
        "leased",
        "gen_random_uuid(), gen_random_uuid(), NOW() + INTERVAL '1 hour', NULL",
    ))
    .bind(creator_id)
    .bind(voided_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let handed_off_id: Uuid =
        sqlx::query_scalar(&legacy_insert("handed_off", "NULL, NULL, NULL, '123'"))
            .bind(creator_id)
            .bind(voided_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let handoff_started_id: Uuid = sqlx::query_scalar(&legacy_insert(
        "handoff_started",
        "gen_random_uuid(), gen_random_uuid(), NOW() + INTERVAL '1 hour', NULL",
    ))
    .bind(creator_id)
    .bind(voided_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let eligible_id: Uuid = sqlx::query_scalar(&legacy_insert("queued", "NULL, NULL, NULL, NULL"))
        .bind(creator_id)
        .bind(voided_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    // A live (observing) invoice with its own queued rows.
    let (live_endpoint_id, live_request_id) =
        create_activated_invoice_for(&database, crypto.clone(), &reader(), "backfill-live").await;

    let outbox = OutboxStore::new(database.pool(), crypto);
    let swept = outbox.sweep_final_invoice_backfill(100).await.unwrap();
    assert_eq!(
        swept, 1,
        "only the one inert row of the final invoice drains"
    );

    assert_eq!(
        outbox_row(&database, live_lease_id).await.0,
        "leased",
        "a live lease is never broken by the backfill"
    );
    assert!(
        outbox_row(&database, live_lease_id).await.3.is_some(),
        "the live lease keeps its claim token"
    );
    assert_eq!(outbox_row(&database, handed_off_id).await.0, "handed_off");
    assert_eq!(
        outbox_row(&database, handoff_started_id).await.0,
        "handoff_started"
    );
    for id in [live_endpoint_id, live_request_id] {
        assert_eq!(
            outbox_row(&database, id).await.0,
            "queued",
            "a non-final invoice's rows are untouched"
        );
    }
    assert_eq!(
        outbox_row(&database, eligible_id).await,
        (
            "permanently_failed".into(),
            Some("invoice_final_backfill".into()),
            Some("invoice_final_backfill".into()),
            None,
        )
    );
    let events: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT outbox_id, event_class, reason FROM outbox_terminal_events
         WHERE event_class = 'invoice_final_backfill'",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![(
            eligible_id,
            "invoice_final_backfill".to_string(),
            "invoice_final_backfill".to_string()
        )],
        "exactly one backfill event, for the one eligible row"
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

async fn grant_pre_0024_runtime_privileges(pool: &sqlx::PgPool) {
    // Production already grants the runtime role access to the schema objects
    // predating 0024. Reconstruct that boundary without granting either the
    // migration ledger, the new sidecar, or any column added by 0024.
    sqlx::raw_sql(
        "DO $$
         DECLARE
             object_name TEXT;
             legacy_outbox_columns TEXT;
         BEGIN
             FOR object_name IN
                 SELECT tablename
                 FROM pg_tables
                 WHERE schemaname = 'public'
                   AND tablename NOT IN (
                       '_sqlx_migrations', 'outbox', 'sdk_outbound_invocations'
                   )
             LOOP
                 EXECUTE format(
                     'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO paykit',
                     object_name
                 );
             END LOOP;

             SELECT string_agg(format('%I', column_name), ', ' ORDER BY ordinal_position)
             INTO legacy_outbox_columns
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = 'outbox'
               AND column_name NOT IN (
                   'handoff_invocation_token',
                   'recovery_attempts',
                   'recovery_first_at',
                   'recovery_last_at'
               );
             EXECUTE format(
                 'GRANT SELECT (%1$s), INSERT (%1$s), UPDATE (%1$s) ON TABLE public.outbox TO paykit',
                 legacy_outbox_columns
             );
         END $$;
         GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO paykit;",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn runtime_role_pool(database: &TestDatabase) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET ROLE paykit").execute(connection).await?;
                Ok(())
            })
        })
        .connect(database.database_url())
        .await
        .unwrap()
}

fn assert_insufficient_privilege(
    operation: &str,
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
) {
    let error = result.unwrap_err();
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.code())
            .as_deref(),
        Some("42501"),
        "{operation} did not fail with insufficient privilege"
    );
}

/// The migration owner applies 0024, while every production persistence
/// operation below runs as the fixed non-owner `paykit` role. The real SDK
/// adapter commits encrypted state and its invocation sidecar atomically, and
/// the real resolver reads that evidence before completing attribution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn runtime_paykit_role_completes_fenced_resolver_without_migration_authority() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    grant_pre_0024_runtime_privileges(database.pool()).await;
    let runtime_pool = runtime_role_pool(&database).await;

    let authority_is_restricted: bool = sqlx::query_scalar(
        "SELECT current_user = 'paykit'
             AND session_user <> current_user
             AND NOT roles.rolsuper
             AND NOT roles.rolcreatedb
             AND NOT roles.rolcreaterole
             AND NOT roles.rolinherit
             AND NOT roles.rolreplication
             AND NOT roles.rolbypassrls
             AND NOT EXISTS (
                 SELECT 1 FROM pg_auth_members memberships WHERE memberships.member = roles.oid
             )
             AND (
                 SELECT tables.relowner <> roles.oid
                 FROM pg_class tables
                 WHERE tables.oid = 'public.sdk_outbound_invocations'::regclass
             )
         FROM pg_roles roles
         WHERE roles.rolname = current_user",
    )
    .fetch_one(&runtime_pool)
    .await
    .unwrap();
    assert!(
        authority_is_restricted,
        "runtime role inherited authority or owns the sidecar"
    );

    let crypto = Arc::new(Crypto::from_master_key(&[79; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture_on_pool(&runtime_pool, crypto.clone(), 79).await;
    let invoice = InvoiceStore::new(&runtime_pool, crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"runtime-role-resolver-bundle",
            payment_request_binding: b"runtime-role-resolver-request",
            new_reader_payloads: &LinkedPayloads {
                reader: reader.clone(),
                marker: peer_marker.clone(),
            },
            payment_request_intent: DeliveryIntentV1::payment_request(
                reader.to_string(),
                &peer_marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                &PaymentRequestTerms {
                    amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                    payment_reference: PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                    proposal_expires_at: None,
                    recurrence: None,
                    accepted_payment_endpoint_identifiers: vec![
                        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    ],
                    metadata: Default::default(),
                },
            )
            .unwrap(),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(&runtime_pool, crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        claim.id(),
        invoice.endpoint_publication_outbox_id().unwrap()
    );
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
            .await
            .unwrap()
    );
    let token = outbox
        .handoff_invocation_token(&claim)
        .await
        .unwrap()
        .unwrap();
    let intent = outbox.delivery_intent(&claim).unwrap();
    let result = handoff_with_invocation_token(&adapter, &intent, token)
        .await
        .expect("runtime role persists SDK state and invocation sidecar");
    let outbound = match result {
        HandoffResult::EndpointPublication {
            outbound_message_id,
        } => outbound_message_id,
        HandoffResult::PaymentRequestProposal { .. } => panic!("endpoint intent created request"),
    };

    let sidecar: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations
         WHERE creator_id = (SELECT creator_id FROM outbox WHERE id = $1)
           AND sdk_outbound_message_id = $2",
    )
    .bind(claim.id())
    .bind(outbound.to_string())
    .fetch_one(&runtime_pool)
    .await
    .unwrap();
    assert_eq!(sidecar, token, "runtime role reads its inserted sidecar");
    let sdk_state = SdkStateStore::new(&runtime_pool, crypto.clone())
        .load(&creator)
        .await
        .unwrap();
    assert!(
        sdk_state
            .outbound_private_messages
            .iter()
            .any(|record| record.outbound_message_id == outbound),
        "runtime role reads the durable SDK record"
    );

    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(claim.id())
        .execute(&runtime_pool)
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        process_fence_recovery(&outbox, &adapter, &recovery)
            .await
            .unwrap()
    );
    let attributed: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(claim.id())
            .fetch_one(&runtime_pool)
            .await
            .unwrap();
    assert_eq!(
        attributed,
        ("handed_off".into(), Some(outbound.to_string())),
        "runtime resolver completes causal attribution"
    );

    assert_insufficient_privilege(
        "sidecar update",
        sqlx::query(
            "UPDATE sdk_outbound_invocations SET invocation_token = gen_random_uuid()
             WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
        )
        .bind(recovery.creator_id())
        .bind(outbound.to_string())
        .execute(&runtime_pool)
        .await,
    );
    assert_insufficient_privilege(
        "sidecar delete",
        sqlx::query(
            "DELETE FROM sdk_outbound_invocations
             WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
        )
        .bind(recovery.creator_id())
        .bind(outbound.to_string())
        .execute(&runtime_pool)
        .await,
    );
    assert_insufficient_privilege(
        "sidecar truncate",
        sqlx::query("TRUNCATE sdk_outbound_invocations")
            .execute(&runtime_pool)
            .await,
    );
    assert_insufficient_privilege(
        "sidecar trigger disable",
        sqlx::query(
            "ALTER TABLE sdk_outbound_invocations
             DISABLE TRIGGER sdk_outbound_invocations_immutable",
        )
        .execute(&runtime_pool)
        .await,
    );
    assert_insufficient_privilege(
        "sidecar trigger drop",
        sqlx::query("DROP TRIGGER sdk_outbound_invocations_immutable ON sdk_outbound_invocations")
            .execute(&runtime_pool)
            .await,
    );
    assert_insufficient_privilege(
        "sidecar table drop",
        sqlx::query("DROP TABLE sdk_outbound_invocations")
            .execute(&runtime_pool)
            .await,
    );
    assert_insufficient_privilege(
        "sidecar ownership alteration",
        sqlx::query("ALTER TABLE sdk_outbound_invocations OWNER TO paykit")
            .execute(&runtime_pool)
            .await,
    );
    verify_migrations_applied(&runtime_pool)
        .await
        .expect("runtime startup verifies the owner-applied migration ledger");
    assert!(
        run_migrations(&runtime_pool).await.is_err(),
        "runtime role executed the migration runner"
    );
    assert_insufficient_privilege(
        "migration ledger write",
        sqlx::query("UPDATE _sqlx_migrations SET success = success WHERE version = 24")
            .execute(&runtime_pool)
            .await,
    );
    assert_insufficient_privilege(
        "migration DDL execution",
        sqlx::query("CREATE TABLE runtime_migration_probe (id INTEGER)")
            .execute(&runtime_pool)
            .await,
    );

    runtime_pool.close().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_attributes_unique_current_token_endpoint() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[71; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 71).await;
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"resolver-endpoint-bundle",
            payment_request_binding: b"resolver-endpoint-request",
            new_reader_payloads: &LinkedPayloads {
                reader: reader.clone(),
                marker: peer_marker.clone(),
            },
            payment_request_intent: DeliveryIntentV1::payment_request(
                reader.to_string(),
                &peer_marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                &PaymentRequestTerms {
                    amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                    payment_reference: PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                    proposal_expires_at: None,
                    recurrence: None,
                    accepted_payment_endpoint_identifiers: vec![
                        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    ],
                    metadata: Default::default(),
                },
            )
            .unwrap(),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        claim.id(),
        invoice.endpoint_publication_outbox_id().unwrap()
    );
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
            .await
            .unwrap()
    );
    let token = outbox
        .handoff_invocation_token(&claim)
        .await
        .unwrap()
        .unwrap();
    let intent = outbox.delivery_intent(&claim).unwrap();
    let result = handoff_with_invocation_token(&adapter, &intent, token)
        .await
        .unwrap();
    let outbound = match result {
        HandoffResult::EndpointPublication {
            outbound_message_id,
        } => outbound_message_id,
        HandoffResult::PaymentRequestProposal { .. } => panic!("endpoint intent created request"),
    };
    let sidecar: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations \
         WHERE creator_id = (SELECT creator_id FROM outbox WHERE id = $1) \
           AND sdk_outbound_message_id = $2",
    )
    .bind(claim.id())
    .bind(outbound.to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(sidecar, token);
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(claim.id())
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        process_fence_recovery(&outbox, &adapter, &recovery)
            .await
            .unwrap()
    );
    assert_eq!(
        outbox_row(&database, claim.id()).await.0,
        "handed_off",
        "resolver outcome: {:?}",
        outbox_row(&database, claim.id()).await
    );
    assert!(
        outbox
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "a handed-off parent cannot admit its child before Sent reconciliation"
    );
    SdkStateStore::new(database.pool(), crypto)
        .update(&creator, move |state| {
            state
                .outbound_private_messages
                .iter_mut()
                .find(|record| record.outbound_message_id == outbound)
                .unwrap()
                .status = OutboundPrivateMessageStatus::Sent;
        })
        .await
        .unwrap();
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        process_reconciliation(&outbox, &adapter, &reconciliation, Duration::from_secs(1),)
            .await
            .unwrap()
    );
    assert_eq!(outbox_row(&database, claim.id()).await.0, "delivered");
    let child = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .expect("exact Sent reconciliation admits the dependent request");
    assert_eq!(child.id(), invoice.payment_request_outbox_id());
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_historical_identical_foreign_is_not_found_and_untagged_is_ambiguous() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[74; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 74).await;
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let outbox = OutboxStore::new(database.pool(), crypto.clone());

    let (_, historical_endpoint, _) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "historical").await;
    let historical_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(historical_claim.id(), historical_endpoint);
    assert!(
        process_claim(
            &outbox,
            &adapter,
            &historical_claim,
            Duration::from_secs(1),
            20,
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
    );
    let (historical_outbound, foreign_token): (String, Uuid) = sqlx::query_as(
        "SELECT o.sdk_outbound_message_id, sidecar.invocation_token \
         FROM outbox o JOIN sdk_outbound_invocations sidecar \
           ON sidecar.creator_id = o.creator_id \
          AND sidecar.sdk_outbound_message_id = o.sdk_outbound_message_id \
         WHERE o.id = $1",
    )
    .bind(historical_endpoint)
    .fetch_one(database.pool())
    .await
    .unwrap();

    let (_, foreign_target, foreign_child) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "foreign").await;
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), foreign_target);
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
            .await
            .unwrap()
    );
    let current_token = outbox
        .handoff_invocation_token(&claim)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(current_token, foreign_token);
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(foreign_target)
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let no_effects = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&outbox, &no_effects, &recovery)
            .await
            .unwrap()
    );
    assert_eq!(no_effects.sdk_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        outbox_row(&database, foreign_target).await.2.as_deref(),
        Some("sdk_effect_not_found")
    );
    assert_eq!(
        outbox_row(&database, foreign_child).await.0,
        "permanently_failed"
    );

    let historical_id = historical_outbound.parse::<u64>().unwrap();
    let untagged_id = Arc::new(Mutex::new(None));
    SdkStateStore::new(database.pool(), crypto.clone())
        .update(&creator, {
            let untagged_id = untagged_id.clone();
            move |state| {
                let mut legacy = state
                    .outbound_private_messages
                    .iter()
                    .find(|record| record.outbound_message_id == historical_id)
                    .unwrap()
                    .clone();
                legacy.outbound_message_id = state.next_outbound_private_message_id;
                state.next_outbound_private_message_id += 1;
                *untagged_id.lock().unwrap() = Some(legacy.outbound_message_id);
                state.outbound_private_messages.push(legacy);
            }
        })
        .await
        .unwrap();
    let untagged_id = untagged_id.lock().unwrap().unwrap();
    let sidecar_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sdk_outbound_invocations \
         WHERE creator_id = $1 AND sdk_outbound_message_id = $2)",
    )
    .bind(recovery.creator_id())
    .bind(untagged_id.to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(!sidecar_exists, "legacy record must remain untagged");

    let (_, untagged_target, untagged_child) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "untagged").await;
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), untagged_target);
    assert!(outbox.begin_handoff(&claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&claim)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(untagged_target)
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        process_fence_recovery(&outbox, &no_effects, &recovery)
            .await
            .unwrap()
    );
    assert_eq!(no_effects.sdk_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        outbox_row(&database, untagged_target).await.2.as_deref(),
        Some("sdk_effect_ambiguous")
    );
    assert_eq!(
        outbox_row(&database, untagged_child).await.0,
        "permanently_failed"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_durable_semantic_and_authenticated_evidence_matrix() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[76; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 76).await;
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let outbox = OutboxStore::new(database.pool(), crypto.clone());

    for case in [
        "wrong-payload",
        "partial-content",
        "superset-content",
        "wrong-reader",
        "wrong-path",
        "wrong-kind",
    ] {
        eprintln!("durable endpoint semantic case: {case}");
        let (_, target_id, child_id) =
            create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, case).await;
        let (_, result, _) = fence_and_emit_exact(&database, &outbox, &adapter, target_id).await;
        let outbound_id = result.outbound_message_id();
        let wrong_reader = creator.to_string();
        SdkStateStore::new(database.pool(), crypto.clone())
            .update(&creator, move |state| {
                let record = state
                    .outbound_private_messages
                    .iter_mut()
                    .find(|record| record.outbound_message_id == outbound_id)
                    .unwrap();
                match case {
                    "wrong-reader" => {
                        record.counterparty =
                            PubkyPublicKey::from_raw_or_app_key(wrong_reader).unwrap();
                    }
                    "wrong-path" => {
                        record.counterparty_receiver_path =
                            PaykitReceiverPath::new("other/server").unwrap();
                    }
                    "wrong-kind" => {
                        record.kind = PrivateMessageKind::PaymentRequest.as_str().into();
                    }
                    content_case => {
                        let mut payload: serde_json::Value =
                            serde_json::from_str(&record.raw_json).unwrap();
                        let endpoints = payload["payment_endpoints"].as_object_mut().unwrap();
                        match content_case {
                            "wrong-payload" => {
                                endpoints.insert(
                                    "btc-bitcoin-p2wpkh".into(),
                                    serde_json::json!("different-address"),
                                );
                            }
                            "partial-content" => {
                                endpoints.remove("btc-lightning-bolt11");
                            }
                            "superset-content" => {
                                endpoints
                                    .insert("btc-extra".into(), serde_json::json!("unexpected"));
                            }
                            _ => unreachable!(),
                        }
                        record.raw_json = payload.to_string();
                    }
                }
            })
            .await
            .unwrap();
        recover_and_assert_closed(
            &database,
            &outbox,
            target_id,
            child_id,
            "sdk_effect_not_found",
        )
        .await;
        if case == "wrong-kind" {
            SdkStateStore::new(database.pool(), crypto.clone())
                .update(&creator, move |state| {
                    state
                        .outbound_private_messages
                        .iter_mut()
                        .find(|record| record.outbound_message_id == outbound_id)
                        .unwrap()
                        .counterparty_receiver_path =
                        PaykitReceiverPath::new("isolated/server").unwrap();
                })
                .await
                .unwrap();
        }
    }

    let (_, owned_target, owned_child) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "owned-target")
            .await;
    eprintln!("durable endpoint semantic case: owned-exact");
    let (_, owned_result, _) =
        fence_and_emit_exact(&database, &outbox, &adapter, owned_target).await;
    let (_, sibling_id, _) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "owned-sibling")
            .await;
    sqlx::query(
        "UPDATE outbox SET status = 'handed_off', sdk_outbound_message_id = $2 \
         WHERE id = $1",
    )
    .bind(sibling_id)
    .bind(owned_result.outbound_message_id().to_string())
    .execute(database.pool())
    .await
    .unwrap();
    recover_and_assert_closed(
        &database,
        &outbox,
        owned_target,
        owned_child,
        "sdk_effect_already_owned",
    )
    .await;
    eprintln!("durable endpoint semantic case: malformed-relevant-record");

    let (_, malformed_target, malformed_child) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "malformed-record",
    )
    .await;
    let (_, malformed_result, _) =
        fence_and_emit_exact(&database, &outbox, &adapter, malformed_target).await;
    let malformed_id = malformed_result.outbound_message_id();
    SdkStateStore::new(database.pool(), crypto.clone())
        .update(&creator, move |state| {
            state
                .outbound_private_messages
                .iter_mut()
                .find(|record| record.outbound_message_id == malformed_id)
                .unwrap()
                .raw_json = "{".into();
        })
        .await
        .unwrap();
    recover_and_assert_closed(
        &database,
        &outbox,
        malformed_target,
        malformed_child,
        "sdk_evidence_indeterminate",
    )
    .await;

    eprintln!("durable endpoint semantic case: malformed-foreign-is-ignored");
    let (_, clean_target, clean_child) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "clean-current-after-malformed-foreign",
    )
    .await;
    let (_, clean_result, _) =
        fence_and_emit_exact(&database, &outbox, &adapter, clean_target).await;
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(clean_target)
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let no_effects = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&outbox, &no_effects, &recovery)
            .await
            .unwrap()
    );
    assert_eq!(no_effects.sdk_calls.load(Ordering::SeqCst), 0);
    let clean_row: (String, Option<String>) =
        sqlx::query_as("SELECT status, sdk_outbound_message_id FROM outbox WHERE id = $1")
            .bind(clean_target)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(
        clean_row,
        (
            "handed_off".into(),
            Some(clean_result.outbound_message_id().to_string())
        )
    );
    assert_eq!(outbox_row(&database, clean_child).await.0, "queued");

    for (case_index, case) in [
        "amount-value",
        "amount-asset",
        "payment-reference",
        "proposal-expiry",
        "accepted-endpoints",
        "recurrence",
        "metadata",
    ]
    .into_iter()
    .enumerate()
    {
        eprintln!("durable payment semantic case: {case}");
        let (_, endpoint_id, target_id) =
            create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, case).await;
        sqlx::query(
            "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = $2 WHERE id = $1",
        )
        .bind(endpoint_id)
        .bind((900_000 + case_index).to_string())
        .execute(database.pool())
        .await
        .unwrap();
        let (_, result, _) = fence_and_emit_exact(&database, &outbox, &adapter, target_id).await;
        let outbound_id = result.outbound_message_id();
        SdkStateStore::new(database.pool(), crypto.clone())
            .update(&creator, move |state| {
                let record = state
                    .outbound_private_messages
                    .iter_mut()
                    .find(|record| record.outbound_message_id == outbound_id)
                    .unwrap();
                let mut payload: serde_json::Value =
                    serde_json::from_str(&record.raw_json).unwrap();
                match case {
                    "amount-value" => {
                        payload["request"]["amount"]["value"] = serde_json::json!("0.00000200");
                    }
                    "amount-asset" => {
                        payload["request"]["amount"]["asset"] = serde_json::json!("USD");
                    }
                    "payment-reference" => {
                        payload["request"]["payment_reference"] =
                            serde_json::json!(Uuid::new_v4().to_string());
                    }
                    "proposal-expiry" => {
                        payload["request"]["proposal_expires_at"] =
                            serde_json::json!("2030-01-01T00:00:00Z");
                    }
                    "accepted-endpoints" => {
                        payload["request"]["accepted_payment_endpoint_identifiers"] =
                            serde_json::json!(["btc-lightning-bolt11"]);
                    }
                    "recurrence" => {
                        payload["request"]["recurrence"] = serde_json::json!({
                            "every": 1,
                            "unit": "month",
                            "starts_at": "2030-01-01T00:00:00Z",
                            "anchor": "2030-01-01T00:00:00Z",
                            "ends_at": null
                        });
                    }
                    "metadata" => {
                        payload["request"]["metadata"] =
                            serde_json::json!({"purpose": "different"});
                    }
                    _ => unreachable!(),
                }
                record.raw_json = payload.to_string();
            })
            .await
            .unwrap();
        recover_and_assert_closed(
            &database,
            &outbox,
            target_id,
            target_id,
            "sdk_effect_not_found",
        )
        .await;
    }

    let (_, endpoint_id, generated_id_target) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "missing-generated-id",
    )
    .await;
    eprintln!("durable payment semantic case: missing-generated-id");
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '900100' \
         WHERE id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let (_, generated_result, _) =
        fence_and_emit_exact(&database, &outbox, &adapter, generated_id_target).await;
    let generated_outbound_id = generated_result.outbound_message_id();
    SdkStateStore::new(database.pool(), crypto.clone())
        .update(&creator, move |state| {
            let record = state
                .outbound_private_messages
                .iter_mut()
                .find(|record| record.outbound_message_id == generated_outbound_id)
                .unwrap();
            let mut payload: serde_json::Value = serde_json::from_str(&record.raw_json).unwrap();
            payload["event_id"] = serde_json::json!("not-an-id");
            record.raw_json = payload.to_string();
        })
        .await
        .unwrap();
    recover_and_assert_closed(
        &database,
        &outbox,
        generated_id_target,
        generated_id_target,
        "sdk_evidence_indeterminate",
    )
    .await;

    for case in [
        "invalid-path",
        "unsupported-version",
        "duplicate-identifier",
    ] {
        eprintln!("authenticated invalid intent case: {case}");
        let (_, target_id, child_id) =
            create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, case).await;
        let (_, _, intent) = fence_and_emit_exact(&database, &outbox, &adapter, target_id).await;
        let invalid = match case {
            "invalid-path" => intent.encoded_with_invalid_path_for_test(),
            "unsupported-version" => intent.encoded_with_unsupported_version_for_test(),
            "duplicate-identifier" => intent.encoded_with_duplicate_expected_identifier_for_test(),
            _ => unreachable!(),
        };
        assert!(
            DeliveryIntentV1::decode(&invalid).is_err(),
            "calibration: {case} must be invalid"
        );
        replace_authenticated_intent(&database, &crypto, target_id, &invalid).await;
        recover_and_assert_closed(
            &database,
            &outbox,
            target_id,
            child_id,
            "sdk_evidence_indeterminate",
        )
        .await;
    }

    let (_, duplicate_payment_parent, duplicate_payment_target) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "duplicate-payment-identifier",
    )
    .await;
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', \
         sdk_outbound_message_id = '900101' WHERE id = $1",
    )
    .bind(duplicate_payment_parent)
    .execute(database.pool())
    .await
    .unwrap();
    let (_, _, payment_intent) =
        fence_and_emit_exact(&database, &outbox, &adapter, duplicate_payment_target).await;
    let invalid_payment = payment_intent.encoded_with_duplicate_expected_identifier_for_test();
    assert!(DeliveryIntentV1::decode(&invalid_payment).is_err());
    replace_authenticated_intent(
        &database,
        &crypto,
        duplicate_payment_target,
        &invalid_payment,
    )
    .await;
    recover_and_assert_closed(
        &database,
        &outbox,
        duplicate_payment_target,
        duplicate_payment_target,
        "sdk_evidence_indeterminate",
    )
    .await;

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_invocation_sidecar_atomic_rollback_retag_conflict_and_callback_barrier() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[75; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        creator_sdk,
        storage,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 75).await;
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let outbox = OutboxStore::new(database.pool(), crypto.clone());

    let (_, first_endpoint, _) =
        create_fixed_linked_invoice(&invoices, &creator, &reader, &peer_marker, "sidecar-first")
            .await;
    let first_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first_claim.id(), first_endpoint);
    assert!(
        process_claim(
            &outbox,
            &adapter,
            &first_claim,
            Duration::from_secs(1),
            20,
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
    );
    let (first_outbound, first_token): (String, Uuid) = sqlx::query_as(
        "SELECT o.sdk_outbound_message_id, sidecar.invocation_token \
         FROM outbox o JOIN sdk_outbound_invocations sidecar \
           ON sidecar.creator_id = o.creator_id \
          AND sidecar.sdk_outbound_message_id = o.sdk_outbound_message_id \
         WHERE o.id = $1",
    )
    .bind(first_endpoint)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let first_sidecars: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(first_token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        first_sidecars, 1,
        "marker/link callbacks cannot consume the enqueue invocation token"
    );

    let (_, update_failure_endpoint, _) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "sidecar-update-failure",
    )
    .await;
    let update_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(update_claim.id(), update_failure_endpoint);
    assert!(outbox.begin_handoff(&update_claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&update_claim)
            .await
            .unwrap()
    );
    let update_token = outbox
        .handoff_invocation_token(&update_claim)
        .await
        .unwrap()
        .unwrap();
    let update_intent = outbox.delivery_intent(&update_claim).unwrap();
    let records_before = SdkStateStore::new(database.pool(), crypto.clone())
        .load(&creator)
        .await
        .unwrap()
        .outbound_private_messages
        .len();
    sqlx::raw_sql(
        "CREATE FUNCTION reject_test_sdk_state_update() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected sdk state update failure'; END $$; \
         CREATE TRIGGER reject_test_sdk_state_update BEFORE UPDATE ON sdk_states \
         FOR EACH ROW EXECUTE FUNCTION reject_test_sdk_state_update();",
    )
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        handoff_with_invocation_token(&adapter, &update_intent, update_token)
            .await
            .is_err()
    );
    assert_eq!(
        SdkStateStore::new(database.pool(), crypto.clone())
            .load(&creator)
            .await
            .unwrap()
            .outbound_private_messages
            .len(),
        records_before
    );
    let update_sidecars: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(update_token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        update_sidecars, 0,
        "failed state update cannot leave a sidecar"
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_test_sdk_state_update ON sdk_states; \
         DROP FUNCTION reject_test_sdk_state_update();",
    )
    .execute(database.pool())
    .await
    .unwrap();

    let update_result = handoff_with_invocation_token(&adapter, &update_intent, update_token)
        .await
        .unwrap();
    assert!(
        outbox
            .mark_handed_off(&update_claim, &update_result)
            .await
            .unwrap()
    );
    let first_token_after: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations \
         WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
    )
    .bind(update_claim.creator_id())
    .bind(&first_outbound)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        first_token_after, first_token,
        "a later invocation cannot retag an existing record"
    );
    let update_record_token: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations \
         WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
    )
    .bind(update_claim.creator_id())
    .bind(update_result.outbound_message_id().to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(update_record_token, update_token);
    let records_after_first_append = SdkStateStore::new(database.pool(), crypto.clone())
        .load(&creator)
        .await
        .unwrap()
        .outbound_private_messages
        .len();
    assert!(
        handoff_with_invocation_token(&adapter, &update_intent, update_token)
            .await
            .is_err(),
        "one invocation token cannot authorize a second append"
    );
    assert_eq!(
        SdkStateStore::new(database.pool(), crypto.clone())
            .load(&creator)
            .await
            .unwrap()
            .outbound_private_messages
            .len(),
        records_after_first_append,
        "the rejected multi-append attempt rolls back its SDK-state record"
    );
    let update_token_sidecars: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(update_token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(update_token_sidecars, 1);

    let (_, conflict_endpoint, _) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "sidecar-conflict",
    )
    .await;
    let conflict_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(conflict_claim.id(), conflict_endpoint);
    assert!(outbox.begin_handoff(&conflict_claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&conflict_claim)
            .await
            .unwrap()
    );
    let conflict_token = outbox
        .handoff_invocation_token(&conflict_claim)
        .await
        .unwrap()
        .unwrap();
    let conflict_intent = outbox.delivery_intent(&conflict_claim).unwrap();
    let conflict_records_before = SdkStateStore::new(database.pool(), crypto)
        .load(&creator)
        .await
        .unwrap()
        .outbound_private_messages
        .len();
    sqlx::query(
        "INSERT INTO sdk_outbound_invocations \
         (creator_id, sdk_outbound_message_id, invocation_token) VALUES ($1, $2, $3)",
    )
    .bind(conflict_claim.creator_id())
    .bind("18446744073709551615")
    .bind(conflict_token)
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        handoff_with_invocation_token(&adapter, &conflict_intent, conflict_token)
            .await
            .is_err()
    );
    let conflict_records_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(conflict_token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(conflict_records_after, 1);
    let durable_record_count: usize = SdkStateStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[75; 32]).unwrap()),
    )
    .load(&creator)
    .await
    .unwrap()
    .outbound_private_messages
    .len();
    assert_eq!(
        durable_record_count, conflict_records_before,
        "sidecar conflict rolls back the SDK-state append"
    );

    let before_multiappend = creator_sdk.export_backup_state().await.unwrap();
    let mut two_append = before_multiappend.clone();
    let mut first_append = two_append
        .outbound_private_messages
        .last()
        .expect("fixture has an outbound record")
        .clone();
    first_append.outbound_message_id = two_append.next_outbound_private_message_id;
    let mut second_append = first_append.clone();
    second_append.outbound_message_id += 1;
    two_append.next_outbound_private_message_id += 2;
    two_append.outbound_private_messages.push(first_append);
    two_append.outbound_private_messages.push(second_append);
    let multiappend_token = Uuid::new_v4();
    storage
        .set_invocation_token_for_test(multiappend_token)
        .unwrap();
    let multiappend = creator_sdk.restore_backup_state(two_append).await;
    storage.clear_invocation_token_for_test();
    assert!(
        multiappend.is_err(),
        "one storage callback appended two outbound records"
    );
    assert_eq!(
        creator_sdk.export_backup_state().await.unwrap(),
        before_multiappend,
        "multiappend rejection rolls back the complete SDK snapshot"
    );
    let multiappend_sidecars: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(multiappend_token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(multiappend_sidecars, 0);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_invocation_sidecar_unlinked_link_callback_cannot_consume_token() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[77; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = unlinked_paykit_fixture(&database, crypto.clone(), 77).await;
    let (_, endpoint_id, _) = create_fixed_linked_invoice(
        &InvoiceStore::new(database.pool(), crypto.clone()),
        &creator,
        &reader,
        &peer_marker,
        "unlinked-callback",
    )
    .await;
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(claim.id(), endpoint_id);
    assert!(
        process_claim(
            &outbox,
            &adapter,
            &claim,
            Duration::from_secs(1),
            20,
            Duration::from_secs(3600),
        )
        .await
        .unwrap()
    );
    let (status, token): (String, Uuid) =
        sqlx::query_as("SELECT status, handoff_invocation_token FROM outbox WHERE id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(status, "retryable");
    let sidecars: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sdk_outbound_invocations WHERE invocation_token = $1",
    )
    .bind(token)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        sidecars, 0,
        "an actually-unlinked link callback cannot consume the handoff token"
    );
    assert!(
        SdkStateStore::new(database.pool(), crypto)
            .load(&creator)
            .await
            .unwrap()
            .outbound_private_messages
            .is_empty(),
        "link establishment did not reach the intended enqueue callback"
    );
    database.cleanup().await;
}

/// A linked peer and the production adapter create the payment-request record
/// in encrypted durable `StorageState`.  Recovery is then allowed to use only
/// the sidecar carrying this claim's token; the generated SDK ids are copied
/// exactly, while the endpoint parent remains the gate for this child.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_attributes_unique_current_token_payment_request() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[72; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 72).await;
    let invoice = InvoiceStore::new(database.pool(), crypto.clone())
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &reader,
            bundle_binding: b"resolver-payment-bundle",
            payment_request_binding: b"resolver-payment-request",
            new_reader_payloads: &LinkedPayloads {
                reader: reader.clone(),
                marker: peer_marker.clone(),
            },
            payment_request_intent: DeliveryIntentV1::payment_request(
                reader.to_string(),
                &peer_marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                &PaymentRequestTerms {
                    amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                    payment_reference: PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                    proposal_expires_at: None,
                    recurrence: None,
                    accepted_payment_endpoint_identifiers: vec![
                        PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    ],
                    metadata: Default::default(),
                },
            )
            .unwrap(),
            required_sats: 100,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());

    // Drive the real worker boundary for the parent.  A local SDK enqueue is
    // only handed_off, so no dependent payment request may be claimed yet.
    let endpoint_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        endpoint_claim.id(),
        invoice.endpoint_publication_outbox_id().unwrap()
    );
    assert!(
        process_claim(
            &outbox,
            &adapter,
            &endpoint_claim,
            Duration::from_secs(1),
            20,
            Duration::from_secs(60 * 60),
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
        "payment-request child stays blocked until the exact endpoint is Sent"
    );

    // Model only the already-reconciled parent so the child can be fenced.
    sqlx::query(
        "UPDATE outbox SET status = 'delivered', sdk_outbound_message_id = '0', \
         lease_owner = NULL, claim_token = NULL, lease_expires_at = NULL WHERE id = $1",
    )
    .bind(endpoint_claim.id())
    .execute(database.pool())
    .await
    .unwrap();
    let request_claim = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(request_claim.id(), invoice.payment_request_outbox_id());
    assert!(outbox.begin_handoff(&request_claim).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&request_claim)
            .await
            .unwrap()
    );
    let token = outbox
        .handoff_invocation_token(&request_claim)
        .await
        .unwrap()
        .expect("fenced invocation mints its token");
    let intent = outbox.delivery_intent(&request_claim).unwrap();
    let result = handoff_with_invocation_token(&adapter, &intent, token)
        .await
        .unwrap();
    let (outbound_id, event_id, payment_request_id) = match result {
        HandoffResult::PaymentRequestProposal {
            outbound_message_id,
            event_id,
            payment_request_id,
        } => (outbound_message_id, event_id, payment_request_id),
        HandoffResult::EndpointPublication { .. } => panic!("payment intent created endpoints"),
    };
    assert!(!event_id.is_empty());
    assert!(!payment_request_id.is_empty());
    let sidecar: Uuid = sqlx::query_scalar(
        "SELECT invocation_token FROM sdk_outbound_invocations \
         WHERE creator_id = (SELECT creator_id FROM outbox WHERE id = $1) \
           AND sdk_outbound_message_id = $2",
    )
    .bind(request_claim.id())
    .bind(outbound_id.to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(sidecar, token, "storage sidecar is the fenced token");

    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(request_claim.id())
        .execute(database.pool())
        .await
        .unwrap();
    let recovery = outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(recovery.id(), request_claim.id());
    assert!(
        process_fence_recovery(&outbox, &adapter, &recovery)
            .await
            .unwrap()
    );
    let attributed: (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id \
         FROM outbox WHERE id = $1",
    )
    .bind(request_claim.id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        attributed,
        (
            "handed_off".into(),
            Some(outbound_id.to_string()),
            Some(event_id),
            Some(payment_request_id),
        ),
        "recovery attributes only the exact causally-tagged SDK result"
    );
    database.cleanup().await;
}

/// Two independent PostgreSQL pools race the same durable recovery claim ten
/// times. The target-row lock and live-fence CAS allow exactly one commit,
/// replay after that commit is a deterministic no-op, and invoice finality on
/// either side of the resolver commit never admits the dependent request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_race_replay_and_finality_orders_10x() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[73; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 73).await;
    let replica_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database.database_url())
        .await
        .unwrap();
    let replica_a = OutboxStore::new(database.pool(), crypto.clone());
    let replica_b = OutboxStore::new(&replica_pool, crypto.clone());
    let invoices = InvoiceStore::new(database.pool(), crypto);

    for iteration in 0..10_u8 {
        let bundle = format!("resolver-race-bundle-{iteration}");
        let request = format!("resolver-race-request-{iteration}");
        let invoice = invoices
            .create_atomic(AtomicInvoiceInput {
                creator: &creator,
                reader: &reader,
                bundle_binding: bundle.as_bytes(),
                payment_request_binding: request.as_bytes(),
                new_reader_payloads: &LinkedPayloads {
                    reader: reader.clone(),
                    marker: peer_marker.clone(),
                },
                payment_request_intent: DeliveryIntentV1::payment_request(
                    reader.to_string(),
                    &peer_marker,
                    PaykitReceiverPath::new("paykit/server").unwrap(),
                    &PaymentRequestTerms {
                        amount: PaymentAmount::new("0.00000100", "BTC").unwrap(),
                        payment_reference: PaymentReference::new(Uuid::new_v4().to_string())
                            .unwrap(),
                        proposal_expires_at: None,
                        recurrence: None,
                        accepted_payment_endpoint_identifiers: vec![
                            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                        ],
                        metadata: Default::default(),
                    },
                )
                .unwrap(),
                required_sats: 100,
                nonce_sats: 1,
                prepare_ttl: Duration::from_secs(900),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
            })
            .await
            .unwrap();
        let endpoint_id = invoice.endpoint_publication_outbox_id().unwrap();
        let child_id = invoice.payment_request_outbox_id();
        let claim = replica_a
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .into_iter()
            .find(|claim| claim.id() == endpoint_id)
            .expect("new endpoint is ordinary-claim eligible");
        assert!(replica_a.begin_handoff(&claim).await.unwrap());
        assert!(
            replica_a
                .mark_handoff_invocation_started(&claim)
                .await
                .unwrap()
        );
        let token = replica_a
            .handoff_invocation_token(&claim)
            .await
            .unwrap()
            .unwrap();
        let intent = replica_a.delivery_intent(&claim).unwrap();
        let result = handoff_with_invocation_token(&adapter, &intent, token)
            .await
            .unwrap();
        let outbound_id = result.outbound_message_id();

        // Serial order one: finality commits before attribution. The already
        // fenced external effect remains auditable, while the child closes.
        if iteration == 0 {
            assert!(
                invoices
                    .resolve_invoice(
                        invoice.invoice_id(),
                        "abandoned",
                        time::OffsetDateTime::now_utc(),
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        sqlx::query(
            "UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
        let recovery = replica_a
            .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .pop()
            .unwrap();

        let (a, b) = tokio::join!(
            process_fence_recovery(&replica_a, &adapter, &recovery),
            process_fence_recovery(&replica_b, &adapter, &recovery),
        );
        assert_eq!(
            usize::from(a.unwrap()) + usize::from(b.unwrap()),
            1,
            "iteration {iteration}: exactly one replica commits attribution"
        );
        assert!(
            !process_fence_recovery(&replica_b, &adapter, &recovery)
                .await
                .unwrap(),
            "iteration {iteration}: after-commit replay must be a no-op"
        );

        let owner_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM outbox WHERE creator_id = $1 \
             AND sdk_outbound_message_id = $2",
        )
        .bind(recovery.creator_id())
        .bind(outbound_id.to_string())
        .fetch_one(database.pool())
        .await
        .unwrap();
        assert_eq!(owner_count, 1);
        assert_eq!(outbox_row(&database, endpoint_id).await.0, "handed_off");
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
                .bind(endpoint_id)
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(events, 0, "successful replay creates no terminal event");

        // Serial order two: finality commits after attribution. The handed-off
        // parent remains auditable, and finality still closes the child.
        if iteration == 1 {
            assert!(
                invoices
                    .resolve_invoice(
                        invoice.invoice_id(),
                        "abandoned",
                        time::OffsetDateTime::now_utc(),
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            replica_a
                .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
                .await
                .unwrap()
                .iter()
                .all(|claim| claim.id() != child_id),
            "iteration {iteration}: child became claimable without exact Sent"
        );
        if iteration <= 1 {
            assert_eq!(
                outbox_row(&database, child_id).await.0,
                "permanently_failed"
            );
        }
    }

    drop(replica_pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fence_recovery_commit_crash_replay_before_and_after_is_deterministic() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[78; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet,
        creator,
        reader,
        adapter,
        peer_marker,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 78).await;
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let base_outbox = OutboxStore::new(database.pool(), crypto.clone());

    let (_, before_id, _) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "crash-before-commit",
    )
    .await;
    let (_, before_result, _) =
        fence_and_emit_exact(&database, &base_outbox, &adapter, before_id).await;
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(before_id)
        .execute(database.pool())
        .await
        .unwrap();
    let before_recovery = base_outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let before_entered = Arc::new(tokio::sync::Notify::new());
    let never_release_before = Arc::new(tokio::sync::Notify::new());
    let before_store = OutboxStore::new(database.pool(), crypto.clone()).with_handoff_fence_seam(
        HandoffFenceSeam {
            before_resolver_commit: Some(Arc::new({
                let entered = before_entered.clone();
                let release = never_release_before.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    Box::pin(async move {
                        entered.notify_one();
                        release.notified().await;
                    })
                }
            })),
            ..HandoffFenceSeam::default()
        },
    );
    let before_task = tokio::spawn({
        let claim = before_recovery.clone();
        async move {
            let no_effects = CountingAdapter {
                sdk_calls: AtomicUsize::new(0),
            };
            process_fence_recovery(&before_store, &no_effects, &claim).await
        }
    });
    before_entered.notified().await;
    before_task.abort();
    assert!(before_task.await.unwrap_err().is_cancelled());
    assert_eq!(outbox_row(&database, before_id).await.0, "handoff_started");
    let before_owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox WHERE creator_id = $1 AND sdk_outbound_message_id = $2",
    )
    .bind(before_recovery.creator_id())
    .bind(before_result.outbound_message_id().to_string())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(before_owner_count, 0, "pre-commit cancellation rolls back");
    let no_effects = CountingAdapter {
        sdk_calls: AtomicUsize::new(0),
    };
    assert!(
        process_fence_recovery(&base_outbox, &no_effects, &before_recovery)
            .await
            .unwrap()
    );
    assert_eq!(no_effects.sdk_calls.load(Ordering::SeqCst), 0);

    let (_, after_id, _) = create_fixed_linked_invoice(
        &invoices,
        &creator,
        &reader,
        &peer_marker,
        "crash-after-commit",
    )
    .await;
    let (_, after_result, _) =
        fence_and_emit_exact(&database, &base_outbox, &adapter, after_id).await;
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(after_id)
        .execute(database.pool())
        .await
        .unwrap();
    let after_recovery = base_outbox
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    let after_entered = Arc::new(tokio::sync::Notify::new());
    let never_release_after = Arc::new(tokio::sync::Notify::new());
    let after_store =
        OutboxStore::new(database.pool(), crypto).with_handoff_fence_seam(HandoffFenceSeam {
            after_resolver_commit: Some(Arc::new({
                let entered = after_entered.clone();
                let release = never_release_after.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    Box::pin(async move {
                        entered.notify_one();
                        release.notified().await;
                    })
                }
            })),
            ..HandoffFenceSeam::default()
        });
    let after_task = tokio::spawn({
        let claim = after_recovery.clone();
        async move {
            let no_effects = CountingAdapter {
                sdk_calls: AtomicUsize::new(0),
            };
            process_fence_recovery(&after_store, &no_effects, &claim).await
        }
    });
    after_entered.notified().await;
    after_task.abort();
    assert!(after_task.await.unwrap_err().is_cancelled());
    assert_eq!(outbox_row(&database, after_id).await.0, "handed_off");
    assert!(
        !process_fence_recovery(&base_outbox, &no_effects, &after_recovery)
            .await
            .unwrap(),
        "post-commit cancellation replays as a no-op"
    );
    for (id, result) in [(before_id, before_result), (after_id, after_result)] {
        let owner_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM outbox WHERE creator_id = $1 \
             AND sdk_outbound_message_id = $2",
        )
        .bind(after_recovery.creator_id())
        .bind(result.outbound_message_id().to_string())
        .fetch_one(database.pool())
        .await
        .unwrap();
        assert_eq!(owner_count, 1);
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1")
                .bind(id)
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(events, 0);
    }

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_sdk_payment_request_retry_persists_distinct_ids_and_only_active_claim_associates() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[11; 32]).unwrap());
    let LinkedPaykitFixture {
        _testnet: testnet,
        creator,
        reader,
        creator_sdk,
        peer_public_key,
        peer_receiver_path,
        ..
    } = linked_paykit_fixture(&database, crypto.clone(), 21).await;
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
            peer_public_key.clone(),
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
        .propose_payment_request(peer_public_key, peer_receiver_path, terms)
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
async fn terminal_acknowledgement_clears_unacknowledged_alert_values() {
    use paykit_server::metrics::{terminal_alert_critical, terminal_alert_warning};

    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[71; 32]).unwrap());
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
    // Age the two retained events deterministically: the parent's oldest
    // unacknowledged age crosses the fifteen-minute critical leg; the
    // child's does not.
    sqlx::query(
        "UPDATE outbox_terminal_events SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE outbox_id = $1",
    )
    .bind(endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE outbox_terminal_events SET created_at = NOW() - INTERVAL '5 minutes' \
         WHERE outbox_id = $1",
    )
    .bind(request_id)
    .execute(database.pool())
    .await
    .unwrap();

    let runtime = health_runtime(database.pool());
    let app = operational_router(Router::new(), runtime.clone());
    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["outbox_terminal_failure_count"], 2);
    let oldest_before = ready["outbox_oldest_terminal_failure_age_seconds"]
        .as_i64()
        .expect("two unacknowledged events must report an oldest age");
    assert!(oldest_before >= 15 * 60, "oldest age: {oldest_before}");
    // The pinned alert contract, evaluated on the exported values: warning
    // and critical both fire.
    let metrics_before = metrics_text(&app).await;
    assert!(
        metrics_before
            .contains("paykit_outbox_terminal_transitions_total{class=\"link_establishment_exhausted\",reason=\"attempt_ceiling\"} 1"),
        "metrics: {metrics_before}"
    );
    assert!(
        metrics_before
            .contains("paykit_outbox_terminal_transitions_total{class=\"dependency_failed\",reason=\"parent_link_establishment_exhausted\"} 1"),
        "metrics: {metrics_before}"
    );
    let transitions_in_window = 2;
    assert!(terminal_alert_warning(transitions_in_window));
    assert!(terminal_alert_critical(
        Some(oldest_before),
        transitions_in_window
    ));

    // The exact documented operator acknowledgement statement
    // (docs/outbox-terminal-acknowledgement.md) clears the oldest event.
    let parent_event: Uuid =
        sqlx::query_scalar("SELECT id FROM outbox_terminal_events WHERE outbox_id = $1")
            .bind(endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    let acknowledged = sqlx::query(
        "UPDATE outbox_terminal_events
         SET acknowledged_at = NOW(),
             acknowledged_by = $1
         WHERE id = $2
           AND acknowledged_at IS NULL",
    )
    .bind("deployment-operator")
    .bind(parent_event)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(acknowledged.rows_affected(), 1);
    let replayed = sqlx::query(
        "UPDATE outbox_terminal_events
         SET acknowledged_at = NOW(),
             acknowledged_by = $1
         WHERE id = $2
           AND acknowledged_at IS NULL",
    )
    .bind("deployment-operator")
    .bind(parent_event)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(replayed.rows_affected(), 0, "acknowledgement is idempotent");

    publish_outbox_health(&outbox, &runtime).await;
    let (status, ready) = ready_json(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["outbox_terminal_failure_count"], 1);
    assert_eq!(
        ready["outbox_terminal_failures_by_class"]["dependency_failed"],
        1
    );
    assert!(
        ready["outbox_terminal_failures_by_class"]
            .get("link_establishment_exhausted")
            .is_none(),
        "acknowledged classes leave the unacknowledged breakdown: {ready}"
    );
    let oldest_after = ready["outbox_oldest_terminal_failure_age_seconds"]
        .as_i64()
        .expect("one unacknowledged event remains");
    assert!(oldest_after < 15 * 60, "oldest age: {oldest_after}");
    // On the computed values the warning still fires (transitions are
    // monotonic) while the critical signal has cleared.
    assert!(terminal_alert_warning(transitions_in_window));
    assert!(!terminal_alert_critical(
        Some(oldest_after),
        transitions_in_window
    ));
    let metrics_after = metrics_text(&app).await;
    assert!(
        metrics_after.contains("paykit_outbox_terminal_failure_count 1"),
        "metrics: {metrics_after}"
    );
    assert!(
        metrics_after
            .contains("paykit_outbox_terminal_transitions_total{class=\"link_establishment_exhausted\",reason=\"attempt_ceiling\"} 1"),
        "acknowledgement never rewinds the monotonic counter: {metrics_after}"
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
    // Fairness telemetry before the pass: exactly one flooded reader
    // partition (five due rows, one admissible per pass) and no active
    // partition leases.
    let metrics = paykit_server::metrics::Metrics::new();
    paykit_server::workers::outbox::publish_claim_fairness_metrics(&outbox, &metrics)
        .await
        .unwrap();
    let encoded = metrics.encode().unwrap();
    assert!(
        encoded.contains("paykit_outbox_reader_saturated_total 1"),
        "metrics: {encoded}"
    );
    assert!(
        encoded.contains("paykit_outbox_active_partitions 0"),
        "metrics: {encoded}"
    );

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

    // After the pass, both partitions hold an unexpired lease and the
    // flooded partition is still flooded (four due rows, zero admissible
    // while leased), so the monotonic counter advances by one again.
    paykit_server::workers::outbox::publish_claim_fairness_metrics(&outbox, &metrics)
        .await
        .unwrap();
    let encoded = metrics.encode().unwrap();
    assert!(
        encoded.contains("paykit_outbox_reader_saturated_total 2"),
        "metrics: {encoded}"
    );
    assert!(
        encoded.contains("paykit_outbox_active_partitions 2"),
        "metrics: {encoded}"
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

/// Recovery has its own durable ceiling: ordinary attempt accounting does not
/// move while twenty recovery claims are issued, attempt 20 terminalizes at
/// retry instead of scheduling another lease, and a fresh store cannot issue
/// claim 21. A separate row proves claim 19 below the DB-time boundary and
/// exact 3600-second terminalization before another claim.
#[tokio::test]
async fn recovery_ceiling_enforces_count_time_restart_and_event_cardinality() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[91; 32]).unwrap());
    let (_, _, _, _, endpoint_id, request_id) =
        create_activated_invoice(&database, crypto.clone(), "000G40R40M30E209185GR38E1W").await;
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let initial = outbox
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(outbox.begin_handoff(&initial).await.unwrap());
    assert!(
        outbox
            .mark_handoff_invocation_started(&initial)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(endpoint_id)
        .execute(database.pool())
        .await
        .unwrap();
    for attempt in 1..=20 {
        let claim = outbox
            .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .pop()
            .expect("recovery claim before ceiling");
        assert_eq!(claim.id(), endpoint_id);
        assert!(
            outbox
                .retry_fence_recovery(&claim, Duration::from_secs(0))
                .await
                .unwrap()
        );
        if attempt == 20 {
            let immediate: (String, Option<time::OffsetDateTime>) =
                sqlx::query_as("SELECT status, lease_expires_at FROM outbox WHERE id = $1")
                    .bind(endpoint_id)
                    .fetch_one(database.pool())
                    .await
                    .unwrap();
            assert_eq!(
                immediate,
                ("permanently_failed".into(), None),
                "attempt 20 must terminalize atomically in retry_fence_recovery"
            );
        }
        if attempt < 20 {
            sqlx::query(
                "UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
            )
            .bind(endpoint_id)
            .execute(database.pool())
            .await
            .unwrap();
        }
    }
    let restarted = OutboxStore::new(database.pool(), crypto);
    assert!(
        restarted
            .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    let row: (
        String,
        i32,
        i32,
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT status, attempt_count, recovery_attempts, recovery_first_at, recovery_last_at, \
         lease_expires_at FROM outbox WHERE id = $1",
    )
    .bind(endpoint_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(row.0, "permanently_failed");
    assert_eq!(row.1, 1, "recovery never changes ordinary attempt_count");
    assert_eq!(row.2, 20);
    assert!(row.3.is_some() && row.4.is_some());
    assert!(row.5.is_none(), "attempt 20 cannot schedule another lease");
    assert_eq!(
        outbox_row(&database, request_id).await.0,
        "permanently_failed"
    );
    let count_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1 \
         AND event_class = 'handoff_unresolved' \
         AND reason = 'sdk_recovery_infrastructure_unavailable'",
    )
    .bind(endpoint_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(count_events, 1);
    assert!(
        restarted
            .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "the exhausted parent never admits its child"
    );

    let time_reader = distinct_readers().into_iter().nth(1).unwrap();
    let (time_endpoint_id, time_request_id) = create_activated_invoice_for(
        &database,
        Arc::new(Crypto::from_master_key(&[91; 32]).unwrap()),
        &time_reader,
        "recovery-time-boundary",
    )
    .await;
    let time_claim = restarted
        .claim(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(time_claim.id(), time_endpoint_id);
    assert!(restarted.begin_handoff(&time_claim).await.unwrap());
    assert!(
        restarted
            .mark_handoff_invocation_started(&time_claim)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE outbox SET attempt_count = 77, recovery_attempts = 18, \
         recovery_first_at = NOW() - INTERVAL '3599 seconds', \
         recovery_last_at = NOW() - INTERVAL '1 second', \
         lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(time_endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    let recovery_19 = restarted
        .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
        .await
        .unwrap()
        .pop()
        .expect("claim 19 remains eligible below 3600 seconds");
    assert!(
        restarted
            .retry_fence_recovery(&recovery_19, Duration::ZERO)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE outbox SET recovery_first_at = NOW() - INTERVAL '3600 seconds', \
         lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(time_endpoint_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        restarted
            .claim_fence_recovery(Uuid::new_v4(), 1, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "exactly 3600 seconds terminalizes before a new claim"
    );
    let time_row: (String, i32, i32) =
        sqlx::query_as("SELECT status, attempt_count, recovery_attempts FROM outbox WHERE id = $1")
            .bind(time_endpoint_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(time_row, ("permanently_failed".into(), 77, 19));
    assert_eq!(
        outbox_row(&database, time_request_id).await.0,
        "permanently_failed"
    );
    let time_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_terminal_events WHERE outbox_id = $1 \
         AND reason = 'sdk_recovery_infrastructure_unavailable'",
    )
    .bind(time_endpoint_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(time_events, 1);
    database.cleanup().await;
}
