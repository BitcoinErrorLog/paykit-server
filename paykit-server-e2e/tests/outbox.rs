use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use async_trait::async_trait;
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
    application::semantic_intent::DeliveryOperationV1,
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, OutboxStore, PersistenceError,
        PostgresStorageAdapter, SdkStateStore, run_migrations,
    },
    workers::outbox::{
        Adapter, HandoffError, HandoffResult, process_claim, process_reconciliation,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
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

    async fn cancel_payment_request(
        &self,
        _reader: &str,
        _path: &str,
        _payment_request_id: &str,
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
    sqlx::query("DELETE FROM outbox WHERE id = $1")
        .bind(row_id)
        .execute(database.pool())
        .await
        .unwrap();
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
            lock_resource_binding: b"outbox-lock",
            payment_request_binding: b"outbox-payment-request",
            new_reader_payloads: &payloads,
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            payment_in_hours: 24,
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
            lock_resource_binding: b"public-sdk-crash-window-lock",
            payment_request_binding: b"public-sdk-crash-window-request",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
            },
            payment_request_intent: common::payment_intent(&reader),
            required_sats: 100,
            payment_in_hours: 24,
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
        DeliveryOperationV1::PaymentRequestCancellation { .. } => {
            panic!("claimed cancellation row")
        }
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
        HandoffResult::EndpointPublication { .. }
        | HandoffResult::PaymentRequestCancellation { .. } => unreachable!(),
    };
    let (second_outbound, second_event, second_request) = match &second_result {
        HandoffResult::PaymentRequestProposal {
            outbound_message_id,
            event_id,
            payment_request_id,
        } => (*outbound_message_id, event_id, payment_request_id),
        HandoffResult::EndpointPublication { .. }
        | HandoffResult::PaymentRequestCancellation { .. } => unreachable!(),
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
