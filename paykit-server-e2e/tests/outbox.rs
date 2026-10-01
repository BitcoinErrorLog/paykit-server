use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use paykit_lib::{
    PaykitAppRegistry, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, OutboundPrivateMessageStatus, PaykitIdentitySecretKey, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionBootstrap, StorageAdapter,
};
use paykit_server::{
    config::{PaykitConfig, PaykitNetwork},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    paykit::{CreatorSessions, PaykitAdapter},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, OutboxStore, PersistenceError, run_migrations,
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

impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("outbox-test-address-{child_index}");
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(&self.reader, address.clone()),
            bitcoin_address: address,
        })
    }
}

struct ReconciliationAdapter {
    statuses: Mutex<VecDeque<OutboundPrivateMessageStatus>>,
}

#[async_trait]
impl Adapter for ReconciliationAdapter {
    async fn fetch_registry(
        &self,
        _reader: &str,
    ) -> Result<Option<PaykitAppRegistry>, HandoffError> {
        Ok(None)
    }

    async fn observe_recovery_marker(&self, _reader: &str) -> Result<(), HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn ensure_link_with_peer(&self, _reader: &str) -> Result<(), HandoffError> {
        Err(HandoffError::Permanent)
    }

    async fn propose_payment_request(
        &self,
        _reader: &str,
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
    sdk_status: Option<OutboundPrivateMessageStatus>,
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
        statuses: Mutex::new(sdk_status.into_iter().collect()),
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
async fn invoice_request_is_claimable_directly_and_preserves_delivery_fences() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = creator();
    let reader = reader();
    CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            "session-secret".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            "xpub-secret".into(),
            0,
        ))
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
            invoice_payloads: &payloads,
            required_sats: 100,
        })
        .await
        .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto);

    let request_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(request_claims.len(), 1);
    assert_eq!(request_claims[0].id(), invoice.payment_request_outbox_id());
    assert_eq!(
        outbox
            .delivery_intent(&request_claims[0])
            .unwrap()
            .terms()
            .payment_endpoints
            .len(),
        1
    );
    let retry_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::new()),
    };
    assert!(
        process_claim(
            &outbox,
            &retry_adapter,
            &request_claims[0],
            Duration::from_secs(5),
        )
        .await
        .unwrap()
    );
    let retry_state: (String, bool, Option<String>) = sqlx::query_as(
        "SELECT status, next_attempt_at > NOW(), error_class FROM outbox WHERE id = $1",
    )
    .bind(request_claims[0].id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        retry_state,
        ("retryable".into(), true, Some("registry_missing".into()))
    );
    sqlx::query("UPDATE outbox SET next_attempt_at = NOW() WHERE id = $1")
        .bind(request_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let request_claims = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(request_claims.len(), 1);
    sqlx::query("UPDATE outbox SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(request_claims[0].id())
        .execute(database.pool())
        .await
        .unwrap();
    let reclaimed_request = outbox
        .claim(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reclaimed_request.len(), 1);
    assert!(
        !outbox
            .mark_handed_off(
                &request_claims[0],
                &HandoffResult {
                    outbound_message_id: 16,
                    event_id: "event-16".into(),
                    payment_request_id: "request-16".into(),
                },
            )
            .await
            .unwrap(),
        "an expired fence overwrote reclaimed work"
    );
    assert!(
        outbox
            .mark_handed_off(
                &reclaimed_request[0],
                &HandoffResult {
                    outbound_message_id: 17,
                    event_id: "event-17".into(),
                    payment_request_id: "request-17".into(),
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
        "handed-off work must not be enqueued again"
    );
    let reconciliation = outbox
        .claim_reconciliation(Uuid::new_v4(), 10, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(reconciliation.len(), 1);
    assert_eq!(reconciliation[0].sdk_outbound_message_id().unwrap(), 17);
    let reconciliation_adapter = ReconciliationAdapter {
        statuses: Mutex::new(VecDeque::from([OutboundPrivateMessageStatus::Pending])),
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
        "Pending SDK state caused another enqueue"
    );
    let payment_claims = reclaimed_request;
    assert_eq!(payment_claims.len(), 1);
    assert_eq!(payment_claims[0].id(), invoice.payment_request_outbox_id());
    assert_eq!(
        outbox
            .delivery_intent(&payment_claims[0])
            .unwrap()
            .terms()
            .payment_endpoints
            .len(),
        1
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
            "17".into(),
            Some("event-17".into()),
            Some("request-17".into())
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
            Some(status),
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
            Some(status),
            "permanently_failed",
            "permanent_sdk_reconciliation",
        )
        .await;
    }

    assert_reconciliation_status(
        &database,
        &outbox,
        300,
        None,
        "permanently_failed",
        "permanent_sdk_reconciliation",
    )
    .await;

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
    let bootstrap =
        PubkySessionBootstrap::with_pubky(testnet.sdk().unwrap(), "app.paykit.server").unwrap();

    let creator_keypair = Keypair::random();
    let creator_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator_session_secret = creator_bootstrap
        .export_session_secret()
        .await
        .unwrap()
        .into_inner();
    let creator = parse_creator(&format!("pubky{}", creator_bootstrap.public_key)).unwrap();
    let creator_record = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            creator_session_secret,
            PubkyLocalSecretKey::new(creator_keypair.secret_key())
                .derive_paykit_identity_secret_key(1)
                .unwrap(),
            "unused-test-xpub".into(),
            0,
        ))
        .await
        .unwrap();
    let creator_sdk =
        sdk_fixtures::hosted_sdk(creator_bootstrap.access.clone(), "paykit-server", 0).await;

    let peer_keypair = Keypair::random();
    let peer_bootstrap = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(peer_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let peer_sdk = sdk_fixtures::hosted_sdk(peer_bootstrap.access.clone(), "bitkit", 0).await;

    creator_sdk
        .initiate_link_with_peer(peer_bootstrap.public_key.clone())
        .await
        .unwrap();
    peer_sdk
        .accept_link_with_peer(creator_bootstrap.public_key.clone())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_link = LinkedPeerState::Linking;
    let mut peer_link = LinkedPeerState::Linking;
    while creator_link != LinkedPeerState::Linked || peer_link != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_link != LinkedPeerState::Linked {
            creator_link = creator_sdk
                .advance_link_handshake(peer_bootstrap.public_key.clone())
                .await
                .unwrap()
                .state;
        }
        if peer_link != LinkedPeerState::Linked {
            peer_link = peer_sdk
                .advance_link_handshake(creator_bootstrap.public_key.clone())
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
            invoice_payloads: &Payloads {
                reader: reader.clone(),
            },
            required_sats: 100,
        })
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
    let terms = intent.terms();
    let terms = PaymentRequestTerms::builder(
        PaymentAmount::new(terms.amount.clone(), terms.asset.clone()).unwrap(),
        PaymentReference::new(terms.payment_reference.clone()).unwrap(),
        terms
            .accepted_endpoint_identifiers
            .iter()
            .cloned()
            .map(PaymentEndpointIdentifier::new)
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .required_app_id(Some(common::app_id()))
    .payment_endpoints(Some(
        terms
            .payment_endpoints
            .iter()
            .map(|(identifier, payload)| {
                (
                    PaymentEndpointIdentifier::new(identifier.clone()).unwrap(),
                    PaymentEndpointPayload::new(payload.clone()),
                )
            })
            .collect(),
    ))
    .proposal_expires_at(terms.proposal_expires_at.clone())
    .metadata(terms.metadata.clone())
    .build()
    .unwrap();

    let first = creator_sdk
        .propose_payment_request(peer_bootstrap.public_key.clone(), terms.clone())
        .await
        .unwrap();
    let first_result = HandoffResult {
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
        .propose_payment_request(peer_bootstrap.public_key.clone(), terms)
        .await
        .unwrap();
    let second_result = HandoffResult {
        outbound_message_id: second.proposal_outbound_message_id.unwrap(),
        event_id: second.proposal_event_id.unwrap(),
        payment_request_id: second.payment_request_id,
    };

    let (first_outbound, first_event, first_request) = (
        first_result.outbound_message_id,
        &first_result.event_id,
        &first_result.payment_request_id,
    );
    let (second_outbound, second_event, second_request) = (
        second_result.outbound_message_id,
        &second_result.event_id,
        &second_result.payment_request_id,
    );
    assert_ne!(first_outbound, second_outbound);
    assert_ne!(first_event, second_event);
    assert_ne!(first_request, second_request);

    let durable_state = creator_sdk.export_backup_state().await.unwrap();
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
        assert!(
            outbound.raw_json.len() <= paykit_lib::pubky_noise::snow_crypto::PUBKY_NOISE_MSG_LEN
        );
        let wire: serde_json::Value = serde_json::from_str(&outbound.raw_json).unwrap();
        assert!(wire.to_string().contains("payment_endpoints"));
    }

    let old_list = creator_sdk
        .enqueue_private_payment_list_with_receiving_details(
            peer_bootstrap.public_key.clone(),
            vec![paykit_sdk::PrivateReceivingDetail {
                identifier: "btc-bitcoin-p2wpkh".into(),
                payload: serde_json::json!({"value": "unrelated-old-address"}).to_string(),
            }],
        )
        .await
        .unwrap();
    creator_sdk
        .enqueue_private_payment_list_with_receiving_details(
            peer_bootstrap.public_key.clone(),
            vec![paykit_sdk::PrivateReceivingDetail {
                identifier: "btc-bitcoin-p2wpkh".into(),
                payload: serde_json::json!({"value": "unrelated-new-address"}).to_string(),
            }],
        )
        .await
        .unwrap();
    // A stored linked peer may no longer publish an App Registry. Its intake
    // failure must degrade maintenance without blocking the healthy peer's sends.
    let missing_registry_peer = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let config = PaykitConfig {
        client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
        app_id: common::app_id(),
        network: PaykitNetwork::Testnet,
    };
    let sessions = CreatorSessions::new(creators.clone(), testnet.sdk().unwrap(), config.clone());
    let provider = sessions.provider(&creator);
    let storage = paykit_sdk::PubkySharedStateStorage::new(provider.clone());
    let adapter = PaykitAdapter::new(creator_record.id(), provider.clone(), &config).unwrap();
    let lease = storage
        .transaction(|tx| {
            let now = sqlx::types::chrono::Utc::now();
            Ok(tx
                .claim_peer_link_operation(
                    &peer_bootstrap.public_key,
                    now,
                    now + Duration::from_secs(60),
                )?
                .unwrap())
        })
        .await
        .unwrap();
    assert!(
        adapter
            .maintain_transport()
            .await
            .unwrap_err()
            .is_concurrent_update()
    );
    storage
        .transaction(|tx| {
            assert_eq!(
                tx.peer_link_operation_lease(&peer_bootstrap.public_key),
                Some(lease.clone())
            );
            let outbound = tx.outbound_private_messages(&peer_bootstrap.public_key);
            for outbound_id in [first_outbound, second_outbound] {
                assert_eq!(
                    outbound
                        .iter()
                        .find(|record| record.outbound_message_id == outbound_id)
                        .unwrap()
                        .status,
                    OutboundPrivateMessageStatus::Pending
                );
            }
            tx.release_peer_link_operation(&peer_bootstrap.public_key, lease.lease_id);
            Ok(())
        })
        .await
        .unwrap();
    storage
        .transaction(|tx| {
            let mut linked_peer = tx.linked_peer(&peer_bootstrap.public_key).unwrap();
            linked_peer.counterparty = missing_registry_peer.public_key.clone();
            tx.save_linked_peer(linked_peer);
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        adapter.maintain_transport().await,
        Err(paykit_sdk::PaykitSdkError::Transport { .. })
    ));
    // Use the process-shared provider after it restores the stored grant.
    let creator_sdk = paykit_sdk::PaykitSdk::new(
        storage,
        provider,
        sdk_fixtures::TestPaymentAdapter,
        paykit_sdk::PaykitSdkConfig::new("paykit-server").unwrap(),
    );
    let compacted = creator_sdk.export_backup_state().await.unwrap();
    assert!(
        !compacted
            .outbound_private_messages
            .iter()
            .any(|record| record.outbound_message_id == old_list.outbound_message_id)
    );
    for outbound_id in [first_outbound, second_outbound] {
        assert!(
            compacted
                .outbound_private_messages
                .iter()
                .any(|record| record.outbound_message_id == outbound_id
                    && record.status == OutboundPrivateMessageStatus::Sent)
        );
    }
    peer_sdk
        .receive_private_messages(creator_bootstrap.public_key.clone())
        .await
        .unwrap();
    let received = peer_sdk
        .actionable_received_payment_requests()
        .await
        .unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(
        received[0].terms, received[1].terms,
        "ambiguous replay preserves all terms"
    );
    for request in received {
        let resolution = peer_sdk
            .resolve_private_payment_request(
                creator_bootstrap.public_key.clone(),
                &paykit_lib::PaymentRequestId::new(request.payment_request_id).unwrap(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            resolution.status,
            paykit_sdk::PrivatePaymentResolutionStatus::Payable
        );
        assert_eq!(resolution.private_payment_list_version, None);
        assert_eq!(
            resolution.payable_endpoints[0].target.payload,
            intent.terms().payment_endpoints["btc-bitcoin-p2wpkh"]
        );
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
