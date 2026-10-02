use std::{sync::Arc, time::Duration};

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentDeadline, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    LinkedPeerState, PAYKIT_SESSION_CAPABILITIES, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionAccess, PubkySessionBootstrap, PubkySharedStateStorage,
};
use paykit_server::{
    application::semantic_intent::{DeliveryIntentV1, DeliveryOperationV1, PaymentTermsV1},
    config::{PaykitConfig, PaykitNetwork},
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext},
    domain::{
        locks::{
            PubkyLockResource, parse_addressed_lock_resource, parse_bundle_id, parse_creator,
            parse_reader,
        },
        payment_request_lifecycle::{
            PaymentRequestLifecycleProjection, PaymentRequestLifecycleState, ProposalCorrelation,
        },
    },
    paykit::{CreatorSessionProvider, PaykitAdapter},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, OutboxStore, PaymentDrainStore,
        PaymentRequestLifecycleApply, PaymentRequestLifecycleStore, PersistenceError,
        run_migrations,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky::ClientId;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use sqlx::Row;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const READER: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";

fn lock_resource() -> PubkyLockResource {
    parse_addressed_lock_resource(LOCK_RESOURCE).unwrap()
}

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap()
}

async fn shared_hosted_sdk(access: PubkySessionAccess, app_id: &str) -> sdk_fixtures::HostedSdk {
    let provider = sdk_fixtures::TestSessionProvider::new(access);
    let sdk = PaykitSdk::new(
        PubkySharedStateStorage::new(provider.clone()),
        provider,
        sdk_fixtures::TestPaymentAdapter,
        PaykitSdkConfig::new(app_id).unwrap(),
    );
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_app(
        paykit_lib::PaykitApp::new(
            "Test App",
            paykit_lib::PaykitAppCapabilities {
                private_payments: true,
                payment_requests: true,
                receipts: true,
                outgoing_payments: true,
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    sdk
}

fn proposal_intent(receiver_path: &str) -> DeliveryIntentV1 {
    proposal_intent_for_reference(
        receiver_path,
        &Uuid::new_v4().hyphenated().to_string(),
        "payload",
    )
}

fn proposal_intent_for_reference(
    receiver_path: &str,
    payment_reference: &str,
    endpoint_payload: &str,
) -> DeliveryIntentV1 {
    let _ = receiver_path;
    let app_id = PaykitAppId::new("paykit-server").unwrap();
    DeliveryIntentV1::payment_request(
        READER.into(),
        app_id.clone(),
        &PaymentRequestTerms::builder(
            PaymentAmount::new("0.00001000", "BTC").unwrap(),
            PaymentReference::new(payment_reference.to_owned()).unwrap(),
            vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
        )
        .proposal_expires_at(Some("2027-01-15T08:00:00Z".into()))
        .payment_deadline(Some(PaymentDeadline::At {
            timestamp: "2027-01-16T08:00:00Z".into(),
        }))
        .required_app_id(Some(app_id))
        .payment_endpoints(Some(HashMap::from([(
            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            PaymentEndpointPayload::new(endpoint_payload),
        )])))
        .build()
        .unwrap(),
    )
    .unwrap()
}

struct RacePayloads;

impl InvoicePayloadFactory for RacePayloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("race-address-{child_index}");
        Ok(InvoicePayloads {
            payment_request_intent: proposal_intent_for_reference(
                "new/wallet",
                "00000000-0000-4000-8000-000000000001",
                &serde_json::json!({ "value": address }).to_string(),
            ),
            bitcoin_address: address,
        })
    }
}

static RACE_PAYLOADS: RacePayloads = RacePayloads;

fn admission_input<'a>(
    creator: &'a paykit_server::domain::locks::CreatorPubky,
    reader: &'a paykit_server::domain::locks::ReaderPubky,
) -> AtomicInvoiceInput<'a> {
    AtomicInvoiceInput {
        creator,
        reader,
        bundle_binding: b"concurrent-admission-bundle",
        lock_resource_binding: LOCK_RESOURCE.as_bytes(),
        payment_request_binding: b"concurrent-admission-request",
        invoice_payloads: &RACE_PAYLOADS,
        required_sats: 1_000,
        proposal_acceptance_seconds: 60 * 60,
        payment_window_seconds: 24 * 60 * 60,
    }
}

async fn wait_for_lock_wait(database: &TestDatabase, query_fragment: &str) {
    let pattern = format!("%{query_fragment}%");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity
                 WHERE datname = current_database()
                   AND wait_event_type = 'Lock'
                   AND query LIKE $1",
            )
            .bind(&pattern)
            .fetch_one(database.pool())
            .await
            .unwrap();
            if blocked > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("expected query containing {query_fragment:?} to wait on a lock"));
}

async fn insert_invoice(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
    lock_resource_generation: i64,
    state: PaymentRequestLifecycleState,
) -> (Uuid, String) {
    insert_invoice_with_receiver_path(
        database,
        crypto,
        creator_id,
        ordinal,
        lock_resource_generation,
        state,
        "bitkit/wallet",
    )
    .await
}

async fn insert_invoice_with_receiver_path(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    ordinal: u8,
    lock_resource_generation: i64,
    state: PaymentRequestLifecycleState,
    receiver_path: &str,
) -> (Uuid, String) {
    let invoice_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let request_id = Uuid::new_v4().to_string();
    let event_id = Uuid::new_v4().to_string();
    let creator_hash = crypto.lookup_hash(CREATOR.as_bytes());
    let intent = proposal_intent(receiver_path);
    let plaintext = postcard::to_allocvec(&intent).unwrap();
    let envelope = crypto
        .encrypt(
            &EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id),
            &plaintext,
        )
        .unwrap();
    let hash = |label: &str| {
        crypto
            .lookup_hash(format!("{label}-{ordinal}").as_bytes())
            .as_bytes()
            .to_vec()
    };
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();

    sqlx::query(
        "INSERT INTO invoices (
             id, creator_id, reader_lookup_hash, bundle_lookup_hash,
             lock_resource_lookup_hash, lock_resource_generation,
             payment_request_lookup_hash,
             invoice_envelope, payment_record_envelope, bitcoin_address_lookup_hash,
             derivation_index_lookup_hash, payment_status, confirmation_count,
             amount_matched, invoice_created_at, proposal_expires_at, payment_deadline,
             proposal_acceptance_seconds, payment_window_seconds
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                   'undetected', 0, FALSE, $12, $12 + INTERVAL '1 hour', $13,
                   3600, 86400)",
    )
    .bind(invoice_id)
    .bind(creator_id)
    .bind(hash("reader"))
    .bind(hash("bundle"))
    .bind(
        crypto
            .lookup_hash(LOCK_RESOURCE.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .bind(lock_resource_generation)
    .bind(hash("request"))
    .bind(b"encrypted-invoice".as_slice())
    .bind(b"encrypted-payment".as_slice())
    .bind(hash("address"))
    .bind(hash("index"))
    .bind(created_at)
    .bind(created_at + time::Duration::hours(24))
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO outbox (
             id, creator_id, invoice_id, intent_envelope, intent_kind, status,
             sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id,
             proposal_lookup_hash
         ) VALUES ($1, $2, $3, $4, 'payment_request_proposal', 'delivered', $5, $6, $7, $8)",
    )
    .bind(outbox_id)
    .bind(creator_id)
    .bind(invoice_id)
    .bind(envelope.as_bytes())
    .bind(u64::from(ordinal + 1).to_string())
    .bind(&event_id)
    .bind(&request_id)
    .bind(
        crypto
            .payment_request_proposal_lookup_hash(request_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(invoice_id)
    .bind(&request_id)
    .bind(state.as_str())
    .bind(event_id)
    .bind(i64::from(ordinal + 1))
    .bind(i64::from(ordinal + 1))
    .bind(created_at)
    .execute(database.pool())
    .await
    .unwrap();

    (invoice_id, request_id)
}

async fn insert_attempt(
    database: &TestDatabase,
    invoice_id: Uuid,
    ordinal: u8,
    state: PaymentRequestLifecycleState,
) -> String {
    let request_id = Uuid::new_v4().to_string();
    let event_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO payment_request_lifecycles (
             invoice_id, sdk_payment_request_id, request_state, state_event_id,
             last_stream_item_id, last_outbound_message_id, last_event_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(invoice_id)
    .bind(&request_id)
    .bind(state.as_str())
    .bind(event_id)
    .bind(i64::from(ordinal + 1))
    .bind(i64::from(ordinal + 1))
    .bind(OffsetDateTime::from_unix_timestamp(1_800_000_000 + i64::from(ordinal)).unwrap())
    .execute(database.pool())
    .await
    .unwrap();
    request_id
}

async fn insert_projectable_attempt(
    database: &TestDatabase,
    crypto: &Crypto,
    creator_id: Uuid,
    invoice_id: Uuid,
) -> PaymentRequestLifecycleProjection {
    let request_id = Uuid::new_v4().to_string();
    let event_id = Uuid::new_v4().to_string();
    let outbox_id = Uuid::new_v4();
    let intent = proposal_intent_for_reference("new/wallet", &request_id, "payload");
    let plaintext = postcard::to_allocvec(&intent).unwrap();
    let creator_hash = crypto.lookup_hash(CREATOR.as_bytes());
    let envelope = crypto
        .encrypt(
            &EnvelopeContext::outbox_semantic_intent(creator_hash, outbox_id),
            &plaintext,
        )
        .unwrap();
    sqlx::query(
        "INSERT INTO outbox (
             id, creator_id, invoice_id, intent_envelope, intent_kind, status,
             sdk_outbound_message_id, sdk_event_id, sdk_payment_request_id,
             proposal_lookup_hash
         ) VALUES ($1, $2, $3, $4, 'payment_request_proposal', 'delivered', $5, $6, $7, $8)",
    )
    .bind(outbox_id)
    .bind(creator_id)
    .bind(invoice_id)
    .bind(envelope.as_bytes())
    .bind("99")
    .bind(&event_id)
    .bind(&request_id)
    .bind(
        crypto
            .payment_request_proposal_lookup_hash(request_id.as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();

    PaymentRequestLifecycleProjection {
        payment_request_id: request_id.clone(),
        proposal: ProposalCorrelation {
            reader_pubky: READER.into(),
            proposal_app_id: "paykit-server".into(),
            terms: PaymentTermsV1 {
                amount: "0.00001000".into(),
                asset: "BTC".into(),
                payment_reference: request_id,
                proposal_expires_at: Some("2027-01-15T08:00:00Z".into()),
                payment_deadline: Some("2027-01-16T08:00:00Z".into()),
                accepted_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                payment_endpoints: [("btc-bitcoin-p2wpkh".into(), "payload".into())]
                    .into_iter()
                    .collect(),
                metadata: serde_json::Map::new(),
            },
        },
        request_state: PaymentRequestLifecycleState::Proposed,
        state_event_id: Some(event_id),
        last_stream_item_id: Some(99),
        last_outbound_message_id: Some(99),
        last_event_at: OffsetDateTime::from_unix_timestamp(1_800_000_100).unwrap(),
    }
}

#[tokio::test]
async fn current_generation_nonterminal_attempts_are_the_only_required_receive_targets() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[50; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (mixed_invoice, _) = insert_invoice_with_receiver_path(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Rejected,
        "mixed/wallet",
    )
    .await;
    insert_attempt(
        &database,
        mixed_invoice,
        3,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    insert_invoice_with_receiver_path(
        &database,
        &crypto,
        creator_id,
        1,
        0,
        PaymentRequestLifecycleState::Rejected,
        "terminal/wallet",
    )
    .await;
    insert_invoice_with_receiver_path(
        &database,
        &crypto,
        creator_id,
        2,
        1,
        PaymentRequestLifecycleState::Accepted,
        "historical/wallet",
    )
    .await;
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_id)
    .bind(
        crypto
            .lookup_hash(lock_resource().to_string().as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();

    let targets = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone())
        .required_receive_targets_for_lock(creator_id, &lock_resource())
        .await
        .unwrap();

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].counterparty(), READER);
    let sdk_counterparty = PubkyPublicKey::from_raw_or_app_key(targets[0].counterparty()).unwrap();
    assert_eq!(sdk_counterparty.to_app_key(), targets[0].counterparty());

    sqlx::query("UPDATE invoices SET bundle_lookup_hash = $1 WHERE id = $2")
        .bind(crypto.lookup_hash(BUNDLE.as_bytes()).as_bytes().as_slice())
        .bind(mixed_invoice)
        .execute(database.pool())
        .await
        .unwrap();
    let status_targets = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone())
        .required_receive_targets_for_bundle(creator_id, &parse_bundle_id(BUNDLE).unwrap())
        .await
        .unwrap();
    assert_eq!(status_targets, targets);

    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'rejected'
         WHERE invoice_id = $1",
    )
    .bind(mixed_invoice)
    .execute(database.pool())
    .await
    .unwrap();
    assert!(
        PaymentRequestLifecycleStore::new(database.pool(), crypto)
            .required_receive_targets_for_lock(creator_id, &lock_resource())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn missing_required_intake_blocks_drain_snapshot_and_status_lookup() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[49; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (invoice_id, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_id)
    .bind(
        crypto
            .lookup_hash(lock_resource().to_string().as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE invoices SET bundle_lookup_hash = $1 WHERE id = $2")
        .bind(crypto.lookup_hash(BUNDLE.as_bytes()).as_bytes().as_slice())
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();

    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    let drains = PaymentDrainStore::new(database.pool(), crypto.clone());

    let drain_result = drains
        .create_after_receive(&lifecycles, &lock_resource(), &[])
        .await;

    assert_eq!(drain_result, Err(PersistenceError::Unavailable));
    assert!(
        drains
            .exact_replay(&lock_resource())
            .await
            .unwrap()
            .is_none()
    );
    let drain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_drains")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(drain_count, 0);

    let status_result = InvoiceStore::new(database.pool(), crypto)
        .payment_request_status_after_receive(
            &lifecycles,
            &creator,
            &parse_bundle_id(BUNDLE).unwrap(),
            &[],
        )
        .await;
    assert_eq!(status_result, Err(PersistenceError::Unavailable));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_foreign_app_records_do_not_poison_existing_invoice_refresh_or_new_drain() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[51; 32]).unwrap());

    let creator_root = PubkyLocalSecretKey::new(Keypair::random().secret_key());
    let creator_account = bootstrap
        .sign_up(
            &creator_root,
            &homeserver,
            None,
            PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_account.public_key)).unwrap();
    let creators = CreatorStore::new(database.pool(), crypto.clone());
    let creator_row = creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            creator_account
                .export_session_secret()
                .await
                .unwrap()
                .into_inner(),
            creator_root.derive_paykit_identity_secret_key(1).unwrap(),
            "unused-test-xpub".into(),
            0,
        ))
        .await
        .unwrap();
    let creator_sdk =
        sdk_fixtures::hosted_sdk(creator_account.access.clone(), "paykit-server", 0).await;
    let foreign_creator_sdk = shared_hosted_sdk(creator_account.access.clone(), "bitkit").await;

    let payer_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            &homeserver,
            None,
            PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let payer_sdk = sdk_fixtures::hosted_sdk(payer_account.access, "bitkit", 0).await;

    creator_sdk
        .initiate_link_with_peer(payer_account.public_key.clone())
        .await
        .unwrap();
    payer_sdk
        .accept_link_with_peer(creator_account.public_key.clone())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_link = LinkedPeerState::Linking;
    let mut payer_link = LinkedPeerState::Linking;
    while creator_link != LinkedPeerState::Linked || payer_link != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_link != LinkedPeerState::Linked {
            creator_link = creator_sdk
                .advance_link_handshake(payer_account.public_key.clone())
                .await
                .unwrap()
                .state;
        }
        if payer_link != LinkedPeerState::Linked {
            payer_link = payer_sdk
                .advance_link_handshake(creator_account.public_key.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    payer_sdk
        .propose_payment_request(
            creator_account.public_key.clone(),
            PaymentRequestTerms::builder(
                PaymentAmount::new("0.00001000", "BTC").unwrap(),
                PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
            )
            .build()
            .unwrap(),
        )
        .await
        .unwrap();
    payer_sdk
        .process_outbound_private_messages(creator_account.public_key.clone())
        .await
        .unwrap();
    creator_sdk
        .receive_private_messages_from_linked_peers()
        .await
        .unwrap();
    let incoming = creator_sdk
        .actionable_received_payment_requests()
        .await
        .unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(
        incoming[0].local_role,
        Some(paykit_sdk::PaymentRequestLocalRole::Payer)
    );

    let foreign_proposal = foreign_creator_sdk
        .propose_payment_request(
            payer_account.public_key.clone(),
            PaymentRequestTerms::builder(
                PaymentAmount::new("0.00001000", "BTC").unwrap(),
                PaymentReference::new(Uuid::new_v4().to_string()).unwrap(),
                vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
            )
            .build()
            .unwrap(),
        )
        .await
        .unwrap();
    foreign_creator_sdk
        .process_outbound_private_messages(payer_account.public_key.clone())
        .await
        .unwrap();
    payer_sdk
        .receive_private_messages_from_linked_peers()
        .await
        .unwrap();
    let foreign_record = foreign_creator_sdk
        .payment_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.payment_request_id == foreign_proposal.payment_request_id)
        .unwrap();
    assert_eq!(
        foreign_record.local_role,
        Some(paykit_sdk::PaymentRequestLocalRole::Payee)
    );
    assert_eq!(
        foreign_record
            .proposal_app_id
            .as_ref()
            .map(PaykitAppId::as_str),
        Some("bitkit")
    );
    assert!(
        foreign_record
            .terms
            .as_ref()
            .unwrap()
            .payment_endpoints
            .is_none()
    );

    let dynamic_lock = parse_addressed_lock_resource(&format!(
        "{creator}/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json"
    ))
    .unwrap();
    let (invoice_id, _) = insert_invoice(
        &database,
        &crypto,
        creator_row.id(),
        0,
        0,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;
    let lock_hash = crypto.lookup_hash(dynamic_lock.to_string().as_bytes());
    sqlx::query(
        "UPDATE invoices
         SET bundle_lookup_hash = $1, lock_resource_lookup_hash = $2
         WHERE id = $3",
    )
    .bind(crypto.lookup_hash(BUNDLE.as_bytes()).as_bytes().as_slice())
    .bind(lock_hash.as_bytes().as_slice())
    .bind(invoice_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_row.id())
    .bind(lock_hash.as_bytes().as_slice())
    .execute(database.pool())
    .await
    .unwrap();

    let paykit = PaykitConfig {
        client_id: ClientId::new("app.paykit.server").unwrap(),
        app_id: PaykitAppId::new("paykit-server").unwrap(),
        network: PaykitNetwork::Testnet,
        proposal_acceptance_window: Duration::from_secs(60 * 60),
        payment_window: Duration::from_secs(24 * 60 * 60),
    };
    let sessions = CreatorSessionProvider::with_pubky(creators, creator.clone(), pubky, &paykit);
    let adapter = PaykitAdapter::new(creator_row.id(), sessions, &paykit).unwrap();
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    for _ in 0..2 {
        let status = adapter
            .reconcile_and_lookup_payment_request_status(
                &lifecycles,
                &invoices,
                &parse_bundle_id(BUNDLE).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            status.request_state(),
            PaymentRequestLifecycleState::Rejected
        );
    }
    let projected_lifecycle_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_request_lifecycles")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(projected_lifecycle_count, 1);

    let drain = adapter
        .reconcile_and_create_payment_drain(
            &lifecycles,
            &PaymentDrainStore::new(database.pool(), crypto),
            &dynamic_lock,
        )
        .await
        .unwrap();
    assert!(drain.completed());
    assert_eq!(drain.accepted_count(), 0);
    assert_eq!(drain.terminal_count(), 1);
    assert_eq!(drain.cancellation_enqueued_count(), 0);

    drop(testnet);
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_invoice_admission_precedes_drain_freshness_decision() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[48; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_id)
    .bind(
        crypto
            .lookup_hash(lock_resource().to_string().as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    let stale_evidence = lifecycles
        .required_receive_targets_for_lock(creator_id, &lock_resource())
        .await
        .unwrap();
    assert!(stale_evidence.is_empty());

    let lock_hash = crypto.lookup_hash(lock_resource().to_string().as_bytes());
    let mut generation_blocker = database.pool().begin().await.unwrap();
    sqlx::query(
        "SELECT current_generation FROM lock_payment_generations
         WHERE creator_id = $1 AND lock_resource_lookup_hash = $2
         FOR UPDATE",
    )
    .bind(creator_id)
    .bind(lock_hash.as_bytes().as_slice())
    .fetch_one(&mut *generation_blocker)
    .await
    .unwrap();

    let invoice_store = InvoiceStore::new(database.pool(), crypto.clone());
    let admission = tokio::spawn(async move {
        let creator = parse_creator(CREATOR).unwrap();
        let reader = parse_reader(READER).unwrap();
        invoice_store
            .create_atomic(admission_input(&creator, &reader))
            .await
    });
    wait_for_lock_wait(&database, "lock_payment_generations").await;

    let drains = PaymentDrainStore::new(database.pool(), crypto.clone());
    let competing_drain = tokio::spawn(async move {
        drains
            .create_after_receive(&lifecycles, &lock_resource(), &stale_evidence)
            .await
    });
    wait_for_lock_wait(&database, "FROM creators").await;

    generation_blocker.commit().await.unwrap();
    admission.await.unwrap().unwrap();
    assert_eq!(
        competing_drain.await.unwrap(),
        Err(PersistenceError::Unavailable)
    );
    let drains = PaymentDrainStore::new(database.pool(), crypto);
    assert!(
        drains
            .exact_replay(&lock_resource())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn concurrent_lifecycle_projection_precedes_status_freshness_decision() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[47; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (invoice_id, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_id)
    .bind(
        crypto
            .lookup_hash(lock_resource().to_string().as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE invoices SET bundle_lookup_hash = $1 WHERE id = $2")
        .bind(crypto.lookup_hash(BUNDLE.as_bytes()).as_bytes().as_slice())
        .bind(invoice_id)
        .execute(database.pool())
        .await
        .unwrap();
    let bundle_id = parse_bundle_id(BUNDLE).unwrap();
    let lifecycles = PaymentRequestLifecycleStore::new(database.pool(), crypto.clone());
    let stale_evidence = lifecycles
        .required_receive_targets_for_bundle(creator_id, &bundle_id)
        .await
        .unwrap();
    assert!(stale_evidence.is_empty());

    let projection = insert_projectable_attempt(&database, &crypto, creator_id, invoice_id).await;
    let mut invoice_blocker = database.pool().begin().await.unwrap();
    sqlx::query("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
        .bind(invoice_id)
        .fetch_one(&mut *invoice_blocker)
        .await
        .unwrap();

    let applying_lifecycles = lifecycles.clone();
    let apply =
        tokio::spawn(async move { applying_lifecycles.apply(creator_id, &projection).await });
    wait_for_lock_wait(&database, "AND creator_id = $2").await;

    let status_lifecycles = lifecycles.clone();
    let invoice_store = InvoiceStore::new(database.pool(), crypto);
    let status = tokio::spawn(async move {
        invoice_store
            .payment_request_status_after_receive(
                &status_lifecycles,
                &creator,
                &bundle_id,
                &stale_evidence,
            )
            .await
    });
    wait_for_lock_wait(
        &database,
        "SELECT id FROM invoices WHERE id = $1 FOR UPDATE",
    )
    .await;

    invoice_blocker.commit().await.unwrap();
    assert_eq!(
        apply.await.unwrap(),
        Ok(PaymentRequestLifecycleApply::Applied)
    );
    assert_eq!(status.await.unwrap(), Err(PersistenceError::Unavailable));
}

#[tokio::test]
async fn drain_atomically_freezes_classification_and_cancellation_intent_for_exact_replay() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[51; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (accepted_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Accepted,
    )
    .await;
    let (rejected_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        1,
        0,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;
    let (proposed_invoice, proposed_request_id) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        2,
        0,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    let (canceled_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        3,
        0,
        PaymentRequestLifecycleState::Canceled,
    )
    .await;
    let (expired_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        4,
        0,
        PaymentRequestLifecycleState::ProposalExpired,
    )
    .await;

    let store = PaymentDrainStore::new(database.pool(), crypto.clone());
    let (proposal_outbox_id, proposal_envelope): (Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT id, intent_envelope FROM outbox
         WHERE invoice_id = $1 AND sdk_payment_request_id = $2",
    )
    .bind(proposed_invoice)
    .bind(&proposed_request_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(b"corrupt-cancellation-source".as_slice())
        .bind(proposal_outbox_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.create(&lock_resource()).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let rollback_counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM payment_drains),
           (SELECT COUNT(*) FROM payment_drain_items),
           (SELECT COUNT(*) FROM outbox)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(rollback_counts, (0, 0, 5));
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(proposal_envelope)
        .bind(proposal_outbox_id)
        .execute(database.pool())
        .await
        .unwrap();

    sqlx::query(
        "UPDATE outbox
         SET status = 'retryable', next_attempt_at = transaction_timestamp()
         WHERE id = $1",
    )
    .bind(proposal_outbox_id)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO lock_payment_generations
             (creator_id, lock_resource_lookup_hash, current_generation)
         VALUES ($1, $2, 0)",
    )
    .bind(creator_id)
    .bind(
        crypto
            .lookup_hash(lock_resource().to_string().as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .execute(database.pool())
    .await
    .unwrap();
    let outbox = OutboxStore::new(database.pool(), crypto.clone());
    let claimed_proposals = outbox
        .claim(Uuid::new_v4(), 10, std::time::Duration::from_secs(30))
        .await
        .unwrap();
    let claimed_proposal = claimed_proposals
        .iter()
        .find(|claim| claim.id() == proposal_outbox_id)
        .expect("proposal retry is claimed before drain");

    let lock = lock_resource();
    let (left, right) = tokio::join!(store.create(&lock), store.create(&lock));
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.drain_id(), right.drain_id());
    assert_ne!(left.replayed(), right.replayed());
    let first = if left.replayed() { right } else { left };
    assert!(!first.replayed());
    assert_eq!(first.accepted_count(), 1);
    assert_eq!(first.terminal_count(), 3);
    assert_eq!(first.cancellation_enqueued_count(), 1);
    assert!(!first.completed());
    assert!(
        !outbox
            .claim_handoff_eligible(claimed_proposal)
            .await
            .unwrap()
    );
    let first_token = crypto.payment_drain_cleanup_token(first.drain_id());

    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), first_token.as_bytes())
            .await,
        Err(PersistenceError::Conflict)
    );
    let retained_active_drain: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_drains WHERE id = $1")
            .bind(first.drain_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(retained_active_drain, 1);

    let items: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT invoice_id, classification
         FROM payment_drain_items WHERE drain_id = $1 ORDER BY classification",
    )
    .bind(first.drain_id())
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert!(items.contains(&(accepted_invoice, "accepted".into())));
    assert!(items.contains(&(rejected_invoice, "rejected".into())));
    assert!(items.contains(&(canceled_invoice, "canceled".into())));
    assert!(items.contains(&(expired_invoice, "proposal_expired".into())));
    assert!(items.contains(&(proposed_invoice, "cancellation_enqueued".into())));
    sqlx::query(
        "UPDATE payment_drain_items SET classification = 'canceled'
         WHERE drain_id = $1 AND invoice_id = $2",
    )
    .bind(first.drain_id())
    .bind(rejected_invoice)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store.exact_replay(&lock_resource()).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query(
        "UPDATE payment_drain_items SET classification = 'rejected'
         WHERE drain_id = $1 AND invoice_id = $2",
    )
    .bind(first.drain_id())
    .bind(rejected_invoice)
    .execute(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices SET lock_resource_generation = lock_resource_generation + 1
         WHERE id = $1",
    )
    .bind(rejected_invoice)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store.exact_replay(&lock_resource()).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query(
        "UPDATE invoices SET lock_resource_generation = lock_resource_generation - 1
         WHERE id = $1",
    )
    .bind(rejected_invoice)
    .execute(database.pool())
    .await
    .unwrap();
    let cancellation_outbox_id: Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id
         FROM payment_drain_cancellations
         WHERE drain_id = $1 AND invoice_id = $2 AND sdk_payment_request_id = $3",
    )
    .bind(first.drain_id())
    .bind(proposed_invoice)
    .bind(&proposed_request_id)
    .fetch_one(database.pool())
    .await
    .expect("proposed request has a durable cancellation intent");
    let cancellation_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT intent_envelope FROM outbox WHERE id = $1")
            .bind(cancellation_outbox_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(b"corrupt-frozen-cancellation".as_slice())
        .bind(cancellation_outbox_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store.exact_replay(&lock_resource()).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query("UPDATE outbox SET intent_envelope = $1 WHERE id = $2")
        .bind(cancellation_envelope)
        .bind(cancellation_outbox_id)
        .execute(database.pool())
        .await
        .unwrap();

    sqlx::query(
        "DELETE FROM payment_drain_cancellations
         WHERE drain_id = $1 AND sdk_payment_request_id = $2",
    )
    .bind(first.drain_id())
    .bind(&proposed_request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store.exact_replay(&lock_resource()).await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query(
        "INSERT INTO payment_drain_cancellations
             (drain_id, invoice_id, sdk_payment_request_id, cancellation_outbox_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(first.drain_id())
    .bind(proposed_invoice)
    .bind(&proposed_request_id)
    .bind(cancellation_outbox_id)
    .execute(database.pool())
    .await
    .unwrap();

    let substituted = sqlx::query(
        "UPDATE payment_drain_cancellations
         SET cancellation_outbox_id = $1
         WHERE drain_id = $2 AND sdk_payment_request_id = $3",
    )
    .bind(proposal_outbox_id)
    .bind(first.drain_id())
    .bind(&proposed_request_id)
    .execute(database.pool())
    .await;
    if substituted.is_ok() {
        sqlx::query(
            "UPDATE payment_drain_cancellations
             SET cancellation_outbox_id = $1
             WHERE drain_id = $2 AND sdk_payment_request_id = $3",
        )
        .bind(cancellation_outbox_id)
        .bind(first.drain_id())
        .bind(&proposed_request_id)
        .execute(database.pool())
        .await
        .unwrap();
    }
    assert!(
        substituted.is_err(),
        "database must reject an outbox row that is not the exact cancellation intent"
    );

    let cancellation_row = sqlx::query(
        "SELECT intent_envelope, invoice_id, status
         FROM outbox WHERE id = $1",
    )
    .bind(cancellation_outbox_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        cancellation_row.get::<Option<Uuid>, _>("invoice_id"),
        Some(proposed_invoice)
    );
    assert_eq!(cancellation_row.get::<String, _>("status"), "queued");
    let plaintext = crypto
        .decrypt(
            &EnvelopeContext::outbox_semantic_intent(
                crypto.lookup_hash(CREATOR.as_bytes()),
                cancellation_outbox_id,
            ),
            &EncryptedEnvelope::from_bytes(cancellation_row.get::<Vec<u8>, _>("intent_envelope")),
        )
        .unwrap();
    let cancellation = DeliveryIntentV1::decode(&plaintext).unwrap();
    match cancellation.operation() {
        DeliveryOperationV1::PaymentRequestCancellation { payment_request_id } => {
            assert_eq!(payment_request_id, &proposed_request_id);
        }
        operation => panic!("unexpected cancellation operation: {operation:?}"),
    }

    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'accepted', state_event_id = $1,
             last_stream_item_id = last_stream_item_id + 1,
             last_event_at = last_event_at + INTERVAL '1 second'
         WHERE invoice_id = $2",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(proposed_invoice)
    .execute(database.pool())
    .await
    .unwrap();

    let replay = PaymentDrainStore::new(database.pool(), crypto.clone())
        .create(&lock_resource())
        .await
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.drain_id(), first.drain_id());
    assert_eq!(replay.created_at(), first.created_at());
    assert_eq!(replay.accepted_count(), 1);
    assert_eq!(replay.terminal_count(), 3);
    assert_eq!(replay.cancellation_enqueued_count(), 1);
    let replayed_classifications: Vec<String> = sqlx::query_scalar(
        "SELECT classification FROM payment_drain_items
         WHERE drain_id = $1 ORDER BY classification",
    )
    .bind(first.drain_id())
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(
        replayed_classifications,
        vec![
            "accepted",
            "canceled",
            "cancellation_enqueued",
            "proposal_expired",
            "rejected",
        ]
    );
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(outbox_count, 6);

    sqlx::query(
        "UPDATE payment_drains
         SET accepted_count = 0, terminal_count = 5, status = 'completed',
             completed_at = clock_timestamp()
         WHERE id = $1",
    )
    .bind(first.drain_id())
    .execute(database.pool())
    .await
    .unwrap();
    let cleanup_token = crypto.payment_drain_cleanup_token(first.drain_id());
    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), cleanup_token.as_bytes())
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );

    let debug = format!("{first:?}");
    for forbidden in [
        accepted_invoice.to_string(),
        rejected_invoice.to_string(),
        proposed_invoice.to_string(),
        canceled_invoice.to_string(),
        expired_invoice.to_string(),
        proposed_request_id,
        first.drain_id().to_string(),
    ] {
        assert!(!debug.contains(&forbidden));
    }

    database.cleanup().await;
}

#[tokio::test]
async fn replay_monotonically_completes_accepted_item_after_timely_amount_match() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[55; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (accepted_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Accepted,
    )
    .await;
    let store = PaymentDrainStore::new(database.pool(), crypto);
    let active = store.create(&lock_resource()).await.unwrap();
    assert!(!active.completed());
    assert_eq!(active.accepted_count(), 1);
    assert_eq!(active.terminal_count(), 0);

    sqlx::query(
        "UPDATE invoices
         SET payment_status = 'detected', amount_matched = TRUE,
             first_amount_matched_observed_at = invoice_created_at,
             first_amount_matched_outpoint_lookup_hash = decode(repeat('01', 32), 'hex')
         WHERE id = $1",
    )
    .bind(accepted_invoice)
    .execute(database.pool())
    .await
    .unwrap();

    let completed = store.exact_replay(&lock_resource()).await.unwrap().unwrap();
    assert!(completed.completed());
    assert_eq!(completed.accepted_count(), 0);
    assert_eq!(completed.terminal_count(), 1);
    assert_eq!(completed.cancellation_enqueued_count(), 0);
    assert_eq!(completed.drain_id(), active.drain_id());

    let replay = store.exact_replay(&lock_resource()).await.unwrap().unwrap();
    assert_eq!(replay.accepted_count(), 0);
    assert_eq!(replay.terminal_count(), 1);
    assert!(replay.completed());

    database.cleanup().await;
}

#[tokio::test]
async fn durable_cancellation_enqueue_is_sufficient_for_completion() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[52; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();
    let (historical_proposed, historical_request_id) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    let (historical_rejected, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        1,
        0,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;
    sqlx::query(
        "UPDATE invoices
         SET payment_status = 'detected', amount_matched = TRUE
         WHERE id = $1",
    )
    .bind(historical_rejected)
    .execute(database.pool())
    .await
    .unwrap();

    let store = PaymentDrainStore::new(database.pool(), crypto.clone());
    let drain = store.create(&lock_resource()).await.unwrap();
    assert!(drain.completed());
    assert_eq!(drain.accepted_count(), 0);
    assert_eq!(drain.terminal_count(), 1);
    assert_eq!(drain.cancellation_enqueued_count(), 1);
    let durable: (String, bool) =
        sqlx::query_as("SELECT status, completed_at IS NOT NULL FROM payment_drains WHERE id = $1")
            .bind(drain.drain_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(durable, ("completed".into(), true));

    let replay = store.create(&lock_resource()).await.unwrap();
    assert!(replay.replayed());
    assert!(replay.completed());
    assert_eq!(replay.drain_id(), drain.drain_id());
    let replay_only = store
        .exact_replay(&lock_resource())
        .await
        .unwrap()
        .expect("durable replay exists");
    assert!(replay_only.replayed());
    assert!(replay_only.completed());
    assert_eq!(replay_only.drain_id(), drain.drain_id());
    let drain_token = crypto.payment_drain_cleanup_token(drain.drain_id());

    let cancellation_outbox_id: Uuid = sqlx::query_scalar(
        "SELECT cancellation_outbox_id FROM payment_drain_cancellations
         WHERE drain_id = $1 AND sdk_payment_request_id = $2",
    )
    .bind(drain.drain_id())
    .bind(&historical_request_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "DELETE FROM payment_drain_cancellations
         WHERE drain_id = $1 AND sdk_payment_request_id = $2",
    )
    .bind(drain.drain_id())
    .bind(&historical_request_id)
    .execute(database.pool())
    .await
    .unwrap();
    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), drain_token.as_bytes())
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    sqlx::query(
        "INSERT INTO payment_drain_cancellations
             (drain_id, invoice_id, sdk_payment_request_id, cancellation_outbox_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(drain.drain_id())
    .bind(historical_proposed)
    .bind(&historical_request_id)
    .bind(cancellation_outbox_id)
    .execute(database.pool())
    .await
    .unwrap();

    store
        .cleanup_completed(&lock_resource(), drain_token.as_bytes())
        .await
        .unwrap();
    let remaining: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM payment_drain_items),
           (SELECT COUNT(*) FROM outbox),
           (SELECT COUNT(*) FROM invoices),
           (SELECT COUNT(*) FROM payment_request_lifecycles)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(remaining, (0, 3, 2, 2));
    let retained_observation: (String, bool) =
        sqlx::query_as("SELECT payment_status, amount_matched FROM invoices WHERE id = $1")
            .bind(historical_rejected)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(retained_observation, ("detected".into(), true));

    let boundary: (i64, Option<Uuid>) = sqlx::query_as(
        "SELECT current_generation, active_drain_id
         FROM lock_payment_generations",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(boundary, (1, None));

    store
        .cleanup_completed(&lock_resource(), drain_token.as_bytes())
        .await
        .unwrap();
    let idempotent_boundary: (i64, Option<Uuid>) = sqlx::query_as(
        "SELECT current_generation, active_drain_id
         FROM lock_payment_generations",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(idempotent_boundary, boundary);

    sqlx::query(
        "UPDATE payment_request_lifecycles
         SET request_state = 'accepted', state_event_id = $1,
             last_stream_item_id = last_stream_item_id + 1,
             last_event_at = last_event_at + INTERVAL '1 second'
         WHERE invoice_id = $2",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(historical_proposed)
    .execute(database.pool())
    .await
    .unwrap();

    let (fresh_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        2,
        1,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    let fresh_drain = store.create(&lock_resource()).await.unwrap();
    assert!(fresh_drain.completed());
    assert_eq!(fresh_drain.accepted_count(), 0);
    assert_eq!(fresh_drain.terminal_count(), 0);
    assert_eq!(fresh_drain.cancellation_enqueued_count(), 1);
    let fresh_items: Vec<Uuid> =
        sqlx::query_scalar("SELECT invoice_id FROM payment_drain_items WHERE drain_id = $1")
            .bind(fresh_drain.drain_id())
            .fetch_all(database.pool())
            .await
            .unwrap();
    assert_eq!(fresh_items, vec![fresh_invoice]);
    assert!(!fresh_items.contains(&historical_proposed));
    assert!(!fresh_items.contains(&historical_rejected));
    let fresh_token = crypto.payment_drain_cleanup_token(fresh_drain.drain_id());

    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), drain_token.as_bytes())
            .await,
        Err(PersistenceError::Conflict)
    );
    let fresh_boundary: (i64, Option<Uuid>) =
        sqlx::query_as("SELECT current_generation, active_drain_id FROM lock_payment_generations")
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(fresh_boundary, (1, Some(fresh_drain.drain_id())));

    let original_envelope: Vec<u8> =
        sqlx::query_scalar("SELECT lock_resource_envelope FROM payment_drains WHERE id = $1")
            .bind(fresh_drain.drain_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let swapped_plaintext = format!("{}-authenticated-mismatch", lock_resource());
    let swapped_envelope = crypto
        .encrypt(
            &EnvelopeContext::payment_drain(
                crypto.lookup_hash(CREATOR.as_bytes()),
                fresh_drain.drain_id(),
            ),
            swapped_plaintext.as_bytes(),
        )
        .unwrap();
    sqlx::query("UPDATE payment_drains SET lock_resource_envelope = $1 WHERE id = $2")
        .bind(swapped_envelope.as_bytes())
        .bind(fresh_drain.drain_id())
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), fresh_token.as_bytes())
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let after_mismatch: (i64, Option<Uuid>, i64) = sqlx::query_as(
        "SELECT current_generation, active_drain_id,
                (SELECT COUNT(*) FROM payment_drains WHERE id = $1)
         FROM lock_payment_generations",
    )
    .bind(fresh_drain.drain_id())
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(after_mismatch, (1, Some(fresh_drain.drain_id()), 1));
    sqlx::query("UPDATE payment_drains SET lock_resource_envelope = $1 WHERE id = $2")
        .bind(original_envelope)
        .bind(fresh_drain.drain_id())
        .execute(database.pool())
        .await
        .unwrap();

    sqlx::query("DELETE FROM lock_payment_generations WHERE creator_id = $1")
        .bind(creator_id)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        store
            .cleanup_completed(&lock_resource(), fresh_token.as_bytes())
            .await,
        Err(PersistenceError::CorruptOrMissing)
    );
    let retained_corrupt_drain: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payment_drains WHERE id = $1")
            .bind(fresh_drain.drain_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(retained_corrupt_drain, 1);

    database.cleanup().await;
}

#[tokio::test]
async fn multi_attempt_drain_counts_invoices_and_cancels_each_live_proposal_once() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[61; 32]).unwrap());
    let creator_id: Uuid = sqlx::query_scalar(
        "INSERT INTO creators (creator_lookup_hash, credential_envelope)
         VALUES ($1, $2) RETURNING id",
    )
    .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
    .bind(b"encrypted-creator".as_slice())
    .fetch_one(database.pool())
    .await
    .unwrap();

    let (cancel_invoice, first_proposed) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        0,
        0,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    let second_proposed = insert_attempt(
        &database,
        cancel_invoice,
        1,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    insert_attempt(
        &database,
        cancel_invoice,
        2,
        PaymentRequestLifecycleState::Rejected,
    )
    .await;

    let (accepted_invoice, _) = insert_invoice(
        &database,
        &crypto,
        creator_id,
        3,
        0,
        PaymentRequestLifecycleState::Proposed,
    )
    .await;
    insert_attempt(
        &database,
        accepted_invoice,
        4,
        PaymentRequestLifecycleState::ProofSubmitted,
    )
    .await;

    let store = PaymentDrainStore::new(database.pool(), crypto);
    let first = store.create(&lock_resource()).await.unwrap();
    assert_eq!(first.accepted_count(), 1);
    assert_eq!(first.terminal_count(), 0);
    assert_eq!(first.cancellation_enqueued_count(), 3);
    assert!(!first.completed());

    let cancellations: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT invoice_id, sdk_payment_request_id
         FROM payment_drain_cancellations ORDER BY sdk_payment_request_id",
    )
    .fetch_all(database.pool())
    .await
    .unwrap();
    assert_eq!(cancellations.len(), 3);
    assert!(cancellations.contains(&(cancel_invoice, first_proposed)));
    assert!(cancellations.contains(&(cancel_invoice, second_proposed)));
    assert!(
        cancellations
            .iter()
            .any(|(invoice_id, _)| *invoice_id == accepted_invoice)
    );

    let replay = store.create(&lock_resource()).await.unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.drain_id(), first.drain_id());
    assert_eq!(replay.cancellation_enqueued_count(), 3);
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(database.pool())
        .await
        .unwrap();
    // Two original proposal intents plus three cancellation attempts. The first
    // invoice's ambiguous SDK attempts intentionally share one outbox intent.
    assert_eq!(outbox_count, 5);

    database.cleanup().await;
}

#[tokio::test]
async fn unsupported_canonical_states_fail_drain_classification_closed() {
    for (state, expected) in [
        (
            PaymentRequestLifecycleState::RecoveryRequired,
            PersistenceError::Unavailable,
        ),
        (
            PaymentRequestLifecycleState::InvalidConflict,
            PersistenceError::Conflict,
        ),
    ] {
        let database = TestDatabase::create().await;
        run_migrations(database.pool()).await.unwrap();
        let crypto = Arc::new(Crypto::from_master_key(&[state.as_str().len() as u8; 32]).unwrap());
        let creator_id: Uuid = sqlx::query_scalar(
            "INSERT INTO creators (creator_lookup_hash, credential_envelope)
             VALUES ($1, $2) RETURNING id",
        )
        .bind(crypto.lookup_hash(CREATOR.as_bytes()).as_bytes().as_slice())
        .bind(b"encrypted-creator".as_slice())
        .fetch_one(database.pool())
        .await
        .unwrap();
        insert_invoice(&database, &crypto, creator_id, 0, 0, state).await;

        let store = PaymentDrainStore::new(database.pool(), crypto);
        assert_eq!(store.create(&lock_resource()).await, Err(expected));
        let durable_rows: (i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT COUNT(*) FROM payment_drains),
               (SELECT COUNT(*) FROM payment_drain_items)",
        )
        .fetch_one(database.pool())
        .await
        .unwrap();
        assert_eq!(durable_rows, (0, 0));
        database.cleanup().await;
    }
}
