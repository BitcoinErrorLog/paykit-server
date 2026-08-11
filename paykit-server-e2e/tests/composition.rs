use std::{sync::Arc, time::Duration};

use paykit_lib::{
    PaykitReceiverCapabilities, PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{
    InMemoryStorage, LinkedPeerState, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey,
    PubkyPublicKey, PubkySessionBootstrap, ReceiverNoiseSecretKey, storage::StorageState,
};
use paykit_server::{
    Server,
    application::semantic_intent::DeliveryIntentV1,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoiceStore,
        NewReaderPayloadFactory, NewReaderPayloads, PersistenceError, PostgresStorageAdapter,
        SdkStateStore, run_migrations,
    },
    runtime::ComponentState,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use uuid::Uuid;

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";

type CreatorSdk = PaykitSdk<PostgresStorageAdapter, TestSessionProvider, TestPaymentAdapter>;
type PeerSdk = PaykitSdk<InMemoryStorage, TestSessionProvider, TestPaymentAdapter>;

struct Payloads {
    reader: ReaderPubky,
    marker: PaykitReceiverMarker,
    address_prefix: &'static str,
}

impl NewReaderPayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        let address = format!("{}-{child_index}", self.address_prefix);
        Ok(NewReaderPayloads {
            endpoint_intent: DeliveryIntentV1::endpoint(
                self.reader.to_string(),
                &self.marker,
                PaykitReceiverPath::new("paykit/server").unwrap(),
                vec![(
                    PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
                    PaymentEndpointPayload::new(address.clone()),
                )],
            )
            .unwrap(),
            bitcoin_address: address,
        })
    }
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

async fn create_creator(
    bootstrap: &PubkySessionBootstrap,
    homeserver: &PubkyPublicKey,
    store: &CreatorStore,
    pool: &sqlx::PgPool,
    crypto: Arc<Crypto>,
    counter_seed: u64,
) -> (CreatorPubky, CreatorSdk) {
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let keypair = Keypair::random();
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(keypair.secret_key()),
            ReceiverNoiseSecretKey::random(),
            homeserver,
            None,
            &PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", account.public_key)).unwrap();
    let state = StorageState {
        next_outbound_private_message_id: counter_seed,
        ..StorageState::default()
    };
    let row = store
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                account.access.session.export_secret(),
                account.access.receiver_noise_secret_key.clone(),
                format!("test-xpub-{counter_seed}"),
                0,
            ),
            &state,
        )
        .await
        .unwrap();
    let sdk = PaykitSdk::new(
        PostgresStorageAdapter::new(pool, crypto, row.id()),
        TestSessionProvider::new(account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(receiver_path),
    )
    .unwrap();
    sdk.initialize().await.unwrap();
    sdk.publish_paykit_receiver_marker(PaykitReceiverCapabilities {
        private_payments: true,
        payment_requests: true,
        receipts: true,
        outgoing_payments: true,
    })
    .await
    .unwrap();
    (creator, sdk)
}

async fn link(
    creator: &CreatorSdk,
    creator_key: PubkyPublicKey,
    peer: &PeerSdk,
    peer_key: PubkyPublicKey,
) {
    let creator_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let peer_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    creator
        .initiate_link_with_peer(peer_key.clone(), peer_path.clone())
        .await
        .unwrap();
    peer.accept_link_with_peer(creator_key.clone(), creator_path.clone())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_state = LinkedPeerState::Linking;
    let mut peer_state = LinkedPeerState::Linking;
    while creator_state != LinkedPeerState::Linked || peer_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_state != LinkedPeerState::Linked {
            creator_state = creator
                .advance_link_handshake(peer_key.clone(), peer_path.clone())
                .await
                .unwrap()
                .state;
        }
        if peer_state != LinkedPeerState::Linked {
            peer_state = peer
                .advance_link_handshake(creator_key.clone(), creator_path.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn payment_intent(reader: &ReaderPubky, marker: &PaykitReceiverMarker) -> DeliveryIntentV1 {
    DeliveryIntentV1::payment_request(
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
    .unwrap()
}

fn config(database_url: &str, electrum_endpoint: &str) -> Config {
    let toml = format!(
        r#"
[http]
listen_addr = "127.0.0.1:0"

[locks]
trusted_public_key = "{TRUSTED_KEY}"

[setup]
allowed_origins = ["https://app.example"]

[paykit]
receiver_path = "paykit/server"
network = "testnet"

[bitcoin]
network = "testnet"

[electrum]
endpoint = "{electrum_endpoint}"
poll_interval = "50ms"
request_timeout = "50ms"
connect_retries = 0

[outbox]
poll_interval = "1s"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "2s"
"#
    );
    Config::from_toml_and_environment(
        &toml,
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn production_server_workers_process_two_creators_without_sdk_state_fallback() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto.clone());

    let peer_path = PaykitReceiverPath::new("bitkit/server").unwrap();
    let peer_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(peer_path.clone()).required_session_capabilities(),
        )
        .await
        .unwrap();
    let peer_key = peer_account.public_key.clone();
    let peer_sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(peer_account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(peer_path.clone()),
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
    let marker = peer_sdk
        .paykit_receiver_marker(peer_key.clone(), peer_path)
        .await
        .unwrap()
        .unwrap();
    let reader = parse_reader(&format!("pubky{peer_key}")).unwrap();

    let (creator_a, sdk_a) = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        database.pool(),
        crypto.clone(),
        100,
    )
    .await;
    let (creator_b, sdk_b) = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        database.pool(),
        crypto.clone(),
        1000,
    )
    .await;
    let (creator_c, _sdk_c) = create_creator(
        &bootstrap,
        &homeserver,
        &creators,
        database.pool(),
        crypto.clone(),
        10_000,
    )
    .await;
    let creator_a_key = PubkyPublicKey::from_raw_or_app_key(creator_a.to_string()).unwrap();
    let creator_b_key = PubkyPublicKey::from_raw_or_app_key(creator_b.to_string()).unwrap();
    link(&sdk_a, creator_a_key, &peer_sdk, peer_key.clone()).await;
    link(&sdk_b, creator_b_key, &peer_sdk, peer_key).await;

    let sdk_states = SdkStateStore::new(database.pool(), crypto.clone());
    let before_a = sdk_states
        .load(&creator_a)
        .await
        .unwrap()
        .next_outbound_private_message_id;
    let before_b = sdk_states
        .load(&creator_b)
        .await
        .unwrap()
        .next_outbound_private_message_id;
    let before_c = sdk_states
        .load(&creator_c)
        .await
        .unwrap()
        .next_outbound_private_message_id;
    assert_ne!(before_a, before_b);

    let invoices = InvoiceStore::new(database.pool(), crypto);
    let invoice_a = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator_a,
            reader: &reader,
            bundle_binding: b"composition-bundle-a",
            payment_request_binding: b"composition-request-a",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
                marker: marker.clone(),
                address_prefix: "creator-a-address",
            },
            payment_request_intent: payment_intent(&reader, &marker),
            required_sats: 100,
            payment_in_hours: 24,
        })
        .await
        .unwrap();
    let invoice_b = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator_b,
            reader: &reader,
            bundle_binding: b"composition-bundle-b",
            payment_request_binding: b"composition-request-b",
            new_reader_payloads: &Payloads {
                reader: reader.clone(),
                marker: marker.clone(),
                address_prefix: "creator-b-address",
            },
            payment_request_intent: payment_intent(&reader, &marker),
            required_sats: 200,
            payment_in_hours: 24,
        })
        .await
        .unwrap();
    let unreachable_key = PubkyPublicKey::from_public_key(&Keypair::random().public_key());
    let unreachable_reader = parse_reader(&format!("pubky{unreachable_key}")).unwrap();
    let invoice_c = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator_c,
            reader: &unreachable_reader,
            bundle_binding: b"composition-bundle-c",
            payment_request_binding: b"composition-request-c",
            new_reader_payloads: &Payloads {
                reader: unreachable_reader.clone(),
                marker: marker.clone(),
                address_prefix: "creator-c-address",
            },
            payment_request_intent: payment_intent(&unreachable_reader, &marker),
            required_sats: 300,
            payment_in_hours: 24,
        })
        .await
        .unwrap();
    assert_eq!(invoice_a.reader_child_index(), 0);
    assert_eq!(invoice_b.reader_child_index(), 0);
    assert_ne!(invoice_a.invoice_id(), invoice_b.invoice_id());
    let address_hash_a: Vec<u8> =
        sqlx::query_scalar("SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1")
            .bind(invoice_a.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    let address_hash_b: Vec<u8> =
        sqlx::query_scalar("SELECT bitcoin_address_lookup_hash FROM invoices WHERE id = $1")
            .bind(invoice_b.invoice_id())
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_ne!(address_hash_a, address_hash_b);
    let endpoint_a = invoice_a.endpoint_publication_outbox_id().unwrap();
    let endpoint_b = invoice_b.endpoint_publication_outbox_id().unwrap();
    let endpoint_c = invoice_c.endpoint_publication_outbox_id().unwrap();

    let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let electrum_endpoint = format!("tcp://{}", unavailable.local_addr().unwrap());
    drop(unavailable);
    let server = Server::build_with_pubky(
        config(database.database_url(), &electrum_endpoint),
        database.pool().clone(),
        pubky,
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_task = tokio::spawn(server.run(listener));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let (outbound_a, outbound_b) = loop {
        let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT id, status, sdk_outbound_message_id FROM outbox WHERE id = ANY($1)",
        )
        .bind(vec![endpoint_a, endpoint_b, endpoint_c])
        .fetch_all(database.pool())
        .await
        .unwrap();
        let lookup = |id| {
            rows.iter()
                .find(|row| row.0 == id && matches!(row.1.as_str(), "handed_off" | "delivered"))
                .and_then(|row| row.2.as_deref())
                .and_then(|id| id.parse::<u64>().ok())
        };
        let retrying_c = rows
            .iter()
            .any(|row| row.0 == endpoint_c && row.1 == "retryable");
        if let (Some(a), Some(b), true) = (lookup(endpoint_a), lookup(endpoint_b), retrying_c) {
            break (a, b);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "production workers did not process both Creator-scoped endpoint intents"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    assert_eq!(outbound_a, before_a);
    assert_eq!(outbound_b, before_b);
    assert_ne!(outbound_a, outbound_b);
    let after_a = sdk_states.load(&creator_a).await.unwrap();
    let after_b = sdk_states.load(&creator_b).await.unwrap();
    let after_c = sdk_states.load(&creator_c).await.unwrap();
    assert!(after_a.next_outbound_private_message_id > before_a);
    assert!(after_b.next_outbound_private_message_id > before_b);
    assert_eq!(after_c.next_outbound_private_message_id, before_c);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let health = runtime.readiness().await;
    assert_eq!(health.status, ComponentState::Degraded);
    assert_eq!(health.paykit_delivery, ComponentState::Degraded);
    assert_eq!(health.outbox, ComponentState::Ready);

    server_task.abort();
    let _ = server_task.await;
    database.cleanup().await;
}
