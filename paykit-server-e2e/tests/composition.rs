use std::{sync::Arc, time::Duration};

mod common;
use paykit_sdk::{LinkedPeerState, PubkyLocalSecretKey, PubkyPublicKey, PubkySessionBootstrap};
use paykit_server::{
    Server,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_creator, parse_reader},
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PersistenceError, run_migrations,
    },
    runtime::ComponentState,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use uuid::Uuid;

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const TRUSTED_KEY: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";

type CreatorSdk = sdk_fixtures::HostedSdk;
type PeerSdk = sdk_fixtures::HostedSdk;

struct Payloads {
    reader: ReaderPubky,
    address_prefix: &'static str,
}

impl InvoicePayloadFactory for Payloads {
    fn for_child_index(&self, child_index: i64) -> Result<InvoicePayloads, PersistenceError> {
        let address = format!("{}-{child_index}", self.address_prefix);
        Ok(InvoicePayloads {
            payment_request_intent: common::payment_intent(&self.reader, address.clone()),
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
    counter_seed: u64,
) -> (CreatorPubky, CreatorSdk) {
    let keypair = Keypair::random();
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(keypair.secret_key()),
            homeserver,
            None,
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let session_secret = account.export_session_secret().await.unwrap().into_inner();
    let creator = parse_creator(&format!("pubky{}", account.public_key)).unwrap();
    store
        .create(&CreatorCredentials::new(
            creator.clone(),
            session_secret,
            PubkyLocalSecretKey::new(keypair.secret_key())
                .derive_paykit_identity_secret_key(1)
                .unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: format!("test-xpub-{counter_seed}").into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    // Independent apps must not refresh the same Pubky session credential.
    let observer = PubkySessionBootstrap::with_pubky(
        account.access.outbox_client.clone(),
        "app.paykit.test-observer",
    )
    .unwrap()
    .sign_in(
        &PubkyLocalSecretKey::new(keypair.secret_key()),
        paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
    )
    .await
    .unwrap();
    let sdk = sdk_fixtures::hosted_sdk(observer.access, "paykit-server", counter_seed).await;
    store.mark_setup_complete(&creator).await.unwrap();
    (creator, sdk)
}

async fn link(
    creator: &CreatorSdk,
    creator_key: PubkyPublicKey,
    peer: &PeerSdk,
    peer_key: PubkyPublicKey,
) {
    creator
        .initiate_link_with_peer(peer_key.clone())
        .await
        .unwrap();
    peer.accept_link_with_peer(creator_key.clone())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_state = LinkedPeerState::Linking;
    let mut peer_state = LinkedPeerState::Linking;
    while creator_state != LinkedPeerState::Linked || peer_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "link timed out");
        if creator_state != LinkedPeerState::Linked {
            creator_state = creator
                .advance_link_handshake(peer_key.clone())
                .await
                .unwrap()
                .state;
        }
        if peer_state != LinkedPeerState::Linked {
            peer_state = peer
                .advance_link_handshake(creator_key.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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
client_id = "app.paykit.server"
app_id = "paykit-server"
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
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto.clone());

    let peer_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let peer_key = peer_account.public_key.clone();
    let peer_sdk = sdk_fixtures::hosted_sdk(peer_account.access, "bitkit", 0).await;
    let reader = parse_reader(&format!("pubky{peer_key}")).unwrap();

    let (creator_a, sdk_a) = create_creator(&bootstrap, &homeserver, &creators, 100).await;
    let (creator_b, sdk_b) = create_creator(&bootstrap, &homeserver, &creators, 1000).await;
    let (creator_c, sdk_c) = create_creator(&bootstrap, &homeserver, &creators, 10_000).await;
    let creator_a_key = PubkyPublicKey::from_raw_or_app_key(creator_a.to_string()).unwrap();
    let creator_b_key = PubkyPublicKey::from_raw_or_app_key(creator_b.to_string()).unwrap();
    link(&sdk_a, creator_a_key, &peer_sdk, peer_key.clone()).await;
    link(&sdk_b, creator_b_key, &peer_sdk, peer_key).await;

    let before_a = sdk_a
        .export_backup_state()
        .await
        .unwrap()
        .next_outbound_private_message_id;
    let before_b = sdk_b
        .export_backup_state()
        .await
        .unwrap()
        .next_outbound_private_message_id;
    let before_c = sdk_c
        .export_backup_state()
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
            lock_resource_binding: b"composition-lock-a",
            payment_request_binding: b"composition-request-a",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
                address_prefix: "creator-a-address",
            },

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
        })
        .await
        .unwrap();
    let invoice_b = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator_b,
            reader: &reader,
            bundle_binding: b"composition-bundle-b",
            lock_resource_binding: b"composition-lock-b",
            payment_request_binding: b"composition-request-b",
            invoice_payloads: &Payloads {
                reader: reader.clone(),
                address_prefix: "creator-b-address",
            },

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
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
            lock_resource_binding: b"composition-lock-c",
            payment_request_binding: b"composition-request-c",
            invoice_payloads: &Payloads {
                reader: unreachable_reader.clone(),
                address_prefix: "creator-c-address",
            },

            proposal_acceptance_seconds: 60 * 60,
            payment_window_seconds: 24 * 60 * 60,
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
    let request_a = invoice_a.payment_request_outbox_id();
    let request_b = invoice_b.payment_request_outbox_id();
    let request_c = invoice_c.payment_request_outbox_id();

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
        .bind(vec![request_a, request_b, request_c])
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
            .any(|row| row.0 == request_c && row.1 == "retryable");
        if let (Some(a), Some(b), true) = (lookup(request_a), lookup(request_b), retrying_c) {
            break (a, b);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "production workers did not process both Creator-scoped request intents"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    assert!(
        (before_a..before_b).contains(&outbound_a),
        "Creator A must allocate from its own seeded outbound counter range"
    );
    assert!(
        (before_b..before_c).contains(&outbound_b),
        "Creator B must allocate from its own seeded outbound counter range"
    );
    assert_ne!(outbound_a, outbound_b);
    let health = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let health = runtime.readiness().await;
            if health.status != ComponentState::NotReady {
                break health;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all workers must publish startup health");
    assert_eq!(health.status, ComponentState::Degraded);
    assert_eq!(health.paykit_delivery, ComponentState::Degraded);
    assert_eq!(health.outbox, ComponentState::Ready);

    runtime.begin_shutdown();
    server_task.await.unwrap().unwrap();
    let after_a = sdk_a.export_backup_state().await.unwrap();
    let after_b = sdk_b.export_backup_state().await.unwrap();
    let after_c = sdk_c.export_backup_state().await.unwrap();
    assert!(after_a.next_outbound_private_message_id > before_a);
    assert!(after_b.next_outbound_private_message_id > before_b);
    assert_eq!(after_c.next_outbound_private_message_id, before_c);

    database.cleanup().await;
}
