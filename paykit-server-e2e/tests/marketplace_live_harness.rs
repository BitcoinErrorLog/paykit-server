//! Protocol-real upstream Paykit server for Marketplace cross-process tests.
//!
//! This ignored test owns a disposable PostgreSQL database, ephemeral Pubky
//! testnet, real Paykit SDK sessions, and production HTTP/workers. It writes a
//! JSON handoff named by `PAYKIT_HARNESS_HANDOFF`, then serves until
//! `<handoff>.stop` exists. Marketplace must use the one `base_url` with its
//! upstream API mode; no fork stack identity is exported.

use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use ed25519_dalek::SigningKey;
use paykit_sdk::{LinkedPeerState, PubkyLocalSecretKey, PubkyPublicKey, PubkySessionBootstrap};
use paykit_server::{
    Server,
    bitcoin::ObservationTarget,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::parse_creator,
    persistence::{CreatorCredentials, CreatorStore},
    runtime::ComponentState,
    startup::initialize_database,
    workers::observer::{ElectrumPort, ObserverError},
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

struct EmptyChain;

#[async_trait]
impl ElectrumPort for EmptyChain {
    async fn observations(
        &self,
        _targets: &[ObservationTarget],
    ) -> Result<Vec<paykit_server::bitcoin::ObservedOutput>, ObserverError> {
        Ok(Vec::new())
    }
}

fn config(database_url: &str, trusted: &SigningKey) -> Config {
    let trusted_key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(trusted.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[signed_services]
trusted_public_keys = ["{trusted_key}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "tcp://127.0.0.1:1"
poll_interval = "25ms"
request_timeout = "1s"
connect_retries = 0
[outbox]
poll_interval = "25ms"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "1s"
rapid_link_retry_attempts = 20
rapid_link_retry_interval_ms = 25
[shutdown]
drain_timeout = "5s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

fn account_xpub(seed: u8) -> String {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Testnet, &[seed; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn trusted_signing_key() -> SigningKey {
    let seed = std::env::var("PAYKIT_HARNESS_TRUSTED_SEED")
        .expect("PAYKIT_HARNESS_TRUSTED_SEED names the trusted signing seed (hex)");
    assert_eq!(seed.len(), 64, "trusted seed is 64 hex characters");
    let bytes = (0..seed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&seed[index..index + 2], 16).expect("trusted seed is hex"))
        .collect::<Vec<_>>();
    SigningKey::from_bytes(&bytes.try_into().expect("trusted seed is 32 bytes"))
}

async fn link(
    creator: &sdk_fixtures::HostedSdk,
    creator_key: PubkyPublicKey,
    reader: &sdk_fixtures::HostedSdk,
    reader_key: PubkyPublicKey,
) {
    creator
        .initiate_link_with_peer(reader_key.clone())
        .await
        .unwrap();
    reader
        .accept_link_with_peer(creator_key.clone())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut creator_state = LinkedPeerState::Linking;
    let mut reader_state = LinkedPeerState::Linking;
    while creator_state != LinkedPeerState::Linked || reader_state != LinkedPeerState::Linked {
        assert!(tokio::time::Instant::now() < deadline, "SDK link timed out");
        if creator_state != LinkedPeerState::Linked {
            creator_state = creator
                .advance_link_handshake(reader_key.clone())
                .await
                .unwrap()
                .state;
        }
        if reader_state != LinkedPeerState::Linked {
            reader_state = reader
                .advance_link_handshake(creator_key.clone())
                .await
                .unwrap()
                .state;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "serves protocol-real upstream Paykit for Marketplace; run explicitly"]
async fn serve_for_marketplace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("paykit_server=debug")
        .with_test_writer()
        .try_init();
    let handoff = std::env::var("PAYKIT_HARNESS_HANDOFF")
        .expect("PAYKIT_HARNESS_HANDOFF names the handoff file");
    let stop = format!("{handoff}.stop");
    let _ = std::fs::remove_file(&handoff);
    let _ = std::fs::remove_file(&stop);
    let serve_seconds = std::env::var("PAYKIT_HARNESS_SERVE_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>().expect("serve seconds"))
        .unwrap_or(1800);

    let database = TestDatabase::create().await;
    let trusted = trusted_signing_key();
    let server_config = config(database.database_url(), &trusted);
    let pool = initialize_database(&server_config).await.unwrap();
    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "app.paykit.server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());

    let creator_keypair = Keypair::random();
    let creator_owner = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator_grant = bootstrap
        .sign_in(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            paykit_sdk::PAYKIT_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_owner.public_key)).unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto);
    creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            creator_grant
                .export_session_secret()
                .await
                .unwrap()
                .into_inner(),
            PubkyLocalSecretKey::new(creator_keypair.secret_key())
                .derive_paykit_identity_secret_key(1)
                .unwrap(),
            Some(paykit_server::domain::receiving::BitcoinAccount {
                xpub: account_xpub(7).into(),
                account_index: 0,
            }),
            None,
        ))
        .await
        .unwrap();
    let creator_sdk =
        sdk_fixtures::hosted_sdk(creator_owner.access.clone(), "paykit-server", 0).await;
    creators.mark_setup_complete(&creator).await.unwrap();

    let reader_keypair = Keypair::random();
    let reader_owner = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(reader_keypair.secret_key()),
            &homeserver,
            None,
            paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
        )
        .await
        .unwrap();
    let reader_sdk = sdk_fixtures::hosted_sdk(reader_owner.access.clone(), "bitkit", 0).await;
    link(
        &creator_sdk,
        creator_owner.public_key.clone(),
        &reader_sdk,
        reader_owner.public_key.clone(),
    )
    .await;

    let server =
        Server::build_with_transports(server_config, pool.clone(), pubky, Arc::new(EmptyChain))
            .await
            .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while runtime.readiness().await.status != ComponentState::Ready {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Paykit never became ready"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let body = serde_json::json!({
        "base_url": format!("http://{address}"),
        "paykit_database_url": database.database_url(),
        "creator_secret_hex": hex_encode(&creator_keypair.secret_key()),
        "reader_secret_hex": hex_encode(&reader_keypair.secret_key()),
    });
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&handoff)
        .unwrap()
        .write_all(&serde_json::to_vec_pretty(&body).unwrap())
        .unwrap();
    eprintln!("upstream Paykit harness ready at http://{address}");

    let serve_deadline = tokio::time::Instant::now() + Duration::from_secs(serve_seconds);
    while tokio::time::Instant::now() < serve_deadline && !std::path::Path::new(&stop).exists() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if std::path::Path::new(&stop).exists() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            reader_sdk
                .receive_private_messages(creator_owner.public_key.clone())
                .await
                .unwrap();
            let requests = reader_sdk
                .actionable_received_payment_requests()
                .await
                .unwrap();
            if requests.len() == 1 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected exactly one real SDK proposal, observed {}",
                requests.len()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let ids: (i64, i64, i64) = sqlx::query_as(
            "SELECT count(*), count(DISTINCT sdk_event_id), count(DISTINCT sdk_payment_request_id) \
             FROM outbox WHERE intent_kind = 'payment_request_proposal' AND status = 'delivered'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ids, (1, 1, 1));
    }

    let _ = shutdown_tx.send(());
    running.await.unwrap().unwrap();
    drop(testnet);
    // Homeserver tasks release their final database handles after cancellation
    // is observed by the runtime; let those destructors register the test DB.
    tokio::time::sleep(Duration::from_millis(100)).await;
    pubky_testnet::drop_test_databases().await;
    pool.close().await;
    database.cleanup().await;
    let _ = std::fs::remove_file(&handoff);
    let _ = std::fs::remove_file(&stop);
}
