//! A live paykit-server for marketplace-service integration tests.
//!
//! `serve_for_marketplace` boots the production server over a real database
//! and an ephemeral pubky testnet (the same composition as `two_phase.rs`),
//! with one claimed creator and one reader whose Paykit receiver marker is
//! published. The signed routes trust the ed25519 key whose 32-byte seed is
//! `PAYKIT_HARNESS_TRUSTED_SEED` (hex). Once ready it writes a JSON handoff
//! to `PAYKIT_HARNESS_HANDOFF`:
//!
//! ```json
//! {"base_url": "...", "stack_id": "...",
//!  "creator_secret_hex": "...", "reader_secret_hex": "..."}
//! ```
//!
//! and serves until the file `<handoff>.stop` exists or
//! `PAYKIT_HARNESS_SERVE_SECONDS` (default 1800) elapse. Electrum is a
//! scripted port reporting an empty chain and a fresh tip, so creation,
//! activation, and void run the production code paths without a network.
//!
//! Run: `TEST_DATABASE_URL=... PAYKIT_HARNESS_TRUSTED_SEED=... \
//! PAYKIT_HARNESS_HANDOFF=... cargo test -p paykit-server-e2e \
//! --test marketplace_live_harness -- --ignored --nocapture`

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use ed25519_dalek::SigningKey;
use paykit_lib::{PaykitReceiverCapabilities, PaykitReceiverPath};
use paykit_sdk::{
    InMemoryStorage, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionBootstrap, ReceiverNoiseSecretKey,
};
use paykit_server::{
    Server,
    allocation::ClaimAllocation,
    bitcoin::ObservationTarget,
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::locks::parse_creator,
    persistence::{CreatorCredentials, CreatorStore, run_migrations},
    runtime::ElectrumProbe,
    startup::initialize_database,
    workers::observer::{
        CreationSnapshot, ElectrumPort, ObservationReport, ObserverError, RequestLimiter, TipProbe,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

struct EmptyChain;

fn tip_time() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[async_trait]
impl ElectrumPort for EmptyChain {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
            unconfirmed_outputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        Ok(ObservationReport {
            outputs: Vec::new(),
            observed: targets
                .iter()
                .map(|target| target.address().to_owned())
                .collect(),
            failed: Vec::new(),
        })
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 300,
            time_unix: tip_time(),
        })
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
[locks]
trusted_public_key = "{trusted_key}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "paykit-server"
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
creation_enabled = true
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
poll_interval = "1h"
observer_lease_ttl = "2h"
request_timeout = "1s"
max_concurrent_creation_snapshots = 1
[outbox]
poll_interval = "1h"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "2s"
[shutdown]
drain_timeout = "2s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            migrator_database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
            ..Default::default()
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn trusted_signing_key() -> SigningKey {
    let seed = std::env::var("PAYKIT_HARNESS_TRUSTED_SEED")
        .expect("PAYKIT_HARNESS_TRUSTED_SEED names the trusted signing seed (hex)");
    let bytes: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&seed[index..index + 2], 16).expect("hex seed"))
        .collect();
    SigningKey::from_bytes(&bytes.try_into().expect("32-byte seed"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "serves a live paykit-server for marketplace-service; run explicitly"]
async fn serve_for_marketplace() {
    let handoff = std::env::var("PAYKIT_HARNESS_HANDOFF")
        .expect("PAYKIT_HARNESS_HANDOFF names the handoff file");
    let stop = format!("{handoff}.stop");
    let _ = std::fs::remove_file(&stop);
    let serve_seconds: u64 = std::env::var("PAYKIT_HARNESS_SERVE_SECONDS")
        .ok()
        .map(|value| value.parse().expect("seconds"))
        .unwrap_or(1800);

    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let trusted = trusted_signing_key();
    let server_config = config(database.database_url(), &trusted);
    let initialized = initialize_database(&server_config).await.unwrap();
    let pool = initialized.pool.clone();
    let stack_identity = initialized.stack_identity.clone();
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
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit-server").unwrap();
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());

    let reader_keypair = Keypair::random();
    let reader_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(reader_keypair.secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let reader_sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(reader_account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap()),
    )
    .unwrap();
    reader_sdk.initialize().await.unwrap();
    reader_sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        })
        .await
        .unwrap();

    let creator_keypair = Keypair::random();
    let creator_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(creator_keypair.secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_account.public_key)).unwrap();
    creators
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                creator_account
                    .export_session_secret()
                    .await
                    .unwrap()
                    .into_inner(),
                creator_account.access.receiver_noise_secret_key.clone(),
                account_xpub(7),
                0,
            ),
            &Default::default(),
            &[7; 65],
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();

    let server = Server::build_with_transports(
        server_config,
        pool.clone(),
        stack_identity.clone(),
        pubky,
        Arc::new(EmptyChain),
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));
    let probes = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            loop {
                runtime.record_electrum_probe(ElectrumProbe::success(300, tip_time()));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !runtime.readiness().await.bitcoin_offer_available {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the offer never became available"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let body = serde_json::json!({
        "base_url": format!("http://{address}"),
        "stack_id": stack_identity.stack_id(),
        "creator_secret_hex": hex(&creator_keypair.secret_key()),
        "reader_secret_hex": hex(&reader_keypair.secret_key()),
    });
    std::fs::write(&handoff, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    eprintln!("paykit harness ready: {body}");

    let serve_deadline = tokio::time::Instant::now() + Duration::from_secs(serve_seconds);
    while tokio::time::Instant::now() < serve_deadline && !std::path::Path::new(&stop).exists() {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    probes.abort();
    let _ = shutdown_tx.send(());
    running.await.unwrap().unwrap();
    drop(testnet);
    pool.close().await;
    database.cleanup().await;
    let _ = std::fs::remove_file(&handoff);
}
