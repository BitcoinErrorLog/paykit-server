//! End-to-end manual watch-only claims against a real ephemeral Pubky
//! testnet: DHT, homeserver, and HTTP relay. The claim exchanges a genuine
//! capability-scoped AuthToken for a homeserver session through the relay
//! loopback, publishes the receiver marker, and persists encrypted creator
//! credentials — the exact production path with no substituted transports.

use std::{str::FromStr, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::{PaykitSdkConfig, PubkyPublicKey};
use paykit_server::{
    application::create_invoice::derive_bip84_p2wpkh_address,
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::BitcoinNetwork,
    crypto::Crypto,
    domain::locks::parse_creator,
    manual_claim::{
        ManualClaimError, ManualClaimRequest, ManualClaimService, RelayLoopbackSessionMinter,
    },
    persistence::{CreatorStore, run_migrations},
    real_setup::DirectMarkerPublisher,
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{
    EphemeralTestnet,
    pubky::{AuthToken, Capabilities, Keypair},
};

static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Scripted claim-scan port: the only mocked seam in this suite. `fail`
/// refuses every batch as an Electrum outage; otherwise the n-th batched
/// call answers window n, reporting usage exactly at the absolute
/// external-chain child indices in `used_indices`.
struct ScriptedHistory {
    fail: bool,
    used_indices: Vec<u32>,
    calls: std::sync::Mutex<u32>,
}

impl ScriptedHistory {
    fn unused() -> Self {
        Self {
            fail: false,
            used_indices: vec![],
            calls: std::sync::Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl ChainHistoryPort for ScriptedHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        if self.fail {
            return Err(ClaimScanError::Unavailable);
        }
        let mut calls = self.calls.lock().unwrap();
        let window = *calls;
        *calls += 1;
        Ok(scripts
            .iter()
            .enumerate()
            .map(|(offset, _)| self.used_indices.contains(&(window * 20 + offset as u32)))
            .collect())
    }
}

fn account_xpub(seed: u8, account_index: u32) -> String {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Testnet, &[seed; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(account_index).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

async fn build_pubky_testnet() -> EphemeralTestnet {
    let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap();
    EphemeralTestnet::builder()
        .postgres(postgres)
        .with_http_relay()
        .build()
        .await
        .unwrap()
}

fn claim_token(keypair: &Keypair, capabilities: &str) -> String {
    let capabilities = Capabilities::try_from(capabilities).unwrap();
    URL_SAFE_NO_PAD.encode(AuthToken::sign(keypair, capabilities).serialize())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_claim_persists_account_publishes_marker_and_refuses_replacement() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let relay_inbox = testnet.http_relay().local_url().join("inbox").unwrap();

    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto);
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let required_capabilities =
        PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities();
    let service = ManualClaimService::new(
        pubky.clone(),
        Arc::new(RelayLoopbackSessionMinter::new(pubky.clone(), relay_inbox)),
        creators.clone(),
        Arc::new(DirectMarkerPublisher),
        Arc::new(ScriptedHistory::unused()),
        BitcoinNetwork::Testnet,
        receiver_path.clone(),
    );
    assert_eq!(service.required_capabilities(), required_capabilities);

    // The seller identity exists on the homeserver; only the keypair signer
    // (Pubky Ring / Bitkit) ever holds its secret.
    let keypair = Keypair::random();
    let homeserver = testnet.homeserver_app().public_key();
    pubky
        .signer(keypair.clone())
        .signup(&homeserver, None)
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", keypair.public_key().z32())).unwrap();
    assert!(!service.account_exists(&creator).await.unwrap());

    let xpub = account_xpub(51, 0);
    let outcome = service
        .claim(ManualClaimRequest {
            auth_token: claim_token(&keypair, &required_capabilities),
            account_xpub: xpub.clone(),
            account_index: 0,
        })
        .await
        .unwrap();
    assert_eq!(outcome.creator, creator.to_string());
    assert_eq!(outcome.account_index, 0);
    assert_eq!(
        outcome.next_child_index, 0,
        "an unused account's scan keeps the derivation cursor at 0"
    );

    // The persisted record is the exact watch-only account: fresh invoice
    // addresses derive from the claimed xpub.
    let credentials = creators.load(&creator).await.unwrap();
    assert_eq!(credentials.xpub(), xpub);
    assert_eq!(credentials.account_index(), 0);
    let first_session_secret = credentials.session_secret().to_owned();
    assert_eq!(
        derive_bip84_p2wpkh_address(credentials.xpub(), 0, &BitcoinNetwork::Testnet, 0).unwrap(),
        derive_bip84_p2wpkh_address(&xpub, 0, &BitcoinNetwork::Testnet, 0).unwrap()
    );

    // The receiver marker was published to the creator's homeserver and is
    // publicly readable, exactly like a companion-flow setup.
    let owner = PubkyPublicKey::from_public_key(&keypair.public_key())
        .to_public_key()
        .unwrap();
    let marker =
        paykit_lib::get_paykit_receiver_marker(&pubky.public_storage(), &owner, &receiver_path)
            .await
            .unwrap()
            .expect("receiver marker is published");
    assert!(marker.capabilities.private_payments);
    assert!(marker.capabilities.payment_requests);
    assert!(!marker.capabilities.receipts);

    assert!(service.account_exists(&creator).await.unwrap());

    // Re-claiming the same account refreshes the session (a wallet re-setup)
    // while the immutable account identity is untouched.
    let outcome = service
        .claim(ManualClaimRequest {
            auth_token: claim_token(&keypair, &required_capabilities),
            account_xpub: xpub.clone(),
            account_index: 0,
        })
        .await
        .unwrap();
    assert_eq!(outcome.creator, creator.to_string());
    let refreshed = creators.load(&creator).await.unwrap();
    assert_eq!(refreshed.xpub(), xpub);
    assert_ne!(
        refreshed.session_secret(),
        first_session_secret,
        "a re-claim replaces the session secret"
    );

    // A different xpub (or index) is refused, matching the companion flow's
    // reauthentication semantics: existing invoices watch addresses derived
    // from the persisted account.
    assert_eq!(
        service
            .claim(ManualClaimRequest {
                auth_token: claim_token(&keypair, &required_capabilities),
                account_xpub: account_xpub(52, 0),
                account_index: 0,
            })
            .await,
        Err(ManualClaimError::AccountMismatch)
    );
    assert_eq!(
        service
            .claim(ManualClaimRequest {
                auth_token: claim_token(&keypair, &required_capabilities),
                account_xpub: account_xpub(51, 1),
                account_index: 1,
            })
            .await,
        Err(ManualClaimError::AccountMismatch)
    );

    // Root-capability tokens are refused outright: the server must never
    // hold a broader session than the receiver paths require.
    let root = Capabilities::try_from("/:rw").unwrap();
    assert_eq!(
        service
            .claim(ManualClaimRequest {
                auth_token: URL_SAFE_NO_PAD.encode(AuthToken::sign(&keypair, root).serialize()),
                account_xpub: xpub.clone(),
                account_index: 0,
            })
            .await,
        Err(ManualClaimError::InvalidCapabilities)
    );

    // An identity that never signed up on any homeserver cannot mint a
    // session, so its claim fails without touching persistence.
    let stranger = Keypair::random();
    let result = service
        .claim(ManualClaimRequest {
            auth_token: claim_token(&stranger, &required_capabilities),
            account_xpub: account_xpub(53, 0),
            account_index: 0,
        })
        .await;
    assert!(
        matches!(
            result,
            Err(ManualClaimError::InvalidToken | ManualClaimError::SessionUnavailable)
        ),
        "unexpected claim result: {result:?}"
    );
    let stranger_creator = parse_creator(&format!("pubky{}", stranger.public_key().z32())).unwrap();
    assert!(!service.account_exists(&stranger_creator).await.unwrap());

    let xpub_str = xpub;
    drop(service);
    // Sanity: the derived first receive address matches BIP84 for the seed.
    let expected = derive_bip84_p2wpkh_address(&xpub_str, 0, &BitcoinNetwork::Testnet, 0).unwrap();
    assert!(expected.starts_with("tb1"));
    assert_eq!(Xpub::from_str(&xpub_str).unwrap().depth, 3);

    database.cleanup().await;
}

/// End-to-end claim-time history scan (design §B.5, W1.2) over the exact
/// production path — real relay loopback, real marker publication, real
/// encrypted persistence — with only the Electrum port scripted: an account
/// used through index 3 claims with `next_child_index` 24 persisted and
/// returned, a re-claim never moves the cursor backwards, and an Electrum
/// outage refuses the claim with `claim_scan_unavailable` and persists
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_claim_persists_the_scanned_start_index_and_refuses_unscanned_claims() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let testnet = build_pubky_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let relay_inbox = testnet.http_relay().local_url().join("inbox").unwrap();

    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(database.pool(), crypto);
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let required_capabilities =
        PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities();
    let service = ManualClaimService::new(
        pubky.clone(),
        Arc::new(RelayLoopbackSessionMinter::new(
            pubky.clone(),
            relay_inbox.clone(),
        )),
        creators.clone(),
        Arc::new(DirectMarkerPublisher),
        // Usage through index 3: window 0 is non-empty, window 1 is empty.
        Arc::new(ScriptedHistory {
            fail: false,
            used_indices: vec![0, 1, 2, 3],
            calls: std::sync::Mutex::new(0),
        }),
        BitcoinNetwork::Testnet,
        receiver_path.clone(),
    );

    let keypair = Keypair::random();
    let homeserver = testnet.homeserver_app().public_key();
    pubky
        .signer(keypair.clone())
        .signup(&homeserver, None)
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", keypair.public_key().z32())).unwrap();
    assert!(!service.account_exists(&creator).await.unwrap());

    let xpub = account_xpub(61, 0);
    let outcome = service
        .claim(ManualClaimRequest {
            auth_token: claim_token(&keypair, &required_capabilities),
            account_xpub: xpub.clone(),
            account_index: 0,
        })
        .await
        .unwrap();
    assert_eq!(outcome.next_child_index, 3 + 1 + 20);
    assert!(service.account_exists(&creator).await.unwrap());
    let persisted: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        persisted, 24,
        "the scanned start index is persisted as the creator's next_child_index"
    );

    // A re-claim of the same account re-scans and refreshes the session, but
    // the cursor never moves backwards.
    let outcome = service
        .claim(ManualClaimRequest {
            auth_token: claim_token(&keypair, &required_capabilities),
            account_xpub: xpub.clone(),
            account_index: 0,
        })
        .await
        .unwrap();
    assert_eq!(outcome.next_child_index, 24);
    let persisted: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(persisted, 24);

    // An Electrum outage refuses the claim with the named reason and
    // persists nothing: an unscanned claim is the P1-A condition.
    let failing_service = ManualClaimService::new(
        pubky.clone(),
        Arc::new(RelayLoopbackSessionMinter::new(pubky.clone(), relay_inbox)),
        creators.clone(),
        Arc::new(DirectMarkerPublisher),
        Arc::new(ScriptedHistory {
            fail: true,
            used_indices: vec![],
            calls: std::sync::Mutex::new(0),
        }),
        BitcoinNetwork::Testnet,
        receiver_path.clone(),
    );
    let stranger = Keypair::random();
    pubky
        .signer(stranger.clone())
        .signup(&homeserver, None)
        .await
        .unwrap();
    let stranger_creator = parse_creator(&format!("pubky{}", stranger.public_key().z32())).unwrap();
    assert_eq!(
        failing_service
            .claim(ManualClaimRequest {
                auth_token: claim_token(&stranger, &required_capabilities),
                account_xpub: account_xpub(62, 0),
                account_index: 0,
            })
            .await,
        Err(ManualClaimError::ClaimScanUnavailable)
    );
    assert!(
        !failing_service
            .account_exists(&stranger_creator)
            .await
            .unwrap(),
        "a refused claim persists nothing"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "only the successful claim's creator exists");

    database.cleanup().await;
}
