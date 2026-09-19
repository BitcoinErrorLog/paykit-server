//! Safe-subset gate for the removed legacy manual-claim endpoint.

use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network, OutPoint, Txid,
    bip32::{ChildNumber, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::Secp256k1,
};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::{
    PaykitSdkConfig, PubkyLocalSecretKey, PubkyPublicKey, PubkySessionBootstrap,
    ReceiverNoiseSecretKey, storage::StorageState,
};
use paykit_server::{
    allocation::{CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, decide_allocation},
    application::create_invoice::derive_bip84_p2wpkh_address,
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    domain::locks::{CreatorPubky, parse_creator},
    http::accounts::{AccountsState, accounts_router},
    key_identity::{canonical_key_tail, key_fingerprint},
    manual_claim::{ClaimedKeyLookup, ManualClaimError, ManualClaimService, SessionMinter},
    persistence::{CreatorCredentials, CreatorStore, run_migrations},
    real_setup::DirectMarkerPublisher,
    sentinel::{SentinelFinding, SentinelPolicy, scan_window_addresses},
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky::{AuthToken, Capabilities, Keypair, PubkySession};
use pubky_testnet::EphemeralTestnet;
use tower::ServiceExt;

static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct CountingMinter(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl SessionMinter for CountingMinter {
    async fn mint(
        &self,
        _token_bytes: &[u8],
        _capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ManualClaimError::SessionUnavailable)
    }
}

struct CountingHistory(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ChainHistoryPort for CountingHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![false; scripts.len()])
    }
}

struct UnclaimedKeys;

#[async_trait::async_trait]
impl ClaimedKeyLookup for UnclaimedKeys {
    async fn key_tail_claimed_by_other(
        &self,
        _key_tail: &[u8; 65],
        _creator: &CreatorPubky,
    ) -> Result<bool, ManualClaimError> {
        Ok(false)
    }
}

#[tokio::test]
async fn removed_manual_claim_returns_named_refusal_and_persists_nothing() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let minter_calls = Arc::new(AtomicUsize::new(0));
    let history_calls = Arc::new(AtomicUsize::new(0));
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let service = Arc::new(ManualClaimService::new(
        pubky::Pubky::new().unwrap(),
        Arc::new(CountingMinter(minter_calls.clone())),
        creators,
        Arc::new(UnclaimedKeys),
        Arc::new(DirectMarkerPublisher),
        Arc::new(CountingHistory(history_calls.clone())),
        BitcoinNetwork::Regtest,
        StackRole::Proof,
        "proof:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19".into(),
        PaykitReceiverPath::new("paykit/server").unwrap(),
    ));
    let router = accounts_router(AccountsState::new(service, 10, vec![]));

    let response = router
        .oneshot(
            Request::post("/v0/accounts/claim")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ignored":"legacy payload"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "manual_claim_removed");
    assert_eq!(minter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(history_calls.load(Ordering::SeqCst), 0);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM creators")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0, "removed claims must not persist creator state");

    database.cleanup().await;
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

fn owner_token(keypair: &Keypair, capabilities: &str) -> String {
    let capabilities = Capabilities::try_from(capabilities).unwrap();
    URL_SAFE_NO_PAD.encode(AuthToken::sign(keypair, capabilities).serialize())
}

async fn status(
    router: &axum::Router,
    creator: &CreatorPubky,
    bearer: &str,
) -> (StatusCode, serde_json::Value) {
    let response = router
        .clone()
        .oneshot(
            Request::get(format!("/v0/accounts/{creator}/status"))
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
    )
}

async fn acknowledge(
    router: &axum::Router,
    creator: &CreatorPubky,
    bearer: Option<&str>,
    event_kind: &str,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::post(format!("/v0/accounts/{creator}/alerts/acknowledge"))
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        request = request.header("authorization", format!("Bearer {bearer}"));
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    serde_json::json!({ "event_kind": event_kind }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grant_created_owner_status_evidence_and_alert_acknowledgement_remain_live() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let postgres = pubky_testnet::pubky_homeserver::ConnectionString::new(
        &std::env::var("TEST_DATABASE_URL").unwrap(),
    )
    .unwrap();
    let testnet = EphemeralTestnet::builder()
        .postgres(postgres)
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let required_capabilities =
        PaykitSdkConfig::new(receiver_path.clone()).required_session_capabilities();
    let seller = Keypair::random();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone(), "paykit-server").unwrap();
    let account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(seller.secret()),
            ReceiverNoiseSecretKey::random(),
            &PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key()),
            None,
            &required_capabilities,
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", account.public_key)).unwrap();
    let xpub = account_xpub(104, 3);
    let serialized_xpub = Xpub::from_str(&xpub).unwrap().encode();
    let key_tail = canonical_key_tail(&serialized_xpub);
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let persisted = creators
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                account.export_session_secret().await.unwrap().into_inner(),
                account.access.receiver_noise_secret_key.clone(),
                xpub.clone(),
                3,
            ),
            &StorageState::default(),
            &key_tail,
            &decide_allocation(CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1, 3, false, false),
            0,
        )
        .await
        .unwrap();
    let service = Arc::new(ManualClaimService::new(
        pubky,
        Arc::new(CountingMinter(Arc::new(AtomicUsize::new(0)))),
        creators.clone(),
        Arc::new(UnclaimedKeys),
        Arc::new(DirectMarkerPublisher),
        Arc::new(CountingHistory(Arc::new(AtomicUsize::new(0)))),
        BitcoinNetwork::Testnet,
        StackRole::Proof,
        "proof:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19".into(),
        receiver_path,
    ));
    let router = accounts_router(AccountsState::new(service, 10, vec![]));
    let owner = owner_token(&seller, &required_capabilities);
    let other = owner_token(&Keypair::random(), &required_capabilities);

    let (status_code, body) = status(&router, &creator, &owner).await;
    assert_eq!(status_code, StatusCode::OK, "{body}");
    assert_eq!(body["creator"], creator.to_string());
    assert_eq!(body["allocation_mode"], "exclusive");
    assert_eq!(body["claim_channel"], CLAIM_CHANNEL_BITKIT_WATCH_ONLY_V1);
    assert!(body["downgrade_reason"].is_null());
    assert_eq!(body["key_fingerprint"], key_fingerprint(&serialized_xpub));
    assert_eq!(
        body["first_derived_address"],
        derive_bip84_p2wpkh_address(&xpub, 3, &BitcoinNetwork::Testnet, 0).unwrap()
    );
    assert_eq!(body["account_index"], 3);
    assert_eq!(body["first_child_index"], 0);
    assert_eq!(body["next_child_index"], 0);
    assert_eq!(body["evidence"].as_array().unwrap().len(), 0);
    assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
    assert_eq!(
        status(&router, &creator, &other).await.0,
        StatusCode::FORBIDDEN
    );

    let window = scan_window_addresses(&xpub, 3, &BitcoinNetwork::Testnet, 0, 20).unwrap();
    let first_outpoint = OutPoint::new(Txid::from_byte_array([78; 32]), 1);
    let outcome = creators
        .apply_sentinel_scan(
            persisted.id(),
            &[SentinelFinding::new(
                4,
                window[4].1.clone(),
                first_outpoint,
                550,
                3,
            )],
            &SentinelPolicy::default().thresholds,
        )
        .await
        .unwrap();
    assert!(outcome.downgraded);

    let (status_code, body) = status(&router, &creator, &owner).await;
    assert_eq!(status_code, StatusCode::OK, "{body}");
    assert_eq!(body["allocation_mode"], "shared_manual");
    assert_eq!(body["downgrade_reason"], "unassigned_sentinel_evidence");
    assert_eq!(body["evidence"].as_array().unwrap().len(), 1);
    assert_eq!(body["evidence"][0]["classification"], "evidence");
    assert_eq!(body["evidence"][0]["outpoint"], first_outpoint.to_string());
    assert_eq!(body["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(body["alerts"][0]["event_kind"], "sentinel_downgrade");
    assert_eq!(body["alerts"][0]["reason"], "unassigned_sentinel_evidence");
    assert!(body["alerts"][0]["acknowledged_at"].is_null());

    assert_eq!(
        acknowledge(&router, &creator, None, "sentinel_downgrade")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        acknowledge(&router, &creator, Some(&other), "sentinel_downgrade")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        acknowledge(&router, &creator, Some(&owner), "typo_kind")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status_code, body) =
        acknowledge(&router, &creator, Some(&owner), "sentinel_downgrade").await;
    assert_eq!(status_code, StatusCode::OK, "{body}");
    assert_eq!(body["acknowledged"], true);
    let first_receipt =
        status(&router, &creator, &owner).await.1["alerts"][0]["acknowledged_at"].clone();
    assert!(first_receipt.is_string());
    assert_eq!(
        acknowledge(&router, &creator, Some(&owner), "sentinel_downgrade")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, &creator, &owner).await.1["alerts"][0]["acknowledged_at"],
        first_receipt
    );

    let second = creators
        .apply_sentinel_scan(
            persisted.id(),
            &[SentinelFinding::new(
                5,
                window[5].1.clone(),
                OutPoint::new(Txid::from_byte_array([79; 32]), 2),
                600,
                2,
            )],
            &SentinelPolicy::default().thresholds,
        )
        .await
        .unwrap();
    assert!(!second.downgraded);
    let body = status(&router, &creator, &owner).await.1;
    assert_eq!(body["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(body["evidence"].as_array().unwrap().len(), 2);

    database.cleanup().await;
}
