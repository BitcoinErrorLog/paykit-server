//! `POST /setup/status` readiness against receiving details stored in PostgreSQL.
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_sdk::{PaykitIdentitySecretKey, PubkyPublicKey};
use paykit_server::{
    application::{
        create_invoice::{SessionValidationError, SessionValidator},
        setup_status::SetupStatusService,
    },
    config::{Config, ConfigEnvironment},
    crypto::Crypto,
    domain::{
        locks::{CreatorPubky, parse_creator},
        receiving::{BitcoinAccount, UsdtAddress},
    },
    http::{auth::SignedServiceAuth, setup_status::setup_status_router},
    persistence::{CreatorCredentials, CreatorStore, run_migrations},
};
use paykit_server_e2e::postgres::TestDatabase;
use tower::ServiceExt;

const READY: &str = r#"{"status":"ready"}"#;
const SETUP_REQUIRED: &str = r#"{"status":"setup_required"}"#;
const USDT_ADDRESS: &str = "0x2222222222222222222222222222222222222222";

/// Authority is whatever the store recorded as completed setup, so each seller's
/// receiving details and authority come from the same PostgreSQL rows.
struct StoredAuthority(CreatorStore);

#[async_trait]
impl SessionValidator for StoredAuthority {
    async fn validate(&self, creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        match self.0.setup_complete(creator).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(SessionValidationError::Invalid),
            Err(_) => Err(SessionValidationError::Unavailable),
        }
    }
}

fn random_creator() -> CreatorPubky {
    let key = pubky::Keypair::random().public_key();
    parse_creator(&PubkyPublicKey::from_public_key(&key).to_app_key()).unwrap()
}

async fn seller(creators: &CreatorStore, bitcoin: bool, usdt: bool) -> CreatorPubky {
    let creator = random_creator();
    creators
        .create(&CreatorCredentials::new(
            creator.clone(),
            "session-secret".to_owned(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            bitcoin.then(|| BitcoinAccount {
                xpub: "xpub-sentinel".to_owned().into(),
                account_index: 0,
            }),
            usdt.then(|| UsdtAddress::try_from(USDT_ADDRESS.to_owned()).unwrap()),
        ))
        .await
        .unwrap();
    creators.mark_setup_complete(&creator).await.unwrap();
    creator
}

fn config(key: &SigningKey) -> Config {
    let key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:8080"
[signed_services]
trusted_public_keys = ["{key}"]
[setup]
allowed_origins = ["https://app.example"]
[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"
[bitcoin]
network = "testnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
[limits]
request_body_bytes = 16384
[rate_limits]
signed_requests_per_second = 100
signed_burst = 200
"#
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:secret@localhost/paykit".to_owned()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned()),
        },
    )
    .unwrap()
}

struct Route {
    signer: SigningKey,
    creators: CreatorStore,
    usdt_enabled: bool,
}

impl Route {
    fn new(creators: &CreatorStore, usdt_enabled: bool) -> Self {
        Self {
            signer: SigningKey::from_bytes(&[7; 32]),
            creators: creators.clone(),
            usdt_enabled,
        }
    }

    async fn ask(&self, body: String) -> (StatusCode, String) {
        let service = SetupStatusService::new(Arc::new(StoredAuthority(self.creators.clone())))
            .with_receiving(Arc::new(self.creators.clone()), self.usdt_enabled);
        let router = setup_status_router(Arc::new(service)).layer(Extension(Arc::new(
            SignedServiceAuth::from_config(&config(&self.signer)),
        )));
        let body = body.into_bytes();
        let preimage =
            paykit_server::http::auth::signature_preimage("POST", "/setup/status", &body);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/setup/status")
            .header(
                "X-Paykit-Signature",
                URL_SAFE_NO_PAD.encode(self.signer.sign(&preimage).to_bytes()),
            )
            .body(Body::from(body))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    async fn ok(&self, body: String) -> String {
        let (status, body) = self.ask(body).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

fn accepted(creator: &CreatorPubky, accepted_asset: &str) -> String {
    format!(r#"{{"accepted_asset":"{accepted_asset}","creator":"{creator}"}}"#)
}

fn denomination(creator: &CreatorPubky, asset: &str) -> String {
    format!(r#"{{"asset":"{asset}","creator":"{creator}"}}"#)
}

fn both(creator: &CreatorPubky, asset: &str, accepted_asset: &str) -> String {
    format!(r#"{{"accepted_asset":"{accepted_asset}","asset":"{asset}","creator":"{creator}"}}"#)
}

#[tokio::test]
async fn accepted_asset_checks_the_receiving_details_stored_for_the_seller() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let bitcoin_only = seller(&creators, true, false).await;
    let usdt_only = seller(&creators, false, true).await;
    let dual = seller(&creators, true, true).await;
    let never_set_up = random_creator();
    let with_usdt = Route::new(&creators, true);
    let without_usdt = Route::new(&creators, false);

    // Bitcoin-only seller: declined USDT.
    assert_eq!(
        with_usdt.ok(accepted(&bitcoin_only, "USDT")).await,
        SETUP_REQUIRED
    );
    assert_eq!(with_usdt.ok(accepted(&bitcoin_only, "BTC")).await, READY);
    // Seller with USDT.
    assert_eq!(with_usdt.ok(accepted(&dual, "USDT")).await, READY);
    assert_eq!(with_usdt.ok(accepted(&dual, "BTC")).await, READY);
    assert_eq!(with_usdt.ok(accepted(&usdt_only, "USDT")).await, READY);
    assert_eq!(
        with_usdt.ok(accepted(&usdt_only, "BTC")).await,
        SETUP_REQUIRED
    );
    // `[usdt]` not configured: the seller's address does not make USDT ready.
    assert_eq!(
        without_usdt.ok(accepted(&dual, "USDT")).await,
        SETUP_REQUIRED
    );
    assert_eq!(
        without_usdt.ok(accepted(&usdt_only, "USDT")).await,
        SETUP_REQUIRED
    );
    assert_eq!(without_usdt.ok(accepted(&dual, "BTC")).await, READY);
    // A wallet that never ran setup.
    for asset in ["BTC", "USDT"] {
        assert_eq!(
            with_usdt.ok(accepted(&never_set_up, asset)).await,
            SETUP_REQUIRED
        );
    }
    database.cleanup().await;
}

#[tokio::test]
async fn asset_denomination_answers_are_unchanged_for_every_seller() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let bitcoin_only = seller(&creators, true, false).await;
    let usdt_only = seller(&creators, false, true).await;
    let dual = seller(&creators, true, true).await;
    let never_set_up = random_creator();
    let with_usdt = Route::new(&creators, true);
    let without_usdt = Route::new(&creators, false);

    // The answers `asset` gave before `accepted_asset` existed, written by hand:
    // any usable receiving detail makes a denomination ready, and a USDT
    // denomination also needs `[usdt]` configured.
    for (route, label, expectations) in [
        (
            &with_usdt,
            "[usdt] configured",
            [
                (&bitcoin_only, [READY, READY, READY]),
                (&usdt_only, [READY, READY, READY]),
                (&dual, [READY, READY, READY]),
                (&never_set_up, [SETUP_REQUIRED; 3]),
            ],
        ),
        (
            &without_usdt,
            "[usdt] not configured",
            [
                (&bitcoin_only, [READY, READY, SETUP_REQUIRED]),
                (&usdt_only, [SETUP_REQUIRED; 3]),
                (&dual, [READY, READY, SETUP_REQUIRED]),
                (&never_set_up, [SETUP_REQUIRED; 3]),
            ],
        ),
    ] {
        for (creator, expected) in expectations {
            for (asset, expected) in ["BTC", "USD", "USDT"].into_iter().zip(expected) {
                assert_eq!(
                    route.ok(denomination(creator, asset)).await,
                    expected,
                    "{label} {asset} {creator}"
                );
            }
        }
    }
    // No asset at all checks authority only.
    for creator in [&bitcoin_only, &usdt_only, &dual] {
        assert_eq!(
            with_usdt.ok(format!(r#"{{"creator":"{creator}"}}"#)).await,
            READY
        );
    }
    assert_eq!(
        with_usdt
            .ok(format!(r#"{{"creator":"{never_set_up}"}}"#))
            .await,
        SETUP_REQUIRED
    );
    database.cleanup().await;
}

#[tokio::test]
async fn both_fields_together_and_unknown_accepted_assets() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let bitcoin_only = seller(&creators, true, false).await;
    let dual = seller(&creators, true, true).await;
    let route = Route::new(&creators, true);

    // The Bitcoin-only seller is ready for a USDT denomination that Locks can
    // convert, but cannot receive USDT.
    assert_eq!(
        route.ok(both(&bitcoin_only, "USDT", "USDT")).await,
        SETUP_REQUIRED
    );
    assert_eq!(route.ok(both(&bitcoin_only, "USDT", "BTC")).await, READY);
    assert_eq!(
        route.ok(both(&bitcoin_only, "USD", "USDT")).await,
        SETUP_REQUIRED
    );
    assert_eq!(route.ok(both(&bitcoin_only, "USD", "BTC")).await, READY);
    for asset in ["BTC", "USD", "USDT"] {
        for accepted_asset in ["BTC", "USDT"] {
            assert_eq!(route.ok(both(&dual, asset, accepted_asset)).await, READY);
        }
    }

    for accepted_asset in ["USD", "btc", "usdt", "", "ETH"] {
        let (status, body) = route.ask(accepted(&dual, accepted_asset)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{accepted_asset:?}");
        assert!(
            body.contains("invalid_request"),
            "{accepted_asset:?}: {body}"
        );
    }
    for body in [
        both(&dual, "DOGE", "USDT"),
        both(&dual, "USDT", "DOGE"),
        format!(r#"{{"accepted_asset":null,"accepted_assets":["USDT"],"creator":"{dual}"}}"#),
    ] {
        let (status, response) = route.ask(body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(response.contains("invalid_request"), "{body}: {response}");
    }
    database.cleanup().await;
}

#[tokio::test]
async fn explicit_null_accepted_asset_is_an_invalid_request_not_an_omission() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let creators = CreatorStore::new(
        database.pool(),
        Arc::new(Crypto::from_master_key(&[1; 32]).unwrap()),
    );
    let no_rails = seller(&creators, false, false).await;
    let bitcoin_only = seller(&creators, true, false).await;
    let dual = seller(&creators, true, true).await;
    let never_set_up = random_creator();
    let route = Route::new(&creators, true);

    // Omission stays the authority-only answer, so a null that decoded as an
    // omission would have made these ready.
    for creator in [&no_rails, &bitcoin_only, &dual] {
        assert_eq!(
            route.ok(format!(r#"{{"creator":"{creator}"}}"#)).await,
            READY
        );
    }
    assert_eq!(
        route.ok(format!(r#"{{"creator":"{never_set_up}"}}"#)).await,
        SETUP_REQUIRED
    );

    for creator in [&no_rails, &bitcoin_only, &dual, &never_set_up] {
        for body in [
            format!(r#"{{"accepted_asset":null,"creator":"{creator}"}}"#),
            format!(r#"{{"accepted_asset":null,"asset":"USDT","creator":"{creator}"}}"#),
        ] {
            let (status, response) = route.ask(body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(response.contains("invalid_request"), "{body}: {response}");
        }
    }
    database.cleanup().await;
}
