use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::{
        create_invoice::{SessionValidationError, SessionValidator},
        setup_status::{SetupStatus, SetupStatusService},
    },
    config::{Config, ConfigEnvironment},
    domain::locks::CreatorPubky,
    http::{auth::SignedServiceAuth, setup_status::setup_status_router},
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

struct FakeSessionValidator {
    result: Mutex<Option<Result<(), SessionValidationError>>>,
}

#[async_trait]
impl SessionValidator for FakeSessionValidator {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        self.result.lock().unwrap().take().unwrap()
    }
}

fn service(result: Result<(), SessionValidationError>) -> Arc<SetupStatusService> {
    Arc::new(SetupStatusService::with_timeout(
        Arc::new(FakeSessionValidator {
            result: Mutex::new(Some(result)),
        }),
        Duration::from_secs(1),
    ))
}

fn config_for(key: &SigningKey) -> Config {
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
"#,
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:secret@localhost/paykit".to_owned()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned()),
        },
    )
    .unwrap()
}

fn router(key: &SigningKey, result: Result<(), SessionValidationError>) -> axum::Router {
    setup_status_router(service(result)).layer(Extension(Arc::new(SignedServiceAuth::from_config(
        &config_for(key),
    ))))
}

fn signed_request(key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    let preimage = paykit_server::http::auth::signature_preimage("POST", "/setup/status", &body);
    Request::builder()
        .method(Method::POST)
        .uri("/setup/status")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

fn canonical_body() -> Vec<u8> {
    format!(r#"{{"creator":"{CREATOR}"}}"#).into_bytes()
}

async fn response_body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn signed_status_maps_live_session_outcomes_to_closed_coarse_states() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for (result, expected) in [
        (Ok(()), r#"{"status":"ready"}"#),
        (
            Err(SessionValidationError::Invalid),
            r#"{"status":"setup_required"}"#,
        ),
        (
            Err(SessionValidationError::Unavailable),
            r#"{"status":"unavailable"}"#,
        ),
    ] {
        let response = router(&key, result)
            .oneshot(signed_request(&key, canonical_body()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, expected);
    }
}

#[tokio::test]
async fn status_service_maps_validation_timeout_to_unavailable() {
    struct PendingValidator;
    #[async_trait]
    impl SessionValidator for PendingValidator {
        async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
            std::future::pending().await
        }
    }

    let service =
        SetupStatusService::with_timeout(Arc::new(PendingValidator), Duration::from_millis(1));
    let creator = paykit_server::domain::locks::parse_creator(CREATOR).unwrap();

    assert_eq!(service.status(&creator).await, SetupStatus::Unavailable);
}

#[tokio::test]
async fn status_route_requires_trusted_service_signature_and_closed_canonical_body() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let wrong_key = SigningKey::from_bytes(&[8; 32]);
    let invalid_signature = router(&key, Ok(()))
        .oneshot(signed_request(&wrong_key, canonical_body()))
        .await
        .unwrap();
    assert_eq!(invalid_signature.status(), StatusCode::UNAUTHORIZED);

    for body in [
        format!(r#"{{ "creator":"{CREATOR}" }}"#).into_bytes(),
        format!(r#"{{"creator":"{CREATOR}","unexpected":true}}"#).into_bytes(),
        br#"{"creator":"not-a-pubky"}"#.to_vec(),
    ] {
        let response = router(&key, Ok(()))
            .oneshot(signed_request(&key, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn asset_readiness_requires_the_optional_receiving_permission() {
    use paykit_server::application::create_invoice::{CreatorReceivingProvider, ReceivingDetails};
    use paykit_server::domain::{
        invoice::CriterionAsset, locks::parse_creator, receiving::UsdtAddress,
    };
    use paykit_server::persistence::PersistenceError;
    struct Receiving(bool);
    #[async_trait]
    impl CreatorReceivingProvider for Receiving {
        async fn receiving(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<ReceivingDetails, PersistenceError> {
            if self.0 {
                Ok(ReceivingDetails {
                    bitcoin: None,
                    usdt: Some(
                        UsdtAddress::try_from(
                            "0x2222222222222222222222222222222222222222".to_owned(),
                        )
                        .unwrap(),
                    ),
                })
            } else {
                Err(PersistenceError::InvalidInput)
            }
        }
    }
    for (enabled, approved, expected) in [
        (false, true, SetupStatus::SetupRequired),
        (true, false, SetupStatus::SetupRequired),
        (true, true, SetupStatus::Ready),
    ] {
        let sut = SetupStatusService::new(Arc::new(FakeSessionValidator {
            result: Mutex::new(Some(Ok(()))),
        }))
        .with_receiving(Arc::new(Receiving(approved)), enabled);
        assert_eq!(
            sut.status_for_asset(&parse_creator(CREATOR).unwrap(), CriterionAsset::Usdt)
                .await,
            expected
        );
    }
}

mod receiving_readiness {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use paykit_server::{
        application::{
            create_invoice::{CreatorReceivingProvider, ReceivingDetails},
            setup_status::{AcceptedAsset, AcceptedAssetError},
        },
        domain::{
            invoice::CriterionAsset,
            locks::parse_creator,
            receiving::{BitcoinAccount, UsdtAddress},
        },
        persistence::PersistenceError,
    };
    use zeroize::Zeroizing;

    use super::*;

    const USDT_ADDRESS: &str = "0x2222222222222222222222222222222222222222";

    #[derive(Clone, Copy, Debug)]
    enum Seller {
        BitcoinOnly,
        UsdtOnly,
        Both,
        Neither,
    }

    struct Receiving {
        outcome: Result<Seller, PersistenceError>,
        calls: AtomicUsize,
    }

    impl Receiving {
        fn seller(seller: Seller) -> Arc<Self> {
            Arc::new(Self {
                outcome: Ok(seller),
                calls: AtomicUsize::new(0),
            })
        }

        fn failing(error: PersistenceError) -> Arc<Self> {
            Arc::new(Self {
                outcome: Err(error),
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl CreatorReceivingProvider for Receiving {
        async fn receiving(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<ReceivingDetails, PersistenceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let seller = match &self.outcome {
                Ok(seller) => *seller,
                Err(PersistenceError::InvalidInput) => return Err(PersistenceError::InvalidInput),
                Err(_) => return Err(PersistenceError::Unavailable),
            };
            let bitcoin =
                matches!(seller, Seller::BitcoinOnly | Seller::Both).then(|| BitcoinAccount {
                    xpub: Zeroizing::new("xpub-sentinel".to_owned()),
                    account_index: 0,
                });
            let usdt = matches!(seller, Seller::UsdtOnly | Seller::Both)
                .then(|| UsdtAddress::try_from(USDT_ADDRESS.to_owned()).unwrap());
            Ok(ReceivingDetails { bitcoin, usdt })
        }
    }

    struct Authority(Result<(), SessionValidationError>);

    #[async_trait]
    impl SessionValidator for Authority {
        async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
            self.0
        }
    }

    fn service(
        authority: Result<(), SessionValidationError>,
        receiving: Arc<Receiving>,
        usdt_enabled: bool,
    ) -> SetupStatusService {
        SetupStatusService::with_timeout(Arc::new(Authority(authority)), Duration::from_secs(1))
            .with_receiving(receiving, usdt_enabled)
    }

    fn creator() -> CreatorPubky {
        parse_creator(CREATOR).unwrap()
    }

    #[test]
    fn accepted_asset_parses_only_payment_assets() {
        assert_eq!(AcceptedAsset::parse("BTC"), Ok(AcceptedAsset::Btc));
        assert_eq!(AcceptedAsset::parse("USDT"), Ok(AcceptedAsset::Usdt));
        for value in ["USD", "btc", "usdt", "", " USDT", "USDT ", "ETH"] {
            assert_eq!(
                AcceptedAsset::parse(value),
                Err(AcceptedAssetError::Unsupported),
                "{value:?}"
            );
        }
    }

    #[tokio::test]
    async fn accepted_asset_requires_the_receiving_detail_for_that_asset() {
        use SetupStatus::{Ready, SetupRequired};
        // (seller, usdt_enabled, accepted BTC, accepted USDT)
        let table = [
            (Seller::BitcoinOnly, true, Ready, SetupRequired),
            (Seller::BitcoinOnly, false, Ready, SetupRequired),
            (Seller::UsdtOnly, true, SetupRequired, Ready),
            (Seller::UsdtOnly, false, SetupRequired, SetupRequired),
            (Seller::Both, true, Ready, Ready),
            (Seller::Both, false, Ready, SetupRequired),
            (Seller::Neither, true, SetupRequired, SetupRequired),
            (Seller::Neither, false, SetupRequired, SetupRequired),
        ];
        for (seller, usdt_enabled, btc, usdt) in table {
            let sut = service(Ok(()), Receiving::seller(seller), usdt_enabled);
            assert_eq!(
                sut.status_for_accepted_asset(&creator(), AcceptedAsset::Btc)
                    .await,
                btc,
                "{seller:?} usdt_enabled={usdt_enabled} accepted BTC"
            );
            assert_eq!(
                sut.status_for_accepted_asset(&creator(), AcceptedAsset::Usdt)
                    .await,
                usdt,
                "{seller:?} usdt_enabled={usdt_enabled} accepted USDT"
            );
        }
    }

    /// Pins the denomination semantics that Locks relies on. These expectations
    /// were written by hand and hold on the code before `accepted_asset` existed.
    #[tokio::test]
    async fn asset_denomination_readiness_is_unchanged() {
        use SetupStatus::{Ready, SetupRequired};
        // (seller, usdt_enabled, BTC, USD, USDT)
        let table = [
            (Seller::BitcoinOnly, true, Ready, Ready, Ready),
            (Seller::BitcoinOnly, false, Ready, Ready, SetupRequired),
            (Seller::UsdtOnly, true, Ready, Ready, Ready),
            (
                Seller::UsdtOnly,
                false,
                SetupRequired,
                SetupRequired,
                SetupRequired,
            ),
            (Seller::Both, true, Ready, Ready, Ready),
            (Seller::Both, false, Ready, Ready, SetupRequired),
            (
                Seller::Neither,
                true,
                SetupRequired,
                SetupRequired,
                SetupRequired,
            ),
            (
                Seller::Neither,
                false,
                SetupRequired,
                SetupRequired,
                SetupRequired,
            ),
        ];
        for (seller, usdt_enabled, btc, usd, usdt) in table {
            let sut = service(Ok(()), Receiving::seller(seller), usdt_enabled);
            for (asset, expected) in [
                (CriterionAsset::Btc, btc),
                (CriterionAsset::Usd, usd),
                (CriterionAsset::Usdt, usdt),
            ] {
                assert_eq!(
                    sut.status_for_asset(&creator(), asset).await,
                    expected,
                    "{seller:?} usdt_enabled={usdt_enabled} asset {}",
                    asset.as_str()
                );
            }
        }
    }

    #[tokio::test]
    async fn both_fields_must_pass_together() {
        use SetupStatus::{Ready, SetupRequired};
        // A Bitcoin-only seller is ready for a USDT denomination that Locks
        // converts, but not for USDT as the payment asset.
        let bitcoin_only = service(Ok(()), Receiving::seller(Seller::BitcoinOnly), true);
        for (asset, accepted, expected) in [
            (CriterionAsset::Usdt, AcceptedAsset::Btc, Ready),
            (CriterionAsset::Usdt, AcceptedAsset::Usdt, SetupRequired),
            (CriterionAsset::Usd, AcceptedAsset::Btc, Ready),
            (CriterionAsset::Usd, AcceptedAsset::Usdt, SetupRequired),
            (CriterionAsset::Btc, AcceptedAsset::Btc, Ready),
        ] {
            assert_eq!(
                bitcoin_only
                    .status_for_asset_and_accepted_asset(&creator(), asset, accepted)
                    .await,
                expected,
                "Bitcoin-only {} / {}",
                asset.as_str(),
                accepted == AcceptedAsset::Usdt
            );
        }
        let both = service(Ok(()), Receiving::seller(Seller::Both), true);
        for asset in [
            CriterionAsset::Btc,
            CriterionAsset::Usd,
            CriterionAsset::Usdt,
        ] {
            for accepted in [AcceptedAsset::Btc, AcceptedAsset::Usdt] {
                assert_eq!(
                    both.status_for_asset_and_accepted_asset(&creator(), asset, accepted)
                        .await,
                    Ready
                );
            }
        }
        let usdt_only = service(Ok(()), Receiving::seller(Seller::UsdtOnly), true);
        assert_eq!(
            usdt_only
                .status_for_asset_and_accepted_asset(
                    &creator(),
                    CriterionAsset::Usdt,
                    AcceptedAsset::Btc
                )
                .await,
            SetupRequired
        );
        let not_configured = service(Ok(()), Receiving::seller(Seller::Both), false);
        for asset in [CriterionAsset::Btc, CriterionAsset::Usd] {
            assert_eq!(
                not_configured
                    .status_for_asset_and_accepted_asset(&creator(), asset, AcceptedAsset::Usdt)
                    .await,
                SetupRequired
            );
        }
    }

    #[tokio::test]
    async fn authority_is_checked_first_and_receiving_failures_stay_coarse() {
        for (authority, expected) in [
            (
                Err(SessionValidationError::Invalid),
                SetupStatus::SetupRequired,
            ),
            (
                Err(SessionValidationError::Unavailable),
                SetupStatus::Unavailable,
            ),
        ] {
            let receiving = Receiving::seller(Seller::Both);
            let sut = service(authority, receiving.clone(), true);
            assert_eq!(
                sut.status_for_accepted_asset(&creator(), AcceptedAsset::Usdt)
                    .await,
                expected
            );
            assert_eq!(
                sut.status_for_asset_and_accepted_asset(
                    &creator(),
                    CriterionAsset::Usdt,
                    AcceptedAsset::Usdt
                )
                .await,
                expected
            );
            assert_eq!(receiving.calls.load(Ordering::SeqCst), 0);
        }

        let invalid = service(
            Ok(()),
            Receiving::failing(PersistenceError::InvalidInput),
            true,
        );
        assert_eq!(
            invalid
                .status_for_accepted_asset(&creator(), AcceptedAsset::Usdt)
                .await,
            SetupStatus::SetupRequired
        );
        let unreadable = service(
            Ok(()),
            Receiving::failing(PersistenceError::Unavailable),
            true,
        );
        assert_eq!(
            unreadable
                .status_for_accepted_asset(&creator(), AcceptedAsset::Usdt)
                .await,
            SetupStatus::Unavailable
        );
        let without_provider =
            SetupStatusService::with_timeout(Arc::new(Authority(Ok(()))), Duration::from_secs(1));
        assert_eq!(
            without_provider
                .status_for_accepted_asset(&creator(), AcceptedAsset::Btc)
                .await,
            SetupStatus::SetupRequired
        );
    }

    #[tokio::test]
    async fn each_request_reads_the_receiving_details_once() {
        let receiving = Receiving::seller(Seller::Both);
        let sut = service(Ok(()), receiving.clone(), true);
        sut.status_for_asset_and_accepted_asset(
            &creator(),
            CriterionAsset::Usdt,
            AcceptedAsset::Usdt,
        )
        .await;
        assert_eq!(receiving.calls.load(Ordering::SeqCst), 1);
    }

    fn router(key: &SigningKey, seller: Seller, usdt_enabled: bool) -> axum::Router {
        setup_status_router(Arc::new(service(
            Ok(()),
            Receiving::seller(seller),
            usdt_enabled,
        )))
        .layer(Extension(Arc::new(SignedServiceAuth::from_config(
            &config_for(key),
        ))))
    }

    async fn post(
        key: &SigningKey,
        seller: Seller,
        usdt_enabled: bool,
        body: String,
    ) -> (StatusCode, String) {
        let response = router(key, seller, usdt_enabled)
            .oneshot(signed_request(key, body.into_bytes()))
            .await
            .unwrap();
        (response.status(), response_body(response).await)
    }

    const READY: &str = r#"{"status":"ready"}"#;
    const SETUP_REQUIRED: &str = r#"{"status":"setup_required"}"#;

    #[tokio::test]
    async fn route_answers_accepted_asset_per_seller_and_configuration() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for (seller, usdt_enabled, accepted, expected) in [
            (Seller::BitcoinOnly, true, "USDT", SETUP_REQUIRED),
            (Seller::BitcoinOnly, true, "BTC", READY),
            (Seller::Both, true, "USDT", READY),
            (Seller::Both, true, "BTC", READY),
            (Seller::Both, false, "USDT", SETUP_REQUIRED),
            (Seller::UsdtOnly, true, "USDT", READY),
            (Seller::UsdtOnly, true, "BTC", SETUP_REQUIRED),
        ] {
            let body = format!(r#"{{"accepted_asset":"{accepted}","creator":"{CREATOR}"}}"#);
            assert_eq!(
                post(&key, seller, usdt_enabled, body).await,
                (StatusCode::OK, expected.to_owned()),
                "{seller:?} usdt_enabled={usdt_enabled} accepted_asset {accepted}"
            );
        }
    }

    #[tokio::test]
    async fn route_keeps_asset_only_requests_unchanged() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for (seller, usdt_enabled, asset, expected) in [
            (Seller::BitcoinOnly, true, "BTC", READY),
            (Seller::BitcoinOnly, true, "USD", READY),
            (Seller::BitcoinOnly, true, "USDT", READY),
            (Seller::BitcoinOnly, false, "USDT", SETUP_REQUIRED),
            (Seller::UsdtOnly, true, "BTC", READY),
            (Seller::UsdtOnly, false, "USD", SETUP_REQUIRED),
            (Seller::Neither, true, "USD", SETUP_REQUIRED),
        ] {
            let body = format!(r#"{{"asset":"{asset}","creator":"{CREATOR}"}}"#);
            assert_eq!(
                post(&key, seller, usdt_enabled, body).await,
                (StatusCode::OK, expected.to_owned()),
                "{seller:?} usdt_enabled={usdt_enabled} asset {asset}"
            );
        }
        assert_eq!(
            post(
                &key,
                Seller::Neither,
                true,
                format!(r#"{{"creator":"{CREATOR}"}}"#)
            )
            .await,
            (StatusCode::OK, READY.to_owned())
        );
    }

    #[tokio::test]
    async fn route_combines_asset_and_accepted_asset() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for (seller, asset, accepted, expected) in [
            (Seller::BitcoinOnly, "USDT", "USDT", SETUP_REQUIRED),
            (Seller::BitcoinOnly, "USDT", "BTC", READY),
            (Seller::BitcoinOnly, "USD", "USDT", SETUP_REQUIRED),
            (Seller::Both, "USDT", "USDT", READY),
            (Seller::Both, "USD", "USDT", READY),
            (Seller::UsdtOnly, "USDT", "BTC", SETUP_REQUIRED),
        ] {
            let body = format!(
                r#"{{"accepted_asset":"{accepted}","asset":"{asset}","creator":"{CREATOR}"}}"#
            );
            assert_eq!(
                post(&key, seller, true, body).await,
                (StatusCode::OK, expected.to_owned()),
                "{seller:?} asset {asset} accepted_asset {accepted}"
            );
        }
    }

    #[tokio::test]
    async fn route_rejects_unknown_accepted_assets_as_invalid_requests() {
        let key = SigningKey::from_bytes(&[7; 32]);
        for accepted in ["USD", "btc", "usdt", "", "ETH", "USDT "] {
            let body = format!(r#"{{"accepted_asset":"{accepted}","creator":"{CREATOR}"}}"#);
            let (status, body) = post(&key, Seller::Both, true, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{accepted:?}");
            assert!(body.contains("invalid_request"), "{accepted:?}: {body}");
        }
        for body in [
            format!(r#"{{"accepted_asset":"USDT","asset":"DOGE","creator":"{CREATOR}"}}"#),
            format!(r#"{{"accepted_asset":"DOGE","asset":"USDT","creator":"{CREATOR}"}}"#),
            format!(r#"{{"accepted_asset":5,"creator":"{CREATOR}"}}"#),
            format!(
                r#"{{"accepted_asset":"USDT","accepted_assets":["USDT"],"creator":"{CREATOR}"}}"#
            ),
            format!(r#"{{ "accepted_asset":"USDT","creator":"{CREATOR}" }}"#),
            format!(r#"{{"creator":"{CREATOR}","accepted_asset":"USDT"}}"#),
        ] {
            let (status, response) = post(&key, Seller::Both, true, body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(response.contains("invalid_request"), "{body}: {response}");
        }
    }
}
