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
    http::{auth::SignedLocksAuth, setup_status::setup_status_router},
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
[locks]
trusted_public_key = "{key}"
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
    setup_status_router(service(result)).layer(Extension(Arc::new(SignedLocksAuth::from_config(
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
async fn status_route_requires_pinned_locks_signature_and_closed_canonical_body() {
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
