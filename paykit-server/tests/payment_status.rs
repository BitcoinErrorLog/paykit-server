use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
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
    application::payment_status::{PaymentStatusService, PersistedPaymentStatus, StatusRepository},
    config::{Config, ConfigEnvironment},
    domain::locks::{BundleId, CreatorPubky},
    http::{auth::SignedLocksAuth, status::status_router},
    persistence::PersistenceError,
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

struct FakeStatusRepository {
    status: Option<PersistedPaymentStatus>,
    calls: AtomicUsize,
}

#[async_trait]
impl StatusRepository for FakeStatusRepository {
    async fn status(
        &self,
        _creator: &CreatorPubky,
        _bundle_id: &BundleId,
    ) -> Result<Option<PersistedPaymentStatus>, PersistenceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.status)
    }
}

fn service(
    status: Option<PersistedPaymentStatus>,
) -> (Arc<PaymentStatusService>, Arc<FakeStatusRepository>) {
    let repository = Arc::new(FakeStatusRepository {
        status,
        calls: AtomicUsize::default(),
    });
    (
        Arc::new(PaymentStatusService::new(repository.clone())),
        repository,
    )
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
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
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

fn router(key: &SigningKey, status: Option<PersistedPaymentStatus>) -> axum::Router {
    let (service, _) = service(status);
    status_router(service).layer(Extension(Arc::new(SignedLocksAuth::from_config(
        &config_for(key),
    ))))
}

fn signed_request(key: &SigningKey) -> Request<Body> {
    signed_request_with_body(
        key,
        format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}"}}"#).into_bytes(),
    )
}

fn signed_request_with_body(key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/transactions/status")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
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
async fn unknown_creator_or_bundle_returns_a_safe_404() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = router(&key, None)
        .oneshot(signed_request(&key))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn known_unobserved_status_is_exactly_undetected() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = router(&key, Some(PersistedPaymentStatus::Undetected))
        .oneshot(signed_request(&key))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        r#"{"status":"undetected","confirmations":0,"amount_matched":false}"#
    );
}

#[tokio::test]
async fn known_observed_statuses_serialize_only_factual_fields() {
    for (status, expected) in [
        (
            PersistedPaymentStatus::Detected {
                confirmations: 0,
                amount_matched: false,
            },
            r#"{"status":"detected","confirmations":0,"amount_matched":false}"#,
        ),
        (
            PersistedPaymentStatus::Confirmed {
                confirmations: 3,
                amount_matched: true,
            },
            r#"{"status":"confirmed","confirmations":3,"amount_matched":true}"#,
        ),
    ] {
        let key = SigningKey::from_bytes(&[7; 32]);
        let response = router(&key, Some(status))
            .oneshot(signed_request(&key))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, expected);
    }
}

#[tokio::test]
async fn status_route_uses_task9_signed_authentication() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let valid = router(&key, Some(PersistedPaymentStatus::Undetected))
        .oneshot(signed_request(&key))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);

    let invalid = router(&key, Some(PersistedPaymentStatus::Undetected))
        .oneshot(signed_request(&SigningKey::from_bytes(&[8; 32])))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_route_rejects_noncanonical_or_nonclosed_bodies() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for body in [
        format!(r#"{{ "bundle_id":"{BUNDLE}","creator":"{CREATOR}" }}"#).into_bytes(),
        format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}","unexpected":true}}"#)
            .into_bytes(),
    ] {
        let response = router(&key, Some(PersistedPaymentStatus::Undetected))
            .oneshot(signed_request_with_body(&key, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn status_service_has_only_the_persisted_status_port() {
    let (service, repository) = service(Some(PersistedPaymentStatus::Undetected));
    let creator = paykit_server::domain::locks::parse_creator(CREATOR).unwrap();
    let bundle_id = paykit_server::domain::locks::parse_bundle_id(BUNDLE).unwrap();

    let response = service.status(&creator, &bundle_id).await.unwrap();

    assert_eq!(response.status(), "undetected");
    assert_eq!(repository.calls.load(Ordering::SeqCst), 1);
}
