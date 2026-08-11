use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::payment_request_status::{
        PaymentRequestStatusError, PaymentRequestStatusOperations, PaymentRequestStatusSummary,
        PaymentState,
    },
    config::{Config, ConfigEnvironment},
    domain::{
        locks::{BundleId, CreatorPubky},
        payment_request_lifecycle::PaymentRequestLifecycleState,
    },
    http::{auth::SignedLocksAuth, payment_requests::payment_requests_router},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

#[derive(Clone)]
struct FakeStatus {
    result: Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError>,
}

#[async_trait]
impl PaymentRequestStatusOperations for FakeStatus {
    async fn lookup(
        &self,
        _creator: &CreatorPubky,
        _bundle_id: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError> {
        self.result
    }
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

fn router(
    key: &SigningKey,
    result: Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError>,
) -> axum::Router {
    payment_requests_router(Arc::new(FakeStatus { result })).layer(Extension(Arc::new(
        SignedLocksAuth::from_config(&config_for(key)),
    )))
}

fn body() -> Vec<u8> {
    format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}"}}"#).into_bytes()
}

fn signed_request(key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/payment-requests/status")
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

fn timestamp(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn summary(
    request_state: PaymentRequestLifecycleState,
    payment_state: PaymentState,
) -> PaymentRequestStatusSummary {
    PaymentRequestStatusSummary::new(
        request_state,
        payment_state,
        timestamp("2026-08-11T09:00:00Z"),
        timestamp("2026-08-12T09:00:00Z"),
        3,
        true,
    )
}

#[tokio::test]
async fn per_bundle_status_returns_only_the_exact_orthogonal_facts() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = router(
        &key,
        Ok(Some(summary(
            PaymentRequestLifecycleState::Accepted,
            PaymentState::Confirmed,
        ))),
    )
    .oneshot(signed_request(&key, body()))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        r#"{"request_state":"accepted","payment_state":"confirmed","invoice_created_at":"2026-08-11T09:00:00Z","payment_deadline":"2026-08-12T09:00:00Z","confirmations":3,"amount_matched":true}"#
    );
}

#[tokio::test]
async fn request_and_payment_state_wire_values_are_closed_and_complete() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for state in [
        PaymentRequestLifecycleState::Proposed,
        PaymentRequestLifecycleState::ProposalExpired,
        PaymentRequestLifecycleState::Accepted,
        PaymentRequestLifecycleState::Rejected,
        PaymentRequestLifecycleState::Canceled,
        PaymentRequestLifecycleState::ProofSubmitted,
        PaymentRequestLifecycleState::ActiveRecurring,
        PaymentRequestLifecycleState::RecoveryRequired,
        PaymentRequestLifecycleState::InvalidConflict,
    ] {
        let response = router(&key, Ok(Some(summary(state, PaymentState::Expired))))
            .oneshot(signed_request(&key, body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        assert!(body.contains(&format!(r#""request_state":"{}""#, state.as_str())));
        assert!(body.contains(r#""payment_state":"expired""#));
    }
}

#[tokio::test]
async fn per_bundle_status_requires_signature_and_a_closed_body() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let result = Ok(Some(summary(
        PaymentRequestLifecycleState::Proposed,
        PaymentState::Undetected,
    )));
    let unsigned = router(&key, result)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/payment-requests/status")
                .body(Body::from(body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);

    let invalid = format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}","unexpected":true}}"#)
        .into_bytes();
    let response = router(&key, result)
        .oneshot(signed_request(&key, invalid))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let query_body = body();
    let query = router(&key, result)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/payment-requests/status?bundle_id=forbidden")
                .header(
                    "X-Paykit-Signature",
                    URL_SAFE_NO_PAD.encode(key.sign(&query_body).to_bytes()),
                )
                .body(Body::from(query_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn per_bundle_absence_and_unavailability_use_stable_errors() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let absent = router(&key, Ok(None))
        .oneshot(signed_request(&key, body()))
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_body(absent).await,
        r#"{"error":{"code":"not_found","message":"requested resource was not found"}}"#
    );

    let unavailable = router(&key, Err(PaymentRequestStatusError::Unavailable))
        .oneshot(signed_request(&key, body()))
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_body(unavailable).await,
        r#"{"error":{"code":"unavailable","message":"payment request state is unavailable"}}"#
    );
}
