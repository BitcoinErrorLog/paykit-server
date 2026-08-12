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
    application::payment_drain::{
        PaymentDrainCleanupToken, PaymentDrainError, PaymentDrainOperations, PaymentDrainSummary,
    },
    config::{Config, ConfigEnvironment},
    domain::locks::PubkyLockResource,
    http::{auth::SignedLocksAuth, payment_drains::payment_drains_router},
};
use tower::ServiceExt;

const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/locks.app/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";

#[derive(Clone)]
struct FakeDrains {
    create: Result<PaymentDrainSummary, PaymentDrainError>,
    lookup: Result<Option<PaymentDrainSummary>, PaymentDrainError>,
    cleanup: Result<(), PaymentDrainError>,
}

#[async_trait]
impl PaymentDrainOperations for FakeDrains {
    async fn create(
        &self,
        _lock_resource: &PubkyLockResource,
    ) -> Result<PaymentDrainSummary, PaymentDrainError> {
        self.create
    }

    async fn lookup(
        &self,
        _lock_resource: &PubkyLockResource,
    ) -> Result<Option<PaymentDrainSummary>, PaymentDrainError> {
        self.lookup
    }

    async fn cleanup(
        &self,
        _lock_resource: &PubkyLockResource,
        _cleanup_token: PaymentDrainCleanupToken,
    ) -> Result<(), PaymentDrainError> {
        self.cleanup
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

fn router(key: &SigningKey, drains: FakeDrains) -> axum::Router {
    payment_drains_router(Arc::new(drains)).layer(Extension(Arc::new(
        SignedLocksAuth::from_config(&config_for(key)),
    )))
}

fn signed_request(key: &SigningKey, path: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

fn body() -> Vec<u8> {
    format!(r#"{{"lock_resource":"{LOCK_RESOURCE}"}}"#).into_bytes()
}

fn cleanup_body(token: &str) -> Vec<u8> {
    format!(r#"{{"cleanup_token":"{token}","lock_resource":"{LOCK_RESOURCE}"}}"#).into_bytes()
}

fn cleanup_token() -> String {
    PaymentDrainCleanupToken::from_bytes([9; 32]).to_canonical_string()
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

fn completed() -> PaymentDrainSummary {
    PaymentDrainSummary::new(true, 0, 2, 1, PaymentDrainCleanupToken::from_bytes([9; 32]))
}

#[tokio::test]
async fn create_and_lookup_return_the_same_closed_redacted_aggregate() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let drains = FakeDrains {
        create: Ok(completed()),
        lookup: Ok(Some(completed())),
        cleanup: Ok(()),
    };
    let expected = format!(
        r#"{{"status":"completed","accepted_count":0,"terminal_count":2,"cancellation_enqueued_count":1,"cleanup_token":"{}"}}"#,
        cleanup_token()
    );

    for path in ["/payment-request-drains", "/payment-request-drain-lookups"] {
        let response = router(&key, drains.clone())
            .oneshot(signed_request(&key, path, body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        assert_eq!(body, expected);
        assert!(!body.contains(LOCK_RESOURCE));
        assert!(!body.contains("drain_id"));
        assert!(!body.contains("replayed"));
    }
}

#[tokio::test]
async fn drain_routes_require_canonical_signature_and_closed_body_only() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let drains = FakeDrains {
        create: Ok(completed()),
        lookup: Ok(Some(completed())),
        cleanup: Ok(()),
    };

    let bad_signature = router(&key, drains.clone())
        .oneshot(signed_request(
            &SigningKey::from_bytes(&[8; 32]),
            "/payment-request-drains",
            body(),
        ))
        .await
        .unwrap();
    assert_eq!(bad_signature.status(), StatusCode::UNAUTHORIZED);

    for invalid in [
        format!(r#"{{ "lock_resource":"{LOCK_RESOURCE}" }}"#).into_bytes(),
        format!(r#"{{"lock_resource":"{LOCK_RESOURCE}","unexpected":true}}"#).into_bytes(),
    ] {
        let response = router(&key, drains.clone())
            .oneshot(signed_request(&key, "/payment-request-drains", invalid))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let query = router(&key, drains)
        .oneshot(signed_request(
            &key,
            "/payment-request-drains?lock_resource=forbidden",
            body(),
        ))
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cleanup_is_signed_query_free_closed_and_idempotent() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let drains = FakeDrains {
        create: Ok(completed()),
        lookup: Ok(None),
        cleanup: Ok(()),
    };
    let token = cleanup_token();
    assert_eq!(token.len(), 43);
    assert_eq!(
        PaymentDrainCleanupToken::parse(&token),
        Some(PaymentDrainCleanupToken::from_bytes([9; 32]))
    );

    for _ in 0..2 {
        let response = router(&key, drains.clone())
            .oneshot(signed_request(
                &key,
                "/payment-request-drain-cleanups",
                cleanup_body(&token),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        assert_eq!(body, r#"{"status":"removed"}"#);
        assert!(!body.contains(LOCK_RESOURCE));
    }

    let query = router(&key, drains.clone())
        .oneshot(signed_request(
            &key,
            "/payment-request-drain-cleanups?lock_resource=forbidden",
            cleanup_body(&token),
        ))
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);

    let unknown =
        format!(r#"{{"cleanup_token":"{token}","extra":true,"lock_resource":"{LOCK_RESOURCE}"}}"#)
            .into_bytes();
    let unknown = router(&key, drains.clone())
        .oneshot(signed_request(
            &key,
            "/payment-request-drain-cleanups",
            unknown,
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    for invalid_token in ["", "CQk=", "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ!"] {
        let invalid = router(&key, drains.clone())
            .oneshot(signed_request(
                &key,
                "/payment-request-drain-cleanups",
                cleanup_body(invalid_token),
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn drain_failures_use_stable_coarse_error_envelopes() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for (error, status, expected) in [
        (
            PaymentDrainError::Conflict,
            StatusCode::CONFLICT,
            r#"{"error":{"code":"conflict","message":"request conflicts with persisted payment state"}}"#,
        ),
        (
            PaymentDrainError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":{"code":"unavailable","message":"payment request state is unavailable"}}"#,
        ),
    ] {
        for path in ["/payment-request-drains", "/payment-request-drain-cleanups"] {
            let response = router(
                &key,
                FakeDrains {
                    create: Err(error),
                    lookup: Err(error),
                    cleanup: Err(error),
                },
            )
            .oneshot(signed_request(
                &key,
                path,
                if path.ends_with("cleanups") {
                    cleanup_body(&cleanup_token())
                } else {
                    body()
                },
            ))
            .await
            .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response_body(response).await, expected);
        }
    }

    let not_found = router(
        &key,
        FakeDrains {
            create: Ok(completed()),
            lookup: Ok(None),
            cleanup: Ok(()),
        },
    )
    .oneshot(signed_request(
        &key,
        "/payment-request-drain-lookups",
        body(),
    ))
    .await
    .unwrap();
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_body(not_found).await,
        r#"{"error":{"code":"not_found","message":"requested resource was not found"}}"#
    );
}
