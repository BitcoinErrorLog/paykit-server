use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::marketplace_lifecycle::{
        MarketplaceLifecyclePersistence, MarketplaceLifecycleService,
    },
    config::{Config, ConfigEnvironment},
    domain::locks::CreatorPubky,
    http::{
        auth::{SignedServiceAuth, signature_preimage},
        marketplace_lifecycle::marketplace_lifecycle_router,
    },
    persistence::{
        MarketplaceActivationInput, MarketplaceActivationResult,
        MarketplaceLifecyclePersistenceError, MarketplaceResolutionOutcome,
        MarketplaceResolutionResult, MarketplaceVoidResult, PersistenceError,
    },
};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const INVOICE_ID: Uuid = Uuid::from_u128(0x4c6e66c7_8a8b_4d54_b97b_340cedb3e1d0);

#[derive(Clone, Copy)]
enum Outcome {
    Success,
    PrepareExpired,
    LifecycleTerminal,
    InvoiceActive,
    TotalMismatch,
    Conflict,
    NotFound,
    Corrupt,
}

struct FakeStore {
    outcome: Outcome,
}

#[async_trait]
impl MarketplaceLifecyclePersistence for FakeStore {
    async fn activate(
        &self,
        input: MarketplaceActivationInput<'_>,
    ) -> Result<Option<MarketplaceActivationResult>, MarketplaceLifecyclePersistenceError> {
        match self.outcome {
            Outcome::Success => Ok(Some(MarketplaceActivationResult::new(
                input.invoice_id,
                OffsetDateTime::UNIX_EPOCH,
                OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
                input.total_sats,
                true,
            ))),
            Outcome::PrepareExpired => Err(MarketplaceLifecyclePersistenceError::PrepareExpired),
            Outcome::LifecycleTerminal => {
                Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal)
            }
            Outcome::InvoiceActive => Err(MarketplaceLifecyclePersistenceError::InvoiceActive),
            Outcome::TotalMismatch => Err(MarketplaceLifecyclePersistenceError::TotalMismatch),
            Outcome::Conflict => Err(PersistenceError::Conflict.into()),
            Outcome::NotFound => Ok(None),
            Outcome::Corrupt => Err(PersistenceError::CorruptOrMissing.into()),
        }
    }

    async fn void(
        &self,
        _creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<MarketplaceVoidResult>, MarketplaceLifecyclePersistenceError> {
        match self.outcome {
            Outcome::Success => Ok(Some(MarketplaceVoidResult::new(
                invoice_id,
                OffsetDateTime::UNIX_EPOCH,
                true,
            ))),
            Outcome::PrepareExpired => Err(MarketplaceLifecyclePersistenceError::PrepareExpired),
            Outcome::LifecycleTerminal => {
                Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal)
            }
            Outcome::InvoiceActive => Err(MarketplaceLifecyclePersistenceError::InvoiceActive),
            Outcome::TotalMismatch => Err(MarketplaceLifecyclePersistenceError::TotalMismatch),
            Outcome::Conflict => Err(PersistenceError::Conflict.into()),
            Outcome::NotFound => Ok(None),
            Outcome::Corrupt => Err(PersistenceError::CorruptOrMissing.into()),
        }
    }

    async fn resolve(
        &self,
        _creator: &CreatorPubky,
        invoice_id: Uuid,
        outcome: MarketplaceResolutionOutcome,
    ) -> Result<Option<MarketplaceResolutionResult>, MarketplaceLifecyclePersistenceError> {
        match self.outcome {
            Outcome::Success => Ok(Some(MarketplaceResolutionResult::new(
                invoice_id,
                outcome,
                OffsetDateTime::UNIX_EPOCH,
                true,
            ))),
            Outcome::Conflict => Err(MarketplaceLifecyclePersistenceError::ResolutionConflict),
            Outcome::NotFound => Ok(None),
            Outcome::Corrupt => Err(PersistenceError::CorruptOrMissing.into()),
            Outcome::PrepareExpired => Err(MarketplaceLifecyclePersistenceError::PrepareExpired),
            Outcome::LifecycleTerminal => {
                Err(MarketplaceLifecyclePersistenceError::LifecycleTerminal)
            }
            Outcome::InvoiceActive => Err(MarketplaceLifecyclePersistenceError::InvoiceActive),
            Outcome::TotalMismatch => Err(MarketplaceLifecyclePersistenceError::TotalMismatch),
        }
    }
}

fn service(outcome: Outcome) -> Arc<MarketplaceLifecycleService> {
    Arc::new(MarketplaceLifecycleService::new(
        Arc::new(FakeStore { outcome }),
        Duration::from_secs(30 * 60),
    ))
}

fn signed_auth(key: &SigningKey) -> Arc<SignedServiceAuth> {
    let key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    let config = Config::from_toml_and_environment(
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
network = "mainnet"
[electrum]
endpoint = "ssl://electrum.example:50002"
[outbox]
poll_interval = "5s"
"#
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:***@localhost/paykit".into()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".into()),
        },
    )
    .unwrap();
    Arc::new(SignedServiceAuth::from_config(&config))
}

fn signed_request(key: &SigningKey, path: &str, value: serde_json::Value) -> Request<Body> {
    let body = serde_json_canonicalizer::to_vec(&value).unwrap();
    let preimage = signature_preimage("POST", path, &body);
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn signed_activate_and_void_have_closed_success_fixtures() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let router =
        marketplace_lifecycle_router(service(Outcome::Success)).layer(Extension(signed_auth(&key)));
    let activate_path = "/marketplace/payment-requests/activate";
    let response = router
        .clone()
        .oneshot(signed_request(
            &key,
            activate_path,
            serde_json::json!({
                "creator": CREATOR,
                "invoice_id": INVOICE_ID,
                "total_sats": 50_000,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json(response).await,
        serde_json::json!({
            "activated_at": "1970-01-01T00:00:00Z",
            "invoice_id": INVOICE_ID,
            "payment_deadline": "1970-01-02T00:00:00Z",
            "state": "active",
            "total_sats": 50_000,
        })
    );

    let void_path = "/marketplace/payment-requests/void";
    let response = router
        .clone()
        .oneshot(signed_request(
            &key,
            void_path,
            serde_json::json!({"creator": CREATOR, "invoice_id": INVOICE_ID}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json(response).await,
        serde_json::json!({
            "invoice_id": INVOICE_ID,
            "state": "voided",
            "voided_at": "1970-01-01T00:00:00Z",
        })
    );

    let response = router
        .clone()
        .oneshot(signed_request(
            &key,
            activate_path,
            serde_json::json!({
                "creator": CREATOR,
                "invoice_id": INVOICE_ID,
                "total_sats": 50_000,
                "stack_id": "forbidden",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = router
        .oneshot(signed_request(
            &key,
            void_path,
            serde_json::json!({
                "creator": CREATOR,
                "invoice_id": INVOICE_ID,
                "resolved_at": "1970-01-01T00:00:00Z",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signed_resolve_has_closed_success_and_error_fixtures() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let path = "/marketplace/payment-requests/resolve";
    let body = || {
        serde_json::json!({
            "creator": CREATOR,
            "invoice_id": INVOICE_ID,
            "outcome": "abandoned",
        })
    };
    let response = marketplace_lifecycle_router(service(Outcome::Success))
        .layer(Extension(signed_auth(&key)))
        .oneshot(signed_request(&key, path, body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json(response).await,
        serde_json::json!({
            "invoice_id": INVOICE_ID,
            "outcome": "abandoned",
            "resolved_at": "1970-01-01T00:00:00Z",
        })
    );

    for invalid in [
        serde_json::json!({
            "creator": CREATOR,
            "invoice_id": INVOICE_ID,
            "outcome": "cancelled",
        }),
        serde_json::json!({
            "creator": CREATOR,
            "invoice_id": INVOICE_ID,
            "outcome": "abandoned",
            "resolved_at": "1970-01-01T00:00:00Z",
        }),
    ] {
        let response = marketplace_lifecycle_router(service(Outcome::Success))
            .layer(Extension(signed_auth(&key)))
            .oneshot(signed_request(&key, path, invalid))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let conflict = marketplace_lifecycle_router(service(Outcome::Conflict))
        .layer(Extension(signed_auth(&key)))
        .oneshot(signed_request(&key, path, body()))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(conflict).await,
        serde_json::json!({"error":{
            "code":"resolution_conflict",
            "message":"business resolution conflicts with persisted outcome"
        }})
    );
}

#[tokio::test]
async fn lifecycle_failures_use_stable_error_fixtures() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let path = "/marketplace/payment-requests/activate";
    let body = || {
        serde_json::json!({
            "creator": CREATOR,
            "invoice_id": INVOICE_ID,
            "total_sats": 50_000,
        })
    };
    for (outcome, code, message) in [
        (
            Outcome::PrepareExpired,
            "prepare_expired",
            "payment preparation expired",
        ),
        (
            Outcome::LifecycleTerminal,
            "lifecycle_terminal",
            "payment lifecycle is already terminal",
        ),
        (
            Outcome::TotalMismatch,
            "total_mismatch",
            "total does not match prepared payment",
        ),
    ] {
        let conflict = marketplace_lifecycle_router(service(outcome))
            .layer(Extension(signed_auth(&key)))
            .oneshot(signed_request(&key, path, body()))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(
            json(conflict).await,
            serde_json::json!({"error":{"code":code,"message":message}})
        );
    }

    let void_path = "/marketplace/payment-requests/void";
    let terminal_void = marketplace_lifecycle_router(service(Outcome::InvoiceActive))
        .layer(Extension(signed_auth(&key)))
        .oneshot(signed_request(
            &key,
            void_path,
            serde_json::json!({"creator": CREATOR, "invoice_id": INVOICE_ID}),
        ))
        .await
        .unwrap();
    assert_eq!(terminal_void.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(terminal_void).await,
        serde_json::json!({"error":{
            "code":"invoice_active",
            "message":"invoice is already active"
        }})
    );

    let absent = marketplace_lifecycle_router(service(Outcome::NotFound))
        .layer(Extension(signed_auth(&key)))
        .oneshot(signed_request(&key, path, body()))
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json(absent).await,
        serde_json::json!({"error":{
            "code":"not_found",
            "message":"requested resource was not found"
        }})
    );

    let corrupt = marketplace_lifecycle_router(service(Outcome::Corrupt))
        .layer(Extension(signed_auth(&key)))
        .oneshot(signed_request(&key, path, body()))
        .await
        .unwrap();
    assert_eq!(corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        json(corrupt).await,
        serde_json::json!({"error":{
            "code":"internal_error",
            "message":"internal server error"
        }})
    );
}
