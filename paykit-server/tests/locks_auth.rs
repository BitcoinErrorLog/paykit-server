use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::Extension,
    http::{Method, Request, StatusCode},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    config::{Config, ConfigEnvironment},
    http::auth::{AuthProcessingObserver, AuthenticatedJson, SignedLocksAuth},
    runtime::{DependencyCheck, Runtime, operational_router},
};
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Default)]
struct ReadyDependency;

#[async_trait::async_trait]
impl DependencyCheck for ReadyDependency {
    async fn postgres_ready(&self) -> bool {
        true
    }
}

#[derive(Deserialize)]
struct TestRequest {
    value: u64,
}

#[derive(Default)]
struct ProcessingCounter {
    signature_verifications: AtomicUsize,
    canonicalizations: AtomicUsize,
}

impl AuthProcessingObserver for ProcessingCounter {
    fn signature_verification_started(&self) {
        self.signature_verifications.fetch_add(1, Ordering::Relaxed);
    }

    fn canonicalization_started(&self) {
        self.canonicalizations.fetch_add(1, Ordering::Relaxed);
    }
}

fn config_for(key: &SigningKey, rate: u64, burst: u64, request_body_bytes: u64) -> Config {
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
request_body_bytes = {request_body_bytes}
[rate_limits]
signed_requests_per_second = {rate}
signed_burst = {burst}
"#,
        ),
        ConfigEnvironment {
            database_url: Some("postgres://paykit:secret@localhost/paykit".to_owned()),
            master_key: Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned()),
        },
    )
    .unwrap()
}

fn router(key: &SigningKey, rate: u64, burst: u64) -> Router {
    let auth = Arc::new(SignedLocksAuth::from_config(&config_for(
        key,
        rate,
        burst,
        16 * 1024,
    )));
    Router::new()
        .route("/test", post(test_endpoint))
        .layer(Extension(auth))
}

fn router_with_observer(
    key: &SigningKey,
    rate: u64,
    burst: u64,
    observer: Arc<dyn AuthProcessingObserver>,
) -> Router {
    let config = config_for(key, rate, burst, 16 * 1024);
    let auth = Arc::new(SignedLocksAuth::with_observer(&config, observer));
    Router::new()
        .route("/test", post(test_endpoint))
        .layer(Extension(auth))
}

async fn test_endpoint(
    AuthenticatedJson(payload): AuthenticatedJson<TestRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({"value": payload.value}))
}

fn signed_request(key: &SigningKey, body: impl Into<Vec<u8>>) -> Request<Body> {
    let body = body.into();
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&body).to_bytes());
    Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("X-Paykit-Signature", signature)
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
async fn missing_malformed_and_invalid_signatures_have_the_same_safe_401_envelope() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let router = router(&key, 100, 200);
    let body = br#"{"value":1}"#;
    let missing = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .body(Body::from(body.as_slice()))
        .unwrap();
    let malformed = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("X-Paykit-Signature", "not_base64!")
        .body(Body::from(body.as_slice()))
        .unwrap();
    let padded = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header(
            "X-Paykit-Signature",
            format!("{}=", URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes())),
        )
        .body(Body::from(body.as_slice()))
        .unwrap();
    let duplicate = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes()),
        )
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(body).to_bytes()),
        )
        .body(Body::from(body.as_slice()))
        .unwrap();
    let invalid = signed_request(&SigningKey::from_bytes(&[8; 32]), body.as_slice());

    for request in [missing, malformed, padded, duplicate, invalid] {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_body(response).await,
            r#"{"error":{"code":"invalid_signature","message":"request authentication failed"}}"#
        );
    }
}

#[tokio::test]
async fn signature_is_verified_over_raw_bytes_before_json_is_parsed() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = router(&key, 100, 200)
        .oneshot(signed_request(&key, br#"{"value":not-json}"#.as_slice()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await,
        r#"{"error":{"code":"invalid_request","message":"request is invalid"}}"#
    );
}

#[tokio::test]
async fn signed_noncanonical_malformed_and_schema_invalid_json_are_safe_400s() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for body in [
        br#"{ "value": 1 }"#.as_slice(),
        br#"{"value":"not-a-number"}"#.as_slice(),
        br#"{"value":1,"value":2}"#.as_slice(),
    ] {
        let response = router(&key, 100, 200)
            .oneshot(signed_request(&key, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_body(response).await,
            r#"{"error":{"code":"invalid_request","message":"request is invalid"}}"#
        );
    }
}

#[tokio::test]
async fn signed_unknown_field_is_rejected_for_a_plain_serde_dto() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = router(&key, 100, 200)
        .oneshot(signed_request(
            &key,
            br#"{"value":1,"unknown":true}"#.as_slice(),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await,
        r#"{"error":{"code":"invalid_request","message":"request is invalid"}}"#
    );
}

#[tokio::test]
async fn raw_body_limit_precedes_signature_and_json_processing() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let oversized = vec![b'x'; 16 * 1024 + 1];
    let request = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .body(Body::from(oversized))
        .unwrap();

    let response = router(&key, 100, 200).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response_body(response).await,
        r#"{"error":{"code":"payload_too_large","message":"request body is too large"}}"#
    );
}

#[tokio::test]
async fn configured_signed_body_limit_is_enforced() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let auth = Arc::new(SignedLocksAuth::from_config(&config_for(&key, 100, 200, 8)));
    let router = Router::new()
        .route("/test", post(test_endpoint))
        .layer(Extension(auth));

    let response = router
        .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn global_signed_request_limiter_allows_burst_then_returns_safe_429() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let router = router(&key, 1, 2);
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = router
        .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "1");
    assert_eq!(
        response_body(response).await,
        r#"{"error":{"code":"rate_limited","message":"request rate limit exceeded"}}"#
    );
}

#[tokio::test]
async fn invalid_and_schema_invalid_requests_do_not_consume_signed_policy_capacity() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let observer = Arc::new(ProcessingCounter::default());
    let router = router_with_observer(&key, 1, 1, observer.clone());

    let wrong_key = SigningKey::from_bytes(&[8; 32]);
    let invalid_requests = [
        Request::builder()
            .method(Method::POST)
            .uri("/test")
            .body(Body::from(br#"{"value":1}"#.as_slice()))
            .unwrap(),
        Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("X-Paykit-Signature", "not_base64!")
            .body(Body::from(br#"{"value":1}"#.as_slice()))
            .unwrap(),
        signed_request(&wrong_key, br#"{"value":1}"#.as_slice()),
        signed_request(&key, br#"{not-json}"#.as_slice()),
        signed_request(&key, br#"{"value":"wrong"}"#.as_slice()),
        signed_request(&key, br#"{"value":1,"unknown":true}"#.as_slice()),
    ];
    for request in invalid_requests {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    let accepted = router
        .clone()
        .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);

    let limited = router
        .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn operational_capacity_rejects_before_signature_verification() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let observer = Arc::new(ProcessingCounter::default());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let auth = Arc::new(SignedLocksAuth::with_observer(
        &config_for(&key, 100, 200, 16 * 1024),
        observer.clone(),
    ));
    let handler_entered = entered.clone();
    let handler_release = release.clone();
    let auth_router = Router::new()
        .route(
            "/test",
            post(
                move |AuthenticatedJson(_): AuthenticatedJson<TestRequest>| {
                    let entered = handler_entered.clone();
                    let release = handler_release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        StatusCode::OK
                    }
                },
            ),
        )
        .layer(Extension(auth));
    let router = operational_router(
        auth_router,
        Arc::new(Runtime::new(Arc::new(ReadyDependency), 1)),
    );

    let entered_wait = entered.notified();
    let first_router = router.clone();
    let first_key = key.clone();
    let first = tokio::spawn(async move {
        first_router
            .oneshot(signed_request(&first_key, br#"{"value":1}"#.as_slice()))
            .await
            .unwrap()
    });
    entered_wait.await;
    assert_eq!(observer.signature_verifications.load(Ordering::Relaxed), 1);

    let rejected = router
        .oneshot(signed_request(&key, br#"{"value":1}"#.as_slice()))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.headers()["retry-after"], "1");
    assert_eq!(observer.signature_verifications.load(Ordering::Relaxed), 1);

    release.notify_one();
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
}

#[test]
fn authentication_state_debug_redacts_the_trusted_public_key() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public_key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    let auth = SignedLocksAuth::from_config(&config_for(&key, 100, 200, 16 * 1024));

    assert!(!format!("{auth:?}").contains(&public_key));
}
