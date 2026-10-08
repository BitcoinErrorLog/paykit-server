use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::connection_status::{
        ConnectionBinding, ConnectionBindingRepository, ConnectionStatusError,
        ConnectionStatusService, PaykitConnectionState, PeerConnectionStateRepository,
    },
    config::{Config, ConfigEnvironment},
    domain::locks::{BundleId, CreatorPubky, parse_bundle_id, parse_creator, parse_reader},
    http::{auth::SignedServiceAuth, connection_status::connection_status_router},
    persistence::PersistenceError,
};
use tower::ServiceExt;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const READER: &str = "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo";
const BUNDLE: &str = "000G40R40M30E209185GR38E1W";

struct FakeBindings {
    result: Result<Option<ConnectionBinding>, PersistenceError>,
}

#[async_trait]
impl ConnectionBindingRepository for FakeBindings {
    async fn binding(
        &self,
        _creator: &CreatorPubky,
        _bundle_id: &BundleId,
    ) -> Result<Option<ConnectionBinding>, PersistenceError> {
        self.result.clone()
    }
}

struct FakePeers {
    result: Result<PaykitConnectionState, PersistenceError>,
    calls: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl PeerConnectionStateRepository for FakePeers {
    async fn connection_state(
        &self,
        creator: &CreatorPubky,
        binding: &ConnectionBinding,
    ) -> Result<PaykitConnectionState, PersistenceError> {
        self.calls
            .lock()
            .unwrap()
            .push((creator.to_string(), binding.reader().to_string()));
        self.result
    }
}

fn binding() -> ConnectionBinding {
    ConnectionBinding::new(parse_reader(READER).unwrap())
}

fn service(
    binding_result: Result<Option<ConnectionBinding>, PersistenceError>,
    state_result: Result<PaykitConnectionState, PersistenceError>,
) -> (Arc<ConnectionStatusService>, Arc<FakePeers>) {
    let peers = Arc::new(FakePeers {
        result: state_result,
        calls: Mutex::new(Vec::new()),
    });
    (
        Arc::new(ConnectionStatusService::new(
            Arc::new(FakeBindings {
                result: binding_result,
            }),
            peers.clone(),
        )),
        peers,
    )
}

#[tokio::test]
async fn service_derives_exact_persisted_binding_before_reading_peer_state() {
    let (service, peers) = service(Ok(Some(binding())), Ok(PaykitConnectionState::Connected));

    let response = service
        .status(
            &parse_creator(CREATOR).unwrap(),
            &parse_bundle_id(BUNDLE).unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response, PaykitConnectionState::Connected);
    assert_eq!(
        peers.calls.lock().unwrap().as_slice(),
        [(CREATOR.into(), READER.into())]
    );
}

#[tokio::test]
async fn missing_invoice_binding_is_not_found_without_peer_lookup() {
    let (service, peers) = service(Ok(None), Ok(PaykitConnectionState::Connected));

    let error = service
        .status(
            &parse_creator(CREATOR).unwrap(),
            &parse_bundle_id(BUNDLE).unwrap(),
        )
        .await
        .unwrap_err();

    assert_eq!(error, ConnectionStatusError::NotFound);
    assert!(peers.calls.lock().unwrap().is_empty());
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

fn signed_request(key: &SigningKey, body: Vec<u8>) -> Request<Body> {
    let preimage =
        paykit_server::http::auth::signature_preimage("POST", "/connections/status", &body);
    Request::builder()
        .method(Method::POST)
        .uri("/connections/status")
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

async fn body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn endpoint_returns_full_closed_connection_state_vocabulary() {
    for (state, expected) in [
        (PaykitConnectionState::None, r#"{"state":"none"}"#),
        (PaykitConnectionState::Handshake, r#"{"state":"handshake"}"#),
        (PaykitConnectionState::Connected, r#"{"state":"connected"}"#),
        (
            PaykitConnectionState::RecoveryRequired,
            r#"{"state":"recovery_required"}"#,
        ),
        (PaykitConnectionState::Blocked, r#"{"state":"blocked"}"#),
    ] {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (service, _) = service(Ok(Some(binding())), Ok(state));
        let router = connection_status_router(service).layer(Extension(Arc::new(
            SignedServiceAuth::from_config(&config_for(&key)),
        )));
        let request_body =
            format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}"}}"#).into_bytes();

        let response = router
            .oneshot(signed_request(&key, request_body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await, expected);
    }
}

#[tokio::test]
async fn endpoint_preserves_not_found_storage_and_auth_failures_as_errors() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let request_body = format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}"}}"#).into_bytes();

    let (missing, _) = service(Ok(None), Ok(PaykitConnectionState::None));
    let missing = connection_status_router(missing).layer(Extension(Arc::new(
        SignedServiceAuth::from_config(&config_for(&key)),
    )));
    assert_eq!(
        missing
            .oneshot(signed_request(&key, request_body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let (unavailable, _) = service(
        Err(PersistenceError::Unavailable),
        Ok(PaykitConnectionState::None),
    );
    let unavailable = connection_status_router(unavailable).layer(Extension(Arc::new(
        SignedServiceAuth::from_config(&config_for(&key)),
    )));
    assert_eq!(
        unavailable
            .oneshot(signed_request(&key, request_body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let (service, _) = service(Ok(Some(binding())), Ok(PaykitConnectionState::None));
    let invalid_signature = connection_status_router(service).layer(Extension(Arc::new(
        SignedServiceAuth::from_config(&config_for(&key)),
    )));
    let other_key = SigningKey::from_bytes(&[8; 32]);
    assert_eq!(
        invalid_signature
            .oneshot(signed_request(&other_key, request_body))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn endpoint_rejects_signed_unknown_request_fields() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let (service, peers) = service(Ok(Some(binding())), Ok(PaykitConnectionState::None));
    let router = connection_status_router(service).layer(Extension(Arc::new(
        SignedServiceAuth::from_config(&config_for(&key)),
    )));
    let request_body =
        format!(r#"{{"bundle_id":"{BUNDLE}","creator":"{CREATOR}","reader":"{READER}"}}"#)
            .into_bytes();

    let response = router
        .oneshot(signed_request(&key, request_body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(peers.calls.lock().unwrap().is_empty());
}
