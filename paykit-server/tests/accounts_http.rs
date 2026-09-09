use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::PaykitSdkConfig;
use paykit_server::{
    chain_history::{ChainHistoryPort, ClaimScanError},
    config::{BitcoinNetwork, StackRole},
    crypto::Crypto,
    domain::locks::CreatorPubky,
    http::accounts::{AccountsState, accounts_router},
    manual_claim::{ClaimedKeyLookup, ManualClaimError, ManualClaimService, SessionMinter},
    persistence::CreatorStore,
    real_setup::DirectMarkerPublisher,
};
use pubky::{AuthToken, Capabilities, Keypair, PubkySession};
use tower::ServiceExt;

/// The validation-path tests never reach the session minter or the database:
/// the minter refuses everything and the pool is lazy, so any accidental
/// dependency access fails the test loudly.
struct RefusingMinter;

#[async_trait::async_trait]
impl SessionMinter for RefusingMinter {
    async fn mint(
        &self,
        _token_bytes: &[u8],
        _capabilities: &Capabilities,
    ) -> Result<PubkySession, ManualClaimError> {
        Err(ManualClaimError::SessionUnavailable)
    }
}

/// No key tail is ever claimed by another seller in these validation-path
/// tests (the authoritative binding write is covered by the E2E suite).
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

/// Every scripted window answers empty: the scan passes so these tests keep
/// exercising the boundary they target (validation, minting, rate limits).
struct UnusedHistory;

#[async_trait::async_trait]
impl ChainHistoryPort for UnusedHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[bitcoin::ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        Ok(vec![false; scripts.len()])
    }
}

fn receiver_path() -> PaykitReceiverPath {
    PaykitReceiverPath::new("paykit/server").unwrap()
}

fn required_capabilities() -> String {
    PaykitSdkConfig::new(receiver_path()).required_session_capabilities()
}

fn service() -> Arc<ManualClaimService> {
    service_with_role(StackRole::Production)
}

fn service_with_role(stack_role: StackRole) -> Arc<ManualClaimService> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    Arc::new(ManualClaimService::new(
        pubky::Pubky::new().unwrap(),
        Arc::new(RefusingMinter),
        CreatorStore::new(&pool, crypto),
        Arc::new(UnclaimedKeys),
        Arc::new(DirectMarkerPublisher),
        Arc::new(UnusedHistory),
        BitcoinNetwork::Regtest,
        stack_role,
        format!(
            "{}:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
            stack_role.as_str()
        ),
        receiver_path(),
    ))
}

fn router(claims_per_minute: u64, origins: Vec<String>) -> axum::Router {
    accounts_router(AccountsState::new(service(), claims_per_minute, origins))
}

fn regtest_tpub() -> String {
    use bitcoin::{
        Network,
        bip32::{ChildNumber, Xpriv, Xpub},
        secp256k1::Secp256k1,
    };
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Regtest, &[7; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

fn claim_request(auth_token: &str, xpub: &str, account_index: u32) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v0/accounts/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "auth_token": auth_token,
                "account_xpub": xpub,
                "account_index": account_index,
            })
            .to_string(),
        ))
        .unwrap()
}

async fn error_code(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, body["error"]["code"].as_str().unwrap_or("").into())
}

fn token(keypair: &Keypair, capabilities: &str) -> String {
    let capabilities = Capabilities::try_from(capabilities).unwrap();
    URL_SAFE_NO_PAD.encode(AuthToken::sign(keypair, capabilities).serialize())
}

#[tokio::test]
async fn garbage_and_tampered_tokens_are_unauthorized() {
    let router = router(10, vec![]);
    let (status, code) = error_code(
        router
            .clone()
            .oneshot(claim_request("not-base64!!", &regtest_tpub(), 0))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_token")
    );

    let mut tampered = token(&Keypair::random(), &required_capabilities());
    tampered.replace_range(0..1, if tampered.starts_with('A') { "B" } else { "A" });
    let (status, code) = error_code(
        router
            .oneshot(claim_request(&tampered, &regtest_tpub(), 0))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNAUTHORIZED, "invalid_token")
    );
}

#[tokio::test]
async fn capability_mismatch_is_refused_before_any_session_minting() {
    let router = router(10, vec![]);
    for capabilities in ["/:rw", "/pub/other.app/:rw"] {
        let (status, code) = error_code(
            router
                .clone()
                .oneshot(claim_request(
                    &token(&Keypair::random(), capabilities),
                    &regtest_tpub(),
                    0,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::UNAUTHORIZED, "invalid_capabilities")
        );
    }
}

#[tokio::test]
async fn invalid_xpubs_are_bad_requests() {
    let router = router(10, vec![]);
    let valid_token = token(&Keypair::random(), &required_capabilities());
    for (xpub, account_index) in [
        ("garbage", 0u32),
        // Valid tpub but claimed at the wrong account index.
        (regtest_tpub().as_str(), 1),
    ] {
        let (status, code) = error_code(
            router
                .clone()
                .oneshot(claim_request(&valid_token, xpub, account_index))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (status, code.as_str()),
            (StatusCode::BAD_REQUEST, "invalid_xpub")
        );
    }
}

#[tokio::test]
async fn valid_inputs_reach_the_minter_boundary_and_map_unavailability() {
    let router = router(10, vec![]);
    let (status, code) = error_code(
        router
            .oneshot(claim_request(
                &token(&Keypair::random(), &required_capabilities()),
                &regtest_tpub(),
                0,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "session_unavailable")
    );
}

#[tokio::test]
async fn claims_beyond_the_minute_budget_are_rate_limited() {
    let router = router(2, vec![]);
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(claim_request("junk", &regtest_tpub(), 0))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let (status, code) = error_code(
        router
            .oneshot(claim_request("junk", &regtest_tpub(), 0))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
    );
}

#[tokio::test]
async fn cors_preflight_admits_allowed_origins_and_refuses_others() {
    let router = router(10, vec!["https://shop.example".into()]);
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v0/accounts/claim")
        .header(header::ORIGIN, "https://shop.example")
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(preflight).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("https://shop.example")
    );

    let refused = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v0/accounts/claim")
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(refused).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );

    // Actual claims from the allowed origin carry the CORS header on the
    // response even when the claim itself is rejected.
    let mut claim = claim_request("junk", &regtest_tpub(), 0);
    claim
        .headers_mut()
        .insert(header::ORIGIN, "https://shop.example".parse().unwrap());
    let response = router.clone().oneshot(claim).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("https://shop.example")
    );
}

#[tokio::test]
async fn wildcard_origin_configuration_allows_any_origin() {
    let router = router(10, vec!["*".into()]);
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v0/accounts/claim")
        .header(header::ORIGIN, "https://anywhere.example")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(preflight).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
}

#[tokio::test]
async fn existence_lookup_rejects_non_canonical_creators() {
    let router = router(10, vec![]);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v0/accounts/not-a-creator")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
