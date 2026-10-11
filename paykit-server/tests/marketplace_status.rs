use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use paykit_server::{
    application::marketplace_status::{
        MarketplaceBitcoinStatus, MarketplaceInvoiceStatus, MarketplaceStatusError,
        MarketplaceStatusPersistence, MarketplaceStatusService,
    },
    config::{Config, ConfigEnvironment},
    domain::locks::CreatorPubky,
    http::{
        auth::{SignedServiceAuth, signature_preimage},
        marketplace_status::marketplace_status_router,
    },
};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

// Exact consumer fixture from Marketplace fe76694bb4eebdf2ee48ed928f25cec2296be1f9,
// retained by composed acceptance 20fa6e66474c1f1edc8ab40e51ebb455859b4802.
const CREATOR: &str = "pubkygy1wnkhfwezwdnawnur1bc3kw1x3jf5ggjj3cm37e31i5ntq3pco";
const INVOICE_ID: Uuid = Uuid::from_u128(0x4c6e66c7_8a8b_4d54_b97b_340cedb3e1d0);
const CONSUMER_STATUS_BODY: &str = r#"{"creator":"pubkygy1wnkhfwezwdnawnur1bc3kw1x3jf5ggjj3cm37e31i5ntq3pco","invoice_id":"4c6e66c7-8a8b-4d54-b97b-340cedb3e1d0"}"#;
const CONSUMER_STATUS_SIGNATURE: &str =
    "wis1mgbBnXe1u13cnM9-CUbS4EoT2q39_SlAnyQUgErHnQflpbEwyoM6AkP6wlD5sN-rQx14BVw7CUGSaznUAQ";

struct FakeStore {
    result: Result<Option<MarketplaceInvoiceStatus>, MarketplaceStatusError>,
}

#[async_trait]
impl MarketplaceStatusPersistence for FakeStore {
    async fn status(
        &self,
        _creator: &CreatorPubky,
        _invoice_id: Uuid,
    ) -> Result<Option<MarketplaceInvoiceStatus>, MarketplaceStatusError> {
        self.result.clone()
    }
}

fn active_status() -> MarketplaceInvoiceStatus {
    MarketplaceInvoiceStatus::active(
        INVOICE_ID,
        "delivered",
        Some("accepted"),
        "confirmed",
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
        Some(MarketplaceBitcoinStatus::new(
            "0000000000000000000000000000000000000000000000000000000000000001".into(),
            2,
            50_000,
            OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
            3,
            true,
            true,
            true,
        )),
        Some("paid_manually"),
        Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2)),
    )
}

fn active_status_with(
    request_state: Option<&'static str>,
    payment_state: &'static str,
    bitcoin: Option<MarketplaceBitcoinStatus>,
) -> MarketplaceInvoiceStatus {
    MarketplaceInvoiceStatus::active(
        INVOICE_ID,
        "delivered",
        request_state,
        payment_state,
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
        bitcoin,
        None,
        None,
    )
}

fn bitcoin_status(
    observed_sats: u64,
    confirmations: u32,
    present: bool,
    amount_matched: bool,
    paid_on_time: bool,
) -> MarketplaceBitcoinStatus {
    MarketplaceBitcoinStatus::new(
        "0000000000000000000000000000000000000000000000000000000000000001".into(),
        2,
        observed_sats,
        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        confirmations,
        present,
        amount_matched,
        paid_on_time,
    )
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

fn request(key: &SigningKey, value: serde_json::Value) -> Request<Body> {
    const PATH: &str = "/marketplace/payment-requests/status";
    let body = serde_json_canonicalizer::to_vec(&value).unwrap();
    let preimage = signature_preimage("POST", PATH, &body);
    Request::builder()
        .method(Method::POST)
        .uri(PATH)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

async fn response_body(response: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_str(&response_body(response).await).unwrap()
}

#[tokio::test]
async fn signed_status_has_exact_closed_active_fixture() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let canonical_body = serde_json_canonicalizer::to_string(&serde_json::json!({
        "creator": CREATOR,
        "invoice_id": INVOICE_ID,
    }))
    .unwrap();
    assert_eq!(canonical_body, CONSUMER_STATUS_BODY);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(
            key.sign(&signature_preimage(
                "POST",
                "/marketplace/payment-requests/status",
                canonical_body.as_bytes(),
            ))
            .to_bytes()
        ),
        CONSUMER_STATUS_SIGNATURE
    );
    let router = marketplace_status_router(Arc::new(MarketplaceStatusService::new(Arc::new(
        FakeStore {
            result: Ok(Some(active_status())),
        },
    ))))
    .layer(Extension(signed_auth(&key)));
    let response = router
        .oneshot(request(
            &key,
            serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body(response).await,
        serde_json::json!({
            "activated_at":"1970-01-01T00:00:00Z",
            "bitcoin":{
                "amount_matched":true,
                "confirmations":3,
                "observed_sats":50000,
                "paid_on_time":true,
                "txid":"0000000000000000000000000000000000000000000000000000000000000001"
            },
            "invoice_id":INVOICE_ID,
            "outcome":"paid_manually",
            "payment_deadline":"1970-01-02T00:00:00Z",
            "payment_state":"confirmed",
            "proposal_delivery_state":"delivered",
            "request_state":"accepted",
            "resolved_at":"1970-01-01T02:00:00Z",
            "state":"active"
        })
    );
}

#[tokio::test]
async fn marketplace_consumer_fixtures_are_emitted_by_the_signed_route() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let success_cases = [
        (
            MarketplaceInvoiceStatus::inactive(INVOICE_ID, "prepared", None, None),
            include_str!("../../docs/fixtures/marketplace-payment-request-status/prepared.json"),
        ),
        (
            active_status_with(None, "undetected", None),
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/active-unprojected.json"
            ),
        ),
        (
            active_status_with(Some("proposed"), "undetected", None),
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/proposed-undetected.json"
            ),
        ),
        (
            active_status_with(
                Some("accepted"),
                "detected",
                Some(bitcoin_status(50_000, 0, true, true, true)),
            ),
            include_str!("../../docs/fixtures/marketplace-payment-request-status/detected.json"),
        ),
        (
            active_status_with(
                Some("accepted"),
                "confirmed",
                Some(bitcoin_status(50_000, 3, true, true, true)),
            ),
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/confirmed-matched.json"
            ),
        ),
        (
            active_status_with(
                Some("accepted"),
                "confirmed",
                Some(bitcoin_status(49_999, 3, true, false, false)),
            ),
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/confirmed-unmatched.json"
            ),
        ),
        (
            active_status_with(
                Some("accepted"),
                "expired",
                Some(bitcoin_status(50_000, 3, true, true, false)),
            ),
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/expired-late-match.json"
            ),
        ),
        (
            active_status_with(
                Some("accepted"),
                "undetected",
                Some(bitcoin_status(50_000, 0, false, false, false)),
            ),
            include_str!("../../docs/fixtures/marketplace-payment-request-status/reorged.json"),
        ),
    ];
    for (status, fixture) in success_cases {
        let response = marketplace_status_router(Arc::new(MarketplaceStatusService::new(
            Arc::new(FakeStore {
                result: Ok(Some(status)),
            }),
        )))
        .layer(Extension(signed_auth(&key)))
        .oneshot(request(
            &key,
            serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, fixture.trim_end());
    }

    for (result, expected_status, fixture) in [
        (
            Ok(None),
            StatusCode::NOT_FOUND,
            include_str!("../../docs/fixtures/marketplace-payment-request-status/not-found.json"),
        ),
        (
            Err(MarketplaceStatusError::Conflict),
            StatusCode::CONFLICT,
            include_str!("../../docs/fixtures/marketplace-payment-request-status/conflict.json"),
        ),
        (
            Err(MarketplaceStatusError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            include_str!("../../docs/fixtures/marketplace-payment-request-status/unavailable.json"),
        ),
        (
            Ok(Some(active_status_with(
                Some("recovery_required"),
                "undetected",
                None,
            ))),
            StatusCode::SERVICE_UNAVAILABLE,
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/recovery-required.json"
            ),
        ),
        (
            Ok(Some(active_status_with(
                Some("invalid_conflict"),
                "undetected",
                None,
            ))),
            StatusCode::CONFLICT,
            include_str!(
                "../../docs/fixtures/marketplace-payment-request-status/invalid-conflict.json"
            ),
        ),
    ] {
        let response = marketplace_status_router(Arc::new(MarketplaceStatusService::new(
            Arc::new(FakeStore { result }),
        )))
        .layer(Extension(signed_auth(&key)))
        .oneshot(request(
            &key,
            serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(response_body(response).await, fixture.trim_end());
    }
}

#[tokio::test]
async fn status_rejects_missing_and_untrusted_signatures() {
    let trusted = SigningKey::from_bytes(&[7; 32]);
    let untrusted = SigningKey::from_bytes(&[8; 32]);
    let router = marketplace_status_router(Arc::new(MarketplaceStatusService::new(Arc::new(
        FakeStore {
            result: Ok(Some(active_status())),
        },
    ))))
    .layer(Extension(signed_auth(&trusted)));

    let unsigned = Request::builder()
        .method(Method::POST)
        .uri("/marketplace/payment-requests/status")
        .body(Body::from(CONSUMER_STATUS_BODY))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(unsigned).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router
            .oneshot(request(
                &untrusted,
                serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unrepresentable_persisted_timestamp_is_unavailable() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let unrepresentable = time::Date::from_calendar_date(-1, time::Month::January, 1)
        .unwrap()
        .midnight()
        .assume_utc();
    let status = MarketplaceInvoiceStatus::active(
        INVOICE_ID,
        "delivered",
        Some("accepted"),
        "confirmed",
        unrepresentable,
        unrepresentable,
        None,
        None,
        None,
    );
    let response = marketplace_status_router(Arc::new(MarketplaceStatusService::new(Arc::new(
        FakeStore {
            result: Ok(Some(status)),
        },
    ))))
    .layer(Extension(signed_auth(&key)))
    .oneshot(request(
        &key,
        serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
    ))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body(response).await["error"]["code"], "unavailable");
}

#[tokio::test]
async fn status_rejects_unknown_fields_and_maps_closed_errors() {
    let key = SigningKey::from_bytes(&[11; 32]);
    let invalid = marketplace_status_router(Arc::new(MarketplaceStatusService::new(Arc::new(
        FakeStore { result: Ok(None) },
    ))))
    .layer(Extension(signed_auth(&key)))
    .oneshot(request(
        &key,
        serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID,"operation_id":"forbidden"}),
    ))
    .await
    .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let mut query_request = request(
        &key,
        serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
    );
    *query_request.uri_mut() = "/marketplace/payment-requests/status?operation_id=forbidden"
        .parse()
        .unwrap();
    let invalid_query = marketplace_status_router(Arc::new(MarketplaceStatusService::new(
        Arc::new(FakeStore { result: Ok(None) }),
    )))
    .layer(Extension(signed_auth(&key)))
    .oneshot(query_request)
    .await
    .unwrap();
    assert_eq!(invalid_query.status(), StatusCode::BAD_REQUEST);

    for (result, status, code) in [
        (Ok(None), StatusCode::NOT_FOUND, "not_found"),
        (
            Err(MarketplaceStatusError::Conflict),
            StatusCode::CONFLICT,
            "conflict",
        ),
        (
            Err(MarketplaceStatusError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
        (
            Err(MarketplaceStatusError::RecoveryRequired),
            StatusCode::SERVICE_UNAVAILABLE,
            "recovery_required",
        ),
        (
            Err(MarketplaceStatusError::InvalidConflict),
            StatusCode::CONFLICT,
            "invalid_conflict",
        ),
    ] {
        let response = marketplace_status_router(Arc::new(MarketplaceStatusService::new(
            Arc::new(FakeStore { result }),
        )))
        .layer(Extension(signed_auth(&key)))
        .oneshot(request(
            &key,
            serde_json::json!({"creator":CREATOR,"invoice_id":INVOICE_ID}),
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(body(response).await["error"]["code"], code);
    }
}
