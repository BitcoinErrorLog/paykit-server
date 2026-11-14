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
    application::marketplace_receipt::{
        MarketplaceReceiptError, MarketplaceReceiptPersistence, MarketplaceReceiptService,
        SellerReceipt, SellerReceiptAmount, StoredSellerReceipt,
    },
    config::{Config, ConfigEnvironment},
    domain::locks::CreatorPubky,
    http::{
        auth::{SignedServiceAuth, signature_preimage},
        marketplace_receipt::marketplace_receipt_router,
    },
};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const PATH: &str = "/marketplace/payment-requests/receipt";
const CREATOR: &str = "pubkygy1wnkhfwezwdnawnur1bc3kw1x3jf5ggjj3cm37e31i5ntq3pco";
const INVOICE_ID: Uuid = Uuid::from_u128(0x4c6e66c7_8a8b_4d54_b97b_340cedb3e1d0);

type Lookup = Result<Option<Option<StoredSellerReceipt>>, MarketplaceReceiptError>;

struct FakeStore {
    result: Lookup,
}

#[async_trait]
impl MarketplaceReceiptPersistence for FakeStore {
    async fn seller_receipt(
        &self,
        _creator: &CreatorPubky,
        invoice_id: Uuid,
    ) -> Result<Option<Option<StoredSellerReceipt>>, MarketplaceReceiptError> {
        assert_eq!(invoice_id, INVOICE_ID);
        self.result.clone()
    }
}

fn stored_receipt() -> StoredSellerReceipt {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "txid".into(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".into(),
    );
    StoredSellerReceipt {
        receipt: SellerReceipt {
            receipt_id: "9b2f3c1e-4d5a-4b6c-8d7e-1f2a3b4c5d6e".into(),
            app_id: "bitkit".into(),
            payment_request_id: "0e2f8c0e-7c43-4a4b-8f1e-35c1d1f0c1a2".into(),
            payment_reference: "7cceb26d-9042-4ea6-bfcb-01bbd778d76e".into(),
            payment_endpoint_identifier: Some("onchain".into()),
            amount: Some(SellerReceiptAmount {
                value: "50000".into(),
                currency: "SAT".into(),
            }),
            metadata,
            issued_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        },
        stored_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2),
    }
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

async fn post(result: Lookup, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let response = marketplace_receipt_router(Arc::new(MarketplaceReceiptService::new(Arc::new(
        FakeStore { result },
    ))))
    .layer(Extension(signed_auth(&key)))
    .oneshot(request)
    .await
    .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn valid_body() -> serde_json::Value {
    serde_json::json!({"creator": CREATOR, "invoice_id": INVOICE_ID})
}

#[tokio::test]
async fn a_stored_seller_receipt_is_reported_in_full() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let (status, body) = post(
        Ok(Some(Some(stored_receipt()))),
        request(&key, valid_body()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "invoice_id": "4c6e66c7-8a8b-4d54-b97b-340cedb3e1d0",
            "receipt": {
                "receipt_id": "9b2f3c1e-4d5a-4b6c-8d7e-1f2a3b4c5d6e",
                "app_id": "bitkit",
                "payment_request_id": "0e2f8c0e-7c43-4a4b-8f1e-35c1d1f0c1a2",
                "payment_reference": "7cceb26d-9042-4ea6-bfcb-01bbd778d76e",
                "payment_endpoint_identifier": "onchain",
                "amount": {"value": "50000", "currency": "SAT"},
                "metadata": {
                    "txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                },
                "issued_at": "1970-01-01T01:00:00Z",
                "stored_at": "1970-01-01T02:00:00Z",
            },
        })
    );
}

#[tokio::test]
async fn a_receipt_without_an_amount_reports_null() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut stored = stored_receipt();
    stored.receipt.amount = None;
    stored.receipt.payment_endpoint_identifier = None;
    let (status, body) = post(Ok(Some(Some(stored))), request(&key, valid_body())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["receipt"]["amount"], serde_json::Value::Null);
    assert_eq!(
        body["receipt"]["payment_endpoint_identifier"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn an_invoice_without_a_seller_receipt_reports_null() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let (status, body) = post(Ok(Some(None)), request(&key, valid_body())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({
            "invoice_id": "4c6e66c7-8a8b-4d54-b97b-340cedb3e1d0",
            "receipt": null,
        })
    );
}

#[tokio::test]
async fn an_unknown_invoice_is_not_found_and_storage_failure_unavailable() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let (status, body) = post(Ok(None), request(&key, valid_body())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");

    let (status, body) = post(
        Err(MarketplaceReceiptError::Unavailable),
        request(&key, valid_body()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "unavailable");
}

#[tokio::test]
async fn malformed_or_unsigned_requests_are_rejected() {
    let key = SigningKey::from_bytes(&[7; 32]);
    for value in [
        serde_json::json!({"creator": CREATOR, "invoice_id": INVOICE_ID, "extra": true}),
        serde_json::json!({"creator": CREATOR}),
        serde_json::json!({"creator": "not-a-pubky", "invoice_id": INVOICE_ID}),
        serde_json::json!({"creator": CREATOR, "invoice_id": "4C6E66C7-8A8B-4D54-B97B-340CEDB3E1D0"}),
    ] {
        let (status, body) = post(Ok(Some(None)), request(&key, value)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_request");
    }

    let mut with_query = request(&key, valid_body());
    *with_query.uri_mut() = format!("{PATH}?invoice_id=forbidden").parse().unwrap();
    let (status, _) = post(Ok(Some(None)), with_query).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let untrusted = SigningKey::from_bytes(&[8; 32]);
    let (status, _) = post(Ok(Some(None)), request(&untrusted, valid_body())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
