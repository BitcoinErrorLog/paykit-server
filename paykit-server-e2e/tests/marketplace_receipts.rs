//! Seller Receipts for Marketplace requests: the Creator's wallet issues a
//! Receipt in the identity's shared SDK state, the server reads it, stores it
//! once, and reports it through the signed receipt route.

use std::time::Duration;

use axum::http::StatusCode;
use paykit_sdk::{PubkyLocalSecretKey, PubkyPublicKey, PubkySessionBootstrap, StorageAdapter};
use paykit_server::{
    application::marketplace_receipt::{SellerReceipt, SellerReceiptAmount},
    config::{PaykitConfig, PaykitNetwork},
    domain::{
        locks::{CreatorPubky, parse_creator, parse_reader},
        receiving::BitcoinAccount,
    },
    paykit::{CreatorSessionProvider, PaykitAdapter, SellerReceiptReads},
    persistence::{CreatorCredentials, CreatorStore, SellerReceiptStored},
};
use pubky_testnet::EphemeralTestnet;
use time::OffsetDateTime;
use uuid::Uuid;

mod common;
#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use common::marketplace_rig::*;

async fn proposal_id(rig: &Rig, invoice: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM outbox WHERE marketplace_preparation_id = $1
           AND intent_kind = 'payment_request_proposal'",
    )
    .bind(Uuid::parse_str(invoice).unwrap())
    .fetch_one(rig.database.pool())
    .await
    .unwrap()
}

async fn creator_id(rig: &Rig) -> Uuid {
    sqlx::query_scalar("SELECT id FROM creators")
        .fetch_one(rig.database.pool())
        .await
        .unwrap()
}

async fn receipt_route(rig: &Rig, creator: &str, invoice: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = rig
        .post(
            RECEIPT,
            serde_json::json!({"creator": creator, "invoice_id": invoice}),
        )
        .await;
    (status, json(&body))
}

fn seller_receipt(receipt_id: &str, payment_request_id: Uuid) -> SellerReceipt {
    let mut metadata = serde_json::Map::new();
    metadata.insert("txid".into(), "ab".repeat(32).into());
    SellerReceipt {
        receipt_id: receipt_id.into(),
        app_id: "bitkit".into(),
        payment_request_id: payment_request_id.to_string(),
        payment_reference: REFERENCE.into(),
        payment_endpoint_identifier: Some("onchain".into()),
        amount: Some(SellerReceiptAmount {
            value: "50000".into(),
            currency: "SAT".into(),
        }),
        metadata,
        issued_at: OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
    }
}

#[tokio::test]
async fn a_seller_receipt_is_stored_once_and_reported_by_the_route() {
    let rig = rig(
        Seller {
            bitcoin: true,
            usdt: false,
        },
        false,
    )
    .await;
    let (status, prepared) = rig
        .prepare("receipt-order", "50000", "BTC", &["BTC"], 3_600)
        .await;
    assert_eq!(status, StatusCode::OK);
    let invoice = invoice_id(&prepared);
    let creator_id = creator_id(&rig).await;

    // A prepared request was never proposed: nothing awaits its Receipt.
    assert!(
        rig.store
            .creators_awaiting_seller_receipts()
            .await
            .unwrap()
            .is_empty()
    );
    let (status, body) = receipt_route(&rig, CREATOR, &invoice).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({"invoice_id": invoice, "receipt": null})
    );

    assert_eq!(
        rig.activate(&invoice, "50000", "BTC").await.0,
        StatusCode::OK
    );
    let request_id = proposal_id(&rig, &invoice).await;
    assert_eq!(
        rig.store.creators_awaiting_seller_receipts().await.unwrap(),
        [creator_id]
    );
    let open = rig
        .store
        .open_seller_receipt_requests(creator_id)
        .await
        .unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].invoice_id.to_string(), invoice);
    // The Payment Request ID is the proposal outbox row, not the invoice.
    assert_eq!(open[0].payment_request_id, request_id.to_string());
    assert_ne!(open[0].payment_request_id, invoice);
    assert_eq!(
        open[0].reader_lookup_hash,
        rig.store.reader_lookup_hash(&reader())
    );

    let first = seller_receipt("9b2f3c1e-4d5a-4b6c-8d7e-1f2a3b4c5d6e", request_id);
    let invoice_uuid = Uuid::parse_str(&invoice).unwrap();
    assert_eq!(
        rig.store
            .store_seller_receipt(creator_id, invoice_uuid, &first)
            .await
            .unwrap(),
        SellerReceiptStored::Stored
    );
    assert_eq!(
        rig.store
            .store_seller_receipt(creator_id, invoice_uuid, &first)
            .await
            .unwrap(),
        SellerReceiptStored::Unchanged
    );
    let second = seller_receipt("0e2f8c0e-7c43-4a4b-8f1e-35c1d1f0c1a2", request_id);
    assert_eq!(
        rig.store
            .store_seller_receipt(creator_id, invoice_uuid, &second)
            .await
            .unwrap(),
        SellerReceiptStored::KeptFirst
    );
    assert!(
        rig.store
            .creators_awaiting_seller_receipts()
            .await
            .unwrap()
            .is_empty()
    );

    let (status, body) = receipt_route(&rig, CREATOR, &invoice).await;
    assert_eq!(status, StatusCode::OK);
    let receipt = &body["receipt"];
    assert_eq!(
        receipt["receipt_id"],
        "9b2f3c1e-4d5a-4b6c-8d7e-1f2a3b4c5d6e"
    );
    assert_eq!(receipt["app_id"], "bitkit");
    assert_eq!(receipt["payment_request_id"], request_id.to_string());
    assert_eq!(receipt["payment_reference"], REFERENCE);
    assert_eq!(receipt["payment_endpoint_identifier"], "onchain");
    assert_eq!(
        receipt["amount"],
        serde_json::json!({"value": "50000", "currency": "SAT"})
    );
    assert_eq!(
        receipt["metadata"],
        serde_json::json!({"txid": "ab".repeat(32)})
    );
    assert_eq!(receipt["issued_at"], "1970-01-01T01:00:00Z");
    assert!(receipt["stored_at"].is_string());

    // The stored row is append-only.
    assert!(
        sqlx::query("DELETE FROM marketplace_seller_receipts")
            .execute(rig.database.pool())
            .await
            .is_err()
    );

    let (status, body) = receipt_route(&rig, CREATOR, &Uuid::new_v4().to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    rig.cleanup().await;
}

#[tokio::test]
async fn a_resolved_request_no_longer_awaits_its_receipt() {
    let rig = rig(
        Seller {
            bitcoin: true,
            usdt: false,
        },
        false,
    )
    .await;
    let (_, prepared) = rig
        .prepare("resolved-order", "50000", "BTC", &["BTC"], 3_600)
        .await;
    let invoice = invoice_id(&prepared);
    assert_eq!(
        rig.activate(&invoice, "50000", "BTC").await.0,
        StatusCode::OK
    );
    assert_eq!(
        rig.store.creators_awaiting_seller_receipts().await.unwrap(),
        [creator_id(&rig).await]
    );
    let (status, _) = rig
        .post(
            "/marketplace/payment-requests/resolve",
            serde_json::json!({"creator": CREATOR, "invoice_id": invoice, "outcome": "refunded"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        rig.store
            .creators_awaiting_seller_receipts()
            .await
            .unwrap()
            .is_empty()
    );
    rig.cleanup().await;
}

/// The Creator's identity on a Pubky testnet: the seller's wallet App
/// (`bitkit`) and the server's grant share its hosted SDK state.
struct SharedIdentity {
    testnet: EphemeralTestnet,
    creator: CreatorPubky,
    wallet: sdk_fixtures::HostedSdk,
    wallet_state: paykit_sdk::PubkySharedStateStorage,
}

impl SharedIdentity {
    /// The identity, and the server's credentials for it.
    async fn new() -> (Self, CreatorCredentials) {
        let postgres = std::env::var("TEST_DATABASE_URL").unwrap();
        let testnet = EphemeralTestnet::builder()
            .postgres(pubky_testnet::pubky_homeserver::ConnectionString::new(&postgres).unwrap())
            .build()
            .await
            .unwrap();
        let client = testnet.sdk().unwrap();
        let root = PubkyLocalSecretKey::new(pubky::Keypair::random().secret_key());
        let home = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
        let wallet_auth = PubkySessionBootstrap::with_pubky(client.clone(), "app.bitkit.wallet")
            .unwrap()
            .sign_up(
                &root,
                &home,
                None,
                paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES,
            )
            .await
            .unwrap();
        let creator = parse_creator(&wallet_auth.public_key.to_app_key()).unwrap();
        let wallet_state = paykit_sdk::PubkySharedStateStorage::new(
            sdk_fixtures::TestSessionProvider::new(wallet_auth.access.clone()),
        );
        let wallet = sdk_fixtures::hosted_sdk(wallet_auth.access, "bitkit", 0).await;
        let grant = PubkySessionBootstrap::with_pubky(client, "app.paykit.server")
            .unwrap()
            .sign_in(&root, paykit_sdk::PAYKIT_SESSION_CAPABILITIES)
            .await
            .unwrap();
        let credentials = CreatorCredentials::new(
            creator.clone(),
            grant
                .export_session_secret()
                .await
                .unwrap()
                .as_str()
                .to_owned(),
            root.derive_paykit_identity_secret_key(1).unwrap(),
            Some(BitcoinAccount {
                xpub: account_xpub().into(),
                account_index: 0,
            }),
            None,
        );
        (
            Self {
                testnet,
                creator,
                wallet,
                wallet_state,
            },
            credentials,
        )
    }

    fn adapter(&self, rig: &Rig, creator_id: Uuid) -> PaykitAdapter {
        let config = PaykitConfig {
            client_id: pubky::ClientId::new("app.paykit.server").unwrap(),
            app_id: paykit_lib::PaykitAppId::new("paykit-server").unwrap(),
            network: PaykitNetwork::Testnet,
            proposal_acceptance_window: Duration::from_secs(3600),
            payment_window: Duration::from_secs(86400),
            conversion_payment_window: Duration::from_secs(3600),
            marketplace_prepare_ttl: Duration::from_secs(15 * 60),
            allowance_intake: false,
            marketplace_seller_receipts: true,
        };
        PaykitAdapter::new(
            creator_id,
            CreatorSessionProvider::with_pubky(
                CreatorStore::new(rig.database.pool(), crypto()),
                self.creator.clone(),
                self.testnet.sdk().unwrap(),
                &config,
            ),
            &config,
        )
        .unwrap()
    }

    async fn issue(
        &self,
        buyer: &PubkyPublicKey,
        payment_request_id: Option<Uuid>,
        metadata: serde_json::Value,
        stored: bool,
    ) -> String {
        let receipt_id = paykit_lib::ReceiptId::new_v4();
        let draft = paykit_lib::ReceiptDraft {
            receipt_id: Some(receipt_id.clone()),
            payment_reference: paykit_lib::PaymentReference::new(REFERENCE).unwrap(),
            payment_request_id: payment_request_id
                .map(|id| paykit_lib::PaymentRequestId::new(id.to_string()).unwrap()),
            billing_period: None,
            payment_endpoint_identifier: None,
            amount: Some(paykit_lib::PaymentAmount::new("50000", "SAT").unwrap()),
            metadata: metadata.as_object().unwrap().clone(),
        };
        self.wallet
            .prepare_receipt_issuance(buyer.clone(), draft)
            .await
            .unwrap();
        if stored {
            // `process_receipt_issuance` uploads the Encrypted Receipt only for a
            // linked buyer, which this rig has none of; record the upload as it does.
            let buyer = buyer.clone();
            let id = receipt_id.as_str().to_owned();
            self.wallet_state
                .transaction(move |tx| {
                    let mut record = tx.receipt_issuance_record(&buyer, &id).unwrap();
                    record.status = paykit_sdk::ReceiptIssuanceStatus::Stored;
                    record.stored_at = Some(chrono::Utc::now());
                    tx.save_receipt_issuance_record(record);
                    Ok(())
                })
                .await
                .unwrap();
        }
        receipt_id.as_str().to_owned()
    }
}

fn random_key() -> PubkyPublicKey {
    PubkyPublicKey::from_public_key(&pubky::Keypair::random().public_key())
}

#[tokio::test]
async fn the_server_reads_the_receipt_the_seller_wallet_issued() {
    let (identity, credentials) = SharedIdentity::new().await;
    let rig = rig_for(credentials, false, Duration::from_secs(15 * 60), None).await;
    let creator = identity.creator.to_string();
    let buyer = random_key();
    let reader = parse_reader(&buyer.to_app_key()).unwrap();
    let (status, prepared) = rig
        .post(
            PREPARE,
            serde_json::json!({
                "creator": creator,
                "reader": reader.to_string(),
                "reference": REFERENCE,
                "operation_id": "wallet-receipt-order",
                "amount": "50000",
                "asset": "BTC",
                "payment_window_seconds": 3_600,
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&prepared)
    );
    let invoice = invoice_id(&prepared);
    let (status, _) = rig
        .post(
            ACTIVATE,
            serde_json::json!({
                "creator": creator,
                "invoice_id": invoice,
                "amount": "50000",
                "asset": "BTC",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let request_id = proposal_id(&rig, &invoice).await;
    let creator_id = creator_id(&rig).await;
    let adapter = identity.adapter(&rig, creator_id);
    // A fresh schedule per read: spacing is covered by the unit tests.
    let read = || async {
        adapter
            .read_seller_receipts(&SellerReceiptReads::new(Duration::ZERO), &rig.store)
            .await
            .unwrap()
    };

    // The seller's other Receipts are listed but never accepted.
    identity
        .issue(
            &random_key(),
            None,
            serde_json::json!({"txid": "11".repeat(32)}),
            true,
        )
        .await;
    identity
        .issue(
            &random_key(),
            Some(request_id),
            serde_json::json!({"txid": "22".repeat(32)}),
            true,
        )
        .await;
    assert_eq!(read().await, 0);
    let (_, body) = receipt_route(&rig, &creator, &invoice).await;
    assert_eq!(body["receipt"], serde_json::Value::Null);

    // A Receipt the wallet has not stored yet is not accepted.
    identity
        .issue(
            &buyer,
            Some(request_id),
            serde_json::json!({"txid": "44".repeat(32)}),
            false,
        )
        .await;
    assert_eq!(read().await, 0);

    let receipt_id = identity
        .issue(
            &buyer,
            Some(request_id),
            serde_json::json!({"payment_hash": "33".repeat(32)}),
            true,
        )
        .await;
    assert_eq!(read().await, 1);
    // Stored: the request no longer awaits a Receipt, so nothing is read again.
    assert_eq!(read().await, 0);

    let (status, body) = receipt_route(&rig, &creator, &invoice).await;
    assert_eq!(status, StatusCode::OK);
    let receipt = &body["receipt"];
    assert_eq!(receipt["receipt_id"], receipt_id);
    assert_eq!(receipt["app_id"], "bitkit");
    assert_eq!(receipt["payment_request_id"], request_id.to_string());
    assert_eq!(receipt["payment_reference"], REFERENCE);
    assert_eq!(
        receipt["amount"],
        serde_json::json!({"value": "50000", "currency": "SAT"})
    );
    assert_eq!(
        receipt["metadata"],
        serde_json::json!({"payment_hash": "33".repeat(32)})
    );
    rig.cleanup().await;
}
