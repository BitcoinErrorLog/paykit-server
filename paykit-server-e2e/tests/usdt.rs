use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{PaykitIdentitySecretKey, PaymentRequestRecord};
use paykit_server::{
    application::{
        payment_request_status::{
            PaymentRequestStatusError, PaymentRequestStatusOperations, PaymentRequestStatusSummary,
        },
        semantic_intent::DeliveryIntentV1,
    },
    crypto::Crypto,
    domain::{
        invoice::CriterionAsset,
        locks::{
            BundleId, CreatorPubky, parse_addressed_lock_resource, parse_bundle_id, parse_creator,
            parse_reader,
        },
        receiving::{USDT_ENDPOINT, UsdtAddress},
    },
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, MarketplaceActivationInput, MarketplacePreparationInput,
        MarketplacePreparationPayloadFactory, MarketplacePreparationPayloads,
        MarketplacePreparationStore, PaymentDrainStore, PersistenceError, run_migrations,
    },
    usdt::{ArbitrumVerifier, PaymentContext, VerificationError},
};
use paykit_server_e2e::postgres::TestDatabase;
use serde_json::{Value, json};
use time::OffsetDateTime;

mod common;

use common::arbitrum::{BLOCK, CREATOR, RECIPIENT, Rpc, fixture, proof, record};

const BUNDLES: [&str; 2] = ["000G40R40M30E209185GR38E1W", "000G40R40M30E209185GR38E2W"];
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";

#[tokio::test]
async fn account_attestation_and_canonical_receipt_are_both_required() {
    let rpc = Rpc::start().await;
    let recipient = UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap();
    let f = fixture(0);
    let context = PaymentContext {
        payer: CREATOR.trim_start_matches("pubky"),
        payee: CREATOR.trim_start_matches("pubky"),
        request_id: f["binding"]["paymentRequestId"].as_str().unwrap(),
        reference: f["binding"]["paymentReference"].as_str().unwrap(),
        recipient: &recipient,
    };
    let valid = proof(0);
    assert!(
        rpc.verifier
            .verify(&context, &valid)
            .await
            .unwrap()
            .is_some()
    );
    for field in ["chain_id", "signature", "receipt_log_index"] {
        let mut wrong = valid.clone();
        wrong.proof.insert(field.into(), json!("0"));
        assert!(matches!(
            rpc.verifier.verify(&context, &wrong).await,
            Err(VerificationError::InvalidProof)
        ));
    }
    assert!(matches!(
        rpc.verifier.verify(&context, &proof(1)).await,
        Err(VerificationError::InvalidProof)
    ));
    let good = rpc.chain.lock().unwrap().clone();
    for mutation in ["token", "recipient", "sender", "reverted"] {
        let mut chain = good.clone();
        match mutation {
            "token" => chain.receipt["logs"][1]["address"] = json!(RECIPIENT),
            "recipient" => chain.receipt["logs"][1]["topics"][2] = json!(BLOCK),
            "sender" => chain.receipt["logs"][1]["topics"][1] = json!(BLOCK),
            _ => chain.receipt["status"] = json!("0x0"),
        }
        *rpc.chain.lock().unwrap() = chain;
        assert!(
            matches!(
                rpc.verifier.verify(&context, &valid).await,
                Err(VerificationError::InvalidProof)
            ),
            "{mutation}"
        );
    }
    *rpc.chain.lock().unwrap() = good;
    rpc.chain.lock().unwrap().reorg = true;
    assert!(
        rpc.verifier
            .verify(&context, &valid)
            .await
            .unwrap()
            .is_none()
    );
    rpc.chain.lock().unwrap().receipt = Value::Null;
    assert!(
        rpc.verifier
            .verify(&context, &valid)
            .await
            .unwrap()
            .is_none()
    );
    rpc.chain.lock().unwrap().unavailable = true;
    assert!(matches!(
        rpc.verifier.verify(&context, &valid).await,
        Err(VerificationError::Unavailable)
    ));
}

#[tokio::test]
async fn concurrent_receipt_checks_share_only_fresh_network_state() {
    let rpc = Rpc::start().await;
    let recipient = UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap();
    let f = fixture(0);
    let context = PaymentContext {
        payer: CREATOR.trim_start_matches("pubky"),
        payee: CREATOR.trim_start_matches("pubky"),
        request_id: f["binding"]["paymentRequestId"].as_str().unwrap(),
        reference: f["binding"]["paymentReference"].as_str().unwrap(),
        recipient: &recipient,
    };
    let proof = proof(0);
    let cloned = rpc.verifier.clone();
    let (first, second) = tokio::join!(
        rpc.verifier.verify(&context, &proof),
        cloned.verify(&context, &proof),
    );
    assert!(first.unwrap().is_some());
    assert!(second.unwrap().is_some());
    let count = |method: &str, params: Value| {
        rpc.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, args)| name == method && *args == params)
            .count()
    };
    assert_eq!(count("eth_chainId", json!([])), 1);
    assert_eq!(count("eth_blockNumber", json!([])), 1);
    assert_eq!(
        count("eth_getBlockByNumber", json!(["finalized", false])),
        1
    );
    assert_eq!(
        count(
            "eth_getTransactionReceipt",
            json!([proof.proof["transaction_hash"]])
        ),
        2
    );
    assert_eq!(count("eth_getBlockByNumber", json!(["0x64", false])), 2);

    // A just-mined receipt refreshes an older cached head immediately.
    {
        let mut chain = rpc.chain.lock().unwrap();
        chain.head = 102;
        chain.receipt["blockNumber"] = json!("0x66");
    }
    assert!(cloned.verify(&context, &proof).await.unwrap().is_some());
    assert_eq!(count("eth_blockNumber", json!([])), 2);
    // Receipt and canonical-block checks are never served from the shared snapshot.
    rpc.chain.lock().unwrap().reorg = true;
    assert!(cloned.verify(&context, &proof).await.unwrap().is_none());
    rpc.chain.lock().unwrap().reorg = false;

    tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
    rpc.chain.lock().unwrap().chain_id = 1;
    assert!(matches!(
        cloned.verify(&context, &proof).await,
        Err(VerificationError::Unavailable)
    ));
    rpc.chain.lock().unwrap().chain_id = 42161;
    rpc.chain.lock().unwrap().unavailable = true;
    assert!(matches!(
        rpc.verifier.verify(&context, &proof).await,
        Err(VerificationError::Unavailable)
    ));
    rpc.chain.lock().unwrap().unavailable = false;
    assert!(
        rpc.verifier
            .verify(&context, &proof)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(count("eth_blockNumber", json!([])), 3);
}

struct Payload {
    index: usize,
}
impl InvoicePayloadFactory for Payload {
    fn for_child_index(&self, _index: i64) -> Result<InvoicePayloads, PersistenceError> {
        invoice_payload(self.index, None)
    }
}

struct QuotedPayload {
    index: usize,
}
impl InvoicePayloadFactory for QuotedPayload {
    fn for_child_index(&self, index: i64) -> Result<InvoicePayloads, PersistenceError> {
        invoice_payload(self.index, Some(format!("quoted-btc-{index}")))
    }
}

fn invoice_payload(
    index: usize,
    bitcoin: Option<String>,
) -> Result<InvoicePayloads, PersistenceError> {
    let endpoint = PaymentEndpointIdentifier::new(USDT_ENDPOINT).unwrap();
    let address = UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap();
    let mut identifiers = vec![endpoint.clone()];
    let mut endpoints = std::collections::HashMap::from([(
        endpoint,
        PaymentEndpointPayload::new(address.endpoint().to_string()),
    )]);
    let quoted = bitcoin.is_some();
    if let Some(bitcoin) = bitcoin {
        let id = PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap();
        identifiers.push(id.clone());
        endpoints.insert(
            id,
            PaymentEndpointPayload::new(json!({"value": bitcoin}).to_string()),
        );
    }
    let terms = PaymentRequestTerms::builder(
        PaymentAmount::new(
            if quoted { "0.05" } else { "0.050000" },
            if quoted { "usd" } else { "usdt" },
        )
        .unwrap(),
        PaymentReference::new(
            fixture(index)["binding"]["paymentReference"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
        identifiers,
    )
    .required_app_id(Some(PaykitAppId::new("paykit-server").unwrap()))
    .conversion(quoted.then(|| paykit_lib::PaymentConversion::Fixed {
        rates: vec![
            paykit_lib::ConversionRate {
                asset: "btc".into(),
                value: "0.00001".into(),
            },
            paykit_lib::ConversionRate {
                asset: "usdt".into(),
                value: "1".into(),
            },
        ],
    }))
    .payment_endpoints(Some(endpoints))
    .build()
    .unwrap();
    Ok(InvoicePayloads {
        payment_request_intent: DeliveryIntentV1::payment_request(
            CREATOR.to_owned(),
            PaykitAppId::new("paykit-server").unwrap(),
            &terms,
        )
        .unwrap(),
    })
}

#[tokio::test]
async fn invoices_share_an_address_but_never_share_payment_evidence() {
    let bundles = BUNDLES.map(|value| parse_bundle_id(value).unwrap());
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let creator_id = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            "test-session".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            None,
            Some(UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap()),
        ))
        .await
        .unwrap()
        .id();
    let store = InvoiceStore::new(database.pool(), crypto.clone());
    let mut ids = Vec::new();
    for (index, binding) in BUNDLES.iter().enumerate() {
        let invoice = store
            .create_atomic(AtomicInvoiceInput {
                creator: &creator,
                reader: &parse_reader(CREATOR).unwrap(),
                bundle_binding: binding.as_bytes(),
                lock_resource_binding: b"lock",
                payment_request_binding: binding.as_bytes(),
                invoice_payloads: &Payload { index },

                proposal_acceptance_seconds: 3600,
                payment_window_seconds: 86400,
            })
            .await
            .unwrap();
        let id = invoice.invoice_id();
        ids.push(id);
        // Establish the same durable attribution produced by the SDK lifecycle projection.
        sqlx::query("INSERT INTO payment_request_lifecycles (invoice_id,sdk_payment_request_id,request_state,last_event_at,last_stream_item_id) VALUES ($1,$2,'proof_submitted',NOW(),1)").bind(id).bind(record(index).payment_request_id).execute(database.pool()).await.unwrap();
    }
    let rpc = Rpc::start().await;
    let paid_at = rpc.chain.lock().unwrap().timestamp;
    for (amount, offset, matched) in [
        (49_999, 0, false),
        (50_001, 86_401, false),
        (50_001, 0, true),
    ] {
        {
            let mut chain = rpc.chain.lock().unwrap();
            chain.receipt["logs"][1]["data"] = json!(format!("0x{amount:064x}"));
            chain.timestamp = paid_at + offset;
        }
        store
            .observe_usdt_request(
                creator_id,
                &creator,
                &record(0),
                &rpc.verifier,
                Some(&bundles[0]),
            )
            .await
            .unwrap();
        assert_eq!(
            status(&store, &bundles[0]).await,
            (matched, 2),
            "amount={amount}, offset={offset}"
        );
        let facts = payment_status(&store, &bundles[0]).await;
        assert!(facts.bitcoin().is_none());
        let facts = facts.usdt_arbitrum().unwrap();
        assert_eq!(facts.amount_matched, amount >= 50_000);
        assert_eq!(facts.paid_on_time, offset == 0 && amount >= 50_000);
        assert!(!facts.finalized);
        let contact = store.claim_buyer_contact().await.unwrap();
        assert_eq!(
            contact.is_some(),
            matched,
            "only a verified timely full receipt queues a contact"
        );
        if let Some(contact) = contact {
            assert_eq!(contact.invoice_id, ids[0]);
            store.complete_buyer_contact(&contact).await.unwrap();
        }
        assert!(matches!(
            store.payment_status(&creator, &bundles[0]).await.unwrap(),
            Some(paykit_server::application::payment_status::PersistedPaymentStatus::Undetected)
        ));
    }
    let request_count = rpc.requests.lock().unwrap().len();
    let restarted = InvoiceStore::new(database.pool(), crypto.clone());
    restarted
        .observe_usdt_request(creator_id, &creator, &record(0), &rpc.verifier, None)
        .await
        .unwrap();
    assert_eq!(rpc.requests.lock().unwrap().len(), request_count);
    sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '1 minute' WHERE invoice_id = $1")
        .bind(ids[0]).execute(database.pool()).await.unwrap();
    rpc.chain.lock().unwrap().reorg = true;
    restarted
        .observe_usdt_request(creator_id, &creator, &record(0), &rpc.verifier, None)
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[0]).await, (false, 0));
    rpc.chain.lock().unwrap().reorg = false;
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    restarted
        .observe_usdt_request(creator_id, &creator, &record(0), &rpc.verifier, None)
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[0]).await, (true, 2));
    store.scan_payment_record_integrity().await.unwrap();
    // Chain timestamps have second precision; invoice timestamps retain subsecond precision.
    let mut evidence = record(0);
    let mut incorrect = proof(1);
    incorrect.payment_reference = evidence.payment_proofs[0].payment_reference.clone();
    evidence.payment_proofs = vec![proof(0); 7];
    evidence.payment_proofs.push(incorrect.clone());
    evidence.payment_proofs.push(incorrect);
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &evidence,
            &rpc.verifier,
            Some(&bundles[0]),
        )
        .await
        .unwrap();
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &evidence,
            &rpc.verifier,
            Some(&bundles[0]),
        )
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[0]).await, (true, 2));
    // Check provider failures independently of the conflicting attestations.
    evidence.payment_proofs = vec![proof(0)];
    rpc.chain.lock().unwrap().unavailable = true;
    assert!(matches!(
        store
            .observe_usdt_request(
                creator_id,
                &creator,
                &evidence,
                &rpc.verifier,
                Some(&bundles[0])
            )
            .await,
        Err(PersistenceError::Unavailable)
    ));
    assert_eq!(status(&store, &bundles[0]).await, (true, 2));
    rpc.chain.lock().unwrap().unavailable = false;
    // An independently valid second signature over the same receipt cannot buy another lock.
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(1),
            &rpc.verifier,
            Some(&bundles[1]),
        )
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[1]).await, (false, 0));
    let restarted = InvoiceStore::new(database.pool(), crypto.clone());
    rpc.chain.lock().unwrap().reorg = true;
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &evidence,
            &rpc.verifier,
            Some(&bundles[0]),
        )
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[0]).await, (false, 0));
    let first_match: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT first_amount_matched_observed_at FROM invoices WHERE id=$1")
            .bind(ids[0])
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(first_match.is_some(), "drain history survives a reorg");
    rpc.chain.lock().unwrap().reorg = false;
    rpc.chain.lock().unwrap().finalized = true;
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &evidence,
            &verifier,
            Some(&bundles[0]),
        )
        .await
        .unwrap();
    rpc.chain.lock().unwrap().unavailable = true;
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &evidence,
            &verifier,
            Some(&bundles[0]),
        )
        .await
        .unwrap();
    assert_eq!(status(&store, &bundles[0]).await, (true, 2));
    assert!(
        payment_status(&restarted, &bundles[0])
            .await
            .usdt_arbitrum()
            .unwrap()
            .finalized
    );
    rpc.chain.lock().unwrap().unavailable = false;
    for (finalized, legacy) in [(false, false), (false, true), (true, false)] {
        rpc.chain.lock().unwrap().finalized = finalized;
        let (observation_id, envelope): (uuid::Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT id, observation_envelope FROM usdt_observations WHERE invoice_id = $1",
        )
        .bind(ids[0])
        .fetch_one(database.pool())
        .await
        .unwrap();
        let context = paykit_server::crypto::EnvelopeContext::usdt_observation(
            crypto.lookup_hash(creator.to_string().as_bytes()),
            observation_id,
            ids[0],
        );
        let plaintext = crypto
            .decrypt(
                &context,
                &paykit_server::crypto::EncryptedEnvelope::from_bytes(envelope),
            )
            .unwrap();
        if legacy {
            let envelope = crypto
                .encrypt(&context, &plaintext[..plaintext.len() - 20])
                .unwrap();
            sqlx::query("UPDATE usdt_observations SET observation_envelope = $1 WHERE id = $2")
                .bind(envelope.as_bytes())
                .bind(observation_id)
                .execute(database.pool())
                .await
                .unwrap();
        }
        sqlx::query(
            "UPDATE usdt_observations SET finalized = $1, present = TRUE, confirmations = 2, checked_at = NOW()",
        )
        .bind(finalized)
        .execute(database.pool())
        .await
        .unwrap();
        let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
        let mut evidence = record(0);
        let mut missing = proof(0);
        missing
            .proof
            .insert("transaction_hash".into(), json!(format!("0x{:064x}", 2)));
        evidence.payment_proofs.push(missing);
        rpc.requests.lock().unwrap().clear();
        for _ in 0..3 {
            store
                .observe_usdt_request(creator_id, &creator, &evidence, &verifier, None)
                .await
                .unwrap();
        }
        assert_eq!(
            rpc.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _)| method == "eth_getTransactionReceipt")
                .count(),
            1
        );
        assert_eq!(status(&store, &bundles[0]).await, (true, 2));
        if !finalized {
            let (code, body) =
                status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(body["usdt_arbitrum"]["amount_matched"], true);
            if legacy {
                let envelope: Vec<u8> = sqlx::query_scalar(
                    "SELECT observation_envelope FROM usdt_observations WHERE id = $1",
                )
                .bind(observation_id)
                .fetch_one(database.pool())
                .await
                .unwrap();
                assert_eq!(
                    crypto
                        .decrypt(
                            &context,
                            &paykit_server::crypto::EncryptedEnvelope::from_bytes(envelope)
                        )
                        .unwrap(),
                    plaintext
                );
            }
            // Forced refresh must not reopen discovery of the missing receipt.
            store
                .observe_usdt_request(creator_id, &creator, &evidence, &verifier, None)
                .await
                .unwrap();
            rpc.chain.lock().unwrap().reorg = true;
            let (code, body) =
                status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
            assert_eq!(code, StatusCode::OK);
            assert!(body["usdt_arbitrum"].is_null());
            assert_eq!(status(&store, &bundles[0]).await, (false, 0));
            assert_eq!(
                rpc.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(method, _)| method == "eth_getTransactionReceipt")
                    .count(),
                3,
            );
            rpc.chain.lock().unwrap().reorg = false;
        }
    }
    // Failed background refreshes keep their durable interval, even after restart.
    sqlx::query("UPDATE usdt_observations SET finalized = FALSE, present = TRUE")
        .execute(database.pool())
        .await
        .unwrap();
    rpc.chain.lock().unwrap().unavailable = true;
    for proof_count in [1, 129] {
        sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '2 minutes'")
            .execute(database.pool())
            .await
            .unwrap();
        let mut evidence = record(0);
        evidence.payment_proofs = vec![proof(0); proof_count];
        let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
        rpc.requests.lock().unwrap().clear();
        assert!(
            store
                .observe_usdt_request(creator_id, &creator, &evidence, &verifier, None)
                .await
                .is_err()
        );
        for retry in [
            verifier.clone(),
            ArbitrumVerifier::new(rpc.url.clone()).unwrap(),
        ] {
            store
                .observe_usdt_request(creator_id, &creator, &evidence, &retry, None)
                .await
                .unwrap();
        }
        assert_eq!(
            rpc.requests.lock().unwrap().len(),
            1,
            "one failed background attempt across restart"
        );
        let (code, _) =
            status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
        assert_eq!(
            code,
            StatusCode::SERVICE_UNAVAILABLE,
            "explicit reads cannot use failed refreshes as fresh facts"
        );
        assert_eq!(status(&store, &bundles[0]).await, (true, 2));
    }
    rpc.chain.lock().unwrap().unavailable = false;
    rpc.chain.lock().unwrap().finalized = false;
    // Status checks prioritize owned receipts even when discovery has a full batch ahead of them.
    sqlx::query("UPDATE usdt_observations SET finalized = FALSE, present = TRUE")
        .execute(database.pool())
        .await
        .unwrap();
    let mut evidence = record(0);
    evidence.payment_proofs.extend((1..=8).map(|index| {
        let mut missing = proof(0);
        missing
            .proof
            .insert("transaction_hash".into(), json!(format!("0x{index:064x}")));
        missing
    }));
    rpc.chain.lock().unwrap().reorg = true;
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    rpc.requests.lock().unwrap().clear();
    let (code, body) = status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
    assert_eq!(code, StatusCode::OK);
    assert!(
        body["usdt_arbitrum"].is_null(),
        "owned receipt must be refreshed before new discovery"
    );
    assert_eq!(
        rpc.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "eth_getTransactionReceipt")
            .count(),
        8
    );
    rpc.chain.lock().unwrap().reorg = false;

    // With multiple owned receipts, the status winner is checked first. Unrefreshed
    // survivors cannot support a paid response when a bounded batch removes the others.
    sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '2 minutes'")
        .execute(database.pool())
        .await
        .unwrap();
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    store
        .observe_usdt_request(creator_id, &creator, &record(0), &verifier, None)
        .await
        .unwrap();
    let (observation_id, bytes): (uuid::Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT id, observation_envelope FROM usdt_observations WHERE invoice_id = $1",
    )
    .bind(ids[0])
    .fetch_one(database.pool())
    .await
    .unwrap();
    let creator_hash = crypto.lookup_hash(creator.to_string().as_bytes());
    let plaintext = crypto
        .decrypt(
            &paykit_server::crypto::EnvelopeContext::usdt_observation(
                creator_hash,
                observation_id,
                ids[0],
            ),
            &paykit_server::crypto::EncryptedEnvelope::from_bytes(bytes),
        )
        .unwrap();
    let (_, amount, timestamp, sender): (String, u64, OffsetDateTime, [u8; 20]) =
        postcard::from_bytes(&plaintext).unwrap();
    for reorg in [false, true] {
        for index in 1..=8 {
            let id = uuid::Uuid::new_v4();
            let identity = format!("42161:0x{index:064x}:1");
            let envelope = crypto
                .encrypt(
                    &paykit_server::crypto::EnvelopeContext::usdt_observation(
                        creator_hash,
                        id,
                        ids[0],
                    ),
                    &postcard::to_allocvec(&(identity.clone(), amount, timestamp, sender)).unwrap(),
                )
                .unwrap();
            sqlx::query("INSERT INTO usdt_observations (id, invoice_id, transfer_lookup_hash, observation_envelope, confirmations, present, finalized) VALUES ($1,$2,$3,$4,2,TRUE,FALSE)")
                .bind(id).bind(ids[0]).bind(crypto.usdt_transfer_lookup_hash(identity.as_bytes()).as_bytes().as_slice()).bind(envelope.as_bytes())
                .execute(database.pool()).await.unwrap();
        }
        let mut evidence = record(0);
        evidence.payment_proofs = vec![proof(0); 129];
        rpc.chain.lock().unwrap().reorg = reorg;
        for pass in 0..2 {
            rpc.requests.lock().unwrap().clear();
            let (code, body) =
                status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
            if reorg && pass == 0 {
                assert_eq!(
                    code,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "a remaining unrefreshed winner must not report paid"
                );
            } else {
                assert_eq!(code, StatusCode::OK);
                assert_eq!(body["usdt_arbitrum"].is_object(), !reorg);
            }
            assert!(
                rpc.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(method, _)| method == "eth_getTransactionReceipt")
                    .count()
                    <= 8
            );
        }
        sqlx::query("DELETE FROM usdt_observations WHERE invoice_id = $1 AND id != $2")
            .bind(ids[0])
            .bind(observation_id)
            .execute(database.pool())
            .await
            .unwrap();
    }
    rpc.chain.lock().unwrap().reorg = false;
    // Overflowing discovery does not suppress independently owned receipt refreshes.
    let mut evidence = record(0);
    evidence.payment_proofs = vec![proof(0); 129];
    sqlx::query("UPDATE usdt_observations SET finalized = FALSE")
        .execute(database.pool())
        .await
        .unwrap();
    let mut original = rpc.chain.lock().unwrap().clone();
    original.finalized = false;
    let mut reorg = original.clone();
    reorg.reorg = true;
    let mut wrong_sender = original.clone();
    wrong_sender.receipt["logs"][1]["topics"][1] = json!(BLOCK);
    let mut unavailable = original.clone();
    unavailable.unavailable = true;
    for (chain_state, paid) in [
        (original.clone(), true),
        (unavailable, true),
        (reorg, false),
        (original.clone(), true),
        (wrong_sender, false),
        (original, true),
    ] {
        let unavailable = chain_state.unavailable;
        *rpc.chain.lock().unwrap() = chain_state;
        sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '2 minutes'")
            .execute(database.pool())
            .await
            .unwrap();
        let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
        let result = store
            .observe_usdt_request(creator_id, &creator, &evidence, &verifier, None)
            .await;
        assert_eq!(result.is_err(), unavailable);
        let (code, body) =
            status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
        assert_eq!(
            code,
            if unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        );
        if !unavailable {
            assert_eq!(body["usdt_arbitrum"].is_object(), paid);
        }
        assert_eq!(status(&store, &bundles[0]).await.0, paid);
    }
    // An explicit invoice status read bypasses the present-receipt background interval.
    rpc.chain.lock().unwrap().reorg = true;
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    let (code, body) = status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body["usdt_arbitrum"].is_null());
    assert_eq!(status(&store, &bundles[0]).await, (false, 0));
    // Finalized receipts remain available without contacting an unavailable provider.
    rpc.chain.lock().unwrap().reorg = false;
    rpc.chain.lock().unwrap().finalized = true;
    sqlx::query("UPDATE usdt_observations SET checked_at = NOW() - INTERVAL '2 minutes'")
        .execute(database.pool())
        .await
        .unwrap();
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    let (code, body) = status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["usdt_arbitrum"]["finalized"], true);
    rpc.chain.lock().unwrap().unavailable = true;
    rpc.requests.lock().unwrap().clear();
    let (code, body) = status_response(&store, creator_id, &evidence, &verifier, &bundles[0]).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["usdt_arbitrum"]["finalized"], true);
    assert!(rpc.requests.lock().unwrap().is_empty());
    database.cleanup().await;
}

// Supplies received SDK records at the status port; persistence, RPC, auth and HTTP are real.
struct ReceiptStatus {
    store: InvoiceStore,
    creator_id: uuid::Uuid,
    record: PaymentRequestRecord,
    verifier: ArbitrumVerifier,
}

#[async_trait]
impl PaymentRequestStatusOperations for ReceiptStatus {
    async fn lookup(
        &self,
        creator: &CreatorPubky,
        bundle: &BundleId,
    ) -> Result<Option<PaymentRequestStatusSummary>, PaymentRequestStatusError> {
        self.store
            .observe_usdt_request(
                self.creator_id,
                creator,
                &self.record,
                &self.verifier,
                Some(bundle),
            )
            .await
            .map_err(|_| PaymentRequestStatusError::Unavailable)?;
        PaymentRequestStatusOperations::lookup(&self.store, creator, bundle).await
    }
}

async fn status_response(
    store: &InvoiceStore,
    creator_id: uuid::Uuid,
    record: &PaymentRequestRecord,
    verifier: &ArbitrumVerifier,
    bundle: &BundleId,
) -> (StatusCode, Value) {
    use paykit_server::http::{
        auth::signature_preimage, payment_requests::payment_requests_router,
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let router = payment_requests_router(Arc::new(ReceiptStatus {
        store: store.clone(),
        creator_id,
        record: record.clone(),
        verifier: verifier.clone(),
    }))
    .layer(Extension(common::marketplace_rig::signed_auth(&key)));
    let body =
        serde_json::to_vec(&json!({"creator":CREATOR,"bundle_id":bundle.to_string()})).unwrap();
    let signature = key.sign(&signature_preimage(
        "POST",
        "/payment-requests/status",
        &body,
    ));
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payment-requests/status")
                .header(
                    "X-Paykit-Signature",
                    URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let code = response.status();
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    (code, serde_json::from_slice(&body).unwrap())
}

async fn payment_status(store: &InvoiceStore, bundle: &BundleId) -> PaymentRequestStatusSummary {
    PaymentRequestStatusOperations::lookup(store, &parse_creator(CREATOR).unwrap(), bundle)
        .await
        .unwrap()
        .unwrap()
}

async fn status(store: &InvoiceStore, bundle: &BundleId) -> (bool, u32) {
    payment_status(store, bundle)
        .await
        .usdt_arbitrum()
        .map_or((false, 0), |payment| {
            (
                payment.amount_matched && payment.paid_on_time,
                payment.confirmations,
            )
        })
}

#[tokio::test]
async fn either_quoted_payment_can_settle_without_overwriting_the_other() {
    let bundle = parse_bundle_id(BUNDLES[0]).unwrap();
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let creator_id = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            "test-session".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            None,
            Some(UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap()),
        ))
        .await
        .unwrap()
        .id();
    let store = InvoiceStore::new(database.pool(), crypto.clone());
    let reader = parse_reader(CREATOR).unwrap();
    let payload = QuotedPayload { index: 0 };
    let input = || AtomicInvoiceInput {
        creator: &creator,
        reader: &reader,
        bundle_binding: BUNDLES[0].as_bytes(),
        lock_resource_binding: b"lock",
        payment_request_binding: b"quoted-request",
        invoice_payloads: &payload,
        proposal_acceptance_seconds: 1800,
        payment_window_seconds: 3600,
    };
    let invoice = store.create_atomic(input()).await.unwrap();
    assert_eq!(
        store.create_atomic(input()).await.unwrap().invoice_id(),
        invoice.invoice_id()
    );
    let id = invoice.invoice_id();
    sqlx::query("INSERT INTO payment_request_lifecycles (invoice_id,sdk_payment_request_id,request_state,last_event_at,last_stream_item_id) VALUES ($1,$2,'proof_submitted',NOW(),1)")
        .bind(id).bind(record(0).payment_request_id).execute(database.pool()).await.unwrap();
    let rpc = Rpc::start().await;
    let outpoint =
        paykit_server::domain::payment::BitcoinOutpoint::from_bitcoin(bitcoin::OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            0,
        ));
    let now = invoice.invoice_created_at();
    // 0.05 USD at the stored quote requires exactly 50 sats or 50,000 micro-USDT.
    store
        .apply_bitcoin_observation_at("quoted-btc-0", &outpoint, 49, 1, true, now)
        .await
        .unwrap();
    assert!(
        !payment_status(&store, &bundle)
            .await
            .bitcoin()
            .unwrap()
            .amount_matched
    );
    let matched_outpoint =
        paykit_server::domain::payment::BitcoinOutpoint::from_bitcoin(bitcoin::OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            1,
        ));
    store
        .apply_bitcoin_observation_at("quoted-btc-0", &matched_outpoint, 50, 1, true, now)
        .await
        .unwrap();
    assert_eq!(
        payment_status(&store, &bundle)
            .await
            .bitcoin()
            .unwrap()
            .confirmations,
        1
    );
    rpc.chain.lock().unwrap().receipt["logs"][1]["data"] = json!(format!("0x{:064x}", 49_999));
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    assert_eq!(
        payment_status(&store, &bundle)
            .await
            .bitcoin()
            .unwrap()
            .confirmations,
        1
    );
    rpc.chain.lock().unwrap().receipt["logs"][1]["data"] = json!(format!("0x{:064x}", 50_000));
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    let both = payment_status(&store, &bundle).await;
    assert!(both.bitcoin().unwrap().amount_matched);
    assert_eq!(both.bitcoin().unwrap().confirmations, 1);
    assert!(both.usdt_arbitrum().unwrap().amount_matched);
    assert_eq!(both.usdt_arbitrum().unwrap().confirmations, 2);
    assert!(!both.usdt_arbitrum().unwrap().finalized);
    // Restart and independently reorg either chain; only losing both payments removes satisfaction.
    let restarted = InvoiceStore::new(database.pool(), crypto);
    restarted
        .apply_bitcoin_observation_at("quoted-btc-0", &matched_outpoint, 50, 0, false, now)
        .await
        .unwrap();
    assert_eq!(status(&restarted, &bundle).await, (true, 2));
    rpc.chain.lock().unwrap().reorg = true;
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    assert_eq!(status(&restarted, &bundle).await, (false, 0));
    restarted
        .apply_bitcoin_observation_at("quoted-btc-0", &matched_outpoint, 50, 6, true, now)
        .await
        .unwrap();
    assert_eq!(
        payment_status(&restarted, &bundle)
            .await
            .bitcoin()
            .unwrap()
            .confirmations,
        6
    );
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    assert_eq!(
        payment_status(&restarted, &bundle)
            .await
            .bitcoin()
            .unwrap()
            .confirmations,
        6
    );
    assert!(restarted.observation_targets().await.unwrap().is_empty());
    restarted.scan_payment_record_integrity().await.unwrap();
    database.cleanup().await;
}

#[tokio::test]
async fn timely_usdt_payment_remains_verifiable_after_drain_cleanup() {
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let bundle = parse_bundle_id(BUNDLES[0]).unwrap();
    let lock = parse_addressed_lock_resource(LOCK_RESOURCE).unwrap();
    let creator_id = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            "test-session".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            None,
            Some(UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap()),
        ))
        .await
        .unwrap()
        .id();
    let store = InvoiceStore::new(database.pool(), crypto.clone());
    let invoice = store
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &parse_reader(CREATOR).unwrap(),
            bundle_binding: BUNDLES[0].as_bytes(),
            lock_resource_binding: LOCK_RESOURCE.as_bytes(),
            payment_request_binding: b"quoted-request",
            invoice_payloads: &QuotedPayload { index: 0 },
            proposal_acceptance_seconds: 1800,
            payment_window_seconds: 3600,
        })
        .await
        .unwrap();
    sqlx::query("INSERT INTO payment_request_lifecycles (invoice_id,sdk_payment_request_id,request_state,last_event_at,last_stream_item_id) VALUES ($1,$2,'proof_submitted',NOW(),1)")
        .bind(invoice.invoice_id()).bind(record(0).payment_request_id).execute(database.pool()).await.unwrap();
    let drains = PaymentDrainStore::new(database.pool(), crypto.clone());
    let active = drains.create(&lock).await.unwrap();
    assert_eq!(active.accepted_count(), 1);
    assert!(!active.completed());

    // A Bitcoin payment observed too late cannot replace earlier on-time USDT evidence.
    let outpoint =
        paykit_server::domain::payment::BitcoinOutpoint::from_bitcoin(bitcoin::OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            0,
        ));
    store
        .apply_bitcoin_observation_at(
            "quoted-btc-0",
            &outpoint,
            50,
            6,
            true,
            invoice.payment_deadline() + time::Duration::seconds(1),
        )
        .await
        .unwrap();
    let late = payment_status(&store, &bundle).await;
    assert!(!late.bitcoin().unwrap().paid_on_time);
    let rpc = Rpc::start().await;
    store
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    let facts = payment_status(&store, &bundle).await;
    assert!(facts.usdt_arbitrum().unwrap().paid_on_time);
    assert!(!facts.usdt_arbitrum().unwrap().finalized);
    assert_ne!(
        facts.payment_state(),
        paykit_server::application::payment_request_status::PaymentState::Expired
    );
    let completed = drains.exact_replay(&lock).await.unwrap().unwrap();
    assert!(completed.completed());
    assert_eq!(completed.terminal_count(), 1);
    let token = crypto.payment_drain_cleanup_token(completed.drain_id());
    drains
        .cleanup_completed(&lock, token.as_bytes())
        .await
        .unwrap();

    // Drain completion closes request creation; it does not decide access or remove evidence.
    let restarted = InvoiceStore::new(database.pool(), crypto);
    assert_eq!(payment_status(&restarted, &bundle).await, facts);
    rpc.chain.lock().unwrap().reorg = true;
    restarted
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    let reorged = payment_status(&restarted, &bundle).await;
    assert!(reorged.usdt_arbitrum().is_none());
    assert!(!reorged.bitcoin().unwrap().paid_on_time);
    rpc.chain.lock().unwrap().reorg = false;
    rpc.chain.lock().unwrap().finalized = true;
    let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
    restarted
        .observe_usdt_request(creator_id, &creator, &record(0), &verifier, Some(&bundle))
        .await
        .unwrap();
    assert!(
        payment_status(&restarted, &bundle)
            .await
            .usdt_arbitrum()
            .unwrap()
            .finalized
    );
    database.cleanup().await;
}

struct MarketplacePayload;

impl MarketplacePreparationPayloadFactory for MarketplacePayload {
    fn for_child_index(
        &self,
        _index: i64,
    ) -> Result<MarketplacePreparationPayloads, PersistenceError> {
        Ok(MarketplacePreparationPayloads {
            payment_request_intent: invoice_payload(2, None)?.payment_request_intent,
        })
    }
}

#[tokio::test]
async fn locks_ignores_a_transfer_a_marketplace_request_already_owns() {
    let bundle = parse_bundle_id(BUNDLES[0]).unwrap();
    let database = TestDatabase::create().await;
    run_migrations(database.pool()).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(CREATOR).unwrap();
    let creator_id = CreatorStore::new(database.pool(), crypto.clone())
        .create(&CreatorCredentials::new(
            creator.clone(),
            "test-session".into(),
            PaykitIdentitySecretKey::new([9; 32], 1).unwrap(),
            None,
            Some(UsdtAddress::try_from(RECIPIENT.to_owned()).unwrap()),
        ))
        .await
        .unwrap()
        .id();

    let invoices = InvoiceStore::new(database.pool(), crypto.clone());
    let locks_invoice = invoices
        .create_atomic(AtomicInvoiceInput {
            creator: &creator,
            reader: &parse_reader(CREATOR).unwrap(),
            bundle_binding: BUNDLES[0].as_bytes(),
            lock_resource_binding: b"lock",
            payment_request_binding: BUNDLES[0].as_bytes(),
            invoice_payloads: &Payload { index: 0 },
            proposal_acceptance_seconds: 3600,
            payment_window_seconds: 86400,
        })
        .await
        .unwrap()
        .invoice_id();
    sqlx::query("INSERT INTO payment_request_lifecycles (invoice_id,sdk_payment_request_id,request_state,last_event_at,last_stream_item_id) VALUES ($1,$2,'proof_submitted',NOW(),1)")
        .bind(locks_invoice)
        .bind(record(0).payment_request_id)
        .execute(database.pool())
        .await
        .unwrap();

    let marketplace = MarketplacePreparationStore::new(database.pool(), crypto.clone());
    let prepared = marketplace
        .prepare(MarketplacePreparationInput {
            creator: &creator,
            reader: &parse_reader(CREATOR).unwrap(),
            reference: fixture(2)["binding"]["paymentReference"].as_str().unwrap(),
            operation_id: "marketplace-usdt",
            request_binding: b"marketplace-usdt",
            amount: 50_000,
            asset: CriterionAsset::Usdt,
            payment_window_seconds: 86_400,
            prepare_ttl_seconds: 900,
            prepare_deadline: common::deadline_after(900),
            payloads: &MarketplacePayload,
        })
        .await
        .unwrap();
    marketplace
        .activate(MarketplaceActivationInput {
            creator: &creator,
            invoice_id: prepared.invoice_id(),
            amount: 50_000,
            asset: CriterionAsset::Usdt,
            proposal_acceptance_window: std::time::Duration::from_secs(1_800),
        })
        .await
        .unwrap()
        .unwrap();
    sqlx::query("INSERT INTO payment_request_lifecycles (marketplace_preparation_id,sdk_payment_request_id,request_state,last_event_at,last_stream_item_id,state_event_id) VALUES ($1,$2,'proof_submitted',NOW(),1,'event')")
        .bind(prepared.invoice_id())
        .bind(record(2).payment_request_id)
        .execute(database.pool())
        .await
        .unwrap();

    let rpc = Rpc::start().await;
    marketplace
        .observe_usdt_request(creator_id, &creator, &record(2), &rpc.verifier)
        .await
        .unwrap();
    // The same on-chain transfer, attested for a Locks invoice, cannot take the receipt.
    invoices
        .observe_usdt_request(
            creator_id,
            &creator,
            &record(0),
            &rpc.verifier,
            Some(&bundle),
        )
        .await
        .unwrap();
    invoices
        .observe_usdt_request(creator_id, &creator, &record(0), &rpc.verifier, None)
        .await
        .unwrap();
    assert_eq!(status(&invoices, &bundle).await, (false, 0));
    let owners: (i64, i64) = sqlx::query_as(
        "SELECT count(invoice_id), count(marketplace_preparation_id) FROM usdt_observations",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(owners, (0, 1));
    // Evidence owned by a different request cannot keep unmatched scans hot.
    for finalized in [false, true] {
        sqlx::query("UPDATE usdt_observations SET finalized = $1")
            .bind(finalized)
            .execute(database.pool())
            .await
            .unwrap();
        let verifier = ArbitrumVerifier::new(rpc.url.clone()).unwrap();
        let mut evidence = record(0);
        let mut missing = proof(0);
        missing
            .proof
            .insert("transaction_hash".into(), json!(format!("0x{:064x}", 2)));
        evidence.payment_proofs.push(missing);
        rpc.chain.lock().unwrap().receipt = Value::Null;
        rpc.requests.lock().unwrap().clear();
        for _ in 0..3 {
            invoices
                .observe_usdt_request(creator_id, &creator, &evidence, &verifier, Some(&bundle))
                .await
                .unwrap();
        }
        assert_eq!(
            rpc.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _)| method == "eth_getTransactionReceipt")
                .count(),
            1
        );
    }
}
