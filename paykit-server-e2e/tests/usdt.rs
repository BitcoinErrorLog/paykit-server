use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, routing::post};
use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentEndpointPayload,
    PaymentReference, PaymentRequestTerms,
};
use paykit_sdk::{PaykitIdentitySecretKey, PaymentProofRecord, PaymentRequestRecord};
use paykit_server::{
    application::{
        payment_request_status::{PaymentRequestStatusOperations, PaymentRequestStatusSummary},
        semantic_intent::DeliveryIntentV1,
    },
    crypto::Crypto,
    domain::{
        locks::{
            BundleId, parse_addressed_lock_resource, parse_bundle_id, parse_creator, parse_reader,
        },
        receiving::{USDT_ENDPOINT, USDT_TOKEN, UsdtAddress},
    },
    persistence::{
        AtomicInvoiceInput, CreatorCredentials, CreatorStore, InvoicePayloadFactory,
        InvoicePayloads, InvoiceStore, PaymentDrainStore, PersistenceError, run_migrations,
    },
    usdt::{ArbitrumVerifier, PaymentContext, VerificationError},
};
use paykit_server_e2e::postgres::TestDatabase;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
const BUNDLES: [&str; 2] = ["000G40R40M30E209185GR38E1W", "000G40R40M30E209185GR38E2W"];
const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
const LOCK_RESOURCE: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy/pub/app.locks/000G40R40M30E209185GR38E1W8124GK2GAHC5RR34D1P70X3RFG.json";
const BLOCK: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture(index: usize) -> Value {
    serde_json::from_str::<Value>(include_str!("fixtures/usdt-proofs.json")).unwrap()["proofs"]
        [index]
        .clone()
}

fn proof(index: usize) -> PaymentProofRecord {
    let fixture = fixture(index);
    serde_json::from_value(json!({
        "event_id": Uuid::new_v4().to_string(), "stream_item_id":1,
        "payment_reference": fixture["binding"]["paymentReference"],
        "payment_app_id":"paykit-server", "payment_endpoint_identifier":USDT_ENDPOINT,
        "proof":fixture["proof"], "recorded_at":"2026-10-07T00:00:00Z"
    }))
    .unwrap()
}

fn record(index: usize) -> PaymentRequestRecord {
    serde_json::from_value(json!({
        "counterparty":CREATOR.trim_start_matches("pubky"),
        "payment_request_id":fixture(index)["binding"]["paymentRequestId"],
        "local_role":"Payee", "state":"ProofSubmitted", "conversion_quotes":[],
        "payment_proofs":[proof(index)],
    }))
    .unwrap()
}

#[derive(Clone)]
struct Chain {
    receipt: Value,
    chain_id: u64,
    head: u64,
    timestamp: i64,
    finalized: bool,
    reorg: bool,
    unavailable: bool,
}

impl Chain {
    fn new() -> Self {
        let hash = fixture(0)["proof"]["transaction_hash"].clone();
        let sender = "0x0000000000000000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf";
        let topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
        let recipient = format!("0x{}{}", "0".repeat(24), &RECIPIENT[2..]);
        Self {
            receipt: json!({"transactionHash":hash,"status":"0x1","blockNumber":"0x64","blockHash":BLOCK,
            "logs":[{}, {"address":USDT_TOKEN,"transactionHash":hash,"blockHash":BLOCK,"removed":false,
                "logIndex":"0xf", "topics":[topic,sender,recipient],"data":format!("0x{:064x}",50_000)}]}),
            chain_id: 42161,
            head: 101,
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
            finalized: false,
            reorg: false,
            unavailable: false,
        }
    }
}

#[derive(Clone)]
struct RpcState {
    chain: Arc<Mutex<Chain>>,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
}

struct Rpc {
    chain: Arc<Mutex<Chain>>,
    verifier: ArbitrumVerifier,
    url: url::Url,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Rpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Rpc {
    async fn start() -> Self {
        async fn handle(State(state): State<RpcState>, Json(request): Json<Value>) -> Json<Value> {
            state.requests.lock().unwrap().push((
                request["method"].as_str().unwrap().to_owned(),
                request["params"].clone(),
            ));
            let chain = state.chain.lock().unwrap();
            if chain.unavailable {
                return Json(
                    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unavailable"}}),
                );
            }
            let result = match request["method"].as_str().unwrap() {
                "eth_chainId" => json!(format!("0x{:x}", chain.chain_id)),
                "eth_getTransactionReceipt" => chain.receipt.clone(),
                "eth_blockNumber" => json!(format!("0x{:x}", chain.head)),
                "eth_getBlockByNumber" if request["params"][0] == "finalized" => {
                    json!({"number":if chain.finalized {"0x64"}else{"0x63"}})
                }
                "eth_getBlockByNumber" => {
                    json!({"number":request["params"][0],"hash":if chain.reorg {"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}else{BLOCK},"timestamp":format!("0x{:x}",chain.timestamp)})
                }
                _ => panic!("unexpected RPC"),
            };
            Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: url::Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let chain = Arc::new(Mutex::new(Chain::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route("/", post(handle)).with_state(RpcState {
            chain: chain.clone(),
            requests: requests.clone(),
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            chain,
            verifier: ArbitrumVerifier::new(url.clone()).unwrap(),
            url,
            requests,
            task,
        }
    }
}

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
    evidence.payment_proofs.insert(0, incorrect.clone());
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
    assert_eq!(status(&store, &bundles[0]).await, (true, 2));
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
    let restarted = InvoiceStore::new(database.pool(), crypto);
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
    database.cleanup().await;
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
