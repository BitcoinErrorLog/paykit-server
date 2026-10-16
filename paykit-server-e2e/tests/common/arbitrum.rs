//! Fake Arbitrum One JSON-RPC and the signed ERC-20 proofs used to verify USDT receipts.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, routing::post};
use paykit_sdk::{PaymentProofRecord, PaymentRequestRecord};
use paykit_server::{
    domain::receiving::{USDT_ENDPOINT, USDT_TOKEN},
    usdt::ArbitrumVerifier,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

pub const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";
pub const RECIPIENT: &str = "0x2222222222222222222222222222222222222222";
pub const BLOCK: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn fixture(index: usize) -> Value {
    serde_json::from_str::<Value>(include_str!("../fixtures/usdt-proofs.json")).unwrap()["proofs"]
        [index]
        .clone()
}

pub fn proof(index: usize) -> PaymentProofRecord {
    let fixture = fixture(index);
    serde_json::from_value(json!({
        "event_id": Uuid::new_v4().to_string(), "stream_item_id":1,
        "payment_reference": fixture["binding"]["paymentReference"],
        "payment_app_id":"paykit-server", "payment_endpoint_identifier":USDT_ENDPOINT,
        "proof":fixture["proof"], "recorded_at":"2026-10-07T00:00:00Z"
    }))
    .unwrap()
}

pub fn record(index: usize) -> PaymentRequestRecord {
    serde_json::from_value(json!({
        "counterparty":CREATOR.trim_start_matches("pubky"),
        "payment_request_id":fixture(index)["binding"]["paymentRequestId"],
        "local_role":"Payee", "state":"ProofSubmitted", "conversion_quotes":[],
        "payment_proofs":[proof(index)],
    }))
    .unwrap()
}

#[derive(Clone)]
pub struct Chain {
    pub receipt: Value,
    pub chain_id: u64,
    pub head: u64,
    pub timestamp: i64,
    pub finalized: bool,
    pub reorg: bool,
    pub unavailable: bool,
}

impl Chain {
    pub fn new() -> Self {
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
    pub chain: Arc<Mutex<Chain>>,
    pub requests: Arc<Mutex<Vec<(String, Value)>>>,
}

pub struct Rpc {
    pub chain: Arc<Mutex<Chain>>,
    pub verifier: ArbitrumVerifier,
    pub url: url::Url,
    pub requests: Arc<Mutex<Vec<(String, Value)>>>,
    pub task: tokio::task::JoinHandle<()>,
}
impl Drop for Rpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Rpc {
    pub async fn start() -> Self {
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
                "eth_getTransactionReceipt" => {
                    if request["params"][0] == chain.receipt["transactionHash"] {
                        chain.receipt.clone()
                    } else {
                        Value::Null
                    }
                }
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
