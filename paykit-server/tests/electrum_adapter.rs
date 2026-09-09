use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use bdk_electrum::electrum_client::{ScriptHash, ToElectrumScriptHash};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Transaction, TxMerkleNode,
    TxOut, absolute, consensus::encode::serialize_hex, hashes::Hash, transaction,
};
use paykit_server::{
    bitcoin::{ObservationTarget, TrackedOutput},
    config::BitcoinNetwork,
    workers::observer::{ElectrumAdapter, ElectrumPort},
};

#[tokio::test]
async fn emits_typed_output_identity_amount_and_confirmations_from_electrum() {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let txid = transaction.compute_txid();
    let server = ProtocolServer::start(
        Network::Regtest,
        120,
        address.script_pubkey(),
        transaction,
        118,
    )
    .await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    let observations = adapter
        .observations(&[ObservationTarget::new(address.to_string(), None)])
        .await
        .unwrap()
        .outputs;

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].outpoint, OutPoint::new(txid, 0));
    assert_eq!(observations[0].sats, 125_000);
    assert_eq!(observations[0].confirmations, 3);
    assert!(observations[0].present);
}

#[tokio::test]
async fn emits_absence_when_a_tracked_prefinal_outpoint_disappears_from_history() {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let outpoint = OutPoint::new(bitcoin::Txid::all_zeros(), 7);
    let server = ProtocolServer::start_empty(Network::Regtest, 120, address.script_pubkey()).await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    let observations = adapter
        .observations(&[ObservationTarget::new(
            address.to_string(),
            Some(TrackedOutput::new(outpoint, 90_000)),
        )])
        .await
        .unwrap()
        .outputs;

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].outpoint, outpoint);
    assert_eq!(observations[0].sats, 90_000);
    assert_eq!(observations[0].confirmations, 0);
    assert!(!observations[0].present);
}

#[tokio::test]
async fn rejects_remote_genesis_for_another_network_before_observing_targets() {
    let server = ProtocolServer::start_empty(Network::Signet, 120, ScriptBuf::new()).await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    assert_eq!(
        adapter.observations(&[]).await,
        Err(paykit_server::workers::observer::ObserverError::WrongNetwork)
    );
}

#[tokio::test]
async fn rejects_a_positive_history_height_above_the_reported_tip() {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let server = ProtocolServer::start(
        Network::Regtest,
        120,
        address.script_pubkey(),
        transaction,
        121,
    )
    .await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    assert_eq!(
        adapter
            .observations(&[ObservationTarget::new(address.to_string(), None)])
            .await,
        Err(paykit_server::workers::observer::ObserverError::Unavailable)
    );
}

#[tokio::test]
async fn treats_nonpositive_history_heights_as_unconfirmed_through_bdk() {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let server = ProtocolServer::start(
        Network::Regtest,
        120,
        address.script_pubkey(),
        transaction,
        -2,
    )
    .await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    let observations = adapter
        .observations(&[ObservationTarget::new(address.to_string(), None)])
        .await
        .unwrap()
        .outputs;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].confirmations, 0);
    assert!(observations[0].present);
}

#[tokio::test]
async fn reconnects_and_reuses_the_same_adapter_after_transport_disconnect() {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(125_000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let server = ProtocolServer::start_disconnect_after_transaction(
        Network::Regtest,
        120,
        address.script_pubkey(),
        transaction,
        118,
    )
    .await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();
    let targets = [ObservationTarget::new(address.to_string(), None)];

    assert_eq!(
        adapter.observations(&targets).await.unwrap().outputs.len(),
        1
    );
    assert_eq!(
        adapter.observations(&targets).await.unwrap().outputs.len(),
        1
    );
}

#[tokio::test]
async fn classifies_endpoint_outage_as_retryable_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    drop(listener);

    let result = ElectrumAdapter::connect(
        endpoint,
        BitcoinNetwork::Regtest,
        Duration::from_millis(50),
        0,
    )
    .await;

    assert_eq!(
        result.err(),
        Some(paykit_server::workers::observer::ObserverError::Unavailable)
    );
}

struct ProtocolServer {
    endpoint: String,
    wake_address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProtocolServer {
    async fn start(
        network: Network,
        tip_height: usize,
        script: ScriptBuf,
        transaction: Transaction,
        transaction_height: i32,
    ) -> Self {
        Self::start_with_history(
            network,
            tip_height,
            script,
            Some((transaction, transaction_height)),
            false,
        )
        .await
    }

    async fn start_empty(network: Network, tip_height: usize, script: ScriptBuf) -> Self {
        Self::start_with_history(network, tip_height, script, None, false).await
    }

    async fn start_disconnect_after_transaction(
        network: Network,
        tip_height: usize,
        script: ScriptBuf,
        transaction: Transaction,
        transaction_height: i32,
    ) -> Self {
        Self::start_with_history(
            network,
            tip_height,
            script,
            Some((transaction, transaction_height)),
            true,
        )
        .await
    }

    async fn start_with_history(
        network: Network,
        tip_height: usize,
        script: ScriptBuf,
        transaction: Option<(Transaction, i32)>,
        disconnect_after_transaction: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let wake_address = listener.local_addr().unwrap();
        let endpoint = format!("tcp://{wake_address}");
        let transaction_hex = transaction
            .as_ref()
            .map(|(transaction, _)| serialize_hex(transaction));
        let transaction_id = transaction
            .as_ref()
            .map(|(transaction, _)| transaction.compute_txid().to_string());
        let transaction_height = transaction.as_ref().map(|(_, height)| *height);
        let genesis_header = bitcoin::constants::genesis_block(network).header;
        let mut tip_header = genesis_header;
        if let Some((transaction, _)) = &transaction {
            tip_header.merkle_root =
                TxMerkleNode::from_byte_array(transaction.compute_txid().to_byte_array());
        }
        let fixture = Arc::new(ProtocolFixture {
            genesis_header: serialize_hex(&genesis_header),
            tip_header: serialize_hex(&tip_header),
            tip_height,
            script,
            transaction_hex,
            transaction_id,
            transaction_height,
            disconnect_after_transaction: AtomicBool::new(disconnect_after_transaction),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let handle = thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                if thread_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                serve_connection(stream, fixture.clone());
            }
        });
        Self {
            endpoint,
            wake_address,
            shutdown,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for ProtocolServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.wake_address);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

struct ProtocolFixture {
    genesis_header: String,
    tip_header: String,
    tip_height: usize,
    script: ScriptBuf,
    transaction_hex: Option<String>,
    transaction_id: Option<String>,
    transaction_height: Option<i32>,
    disconnect_after_transaction: AtomicBool,
}

fn serve_connection(mut stream: TcpStream, fixture: Arc<ProtocolFixture>) {
    let reader = BufReader::new(stream.try_clone().unwrap());
    for line in reader.lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "server.version" => serde_json::json!(["paykit-test-electrum", "1.4"]),
            "blockchain.block.header" => {
                if request["params"][0].as_u64() == Some(0) {
                    serde_json::json!(fixture.genesis_header)
                } else {
                    serde_json::json!(fixture.tip_header)
                }
            }
            "blockchain.headers.subscribe" => serde_json::json!({
                "height": fixture.tip_height,
                "hex": fixture.tip_header,
            }),
            "blockchain.block.headers" => {
                let count = request["params"][1].as_u64().unwrap() as usize;
                serde_json::json!({
                    "count": count,
                    "hex": fixture.tip_header.repeat(count),
                    "max": 2016,
                })
            }
            "blockchain.scripthash.get_history" => {
                let requested_hash: ScriptHash =
                    serde_json::from_value(request["params"][0].clone()).unwrap();
                assert_eq!(requested_hash, fixture.script.to_electrum_scripthash());
                match (&fixture.transaction_id, fixture.transaction_height) {
                    (Some(transaction_id), Some(transaction_height)) => serde_json::json!([{
                        "height": transaction_height,
                        "tx_hash": transaction_id,
                        "fee": null,
                    }]),
                    _ => serde_json::json!([]),
                }
            }
            "blockchain.transaction.get" => {
                serde_json::json!(fixture.transaction_hex.as_ref().unwrap())
            }
            "blockchain.transaction.get_merkle" => {
                assert_eq!(
                    request["params"][0].as_str(),
                    fixture.transaction_id.as_deref()
                );
                assert_eq!(
                    request["params"][1].as_i64(),
                    fixture.transaction_height.map(i64::from)
                );
                serde_json::json!({
                    "block_height": fixture.transaction_height.unwrap(),
                    "merkle": [],
                    "pos": 0,
                })
            }
            method => panic!("unexpected Electrum method: {method}"),
        };
        let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        writeln!(stream, "{response}").unwrap();
        stream.flush().unwrap();
        if method == "blockchain.transaction.get"
            && fixture
                .disconnect_after_transaction
                .swap(false, Ordering::SeqCst)
        {
            break;
        }
    }
}

#[tokio::test]
async fn probe_reports_the_tip_and_verifies_the_endpoint_genesis() {
    let server = ProtocolServer::start_empty(Network::Regtest, 120, ScriptBuf::new()).await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    let tip = adapter.probe().await.unwrap();
    assert_eq!(tip.height, 120);
    assert!(tip.time_unix > 0);
}

#[tokio::test]
async fn probe_rejects_an_endpoint_serving_the_wrong_genesis() {
    let server = ProtocolServer::start_empty(Network::Signet, 120, ScriptBuf::new()).await;
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();

    assert_eq!(
        adapter.probe().await,
        Err(paykit_server::workers::observer::ObserverError::WrongNetwork)
    );
}

#[tokio::test]
async fn probe_classifies_endpoint_outage_as_retryable_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
    drop(listener);
    let adapter = ElectrumAdapter::configured(
        endpoint,
        BitcoinNetwork::Regtest,
        Duration::from_millis(50),
        0,
    )
    .unwrap();

    assert_eq!(
        adapter.probe().await,
        Err(paykit_server::workers::observer::ObserverError::Unavailable)
    );
}
