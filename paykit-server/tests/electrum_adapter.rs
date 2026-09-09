//! Protocol-fixture tests for the raw `script_list_unspent` observation
//! adapter. Every fixture pins the literal Electrum JSON response; the mock
//! server panics on `blockchain.scripthash.get_history` and
//! `blockchain.transaction.get`, so any history fanout in the adapter fails
//! loudly, and every request is logged for exact RPC-count assertions.

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use bitcoin::{
    Address, CompressedPublicKey, Network, OutPoint, ScriptBuf, Transaction, Txid,
    absolute::LockTime, consensus::encode, transaction::Version,
};
use electrum_client::{ScriptHash, ToElectrumScriptHash};
use paykit_server::{
    bitcoin::{ObservationTarget, TrackedOutput},
    config::BitcoinNetwork,
    workers::observer::{
        AddressFailureReason, ElectrumAdapter, ElectrumPort, FailedObservation, ObserverError,
        RequestLimiter,
    },
};

const TIP_HEIGHT: usize = 120;

fn fixture_address() -> Address {
    let public_key = CompressedPublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    Address::p2wpkh(&public_key, Network::Regtest)
}

/// One literal `blockchain.scripthash.listunspent` result item.
fn unspent_entry(label: u64, value_sats: u64, height: usize) -> serde_json::Value {
    serde_json::json!({
        "tx_hash": format!("{label:064x}"),
        "tx_pos": 0,
        "value": value_sats,
        "height": height,
    })
}

/// A syntactically valid JSON result item whose `tx_hash` cannot decode
/// into `ListUnspentRes`: any code path that converts items before
/// checking the item-count cap fails with a decode error instead.
fn undecodable_entry(label: u64) -> serde_json::Value {
    serde_json::json!({
        "tx_hash": format!("not-a-txid-{label}"),
        "tx_pos": 0,
        "value": 546,
        "height": TIP_HEIGHT,
    })
}

fn outpoint(label: u64) -> OutPoint {
    OutPoint::new(Txid::from_str(&format!("{label:064x}")).unwrap(), 0)
}

fn failed(address: &Address, reason: AddressFailureReason) -> FailedObservation {
    FailedObservation {
        address: address.to_string(),
        reason,
    }
}

/// Test adapter matching the production defaults: the configured UTXO cap
/// (200) and a generous 5s per-address deadline.
async fn connect(server: &ProtocolServer) -> ElectrumAdapter {
    connect_bounded(server, 200, Duration::from_secs(5)).await
}

async fn connect_bounded(
    server: &ProtocolServer,
    max_utxos_per_address: usize,
    address_deadline: Duration,
) -> ElectrumAdapter {
    ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        max_utxos_per_address,
        address_deadline,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_empty_address_observes_no_outputs_with_one_lookup() {
    let address = fixture_address();
    // Literal fixture: the address has never been used.
    let server = ProtocolServer::start(Network::Regtest, address.script_pubkey(), |_| {
        serde_json::json!([])
    })
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(address.to_string(), None)],
        )
        .await
        .unwrap();

    assert!(report.outputs.is_empty());
    assert_eq!(report.observed, vec![address.to_string()]);
    assert!(report.failed.is_empty());
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn a_mempool_utxo_observes_present_with_zero_confirmations() {
    let address = fixture_address();
    // Literal fixture: one mempool UTXO (height 0) of 125_000 sats.
    let server = ProtocolServer::start(Network::Regtest, address.script_pubkey(), |_| {
        serde_json::json!([unspent_entry(1, 125_000, 0)])
    })
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(address.to_string(), None)],
        )
        .await
        .unwrap();

    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.outputs[0].outpoint, outpoint(1));
    assert_eq!(report.outputs[0].sats, 125_000);
    assert_eq!(report.outputs[0].confirmations, 0);
    assert!(report.outputs[0].present);
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn a_confirmed_utxo_derives_confirmations_from_the_probe_tip() {
    let address = fixture_address();
    // Literal fixture: one UTXO confirmed at height 118; tip 120.
    let server = ProtocolServer::start(Network::Regtest, address.script_pubkey(), |_| {
        serde_json::json!([unspent_entry(2, 125_000, 118)])
    })
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(address.to_string(), None)],
        )
        .await
        .unwrap();

    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.outputs[0].confirmations, 3);
    assert!(report.outputs[0].present);
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn a_many_utxo_address_completes_with_one_lookup_and_zero_transaction_fetches() {
    let address = fixture_address();
    // Literal fixture: the address was dusted with 200 minimal UTXOs.
    const DUST: u64 = 200;
    let server = ProtocolServer::start(Network::Regtest, address.script_pubkey(), |_| {
        serde_json::Value::Array(
            (1..=DUST)
                .map(|label| unspent_entry(label, 546, TIP_HEIGHT))
                .collect(),
        )
    })
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(address.to_string(), None)],
        )
        .await
        .unwrap();

    assert_eq!(report.outputs.len(), DUST as usize);
    assert!(report.outputs.iter().all(|output| output.present));
    assert_eq!(report.observed, vec![address.to_string()]);
    // ONE list_unspent call, ZERO history calls, ZERO transaction fetches.
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn a_many_history_address_causes_no_transaction_fetch_fanout() {
    let address = fixture_address();
    // The endpoint would answer get_history with 600 entries for this
    // script and panics on any transaction.get: the adapter must never
    // ask. Its single list_unspent lookup returns the current UTXO set.
    let server =
        ProtocolServer::start_with_history(Network::Regtest, address.script_pubkey(), 600).await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(address.to_string(), None)],
        )
        .await
        .unwrap();

    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.observed, vec![address.to_string()]);
    // RPC-count evidence: one lookup, no history call, no fanout.
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn candidate_fetch_uses_exactly_one_distinct_transaction_request() {
    let transaction = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let txid = transaction.compute_txid();
    let server = ProtocolServer::start_with_transaction(
        Network::Regtest,
        encode::serialize_hex(&transaction),
    )
    .await;
    let adapter = connect(&server).await;

    let fetched = adapter.candidate_transaction(txid, 400_000).await.unwrap();

    assert_eq!(fetched.txid, txid);
    assert!(fetched.inputs.is_empty());
    server.assert_rpc_counts(0, 0, 1);
}

#[tokio::test]
async fn candidate_fetch_rejects_a_transaction_over_the_byte_cap() {
    let transaction = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let txid = transaction.compute_txid();
    let server = ProtocolServer::start_with_transaction(
        Network::Regtest,
        encode::serialize_hex(&transaction),
    )
    .await;
    let adapter = connect(&server).await;

    assert_eq!(
        adapter.candidate_transaction(txid, 0).await,
        Err(ObserverError::Unavailable)
    );
    server.assert_rpc_counts(0, 0, 1);
}

#[tokio::test]
async fn a_spent_tracked_outpoint_observes_absence() {
    let address = fixture_address();
    let tracked = outpoint(77);
    // Literal fixture: the unspent set no longer contains the tracked
    // outpoint (it was spent or replaced).
    let server = ProtocolServer::start(Network::Regtest, address.script_pubkey(), |_| {
        serde_json::json!([])
    })
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[ObservationTarget::new(
                address.to_string(),
                Some(TrackedOutput::new(tracked, 90_000)),
            )],
        )
        .await
        .unwrap();

    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.outputs[0].outpoint, tracked);
    assert_eq!(report.outputs[0].sats, 90_000);
    assert_eq!(report.outputs[0].confirmations, 0);
    assert!(!report.outputs[0].present);
    server.assert_rpc_counts(1, 0, 0);
}

#[tokio::test]
async fn a_utxo_height_above_the_tip_fails_only_that_address() {
    let address = fixture_address();
    let other = Address::p2wpkh(
        &CompressedPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap(),
        Network::Regtest,
    );
    // Literal fixtures: the first address reports a UTXO above the probed
    // tip (an inconsistent endpoint view); the second is healthy.
    let server = ProtocolServer::start_multi(
        Network::Regtest,
        vec![
            (
                address.script_pubkey(),
                serde_json::json!([unspent_entry(3, 125_000, TIP_HEIGHT + 1)]),
            ),
            (
                other.script_pubkey(),
                serde_json::json!([unspent_entry(4, 50_000, TIP_HEIGHT)]),
            ),
        ],
    )
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[
                ObservationTarget::new(address.to_string(), None),
                ObservationTarget::new(other.to_string(), None),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        report.failed,
        vec![failed(&address, AddressFailureReason::Error)]
    );
    assert_eq!(report.observed, vec![other.to_string()]);
    assert_eq!(report.outputs.len(), 1);
    assert_eq!(report.outputs[0].sats, 50_000);
}

#[tokio::test]
async fn a_per_address_timeout_isolates_the_failed_address_and_the_rest_are_observed() {
    let stalled = fixture_address();
    let healthy_a = Address::p2wpkh(
        &CompressedPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap(),
        Network::Regtest,
    );
    let healthy_b = Address::p2wpkh(
        &CompressedPublicKey::from_str(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )
        .unwrap(),
        Network::Regtest,
    );
    // The stalled address's list_unspent response takes ten times the
    // client timeout; the healthy addresses answer immediately.
    let server = ProtocolServer::start_multi_with_stall(
        Network::Regtest,
        stalled.script_pubkey(),
        Duration::from_secs(10),
        vec![
            (
                healthy_a.script_pubkey(),
                serde_json::json!([unspent_entry(5, 10_000, TIP_HEIGHT)]),
            ),
            (
                healthy_b.script_pubkey(),
                serde_json::json!([unspent_entry(6, 20_000, TIP_HEIGHT)]),
            ),
        ],
    )
    .await;
    let adapter = connect(&server).await;

    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[
                ObservationTarget::new(stalled.to_string(), None),
                ObservationTarget::new(healthy_a.to_string(), None),
                ObservationTarget::new(healthy_b.to_string(), None),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        report.failed,
        vec![failed(&stalled, AddressFailureReason::Error)]
    );
    assert_eq!(
        report.observed,
        vec![healthy_a.to_string(), healthy_b.to_string()],
        "the timed-out address must not discard the other addresses' observations"
    );
    assert_eq!(report.outputs.len(), 2);
    // Retry-path evidence: exactly one list_unspent per admitted target —
    // the timed-out lookup is NOT reissued (client retries are pinned at
    // zero; the observer's own next tick is the retry).
    server.assert_rpc_counts(3, 0, 0);
}

#[tokio::test]
async fn an_oversized_listunspent_response_fails_only_that_address_before_materialising_records() {
    let dusted = fixture_address();
    let healthy = Address::p2wpkh(
        &CompressedPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap(),
        Network::Regtest,
    );
    // Literal fixtures: the dusted address answers with a 10k-item
    // listunspent response whose items cannot even decode into
    // ListUnspentRes; the healthy address answers normally. The cap (200)
    // must fire BEFORE any per-item conversion: a convert-first code path
    // would fail with AddressFailureReason::Error instead.
    const DUST: u64 = 10_000;
    let server = ProtocolServer::start_multi(
        Network::Regtest,
        vec![
            (
                dusted.script_pubkey(),
                serde_json::Value::Array((1..=DUST).map(undecodable_entry).collect()),
            ),
            (
                healthy.script_pubkey(),
                serde_json::json!([unspent_entry(7, 30_000, TIP_HEIGHT)]),
            ),
        ],
    )
    .await;
    let adapter = connect(&server).await;

    let started = std::time::Instant::now();
    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[
                ObservationTarget::new(dusted.to_string(), None),
                ObservationTarget::new(healthy.to_string(), None),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        report.failed,
        vec![failed(&dusted, AddressFailureReason::ResponseTooLarge)],
        "the over-cap response is rejected by the item-count cap, not by a \
         per-item decode — no 10k-element record vector is ever built"
    );
    assert_eq!(
        report.observed,
        vec![healthy.to_string()],
        "the next seller is observed in the same tick"
    );
    assert_eq!(report.outputs.len(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the rejection happens well within the per-address deadline"
    );
    server.assert_rpc_counts(2, 0, 0);
}

#[tokio::test]
async fn a_trickling_response_exceeding_the_address_deadline_fails_only_that_address() {
    let trickled = fixture_address();
    let healthy = Address::p2wpkh(
        &CompressedPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap(),
        Network::Regtest,
    );
    // The trickled address's response arrives after 10s — well past the
    // 300ms per-address deadline and past the 1s client socket timeout, so
    // only the wall-clock deadline can bound it; the healthy address
    // answers immediately.
    let server = ProtocolServer::start_multi_with_stall(
        Network::Regtest,
        trickled.script_pubkey(),
        Duration::from_secs(10),
        vec![(
            healthy.script_pubkey(),
            serde_json::json!([unspent_entry(8, 40_000, TIP_HEIGHT)]),
        )],
    )
    .await;
    let adapter = connect_bounded(&server, 200, Duration::from_millis(300)).await;

    let started = std::time::Instant::now();
    let report = adapter
        .observations(
            TIP_HEIGHT as u32,
            &[
                ObservationTarget::new(trickled.to_string(), None),
                ObservationTarget::new(healthy.to_string(), None),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        report.failed,
        vec![failed(&trickled, AddressFailureReason::Deadline)]
    );
    assert_eq!(
        report.observed,
        vec![healthy.to_string()],
        "the deadline returns to the tick and the next seller is observed \
         over a fresh connection"
    );
    assert_eq!(report.outputs.len(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the 300ms deadline bounds the wait; the 10s trickle never completes"
    );
    server.assert_rpc_counts(2, 0, 0);
}

#[tokio::test]
async fn reconnects_and_reuses_the_same_adapter_after_transport_disconnect() {
    let address = fixture_address();
    let server =
        ProtocolServer::start_disconnecting(Network::Regtest, address.script_pubkey()).await;
    let adapter = connect(&server).await;
    let targets = [ObservationTarget::new(address.to_string(), None)];

    assert_eq!(
        adapter
            .observations(TIP_HEIGHT as u32, &targets)
            .await
            .unwrap()
            .outputs
            .len(),
        1
    );
    assert_eq!(
        adapter
            .observations(TIP_HEIGHT as u32, &targets)
            .await
            .unwrap()
            .outputs
            .len(),
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
        200,
        Duration::from_secs(5),
    )
    .await;

    assert_eq!(result.err(), Some(ObserverError::Unavailable));
}

#[tokio::test]
async fn probe_reports_the_tip_and_verifies_the_endpoint_genesis() {
    let server =
        ProtocolServer::start(
            Network::Regtest,
            ScriptBuf::new(),
            |_| serde_json::json!([]),
        )
        .await;
    let adapter = connect(&server).await;

    let tip = adapter.probe().await.unwrap();
    assert_eq!(tip.height, TIP_HEIGHT as u32);
    assert!(tip.time_unix > 0);
}

#[tokio::test]
async fn probe_rejects_an_endpoint_serving_the_wrong_genesis() {
    let server =
        ProtocolServer::start(Network::Signet, ScriptBuf::new(), |_| serde_json::json!([])).await;
    let adapter = connect(&server).await;

    assert_eq!(adapter.probe().await, Err(ObserverError::WrongNetwork));
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
        200,
        Duration::from_secs(5),
    )
    .unwrap();

    assert_eq!(adapter.probe().await, Err(ObserverError::Unavailable));
}

#[tokio::test]
async fn creation_snapshot_reads_tip_after_history_and_unspent() {
    let address = fixture_address();
    let server =
        ProtocolServer::start_creation_snapshot(Network::Regtest, address.script_pubkey()).await;
    let adapter = ElectrumAdapter::configured(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        200,
        Duration::from_secs(5),
    )
    .unwrap();

    let snapshot = adapter
        .creation_snapshot(
            &address.to_string(),
            50,
            400_000,
            &RequestLimiter::new(100, 0),
            Arc::new(tokio::sync::Semaphore::new(1))
                .acquire_owned()
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot.tip_height, u32::try_from(TIP_HEIGHT).unwrap());
    let requests = server.fixture.request_log.lock().unwrap();
    let ordered = requests
        .iter()
        .filter(|request| {
            matches!(
                request.as_str(),
                "blockchain.scripthash.get_history"
                    | "blockchain.scripthash.listunspent"
                    | "blockchain.headers.subscribe"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            "blockchain.scripthash.get_history",
            "blockchain.scripthash.listunspent",
            "blockchain.headers.subscribe",
        ],
        "a transaction mined while history is read is either captured by the snapshot or at/below the later floor"
    );
}

#[tokio::test]
async fn creation_snapshot_rejects_history_over_the_entry_cap_before_transaction_fetches() {
    let address = fixture_address();
    let server = ProtocolServer::start_with_fixture(
        Network::Regtest,
        vec![(address.script_pubkey(), serde_json::json!([]))],
        51,
        true,
        None,
        false,
        None,
        None,
    )
    .await;
    let adapter = ElectrumAdapter::configured(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        200,
        Duration::from_secs(5),
    )
    .unwrap();

    assert_eq!(
        adapter
            .creation_snapshot(
                &address.to_string(),
                50,
                400_000,
                &RequestLimiter::new(100, 0),
                Arc::new(tokio::sync::Semaphore::new(1))
                    .acquire_owned()
                    .await
                    .unwrap(),
            )
            .await,
        Err(ObserverError::Unavailable)
    );
    server.assert_rpc_counts(0, 1, 0);
}

#[tokio::test]
async fn creation_snapshot_permit_outlives_an_abandoned_await() {
    let address = fixture_address();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let server = ProtocolServer::start_with_fixture(
        Network::Regtest,
        vec![(address.script_pubkey(), serde_json::json!([]))],
        0,
        true,
        None,
        false,
        None,
        Some(gate.clone()),
    )
    .await;
    // The client wire timeout (30s) far exceeds the test window, so the
    // gated read stays parked until the gate is released.
    let adapter = ElectrumAdapter::configured(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(30),
        200,
        Duration::from_secs(5),
    )
    .unwrap();
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let snapshot = {
        let adapter = adapter.clone();
        let address = address.to_string();
        tokio::spawn(async move {
            adapter
                .creation_snapshot(&address, 50, 400_000, &RequestLimiter::new(100, 0), permit)
                .await
        })
    };
    for _ in 0..200 {
        let parked = server
            .fixture
            .request_log
            .lock()
            .unwrap()
            .iter()
            .any(|method| method == "blockchain.scripthash.get_history");
        if parked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The awaiting side gives up (the request deadline passed); the
    // blocking read is orphaned on the gated history response.
    snapshot.abort();
    let _ = snapshot.await;
    assert_eq!(
        slots.available_permits(),
        0,
        "the orphaned blocking read must retain its slot until the read returns"
    );
    assert!(slots.clone().try_acquire_owned().is_err());

    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    for _ in 0..500 {
        if slots.available_permits() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        slots.available_permits(),
        1,
        "the slot is released only when the detached blocking read exits"
    );
}

struct ProtocolServer {
    endpoint: String,
    wake_address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    fixture: Arc<ProtocolFixture>,
    handle: Option<thread::JoinHandle<()>>,
}

struct ProtocolFixture {
    genesis_header: String,
    tip_header: String,
    tip_height: usize,
    /// Literal list_unspent result per script hash.
    unspent_by_script: Vec<(ScriptBuf, serde_json::Value)>,
    /// History length served if the adapter ever calls get_history.
    history_len: usize,
    serve_history: bool,
    /// Script whose list_unspent response is delayed, and the delay.
    stall: Option<(ScriptBuf, Duration)>,
    /// Close each connection after its first list_unspent response.
    disconnect_after_unspent: bool,
    transaction_raw: Option<String>,
    /// When set, every `get_history` response parks on this gate until it
    /// is released, modelling a blocking read that outlives its caller.
    gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    request_log: Mutex<Vec<String>>,
}

impl ProtocolServer {
    /// Starts a server whose single script answers list_unspent with the
    /// given literal JSON fixture.
    async fn start(
        network: Network,
        script: ScriptBuf,
        unspent: impl FnOnce(&ScriptBuf) -> serde_json::Value,
    ) -> Self {
        let unspent = unspent(&script);
        Self::start_multi(network, vec![(script, unspent)]).await
    }

    async fn start_multi(network: Network, unspent: Vec<(ScriptBuf, serde_json::Value)>) -> Self {
        Self::start_with_fixture(network, unspent, 0, false, None, false, None, None).await
    }

    /// Starts a server that would answer get_history with `history_len`
    /// entries for the script (and panics on transaction.get); the
    /// list_unspent fixture is one current UTXO.
    async fn start_with_history(network: Network, script: ScriptBuf, history_len: usize) -> Self {
        let unspent = serde_json::json!([unspent_entry(9, 125_000, TIP_HEIGHT)]);
        Self::start_with_fixture(
            network,
            vec![(script, unspent)],
            history_len,
            false,
            None,
            false,
            None,
            None,
        )
        .await
    }

    async fn start_multi_with_stall(
        network: Network,
        stalled_script: ScriptBuf,
        stall: Duration,
        healthy: Vec<(ScriptBuf, serde_json::Value)>,
    ) -> Self {
        Self::start_with_fixture(
            network,
            healthy,
            0,
            false,
            Some((stalled_script, stall)),
            false,
            None,
            None,
        )
        .await
    }

    async fn start_disconnecting(network: Network, script: ScriptBuf) -> Self {
        let unspent = serde_json::json!([unspent_entry(11, 125_000, TIP_HEIGHT)]);
        Self::start_with_fixture(
            network,
            vec![(script, unspent)],
            0,
            false,
            None,
            true,
            None,
            None,
        )
        .await
    }

    async fn start_with_transaction(network: Network, transaction_raw: String) -> Self {
        Self::start_with_fixture(
            network,
            Vec::new(),
            0,
            false,
            None,
            false,
            Some(transaction_raw),
            None,
        )
        .await
    }

    async fn start_creation_snapshot(network: Network, script: ScriptBuf) -> Self {
        Self::start_with_fixture(
            network,
            vec![(script, serde_json::json!([]))],
            0,
            true,
            None,
            false,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_with_fixture(
        network: Network,
        unspent_by_script: Vec<(ScriptBuf, serde_json::Value)>,
        history_len: usize,
        serve_history: bool,
        stall: Option<(ScriptBuf, Duration)>,
        disconnect_after_unspent: bool,
        transaction_raw: Option<String>,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let wake_address = listener.local_addr().unwrap();
        let endpoint = format!("tcp://{wake_address}");
        let genesis_header = bitcoin::constants::genesis_block(network).header;
        let fixture = Arc::new(ProtocolFixture {
            genesis_header: encode::serialize_hex(&genesis_header),
            tip_header: encode::serialize_hex(&genesis_header),
            tip_height: TIP_HEIGHT,
            unspent_by_script,
            history_len,
            serve_history,
            stall,
            disconnect_after_unspent,
            transaction_raw,
            gate,
            request_log: Mutex::new(Vec::new()),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread_fixture = fixture.clone();
        let handle = thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                if thread_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                // One thread per connection: a stalled response on one
                // connection must not block the adapter's reconnect.
                let fixture = thread_fixture.clone();
                thread::spawn(move || serve_connection(stream, fixture));
            }
        });
        Self {
            endpoint,
            wake_address,
            shutdown,
            fixture,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// RPC-count evidence: exactly `unspent` list_unspent calls, `history`
    /// get_history calls, and `transactions` transaction.get calls were
    /// served across every connection this server accepted.
    fn assert_rpc_counts(&self, unspent: usize, history: usize, transactions: usize) {
        let log = self.fixture.request_log.lock().unwrap();
        eprintln!("electrum request log: {log:?}");
        let count = |method: &str| log.iter().filter(|entry| *entry == method).count();
        assert_eq!(
            (
                count("blockchain.scripthash.listunspent"),
                count("blockchain.scripthash.get_history"),
                count("blockchain.transaction.get"),
            ),
            (unspent, history, transactions),
            "unexpected Electrum request mix: {log:?}"
        );
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

fn serve_connection(mut stream: TcpStream, fixture: Arc<ProtocolFixture>) {
    let reader = BufReader::new(stream.try_clone().unwrap());
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap();
        fixture.request_log.lock().unwrap().push(method.to_owned());
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
            "blockchain.scripthash.listunspent" => {
                let requested_hash: ScriptHash =
                    serde_json::from_value(request["params"][0].clone()).unwrap();
                if let Some((stalled_script, delay)) = &fixture.stall
                    && requested_hash == stalled_script.to_electrum_scripthash()
                {
                    thread::sleep(*delay);
                }
                fixture
                    .unspent_by_script
                    .iter()
                    .find(|(script, _)| script.to_electrum_scripthash() == requested_hash)
                    .map(|(_, result)| result.clone())
                    .unwrap_or_else(|| serde_json::json!([]))
            }
            // The adapter must never call these; if it ever does, fail the
            // test loudly instead of silently serving a fanout.
            "blockchain.scripthash.get_history" => {
                if let Some(gate) = &fixture.gate {
                    let (released, condvar) = &**gate;
                    let mut released = released.lock().unwrap();
                    while !*released {
                        released = condvar.wait(released).unwrap();
                    }
                }
                if fixture.serve_history {
                    serde_json::Value::Array(
                        (0..fixture.history_len)
                            .map(|index| {
                                serde_json::json!({
                                    "tx_hash": format!("{:064x}", index + 1),
                                    "height": 1
                                })
                            })
                            .collect(),
                    )
                } else {
                    let _ = fixture.history_len;
                    panic!("adapter called blockchain.scripthash.get_history");
                }
            }
            "blockchain.transaction.get" => serde_json::Value::String(
                fixture
                    .transaction_raw
                    .clone()
                    .unwrap_or_else(|| panic!("adapter called blockchain.transaction.get")),
            ),
            method => panic!("unexpected Electrum method: {method}"),
        };
        let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        if writeln!(stream, "{response}").is_err() {
            break;
        }
        if stream.flush().is_err() {
            break;
        }
        if method == "blockchain.scripthash.listunspent" && fixture.disconnect_after_unspent {
            break;
        }
    }
}
