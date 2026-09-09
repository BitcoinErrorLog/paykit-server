//! Claim-time address-index scan tests (design §B.5, W1.2).
//!
//! The protocol-fixture tests drive the REAL `ElectrumAdapter` through the
//! real scan loop against a mock Electrum server that serves literal
//! `blockchain.scripthash.get_history` fixtures and panics on
//! `listunspent`/`transaction.get`, so any non-presence RPC fails loudly;
//! every request is logged for exact batched-request-count assertions. The
//! handler tests drive the real `POST /v0/accounts/claim` handler and the
//! real `ManualClaimService` with a scripted `ChainHistoryPort` (the only
//! mocked seam) and a refusing session minter: the lazy pool is unreachable,
//! so any accidental persistence fails loudly instead of persisting.

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Address, Network, ScriptBuf,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use paykit_lib::PaykitReceiverPath;
use paykit_sdk::PaykitSdkConfig;
use paykit_server::{
    application::create_invoice::derive_bip84_p2wpkh_address,
    chain_history::{
        CLAIM_SCAN_MAX_WINDOWS, CLAIM_SCAN_WINDOW, ChainHistoryPort, ClaimScanError,
        scan_claim_start_index,
    },
    config::BitcoinNetwork,
    crypto::Crypto,
    http::accounts::{AccountsState, accounts_router},
    manual_claim::{ManualClaimError, ManualClaimService, SessionMinter},
    persistence::CreatorStore,
    real_setup::DirectMarkerPublisher,
    workers::observer::ElectrumAdapter,
};
use pubky::{AuthToken, Capabilities, Keypair, PubkySession};
use tower::ServiceExt;

const USED_HISTORY_HEIGHT: i64 = 117;

fn regtest_account_tpub() -> String {
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

/// External-chain script at `0/{child_index}` for the claimed account — the
/// exact derivation the scan performs.
fn derived_script(xpub: &str, child_index: u32) -> ScriptBuf {
    let address =
        derive_bip84_p2wpkh_address(xpub, 0, &BitcoinNetwork::Regtest, child_index.into()).unwrap();
    Address::from_str(&address)
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

async fn scan(server: &HistoryServer, xpub: &str) -> Result<u32, ClaimScanError> {
    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();
    scan_claim_start_index(&adapter, xpub, 0, &BitcoinNetwork::Regtest).await
}

#[tokio::test]
async fn manual_claim_scan_of_an_unused_account_starts_at_zero_with_one_batched_request() {
    let xpub = regtest_account_tpub();
    let server = HistoryServer::start(vec![]).await;

    let start = scan(&server, &xpub).await.unwrap();

    assert_eq!(start, 0, "an unused account keeps start index 0");
    // ONE batched window = exactly 20 scripthash queries, and nothing else:
    // presence-only means no transaction fanout, ever.
    server.assert_rpc_counts(CLAIM_SCAN_WINDOW as usize, 0, 0);
}

#[tokio::test]
async fn manual_claim_scan_with_usage_at_index_three_starts_at_twenty_four_after_two_windows() {
    let xpub = regtest_account_tpub();
    let server = HistoryServer::start(vec![derived_script(&xpub, 3)]).await;

    let start = scan(&server, &xpub).await.unwrap();

    assert_eq!(start, 3 + 1 + 20, "start is last_used_index + 1 + 20");
    // Window 0 (usage at 3) + window 1 (empty) = two batched requests.
    server.assert_rpc_counts(2 * CLAIM_SCAN_WINDOW as usize, 0, 0);
}

#[tokio::test]
async fn manual_claim_scan_with_usage_at_index_twenty_five_starts_at_forty_six_after_three_windows()
{
    let xpub = regtest_account_tpub();
    // A standards-compliant wallet whose usage reaches into the second
    // window: indices 0..=25 are used, so the last used index (25) sits in
    // the second window (20..40) behind a non-empty first window.
    let used: Vec<ScriptBuf> = (0..=25).map(|index| derived_script(&xpub, index)).collect();
    let server = HistoryServer::start(used).await;

    let start = scan(&server, &xpub).await.unwrap();

    assert_eq!(start, 25 + 1 + 20, "start is last_used_index + 1 + 20");
    // Windows 0 (empty), 1 (usage at 25), 2 (empty) = three batched requests.
    server.assert_rpc_counts(3 * CLAIM_SCAN_WINDOW as usize, 0, 0);
}

#[tokio::test]
async fn manual_claim_scan_fails_unavailable_when_electrum_is_down() {
    let xpub = regtest_account_tpub();
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

    let result = scan_claim_start_index(&adapter, &xpub, 0, &BitcoinNetwork::Regtest).await;

    assert_eq!(result, Err(ClaimScanError::Unavailable));
}

#[tokio::test]
async fn manual_claim_scan_beyond_a_thousand_addresses_refuses_after_exactly_fifty_batches() {
    let xpub = regtest_account_tpub();
    // Usage in EVERY window: all 1,000 bounded addresses carry history.
    let used: Vec<ScriptBuf> = (0..CLAIM_SCAN_MAX_WINDOWS * CLAIM_SCAN_WINDOW)
        .map(|index| derived_script(&xpub, index))
        .collect();
    let server = HistoryServer::start(used).await;

    let adapter = ElectrumAdapter::connect(
        server.endpoint(),
        BitcoinNetwork::Regtest,
        Duration::from_secs(1),
        1,
    )
    .await
    .unwrap();
    let result = scan_claim_start_index(&adapter, &xpub, 0, &BitcoinNetwork::Regtest).await;

    assert_eq!(result, Err(ClaimScanError::HistoryTooDeep));
    server.assert_rpc_counts((CLAIM_SCAN_MAX_WINDOWS * CLAIM_SCAN_WINDOW) as usize, 0, 0);
}

#[tokio::test]
async fn manual_claim_scan_treats_an_over_cap_history_window_as_used() {
    let xpub = regtest_account_tpub();
    // Index 3 carries 2,001 history entries: one over the default 2,000
    // raw-item cap across the window's batched response. The cap is
    // enforced on the raw response values before any domain value is
    // materialised.
    let server =
        HistoryServer::start_with_heavy(vec![], vec![(derived_script(&xpub, 3), 2_001)]).await;

    let start = scan(&server, &xpub).await.unwrap();

    // The over-cap window is treated as used for the WHOLE window — never
    // attributed to individual addresses — so last_used is the window's
    // last index (19) and the scan stops at the next, empty window. This
    // only advances the start index; nothing is derived onto the
    // deep-history address.
    assert_eq!(
        start,
        19 + 1 + 20,
        "over-cap window treated as used: start is the window's last index + 1 + 20"
    );
    // Literal request-log evidence: exactly two batched windows (40
    // get_history queries), no unspent, no transaction fetches.
    server.assert_rpc_counts(40, 0, 0);
}

#[tokio::test]
async fn manual_claim_scan_treats_a_malformed_presence_answer_as_unavailable() {
    struct TruncatingHistory;
    #[async_trait::async_trait]
    impl ChainHistoryPort for TruncatingHistory {
        async fn history_presence_batch(
            &self,
            scripts: &[ScriptBuf],
        ) -> Result<Vec<bool>, ClaimScanError> {
            Ok(vec![false; scripts.len() - 1])
        }
    }
    let xpub = regtest_account_tpub();

    let result =
        scan_claim_start_index(&TruncatingHistory, &xpub, 0, &BitcoinNetwork::Regtest).await;

    assert_eq!(result, Err(ClaimScanError::Unavailable));
}

// ---------------------------------------------------------------------------
// Handler-level tests: the real claim route and service, scripted history
// port, refusing minter, unreachable (lazy) pool.
// ---------------------------------------------------------------------------

/// Scripted claim-scan port. `fail` refuses every batch as an Electrum
/// outage; `used_in_every_window` reports usage for every script; otherwise
/// every window is empty. Every batched call is counted.
struct ScriptedHistory {
    calls: Mutex<usize>,
    fail: bool,
    used_in_every_window: bool,
}

#[async_trait::async_trait]
impl ChainHistoryPort for ScriptedHistory {
    async fn history_presence_batch(
        &self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<bool>, ClaimScanError> {
        *self.calls.lock().unwrap() += 1;
        if self.fail {
            return Err(ClaimScanError::Unavailable);
        }
        Ok(vec![self.used_in_every_window; scripts.len()])
    }
}

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

fn claim_router(history: Arc<ScriptedHistory>) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/paykit")
        .unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let service = Arc::new(ManualClaimService::new(
        pubky::Pubky::new().unwrap(),
        Arc::new(RefusingMinter),
        CreatorStore::new(&pool, crypto),
        Arc::new(DirectMarkerPublisher),
        history,
        BitcoinNetwork::Regtest,
        receiver_path.clone(),
    ));
    accounts_router(AccountsState::new(service, 10, vec![]))
}

fn claim_request() -> Request<Body> {
    let receiver_path = PaykitReceiverPath::new("paykit/server").unwrap();
    let capabilities = PaykitSdkConfig::new(receiver_path).required_session_capabilities();
    let capabilities = Capabilities::try_from(capabilities.as_str()).unwrap();
    let auth_token =
        URL_SAFE_NO_PAD.encode(AuthToken::sign(&Keypair::random(), capabilities).serialize());
    Request::builder()
        .method(Method::POST)
        .uri("/v0/accounts/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "auth_token": auth_token,
                "account_xpub": regtest_account_tpub(),
                "account_index": 0,
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

#[tokio::test]
async fn manual_claim_electrum_failure_refuses_the_claim_with_claim_scan_unavailable() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        fail: true,
        used_in_every_window: false,
    });
    let router = claim_router(history.clone());

    let (status, code) = error_code(router.oneshot(claim_request()).await.unwrap()).await;

    // The claim is REFUSED — never defaulted to index 0 (P1-A) — before the
    // session minter or persistence are reached: the lazy pool is
    // unreachable, so reaching it would have answered `unavailable` instead.
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "claim_scan_unavailable")
    );
    assert_eq!(
        *history.calls.lock().unwrap(),
        1,
        "one batched scan attempt, then refusal"
    );
}

#[tokio::test]
async fn manual_claim_history_too_deep_refuses_the_claim_with_account_history_too_deep() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        fail: false,
        used_in_every_window: true,
    });
    let router = claim_router(history.clone());

    let (status, code) = error_code(router.oneshot(claim_request()).await.unwrap()).await;

    assert_eq!(
        (status, code.as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "account_history_too_deep")
    );
    assert_eq!(
        *history.calls.lock().unwrap(),
        CLAIM_SCAN_MAX_WINDOWS as usize,
        "exactly 50 batched requests before the too-deep refusal"
    );
}

#[tokio::test]
async fn manual_claim_passing_scan_proceeds_to_session_minting() {
    let history = Arc::new(ScriptedHistory {
        calls: Mutex::new(0),
        fail: false,
        used_in_every_window: false,
    });
    let router = claim_router(history.clone());

    let (status, code) = error_code(router.oneshot(claim_request()).await.unwrap()).await;

    // The unused-account scan passed, so the claim advanced to the session
    // minter boundary — proving the scan runs first and gates the claim.
    assert_eq!(
        (status, code.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "session_unavailable")
    );
    assert_eq!(*history.calls.lock().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Mock Electrum server: literal get_history fixtures, request log, loud
// panics on any non-presence RPC.
// ---------------------------------------------------------------------------

struct HistoryServer {
    endpoint: String,
    wake_address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    fixture: Arc<HistoryFixture>,
    handle: Option<thread::JoinHandle<()>>,
}

struct HistoryFixture {
    /// Scripts that answer get_history with one literal history entry.
    used: Vec<ScriptBuf>,
    /// Scripts that answer get_history with a precomputed oversized
    /// history, for the response-item-cap test.
    heavy: Vec<(ScriptBuf, serde_json::Value)>,
    request_log: Mutex<Vec<String>>,
}

impl HistoryServer {
    async fn start(used: Vec<ScriptBuf>) -> Self {
        Self::start_with_fixture(used, vec![]).await
    }

    /// `heavy` maps a script to the number of history entries its
    /// get_history answer carries, precomputed once so serving stays cheap.
    async fn start_with_heavy(used: Vec<ScriptBuf>, heavy: Vec<(ScriptBuf, usize)>) -> Self {
        let heavy = heavy
            .into_iter()
            .map(|(script, entries)| {
                let history = serde_json::Value::Array(
                    (0..entries)
                        .map(|_| {
                            serde_json::json!({
                                "height": USED_HISTORY_HEIGHT,
                                "tx_hash": format!("{:064x}", 42),
                            })
                        })
                        .collect(),
                );
                (script, history)
            })
            .collect();
        Self::start_with_fixture(used, heavy).await
    }

    async fn start_with_fixture(
        used: Vec<ScriptBuf>,
        heavy: Vec<(ScriptBuf, serde_json::Value)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let wake_address = listener.local_addr().unwrap();
        let endpoint = format!("tcp://{wake_address}");
        let fixture = Arc::new(HistoryFixture {
            used,
            heavy,
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

    /// RPC-count evidence: exactly `history` get_history queries,
    /// `unspent` list_unspent calls, and `transactions` transaction.get
    /// calls were served across every connection this server accepted.
    fn assert_rpc_counts(&self, history: usize, unspent: usize, transactions: usize) {
        let log = self.fixture.request_log.lock().unwrap();
        eprintln!("electrum request log: {log:?}");
        let count = |method: &str| log.iter().filter(|entry| *entry == method).count();
        assert_eq!(
            (
                count("blockchain.scripthash.get_history"),
                count("blockchain.scripthash.listunspent"),
                count("blockchain.transaction.get"),
            ),
            (history, unspent, transactions),
            "unexpected Electrum request mix: {log:?}"
        );
    }
}

impl Drop for HistoryServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.wake_address);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

// Multi-threaded: two scans must make progress concurrently while the
// test task polls the in-flight count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_claim_scan_refuses_scans_beyond_the_concurrency_bound_without_an_electrum_call() {
    let xpub = regtest_account_tpub();
    let server = GatedHistoryServer::start().await;
    // Concurrency bound 2 (the default); item cap and deadline explicit.
    let adapter = Arc::new(
        ElectrumAdapter::connect(
            server.endpoint(),
            BitcoinNetwork::Regtest,
            Duration::from_secs(5),
            1,
        )
        .await
        .unwrap()
        .with_claim_scan_bounds(2_000, Duration::from_secs(5), 2),
    );
    let spawn_scan = |adapter: &Arc<ElectrumAdapter>| {
        let adapter = adapter.clone();
        let xpub = xpub.clone();
        tokio::spawn(async move {
            scan_claim_start_index(adapter.as_ref(), &xpub, 0, &BitcoinNetwork::Regtest).await
        })
    };
    // Two concurrent claims take both scan permits and block mid-window
    // behind the server's closed gate.
    let scan_a = spawn_scan(&adapter);
    let scan_b = spawn_scan(&adapter);
    server.wait_in_flight(2);

    // The third concurrent claim exceeds the bound: it is refused
    // Unavailable — `claim_scan_unavailable` at the handler — IMMEDIATELY,
    // before any Electrum call exists.
    let result = scan_claim_start_index(adapter.as_ref(), &xpub, 0, &BitcoinNetwork::Regtest).await;

    assert_eq!(result, Err(ClaimScanError::Unavailable));
    // The refused scan never reached Electrum: still exactly the two
    // admitted windows in flight (a third connection's first get_history
    // would have joined them behind the gate), and only their two first
    // batched lines logged so far.
    assert_eq!(
        server.in_flight(),
        2,
        "no third window fetch joined the two admitted scans"
    );
    assert_eq!(
        server.rpc_count("blockchain.scripthash.get_history"),
        2,
        "only the two admitted windows reached Electrum"
    );

    // The two admitted claims proceed once the gate opens; the refused
    // one never made an Electrum call, so the log ends at exactly two
    // batched windows (2 x 20).
    server.open_gate();
    assert_eq!(scan_a.await.unwrap(), Ok(0));
    assert_eq!(scan_b.await.unwrap(), Ok(0));
    assert_eq!(
        server.rpc_count("blockchain.scripthash.get_history"),
        40,
        "the refused scan never made an Electrum call"
    );
}

// ---------------------------------------------------------------------------
// Gated mock Electrum server: blocks each connection's first get_history
// response behind a test-controlled gate, so concurrent scans can be held
// mid-window deterministically. Serves empty histories once the gate opens.
// ---------------------------------------------------------------------------

struct GatedHistoryServer {
    endpoint: String,
    wake_address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    request_log: Arc<Mutex<Vec<String>>>,
    in_flight: Arc<AtomicUsize>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl GatedHistoryServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let wake_address = listener.local_addr().unwrap();
        let endpoint = format!("tcp://{wake_address}");
        let request_log = Arc::new(Mutex::new(Vec::new()));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread_log = request_log.clone();
        let thread_in_flight = in_flight.clone();
        let thread_gate = gate.clone();
        let handle = thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                if thread_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let log = thread_log.clone();
                let in_flight = thread_in_flight.clone();
                let gate = thread_gate.clone();
                thread::spawn(move || serve_gated_connection(stream, log, in_flight, gate));
            }
        });
        Self {
            endpoint,
            wake_address,
            shutdown,
            request_log,
            in_flight,
            gate,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Waits until `expected` window fetches are blocked behind the gate
    /// (their permits held), panicking after five seconds.
    fn wait_in_flight(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.in_flight.load(Ordering::SeqCst) < expected {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected} in-flight scan windows; request log: {:?}",
                self.request_log.lock().unwrap()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    fn open_gate(&self) {
        let (lock, condvar) = &*self.gate;
        *lock.lock().unwrap() = true;
        condvar.notify_all();
    }

    fn rpc_count(&self, method: &str) -> usize {
        self.request_log
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| *entry == method)
            .count()
    }
}

impl Drop for GatedHistoryServer {
    fn drop(&mut self) {
        // Release any blocked handler before shutting the listener down.
        self.open_gate();
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.wake_address);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn serve_gated_connection(
    mut stream: TcpStream,
    request_log: Arc<Mutex<Vec<String>>>,
    in_flight: Arc<AtomicUsize>,
    gate: Arc<(Mutex<bool>, Condvar)>,
) {
    let reader = BufReader::new(stream.try_clone().unwrap());
    let mut waited = false;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap();
        request_log.lock().unwrap().push(method.to_owned());
        let result = match method {
            "server.version" => serde_json::json!(["paykit-test-electrum", "1.4"]),
            "blockchain.scripthash.get_history" => {
                // Block this connection's first get_history response until
                // the test opens the gate.
                if !waited {
                    waited = true;
                    in_flight.fetch_add(1, Ordering::SeqCst);
                    let (lock, condvar) = &*gate;
                    let mut open = lock.lock().unwrap();
                    while !*open {
                        open = condvar.wait(open).unwrap();
                    }
                    drop(open);
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
                serde_json::json!([])
            }
            // The claim scan is presence-only; any other RPC fails loudly.
            "blockchain.scripthash.listunspent" => {
                panic!("claim scan called blockchain.scripthash.listunspent")
            }
            "blockchain.transaction.get" => {
                panic!("claim scan called blockchain.transaction.get")
            }
            method => panic!("unexpected Electrum method: {method}"),
        };
        let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        if writeln!(stream, "{response}").is_err() {
            break;
        }
        if stream.flush().is_err() {
            break;
        }
    }
}

fn serve_connection(mut stream: TcpStream, fixture: Arc<HistoryFixture>) {
    use bdk_electrum::electrum_client::{ScriptHash, ToElectrumScriptHash};
    let reader = BufReader::new(stream.try_clone().unwrap());
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap();
        fixture.request_log.lock().unwrap().push(method.to_owned());
        let result = match method {
            "server.version" => serde_json::json!(["paykit-test-electrum", "1.4"]),
            "blockchain.scripthash.get_history" => {
                let requested_hash: ScriptHash =
                    serde_json::from_value(request["params"][0].clone()).unwrap();
                if let Some((_, history)) = fixture
                    .heavy
                    .iter()
                    .find(|(script, _)| script.to_electrum_scripthash() == requested_hash)
                {
                    history.clone()
                } else if fixture
                    .used
                    .iter()
                    .any(|script| script.to_electrum_scripthash() == requested_hash)
                {
                    serde_json::json!([{
                        "height": USED_HISTORY_HEIGHT,
                        "tx_hash": format!("{:064x}", 42),
                    }])
                } else {
                    serde_json::json!([])
                }
            }
            // The claim scan is presence-only; if it ever asks for UTXOs or
            // transactions, fail the test loudly instead of silently serving
            // a fanout.
            "blockchain.scripthash.listunspent" => {
                panic!("claim scan called blockchain.scripthash.listunspent")
            }
            "blockchain.transaction.get" => {
                panic!("claim scan called blockchain.transaction.get")
            }
            method => panic!("unexpected Electrum method: {method}"),
        };
        let response = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result});
        if writeln!(stream, "{response}").is_err() {
            break;
        }
        if stream.flush().is_err() {
            break;
        }
    }
}
