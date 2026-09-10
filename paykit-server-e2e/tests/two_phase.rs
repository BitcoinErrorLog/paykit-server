//! W1.1c — two-phase creation and activation (design §B.11), against real
//! Postgres and the production HTTP path.
//!
//! Covered here, each test named in the work-item report:
//! - phase 1 returns 200 with the verbatim §B.11.3 body on BOTH entrypoints,
//!   lands the invoice `prepared`, writes both outbox rows `'prepared'`, and
//!   `OutboxStore::claim` returns zero rows for them (zero-claims);
//! - §B.11.5 immutability: a funded `prepared` address is never observed,
//!   never published, never payable;
//! - activate: signature/total/stack_id refusals change nothing; success
//!   flips `prepared → observing`, queues both rows, persists the §B.4.6
//!   tick-1 snapshot and `activated_at`; replay is byte-identical and
//!   write-free;
//! - void: `prepared → void_cancelled`, idempotent replay, and the §B.11.3 /
//!   §B.11.6 named errors for every other state;
//! - the §B.11.1 reaper voids only expired prepares;
//! - a phase-1 replay on `prepared` mints nothing (index cursor, nonce,
//!   outbox rows all equal before/after);
//! - W1.4 continuity: a hidden offer refuses a New prepare with 503
//!   `bitcoin_offer_unavailable` while activate/void keep working.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bitcoin::{
    Network, OutPoint, Txid,
    bip32::{ChildNumber, Xpriv, Xpub},
    hashes::Hash,
    secp256k1::Secp256k1,
};
use ed25519_dalek::{Signer, SigningKey};
use locks_core::{
    ids::CreatorPubky as RawCreatorPubky,
    lock_policy::{
        AccessPolicy, CONTENT_LOCK_VERSION, ContentLock, Criterion, LockLogic, LockServerConfig,
        VerifierType,
    },
};
use paykit_lib::{PaykitReceiverCapabilities, PaykitReceiverPath};
use paykit_sdk::{
    InMemoryStorage, PaykitSdk, PaykitSdkConfig, PubkyLocalSecretKey, PubkyPublicKey,
    PubkySessionBootstrap, ReceiverNoiseSecretKey,
};
use paykit_server::{
    Server,
    allocation::ClaimAllocation,
    application::create_invoice::{
        CreateInvoiceError, DeadlineClock, InvoicePersistence, MarkerDiscovery,
        PaykitIntentBuilder, SessionValidationError, SessionValidator, derive_bip84_p2wpkh_address,
    },
    application::create_payment_request::{
        MarketplacePaymentRequest, MarketplacePaymentRequestService,
    },
    bitcoin::ObservationTarget,
    config::{BitcoinNetwork, Config, ConfigEnvironment, ReceiverPathPriority},
    crypto::Crypto,
    domain::locks::{CreatorPubky, ReaderPubky, parse_bundle_id, parse_creator, parse_reader},
    domain::payment::BitcoinOutpoint,
    persistence::{
        AtomicInvoiceInput, AtomicInvoiceResult, CreatorCredentials, CreatorStore,
        InvoicePhaseView, InvoicePreflight, InvoiceStore, NewReaderPayloadFactory,
        NewReaderPayloads, OutboxStore, PersistenceError, run_migrations,
    },
    runtime::{ElectrumProbe, Runtime},
    startup::initialize_database,
    workers::observer::{
        CreationSnapshot, ElectrumPort, ObservationReport, ObserverError, RequestLimiter, TipProbe,
    },
};
use paykit_server_e2e::postgres::TestDatabase;
use pubky_testnet::{EphemeralTestnet, pubky::Keypair};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "fixtures/sdk.rs"]
mod sdk_fixtures;

use sdk_fixtures::{TestPaymentAdapter, TestSessionProvider};

const MASTER_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const REFERENCE_A: &str = "000G40R40M30E209185GR38E1W";
const REFERENCE_B: &str = "000G40R40M30E209185GR38E2W";
const REFERENCE_C: &str = "000G40R40M30E209185GR38E3W";
const BUNDLE_LOCKS: &str = "000G40R40M30E209185GR38E4W";
const EXPIRES_AT: &str = "2030-01-01T00:00:00Z";
static PUBKY_TESTNET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Electrum fake: a fundable UTXO map for observations, plus a scriptable
/// set of unconfirmed outputs/inputs returned by the next creation-style
/// snapshot (the §B.4.6 tick-1 snapshot inside activation reuses that
/// snapshot shape).
/// (unconfirmed outputs, their inputs) scripted for one address's next
/// creation-style snapshot.
type ScriptedSnapshot = (Vec<OutPoint>, Vec<OutPoint>);

struct ScriptedElectrum {
    outputs: Mutex<HashMap<String, (u64, OutPoint)>>,
    snapshot_unconfirmed: Mutex<HashMap<String, ScriptedSnapshot>>,
}

impl ScriptedElectrum {
    fn new() -> Self {
        Self {
            outputs: Mutex::new(HashMap::new()),
            snapshot_unconfirmed: Mutex::new(HashMap::new()),
        }
    }

    fn fund(&self, address: &str, sats: u64, outpoint: OutPoint) {
        self.outputs
            .lock()
            .unwrap()
            .insert(address.to_owned(), (sats, outpoint));
    }

    /// The next creation-style snapshot of `address` reports these
    /// unconfirmed outputs (and their inputs) — scripted AFTER the creation
    /// baseline so only the activation tick-1 snapshot can see them.
    fn script_unconfirmed_at_snapshot(
        &self,
        address: &str,
        outputs: Vec<OutPoint>,
        inputs: Vec<OutPoint>,
    ) {
        self.snapshot_unconfirmed
            .lock()
            .unwrap()
            .insert(address.to_owned(), (outputs, inputs));
    }
}

#[async_trait]
impl ElectrumPort for ScriptedElectrum {
    async fn creation_snapshot(
        &self,
        address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        let (unconfirmed_outputs, unconfirmed_inputs) = self
            .snapshot_unconfirmed
            .lock()
            .unwrap()
            .remove(address)
            .unwrap_or_default();
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: unconfirmed_outputs.clone(),
            unconfirmed_inputs,
            unconfirmed_outputs,
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        let outputs = self.outputs.lock().unwrap();
        Ok(ObservationReport {
            outputs: targets
                .iter()
                .filter_map(|target| {
                    outputs.get(target.address()).map(|(sats, outpoint)| {
                        paykit_server::bitcoin::ObservedOutput {
                            network: BitcoinNetwork::Testnet,
                            address: target.address().to_owned(),
                            outpoint: *outpoint,
                            sats: *sats,
                            confirmations: 6,
                            confirmed_height: Some(301),
                            present: true,
                        }
                    })
                })
                .collect(),
            observed: targets
                .iter()
                .map(|target| target.address().to_owned())
                .collect(),
            failed: Vec::new(),
        })
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 300,
            time_unix: fresh_tip_time(),
        })
    }
}

fn fresh_tip_time() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn config(database_url: &str, signing_key: &SigningKey) -> Config {
    let trusted_key = pubky::PublicKey::from(
        pubky::pkarr::PublicKey::try_from(signing_key.verifying_key().as_bytes()).unwrap(),
    )
    .to_string();
    Config::from_toml_and_environment(
        &format!(
            r#"
[http]
listen_addr = "127.0.0.1:0"
[locks]
trusted_public_key = "{trusted_key}"
[setup]
allowed_origins = ["https://app.example"]
[paykit]
receiver_path = "paykit/server"
network = "testnet"
[bitcoin]
network = "testnet"
[deployment]
stack_role = "proof"
[electrum]
endpoint = "tcp://127.0.0.1:1"
poll_interval = "1s"
request_timeout = "1s"
max_concurrent_creation_snapshots = 1
[outbox]
poll_interval = "1h"
batch_size = 16
lease_duration = "5s"
retry_initial = "1s"
retry_max = "2s"
[shutdown]
drain_timeout = "2s"
"#
        ),
        ConfigEnvironment {
            database_url: Some(database_url.to_owned()),
            master_key: Some(MASTER_KEY.to_owned()),
        },
    )
    .unwrap()
}

struct CreatorFixture {
    creator: CreatorPubky,
    lock_resource: String,
    xpub: String,
    account_index: u32,
}

fn account_xpub(seed: u8, account_index: u32) -> String {
    let secp = Secp256k1::new();
    let account = Xpriv::new_master(Network::Testnet, &[seed; 32])
        .unwrap()
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).unwrap(),
                ChildNumber::from_hardened_idx(1).unwrap(),
                ChildNumber::from_hardened_idx(account_index).unwrap(),
            ],
        )
        .unwrap();
    Xpub::from_priv(&secp, &account).to_string()
}

fn content_lock(creator: &CreatorPubky, amount_sats: u64) -> ContentLock {
    ContentLock {
        version: CONTENT_LOCK_VERSION,
        creator: RawCreatorPubky::from_str(&creator.to_string()).unwrap(),
        primary_resource: None,
        secondary_resources: BTreeMap::new(),
        criteria: vec![Criterion {
            criterion_id: "payment".into(),
            verifier_type: VerifierType::PaykitPayment,
            params: serde_json::json!({
                "recipient_pubky": creator.to_string(),
                "amount": amount_sats.to_string(),
                "asset": "BTC"
            }),
        }],
        lock_logic: LockLogic::All {
            criteria: vec!["payment".into()],
        },
        access_policy: AccessPolicy {
            requested_credential_ttl_seconds: 900,
        },
        lock_server: LockServerConfig { override_: None },
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

struct BootedStack {
    address: SocketAddr,
    pool: PgPool,
    runtime: Arc<Runtime>,
    stack_id: String,
    store: InvoiceStore,
    outbox: OutboxStore,
    signing_key: SigningKey,
    creator: CreatorFixture,
    reader: ReaderPubky,
    electrum: Arc<ScriptedElectrum>,
    /// Held only for its Drop: dropping the testnet shuts the homeserver
    /// down, and every pubky read (session validation, marker discovery)
    /// fails from that moment.
    _testnet: EphemeralTestnet,
    database: TestDatabase,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    running: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl BootedStack {
    fn invoice_address(&self, child_index: i64) -> String {
        derive_bip84_p2wpkh_address(
            &self.creator.xpub,
            self.creator.account_index,
            &BitcoinNetwork::Testnet,
            child_index,
        )
        .unwrap()
    }

    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        self.running.await.unwrap().unwrap();
        self.pool.close().await;
        self.database.cleanup().await;
    }
}

/// Boots the production server over a real database and an ephemeral pubky
/// testnet, with one creator (credentials stored, content lock published)
/// and one reader (marker published). The outbox worker is configured at a
/// 1 h poll so NOTHING delivers unless a test drives the store directly —
/// 'queued' vs 'prepared' visibility is asserted, never raced.
async fn boot(seed: u8) -> BootedStack {
    let database = TestDatabase::create().await;
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let server_config = config(database.database_url(), &signing_key);
    let initialized = initialize_database(&server_config).await.unwrap();
    let pool = initialized.pool.clone();
    let stack_identity = initialized.stack_identity.clone();
    let testnet = EphemeralTestnet::builder()
        .postgres(
            pubky_testnet::pubky_homeserver::ConnectionString::new(
                &std::env::var("TEST_DATABASE_URL").unwrap(),
            )
            .unwrap(),
        )
        .build()
        .await
        .unwrap();
    let pubky = testnet.sdk().unwrap();
    let bootstrap = PubkySessionBootstrap::with_pubky(pubky.clone());
    let homeserver = PubkyPublicKey::from_public_key(&testnet.homeserver_app().public_key());
    let crypto = Arc::new(Crypto::from_master_key(&[1; 32]).unwrap());
    let creators = CreatorStore::new(&pool, crypto.clone());

    // Reader: marker published, nothing else.
    let reader_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let reader_sdk = PaykitSdk::new(
        InMemoryStorage::default(),
        TestSessionProvider::new(reader_account.access),
        TestPaymentAdapter,
        PaykitSdkConfig::new(PaykitReceiverPath::new("bitkit/server").unwrap()),
    )
    .unwrap();
    reader_sdk.initialize().await.unwrap();
    reader_sdk
        .publish_paykit_receiver_marker(PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: true,
            outgoing_payments: true,
        })
        .await
        .unwrap();
    let reader = parse_reader(&format!("pubky{}", reader_account.public_key)).unwrap();

    // Creator: credentials in the store, content lock published.
    let creator_account = bootstrap
        .sign_up(
            &PubkyLocalSecretKey::new(Keypair::random().secret_key()),
            ReceiverNoiseSecretKey::random(),
            &homeserver,
            None,
            &PaykitSdkConfig::new(PaykitReceiverPath::new("paykit/server").unwrap())
                .required_session_capabilities(),
        )
        .await
        .unwrap();
    let creator = parse_creator(&format!("pubky{}", creator_account.public_key)).unwrap();
    let xpub = account_xpub(seed, 0);
    let amount_sats = 50_000;
    let lock = content_lock(&creator, amount_sats);
    let lock_path = lock.content_lock_path().unwrap().to_string();
    creator_account
        .access
        .session
        .storage()
        .put_json(lock_path.clone(), &lock)
        .await
        .unwrap();
    creators
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                creator_account.access.session.export_secret(),
                creator_account.access.receiver_noise_secret_key.clone(),
                xpub.clone(),
                0,
            ),
            &Default::default(),
            &key_tail(seed),
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();

    let electrum = Arc::new(ScriptedElectrum::new());
    let server = Server::build_with_transports(
        server_config,
        pool.clone(),
        stack_identity.clone(),
        pubky,
        electrum.clone(),
    )
    .await
    .unwrap();
    let runtime = server.runtime();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run_until(listener, async move {
        let _ = shutdown_rx.await;
    }));
    wait_until_listening(address).await;
    wait_until_ready(address).await;
    for _ in 0..3 {
        runtime.record_electrum_probe(ElectrumProbe::success(300, fresh_tip_time()));
    }
    assert!(runtime.readiness().await.bitcoin_offer_available);

    BootedStack {
        address,
        store: InvoiceStore::new(&pool, crypto.clone()),
        outbox: OutboxStore::new(&pool, crypto.clone()),
        pool,
        runtime,
        stack_id: stack_identity.stack_id(),
        signing_key,
        creator: CreatorFixture {
            creator: creator.clone(),
            lock_resource: format!("{creator}{lock_path}"),
            xpub,
            account_index: 0,
        },
        reader,
        electrum,
        _testnet: testnet,
        database,
        shutdown_tx,
        running,
    }
}

fn key_tail(seed: u8) -> [u8; 65] {
    [seed; 65]
}

struct HttpResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response body is not JSON ({error}): {}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

fn signed_request(signing_key: &SigningKey, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            "X-Paykit-Signature",
            URL_SAFE_NO_PAD.encode(signing_key.sign(body.as_bytes()).to_bytes()),
        )
        .body(Body::from(body))
        .unwrap()
}

/// Canonical JSON (sorted keys) — the signed-body middleware rejects
/// anything else.
fn payment_request_body(creator: &CreatorPubky, reader: &ReaderPubky, reference: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "amount_sats": 50_000,
        "creator": creator.to_string(),
        "reader": reader.to_string(),
        "reference": reference,
        "expires_at": EXPIRES_AT,
        "idempotency_key": format!("{reference}:1"),
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn locks_invoice_body(fixture: &CreatorFixture, reader: &ReaderPubky, bundle: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "bundle_id": bundle,
        "lock_resource": fixture.lock_resource,
        "reader": reader.to_string(),
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn activate_body(invoice_id: &str, stack_id: &str, total_sats: u64) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "activation_attempt": 1,
        "invoice_id": invoice_id,
        "stack_id": stack_id,
        "total_sats": total_sats,
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

fn void_body(invoice_id: &str, stack_id: &str) -> String {
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "invoice_id": invoice_id,
        "reason": "marketplace_bind_rolled_back",
        "stack_id": stack_id,
    }))
    .unwrap()
    .into_iter()
    .map(char::from)
    .collect()
}

async fn post(stack: &BootedStack, uri: &str, body: String) -> HttpResponse {
    send_http(stack.address, signed_request(&stack.signing_key, uri, body)).await
}

/// Phase 1 on the marketplace entrypoint; asserts 200 and returns the body.
async fn prepare(stack: &BootedStack, reference: &str) -> serde_json::Value {
    let response = post(
        stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, reference),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "prepare body: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json()
}

async fn activate(stack: &BootedStack, invoice_id: &str, total_sats: u64) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/activate"),
        activate_body(invoice_id, &stack.stack_id.clone(), total_sats),
    )
    .await
}

async fn void(stack: &BootedStack, invoice_id: &str) -> HttpResponse {
    post(
        stack,
        &format!("/v0/payment-requests/{invoice_id}/void"),
        void_body(invoice_id, &stack.stack_id.clone()),
    )
    .await
}

async fn send_http(address: SocketAddr, request: Request<Body>) -> HttpResponse {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 32 * 1024).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        parts.method,
        parts.uri,
        address,
        body.len()
    );
    for (name, value) in &parts.headers {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value.to_str().unwrap());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&response[..header_end]).unwrap();
    let status = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    HttpResponse {
        status: StatusCode::from_u16(status).unwrap(),
        body: response[(header_end + 4)..].to_vec(),
    }
}

async fn wait_until_listening(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("server did not start listening");
}

async fn wait_until_ready(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(address).await {
            let _ = stream
                .write_all(b"GET /health/ready HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await;
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response).await;
            let head = String::from_utf8_lossy(&response);
            if head.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server did not become ready");
}

async fn baseline_state(pool: &PgPool, invoice_id: &str) -> String {
    sqlx::query_scalar("SELECT baseline_state FROM invoices WHERE id = $1")
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn outbox_statuses(pool: &PgPool, invoice_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT status FROM outbox WHERE invoice_id = $1 ORDER BY depends_on_id NULLS FIRST",
    )
    .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
    .fetch_all(pool)
    .await
    .unwrap()
}

fn assert_b11_prepare_body(body: &serde_json::Value, stack_id: &str, amount_sats: u64) {
    assert_eq!(body["state"], "prepared");
    assert_eq!(body["stack_id"], stack_id);
    assert_eq!(body["allocation_mode"], "shared_manual");
    let nonce = body["nonce_sats"].as_u64().unwrap();
    assert!((1..=999).contains(&nonce), "nonce {nonce} outside [1, 999]");
    assert_eq!(body["total_sats"].as_u64().unwrap(), amount_sats + nonce);
    assert_eq!(body["expires_at"], EXPIRES_AT);
    assert!(
        body["prepare_expires_at"].as_str().is_some(),
        "prepare_expires_at must be set: {body}"
    );
    let fingerprint = body["derived_address_fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 16);
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    // The address itself is NEVER in the body (§B.11.3): only its
    // fingerprint leaves the server before activation.
    let serialized = serde_json::to_string(body).unwrap();
    assert!(!serialized.contains("bcrt1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn prepare_returns_the_b11_body_and_zero_claims_on_both_entrypoints() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(61).await;

    // Marketplace entrypoint.
    let body = prepare(&stack, REFERENCE_A).await;
    assert_b11_prepare_body(&body, &stack.stack_id, 50_000);
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    // Zero-claims: `OutboxStore::claim` must never select a 'prepared' row.
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty(),
        "a 'prepared' outbox row must never be claimable"
    );
    // And the invoice is not an observation target while prepared.
    assert!(stack.store.observation_plan().await.unwrap().is_empty());

    // Locks entrypoint: same body shape (expires_at is null until the §B.9
    // expiry edges land for this path), same prepared landing, same
    // zero-claims.
    let locks_response = post(
        &stack,
        "/invoices",
        locks_invoice_body(&stack.creator, &stack.reader, BUNDLE_LOCKS),
    )
    .await;
    assert_eq!(
        locks_response.status,
        StatusCode::OK,
        "locks prepare body: {}",
        String::from_utf8_lossy(&locks_response.body)
    );
    let locks_body = locks_response.json();
    assert_eq!(locks_body["state"], "prepared");
    assert_eq!(locks_body["stack_id"], stack.stack_id);
    assert_eq!(locks_body["allocation_mode"], "shared_manual");
    let locks_nonce = locks_body["nonce_sats"].as_u64().unwrap();
    assert_eq!(
        locks_body["total_sats"].as_u64().unwrap(),
        50_000 + locks_nonce
    );
    assert!(locks_body["expires_at"].is_null());
    let locks_invoice_id = locks_body["invoice_id"].as_str().unwrap().to_owned();
    assert_eq!(
        baseline_state(&stack.pool, &locks_invoice_id).await,
        "prepared"
    );
    assert_eq!(
        outbox_statuses(&stack.pool, &locks_invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(stack.store.observation_plan().await.unwrap().is_empty());

    stack.shutdown().await;
}

/// §B.11.5: a funded `prepared` address is never observed, never published,
/// never payable.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_funded_prepared_address_is_never_observed_published_or_payable() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(62).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let address = stack.invoice_address(0);

    // Fund the derived address (as if a buyer somehow obtained it) with the
    // exact nonce'd total, confirmed well above the creation floor.
    let funding = OutPoint::new(Txid::from_byte_array([77; 32]), 0);
    stack.electrum.fund(&address, total_sats, funding);

    // Zero targets: the invoice is not in the observation plan.
    assert!(
        stack.store.observation_plan().await.unwrap().is_empty(),
        "a prepared invoice must never be an observation target"
    );
    // Zero observations: even a direct application of the funded output
    // changes nothing (the store gate admits only `observing` invoices and
    // reports the no-op as handled).
    assert!(
        stack
            .store
            .apply_bitcoin_observation_at_height(
                &address,
                &BitcoinOutpoint::from_bitcoin(funding),
                total_sats,
                6,
                Some(301),
                true,
            )
            .await
            .unwrap(),
        "a non-observing invoice must no-op the observation"
    );
    let facts: (String, i64) = sqlx::query_as(
        "SELECT payment_status, (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1) FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(facts.0, "undetected");
    assert_eq!(facts.1, 0, "no observation row may be written");
    // Zero publishes: both outbox rows are still 'prepared', never claimed.
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    assert!(
        stack
            .outbox
            .claim(uuid::Uuid::new_v4(), 10, Duration::from_secs(30))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");

    stack.shutdown().await;
}

/// activate: signature, total and stack_id refusals each leave the invoice
/// and its outbox rows exactly as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn activate_refusals_leave_the_invoice_untouched() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(63).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let updated_at: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM invoices WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();

    // A stranger's signature is refused by the same middleware the create
    // routes use — the request never reaches the state machine.
    let stranger = SigningKey::from_bytes(&[250; 32]);
    let response = send_http(
        stack.address,
        signed_request(
            &stranger,
            &format!("/v0/payment-requests/{invoice_id}/activate"),
            activate_body(&invoice_id, &stack.stack_id, total_sats),
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // A wrong echoed total is the R3-3 guard: activation_total_mismatch,
    // no activation.
    let response = activate(&stack, &invoice_id, total_sats - 1).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(
        response.json()["error"]["code"],
        "activation_total_mismatch"
    );

    // A body naming another stack is refused at the first message.
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{invoice_id}/activate"),
        activate_body(
            &invoice_id,
            "production:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
            total_sats,
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "stack_identity_mismatch");

    // A path/body invoice-id disagreement is a plain invalid request (the
    // signature covers the body, not the path).
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{}/activate", uuid::Uuid::new_v4()),
        activate_body(&invoice_id, &stack.stack_id, total_sats),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);

    // NO state change anywhere.
    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "prepared");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["prepared".to_owned(), "prepared".to_owned()]
    );
    let after: time::OffsetDateTime =
        sqlx::query_scalar("SELECT updated_at FROM invoices WHERE id = $1")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_one(&stack.pool)
            .await
            .unwrap();
    assert_eq!(
        after, updated_at,
        "a refusal must not touch the invoice row"
    );

    stack.shutdown().await;
}

/// activate success: `prepared → observing`, both rows queued, the §B.4.6
/// tick-1 snapshot persisted, `activated_at` set — and a replay returns the
/// identical body while writing nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn activate_flips_persists_the_tick1_snapshot_and_replays_without_writes() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(64).await;
    let body = prepare(&stack, REFERENCE_A).await;
    let invoice_id = body["invoice_id"].as_str().unwrap().to_owned();
    let total_sats = body["total_sats"].as_u64().unwrap();
    let address = stack.invoice_address(0);

    // R1's case: a transaction the Electrum had not indexed at the creation
    // baseline is unconfirmed at the activation (tick-1) snapshot.
    let pre_existing = OutPoint::new(Txid::from_byte_array([88; 32]), 1);
    let spent_input = OutPoint::new(Txid::from_byte_array([89; 32]), 0);
    stack
        .electrum
        .script_unconfirmed_at_snapshot(&address, vec![pre_existing], vec![spent_input]);

    let response = activate(&stack, &invoice_id, total_sats).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "activate body: {}",
        String::from_utf8_lossy(&response.body)
    );
    let activated = response.json();
    assert_eq!(activated["state"], "observing");
    assert_eq!(activated["invoice_id"], invoice_id);
    assert_eq!(activated["total_sats"], total_sats);
    assert_eq!(activated["expires_at"], EXPIRES_AT);
    assert!(activated["activated_at"].as_str().is_some());

    assert_eq!(baseline_state(&stack.pool, &invoice_id).await, "observing");
    assert_eq!(
        outbox_statuses(&stack.pool, &invoice_id).await,
        vec!["queued".to_owned(), "queued".to_owned()]
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT activated_at IS NOT NULL FROM invoices WHERE id = $1"
        )
        .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
        .fetch_one(&stack.pool)
        .await
        .unwrap()
    );
    // The tick-1 snapshot is persisted: the unconfirmed output is a
    // `pre_existing` baseline member and its inputs are recorded for the
    // §B.4.3 replacement rule.
    let baseline_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT txid || ':' || vout, kind FROM invoice_baseline_outpoints WHERE invoice_id = $1 ORDER BY kind",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_all(&stack.pool)
    .await
    .unwrap();
    assert_eq!(
        baseline_rows,
        vec![
            (pre_existing.to_string(), "pre_existing".to_owned()),
            (spent_input.to_string(), "replaced_input".to_owned()),
        ]
    );

    // The `pre_existing` output is permanently ineligible: funded confirmed
    // above the floor, it writes no observation and changes no status.
    assert!(
        stack
            .store
            .apply_bitcoin_observation_at_height(
                &address,
                &BitcoinOutpoint::from_bitcoin(pre_existing),
                total_sats,
                1,
                Some(301),
                true,
            )
            .await
            .unwrap()
    );
    let facts: (String, i64) = sqlx::query_as(
        "SELECT payment_status, (SELECT COUNT(*) FROM bitcoin_observations WHERE invoice_id = $1) FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(facts.0, "undetected");
    assert_eq!(facts.1, 0);

    // Replay: the same body, and provably no writes (row counts and
    // updated_at columns unchanged).
    let before: (time::OffsetDateTime, i64, i64) = sqlx::query_as(
        "SELECT updated_at, \
                (SELECT COUNT(*) FROM outbox WHERE invoice_id = $1), \
                (SELECT COUNT(*) FROM invoice_baseline_outpoints WHERE invoice_id = $1) \
         FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    let outbox_updated: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT updated_at FROM outbox WHERE invoice_id = $1 ORDER BY id")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_all(&stack.pool)
            .await
            .unwrap();
    let replay = activate(&stack, &invoice_id, total_sats).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.body, response.body,
        "activate replay must be byte-identical"
    );
    let after: (time::OffsetDateTime, i64, i64) = sqlx::query_as(
        "SELECT updated_at, \
                (SELECT COUNT(*) FROM outbox WHERE invoice_id = $1), \
                (SELECT COUNT(*) FROM invoice_baseline_outpoints WHERE invoice_id = $1) \
         FROM invoices WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
    .fetch_one(&stack.pool)
    .await
    .unwrap();
    assert_eq!(after, before, "an activate replay must write nothing");
    let outbox_updated_after: Vec<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT updated_at FROM outbox WHERE invoice_id = $1 ORDER BY id")
            .bind(uuid::Uuid::parse_str(&invoice_id).unwrap())
            .fetch_all(&stack.pool)
            .await
            .unwrap();
    assert_eq!(outbox_updated_after, outbox_updated);

    stack.shutdown().await;
}

/// What one phase-2 operation must do against one §B.11.1 state.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase2Outcome {
    /// 200 echoing the stored state — an idempotent replay or an
    /// already-satisfied intent; zero writes (§B.11.6).
    Replay,
    /// The operation's own transition (`prepared` only): it writes.
    Transition,
    /// The named refusal; zero writes (§B.11.3/§B.11.6).
    Refused(StatusCode, &'static str),
}

/// A distinct, canonical marketplace reference per table row (Crockford
/// base32, 26 chars): the last two characters encode the row index.
fn table_reference(index: usize) -> String {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut reference = REFERENCE_A[..24].to_owned();
    reference.push(CROCKFORD[(index / 8) % 32] as char);
    // The final symbol of a 16-byte Crockford encoding carries only its
    // top three bits; keep the low two zero or the id is non-canonical.
    reference.push(CROCKFORD[(index % 8) * 4] as char);
    reference
}

/// Everything a refused or replayed phase-2 operation must NOT move: the
/// invoice's `updated_at`, its outbox rows, and the observation targets.
struct WritesSnapshot {
    baseline_state: String,
    updated_at: String,
    outbox: Vec<(String, String, String)>,
    observation_targets: Vec<String>,
}

async fn writes_snapshot(stack: &BootedStack, invoice_id: &str) -> WritesSnapshot {
    let id = uuid::Uuid::parse_str(invoice_id).unwrap();
    let (baseline_state, updated_at): (String, String) =
        sqlx::query_as("SELECT baseline_state, updated_at::text FROM invoices WHERE id = $1")
            .bind(id)
            .fetch_one(&stack.pool)
            .await
            .unwrap();
    let outbox: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id::text, status, updated_at::text FROM outbox \
         WHERE invoice_id = $1 ORDER BY created_at, id",
    )
    .bind(id)
    .fetch_all(&stack.pool)
    .await
    .unwrap();
    let mut observation_targets: Vec<String> = stack
        .store
        .observation_plan()
        .await
        .unwrap()
        .iter()
        .map(|planned| planned.target().address().to_owned())
        .collect();
    observation_targets.sort();
    WritesSnapshot {
        baseline_state,
        updated_at,
        outbox,
        observation_targets,
    }
}

fn assert_zero_writes(before: &WritesSnapshot, after: &WritesSnapshot, op: &str, state: &str) {
    assert_eq!(
        after.baseline_state, before.baseline_state,
        "{op} on {state} must not move the state"
    );
    assert_eq!(
        after.updated_at, before.updated_at,
        "{op} on {state} must not touch updated_at"
    );
    assert_eq!(
        after.outbox, before.outbox,
        "{op} on {state} must not touch outbox rows"
    );
    assert_eq!(
        after.observation_targets, before.observation_targets,
        "{op} on {state} must not move observation targets"
    );
}

/// Drives a freshly prepared invoice into the row's §B.11.1 state.
async fn drive_to_state(stack: &BootedStack, invoice_id: &str, total_sats: u64, state: &str) {
    match state {
        "prepared" => {}
        "observing" | "expired_tail" => {
            let response = activate(stack, invoice_id, total_sats).await;
            assert_eq!(
                response.status,
                StatusCode::OK,
                "setup activation for {state}: {}",
                String::from_utf8_lossy(&response.body)
            );
            if state == "expired_tail" {
                set_baseline_state(stack, invoice_id, state).await;
            }
        }
        other => set_baseline_state(stack, invoice_id, other).await,
    }
    assert_eq!(baseline_state(&stack.pool, invoice_id).await, state);
}

async fn set_baseline_state(stack: &BootedStack, invoice_id: &str, state: &str) {
    sqlx::query("UPDATE invoices SET baseline_state = $1 WHERE id = $2")
        .bind(state)
        .bind(uuid::Uuid::parse_str(invoice_id).unwrap())
        .execute(&stack.pool)
        .await
        .unwrap();
}

/// void and activate across the TOTAL §B.11.1 state set: the named result
/// of each operation for every state, zero writes for every refusal and
/// every replay, and the one transitioning pair (`prepared`) asserting
/// exactly its designed writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn void_and_activate_named_errors_for_every_state() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(65).await;

    const FINALIZED: Phase2Outcome =
        Phase2Outcome::Refused(StatusCode::CONFLICT, "invoice_finalized");
    // (state, activate outcome, void outcome) — every §B.11.1 state.
    let table: [(&str, Phase2Outcome, Phase2Outcome); 10] = [
        (
            "awaiting_baseline",
            Phase2Outcome::Refused(StatusCode::CONFLICT, "invoice_baseline_in_progress"),
            Phase2Outcome::Refused(StatusCode::CONFLICT, "invoice_baseline_in_progress"),
        ),
        (
            "prepared",
            Phase2Outcome::Transition,
            Phase2Outcome::Transition,
        ),
        ("observing", Phase2Outcome::Replay, FINALIZED),
        ("expired_tail", Phase2Outcome::Replay, FINALIZED),
        ("expired_final", FINALIZED, FINALIZED),
        ("void_baseline_failed", FINALIZED, FINALIZED),
        (
            "void_prepare_expired",
            Phase2Outcome::Refused(StatusCode::CONFLICT, "prepare_expired"),
            Phase2Outcome::Replay,
        ),
        ("void_cancelled", FINALIZED, Phase2Outcome::Replay),
        ("resolved_paid_manually", FINALIZED, FINALIZED),
        ("resolved_closed", FINALIZED, FINALIZED),
    ];

    // The references that drove each state, for the phase-1 replay rows
    // asserted after the table.
    let mut reference_of: HashMap<&str, String> = HashMap::new();
    for (index, (state, activate_outcome, void_outcome)) in table.iter().enumerate() {
        let reference = table_reference(index);
        reference_of.insert(*state, reference.clone());

        // `prepared` is the one state whose operations write, and each
        // operation consumes the state — so each gets its own invoice.
        let invoices: Vec<(String, u64)> = if *state == "prepared" {
            let mut pair = Vec::new();
            for attempt in 0..2 {
                let body = prepare(&stack, &table_reference(20 + 2 * index + attempt)).await;
                pair.push((
                    body["invoice_id"].as_str().unwrap().to_owned(),
                    body["total_sats"].as_u64().unwrap(),
                ));
            }
            pair
        } else {
            let body = prepare(&stack, &reference).await;
            vec![(
                body["invoice_id"].as_str().unwrap().to_owned(),
                body["total_sats"].as_u64().unwrap(),
            )]
        };

        let void_invoice = if *state == "prepared" {
            &invoices[1]
        } else {
            &invoices[0]
        };
        for (op, outcome, (invoice_id, total_sats)) in [
            ("activate", activate_outcome, &invoices[0]),
            ("void", void_outcome, void_invoice),
        ] {
            drive_to_state(&stack, invoice_id, *total_sats, state).await;
            let before = writes_snapshot(&stack, invoice_id).await;
            let response = match op {
                "activate" => activate(&stack, invoice_id, *total_sats).await,
                _ => void(&stack, invoice_id).await,
            };
            match outcome {
                Phase2Outcome::Replay => {
                    assert_eq!(
                        response.status,
                        StatusCode::OK,
                        "{op} on {state}: {}",
                        String::from_utf8_lossy(&response.body)
                    );
                    let body = response.json();
                    assert_eq!(body["state"], *state, "{op} replay on {state}");
                    assert_eq!(body["invoice_id"], invoice_id.as_str());
                    assert_zero_writes(
                        &before,
                        &writes_snapshot(&stack, invoice_id).await,
                        op,
                        state,
                    );
                }
                Phase2Outcome::Refused(status, code) => {
                    assert_eq!(
                        response.status,
                        *status,
                        "{op} on {state}: {}",
                        String::from_utf8_lossy(&response.body)
                    );
                    assert_eq!(response.json()["error"]["code"], *code, "{op} on {state}");
                    assert_zero_writes(
                        &before,
                        &writes_snapshot(&stack, invoice_id).await,
                        op,
                        state,
                    );
                }
                Phase2Outcome::Transition => {
                    assert_eq!(
                        response.status,
                        StatusCode::OK,
                        "{op} on {state}: {}",
                        String::from_utf8_lossy(&response.body)
                    );
                    let body = response.json();
                    let landed = baseline_state(&stack.pool, invoice_id).await;
                    match op {
                        // The designed writes and only they: state flip,
                        // both outbox rows queued, nothing else.
                        "activate" => {
                            assert_eq!(body["state"], "observing");
                            assert_eq!(landed, "observing");
                            assert_eq!(
                                outbox_statuses(&stack.pool, invoice_id).await,
                                vec!["queued".to_owned(), "queued".to_owned()]
                            );
                        }
                        _ => {
                            assert_eq!(body["state"], "void_cancelled");
                            assert!(body["voided_at"].as_str().is_some());
                            assert_eq!(landed, "void_cancelled");
                        }
                    }
                }
            }
        }
    }

    // A void replay is byte-identical (§B.11.6 idempotence).
    let voided_reference = reference_of["void_cancelled"].clone();
    let voided_body = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, &voided_reference),
    )
    .await;
    assert_eq!(voided_body.status, StatusCode::CONFLICT);
    assert_eq!(voided_body.json()["error"]["code"], "invoice_finalized");

    // Phase-1 replays against the same bindings (§B.11.6): `observing`
    // returns the stored body; the reaped and voided states answer their
    // named refusals.
    let observing_reference = reference_of["observing"].clone();
    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, &observing_reference),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "observing replay: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.json()["state"], "observing");
    let reaped_reference = reference_of["void_prepare_expired"].clone();
    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, &reaped_reference),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "prepare_expired");

    // unknown_invoice on both phase-2 routes (404), behind a valid
    // signature and the correct stack_id.
    let unknown = uuid::Uuid::new_v4().to_string();
    let response = activate(&stack, &unknown, 1).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json()["error"]["code"], "unknown_invoice");
    let response = void(&stack, &unknown).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.json()["error"]["code"], "unknown_invoice");

    // void naming another stack is refused before touching anything.
    let observing_id = {
        let mut rows: Vec<String> =
            sqlx::query_scalar("SELECT id::text FROM invoices WHERE baseline_state = 'observing'")
                .fetch_all(&stack.pool)
                .await
                .unwrap();
        rows.pop().unwrap()
    };
    let before = writes_snapshot(&stack, &observing_id).await;
    let response = post(
        &stack,
        &format!("/v0/payment-requests/{observing_id}/void"),
        void_body(
            &observing_id,
            "production:6f1d0c2a-9b47-4e35-8a10-73c5e2d84b19",
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "stack_identity_mismatch");
    assert_zero_writes(
        &before,
        &writes_snapshot(&stack, &observing_id).await,
        "void",
        "observing (foreign stack_id)",
    );

    stack.shutdown().await;
}

const REAPER_CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn reaper_reader() -> ReaderPubky {
    for character in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = REAPER_CREATOR.to_owned();
        candidate.replace_range(5..6, &character.to_string());
        if let Ok(reader) = parse_reader(&candidate) {
            return reader;
        }
    }
    panic!("valid reader fixture")
}

fn test_marker() -> paykit_lib::PaykitReceiverMarker {
    paykit_lib::PaykitReceiverMarker::new(
        PaykitReceiverPath::new("bitkit/wallet").unwrap(),
        PaykitReceiverCapabilities {
            private_payments: true,
            payment_requests: true,
            receipts: false,
            outgoing_payments: false,
        },
        paykit_lib::PublicKey::try_from_z32("tkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy")
            .unwrap(),
    )
}

struct ReaperPayloads(ReaderPubky);
impl NewReaderPayloadFactory for ReaperPayloads {
    fn for_child_index(&self, child_index: i64) -> Result<NewReaderPayloads, PersistenceError> {
        Ok(NewReaderPayloads {
            endpoint_intent:
                paykit_server::application::semantic_intent::DeliveryIntentV1::endpoint(
                    self.0.to_string(),
                    &test_marker(),
                    PaykitReceiverPath::new("paykit/server").unwrap(),
                    vec![(
                        paykit_lib::PaymentEndpointIdentifier::new("btc-testnet-p2wpkh").unwrap(),
                        paykit_lib::PaymentEndpointPayload::new(
                            serde_json::json!({ "value": format!("reaper-address-{child_index}") })
                                .to_string(),
                        ),
                    )],
                )
                .unwrap(),
            bitcoin_address: format!("reaper-address-{child_index}"),
        })
    }
}

/// The §B.11.1 reaper: one query per tick, `prepared` past
/// `prepare_expires_at` → `void_prepare_expired`; anything else untouched.
#[tokio::test]
async fn reaper_voids_expired_prepares_and_nothing_else() {
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[7; 32]).unwrap());
    let creator = parse_creator(REAPER_CREATOR).unwrap();
    CreatorStore::new(pool, crypto.clone())
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session".into(),
                ReceiverNoiseSecretKey::new([9; 32]),
                "xpub".into(),
                0,
            ),
            &Default::default(),
            &key_tail(66),
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let store = InvoiceStore::new(pool, crypto);
    let reader = reaper_reader();
    let payloads = ReaperPayloads(reader.clone());

    fn input<'a>(
        creator: &'a CreatorPubky,
        reader: &'a ReaderPubky,
        payloads: &'a ReaperPayloads,
        bundle: &'a [u8],
    ) -> AtomicInvoiceInput<'a> {
        AtomicInvoiceInput {
            creator,
            reader,
            bundle_binding: bundle,
            payment_request_binding: bundle,
            new_reader_payloads: payloads,
            payment_request_intent:
                paykit_server::application::semantic_intent::DeliveryIntentV1::payment_request(
                    reader.to_string(),
                    &test_marker(),
                    PaykitReceiverPath::new("paykit/server").unwrap(),
                    &paykit_lib::PaymentRequestTerms {
                        amount: paykit_lib::PaymentAmount::new("0.00001010", "btc").unwrap(),
                        payment_reference: paykit_lib::PaymentReference::new(
                            uuid::Uuid::new_v4().hyphenated().to_string(),
                        )
                        .unwrap(),
                        proposal_expires_at: None,
                        recurrence: None,
                        accepted_payment_endpoint_identifiers: vec![
                            paykit_lib::PaymentEndpointIdentifier::new("btc-testnet-p2wpkh")
                                .unwrap(),
                        ],
                        metadata: Default::default(),
                    },
                )
                .unwrap(),
            required_sats: 101,
            nonce_sats: 1,
            prepare_ttl: Duration::from_secs(900),
            expires_at: None,
        }
    }

    // Three invoices: an expired prepare, a live prepare, an observing one.
    let expired = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-expired"))
        .await
        .unwrap();
    let live = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-live"))
        .await
        .unwrap();
    let observing = store
        .create_awaiting_baseline(input(&creator, &reader, &payloads, b"reaper-observing"))
        .await
        .unwrap();
    for created in [&expired, &live, &observing] {
        store
            .complete_creation_baseline(created.invoice_id(), 100, &[], &[])
            .await
            .unwrap();
    }
    store
        .activate_invoice(observing.invoice_id(), &[], &[])
        .await
        .unwrap();
    sqlx::query(
        "UPDATE invoices SET prepare_expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(expired.invoice_id())
    .execute(pool)
    .await
    .unwrap();

    assert_eq!(store.reap_expired_prepares().await.unwrap(), 1);
    let states: Vec<String> =
        sqlx::query_scalar("SELECT baseline_state FROM invoices ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(
        states,
        vec!["void_prepare_expired", "prepared", "observing"]
    );
    // Final and never a target; the reaper is idempotent and never selects
    // `observing`.
    assert_eq!(store.reap_expired_prepares().await.unwrap(), 0);
    assert_eq!(store.observation_plan().await.unwrap().len(), 1);

    database.cleanup().await;
}

/// A phase-1 replay on `prepared` mints nothing: the derivation cursor, the
/// nonce, the outbox row count and every body field are equal before/after.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn prepare_replay_on_prepared_mints_nothing_and_returns_the_stored_body() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(67).await;
    let body = prepare(&stack, REFERENCE_A).await;

    let cursor_before: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    let outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(&stack.pool)
        .await
        .unwrap();

    let replay = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_A),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(
        replay.json(),
        body,
        "a replay returns the stored body byte-for-byte"
    );

    let cursor_after: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    let outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
        .fetch_one(&stack.pool)
        .await
        .unwrap();
    assert_eq!(cursor_after, cursor_before, "no second index is burned");
    assert_eq!(
        outbox_after, outbox_before,
        "no second outbox row is minted"
    );

    stack.shutdown().await;
}

/// W1.4 continuity: a hidden offer refuses a New prepare with 503
/// `bitcoin_offer_unavailable`, while activate and void of an existing
/// `prepared` invoice keep working (they are never gated).
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn hidden_offer_gates_prepare_but_never_activate_or_void() {
    let _testnet_guard = PUBKY_TESTNET_LOCK.lock().await;
    let stack = boot(68).await;
    let first = prepare(&stack, REFERENCE_A).await;
    let second = prepare(&stack, REFERENCE_B).await;

    // Drive the offer-availability hysteresis to hidden.
    for _ in 0..3 {
        stack.runtime.record_electrum_probe_failure();
    }
    assert!(!stack.runtime.readiness().await.bitcoin_offer_available);

    let response = post(
        &stack,
        "/v0/payment-requests",
        payment_request_body(&stack.creator.creator, &stack.reader, REFERENCE_C),
    )
    .await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json()["error"]["code"],
        "bitcoin_offer_unavailable"
    );

    // activate/void are never gated by offer availability (§C.16: refusing
    // them would strand exactly the prepared invoices the switch drains).
    let response = activate(
        &stack,
        first["invoice_id"].as_str().unwrap(),
        first["total_sats"].as_u64().unwrap(),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "activate under a hidden offer: {}",
        String::from_utf8_lossy(&response.body)
    );
    let response = void(&stack, second["invoice_id"].as_str().unwrap()).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "void under a hidden offer: {}",
        String::from_utf8_lossy(&response.body)
    );

    stack.shutdown().await;
}

// ---------------------------------------------------------------------------
// §B.11.6 replay-wait (phase 1 against `awaiting_baseline`), proven at the
// application-service level over a REAL Postgres store: the deadline is
// driven through the `DeadlineClock` seam, never through wall-clock sleeps.
// ---------------------------------------------------------------------------

/// A deadline clock the test advances by hand: the replay's request budget
/// elapses exactly when the test says so, with no sleeping.
struct ManualClock {
    now: Mutex<std::time::Instant>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            now: Mutex::new(std::time::Instant::now()),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += duration;
    }
}

impl DeadlineClock for ManualClock {
    fn now(&self) -> std::time::Instant {
        *self.now.lock().unwrap()
    }
}

/// The real Postgres [`InvoiceStore`] behind the `InvoicePersistence`
/// port, with a preflight counter so the test can synchronize on the
/// replay having entered its §B.11.6 wait loop.
struct CountingStore {
    inner: InvoiceStore,
    preflight_calls: AtomicUsize,
}

#[async_trait]
impl InvoicePersistence for CountingStore {
    async fn preflight(
        &self,
        creator: &CreatorPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<InvoicePreflight, PersistenceError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .preflight(creator, bundle_binding, payment_binding)
            .await
    }

    async fn exact_replay(
        &self,
        creator: &CreatorPubky,
        reader: &ReaderPubky,
        bundle_binding: &[u8],
        payment_binding: &[u8],
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.inner
            .exact_replay(creator, reader, bundle_binding, payment_binding)
            .await
    }

    async fn create_atomic(
        &self,
        input: AtomicInvoiceInput<'_>,
    ) -> Result<AtomicInvoiceResult, PersistenceError> {
        self.inner.create_awaiting_baseline(input).await
    }

    async fn complete_creation_baseline(
        &self,
        invoice_id: uuid::Uuid,
        snapshot: &CreationSnapshot,
    ) -> Result<(), PersistenceError> {
        self.inner
            .complete_creation_baseline(
                invoice_id,
                snapshot.tip_height,
                &snapshot.baseline_outputs,
                &snapshot.unconfirmed_inputs,
            )
            .await
    }

    async fn fail_creation_baseline(&self, invoice_id: uuid::Uuid) -> Result<(), PersistenceError> {
        self.inner.fail_creation_baseline(invoice_id).await
    }

    async fn prepare_view(
        &self,
        invoice_id: uuid::Uuid,
    ) -> Result<Option<InvoicePhaseView>, PersistenceError> {
        self.inner.prepare_view(invoice_id).await
    }
}

/// An Electrum fake whose creation snapshot parks until the test releases
/// it (a watch channel: no missed wakeups), then either completes or fails
/// the baseline as the test scripted.
struct GatedBaselineElectrum {
    snapshot_starts: AtomicUsize,
    release: tokio::sync::watch::Receiver<bool>,
    fail_on_release: AtomicBool,
}

#[async_trait]
impl ElectrumPort for GatedBaselineElectrum {
    async fn creation_snapshot(
        &self,
        _address: &str,
        _max_history_entries: usize,
        _max_transaction_bytes: usize,
        _request_limiter: &RequestLimiter,
        _snapshot_slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<CreationSnapshot, ObserverError> {
        self.snapshot_starts.fetch_add(1, Ordering::SeqCst);
        let mut release = self.release.clone();
        while !*release.borrow_and_update() {
            release
                .changed()
                .await
                .map_err(|_| ObserverError::Unavailable)?;
        }
        if self.fail_on_release.load(Ordering::SeqCst) {
            return Err(ObserverError::Unavailable);
        }
        Ok(CreationSnapshot {
            tip_height: 300,
            baseline_outputs: Vec::new(),
            unconfirmed_inputs: Vec::new(),
            unconfirmed_outputs: Vec::new(),
        })
    }

    async fn observations(
        &self,
        _tip_height: u32,
        _targets: &[ObservationTarget],
    ) -> Result<ObservationReport, ObserverError> {
        Ok(ObservationReport::default())
    }

    async fn probe(&self) -> Result<TipProbe, ObserverError> {
        Ok(TipProbe {
            height: 300,
            time_unix: fresh_tip_time(),
        })
    }
}

struct OkSession;
#[async_trait]
impl SessionValidator for OkSession {
    async fn validate(&self, _creator: &CreatorPubky) -> Result<(), SessionValidationError> {
        Ok(())
    }
}

struct StaticMarkers;
#[async_trait]
impl MarkerDiscovery for StaticMarkers {
    async fn discover(
        &self,
        _reader: &ReaderPubky,
    ) -> Result<Vec<paykit_lib::PaykitReceiverMarker>, CreateInvoiceError> {
        Ok(vec![test_marker()])
    }
}

/// One creator in a real database, one gated Electrum, and the shared
/// counting store — everything two marketplace services (creation with a
/// frozen clock, replay with the test-advanced clock) need.
struct ReplayFixture {
    pool: PgPool,
    store: Arc<CountingStore>,
    electrum: Arc<GatedBaselineElectrum>,
    release: tokio::sync::watch::Sender<bool>,
    creators: CreatorStore,
    creator: CreatorPubky,
    reader: ReaderPubky,
    database: TestDatabase,
}

impl ReplayFixture {
    fn service(&self, clock: Arc<dyn DeadlineClock>) -> MarketplacePaymentRequestService {
        MarketplacePaymentRequestService::with_clock(
            Arc::new(OkSession),
            Arc::new(StaticMarkers),
            vec![ReceiverPathPriority::parse("bitkit".into()).unwrap()],
            PaykitReceiverPath::new("paykit/server").unwrap(),
            Arc::new(self.creators.clone()),
            BitcoinNetwork::Testnet,
            true,
            self.store.clone(),
            self.electrum.clone(),
            50,
            400_000,
            Arc::new(PaykitIntentBuilder::for_network(&BitcoinNetwork::Testnet)),
            clock,
        )
    }

    fn request(&self, reference: &str) -> MarketplacePaymentRequest {
        MarketplacePaymentRequest {
            creator: self.creator.clone(),
            reader: self.reader.clone(),
            reference: parse_bundle_id(reference).unwrap(),
            amount_sats: 50_000,
            expires_at: time::OffsetDateTime::parse(
                EXPIRES_AT,
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
            idempotency_key: format!("{reference}:1"),
        }
    }

    /// Waits until the creation's `awaiting_baseline` row is committed and
    /// its snapshot is parked on the gate. Only then may the replay be
    /// spawned: its preflight must read the committed row (never `New`),
    /// so it always takes the §B.11.6 wait path.
    async fn wait_until_baseline_parked(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let awaiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoices WHERE baseline_state = 'awaiting_baseline'",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap();
            if awaiting == 1 && self.electrum.snapshot_starts.load(Ordering::SeqCst) == 1 {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the creation never reached the parked snapshot"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits until the replay has polled at least once inside the §B.11.6
    /// wait loop (one creation preflight, one replay preflight, one
    /// wait-loop poll).
    async fn wait_until_replay_is_waiting(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while self.store.preflight_calls.load(Ordering::SeqCst) < 3 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the replay never entered the §B.11.6 wait"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The replay minted nothing: one invoice, one derivation index, the
    /// original two outbox rows.
    async fn assert_single_allocation(&self) {
        let invoices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(invoices, 1, "no second invoice may exist");
        let next_index: i64 = sqlx::query_scalar("SELECT next_child_index FROM creators")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(next_index, 1, "no second derivation index may be burned");
        let outbox_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(outbox_rows, 2, "no second outbox row may be minted");
        assert_eq!(
            self.electrum.snapshot_starts.load(Ordering::SeqCst),
            1,
            "no second baseline snapshot may run"
        );
    }

    async fn cleanup(self) {
        self.pool.close().await;
        self.database.cleanup().await;
    }
}

async fn replay_fixture(seed: u8) -> ReplayFixture {
    let database = TestDatabase::create().await;
    let pool = database.pool();
    run_migrations(pool).await.unwrap();
    let crypto = Arc::new(Crypto::from_master_key(&[seed; 32]).unwrap());
    let creator = parse_creator(REAPER_CREATOR).unwrap();
    let creators = CreatorStore::new(pool, crypto.clone());
    creators
        .create(
            &CreatorCredentials::new(
                creator.clone(),
                "session".into(),
                ReceiverNoiseSecretKey::new([seed; 32]),
                account_xpub(seed, 0),
                0,
            ),
            &Default::default(),
            &key_tail(seed),
            &ClaimAllocation::shared_manual_default(),
            0,
        )
        .await
        .unwrap();
    let (release, release_rx) = tokio::sync::watch::channel(false);
    ReplayFixture {
        pool: pool.clone(),
        store: Arc::new(CountingStore {
            inner: InvoiceStore::new(pool, crypto),
            preflight_calls: AtomicUsize::new(0),
        }),
        electrum: Arc::new(GatedBaselineElectrum {
            snapshot_starts: AtomicUsize::new(0),
            release: release_rx,
            fail_on_release: AtomicBool::new(false),
        }),
        release,
        creators,
        creator,
        reader: reaper_reader(),
        database,
    }
}

/// §B.11.6: an exact replay that lands on `awaiting_baseline` waits for
/// the in-flight baseline and is then served the stored body — identical
/// to the original caller's — with exactly one index, one nonce and the
/// original two outbox rows in existence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepare_replay_during_baseline_waits_and_returns_the_stored_body() {
    let fixture = replay_fixture(70).await;
    let reference = table_reference(30);
    let creation = tokio::spawn({
        let service = fixture.service(Arc::new(ManualClock::new()));
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_baseline_parked().await;
    let replay = tokio::spawn({
        let service = fixture.service(Arc::new(ManualClock::new()));
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_replay_is_waiting().await;

    // The in-flight baseline completes inside the replay's request budget.
    fixture.release.send(true).unwrap();
    let replayed = replay
        .await
        .unwrap()
        .expect("the waiting replay is served the stored body");
    let created = creation
        .await
        .unwrap()
        .expect("the held-open creation completes once released");
    assert_eq!(
        replayed, created,
        "the replay body is identical to the original response"
    );
    fixture.assert_single_allocation().await;
    fixture.cleanup().await;
}

/// §B.11.6: the wait is bounded by the request deadline. With the deadline
/// elapsed before the baseline completes, the replay answers
/// `DeadlineExceeded` (503 `dependency_timeout`) — never the in-progress
/// refusal — and the in-flight baseline still completes afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepare_replay_during_baseline_times_out_as_dependency_timeout() {
    let fixture = replay_fixture(71).await;
    let reference = table_reference(31);
    // The creation's clock stays frozen: its own request deadline can
    // never fire while the baseline is parked — only the replay's budget
    // elapses, driven through the clock seam.
    let creation = tokio::spawn({
        let service = fixture.service(Arc::new(ManualClock::new()));
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_baseline_parked().await;
    let replay_clock = Arc::new(ManualClock::new());
    let replay = tokio::spawn({
        let service = fixture.service(replay_clock.clone());
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_replay_is_waiting().await;

    // The deadline/clock seam: the replay's whole request budget elapses
    // while the baseline is still parked.
    replay_clock.advance(Duration::from_secs(16));
    let outcome = replay.await.unwrap();
    assert_eq!(
        outcome,
        Err(CreateInvoiceError::DeadlineExceeded),
        "the wait is bounded by the request deadline"
    );
    fixture.assert_single_allocation().await;

    // The in-flight baseline is unaffected: it completes to `prepared`.
    fixture.release.send(true).unwrap();
    creation
        .await
        .unwrap()
        .expect("the held-open creation completes once released");
    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(state, "prepared");
    fixture.cleanup().await;
}

/// §B.11.6: when the in-flight baseline fails during the wait, the replay
/// lands on `void_baseline_failed` and answers the named
/// `invoice_finalized` refusal — never replay success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepare_replay_during_failed_baseline_returns_invoice_finalized() {
    let fixture = replay_fixture(72).await;
    let reference = table_reference(32);
    let creation = tokio::spawn({
        let service = fixture.service(Arc::new(ManualClock::new()));
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_baseline_parked().await;
    let replay = tokio::spawn({
        let service = fixture.service(Arc::new(ManualClock::new()));
        let request = fixture.request(&reference);
        async move { service.create(request).await }
    });
    fixture.wait_until_replay_is_waiting().await;

    // The baseline fails during the wait: the replay must land on
    // `void_baseline_failed` and answer `invoice_finalized`.
    fixture
        .electrum
        .fail_on_release
        .store(true, Ordering::SeqCst);
    fixture.release.send(true).unwrap();
    let created = creation.await.unwrap();
    assert_eq!(
        created,
        Err(CreateInvoiceError::Unavailable),
        "the failed baseline refuses the original caller"
    );
    let replayed = replay.await.unwrap();
    assert_eq!(
        replayed,
        Err(CreateInvoiceError::InvoiceFinalized),
        "a baseline that fails during the wait is the finalized refusal"
    );
    let state: String = sqlx::query_scalar("SELECT baseline_state FROM invoices")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(state, "void_baseline_failed");
    fixture.assert_single_allocation().await;
    fixture.cleanup().await;
}
